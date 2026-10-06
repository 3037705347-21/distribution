package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/opencontainers/go-digest"
)

// This file implements the independent verification pass and the cutover
// gate:
//
//   verify   re-hashes every migrated blob, checks every migrated link and
//            compares each repository's tag tree byte-for-byte with the
//            source; failures demote units and are written to quarantine.
//   cutover  is the single explicit switchover point. It writes the marker
//            only after: ledger convergence, zero source drift, a clean
//            verify pass and an empty staging area.

// VerifyOptions scopes a verify pass.
type VerifyOptions struct {
	Repositories []string
	// LedgerPrefix overrides the reserved ledger prefix (optional).
	LedgerPrefix string
}

// VerifyReport summarizes an independent verification pass.
type VerifyReport struct {
	BlobsChecked int64
	BlobsBad     int64

	LinksChecked int64
	LinksBad     int64

	TagTreesCompared int
	TagMismatches    int64

	StaleInProgress int64
	TmpLeftovers    int

	Failures []string
	Passed   bool
}

// runVerify independently validates the destination against the ledger and
// the source.
func runVerify(ctx context.Context, src, dst driver.StorageDriver, opts VerifyOptions) (*VerifyReport, error) {
	l := newMigrationLedger(dst, opts.LedgerPrefix)
	rep := &VerifyReport{}
	filter := repoSet(opts.Repositories)

	liveRunner := liveMigrationRunner(ctx, l)

	// ---- global blobs: full rehash ----
	if err := l.listBlobRecords(ctx, func(b *blobRecord) error {
		switch b.State {
		case stateCompleted:
			rep.BlobsChecked++
			p, err := blobDataCanonicalPath(digestDigest(b.Digest))
			if err != nil {
				return err
			}
			observed, size, err := hashDriverObject(ctx, dst, p, digest.Algorithm(b.Algorithm))
			if err != nil || observed != b.Digest || size != b.ExpectedSize {
				rep.BlobsBad++
				reason := "post-migration blob verification failed"
				if err != nil {
					reason = "post-migration blob unreadable: " + err.Error()
				}
				_, _ = l.quarantine(ctx, &quarantineRecord{
					Kind: qKindBlobConflict, Key: b.Digest,
					ExpectedDigest: b.Digest, ExpectedSize: b.ExpectedSize,
					ObservedDigest: observed, ObservedSize: size, Reason: reason,
				})
				_, _ = l.mutateBlobRecord(ctx, digestDigest(b.Digest), false, func(r *blobRecord) error {
					r.State = stateConflict
					recordError(&r.Errors, "%s", reason)
					return nil
				})
				rep.Failures = append(rep.Failures, "blob "+b.Digest+": "+reason)
			}
		case stateConflict:
			// Deterministic re-check: an operator may have replaced the bad
			// destination object; verify completes it when it now validates.
			p, err := blobDataCanonicalPath(digestDigest(b.Digest))
			if err != nil {
				return err
			}
			fi, statErr := dst.Stat(ctx, p)
			if statErr == nil && !fi.IsDir() && fi.Size() == b.ExpectedSize {
				if observed, size, herr := hashDriverObject(ctx, dst, p, digest.Algorithm(b.Algorithm)); herr == nil &&
					observed == b.Digest && size == b.ExpectedSize {
					if _, err := l.mutateBlobRecord(ctx, digestDigest(b.Digest), false, func(r *blobRecord) error {
						r.State = stateCompleted
						r.Origin = originReused
						r.ObservedDigest = ""
						r.ObservedSize = 0
						return nil
					}); err != nil {
						return err
					}
					_, _ = l.resolveQuarantineByKey(ctx, b.Digest, "object replaced and re-verified")
				}
			}
		case statePending, stateInProgress:
			if !liveRunner {
				rep.StaleInProgress++
				rep.Failures = append(rep.Failures, "stale unfinished blob: "+b.Digest)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// ---- per-repository links and tag trees ----
	if err := l.listRepoRecords(ctx, func(rec *repoRecord) error {
		if len(filter) > 0 {
			if _, ok := filter[rec.Name]; !ok {
				return nil
			}
		}
		name := rec.Name
		recheck := func(area, dg string, spec pathSpec, promote func() error) {
			rep.LinksChecked++
			if verifyLinkFile(ctx, l, dst, rep, name, area, dg, spec) {
				if err := promote(); err == nil {
					_, _ = l.resolveQuarantineByKey(ctx, area+":"+dg, "link re-verified")
				}
			}
		}

		for dg, su := range rec.Layers {
			if su.Gone {
				continue
			}
			switch su.State {
			case stateCompleted:
				rep.LinksChecked++
				if !verifyLinkFile(ctx, l, dst, rep, name, "layer", dg, layerLinkPathSpec{name: name, digest: digestDigest(dg)}) {
					_ = demoteLayer(ctx, l, name, dg)
				}
			case stateConflict:
				recheck("layer", dg, layerLinkPathSpec{name: name, digest: digestDigest(dg)},
					func() error { return promoteLayer(ctx, l, name, dg) })
			}
		}
		for dg, su := range rec.Revisions {
			if su.Gone {
				continue
			}
			switch su.State {
			case stateCompleted:
				rep.LinksChecked++
				if !verifyLinkFile(ctx, l, dst, rep, name, "revision", dg, manifestRevisionLinkPathSpec{name: name, revision: digestDigest(dg)}) {
					_ = demoteRevision(ctx, l, name, dg)
				}
			case stateConflict:
				recheck("revision", dg, manifestRevisionLinkPathSpec{name: name, revision: digestDigest(dg)},
					func() error { return promoteRevision(ctx, l, name, dg) })
			}
		}
		for tag, tu := range rec.Tags {
			if tu.Gone {
				continue
			}
			for dg, st := range tu.Index {
				if tu.IndexGone[dg] {
					continue
				}
				spec := manifestTagIndexEntryLinkPathSpec{name: name, tag: tag, revision: digestDigest(dg)}
				area := "tag-index:" + tag
				switch st {
				case stateCompleted:
					rep.LinksChecked++
					if !verifyLinkFile(ctx, l, dst, rep, name, area, dg, spec) {
						_ = demoteTagIndex(ctx, l, name, tag, dg)
					}
				case stateConflict:
					recheck(area, dg, spec,
						func() error { return promoteTagIndex(ctx, l, name, tag, dg) })
				}
			}
			if tu.HasCurrent && (tu.CurrentState == stateCompleted || tu.CurrentState == stateConflict) {
				area := "tag-current:" + tag
				spec := manifestTagCurrentPathSpec{name: name, tag: tag}
				if tu.CurrentState == stateCompleted {
					rep.LinksChecked++
					if !verifyLinkFile(ctx, l, dst, rep, name, area, tu.Current, spec) {
						_ = demoteTagCurrent(ctx, l, name, tag)
					}
				} else {
					recheck(area, tu.Current, spec,
						func() error { return promoteTagCurrent(ctx, l, name, tag, tu.Current) })
				}
			}
		}

		// Byte-for-byte comparison of the link trees with the source, so a
		// link cannot be silently swapped for another valid-looking digest.
		if src != nil {
			compareLinkTree(ctx, src, dst, rep, name, "manifests", manifestsPathSpec{name: name})
			compareLinkTree(ctx, src, dst, rep, name, "layers", layersPathSpec{name: name})
		}
		return nil
	}); err != nil {
		return nil, err
	}

	tmp, err := l.listTempFiles(ctx)
	if err != nil {
		return nil, err
	}
	rep.TmpLeftovers = len(tmp)
	if rep.TmpLeftovers > 0 {
		rep.Failures = append(rep.Failures, fmt.Sprintf("%d files left in staging area", rep.TmpLeftovers))
	}

	rep.Passed = rep.BlobsBad == 0 && rep.LinksBad == 0 && rep.TagMismatches == 0 &&
		rep.StaleInProgress == 0 && rep.TmpLeftovers == 0 && len(rep.Failures) == 0
	return rep, nil
}

// String renders the verify report for the CLI.
func (r *VerifyReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Verification %s\n", map[bool]string{true: "PASSED", false: "FAILED"}[r.Passed])
	fmt.Fprintf(&b, "  blobs:        %d checked, %d bad\n", r.BlobsChecked, r.BlobsBad)
	fmt.Fprintf(&b, "  links:        %d checked, %d bad\n", r.LinksChecked, r.LinksBad)
	fmt.Fprintf(&b, "  tag trees:    %d compared, %d mismatched\n", r.TagTreesCompared, r.TagMismatches)
	fmt.Fprintf(&b, "  stale units:  %d\n", r.StaleInProgress)
	fmt.Fprintf(&b, "  staging junk: %d\n", r.TmpLeftovers)
	if len(r.Failures) > 0 {
		fmt.Fprintln(&b, "  failures:")
		for _, f := range r.Failures {
			fmt.Fprintf(&b, "    - %s\n", f)
		}
	}
	return b.String()
}

// verifyLinkFile checks that a migrated link exists on the target, parses as
// a digest, and points at a blob that also exists on the target.
func verifyLinkFile(ctx context.Context, l *migrationLedger, dst driver.StorageDriver, rep *VerifyReport, repo, area, dg string, spec pathSpec) bool {
	p, err := pathFor(spec)
	if err != nil {
		rep.Failures = append(rep.Failures, area+" "+dg+": "+err.Error())
		return false
	}
	b, err := dst.GetContent(ctx, p)
	if err != nil {
		rep.LinksBad++
		_, _ = l.quarantine(ctx, &quarantineRecord{
			Kind: "link-verify-failed", Repo: repo, Key: area + ":" + dg, Reason: "target link unreadable: " + err.Error(),
		})
		rep.Failures = append(rep.Failures, area+" "+dg+": link unreadable on target")
		return false
	}
	parsed, err := digest.Parse(string(b))
	if err != nil {
		rep.LinksBad++
		_, _ = l.quarantine(ctx, &quarantineRecord{
			Kind: "link-verify-failed", Repo: repo, Key: area + ":" + dg,
			ObservedDigest: string(b), Reason: "target link content is not a digest",
		})
		rep.Failures = append(rep.Failures, area+" "+dg+": malformed link content")
		return false
	}
	if parsed.String() != dg {
		rep.LinksBad++
		_, _ = l.quarantine(ctx, &quarantineRecord{
			Kind: "link-verify-failed", Repo: repo, Key: area + ":" + dg,
			ExpectedDigest: dg, ObservedDigest: parsed.String(),
			Reason: "target link points at a different digest than the ledger expects",
		})
		rep.Failures = append(rep.Failures, area+" "+dg+": link points to "+parsed.String())
		return false
	}
	bp, err := blobDataCanonicalPath(parsed)
	if err != nil {
		return false
	}
	if _, err := dst.Stat(ctx, bp); err != nil {
		rep.LinksBad++
		_, _ = l.quarantine(ctx, &quarantineRecord{
			Kind: "link-verify-failed", Repo: repo, Key: area + ":" + dg,
			ExpectedDigest: parsed.String(), Reason: "link target blob missing on destination",
		})
		rep.Failures = append(rep.Failures, area+" "+dg+": target blob missing")
		return false
	}
	return true
}

// compareLinkTree walks one link subtree (manifests or layers) on both
// backends and records any set or byte difference.
func compareLinkTree(ctx context.Context, src, dst driver.StorageDriver, rep *VerifyReport, name, kind string, spec pathSpec) {
	prefix, err := pathFor(spec)
	if err != nil {
		rep.Failures = append(rep.Failures, kind+" tree "+name+": "+err.Error())
		return
	}
	srcTree, err := readAllFiles(ctx, src, prefix)
	if err != nil {
		rep.Failures = append(rep.Failures, kind+" tree "+name+": source walk: "+err.Error())
		return
	}
	dstTree, err := readAllFiles(ctx, dst, prefix)
	if err != nil {
		rep.Failures = append(rep.Failures, kind+" tree "+name+": target walk: "+err.Error())
		rep.TagMismatches++
		return
	}
	rep.TagTreesCompared++
	var mismatches []string
	for p, content := range srcTree {
		got, ok := dstTree[p]
		if !ok {
			mismatches = append(mismatches, "missing on target: "+p)
			continue
		}
		if got != content {
			mismatches = append(mismatches, "content differs: "+p)
		}
	}
	for p := range dstTree {
		if _, ok := srcTree[p]; !ok {
			mismatches = append(mismatches, "unexpected extra on target: "+p)
		}
	}
	if len(mismatches) > 0 {
		rep.TagMismatches++
		rep.Failures = append(rep.Failures,
			append([]string{kind + " tree " + name + " mismatches:"}, mismatches...)...)
	}
}

func readAllFiles(ctx context.Context, d driver.StorageDriver, prefix string) (map[string]string, error) {
	out := map[string]string{}
	err := d.Walk(ctx, prefix, func(fi driver.FileInfo) error {
		if fi.IsDir() {
			return nil
		}
		b, err := d.GetContent(ctx, fi.Path())
		if err != nil {
			return err
		}
		out[fi.Path()] = string(b)
		return nil
	})
	if err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return out, nil
		}
		return nil, err
	}
	return out, nil
}

// liveMigrationRunner reports whether a lock with a fresh heartbeat exists.
func liveMigrationRunner(ctx context.Context, l *migrationLedger) bool {
	var lock migrationLockRecord
	exists, err := l.readJSON(ctx, l.lockPath(), &lock)
	if err != nil || !exists {
		return false
	}
	ttl := time.Duration(lock.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultLockTTL
	}
	return time.Now().UTC().Before(lock.Heartbeat.Add(ttl))
}

func digestDigest(s string) digest.Digest { return digest.Digest(s) }

func demoteLayer(ctx context.Context, l *migrationLedger, name, dg string) error {
	_, err := l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Layers[dg]
		cur.State = stateConflict
		r.Layers[dg] = cur
		return nil
	})
	return err
}

func demoteRevision(ctx context.Context, l *migrationLedger, name, dg string) error {
	_, err := l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Revisions[dg]
		cur.State = stateConflict
		r.Revisions[dg] = cur
		return nil
	})
	return err
}

func demoteTagIndex(ctx context.Context, l *migrationLedger, name, tag, dg string) error {
	_, err := l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Tags[tag]
		cur.Index[dg] = stateConflict
		r.Tags[tag] = cur
		return nil
	})
	return err
}

func promoteSubUnit(ctx context.Context, l *migrationLedger, area, name, dg, tag string) error {
	_, err := l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		set := func(su migrationSubUnit) migrationSubUnit { su.State = stateCompleted; return su }
		switch area {
		case "layer":
			r.Layers[dg] = set(r.Layers[dg])
		case "revision":
			r.Revisions[dg] = set(r.Revisions[dg])
		case "tag-index":
			cur := r.Tags[tag]
			cur.Index[dg] = stateCompleted
			r.Tags[tag] = cur
		case "tag-current":
			cur := r.Tags[tag]
			cur.CurrentState = stateCompleted
			r.Tags[tag] = cur
		}
		return nil
	})
	return err
}

func promoteLayer(ctx context.Context, l *migrationLedger, name, dg string) error {
	return promoteSubUnit(ctx, l, "layer", name, dg, "")
}
func promoteRevision(ctx context.Context, l *migrationLedger, name, dg string) error {
	return promoteSubUnit(ctx, l, "revision", name, dg, "")
}
func promoteTagIndex(ctx context.Context, l *migrationLedger, name, tag, dg string) error {
	return promoteSubUnit(ctx, l, "tag-index", name, dg, tag)
}
func promoteTagCurrent(ctx context.Context, l *migrationLedger, name, tag, dg string) error {
	return promoteSubUnit(ctx, l, "tag-current", name, dg, tag)
}

func demoteTagCurrent(ctx context.Context, l *migrationLedger, name, tag string) error {
	_, err := l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Tags[tag]
		cur.CurrentState = stateConflict
		r.Tags[tag] = cur
		return nil
	})
	return err
}

// ---- cutover ----------------------------------------------------------------

// ErrCutoverBlocked indicates at least one cutover precondition failed.
var ErrCutoverBlocked = errors.New("cutover blocked")

// runCutover performs the final gate and, when it passes, writes the explicit
// switchover marker. It never writes to the source.
func runCutover(ctx context.Context, src, dst driver.StorageDriver, opts VerifyOptions) (*cutoverRecord, error) {
	l := newMigrationLedger(dst, opts.LedgerPrefix)

	// Idempotent: an existing, well-formed marker is returned as-is.
	if existing, exists, err := l.getCutover(ctx); err != nil {
		return nil, err
	} else if exists {
		return existing, nil
	}

	var blockers []string

	// 1. Ledger convergence.
	status, err := buildStatus(ctx, l, nil)
	if err != nil {
		return nil, err
	}
	if !status.Converged {
		blockers = append(blockers, status.Blockers...)
	}

	// 2. Fresh source sweep must match the ledger exactly (zero drift).
	if src != nil {
		snap, err := discover(ctx, src, nil)
		if err != nil {
			return nil, err
		}
		drift, err := ledgerDrift(ctx, l, snap)
		if err != nil {
			return nil, err
		}
		blockers = append(blockers, drift...)
	}

	// 3. Full independent verification.
	rep, err := runVerify(ctx, src, dst, opts)
	if err != nil {
		return nil, err
	}
	if !rep.Passed {
		blockers = append(blockers, rep.Failures...)
	}

	if len(blockers) > 0 {
		sort.Strings(blockers)
		return nil, fmt.Errorf("%w:\n  - %s", ErrCutoverBlocked, strings.Join(blockers, "\n  - "))
	}

	// 4. Write the switchover marker.
	fingerprint := status.SourceFingerprint
	counts := map[string]int64{
		"blobs":              status.TotalBlobs,
		"repositories":       status.TotalRepos,
		"layer_links":        sumStates(status.LayerLinks),
		"revision_links":     sumStates(status.RevisionLinks),
		"tag_current_links":  sumStates(status.TagCurrents),
		"tag_index_links":    sumStates(status.TagIndex),
		"upload_sessions":    sumStates(status.Uploads),
		"quarantine_records": int64(status.QuarantineAll),
	}
	rec := &cutoverRecord{
		RunID: status.RunID, CutoverAt: time.Now().UTC(),
		SourceDriver: status.SourceDriver, SourceFingerprint: fingerprint,
		Counts: counts, TotalBytes: status.BlobBytes[stateCompleted],
		LedgerDigest: ledgerDigest(status),
	}
	if err := l.writeCutover(ctx, rec); err != nil {
		return nil, err
	}
	_, _ = l.updateRun(ctx, func(r *runRecord) { r.Phase = "cutover" })
	return rec, nil
}

// ledgerDrift compares a fresh source snapshot against ledger expectations.
// Every returned string is one drift blocker.
func ledgerDrift(ctx context.Context, l *migrationLedger, snap *migrationDiscovery) ([]string, error) {
	var blockers []string

	repoDocs := map[string]*repoRecord{}
	if err := l.listRepoRecords(ctx, func(r *repoRecord) error {
		repoDocs[r.Name] = r
		return nil
	}); err != nil {
		return nil, err
	}

	for name := range snap.Repos {
		rec, ok := repoDocs[name]
		if !ok {
			blockers = append(blockers, "new repository discovered on source: "+name)
			continue
		}
		if rec.Gone {
			blockers = append(blockers, "repository "+name+" marked gone but present on source")
		}
		dr := snap.Repos[name]
		for dg := range dr.Layers {
			if _, ok := rec.Layers[dg]; !ok {
				blockers = append(blockers, "repo "+name+" new layer: "+dg)
			}
		}
		for dg := range dr.Revisions {
			if _, ok := rec.Revisions[dg]; !ok {
				blockers = append(blockers, "repo "+name+" new revision: "+dg)
			}
		}
		for tag, tu := range dr.Tags {
			lt, ok := rec.Tags[tag]
			if !ok {
				blockers = append(blockers, "repo "+name+" new tag: "+tag)
				continue
			}
			if tu.HasCurrent && lt.Current != tu.Current {
				blockers = append(blockers, fmt.Sprintf("repo %s tag %s current changed: %s -> %s", name, tag, lt.Current, tu.Current))
			}
			for dg := range tu.Index {
				if _, ok := lt.Index[dg]; !ok {
					blockers = append(blockers, "repo "+name+" tag "+tag+" new index entry: "+dg)
				}
			}
			for dg := range lt.Index {
				if !tu.Index[dg] && !lt.IndexGone[dg] {
					blockers = append(blockers, "repo "+name+" tag "+tag+" index entry vanished: "+dg)
				}
			}
		}
		for id := range dr.Uploads {
			if _, ok := rec.Uploads[id]; !ok {
				blockers = append(blockers, "repo "+name+" new upload session: "+id)
			}
		}
		// Reverse direction: deletions on the frozen source are drift too.
		for dg, su := range rec.Layers {
			if _, ok := dr.Layers[dg]; !ok && !su.Gone {
				blockers = append(blockers, "repo "+name+" layer vanished from source: "+dg)
			}
		}
		for dg, su := range rec.Revisions {
			if _, ok := dr.Revisions[dg]; !ok && !su.Gone {
				blockers = append(blockers, "repo "+name+" revision vanished from source: "+dg)
			}
		}
		for id, uu := range rec.Uploads {
			if _, ok := dr.Uploads[id]; !ok && !uu.Gone {
				blockers = append(blockers, "repo "+name+" upload session vanished from source: "+id)
			}
		}
	}
	for name, rec := range repoDocs {
		if _, ok := snap.Repos[name]; !ok && !rec.Gone {
			blockers = append(blockers, "repository vanished from source: "+name)
		}
	}

	if err := l.listBlobRecords(ctx, func(b *blobRecord) error {
		size, ok := snap.BlobSizes[b.Digest]
		if !ok {
			// Blob may be referenced by a repo filtered out? Drift runs full,
			// so any unknown blob means source no longer references it.
			blockers = append(blockers, "blob no longer referenced on source: "+b.Digest)
			return nil
		}
		if size != b.ExpectedSize {
			blockers = append(blockers, fmt.Sprintf("blob %s size changed on source: %d -> %d", b.Digest, b.ExpectedSize, size))
		}
		return nil
	}); err != nil {
		return nil, err
	}

	sort.Strings(blockers)
	return blockers, nil
}

func sumStates(m map[migrationState]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}

// ledgerDigest produces a compact digest over the converged status content.
func ledgerDigest(r *MigrationStatusReport) string {
	h := sha256.New()
	fmt.Fprintf(h, "run=%s fp=%s\n", r.RunID, r.SourceFingerprint)
	writeDigestStates(h, "blob", r.Blobs, r.BlobBytes)
	writeDigestStates(h, "repo", r.Repos, nil)
	writeDigestStates(h, "layer", r.LayerLinks, nil)
	writeDigestStates(h, "revision", r.RevisionLinks, nil)
	writeDigestStates(h, "tag-current", r.TagCurrents, nil)
	writeDigestStates(h, "tag-index", r.TagIndex, nil)
	writeDigestStates(h, "upload", r.Uploads, nil)
	fmt.Fprintf(h, "quarantine=%d temp=%d\n", r.QuarantineAll, r.TempRemaining)
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func writeDigestStates(w io.Writer, kind string, counts, bytes map[migrationState]int64) {
	for _, st := range stateOrder() {
		if n, ok := counts[st]; ok && n > 0 {
			b := int64(0)
			if bytes != nil {
				b = bytes[st]
			}
			fmt.Fprintf(w, "%s=%s:%d:%d\n", kind, st, n, b)
		}
	}
}
