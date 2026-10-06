package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
)

// This file migrates the per-repository namespace once the referenced global
// blobs are available:
//
//   - _layers/<alg>/<hex>/link                 (layer links)
//   - _manifests/revisions/<alg>/<hex>/link    (manifest revision links)
//   - _manifests/tags/<tag>/current/link       (tag pointer)
//   - _manifests/tags/<tag>/index/.../link     (manually retained history)
//   - _uploads/<id>/{data,startedat,hashstates} (interrupted sessions)
//
// Link files are copied byte-for-byte and only after their target blob is
// completed on the destination. Upload sessions are copied as session state
// only: data lands at the _uploads path via a verified-size staging move, but
// nothing is promoted into the blob store and no links are created.

type repoMigrator struct {
	src driver.StorageDriver
	dst driver.StorageDriver
	l   *migrationLedger
	bm  *blobMigrator

	chunkSize int64
	budget    *unitBudget
}

func (m *repoMigrator) takeUnit() bool {
	return m.budget == nil || m.budget.take()
}

func newRepoMigrator(src, dst driver.StorageDriver, l *migrationLedger, bm *blobMigrator) *repoMigrator {
	return &repoMigrator{src: src, dst: dst, l: l, bm: bm, chunkSize: defaultBlobCopyChunkSize}
}

// repoMigrateResult summarizes one repository pass.
type repoMigrateResult struct {
	Repo            string
	Completed       bool
	BudgetExhausted bool
	Blockers        []string
	LinksCopied     int
	SessionsCopied  int
	SessionsSkipped int
}

// migrateRepo drives one repository to completion (or reports blockers).
func (m *repoMigrator) migrateRepo(ctx context.Context, name string) (*repoMigrateResult, error) {
	res := &repoMigrateResult{Repo: name}

	rec, exists, err := m.l.getRepoRecord(ctx, name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("repository %s missing from ledger; run discovery first", name)
	}
	if rec.Gone {
		res.Completed = false
		res.Blockers = append(res.Blockers, "repository disappeared from source (gone)")
		return res, nil
	}

	// ---- layer links ----
	for _, dg := range sortedStringKeys(rec.Layers) {
		su := rec.Layers[dg]
		if su.Gone || su.State == stateCompleted {
			continue
		}
		dgst, perr := digest.Parse(dg)
		if perr != nil {
			if err := m.quarantineLinkUnit(ctx, name, "layer", dg, "invalid digest key: "+perr.Error()); err != nil {
				return nil, err
			}
			continue
		}
		ok, err := m.ensureBlob(ctx, dgst, res)
		if err != nil {
			return nil, err
		}
		if !ok {
			_ = m.quarantineLinkUnit(ctx, name, "layer", dg, "target blob not available (quarantined or conflicting)")
			continue
		}
		if !m.linkBudgetGate(res) {
			return res, nil
		}
		copied, err := m.copyLinkFile(ctx, name,
			layerLinkPathSpec{name: name, digest: dgst},
			layerLinkPathSpec{name: name, digest: dgst})
		if err != nil {
			return nil, err
		}
		if !copied {
			continue // source link vanished; next discovery sweep settles it
		}
		rec, err = m.markLayer(ctx, name, dg)
		if err != nil {
			return nil, err
		}
		res.LinksCopied++
	}

	// ---- manifest revision links ----
	for _, dg := range sortedStringKeys(rec.Revisions) {
		su := rec.Revisions[dg]
		if su.Gone || su.State == stateCompleted {
			continue
		}
		dgst, perr := digest.Parse(dg)
		if perr != nil {
			_ = m.quarantineLinkUnit(ctx, name, "revision", dg, "invalid digest key: "+perr.Error())
			continue
		}
		ok, err := m.ensureBlob(ctx, dgst, res)
		if err != nil {
			return nil, err
		}
		if !ok {
			_ = m.quarantineLinkUnit(ctx, name, "revision", dg, "target blob not available (quarantined or conflicting)")
			continue
		}
		if !m.linkBudgetGate(res) {
			return res, nil
		}
		copied, err := m.copyLinkFile(ctx, name,
			manifestRevisionLinkPathSpec{name: name, revision: dgst},
			manifestRevisionLinkPathSpec{name: name, revision: dgst})
		if err != nil {
			return nil, err
		}
		if !copied {
			continue
		}
		rec, err = m.markRevision(ctx, name, dg)
		if err != nil {
			return nil, err
		}
		res.LinksCopied++
	}

	// ---- tags: index history first, then the current pointer ----
	for _, tag := range sortedStringKeys(rec.Tags) {
		tu := rec.Tags[tag]
		if tu.Gone {
			continue
		}
		for _, dg := range sortedStringKeys(tu.Index) {
			if tu.IndexGone[dg] || tu.Index[dg] == stateCompleted {
				continue
			}
			dgst, perr := digest.Parse(dg)
			if perr != nil {
				_ = m.quarantineLinkUnit(ctx, name, "tag-index:"+tag, dg, "invalid digest key: "+perr.Error())
				continue
			}
			ok, err := m.ensureBlob(ctx, dgst, res)
			if err != nil {
				return nil, err
			}
			if !ok {
				_ = m.quarantineLinkUnit(ctx, name, "tag-index:"+tag, dg, "target blob not available (quarantined or conflicting)")
				continue
			}
			if !m.linkBudgetGate(res) {
				return res, nil
			}
			copied, err := m.copyLinkFile(ctx, name,
				manifestTagIndexEntryLinkPathSpec{name: name, tag: tag, revision: dgst},
				manifestTagIndexEntryLinkPathSpec{name: name, tag: tag, revision: dgst})
			if err != nil {
				return nil, err
			}
			if !copied {
				continue
			}
			rec, err = m.markTagIndex(ctx, name, tag, dg)
			if err != nil {
				return nil, err
			}
			res.LinksCopied++
		}
		if tu.HasCurrent && tu.CurrentState != stateCompleted {
			dgst, perr := digest.Parse(tu.Current)
			if perr != nil {
				_ = m.quarantineLinkUnit(ctx, name, "tag-current:"+tag, tu.Current, "invalid digest key: "+perr.Error())
				continue
			}
			ok, eerr := m.ensureBlob(ctx, dgst, res)
			if eerr != nil {
				return nil, eerr
			}
			if !ok {
				_ = m.quarantineLinkUnit(ctx, name, "tag-current:"+tag, tu.Current, "target blob not available (quarantined or conflicting)")
				continue
			}
			if !m.linkBudgetGate(res) {
				return res, nil
			}
			copied, cerr := m.copyLinkFile(ctx, name,
				manifestTagCurrentPathSpec{name: name, tag: tag},
				manifestTagCurrentPathSpec{name: name, tag: tag})
			if cerr != nil {
				return nil, cerr
			}
			if !copied {
				continue
			}
			rec, cerr = m.markTagCurrent(ctx, name, tag, tu.Current)
			if cerr != nil {
				return nil, cerr
			}
			res.LinksCopied++
		}
	}

	// ---- interrupted upload sessions ----
	for _, id := range sortedStringKeys(rec.Uploads) {
		u := rec.Uploads[id]
		if u.Gone {
			continue
		}
		switch u.State {
		case stateCompleted:
			res.SessionsCopied++
			continue
		case stateSkipped:
			res.SessionsSkipped++
			continue
		case stateQuarantined, stateConflict:
			continue
		default:
		}
		if !m.linkBudgetGate(res) {
			return res, nil
		}
		if err := m.migrateUploadSession(ctx, name, id, &u); err != nil {
			return nil, err
		}
		rec, _, err = m.l.getRepoRecord(ctx, name)
		if err != nil {
			return nil, err
		}
		if rec.Uploads[id].State == stateCompleted {
			res.SessionsCopied++
		}
		if rec.Uploads[id].State == stateSkipped {
			res.SessionsSkipped++
		}
	}

	// Reload the document so the completion predicate sees persisted states.
	rec, _, err = m.l.getRepoRecord(ctx, name)
	if err != nil {
		return nil, err
	}

	// ---- repository completion predicate ----
	done, blockers := evaluateRepoCompletion(rec)
	if !done {
		res.Blockers = append(res.Blockers, blockers...)
		return res, nil
	}
	if _, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		r.State = stateCompleted
		return nil
	}); err != nil {
		return nil, err
	}
	res.Completed = true
	return res, nil
}

// ensureBlob drives the referenced global blob to completion. ok=false means
// the blob is unavailable (quarantined, conflicting). A non-nil error is a
// transient (or budget) failure that must propagate to the runner.
func (m *repoMigrator) ensureBlob(ctx context.Context, dgst digest.Digest, res *repoMigrateResult) (bool, error) {
	// A dangling link has no global blob record (discovery already recorded
	// it): that is an isolation case, not a transient driver failure.
	rec, exists, err := m.l.getBlobRecord(ctx, dgst)
	if err != nil {
		return false, err
	}
	if !exists {
		res.Blockers = append(res.Blockers, "blob "+dgst.String()+": missing (dangling link)")
		return false, nil
	}
	rec, err = m.bm.migrateOne(ctx, dgst)
	if err != nil {
		return false, err
	}
	if rec.State == stateCompleted {
		return true, nil
	}
	res.Blockers = append(res.Blockers, "blob "+dgst.String()+": "+string(rec.State))
	return false, nil
}

// linkBudgetGate consumes one link/session unit from the batch budget. When it
// returns false the run must stop claiming work and exit cleanly.
func (m *repoMigrator) linkBudgetGate(res *repoMigrateResult) bool {
	if !m.takeUnit() {
		res.BudgetExhausted = true
		return false
	}
	return true
}

// copyLinkFile copies one link file verbatim from source to target. A false
// result with nil error means the source link has disappeared since discovery;
// the unit stays pending until the next discovery sweep marks it gone, and it
// must never be reported completed.
func (m *repoMigrator) copyLinkFile(ctx context.Context, repo string, srcSpec, dstSpec pathSpec) (bool, error) {
	srcP, err := pathFor(srcSpec)
	if err != nil {
		return false, err
	}
	dstP, err := pathFor(dstSpec)
	if err != nil {
		return false, err
	}
	b, err := m.src.GetContent(ctx, srcP)
	if err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return false, nil
		}
		return false, fmt.Errorf("read link %s in repo %s: %w", srcP, repo, err)
	}
	if err := m.dst.PutContent(ctx, dstP, b); err != nil {
		return false, fmt.Errorf("write link %s in repo %s: %w", dstP, repo, err)
	}
	return true, nil
}

// migrateUploadSession copies one _uploads session as session state. The data
// is staged with plain-size checkpointing and committed (Move) into the
// uploads path; nothing is promoted to the blob store.
func (m *repoMigrator) migrateUploadSession(ctx context.Context, name, id string, u *migrationUploadUnit) error {
	// Mark in_progress.
	_, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Uploads[id]
		cur.State = stateInProgress
		cur.Attempts++
		r.Uploads[id] = cur
		return nil
	})
	if err != nil {
		return err
	}

	// Small session files first (startedat, hashstates).
	for _, rel := range u.Files {
		if rel == "data" {
			continue
		}
		srcP, dstP, perr := uploadSessionFilePaths(name, id, rel)
		if perr != nil {
			return m.markUploadFault(ctx, name, id, "resolve session file "+rel+": "+perr.Error())
		}
		b, gerr := m.src.GetContent(ctx, srcP)
		if gerr != nil {
			var pnf driver.PathNotFoundError
			if errors.As(gerr, &pnf) {
				continue // source pruned the file meanwhile
			}
			return gerr
		}
		if err := m.dst.PutContent(ctx, dstP, b); err != nil {
			return err
		}
	}

	// Data: resumable staged streaming copy, then Move into the upload path.
	if containsString(u.Files, "data") {
		finalPath, err := pathFor(uploadDataPathSpec{name: name, id: id})
		if err != nil {
			return err
		}
		if err := m.streamUploadData(ctx, name, id, u, finalPath); err != nil {
			return err
		}
	}

	// Resolve isolation before completing; a failure here is retried on the
	// next run (the data move is idempotent).
	if _, err := m.l.resolveQuarantineByKey(ctx, "upload:"+id, "upload session copied"); err != nil {
		return err
	}
	_, err = m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Uploads[id]
		cur.State = stateCompleted
		cur.LastUpdate = time.Now().UTC()
		r.Uploads[id] = cur
		return nil
	})
	return err
}

// streamUploadData stages the upload data with size-only checkpointing and
// verifies the resulting length against discovery before moving it into the
// upload path. It resumes from the ledger checkpoint after a restart.
func (m *repoMigrator) streamUploadData(ctx context.Context, name, id string, u *migrationUploadUnit, finalPath string) error {
	tempPath := u.TempPath
	offset := u.CommittedOffset

	// Resume through driver-native append (enumerates in-progress multipart
	// state on cloud stores; Stat cannot see those until completion).
	if tempPath == "" {
		p, err := m.l.tempUploadDataPath(name, id, uuid.NewString())
		if err != nil {
			return err
		}
		tempPath, offset = p, 0
		if err := m.persistUploadStage(ctx, name, id, tempPath, 0); err != nil {
			return err
		}
	}

	fw, err := m.dst.Writer(ctx, tempPath, offset > 0)
	if err != nil || fw == nil || fw.Size() != offset {
		if fw != nil {
			_ = fw.Cancel(ctx)
		}
		_ = m.removeUploadTemp(ctx, tempPath)
		p, perr := m.l.tempUploadDataPath(name, id, uuid.NewString())
		if perr != nil {
			return perr
		}
		tempPath, offset = p, 0
		if perr := m.persistUploadStage(ctx, name, id, tempPath, 0); perr != nil {
			return perr
		}
		fw, err = m.dst.Writer(ctx, tempPath, false)
		if err != nil {
			return err
		}
	}

	rc, err := m.src.Reader(ctx, finalPath, offset)
	if err != nil {
		_ = fw.Close()
		return m.parkUploadRetry(ctx, name, id, tempPath, offset, err)
	}

	buf := make([]byte, m.chunkSize)
	total := offset
	for {
		nr, er := io.ReadFull(rc, buf)
		if nr > 0 {
			if _, err := fw.Write(buf[:nr]); err != nil {
				_ = rc.Close()
				_ = fw.Close()
				return err
			}
			total += int64(nr)
		}
		switch {
		case er == nil:
			if err := fw.Close(); err != nil {
				_ = rc.Close()
				return err
			}
			if err := m.persistUploadStage(ctx, name, id, tempPath, total); err != nil {
				_ = rc.Close()
				return err
			}
			fw, err = m.dst.Writer(ctx, tempPath, true)
			if err != nil {
				_ = rc.Close()
				return err
			}
			if fw.Size() != total {
				_ = rc.Close()
				_ = fw.Close()
				return fmt.Errorf("upload stage size mismatch: writer=%d expected=%d", fw.Size(), total)
			}
		case er == io.EOF, er == io.ErrUnexpectedEOF:
			_ = rc.Close()
			if err := fw.Commit(ctx); err != nil {
				return err
			}
			if u.DataSize > 0 && total != u.DataSize {
				_ = m.removeUploadTemp(ctx, tempPath)
				return m.markUploadFault(ctx, name, id,
					fmt.Sprintf("upload data size %d does not match discovery %d", total, u.DataSize))
			}
			if err := m.dst.Move(ctx, tempPath, finalPath); err != nil {
				return err
			}
			return m.persistUploadStage(ctx, name, id, "", 0)
		default:
			_ = rc.Close()
			_ = fw.Close()
			// Park the session for retry; the part boundary is checkpointed.
			return m.parkUploadRetry(ctx, name, id, tempPath, total, er)
		}
	}
}

func uploadSessionFilePaths(name, id, rel string) (string, string, error) {
	switch {
	case rel == "startedat":
		p, err := pathFor(uploadStartedAtPathSpec{name: name, id: id})
		return p, p, err
	case len(rel) > len("hashstates/") && rel[:len("hashstates/")] == "hashstates/":
		alg, off, ok := hashstateOffset(rel)
		if !ok {
			return "", "", fmt.Errorf("unparseable hashstate file %q", rel)
		}
		p, err := pathFor(uploadHashStatePathSpec{
			name: name, id: id, alg: digest.Algorithm(alg), offset: off,
		})
		return p, p, err
	default:
		return "", "", fmt.Errorf("unknown session file %q", rel)
	}
}

func (m *repoMigrator) persistUploadStage(ctx context.Context, name, id, tempPath string, offset int64) error {
	_, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Uploads[id]
		cur.TempPath = tempPath
		cur.CommittedOffset = offset
		r.Uploads[id] = cur
		return nil
	})
	return err
}

func (m *repoMigrator) parkUploadRetry(ctx context.Context, name, id, tempPath string, offset int64, cause error) error {
	_, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Uploads[id]
		cur.State = statePending
		cur.TempPath = tempPath
		cur.CommittedOffset = offset
		recordError(&cur.Errors, "upload copy failed: %v", cause)
		r.Uploads[id] = cur
		return nil
	})
	return err
}

func (m *repoMigrator) markUploadFault(ctx context.Context, name, id, reason string) error {
	if _, err := m.l.quarantine(ctx, &quarantineRecord{
		Kind: "upload-corrupt", Repo: name, Key: "upload:" + id, Reason: reason,
	}); err != nil {
		return err
	}
	_, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Uploads[id]
		cur.State = stateQuarantined
		recordError(&cur.Errors, "%s", reason)
		r.Uploads[id] = cur
		return nil
	})
	return err
}

func (m *repoMigrator) removeUploadTemp(ctx context.Context, p string) error {
	if p == "" {
		return nil
	}
	if err := m.dst.Delete(ctx, p); err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil
		}
		return err
	}
	return nil
}

// quarantineLinkUnit records an isolation entry and flips the affected link
// unit to quarantined in the repository ledger document. area is one of
// "layer", "revision", "tag-index:<tag>", "tag-current:<tag>".
func (m *repoMigrator) quarantineLinkUnit(ctx context.Context, repo, area, dg, reason string) error {
	kind := strings.ReplaceAll(area, ":", "-") + "-unavailable"
	if _, err := m.l.quarantine(ctx, &quarantineRecord{
		Kind: kind, Repo: repo, Key: area + ":" + dg,
		ExpectedDigest: dg, Reason: reason,
	}); err != nil {
		return err
	}
	_, err := m.l.mutateRepoRecord(ctx, repo, false, func(r *repoRecord) error {
		switch {
		case area == "layer":
			cur := r.Layers[dg]
			cur.State = stateQuarantined
			recordError(&cur.Errors, "%s", reason)
			r.Layers[dg] = cur
		case area == "revision":
			cur := r.Revisions[dg]
			cur.State = stateQuarantined
			recordError(&cur.Errors, "%s", reason)
			r.Revisions[dg] = cur
		case strings.HasPrefix(area, "tag-index:"):
			tag := strings.TrimPrefix(area, "tag-index:")
			cur := r.Tags[tag]
			cur.Index[dg] = stateQuarantined
			recordError(&cur.Errors, "%s: %s", dg, reason)
			r.Tags[tag] = cur
		case strings.HasPrefix(area, "tag-current:"):
			tag := strings.TrimPrefix(area, "tag-current:")
			cur := r.Tags[tag]
			cur.CurrentState = stateQuarantined
			recordError(&cur.Errors, "%s: %s", dg, reason)
			r.Tags[tag] = cur
		}
		return nil
	})
	return err
}

// ---- sub-state writers ------------------------------------------------------

func (m *repoMigrator) markLayer(ctx context.Context, name, dg string) (*repoRecord, error) {
	rec, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Layers[dg]
		cur.State = stateCompleted
		cur.LastUpdate = time.Now().UTC()
		r.Layers[dg] = cur
		return nil
	})
	if err != nil {
		return nil, err
	}
	_, err = m.l.resolveQuarantineByKey(ctx, "layer:"+dg, "layer link completed")
	return rec, err
}

func (m *repoMigrator) markRevision(ctx context.Context, name, dg string) (*repoRecord, error) {
	rec, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Revisions[dg]
		cur.State = stateCompleted
		cur.LastUpdate = time.Now().UTC()
		r.Revisions[dg] = cur
		return nil
	})
	if err != nil {
		return nil, err
	}
	_, err = m.l.resolveQuarantineByKey(ctx, "revision:"+dg, "revision link completed")
	return rec, err
}

func (m *repoMigrator) markTagIndex(ctx context.Context, name, tag, dg string) (*repoRecord, error) {
	rec, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Tags[tag]
		cur.Index[dg] = stateCompleted
		r.Tags[tag] = cur
		return nil
	})
	if err != nil {
		return nil, err
	}
	_, err = m.l.resolveQuarantineByKey(ctx, "tag-index:"+tag+":"+dg, "tag index link completed")
	return rec, err
}

func (m *repoMigrator) markTagCurrent(ctx context.Context, name, tag, dg string) (*repoRecord, error) {
	rec, err := m.l.mutateRepoRecord(ctx, name, false, func(r *repoRecord) error {
		cur := r.Tags[tag]
		cur.CurrentState = stateCompleted
		r.Tags[tag] = cur
		return nil
	})
	if err != nil {
		return nil, err
	}
	_, err = m.l.resolveQuarantineByKey(ctx, "tag-current:"+tag+":"+dg, "tag current link completed")
	return rec, err
}

// evaluateRepoCompletion decides whether every non-gone unit in a repository
// is settled. Uploads may be completed or explicitly skipped.
func evaluateRepoCompletion(rec *repoRecord) (bool, []string) {
	var blockers []string
	if rec.Gone {
		return false, []string{"repository gone from source"}
	}
	for dg, su := range rec.Layers {
		if su.Gone {
			continue
		}
		if su.State != stateCompleted {
			blockers = append(blockers, "layer "+dg+": "+string(su.State))
		}
	}
	for dg, su := range rec.Revisions {
		if su.Gone {
			continue
		}
		if su.State != stateCompleted {
			blockers = append(blockers, "revision "+dg+": "+string(su.State))
		}
	}
	for tag, tu := range rec.Tags {
		if tu.Gone {
			continue
		}
		if tu.HasCurrent && tu.CurrentState != stateCompleted {
			blockers = append(blockers, "tag "+tag+" current: "+string(tu.CurrentState))
		}
		for dg, st := range tu.Index {
			if tu.IndexGone[dg] {
				continue
			}
			if st != stateCompleted {
				blockers = append(blockers, "tag "+tag+" index "+dg+": "+string(st))
			}
		}
	}
	for id, u := range rec.Uploads {
		if u.Gone {
			continue
		}
		switch u.State {
		case stateCompleted, stateSkipped:
		default:
			blockers = append(blockers, "upload "+id+": "+string(u.State))
		}
	}
	sortStrings(blockers)
	return len(blockers) == 0, blockers
}

func sortedStringKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortStrings(x []string) { sort.Strings(x) }
