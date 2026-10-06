package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/opencontainers/go-digest"
)

// This file implements source discovery: one read-only Walk over the source
// repositories tree classifies every object into the migration inventory
// (layer links, manifest revision links, tag current/index links, interrupted
// upload sessions). After the walk, every referenced digest is resolved once
// against the global blob store; malformed links and dangling references
// become discovery problems. The snapshot feeds ledger upsert, drift
// detection and the source fingerprint.

// quarantine kinds produced by discovery and later phases.
const (
	qKindLinkMalformed    = "link-malformed"
	qKindLinkDangling     = "link-dangling"
	qKindBlobUnreadable   = "blob-unreadable"
	qKindBlobCorrupt      = "blob-corrupt"
	qKindBlobConflict     = "blob-conflict"
	qKindTagTargetMissing = "tag-target-missing"
)

type discoveredTag struct {
	HasCurrent bool
	Current    string          // digest in tags/<tag>/current/link
	Index      map[string]bool // index/.../link digest set (tag history)
}

type discoveredUpload struct {
	// Files are paths relative to repositories/<name>/_uploads/<id>/:
	// "data", "startedat", "hashstates/<alg>/<offset>".
	Files    []string
	DataSize int64
	HasData  bool
}

// discoveredRepo is one repository's inventory.
type discoveredRepo struct {
	Name      string
	Layers    map[string]bool // linked blob digests
	Revisions map[string]bool
	Tags      map[string]*discoveredTag
	Uploads   map[string]*discoveredUpload
}

// discoveryProblem is an un-parseable or unresolvable source reference.
type discoveryProblem struct {
	Kind   string
	Repo   string
	Key    string // digest, tag key or source path
	Target string // raw link target when available
	Reason string
}

// migrationDiscovery is a point-in-time inventory of the source backend.
type migrationDiscovery struct {
	GeneratedAt time.Time

	Repos map[string]*discoveredRepo

	// BlobSizes maps every resolvable linked digest to its source blob size.
	BlobSizes map[string]int64

	Problems []discoveryProblem
}

func newMigrationDiscovery() *migrationDiscovery {
	return &migrationDiscovery{
		GeneratedAt: time.Now().UTC(),
		Repos:       map[string]*discoveredRepo{},
		BlobSizes:   map[string]int64{},
	}
}

func (snap *migrationDiscovery) repo(name string) *discoveredRepo {
	r := snap.Repos[name]
	if r == nil {
		r = &discoveredRepo{
			Name:      name,
			Layers:    map[string]bool{},
			Revisions: map[string]bool{},
			Tags:      map[string]*discoveredTag{},
			Uploads:   map[string]*discoveredUpload{},
		}
		snap.Repos[name] = r
	}
	return r
}

func (r *discoveredRepo) tag(name string) *discoveredTag {
	t := r.Tags[name]
	if t == nil {
		t = &discoveredTag{Index: map[string]bool{}}
		r.Tags[name] = t
	}
	return t
}

func (r *discoveredRepo) upload(id string) *discoveredUpload {
	u := r.Uploads[id]
	if u == nil {
		u = &discoveredUpload{}
		r.Uploads[id] = u
	}
	return u
}

// discover performs the read-only inventory of the source backend. When
// repoFilter is non-empty, only repositories in the set are inventoried.
func discover(ctx context.Context, src driver.StorageDriver, repoFilter map[string]struct{}) (*migrationDiscovery, error) {
	root, err := pathFor(repositoriesRootPathSpec{})
	if err != nil {
		return nil, err
	}
	snap := newMigrationDiscovery()

	walkErr := src.Walk(ctx, root, func(fi driver.FileInfo) error {
		if fi.IsDir() {
			return nil
		}
		segments := strings.Split(strings.TrimPrefix(fi.Path(), root+"/"), "/")

		marker := -1
		for i, s := range segments {
			if s == "_layers" || s == "_manifests" || s == "_uploads" {
				marker = i
				break
			}
		}
		if marker <= 0 {
			return nil
		}
		repoName := strings.Join(segments[:marker], "/")
		if len(repoFilter) > 0 {
			if _, ok := repoFilter[repoName]; !ok {
				return nil
			}
		}
		rest := segments[marker:]
		r := snap.repo(repoName)

		switch {
		case rest[0] == "_layers":
			classifyLayerLink(ctx, src, snap, r, rest, fi.Path())
		case rest[0] == "_manifests":
			classifyManifestEntry(ctx, src, snap, r, rest, fi.Path())
		case rest[0] == "_uploads" && len(rest) >= 3:
			classifyUploadFile(r, rest, fi.Size())
		}
		return nil
	})
	if walkErr != nil {
		var pnf driver.PathNotFoundError
		if !errors.As(walkErr, &pnf) {
			return nil, walkErr
		}
	}

	if err := snap.resolveBlobs(ctx, src); err != nil {
		return nil, err
	}
	return snap, nil
}

// classifyLayerLink handles _layers/<alg>/<hex>/link files.
func classifyLayerLink(ctx context.Context, src driver.StorageDriver, snap *migrationDiscovery, r *discoveredRepo, rest []string, fp string) {
	if len(rest) != 4 || rest[3] != "link" {
		return
	}
	dgst, ok := parseLink(ctx, src, snap, r.Name, fp)
	if !ok {
		return
	}
	r.Layers[dgst] = true
}

// classifyManifestEntry handles revision and tag files under _manifests.
func classifyManifestEntry(ctx context.Context, src driver.StorageDriver, snap *migrationDiscovery, r *discoveredRepo, rest []string, fp string) {
	// rest = ["_manifests", ...]
	if len(rest) < 2 {
		return
	}
	switch rest[1] {
	case "revisions":
		// _manifests/revisions/<alg>/<hex>/link
		if len(rest) == 5 && rest[4] == "link" {
			if dgst, ok := parseLink(ctx, src, snap, r.Name, fp); ok {
				r.Revisions[dgst] = true
			}
		}
	case "tags":
		// _manifests/tags/<tag>/current/link | .../index/<alg>/<hex>/link
		if len(rest) < 3 {
			return
		}
		tagName := rest[2]
		t := r.tag(tagName)
		tail := rest[3:]
		switch {
		case len(tail) == 2 && tail[0] == "current" && tail[1] == "link":
			if dgst, ok := parseLink(ctx, src, snap, r.Name, fp); ok {
				t.HasCurrent = true
				t.Current = dgst
			}
		case len(tail) == 4 && tail[0] == "index" && tail[3] == "link":
			if dgst, ok := parseLink(ctx, src, snap, r.Name, fp); ok {
				t.Index[dgst] = true
			}
		}
	}
}

// parseLink reads and validates one link file, returning the canonical digest
// string. Malformed content is recorded as a discovery problem.
func parseLink(ctx context.Context, src driver.StorageDriver, snap *migrationDiscovery, repo, fp string) (string, bool) {
	b, err := src.GetContent(ctx, fp)
	if err != nil {
		snap.Problems = append(snap.Problems, discoveryProblem{
			Kind: qKindBlobUnreadable, Repo: repo, Key: fp, Reason: err.Error(),
		})
		return "", false
	}
	raw := string(b)
	if _, err := digest.Parse(raw); err != nil {
		snap.Problems = append(snap.Problems, discoveryProblem{
			Kind: qKindLinkMalformed, Repo: repo, Key: fp, Target: raw,
			Reason: fmt.Sprintf("invalid link digest: %v", err),
		})
		return "", false
	}
	return raw, true
}

// classifyUploadFile records one file of an _uploads session.
func classifyUploadFile(r *discoveredRepo, rest []string, size int64) {
	// rest = ["_uploads", <id>, ...]
	id := rest[1]
	u := r.upload(id)
	rel := strings.Join(rest[2:], "/")
	switch {
	case len(rest) == 3 && rest[2] == "data":
		u.HasData = true
		u.DataSize = size
		if !containsString(u.Files, "data") {
			u.Files = append(u.Files, "data")
		}
	case len(rest) == 3 && rest[2] == "startedat":
		if !containsString(u.Files, "startedat") {
			u.Files = append(u.Files, "startedat")
		}
	case len(rest) >= 4 && rest[2] == "hashstates":
		if !containsString(u.Files, rel) {
			u.Files = append(u.Files, rel)
		}
	}
}

// blobRef remembers one repository reference to a global blob so dangling
// targets can be attributed to the right links.
type blobRef struct {
	repo string
	kind string // layer | revision | tag-current | tag-index
	key  string // human-readable reference key
}

// collectRefs gathers every digest reference found in the inventory.
func (snap *migrationDiscovery) collectRefs() map[string][]blobRef {
	refs := map[string][]blobRef{}
	add := func(repo, kind, dg string, key string) {
		refs[dg] = append(refs[dg], blobRef{repo: repo, kind: kind, key: key})
	}
	for name, r := range snap.Repos {
		for dg := range r.Layers {
			add(name, "layer", dg, "layer:"+dg)
		}
		for dg := range r.Revisions {
			add(name, "revision", dg, "revision:"+dg)
		}
		for tag, t := range r.Tags {
			if t.HasCurrent {
				add(name, "tag-current", t.Current, "tag:"+tag+":current")
			}
			for dg := range t.Index {
				add(name, "tag-index", dg, "tag:"+tag+":index")
			}
		}
	}
	return refs
}

// resolveBlobs stats every referenced blob exactly once, populating BlobSizes
// and emitting one dangling/unreadable problem per reference on failure.
func (snap *migrationDiscovery) resolveBlobs(ctx context.Context, src driver.StorageDriver) error {
	refs := snap.collectRefs()
	dgsts := make([]string, 0, len(refs))
	for dg := range refs {
		dgsts = append(dgsts, dg)
	}
	sort.Strings(dgsts)

	for _, raw := range dgsts {
		dgst, err := digest.Parse(raw)
		if err != nil {
			continue // already recorded as malformed
		}
		bp, err := pathFor(blobDataPathSpec{digest: dgst})
		if err != nil {
			return err
		}
		fi, statErr := src.Stat(ctx, bp)
		if statErr != nil {
			snap.problemForRefs(refs[raw], statErr)
			continue
		}
		if fi.IsDir() {
			snap.problemForRefs(refs[raw], errors.New("blob data path is a directory"))
			continue
		}
		snap.BlobSizes[raw] = fi.Size()
	}
	return nil
}

func (snap *migrationDiscovery) problemForRefs(refs []blobRef, cause error) {
	var pnf driver.PathNotFoundError
	missing := errors.As(cause, &pnf) || cause.Error() == "blob data path is a directory"
	for _, ref := range refs {
		kind := qKindLinkDangling
		if strings.HasPrefix(ref.kind, "tag") {
			kind = qKindTagTargetMissing
		}
		if !missing {
			// A genuine stat error (not absence) is attributed once to the
			// blob itself; individual links are not additionally blamed.
			kind = qKindBlobUnreadable
		}
		snap.Problems = append(snap.Problems, discoveryProblem{
			Kind:   kind,
			Repo:   ref.repo,
			Key:    ref.key,
			Target: ref.kind,
			Reason: cause.Error(),
		})
	}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ---- fingerprint -----------------------------------------------------------

// fingerprint hashes the inventory into a stable source fingerprint.
func (snap *migrationDiscovery) fingerprint(sourceDriver string) string {
	h := sha256.New()
	fmt.Fprintf(h, "driver=%s\n", sourceDriver)

	repos := make([]string, 0, len(snap.Repos))
	for name := range snap.Repos {
		repos = append(repos, name)
	}
	sort.Strings(repos)
	for _, name := range repos {
		r := snap.Repos[name]
		fmt.Fprintf(h, "repo=%s\n", name)
		writeLines(h, "layer", sortedKeys(r.Layers))
		writeLines(h, "revision", sortedKeys(r.Revisions))
		tags := make([]string, 0, len(r.Tags))
		for t := range r.Tags {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		for _, t := range tags {
			tg := r.Tags[t]
			fmt.Fprintf(h, "tag=%s current=%s\n", t, tg.Current)
			writeLines(h, "tagindex", sortedKeys(tg.Index))
		}
		uploads := make([]string, 0, len(r.Uploads))
		for u := range r.Uploads {
			uploads = append(uploads, u)
		}
		sort.Strings(uploads)
		for _, u := range uploads {
			ud := r.Uploads[u]
			fmt.Fprintf(h, "upload=%s size=%d files=%d\n", u, ud.DataSize, len(ud.Files))
		}
	}
	digests := make([]string, 0, len(snap.BlobSizes))
	for d := range snap.BlobSizes {
		digests = append(digests, d)
	}
	sort.Strings(digests)
	for _, d := range digests {
		fmt.Fprintf(h, "blob=%s size=%d\n", d, snap.BlobSizes[d])
	}
	fmt.Fprintf(h, "problems=%d\n", len(snap.Problems))
	return sourceDriver + ":" + hex.EncodeToString(h.Sum(nil))[:16]
}

func writeLines(w io.Writer, kind string, xs []string) {
	for _, x := range xs {
		fmt.Fprintf(w, "%s=%s\n", kind, x)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- drift -----------------------------------------------------------------

type repoDrift struct {
	AddedLayers      []string
	RemovedLayers    []string
	AddedRevisions   []string
	RemovedRevisions []string
	AddedTags        []string
	RemovedTags      []string
	ChangedCurrent   []string
	AddedIndex       map[string][]string // tag -> added index digests
	RemovedIndex     map[string][]string
	AddedUploads     []string
	RemovedUploads   []string
}

func (d *repoDrift) empty() bool {
	return len(d.AddedLayers)+len(d.RemovedLayers)+len(d.AddedRevisions)+len(d.RemovedRevisions)+
		len(d.AddedTags)+len(d.RemovedTags)+len(d.ChangedCurrent)+
		len(d.AddedIndex)+len(d.RemovedIndex)+len(d.AddedUploads)+len(d.RemovedUploads) == 0
}

type discoveryDrift struct {
	AddedRepos      []string
	RemovedRepos    []string
	RepoChanges     map[string]*repoDrift
	BlobSizeChanges map[string][2]int64
}

func (d *discoveryDrift) Clean() bool {
	return len(d.AddedRepos)+len(d.RemovedRepos)+len(d.BlobSizeChanges) == 0 && len(d.RepoChanges) == 0
}

// diffDiscovery returns everything that changed between two source snapshots.
func diffDiscovery(before, after *migrationDiscovery) *discoveryDrift {
	d := &discoveryDrift{RepoChanges: map[string]*repoDrift{}, BlobSizeChanges: map[string][2]int64{}}

	for name := range after.Repos {
		if _, ok := before.Repos[name]; !ok {
			d.AddedRepos = append(d.AddedRepos, name)
		}
	}
	for name := range before.Repos {
		if _, ok := after.Repos[name]; !ok {
			d.RemovedRepos = append(d.RemovedRepos, name)
		}
	}
	sort.Strings(d.AddedRepos)
	sort.Strings(d.RemovedRepos)

	for name, b := range before.Repos {
		a, ok := after.Repos[name]
		if !ok {
			continue
		}
		rd := &repoDrift{AddedIndex: map[string][]string{}, RemovedIndex: map[string][]string{}}
		rd.AddedLayers, rd.RemovedLayers = diffSets(b.Layers, a.Layers)
		rd.AddedRevisions, rd.RemovedRevisions = diffSets(b.Revisions, a.Revisions)

		for tag, at := range a.Tags {
			bt, ok := b.Tags[tag]
			if !ok {
				rd.AddedTags = append(rd.AddedTags, tag)
				continue
			}
			if bt.Current != at.Current {
				rd.ChangedCurrent = append(rd.ChangedCurrent, tag)
			}
			added, removed := diffSets(bt.Index, at.Index)
			if len(added) > 0 {
				rd.AddedIndex[tag] = added
			}
			if len(removed) > 0 {
				rd.RemovedIndex[tag] = removed
			}
		}
		for tag := range b.Tags {
			if _, ok := a.Tags[tag]; !ok {
				rd.RemovedTags = append(rd.RemovedTags, tag)
			}
		}
		rd.AddedUploads, rd.RemovedUploads = diffSets(uploadSet(b.Uploads), uploadSet(a.Uploads))

		sortDrift(rd)
		if !rd.empty() {
			d.RepoChanges[name] = rd
		}
	}

	for dgst, size := range after.BlobSizes {
		if old, ok := before.BlobSizes[dgst]; ok && old != size {
			d.BlobSizeChanges[dgst] = [2]int64{old, size}
		}
	}
	return d
}

func sortDrift(rd *repoDrift) {
	for _, x := range []*[]string{
		&rd.AddedLayers, &rd.RemovedLayers, &rd.AddedRevisions, &rd.RemovedRevisions,
		&rd.AddedTags, &rd.RemovedTags, &rd.ChangedCurrent, &rd.AddedUploads, &rd.RemovedUploads,
	} {
		sort.Strings(*x)
	}
	for _, m := range []map[string][]string{rd.AddedIndex, rd.RemovedIndex} {
		for tag := range m {
			sort.Strings(m[tag])
		}
	}
}

// diffSets returns added (in after not before) and removed sets.
func diffSets(before, after map[string]bool) (added, removed []string) {
	for k := range after {
		if !before[k] {
			added = append(added, k)
		}
	}
	for k := range before {
		if !after[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func uploadSet(m map[string]*discoveredUpload) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// hashstateOffset parses the algorithm and numeric offset of a discovered
// hashstate relative path ("hashstates/<alg>/<offset>").
func hashstateOffset(rel string) (string, int64, bool) {
	const prefix = "hashstates/"
	if !strings.HasPrefix(rel, prefix) {
		return "", 0, false
	}
	parts := strings.Split(strings.TrimPrefix(rel, prefix), "/")
	if len(parts) != 2 {
		return "", 0, false
	}
	off, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return parts[0], off, true
}
