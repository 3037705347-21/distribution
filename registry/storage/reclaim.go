package storage

import (
	"context"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/opencontainers/go-digest"
)

// closureSet is the transitive reference closure of a set of manifest
// revisions: the revisions themselves and every blob digest they reference
// (config/layers and image index child manifests, recursively).
type closureSet struct {
	revisions map[digest.Digest]struct{}
	blobs     map[digest.Digest]struct{}
}

func newClosureSet() *closureSet {
	return &closureSet{
		revisions: map[digest.Digest]struct{}{},
		blobs:     map[digest.Digest]struct{}{},
	}
}

// walkClosure resolves the transitive reference closure of root revisions
// through the manifest service (the same content-type agnostic entry point
// used by offline GC marking). References that resolve as revisions are
// walked recursively; all other references are recorded as blobs.
func (ms *manifestStore) walkClosure(ctx context.Context, roots []digest.Digest) (*closureSet, error) {
	set := newClosureSet()
	pending := append([]digest.Digest(nil), roots...)
	for len(pending) > 0 {
		d := pending[0]
		pending = pending[1:]
		if _, ok := set.revisions[d]; ok {
			continue
		}
		m, err := ms.Get(ctx, d)
		if err != nil {
			// revision unreadable/no longer present: skip it.
			continue
		}
		set.revisions[d] = struct{}{}
		for _, ref := range m.References() {
			if _, seen := set.blobs[ref.Digest]; seen {
				continue
			}
			if _, seen := set.revisions[ref.Digest]; seen {
				continue
			}
			// A reference that itself resolves as a revision is an image
			// index child manifest; everything else is a referenced blob.
			if ok, _ := ms.Exists(ctx, ref.Digest); ok {
				pending = append(pending, ref.Digest)
			} else {
				set.blobs[ref.Digest] = struct{}{}
			}
		}
	}
	return set, nil
}

// enumerateRevisions lists every manifest revision currently linked in the
// repository.
func (ms *manifestStore) enumerateRevisions(ctx context.Context) ([]digest.Digest, error) {
	var roots []digest.Digest
	err := ms.blobStore.Enumerate(ctx, func(dgst digest.Digest) error {
		roots = append(roots, dgst)
		return nil
	})
	return roots, err
}

// cleanupExclusive removes revision links and layer links present in the
// removed closure but absent from the kept closure, debiting the ledger for
// every removed natural key. Physical blob data is never deleted here; the
// offline GC owns that. Missing links are treated as already removed.
func (ms *manifestStore) cleanupExclusive(ctx context.Context, removed, kept *closureSet) {
	layerStore := ms.repository.Blobs(ctx)

	for d := range removed.blobs {
		if _, ok := kept.blobs[d]; ok {
			continue
		}
		if err := layerStore.Delete(ctx, d); err != nil && err != distribution.ErrBlobUnknown {
			dcontext.GetLogger(ctx).WithError(err).WithField("digest", d).
				Warn("accounting: failed to remove unreferenced layer link")
		}
	}

	for d := range removed.revisions {
		if _, ok := kept.revisions[d]; ok {
			continue
		}
		if err := ms.blobStore.Delete(ctx, d); err != nil && err != distribution.ErrBlobUnknown {
			dcontext.GetLogger(ctx).WithError(err).WithField("digest", d).
				Warn("accounting: failed to remove unreachable manifest revision")
		}
	}
}

// reclaimDeletedManifest computes the closure of the manifest about to be
// deleted while its revision is still readable. Returns nil when accounting
// is disabled.
func (ms *manifestStore) reclaimDeletedManifest(ctx context.Context, dgst digest.Digest) *closureSet {
	if ms.repository.ledger() == nil {
		return nil
	}
	set, err := ms.walkClosure(ctx, []digest.Digest{dgst})
	if err != nil {
		dcontext.GetLogger(ctx).WithError(err).Warn("accounting: closure walk before manifest delete failed")
		return nil
	}
	return set
}

// postDeleteReclaim reclaims revisions/blobs exclusive to a removed closure.
func (ms *manifestStore) postDeleteReclaim(ctx context.Context, removed *closureSet) {
	if removed == nil || ms.repository.ledger() == nil {
		return
	}
	roots, err := ms.enumerateRevisions(ctx)
	if err != nil {
		dcontext.GetLogger(ctx).WithError(err).Warn("accounting: cannot enumerate revisions for reclaim")
		return
	}
	kept, err := ms.walkClosure(ctx, roots)
	if err != nil {
		dcontext.GetLogger(ctx).WithError(err).Warn("accounting: cannot walk remaining revisions for reclaim")
		return
	}
	ms.cleanupExclusive(ctx, removed, kept)
}

// reclaimAfterUntag removes manifest revisions no longer reachable from any
// tag together with their exclusive blob links, debiting the ledger. Used
// when release_on_untag is enabled.
func (repo *repository) reclaimAfterUntag(ctx context.Context) error {
	if repo.ledger() == nil {
		return nil
	}

	ms, err := repo.Manifests(ctx)
	if err != nil {
		return err
	}
	mms, ok := ms.(*manifestStore)
	if !ok {
		return nil
	}

	tagService := repo.Tags(ctx)
	allTags, err := tagService.All(ctx)
	if err != nil {
		return err
	}
	taggedRoots := make([]digest.Digest, 0, len(allTags))
	for _, t := range allTags {
		desc, err := tagService.Get(ctx, t)
		if err != nil {
			// a tag that cannot be resolved contributes no root
			continue
		}
		taggedRoots = append(taggedRoots, desc.Digest)
	}
	taggedClosure, err := mms.walkClosure(ctx, taggedRoots)
	if err != nil {
		return err
	}

	allRoots, err := mms.enumerateRevisions(ctx)
	if err != nil {
		return err
	}
	var orphanRoots []digest.Digest
	for _, r := range allRoots {
		if _, reachable := taggedClosure.revisions[r]; !reachable {
			orphanRoots = append(orphanRoots, r)
		}
	}
	if len(orphanRoots) == 0 {
		return nil
	}
	orphanClosure, err := mms.walkClosure(ctx, orphanRoots)
	if err != nil {
		return err
	}
	mms.cleanupExclusive(ctx, orphanClosure, taggedClosure)
	return nil
}
