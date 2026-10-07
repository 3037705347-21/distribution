package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/registry/storage/accounting"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// putBlob is a small-blob Put helper returning the descriptor.
func putBlob(t *testing.T, ctx context.Context, repo distribution.Repository, mediaType string, content []byte) v1.Descriptor {
	t.Helper()
	desc, err := repo.Blobs(ctx).Put(ctx, mediaType, content)
	if err != nil {
		t.Fatalf("put blob: %v", err)
	}
	return desc
}

// pushManifest uploads config/layer blobs and an OCI image manifest
// referencing them. Returns the manifest descriptor and payload size.
func pushManifest(t *testing.T, ctx context.Context, repo distribution.Repository,
	configContent []byte, layerContents [][]byte, options ...distribution.ManifestServiceOption,
) (v1.Descriptor, int) {
	t.Helper()
	configDesc := putBlob(t, ctx, repo, v1.MediaTypeImageConfig, configContent)
	layers := make([]v1.Descriptor, 0, len(layerContents))
	for _, lc := range layerContents {
		layers = append(layers, putBlob(t, ctx, repo, v1.MediaTypeImageLayerGzip, lc))
	}
	m := ocischema.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    layers,
	}
	dm, err := ocischema.FromStruct(m)
	if err != nil {
		t.Fatalf("from struct: %v", err)
	}
	ms, err := repo.Manifests(ctx)
	if err != nil {
		t.Fatalf("manifests: %v", err)
	}
	dgst, err := ms.Put(ctx, dm, options...)
	if err != nil {
		t.Fatalf("manifest put: %v", err)
	}
	_, payload, err := dm.Payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	return v1.Descriptor{Digest: dgst, Size: int64(len(payload)), MediaType: v1.MediaTypeImageManifest}, len(payload)
}

func linkExists(t *testing.T, ctx context.Context, drvr driver.StorageDriver, repoName string, dgst digest.Digest, layer bool) bool {
	t.Helper()
	var p string
	var err error
	if layer {
		p, err = pathFor(layerLinkPathSpec{name: repoName, digest: dgst})
	} else {
		p, err = pathFor(manifestRevisionLinkPathSpec{name: repoName, revision: dgst})
	}
	if err != nil {
		t.Fatalf("pathFor: %v", err)
	}
	_, err = drvr.Stat(ctx, p)
	return err == nil
}

func blobDataExists(t *testing.T, ctx context.Context, drvr driver.StorageDriver, dgst digest.Digest) bool {
	t.Helper()
	p, err := pathFor(blobDataPathSpec{digest: dgst})
	if err != nil {
		t.Fatalf("pathFor: %v", err)
	}
	_, err = drvr.Stat(ctx, p)
	return err == nil
}

func mountExists(t *testing.T, ctx context.Context, target, source distribution.Repository, dgst digest.Digest) {
	t.Helper()
	canonical, err := reference.WithDigest(source.Named(), dgst)
	if err != nil {
		t.Fatalf("WithDigest: %v", err)
	}
	_, err = target.Blobs(ctx).Create(ctx, WithMountFrom(canonical))
	var mounted distribution.ErrBlobMounted
	if !errors.As(err, &mounted) {
		t.Fatalf("expected ErrBlobMounted, got %v", err)
	}
}

func TestAccountingDeleteManifestReleasesExclusive(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)

	a := mustRepo(t, reg, "team-a/app")
	b := mustRepo(t, reg, "team-b/other")

	c1 := []byte(`{"config":1}`)
	l1 := []byte("layer-one-data")
	shared := []byte("shared-layer-data")
	c2 := []byte(`{"config":2}`)

	r1, _ := pushManifest(t, ctx, a, c1, [][]byte{l1, shared})
	r2, r2Payload := pushManifest(t, ctx, a, c2, [][]byte{shared})

	// B mounts the shared blob.
	sharedDGST := digest.FromBytes(shared)
	mountExists(t, ctx, b, a, sharedDGST)

	viewBefore, _ := svc.View(ctx, "team-a/app")
	if viewBefore.Settled <= 0 {
		t.Fatalf("no settled usage before delete: %+v", viewBefore)
	}

	ms, _ := a.Manifests(ctx)
	if err := ms.Delete(ctx, r1.Digest); err != nil {
		t.Fatalf("delete revision: %v", err)
	}

	// exclusive links of R1 gone; shared/remaining stay.
	if linkExists(t, ctx, drvr, "team-a/app", digest.FromBytes(l1), true) {
		t.Error("exclusive layer link still present after revision delete")
	}
	if linkExists(t, ctx, drvr, "team-a/app", digest.FromBytes(c1), true) {
		t.Error("exclusive config link still present after revision delete")
	}
	if !linkExists(t, ctx, drvr, "team-a/app", sharedDGST, true) {
		t.Error("shared layer link removed although R2 references it")
	}
	if !linkExists(t, ctx, drvr, "team-a/app", digest.FromBytes(c2), true) {
		t.Error("R2 config link removed unexpectedly")
	}
	if linkExists(t, ctx, drvr, "team-a/app", r1.Digest, false) {
		t.Error("deleted revision link still present")
	}
	if !linkExists(t, ctx, drvr, "team-a/app", r2.Digest, false) {
		t.Error("remaining revision link removed")
	}

	// ledger: c2 + shared blob sizes and R2 payload remain (digests unique).
	viewAfter, _ := svc.View(ctx, "team-a/app")
	want := int64(len(c2)+len(shared)) + int64(r2Payload)
	if viewAfter.Settled != want {
		t.Fatalf("settled after delete = %d, want %d", viewAfter.Settled, want)
	}

	// physical blob data is untouched (GC owns physical deletion).
	for _, content := range [][]byte{c1, l1} {
		if !blobDataExists(t, ctx, drvr, digest.FromBytes(content)) {
			t.Errorf("physical blob removed prematurely for %s", content)
		}
	}

	// B ledger untouched.
	vB, _ := svc.View(ctx, "team-b/other")
	if vB.Settled != int64(len(shared)) {
		t.Fatalf("mounting repo settled changed: %d", vB.Settled)
	}
}

func TestAccountingUntagReleaseToggle(t *testing.T) {
	cases := []struct {
		name           string
		releaseOnUntag bool
	}{
		{"released", true},
		{"kept", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			drvr := inmemory.New()
			budgets, _ := accounting.NewBudgets("10GiB", nil)
			svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: tc.releaseOnUntag})
			reg := newAccountingRegistry(t, drvr, svc)
			repo := mustRepo(t, reg, "team-a/app")

			config := []byte(`{"cfg":"x"}`)
			layer := []byte("untag-layer")
			desc, _ := pushManifest(t, ctx, repo, config, [][]byte{layer})
			if err := repo.Tags(ctx).Tag(ctx, "v1", desc); err != nil {
				t.Fatalf("tag: %v", err)
			}

			before, _ := svc.View(ctx, "team-a/app")
			if err := repo.Tags(ctx).Untag(ctx, "v1"); err != nil {
				t.Fatalf("untag: %v", err)
			}
			after, _ := svc.View(ctx, "team-a/app")

			if tc.releaseOnUntag {
				if after.Settled != 0 {
					t.Fatalf("settled after untag = %d, want 0", after.Settled)
				}
				if linkExists(t, ctx, drvr, "team-a/app", desc.Digest, false) {
					t.Error("revision link still present after untag")
				}
				if linkExists(t, ctx, drvr, "team-a/app", digest.FromBytes(layer), true) {
					t.Error("layer link still present after untag")
				}
			} else {
				if after.Settled != before.Settled {
					t.Fatalf("settled changed with release disabled: %d -> %d", before.Settled, after.Settled)
				}
				if !linkExists(t, ctx, drvr, "team-a/app", desc.Digest, false) {
					t.Error("revision link removed with release disabled")
				}
				ms, _ := repo.Manifests(ctx)
				if _, err := ms.Get(ctx, desc.Digest); err != nil {
					t.Fatalf("revision get after untag: %v", err)
				}
			}
		})
	}
}

func TestAccountingBlobDeleteRepoIsolation(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)
	a := mustRepo(t, reg, "team-a/app")
	b := mustRepo(t, reg, "team-b/other")

	content := []byte("cross-repo-blob")
	dgst := digest.FromBytes(content)
	if _, err := commitBlobUpload(t, ctx, a.Blobs(ctx), content, true); err != nil {
		t.Fatalf("A upload: %v", err)
	}
	mountExists(t, ctx, b, a, dgst)

	if err := a.Blobs(ctx).Delete(ctx, dgst); err != nil {
		t.Fatalf("A delete: %v", err)
	}
	vA, _ := svc.View(ctx, "team-a/app")
	vB, _ := svc.View(ctx, "team-b/other")
	if vA.Settled != 0 {
		t.Fatalf("A settled after delete = %d", vA.Settled)
	}
	if vB.Settled != int64(len(content)) {
		t.Fatalf("B settled changed = %d, want %d", vB.Settled, len(content))
	}

	// repeated delete: link already gone (ErrBlobUnknown), no negative drift.
	if err := a.Blobs(ctx).Delete(ctx, dgst); !errors.Is(err, distribution.ErrBlobUnknown) {
		t.Fatalf("second delete expected ErrBlobUnknown, got %v", err)
	}
	vA2, _ := svc.View(ctx, "team-a/app")
	if vA2.Settled != 0 {
		t.Fatalf("duplicate delete drifted ledger: %d", vA2.Settled)
	}
}

func TestAccountingIndexRecursiveReclaim(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)
	repo := mustRepo(t, reg, "team-a/indexed")

	// child image manifest
	childDesc, _ := pushManifest(t, ctx, repo, []byte(`{"cfg":"child"}`), [][]byte{[]byte("child-layer")})

	// image index referencing it, tagged
	index, err := ocischema.FromDescriptors([]v1.Descriptor{{
		Digest:    childDesc.Digest,
		MediaType: v1.MediaTypeImageManifest,
		Size:      childDesc.Size,
	}}, nil)
	if err != nil {
		t.Fatalf("from descriptors: %v", err)
	}
	ms, _ := repo.Manifests(ctx)
	indexDGST, err := ms.Put(ctx, index)
	if err != nil {
		t.Fatalf("index put: %v", err)
	}
	indexDesc := v1.Descriptor{Digest: indexDGST, MediaType: v1.MediaTypeImageIndex}
	if err := repo.Tags(ctx).Tag(ctx, "idx", indexDesc); err != nil {
		t.Fatalf("tag index: %v", err)
	}

	if err := repo.Tags(ctx).Untag(ctx, "idx"); err != nil {
		t.Fatalf("untag: %v", err)
	}

	if linkExists(t, ctx, drvr, "team-a/indexed", indexDGST, false) {
		t.Error("index revision link still present")
	}
	if linkExists(t, ctx, drvr, "team-a/indexed", childDesc.Digest, false) {
		t.Error("child revision link still present")
	}
	if linkExists(t, ctx, drvr, "team-a/indexed", digest.FromBytes([]byte("child-layer")), true) {
		t.Error("child layer link still present")
	}
	v, _ := svc.View(ctx, "team-a/indexed")
	if v.Settled != 0 {
		t.Fatalf("settled after index untag = %d, want 0", v.Settled)
	}
	if !blobDataExists(t, ctx, drvr, digest.FromBytes([]byte("child-layer"))) {
		t.Error("physical child layer blob removed prematurely")
	}
}
