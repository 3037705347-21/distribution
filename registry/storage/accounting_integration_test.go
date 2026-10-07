package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/registry/storage/accounting"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func newAccountingRegistry(t *testing.T, drvr *inmemory.Driver, svc *accounting.Service, opts ...RegistryOption) distribution.Namespace {
	t.Helper()
	allOpts := append([]RegistryOption{EnableDelete, AccountingService(svc)}, opts...)
	reg, err := NewRegistry(context.Background(), drvr, allOpts...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

func mustRepo(t *testing.T, reg distribution.Namespace, name string) distribution.Repository {
	t.Helper()
	named, err := reference.WithName(name)
	if err != nil {
		t.Fatalf("WithName: %v", err)
	}
	repo, err := reg.Repository(context.Background(), named)
	if err != nil {
		t.Fatalf("Repository: %v", err)
	}
	return repo
}

// commitBlobUpload runs a full create/write/resume/commit cycle for content.
// If commit fails the upload is cancelled (mirroring the HTTP handler).
func commitBlobUpload(t *testing.T, ctx context.Context, bs distribution.BlobStore, content []byte, cancelOnErr bool) (v1.Descriptor, error) {
	t.Helper()
	wr, err := bs.Create(ctx)
	if err != nil {
		return v1.Descriptor{}, err
	}
	if _, err := io.Copy(wr, bytes.NewReader(content)); err != nil {
		_ = wr.Cancel(ctx)
		return v1.Descriptor{}, err
	}
	if err := wr.Close(); err != nil {
		_ = wr.Cancel(ctx)
		return v1.Descriptor{}, err
	}
	wr2, err := bs.Resume(ctx, wr.ID())
	if err != nil {
		_ = wr.Cancel(ctx)
		return v1.Descriptor{}, err
	}
	desc, err := wr2.Commit(ctx, v1.Descriptor{Digest: digest.FromBytes(content)})
	if err != nil {
		if cancelOnErr {
			_ = wr2.Cancel(ctx)
		}
		return v1.Descriptor{}, err
	}
	return desc, nil
}

func TestAccountingUploadSettleAndIdempotentReupload(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, err := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	reg := newAccountingRegistry(t, drvr, svc)
	repo := mustRepo(t, reg, "team-a/app")
	bs := repo.Blobs(ctx)

	content := bytes.Repeat([]byte("layer-data-"), 10) // 110 bytes
	desc, err := commitBlobUpload(t, ctx, bs, content, true)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if desc.Size != int64(len(content)) {
		t.Fatalf("desc size = %d, want %d", desc.Size, len(content))
	}

	view, err := svc.View(ctx, "team-a/app")
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if view.Settled != int64(len(content)) || view.Reserved != 0 {
		t.Fatalf("view after commit: %+v", view)
	}

	// re-upload the same digest through a brand new session: settled unchanged.
	if _, err := commitBlobUpload(t, ctx, bs, content, true); err != nil {
		t.Fatalf("second commit: %v", err)
	}
	view, _ = svc.View(ctx, "team-a/app")
	if view.Settled != int64(len(content)) || view.Reserved != 0 {
		t.Fatalf("view after re-upload: %+v", view)
	}

	// physical blob exists exactly once in the CAS.
	blobData, err := pathFor(blobDataPathSpec{digest: desc.Digest})
	if err != nil {
		t.Fatalf("pathFor: %v", err)
	}
	if _, err := drvr.Stat(ctx, blobData); err != nil {
		t.Fatalf("blob data missing: %v", err)
	}
}

func TestAccountingMountCountsMountingRepo(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)

	src := mustRepo(t, reg, "team-a/base")
	content := []byte("shared-base-layer")
	desc, err := commitBlobUpload(t, ctx, src.Blobs(ctx), content, true)
	if err != nil {
		t.Fatalf("source commit: %v", err)
	}

	dst := mustRepo(t, reg, "team-b/app")
	canonical, err := reference.WithDigest(src.Named(), desc.Digest)
	if err != nil {
		t.Fatalf("WithDigest: %v", err)
	}
	_, err = dst.Blobs(ctx).Create(ctx, WithMountFrom(canonical))
	var mounted distribution.ErrBlobMounted
	if !errors.As(err, &mounted) {
		t.Fatalf("expected ErrBlobMounted after mount, got %v", err)
	}

	vDst, _ := svc.View(ctx, "team-b/app")
	vSrc, _ := svc.View(ctx, "team-a/base")
	if vDst.Settled != int64(len(content)) {
		t.Fatalf("dst settled = %d, want %d", vDst.Settled, len(content))
	}
	if vSrc.Settled != int64(len(content)) {
		t.Fatalf("src settled changed = %d, want %d", vSrc.Settled, len(content))
	}
	if vDst.Reserved != 0 || vSrc.Reserved != 0 {
		t.Fatal("reservations must be closed after mount settle")
	}

	// repeat mount: no double count.
	if _, err := dst.Blobs(ctx).Create(ctx, WithMountFrom(canonical)); !errors.As(err, &mounted) {
		t.Fatalf("second mount should report ErrBlobMounted, got %v", err)
	}
	vDst, _ = svc.View(ctx, "team-b/app")
	if vDst.Settled != int64(len(content)) {
		t.Fatalf("dst settled after remount = %d", vDst.Settled)
	}
}

func TestAccountingOverBudgetDeniedBeforeRealWrite(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("50", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)
	repo := mustRepo(t, reg, "team-a/app")
	bs := repo.Blobs(ctx)

	content := bytes.Repeat([]byte("x"), 100)
	dgst := digest.FromBytes(content)
	_, err := commitBlobUpload(t, ctx, bs, content, true)
	var qe *accounting.ErrQuotaExceeded
	if !errors.As(err, &qe) {
		t.Fatalf("expected quota error at commit, got %v", err)
	}
	if qe.Requested != 100 || qe.Limit != 50 {
		t.Fatalf("quota detail = %+v", qe)
	}

	// nothing in the global blob store and no layer link.
	blobData, _ := pathFor(blobDataPathSpec{digest: dgst})
	if _, err := drvr.Stat(ctx, blobData); err == nil {
		t.Fatal("blob data must not exist after denied commit")
	}
	linkPath, _ := pathFor(layerLinkPathSpec{name: "team-a/app", digest: dgst})
	if _, err := drvr.Stat(ctx, linkPath); err == nil {
		t.Fatal("layer link must not exist after denied commit")
	}

	view, _ := svc.View(ctx, "team-a/app")
	if view.Reserved != 0 || view.Settled != 0 {
		t.Fatalf("ledger after denial: %+v", view)
	}

	// mount denied by quota must not fall back to an upload session. The
	// source repo gets a generous dedicated rule, while the dst repo keeps
	// the 50-byte default budget.
	srcBudgets, _ := accounting.NewBudgets("", map[string]string{"team-a/base": "1GiB"})
	// share the same backend and ledger root by constructing both services
	// over the same driver but with their own budget tables.
	srcSvc, _ := accounting.NewService(drvr, srcBudgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	srcReg := newAccountingRegistry(t, drvr, srcSvc)
	src := mustRepo(t, srcReg, "team-a/base")
	srcContent := bytes.Repeat([]byte("b"), 100) // larger than dst default budget (50)
	if _, err := commitBlobUpload(t, ctx, src.Blobs(ctx), srcContent, true); err != nil {
		t.Fatalf("source commit: %v", err)
	}
	canonical, _ := reference.WithDigest(src.Named(), digest.FromBytes(srcContent))
	_, err = repo.Blobs(ctx).Create(ctx, WithMountFrom(canonical))
	if !errors.As(err, &qe) {
		t.Fatalf("mount quota denial got %v", err)
	}
	var mounted distribution.ErrBlobMounted
	if errors.As(err, &mounted) {
		t.Fatal("denied mount must not report mounted")
	}
}

func TestAccountingStreamingQuotaGate(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)
	bs := mustRepo(t, reg, "team-a/app").Blobs(ctx)

	wr, err := bs.Create(ctx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = wr.Write(bytes.Repeat([]byte("y"), 100))
	if err == nil {
		_ = wr.Cancel(ctx)
		t.Fatal("expected quota error while streaming")
	}
	var qe *accounting.ErrQuotaExceeded
	if !errors.As(err, &qe) {
		_ = wr.Cancel(ctx)
		t.Fatalf("expected quota error, got %v", err)
	}
	if err := wr.Cancel(ctx); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	view, _ := svc.View(ctx, "team-a/app")
	if view.Reserved != 0 || view.Settled != 0 {
		t.Fatalf("ledger after denied stream: %+v", view)
	}
}

func TestAccountingSmallUploadFitsTightBudget(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)
	bs := mustRepo(t, reg, "team-a/app").Blobs(ctx)

	content := []byte("0123456789") // exactly the budget
	desc, err := commitBlobUpload(t, ctx, bs, content, true)
	if err != nil {
		t.Fatalf("exact-size upload should fit tight budget: %v", err)
	}
	if desc.Size != 10 {
		t.Fatalf("size = %d", desc.Size)
	}
	view, _ := svc.View(ctx, "team-a/app")
	if view.Settled != 10 || view.Reserved != 0 {
		t.Fatalf("view: %+v", view)
	}
}

func TestAccountingCancelReleasesReservation(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)
	bs := mustRepo(t, reg, "team-a/app").Blobs(ctx)

	wr, err := bs.Create(ctx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := wr.Write(make([]byte, 4096)); err != nil {
		t.Fatalf("write: %v", err)
	}
	view, _ := svc.View(ctx, "team-a/app")
	if view.Reserved == 0 {
		t.Fatal("expected grown reservation")
	}
	if err := wr.Cancel(ctx); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	view, _ = svc.View(ctx, "team-a/app")
	if view.Reserved != 0 || view.Settled != 0 {
		t.Fatalf("ledger after cancel: %+v", view)
	}
}

func TestAccountingManifestInlinePut(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)
	repo := mustRepo(t, reg, "team-a/app")

	configContent := []byte(`{"rootfs":{"type":"layers"}}`)
	configDesc, err := repo.Blobs(ctx).Put(ctx, v1.MediaTypeImageConfig, configContent)
	if err != nil {
		t.Fatalf("config put: %v", err)
	}
	layerContent := []byte("gzipped-layer")
	layerDesc, err := repo.Blobs(ctx).Put(ctx, v1.MediaTypeImageLayerGzip, layerContent)
	if err != nil {
		t.Fatalf("layer put: %v", err)
	}

	before, _ := svc.View(ctx, "team-a/app")
	if before.Settled != int64(len(configContent)+len(layerContent)) {
		t.Fatalf("settled after blob puts = %d", before.Settled)
	}

	m := ocischema.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []v1.Descriptor{layerDesc},
	}
	dm, err := ocischema.FromStruct(m)
	if err != nil {
		t.Fatalf("FromStruct: %v", err)
	}
	ms, err := repo.Manifests(ctx)
	if err != nil {
		t.Fatalf("manifests: %v", err)
	}
	_, payload, err := dm.Payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if _, err := ms.Put(ctx, dm); err != nil {
		t.Fatalf("manifest put: %v", err)
	}

	after, _ := svc.View(ctx, "team-a/app")
	if after.Settled != int64(len(configContent)+len(layerContent))+int64(len(payload)) {
		t.Fatalf("settled after manifest = %d, want %d", after.Settled,
			int64(len(configContent)+len(layerContent))+int64(len(payload)))
	}
	if after.Reserved != 0 {
		t.Fatalf("reserved after manifest = %d", after.Reserved)
	}

	// re-put same manifest: no delta.
	if _, err := ms.Put(ctx, dm); err != nil {
		t.Fatalf("second manifest put: %v", err)
	}
	after2, _ := svc.View(ctx, "team-a/app")
	if after2.Settled != after.Settled {
		t.Fatalf("manifest double counted: %d vs %d", after2.Settled, after.Settled)
	}
}
