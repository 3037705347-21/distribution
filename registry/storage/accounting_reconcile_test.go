package storage

import (
	"context"
	"path"
	"testing"
	"time"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/registry/storage/accounting"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// physicalRepo pushes blobs and a manifest through a registry WITHOUT
// accounting, simulating storage that predates ledger enablement.
func physicalRepo(t *testing.T, ctx context.Context, drvr *inmemory.Driver, name string,
	configContent, layerContent []byte,
) int {
	t.Helper()
	reg, err := NewRegistry(ctx, drvr, EnableDelete)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	repo := mustRepo(t, reg, name)
	_, payloadSize := pushManifest(t, ctx, repo, configContent, [][]byte{layerContent})
	return len(configContent) + len(layerContent) + payloadSize
}

func TestAccountingReconcileSeedsAndRepairs(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()

	// 1. physical state exists before accounting is enabled.
	wantA := physicalRepo(t, ctx, drvr, "team-a/app", []byte(`{"seed":1}`), []byte("seed-layer"))
	// shared physical blob via second plain registry mount
	plainReg, _ := NewRegistry(ctx, drvr, EnableDelete)
	aPlain := mustRepo(t, plainReg, "team-a/app")
	bPlain := mustRepo(t, plainReg, "team-b/mnt")
	shared := []byte("seed-layer")
	sharedDGST := digest.FromBytes(shared)
	canonical, _ := reference.WithDigest(aPlain.Named(), sharedDGST)
	_, err := bPlain.Blobs(ctx).Create(ctx, WithMountFrom(canonical))
	_ = err
	mountExists(t, ctx, bPlain, aPlain, sharedDGST)

	// 2. enable accounting over the same backend and reconcile.
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, err := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	reg, err := NewRegistry(ctx, drvr, EnableDelete, AccountingService(svc))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	r := reg.(*registry)
	if err := r.ReconcileAccounting(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	vA, _ := svc.View(ctx, "team-a/app")
	vB, _ := svc.View(ctx, "team-b/mnt")
	if vA.Settled != int64(wantA) {
		t.Fatalf("seeded settled A = %d, want %d", vA.Settled, wantA)
	}
	if vB.Settled != int64(len(shared)) {
		t.Fatalf("seeded settled B = %d, want %d (shared counted per repo)", vB.Settled, len(shared))
	}
	if vA.Reserved != 0 || vB.Reserved != 0 {
		t.Fatal("no reservations expected after reconcile")
	}

	// 3. drift repair: delete a physical layer link directly (lost debit).
	layerLink, err := pathFor(layerLinkPathSpec{name: "team-a/app", digest: sharedDGST})
	if err != nil {
		t.Fatalf("pathFor: %v", err)
	}
	if err := drvr.Delete(ctx, layerLink); err != nil {
		t.Fatalf("delete layer link: %v", err)
	}
	if err := r.ReconcileAccounting(ctx); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	vA2, _ := svc.View(ctx, "team-a/app")
	if vA2.Settled != int64(wantA-len(shared)) {
		t.Fatalf("settled after physical link loss = %d, want %d", vA2.Settled, wantA-len(shared))
	}

	// 4. drift repair: ledger entry with no physical reference is removed.
	ghost := digest.FromBytes([]byte("ghost-ghost"))
	if err := svc.SettleExplicit(ctx, "team-a/app", ghost, accounting.RoleLayer, 99); err != nil {
		t.Fatalf("settle explicit: %v", err)
	}
	if err := r.ReconcileAccounting(ctx); err != nil {
		t.Fatalf("third reconcile: %v", err)
	}
	vA3, _ := svc.View(ctx, "team-a/app")
	if vA3.Settled != vA2.Settled {
		t.Fatalf("ghost entry survived reconciliation: %d", vA3.Settled)
	}

	// 5. repeated reconcile is a no-op (stable).
	if err := r.ReconcileAccounting(ctx); err != nil {
		t.Fatalf("fourth reconcile: %v", err)
	}
	vA4, _ := svc.View(ctx, "team-a/app")
	if vA4.Settled != vA3.Settled {
		t.Fatalf("idempotent reconcile drifted: %d vs %d", vA4.Settled, vA3.Settled)
	}
}

func TestAccountingExpireReservations(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc).(*registry)
	repo := "team-a/app"

	// mount reservation: older than cutoff (1h in the future) -> expired.
	mountRes, err := svc.Reserve(ctx, repo, 100, accounting.KindMount, digest.FromBytes([]byte("m")), accounting.PhaseMount)
	if err != nil {
		t.Fatalf("mount reserve: %v", err)
	}
	// inline reservation also expired by age.
	if _, err := svc.Reserve(ctx, repo, 50, accounting.KindInline, "", accounting.PhaseManifest); err != nil {
		t.Fatalf("inline reserve: %v", err)
	}
	// upload reservation with live _uploads dir -> kept even past cutoff.
	bs := mustRepo(t, reg, repo).Blobs(ctx)
	wr, err := bs.Create(ctx)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	uploadID := wr.ID()
	if _, err := wr.Write(make([]byte, 2048)); err != nil {
		t.Fatalf("write: %v", err)
	}

	cutoff := time.Now().Add(time.Hour)
	if _, err := svc.ExpireReservations(ctx, repo, cutoff, map[string]bool{uploadID: true}); err != nil {
		t.Fatalf("expire with live upload: %v", err)
	}
	view, _ := svc.View(ctx, repo)
	if view.Reserved == 0 {
		t.Fatal("live upload reservation should be kept past cutoff")
	}
	if err := wr.Cancel(ctx); err != nil {
		t.Fatalf("cancel live upload: %v", err)
	}

	// an upload whose _uploads directory vanished (purger/crash) is swept
	// even though the cutoff would otherwise apply.
	wr2, err := bs.Create(ctx)
	if err != nil {
		t.Fatalf("create2: %v", err)
	}
	orphanID := wr2.ID()
	uploadDir, _ := pathFor(uploadStartedAtPathSpec{name: repo, id: orphanID})
	if err := drvr.Delete(ctx, path.Dir(uploadDir)); err != nil {
		t.Fatalf("delete upload dir: %v", err)
	}
	n, err := svc.ExpireReservations(ctx, repo, cutoff, map[string]bool{})
	if err != nil {
		t.Fatalf("expire orphan: %v", err)
	}
	if n == 0 {
		t.Fatal("expected orphaned reservation to be swept")
	}
	view, _ = svc.View(ctx, repo)
	if view.Reserved != 0 {
		t.Fatalf("reserved after sweep = %d", view.Reserved)
	}
	_ = mountRes
}

func TestAccountingRepositoryRemove(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)

	a := mustRepo(t, reg, "team-a/app")
	b := mustRepo(t, reg, "team-b/other")
	content := []byte("repo-remove-blob")
	if _, err := commitBlobUpload(t, ctx, a.Blobs(ctx), content, true); err != nil {
		t.Fatalf("A upload: %v", err)
	}
	mountExists(t, ctx, b, a, digest.FromBytes(content))

	remover := reg.(distribution.RepositoryRemover)
	if err := remover.Remove(ctx, a.Named()); err != nil {
		t.Fatalf("remove: %v", err)
	}

	vA, _ := svc.View(ctx, "team-a/app")
	if vA.Settled != 0 || vA.Reserved != 0 {
		t.Fatalf("A ledger after remove: %+v", vA)
	}
	if _, err := drvr.Stat(ctx, "/docker/registry/v2/accounting/repositories/team-a/app"); err == nil {
		t.Fatal("accounting directory still present after repository remove")
	}
	vB, _ := svc.View(ctx, "team-b/other")
	if vB.Settled != int64(len(content)) {
		t.Fatalf("B ledger affected by A removal: %d", vB.Settled)
	}
}
