package storage

import (
	"context"
	"testing"

	"github.com/opencontainers/go-digest"

	"github.com/distribution/distribution/v3/registry/storage/accounting"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
)

func TestAccountingGCDebitsAndDryRun(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, _ := accounting.NewBudgets("10GiB", nil)
	svc, _ := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	reg := newAccountingRegistry(t, drvr, svc)

	a := mustRepo(t, reg, "team-a/app")
	b := mustRepo(t, reg, "team-b/other")

	// tagged image (kept by GC)
	keepConfig := []byte(`{"keep":true}`)
	keepLayer := []byte("keep-layer-data")
	keepDesc, keepPayload := pushManifest(t, ctx, a, keepConfig, [][]byte{keepLayer})
	if err := a.Tags(ctx).Tag(ctx, "keep", keepDesc); err != nil {
		t.Fatalf("tag keep: %v", err)
	}

	// untagged image (eligible for --delete-untagged)
	delConfig := []byte(`{"del":true}`)
	delLayer := []byte("untagged-layer-data")
	delDesc, _ := pushManifest(t, ctx, a, delConfig, [][]byte{delLayer})
	delLayerDGST := digest.FromBytes(delLayer)
	delConfigDGST := digest.FromBytes(delConfig)

	// B mounts the untagged layer. B has no manifests directory, so GC leaves
	// its link in place (pre-existing GC behavior): its ledger must remain
	// untouched.
	mountExists(t, ctx, b, a, delLayerDGST)

	baselineA, _ := svc.View(ctx, "team-a/app")
	baselineB, _ := svc.View(ctx, "team-b/other")

	// Dry run changes neither storage nor the ledger.
	if err := MarkAndSweep(ctx, drvr, reg, GCOpts{
		DryRun:         true,
		RemoveUntagged: true,
		Quiet:          true,
		Accounting:     svc,
	}); err != nil {
		t.Fatalf("dry run gc: %v", err)
	}
	if !linkExists(t, ctx, drvr, "team-a/app", delDesc.Digest, false) {
		t.Fatal("dry run removed untagged revision link")
	}
	vA, _ := svc.View(ctx, "team-a/app")
	vB, _ := svc.View(ctx, "team-b/other")
	if vA.Settled != baselineA.Settled || vB.Settled != baselineB.Settled {
		t.Fatalf("dry run changed ledger: A %d->%d B %d->%d",
			baselineA.Settled, vA.Settled, baselineB.Settled, vB.Settled)
	}

	// Real run.
	if err := MarkAndSweep(ctx, drvr, reg, GCOpts{
		DryRun:         false,
		RemoveUntagged: true,
		Quiet:          true,
		Accounting:     svc,
	}); err != nil {
		t.Fatalf("gc: %v", err)
	}

	// A keeps exactly the tagged image closure; untagged revision + its
	// exclusive config/layer links are gone and debited.
	wantA := int64(len(keepConfig)+len(keepLayer)) + int64(keepPayload)
	vA, _ = svc.View(ctx, "team-a/app")
	if vA.Settled != wantA {
		t.Fatalf("A settled after GC = %d, want %d", vA.Settled, wantA)
	}
	if linkExists(t, ctx, drvr, "team-a/app", delDesc.Digest, false) {
		t.Error("untagged revision link still present after GC")
	}
	if linkExists(t, ctx, drvr, "team-a/app", delLayerDGST, true) {
		t.Error("untagged layer link still present after GC")
	}
	if linkExists(t, ctx, drvr, "team-a/app", delConfigDGST, true) {
		t.Error("untagged config link still present after GC")
	}
	if !linkExists(t, ctx, drvr, "team-a/app", keepDesc.Digest, false) {
		t.Error("tagged revision removed by GC")
	}
	if !linkExists(t, ctx, drvr, "team-a/app", digest.FromBytes(keepLayer), true) {
		t.Error("tagged layer removed by GC")
	}

	// B is repo-isolated: GC over A does not debit B (B has no manifest root
	// for link enumeration).
	vB, _ = svc.View(ctx, "team-b/other")
	if vB.Settled != int64(len(delLayer)) {
		t.Fatalf("B settled changed = %d, want %d", vB.Settled, len(delLayer))
	}
	if !linkExists(t, ctx, drvr, "team-b/other", delLayerDGST, true) {
		t.Error("B mount link should remain (no manifests in B to sweep)")
	}

	// Idempotent second run.
	if err := MarkAndSweep(ctx, drvr, reg, GCOpts{
		DryRun:         false,
		RemoveUntagged: true,
		Quiet:          true,
		Accounting:     svc,
	}); err != nil {
		t.Fatalf("second gc: %v", err)
	}
	vA2, _ := svc.View(ctx, "team-a/app")
	if vA2.Settled != wantA {
		t.Fatalf("ledger drifted on second GC: %d vs %d", vA2.Settled, wantA)
	}
}
