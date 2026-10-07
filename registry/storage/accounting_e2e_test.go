package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/registry/storage/accounting"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// TestAccountingEndToEndScenario walks the complete lifecycle: push -> mount
// -> over-budget denials -> tagged manifest -> untag release -> process
// restart replay -> repository removal, asserting balances at every stage.
func TestAccountingEndToEndScenario(t *testing.T) {
	ctx := context.Background()
	drvr := inmemory.New()
	budgets, err := accounting.NewBudgets("1MiB", map[string]string{"team-a/base": "1GiB"})
	if err != nil {
		t.Fatalf("budgets: %v", err)
	}
	svc, err := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	reg := newAccountingRegistry(t, drvr, svc)

	base := mustRepo(t, reg, "team-a/base")
	app := mustRepo(t, reg, "team-b/app")

	// 1. push a small layer and a tagged manifest to A
	small := bytes.Repeat([]byte("a"), 100)
	smallDGST := digest.FromBytes(small)
	desc, payloadSize := pushManifest(t, ctx, base, []byte(`{"e2e":1}`), [][]byte{small})
	if err := base.Tags(ctx).Tag(ctx, "v1", desc); err != nil {
		t.Fatalf("tag: %v", err)
	}
	wantBase := int64(100+len(`{"e2e":1}`)) + int64(payloadSize)
	v, _ := svc.View(ctx, "team-a/base")
	if v.Settled != wantBase || v.Reserved != 0 {
		t.Fatalf("phase1 A: %+v want settled %d", v, wantBase)
	}

	// 2. B mounts the small layer
	mountExists(t, ctx, app, base, smallDGST)
	v, _ = svc.View(ctx, "team-b/app")
	if v.Settled != 100 {
		t.Fatalf("phase2 B settled = %d, want 100", v.Settled)
	}

	// 3. push a 2MiB blob to A (fits its dedicated rule)
	big := bytes.Repeat([]byte("b"), 2*1024*1024)
	bigDGST := digest.FromBytes(big)
	if _, err := commitBlobUpload(t, ctx, base.Blobs(ctx), big, true); err != nil {
		t.Fatalf("big upload to A: %v", err)
	}

	// 4. B cannot upload 2MiB (default budget 1MiB, already holding 100 bytes)
	wr, err := app.Blobs(ctx).Create(ctx)
	if err != nil {
		t.Fatalf("B create: %v", err)
	}
	if _, err := wr.Write(big); err == nil {
		t.Fatal("expected over-budget write failure")
	} else {
		var qe *accounting.ErrQuotaExceeded
		if !errors.As(err, &qe) {
			t.Fatalf("expected quota error, got %v", err)
		}
	}
	if err := wr.Cancel(ctx); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	v, _ = svc.View(ctx, "team-b/app")
	if v.Settled != 100 || v.Reserved != 0 {
		t.Fatalf("phase4 B after denied upload: %+v", v)
	}

	// 5. B cannot mount the 2MiB blob either, and no upload session starts
	canonical, _ := reference.WithDigest(base.Named(), bigDGST)
	_, err = app.Blobs(ctx).Create(ctx, WithMountFrom(canonical))
	var qe *accounting.ErrQuotaExceeded
	if !errors.As(err, &qe) {
		t.Fatalf("phase5 mount: expected quota error, got %v", err)
	}
	if _, ok := err.(distribution.ErrBlobMounted); ok {
		t.Fatal("denied mount reported mounted")
	}
	v, _ = svc.View(ctx, "team-b/app")
	if v.Settled != 100 || v.Reserved != 0 {
		t.Fatalf("phase5 B after denied mount: %+v", v)
	}

	// 6. untag v1 on A releases the tagged manifest closure immediately
	// (config, small layer, revision). The staged 2MiB layer not referenced
	// by any manifest is left for offline GC, exactly like GC semantics.
	if err := base.Tags(ctx).Untag(ctx, "v1"); err != nil {
		t.Fatalf("untag: %v", err)
	}
	v, _ = svc.View(ctx, "team-a/base")
	if v.Settled != int64(len(big)) {
		t.Fatalf("phase6 A after untag = %d, want only staged blob %d", v.Settled, len(big))
	}
	v, _ = svc.View(ctx, "team-b/app")
	if v.Settled != 100 {
		t.Fatalf("phase6 B changed: %d, want 100", v.Settled)
	}
	if !blobDataExistsBytes(t, ctx, drvr, small) {
		t.Fatal("physical blob of B mount must survive A untag")
	}

	// 7. restart: a fresh service/registry over the same backend replays the
	// event log and reports identical balances.
	svc2, err := accounting.NewService(drvr, budgets, accounting.RuntimeConfig{ReleaseOnUntag: true})
	if err != nil {
		t.Fatalf("service2: %v", err)
	}
	reg2, err := NewRegistry(ctx, drvr, EnableDelete, AccountingService(svc2))
	if err != nil {
		t.Fatalf("registry2: %v", err)
	}
	v2A, _ := svc2.View(ctx, "team-a/base")
	v2B, _ := svc2.View(ctx, "team-b/app")
	if v2A.Settled != int64(len(big)) || v2B.Settled != 100 {
		t.Fatalf("after restart balances differ: A=%d B=%d", v2A.Settled, v2B.Settled)
	}

	// 8. removing B drops its ledger and metrics, leaves A untouched.
	if err := reg2.(*registry).Remove(ctx, app.Named()); err != nil {
		t.Fatalf("remove B: %v", err)
	}
	if _, err := svc2.View(ctx, "team-b/app"); err != nil {
		t.Fatalf("view removed repo: %v", err)
	}
	entriesB, _ := svc2.StateEntries(ctx, "team-b/app")
	if len(entriesB) != 0 {
		t.Fatalf("B entries after remove: %d", len(entriesB))
	}
	v2A2, _ := svc2.View(ctx, "team-a/base")
	if v2A2.Settled != int64(len(big)) {
		t.Fatalf("A changed after removing B: %d", v2A2.Settled)
	}
}

func blobDataExistsBytes(t *testing.T, ctx context.Context, drvr *inmemory.Driver, content []byte) bool {
	t.Helper()
	return blobDataExists(t, ctx, drvr, digest.FromBytes(content))
}
