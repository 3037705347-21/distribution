package storage

import (
	"context"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

func drain(t *testing.T, ctx context.Context, src, dst driver.StorageDriver) *RunSummary {
	s, err := runMigration(ctx, src, dst, MigrationOptions{
		BatchSize: 0, Concurrency: 2, IncludeUploads: true,
		LockTTL: 2 * time.Second, ChunkSize: 100,
	})
	require.NoError(t, err)
	return s
}

// ---- TR-6.1: verify clean passes; tampering is detected ---------------------

func TestVerifyCleanAndTampered(t *testing.T) {
	ctx := context.Background()
	src := newMigrationTestDriver(inmemory.New())
	dst := newMigrationTestDriver(inmemory.New())
	f := seedRegistryOn(t, src)

	drain(t, ctx, src, dst)
	// Healthy subset verifies (broken repo excluded).
	rep, err := runVerify(ctx, src, dst, VerifyOptions{Repositories: []string{"a", "b"}})
	require.NoError(t, err)
	// Even with the repo filter, global blob verification covers everything;
	// links/tags for a/b must be clean.
	require.Zero(t, rep.BlobsBad)
	require.Zero(t, rep.LinksBad)
	require.Zero(t, rep.TagMismatches)
	require.Equal(t, 4, rep.TagTreesCompared, "manifests+layers trees for both repos")

	// Tamper one byte of blob m1 on the destination.
	m1p, err := pathFor(blobDataPathSpec{digest: f.m1})
	require.NoError(t, err)
	orig := []byte("manifest-one")
	bad := append([]byte(nil), orig...)
	bad[3] = 'X'
	require.NoError(t, dst.PutContent(ctx, m1p, bad))
	rep, err = runVerify(ctx, src, dst, VerifyOptions{Repositories: []string{"a", "b"}})
	require.NoError(t, err)
	require.False(t, rep.Passed)
	require.Equal(t, int64(1), rep.BlobsBad)
	rec, _, err := newMigrationLedger(dst, "").getBlobRecord(ctx, f.m1)
	require.NoError(t, err)
	require.Equal(t, stateConflict, rec.State, "tampered blob must be demoted")

	// Tamper a layer link on repo b.
	lp, err := pathFor(layerLinkPathSpec{name: "b", digest: f.l1})
	require.NoError(t, err)
	require.NoError(t, dst.PutContent(ctx, lp, []byte(digest.FromString("ghost").String())))
	rep, err = runVerify(ctx, src, dst, VerifyOptions{Repositories: []string{"b"}})
	require.NoError(t, err)
	require.GreaterOrEqual(t, rep.LinksBad, int64(1))
	require.NotEmpty(t, rep.Failures)
}

// ---- TR-6.2: the four cutover gate scenarios --------------------------------

func TestCutoverGateScenarios(t *testing.T) {
	ctx := context.Background()

	// Scenario 1: unfinished units block the marker.
	src1 := newMigrationTestDriver(inmemory.New())
	dst1 := newMigrationTestDriver(inmemory.New())
	seedTwoRepoOneBlobEach(t, src1)
	_, err := runMigration(ctx, src1, dst1, MigrationOptions{
		BatchSize: 2, Concurrency: 1, LockTTL: 2 * time.Second, ChunkSize: 100,
	})
	require.NoError(t, err)
	_, err = runCutover(ctx, src1, dst1, VerifyOptions{})
	require.ErrorIs(t, err, ErrCutoverBlocked)
	require.False(t, cutoverExists(t, ctx, dst1))

	// Scenario 2: quarantine blocks the marker.
	src2 := newMigrationTestDriver(inmemory.New())
	dst2 := newMigrationTestDriver(inmemory.New())
	seedRegistryOn(t, src2)
	drain(t, ctx, src2, dst2)
	_, err = runCutover(ctx, src2, dst2, VerifyOptions{})
	require.ErrorIs(t, err, ErrCutoverBlocked)
	require.Contains(t, err.Error(), "blocked")
	require.False(t, cutoverExists(t, ctx, dst2))

	// Scenario 3: source drift (new tag) blocks the marker.
	src3 := newMigrationTestDriver(inmemory.New())
	dst3 := newMigrationTestDriver(inmemory.New())
	seedTwoRepoOneBlobEach(t, src3)
	drain(t, ctx, src3, dst3)
	d1 := digest.FromString("blob-one")
	tagP, err := pathFor(manifestTagCurrentPathSpec{name: "r1", tag: "v9"})
	require.NoError(t, err)
	require.NoError(t, src3.PutContent(ctx, tagP, []byte(d1.String())))
	idxP, err := pathFor(manifestTagIndexEntryLinkPathSpec{name: "r1", tag: "v9", revision: d1})
	require.NoError(t, err)
	require.NoError(t, src3.PutContent(ctx, idxP, []byte(d1.String())))
	_, err = runCutover(ctx, src3, dst3, VerifyOptions{})
	require.ErrorIs(t, err, ErrCutoverBlocked)
	require.Contains(t, err.Error(), "new tag")
	require.False(t, cutoverExists(t, ctx, dst3))

	// Scenario 4: fully converged, zero drift, verify clean -> marker.
	src4 := newPanicWriteDriver(t, src3.StorageDriver) // source must stay read-only
	rec, err := runCutover(ctx, src4, dst3, VerifyOptions{})
	// NOTE: drift still present (v9); revert drift first by migrating it.
	require.Error(t, err)

	// Clear the drift the normal operational way: run again, then cutover.
	drain(t, ctx, src3, dst3)
	srcRO := newPanicWriteDriver(t, src3.StorageDriver)
	rec, err = runCutover(ctx, srcRO, dst3, VerifyOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, rec.RunID)
	require.NotEmpty(t, rec.CutoverAt)
	require.Equal(t, "inmemory", rec.SourceDriver)
	require.NotEmpty(t, rec.SourceFingerprint)
	require.NotEmpty(t, rec.LedgerDigest)
	require.Equal(t, int64(2), rec.Counts["blobs"])

	// Idempotent: second cutover returns the same marker.
	again, err := runCutover(ctx, srcRO, dst3, VerifyOptions{})
	require.NoError(t, err)
	require.Equal(t, rec.RunID, again.RunID)
	require.True(t, cutoverExists(t, ctx, dst3))
}

// ---- TR-6.4: verify/cutover issue no source writes ---------------------------

func TestVerifyCutoverSourceIsReadOnly(t *testing.T) {
	ctx := context.Background()
	inner := newMigrationTestDriver(inmemory.New())
	dst := newMigrationTestDriver(inmemory.New())
	seedTwoRepoOneBlobEach(t, inner)
	drain(t, ctx, inner, dst)

	src := newPanicWriteDriver(t, inner)
	rep, err := runVerify(ctx, src, dst, VerifyOptions{})
	require.NoError(t, err)
	require.True(t, rep.Passed)

	cut, err := runCutover(ctx, src, dst, VerifyOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, cut.LedgerDigest)
}

func cutoverExists(t *testing.T, ctx context.Context, dst driver.StorageDriver) bool {
	t.Helper()
	l := newMigrationLedger(dst, "")
	_, exists, err := l.getCutover(ctx)
	require.NoError(t, err)
	return exists
}
