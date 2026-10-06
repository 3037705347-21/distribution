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

// R-1: the checkpoint part size must clear the S3 5 MiB non-final part floor.
func TestReviewFixChunkSizeAboveS3Floor(t *testing.T) {
	const s3MinPartSize = 5 << 20
	require.GreaterOrEqual(t, int64(defaultBlobCopyChunkSize), int64(s3MinPartSize))
}

// R-4: a layer link silently swapped for another valid blob digest must fail
// verification (digest mismatch, even though the target blob is healthy).
func TestReviewFixLayerLinkSwapDetected(t *testing.T) {
	ctx := context.Background()
	src := newMigrationTestDriver(inmemory.New())
	dst := newMigrationTestDriver(inmemory.New())
	f := seedRegistryOn(t, src)
	drain(t, ctx, src, dst)

	// Repo b layer link l1 -> point it at m2, which exists and verifies.
	lp, err := pathFor(layerLinkPathSpec{name: "b", digest: f.l1})
	require.NoError(t, err)
	require.NoError(t, dst.PutContent(ctx, lp, []byte(f.m2.String())))

	rep, err := RunVerify(ctx, src, dst, VerifyOptions{Repositories: []string{"b"}})
	require.NoError(t, err)
	require.False(t, rep.Passed)
	require.GreaterOrEqual(t, rep.LinksBad, int64(1))
	require.Contains(t, joinFailures(rep.Failures), "link points to")
}

// R-5: deleting a layer link from the frozen source blocks cutover.
func TestReviewFixDriftDeletedLayerBlocksCutover(t *testing.T) {
	ctx := context.Background()
	src := newMigrationTestDriver(inmemory.New())
	dst := newMigrationTestDriver(inmemory.New())
	d1, _ := seedTwoRepoOneBlobEach(t, src)
	// Give r1 a second layer so deleting one does not remove the repo itself.
	dExtra := digest.FromString("blob-extra")
	ep, err := pathFor(blobDataPathSpec{digest: dExtra})
	require.NoError(t, err)
	require.NoError(t, src.PutContent(ctx, ep, []byte("blob-extra")))
	elp, err := pathFor(layerLinkPathSpec{name: "r1", digest: dExtra})
	require.NoError(t, err)
	require.NoError(t, src.PutContent(ctx, elp, []byte(dExtra.String())))
	drain(t, ctx, src, dst)

	lp, err := pathFor(layerLinkPathSpec{name: "r1", digest: digest.Digest(d1)})
	require.NoError(t, err)
	require.NoError(t, src.Delete(ctx, lp))

	_, err = RunCutover(ctx, src, dst, VerifyOptions{})
	require.ErrorIs(t, err, ErrCutoverBlocked)
	require.Contains(t, err.Error(), "layer vanished from source")
}

// R-7: when a source link disappears between discovery and migration, the
// unit must not be marked completed (the next discovery sweep decides).
func TestReviewFixMissingSourceLinkNotCompleted(t *testing.T) {
	h := newRepoMigrationHarness(t, true)
	dg := h.f.l1.String()

	// Remove the source layer link after discovery but before migration.
	lp, err := pathFor(layerLinkPathSpec{name: "a", digest: h.f.l1})
	require.NoError(t, err)
	require.NoError(t, h.src.Delete(h.ctx, lp))

	res, err := h.rm.migrateRepo(h.ctx, "a")
	require.NoError(t, err)
	require.False(t, res.Completed)
	rec, _, err := h.l.getRepoRecord(h.ctx, "a")
	require.NoError(t, err)
	require.NotEqual(t, stateCompleted, rec.Layers[dg].State,
		"missing source link must never be reported completed")
}

// R-8: an empty source and an empty target ledger cannot produce a cutover.
func TestReviewFixEmptyLedgerBlocksCutover(t *testing.T) {
	ctx := context.Background()
	src := newPanicWriteDriver(t, inmemory.New())
	dst := inmemory.New()
	_, err := RunCutover(ctx, src, dst, VerifyOptions{})
	require.ErrorIs(t, err, ErrCutoverBlocked)
	require.Contains(t, err.Error(), "no migration run")

	// Status on a pristine ledger is likewise not converged.
	st, err := MigrationStatus(ctx, dst, nil, "")
	require.NoError(t, err)
	require.False(t, st.Converged)
}

// R-3: counters are safe under concurrent repository workers (-race).
func TestReviewFixConcurrentCounterRace(t *testing.T) {
	ctx := context.Background()
	src := newMigrationTestDriver(inmemory.New())
	dst := newMigrationTestDriver(inmemory.New())
	for i := 0; i < 6; i++ {
		content := "race-blob-" + string(rune('a'+i)) + "-padding-padding"
		seedSingleLayerRepo(t, ctx, src, "rc"+string(rune('a'+i)), content)
	}
	s, err := RunMigration(ctx, src, dst, MigrationOptions{
		BatchSize: 0, Concurrency: 4, IncludeUploads: true,
		LockTTL: 2 * time.Second, ChunkSize: 64,
	})
	require.NoError(t, err)
	require.True(t, s.Status.Converged, s.Status.Blockers)
	require.Equal(t, 6, s.ReposAttempted)
	require.Equal(t, 6, s.ReposCompleted)
}

func joinFailures(fs []string) string {
	out := ""
	for _, f := range fs {
		out += f + "\n"
	}
	return out
}

// seedSingleLayerRepo creates one repository with exactly one layer blob.
func seedSingleLayerRepo(t *testing.T, ctx context.Context, d driver.StorageDriver, repo, content string) digest.Digest {
	t.Helper()
	dgst := digest.FromString(content)
	bp, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(t, err)
	require.NoError(t, d.PutContent(ctx, bp, []byte(content)))
	lp, err := pathFor(layerLinkPathSpec{name: repo, digest: dgst})
	require.NoError(t, err)
	require.NoError(t, d.PutContent(ctx, lp, []byte(dgst.String())))
	return dgst
}
