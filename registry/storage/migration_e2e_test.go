package storage

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

// TestMigrationEndToEndFilesystemRestart exercises the full lifecycle against
// filesystem-backed roots with fresh driver instances between passes (a real
// restart), partial batches, a transient copy failure, pre-existing target
// objects (one good, one conflicting), a corrupted source repository and its
// operator-driven repair, finishing in verify + cutover and full semantic
// equivalence.
func TestMigrationEndToEndFilesystemRestart(t *testing.T) {
	ctx := context.Background()
	srcRoot, dstRoot := t.TempDir(), t.TempDir()

	// Seed the source through a filesystem driver.
	srcSeed := newMigrationTestDriver(newFSDriver(srcRoot))
	f := seedRegistryOn(t, srcSeed)

	// Pre-place destination objects: m2 is good (reused), m1 conflicts.
	dstSeed := newFSDriver(dstRoot)
	putCanonical := func(dgst digest.Digest, content string) {
		p, err := pathFor(blobDataPathSpec{digest: dgst})
		require.NoError(t, err)
		require.NoError(t, dstSeed.PutContent(ctx, p, []byte(content)))
	}
	putCanonical(f.m2, "manifest-two")
	putCanonical(f.m1, "totally-wrong-content-different-size")

	// Add a 250-byte blob to repo a so a mid-stream failure leaves a non-zero
	// checkpoint with chunk size 64.
	bigContent := repeatByte('z', 250)
	bigDgst := digest.FromString(bigContent)
	bigP, err := pathFor(blobDataPathSpec{digest: bigDgst})
	require.NoError(t, err)
	require.NoError(t, srcSeed.PutContent(ctx, bigP, []byte(bigContent)))
	bigLink, err := pathFor(layerLinkPathSpec{name: "a", digest: bigDgst})
	require.NoError(t, err)
	require.NoError(t, srcSeed.PutContent(ctx, bigLink, []byte(bigDgst.String())))

	// Pass 1: fail the big blob read after 128 bytes (two checkpoints), no
	// in-pass retries, serial execution so repo a is the first and only
	// repository claimed this pass.
	run1Src := newMigrationTestDriver(newFSDriver(srcRoot))
	var failedOnce bool
	run1Src.readerHook = func(p string, _ int64, rc io.ReadCloser) io.ReadCloser {
		counted := &countingReadCloser{d: run1Src, path: p, ReadCloser: rc}
		if p == bigP && !failedOnce {
			failedOnce = true
			return &failAfterReadCloser{rc: counted, after: 128}
		}
		return counted
	}
	s1, err := RunMigration(ctx, run1Src, newMigrationTestDriver(newFSDriver(dstRoot)), MigrationOptions{
		BatchSize: 6, Concurrency: 1, IncludeUploads: true,
		MaxAttempts: 1, LockTTL: 2 * time.Second, ChunkSize: 64,
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, s1.ProcessedUnits, int64(1))
	require.NotEmpty(t, s1.RepoErrors, "the injected failure must surface as a pass error")
	require.Equal(t, int64(128), run1Src.bytesReadFor(bigP), "source read stops at the failure point")

	// The ledger (reopened from disk) remembers the non-zero checkpoint.
	lOnDisk := newMigrationLedger(newFSDriver(dstRoot), "")
	bigRec, exists, err := lOnDisk.getBlobRecord(ctx, bigDgst)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, int64(128), bigRec.CommittedOffset, "restart resumes from the checkpoint, not zero")
	require.Equal(t, statePending, bigRec.State)

	// "Restart": brand new driver instances over the same on-disk roots. The
	// big blob must be re-read from offset 128 (122 remaining bytes), never
	// from zero, and the source driver rejects every write.
	run2Acct := newMigrationTestDriver(newFSDriver(srcRoot))
	s2, err := RunMigration(ctx,
		newPanicWriteDriver(t, run2Acct),
		newMigrationTestDriver(newFSDriver(dstRoot)),
		MigrationOptions{BatchSize: 0, Concurrency: 2, IncludeUploads: true,
			LockTTL: 2 * time.Second, ChunkSize: 64})
	require.NoError(t, err)
	require.False(t, s2.Status.Converged, "conflict and broken repo still block convergence")
	require.Equal(t, []int64{128}, run2Acct.offsetsFor(bigP), "resume offset after restart")
	require.Equal(t, int64(122), run2Acct.bytesReadFor(bigP), "only the tail is re-read after restart")

	// Operator repair cycle:
	//  1. replace the conflicting m1 object with valid bytes;
	repair := newFSDriver(dstRoot)
	putCanonicalVia(t, ctx, repair, f.m1, "manifest-one")
	//  2. provide the dangling blob referenced by repo "broken";
	putCanonicalVia(t, ctx, newFSDriver(srcRoot), f.dangling, "missing-blob")
	//  3. remove the malformed link from the source.
	badLink, err := pathFor(layerLinkPathSpec{name: "broken", digest: digest.FromString("whatever")})
	require.NoError(t, err)
	require.NoError(t, newFSDriver(srcRoot).Delete(ctx, badLink))

	// Pass 3 (another restart) drains, re-arms repaired units and converges.
	s3, err := RunMigration(ctx,
		newPanicWriteDriver(t, newFSDriver(srcRoot)),
		newMigrationTestDriver(newFSDriver(dstRoot)),
		MigrationOptions{BatchSize: 0, Concurrency: 2, IncludeUploads: true,
			LockTTL: 2 * time.Second, ChunkSize: 64})
	require.NoError(t, err)
	require.True(t, s3.Status.Converged, "blockers: %v", s3.Status.Blockers)
	require.Zero(t, s3.Status.QuarantineActive)

	// A further pass claims nothing and reads nothing from the source.
	s4, err := RunMigration(ctx,
		newPanicWriteDriver(t, newFSDriver(srcRoot)),
		newMigrationTestDriver(newFSDriver(dstRoot)),
		MigrationOptions{BatchSize: 0, Concurrency: 2, IncludeUploads: true,
			LockTTL: 2 * time.Second, ChunkSize: 64})
	require.NoError(t, err)
	require.Zero(t, s4.ProcessedUnits)
	require.True(t, s4.Status.Converged)

	// Independent verification and cutover, source strictly read-only.
	verifyRep, err := RunVerify(ctx,
		newPanicWriteDriver(t, newFSDriver(srcRoot)),
		newFSDriver(dstRoot), VerifyOptions{})
	require.NoError(t, err)
	require.True(t, verifyRep.Passed, verifyRep.String())

	cut, err := RunCutover(ctx,
		newPanicWriteDriver(t, newFSDriver(srcRoot)),
		newFSDriver(dstRoot), VerifyOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, cut.LedgerDigest)

	// ---- TR-8.1/8.2: semantic equivalence of source and target -------------
	srcSnap, err := discover(ctx, newFSDriver(srcRoot), nil)
	require.NoError(t, err)
	dstSnap, err := discover(ctx, newFSDriver(dstRoot), nil)
	require.NoError(t, err)

	require.ElementsMatch(t, keysOf(srcSnap.Repos), keysOf(dstSnap.Repos))
	require.Equal(t, len(srcSnap.BlobSizes), len(dstSnap.BlobSizes))
	for dg, size := range srcSnap.BlobSizes {
		require.Equal(t, size, dstSnap.BlobSizes[dg], "blob %s size mismatch", dg)
	}
	for name, sr := range srcSnap.Repos {
		dr := dstSnap.Repos[name]
		require.NotNil(t, dr, "repo missing on target: %s", name)
		require.ElementsMatch(t, keysOf(sr.Layers), keysOf(dr.Layers))
		require.ElementsMatch(t, keysOf(sr.Revisions), keysOf(dr.Revisions))
		require.ElementsMatch(t, keysOf(sr.Uploads), keysOf(dr.Uploads))
		require.Equal(t, len(sr.Tags), len(dr.Tags))
		for tag, st := range sr.Tags {
			dt := dr.Tags[tag]
			require.NotNil(t, dt)
			require.Equal(t, st.Current, dt.Current)
			require.ElementsMatch(t, keysOf(st.Index), keysOf(dt.Index))
		}
	}

	// Every blob object on the target hashes to its path digest, and the
	// interrupted upload's partial data is not among them.
	dstDriver := newFSDriver(dstRoot)
	for dg := range srcSnap.BlobSizes {
		p, err := pathFor(blobDataPathSpec{digest: digest.Digest(dg)})
		require.NoError(t, err)
		observed, size, err := hashDriverObject(ctx, dstDriver, p, digest.Canonical)
		require.NoError(t, err)
		require.Equal(t, dg, observed)
		require.Equal(t, srcSnap.BlobSizes[dg], size)
	}
	partialDataPath, err := pathFor(blobDataPathSpec{digest: digest.FromString("partial-data")})
	require.NoError(t, err)
	_, err = dstDriver.Stat(ctx, partialDataPath)
	var pnf driver.PathNotFoundError
	require.ErrorAs(t, err, &pnf, "upload data must never be promoted to a blob")

	// The upload session itself was copied byte-for-byte.
	upDataPath, err := pathFor(uploadDataPathSpec{name: "a", id: f.uploadID})
	require.NoError(t, err)
	b, err := dstDriver.GetContent(ctx, upDataPath)
	require.NoError(t, err)
	require.Equal(t, "partial-data", string(b))
}

func putCanonicalVia(t *testing.T, ctx context.Context, d driver.StorageDriver, dgst digest.Digest, content string) {
	t.Helper()
	p, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(t, err)
	require.NoError(t, d.PutContent(ctx, p, []byte(content)))
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
