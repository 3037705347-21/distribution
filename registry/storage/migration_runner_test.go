package storage

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

// seedTwoRepoOneBlobEach builds two repositories, each linking exactly one
// unique blob: 2 blobs + 2 links = 4 claimable units, nothing else.
func seedTwoRepoOneBlobEach(t *testing.T, src driver.StorageDriver) (string, string) {
	ctx := context.Background()
	put := func(repo, content string) digest.Digest {
		dgst := digest.FromString(content)
		bp, err := pathFor(blobDataPathSpec{digest: dgst})
		require.NoError(t, err)
		require.NoError(t, src.PutContent(ctx, bp, []byte(content)))
		lp, err := pathFor(layerLinkPathSpec{name: repo, digest: dgst})
		require.NoError(t, err)
		require.NoError(t, src.PutContent(ctx, lp, []byte(dgst.String())))
		return dgst
	}
	d1 := put("r1", "blob-one")
	d2 := put("r2", "blob-two")
	return d1.String(), d2.String()
}

// ---- TR-5.1: batch limit, repeated runs drain, no duplicate transfer -------

func TestRunMigrationBatching(t *testing.T) {
	ctx := context.Background()
	src := newMigrationTestDriver(inmemory.New())
	dst := newMigrationTestDriver(inmemory.New())
	seedTwoRepoOneBlobEach(t, src)

	opts := MigrationOptions{
		BatchSize:      2,
		Concurrency:    1,
		IncludeUploads: true,
		LockTTL:        2 * time.Second,
		ChunkSize:      100,
	}

	s1, err := runMigration(ctx, src, dst, opts)
	require.NoError(t, err)
	require.Equal(t, int64(2), s1.ProcessedUnits)

	s2, err := runMigration(ctx, src, dst, opts)
	require.NoError(t, err)
	require.Equal(t, int64(2), s2.ProcessedUnits)

	s3, err := runMigration(ctx, src, dst, opts)
	require.NoError(t, err)
	require.Zero(t, s3.ProcessedUnits, "nothing left to claim")
	require.True(t, s3.Status.Converged, "blockers: %v", s3.Status.Blockers)
	require.Equal(t, int64(2), s3.Status.TotalRepos)

	// Each source blob read exactly once across all runs.
	var totalSourceBytes int64
	blobsRoot := "/docker/registry/v2/blobs"
	require.NoError(t, src.Walk(ctx, blobsRoot, func(fi driver.FileInfo) error {
		if fi.IsDir() {
			return nil
		}
		totalSourceBytes += src.bytesReadFor(fi.Path())
		return nil
	}))
	require.Equal(t, int64(len("blob-one")+len("blob-two")), totalSourceBytes,
		"no blob is re-transferred after completion")
}

// ---- TR-5.2: transient failures are retried with backoff --------------------

type failFirstReaders struct {
	driver.StorageDriver
	failuresLeft int64
}

func (d *failFirstReaders) Reader(ctx context.Context, p string, offset int64) (io.ReadCloser, error) {
	rc, err := d.StorageDriver.Reader(ctx, p, offset)
	if err != nil {
		return nil, err
	}
	if atomic.LoadInt64(&d.failuresLeft) > 0 {
		atomic.AddInt64(&d.failuresLeft, -1)
		return &errorReadCloser{rc: rc}, nil
	}
	return rc, nil
}

type errorReadCloser struct{ rc io.ReadCloser }

func (e *errorReadCloser) Read([]byte) (int, error) {
	return 0, injectedError("transient read failure")
}
func (e *errorReadCloser) Close() error { return e.rc.Close() }

func TestRunMigrationRetriesTransientFailures(t *testing.T) {
	ctx := context.Background()
	src := &failFirstReaders{StorageDriver: newMigrationTestDriver(inmemory.New()), failuresLeft: 2}
	dst := newMigrationTestDriver(inmemory.New())
	seedTwoRepoOneBlobEach(t, src)

	opts := MigrationOptions{
		BatchSize:      0,
		Concurrency:    1,
		IncludeUploads: true,
		LockTTL:        2 * time.Second,
		MaxAttempts:    4,
		ChunkSize:      100,
	}
	s, err := runMigration(ctx, src, dst, opts)
	require.NoError(t, err)
	require.True(t, s.Status.Converged, "retry must converge: %v", s.Status.Blockers)
	require.Empty(t, s.RepoErrors)
	require.Equal(t, int64(0), atomic.LoadInt64(&src.failuresLeft))
}

// ---- TR-5.3: status aggregation and quarantine visibility --------------------

func TestRunMigrationStatus(t *testing.T) {
	ctx := context.Background()
	src := newMigrationTestDriver(inmemory.New())
	dst := newMigrationTestDriver(inmemory.New())

	// Full demo fixture includes a broken repo and an interrupted upload.
	fixture := seedRegistryOn(t, src)
	_ = fixture

	// A first run migrates everything except the broken repository's links.
	s, err := runMigration(ctx, src, dst, MigrationOptions{
		BatchSize: 0, Concurrency: 2, IncludeUploads: true,
		LockTTL: 2 * time.Second, ChunkSize: 100,
	})
	require.NoError(t, err)
	require.False(t, s.Status.Converged, "broken repo must prevent convergence")
	require.GreaterOrEqual(t, s.Status.QuarantineActive, 2)
	require.GreaterOrEqual(t, s.Status.LayerLinks[stateQuarantined], int64(1))
	require.Equal(t, int64(3), s.Status.TotalRepos)
	require.Contains(t, s.Status.String(), "Converged: NO")
	require.Contains(t, s.Status.String(), "blocker")

	// Single-repo filter: healthy repo a is converged on its own.
	st, err := migrationStatus(ctx, dst, []string{"a"}, "")
	require.NoError(t, err)
	require.Equal(t, int64(1), st.TotalRepos)
	// Global blobs/quarantine are always reported in full.
	require.GreaterOrEqual(t, st.QuarantineActive, 2)
}

// ---- TR-5.4: runner never writes the source ----------------------------------

func TestRunMigrationSourceIsReadOnly(t *testing.T) {
	ctx := context.Background()
	inner := newMigrationTestDriver(inmemory.New())
	seedTwoRepoOneBlobEach(t, inner)
	src := newPanicWriteDriver(t, inner)
	dst := newMigrationTestDriver(inmemory.New())

	s, err := runMigration(ctx, src, dst, MigrationOptions{
		BatchSize: 0, Concurrency: 1, IncludeUploads: true,
		LockTTL: 2 * time.Second, ChunkSize: 100,
	})
	require.NoError(t, err)
	require.True(t, s.Status.Converged)
}
