package storage

import (
	"context"
	"path"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

// ---- TR-1.1: durable records reopenable with a fresh driver instance -------

func TestMigrationLedgerDurableAcrossDriverInstances(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	mkFS := func() *migrationTestDriver {
		return newMigrationTestDriver(newFSDriver(root))
	}

	dgst := digest.FromString("layer-blob-content")
	l1 := newMigrationLedger(mkFS(), "")
	run, err := l1.initRun(ctx, "filesystem", "fp-1")
	require.NoError(t, err)

	rec, err := l1.mutateBlobRecord(ctx, dgst, true, func(r *blobRecord) error {
		r.ExpectedSize = 17
		r.State = stateCompleted
		r.Origin = originCopied
		addBlobRef(r, "library/app")
		addBlobRef(r, "library/app") // idempotent
		addBlobRef(r, "library/other")
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), rec.Version) // create + completed in one commit
	require.Equal(t, []string{"library/app", "library/other"}, rec.Refs)

	repo := "library/my/app"
	_, err = l1.mutateRepoRecord(ctx, repo, true, func(r *repoRecord) error {
		r.Layers[dgst.String()] = migrationSubUnit{State: stateCompleted, Target: dgst.String()}
		r.Tags["v1"] = migrationTagUnit{
			Current:      dgst.String(),
			CurrentState: stateCompleted,
			Index:        map[string]migrationState{dgst.String(): stateCompleted},
		}
		r.Uploads[uuid.NewString()] = migrationUploadUnit{State: stateCompleted}
		return nil
	})
	require.NoError(t, err)

	q, err := l1.quarantine(ctx, &quarantineRecord{
		Kind: "blob-corrupt", Repo: "library/app", Key: dgst.String(),
		ExpectedDigest: dgst.String(), Reason: "boom",
	})
	require.NoError(t, err)

	// Reopen the ledger through a brand new driver instance, as a runner on
	// another host (or after a restart) would.
	l2 := newMigrationLedger(mkFS(), "")
	run2, err := l2.initRun(ctx, "filesystem", "fp-1")
	require.NoError(t, err)
	require.Equal(t, run.RunID, run2.RunID, "run identity must survive restart")

	got, exists, err := l2.getBlobRecord(ctx, dgst)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, stateCompleted, got.State)
	require.Equal(t, originCopied, got.Origin)
	require.Equal(t, int64(1), got.Version)
	require.Equal(t, []string{"library/app", "library/other"}, got.Refs)

	repoRec, exists, err := l2.getRepoRecord(ctx, repo)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, stateCompleted, repoRec.Tags["v1"].CurrentState)
	require.Len(t, repoRec.Uploads, 1)

	var qs []*quarantineRecord
	require.NoError(t, l2.listQuarantineRecords(ctx, func(q *quarantineRecord) error {
		if !q.Resolved {
			qs = append(qs, q)
		}
		return nil
	}))
	require.Len(t, qs, 1)
	require.Equal(t, q.ID, qs[0].ID)

	// The cutover marker round-trips too.
	require.NoError(t, l2.writeCutover(ctx, &cutoverRecord{
		RunID: run2.RunID, CutoverAt: time.Now().UTC(), SourceFingerprint: "fp-1",
		Counts: map[string]int64{"blobs": 1}, TotalBytes: 17,
	}))
	cut, exists, err := l2.getCutover(ctx)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, "fp-1", cut.SourceFingerprint)
}

// ---- TR-1.2: ledger keys are driver-path legal, digest ':' never in path ---

func TestMigrationLedgerPathsAreLegal(t *testing.T) {
	l := newMigrationLedger(inmemory.New(), "")
	dgst := digest.FromString("abc")

	for _, p := range mustPaths(t, l, dgst) {
		require.Truef(t, driver.PathRegexp.MatchString(p), "ledger path illegal: %s", p)
		require.NotContains(t, p, ":")
	}

	// Multi-level repository names are supported.
	rec, err := l.mutateRepoRecord(context.Background(), "library/my/app", true, func(r *repoRecord) error {
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "library/my/app", rec.Name)

	for _, bad := range []string{"", "/leading", "trailing/", "a//b", "Upper", "../escape", "a/.."} {
		_, err := l.repoRecordPath(bad)
		require.ErrorIs(t, err, ErrMigrationInvalidPath, "name=%q", bad)
	}
}

func mustPaths(t *testing.T, l *migrationLedger, dgst digest.Digest) []string {
	t.Helper()
	var ps []string
	appendPath := func(p string, err error) string {
		require.NoError(t, err)
		require.NotEmpty(t, p)
		return p
	}
	ps = append(ps, appendPath(l.blobRecordPath(dgst)))
	ps = append(ps, appendPath(l.repoRecordPath("library/app")))
	ps = append(ps, appendPath(l.tempBlobPath(dgst, "nonce")))
	ps = append(ps, appendPath(l.tempUploadDataPath("library/app", uuid.NewString(), "nonce")))
	ps = append(ps, l.runStatePath(), l.lockPath(), l.cutoverPath(), l.quarantinePath(uuid.NewString()), l.tempRoot())
	return ps
}

// ---- TR-1.3: state machine, monotonic versions, no lost updates ------------

func TestMigrationLedgerStateTransitions(t *testing.T) {
	ctx := context.Background()
	l := newMigrationLedger(inmemory.New(), "")
	dgst := digest.FromString("states")

	// Legal forward chain.
	for _, st := range []migrationState{stateInProgress, stateCompleted} {
		_, err := l.mutateBlobRecord(ctx, dgst, true, func(r *blobRecord) error {
			r.State = st
			return nil
		})
		require.NoError(t, err)
	}
	got, _, err := l.getBlobRecord(ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, int64(2), got.Version) // two committed mutations

	// Illegal backward transition is rejected and the record is untouched.
	_, err = l.mutateBlobRecord(ctx, dgst, true, func(r *blobRecord) error {
		r.State = statePending
		return nil
	})
	require.ErrorIs(t, err, ErrMigrationInvalidTransit)
	got, _, err = l.getBlobRecord(ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, stateCompleted, got.State)
	require.Equal(t, int64(2), got.Version, "rejected transition must not bump the version")
}

func TestMigrationLedgerConcurrentMutationsNoLostUpdate(t *testing.T) {
	ctx := context.Background()
	l := newMigrationLedger(inmemory.New(), "")
	dgst := digest.FromString("concurrent")

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := l.mutateBlobRecord(ctx, dgst, true, func(r *blobRecord) error {
				addBlobRef(r, "repo-"+strconv.Itoa(i))
				return nil
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	got, _, err := l.getBlobRecord(ctx, dgst)
	require.NoError(t, err)
	require.Len(t, got.Refs, n, "every ref mutation must survive")
	require.Equal(t, int64(n), got.Version, "one committed mutation (the first creates the record) per goroutine")
}

// ---- TR-1.4: advisory lock --------------------------------------------------

func TestMigrationLedgerAdvisoryLock(t *testing.T) {
	ctx := context.Background()
	d := inmemory.New()
	ttl := 200 * time.Millisecond

	a := newMigrationLedger(d, "")
	_, err := a.initRun(ctx, "inmemory", "fp")
	require.NoError(t, err)
	require.NoError(t, a.acquireLock(ctx, false, ttl))

	// A different run must not take a fresh lock.
	b := newMigrationLedger(d, "")
	b.runID = uuid.NewString()
	err = b.acquireLock(ctx, false, ttl)
	require.ErrorIs(t, err, ErrMigrationLocked)

	// Once stale, takeover requires force.
	time.Sleep(ttl + 50*time.Millisecond)
	err = b.acquireLock(ctx, false, ttl)
	require.ErrorIs(t, err, ErrMigrationLockExpired)
	require.NoError(t, b.acquireLock(ctx, true, ttl))

	// A must not be able to heartbeat after losing the lock.
	time.Sleep(10 * time.Millisecond)
	err = a.heartbeat(ctx, ttl)
	require.ErrorIs(t, err, ErrMigrationLockExpired)

	// The new owner can heartbeat and release.
	require.NoError(t, b.heartbeat(ctx, ttl))
	require.NoError(t, b.releaseLock(ctx))

	// Releasing again is harmless, and A must not delete B's lock semantics:
	// after release A (foreign) release is a no-op, then A can re-acquire.
	require.NoError(t, a.releaseLock(ctx))
	require.NoError(t, a.acquireLock(ctx, true, ttl))
}

// ---- TR-1.5: crash between temp write and Move leaves the old record --------

func TestMigrationLedgerAtomicWriteCrashBeforeMove(t *testing.T) {
	ctx := context.Background()
	inner := inmemory.New()
	d := newMigrationTestDriver(inner)
	l := newMigrationLedger(d, "")
	dgst := digest.FromString("atomic")

	// First commit fails at Move: no document must appear at the record path.
	recPath := path.Join(l.prefix, "blobs", dgst.Algorithm().String(), dgst.Encoded()[:2], dgst.Encoded()+".json")
	d.failMove = func(p string) bool { return p == recPath }

	_, err := l.mutateBlobRecord(ctx, dgst, true, func(r *blobRecord) error {
		r.State = stateInProgress
		return nil
	})
	require.Error(t, err)

	_, exists, err := l.getBlobRecord(ctx, dgst)
	require.NoError(t, err)
	require.False(t, exists, "failed commit must not expose a record")

	// A successful commit later lands version 1; a subsequent failed update
	// must leave the committed version readable.
	d.failMove = nil
	_, err = l.mutateBlobRecord(ctx, dgst, true, func(r *blobRecord) error {
		r.State = stateInProgress
		return nil
	})
	require.NoError(t, err)

	var failedOnce sync.Once
	d.failMove = func(p string) bool {
		if p == recPath {
			inject := false
			failedOnce.Do(func() { inject = true })
			return inject
		}
		return false
	}
	_, err = l.mutateBlobRecord(ctx, dgst, false, func(r *blobRecord) error {
		r.Attempts = 9
		return nil
	})
	require.Error(t, err)

	got, exists, err := l.getBlobRecord(ctx, dgst)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, stateInProgress, got.State)
	require.Zero(t, got.Attempts, "the old committed version must be untouched")
}

// ---- quarantine dedup / resolution ------------------------------------------

func TestMigrationLedgerQuarantineDedupAndResolve(t *testing.T) {
	ctx := context.Background()
	l := newMigrationLedger(inmemory.New(), "")
	dgst := digest.FromString("q")

	q1, err := l.quarantine(ctx, &quarantineRecord{Kind: "blob-conflict", Repo: "r", Key: dgst.String(), Reason: "size"})
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond)
	q2, err := l.quarantine(ctx, &quarantineRecord{Kind: "blob-conflict", Repo: "r", Key: dgst.String(), Reason: "size", ObservedSize: 99})
	require.NoError(t, err)
	require.Equal(t, q1.ID, q2.ID, "repeat findings refresh one record")
	require.Equal(t, int64(99), q2.ObservedSize)
	require.True(t, q2.LastUpdate.After(q1.LastUpdate) || q2.LastUpdate.Equal(q1.LastUpdate))

	var n int
	require.NoError(t, l.listQuarantineRecords(ctx, func(*quarantineRecord) error { n++; return nil }))
	require.Equal(t, 1, n)

	require.NoError(t, l.resolveQuarantine(ctx, q1.ID, "object replaced"))
	var unresolved int
	require.NoError(t, l.listQuarantineRecords(ctx, func(q *quarantineRecord) error {
		if !q.Resolved {
			unresolved++
		}
		return nil
	}))
	require.Zero(t, unresolved)
}
