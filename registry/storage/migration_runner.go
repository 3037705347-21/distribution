package storage

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
)

// This file is the batch orchestrator: discovery + ledger upsert, bounded
// concurrency over repositories, a claim budget implementing --batch-size,
// bounded retries with backoff for transient failures, lock heartbeats, and
// the end-of-run status/convergence snapshot.

// errMigrationBudget signals that the run's unit budget for this invocation
// has been exhausted; the unit stays pending and is retried next run.
var errMigrationBudget = errors.New("migration batch budget exhausted")

// unitBudget bounds how many ledger units one run invocation may claim. A
// zero limit allows the current drain to finish but claims nothing new; a
// negative limit means unlimited.
type unitBudget struct {
	mu      sync.Mutex
	limit   int64
	claimed int64
}

func newUnitBudget(limit int64) *unitBudget { return &unitBudget{limit: limit} }

func (b *unitBudget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit < 0 {
		b.claimed++
		return true
	}
	if b.claimed >= b.limit {
		return false
	}
	b.claimed++
	return true
}

func (b *unitBudget) claimedCount() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.claimed
}

// MigrationOptions controls one `migrate run` invocation.
type MigrationOptions struct {
	// BatchSize limits newly claimed units per invocation; 0 drains all
	// currently pending work.
	BatchSize int64
	// Concurrency is the repository worker count.
	Concurrency int
	// IncludeUploads copies _uploads sessions; false records them skipped.
	IncludeUploads bool
	// Repositories optionally restricts the run to a repo set.
	Repositories []string
	// Force takes over an expired advisory lock.
	Force bool
	// LockTTL is the advisory lock freshness interval.
	LockTTL time.Duration
	// MaxAttempts is the retry count per repository pass for transient errors.
	MaxAttempts int
	// ChunkSize overrides the streaming part size (tests).
	ChunkSize int64
	// LedgerPrefix overrides the reserved ledger prefix (optional).
	LedgerPrefix string
}

// RunSummary reports what one invocation did.
type RunSummary struct {
	Discovery      *upsertResult
	ProcessedUnits int64
	ReposAttempted int
	ReposCompleted int
	RepoErrors     []string
	Status         *MigrationStatusReport
}

// runMigration performs one (possibly batch-limited) migration pass.
func runMigration(ctx context.Context, src, dst driver.StorageDriver, opts MigrationOptions) (*RunSummary, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 3
	}
	if opts.LockTTL <= 0 {
		opts.LockTTL = defaultLockTTL
	}

	l := newMigrationLedger(dst, opts.LedgerPrefix)
	snap, err := discover(ctx, src, repoSet(opts.Repositories))
	if err != nil {
		return nil, err
	}
	if _, err := l.initRun(ctx, src.Name(), snap.fingerprint(src.Name())); err != nil {
		return nil, err
	}
	if err := l.acquireLock(ctx, opts.Force, opts.LockTTL); err != nil {
		return nil, err
	}
	defer func() { _ = l.releaseLock(ctx) }()

	hbCtx, stopHB := context.WithCancel(ctx)
	defer stopHB()
	go heartbeatLoop(hbCtx, l, opts.LockTTL/2)

	if _, err := l.updateRun(ctx, func(r *runRecord) {
		r.Phase = "discovering"
		r.SourceFingerprint = snap.fingerprint(src.Name())
	}); err != nil {
		return nil, err
	}
	upsert, err := upsertDiscovery(ctx, l, snap, opts.IncludeUploads, len(opts.Repositories) == 0)
	if err != nil {
		return nil, err
	}
	if _, err := l.updateRun(ctx, func(r *runRecord) { r.Phase = "running" }); err != nil {
		return nil, err
	}

	// Budget semantics: 0 means drain (unlimited), positive limits claims.
	budgetLimit := opts.BatchSize
	if budgetSizeIsDrain(opts.BatchSize) {
		budgetLimit = -1
	}
	budget := newUnitBudget(budgetLimit)

	bm := newBlobMigrator(src, dst, l)
	rm := newRepoMigrator(src, dst, l, bm)
	if opts.ChunkSize > 0 {
		bm.chunkSize = opts.ChunkSize
		rm.chunkSize = opts.ChunkSize
	}
	bm.budget = budget
	rm.budget = budget

	names, err := repoNames(ctx, l, opts.Repositories)
	if err != nil {
		return nil, err
	}

	summary := &RunSummary{Discovery: upsert}
	sem := semaphore.NewWeighted(int64(opts.Concurrency))
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var attempted, completed atomic.Int64
	for _, name := range names {
		if err := sem.Acquire(ctx, 1); err != nil {
			return nil, err
		}
		// Do not even dispatch a repository when the budget is already spent.
		if opts.BatchSize > 0 && budget.claimedCount() >= opts.BatchSize {
			sem.Release(1)
			break
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			defer sem.Release(1)

			res, err := migrateRepoWithRetry(ctx, rm, name, opts.MaxAttempts)
			if err != nil {
				errMu.Lock()
				summary.RepoErrors = append(summary.RepoErrors, name+": "+err.Error())
				errMu.Unlock()
				logrus.WithError(err).WithField("repository", name).Error("migration repository pass failed")
				return
			}
			attempted.Add(1)
			if res.Completed {
				completed.Add(1)
			}
			for _, b := range res.Blockers {
				logrus.WithField("repository", name).Info("migration blocker: " + b)
			}
		}(name)
	}
	wg.Wait()

	summary.ReposAttempted = int(attempted.Load())
	summary.ReposCompleted = int(completed.Load())
	summary.ProcessedUnits = budget.claimedCount()

	if _, err := l.updateRun(ctx, func(r *runRecord) { r.Phase = "idle" }); err != nil {
		return nil, err
	}
	status, err := buildStatus(ctx, l, repoSet(opts.Repositories))
	if err != nil {
		return nil, err
	}
	summary.Status = status
	logrus.WithFields(logrus.Fields{
		"claimed_units": summary.ProcessedUnits,
		"repos_done":    summary.ReposCompleted,
		"converged":     status.Converged,
	}).Info("migration pass finished")
	return summary, nil
}

// migrateRepoWithRetry retries transient repository-pass failures with capped
// exponential backoff. A missing budget is not an error: the pass ends.
func migrateRepoWithRetry(ctx context.Context, rm *repoMigrator, name string, attempts int) (*repoMigrateResult, error) {
	var lastErr error
	backoff := 20 * time.Millisecond
	for try := 0; try < attempts; try++ {
		res, err := rm.migrateRepo(ctx, name)
		if err == nil {
			return res, nil
		}
		if errors.Is(err, errMigrationBudget) {
			return &repoMigrateResult{Repo: name, BudgetExhausted: true}, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, lastErr
}

// migrationStatus builds the status report without taking the run lock.
func migrationStatus(ctx context.Context, dst driver.StorageDriver, repos []string, ledgerPrefix string) (*MigrationStatusReport, error) {
	l := newMigrationLedger(dst, ledgerPrefix)
	return buildStatus(ctx, l, repoSet(repos))
}

func heartbeatLoop(ctx context.Context, l *migrationLedger, interval time.Duration) {
	if interval <= 0 {
		interval = defaultLockTTL / 2
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.heartbeat(ctx, interval*2); err != nil {
				return
			}
		}
	}
}

func repoSet(repos []string) map[string]struct{} {
	if len(repos) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(repos))
	for _, r := range repos {
		m[r] = struct{}{}
	}
	return m
}

func budgetSizeIsDrain(n int64) bool { return n == 0 }

// repoNames returns the sorted repository names in the ledger, optionally
// filtered.
func repoNames(ctx context.Context, l *migrationLedger, filter []string) ([]string, error) {
	var out []string
	if err := l.listRepoRecords(ctx, func(r *repoRecord) error {
		if r.Gone {
			return nil
		}
		out = append(out, r.Name)
		return nil
	}); err != nil {
		return nil, err
	}
	sortStrings(out)
	if len(filter) == 0 {
		return out, nil
	}
	want := repoSet(filter)
	filtered := out[:0]
	for _, n := range out {
		if _, ok := want[n]; ok {
			filtered = append(filtered, n)
		}
	}
	return filtered, nil
}
