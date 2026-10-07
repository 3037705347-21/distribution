package accounting

import (
	"context"
	"fmt"
	"path"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/opencontainers/go-digest"
)

type testEnv struct {
	t    *testing.T
	drvr driver.StorageDriver
	now  time.Time
	seq  int
}

func newTestEnv(t *testing.T) *testEnv {
	return &testEnv{t: t, drvr: inmemory.New(), now: time.Unix(1_000_000, 0)}
}

func (e *testEnv) newID(now time.Time) string {
	e.seq++
	return fmt.Sprintf("%016x-%04x", now.UnixNano(), e.seq)
}

func (e *testEnv) newStore(b *Budgets, opts ...Option) *Store {
	now := e.now
	allOpts := append([]Option{withNow(func() time.Time { return now }), withIDGen(e.newID)}, opts...)
	s, err := New(e.drvr, b, allOpts...)
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	return s
}

func (e *testEnv) sleep(d time.Duration) { e.now = e.now.Add(d) }

func TestStoreReserveSettleReleaseDebit(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("1000", nil)
	s := env.newStore(b)
	ctx := context.Background()
	const repo = "team-a/app"

	r, err := s.Reserve(ctx, repo, 100, KindUpload, dgA, PhaseUpload)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	v, _ := s.View(ctx, repo)
	if v.Settled != 0 || v.Reserved != 100 || v.Available() != 900 {
		t.Fatalf("view after reserve: %+v", v)
	}

	if err := s.Settle(ctx, r, dgA, RoleLayer, 100); err != nil {
		t.Fatalf("settle: %v", err)
	}
	v, _ = s.View(ctx, repo)
	if v.Settled != 100 || v.Reserved != 0 {
		t.Fatalf("view after settle: %+v", v)
	}

	// second upload of the same digest settles idempotently.
	r2, err := s.Reserve(ctx, repo, 100, KindUpload, dgA, PhaseUpload)
	if err != nil {
		t.Fatalf("reserve2: %v", err)
	}
	if err := s.Settle(ctx, r2, dgA, RoleLayer, 100); err != nil {
		t.Fatalf("settle2: %v", err)
	}
	v, _ = s.View(ctx, repo)
	if v.Settled != 100 {
		t.Fatalf("duplicate settle double-counted: %+v", v)
	}

	if err := s.Debit(ctx, repo, dgA, RoleLayer); err != nil {
		t.Fatalf("debit: %v", err)
	}
	v, _ = s.View(ctx, repo)
	if v.Settled != 0 {
		t.Fatalf("view after debit: %+v", v)
	}
	if err := s.Debit(ctx, repo, dgA, RoleLayer); err != nil {
		t.Fatalf("duplicate debit: %v", err)
	}
	v, _ = s.View(ctx, repo)
	if v.Settled != 0 {
		t.Fatalf("duplicate debit drifted: %+v", v)
	}
}

func TestStoreQuotaDeniedBeforeUsage(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("100", nil)
	s := env.newStore(b)
	ctx := context.Background()
	const repo = "team-a/app"

	// existing settled usage of 60.
	r0, err := s.Reserve(ctx, repo, 60, KindUpload, dgB, PhaseUpload)
	if err != nil {
		t.Fatalf("reserve0: %v", err)
	}
	if err := s.Settle(ctx, r0, dgB, RoleLayer, 60); err != nil {
		t.Fatalf("settle0: %v", err)
	}

	// reservation of 50 overshoots: must be denied AND released.
	_, err = s.Reserve(ctx, repo, 50, KindMount, dgA, PhaseMount)
	var qe *ErrQuotaExceeded
	if !asQuota(err, &qe) {
		t.Fatalf("expected ErrQuotaExceeded, got %v", err)
	}
	if qe.Phase != PhaseMount || qe.Limit != 100 || qe.Requested != 50 || qe.Settled != 60 {
		t.Fatalf("error detail = %+v", qe)
	}
	v, _ := s.View(ctx, repo)
	if v.Reserved != 0 || v.Settled != 60 {
		t.Fatalf("denied reservation leaked: %+v", v)
	}

	// no event object must reference dgA as settled.
	entries, _ := s.StateEntries(ctx, repo)
	for _, e := range entries {
		if e.Digest == dgA {
			t.Fatal("denied digest must not appear as settled")
		}
	}
}

func TestStoreAdjustRollback(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("100", nil)
	s := env.newStore(b)
	ctx := context.Background()
	const repo = "team-a/app"

	r, err := s.Reserve(ctx, repo, 40, KindUpload, "", PhaseUpload)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	// growth that fits
	if err := s.Adjust(ctx, r, 80, PhaseUpload); err != nil {
		t.Fatalf("adjust: %v", err)
	}
	// growth that exceeds: rolled back to 80
	if err := s.Adjust(ctx, r, 120, PhaseUpload); err == nil {
		t.Fatal("expected quota error from adjust")
	}
	v, _ := s.View(ctx, repo)
	if v.Reserved != 80 {
		t.Fatalf("reservation after rollback = %d, want 80", v.Reserved)
	}
}

func TestStoreCrossReplicaReserveRecheck(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("100", nil)
	s1 := env.newStore(b)
	s2 := env.newStore(b) // second "replica", same backend, no shared cache
	ctx := context.Background()
	const repo = "team-a/app"

	r1, err := s1.Reserve(ctx, repo, 60, KindUpload, dgA, PhaseUpload)
	if err != nil {
		t.Fatalf("replica1 reserve: %v", err)
	}
	// replica2 has no in-process knowledge of r1 but reloads the log.
	if _, err := s2.Reserve(ctx, repo, 60, KindMount, dgB, PhaseMount); err == nil {
		t.Fatal("replica2 must observe replica1 reservation and be denied")
	}
	v, _ := s2.View(ctx, repo)
	if v.Reserved != 60 {
		t.Fatalf("total reserved = %d, want 60", v.Reserved)
	}
	if err := s1.Settle(ctx, r1, dgA, RoleLayer, 60); err != nil {
		t.Fatalf("settle: %v", err)
	}
	// now exactly 40 remain: a 40 reservation succeeds, 41 fails.
	if _, err := s2.Reserve(ctx, repo, 40, KindMount, dgB, PhaseMount); err != nil {
		t.Fatalf("boundary reserve should succeed: %v", err)
	}
}

func TestStoreRestartReplay(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("1GiB", nil)
	s := env.newStore(b)
	ctx := context.Background()
	const repo = "team-a/app"

	r1, _ := s.Reserve(ctx, repo, 100, KindUpload, dgA, PhaseUpload)
	_ = s.Settle(ctx, r1, dgA, RoleLayer, 100)
	r2, _ := s.Reserve(ctx, repo, 30, KindMount, dgB, PhaseMount)
	_ = s.Release(ctx, r2)

	// simulate process restart: fresh store, empty caches.
	restarted := env.newStore(b)
	v, _ := restarted.View(ctx, repo)
	if v.Settled != 100 || v.Reserved != 0 {
		t.Fatalf("after restart: %+v", v)
	}
}

func TestStoreCompactionAndSnapshotRecovery(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("100GiB", nil)
	s := env.newStore(b, WithCompactionThreshold(4))
	ctx := context.Background()
	const repo = "team-a/app"

	// generate more events than the threshold.
	for i := 0; i < 5; i++ {
		d := digest.FromString(fmt.Sprintf("blob-%d", i))
		r, err := s.Reserve(ctx, repo, 10, KindUpload, d, PhaseUpload)
		if err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
		if err := s.Settle(ctx, r, d, RoleLayer, 10); err != nil {
			t.Fatalf("settle %d: %v", i, err)
		}
	}

	snapDir, _ := s.paths.snapshotsDir(repo)
	snaps, err := env.drvr.List(ctx, snapDir)
	if err != nil || len(snaps) == 0 {
		t.Fatalf("expected snapshot objects, got %v (err=%v)", snaps, err)
	}

	// fresh store replays snapshot + remaining events.
	restarted := env.newStore(b, WithCompactionThreshold(4))
	v, _ := restarted.View(ctx, repo)
	if v.Settled != 50 {
		t.Fatalf("settled after restart = %d, want 50", v.Settled)
	}
	entries, _ := restarted.StateEntries(ctx, repo)
	if len(entries) != 5 {
		t.Fatalf("entries = %d, want 5", len(entries))
	}
}

func TestStoreCorruptSnapshotFallback(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("100GiB", nil)
	// high threshold: events are retained, no automatic compaction.
	s := env.newStore(b, WithCompactionThreshold(10000))
	ctx := context.Background()
	const repo = "team-a/app"

	r, _ := s.Reserve(ctx, repo, 100, KindUpload, dgA, PhaseUpload)
	_ = s.Settle(ctx, r, dgA, RoleLayer, 100)

	// plant a corrupt snapshot object with the newest name.
	obj, _ := s.paths.snapshotObject(repo, "ffffffffffffffff-ffff")
	if err := env.drvr.PutContent(ctx, obj, []byte("{not-json")); err != nil {
		t.Fatalf("plant snapshot: %v", err)
	}

	restarted := env.newStore(b, WithCompactionThreshold(10000))
	v, _ := restarted.View(ctx, repo)
	if v.Settled != 100 {
		t.Fatalf("fallback replay settled = %d, want 100", v.Settled)
	}
}

func TestStoreDeleteRepository(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("1GiB", nil)
	s := env.newStore(b)
	ctx := context.Background()
	const repo = "team-a/app"

	r, _ := s.Reserve(ctx, repo, 100, KindUpload, dgA, PhaseUpload)
	_ = s.Settle(ctx, r, dgA, RoleLayer, 100)

	if err := s.DeleteRepository(ctx, repo); err != nil {
		t.Fatalf("delete: %v", err)
	}
	dir, _ := s.paths.repoDir(repo)
	if _, err := env.drvr.Stat(ctx, dir); err == nil {
		t.Fatal("ledger directory still present after delete")
	}
	// idempotent
	if err := s.DeleteRepository(ctx, repo); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	v, _ := s.View(ctx, repo)
	if v.Settled != 0 || v.Reserved != 0 {
		t.Fatalf("state after delete: %+v", v)
	}
}

func TestStorePathsMatchDriverRegexp(t *testing.T) {
	env := newTestEnv(t)
	s, _ := New(env.drvr, nil)
	ctx := context.Background()
	const repo = "team-a/sub/app"

	r, err := s.Reserve(ctx, repo, 1, KindUpload, dgA, PhaseUpload)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	evObj, _ := s.paths.eventObject(repo, r.ID)
	snapObj, _ := s.paths.snapshotObject(repo, "0123456789abcdef-0001")
	for _, p := range []string{evObj, snapObj, path.Dir(evObj), path.Dir(snapObj)} {
		if !driver.PathRegexp.MatchString(p) {
			t.Errorf("path %q does not match driver PathRegexp", p)
		}
	}
}

type countingDriver struct {
	driver.StorageDriver
	mu        sync.Mutex
	put, get  int
	list, del int
}

func (c *countingDriver) PutContent(ctx context.Context, p string, content []byte) error {
	c.mu.Lock()
	c.put++
	c.mu.Unlock()
	return c.StorageDriver.PutContent(ctx, p, content)
}
func (c *countingDriver) GetContent(ctx context.Context, p string) ([]byte, error) {
	c.mu.Lock()
	c.get++
	c.mu.Unlock()
	return c.StorageDriver.GetContent(ctx, p)
}
func (c *countingDriver) List(ctx context.Context, p string) ([]string, error) {
	c.mu.Lock()
	c.list++
	c.mu.Unlock()
	return c.StorageDriver.List(ctx, p)
}
func (c *countingDriver) Delete(ctx context.Context, p string) error {
	c.mu.Lock()
	c.del++
	c.mu.Unlock()
	return c.StorageDriver.Delete(ctx, p)
}

func TestStoreWarmPathConstantCost(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("100GiB", nil)
	cd := &countingDriver{StorageDriver: inmemory.New()}
	now := env.now
	s, err := New(cd, b, withNow(func() time.Time { return now }), withIDGen(env.newID), WithCompactionThreshold(4))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	const repo = "team-a/app"

	// seed a compacted history
	for i := 0; i < 10; i++ {
		d := digest.FromString(fmt.Sprintf("seed-%d", i))
		r, _ := s.Reserve(ctx, repo, 10, KindUpload, d, PhaseUpload)
		_ = s.Settle(ctx, r, d, RoleLayer, 10)
	}

	cd.mu.Lock()
	getBefore, listBefore := cd.get, cd.list
	cd.mu.Unlock()

	// one more reserve on the warm, compacted ledger must be a small constant
	// number of reads, independent of the 20 prior events.
	_, _ = s.Reserve(ctx, repo, 10, KindMount, dgB, PhaseMount)

	cd.mu.Lock()
	getAfter, listAfter := cd.get, cd.list
	cd.mu.Unlock()

	gets, lists := getAfter-getBefore, listAfter-listBefore
	if gets > 4 || lists > 4 {
		t.Fatalf("warm reserve cost too high: %d gets, %d lists", gets, lists)
	}
}

func TestStoreConcurrentReservations(t *testing.T) {
	env := newTestEnv(t)
	b, _ := NewBudgets("100", nil)
	s := env.newStore(b)
	ctx := context.Background()
	const repo = "team-a/app"

	var wg sync.WaitGroup
	accepted, denied := make(chan int64, 20), make(chan struct{}, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := digest.FromString(fmt.Sprintf("c-%d", i))
			r, err := s.Reserve(ctx, repo, 10, KindUpload, d, PhaseUpload)
			if err != nil {
				denied <- struct{}{}
				return
			}
			accepted <- r.Size
		}(i)
	}
	wg.Wait()
	close(accepted)
	close(denied)

	var total int64
	for sz := range accepted {
		total += sz
	}
	if total > 100 {
		t.Fatalf("accepted reservation total %d exceeds budget", total)
	}
	v, _ := s.View(ctx, repo)
	if v.Reserved != total {
		t.Fatalf("reserved %d != accepted total %d", v.Reserved, total)
	}
}

func asQuota(err error, target **ErrQuotaExceeded) bool {
	if err == nil {
		return false
	}
	if qe, ok := err.(*ErrQuotaExceeded); ok {
		*target = qe
		return true
	}
	return false
}

var _ = sort.Strings
