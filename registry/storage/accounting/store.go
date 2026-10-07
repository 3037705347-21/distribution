package accounting

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"sync"
	"time"

	"github.com/distribution/distribution/v3/internal/dcontext"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
)

// defaultCompactionThreshold is the number of post-snapshot events tolerated
// before a repository ledger is compacted into a new snapshot.
const defaultCompactionThreshold = 64

// Reservation is a handle returned by Store.Reserve.
type Reservation struct {
	ID     string
	Repo   string
	Size   int64
	Kind   Kind
	Digest digest.Digest
}

// View is a point-in-time projected ledger view for one repository.
type View struct {
	Repository string
	Settled    int64
	Reserved   int64
	Limit      int64
	Limited    bool
}

// Available returns budget minus settled minus reserved; for unlimited
// repositories it returns Unlimited.
func (v View) Available() int64 {
	if !v.Limited {
		return Unlimited
	}
	return v.Limit - v.Settled - v.Reserved
}

// Sink receives ledger change notifications. It is implemented by the
// metrics adapter; nil disables notifications.
type Sink interface {
	Observe(repo string, settled, reserved, limit int64)
	Denied(repo string, phase Phase)
	Forget(repo string)
}

// Option configures a Store.
type Option func(*Store)

// WithRoot overrides the ledger storage root.
func WithRoot(root string) Option {
	return func(s *Store) { s.rootOverride = root }
}

// WithCompactionThreshold sets the post-snapshot event count that triggers
// compaction.
func WithCompactionThreshold(n int) Option {
	return func(s *Store) {
		if n > 0 {
			s.compactThreshold = n
		}
	}
}

// WithSink attaches a metrics/observation sink.
func WithSink(sink Sink) Option {
	return func(s *Store) { s.sink = sink }
}

// withNow overrides the clock (tests).
func withNow(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// withIDGen overrides event id generation (tests).
func withIDGen(gen func(time.Time) string) Option {
	return func(s *Store) { s.newID = gen }
}

// Store persists and serves per-repository ledgers through a storage driver.
// A Store is safe for concurrent use: each repository has an in-process
// mutex; cross-replica races are handled by reloading the whole repository
// ledger after every append (reserve-recheck protocol).
type Store struct {
	driver  storagedriver.StorageDriver
	budgets *Budgets
	paths   *paths

	mu    sync.Map // repo -> *sync.Mutex
	cache sync.Map // repo -> *repoLedger
	sink  Sink

	rootOverride     string
	compactThreshold int
	now              func() time.Time
	newID            func(time.Time) string
}

type repoLedger struct {
	state        *State
	last         marker // newest event marker included
	snapshotAt   marker // marker covered by the loaded snapshot (zero if none)
	pendingCount int    // events newer than snapshotAt
}

// New creates a Store.
func New(d storagedriver.StorageDriver, budgets *Budgets, opts ...Option) (*Store, error) {
	s := &Store{
		driver:           d,
		budgets:          budgets,
		compactThreshold: defaultCompactionThreshold,
		now:              func() time.Time { return time.Now().UTC() },
		newID:            generateEventID,
	}
	for _, o := range opts {
		o(s)
	}
	p, err := newPaths(s.rootOverride)
	if err != nil {
		return nil, err
	}
	s.paths = p
	return s, nil
}

func (s *Store) repoLock(repo string) *sync.Mutex {
	v, _ := s.mu.LoadOrStore(repo, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// newEventID returns a time-sortable unique event identifier.
func (s *Store) eventID() string {
	return s.newID(s.now())
}

func generateEventID(now time.Time) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%016x-%s", now.UnixNano(), hex.EncodeToString(b[:]))
}

// Reserve appends a reserved event and enforces the budget using the
// reserve-recheck protocol: the event is persisted first, then the complete
// repository ledger (including reservations concurrently written by other
// registry replicas) is re-aggregated. If the repository is over budget the
// reservation is immediately released and ErrQuotaExceeded is returned
// before the caller performs any real write.
func (s *Store) Reserve(ctx context.Context, repo string, size int64, kind Kind, dgst digest.Digest, phase Phase) (*Reservation, error) {
	return s.ReserveWithID(ctx, s.eventID(), repo, size, kind, dgst, phase)
}

// ReserveWithID is Reserve with an explicit reservation ID. Upload sessions
// use their upload UUID so reservations can be rebound on resume and
// reconciled against the _uploads directory during crash recovery.
func (s *Store) ReserveWithID(ctx context.Context, id, repo string, size int64, kind Kind, dgst digest.Digest, phase Phase) (*Reservation, error) {
	if size < 0 {
		return nil, fmt.Errorf("accounting: cannot reserve negative size %d", size)
	}
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	if err := s.appendEvent(ctx, Reserved(id, repo, size, kind, dgst, s.now())); err != nil {
		return nil, err
	}

	ledger, err := s.reload(ctx, repo)
	if err != nil {
		return nil, err
	}

	if exceeded, limit := s.overBudget(repo, ledger, size); exceeded {
		if err := s.appendEvent(ctx, Released(s.eventID(), id, repo, s.now())); err != nil {
			return nil, err
		}
		if _, err := s.reload(ctx, repo); err != nil {
			return nil, err
		}
		s.notifyDenied(repo, phase)
		return nil, &ErrQuotaExceeded{
			Repository: repo,
			Phase:      phase,
			Limit:      limit,
			Settled:    ledger.state.SettledBytes(),
			Reserved:   ledger.state.ReservedBytes(),
			Requested:  size,
		}
	}

	s.notify(repo, ledger)
	return &Reservation{ID: id, Repo: repo, Size: size, Kind: kind, Digest: dgst}, nil
}

// Adjust changes a reservation to newSize (high-water growth at PATCH time or
// the final size at commit). Over-budget adjustments are rolled back to the
// previous size and return ErrQuotaExceeded.
func (s *Store) Adjust(ctx context.Context, r *Reservation, newSize int64, phase Phase) error {
	if r == nil {
		return fmt.Errorf("accounting: Adjust called without reservation")
	}
	if newSize < 0 {
		return fmt.Errorf("accounting: cannot adjust reservation to negative size %d", newSize)
	}
	if newSize == r.Size {
		return nil
	}
	mu := s.repoLock(r.Repo)
	mu.Lock()
	defer mu.Unlock()

	ledger, err := s.load(ctx, r.Repo)
	if err != nil {
		return err
	}
	var found bool
	for _, a := range ledger.state.ActiveReservations() {
		if a.ID == r.ID {
			found = true
			break
		}
	}
	if !found {
		return &ErrReservationUnknown{Repository: r.Repo, ID: r.ID}
	}

	oldSize := r.Size
	// A reserved event with the same ID and a later timestamp updates the
	// reservation size via the last-writer-wins hold marker.
	if err := s.appendEvent(ctx, Reserved(r.ID, r.Repo, newSize, r.Kind, r.Digest, s.now())); err != nil {
		return err
	}
	ledger, err = s.reload(ctx, r.Repo)
	if err != nil {
		return err
	}

	if exceeded, limit := s.overBudget(r.Repo, ledger, newSize); exceeded {
		// Roll the reservation back to its previous size with a later event.
		if err := s.appendEvent(ctx, Reserved(r.ID, r.Repo, oldSize, r.Kind, r.Digest, s.now())); err != nil {
			return err
		}
		if _, err := s.reload(ctx, r.Repo); err != nil {
			return err
		}
		s.notifyDenied(r.Repo, phase)
		return &ErrQuotaExceeded{
			Repository: r.Repo,
			Phase:      phase,
			Limit:      limit,
			Settled:    ledger.state.SettledBytes(),
			Reserved:   ledger.state.ReservedBytes(),
			Requested:  newSize,
		}
	}

	r.Size = newSize
	s.notify(r.Repo, ledger)
	return nil
}

// Release cancels a reservation. A nil reservation is a no-op so callers can
// defer it unconditionally. Releasing an unknown or already closed
// reservation is a no-op (idempotent).
func (s *Store) Release(ctx context.Context, r *Reservation) error {
	if r == nil {
		return nil
	}
	mu := s.repoLock(r.Repo)
	mu.Lock()
	defer mu.Unlock()

	if err := s.appendEvent(ctx, Released(s.eventID(), r.ID, r.Repo, s.now())); err != nil {
		return err
	}
	ledger, err := s.reload(ctx, r.Repo)
	if err != nil {
		return err
	}
	s.notify(r.Repo, ledger)
	return nil
}

// Settle converts a reservation into settled usage for the (digest, role)
// natural key. Settling an already present natural key is idempotent: usage
// is not counted twice and the carried reservation is closed.
func (s *Store) Settle(ctx context.Context, r *Reservation, dgst digest.Digest, role Role, size int64) error {
	if r == nil {
		return fmt.Errorf("accounting: Settle called without reservation")
	}
	mu := s.repoLock(r.Repo)
	mu.Lock()
	defer mu.Unlock()

	if err := s.appendEvent(ctx, Settled(s.eventID(), r.ID, r.Repo, dgst, role, size, s.now())); err != nil {
		return err
	}
	ledger, err := s.reload(ctx, r.Repo)
	if err != nil {
		return err
	}
	s.notify(r.Repo, ledger)
	return nil
}

// SettleExplicit records settled usage without a reservation. It is used by
// reconciliation seeding/repair and is idempotent per (digest, role): a
// later event supersedes an earlier one.
func (s *Store) SettleExplicit(ctx context.Context, repo string, dgst digest.Digest, role Role, size int64) error {
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	if err := s.appendEvent(ctx, SettledReconcile(s.eventID(), repo, dgst, role, size, s.now())); err != nil {
		return err
	}
	ledger, err := s.reload(ctx, repo)
	if err != nil {
		return err
	}
	s.notify(repo, ledger)
	return nil
}

// Debit removes a (digest, role) natural key from the repository ledger. It
// is idempotent: debiting an absent key is a no-op and other repositories are
// never touched.
func (s *Store) Debit(ctx context.Context, repo string, dgst digest.Digest, role Role) error {
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	if err := s.appendEvent(ctx, Debited(s.eventID(), repo, dgst, role, s.now())); err != nil {
		return err
	}
	ledger, err := s.reload(ctx, repo)
	if err != nil {
		return err
	}
	s.notify(repo, ledger)
	return nil
}

// ActiveReservation returns the active reservation with the given ID and
// whether it exists. It is used to rebind resumable upload sessions to their
// reservations.
func (s *Store) ActiveReservation(ctx context.Context, repo, id string) (ReservationView, bool, error) {
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	ledger, err := s.load(ctx, repo)
	if err != nil {
		return ReservationView{}, false, err
	}
	for _, a := range ledger.state.ActiveReservations() {
		if a.ID == id {
			return a, true, nil
		}
	}
	return ReservationView{}, false, nil
}

// View returns the current projected ledger state for a repository.
func (s *Store) View(ctx context.Context, repo string) (View, error) {
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	ledger, err := s.load(ctx, repo)
	if err != nil {
		return View{}, err
	}
	limit, limited := s.budgets.Limit(repo)
	return View{
		Repository: repo,
		Settled:    ledger.state.SettledBytes(),
		Reserved:   ledger.state.ReservedBytes(),
		Limit:      limit,
		Limited:    limited,
	}, nil
}

// StateEntries exposes the settled entries of a repository (reconciliation
// support).
func (s *Store) StateEntries(ctx context.Context, repo string) ([]Entry, error) {
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	ledger, err := s.load(ctx, repo)
	if err != nil {
		return nil, err
	}
	return ledger.state.Entries(), nil
}

// DeleteRepository removes all ledger data of a repository and forgets its
// cached state and metrics series.
func (s *Store) DeleteRepository(ctx context.Context, repo string) error {
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	dir, err := s.paths.repoDir(repo)
	if err != nil {
		return err
	}
	if err := s.driver.Delete(ctx, dir); err != nil {
		var pnf storagedriver.PathNotFoundError
		if !errors.As(err, &pnf) {
			return err
		}
	}
	s.cache.Delete(repo)
	if s.sink != nil {
		s.sink.Forget(repo)
	}
	return nil
}

func (s *Store) overBudget(repo string, ledger *repoLedger, requested int64) (bool, int64) {
	limit, limited := s.budgets.Limit(repo)
	if !limited {
		return false, Unlimited
	}
	total := ledger.state.SettledBytes() + ledger.state.ReservedBytes()
	return total > limit, limit
}

func (s *Store) notify(repo string, l *repoLedger) {
	if s.sink == nil {
		return
	}
	limit, limited := s.budgets.Limit(repo)
	if !limited {
		limit = Unlimited
	}
	s.sink.Observe(repo, l.state.SettledBytes(), l.state.ReservedBytes(), limit)
}

func (s *Store) notifyDenied(repo string, phase Phase) {
	if s.sink != nil {
		s.sink.Denied(repo, phase)
	}
}

// appendEvent writes one immutable event object. Every record gets a unique
// time-sortable storage key (Seq); the reservation/operation identity lives
// in the event payload, which for size updates is a reserved event that
// reuses the same reservation ID with a later timestamp.
func (s *Store) appendEvent(ctx context.Context, e Event) error {
	e.Seq = s.eventID()
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	obj, err := s.paths.eventObject(e.Repo, e.Seq)
	if err != nil {
		return err
	}
	return s.driver.PutContent(ctx, obj, data)
}

// load returns the current repository ledger, preferring the in-process
// cache. Callers must hold the repository lock.
func (s *Store) load(ctx context.Context, repo string) (*repoLedger, error) {
	if v, ok := s.cache.Load(repo); ok {
		return v.(*repoLedger), nil
	}
	return s.reload(ctx, repo)
}

// reload rebuilds the ledger from storage (newest complete snapshot plus all
// later events), updates the cache and triggers compaction when needed.
// Callers must hold the repository lock.
func (s *Store) reload(ctx context.Context, repo string) (*repoLedger, error) {
	state, snap, pending, last, err := s.readState(ctx, repo)
	if err != nil {
		return nil, err
	}
	ledger := &repoLedger{state: state, last: last, snapshotAt: snap, pendingCount: pending}
	s.cache.Store(repo, ledger)

	if pending >= s.compactThreshold {
		if err := s.compact(ctx, repo, ledger); err != nil {
			// compaction is best effort: ledger reads remain correct.
			dcontext.GetLogger(ctx).WithError(err).WithField("repository", repo).
				Warn("accounting ledger compaction failed")
		} else if compacted, err := s.reloadAfterCompact(ctx, repo); err == nil {
			ledger = compacted
		}
	}
	return ledger, nil
}

// readState performs the actual storage reads.
func (s *Store) readState(ctx context.Context, repo string) (*State, marker, int, marker, error) {
	snapData, snapMarker, err := s.readSnapshot(ctx, repo)
	if err != nil {
		return nil, marker{}, 0, marker{}, err
	}
	state := NewState()
	if snapData != nil {
		state, err = UnmarshalState(snapData)
		if err != nil {
			return nil, marker{}, 0, marker{}, err
		}
	}

	eventsDir, err := s.paths.eventsDir(repo)
	if err != nil {
		return nil, marker{}, 0, marker{}, err
	}
	names, err := s.driver.List(ctx, eventsDir)
	if err != nil {
		var pnf storagedriver.PathNotFoundError
		if !errors.As(err, &pnf) {
			return nil, marker{}, 0, marker{}, err
		}
		names = nil
	}
	sort.Strings(names)

	pending := 0
	highest := snapMarker
	for _, obj := range names {
		// drivers return full object paths from List.
		data, err := s.driver.GetContent(ctx, obj)
		if err != nil {
			var pnf storagedriver.PathNotFoundError
			if errors.As(err, &pnf) {
				continue // concurrently deleted by compaction
			}
			return nil, marker{}, 0, marker{}, err
		}
		var e Event
		if err := json.Unmarshal(data, &e); err != nil {
			logrus.WithError(err).WithField("path", obj).Warn("accounting: skipping unreadable event object")
			continue
		}
		if !snapMarker.isZero() && !eventAfter(e, snapMarker) {
			continue // already covered by the snapshot
		}
		state.Apply(e)
		pending++
		if eventMarker(e).after(highest) {
			highest = eventMarker(e)
		}
	}
	return state, snapMarker, pending, highest, nil
}

// readSnapshot finds the newest readable complete snapshot for the repo.
func (s *Store) readSnapshot(ctx context.Context, repo string) ([]byte, marker, error) {
	dir, err := s.paths.snapshotsDir(repo)
	if err != nil {
		return nil, marker{}, err
	}
	names, err := s.driver.List(ctx, dir)
	if err != nil {
		var pnf storagedriver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil, marker{}, nil
		}
		return nil, marker{}, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	for _, obj := range names {
		// drivers return full object paths from List.
		data, err := s.driver.GetContent(ctx, obj)
		if err != nil {
			var pnf storagedriver.PathNotFoundError
			if errors.As(err, &pnf) {
				continue
			}
			return nil, marker{}, err
		}
		var sf snapshotFile
		if err := json.Unmarshal(data, &sf); err != nil || sf.Version != snapshotVersion || sf.LastSeq == "" {
			logrus.WithError(err).WithField("path", obj).Warn("accounting: ignoring incomplete or corrupt snapshot")
			continue
		}
		m := marker{At: sf.LastAt, Seq: sf.LastSeq}
		return sf.State, m, nil
	}
	return nil, marker{}, nil
}

// compact writes a snapshot of the current state and prunes covered events
// and older snapshots. Any failure is retryable and never loses data: an
// unreadable snapshot causes readState to fall back to full event replay.
func (s *Store) compact(ctx context.Context, repo string, ledger *repoLedger) error {
	last := ledger.last
	if last.Seq == "" {
		return nil // nothing to snapshot
	}

	stateData, err := ledger.state.Marshal()
	if err != nil {
		return err
	}
	sf := snapshotFile{
		Version: snapshotVersion,
		LastSeq: last.Seq,
		LastAt:  last.At,
		State:   stateData,
	}
	data, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	obj, err := s.paths.snapshotObject(repo, last.Seq)
	if err != nil {
		return err
	}
	if err := s.driver.PutContent(ctx, obj, data); err != nil {
		return err
	}

	// Prune events covered by the snapshot.
	eventsDir, err := s.paths.eventsDir(repo)
	if err != nil {
		return err
	}
	if names, err := s.driver.List(ctx, eventsDir); err == nil {
		for _, obj := range names {
			if path.Base(obj) <= last.Seq {
				if err := s.driver.Delete(ctx, obj); err != nil {
					var pnf storagedriver.PathNotFoundError
					if !errors.As(err, &pnf) {
						logrus.WithError(err).WithField("path", obj).Debug("accounting: pruning old event failed")
					}
				}
			}
		}
	} else {
		var pnf storagedriver.PathNotFoundError
		if !errors.As(err, &pnf) {
			return err
		}
	}

	// Keep only the newest snapshot object.
	snapDir, err := s.paths.snapshotsDir(repo)
	if err != nil {
		return err
	}
	if names, err := s.driver.List(ctx, snapDir); err == nil {
		sort.Strings(names)
		for _, obj := range names {
			if path.Base(obj) >= last.Seq {
				continue
			}
			_ = s.driver.Delete(ctx, obj)
		}
	}
	return nil
}

func (s *Store) reloadAfterCompact(ctx context.Context, repo string) (*repoLedger, error) {
	// Rebuild directly without triggering another compaction pass.
	state, snap, pending, last, err := s.readState(ctx, repo)
	if err != nil {
		return nil, err
	}
	ledger := &repoLedger{state: state, last: last, snapshotAt: snap, pendingCount: pending}
	s.cache.Store(repo, ledger)
	return ledger, nil
}

func eventAfter(e Event, m marker) bool {
	return eventMarker(e).after(m)
}

func eventMarker(e Event) marker {
	return marker{At: e.At, Seq: e.Seq}
}

const snapshotVersion = 1

type snapshotFile struct {
	Version int             `json:"version"`
	LastSeq string          `json:"last_seq"`
	LastAt  time.Time       `json:"last_at"`
	State   json.RawMessage `json:"state"`
}
