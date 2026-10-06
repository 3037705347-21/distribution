package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
)

// This file implements the migration ledger: the durable, per-repository and
// per-digest progress store used by the offline storage backend migration
// (see `registry migrate`).
//
// The ledger lives on the destination driver under a reserved prefix that is
// outside the /v2/blobs and /v2/repositories trees, so regular registry
// traffic and garbage collection never touch it. Every record is a small JSON
// document committed via a write-temp-then-Move sequence: readers therefore
// never observe a half-written record and a crash before Move leaves the
// previous committed version in place.
//
// A single migration runner is expected to be active at a time (enforced
// best-effort by the advisory lock), so record mutations are additionally
// serialized in-process by keyed mutexes and records carry monotonic version
// numbers.

const (
	// defaultMigrationPrefix is the reserved destination prefix under which
	// the ledger, the temp staging area and the cutover marker are stored.
	defaultMigrationPrefix = "/docker/registry/migration/v1"

	migrationSchemaVersion = 1

	// defaultLockTTL is how long a lock heartbeat remains fresh. A second
	// runner must not take over a fresh lock; an expired lock may be taken
	// over explicitly.
	defaultLockTTL = 90 * time.Second
)

// migrationState is the lifecycle state of any migration unit (a global blob,
// a per-repository link, a tag, an upload session, a repository itself).
type migrationState string

const (
	statePending     migrationState = "pending"
	stateInProgress  migrationState = "in_progress"
	stateCompleted   migrationState = "completed"
	stateQuarantined migrationState = "quarantined"
	stateConflict    migrationState = "conflict"
	stateSkipped     migrationState = "skipped"
)

// migrationOrigins record how a completed blob got onto the destination.
const (
	originCopied = "copied" // streamed from the source and verified
	originReused = "reused" // pre-existing destination object verified and reused
)

// allowedMigrationTransitions is the explicit state machine for migration
// units. Retrying a failed in_progress unit returns it to pending; verify may
// demote a completed unit that no longer validates; terminal quarantine and
// conflict states can only be left by an explicit retry.
var allowedMigrationTransitions = map[migrationState]map[migrationState]bool{
	"": {
		statePending: true, stateInProgress: true, stateCompleted: true,
		stateQuarantined: true, stateConflict: true, stateSkipped: true,
	},
	statePending: {
		stateInProgress: true, stateCompleted: true,
		stateQuarantined: true, stateConflict: true, stateSkipped: true,
	},
	stateInProgress: {
		statePending: true, stateInProgress: true, stateCompleted: true,
		stateQuarantined: true, stateConflict: true, stateSkipped: true,
	},
	stateCompleted: {
		stateInProgress: true, stateQuarantined: true, stateConflict: true,
	},
	stateQuarantined: {
		statePending: true, stateInProgress: true, stateConflict: true,
	},
	stateConflict: {
		statePending: true, stateInProgress: true, stateQuarantined: true,
		// A deterministic re-verification after operator repair may complete
		// a conflicting unit directly.
		stateCompleted: true,
	},
	stateSkipped: {
		statePending: true,
	},
}

// Migration errors. Callers (notably the CLI layer) can detect lock
// contention with errors.Is.
var (
	ErrMigrationLocked         = errors.New("migration ledger is locked by another run")
	ErrMigrationInvalidTransit = errors.New("invalid migration state transition")
	ErrMigrationInvalidPath    = errors.New("migration ledger path rejected by driver path rules")
	ErrMigrationLockExpired    = errors.New("migration lock has expired")
)

// migrationErrorEvent is one timestamped failure attached to a unit record.
type migrationErrorEvent struct {
	At      time.Time `json:"at"`
	Message string    `json:"message"`
}

// blobRecord is the global, content-addressed migration unit. One record
// exists per digest regardless of how many repositories reference the blob.
type blobRecord struct {
	SchemaVersion int `json:"schema_version"`

	Algorithm    string `json:"algorithm"`
	Hex          string `json:"hex"`
	Digest       string `json:"digest"`
	ExpectedSize int64  `json:"expected_size"`

	State  migrationState `json:"state"`
	Origin string         `json:"origin,omitempty"` // copied | reused

	// TempPath/CommittedOffset/HashState support resumable streaming copies.
	// HashState is the marshaled digester state at CommittedOffset, mirroring
	// the registry's own resumable-upload hashstate mechanism.
	TempPath        string `json:"temp_path,omitempty"`
	CommittedOffset int64  `json:"committed_offset,omitempty"`
	HashState       []byte `json:"hash_state,omitempty"`

	// Refs is the sorted, de-duplicated set of repositories known to link
	// this blob; it is evidence for the copy-once/share-many guarantee.
	Refs []string `json:"refs,omitempty"`

	Attempts int    `json:"attempts"`
	RunID    string `json:"run_id,omitempty"`

	ObservedDigest string `json:"observed_digest,omitempty"`
	ObservedSize   int64  `json:"observed_size,omitempty"`

	FirstSeen  time.Time             `json:"first_seen"`
	LastUpdate time.Time             `json:"last_update"`
	Errors     []migrationErrorEvent `json:"errors,omitempty"`

	// Version is a monotonically increasing CAS token for the document.
	Version int64 `json:"version"`
}

// migrationSubUnit is a per-repository unit state: a layer link, a manifest
// revision link, or one tag index entry. Target is the digest contained in
// the link file. Gone marks a unit that an earlier discovery saw but the
// latest source sweep no longer contains; it is annotated, never deleted.
type migrationSubUnit struct {
	State      migrationState        `json:"state"`
	Target     string                `json:"target,omitempty"`
	Gone       bool                  `json:"gone,omitempty"`
	Attempts   int                   `json:"attempts,omitempty"`
	Errors     []migrationErrorEvent `json:"errors,omitempty"`
	LastUpdate time.Time             `json:"last_update,omitempty"`
}

// migrationTagUnit captures one tag: its current/link digest and the set of
// index/.../link entries (manually retained tag history).
type migrationTagUnit struct {
	HasCurrent   bool                      `json:"has_current,omitempty"`
	Current      string                    `json:"current"`
	CurrentState migrationState            `json:"current_state"`
	Gone         bool                      `json:"gone,omitempty"`
	Index        map[string]migrationState `json:"index,omitempty"`
	IndexGone    map[string]bool           `json:"index_gone,omitempty"`
	Errors       []migrationErrorEvent     `json:"errors,omitempty"`
}

// migrationUploadUnit is an interrupted upload session. Such sessions are
// copied as session state only and are never promoted into the blob store.
type migrationUploadUnit struct {
	State      migrationState        `json:"state"`
	DataSize   int64                 `json:"data_size,omitempty"`
	Files      []string              `json:"files,omitempty"`
	Gone       bool                  `json:"gone,omitempty"`
	Attempts   int                   `json:"attempts,omitempty"`
	Errors     []migrationErrorEvent `json:"errors,omitempty"`
	LastUpdate time.Time             `json:"last_update,omitempty"`

	// Staging bookkeeping for resumable upload-data copies. Upload data is
	// copied as session state only and is never promoted into the blob store.
	TempPath        string `json:"temp_path,omitempty"`
	CommittedOffset int64  `json:"committed_offset,omitempty"`
}

// repoRecord is the single ledger document for one repository.
type repoRecord struct {
	SchemaVersion int `json:"schema_version"`

	Name  string         `json:"name"`
	State migrationState `json:"state"`
	Gone  bool           `json:"gone,omitempty"`

	// Layers and Revisions map the linked digest to its unit state.
	Layers    map[string]migrationSubUnit    `json:"layers,omitempty"`
	Revisions map[string]migrationSubUnit    `json:"revisions,omitempty"`
	Tags      map[string]migrationTagUnit    `json:"tags,omitempty"`
	Uploads   map[string]migrationUploadUnit `json:"uploads,omitempty"`

	FirstSeen  time.Time `json:"first_seen"`
	LastUpdate time.Time `json:"last_update"`

	Version int64 `json:"version"`
}

// quarantineRecord is the durable evidence for a damaged source object or a
// conflicting destination object.
type quarantineRecord struct {
	SchemaVersion int `json:"schema_version"`

	ID   string `json:"id"`
	Kind string `json:"kind"` // e.g. blob-corrupt, blob-conflict, link-dangling, link-malformed
	Repo string `json:"repo,omitempty"`
	Key  string `json:"key"` // digest or source-relative key

	ExpectedDigest string `json:"expected_digest,omitempty"`
	ObservedDigest string `json:"observed_digest,omitempty"`
	ExpectedSize   int64  `json:"expected_size,omitempty"`
	ObservedSize   int64  `json:"observed_size,omitempty"`

	Reason string `json:"reason"`

	FirstSeen  time.Time `json:"first_seen"`
	LastUpdate time.Time `json:"last_update"`

	Resolved   bool      `json:"resolved"`
	Resolution string    `json:"resolution,omitempty"`
	ResolvedAt time.Time `json:"resolved_at,omitempty"`

	Version int64 `json:"version"`
}

// runRecord is the identity and liveness document of a migration run.
type runRecord struct {
	SchemaVersion int `json:"schema_version"`

	RunID             string    `json:"run_id"`
	SourceDriver      string    `json:"source_driver"`
	SourceFingerprint string    `json:"source_fingerprint,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	Heartbeat         time.Time `json:"heartbeat"`
	Phase             string    `json:"phase"`

	Version int64 `json:"version"`
}

// migrationLockRecord is the advisory lock payload.
type migrationLockRecord struct {
	RunID      string    `json:"run_id"`
	Host       string    `json:"host,omitempty"`
	AcquiredAt time.Time `json:"acquired_at"`
	Heartbeat  time.Time `json:"heartbeat"`
	TTLSeconds int64     `json:"ttl_seconds"`
}

// cutoverRecord is the explicit switchover marker. It is written only when
// the migration has converged and the final checks pass.
type cutoverRecord struct {
	SchemaVersion int `json:"schema_version"`

	RunID             string    `json:"run_id"`
	CutoverAt         time.Time `json:"cutover_at"`
	SourceDriver      string    `json:"source_driver"`
	SourceFingerprint string    `json:"source_fingerprint"`

	Counts       map[string]int64 `json:"counts"`
	TotalBytes   int64            `json:"total_bytes"`
	LedgerDigest string           `json:"ledger_digest,omitempty"`
}

// migrationLedger is the ledger storage layer over a destination driver.
type migrationLedger struct {
	drv    driver.StorageDriver
	prefix string
	runID  string

	// locks serializes in-process mutations of one record key.
	locks sync.Map
}

// newMigrationLedger opens a ledger under prefix on drv. An empty prefix
// selects defaultMigrationPrefix.
func newMigrationLedger(drv driver.StorageDriver, prefix string) *migrationLedger {
	if prefix == "" {
		prefix = defaultMigrationPrefix
	}
	return &migrationLedger{
		drv:    drv,
		prefix: strings.TrimSuffix(prefix, "/"),
	}
}

func (l *migrationLedger) lockFor(key string) *sync.Mutex {
	v, _ := l.locks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// ---- paths ----------------------------------------------------------------

func (l *migrationLedger) join(elem ...string) string {
	return path.Join(append([]string{l.prefix}, elem...)...)
}

func (l *migrationLedger) runStatePath() string { return l.join("run", "state.json") }
func (l *migrationLedger) lockPath() string     { return l.join("run", "lock.json") }
func (l *migrationLedger) cutoverPath() string  { return l.join("run", "cutover.json") }

// blobRecordPath returns prefix/blobs/<alg>/<xx>/<hex>.json. Digest components
// are derived with the same rules as the registry blob store, so no ':' ever
// reaches the driver path.
func (l *migrationLedger) blobRecordPath(dgst digest.Digest) (string, error) {
	comps, err := digestPathComponents(dgst, true)
	if err != nil {
		return "", err
	}
	last := len(comps) - 1
	comps[last] = comps[last] + ".json"
	p := l.join(append([]string{"blobs"}, comps...)...)
	return p, checkPath(p)
}

// repoRecordPath returns prefix/repositories/<name>/state.json. Repository
// names follow the reference grammar and therefore only contain driver-safe
// path components.
func (l *migrationLedger) repoRecordPath(name string) (string, error) {
	if err := validateLedgerName(name); err != nil {
		return "", err
	}
	p := l.join("repositories", name, "state.json")
	return p, checkPath(p)
}

func (l *migrationLedger) quarantinePath(id string) string {
	return l.join("quarantine", id+".json")
}

// tempBlobPath returns the staging path for one blob copy attempt.
func (l *migrationLedger) tempBlobPath(dgst digest.Digest, nonce string) (string, error) {
	comps, err := digestPathComponents(dgst, true)
	if err != nil {
		return "", err
	}
	last := len(comps) - 1
	comps[last] = fmt.Sprintf("%s.%s.data", comps[last], nonce)
	p := l.join(append([]string{"tmp", "blobs"}, comps...)...)
	return p, checkPath(p)
}

// tempUploadDataPath returns the staging path for an upload session's data.
// Registry upload ids are UUIDs; defensively reject separators anyway.
func (l *migrationLedger) tempUploadDataPath(repo, uploadID, nonce string) (string, error) {
	if err := validateLedgerName(repo); err != nil {
		return "", err
	}
	if strings.ContainsAny(uploadID, "/\\") || uploadID == "" || uploadID == "." || uploadID == ".." {
		return "", fmt.Errorf("%w: upload id %q", ErrMigrationInvalidPath, uploadID)
	}
	p := l.join("tmp", "uploads", repo, uploadID+"."+nonce+".data")
	return p, checkPath(p)
}

func (l *migrationLedger) tempRoot() string { return l.join("tmp") }

// validateLedgerName ensures a repository name embedded into a ledger path
// can only produce driver-legal paths.
func validateLedgerName(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return fmt.Errorf("%w: repository name %q", ErrMigrationInvalidPath, name)
	}
	for _, comp := range strings.Split(name, "/") {
		if comp == "" || comp == "." || comp == ".." {
			return fmt.Errorf("%w: repository name %q", ErrMigrationInvalidPath, name)
		}
		for _, r := range comp {
			switch {
			case r >= 'a' && r <= 'z',
				r >= '0' && r <= '9',
				r == '.', r == '_', r == '-', r == '/':
			default:
				return fmt.Errorf("%w: component %q", ErrMigrationInvalidPath, comp)
			}
		}
	}
	return nil
}

// checkPath validates any ledger-constructed path against the driver rules.
func checkPath(p string) error {
	if !driver.PathRegexp.MatchString(p) {
		return fmt.Errorf("%w: %s", ErrMigrationInvalidPath, p)
	}
	return nil
}

// ---- JSON plumbing --------------------------------------------------------

func (l *migrationLedger) writeJSONAtomic(ctx context.Context, p string, v any) error {
	if err := checkPath(p); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp-%s", p, uuid.NewString())
	if err := checkPath(tmp); err != nil {
		return err
	}
	if err := l.drv.PutContent(ctx, tmp, b); err != nil {
		return err
	}
	return l.drv.Move(ctx, tmp, p)
}

// readJSON unmarshals the object at p. A missing object returns exists=false.
func (l *migrationLedger) readJSON(ctx context.Context, p string, v any) (bool, error) {
	b, err := l.drv.GetContent(ctx, p)
	if err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return false, nil
		}
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("corrupt ledger document %s: %w", p, err)
	}
	return true, nil
}

// ---- run state and lock ---------------------------------------------------

// initRun loads the run record, creating one (with a fresh run id) when the
// ledger is used for the first time.
func (l *migrationLedger) initRun(ctx context.Context, sourceDriverName, fingerprint string) (*runRecord, error) {
	p := l.runStatePath()
	l.lockFor("run").Lock()
	defer l.lockFor("run").Unlock()

	var rec runRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if !exists {
		rec = runRecord{
			SchemaVersion:     migrationSchemaVersion,
			RunID:             uuid.NewString(),
			SourceDriver:      sourceDriverName,
			SourceFingerprint: fingerprint,
			StartedAt:         now,
			Heartbeat:         now,
			Phase:             "init",
		}
		rec.Version = 1
		if err := l.writeJSONAtomic(ctx, p, &rec); err != nil {
			return nil, err
		}
	}
	l.runID = rec.RunID
	return &rec, nil
}

func (l *migrationLedger) runIDOrNew() string {
	if l.runID != "" {
		return l.runID
	}
	l.runID = uuid.NewString()
	return l.runID
}

// updateRun mutates the run document under the run lock.
func (l *migrationLedger) updateRun(ctx context.Context, fn func(*runRecord)) (*runRecord, error) {
	p := l.runStatePath()
	mu := l.lockFor("run")
	mu.Lock()
	defer mu.Unlock()

	var rec runRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("migration run record missing; initialize the ledger first")
	}
	oldVersion := rec.Version
	fn(&rec)
	rec.Heartbeat = time.Now().UTC()
	rec.Version = oldVersion + 1
	if err := l.writeJSONAtomic(ctx, p, &rec); err != nil {
		return nil, err
	}
	l.runID = rec.RunID
	return &rec, nil
}

// acquireLock takes the advisory lock for this run. A fresh foreign lock is
// rejected; an expired foreign lock may be taken over only with force=true.
func (l *migrationLedger) acquireLock(ctx context.Context, force bool, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultLockTTL
	}
	runID := l.runIDOrNew()
	p := l.lockPath()
	mu := l.lockFor("lock")
	mu.Lock()
	defer mu.Unlock()

	now := time.Now().UTC()
	var existing migrationLockRecord
	exists, err := l.readJSON(ctx, p, &existing)
	if err != nil {
		return err
	}
	if exists && existing.RunID != runID {
		freshUntil := existing.Heartbeat.Add(ttlOf(existing, ttl))
		if now.Before(freshUntil) {
			return fmt.Errorf("%w: held by run %s (heartbeat %s, host %s)",
				ErrMigrationLocked, existing.RunID, existing.Heartbeat.Format(time.RFC3339), existing.Host)
		}
		if !force {
			return fmt.Errorf("%w: lock held by run %s expired at %s; rerun with --force to take it over",
				ErrMigrationLockExpired, existing.RunID, freshUntil.Format(time.RFC3339))
		}
	}

	host, _ := os.Hostname()
	rec := migrationLockRecord{
		RunID:      runID,
		Host:       host,
		AcquiredAt: now,
		Heartbeat:  now,
		TTLSeconds: int64(ttl.Seconds()),
	}
	return l.writeJSONAtomic(ctx, p, &rec)
}

func ttlOf(rec migrationLockRecord, fallback time.Duration) time.Duration {
	if rec.TTLSeconds > 0 {
		return time.Duration(rec.TTLSeconds) * time.Second
	}
	return fallback
}

// heartbeat refreshes the lock, proving this run is still alive.
func (l *migrationLedger) heartbeat(ctx context.Context, ttl time.Duration) error {
	runID := l.runIDOrNew()
	p := l.lockPath()
	mu := l.lockFor("lock")
	mu.Lock()
	defer mu.Unlock()

	var rec migrationLockRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		return err
	}
	if !exists || rec.RunID != runID {
		return ErrMigrationLockExpired
	}
	now := time.Now().UTC()
	rec.Heartbeat = now
	if ttl > 0 {
		rec.TTLSeconds = int64(ttl.Seconds())
	}
	return l.writeJSONAtomic(ctx, p, &rec)
}

// releaseLock removes the lock when it belongs to this run.
func (l *migrationLedger) releaseLock(ctx context.Context) error {
	runID := l.runIDOrNew()
	p := l.lockPath()
	mu := l.lockFor("lock")
	mu.Lock()
	defer mu.Unlock()

	var rec migrationLockRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil
		}
		return err
	}
	if exists && rec.RunID != runID {
		// Never delete another run's lock.
		return nil
	}
	if err := l.drv.Delete(ctx, p); err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil
		}
		return err
	}
	return nil
}

// ---- blob records ---------------------------------------------------------

func (l *migrationLedger) getBlobRecord(ctx context.Context, dgst digest.Digest) (*blobRecord, bool, error) {
	p, err := l.blobRecordPath(dgst)
	if err != nil {
		return nil, false, err
	}
	var rec blobRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	return &rec, true, nil
}

// mutateBlobRecord reads the blob record (creating a pending skeleton when
// create=true and it is absent), applies fn under the record lock, validates
// the resulting state transition and commits the next version.
func (l *migrationLedger) mutateBlobRecord(
	ctx context.Context,
	dgst digest.Digest,
	create bool,
	fn func(*blobRecord) error,
) (*blobRecord, error) {
	p, err := l.blobRecordPath(dgst)
	if err != nil {
		return nil, err
	}
	key := "blob:" + dgst.String()
	mu := l.lockFor(key)
	mu.Lock()
	defer mu.Unlock()

	var rec blobRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		return nil, err
	}
	if !exists {
		if !create {
			return nil, nil
		}
		rec = blobRecord{
			SchemaVersion: migrationSchemaVersion,
			Algorithm:     dgst.Algorithm().String(),
			Hex:           dgst.Encoded(),
			Digest:        dgst.String(),
			State:         statePending,
			FirstSeen:     time.Now().UTC(),
		}
	}
	before := rec.State
	oldVersion := rec.Version
	if err := fn(&rec); err != nil {
		return nil, err
	}
	if rec.State != before && !allowedMigrationTransitions[before][rec.State] {
		return nil, fmt.Errorf("%w: blob %s %s -> %s", ErrMigrationInvalidTransit, dgst, before, rec.State)
	}
	now := time.Now().UTC()
	rec.LastUpdate = now
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	rec.SchemaVersion = migrationSchemaVersion
	rec.Algorithm = dgst.Algorithm().String()
	rec.Hex = dgst.Encoded()
	rec.Digest = dgst.String()
	rec.Version = oldVersion + 1
	if err := l.writeJSONAtomic(ctx, p, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// addBlobRef records that repo links the blob, keeping Refs sorted-unique.
func addBlobRef(rec *blobRecord, repo string) {
	i := sort.SearchStrings(rec.Refs, repo)
	if i < len(rec.Refs) && rec.Refs[i] == repo {
		return
	}
	rec.Refs = append(rec.Refs, "")
	copy(rec.Refs[i+1:], rec.Refs[i:])
	rec.Refs[i] = repo
}

// walkJSON walks root for *.json leaf objects and unmarshals them into v for
// fn. A not-yet-created root (empty ledger section) is not an error.
func (l *migrationLedger) walkJSON(ctx context.Context, root string, fn func(string, []byte) error) error {
	err := l.drv.Walk(ctx, root, func(fi driver.FileInfo) error {
		if fi.IsDir() || !strings.HasSuffix(fi.Path(), ".json") {
			return nil
		}
		b, err := l.drv.GetContent(ctx, fi.Path())
		if err != nil {
			return err
		}
		return fn(fi.Path(), b)
	})
	if err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil
		}
		return err
	}
	return nil
}

// listBlobRecords invokes fn for every blob record in the ledger.
func (l *migrationLedger) listBlobRecords(ctx context.Context, fn func(*blobRecord) error) error {
	return l.walkJSON(ctx, l.join("blobs"), func(_ string, b []byte) error {
		var rec blobRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return err
		}
		return fn(&rec)
	})
}

// ---- repo records ---------------------------------------------------------

func (l *migrationLedger) getRepoRecord(ctx context.Context, name string) (*repoRecord, bool, error) {
	p, err := l.repoRecordPath(name)
	if err != nil {
		return nil, false, err
	}
	var rec repoRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	return &rec, true, nil
}

// mutateRepoRecord is the repo-document counterpart of mutateBlobRecord.
func (l *migrationLedger) mutateRepoRecord(
	ctx context.Context,
	name string,
	create bool,
	fn func(*repoRecord) error,
) (*repoRecord, error) {
	p, err := l.repoRecordPath(name)
	if err != nil {
		return nil, err
	}
	mu := l.lockFor("repo:" + name)
	mu.Lock()
	defer mu.Unlock()

	var rec repoRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		return nil, err
	}
	if !exists {
		if !create {
			return nil, nil
		}
		rec = repoRecord{
			SchemaVersion: migrationSchemaVersion,
			Name:          name,
			State:         statePending,
			Layers:        map[string]migrationSubUnit{},
			Revisions:     map[string]migrationSubUnit{},
			Tags:          map[string]migrationTagUnit{},
			Uploads:       map[string]migrationUploadUnit{},
			FirstSeen:     time.Now().UTC(),
		}
	}
	before := rec.State
	oldVersion := rec.Version
	if err := fn(&rec); err != nil {
		return nil, err
	}
	if rec.State != before && !allowedMigrationTransitions[before][rec.State] {
		return nil, fmt.Errorf("%w: repo %s %s -> %s", ErrMigrationInvalidTransit, name, before, rec.State)
	}
	now := time.Now().UTC()
	rec.LastUpdate = now
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = now
	}
	rec.SchemaVersion = migrationSchemaVersion
	rec.Name = name
	rec.Version = oldVersion + 1
	if err := l.writeJSONAtomic(ctx, p, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// listRepoRecords invokes fn for every repository ledger document.
func (l *migrationLedger) listRepoRecords(ctx context.Context, fn func(*repoRecord) error) error {
	return l.walkJSON(ctx, l.join("repositories"), func(p string, b []byte) error {
		if path.Base(p) != "state.json" {
			return nil
		}
		var rec repoRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return err
		}
		return fn(&rec)
	})
}

// ---- quarantine records ---------------------------------------------------

// quarantine upserts an isolation record. An unresolved record with the same
// kind/repo/key is refreshed rather than duplicated.
func (l *migrationLedger) quarantine(ctx context.Context, rec *quarantineRecord) (*quarantineRecord, error) {
	mu := l.lockFor("quarantine")
	mu.Lock()
	defer mu.Unlock()

	now := time.Now().UTC()
	var existing *quarantineRecord
	err := l.listQuarantineRecords(ctx, func(q *quarantineRecord) error {
		if !q.Resolved && q.Kind == rec.Kind && q.Repo == rec.Repo && q.Key == rec.Key {
			cp := *q
			existing = &cp
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if existing != nil {
		existing.LastUpdate = now
		if rec.Reason != "" {
			existing.Reason = rec.Reason
		}
		if rec.ObservedDigest != "" {
			existing.ObservedDigest = rec.ObservedDigest
		}
		if rec.ObservedSize != 0 {
			existing.ObservedSize = rec.ObservedSize
		}
		existing.Version++
		if err := l.writeJSONAtomic(ctx, l.quarantinePath(existing.ID), existing); err != nil {
			return nil, err
		}
		return existing, nil
	}

	rec.SchemaVersion = migrationSchemaVersion
	if rec.ID == "" {
		rec.ID = uuid.NewString()
	}
	rec.FirstSeen = now
	rec.LastUpdate = now
	rec.Version = 1
	if err := l.writeJSONAtomic(ctx, l.quarantinePath(rec.ID), rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// resolveQuarantine marks an isolation record resolved.
func (l *migrationLedger) resolveQuarantine(ctx context.Context, id, resolution string) error {
	p := l.quarantinePath(id)
	mu := l.lockFor("quarantine:" + id)
	mu.Lock()
	defer mu.Unlock()

	var rec quarantineRecord
	exists, err := l.readJSON(ctx, p, &rec)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("quarantine record %s not found", id)
	}
	rec.Resolved = true
	rec.Resolution = resolution
	rec.ResolvedAt = time.Now().UTC()
	rec.Version++
	return l.writeJSONAtomic(ctx, p, &rec)
}

// resolveQuarantineByKey resolves every unresolved record with the given key.
func (l *migrationLedger) resolveQuarantineByKey(ctx context.Context, key, resolution string) (int, error) {
	var ids []string
	if err := l.listQuarantineRecords(ctx, func(q *quarantineRecord) error {
		if !q.Resolved && q.Key == key {
			ids = append(ids, q.ID)
		}
		return nil
	}); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if err := l.resolveQuarantine(ctx, id, resolution); err != nil {
			return len(ids), err
		}
	}
	return len(ids), nil
}

func (l *migrationLedger) listQuarantineRecords(ctx context.Context, fn func(*quarantineRecord) error) error {
	return l.walkJSON(ctx, l.join("quarantine"), func(_ string, b []byte) error {
		var rec quarantineRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return err
		}
		return fn(&rec)
	})
}

// ---- cutover marker --------------------------------------------------------

func (l *migrationLedger) writeCutover(ctx context.Context, rec *cutoverRecord) error {
	rec.SchemaVersion = migrationSchemaVersion
	return l.writeJSONAtomic(ctx, l.cutoverPath(), rec)
}

func (l *migrationLedger) getCutover(ctx context.Context) (*cutoverRecord, bool, error) {
	var rec cutoverRecord
	exists, err := l.readJSON(ctx, l.cutoverPath(), &rec)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	return &rec, true, nil
}

// ---- temp area -------------------------------------------------------------

// listTempFiles returns every object left under the staging prefix.
func (l *migrationLedger) listTempFiles(ctx context.Context) ([]string, error) {
	var out []string
	err := l.drv.Walk(ctx, l.tempRoot(), func(fi driver.FileInfo) error {
		if fi.IsDir() {
			return nil
		}
		out = append(out, fi.Path())
		return nil
	})
	if err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil, nil
		}
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// recordError appends a timestamped error event, capping retained history.
func recordError(events *[]migrationErrorEvent, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	*events = append(*events, migrationErrorEvent{At: time.Now().UTC(), Message: msg})
	if len(*events) > 20 {
		*events = (*events)[len(*events)-20:]
	}
}
