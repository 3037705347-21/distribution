package trustlease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
)

// Store delivers trust lease documents through a storage driver. Persisting
// documents in the registry storage means every registry process restarted
// against the same storage reloads the same document and therefore reaches the
// same trust decisions.
type Store struct {
	driver storagedriver.StorageDriver
	path   string
	mgr    *Manager
}

// NewStore returns a Store reading and writing the lease document at path
// inside the given storage driver. Path must be an absolute storage path.
func NewStore(driver storagedriver.StorageDriver, path string, mgr *Manager) (*Store, error) {
	if driver == nil {
		return nil, errors.New("trust lease store requires a storage driver")
	}
	if mgr == nil {
		return nil, errors.New("trust lease store requires a manager")
	}
	if !storagedriver.PathRegexp.MatchString(path) {
		return nil, fmt.Errorf("invalid trust lease document path %q", path)
	}
	return &Store{driver: driver, path: path, mgr: mgr}, nil
}

// Load reads the document from storage and installs it into the manager.
//
// A missing document is not an error: changed is false and no document is
// installed. Otherwise Manager.Replace semantics apply: a same-version
// identical document is a no-op (so repeated loads, including after a process
// restart, do not change results), an unreadable or invalid document returns an
// error and leaves the previously active version in place.
func (s *Store) Load(ctx context.Context) (changed bool, err error) {
	content, err := s.driver.GetContent(ctx, s.path)
	if err != nil {
		var notFound storagedriver.PathNotFoundError
		if errors.As(err, &notFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read trust lease document from %q: %w", s.path, err)
	}

	var doc Document
	if err := json.Unmarshal(content, &doc); err != nil {
		return false, fmt.Errorf("failed to parse trust lease document at %q: %w", s.path, err)
	}

	return s.mgr.Replace(&doc)
}

// Publish validates a document, persists it to storage and installs it into
// the manager. A stale or version-conflicting document is rejected before
// anything is written. Republishing the active version with identical content
// is an idempotent no-op. The persisted document is the source of truth picked
// up by Load (for example, after a restart or a periodic refresh).
func (s *Store) Publish(ctx context.Context, doc *Document) error {
	// Validate and compile before touching storage.
	next, err := compile(doc)
	if err != nil {
		return err
	}

	// Refuse to regress or redefine a version that is already installed.
	if cur := s.mgr.cur.Load(); cur != nil {
		switch {
		case next.version < cur.version:
			return fmt.Errorf("%w: active version is %d", ErrStaleVersion, cur.version)
		case next.version == cur.version && next.digest != cur.digest:
			return fmt.Errorf("%w: version %d already active with different content", ErrVersionConflict, cur.version)
		case next.version == cur.version:
			// Same content is already active and was persisted by the call
			// that installed it.
			return nil
		}
	}

	// Enforce the same monotonicity against the persisted document, which is
	// what a restarted process or another replica would load.
	if existing, err := s.readDocument(ctx); err != nil {
		return err
	} else if existing != nil {
		switch {
		case next.version < existing.version:
			return fmt.Errorf("%w: persisted version is %d", ErrStaleVersion, existing.version)
		case next.version == existing.version && next.digest != existing.digest:
			return fmt.Errorf("%w: version %d already persisted with different content", ErrVersionConflict, existing.version)
		case next.version == existing.version:
			// Already persisted with identical content; just make sure the
			// manager has it installed.
			_, err := s.mgr.Replace(doc)
			return err
		}
	}

	content, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to encode trust lease document: %w", err)
	}

	if err := s.driver.PutContent(ctx, s.path, content); err != nil {
		return fmt.Errorf("failed to persist trust lease document to %q: %w", s.path, err)
	}

	// Install from the same validated content that was persisted.
	if _, err := s.mgr.Replace(doc); err != nil {
		return err
	}
	return nil
}

// readDocument loads and compiles the persisted document, returning nil without
// an error when no document is stored yet.
func (s *Store) readDocument(ctx context.Context) (*snapshot, error) {
	content, err := s.driver.GetContent(ctx, s.path)
	if err != nil {
		var notFound storagedriver.PathNotFoundError
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read trust lease document from %q: %w", s.path, err)
	}

	var doc Document
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse trust lease document at %q: %w", s.path, err)
	}
	return compile(&doc)
}

// StartRefresh periodically reloads the document until ctx is canceled. A
// non-positive interval disables periodic refresh; the document can still be
// loaded explicitly with Load. Refresh errors are reported through onError
// (which may be nil) and never stop the loop: a broken document simply leaves
// the previous version active.
func (s *Store) StartRefresh(ctx context.Context, interval time.Duration, onError func(error)) {
	if interval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.Load(ctx); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}
