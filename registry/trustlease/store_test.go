package trustlease

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
)

const testLeasePath = "/trustleases/leases.json"

func newTestStore(t *testing.T) (*Store, *Manager) {
	t.Helper()
	m := NewManager()
	s, err := NewStore(inmemory.New(), testLeasePath, m)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, m
}

func TestNewStoreRejectsInvalidPath(t *testing.T) {
	driver := inmemory.New()
	if _, err := NewStore(driver, "relative/path", NewManager()); err == nil {
		t.Fatal("expected error for relative path")
	}
	if _, err := NewStore(nil, testLeasePath, NewManager()); err == nil {
		t.Fatal("expected error for nil driver")
	}
	if _, err := NewStore(driver, testLeasePath, nil); err == nil {
		t.Fatal("expected error for nil manager")
	}
}

func TestLoadMissingDocument(t *testing.T) {
	s, m := newTestStore(t)
	changed, err := s.Load(context.Background())
	if err != nil || changed {
		t.Fatalf("Load missing document: changed=%v err=%v", changed, err)
	}
	if m.Version() != 0 {
		t.Fatalf("expected no active version, got %d", m.Version())
	}
}

func TestPublishLoadAndIdempotentReload(t *testing.T) {
	ctx := context.Background()
	driver := inmemory.New()
	m1 := NewManager()
	s1, err := NewStore(driver, testLeasePath, m1)
	if err != nil {
		t.Fatal(err)
	}

	v1 := validDoc(1, Lease{Repository: "a/b", Allow: []string{"^https?://v1"}})
	if err := s1.Publish(ctx, v1); err != nil {
		t.Fatalf("Publish v1: %v", err)
	}
	if m1.Version() != 1 {
		t.Fatalf("expected version 1 active, got %d", m1.Version())
	}

	// Repeated loads of the same persisted document do not change results.
	changed, err := s1.Load(ctx)
	if err != nil || changed {
		t.Fatalf("repeat Load: changed=%v err=%v", changed, err)
	}

	// Repeated publish of the same content is also an idempotent no-op.
	if err := s1.Publish(ctx, v1); err != nil {
		t.Fatalf("republish v1: %v", err)
	}

	// Simulate a process restart: new manager loading from the same storage
	// observes the same version and reaches the same decisions.
	m2 := NewManager()
	s2, err := NewStore(driver, testLeasePath, m2)
	if err != nil {
		t.Fatal(err)
	}
	changed, err = s2.Load(ctx)
	if err != nil || !changed {
		t.Fatalf("restart Load: changed=%v err=%v", changed, err)
	}
	if m2.Version() != 1 {
		t.Fatalf("restart: expected version 1, got %d", m2.Version())
	}
	allow, _, ok := m2.Policy("a/b")
	if !ok || allow == nil || !allow.MatchString("http://v1/x") {
		t.Fatal("restart: lease policy differs from persisted document")
	}
}

func TestPublishVersionGuards(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)

	if err := s.Publish(ctx, validDoc(1, Lease{Repository: "a/b", Allow: []string{"^https?://v1"}})); err != nil {
		t.Fatal(err)
	}

	// Stale version rejected.
	err := s.Publish(ctx, validDoc(1, Lease{Repository: "a/b", Allow: []string{"^https?://v0"}}))
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("same version different content: expected conflict, got %v", err)
	}
	if err := s.Publish(ctx, validDoc(0, Lease{Repository: "a/b", Allow: []string{".*"}})); err == nil {
		t.Fatal("expected invalid version zero to be rejected")
	}

	// Invalid document is rejected before storage is touched.
	err = s.Publish(ctx, validDoc(2, Lease{Repository: "a/b", Allow: []string{"["}}))
	if err == nil {
		t.Fatal("expected invalid regexp to be rejected")
	}

	// The persisted document must still be v1.
	if changed, err := s.Load(ctx); err != nil || changed {
		t.Fatalf("after rejected publish: changed=%v err=%v", changed, err)
	}
}

func TestLoadCorruptDocumentKeepsPreviousVersion(t *testing.T) {
	ctx := context.Background()
	driver := inmemory.New()
	m := NewManager()
	s, err := NewStore(driver, testLeasePath, m)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Publish(ctx, validDoc(1, Lease{Repository: "a/b", Allow: []string{"^https?://v1"}})); err != nil {
		t.Fatal(err)
	}

	// A bad document delivered to storage (for example, a torn write from
	// another tooling path) must not replace the active version.
	if err := driver.PutContent(ctx, testLeasePath, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx); err == nil {
		t.Fatal("expected parse error from Load")
	}
	if m.Version() != 1 {
		t.Fatalf("corrupt document changed active version to %d", m.Version())
	}
	allow, _, ok := m.Policy("a/b")
	if !ok || !allow.MatchString("http://v1/x") {
		t.Fatal("previous version lost after loading corrupt document")
	}
}

func TestStartRefreshPicksUpNewVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	driver := inmemory.New()
	m := NewManager()
	s, err := NewStore(driver, testLeasePath, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx); err != nil {
		t.Fatal(err)
	}

	var refreshErr error
	s.StartRefresh(ctx, 10*time.Millisecond, func(err error) { refreshErr = err })

	// Deliver v2 through another process sharing the same storage.
	other, err := NewStore(driver, testLeasePath, NewManager())
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Publish(ctx, validDoc(2, Lease{Repository: "a/b", Allow: []string{"^https?://v2"}})); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.Version() == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if m.Version() != 2 {
		t.Fatalf("refresh did not pick up v2, active version=%d err=%v", m.Version(), refreshErr)
	}
	allow, _, ok := m.Policy("a/b")
	if !ok || !allow.MatchString("http://v2/x") {
		t.Fatal("refreshed lease policy not in effect")
	}
}
