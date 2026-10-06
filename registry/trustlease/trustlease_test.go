package trustlease

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func at(t time.Time) *time.Time { return &t }

func validDoc(version uint64, leases ...Lease) *Document {
	return &Document{Version: version, Leases: leases}
}

func TestReplaceAndPolicy(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	now := base
	m := NewManagerWithClock(func() time.Time { return now })

	if m.Version() != 0 {
		t.Fatalf("expected no active version, got %d", m.Version())
	}

	doc := validDoc(1,
		Lease{
			Repository: "library/app",
			Allow:      []string{"^https?://allowed"},
			Deny:       []string{"/blocked"},
		},
		Lease{
			Repository: "window/app",
			Allow:      []string{"^https?://window"},
			NotBefore:  at(base.Add(-time.Hour)),
			NotAfter:   at(base.Add(time.Hour)),
		},
	)

	changed, err := m.Replace(doc)
	if err != nil || !changed {
		t.Fatalf("Replace: changed=%v err=%v", changed, err)
	}
	if m.Version() != 1 {
		t.Fatalf("expected version 1, got %d", m.Version())
	}

	allow, deny, ok := m.Policy("library/app")
	if !ok || allow == nil || deny == nil {
		t.Fatalf("expected active lease for library/app, got ok=%v", ok)
	}
	if !allow.MatchString("http://allowed/x") || allow.MatchString("http://other/x") {
		t.Fatal("allow list does not behave as expected")
	}
	if !deny.MatchString("http://allowed/blocked") {
		t.Fatal("deny list does not behave as expected")
	}

	// Unknown repository: no lease, caller falls back to global policy.
	if _, _, ok := m.Policy("unknown/app"); ok {
		t.Fatal("expected no lease for unknown repository")
	}

	// Lease within its validity window is active.
	if _, _, ok := m.Policy("window/app"); !ok {
		t.Fatal("expected lease to be active inside its validity window")
	}

	// Before the validity window: inactive.
	now = base.Add(-2 * time.Hour)
	if _, _, ok := m.Policy("window/app"); ok {
		t.Fatal("expected lease to be inactive before notBefore")
	}

	// At or after notAfter: expired, inactive.
	now = base.Add(time.Hour)
	if _, _, ok := m.Policy("window/app"); ok {
		t.Fatal("expected lease to be expired at notAfter")
	}
	now = base.Add(2 * time.Hour)
	if _, _, ok := m.Policy("window/app"); ok {
		t.Fatal("expected lease to be expired after notAfter")
	}
}

func TestDenyOnlyLease(t *testing.T) {
	m := NewManager()
	doc := validDoc(1, Lease{
		Repository: "deny/app",
		Deny:       []string{"^https?://evil"},
	})
	if _, err := m.Replace(doc); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	allow, deny, ok := m.Policy("deny/app")
	if !ok {
		t.Fatal("expected active lease")
	}
	if allow != nil {
		t.Fatal("deny-only lease must not install an allow-list")
	}
	if deny == nil || !deny.MatchString("http://evil/x") {
		t.Fatal("deny list not compiled correctly")
	}
}

func TestInvalidDocumentsRejectedWholesale(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	later := base.Add(time.Hour)

	cases := []struct {
		name string
		doc  *Document
	}{
		{"nil document", nil},
		{"zero version", validDoc(0, Lease{Repository: "a/b", Allow: []string{".*"}})},
		{"empty repository", validDoc(1, Lease{Allow: []string{".*"}})},
		{"invalid repository", validDoc(1, Lease{Repository: "Upper/Name", Allow: []string{".*"}})},
		{"bad allow regexp", validDoc(1, Lease{Repository: "a/b", Allow: []string{"["}})},
		{"bad deny regexp", validDoc(1, Lease{Repository: "a/b", Deny: []string{"("}})},
		{"no rules", validDoc(1, Lease{Repository: "a/b"})},
		{"duplicate repository", validDoc(1,
			Lease{Repository: "a/b", Allow: []string{".*"}},
			Lease{Repository: "a/b", Deny: []string{"x"}},
		)},
		{"inverted window", validDoc(1, Lease{
			Repository: "a/b",
			Allow:      []string{".*"},
			NotBefore:  at(later),
			NotAfter:   at(base),
		})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager()
			if _, err := m.Replace(tc.doc); err == nil {
				t.Fatalf("expected validation error for %q", tc.name)
			}
			if m.Version() != 0 {
				t.Fatalf("invalid document must not be installed, got version %d", m.Version())
			}
			if err := Validate(tc.doc); err == nil {
				t.Fatalf("expected Validate to reject %q", tc.name)
			}
		})
	}
}

func TestBadNewDocumentKeepsPreviousVersion(t *testing.T) {
	m := NewManager()
	v1 := validDoc(1, Lease{Repository: "a/b", Allow: []string{"^https?://v1"}})
	if _, err := m.Replace(v1); err != nil {
		t.Fatalf("Replace v1: %v", err)
	}

	// A newer document with one bad lease must not partially override v1.
	v2 := validDoc(2,
		Lease{Repository: "a/b", Allow: []string{"^https?://v2"}},
		Lease{Repository: "c/d", Allow: []string{"["}},
	)
	if _, err := m.Replace(v2); err == nil {
		t.Fatal("expected invalid v2 to be rejected")
	}
	if m.Version() != 1 {
		t.Fatalf("active version changed to %d after invalid document", m.Version())
	}
	allow, _, ok := m.Policy("a/b")
	if !ok || !allow.MatchString("http://v1/x") || allow.MatchString("http://v2/x") {
		t.Fatal("previous version was partially overridden by invalid document")
	}
}

func TestEmptyDocumentRevokesAllLeases(t *testing.T) {
	m := NewManager()
	if _, err := m.Replace(validDoc(1, Lease{Repository: "a/b", Allow: []string{".*"}})); err != nil {
		t.Fatal(err)
	}
	changed, err := m.Replace(validDoc(2))
	if err != nil || !changed {
		t.Fatalf("empty revoke document: changed=%v err=%v", changed, err)
	}
	if _, _, ok := m.Policy("a/b"); ok {
		t.Fatal("expected all leases to be revoked")
	}
}

func TestVersionMonotonicityAndIdempotentReload(t *testing.T) {
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	// Fixed clock keeps v2 (which expires at base) inside its validity window.
	m := NewManagerWithClock(func() time.Time { return base.Add(-time.Hour) })
	v1 := validDoc(1, Lease{Repository: "a/b", Allow: []string{"^https?://v1"}})
	v1Reordered := validDoc(1,
		Lease{Repository: "z/y", Allow: []string{"^https?://zz"}},
		Lease{Repository: "a/b", Allow: []string{"^https?://v1"}},
	)
	v1ReorderedFixed := validDoc(1,
		Lease{Repository: "a/b", Allow: []string{"^https?://v1"}},
		Lease{Repository: "z/y", Allow: []string{"^https?://zz"}},
	)

	if _, err := m.Replace(v1); err != nil {
		t.Fatal(err)
	}

	// Same version, identical content: idempotent no-op even when leases are
	// ordered differently or timestamps are rendered in different zones.
	if changed, err := m.Replace(v1); err != nil || changed {
		t.Fatalf("duplicate load: changed=%v err=%v", changed, err)
	}

	if _, err := m.Replace(validDoc(2, Lease{
		Repository: "a/b",
		Allow:      []string{"^https?://v1"},
		NotAfter:   at(base),
	})); err != nil {
		t.Fatal(err)
	}
	sameInstantOtherZone := validDoc(2, Lease{
		Repository: "a/b",
		Allow:      []string{"^https?://v1"},
		NotAfter:   at(base.In(time.FixedZone("other", 2*3600))),
	})
	if changed, err := m.Replace(sameInstantOtherZone); err != nil || changed {
		t.Fatalf("equivalent document in different time zone: changed=%v err=%v", changed, err)
	}

	// Reordering leases does not change content identity.
	m2 := NewManager()
	if _, err := m2.Replace(v1ReorderedFixed); err != nil {
		t.Fatal(err)
	}
	if changed, err := m2.Replace(v1Reordered); err != nil || changed {
		t.Fatalf("reordered duplicate load: changed=%v err=%v", changed, err)
	}

	// Same version, different content: conflict, active version untouched.
	conflict := validDoc(2, Lease{Repository: "a/b", Allow: []string{"^https?://other"}})
	_, err := m.Replace(conflict)
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("expected ErrVersionConflict, got %v", err)
	}
	allow, _, ok := m.Policy("a/b")
	if !ok || allow == nil || !allow.MatchString("http://v1/x") {
		t.Fatal("conflicting document modified the active version")
	}

	// Newer version installs.
	if _, err := m.Replace(validDoc(3, Lease{Repository: "a/b", Allow: []string{"^https?://v3"}})); err != nil {
		t.Fatalf("Replace v3: %v", err)
	}

	// Older version rejected.
	if _, err := m.Replace(validDoc(1, Lease{Repository: "a/b", Allow: []string{".*"}})); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("expected ErrStaleVersion, got %v", err)
	}
}

// TestReplaceConcurrent ensures concurrent installs converge on the highest
// version without panic or torn reads.
func TestReplaceConcurrent(t *testing.T) {
	m := NewManager()
	const n = 50
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		v := uint64(i)
		go func() {
			defer wg.Done()
			_, _ = m.Replace(validDoc(v, Lease{Repository: "a/b", Allow: []string{".*"}}))
		}()
	}
	wg.Wait()

	if m.Version() != n {
		t.Fatalf("expected highest version %d, got %d", n, m.Version())
	}
	if _, _, ok := m.Policy("a/b"); !ok {
		t.Fatal("expected lease to remain available after concurrent installs")
	}
}
