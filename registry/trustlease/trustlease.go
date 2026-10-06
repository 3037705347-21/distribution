// Package trustlease manages per-repository trust leases for the external URLs
// that may appear in pushed manifests (for example, the URLs of foreign or
// non-distributable layers).
//
// A lease document is the complete set of leases delivered to a registry. It is
// versioned and each lease is bound to a target repository, an URL trust scope
// (allow/deny regular expressions) and an optional validity window.
//
// Replacement of the active document is all-or-nothing: a document is compiled
// and validated in full before it is installed, so a malformed document can
// never partially override the previously active version. Once installed, the
// active document is an immutable snapshot and is published atomically; in
// flight requests keep using the snapshot they started with while subsequent
// requests observe the new document. Loading the same document version again is
// a no-op, so repeated loads and process restarts do not change results.
package trustlease

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// Sentinel errors returned by Manager.Replace. Callers should use errors.Is to
// test for them.
var (
	// ErrStaleVersion is returned when a document carries a version lower than
	// the currently active version.
	ErrStaleVersion = errors.New("trust lease document version is older than the active version")

	// ErrVersionConflict is returned when a document carries the same version
	// as the active document but different content. The active document is
	// left untouched.
	ErrVersionConflict = errors.New("trust lease document version conflicts with the active version")
)

// Document is a complete, versioned set of trust leases.
type Document struct {
	// Version is the monotonically increasing document version. It must be at
	// least 1. A document fully replaces every lease of the previously active
	// version; there is no per-lease merging.
	Version uint64 `json:"version"`

	// Leases is the complete lease set. It may be empty, which explicitly
	// revokes all previously delivered leases.
	Leases []Lease `json:"leases"`
}

// Lease binds a target repository to a time-bounded trust scope for external
// URLs. The allow/deny regular expressions use the same matching semantics as
// the global validation.manifests.urls configuration: when Allow is empty,
// every URL passes the allow check (subject to Deny); otherwise URLs must match
// Allow; URLs matching Deny are always rejected.
type Lease struct {
	// Repository is the canonical repository name the lease applies to.
	Repository string `json:"repository"`

	// Allow specifies regular expressions that external URLs must match.
	Allow []string `json:"allow,omitempty"`

	// Deny specifies regular expressions that external URLs must not match.
	Deny []string `json:"deny,omitempty"`

	// NotBefore, when set, bounds the validity window: the lease is not
	// consumed by requests before this time.
	NotBefore *time.Time `json:"notBefore,omitempty"`

	// NotAfter, when set, bounds the validity window: at or after this time
	// the lease is expired and no longer consumed.
	NotAfter *time.Time `json:"notAfter,omitempty"`
}

// compiledLease is the immutable, compiled representation of a Lease.
type compiledLease struct {
	allow     *regexp.Regexp
	deny      *regexp.Regexp
	notBefore *time.Time
	notAfter  *time.Time
}

// snapshot is an immutable, atomically published view of a validated document.
type snapshot struct {
	version uint64
	digest  digest.Digest
	leases  map[string]*compiledLease
}

// Validate validates a document without installing it. All leases, repository
// names, regular expressions and validity windows are checked, so a returned
// error means the whole document is rejected and no part of it would take
// effect.
func Validate(doc *Document) error {
	_, err := compile(doc)
	return err
}

// compile validates the document and builds the immutable snapshot.
func compile(doc *Document) (*snapshot, error) {
	if doc == nil {
		return nil, errors.New("trust lease document is nil")
	}
	if doc.Version < 1 {
		return nil, errors.New("trust lease document version must be at least 1")
	}

	leases := make(map[string]*compiledLease, len(doc.Leases))
	for i := range doc.Leases {
		l := &doc.Leases[i]

		if l.Repository == "" {
			return nil, fmt.Errorf("trust lease at index %d has an empty repository", i)
		}
		named, err := reference.WithName(l.Repository)
		if err != nil {
			return nil, fmt.Errorf("trust lease at index %d has invalid repository %q: %w", i, l.Repository, err)
		}
		// Only accept canonical names so that lookups by the request's target
		// repository are unambiguous.
		if named.Name() != l.Repository {
			return nil, fmt.Errorf("trust lease at index %d has non-canonical repository %q (expected %q)", i, l.Repository, named.Name())
		}
		if _, exists := leases[l.Repository]; exists {
			return nil, fmt.Errorf("trust lease at index %d duplicates repository %q", i, l.Repository)
		}

		if len(l.Allow) == 0 && len(l.Deny) == 0 {
			return nil, fmt.Errorf("trust lease for repository %q must specify at least one allow or deny rule", l.Repository)
		}

		cl := &compiledLease{
			notBefore: l.NotBefore,
			notAfter:  l.NotAfter,
		}
		if len(l.Allow) > 0 {
			cl.allow, err = compileRuleSet("allow", l.Repository, l.Allow)
			if err != nil {
				return nil, err
			}
		}
		if len(l.Deny) > 0 {
			cl.deny, err = compileRuleSet("deny", l.Repository, l.Deny)
			if err != nil {
				return nil, err
			}
		}

		if l.NotBefore != nil && l.NotAfter != nil && l.NotAfter.Before(*l.NotBefore) {
			return nil, fmt.Errorf("trust lease for repository %q has notAfter before notBefore", l.Repository)
		}

		leases[l.Repository] = cl
	}

	return &snapshot{
		version: doc.Version,
		digest:  canonicalDigest(doc),
		leases:  leases,
	}, nil
}

// compileRuleSet compiles a set of rules into a single alternation
// expression, mirroring the handling of the global URL configuration.
func compileRuleSet(kind, repository string, rules []string) (*regexp.Regexp, error) {
	wrapped := make([]string, 0, len(rules))
	for _, rule := range rules {
		if _, err := regexp.Compile(rule); err != nil {
			return nil, fmt.Errorf("trust lease for repository %q has invalid %s regular expression %q: %w", repository, kind, rule, err)
		}
		wrapped = append(wrapped, "(?:"+rule+")")
	}
	return regexp.MustCompile(strings.Join(wrapped, "|")), nil
}

// canonicalDigest computes a digest over an order-independent, canonical JSON
// rendering of the document. It is used to detect same-version reloads that
// carry identical content regardless of lease ordering or time zone rendering.
func canonicalDigest(doc *Document) digest.Digest {
	type canonicalLease struct {
		Repository string   `json:"repository"`
		Allow      []string `json:"allow,omitempty"`
		Deny       []string `json:"deny,omitempty"`
		NotBefore  string   `json:"notBefore,omitempty"`
		NotAfter   string   `json:"notAfter,omitempty"`
	}
	type canonicalDocument struct {
		Version uint64           `json:"version"`
		Leases  []canonicalLease `json:"leases"`
	}

	canonical := canonicalDocument{Version: doc.Version}
	for i := range doc.Leases {
		l := &doc.Leases[i]
		cl := canonicalLease{
			Repository: l.Repository,
			Allow:      l.Allow,
			Deny:       l.Deny,
		}
		if l.NotBefore != nil {
			cl.NotBefore = l.NotBefore.UTC().Format(time.RFC3339Nano)
		}
		if l.NotAfter != nil {
			cl.NotAfter = l.NotAfter.UTC().Format(time.RFC3339Nano)
		}
		canonical.Leases = append(canonical.Leases, cl)
	}
	sort.Slice(canonical.Leases, func(i, j int) bool {
		return canonical.Leases[i].Repository < canonical.Leases[j].Repository
	})

	content, err := json.Marshal(canonical)
	if err != nil {
		// All inputs are basic types and pre-validated time values, so
		// marshaling cannot fail.
		panic(fmt.Sprintf("failed to marshal canonical trust lease document: %v", err))
	}
	return digest.FromBytes(content)
}

// Manager owns the active trust lease document. It is safe for concurrent use:
// the active document is an immutable snapshot referenced through an atomic
// pointer.
type Manager struct {
	now func() time.Time
	cur atomic.Pointer[snapshot]
}

// NewManager returns a Manager with no active document.
func NewManager() *Manager {
	return NewManagerWithClock(time.Now)
}

// NewManagerWithClock returns a Manager using the supplied clock for validity
// window evaluation. It is primarily intended for tests.
func NewManagerWithClock(now func() time.Time) *Manager {
	return &Manager{now: now}
}

// Replace validates the full document and atomically installs it:
//
//   - A newer version replaces the active snapshot and returns changed=true.
//   - The same version with identical content is an idempotent no-op and
//     returns changed=false, so repeated loads and restarts do not alter
//     results.
//   - The same version with different content returns ErrVersionConflict; the
//     active snapshot is kept.
//   - An older version returns ErrStaleVersion.
//   - Any validation error leaves the previously active snapshot untouched.
func (m *Manager) Replace(doc *Document) (changed bool, err error) {
	next, err := compile(doc)
	if err != nil {
		return false, err
	}

	for {
		cur := m.cur.Load()
		if cur != nil {
			switch {
			case next.version < cur.version:
				return false, ErrStaleVersion
			case next.version == cur.version:
				if next.digest == cur.digest {
					return false, nil
				}
				return false, fmt.Errorf("%w: version %d redefined with different content", ErrVersionConflict, cur.version)
			}
		}

		if m.cur.CompareAndSwap(cur, next) {
			return true, nil
		}
	}
}

// Version returns the version of the active document, or 0 if no document has
// been installed.
func (m *Manager) Version() uint64 {
	if cur := m.cur.Load(); cur != nil {
		return cur.version
	}
	return 0
}

// Policy resolves the effective external URL policy for a target repository.
// ok is false when no lease exists for the repository, the lease has not
// started yet, or it has expired; in that case callers fall back to the
// baseline global policy. A returned allow regexp may be nil, meaning no
// allow-list restriction; deny may be nil, meaning no deny-list.
func (m *Manager) Policy(repository string) (allow, deny *regexp.Regexp, ok bool) {
	cur := m.cur.Load()
	if cur == nil {
		return nil, nil, false
	}
	lease := cur.leases[repository]
	if lease == nil {
		return nil, nil, false
	}

	now := m.now()
	if lease.notBefore != nil && now.Before(*lease.notBefore) {
		return nil, nil, false
	}
	if lease.notAfter != nil && !now.Before(*lease.notAfter) {
		return nil, nil, false
	}

	return lease.allow, lease.deny, true
}
