package revocation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/distribution/distribution/v3/registry/auth"
)

// ruleKey locates the rules applicable to a given token.
type ruleKey struct {
	issuer string
	jti    string
}

// rule is a validated, compiled Entry.
type rule struct {
	// audience is empty for an audience wildcard.
	audience string
	// repository is empty for a repository wildcard.
	repository string
	// actions is nil/empty for an action wildcard.
	actions map[string]struct{}
}

// Snapshot is an immutable, compiled view of a revocation list. Snapshots
// are never mutated after creation; updates are published by replacing the
// whole Snapshot, which makes every read observe either the previous or the
// new complete state, never a partial one.
type Snapshot struct {
	rules map[ruleKey][]rule
}

// Empty returns a snapshot that revokes nothing.
func Empty() *Snapshot {
	return &Snapshot{rules: make(map[ruleKey][]rule)}
}

// Parse decodes, validates and compiles a complete revocation list
// document. The returned error describes the offending field so that
// publishers can correct bad documents; callers must discard the entire
// document on any error and keep their previous snapshot.
func Parse(data []byte) (*Snapshot, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("revocation list is empty")
	}
	if len(data) > MaxListBytes {
		return nil, fmt.Errorf("revocation list is %d bytes, exceeds maximum of %d", len(data), MaxListBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var list List
	if err := decoder.Decode(&list); err != nil {
		return nil, fmt.Errorf("failed to parse revocation list: %w", err)
	}

	// The document must contain exactly one JSON value: trailing data is
	// rejected so that a concatenated or truncated update cannot be
	// partially interpreted.
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("revocation list contains trailing data after the document")
		}
		return nil, fmt.Errorf("failed to parse revocation list: %w", err)
	}

	if list.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported revocation list version %d, expected %d", list.Version, CurrentVersion)
	}
	if list.Revoked == nil {
		return nil, fmt.Errorf("revocation list is missing the required %q field", "revoked")
	}

	entries := *list.Revoked
	snapshot := &Snapshot{rules: make(map[ruleKey][]rule, len(entries))}

	for i, entry := range entries {
		compiled, err := compileRule(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid revoked entry %d: %w", i, err)
		}
		key := ruleKey{issuer: entry.Issuer, jti: entry.JWTID}
		snapshot.rules[key] = append(snapshot.rules[key], compiled)
	}

	return snapshot, nil
}

func compileRule(entry Entry) (rule, error) {
	if strings.TrimSpace(entry.Issuer) == "" {
		return rule{}, fmt.Errorf("%q must be a non-empty string", "iss")
	}
	if strings.TrimSpace(entry.JWTID) == "" {
		return rule{}, fmt.Errorf("%q must be a non-empty string", "jti")
	}

	var actions map[string]struct{}
	if len(entry.Actions) > 0 {
		actions = make(map[string]struct{}, len(entry.Actions))
		for _, action := range entry.Actions {
			switch action {
			case ActionPull, ActionPush:
			default:
				return rule{}, fmt.Errorf("action %q is not allowed, only %q and %q are supported", action, ActionPull, ActionPush)
			}
			if _, exists := actions[action]; exists {
				return rule{}, fmt.Errorf("action %q is listed more than once", action)
			}
			actions[action] = struct{}{}
		}
	}

	return rule{
		audience:   entry.Audience,
		repository: entry.Repository,
		actions:    actions,
	}, nil
}

// IsRevoked reports whether the given request is denied by this snapshot for
// the token identified by issuer, jti and its audience claim values. Every
// selector of at least one compiled rule must match: an empty audience
// matches any token, an empty repository matches any resource, and an empty
// action set matches any action. A repository selector only matches
// resources of type "repository". A nil snapshot revokes nothing.
func (s *Snapshot) IsRevoked(issuer, jti string, audiences []string, resource auth.Resource, action string) bool {
	if s == nil {
		return false
	}

	rules, ok := s.rules[ruleKey{issuer: issuer, jti: jti}]
	if !ok {
		return false
	}

	for _, candidate := range rules {
		if candidate.audience != "" && !slices.Contains(audiences, candidate.audience) {
			continue
		}
		if candidate.repository != "" {
			if resource.Type != RepositoryResourceType || resource.Name != candidate.repository {
				continue
			}
		}
		if len(candidate.actions) > 0 {
			if _, ok := candidate.actions[action]; !ok {
				continue
			}
		}
		return true
	}

	return false
}
