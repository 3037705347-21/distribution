// Package revocation implements token revocation lists for the bearer token
// authentication backend.
//
// A revocation list is a complete JSON snapshot of all currently revoked
// credentials. Entries are keyed by the token issuer ("iss") and JWT unique
// identifier ("jti") claims and may narrow the revocation to a specific
// audience, repository and set of actions (pull/push). A parsed list is
// compiled into an immutable Snapshot which is safe for concurrent,
// lock-free reads.
package revocation

// CurrentVersion is the only supported revision of the revocation list
// document format.
const CurrentVersion = 1

// MaxListBytes is the maximum accepted size of a revocation list document.
const MaxListBytes = 16 << 20 // 16 MiB

const (
	// RepositoryResourceType is the resource type whose name the optional
	// "repository" selector matches.
	RepositoryResourceType = "repository"

	// ActionPull and ActionPush are the only selectable token actions.
	ActionPull = "pull"
	ActionPush = "push"
)

// List is the on-the-wire revocation list document. It is a complete
// snapshot: every revoked credential currently in effect must be present.
type List struct {
	// Version is the document format version. Must be CurrentVersion.
	Version int `json:"version"`

	// Revoked holds the revocation entries. The field must be present
	// (an empty array is valid) so that an accidentally truncated
	// document cannot be mistaken for an empty revocation list.
	Revoked *[]Entry `json:"revoked"`
}

// Entry describes a single revoked credential. Issuer and JWTID are
// required and identify the token via its "iss" and "jti" claims. The
// remaining fields are optional selectors that narrow the revocation;
// an omitted selector matches every value.
type Entry struct {
	// Issuer matches the token "iss" claim. Required.
	Issuer string `json:"iss"`

	// JWTID matches the token "jti" claim. Required. Tokens without a
	// jti cannot be revoked.
	JWTID string `json:"jti"`

	// Audience, when non-empty, limits the entry to tokens whose "aud"
	// claim contains this value.
	Audience string `json:"aud,omitempty"`

	// Repository, when non-empty, limits the entry to the repository
	// resource with this exact name.
	Repository string `json:"repository,omitempty"`

	// Actions, when non-empty, limits the entry to the listed actions.
	// Only "pull" and "push" are allowed.
	Actions []string `json:"actions,omitempty"`
}
