package revocation

import (
	"strings"
	"testing"

	"github.com/distribution/distribution/v3/registry/auth"
)

func mustParse(t *testing.T, data string) *Snapshot {
	t.Helper()
	snapshot, err := Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	return snapshot
}

func TestParseValidDocuments(t *testing.T) {
	documents := []string{
		`{"version":1,"revoked":[]}`,
		`{"version":1,"revoked":[{"iss":"auth.example","jti":"j1"}]}`,
		`{"version":1,"revoked":[{"iss":"auth.example","jti":"j1"},{"iss":"auth.example","jti":"j1","actions":["pull"]}]}`,
		`{"version":1,"revoked":[{"iss":"auth.example","jti":"j1","aud":"registry.example","repository":"samalba/my-app","actions":["pull","push"]}]}`,
	}

	for i, document := range documents {
		if _, err := Parse([]byte(document)); err != nil {
			t.Errorf("document %d: expected parse success, got error: %v", i, err)
		}
	}
}

func TestParseInvalidDocuments(t *testing.T) {
	overLimit := `{"version":1,"revoked":[{"iss":"x","jti":"` + strings.Repeat("a", MaxListBytes) + `"}]}`

	tests := []struct {
		name     string
		document string
	}{
		{name: "empty input", document: ``},
		{name: "invalid json", document: `{"version":1,"revoked":[`},
		{name: "unknown field", document: `{"version":1,"revoked":[],"extra":true}`},
		{name: "unknown entry field", document: `{"version":1,"revoked":[{"iss":"a","jti":"b","scope":""}]}`},
		{name: "missing version", document: `{"revoked":[]}`},
		{name: "unsupported version", document: `{"version":2,"revoked":[]}`},
		{name: "missing revoked", document: `{"version":1}`},
		{name: "null revoked", document: `{"version":1,"revoked":null}`},
		{name: "missing iss", document: `{"version":1,"revoked":[{"jti":"j1"}]}`},
		{name: "empty iss", document: `{"version":1,"revoked":[{"iss":"","jti":"j1"}]}`},
		{name: "whitespace iss", document: `{"version":1,"revoked":[{"iss":"   ","jti":"j1"}]}`},
		{name: "empty jti", document: `{"version":1,"revoked":[{"iss":"auth.example","jti":""}]}`},
		{name: "invalid action", document: `{"version":1,"revoked":[{"iss":"a","jti":"b","actions":["delete"]}]}`},
		{name: "duplicate action", document: `{"version":1,"revoked":[{"iss":"a","jti":"b","actions":["pull","pull"]}]}`},
		{name: "trailing data", document: `{"version":1,"revoked":[]}{"version":1,"revoked":[]}`},
		{name: "over size limit", document: overLimit},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.document)); err == nil {
				t.Errorf("Parse() expected error for %q, got nil", tc.name)
			}
		})
	}
}

func repo(name string) auth.Resource {
	return auth.Resource{Type: RepositoryResourceType, Name: name}
}

func TestIsRevoked(t *testing.T) {
	// One snapshot exercising every selector shape and rule-key isolation.
	document := `{
		"version": 1,
		"revoked": [
			{"iss":"auth.example","jti":"whole"},
			{"iss":"auth.example","jti":"audonly","aud":"registry-a"},
			{"iss":"auth.example","jti":"reponly","repository":"library/a"},
			{"iss":"auth.example","jti":"pulla","repository":"library/a","actions":["pull"]},
			{"iss":"auth.example","jti":"bothaud","aud":"registry-a","repository":"library/a","actions":["pull"]},
			{"iss":"other-issuer","jti":"whole"}
		]
	}`
	snapshot := mustParse(t, document)

	tests := []struct {
		name      string
		issuer    string
		jti       string
		audiences []string
		resource  auth.Resource
		action    string
		revoked   bool
	}{
		{name: "whole token on repository pull", issuer: "auth.example", jti: "whole", resource: repo("library/x"), action: ActionPull, revoked: true},
		{name: "whole token on push", issuer: "auth.example", jti: "whole", resource: repo("library/x"), action: ActionPush, revoked: true},
		{name: "whole token on catalog", issuer: "auth.example", jti: "whole", resource: auth.Resource{Type: "registry", Name: "catalog"}, action: "*", revoked: true},
		{name: "whole token with zero resource", issuer: "auth.example", jti: "whole", resource: auth.Resource{}, action: "", revoked: true},
		{name: "unknown jti", issuer: "auth.example", jti: "unknown", resource: repo("library/x"), action: ActionPull, revoked: false},
		{name: "unknown issuer same jti", issuer: "third-issuer", jti: "whole", resource: repo("library/x"), action: ActionPull, revoked: false},
		{name: "empty jti cannot be revoked", issuer: "auth.example", jti: "", resource: repo("library/x"), action: ActionPull, revoked: false},
		{name: "audience match single", issuer: "auth.example", jti: "audonly", audiences: []string{"registry-a"}, resource: repo("library/x"), action: ActionPull, revoked: true},
		{name: "audience match among many", issuer: "auth.example", jti: "audonly", audiences: []string{"registry-b", "registry-a"}, resource: repo("library/x"), action: ActionPush, revoked: true},
		{name: "audience mismatch", issuer: "auth.example", jti: "audonly", audiences: []string{"registry-b"}, resource: repo("library/x"), action: ActionPull, revoked: false},
		{name: "audience selector and no aud claim", issuer: "auth.example", jti: "audonly", audiences: nil, resource: repo("library/x"), action: ActionPull, revoked: false},
		{name: "repository exact match", issuer: "auth.example", jti: "reponly", resource: repo("library/a"), action: ActionPull, revoked: true},
		{name: "repository other name", issuer: "auth.example", jti: "reponly", resource: repo("library/b"), action: ActionPull, revoked: false},
		{name: "repository selector on catalog resource", issuer: "auth.example", jti: "reponly", resource: auth.Resource{Type: "registry", Name: "catalog"}, action: "*", revoked: false},
		{name: "pull action revoked on pull", issuer: "auth.example", jti: "pulla", resource: repo("library/a"), action: ActionPull, revoked: true},
		{name: "pull action not revoked on push", issuer: "auth.example", jti: "pulla", resource: repo("library/a"), action: ActionPush, revoked: false},
		{name: "pull action on other repository", issuer: "auth.example", jti: "pulla", resource: repo("library/b"), action: ActionPull, revoked: false},
		{name: "all selectors match", issuer: "auth.example", jti: "bothaud", audiences: []string{"registry-a"}, resource: repo("library/a"), action: ActionPull, revoked: true},
		{name: "all selectors aud mismatch", issuer: "auth.example", jti: "bothaud", audiences: []string{"registry-b"}, resource: repo("library/a"), action: ActionPull, revoked: false},
		{name: "all selectors repo mismatch", issuer: "auth.example", jti: "bothaud", audiences: []string{"registry-a"}, resource: repo("library/b"), action: ActionPull, revoked: false},
		{name: "all selectors action mismatch", issuer: "auth.example", jti: "bothaud", audiences: []string{"registry-a"}, resource: repo("library/a"), action: ActionPush, revoked: false},
		{name: "other issuer whole token isolated", issuer: "other-issuer", jti: "whole", resource: repo("library/x"), action: ActionPull, revoked: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := snapshot.IsRevoked(tc.issuer, tc.jti, tc.audiences, tc.resource, tc.action)
			if got != tc.revoked {
				t.Errorf("IsRevoked() = %v, want %v", got, tc.revoked)
			}
		})
	}
}

func TestNilAndEmptySnapshotRevokeNothing(t *testing.T) {
	resource := repo("library/a")
	var nilSnapshot *Snapshot
	if nilSnapshot.IsRevoked("a", "b", nil, resource, ActionPull) {
		t.Fatal("nil snapshot must not revoke anything")
	}
	empty := mustParse(t, `{"version":1,"revoked":[]}`)
	if empty.IsRevoked("a", "b", nil, resource, ActionPull) {
		t.Fatal("empty snapshot must not revoke anything")
	}
	if Empty().IsRevoked("a", "b", nil, resource, ActionPull) {
		t.Fatal("Empty() snapshot must not revoke anything")
	}
}

func TestParseDeterminism(t *testing.T) {
	document := `{"version":1,"revoked":[{"iss":"auth.example","jti":"j1","repository":"library/a","actions":["pull"]},{"iss":"auth.example","jti":"j2"}]}`

	first := mustParse(t, document)
	second := mustParse(t, document)

	cases := []struct {
		issuer   string
		jti      string
		resource auth.Resource
		action   string
	}{
		{issuer: "auth.example", jti: "j1", resource: repo("library/a"), action: ActionPull},
		{issuer: "auth.example", jti: "j1", resource: repo("library/a"), action: ActionPush},
		{issuer: "auth.example", jti: "j1", resource: repo("library/b"), action: ActionPull},
		{issuer: "auth.example", jti: "j2", resource: repo("library/a"), action: ActionPull},
		{issuer: "auth.example", jti: "j3", resource: repo("library/a"), action: ActionPull},
	}

	for i, tc := range cases {
		if got, want := first.IsRevoked(tc.issuer, tc.jti, nil, tc.resource, tc.action), second.IsRevoked(tc.issuer, tc.jti, nil, tc.resource, tc.action); got != want {
			t.Errorf("case %d: snapshots parsed from the same document disagree: %v != %v", i, got, want)
		}
	}
}
