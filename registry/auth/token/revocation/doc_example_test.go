package revocation

import (
	"testing"

	"github.com/distribution/distribution/v3/registry/auth"
)

func TestDocExampleAccepted(t *testing.T) {
	doc := `{
  "version": 1,
  "revoked": [
    {"iss": "registry-token-issuer", "jti": "revoked-everywhere"},
    {"iss": "registry-token-issuer", "jti": "abc-123", "aud": "token-service"},
    {"iss": "registry-token-issuer", "jti": "def-456", "repository": "samalba/my-app"},
    {"iss": "registry-token-issuer", "jti": "ghi-789", "repository": "samalba/my-app", "actions": ["pull"]}
  ]
}`
	snapshot, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("documented example must parse: %v", err)
	}
	if snapshot.IsRevoked("registry-token-issuer", "ghi-789", nil,
		auth.Resource{Type: RepositoryResourceType, Name: "samalba/my-app"}, ActionPull) != true {
		t.Fatal("documented example entry should revoke pull on the repository")
	}
	if snapshot.IsRevoked("registry-token-issuer", "ghi-789", nil,
		auth.Resource{Type: RepositoryResourceType, Name: "samalba/my-app"}, ActionPush) {
		t.Fatal("documented example entry should not revoke push")
	}
}
