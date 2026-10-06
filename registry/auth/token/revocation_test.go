package token

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/auth"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testEmptyRevocationList = `{"version":1,"revoked":[]}`

// makeTokenStringWithJTI mints a signed bearer token with the given jti and
// access records, returning its compact serialization.
func makeTokenStringWithJTI(t *testing.T, jwk *jose.JSONWebKey, issuer, audience, jti string, access []*ResourceActions, now, exp time.Time) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jwk}, (&jose.SignerOptions{EmbedJWK: true}).WithType("JWT"))
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	claims := &ClaimSet{
		Issuer:     issuer,
		Subject:    "foo",
		Audience:   []string{audience},
		Expiration: exp.Unix(),
		NotBefore:  now.Unix(),
		IssuedAt:   now.Unix(),
		JWTID:      jti,
		Access:     access,
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}
	return raw
}

func writeRevocationFile(t *testing.T, path, content string) {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".revocation-*")
	if err != nil {
		t.Fatalf("create temp revocation file: %v", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("write temp revocation file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp revocation file: %v", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		t.Fatalf("publish revocation file: %v", err)
	}
}

// newRevocationTestController builds an accessController backed by the
// revocation file at listPath and returns the JWK used to sign test tokens
// that the controller trusts.
func newRevocationTestController(t *testing.T, listPath, interval string) (*accessController, *jose.JSONWebKey) {
	t.Helper()

	rootKeys, err := makeRootKeys(1)
	if err != nil {
		t.Fatal(err)
	}
	rootCertBundle, err := writeTempRootCerts(rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(rootCertBundle) })

	jwksPath, err := writeTempJWKS(rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(jwksPath) })

	options := map[string]any{
		"realm":          "https://auth.example.com/token/",
		"issuer":         "test-issuer.example.com",
		"service":        "test-service.example.com",
		"rootcertbundle": rootCertBundle,
		"jwks":           jwksPath,
		"revocation": map[string]any{
			"path":     listPath,
			"interval": interval,
		},
	}

	controller, err := newAccessController(options)
	if err != nil {
		t.Fatalf("newAccessController: %v", err)
	}
	ac := controller.(*accessController)
	t.Cleanup(func() { _ = ac.revocation.Close() })

	signingJWK, err := makeSigningKeyWithChain(rootKeys[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	return ac, signingJWK
}

func bearerRequest(raw string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/v2/", nil)
	if raw != "" {
		req.Header.Set("Authorization", "Bearer "+raw)
	}
	return req
}

func repoAccess(name, action string) auth.Access {
	return auth.Access{
		Resource: auth.Resource{Type: "repository", Name: name},
		Action:   action,
	}
}

func TestRevocationEnforcement(t *testing.T) {
	listPath := filepath.Join(t.TempDir(), "revocation.json")
	writeRevocationFile(t, listPath, `{
		"version": 1,
		"revoked": [
			{"iss":"test-issuer.example.com","jti":"revoked-whole"},
			{"iss":"test-issuer.example.com","jti":"revoked-pulla","repository":"library/a","actions":["pull"]},
			{"iss":"test-issuer.example.com","jti":"revoked-otheraud","aud":"other-service.example.com"}
		]
	}`)

	ac, jwk := newRevocationTestController(t, listPath, "1h")

	now := time.Now()
	access := []*ResourceActions{
		{Type: "repository", Name: "library/a", Actions: []string{"pull", "push"}},
		{Type: "repository", Name: "library/b", Actions: []string{"pull", "push"}},
	}
	mint := func(jti string) string {
		return makeTokenStringWithJTI(t, jwk, "test-issuer.example.com", "test-service.example.com", jti, access, now, now.Add(5*time.Minute))
	}

	noJTI := makeTokenStringWithJTI(t, jwk, "test-issuer.example.com", "test-service.example.com", "", access, now, now.Add(5*time.Minute))

	denied := func(rawToken string, accessItems ...auth.Access) {
		t.Helper()
		grant, err := ac.Authorized(bearerRequest(rawToken), accessItems...)
		challenge, ok := err.(auth.Challenge)
		if !ok {
			t.Fatalf("expected challenge, got grant=%v err=%v", grant, err)
		}
		if challenge.Error() != ErrTokenRevoked.Error() {
			t.Fatalf("expected ErrTokenRevoked, got %q", challenge.Error())
		}
		recorder := httptest.NewRecorder()
		challenge.SetHeaders(bearerRequest(rawToken), recorder)
		if header := recorder.Header().Get("WWW-Authenticate"); !strings.Contains(header, `error="invalid_token"`) {
			t.Fatalf("WWW-Authenticate %q missing invalid_token error", header)
		}
	}

	allowed := func(rawToken string, accessItems ...auth.Access) {
		t.Helper()
		grant, err := ac.Authorized(bearerRequest(rawToken), accessItems...)
		if err != nil {
			t.Fatalf("expected access granted, got %v", err)
		}
		if grant == nil {
			t.Fatal("expected non-nil grant")
		}
	}

	// Unlisted jti: all access unaffected.
	allowed(mint("good-jti"), repoAccess("library/a", "pull"))
	allowed(mint("good-jti"), repoAccess("library/a", "push"))
	// Token without jti cannot be revoked.
	allowed(noJTI, repoAccess("library/a", "pull"))

	// Whole-token revocation denies every action and repository.
	denied(mint("revoked-whole"), repoAccess("library/a", "pull"))
	denied(mint("revoked-whole"), repoAccess("library/a", "push"))
	denied(mint("revoked-whole"), repoAccess("library/b", "pull"))
	// ...including requests without access items.
	denied(mint("revoked-whole"))

	// Pull revoked on library/a: pull denied, push on the same repository
	// and any access on library/b remain authorized.
	denied(mint("revoked-pulla"), repoAccess("library/a", "pull"))
	allowed(mint("revoked-pulla"), repoAccess("library/a", "push"))
	allowed(mint("revoked-pulla"), repoAccess("library/b", "pull"))
	allowed(mint("revoked-pulla"), repoAccess("library/b", "push"))

	// Audience selector that does not match this service revokes nothing.
	allowed(mint("revoked-otheraud"), repoAccess("library/a", "pull"))
	allowed(mint("revoked-otheraud"))

	// A good token is still allowed after revocations were evaluated.
	allowed(mint("another-good-jti"), repoAccess("library/a", "pull"))
}

func TestRevocationHotReload(t *testing.T) {
	listPath := filepath.Join(t.TempDir(), "revocation.json")
	writeRevocationFile(t, listPath, testEmptyRevocationList)

	// A long interval keeps the poller quiet; reloads below are driven
	// explicitly through the same Reload path the poller uses.
	ac, jwk := newRevocationTestController(t, listPath, "1h")

	now := time.Now()
	access := []*ResourceActions{{Type: "repository", Name: "library/a", Actions: []string{"pull"}}}
	rawJ1 := makeTokenStringWithJTI(t, jwk, "test-issuer.example.com", "test-service.example.com", "j1", access, now, now.Add(5*time.Minute))
	rawJ2 := makeTokenStringWithJTI(t, jwk, "test-issuer.example.com", "test-service.example.com", "j2", access, now, now.Add(5*time.Minute))

	pullA := repoAccess("library/a", "pull")
	reload := func() {
		t.Helper()
		if err := ac.revocation.Reload(context.Background()); err != nil {
			t.Fatalf("Reload(): %v", err)
		}
	}

	if _, err := ac.Authorized(bearerRequest(rawJ1), pullA); err != nil {
		t.Fatalf("j1 should start authorized: %v", err)
	}

	// New snapshot revokes j1.
	writeRevocationFile(t, listPath, `{"version":1,"revoked":[{"iss":"test-issuer.example.com","jti":"j1"}]}`)
	reload()
	if _, err := ac.Authorized(bearerRequest(rawJ1), pullA); err == nil || err.Error() != ErrTokenRevoked.Error() {
		t.Fatalf("j1 should be revoked after reload, got %v", err)
	}

	// j2 is not on the list.
	if _, err := ac.Authorized(bearerRequest(rawJ2), pullA); err != nil {
		t.Fatalf("j2 must remain authorized: %v", err)
	}

	// A bad document must not drop the existing revocation.
	previous := ac.revocation.Current()
	writeRevocationFile(t, listPath, `{"version":1,"revoked":[`)
	if err := ac.revocation.Reload(context.Background()); err == nil {
		t.Fatal("Reload() of bad document should fail")
	}
	if ac.revocation.Current() != previous {
		t.Fatal("bad document replaced the snapshot")
	}
	if _, err := ac.Authorized(bearerRequest(rawJ1), pullA); err == nil || err.Error() != ErrTokenRevoked.Error() {
		t.Fatalf("j1 must stay revoked after bad update, got %v", err)
	}

	// A valid snapshot removing j1 and adding j2 applies as a whole.
	writeRevocationFile(t, listPath, `{"version":1,"revoked":[{"iss":"test-issuer.example.com","jti":"j2"}]}`)
	reload()
	if _, err := ac.Authorized(bearerRequest(rawJ1), pullA); err != nil {
		t.Fatalf("j1 should be authorized after snapshot replacement, got %v", err)
	}
	if _, err := ac.Authorized(bearerRequest(rawJ2), pullA); err == nil || err.Error() != ErrTokenRevoked.Error() {
		t.Fatalf("j2 should be revoked after snapshot replacement, got %v", err)
	}
}

// TestRevocationPolling applies a published file through the background
// poller to prove the loop itself converges without an explicit reload.
func TestRevocationPolling(t *testing.T) {
	listPath := filepath.Join(t.TempDir(), "revocation.json")
	writeRevocationFile(t, listPath, testEmptyRevocationList)

	ac, jwk := newRevocationTestController(t, listPath, "20ms")

	now := time.Now()
	access := []*ResourceActions{{Type: "repository", Name: "library/a", Actions: []string{"pull"}}}
	rawJ1 := makeTokenStringWithJTI(t, jwk, "test-issuer.example.com", "test-service.example.com", "j1", access, now, now.Add(5*time.Minute))

	writeRevocationFile(t, listPath, `{"version":1,"revoked":[{"iss":"test-issuer.example.com","jti":"j1"}]}`)
	waitForCondition(t, 5*time.Second, func() bool {
		_, err := ac.Authorized(bearerRequest(rawJ1), repoAccess("library/a", "pull"))
		return err != nil && err.Error() == ErrTokenRevoked.Error()
	}, "background poller to apply the published list")
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", message)
}

func TestRevocationConstructionFailures(t *testing.T) {
	rootKeys, err := makeRootKeys(1)
	if err != nil {
		t.Fatal(err)
	}
	rootCertBundle, err := writeTempRootCerts(rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	jwksPath, err := writeTempJWKS(rootKeys)
	if err != nil {
		t.Fatal(err)
	}

	base := func(extra map[string]any) map[string]any {
		options := map[string]any{
			"realm":          "https://auth.example.com/token/",
			"issuer":         "test-issuer.example.com",
			"service":        "test-service.example.com",
			"rootcertbundle": rootCertBundle,
			"jwks":           jwksPath,
		}
		for k, v := range extra {
			options[k] = v
		}
		return options
	}

	missing := filepath.Join(t.TempDir(), "missing.json")
	cases := []struct {
		name    string
		options map[string]any
	}{
		{name: "missing file", options: base(map[string]any{"revocation": map[string]any{"path": missing}})},
		{name: "path and url", options: base(map[string]any{"revocation": map[string]any{"path": missing, "url": "http://example.com/list.json"}})},
		{name: "neither", options: base(map[string]any{"revocation": map[string]any{}})},
		{name: "bad scheme", options: base(map[string]any{"revocation": map[string]any{"url": "ftp://example.com/list.json"}})},
		{name: "bad interval", options: base(map[string]any{"revocation": map[string]any{"url": "http://example.com/list.json", "interval": "soon"}})},
		{name: "unknown key", options: base(map[string]any{"revocation": map[string]any{"path": missing, "watch": true}})},
		{name: "not a map", options: base(map[string]any{"revocation": "file.json"})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newAccessController(tc.options); err == nil {
				t.Fatal("expected construction error, got nil")
			}
		})
	}
}

func TestRevocationDisabledByDefault(t *testing.T) {
	rootKeys, err := makeRootKeys(1)
	if err != nil {
		t.Fatal(err)
	}
	rootCertBundle, err := writeTempRootCerts(rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	jwksPath, err := writeTempJWKS(rootKeys)
	if err != nil {
		t.Fatal(err)
	}

	controller, err := newAccessController(map[string]any{
		"realm":          "https://auth.example.com/token/",
		"issuer":         "test-issuer.example.com",
		"service":        "test-service.example.com",
		"rootcertbundle": rootCertBundle,
		"jwks":           jwksPath,
	})
	if err != nil {
		t.Fatalf("newAccessController: %v", err)
	}
	if controller.(*accessController).revocation != nil {
		t.Fatal("revocation loader must be nil when unconfigured")
	}
}
