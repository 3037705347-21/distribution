package token

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/auth"
	"github.com/distribution/distribution/v3/registry/auth/token/revocation"
	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"
)

// init handles registering the token auth backend.
func init() {
	if err := auth.Register("token", auth.InitFunc(newAccessController)); err != nil {
		logrus.Errorf("failed to register token auth: %v", err)
	}
}

// accessSet maps a typed, named resource to
// a set of actions requested or authorized.
type accessSet map[auth.Resource]actionSet

// newAccessSet constructs an accessSet from
// a variable number of auth.Access items.
func newAccessSet(accessItems ...auth.Access) accessSet {
	accessSet := make(accessSet, len(accessItems))

	for _, access := range accessItems {
		resource := auth.Resource{
			Type: access.Type,
			Name: access.Name,
		}

		set, exists := accessSet[resource]
		if !exists {
			set = newActionSet()
			accessSet[resource] = set
		}

		set.add(access.Action)
	}

	return accessSet
}

// contains returns whether or not the given access is in this accessSet.
func (s accessSet) contains(access auth.Access) bool {
	actionSet, ok := s[access.Resource]
	if ok {
		return actionSet.contains(access.Action)
	}

	return false
}

// scopeParam returns a collection of scopes which can
// be used for a WWW-Authenticate challenge parameter.
// See https://tools.ietf.org/html/rfc6750#section-3
func (s accessSet) scopeParam() string {
	scopes := make([]string, 0, len(s))

	for resource, actionSet := range s {
		actions := strings.Join(actionSet.keys(), ",")
		scopes = append(scopes, fmt.Sprintf("%s:%s:%s", resource.Type, resource.Name, actions))
	}

	return strings.Join(scopes, " ")
}

// Errors used and exported by this package.
var (
	ErrInsufficientScope = errors.New("insufficient scope")
	ErrTokenRequired     = errors.New("authorization token required")
	// ErrTokenRevoked is returned when the presented token matches an
	// entry of the configured revocation list. It is surfaced to clients
	// as the OAuth "invalid_token" error.
	ErrTokenRevoked = errors.New("token has been revoked")
)

// authChallenge implements the auth.Challenge interface.
type authChallenge struct {
	err              error
	realm            string
	autoRedirect     bool
	autoRedirectPath string
	service          string
	accessSet        accessSet
}

var _ auth.Challenge = authChallenge{}

// Error returns the internal error string for this authChallenge.
func (ac authChallenge) Error() string {
	return ac.err.Error()
}

// Status returns the HTTP Response Status Code for this authChallenge.
func (ac authChallenge) Status() int {
	return http.StatusUnauthorized
}

func buildAutoRedirectURL(r *http.Request, autoRedirectPath string) string {
	scheme := "https"

	if forwardedProto := r.Header.Get("X-Forwarded-Proto"); len(forwardedProto) > 0 {
		scheme = forwardedProto
	}

	u := &url.URL{
		Scheme: scheme,
		Host:   r.Host,
		Path:   autoRedirectPath,
	}
	return u.String()
}

// challengeParams constructs the value to be used in
// the WWW-Authenticate response challenge header.
// See https://tools.ietf.org/html/rfc6750#section-3
func (ac authChallenge) challengeParams(r *http.Request) string {
	var realm string
	if ac.autoRedirect {
		realm = buildAutoRedirectURL(r, ac.autoRedirectPath)
	} else {
		realm = ac.realm
	}
	str := fmt.Sprintf("Bearer realm=%q,service=%q", realm, ac.service)

	if scope := ac.accessSet.scopeParam(); scope != "" {
		str = fmt.Sprintf("%s,scope=%q", str, scope)
	}

	switch ac.err {
	case ErrInvalidToken, ErrMalformedToken, ErrTokenRevoked:
		str = fmt.Sprintf("%s,error=%q", str, "invalid_token")
	case ErrInsufficientScope:
		str = fmt.Sprintf("%s,error=%q", str, "insufficient_scope")
	}

	return str
}

// SetHeaders sets the WWW-Authenticate value for the response.
func (ac authChallenge) SetHeaders(r *http.Request, w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", ac.challengeParams(r))
}

// accessController implements the auth.AccessController interface.
type accessController struct {
	realm             string
	autoRedirect      bool
	autoRedirectPath  string
	issuer            string
	service           string
	rootCerts         *x509.CertPool
	trustedKeys       map[string]crypto.PublicKey
	signingAlgorithms []jose.SignatureAlgorithm
	// revocation is optional. When configured, presented tokens are
	// additionally checked against its current snapshot; it is nil when
	// revocation is disabled, leaving the read path unchanged.
	revocation *revocation.Loader
}

const (
	defaultAutoRedirectPath = "/auth/token"
)

// tokenAccessOptions is a convenience type for handling
// options to the constructor of an accessController.
type tokenAccessOptions struct {
	realm             string
	autoRedirect      bool
	autoRedirectPath  string
	issuer            string
	service           string
	rootCertBundle    string
	jwks              string
	signingAlgorithms []string
	revocation        *revocation.Config
}

// checkOptions gathers the necessary options
// for an accessController from the given map.
func checkOptions(options map[string]any) (tokenAccessOptions, error) {
	var opts tokenAccessOptions

	keys := []string{"realm", "issuer", "service", "rootcertbundle", "jwks"}
	vals := make([]string, 0, len(keys))
	for _, key := range keys {
		val, ok := options[key].(string)
		if !ok {
			// NOTE(milosgajdos): this func makes me intensely sad
			// just like all the other weakly typed config options.
			// Either of these config options may be missing, but
			// at least one must be present: we handle those cases
			// in newAccessController func which consumes this one.
			if key == "rootcertbundle" || key == "jwks" {
				vals = append(vals, "")
				continue
			}
			return tokenAccessOptions{}, fmt.Errorf("token auth requires a valid option string: %q", key)
		}
		vals = append(vals, val)
	}

	opts.realm, opts.issuer, opts.service, opts.rootCertBundle, opts.jwks = vals[0], vals[1], vals[2], vals[3], vals[4]

	autoRedirectVal, ok := options["autoredirect"]
	if ok {
		autoRedirect, ok := autoRedirectVal.(bool)
		if !ok {
			return tokenAccessOptions{}, errors.New("token auth requires a valid option bool: autoredirect")
		}
		opts.autoRedirect = autoRedirect
	}
	if opts.autoRedirect {
		autoRedirectPathVal, ok := options["autoredirectpath"]
		if ok {
			autoRedirectPath, ok := autoRedirectPathVal.(string)
			if !ok {
				return tokenAccessOptions{}, errors.New("token auth requires a valid option string: autoredirectpath")
			}
			opts.autoRedirectPath = autoRedirectPath
		}
		if opts.autoRedirectPath == "" {
			opts.autoRedirectPath = defaultAutoRedirectPath
		}
	}

	signingAlgos, ok := options["signingalgorithms"]
	if ok {
		signingAlgorithmsVals, ok := signingAlgos.([]any)
		if !ok {
			return tokenAccessOptions{}, errors.New("signingalgorithms must be a list of signing algorithms")
		}

		for _, signingAlgorithmVal := range signingAlgorithmsVals {
			signingAlgorithm, ok := signingAlgorithmVal.(string)
			if !ok {
				return tokenAccessOptions{}, errors.New("signingalgorithms must be a list of signing algorithms")
			}

			opts.signingAlgorithms = append(opts.signingAlgorithms, signingAlgorithm)
		}
	}

	if revocationVal, ok := options["revocation"]; ok {
		revocationConfig, err := parseRevocationOptions(revocationVal)
		if err != nil {
			return tokenAccessOptions{}, err
		}
		opts.revocation = revocationConfig
	}

	return opts, nil
}

// parseRevocationOptions parses the optional "revocation" configuration
// block: exactly one of "path" or "url", plus optional "interval" and
// "timeout" Go duration strings.
func parseRevocationOptions(raw any) (*revocation.Config, error) {
	values, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("token revocation requires a map of configuration options")
	}

	config := &revocation.Config{}
	for key, value := range values {
		switch key {
		case "path", "url":
			strValue, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("token revocation %q must be a string", key)
			}
			if key == "path" {
				config.Path = strValue
			} else {
				config.URL = strValue
			}
		case "interval", "timeout":
			strValue, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("token revocation %q must be a duration string", key)
			}
			duration, err := time.ParseDuration(strValue)
			if err != nil {
				return nil, fmt.Errorf("token revocation %q must be a valid duration: %w", key, err)
			}
			if key == "interval" {
				config.Interval = duration
			} else {
				config.Timeout = duration
			}
		default:
			return nil, fmt.Errorf("unknown token revocation option %q", key)
		}
	}

	return config, nil
}

var (
	rootCertFetcher func(string) ([]*x509.Certificate, error) = getRootCerts
	jwkFetcher      func(string) (*jose.JSONWebKeySet, error) = getJwks
)

func getRootCerts(path string) ([]*x509.Certificate, error) {
	fp, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open token auth root certificate bundle file %q: %s", path, err)
	}
	defer fp.Close()

	rawCertBundle, err := io.ReadAll(fp)
	if err != nil {
		return nil, fmt.Errorf("unable to read token auth root certificate bundle file %q: %s", path, err)
	}

	var rootCerts []*x509.Certificate
	pemBlock, rawCertBundle := pem.Decode(rawCertBundle)
	for pemBlock != nil {
		if pemBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return nil, fmt.Errorf("unable to parse token auth root certificate: %s", err)
			}

			rootCerts = append(rootCerts, cert)
		}

		pemBlock, rawCertBundle = pem.Decode(rawCertBundle)
	}

	return rootCerts, nil
}

func getJwks(path string) (*jose.JSONWebKeySet, error) {
	// TODO(milosgajdos): we should consider providing a JWKS
	// URL from which the JWKS could be fetched
	jp, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open jwks file %q: %s", path, err)
	}
	defer jp.Close()

	rawJWKS, err := io.ReadAll(jp)
	if err != nil {
		return nil, fmt.Errorf("unable to read token jwks file %q: %s", path, err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(rawJWKS, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse jwks: %v", err)
	}

	return &jwks, nil
}

func getSigningAlgorithms(algos []string) ([]jose.SignatureAlgorithm, error) {
	signAlgVals := make([]jose.SignatureAlgorithm, 0, len(algos))
	for _, alg := range algos {
		signAlg, ok := signingAlgorithms[alg]
		if !ok {
			return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
		}
		signAlgVals = append(signAlgVals, signAlg)
	}
	return signAlgVals, nil
}

// newAccessController creates an accessController using the given options.
func newAccessController(options map[string]any) (auth.AccessController, error) {
	config, err := checkOptions(options)
	if err != nil {
		return nil, err
	}

	var (
		rootCerts []*x509.Certificate
		jwks      *jose.JSONWebKeySet
		signAlgos []jose.SignatureAlgorithm
	)

	if config.rootCertBundle != "" {
		rootCerts, err = rootCertFetcher(config.rootCertBundle)
		if err != nil {
			return nil, err
		}
	}

	if config.jwks != "" {
		jwks, err = jwkFetcher(config.jwks)
		if err != nil {
			return nil, err
		}
	}

	if (len(rootCerts) == 0 && jwks == nil) || // no certs bundle and no jwks
		(len(rootCerts) == 0 && jwks != nil && len(jwks.Keys) == 0) { // no certs bundle and empty jwks
		return nil, errors.New("token auth requires at least one token signing key")
	}

	trustedKeys := make(map[string]crypto.PublicKey)
	rootPool := x509.NewCertPool()
	for _, rootCert := range rootCerts {
		rootPool.AddCert(rootCert)
		if key := GetJWKThumbprint(rootCert.PublicKey); key != "" {
			trustedKeys[key] = rootCert.PublicKey
		}
	}

	if jwks != nil {
		for _, key := range jwks.Keys {
			trustedKeys[key.KeyID] = key.Public()
		}
	}

	signAlgos, err = getSigningAlgorithms(config.signingAlgorithms)
	if err != nil {
		return nil, err
	}
	if len(signAlgos) == 0 {
		// NOTE: this is to maintain backwards compat
		// with existing registry deployments
		signAlgos = defaultSigningAlgorithms
	}

	var revocationLoader *revocation.Loader
	if config.revocation != nil {
		// The initial load is synchronous and must succeed: the registry
		// refuses to start rather than running without revocations enforced.
		revocationLoader, err = revocation.New(context.Background(), *config.revocation)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize token revocation list: %w", err)
		}
	}

	return &accessController{
		realm:             config.realm,
		autoRedirect:      config.autoRedirect,
		autoRedirectPath:  config.autoRedirectPath,
		issuer:            config.issuer,
		service:           config.service,
		rootCerts:         rootPool,
		trustedKeys:       trustedKeys,
		signingAlgorithms: signAlgos,
		revocation:        revocationLoader,
	}, nil
}

// Authorized handles checking whether the given request is authorized
// for actions on resources described by the given access items.
func (ac *accessController) Authorized(req *http.Request, accessItems ...auth.Access) (*auth.Grant, error) {
	challenge := &authChallenge{
		realm:            ac.realm,
		autoRedirect:     ac.autoRedirect,
		autoRedirectPath: ac.autoRedirectPath,
		service:          ac.service,
		accessSet:        newAccessSet(accessItems...),
	}

	prefix, rawToken, ok := strings.Cut(req.Header.Get("Authorization"), " ")
	if !ok || rawToken == "" || !strings.EqualFold(prefix, "bearer") {
		challenge.err = ErrTokenRequired
		return nil, challenge
	}

	token, err := NewToken(rawToken, ac.signingAlgorithms)
	if err != nil {
		challenge.err = err
		return nil, challenge
	}

	verifyOpts := VerifyOptions{
		TrustedIssuers:    []string{ac.issuer},
		AcceptedAudiences: []string{ac.service},
		Roots:             ac.rootCerts,
		TrustedKeys:       ac.trustedKeys,
	}

	claims, err := token.Verify(verifyOpts)
	if err != nil {
		challenge.err = err
		return nil, challenge
	}

	accessSet := claims.accessSet()

	// The snapshot is an immutable, atomically published value; reading it
	// here does not take a lock and every access item below is checked
	// against the same snapshot.
	var revokedSnapshot *revocation.Snapshot
	if ac.revocation != nil {
		revokedSnapshot = ac.revocation.Current()
	}

	for _, access := range accessItems {
		if !accessSet.contains(access) {
			challenge.err = ErrInsufficientScope
			return nil, challenge
		}
		if revokedSnapshot != nil && revokedSnapshot.IsRevoked(
			claims.Issuer, claims.JWTID, claims.Audience,
			access.Resource, access.Action,
		) {
			challenge.err = ErrTokenRevoked
			return nil, challenge
		}
	}

	// Requests carrying no required access (e.g. base endpoints) are still
	// denied for tokens revoked wholesale (an entry with only iss and jti).
	if len(accessItems) == 0 && revokedSnapshot != nil && revokedSnapshot.IsRevoked(
		claims.Issuer, claims.JWTID, claims.Audience,
		auth.Resource{}, "",
	) {
		challenge.err = ErrTokenRevoked
		return nil, challenge
	}

	return &auth.Grant{
		User:      auth.UserInfo{Name: claims.Subject},
		Resources: claims.resources(),
	}, nil
}
