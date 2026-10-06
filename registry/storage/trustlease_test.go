package storage

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/distribution/v3/registry/trustlease"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const foreignLayerDigest = "sha256:463435349086340864309863409683460843608348608934092322395278926a"

// firstVerifyError unwraps the leading error from an ErrManifestVerification
// pair, matching the convention of the existing manifest handler tests.
func firstVerifyError(err error) error {
	if verr, ok := err.(distribution.ErrManifestVerification); ok {
		if len(verr) == 2 {
			if _, ok := verr[1].(distribution.ErrManifestBlobUnknown); ok {
				return verr[0]
			}
		}
		if len(verr) == 1 {
			return verr[0]
		}
	}
	return err
}

// newLeaseTestRegistry builds a registry whose global external URL policy
// only trusts "foo" hosts, with the supplied lease manager installed.
func newLeaseTestRegistry(t *testing.T, mgr *trustlease.Manager) distribution.Namespace {
	t.Helper()
	return createRegistry(t, inmemory.New(),
		ManifestURLsAllowRegexp(regexp.MustCompile("^https?://foo")),
		ManifestURLsDenyRegexp(regexp.MustCompile("^https?://foo/nope")),
		ManifestURLTrustLeases(mgr),
	)
}

func TestSchema2ForeignLayerConsumesRepositoryLease(t *testing.T) {
	ctx := dcontext.Background()
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	now := base
	mgr := trustlease.NewManagerWithClock(func() time.Time { return now })

	// The leased repository may point foreign layers at "bar"; the global
	// policy only trusts "foo".
	_, err := mgr.Replace(&trustlease.Document{Version: 1, Leases: []trustlease.Lease{{
		Repository: "leased/app",
		Allow:      []string{"^https?://bar"},
		NotAfter:   ptrTime(base.Add(time.Hour)),
	}}})
	if err != nil {
		t.Fatalf("install v1 lease: %v", err)
	}

	registry := newLeaseTestRegistry(t, mgr)
	leasedRepo := makeRepository(t, registry, "leased/app")
	plainRepo := makeRepository(t, registry, "plain/app")
	leasedConfig, err := leasedRepo.Blobs(ctx).Put(ctx, schema2.MediaTypeImageConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	plainConfig, err := plainRepo.Blobs(ctx).Put(ctx, schema2.MediaTypeImageConfig, nil)
	if err != nil {
		t.Fatal(err)
	}

	putSchema2 := func(repo distribution.Repository, config v1.Descriptor, u string) error {
		m := schema2.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: schema2.MediaTypeManifest,
			Config:    config,
			Layers: []v1.Descriptor{{
				Digest:    foreignLayerDigest,
				Size:      6323,
				MediaType: schema2.MediaTypeForeignLayer,
				URLs:      []string{u},
			}},
		}
		dm, err := schema2.FromStruct(m)
		if err != nil {
			return err
		}
		ms, err := repo.Manifests(ctx)
		if err != nil {
			return err
		}
		_, err = ms.Put(ctx, dm)
		return firstVerifyError(err)
	}

	cases := []struct {
		name   string
		repo   distribution.Repository
		config v1.Descriptor
		url    string
		err    error
	}{
		{"leased repo trusts bar", leasedRepo, leasedConfig, "http://bar/layer", nil},
		{"leased repo no longer trusts global foo", leasedRepo, leasedConfig, "http://foo/layer", errInvalidURL},
		{"plain repo still uses global policy (bar rejected)", plainRepo, plainConfig, "http://bar/layer", errInvalidURL},
		{"plain repo still uses global policy (foo allowed)", plainRepo, plainConfig, "http://foo/layer", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := putSchema2(c.repo, c.config, c.url); got != c.err {
				t.Fatalf("expected %v, got %v", c.err, got)
			}
		})
	}

	// Expire the lease: the next batch of requests falls back to the global
	// policy for the target repository.
	now = base.Add(2 * time.Hour)
	if got := putSchema2(leasedRepo, leasedConfig, "http://bar/layer"); got != errInvalidURL {
		t.Fatalf("expired lease: expected errInvalidURL, got %v", got)
	}
	if got := putSchema2(leasedRepo, leasedConfig, "http://foo/layer"); got != nil {
		t.Fatalf("expired lease: expected global allow, got %v", got)
	}

	// Tightening with a bad document must not partially override v1 while the
	// lease is active again.
	now = base
	_, err = mgr.Replace(&trustlease.Document{Version: 2, Leases: []trustlease.Lease{{
		Repository: "leased/app",
		Allow:      []string{"^https?://new"},
	}, {
		Repository: "broken/app",
		Allow:      []string{"["},
	}}})
	if err == nil {
		t.Fatal("expected invalid v2 document to be rejected")
	}
	if mgr.Version() != 1 {
		t.Fatalf("active version changed to %d after bad document", mgr.Version())
	}
	if got := putSchema2(leasedRepo, leasedConfig, "http://bar/layer"); got != nil {
		t.Fatalf("bad document changed push behavior: %v", got)
	}
	if got := putSchema2(leasedRepo, leasedConfig, "http://new/layer"); got != errInvalidURL {
		t.Fatalf("bad document partially tightened policy: %v", got)
	}

	// A valid tightening document takes effect for subsequent requests.
	_, err = mgr.Replace(&trustlease.Document{Version: 2, Leases: []trustlease.Lease{{
		Repository: "leased/app",
		Allow:      []string{"^https?://new"},
	}}})
	if err != nil {
		t.Fatalf("install v2: %v", err)
	}
	if got := putSchema2(leasedRepo, leasedConfig, "http://bar/layer"); got != errInvalidURL {
		t.Fatalf("v2 should reject bar, got %v", got)
	}
	if got := putSchema2(leasedRepo, leasedConfig, "http://new/layer"); got != nil {
		t.Fatalf("v2 should allow new, got %v", got)
	}

	// Revoking all leases restores the global policy.
	if _, err := mgr.Replace(&trustlease.Document{Version: 3}); err != nil {
		t.Fatalf("install revoke document: %v", err)
	}
	if got := putSchema2(leasedRepo, leasedConfig, "http://foo/layer"); got != nil {
		t.Fatalf("revoked lease: expected global allow, got %v", got)
	}
}

func TestOCINonDistributableLayerConsumesRepositoryLease(t *testing.T) {
	ctx := context.Background()
	mgr := trustlease.NewManager()
	if _, err := mgr.Replace(&trustlease.Document{Version: 1, Leases: []trustlease.Lease{{
		Repository: "oci/leased",
		Allow:      []string{"^https?://bar"},
	}}}); err != nil {
		t.Fatalf("install lease: %v", err)
	}

	registry := newLeaseTestRegistry(t, mgr)
	repo := makeRepository(t, registry, "oci/leased")
	manifestService := makeManifestService(t, repo)

	config, err := repo.Blobs(ctx).Put(ctx, v1.MediaTypeImageConfig, nil)
	if err != nil {
		t.Fatal(err)
	}

	putOCI := func(u string) error {
		m := ocischema.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: v1.MediaTypeImageManifest,
			Config:    config,
			Layers: []v1.Descriptor{{
				Digest:    foreignLayerDigest,
				Size:      6323,
				MediaType: v1.MediaTypeImageLayerNonDistributableGzip, //nolint:staticcheck // deprecated media type used intentionally to exercise URL validation
				URLs:      []string{u},
			}},
		}
		dm, err := ocischema.FromStruct(m)
		if err != nil {
			return err
		}
		_, err = manifestService.Put(ctx, dm)
		return firstVerifyError(err)
	}

	if got := putOCI("http://bar/layer"); got != nil {
		t.Fatalf("leased OCI repo should accept bar URL, got %v", got)
	}
	if got := putOCI("http://foo/layer"); got != errInvalidURL {
		t.Fatalf("leased OCI repo should reject global foo URL, got %v", got)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
