package handlers

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/registry/api/errcode"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

const emptyDigest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func accountingHTTPConfig() *configuration.Configuration {
	config := &configuration.Configuration{
		Storage: configuration.Storage{
			"inmemory": configuration.Parameters{},
			"delete":   configuration.Parameters{"enabled": true},
		},
		Accounting: configuration.Accounting{
			Enabled: true,
			Budget: configuration.AccountingBudget{
				Default: "10",
				Repositories: map[string]string{
					"team-a/base":     "1GiB",
					"team-c/manifest": "200",
				},
			},
		},
	}
	config.HTTP.Headers = headerConfig
	return config
}

func pushEmptyBlob(t *testing.T, env *testEnv, name reference.Named) {
	t.Helper()
	location, _ := startPushLayer(t, env, name)
	putURL := location + "&digest=" + url.QueryEscape(emptyDigest)
	req, err := http.NewRequest(http.MethodPut, putURL, nil)
	if err != nil {
		t.Fatalf("new put: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put empty blob: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("empty blob put status = %d: %s", resp.StatusCode, string(body))
	}
}

// TestQuotaExceededHTTPResponses drives the real HTTP stack and asserts that
// over-budget mount, blob upload and manifest put all return 507 with
// QUOTA_EXCEEDED and that a denied mount never starts an upload session.
func TestQuotaExceededHTTPResponses(t *testing.T) {
	env := newTestEnvWithConfig(t, accountingHTTPConfig())
	defer env.Shutdown()

	baseName, _ := reference.WithName("team-a/base")
	appName, _ := reference.WithName("team-b/app")
	manifestName, _ := reference.WithName("team-c/manifest")

	// Seed a 100-byte blob in the generous source repository.
	srcBody := bytes.Repeat([]byte("s"), 100)
	srcDGST := digest.FromBytes(srcBody)
	loc, _ := startPushLayer(t, env, baseName)
	finish := pushLayer(t, env.builder, baseName, srcDGST, loc, bytes.NewReader(srcBody))
	_ = finish

	// 1. Mount over budget (dst default budget is 10 bytes).
	mountURL, err := env.builder.BuildBlobUploadURL(appName, map[string][]string{
		"from":  {"team-a/base"},
		"mount": {srcDGST.String()},
	})
	if err != nil {
		t.Fatalf("build mount url: %v", err)
	}
	resp, err := http.Post(mountURL, "", nil)
	if err != nil {
		t.Fatalf("mount post: %v", err)
	}
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("mount status = %d, want 507", resp.StatusCode)
	}
	if resp.Header.Get("Docker-Upload-UUID") != "" {
		t.Fatal("denied mount must not start an upload session")
	}
	_, body, counts := checkBodyHasErrorCodes(t, "mount over quota", resp, errcode.ErrorCodeQuotaExceeded)
	resp.Body.Close()
	if counts[errcode.ErrorCodeQuotaExceeded] != 1 {
		t.Fatalf("mount body: %s", string(body))
	}

	// 2. Blob PUT over budget.
	uploadLocation, _ := startPushLayer(t, env, appName)
	putURL := uploadLocation + "&digest=" + url.QueryEscape(digest.FromBytes(bytes.Repeat([]byte("z"), 100)).String())
	req, _ := http.NewRequest(http.MethodPut, putURL, bytes.NewReader(bytes.Repeat([]byte("z"), 100)))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("blob put: %v", err)
	}
	if resp.StatusCode != http.StatusInsufficientStorage {
		t.Fatalf("blob put status = %d, want 507", resp.StatusCode)
	}
	checkBodyHasErrorCodes(t, "blob put over quota", resp, errcode.ErrorCodeQuotaExceeded)
	resp.Body.Close()

	// 3. Manifest PUT over budget: referenced empty blobs fit, payload does
	// not (budget 200).
	pushEmptyBlob(t, env, manifestName)
	emptyDesc := v1.Descriptor{
		Digest:    digest.Digest(emptyDigest),
		MediaType: v1.MediaTypeImageLayerGzip,
		Size:      0,
	}
	configDesc := v1.Descriptor{
		Digest:    digest.Digest(emptyDigest),
		MediaType: v1.MediaTypeImageConfig,
		Size:      0,
	}
	m := ocischema.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: v1.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []v1.Descriptor{emptyDesc},
	}
	dm, err := ocischema.FromStruct(m)
	if err != nil {
		t.Fatalf("from struct: %v", err)
	}
	tagRef, _ := reference.WithTag(manifestName, "latest")
	manifestURL, err := env.builder.BuildManifestURL(tagRef)
	if err != nil {
		t.Fatalf("manifest url: %v", err)
	}
	resp = putManifest(t, "over-quota manifest", manifestURL, v1.MediaTypeImageManifest, dm)
	if resp.StatusCode != http.StatusInsufficientStorage {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("manifest put status = %d, want 507: %s", resp.StatusCode, string(b))
	}
	checkBodyHasErrorCodes(t, "manifest put over quota", resp, errcode.ErrorCodeQuotaExceeded)
	resp.Body.Close()
}
