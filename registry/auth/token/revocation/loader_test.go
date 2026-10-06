package revocation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/auth"
)

const emptyList = `{"version":1,"revoked":[]}`

func listWith(jtis ...string) string {
	var entries string
	for i, jti := range jtis {
		if i > 0 {
			entries += ","
		}
		entries += fmt.Sprintf(`{"iss":"auth.example","jti":%q}`, jti)
	}
	return fmt.Sprintf(`{"version":1,"revoked":[%s]}`, entries)
}

// writeAtomically writes the file via a temporary file and rename, the
// expected publisher pattern.
func writeAtomically(t *testing.T, path, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".revocation-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		t.Fatalf("rename temp file: %v", err)
	}
}

func waitFor(t *testing.T, timeout, interval time.Duration, condition func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(interval)
	}
	t.Fatalf("timed out waiting for condition: %s", msg)
}

func revoked(l *Loader, jti string) bool {
	return l.Current().IsRevoked("auth.example", jti, nil,
		auth.Resource{Type: RepositoryResourceType, Name: "library/a"}, ActionPull)
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{name: "file path", config: Config{Path: "/tmp/list.json"}, wantErr: false},
		{name: "http url", config: Config{URL: "http://example.com/list.json"}, wantErr: false},
		{name: "https url", config: Config{URL: "https://example.com/list.json"}, wantErr: false},
		{name: "both path and url", config: Config{Path: "/tmp/list.json", URL: "http://example.com"}, wantErr: true},
		{name: "neither", config: Config{}, wantErr: true},
		{name: "bad scheme", config: Config{URL: "ftp://example.com/list.json"}, wantErr: true},
		{name: "missing host", config: Config{URL: "http://"}, wantErr: true},
		{name: "negative interval", config: Config{Path: "/tmp/list.json", Interval: -1}, wantErr: true},
		{name: "negative timeout", config: Config{Path: "/tmp/list.json", Timeout: -1}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.validate()
			if tc.wantErr && err == nil {
				t.Fatalf("validate() expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validate() unexpected error: %v", err)
			}
		})
	}

	t.Run("defaults applied", func(t *testing.T) {
		c := Config{Path: "/tmp/list.json"}
		if err := c.validate(); err != nil {
			t.Fatalf("validate(): %v", err)
		}
		if c.Interval != defaultInterval {
			t.Errorf("interval = %v, want %v", c.Interval, defaultInterval)
		}
		if c.Timeout != defaultTimeout {
			t.Errorf("timeout = %v, want %v", c.Timeout, defaultTimeout)
		}
	})

	t.Run("sub minimum interval raised", func(t *testing.T) {
		c := Config{Path: "/tmp/list.json", Interval: time.Nanosecond}
		if err := c.validate(); err != nil {
			t.Fatalf("validate(): %v", err)
		}
		if c.Interval != minimumInterval {
			t.Errorf("interval = %v, want %v", c.Interval, minimumInterval)
		}
	})
}

func TestFileLoaderHotReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.json")
	writeAtomically(t, path, emptyList)

	ctx := context.Background()
	loader, err := New(ctx, Config{Path: path, Interval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer loader.Close()

	if revoked(loader, "j1") {
		t.Fatal("j1 must not be revoked from the empty initial list")
	}

	// Publish a new snapshot atomically and wait for the poller to apply it.
	writeAtomically(t, path, listWith("j1"))
	waitFor(t, 5*time.Second, 5*time.Millisecond, func() bool {
		return revoked(loader, "j1")
	}, "j1 revocation to take effect")

	if revoked(loader, "j2") {
		t.Fatal("j2 must remain authorized")
	}

	// Republish identical content and reload explicitly: the snapshot
	// pointer must not change (idempotent), regardless of ticker timing.
	pointer := loader.Current()
	writeAtomically(t, path, listWith("j1"))
	if err := loader.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() of unchanged content: %v", err)
	}
	if loader.Current() != pointer {
		t.Fatal("reloading unchanged content replaced the snapshot pointer")
	}
	if !revoked(loader, "j1") || revoked(loader, "j2") {
		t.Fatal("idempotent reload changed enforcement")
	}

	// The background poller must also converge on its own without
	// replacing an equal snapshot.
	time.Sleep(1100 * time.Millisecond)
	if loader.Current() != pointer {
		t.Fatal("background poll of unchanged content replaced the pointer")
	}
}

func TestBadUpdateKeepsPreviousSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.json")
	writeAtomically(t, path, listWith("j1"))

	loader, err := New(context.Background(), Config{Path: path, Interval: time.Hour})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer loader.Close()

	badDocuments := map[string]string{
		"truncated json": `{"version":1,"revoked":[`,
		"unknown field":  `{"version":1,"revoked":[],"bogus":1}`,
		"empty iss":      `{"version":1,"revoked":[{"iss":"","jti":"jx"}]}`,
		"bad action":     `{"version":1,"revoked":[{"iss":"auth.example","jti":"jx","actions":["burn"]}]}`,
		"wrong version":  `{"version":9,"revoked":[]}`,
	}

	for name, bad := range badDocuments {
		t.Run(name, func(t *testing.T) {
			previous := loader.Current()
			writeAtomically(t, path, bad)
			if err := loader.Reload(context.Background()); err == nil {
				t.Fatalf("Reload() expected error for %s", name)
			}
			if loader.Current() != previous {
				t.Fatal("bad update replaced the snapshot")
			}
			if !revoked(loader, "j1") {
				t.Fatal("previously revoked j1 became authorized after bad update")
			}
		})
	}

	// A valid document after bad ones applies wholesale.
	writeAtomically(t, path, listWith("j1", "j3"))
	if err := loader.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() of valid document: %v", err)
	}
	if !revoked(loader, "j1") || !revoked(loader, "j3") {
		t.Fatal("valid update did not apply to the complete entry set")
	}
}

func TestOversizedUpdateRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.json")
	writeAtomically(t, path, listWith("j1"))

	loader, err := New(context.Background(), Config{Path: path, Interval: time.Hour})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer loader.Close()

	previous := loader.Current()
	writeAtomically(t, path, `{"version":1,"revoked":[{"iss":"x","jti":"`+string(make([]byte, MaxListBytes))+`"}]}`)
	if err := loader.Reload(context.Background()); err == nil {
		t.Fatal("Reload() expected error for oversized document")
	}
	if loader.Current() != previous {
		t.Fatal("oversized update replaced the snapshot")
	}
}

func TestNewFailsClosedWhenSourceMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := New(context.Background(), Config{Path: missing}); err == nil {
		t.Fatal("New() expected error for missing revocation file")
	}
}

func TestNewFailsClosedWhenSourceInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.json")
	writeAtomically(t, path, `{"version":1,"revoked":[`)
	if _, err := New(context.Background(), Config{Path: path}); err == nil {
		t.Fatal("New() expected error for invalid initial list")
	}
}

func TestRestartEquivalence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocation.json")
	writeAtomically(t, path, `{
		"version": 1,
		"revoked": [
			{"iss":"auth.example","jti":"whole"},
			{"iss":"auth.example","jti":"pulla","repository":"library/a","actions":["pull"]},
			{"iss":"auth.example","jti":"aud","aud":"registry-a"}
		]
	}`)

	first, err := New(context.Background(), Config{Path: path, Interval: time.Hour})
	if err != nil {
		t.Fatalf("first New(): %v", err)
	}
	defer first.Close()

	second, err := New(context.Background(), Config{Path: path, Interval: time.Hour})
	if err != nil {
		t.Fatalf("second New(): %v", err)
	}
	defer second.Close()

	resources := []auth.Resource{
		{Type: RepositoryResourceType, Name: "library/a"},
		{Type: RepositoryResourceType, Name: "library/b"},
		{Type: "registry", Name: "catalog"},
	}
	jtis := []string{"whole", "pulla", "aud", "unknown"}
	audiences := [][]string{nil, {"registry-a"}, {"registry-b"}}
	actions := []string{ActionPull, ActionPush, "*"}

	for _, jti := range jtis {
		for _, resource := range resources {
			for _, action := range actions {
				for _, aud := range audiences {
					got := first.Current().IsRevoked("auth.example", jti, aud, resource, action)
					want := second.Current().IsRevoked("auth.example", jti, aud, resource, action)
					if got != want {
						t.Fatalf("snapshot mismatch after restart for jti=%q resource=%v action=%q aud=%v: %v != %v",
							jti, resource, action, aud, got, want)
					}
				}
			}
		}
	}
}

func TestHTTPSourceRefreshProtocol(t *testing.T) {
	const (
		body1 = `{"version":1,"revoked":[{"iss":"auth.example","jti":"j1"}]}`
		body2 = `{"version":1,"revoked":[{"iss":"auth.example","jti":"j1"},{"iss":"auth.example","jti":"j2"}]}`
	)

	var (
		mu              sync.Mutex
		request         int
		conditionalTags []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		request++
		n := request
		conditionalTags = append(conditionalTags, r.Header.Get("If-None-Match"))
		mu.Unlock()

		switch n {
		case 1:
			w.Header().Set("ETag", `"v1"`)
			fmt.Fprint(w, body1)
		case 2:
			w.WriteHeader(http.StatusNotModified)
		case 3:
			w.Header().Set("ETag", `"v2"`)
			fmt.Fprint(w, body2)
		case 4:
			w.WriteHeader(http.StatusInternalServerError)
		case 5:
			// 200 with a fresh validator but an unusable body: the loader
			// must reject the body and must not adopt this validator.
			w.Header().Set("ETag", `"v3-bad"`)
			fmt.Fprint(w, `{"version":1,"revoked":[`)
		default:
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer server.Close()

	loader, err := New(context.Background(), Config{URL: server.URL, Interval: time.Hour, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	defer loader.Close()

	if !revoked(loader, "j1") || revoked(loader, "j2") {
		t.Fatal("initial HTTP snapshot has unexpected state")
	}
	firstPointer := loader.Current()

	// 304: unchanged, snapshot retained.
	if err := loader.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() on 304: %v", err)
	}
	if loader.Current() != firstPointer {
		t.Fatal("304 response replaced the snapshot")
	}

	// 200 with ETag v2: new snapshot applied.
	if err := loader.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() on v2 200: %v", err)
	}
	if !revoked(loader, "j2") {
		t.Fatal("j2 revocation from v2 body did not take effect")
	}

	// 500: fetch error, previous snapshot retained.
	previous := loader.Current()
	if err := loader.Reload(context.Background()); err == nil {
		t.Fatal("Reload() expected error on HTTP 500")
	}
	if loader.Current() != previous {
		t.Fatal("HTTP 500 replaced the snapshot")
	}
	if !revoked(loader, "j1") || !revoked(loader, "j2") {
		t.Fatal("last-known-good snapshot lost after HTTP 500")
	}

	// 200 with a new ETag but an invalid body: the update is rejected and
	// the new validator must not be committed, so the bad document is
	// fetched again rather than hidden behind a 304.
	if err := loader.Reload(context.Background()); err == nil {
		t.Fatal("Reload() expected error on 200 with invalid body")
	}
	if loader.Current() != previous {
		t.Fatal("invalid body replaced the snapshot")
	}

	// Next request must reuse the last committed validator (v2); server
	// replies 304 and state stays put.
	if err := loader.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() after rejected body: %v", err)
	}
	if loader.Current() != previous {
		t.Fatal("304 after rejected body replaced the snapshot")
	}
	if !revoked(loader, "j1") || !revoked(loader, "j2") {
		t.Fatal("last-known-good snapshot lost")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(conditionalTags) < 6 || conditionalTags[0] != "" {
		t.Fatalf("first request must not carry If-None-Match, got %q", conditionalTags)
	}
	if conditionalTags[1] != `"v1"` {
		t.Fatalf("second request must carry If-None-Match %q, got %q", `"v1"`, conditionalTags[1])
	}
	if conditionalTags[2] != `"v1"` {
		t.Fatalf("third request must keep using validator %q, got %q", `"v1"`, conditionalTags[2])
	}
	if conditionalTags[4] != `"v2"` {
		t.Fatalf("request after 500 must carry validator %q, got %q", `"v2"`, conditionalTags[4])
	}
	if conditionalTags[5] != `"v2"` {
		t.Fatalf("request after a rejected body must keep validator %q, got %q", `"v2"`, conditionalTags[5])
	}
}

func TestNewFailsClosedWhenHTTPUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	server.Close() // immediately refuse connections

	if _, err := New(context.Background(), Config{URL: server.URL, Timeout: time.Second}); err == nil {
		t.Fatal("New() expected error for unreachable revocation endpoint")
	}
}

// fakeSource serves atomically swappable documents for the concurrency test.
type fakeSource struct {
	data atomic.Pointer[[]byte]
}

func (f *fakeSource) Fetch(_ context.Context) ([]byte, func(), error) {
	data := f.data.Load()
	if data == nil {
		return nil, nil, errors.New("no document")
	}
	return *data, nil, nil
}

func (f *fakeSource) String() string { return "fake://revocation" }

func TestLoaderConcurrentReadsAndSwaps(t *testing.T) {
	source := &fakeSource{}
	initial := []byte(listWith("j1"))
	source.data.Store(&initial)

	loader := &Loader{source: source, done: make(chan struct{})}
	snapshot, err := Parse(initial)
	if err != nil {
		t.Fatalf("Parse(): %v", err)
	}
	loader.current.Store(snapshot)
	loader.lastSum = checksum(initial)

	ctx, cancel := context.WithCancel(context.Background())
	go loader.run(ctx, 5*time.Millisecond)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					snap := loader.Current()
					if snap == nil {
						t.Error("Current() returned nil during concurrent swaps")
						return
					}
					_ = snap.IsRevoked("auth.example", "j1", nil,
						auth.Resource{Type: RepositoryResourceType, Name: "library/a"}, ActionPull)
					_ = snap.IsRevoked("auth.example", "j2", nil,
						auth.Resource{Type: RepositoryResourceType, Name: "library/b"}, ActionPush)
				}
			}
		}()
	}

	documents := [][]byte{
		[]byte(listWith("j1")),
		[]byte(listWith("j1", "j2")),
		[]byte(listWith("j2")),
		[]byte(`{"version":1,"revoked":[]}`),
		[]byte(`{"version":1,"revoked":[`), // bad document must not panic readers
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	i := 0
	for time.Now().Before(deadline) {
		doc := documents[i%len(documents)]
		source.data.Store(&doc)
		i++
		time.Sleep(3 * time.Millisecond)
	}

	close(stop)
	readers.Wait()
	cancel()
	<-loader.done
}
