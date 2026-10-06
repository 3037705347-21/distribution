package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"path"
	"reflect"
	"testing"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/registry/storage/cache/memory"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/distribution/distribution/v3/testutil"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

type setupEnv struct {
	ctx      context.Context
	driver   driver.StorageDriver
	expected []string
	registry distribution.Namespace
}

func setupFS(t *testing.T) *setupEnv {
	d := inmemory.New()
	ctx := context.Background()
	registry, err := NewRegistry(ctx, d, BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)), EnableRedirect)
	if err != nil {
		t.Fatalf("error creating registry: %v", err)
	}

	repos := []string{
		"foo/a",
		"foo/b",
		"foo-bar/a",
		"bar/c",
		"bar/d",
		"bar/e",
		"foo/d/in",
		"foo-bar/b",
		"test",
	}

	for _, repo := range repos {
		makeRepo(ctx, t, repo, registry)
	}

	expected := []string{
		"bar/c",
		"bar/d",
		"bar/e",
		"foo/a",
		"foo/b",
		"foo/d/in",
		"foo-bar/a",
		"foo-bar/b",
		"test",
	}

	return &setupEnv{
		ctx:      ctx,
		driver:   d,
		expected: expected,
		registry: registry,
	}
}

func makeRepo(ctx context.Context, t *testing.T, name string, reg distribution.Namespace) {
	named, err := reference.WithName(name)
	if err != nil {
		t.Fatal(err)
	}

	repo, _ := reg.Repository(ctx, named)
	manifests, _ := repo.Manifests(ctx)

	layers, err := testutil.CreateRandomLayers(1)
	if err != nil {
		t.Fatal(err)
	}

	// upload the layers
	err = testutil.UploadBlobs(repo, layers)
	if err != nil {
		t.Fatalf("failed to upload layers: %v", err)
	}

	digests := make([]digest.Digest, 0, len(layers))
	for digest := range layers {
		digests = append(digests, digest)
	}

	manifest, err := testutil.MakeSchema2Manifest(repo, digests)
	if err != nil {
		t.Fatal(err)
	}

	_, err = manifests.Put(ctx, manifest)
	if err != nil {
		t.Fatalf("manifest upload failed: %v", err)
	}
}

func TestCatalog(t *testing.T) {
	env := setupFS(t)

	p := make([]string, 50)

	numFilled, err := env.registry.Repositories(env.ctx, p, "")
	if numFilled != len(env.expected) {
		t.Errorf("missing items in catalog")
	}

	if !testEq(p, env.expected, len(env.expected)) {
		t.Errorf("Expected catalog repos err")
	}

	if err != io.EOF {
		t.Errorf("Catalog has more values which we aren't expecting")
	}
}

func TestCatalogInParts(t *testing.T) {
	env := setupFS(t)

	chunkLen := 3
	p := make([]string, chunkLen)

	numFilled, err := env.registry.Repositories(env.ctx, p, "")
	if err == io.EOF || numFilled != len(p) {
		t.Errorf("Expected more values in catalog")
	}

	if !testEq(p, env.expected[0:chunkLen], numFilled) {
		t.Errorf("Expected catalog first chunk err")
	}

	lastRepo := p[len(p)-1]
	numFilled, err = env.registry.Repositories(env.ctx, p, lastRepo)

	if err == io.EOF || numFilled != len(p) {
		t.Errorf("Expected more values in catalog")
	}

	if !testEq(p, env.expected[chunkLen:chunkLen*2], numFilled) {
		t.Errorf("Expected catalog second chunk err")
	}

	lastRepo = p[len(p)-1]
	numFilled, err = env.registry.Repositories(env.ctx, p, lastRepo)

	if numFilled != len(p) {
		t.Errorf("Expected more values in catalog")
	}

	if err != io.EOF {
		t.Errorf("Expected end of catalog")
	}

	if !testEq(p, env.expected[chunkLen*2:chunkLen*3], numFilled) {
		t.Errorf("Expected catalog third chunk err")
	}

	lastRepo = p[len(p)-1]
	numFilled, err = env.registry.Repositories(env.ctx, p, lastRepo)

	if err != io.EOF {
		t.Errorf("Catalog has more values which we aren't expecting")
	}

	if numFilled != 0 {
		t.Errorf("Expected catalog fourth chunk err")
	}
}

func TestCatalogEnumerate(t *testing.T) {
	env := setupFS(t)

	var repos []string
	repositoryEnumerator := env.registry.(distribution.RepositoryEnumerator)
	err := repositoryEnumerator.Enumerate(env.ctx, func(repoName string) error {
		repos = append(repos, repoName)
		return nil
	})
	if err != nil {
		t.Errorf("Expected catalog enumerate err")
	}

	if len(repos) != len(env.expected) {
		t.Errorf("Expected catalog enumerate doesn't have correct number of values")
	}

	if !testEq(repos, env.expected, len(env.expected)) {
		t.Errorf("Expected catalog enumerate not over all values")
	}
}

func testEq(a, b []string, size int) bool {
	for cnt := 0; cnt < size-1; cnt++ {
		if a[cnt] != b[cnt] {
			return false
		}
	}
	return true
}

func setupBadWalkEnv(t *testing.T) *setupEnv {
	d := newBadListDriver()
	ctx := context.Background()
	registry, err := NewRegistry(ctx, d, BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)), EnableRedirect)
	if err != nil {
		t.Fatalf("error creating registry: %v", err)
	}

	return &setupEnv{
		ctx:      ctx,
		driver:   d,
		registry: registry,
	}
}

type badListDriver struct {
	driver.StorageDriver
}

var _ driver.StorageDriver = &badListDriver{}

func newBadListDriver() *badListDriver {
	return &badListDriver{StorageDriver: inmemory.New()}
}

func (d *badListDriver) List(ctx context.Context, path string) ([]string, error) {
	return nil, fmt.Errorf("List error")
}

// Walk drives the fallback walk through the outer driver so the List failure
// above is actually observed (the embedded inmemory driver's Walk would
// otherwise recurse through its own inner driver).
func (d *badListDriver) Walk(ctx context.Context, path string, f driver.WalkFn, options ...func(*driver.WalkOptions)) error {
	return driver.WalkFallback(ctx, d, path, f, options...)
}

func TestCatalogWalkError(t *testing.T) {
	env := setupBadWalkEnv(t)
	p := make([]string, 1)

	_, err := env.registry.Repositories(env.ctx, p, "")
	if err == io.EOF {
		t.Errorf("Expected catalog driver list error")
	}
}

func BenchmarkPathCompareEqual(B *testing.B) {
	B.StopTimer()
	pp := randomPath(100)
	// make a real copy
	ppb := append([]byte{}, []byte(pp)...)
	a, b := pp, string(ppb)

	B.StartTimer()
	for i := 0; i < B.N; i++ {
		lessPath(a, b)
	}
}

func BenchmarkPathCompareNotEqual(B *testing.B) {
	B.StopTimer()
	a, b := randomPath(100), randomPath(100)
	B.StartTimer()

	for i := 0; i < B.N; i++ {
		lessPath(a, b)
	}
}

func BenchmarkPathCompareNative(B *testing.B) {
	B.StopTimer()
	a, b := randomPath(100), randomPath(100)
	B.StartTimer()

	for i := 0; i < B.N; i++ {
		c := a < b
		_ = c && false
	}
}

func BenchmarkPathCompareNativeEqual(B *testing.B) {
	B.StopTimer()
	pp := randomPath(100)
	a, b := pp, pp
	B.StartTimer()

	for i := 0; i < B.N; i++ {
		c := a < b
		_ = c && false
	}
}

var (
	filenameChars  = []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	separatorChars = []byte("._-")
)

func randomPath(length int64) string {
	path := "/"
	for int64(len(path)) < length {
		chunkLength := rand.Int63n(length-int64(len(path))) + 1
		chunk := randomFilename(chunkLength)
		path += chunk
		remaining := length - int64(len(path))
		if remaining == 1 {
			path += randomFilename(1)
		} else if remaining > 1 {
			path += "/"
		}
	}
	return path
}

func randomFilename(length int64) string {
	b := make([]byte, length)
	wasSeparator := true
	for i := range b {
		if !wasSeparator && i < len(b)-1 && rand.Intn(4) == 0 {
			b[i] = separatorChars[rand.Intn(len(separatorChars))]
			wasSeparator = true
		} else {
			b[i] = filenameChars[rand.Intn(len(filenameChars))]
			wasSeparator = false
		}
	}
	return string(b)
}

// paginateCatalog walks the entire catalog in pages of chunkLen, failing if
// the sequence does not converge (a regression guard for skips, duplicates or
// hangs in pagination).
func paginateCatalog(t *testing.T, ctx context.Context, ns distribution.Namespace, chunkLen int) []string {
	t.Helper()

	var got []string
	last := ""
	for range 1000 {
		p := make([]string, chunkLen)
		n, err := ns.Repositories(ctx, p, last)
		got = append(got, p[:n]...)
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatalf("Repositories returned error: %v", err)
		}
		if n == 0 {
			t.Fatal("Repositories returned 0 entries without io.EOF")
		}
		last = p[n-1]
	}
	t.Fatal("catalog pagination did not converge")
	return nil
}

// TestCatalogSnapshotStablePagination verifies that once a snapshot is
// published, deletes and temporary upload directories appearing in storage do
// not change what any subsequent page returns.
func TestCatalogSnapshotStablePagination(t *testing.T) {
	env := setupFS(t)
	reg := env.registry.(*registry)

	if err := reg.RefreshCatalog(env.ctx); err != nil {
		t.Fatalf("initial refresh failed: %v", err)
	}

	// mutate storage after publication
	for _, name := range []string{"bar/c", "foo/a", "test"} {
		manifestsPath, err := pathFor(manifestsPathSpec{name: name})
		if err != nil {
			t.Fatal(err)
		}
		if err := env.driver.Delete(env.ctx, manifestsPath); err != nil {
			t.Fatalf("delete failed: %v", err)
		}
	}
	uploadPath, err := pathFor(uploadDataPathSpec{name: "bar/d", id: "temp123"})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.driver.PutContent(env.ctx, uploadPath, []byte("partial upload")); err != nil {
		t.Fatal(err)
	}

	got := paginateCatalog(t, env.ctx, env.registry, 3)
	if !reflect.DeepEqual(got, env.expected) {
		t.Errorf("paginated catalog drifted from published snapshot:\nwant %v\ngot  %v", env.expected, got)
	}
}

// TestCatalogSnapshotRefreshConverges verifies additions and deletions become
// visible after a rebuild, in stable order.
func TestCatalogSnapshotRefreshConverges(t *testing.T) {
	env := setupFS(t)
	reg := env.registry.(*registry)

	if err := reg.RefreshCatalog(env.ctx); err != nil {
		t.Fatalf("initial refresh failed: %v", err)
	}

	// delete bar/c and add zzz/new
	manifestsPath, err := pathFor(manifestsPathSpec{name: "bar/c"})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.driver.Delete(env.ctx, manifestsPath); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	makeRepo(env.ctx, t, "zzz/new", env.registry)

	if err := reg.RefreshCatalog(env.ctx); err != nil {
		t.Fatalf("second refresh failed: %v", err)
	}

	want := []string{
		"bar/d", "bar/e",
		"foo/a", "foo/b", "foo/d/in",
		"foo-bar/a", "foo-bar/b",
		"test", "zzz/new",
	}
	got := paginateCatalog(t, env.ctx, env.registry, 4)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("catalog did not converge to expected set:\nwant %v\ngot  %v", want, got)
	}
}

// flakyDriver injects failures into Move or PutContent while forwarding all
// other calls to the wrapped driver.
type flakyDriver struct {
	driver.StorageDriver
	failMove bool
	failPut  bool
}

func (d *flakyDriver) Move(ctx context.Context, sourcePath, destPath string) error {
	if d.failMove {
		return errors.New("simulated move failure")
	}
	return d.StorageDriver.Move(ctx, sourcePath, destPath)
}

func (d *flakyDriver) PutContent(ctx context.Context, path string, content []byte) error {
	if d.failPut {
		return errors.New("simulated put failure")
	}
	return d.StorageDriver.PutContent(ctx, path, content)
}

// TestCatalogSnapshotPublishFailureKeepsPrevious verifies that a failed
// publish never replaces the served snapshot, the on-disk published object, or
// leaks staging objects — and that a later successful publish converges.
func TestCatalogSnapshotPublishFailureKeepsPrevious(t *testing.T) {
	ctx := context.Background()
	d := &flakyDriver{StorageDriver: inmemory.New()}
	ns, err := NewRegistry(ctx, d,
		BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)),
		EnableRedirect, CatalogRefreshInterval(0))
	if err != nil {
		t.Fatalf("error creating registry: %v", err)
	}
	reg := ns.(*registry)

	for _, name := range []string{"a/one", "a/two", "b/one"} {
		makeRepo(ctx, t, name, ns)
	}
	if err := reg.RefreshCatalog(ctx); err != nil {
		t.Fatalf("initial publish failed: %v", err)
	}

	makeRepo(ctx, t, "c/new", ns)

	// Move failure: staging can never replace current.
	d.failMove = true
	if err := reg.RefreshCatalog(ctx); err == nil {
		t.Fatal("expected RefreshCatalog to fail when move fails")
	}
	want := []string{"a/one", "a/two", "b/one"}
	if got := paginateCatalog(t, ctx, ns, 2); !reflect.DeepEqual(got, want) {
		t.Errorf("snapshot changed after failed move:\nwant %v\ngot  %v", want, got)
	}

	// Put failure: not even a staging object should survive.
	d.failMove = false
	d.failPut = true
	if err := reg.RefreshCatalog(ctx); err == nil {
		t.Fatal("expected RefreshCatalog to fail when put fails")
	}
	if got := paginateCatalog(t, ctx, ns, 2); !reflect.DeepEqual(got, want) {
		t.Errorf("snapshot changed after failed put:\nwant %v\ngot  %v", want, got)
	}
	stagingDir, err := pathFor(catalogStagingDirPathSpec{})
	if err != nil {
		t.Fatal(err)
	}
	remnants, err := d.List(ctx, stagingDir)
	if err != nil {
		t.Fatalf("list staging failed: %v", err)
	}
	if len(remnants) != 0 {
		t.Errorf("failed publish left staging objects: %v", remnants)
	}

	// Recovery: the new set converges once publishes succeed again.
	d.failPut = false
	if err := reg.RefreshCatalog(ctx); err != nil {
		t.Fatalf("recovery refresh failed: %v", err)
	}
	wantConverged := []string{"a/one", "a/two", "b/one", "c/new"}
	if got := paginateCatalog(t, ctx, ns, 3); !reflect.DeepEqual(got, wantConverged) {
		t.Errorf("catalog did not converge after recovery:\nwant %v\ngot  %v", wantConverged, got)
	}
}

// TestCatalogDisplayAnnotationsPreserved verifies tenant-maintained display
// information is merged into the snapshot, survives while the repository is
// absent, and reattaches when the repository comes back.
func TestCatalogDisplayAnnotationsPreserved(t *testing.T) {
	env := setupFS(t)
	reg := env.registry.(*registry)
	ctx := env.ctx

	named, err := reference.WithName("foo/a")
	if err != nil {
		t.Fatal(err)
	}
	display := CatalogDisplay{
		Title:       "Foo A",
		Description: "the first foo",
		Labels:      map[string]string{"team": "platform"},
	}
	if err := reg.UpdateCatalogDisplay(ctx, named, display); err != nil {
		t.Fatalf("update display failed: %v", err)
	}
	if err := reg.RefreshCatalog(ctx); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	if got := snapshotDisplay(reg, "foo/a"); got == nil || got.Title != "Foo A" {
		t.Errorf("display not merged into snapshot: %+v", got)
	}

	// remove the repository and rebuild
	manifestsPath, err := pathFor(manifestsPathSpec{name: "foo/a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.driver.Delete(ctx, manifestsPath); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if err := reg.RefreshCatalog(ctx); err != nil {
		t.Fatalf("refresh after delete failed: %v", err)
	}
	got := paginateCatalog(t, ctx, env.registry, 5)
	for _, name := range got {
		if name == "foo/a" {
			t.Fatalf("deleted repository still served: %v", got)
		}
	}
	if got := snapshotDisplay(reg, "foo/a"); got != nil {
		t.Errorf("display attached to absent repository: %+v", got)
	}
	info, err := reg.CatalogDisplayInfo(ctx, named)
	if err != nil {
		t.Fatalf("read display failed: %v", err)
	}
	if info == nil || info.Title != "Foo A" {
		t.Errorf("display information lost while repository absent: %+v", info)
	}

	// recreate the repository; the hand-maintained display information reattaches
	makeRepo(ctx, t, "foo/a", env.registry)
	if err := reg.RefreshCatalog(ctx); err != nil {
		t.Fatalf("refresh after recreate failed: %v", err)
	}
	if got := snapshotDisplay(reg, "foo/a"); got == nil || got.Title != "Foo A" {
		t.Errorf("display not reattached after repository recreated: %+v", got)
	}
}

// snapshotDisplay returns the display entry for name in the current snapshot.
func snapshotDisplay(reg *registry, name string) *CatalogDisplay {
	snap := reg.catalogSnapshot.Load()
	if snap == nil {
		return nil
	}
	for _, entry := range snap.Repositories {
		if entry.Name == name {
			return entry.Display
		}
	}
	return nil
}

// TestCatalogExcludesNonRepositoryPaths verifies directories without a
// _manifests marker, underscore entries and temporary upload paths never enter
// the catalog.
func TestCatalogExcludesNonRepositoryPaths(t *testing.T) {
	env := setupFS(t)
	reg := env.registry.(*registry)

	root, err := pathFor(repositoriesRootPathSpec{})
	if err != nil {
		t.Fatal(err)
	}
	junk := []string{
		path.Join(root, "scratch", "notes"),
		path.Join(root, "_tmp", "abc"),
		path.Join(root, "foo", "_uploads", "x", "data"),
	}
	for _, junkPath := range junk {
		if err := env.driver.PutContent(env.ctx, junkPath, []byte("junk")); err != nil {
			t.Fatalf("failed to place junk path %s: %v", junkPath, err)
		}
	}

	if err := reg.RefreshCatalog(env.ctx); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	got := paginateCatalog(t, env.ctx, env.registry, 2)
	if !reflect.DeepEqual(got, env.expected) {
		t.Errorf("non-repository paths leaked into catalog:\nwant %v\ngot  %v", env.expected, got)
	}
}

// TestCatalogSnapshotRecovery verifies recovery from interrupted builds:
// leftover staging objects are cleared on the next build, and a registry
// restart facing a corrupted published snapshot rebuilds rather than serving
// garbage.
func TestCatalogSnapshotRecovery(t *testing.T) {
	ctx := context.Background()
	d := inmemory.New()
	ns, err := NewRegistry(ctx, d,
		BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)),
		EnableRedirect, CatalogRefreshInterval(0))
	if err != nil {
		t.Fatalf("error creating registry: %v", err)
	}

	// an interrupted build left half-written staging content
	leftoverPath, err := pathFor(catalogStagingPathSpec{id: "interrupted"})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PutContent(ctx, leftoverPath, []byte("{incomplete")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"repo/a", "repo/b"} {
		makeRepo(ctx, t, name, ns)
	}

	want := []string{"repo/a", "repo/b"}
	if got := paginateCatalog(t, ctx, ns, 1); !reflect.DeepEqual(got, want) {
		t.Errorf("catalog after interrupted build:\nwant %v\ngot  %v", want, got)
	}
	stagingDir, err := pathFor(catalogStagingDirPathSpec{})
	if err != nil {
		t.Fatal(err)
	}
	remnants, err := d.List(ctx, stagingDir)
	if err != nil {
		t.Fatalf("list staging failed: %v", err)
	}
	if len(remnants) != 0 {
		t.Errorf("staging leftovers not cleaned: %v", remnants)
	}

	// simulate a corrupted published object and a fresh registry process
	currentPath, err := pathFor(catalogSnapshotPathSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PutContent(ctx, currentPath, []byte("{broken")); err != nil {
		t.Fatal(err)
	}
	ns2, err := NewRegistry(ctx, d,
		BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)),
		EnableRedirect, CatalogRefreshInterval(0))
	if err != nil {
		t.Fatalf("error creating second registry: %v", err)
	}
	if got := paginateCatalog(t, ctx, ns2, 1); !reflect.DeepEqual(got, want) {
		t.Errorf("catalog did not recover from corrupted snapshot:\nwant %v\ngot  %v", want, got)
	}
}

// TestCatalogEmptyNotFrozen verifies an empty registry does not pin an empty
// snapshot, so the first pushes become visible immediately (regression guard
// for the /v2/_catalog empty-then-populated flow).
func TestCatalogEmptyNotFrozen(t *testing.T) {
	ctx := context.Background()
	d := inmemory.New()
	ns, err := NewRegistry(ctx, d,
		BlobDescriptorCacheProvider(memory.NewInMemoryBlobDescriptorCacheProvider(memory.UnlimitedSize)),
		EnableRedirect, CatalogRefreshInterval(0))
	if err != nil {
		t.Fatalf("error creating registry: %v", err)
	}
	reg := ns.(*registry)

	p := make([]string, 5)
	n, err := reg.Repositories(ctx, p, "")
	if n != 0 || err != io.EOF {
		t.Fatalf("empty catalog: n=%d err=%v, want n=0 err=io.EOF", n, err)
	}
	if reg.catalogSnapshot.Load() != nil {
		t.Fatal("empty view must not be frozen as a snapshot")
	}

	makeRepo(ctx, t, "new/repo", ns)
	n, err = reg.Repositories(ctx, p, "")
	if n != 1 || err != io.EOF {
		t.Fatalf("populated catalog: n=%d err=%v, want n=1 err=io.EOF", n, err)
	}
	if p[0] != "new/repo" {
		t.Errorf("got %q, want new/repo", p[0])
	}
}
