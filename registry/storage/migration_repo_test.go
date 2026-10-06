package storage

import (
	"context"
	"strings"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

type repoMigrationHarness struct {
	t   *testing.T
	ctx context.Context
	f   *seededFixture
	src driver.StorageDriver
	dst *migrationTestDriver
	l   *migrationLedger
	bm  *blobMigrator
	rm  *repoMigrator
}

func newRepoMigrationHarness(t *testing.T, includeUploads bool) *repoMigrationHarness {
	f := seedRegistry(t)
	dst := newMigrationTestDriver(inmemory.New())
	l := newMigrationLedger(dst, "")
	ctx := context.Background()
	_, err := l.initRun(ctx, "inmemory", "fp")
	require.NoError(t, err)

	snap, err := discover(ctx, f.d, nil)
	require.NoError(t, err)
	_, err = upsertDiscovery(ctx, l, snap, includeUploads, true)
	require.NoError(t, err)

	bm := newBlobMigrator(f.d, dst, l)
	rm := newRepoMigrator(f.d, dst, l, bm)
	bm.chunkSize, rm.chunkSize = 100, 100
	return &repoMigrationHarness{t: t, ctx: ctx, f: f, src: f.d, dst: dst, l: l, bm: bm, rm: rm}
}

// readTree walks a source-side prefix on a driver and returns path->content
// for every file below it.
func readLinkTree(t *testing.T, ctx context.Context, d driver.StorageDriver, prefix string) map[string]string {
	t.Helper()
	out := map[string]string{}
	require.NoError(t, d.Walk(ctx, prefix, func(fi driver.FileInfo) error {
		if fi.IsDir() {
			return nil
		}
		b, err := d.GetContent(ctx, fi.Path())
		require.NoError(t, err)
		out[fi.Path()] = string(b)
		return nil
	}))
	return out
}

// ---- TR-4.1: revisions and full tag history copied byte-for-byte -----------

func TestRepoMigrateTagsHistory(t *testing.T) {
	h := newRepoMigrationHarness(t, true)

	ra, err := h.rm.migrateRepo(h.ctx, "a")
	require.NoError(t, err)
	require.True(t, ra.Completed, "blockers: %v", ra.Blockers)
	rb, err := h.rm.migrateRepo(h.ctx, "b")
	require.NoError(t, err)
	require.True(t, rb.Completed)

	// Compare the _manifests tree of repo "a" between source and target.
	srcRoot, err := pathFor(manifestsPathSpec{name: "a"})
	require.NoError(t, err)
	srcTree := readLinkTree(t, h.ctx, h.src, srcRoot)
	dstTree := readLinkTree(t, h.ctx, h.dst, srcRoot)
	require.Equal(t, srcTree, dstTree, "revisions, current and index links must be identical")

	// The historical (index-only) manifest blob is present and verifiable.
	histPath, err := pathFor(blobDataPathSpec{digest: h.f.m0})
	require.NoError(t, err)
	b, err := h.dst.GetContent(h.ctx, histPath)
	require.NoError(t, err)
	require.Equal(t, "manifest-old", string(b))
	require.Equal(t, h.f.m0, digest.FromBytes(b))

	// Repo record is completed including the index history.
	rec, _, err := h.l.getRepoRecord(h.ctx, "a")
	require.NoError(t, err)
	require.Equal(t, stateCompleted, rec.State)
	require.Equal(t, stateCompleted, rec.Tags["v1"].CurrentState)
	require.Equal(t, stateCompleted, rec.Tags["v1"].Index[h.f.m0.String()])
	require.Equal(t, stateCompleted, rec.Tags["v1"].Index[h.f.m1.String()])
}

// ---- TR-4.2: upload sessions copied as sessions, never promoted -------------

func TestRepoMigrateUploadSessionNeverPromoted(t *testing.T) {
	h := newRepoMigrationHarness(t, true)
	ra, err := h.rm.migrateRepo(h.ctx, "a")
	require.NoError(t, err)
	require.True(t, ra.Completed)
	require.Equal(t, 1, ra.SessionsCopied)

	id := h.f.uploadID
	dataP, err := pathFor(uploadDataPathSpec{name: "a", id: id})
	require.NoError(t, err)
	b, err := h.dst.GetContent(h.ctx, dataP)
	require.NoError(t, err)
	require.Equal(t, "partial-data", string(b))

	startP, err := pathFor(uploadStartedAtPathSpec{name: "a", id: id})
	require.NoError(t, err)
	srcStart, err := h.src.GetContent(h.ctx, startP)
	require.NoError(t, err)
	dstStart, err := h.dst.GetContent(h.ctx, startP)
	require.NoError(t, err)
	require.Equal(t, string(srcStart), string(dstStart))

	hashP, err := pathFor(uploadHashStatePathSpec{name: "a", id: id, alg: digest.Canonical, offset: 0})
	require.NoError(t, err)
	hb, err := h.dst.GetContent(h.ctx, hashP)
	require.NoError(t, err)
	require.Equal(t, "hashstate", string(hb))

	// The partial bytes must not appear in the global blob store.
	partialDigest := digest.FromString("partial-data")
	blobP, err := pathFor(blobDataPathSpec{digest: partialDigest})
	require.NoError(t, err)
	_, err = h.dst.Stat(h.ctx, blobP)
	var pnf driver.PathNotFoundError
	require.ErrorAs(t, err, &pnf, "upload data must never be promoted to a blob")

	// And no link file anywhere references the upload digest.
	repoRoot, err := pathFor(repositoriesRootPathSpec{})
	require.NoError(t, err)
	foundLink := false
	require.NoError(t, h.dst.Walk(h.ctx, repoRoot, func(fi driver.FileInfo) error {
		if fi.IsDir() || pathBase(fi.Path()) != "link" {
			return nil
		}
		c, err := h.dst.GetContent(h.ctx, fi.Path())
		if err == nil && strings.TrimSpace(string(c)) == partialDigest.String() {
			foundLink = true
		}
		return nil
	}))
	require.False(t, foundLink, "no link may point at an upload session")
}

// ---- TR-4.3: skipped uploads do not block repo completion --------------------

func TestRepoMigrateSkipsUploads(t *testing.T) {
	h := newRepoMigrationHarness(t, false)
	ra, err := h.rm.migrateRepo(h.ctx, "a")
	require.NoError(t, err)
	require.True(t, ra.Completed)
	require.Zero(t, ra.SessionsCopied)
	require.Equal(t, 1, ra.SessionsSkipped)

	dataP, err := pathFor(uploadDataPathSpec{name: "a", id: h.f.uploadID})
	require.NoError(t, err)
	_, err = h.dst.Stat(h.ctx, dataP)
	var pnf driver.PathNotFoundError
	require.ErrorAs(t, err, &pnf, "skipped upload data must not be copied")
}

// ---- TR-4.4: missing target blob isolates the link and blocks completion ------

func TestRepoMigrateMissingBlobThenRepair(t *testing.T) {
	ctx := context.Background()
	src := newMigrationTestDriver(inmemory.New())
	dst := newMigrationTestDriver(inmemory.New())
	l := newMigrationLedger(dst, "")
	_, err := l.initRun(ctx, "inmemory", "fp")
	require.NoError(t, err)

	dangling := digest.FromString("ghost-blob")
	good := digest.FromString("good-layer")
	goodP, err := pathFor(blobDataPathSpec{digest: good})
	require.NoError(t, err)
	require.NoError(t, src.PutContent(ctx, goodP, []byte("good-layer")))

	// repo "r" links a good layer and a dangling layer.
	p, err := pathFor(layerLinkPathSpec{name: "r", digest: good})
	require.NoError(t, err)
	require.NoError(t, src.PutContent(ctx, p, []byte(good.String())))
	p, err = pathFor(layerLinkPathSpec{name: "r", digest: dangling})
	require.NoError(t, err)
	require.NoError(t, src.PutContent(ctx, p, []byte(dangling.String())))

	sweep := func() {
		snap, derr := discover(ctx, src, nil)
		require.NoError(t, derr)
		_, derr = upsertDiscovery(ctx, l, snap, true, true)
		require.NoError(t, derr)
	}
	sweep()
	bm := newBlobMigrator(src, dst, l)
	rm := newRepoMigrator(src, dst, l, bm)

	res, err := rm.migrateRepo(ctx, "r")
	require.NoError(t, err)
	require.False(t, res.Completed, "dangling layer must block completion")
	rec, _, err := l.getRepoRecord(ctx, "r")
	require.NoError(t, err)
	require.Equal(t, stateQuarantined, rec.Layers[dangling.String()].State)

	// Repair the source: provide the missing blob, re-discover, re-migrate.
	ghostP, err := pathFor(blobDataPathSpec{digest: dangling})
	require.NoError(t, err)
	require.NoError(t, src.PutContent(ctx, ghostP, []byte("ghost-blob")))
	sweep()
	res, err = rm.migrateRepo(ctx, "r")
	require.NoError(t, err)
	require.True(t, res.Completed, "blockers: %v", res.Blockers)
}

// ---- TR-4.5: idempotent rerun --------------------------------------------------

func TestRepoMigrateIdempotent(t *testing.T) {
	h := newRepoMigrationHarness(t, true)
	first, err := h.rm.migrateRepo(h.ctx, "a")
	require.NoError(t, err)
	require.True(t, first.Completed)
	require.Greater(t, first.LinksCopied, 0)

	second, err := h.rm.migrateRepo(h.ctx, "a")
	require.NoError(t, err)
	require.True(t, second.Completed)
	require.Zero(t, second.LinksCopied, "rerun must not recopy settled links")
}

// ---- read-only source for repo migration ---------------------------------------

func TestRepoMigrateSourceIsReadOnly(t *testing.T) {
	f := seedRegistry(t)
	ro := newPanicWriteDriver(t, f.d)
	dst := inmemory.New()
	l := newMigrationLedger(dst, "")
	ctx := context.Background()
	_, err := l.initRun(ctx, "inmemory", "fp")
	require.NoError(t, err)
	snap, err := discover(ctx, ro, nil)
	require.NoError(t, err)
	_, err = upsertDiscovery(ctx, l, snap, true, true)
	require.NoError(t, err)
	bm := newBlobMigrator(ro, dst, l)
	rm := newRepoMigrator(ro, dst, l, bm)
	res, err := rm.migrateRepo(ctx, "a")
	require.NoError(t, err)
	require.True(t, res.Completed, "blockers: %v", res.Blockers)
}

func pathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
