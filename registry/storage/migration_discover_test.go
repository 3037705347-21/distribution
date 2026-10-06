package storage

import (
	"context"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

// seedRegistry builds a representative source registry:
//   - repo a: layer L1, manifest revision M1, tag v1 (current M1, index
//     history M0+M1 where M0 is an index-only historical manifest), upload u1;
//   - repo b: shared layer L1, revision M2, tag latest → M2;
//   - repo broken: a malformed layer link and a dangling layer link.
type seededFixture struct {
	d   driver.StorageDriver
	ctx context.Context

	l1, m0, m1, m2 digest.Digest
	// dangling is a well-formed digest with no backing blob data.
	dangling digest.Digest

	uploadID string
}

func seedRegistry(t *testing.T) *seededFixture {
	t.Helper()
	return seedRegistryOn(t, inmemory.New())
}

func seedRegistryOn(t *testing.T, d driver.StorageDriver) *seededFixture {
	t.Helper()
	ctx := context.Background()
	f := &seededFixture{d: d, ctx: ctx, uploadID: "11111111-1111-1111-1111-111111111111"}

	putBlob := func(content string) digest.Digest {
		dgst := digest.FromString(content)
		p, err := pathFor(blobDataPathSpec{digest: dgst})
		require.NoError(t, err)
		require.NoError(t, d.PutContent(ctx, p, []byte(content)))
		return dgst
	}
	putLink := func(spec pathSpec, content string) {
		p, err := pathFor(spec)
		require.NoError(t, err)
		require.NoError(t, d.PutContent(ctx, p, []byte(content)))
	}

	f.l1 = putBlob("layer-one")
	f.m0 = putBlob("manifest-old")
	f.m1 = putBlob("manifest-one")
	f.m2 = putBlob("manifest-two")
	f.dangling = digest.FromString("missing-blob")

	// repo a
	putLink(layerLinkPathSpec{name: "a", digest: f.l1}, f.l1.String())
	putLink(manifestRevisionLinkPathSpec{name: "a", revision: f.m1}, f.m1.String())
	putLink(manifestTagCurrentPathSpec{name: "a", tag: "v1"}, f.m1.String())
	putLink(manifestTagIndexEntryLinkPathSpec{name: "a", tag: "v1", revision: f.m1}, f.m1.String())
	putLink(manifestTagIndexEntryLinkPathSpec{name: "a", tag: "v1", revision: f.m0}, f.m0.String())

	// interrupted upload session on repo a
	dataP, err := pathFor(uploadDataPathSpec{name: "a", id: f.uploadID})
	require.NoError(t, err)
	require.NoError(t, d.PutContent(ctx, dataP, []byte("partial-data")))
	startP, err := pathFor(uploadStartedAtPathSpec{name: "a", id: f.uploadID})
	require.NoError(t, err)
	require.NoError(t, d.PutContent(ctx, startP, []byte(time.Now().UTC().Format(time.RFC3339))))
	hashP, err := pathFor(uploadHashStatePathSpec{name: "a", id: f.uploadID, alg: digest.Canonical, offset: 0})
	require.NoError(t, err)
	require.NoError(t, d.PutContent(ctx, hashP, []byte("hashstate")))

	// repo b shares L1
	putLink(layerLinkPathSpec{name: "b", digest: f.l1}, f.l1.String())
	putLink(manifestRevisionLinkPathSpec{name: "b", revision: f.m2}, f.m2.String())
	putLink(manifestTagCurrentPathSpec{name: "b", tag: "latest"}, f.m2.String())
	putLink(manifestTagIndexEntryLinkPathSpec{name: "b", tag: "latest", revision: f.m2}, f.m2.String())

	// repo broken
	putLink(layerLinkPathSpec{name: "broken", digest: f.dangling}, f.dangling.String())
	malformedPath, err := pathFor(layerLinkPathSpec{name: "broken", digest: digest.FromString("whatever")})
	require.NoError(t, err)
	require.NoError(t, d.PutContent(ctx, malformedPath, []byte("not-a-digest!!")))

	return f
}

// ---- TR-2.1: inventory correctness -----------------------------------------

func TestMigrationDiscoveryInventory(t *testing.T) {
	f := seedRegistry(t)
	snap, err := discover(f.ctx, f.d, nil)
	require.NoError(t, err)

	require.ElementsMatch(t, []string{"a", "b", "broken"}, sortedRepoKeys(snap.Repos))

	ra := snap.Repos["a"]
	require.ElementsMatch(t, []string{f.l1.String()}, sortedKeys(ra.Layers))
	require.ElementsMatch(t, []string{f.m1.String()}, sortedKeys(ra.Revisions))
	tv1 := ra.Tags["v1"]
	require.True(t, tv1.HasCurrent)
	require.Equal(t, f.m1.String(), tv1.Current)
	require.ElementsMatch(t, []string{f.m0.String(), f.m1.String()}, sortedKeys(tv1.Index))

	u := ra.Uploads[f.uploadID]
	require.NotNil(t, u)
	require.True(t, u.HasData)
	require.ElementsMatch(t,
		[]string{"data", "startedat", "hashstates/" + string(digest.Canonical) + "/0"},
		u.Files)
	require.Equal(t, int64(len("partial-data")), u.DataSize)

	rb := snap.Repos["b"]
	require.ElementsMatch(t, []string{f.l1.String()}, sortedKeys(rb.Layers))
	require.Equal(t, f.m2.String(), rb.Tags["latest"].Current)

	// Global blob inventory resolves each linked digest exactly once.
	require.Len(t, snap.BlobSizes, 4)
	require.Equal(t, int64(len("layer-one")), snap.BlobSizes[f.l1.String()])

	// Malformed and dangling links are problems, not inventory.
	var kinds []string
	for _, p := range snap.Problems {
		kinds = append(kinds, p.Kind)
	}
	require.Contains(t, kinds, qKindLinkMalformed)
	require.Contains(t, kinds, qKindLinkDangling)
	require.NotContains(t, kinds, f.dangling.String()+"-as-blob")
}

// ---- TR-2.2: malformed / dangling links never abort enumeration -------------

func TestMigrationDiscoveryProblemsDoNotAbort(t *testing.T) {
	f := seedRegistry(t)
	snap, err := discover(f.ctx, f.d, nil)
	require.NoError(t, err)

	var dangling, malformed int
	for _, p := range snap.Problems {
		switch p.Kind {
		case qKindLinkDangling:
			dangling++
			require.Equal(t, "broken", p.Repo)
		case qKindLinkMalformed:
			malformed++
		}
	}
	require.GreaterOrEqual(t, dangling, 1)
	require.GreaterOrEqual(t, malformed, 1)
}

// ---- TR-2.3: drift detection and fingerprint --------------------------------

func TestMigrationDiscoveryDrift(t *testing.T) {
	f := seedRegistry(t)
	before, err := discover(f.ctx, f.d, nil)
	require.NoError(t, err)

	// No drift when the source is untouched.
	stable, err := discover(f.ctx, f.d, nil)
	require.NoError(t, err)
	require.True(t, diffDiscovery(before, stable).Clean())
	require.Equal(t, before.fingerprint("inmemory"), stable.fingerprint("inmemory"))

	// Source drift: push a new tag v2 onto repo a.
	p, err := pathFor(manifestTagCurrentPathSpec{name: "a", tag: "v2"})
	require.NoError(t, err)
	require.NoError(t, f.d.PutContent(f.ctx, p, []byte(f.m1.String())))
	p, err = pathFor(manifestTagIndexEntryLinkPathSpec{name: "a", tag: "v2", revision: f.m1})
	require.NoError(t, err)
	require.NoError(t, f.d.PutContent(f.ctx, p, []byte(f.m1.String())))

	after, err := discover(f.ctx, f.d, nil)
	require.NoError(t, err)
	d := diffDiscovery(before, after)
	require.False(t, d.Clean())
	require.ElementsMatch(t, []string{"v2"}, d.RepoChanges["a"].AddedTags)
	require.NotEqual(t, before.fingerprint("inmemory"), after.fingerprint("inmemory"))
}

// ---- TR-2.4: discovery is read-only on the source ---------------------------

func TestMigrationDiscoveryIsReadOnly(t *testing.T) {
	f := seedRegistry(t)
	ro := newPanicWriteDriver(t, f.d)
	snap, err := discover(f.ctx, ro, nil)
	require.NoError(t, err)
	require.Len(t, snap.Repos, 3)
}

// ---- upsert: discovery merged into ledger -----------------------------------

func TestMigrationUpsert(t *testing.T) {
	f := seedRegistry(t)
	snap, err := discover(f.ctx, f.d, nil)
	require.NoError(t, err)

	l := newMigrationLedger(inmemory.New(), "")
	res, err := upsertDiscovery(f.ctx, l, snap, true, true)
	require.NoError(t, err)
	require.Equal(t, 4, res.NewBlobs)
	require.GreaterOrEqual(t, res.Problems, 2)

	// The shared layer record carries both repositories as refs.
	rec, exists, err := l.getBlobRecord(f.ctx, f.l1)
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, statePending, rec.State)
	require.Equal(t, []string{"a", "b"}, rec.Refs)
	require.Equal(t, int64(len("layer-one")), rec.ExpectedSize)

	ra, exists, err := l.getRepoRecord(f.ctx, "a")
	require.NoError(t, err)
	require.True(t, exists)
	require.Equal(t, statePending, ra.Layers[f.l1.String()].State)
	require.Equal(t, f.m1.String(), ra.Tags["v1"].Current)
	require.Contains(t, ra.Tags["v1"].Index, f.m0.String())
	require.Equal(t, statePending, ra.Uploads[f.uploadID].State)

	// Problems land in quarantine, unresolved.
	var qs []*quarantineRecord
	require.NoError(t, l.listQuarantineRecords(f.ctx, func(q *quarantineRecord) error {
		if !q.Resolved {
			qs = append(qs, q)
		}
		return nil
	}))
	require.GreaterOrEqual(t, len(qs), 2)

	// Idempotent re-upsert introduces no new units / duplicates quarantine.
	res2, err := upsertDiscovery(f.ctx, l, snap, true, true)
	require.NoError(t, err)
	require.Zero(t, res2.NewBlobs)
	require.Zero(t, res2.NewLayerLinks)

	var qs2 []*quarantineRecord
	require.NoError(t, l.listQuarantineRecords(f.ctx, func(q *quarantineRecord) error {
		if !q.Resolved {
			qs2 = append(qs2, q)
		}
		return nil
	}))
	require.Len(t, qs2, len(qs))
}

func TestMigrationUpsertSkipsUploads(t *testing.T) {
	f := seedRegistry(t)
	snap, err := discover(f.ctx, f.d, nil)
	require.NoError(t, err)

	l := newMigrationLedger(inmemory.New(), "")
	_, err = upsertDiscovery(f.ctx, l, snap, false, true)
	require.NoError(t, err)
	ra, _, err := l.getRepoRecord(f.ctx, "a")
	require.NoError(t, err)
	require.Equal(t, stateSkipped, ra.Uploads[f.uploadID].State)
}

func sortedRepoKeys(m map[string]*discoveredRepo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
