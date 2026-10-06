package storage

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/inmemory"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

// blobMigrationHarness wires a recording source, a destination and a ledger.
type blobMigrationHarness struct {
	t   *testing.T
	ctx context.Context

	src *migrationTestDriver
	dst *migrationTestDriver
	l   *migrationLedger
}

func newBlobMigrationHarness(t *testing.T) *blobMigrationHarness {
	ctx := context.Background()
	// The ledger lives on the destination backend, exactly as in production.
	dst := newMigrationTestDriver(inmemory.New())
	h := &blobMigrationHarness{
		t:   t,
		ctx: ctx,
		src: newMigrationTestDriver(inmemory.New()),
		dst: dst,
		l:   newMigrationLedger(dst, ""),
	}
	_, err := h.l.initRun(ctx, "inmemory", "fp")
	require.NoError(t, err)
	return h
}

func (h *blobMigrationHarness) putSourceBlob(content string) digest.Digest {
	dgst := digest.FromString(content)
	p, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(h.t, err)
	require.NoError(h.t, h.src.PutContent(h.ctx, p, []byte(content)))
	return dgst
}

func (h *blobMigrationHarness) putTargetBlob(dgst digest.Digest, content string) {
	p, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(h.t, err)
	require.NoError(h.t, h.dst.PutContent(h.ctx, p, []byte(content)))
}

func (h *blobMigrationHarness) seedBlobRecord(dgst digest.Digest, size int64) {
	_, err := h.l.mutateBlobRecord(h.ctx, dgst, true, func(r *blobRecord) error {
		r.ExpectedSize = size
		return nil
	})
	require.NoError(h.t, err)
}

func (h *blobMigrationHarness) migrator() *blobMigrator {
	m := newBlobMigrator(h.src, h.dst, h.l)
	m.chunkSize = 100
	return m
}

func (h *blobMigrationHarness) targetContent(dgst digest.Digest) []byte {
	p, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(h.t, err)
	b, err := h.dst.GetContent(h.ctx, p)
	require.NoError(h.t, err)
	return b
}

func (h *blobMigrationHarness) targetCanonicalExists(dgst digest.Digest) bool {
	p, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(h.t, err)
	_, err = h.dst.Stat(h.ctx, p)
	return err == nil
}

// failAfterReadCloser errors once after `after` bytes have been read.
type failAfterReadCloser struct {
	rc     io.ReadCloser
	after  int64
	read   int64
	failed bool
}

func (r *failAfterReadCloser) Read(p []byte) (int, error) {
	if r.read >= r.after {
		r.failed = true
		return 0, injectedError("injected failure at part boundary")
	}
	if int64(len(p)) > r.after-r.read {
		p = p[:r.after-r.read]
	}
	n, err := r.rc.Read(p)
	r.read += int64(n)
	return n, err
}

func (r *failAfterReadCloser) Close() error { return r.rc.Close() }

// ---- TR-3.1: resume at the part boundary -----------------------------------

func TestBlobCopyResumesAtPartBoundary(t *testing.T) {
	h := newBlobMigrationHarness(t)
	content := repeatByte('a', 250)
	dgst := h.putSourceBlob(content)
	h.seedBlobRecord(dgst, int64(len(content)))
	canonical, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(t, err)

	h.src.readerHook = func(_ string, _ int64, rc io.ReadCloser) io.ReadCloser {
		return &countingReadCloser{d: h.src, path: canonical, ReadCloser: &failAfterReadCloser{rc: rc, after: 100}}
	}

	m := h.migrator()
	_, err = m.migrateOne(h.ctx, dgst)
	require.Error(t, err, "first attempt must fail at the injected error")

	rec, _, err := h.l.getBlobRecord(h.ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, statePending, rec.State)
	require.Equal(t, int64(100), rec.CommittedOffset)
	require.NotEmpty(t, rec.HashState)
	require.NotEmpty(t, rec.TempPath)
	require.Equal(t, []int64{0}, h.src.offsetsFor(canonical))

	// "Restart": a fresh migrator instance, ledger state resumes the copy.
	h.src.readerHook = nil
	m2 := h.migrator()
	rec2, err := m2.migrateOne(h.ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, stateCompleted, rec2.State)
	require.Equal(t, originCopied, rec2.Origin)

	require.Equal(t, []int64{0, 100}, h.src.offsetsFor(canonical),
		"the source must be re-read from the checkpoint offset, never from zero")
	require.Equal(t, content, string(h.targetContent(dgst)))

	tmp, err := h.l.listTempFiles(h.ctx)
	require.NoError(t, err)
	require.Empty(t, tmp)
}

// ---- TR-3.2: crash before commit move leaves no canonical object -----------

func TestBlobCopyCrashBeforeMoveRecovers(t *testing.T) {
	h := newBlobMigrationHarness(t)
	content := repeatByte('b', 250)
	dgst := h.putSourceBlob(content)
	h.seedBlobRecord(dgst, int64(len(content)))
	canonical, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(t, err)

	var once sync.Once
	h.dst.failMove = func(p string) bool {
		if p == canonical {
			inject := false
			once.Do(func() { inject = true })
			return inject
		}
		return false
	}

	_, err = h.migrator().migrateOne(h.ctx, dgst)
	require.Error(t, err)
	require.False(t, h.targetCanonicalExists(dgst), "failed move must not expose a canonical object")
	tmp, err := h.l.listTempFiles(h.ctx)
	require.NoError(t, err)
	require.NotEmpty(t, tmp, "staged bytes remain for the retry")

	// Retry converges.
	h.dst.failMove = nil
	rec, err := h.migrator().migrateOne(h.ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, stateCompleted, rec.State)
	require.True(t, h.targetCanonicalExists(dgst))
	require.Equal(t, content, string(h.targetContent(dgst)))
	tmp, err = h.l.listTempFiles(h.ctx)
	require.NoError(t, err)
	require.Empty(t, tmp)
}

// ---- TR-3.3: a shared blob is copied exactly once ---------------------------

func TestBlobCopySharedBlobCopiedOnce(t *testing.T) {
	h := newBlobMigrationHarness(t)
	content := repeatByte('c', 333)
	dgst := h.putSourceBlob(content)
	h.seedBlobRecord(dgst, int64(len(content)))
	canonical, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(t, err)

	m := h.migrator()
	for i := 0; i < 3; i++ { // three "repositories" claiming the same blob
		rec, err := m.migrateOne(h.ctx, dgst)
		require.NoError(t, err)
		if i == 0 {
			require.Equal(t, originCopied, rec.Origin)
		} else {
			require.Equal(t, stateCompleted, rec.State)
		}
	}

	require.Equal(t, int64(333), h.src.bytesReadFor(canonical),
		"shared blob source bytes are read exactly once")
	require.Len(t, h.src.offsetsFor(canonical), 1)
}

// ---- TR-3.4: existing destination objects verified then reused/conflict ------

func TestBlobCopyExistingDestinationReuseAndConflict(t *testing.T) {
	h := newBlobMigrationHarness(t)
	content := repeatByte('d', 150)
	dgst := h.putSourceBlob(content)
	canonical, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(t, err)

	// Identical object: zero source reads, reused.
	h.putTargetBlob(dgst, content)
	h.seedBlobRecord(dgst, int64(len(content)))
	rec, err := h.migrator().migrateOne(h.ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, stateCompleted, rec.State)
	require.Equal(t, originReused, rec.Origin)
	require.Zero(t, h.src.bytesReadFor(canonical))

	// Same digest, wrong size: conflict; destination untouched.
	h2 := newBlobMigrationHarness(t)
	badSizeContent := repeatByte('e', 151)
	h2.putTargetBlob(dgst, badSizeContent)
	h2.seedBlobRecord(dgst, 150)
	rec, err = h2.migrator().migrateOne(h2.ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, stateConflict, rec.State)
	require.Equal(t, badSizeContent, string(h2.targetContent(dgst)), "conflicting object must not be overwritten")
	require.True(t, h2.hasUnresolvedQuarantine(qKindBlobConflict))

	// Same size, corrupted content: conflict as well.
	h3 := newBlobMigrationHarness(t)
	corrupt := []byte(repeatByte('f', 150))
	corrupt[10] = 'Z'
	h3.putTargetBlob(dgst, string(corrupt))
	h3.seedBlobRecord(dgst, 150)
	rec, err = h3.migrator().migrateOne(h3.ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, stateConflict, rec.State)
	require.Equal(t, string(corrupt), string(h3.targetContent(dgst)))
}

// ---- TR-3.5: corrupted source bytes are quarantined, never canonical ----------

func TestBlobCopyCorruptSourceQuarantined(t *testing.T) {
	h := newBlobMigrationHarness(t)
	content := repeatByte('g', 180)
	dgst := digest.FromString(content)
	h.seedBlobRecord(dgst, int64(len(content)))

	// Source actually holds different bytes of the same length (the damage
	// happened after the link digest was recorded).
	tampered := []byte(content)
	tampered[42] = 'X'
	p, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(t, err)
	require.NoError(t, h.src.PutContent(h.ctx, p, tampered))

	rec, err := h.migrator().migrateOne(h.ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, stateQuarantined, rec.State)
	require.Equal(t, digest.FromBytes(tampered).String(), rec.ObservedDigest)
	require.False(t, h.targetCanonicalExists(dgst), "unverified bytes must never land at the canonical path")
	require.True(t, h.hasUnresolvedQuarantine(qKindBlobCorrupt))

	// Suspect bytes were moved under the quarantine area, not staged.
	quarantineFiles := h.listQuarantineData(t)
	require.NotEmpty(t, quarantineFiles)
	tmp, err := h.l.listTempFiles(h.ctx)
	require.NoError(t, err)
	require.Empty(t, tmp)
}

// ---- TR-3.6: source is never written to ---------------------------------------

func TestBlobCopySourceIsReadOnly(t *testing.T) {
	ctx := context.Background()
	inner := inmemory.New()
	dgst := digest.FromString("readonly-blob")
	p, err := pathFor(blobDataPathSpec{digest: dgst})
	require.NoError(t, err)
	require.NoError(t, inner.PutContent(ctx, p, []byte("readonly-blob")))

	src := newPanicWriteDriver(t, inner)
	dst := inmemory.New()
	l := newMigrationLedger(dst, "")
	_, err = l.initRun(ctx, "inmemory", "fp")
	require.NoError(t, err)
	_, err = l.mutateBlobRecord(ctx, dgst, true, func(r *blobRecord) error { r.ExpectedSize = 13; return nil })
	require.NoError(t, err)

	rec, err := newBlobMigrator(src, dst, l).migrateOne(ctx, dgst)
	require.NoError(t, err)
	require.Equal(t, stateCompleted, rec.State)
}

// ---- TR-3.7: concurrent claims, -race ------------------------------------------

func TestBlobCopyConcurrentClaims(t *testing.T) {
	h := newBlobMigrationHarness(t)
	dgsts := make([]digest.Digest, 8)
	for i := range dgsts {
		content := repeatByte(byte('A'+i), 120+i*7)
		dgsts[i] = h.putSourceBlob(content)
		h.seedBlobRecord(dgsts[i], int64(len(content)))
	}

	m := h.migrator()
	var wg sync.WaitGroup
	errs := make(chan error, len(dgsts)*2)
	for _, dgst := range dgsts {
		for range 2 { // duplicate workers per blob
			wg.Add(1)
			go func(dgst digest.Digest) {
				defer wg.Done()
				_, err := m.migrateOne(h.ctx, dgst)
				errs <- err
			}(dgst)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	for _, dgst := range dgsts {
		rec, ok, err := h.l.getBlobRecord(h.ctx, dgst)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, stateCompleted, rec.State)
		require.True(t, h.targetCanonicalExists(dgst))
	}
}

// ---- helpers -------------------------------------------------------------------

func (h *blobMigrationHarness) hasUnresolvedQuarantine(kind string) bool {
	found := false
	_ = h.l.listQuarantineRecords(h.ctx, func(q *quarantineRecord) error {
		if !q.Resolved && q.Kind == kind {
			found = true
		}
		return nil
	})
	return found
}

func (h *blobMigrationHarness) listQuarantineData(t *testing.T) []string {
	var out []string
	root := h.l.join("quarantine", "blobdata")
	err := h.dst.Walk(h.ctx, root, func(fi driver.FileInfo) error {
		if !fi.IsDir() {
			out = append(out, fi.Path())
		}
		return nil
	})
	if err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil
		}
		require.NoError(t, err)
	}
	return out
}

func repeatByte(b byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return string(out)
}
