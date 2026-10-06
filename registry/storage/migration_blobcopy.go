package storage

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
)

// This file implements the global blob migration pipeline:
//
//	pending -> in_progress -> (resumable staged copy + verify) -> completed
//	          |-> quarantined (source bytes damaged / unreadable)
//	          '-> conflict     (destination object exists but fails verify)
//
// Bytes are streamed through a ledger-private staging path and only Moved to
// the canonical /v2/blobs/.../data path after the full content hashes to the
// expected digest and matches the source size. An unverified object can
// therefore never appear at the canonical path. Progress (byte offset and
// digester state) is checkpointed to the ledger at each part boundary, so a
// killed runner resumes there instead of restarting the blob.

const (
	// defaultBlobCopyChunkSize is the streaming part size at which progress
	// is flushed and checkpointed. It must stay above the strictest cloud
	// minimum part size: S3 requires every non-final multipart part to be at
	// least 5 MiB, so a flush at the part boundary emits a valid part on S3
	// (and on GCS/Azure/filesystem/inmemory). 8 MiB clears that floor while
	// bounding replay to at most one part after a crash.
	defaultBlobCopyChunkSize = 8 << 20
	defaultStatRetryAttempts = 6
	defaultStatRetryDelay    = 200 * time.Millisecond
)

// blobMigrator copies one global blob at a time. It never writes to src.
type blobMigrator struct {
	src driver.StorageDriver
	dst driver.StorageDriver
	l   *migrationLedger

	chunkSize int64
	budget    *unitBudget

	// flights single-flights concurrent callers for the same digest: two
	// repositories referencing a shared blob must not open the same staging
	// file twice. Followers block on the leader's result.
	flights sync.Map // digest.Digest -> *blobFlight
}

// blobFlight is one in-progress blob migration and its shared result.
type blobFlight struct {
	done chan struct{}
	rec  *blobRecord
	err  error
}

func newBlobMigrator(src, dst driver.StorageDriver, l *migrationLedger) *blobMigrator {
	return &blobMigrator{src: src, dst: dst, l: l, chunkSize: defaultBlobCopyChunkSize}
}

// blobDataCanonicalPath returns the canonical registry data path for a digest;
// source and target share the same v2 layout.
func blobDataCanonicalPath(dgst digest.Digest) (string, error) {
	return pathFor(blobDataPathSpec{digest: dgst})
}

// migrateOne ensures one blob is completed, quarantined or conflicted. Records
// already in a terminal state are returned untouched. Concurrent calls for the
// same digest are single-flighted to the leader's result. The returned record
// is never nil when err is nil.
func (m *blobMigrator) migrateOne(ctx context.Context, dgst digest.Digest) (*blobRecord, error) {
	f := &blobFlight{done: make(chan struct{})}
	if v, loaded := m.flights.LoadOrStore(dgst, f); loaded {
		flight := v.(*blobFlight)
		select {
		case <-flight.done:
			return flight.rec, flight.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	rec, err := m.migrateOneLeader(ctx, dgst)
	f.rec, f.err = rec, err
	close(f.done)
	m.flights.Delete(dgst)
	return rec, err
}

func (m *blobMigrator) migrateOneLeader(ctx context.Context, dgst digest.Digest) (*blobRecord, error) {
	rec, exists, err := m.l.getBlobRecord(ctx, dgst)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("blob %s missing from ledger; run discovery first", dgst)
	}
	switch rec.State {
	case stateCompleted:
		return rec, nil
	case stateQuarantined:
		return rec, nil
	case stateConflict:
		// A conflict was caused by a pre-existing destination object. Every
		// run deterministically re-checks it: once an operator replaces the
		// object with valid bytes, the blob converges without manual ledger
		// edits. A still-bad object keeps the conflict.
		canonical, cerr := blobDataCanonicalPath(dgst)
		if cerr != nil {
			return rec, nil
		}
		fi, serr := m.dst.Stat(ctx, canonical)
		if serr == nil && !fi.IsDir() && fi.Size() == rec.ExpectedSize &&
			m.verifiedCanonical(ctx, dgst, canonical, rec.ExpectedSize) {
			return m.complete(ctx, dgst, originReused)
		}
		return rec, nil
	}

	// Claim the unit for this run, subject to the batch budget.
	if m.budget != nil && !m.budget.take() {
		return nil, errMigrationBudget
	}
	rec, err = m.l.mutateBlobRecord(ctx, dgst, false, func(r *blobRecord) error {
		r.State = stateInProgress
		r.Attempts++
		r.RunID = m.l.runID
		return nil
	})
	if err != nil {
		return nil, err
	}

	if rec.ExpectedSize == 0 {
		size, statErr := m.sourceSize(ctx, dgst)
		if statErr != nil {
			return m.fault(ctx, dgst, qKindBlobUnreadable, "stat source blob: "+statErr.Error(), 0, "", rec, rec.TempPath, false)
		}
		rec, err = m.l.mutateBlobRecord(ctx, dgst, false, func(r *blobRecord) error { r.ExpectedSize = size; return nil })
		if err != nil {
			return nil, err
		}
	}

	canonical, err := blobDataCanonicalPath(dgst)
	if err != nil {
		return nil, err
	}

	// A pre-existing destination object is verified and reused, or isolated
	// as a conflict. It is never overwritten. Absence here is the normal
	// case, so do not apply read-after-write retries.
	fi, statErr := m.dst.Stat(ctx, canonical)
	if statErr == nil {
		if fi.IsDir() {
			return m.fault(ctx, dgst, qKindBlobConflict, "canonical path is a directory", fi.Size(), "", rec, rec.TempPath, false)
		}
		if fi.Size() != rec.ExpectedSize {
			return m.fault(ctx, dgst, qKindBlobConflict,
				fmt.Sprintf("destination size %d does not match expected %d", fi.Size(), rec.ExpectedSize),
				fi.Size(), "", rec, rec.TempPath, false)
		}
		if !m.verifiedCanonical(ctx, dgst, canonical, rec.ExpectedSize) {
			return m.fault(ctx, dgst, qKindBlobConflict,
				"destination object digest verification failed", fi.Size(), "", rec, rec.TempPath, false)
		}
		_ = m.removeTemp(ctx, rec.TempPath)
		return m.complete(ctx, dgst, originReused)
	} else {
		var pnf driver.PathNotFoundError
		if !errors.As(statErr, &pnf) {
			return nil, statErr
		}
	}

	// Stream-copy through the staging area with checkpointed resume.
	stagePath, observed, size, err := m.streamCopy(ctx, dgst, canonical, rec)
	if err != nil {
		// Transient transport failure: park as pending. Stage progress is
		// already checkpointed at the last part boundary.
		_, _ = m.l.mutateBlobRecord(ctx, dgst, false, func(r *blobRecord) error {
			r.State = statePending
			recordError(&r.Errors, "copy failed: %v", err)
			return nil
		})
		return nil, err
	}

	if observed != dgst.String() || size != rec.ExpectedSize {
		return m.fault(ctx, dgst, qKindBlobCorrupt,
			fmt.Sprintf("verification failed: observed %s/%d expected %s/%d", observed, size, dgst, rec.ExpectedSize),
			size, observed, rec, stagePath, true)
	}

	// Canonical race: another worker/run may have landed the object meanwhile.
	if fi, statErr := m.dst.Stat(ctx, canonical); statErr == nil && !fi.IsDir() {
		if m.verifiedCanonical(ctx, dgst, canonical, rec.ExpectedSize) {
			_ = m.removeTemp(ctx, stagePath)
			return m.complete(ctx, dgst, originReused)
		}
		return m.fault(ctx, dgst, qKindBlobConflict,
			"destination object at canonical path failed verification while copy was finishing",
			fi.Size(), "", rec, stagePath, false)
	}

	if err := m.dst.Move(ctx, stagePath, canonical); err != nil {
		// A racer may have created the canonical object between the stat and
		// the move. Verify rather than assuming the worst.
		if m.verifiedCanonical(ctx, dgst, canonical, rec.ExpectedSize) {
			_ = m.removeTemp(ctx, stagePath)
			return m.complete(ctx, dgst, originReused)
		}
		_, _ = m.l.mutateBlobRecord(ctx, dgst, false, func(r *blobRecord) error {
			r.State = statePending
			recordError(&r.Errors, "commit move failed: %v", err)
			return nil
		})
		return nil, err
	}

	if _, err := m.statWithRetry(ctx, m.dst, canonical); err != nil {
		return nil, fmt.Errorf("blob %s committed but not visible at %s: %w", dgst, canonical, err)
	}
	return m.complete(ctx, dgst, originCopied)
}

// verifiedCanonical streams the canonical destination object through its
// expected digester and checks digest and length.
func (m *blobMigrator) verifiedCanonical(ctx context.Context, dgst digest.Digest, canonical string, wantSize int64) bool {
	observed, size, err := hashDriverObject(ctx, m.dst, canonical, dgst.Algorithm())
	if err != nil {
		return false
	}
	return size == wantSize && observed == dgst.String()
}

// prepareStage opens (or creates) the staged writer. Resume deliberately goes
// through Writer(append=true) rather than Stat: on object stores (S3/GCS) an
// in-progress multipart/block upload is invisible to Stat until it completes,
// while the driver re-enumerates and appends to it. When the driver position
// or the digester checkpoint disagrees with the ledger, the stale upload is
// canceled/aborted explicitly and a clean stage starts from zero.
func (m *blobMigrator) prepareStage(
	ctx context.Context,
	dgst digest.Digest,
	rec *blobRecord,
) (string, driver.FileWriter, int64, digest.Digester, error) {
	alg := digest.Algorithm(dgst.Algorithm())
	tempPath := rec.TempPath
	offset := rec.CommittedOffset

	newStage := func() (string, driver.FileWriter, int64, digest.Digester, error) {
		p, err := m.l.tempBlobPath(dgst, uuid.NewString())
		if err != nil {
			return "", nil, 0, nil, err
		}
		// Track the empty stage so a crash before the first part is
		// reconciled by the next run.
		if err := m.persistStage(ctx, dgst, p, 0, nil); err != nil {
			return "", nil, 0, nil, err
		}
		fw, err := m.dst.Writer(ctx, p, false)
		return p, fw, 0, alg.Digester(), err
	}

	if tempPath == "" {
		return newStage()
	}

	// Driver-native resume at the checkpointed offset.
	dig := alg.Digester()
	hashOK := offset == 0 || unmarshalHashState(dig.Hash(), rec.HashState) == nil
	w, werr := m.dst.Writer(ctx, tempPath, offset > 0)
	if werr != nil || w == nil || w.Size() != offset || !hashOK {
		if w != nil {
			_ = w.Cancel(ctx) // abort the orphan multipart/block upload
		}
		_ = m.removeTemp(ctx, tempPath)
		return newStage()
	}
	return tempPath, w, offset, dig, nil
}

// streamCopy performs (or resumes) the staged streaming copy and returns the
// stage path, observed digest and total byte count. On success the staged file
// is committed at stagePath.
func (m *blobMigrator) streamCopy(
	ctx context.Context,
	dgst digest.Digest,
	canonical string,
	rec *blobRecord,
) (string, string, int64, error) {
	tempPath, fw, offset, dig, err := m.prepareStage(ctx, dgst, rec)
	if err != nil {
		return "", "", 0, err
	}

	rc, err := m.src.Reader(ctx, canonical, offset)
	if err != nil {
		_ = fw.Close()
		return tempPath, "", 0, err
	}

	buf := make([]byte, m.chunkSize)
	total := offset
	for {
		nr, er := io.ReadFull(rc, buf)
		if nr > 0 {
			if _, err := fw.Write(buf[:nr]); err != nil {
				_ = rc.Close()
				_ = fw.Close()
				return tempPath, "", 0, err
			}
			if _, err := dig.Hash().Write(buf[:nr]); err != nil {
				_ = rc.Close()
				_ = fw.Close()
				return tempPath, "", 0, err
			}
			total += int64(nr)
		}

		switch {
		case er == nil:
			// Part boundary: flush + persist offset/hashstate, reopen writer.
			if err := fw.Close(); err != nil {
				_ = rc.Close()
				return tempPath, "", 0, err
			}
			state, err := marshalHashState(dig.Hash())
			if err != nil {
				_ = rc.Close()
				return tempPath, "", 0, err
			}
			if err := m.persistStage(ctx, dgst, tempPath, total, state); err != nil {
				_ = rc.Close()
				return tempPath, "", 0, err
			}
			fw, err = m.dst.Writer(ctx, tempPath, true)
			if err != nil {
				_ = rc.Close()
				return tempPath, "", 0, err
			}
			if fw.Size() != total {
				_ = rc.Close()
				_ = fw.Close()
				return tempPath, "", 0, fmt.Errorf("stage size mismatch after checkpoint: writer=%d expected=%d", fw.Size(), total)
			}
		case er == io.EOF || er == io.ErrUnexpectedEOF:
			// End of source. Commit the staged object.
			if err := rc.Close(); err != nil {
				_ = fw.Close()
				return tempPath, "", 0, err
			}
			if err := fw.Commit(ctx); err != nil {
				return tempPath, "", 0, err
			}
			return tempPath, dig.Digest().String(), total, nil
		default:
			// Genuine read error. Last part boundary is already checkpointed;
			// close the writer so drivers flush the in-flight part where
			// applicable, then surface the error for an outer retry.
			_ = rc.Close()
			_ = fw.Close()
			return tempPath, "", 0, er
		}
	}
}

// persistStage writes resumable copy progress into the blob record.
func (m *blobMigrator) persistStage(ctx context.Context, dgst digest.Digest, tempPath string, offset int64, state []byte) error {
	_, err := m.l.mutateBlobRecord(ctx, dgst, false, func(r *blobRecord) error {
		r.TempPath = tempPath
		r.CommittedOffset = offset
		r.HashState = state
		return nil
	})
	return err
}

// complete marks the blob completed, clears staging bookkeeping and resolves
// any isolation record previously attached to this digest.
func (m *blobMigrator) complete(ctx context.Context, dgst digest.Digest, origin string) (*blobRecord, error) {
	// Resolve before flipping state: a ledger write failure here leaves the
	// blob uncompleted; the next run finds the canonical object, reuses it
	// and retries completion, so a stale isolation record can never wedge
	// convergence permanently.
	if _, err := m.l.resolveQuarantineByKey(ctx, dgst.String(), "blob now verifies"); err != nil {
		return nil, err
	}
	return m.l.mutateBlobRecord(ctx, dgst, false, func(r *blobRecord) error {
		r.State = stateCompleted
		r.Origin = origin
		r.TempPath = ""
		r.CommittedOffset = 0
		r.HashState = nil
		r.ObservedDigest = ""
		r.ObservedSize = 0
		return nil
	})
}

// fault records a damaged source blob or a conflicting destination object.
// Suspect bytes produced by this run (corrupt copies) are moved into the
// quarantine area; pre-existing destination objects involved in conflicts are
// left exactly where they were.
func (m *blobMigrator) fault(
	ctx context.Context,
	dgst digest.Digest,
	kind, reason string,
	observedSize int64,
	observedDigest string,
	rec *blobRecord,
	tempPath string,
	moveStage bool,
) (*blobRecord, error) {
	if moveStage && tempPath != "" {
		if dest, err := m.quarantineDataPath(dgst); err == nil {
			if err := m.dst.Move(ctx, tempPath, dest); err != nil {
				_ = m.removeTemp(ctx, tempPath)
			}
		}
	} else {
		_ = m.removeTemp(ctx, tempPath)
	}

	target := stateQuarantined
	if kind == qKindBlobConflict {
		target = stateConflict
	}
	if _, err := m.l.quarantine(ctx, &quarantineRecord{
		Kind:           kind,
		Key:            dgst.String(),
		ExpectedDigest: dgst.String(),
		ObservedDigest: observedDigest,
		ExpectedSize:   rec.ExpectedSize,
		ObservedSize:   observedSize,
		Reason:         reason,
	}); err != nil {
		return nil, err
	}
	return m.l.mutateBlobRecord(ctx, dgst, false, func(r *blobRecord) error {
		r.State = target
		r.TempPath = ""
		r.CommittedOffset = 0
		r.HashState = nil
		r.ObservedDigest = observedDigest
		r.ObservedSize = observedSize
		recordError(&r.Errors, "%s: %s", kind, reason)
		return nil
	})
}

func (m *blobMigrator) quarantineDataPath(dgst digest.Digest) (string, error) {
	comps, err := digestPathComponents(dgst, true)
	if err != nil {
		return "", err
	}
	last := len(comps) - 1
	comps[last] = comps[last] + "." + uuid.NewString()[:13] + ".data"
	p := m.l.join(append([]string{"quarantine", "blobdata"}, comps...)...)
	return p, checkPath(p)
}

func (m *blobMigrator) removeTemp(ctx context.Context, p string) error {
	if p == "" {
		return nil
	}
	if err := m.dst.Delete(ctx, p); err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil
		}
		return err
	}
	return nil
}

func (m *blobMigrator) sourceSize(ctx context.Context, dgst digest.Digest) (int64, error) {
	p, err := blobDataCanonicalPath(dgst)
	if err != nil {
		return 0, err
	}
	fi, err := m.src.Stat(ctx, p)
	if err != nil {
		return 0, err
	}
	if fi.IsDir() {
		return 0, fmt.Errorf("blob path is a directory")
	}
	return fi.Size(), nil
}

// statWithRetry tolerates brief read-after-write visibility gaps.
func (m *blobMigrator) statWithRetry(ctx context.Context, d driver.StorageDriver, p string) (driver.FileInfo, error) {
	var lastErr error
	delay := defaultStatRetryDelay
	for attempt := 0; attempt < defaultStatRetryAttempts; attempt++ {
		fi, err := d.Stat(ctx, p)
		if err == nil {
			return fi, nil
		}
		var pnf driver.PathNotFoundError
		if !errors.As(err, &pnf) {
			return nil, err
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
	return nil, lastErr
}

// hashDriverObject streams an object through its algorithm digester and
// returns digest string and byte count.
func hashDriverObject(ctx context.Context, d driver.StorageDriver, p string, alg digest.Algorithm) (string, int64, error) {
	rc, err := d.Reader(ctx, p, 0)
	if err != nil {
		return "", 0, err
	}
	defer rc.Close()

	dig := alg.Digester()
	n, err := io.CopyBuffer(dig.Hash(), rc, make([]byte, 1<<20))
	if err != nil {
		return "", 0, err
	}
	return dig.Digest().String(), n, nil
}

func marshalHashState(h hash.Hash) ([]byte, error) {
	m, ok := h.(encoding.BinaryMarshaler)
	if !ok {
		return nil, fmt.Errorf("digester does not support resumable state")
	}
	return m.MarshalBinary()
}

func unmarshalHashState(h hash.Hash, state []byte) error {
	if len(state) == 0 {
		return fmt.Errorf("missing digester checkpoint state")
	}
	u, ok := h.(encoding.BinaryUnmarshaler)
	if !ok {
		return fmt.Errorf("digester does not support resumable state")
	}
	return u.UnmarshalBinary(state)
}
