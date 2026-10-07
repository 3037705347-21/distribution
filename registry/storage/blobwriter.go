package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/distribution/distribution/v3/registry/storage/accounting"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

var errResumableDigestNotAvailable = errors.New("resumable digest not available")

const (
	// digestSha256Empty is the canonical sha256 digest of empty data
	digestSha256Empty = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// blobWriter is used to control the various aspects of resumable
// blob upload.
type blobWriter struct {
	ctx       context.Context
	blobStore *linkedBlobStore

	id        string
	startedAt time.Time
	digester  digest.Digester
	written   int64 // track the write to digester

	fileWriter storagedriver.FileWriter
	driver     storagedriver.StorageDriver
	path       string

	resumableDigestEnabled bool
	committed              bool

	// reservation is the ledger reservation backing this upload; nil when
	// accounting is disabled.
	reservation *accounting.Reservation
}

// quotaGrowUnit bounds the number of reservation growth events produced while
// streaming an upload whose total size is not known up front.
const quotaGrowUnit int64 = 1 << 20 // 1 MiB

// growReservation raises the upload reservation high-water mark to cover
// bw.written+incoming bytes. Geometric growth keeps ledger event counts
// logarithmic in the upload size. The check happens before the bytes are
// written, so over-budget uploads fail before touching the upload data file.
func (bw *blobWriter) growReservation(incoming int64) error {
	if bw.reservation == nil {
		return nil
	}
	target := bw.written + incoming
	if target <= bw.reservation.Size {
		return nil
	}
	grown := bw.reservation.Size
	if grown == 0 {
		grown = quotaGrowUnit
	}
	for grown < target {
		grown *= 2
	}
	ledger := bw.blobStore.ledger()
	if ledger == nil {
		return nil
	}
	if err := ledger.Adjust(bw.ctx, bw.reservation, grown, accounting.PhaseUpload); err != nil {
		// Geometric growth overshot the budget. Retry with the exact target
		// so a slightly-too-large upload fails with its real byte count and
		// an upload that actually fits at the target is admitted.
		var qe *accounting.ErrQuotaExceeded
		if errors.As(err, &qe) && target != grown {
			if retryErr := ledger.Adjust(bw.ctx, bw.reservation, target, accounting.PhaseUpload); retryErr == nil {
				return nil
			} else {
				return retryErr
			}
		}
		return err
	}
	return nil
}

var _ distribution.BlobWriter = &blobWriter{}

// ID returns the identifier for this upload.
func (bw *blobWriter) ID() string {
	return bw.id
}

func (bw *blobWriter) StartedAt() time.Time {
	return bw.startedAt
}

// Commit marks the upload as completed, returning a valid descriptor. The
// final size and digest are checked against the first descriptor provided.
func (bw *blobWriter) Commit(ctx context.Context, desc v1.Descriptor) (v1.Descriptor, error) {
	dcontext.GetLogger(ctx).Debug("(*blobWriter).Commit")

	if err := bw.fileWriter.Commit(ctx); err != nil {
		return v1.Descriptor{}, err
	}

	bw.Close()
	desc.Size = bw.Size()

	canonical, err := bw.validateBlob(ctx, desc)
	if err != nil {
		return v1.Descriptor{}, err
	}

	// Hard quota gate: the final size is known now and the blob has not yet
	// been moved into the content-addressable store or linked.
	if bw.reservation != nil {
		if err := bw.blobStore.ledger().Adjust(ctx, bw.reservation, canonical.Size, accounting.PhaseUpload); err != nil {
			return v1.Descriptor{}, err
		}
	}

	if err := bw.moveBlob(ctx, canonical); err != nil {
		return v1.Descriptor{}, err
	}

	if err := bw.blobStore.linkBlob(ctx, canonical, desc.Digest); err != nil {
		return v1.Descriptor{}, err
	}

	if err := bw.removeResources(ctx); err != nil {
		return v1.Descriptor{}, err
	}

	err = bw.blobStore.blobAccessController.SetDescriptor(ctx, canonical.Digest, canonical)
	if err != nil {
		return v1.Descriptor{}, err
	}

	// Settle the reservation into the repository ledger. A failure here does
	// not fail the commit (the blob is already committed and linked); the
	// reconciler repairs the missing settle against physical state.
	if bw.reservation != nil {
		if err := bw.blobStore.ledger().Settle(ctx, bw.reservation, canonical.Digest, accounting.RoleLayer, canonical.Size); err != nil {
			dcontext.GetLogger(ctx).WithError(err).
				WithField("digest", canonical.Digest).
				Error("accounting: failed to settle blob upload; ledger will reconcile")
		}
	}

	bw.committed = true
	return canonical, nil
}

// Cancel the blob upload process, releasing any resources associated with
// the writer and canceling the operation.
func (bw *blobWriter) Cancel(ctx context.Context) error {
	dcontext.GetLogger(ctx).Debug("(*blobWriter).Cancel")
	if err := bw.fileWriter.Cancel(ctx); err != nil {
		return err
	}

	if err := bw.Close(); err != nil {
		dcontext.GetLogger(ctx).Errorf("error closing blobwriter: %s", err)
	}

	if err := bw.removeResources(ctx); err != nil {
		return err
	}

	if bw.reservation != nil {
		if err := bw.blobStore.ledger().Release(ctx, bw.reservation); err != nil {
			dcontext.GetLogger(ctx).Errorf("error releasing ledger reservation: %v", err)
		}
	}
	return nil
}

func (bw *blobWriter) Size() int64 {
	return bw.fileWriter.Size()
}

func (bw *blobWriter) Write(p []byte) (int, error) {
	// Ensure that the current write offset matches how many bytes have been
	// written to the digester. If not, we need to update the digest state to
	// match the current write position.
	if err := bw.resumeDigest(bw.blobStore.ctx); err != nil && err != errResumableDigestNotAvailable {
		return 0, err
	}

	// Enforce the quota before the bytes land in storage.
	if err := bw.growReservation(int64(len(p))); err != nil {
		return 0, err
	}

	_, err := bw.fileWriter.Write(p)
	if err != nil {
		return 0, err
	}

	n, err := bw.digester.Hash().Write(p)
	bw.written += int64(n)

	return n, err
}

func (bw *blobWriter) ReadFrom(r io.Reader) (n int64, err error) {
	// Ensure that the current write offset matches how many bytes have been
	// written to the digester. If not, we need to update the digest state to
	// match the current write position.
	if err := bw.resumeDigest(bw.blobStore.ctx); err != nil && err != errResumableDigestNotAvailable {
		return 0, err
	}

	// Grow the reservation (and therefore enforce the quota) as bytes are
	// read, before they are tee'd into the upload data file.
	r = &quotaReader{src: r, bw: bw}

	// Using a TeeReader instead of MultiWriter ensures Copy returns
	// the amount written to the digester as well as ensuring that we
	// write to the fileWriter first
	tee := io.TeeReader(r, bw.fileWriter)
	nn, err := io.Copy(bw.digester.Hash(), tee)
	bw.written += nn

	return nn, err
}

// quotaReader grows the upload reservation as data flows through it. When the
// repository budget is exhausted it returns the accounting error instead of
// delivering the bytes, which aborts the upload before the temp data grows.
type quotaReader struct {
	src io.Reader
	bw  *blobWriter
}

func (q *quotaReader) Read(p []byte) (int, error) {
	n, err := q.src.Read(p)
	if n > 0 {
		if gErr := q.bw.growReservation(int64(n)); gErr != nil {
			return 0, gErr
		}
	}
	return n, err
}

func (bw *blobWriter) Close() error {
	if bw.committed {
		return errors.New("blobwriter close after commit")
	}

	if err := bw.storeHashState(bw.blobStore.ctx); err != nil && err != errResumableDigestNotAvailable {
		return err
	}

	return bw.fileWriter.Close()
}

// validateBlob checks the data against the digest, returning an error if it
// does not match. The canonical descriptor is returned.
func (bw *blobWriter) validateBlob(ctx context.Context, desc v1.Descriptor) (v1.Descriptor, error) {
	var (
		verified, fullHash bool
		canonical          digest.Digest
	)

	if desc.Digest == "" {
		// if no descriptors are provided, we have nothing to validate
		// against. We don't really want to support this for the registry.
		return v1.Descriptor{}, distribution.ErrBlobInvalidDigest{
			Reason: fmt.Errorf("cannot validate against empty digest"),
		}
	}

	var size int64

	// Stat the on disk file
	if fi, err := bw.driver.Stat(ctx, bw.path); err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError:
			// NOTE(stevvooe): We really don't care if the file is
			// not actually present for the reader. We now assume
			// that the desc length is zero.
			desc.Size = 0
		default:
			// Any other error we want propagated up the stack.
			return v1.Descriptor{}, err
		}
	} else {
		if fi.IsDir() {
			return v1.Descriptor{}, fmt.Errorf("unexpected directory at upload location %q", bw.path)
		}

		size = fi.Size()
	}

	if desc.Size > 0 {
		if desc.Size != size {
			return v1.Descriptor{}, distribution.ErrBlobInvalidLength
		}
	} else {
		// if provided 0 or negative length, we can assume caller doesn't know or
		// care about length.
		desc.Size = size
	}

	// TODO(stevvooe): This section is very meandering. Need to be broken down
	// to be a lot more clear.

	if err := bw.resumeDigest(ctx); err == nil {
		canonical = bw.digester.Digest()

		if canonical.Algorithm() == desc.Digest.Algorithm() {
			// Common case: client and server prefer the same canonical digest
			// algorithm - currently SHA256.
			verified = desc.Digest == canonical
		} else {
			// The client wants to use a different digest algorithm. They'll just
			// have to be patient and wait for us to download and re-hash the
			// uploaded content using that digest algorithm.
			fullHash = true
		}
	} else if err == errResumableDigestNotAvailable {
		// Not using resumable digests, so we need to hash the entire layer.
		fullHash = true
	} else {
		return v1.Descriptor{}, err
	}

	if fullHash {
		// a fantastic optimization: if the written data and the size are
		// the same, we don't need to read the data from the backend. This is
		// because we've written the entire file in the lifecycle of the
		// current instance.
		if bw.written == size && digest.Canonical == desc.Digest.Algorithm() {
			canonical = bw.digester.Digest()
			verified = desc.Digest == canonical
		}

		// If the check based on size fails, we fall back to the slowest of
		// paths. We may be able to make the size-based check a stronger
		// guarantee, so this may be defensive.
		if !verified {
			digester := digest.Canonical.Digester()
			verifier := desc.Digest.Verifier()

			// Read the file from the backend driver and validate it.
			fr, err := newFileReader(ctx, bw.driver, bw.path, desc.Size)
			if err != nil {
				return v1.Descriptor{}, err
			}
			defer fr.Close()

			tr := io.TeeReader(fr, digester.Hash())

			if _, err := io.Copy(verifier, tr); err != nil {
				return v1.Descriptor{}, err
			}

			canonical = digester.Digest()
			verified = verifier.Verified()
		}
	}

	if !verified {
		dcontext.GetLoggerWithFields(ctx,
			map[any]any{
				"canonical": canonical,
				"provided":  desc.Digest,
			}, "canonical", "provided").
			Errorf("canonical digest does match provided digest")
		return v1.Descriptor{}, distribution.ErrBlobInvalidDigest{
			Digest: desc.Digest,
			Reason: fmt.Errorf("content does not match digest"),
		}
	}

	// update desc with canonical hash
	desc.Digest = canonical

	if desc.MediaType == "" {
		desc.MediaType = "application/octet-stream"
	}

	return desc, nil
}

// moveBlob moves the data into its final, hash-qualified destination,
// identified by dgst. The layer should be validated before commencing the
// move.
func (bw *blobWriter) moveBlob(ctx context.Context, desc v1.Descriptor) error {
	blobPath, err := pathFor(blobDataPathSpec{
		digest: desc.Digest,
	})
	if err != nil {
		return err
	}

	// Check for existence
	if _, err := bw.blobStore.driver.Stat(ctx, blobPath); err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError:
			break // ensure that it doesn't exist.
		default:
			return err
		}
	} else {
		// If the path exists, we can assume that the content has already
		// been uploaded, since the blob storage is content-addressable.
		// While it may be corrupted, detection of such corruption belongs
		// elsewhere.
		return nil
	}

	// If no data was received, we may not actually have a file on disk. Check
	// the size here and write a zero-length file to blobPath if this is the
	// case. For the most part, this should only ever happen with zero-length
	// blobs.
	if _, err := bw.blobStore.driver.Stat(ctx, bw.path); err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError:
			// HACK(stevvooe): This is slightly dangerous: if we verify above,
			// get a hash, then the underlying file is deleted, we risk moving
			// a zero-length blob into a nonzero-length blob location. To
			// prevent this horrid thing, we employ the hack of only allowing
			// to this happen for the digest of an empty blob.
			if desc.Digest == digestSha256Empty {
				return bw.blobStore.driver.PutContent(ctx, blobPath, []byte{})
			}

			// We let this fail during the move below.
			logrus.
				WithField("upload.id", bw.ID()).
				WithField("digest", desc.Digest).Warnf("attempted to move zero-length content with non-zero digest")
		default:
			return err // unrelated error
		}
	}

	// TODO(stevvooe): We should also write the mediatype when executing this move.

	return bw.blobStore.driver.Move(ctx, bw.path, blobPath)
}

// removeResources should clean up all resources associated with the upload
// instance. An error will be returned if the clean up cannot proceed. If the
// resources are already not present, no error will be returned.
func (bw *blobWriter) removeResources(ctx context.Context) error {
	dataPath, err := pathFor(uploadDataPathSpec{
		name: bw.blobStore.repository.Named().Name(),
		id:   bw.id,
	})
	if err != nil {
		return err
	}

	// Resolve and delete the containing directory, which should include any
	// upload related files.
	dirPath := path.Dir(dataPath)
	if err := bw.blobStore.driver.Delete(ctx, dirPath); err != nil {
		switch err := err.(type) {
		case storagedriver.PathNotFoundError:
			break // already gone!
		default:
			// This should be uncommon enough such that returning an error
			// should be okay. At this point, the upload should be mostly
			// complete, but perhaps the backend became unaccessible.
			dcontext.GetLogger(ctx).Errorf("unable to delete layer upload resources %q: %v", dirPath, err)
			return err
		}
	}

	return nil
}

func (bw *blobWriter) Reader() (io.ReadCloser, error) {
	// todo(richardscothern): Change to exponential backoff, i=0.5, e=2, n=4
	try := 1
	for try <= 5 {
		_, err := bw.driver.Stat(bw.ctx, bw.path)
		if err == nil {
			break
		}
		switch err.(type) {
		case storagedriver.PathNotFoundError:
			dcontext.GetLogger(bw.ctx).Debugf("Nothing found on try %d, sleeping...", try)
			time.Sleep(1 * time.Second)
			try++
		default:
			return nil, err
		}
	}

	readCloser, err := bw.driver.Reader(bw.ctx, bw.path, 0)
	if err != nil {
		return nil, err
	}

	return readCloser, nil
}
