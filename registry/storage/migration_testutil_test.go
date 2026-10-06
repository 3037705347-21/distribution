package storage

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
)

// newFSDriver builds a filesystem storage driver rooted at root. MaxThreads
// must be non-zero, otherwise the driver regulator admits zero operations.
func newFSDriver(root string) driver.StorageDriver {
	return filesystem.New(filesystem.DriverParameters{RootDirectory: root, MaxThreads: 16})
}

// migrationTestDriver wraps a StorageDriver with the observability and fault
// injection hooks that the migration tests need:
//   - read accounting per path and total bytes read (resume / copy-once);
//   - a Reader hook (byte corruption, forced mid-stream errors);
//   - a Move failure hook (atomic-commit fault injection);
//   - a log of every mutating call (source read-only assertions).
type migrationTestDriver struct {
	driver.StorageDriver

	mu sync.Mutex

	// read accounting
	readOffsets map[string][]int64
	bytesByPath map[string]int64
	totalRead   int64

	// mutation call log
	mutatingCalls []string

	// hooks
	readerHook func(path string, offset int64, rc io.ReadCloser) io.ReadCloser
	failMove   func(path string) bool
}

func newMigrationTestDriver(inner driver.StorageDriver) *migrationTestDriver {
	return &migrationTestDriver{
		StorageDriver: inner,
		readOffsets:   map[string][]int64{},
		bytesByPath:   map[string]int64{},
	}
}

func (d *migrationTestDriver) GetContent(ctx context.Context, p string) ([]byte, error) {
	b, err := d.StorageDriver.GetContent(ctx, p)
	d.mu.Lock()
	d.totalRead += int64(len(b))
	d.bytesByPath[p] += int64(len(b))
	d.mu.Unlock()
	return b, err
}

func (d *migrationTestDriver) Reader(ctx context.Context, p string, offset int64) (io.ReadCloser, error) {
	d.mu.Lock()
	d.readOffsets[p] = append(d.readOffsets[p], offset)
	d.mu.Unlock()
	rc, err := d.StorageDriver.Reader(ctx, p, offset)
	if err != nil {
		return nil, err
	}
	if d.readerHook != nil {
		return d.readerHook(p, offset, rc), nil
	}
	return &countingReadCloser{d: d, path: p, ReadCloser: rc}, nil
}

func (d *migrationTestDriver) PutContent(ctx context.Context, p string, content []byte) error {
	d.recordMutating("PutContent:" + p)
	return d.StorageDriver.PutContent(ctx, p, content)
}

func (d *migrationTestDriver) Writer(ctx context.Context, p string, append bool) (driver.FileWriter, error) {
	d.recordMutating("Writer:" + p)
	return d.StorageDriver.Writer(ctx, p, append)
}

func (d *migrationTestDriver) Move(ctx context.Context, src, dst string) error {
	d.recordMutating("Move:" + dst)
	if d.failMove != nil && d.failMove(dst) {
		return driver.Error{DriverName: d.Name(), Detail: errInjectedMoveFailure}
	}
	return d.StorageDriver.Move(ctx, src, dst)
}

func (d *migrationTestDriver) Delete(ctx context.Context, p string) error {
	d.recordMutating("Delete:" + p)
	return d.StorageDriver.Delete(ctx, p)
}

func (d *migrationTestDriver) recordMutating(op string) {
	d.mu.Lock()
	d.mutatingCalls = append(d.mutatingCalls, op)
	d.mu.Unlock()
}

func (d *migrationTestDriver) offsetsFor(p string) []int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]int64, len(d.readOffsets[p]))
	copy(out, d.readOffsets[p])
	return out
}

func (d *migrationTestDriver) bytesReadFor(p string) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.bytesByPath[p]
}

func (d *migrationTestDriver) totalBytesRead() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.totalRead
}

func (d *migrationTestDriver) mutatingCallCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.mutatingCalls)
}

type countingReadCloser struct {
	d    *migrationTestDriver
	path string
	io.ReadCloser
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.d.mu.Lock()
	c.d.totalRead += int64(n)
	c.d.bytesByPath[c.path] += int64(n)
	c.d.mu.Unlock()
	return n, err
}

// panicWriteDriver wraps a driver and fails the test on any mutating call.
// It is the hard evidence that discovery/verify/cutover never write to the
// source backend.
type panicWriteDriver struct {
	driver.StorageDriver
	t *testing.T
}

func newPanicWriteDriver(t *testing.T, inner driver.StorageDriver) *panicWriteDriver {
	return &panicWriteDriver{StorageDriver: inner, t: t}
}

func (d *panicWriteDriver) PutContent(context.Context, string, []byte) error {
	d.t.Fatalf("source must be read-only: PutContent attempted")
	return nil
}

func (d *panicWriteDriver) Writer(context.Context, string, bool) (driver.FileWriter, error) {
	d.t.Fatalf("source must be read-only: Writer attempted")
	return nil, nil
}

func (d *panicWriteDriver) Move(context.Context, string, string) error {
	d.t.Fatalf("source must be read-only: Move attempted")
	return nil
}

func (d *panicWriteDriver) Delete(context.Context, string) error {
	d.t.Fatalf("source must be read-only: Delete attempted")
	return nil
}

// errInjectedMoveFailure is returned by the failMove test hook.
var errInjectedMoveFailure = injectedError("injected move failure")

type injectedError string

func (e injectedError) Error() string { return string(e) }
