package storage

import (
	"context"
	"errors"

	"github.com/distribution/distribution/v3/registry/storage/driver"
)

// ErrReadOnlyStorage is returned by every mutating method of a source driver
// wrapper used during migration. The migration tool must never modify the
// source backend, which stays readable and serviceable until cutover.
var ErrReadOnlyStorage = errors.New("the migration source storage driver is read-only")

// readOnlyStorageDriver wraps a StorageDriver and refuses every mutating
// operation. Read operations (GetContent, Reader, Stat, List, Walk,
// RedirectURL) pass through unchanged.
type readOnlyStorageDriver struct {
	driver.StorageDriver
}

// WrapReadOnly guards a source driver so migration code paths cannot mutate
// it even by accident.
func WrapReadOnly(d driver.StorageDriver) driver.StorageDriver {
	return &readOnlyStorageDriver{StorageDriver: d}
}

func (d *readOnlyStorageDriver) PutContent(context.Context, string, []byte) error {
	return ErrReadOnlyStorage
}

func (d *readOnlyStorageDriver) Writer(context.Context, string, bool) (driver.FileWriter, error) {
	return nil, ErrReadOnlyStorage
}

func (d *readOnlyStorageDriver) Move(context.Context, string, string) error {
	return ErrReadOnlyStorage
}

func (d *readOnlyStorageDriver) Delete(context.Context, string) error {
	return ErrReadOnlyStorage
}
