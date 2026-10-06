package storage

import (
	"context"

	"github.com/distribution/distribution/v3/registry/storage/driver"
)

// This file is the exported entry surface consumed by the `registry migrate`
// CLI commands in package registry. All types are implemented in the adjacent
// migration_*.go files; these wrappers keep the cross-package API explicit.

// RunMigration performs one (possibly batch-limited) migration pass.
func RunMigration(ctx context.Context, src, dst driver.StorageDriver, opts MigrationOptions) (*RunSummary, error) {
	return runMigration(ctx, src, dst, opts)
}

// MigrationStatus aggregates the current ledger state.
func MigrationStatus(ctx context.Context, dst driver.StorageDriver, repos []string, ledgerPrefix string) (*MigrationStatusReport, error) {
	return migrationStatus(ctx, dst, repos, ledgerPrefix)
}

// RunVerify independently verifies migrated objects on the destination.
func RunVerify(ctx context.Context, src, dst driver.StorageDriver, opts VerifyOptions) (*VerifyReport, error) {
	return runVerify(ctx, src, dst, opts)
}

// RunCutover gates and writes the explicit switchover marker.
func RunCutover(ctx context.Context, src, dst driver.StorageDriver, opts VerifyOptions) (*CutoverRecord, error) {
	return runCutover(ctx, src, dst, opts)
}

// CutoverRecord is the exported switchover marker.
type CutoverRecord = cutoverRecord

// ReadOnlyDriver wraps a driver so migration cannot mutate it.
func ReadOnlyDriver(d driver.StorageDriver) driver.StorageDriver { return WrapReadOnly(d) }
