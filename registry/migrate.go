package registry

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/storage"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	"github.com/spf13/cobra"
)

// `registry migrate` copies an entire registry from one storage backend to
// another with a durable, per-repository/per-digest migration ledger living
// on the destination. The source driver is always wrapped read-only.
//
// Subcommands:
//
//	migrate run       discover, copy and checkpoint (repeatable, batchable)
//	migrate status    show progress, isolation and convergence
//	migrate verify    independently re-verify the destination
//	migrate cutover   final gate + explicit switchover marker

var (
	migrateSource       string
	migrateTarget       string
	migrateRepos        []string
	migrateBatchSize    int64
	migrateConcurrency  int
	migrateIncludeUp    bool
	migrateForce        bool
	migrateLockTTL      time.Duration
	migrateLedgerPrefix string
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "migrate registry data between storage backends",
	Long: `Migrate an entire registry from the --source storage backend to the
--target storage backend. Progress is recorded in a migration ledger stored on
the target backend, so repeated runs resume without restarting. The source is
never modified; after convergence, verification and a final zero-drift sweep,
"migrate cutover" writes the explicit switchover marker.`,
}

var migrateRunCmd = &cobra.Command{
	Use:   "run",
	Short: "run one (batch-limited) migration pass",
	Long: `Discover the source, copy pending blobs/links/upload sessions to the
target and checkpoint progress. Repeat the command to continue; completed work
is never copied twice. --batch-size limits newly claimed units per invocation
(0, the default, drains all currently pending work).`,
	RunE: runMigrate,
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "show migration progress and convergence",
	RunE:  statusMigrate,
}

var migrateVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "independently verify the migrated destination",
	Long: `Re-hash every migrated blob, check every migrated link and compare
tag trees with the source. Failed units are moved into quarantine and the
command exits non-zero when verification does not pass.`,
	RunE: verifyMigrate,
}

var migrateCutoverCmd = &cobra.Command{
	Use:   "cutover",
	Short: "final cutover gate and switchover marker",
	Long: `Write the switchover marker only when the migration is converged,
the source has zero drift versus a fresh sweep, verification passes and no
staging files remain. Freeze writes on the source before running this command;
after it succeeds, point the registry at the target and restart.

Note: the empty-staging gate observes committed ledger-tracked objects.
In-progress cloud multipart uploads left by a process killed outside of this
tool (and therefore never recorded in the ledger) are not enumerable through
the storage driver; tracked uploads are resumed or aborted automatically.`,
	RunE: cutoverMigrate,
}

func init() {
	migrateCmd.PersistentFlags().StringVar(&migrateSource, "source", "", "registry configuration file describing the source backend")
	migrateCmd.PersistentFlags().StringVar(&migrateTarget, "target", "", "registry configuration file describing the target backend")
	migrateCmd.PersistentFlags().StringVar(&migrateLedgerPrefix, "ledger-prefix", "", "override the destination ledger prefix")
	migrateCmd.PersistentFlags().StringArrayVar(&migrateRepos, "repo", nil, "limit the operation to this repository (can be repeated)")

	migrateRunCmd.Flags().Int64Var(&migrateBatchSize, "batch-size", 0, "maximum newly claimed units in this pass (0 = drain pending work)")
	migrateRunCmd.Flags().IntVar(&migrateConcurrency, "concurrency", runtime.GOMAXPROCS(0), "repository worker concurrency")
	migrateRunCmd.Flags().BoolVar(&migrateIncludeUp, "include-uploads", true, "copy interrupted _uploads sessions as session state (never promoted to blobs)")
	migrateRunCmd.Flags().BoolVar(&migrateForce, "force", false, "take over an expired migration lock")
	migrateRunCmd.Flags().DurationVar(&migrateLockTTL, "lock-ttl", 0, "advisory lock TTL (default 90s)")

	migrateCmd.AddCommand(migrateRunCmd, migrateStatusCmd, migrateVerifyCmd, migrateCutoverCmd)
	RootCmd.AddCommand(migrateCmd)
}

// openMigrationDriver constructs a storage driver from a standard registry
// configuration file.
func openMigrationDriver(configPath string) (string, driver.StorageDriver, error) {
	if strings.TrimSpace(configPath) == "" {
		return "", nil, errors.New("configuration file path unspecified")
	}
	cfg, err := resolveConfiguration([]string{configPath})
	if err != nil {
		return "", nil, fmt.Errorf("load %s: %w", configPath, err)
	}
	d, err := factory.Create(context.Background(), cfg.Storage.Type(), cfg.Storage.Parameters())
	if err != nil {
		return "", nil, fmt.Errorf("construct storage driver from %s: %w", configPath, err)
	}
	return cfg.Storage.Type(), d, nil
}

func requireBothBackends(cmd string) error {
	if migrateSource == "" {
		return fmt.Errorf("%s requires --source", cmd)
	}
	if migrateTarget == "" {
		return fmt.Errorf("%s requires --target", cmd)
	}
	return nil
}

func runMigrate(cmd *cobra.Command, _ []string) error {
	if err := requireBothBackends("migrate run"); err != nil {
		return err
	}
	srcName, src, err := openMigrationDriver(migrateSource)
	if err != nil {
		return err
	}
	dstName, dst, err := openMigrationDriver(migrateTarget)
	if err != nil {
		return err
	}
	ctx := context.Background()
	summary, err := storage.RunMigration(ctx, storage.ReadOnlyDriver(src), dst, storage.MigrationOptions{
		BatchSize:      migrateBatchSize,
		Concurrency:    migrateConcurrency,
		IncludeUploads: migrateIncludeUp,
		Repositories:   migrateRepos,
		Force:          migrateForce,
		LockTTL:        migrateLockTTL,
		LedgerPrefix:   migrateLedgerPrefix,
	})
	if err != nil {
		return describeMigrationError(err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "migration pass: source=%s target=%s claimed=%d repos=%d/%d\n",
		srcName, dstName, summary.ProcessedUnits, summary.ReposCompleted, summary.ReposAttempted)
	fmt.Fprintln(cmd.OutOrStdout(), summary.Status.String())
	if len(summary.RepoErrors) > 0 {
		return fmt.Errorf("migration pass finished with %d repository errors; rerun to retry: %s",
			len(summary.RepoErrors), strings.Join(summary.RepoErrors, "; "))
	}
	return nil
}

func statusMigrate(cmd *cobra.Command, _ []string) error {
	if migrateTarget == "" {
		return errors.New("migrate status requires --target")
	}
	dstName, dst, err := openMigrationDriver(migrateTarget)
	if err != nil {
		return err
	}
	report, err := storage.MigrationStatus(context.Background(), dst, migrateRepos, migrateLedgerPrefix)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "target=%s\n", dstName)
	fmt.Fprintln(cmd.OutOrStdout(), report.String())
	return nil
}

func verifyMigrate(cmd *cobra.Command, _ []string) error {
	if err := requireBothBackends("migrate verify"); err != nil {
		return err
	}
	_, src, err := openMigrationDriver(migrateSource)
	if err != nil {
		return err
	}
	_, dst, err := openMigrationDriver(migrateTarget)
	if err != nil {
		return err
	}
	report, err := storage.RunVerify(context.Background(), storage.ReadOnlyDriver(src), dst, storage.VerifyOptions{
		Repositories: migrateRepos, LedgerPrefix: migrateLedgerPrefix,
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), report.String())
	if !report.Passed {
		return fmt.Errorf("verification failed: %d issue(s)", len(report.Failures))
	}
	return nil
}

func cutoverMigrate(cmd *cobra.Command, _ []string) error {
	if err := requireBothBackends("migrate cutover"); err != nil {
		return err
	}
	_, src, err := openMigrationDriver(migrateSource)
	if err != nil {
		return err
	}
	_, dst, err := openMigrationDriver(migrateTarget)
	if err != nil {
		return err
	}
	rec, err := storage.RunCutover(context.Background(), storage.ReadOnlyDriver(src), dst, storage.VerifyOptions{
		Repositories: migrateRepos, LedgerPrefix: migrateLedgerPrefix,
	})
	if err != nil {
		return describeMigrationError(err)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "CUTOVER MARKER WRITTEN")
	fmt.Fprintf(out, "  run id:           %s\n", rec.RunID)
	fmt.Fprintf(out, "  cutover at (UTC): %s\n", rec.CutoverAt.Format(time.RFC3339))
	fmt.Fprintf(out, "  source:           %s (%s)\n", rec.SourceDriver, rec.SourceFingerprint)
	fmt.Fprintf(out, "  ledger digest:    %s\n", rec.LedgerDigest)
	fmt.Fprintln(out, `
Switch steps:
  1. freeze/stop writes to the source registry
  2. point the registry configuration storage at the target backend
  3. restart the registry and confirm pulls/pushes work
  4. keep the source backend read-only until confident, then decommission`)
	return nil
}

// describeMigrationError makes lock and cutover errors self-explanatory.
func describeMigrationError(err error) error {
	switch {
	case errors.Is(err, storage.ErrMigrationLocked):
		return fmt.Errorf("%w\nanother migration run holds an active lock; wait for it or re-run once it is stale", err)
	case errors.Is(err, storage.ErrMigrationLockExpired):
		return fmt.Errorf("%w\nre-run migrate run with --force to take over the expired lock", err)
	case errors.Is(err, storage.ErrCutoverBlocked):
		return fmt.Errorf("%w\nresolve the listed blockers (see 'migrate status' and 'migrate verify'), then re-run", err)
	default:
		return err
	}
}
