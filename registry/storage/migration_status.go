package storage

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// This file aggregates ledger state into the migration status report used by
// `migrate status`, the convergence predicate and the cutover gate.

type MigrationStatusReport struct {
	RunID             string
	SourceDriver      string
	SourceFingerprint string
	GeneratedAt       time.Time

	// Global blobs.
	Blobs      map[migrationState]int64
	BlobBytes  map[migrationState]int64
	TotalBlobs int64

	// Repositories (top-level state).
	Repos      map[migrationState]int64
	TotalRepos int64

	// Per-repository sub-units.
	LayerLinks    map[migrationState]int64
	RevisionLinks map[migrationState]int64
	TagCurrents   map[migrationState]int64
	TagIndex      map[migrationState]int64
	Uploads       map[migrationState]int64

	// Isolation and staging.
	QuarantineActive int
	QuarantineAll    int
	QuarantineItems  []quarantineRecord
	TempRemaining    int

	Converged bool
	Blockers  []string
}

func newMigrationStatusReport() *MigrationStatusReport {
	return &MigrationStatusReport{
		GeneratedAt:   time.Now().UTC(),
		Blobs:         map[migrationState]int64{},
		BlobBytes:     map[migrationState]int64{},
		Repos:         map[migrationState]int64{},
		LayerLinks:    map[migrationState]int64{},
		RevisionLinks: map[migrationState]int64{},
		TagCurrents:   map[migrationState]int64{},
		TagIndex:      map[migrationState]int64{},
		Uploads:       map[migrationState]int64{},
	}
}

// buildStatus walks the ledger and computes the status report. When repoFilter
// is non-empty only those repository documents are aggregated (global blobs
// and quarantine are always reported in full, since they are shared state).
func buildStatus(ctx context.Context, l *migrationLedger, repoFilter map[string]struct{}) (*MigrationStatusReport, error) {
	r := newMigrationStatusReport()

	if run, exists, err := readRun(ctx, l); err != nil {
		return nil, err
	} else if exists {
		r.RunID = run.RunID
		r.SourceDriver = run.SourceDriver
		r.SourceFingerprint = run.SourceFingerprint
	}

	if err := l.listBlobRecords(ctx, func(b *blobRecord) error {
		r.TotalBlobs++
		r.Blobs[b.State]++
		r.BlobBytes[b.State] += b.ExpectedSize
		return nil
	}); err != nil {
		return nil, err
	}

	if err := l.listRepoRecords(ctx, func(rec *repoRecord) error {
		if len(repoFilter) > 0 {
			if _, ok := repoFilter[rec.Name]; !ok {
				return nil
			}
		}
		r.TotalRepos++
		r.Repos[rec.State]++

		for _, su := range rec.Layers {
			r.LayerLinks[su.State]++
		}
		for _, su := range rec.Revisions {
			r.RevisionLinks[su.State]++
		}
		for _, tu := range rec.Tags {
			if tu.HasCurrent {
				r.TagCurrents[tu.CurrentState]++
			}
			for _, st := range tu.Index {
				r.TagIndex[st]++
			}
		}
		for _, u := range rec.Uploads {
			r.Uploads[u.State]++
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if err := l.listQuarantineRecords(ctx, func(q *quarantineRecord) error {
		r.QuarantineAll++
		if !q.Resolved {
			r.QuarantineActive++
			if len(r.QuarantineItems) < 50 {
				r.QuarantineItems = append(r.QuarantineItems, *q)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	tmp, err := l.listTempFiles(ctx)
	if err != nil {
		return nil, err
	}
	r.TempRemaining = len(tmp)

	r.computeConvergence(repoFilter)
	return r, nil
}

// computeConvergence populates Converged/Blockers. Convergence requires:
//   - no pending/in_progress blobs;
//   - no quarantined/conflicting blobs;
//   - every (filtered) repository completed with all sub-units settled
//     (uploads may be completed or skipped) and no gone repository;
//   - no unresolved quarantine records;
//   - empty staging area.
func (r *MigrationStatusReport) computeConvergence(repoFilter map[string]struct{}) {
	add := func(format string, args ...any) {
		r.Blockers = append(r.Blockers, fmt.Sprintf(format, args...))
	}

	// An empty ledger means no migration discovery/run ever happened; it must
	// never be reported converged (an unconfigured target would otherwise
	// pass every gate and get a cutover marker).
	if r.RunID == "" {
		add("no migration run recorded on the target ledger")
	}
	if r.TotalRepos == 0 && r.TotalBlobs == 0 {
		add("ledger is empty: no repositories or blobs discovered yet")
	}

	if n := r.Blobs[statePending] + r.Blobs[stateInProgress]; n > 0 {
		add("%d blobs still pending/in_progress", n)
	}
	if n := r.Blobs[stateQuarantined]; n > 0 {
		add("%d blobs quarantined", n)
	}
	if n := r.Blobs[stateConflict]; n > 0 {
		add("%d blobs in conflict", n)
	}
	if n := r.LayerLinks[statePending] + r.LayerLinks[stateInProgress] +
		r.RevisionLinks[statePending] + r.RevisionLinks[stateInProgress] +
		r.TagCurrents[statePending] + r.TagCurrents[stateInProgress] +
		r.TagIndex[statePending] + r.TagIndex[stateInProgress] +
		r.Uploads[statePending] + r.Uploads[stateInProgress]; n > 0 {
		add("%d repository units still pending/in_progress", n)
	}
	if n := r.LayerLinks[stateQuarantined] + r.LayerLinks[stateConflict] +
		r.RevisionLinks[stateQuarantined] + r.RevisionLinks[stateConflict] +
		r.TagCurrents[stateQuarantined] + r.TagCurrents[stateConflict] +
		r.TagIndex[stateQuarantined] + r.TagIndex[stateConflict] +
		r.Uploads[stateQuarantined] + r.Uploads[stateConflict]; n > 0 {
		add("%d repository units quarantined/conflicting", n)
	}
	if n := r.Uploads[stateInProgress]; n > 0 {
		add("%d upload sessions still in progress", n)
	}
	if n := r.Repos[statePending] + r.Repos[stateInProgress] +
		r.Repos[stateQuarantined] + r.Repos[stateConflict]; n > 0 {
		add("%d repositories not completed", n)
	}
	if r.QuarantineActive > 0 {
		add("%d unresolved quarantine/conflict records", r.QuarantineActive)
	}
	if r.TempRemaining > 0 {
		add("%d files left in the staging area", r.TempRemaining)
	}

	_ = repoFilter
	r.Converged = len(r.Blockers) == 0
}

// writeText renders the report in the human-readable form used by the CLI.
func (r *MigrationStatusReport) writeText(w io.Writer) {
	fmt.Fprintf(w, "Migration status\n")
	if r.RunID != "" {
		fmt.Fprintf(w, "  run id:             %s\n", r.RunID)
	}
	if r.SourceDriver != "" {
		fmt.Fprintf(w, "  source:             %s (%s)\n", r.SourceDriver, r.SourceFingerprint)
	}
	fmt.Fprintf(w, "  generated at:       %s\n", r.GeneratedAt.Format(time.RFC3339))

	fmt.Fprintf(w, "Blobs: %d total\n", r.TotalBlobs)
	writeStateLine(w, "    ", r.Blobs, r.BlobBytes)
	fmt.Fprintf(w, "Repositories: %d total\n", r.TotalRepos)
	writeCountLine(w, "    ", r.Repos)
	fmt.Fprintln(w, "  layer links:")
	writeCountLine(w, "    ", r.LayerLinks)
	fmt.Fprintln(w, "  revision links:")
	writeCountLine(w, "    ", r.RevisionLinks)
	fmt.Fprintln(w, "  tag current links:")
	writeCountLine(w, "    ", r.TagCurrents)
	fmt.Fprintln(w, "  tag index links:")
	writeCountLine(w, "    ", r.TagIndex)
	fmt.Fprintln(w, "  upload sessions:")
	writeCountLine(w, "    ", r.Uploads)

	fmt.Fprintf(w, "Quarantine: %d active (%d recorded)\n", r.QuarantineActive, r.QuarantineAll)
	items := append([]quarantineRecord(nil), r.QuarantineItems...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	for _, q := range items {
		fmt.Fprintf(w, "    - [%s] %s repo=%q key=%s: %s\n", q.Kind, q.ID, q.Repo, q.Key, q.Reason)
	}
	fmt.Fprintf(w, "Staging leftovers: %d\n", r.TempRemaining)
	if r.Converged {
		fmt.Fprintln(w, "Converged: YES")
	} else {
		fmt.Fprintln(w, "Converged: NO")
		for _, b := range r.Blockers {
			fmt.Fprintf(w, "  blocker: %s\n", b)
		}
	}
}

func writeStateLine(w io.Writer, indent string, counts map[migrationState]int64, bytes map[migrationState]int64) {
	for _, st := range stateOrder() {
		if counts[st] > 0 {
			fmt.Fprintf(w, "%s%s: %d (%d bytes)\n", indent, st, counts[st], bytes[st])
		}
	}
}

func writeCountLine(w io.Writer, indent string, counts map[migrationState]int64) {
	for _, st := range stateOrder() {
		if counts[st] > 0 {
			fmt.Fprintf(w, "%s%s: %d\n", indent, st, counts[st])
		}
	}
}

func stateOrder() []migrationState {
	return []migrationState{statePending, stateInProgress, stateCompleted, stateSkipped, stateQuarantined, stateConflict}
}

func (r *MigrationStatusReport) String() string {
	var b strings.Builder
	r.writeText(&b)
	return b.String()
}

// readRun is a small helper around the run record used by status/verify.
func readRun(ctx context.Context, l *migrationLedger) (*runRecord, bool, error) {
	var rec runRecord
	exists, err := l.readJSON(ctx, l.runStatePath(), &rec)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	return &rec, true, nil
}
