package storage

import (
	"context"
	"sort"

	"github.com/opencontainers/go-digest"
)

// This file merges a source discovery snapshot into the migration ledger:
// new units become pending, units that disappeared from the source are
// annotated Gone (never deleted), referenced blobs get global records with
// their source size, and discovery problems become quarantine records.

// upsertResult counts what the merge introduced.
type upsertResult struct {
	NewBlobs         int
	NewLayerLinks    int
	NewRevisionLinks int
	NewTagUnits      int
	NewTagIndex      int
	NewUploads       int
	Problems         int
}

// upsertDiscovery merges snap into the ledger. When includeUploads is false
// newly discovered upload sessions are recorded as skipped. When full is true
// (unfiltered discovery), repositories present in the ledger but absent from
// the snapshot are marked Gone.
func upsertDiscovery(ctx context.Context, l *migrationLedger, snap *migrationDiscovery, includeUploads, full bool) (*upsertResult, error) {
	res := &upsertResult{}

	names := make([]string, 0, len(snap.Repos))
	for name := range snap.Repos {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		dr := snap.Repos[name]

		_, err := l.mutateRepoRecord(ctx, name, true, func(rec *repoRecord) error {
			rec.Gone = false
			res.NewLayerLinks += mergeSubUnits(&rec.Layers, dr.Layers)
			res.NewRevisionLinks += mergeSubUnits(&rec.Revisions, dr.Revisions)
			res.NewTagUnits += mergeTags(rec, dr.Tags, &res.NewTagIndex)
			res.NewUploads += mergeUploads(rec, dr.Uploads, includeUploads)
			return nil
		})
		if err != nil {
			return nil, err
		}

		// Create/refresh global blob records for every resolvable reference.
		blobSet := map[string]bool{}
		for dg := range dr.Layers {
			blobSet[dg] = true
		}
		for dg := range dr.Revisions {
			blobSet[dg] = true
		}
		for _, t := range dr.Tags {
			if t.HasCurrent {
				blobSet[t.Current] = true
			}
			for dg := range t.Index {
				blobSet[dg] = true
			}
		}
		dgsts := make([]string, 0, len(blobSet))
		for dg := range blobSet {
			dgsts = append(dgsts, dg)
		}
		sort.Strings(dgsts)
		for _, raw := range dgsts {
			size, resolvable := snap.BlobSizes[raw]
			if !resolvable {
				continue // dangling references are handled via quarantine below
			}
			dgst, err := digest.Parse(raw)
			if err != nil {
				continue
			}
			_, existed, gerr := l.getBlobRecord(ctx, dgst)
			if gerr != nil {
				return nil, gerr
			}
			_, err = l.mutateBlobRecord(ctx, dgst, true, func(rec *blobRecord) error {
				if rec.ExpectedSize == 0 {
					rec.ExpectedSize = size
				}
				addBlobRef(rec, name)
				return nil
			})
			if err != nil {
				return nil, err
			}
			if !existed {
				res.NewBlobs++
			}
		}
	}

	// Discovery problems become quarantine records (deduped).
	currentProblems := map[string]bool{}
	for _, p := range snap.Problems {
		res.Problems++
		currentProblems[discoveryProblemIdentity(p.Kind, p.Repo, p.Key)] = true
		if _, err := l.quarantine(ctx, &quarantineRecord{
			Kind:   p.Kind,
			Repo:   p.Repo,
			Key:    p.Key,
			Reason: p.Reason + targetSuffix(p.Target),
		}); err != nil {
			return nil, err
		}
	}

	// Problems that a fresh full sweep no longer sees are auto-resolved so a
	// repaired source stops blocking convergence. Skipped for filtered runs,
	// whose snapshot is deliberately partial.
	if full {
		if err := resolveStaleDiscoveryQuarantine(ctx, l, currentProblems); err != nil {
			return nil, err
		}
	}

	// Mark repositories that vanished from the source (full sweeps only).
	if full {
		if err := l.listRepoRecords(ctx, func(rec *repoRecord) error {
			if _, ok := snap.Repos[rec.Name]; !ok && !rec.Gone {
				_, err := l.mutateRepoRecord(ctx, rec.Name, false, func(rec *repoRecord) error {
					rec.Gone = true
					return nil
				})
				return err
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	return res, nil
}

// discoveryQuarantineKinds are isolation records that can be auto-resolved
// when the corresponding problem disappears from a fresh source sweep.
var discoveryQuarantineKinds = map[string]bool{
	qKindLinkMalformed:    true,
	qKindLinkDangling:     true,
	qKindTagTargetMissing: true,
	qKindBlobUnreadable:   true,
}

func discoveryProblemIdentity(kind, repo, key string) string {
	return kind + "\x00" + repo + "\x00" + key
}

func resolveStaleDiscoveryQuarantine(ctx context.Context, l *migrationLedger, current map[string]bool) error {
	var stale []string
	if err := l.listQuarantineRecords(ctx, func(q *quarantineRecord) error {
		if q.Resolved || !discoveryQuarantineKinds[q.Kind] {
			return nil
		}
		if !current[discoveryProblemIdentity(q.Kind, q.Repo, q.Key)] {
			stale = append(stale, q.ID)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, id := range stale {
		if err := l.resolveQuarantine(ctx, id, "no longer present on source in latest sweep"); err != nil {
			return err
		}
	}
	return nil
}

func targetSuffix(target string) string {
	if target == "" {
		return ""
	}
	return " (target: " + target + ")"
}

// mergeSubUnits upserts digest-keyed layer/revision units and marks vanished
// keys Gone. It returns the number of newly introduced units.
func mergeSubUnits(m *map[string]migrationSubUnit, found map[string]bool) int {
	new := 0
	if *m == nil {
		*m = map[string]migrationSubUnit{}
	}
	for dg := range found {
		su, ok := (*m)[dg]
		if !ok {
			(*m)[dg] = migrationSubUnit{State: statePending, Target: dg}
			new++
			continue
		}
		// A unit isolated on a previous sweep is re-armed when a fresh sweep
		// still sees it (the operator may have repaired the source).
		if su.State == stateQuarantined || su.State == stateConflict {
			su.State = statePending
			su.Gone = false
			(*m)[dg] = su
		}
	}
	for dg, su := range *m {
		_, present := found[dg]
		if su.Gone != !present {
			su.Gone = !present
			(*m)[dg] = su
		}
	}
	return new
}

// mergeTags upserts tags including their index history.
func mergeTags(rec *repoRecord, found map[string]*discoveredTag, newIndex *int) int {
	newTags := 0
	if rec.Tags == nil {
		rec.Tags = map[string]migrationTagUnit{}
	}
	for name, dt := range found {
		t, ok := rec.Tags[name]
		if !ok {
			t = migrationTagUnit{Index: map[string]migrationState{}}
			newTags++
		}
		if t.Index == nil {
			t.Index = map[string]migrationState{}
		}
		t.Gone = false
		t.HasCurrent = dt.HasCurrent
		if dt.HasCurrent {
			if t.Current != dt.Current {
				t.Current = dt.Current
				t.CurrentState = statePending
			} else if t.CurrentState == stateQuarantined || t.CurrentState == stateConflict {
				t.CurrentState = statePending
			}
		}
		for dg := range dt.Index {
			if st, ok := t.Index[dg]; !ok {
				t.Index[dg] = statePending
				*newIndex++
			} else if st == stateQuarantined || st == stateConflict {
				t.Index[dg] = statePending
			}
			t.unmarkIndexGone(dg)
		}
		for dg := range t.Index {
			if !dt.Index[dg] {
				t.markIndexGone(dg)
			}
		}
		rec.Tags[name] = t
	}
	for name, t := range rec.Tags {
		if _, ok := found[name]; !ok {
			t.Gone = true
			rec.Tags[name] = t
		}
	}
	return newTags
}

// mergeUploads upserts interrupted upload sessions.
func mergeUploads(rec *repoRecord, found map[string]*discoveredUpload, includeUploads bool) int {
	newUploads := 0
	if rec.Uploads == nil {
		rec.Uploads = map[string]migrationUploadUnit{}
	}
	for id, du := range found {
		u, ok := rec.Uploads[id]
		if !ok {
			u = migrationUploadUnit{}
			if includeUploads {
				u.State = statePending
			} else {
				u.State = stateSkipped
			}
			newUploads++
		} else if u.State == stateQuarantined || u.State == stateConflict {
			// Re-arm after a source repair; honor the current include policy.
			if includeUploads {
				u.State = statePending
			} else {
				u.State = stateSkipped
			}
		}
		u.Gone = false
		u.Files = append([]string(nil), du.Files...)
		u.DataSize = du.DataSize
		rec.Uploads[id] = u
	}
	for id, u := range rec.Uploads {
		if _, ok := found[id]; !ok {
			u.Gone = true
			rec.Uploads[id] = u
		}
	}
	return newUploads
}

func (t *migrationTagUnit) markIndexGone(dg string) {
	if t.IndexGone == nil {
		t.IndexGone = map[string]bool{}
	}
	t.IndexGone[dg] = true
}

func (t *migrationTagUnit) unmarkIndexGone(dg string) {
	if t.IndexGone != nil {
		delete(t.IndexGone, dg)
		if len(t.IndexGone) == 0 {
			t.IndexGone = nil
		}
	}
}
