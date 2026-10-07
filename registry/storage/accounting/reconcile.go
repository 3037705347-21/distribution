package accounting

import (
	"context"
	"time"

	"github.com/opencontainers/go-digest"
)

// ExpectedKey describes one physical (digest, role) reference observed in a
// repository during reconciliation.
type ExpectedKey struct {
	Digest digest.Digest
	Role   Role
	Size   int64
}

// Correct repairs the repository ledger against the physical reference set:
// missing natural keys are seeded with idempotent settle events, present
// ledger entries without a physical reference are debited. Nothing is
// emitted for keys that already agree, so repeated reconciliation is cheap
// and event-log friendly.
func (s *Store) Correct(ctx context.Context, repo string, expected []ExpectedKey) error {
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	ledger, err := s.load(ctx, repo)
	if err != nil {
		return err
	}

	type naturalKey struct {
		digest digest.Digest
		role   Role
	}
	expectedSet := make(map[naturalKey]int64, len(expected))
	for _, k := range expected {
		expectedSet[naturalKey{k.Digest, k.Role}] = k.Size
	}

	var events []Event
	now := s.now()

	// seed missing keys
	for _, k := range expected {
		if ledger.state.HasRole(k.Digest, k.Role) {
			continue
		}
		events = append(events, SettledReconcile(s.eventID(), repo, k.Digest, k.Role, k.Size, now))
	}

	// debit entries without a physical reference
	for _, e := range ledger.state.Entries() {
		for _, role := range e.Roles {
			if _, ok := expectedSet[naturalKey{e.Digest, role}]; ok {
				continue
			}
			events = append(events, Debited(s.eventID(), repo, e.Digest, role, now))
		}
	}

	for _, e := range events {
		if err := s.appendEvent(ctx, e); err != nil {
			return err
		}
	}
	if len(events) > 0 {
		updated, err := s.reload(ctx, repo)
		if err != nil {
			return err
		}
		s.notify(repo, updated)
	}
	return nil
}

// ExpireReservations releases active reservations older than cutoff. Upload
// reservations whose _uploads directory still exists (liveUploads contains
// the upload UUID) are kept; mount/inline reservations expire purely by age.
// Returns the number of reservations released.
func (s *Store) ExpireReservations(ctx context.Context, repo string, cutoff time.Time, liveUploads map[string]bool) (int, error) {
	mu := s.repoLock(repo)
	mu.Lock()
	defer mu.Unlock()

	ledger, err := s.load(ctx, repo)
	if err != nil {
		return 0, err
	}

	var released int
	for _, r := range ledger.state.ActiveReservations() {
		if !r.Since.Before(cutoff) {
			continue
		}
		if r.Kind == KindUpload && liveUploads[r.ID] {
			continue
		}
		if err := s.appendEvent(ctx, Released(s.eventID(), r.ID, repo, s.now())); err != nil {
			return released, err
		}
		released++
	}
	if released > 0 {
		updated, err := s.reload(ctx, repo)
		if err != nil {
			return released, err
		}
		s.notify(repo, updated)
	}
	return released, nil
}
