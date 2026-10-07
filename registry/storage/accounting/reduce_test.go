package accounting

import (
	"math/rand"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
)

var (
	dgA = digest.FromString("blob-a")
	dgB = digest.FromString("blob-b")
	t0  = time.Unix(1000, 0)
)

func TestReserveReleaseSettleFlow(t *testing.T) {
	events := []Event{
		Reserved("r1", "repo", 100, KindUpload, dgA, t0),
		Reserved("r2", "repo", 50, KindMount, dgB, t0.Add(time.Second)),
	}
	s := Reduce(events)
	if got := s.ReservedBytes(); got != 150 {
		t.Fatalf("reserved = %d, want 150", got)
	}
	if got := s.SettledBytes(); got != 0 {
		t.Fatalf("settled = %d, want 0", got)
	}

	// settle r1 into dgA layer role.
	s.Apply(Settled("e1", "r1", "repo", dgA, RoleLayer, 100, t0.Add(2*time.Second)))
	if got := s.ReservedBytes(); got != 50 {
		t.Fatalf("reserved after settle = %d, want 50", got)
	}
	if got := s.SettledBytes(); got != 100 {
		t.Fatalf("settled = %d, want 100", got)
	}

	// release r2.
	s.Apply(Released("e2", "r2", "repo", t0.Add(3*time.Second)))
	if got := s.ReservedBytes(); got != 0 {
		t.Fatalf("reserved after release = %d, want 0", got)
	}
	if len(s.ActiveReservations()) != 0 {
		t.Fatal("expected no active reservations")
	}
}

func TestDuplicateSettleSameDigestCountedOnce(t *testing.T) {
	// Same digest committed twice via two independent uploads: only the first
	// settle counts and both reservations are closed.
	events := []Event{
		Reserved("r1", "repo", 100, KindUpload, dgA, t0),
		Reserved("r2", "repo", 100, KindUpload, dgA, t0.Add(time.Second)),
		Settled("e1", "r1", "repo", dgA, RoleLayer, 100, t0.Add(2*time.Second)),
		Settled("e2", "r2", "repo", dgA, RoleLayer, 100, t0.Add(3*time.Second)),
	}
	s := Reduce(events)
	if got := s.SettledBytes(); got != 100 {
		t.Fatalf("settled = %d, want 100", got)
	}
	if got := s.ReservedBytes(); got != 0 {
		t.Fatalf("reserved = %d, want 0", got)
	}
	if len(s.ActiveReservations()) != 0 {
		t.Fatal("both reservations must be closed after duplicate settle")
	}
}

func TestDebitRoleSemantics(t *testing.T) {
	// dgA holds both roles. Debiting one keeps the entry; debiting the other
	// removes it; an extra duplicate debit is a no-op and never negative.
	events := []Event{
		Reserved("r1", "repo", 100, KindInline, dgA, t0),
		Settled("e1", "r1", "repo", dgA, RoleLayer, 100, t0.Add(time.Second)),
		Settled("e2", "r2", "repo", dgA, RoleRevision, 100, t0.Add(2*time.Second)),
	}
	s := Reduce(events)
	if got := s.SettledBytes(); got != 100 {
		t.Fatalf("settled with both roles = %d, want 100", got)
	}

	s.Apply(Debited("d1", "repo", dgA, RoleLayer, t0.Add(3*time.Second)))
	if got := s.SettledBytes(); got != 100 {
		t.Fatalf("settled after layer debit = %d, want 100 (revision still present)", got)
	}
	s.Apply(Debited("d2", "repo", dgA, RoleLayer, t0.Add(4*time.Second))) // duplicate role debit
	if got := s.SettledBytes(); got != 100 {
		t.Fatalf("duplicate debit drifted settled to %d", got)
	}
	s.Apply(Debited("d3", "repo", dgA, RoleRevision, t0.Add(5*time.Second)))
	if got := s.SettledBytes(); got != 0 {
		t.Fatalf("settled after both debits = %d, want 0", got)
	}
	// debit of an unknown digest/role is a no-op, never negative.
	s.Apply(Debited("d4", "repo", dgB, RoleLayer, t0.Add(6*time.Second)))
	if got := s.SettledBytes(); got != 0 {
		t.Fatalf("unknown debit produced settled = %d", got)
	}
}

func TestRelinkAfterDebit(t *testing.T) {
	// delete then re-push: a later settle supersedes an earlier debit.
	events := []Event{
		Reserved("r1", "repo", 100, KindUpload, dgA, t0),
		Settled("e1", "r1", "repo", dgA, RoleLayer, 100, t0.Add(time.Second)),
		Debited("d1", "repo", dgA, RoleLayer, t0.Add(2*time.Second)),
		Reserved("r2", "repo", 100, KindUpload, dgA, t0.Add(3*time.Second)),
		Settled("e2", "r2", "repo", dgA, RoleLayer, 100, t0.Add(4*time.Second)),
	}
	s := Reduce(events)
	if got := s.SettledBytes(); got != 100 {
		t.Fatalf("settled after re-link = %d, want 100", got)
	}
	if !s.HasRole(dgA, RoleLayer) {
		t.Fatal("layer role should be present after re-settle")
	}
}

func TestCompensatingEvents(t *testing.T) {
	// release for unknown reservation then a late duplicate reserved event
	// must not revive the reservation.
	s := NewState()
	s.Apply(Released("e2", "ghost", "repo", t0.Add(2*time.Second)))
	s.Apply(Reserved("ghost", "repo", 100, KindMount, dgA, t0))
	if got := s.ReservedBytes(); got != 0 {
		t.Fatalf("late reserved after release revived reservation: %d", got)
	}

	// settle referencing an unknown reservation simply settles the entry.
	s.Apply(Settled("e3", "other", "repo", dgB, RoleLayer, 50, t0.Add(3*time.Second)))
	if got := s.SettledBytes(); got != 50 {
		t.Fatalf("settled = %d, want 50", got)
	}
}

func TestOrderIndependence(t *testing.T) {
	base := []Event{
		Reserved("r1", "repo", 100, KindUpload, dgA, t0),
		Reserved("r2", "repo", 70, KindMount, dgB, t0),
		Settled("e1", "r1", "repo", dgA, RoleLayer, 100, t0.Add(time.Second)),
		Settled("e2", "r2", "repo", dgB, RoleLayer, 70, t0.Add(2*time.Second)),
		Released("x1", "r9", "repo", t0.Add(3*time.Second)),
		Debited("d1", "repo", dgA, RoleLayer, t0.Add(4*time.Second)),
		Settled("e3", "r3", "repo", dgA, RoleLayer, 100, t0.Add(5*time.Second)),
		Reserved("r3", "repo", 100, KindUpload, dgA, t0.Add(4500*time.Millisecond)),
	}

	want := Reduce(base)
	wantSettled, wantReserved := want.SettledBytes(), want.ReservedBytes()

	rng := rand.New(rand.NewSource(42))
	for iter := 0; iter < 50; iter++ {
		shuffled := append([]Event(nil), base...)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		// duplicate every event to simulate replays.
		dup := append(append([]Event(nil), shuffled...), base...)
		got := Reduce(dup)
		if got.SettledBytes() != wantSettled || got.ReservedBytes() != wantReserved {
			t.Fatalf("iter %d: got (settled=%d reserved=%d), want (settled=%d reserved=%d)",
				iter, got.SettledBytes(), got.ReservedBytes(), wantSettled, wantReserved)
		}
	}

	// repeated full reductions must be identical structurally.
	f1 := Reduce(base)
	data1, _ := f1.Marshal()
	f2 := Reduce(base)
	data2, _ := f2.Marshal()
	if string(data1) != string(data2) {
		t.Fatal("repeated reductions are not identical")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	events := []Event{
		Reserved("r1", "repo", 100, KindUpload, dgA, t0),
		Settled("e1", "r1", "repo", dgA, RoleLayer, 100, t0.Add(time.Second)),
		Settled("e2", "r2", "repo", dgA, RoleRevision, 100, t0.Add(2*time.Second)),
		Reserved("r9", "repo", 30, KindInline, dgB, t0.Add(3*time.Second)),
	}
	original := Reduce(events)

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	restored, err := UnmarshalState(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if restored.SettledBytes() != original.SettledBytes() ||
		restored.ReservedBytes() != original.ReservedBytes() {
		t.Fatalf("snapshot round trip mismatch: (%d,%d) vs (%d,%d)",
			restored.SettledBytes(), restored.ReservedBytes(),
			original.SettledBytes(), original.ReservedBytes())
	}

	// apply post-snapshot events on restored state and compare with a full
	// reduction.
	restored.Apply(Debited("d1", "repo", dgA, RoleLayer, t0.Add(4*time.Second)))
	restored.Apply(Released("e9", "r9", "repo", t0.Add(5*time.Second)))

	full := Reduce(append(events,
		Debited("d1", "repo", dgA, RoleLayer, t0.Add(4*time.Second)),
		Released("e9", "r9", "repo", t0.Add(5*time.Second)),
	))
	if restored.SettledBytes() != full.SettledBytes() || restored.ReservedBytes() != full.ReservedBytes() {
		t.Fatalf("post-snapshot application mismatch: (%d,%d) vs (%d,%d)",
			restored.SettledBytes(), restored.ReservedBytes(),
			full.SettledBytes(), full.ReservedBytes())
	}
}
