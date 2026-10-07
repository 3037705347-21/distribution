package accounting

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/opencontainers/go-digest"
)

// marker is a last-writer-wins version vector: the event with the latest time
// (event Seq breaks ties) wins for a natural key. This makes reduction
// independent of event delivery/replay order.
type marker struct {
	At  time.Time `json:"at"`
	Seq string    `json:"seq,omitempty"`
}

func (m marker) after(o marker) bool {
	if m.At.After(o.At) {
		return true
	}
	if m.At.Before(o.At) {
		return false
	}
	return m.Seq > o.Seq
}

func (m marker) isZero() bool { return m.Seq == "" && m.At.IsZero() }

// roleMarker records the latest settle and latest debit markers for one
// (digest, role) natural key. The role is present when settle wins.
type roleMarker struct {
	Size   int64  `json:"size"`
	Settle marker `json:"settle"`
	Debit  marker `json:"debit,omitempty"`
}

func (rm roleMarker) present() bool {
	if rm.Settle.isZero() {
		return false
	}
	return rm.Settle.after(rm.Debit)
}

// digestState holds the per-role markers for one digest within a repository.
type digestState struct {
	Roles map[Role]*roleMarker `json:"roles"`
}

// reservationState tracks a reservation lifecycle. A reservation is active
// while its reserved marker is later than any close (release or settle)
// marker.
type reservationState struct {
	Size   int64         `json:"size"`
	Kind   Kind          `json:"kind,omitempty"`
	Digest digest.Digest `json:"digest,omitempty"`
	Hold   marker        `json:"hold"`
	Close  marker        `json:"close,omitempty"`
}

func (r *reservationState) active() bool {
	if r.Hold.isZero() {
		return false
	}
	return r.Hold.after(r.Close)
}

// snapshotFormat is the serializable representation of reduced state used for
// compaction snapshots. It is exported via State.Marshal and consumed by
// State.Unmarshal.
type snapshotFormat struct {
	Entries      map[digest.Digest]*digestState `json:"entries"`
	Reservations map[string]*reservationState   `json:"reservations"`
}

// Entry is a projected settled usage record for a digest.
type Entry struct {
	Digest digest.Digest
	Size   int64
	Roles  []Role
}

// ReservationView is a projected active reservation.
type ReservationView struct {
	ID     string
	Size   int64
	Kind   Kind
	Digest digest.Digest
	Since  time.Time
}

// State is the reduced ledger state for one repository.
type State struct {
	entries      map[digest.Digest]*digestState
	reservations map[string]*reservationState
}

// NewState returns an empty State.
func NewState() *State {
	return &State{
		entries:      map[digest.Digest]*digestState{},
		reservations: map[string]*reservationState{},
	}
}

// Apply folds one event into the state. Because each natural key uses
// last-writer-wins markers, Apply is independent of the order in which
// unrelated events are applied.
func (s *State) Apply(e Event) {
	switch e.Type {
	case EventReserved:
		r, ok := s.reservations[e.ID]
		if !ok {
			r = &reservationState{}
			s.reservations[e.ID] = r
		}
		hold := marker{At: e.At, Seq: e.Seq}
		if hold.after(r.Hold) {
			r.Hold = hold
			r.Size = e.Size
			r.Kind = e.Kind
			r.Digest = e.Digest
		}

	case EventReleased:
		r, ok := s.reservations[e.ReservationID]
		if !ok {
			// Compensating release for an unknown reservation: remember it
			// so a late-arriving/duplicate reserved event cannot revive it.
			r = &reservationState{}
			s.reservations[e.ReservationID] = r
		}
		close := marker{At: e.At, Seq: e.Seq}
		if close.after(r.Close) {
			r.Close = close
		}

	case EventSettled:
		dst, ok := s.entries[e.Digest]
		if !ok {
			dst = &digestState{Roles: map[Role]*roleMarker{}}
			s.entries[e.Digest] = dst
		}
		rm, ok := dst.Roles[e.Role]
		if !ok {
			rm = &roleMarker{}
			dst.Roles[e.Role] = rm
		}
		settle := marker{At: e.At, Seq: e.Seq}
		if settle.after(rm.Settle) {
			rm.Settle = settle
			rm.Size = e.Size
		}

		// settling closes its reservation (if any).
		if e.ReservationID != "" {
			r, ok := s.reservations[e.ReservationID]
			if !ok {
				r = &reservationState{}
				s.reservations[e.ReservationID] = r
			}
			close := marker{At: e.At, Seq: e.Seq}
			if close.after(r.Close) {
				r.Close = close
			}
		}

	case EventDebited:
		dst, ok := s.entries[e.Digest]
		if !ok {
			dst = &digestState{Roles: map[Role]*roleMarker{}}
			s.entries[e.Digest] = dst
		}
		rm, ok := dst.Roles[e.Role]
		if !ok {
			rm = &roleMarker{}
			dst.Roles[e.Role] = rm
		}
		debit := marker{At: e.At, Seq: e.Seq}
		if debit.after(rm.Debit) {
			rm.Debit = debit
		}
	}
}

// Reduce folds a list of events into a State. The input is processed in a
// deterministic (At, ID) order but the result does not depend on it.
func Reduce(events []Event) *State {
	sorted := make([]Event, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].At.Equal(sorted[j].At) {
			return sorted[i].At.Before(sorted[j].At)
		}
		return sorted[i].Seq < sorted[j].Seq
	})
	s := NewState()
	for _, e := range sorted {
		s.Apply(e)
	}
	return s
}

// Marshal serializes the reduced state for a compaction snapshot.
func (s *State) Marshal() ([]byte, error) {
	return json.Marshal(snapshotFormat{Entries: s.entries, Reservations: s.reservations})
}

// Unmarshal restores State from a snapshot; subsequent events can be applied
// on top.
func UnmarshalState(data []byte) (*State, error) {
	var f snapshotFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.Entries == nil {
		f.Entries = map[digest.Digest]*digestState{}
	}
	if f.Reservations == nil {
		f.Reservations = map[string]*reservationState{}
	}
	return &State{entries: f.Entries, reservations: f.Reservations}, nil
}

// Entries returns the currently settled entries (digest, size and present
// roles) in digest order for deterministic tests/output.
func (s *State) Entries() []Entry {
	out := make([]Entry, 0, len(s.entries))
	for dgst, dst := range s.entries {
		var (
			roles      []Role
			latestSett marker
			size       int64
		)
		for role, rm := range dst.Roles {
			if !rm.present() {
				continue
			}
			roles = append(roles, role)
			if rm.Settle.after(latestSett) {
				latestSett = rm.Settle
				size = rm.Size
			}
		}
		if len(roles) == 0 {
			continue
		}
		sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
		out = append(out, Entry{Digest: dgst, Size: size, Roles: roles})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out
}

// HasRole reports whether a digest currently has the given role present.
func (s *State) HasRole(dgst digest.Digest, role Role) bool {
	dst, ok := s.entries[dgst]
	if !ok {
		return false
	}
	rm, ok := dst.Roles[role]
	return ok && rm.present()
}

// ActiveReservations returns currently open reservations in ID order.
func (s *State) ActiveReservations() []ReservationView {
	out := make([]ReservationView, 0, len(s.reservations))
	for id, r := range s.reservations {
		if !r.active() {
			continue
		}
		out = append(out, ReservationView{
			ID:     id,
			Size:   r.Size,
			Kind:   r.Kind,
			Digest: r.Digest,
			Since:  r.Hold.At,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SettledBytes sums the size of every settled digest once, regardless of how
// many roles reference it.
func (s *State) SettledBytes() int64 {
	var total int64
	for _, e := range s.Entries() {
		total += e.Size
	}
	return total
}

// ReservedBytes sums the size of every active reservation.
func (s *State) ReservedBytes() int64 {
	var total int64
	for _, r := range s.reservations {
		if r.active() {
			total += r.Size
		}
	}
	return total
}
