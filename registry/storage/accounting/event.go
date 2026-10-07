package accounting

import (
	"time"

	"github.com/opencontainers/go-digest"
)

// EventType discriminates ledger event kinds.
type EventType string

const (
	// EventReserved marks bytes reserved before a real write (push upload,
	// cross-repository mount or inline manifest/blob put). Its event ID is
	// also the reservation ID referenced by later lifecycle events.
	EventReserved EventType = "reserved"

	// EventReleased cancels a reservation (client cancel, failed commit or
	// quota denial after reservation).
	EventReleased EventType = "released"

	// EventSettled converts a reservation into settled usage for a
	// (repository, digest, role) natural key.
	EventSettled EventType = "settled"

	// EventDebited removes a role from a (repository, digest) settled entry
	// after the corresponding link or revision is deleted.
	EventDebited EventType = "debited"
)

// Kind classifies a reservation by its originating operation.
type Kind string

const (
	KindUpload Kind = "upload"
	KindMount  Kind = "mount"
	KindInline Kind = "inline"
)

// Role is the way a digest is referenced by a repository: a layer/blob link
// or a manifest revision link.
type Role string

const (
	RoleLayer    Role = "layer"
	RoleRevision Role = "revision"
)

// Event is one immutable ledger record. Events are written once to unique
// storage keys and never modified.
type Event struct {
	// ID is the globally unique identifier of this event record. For
	// reserved events it is identical to ReservationID.
	ID string `json:"id"`

	// Seq is the storage-assigned, time-sortable ordering key of the event
	// object. It participates in last-writer-wins tie-breaking together with
	// At. Event ID identifies the operation; Seq identifies the record.
	Seq string `json:"seq,omitempty"`

	// Type is the event discriminator.
	Type EventType `json:"type"`

	// Repo is the repository whose ledger this event belongs to.
	Repo string `json:"repo"`

	// At is the event creation time and participates (together with ID) in
	// the deterministic last-writer-wins ordering.
	At time.Time `json:"at"`

	// Size is the reserved or settled byte count.
	Size int64 `json:"size,omitempty"`

	// Kind classifies a reservation. Used by reserved events.
	Kind Kind `json:"kind,omitempty"`

	// Digest is the target blob digest. Used by reserved (optional) and
	// settled/debited events.
	Digest digest.Digest `json:"digest,omitempty"`

	// Role is the natural-key role of a settled or debited entry.
	Role Role `json:"role,omitempty"`

	// ReservationID links released/settled events back to their reserved
	// event.
	ReservationID string `json:"reservation_id,omitempty"`
}

// Reserved constructs a reserved event.
func Reserved(id, repo string, size int64, kind Kind, dgst digest.Digest, at time.Time) Event {
	return Event{
		ID:            id,
		Seq:           id,
		Type:          EventReserved,
		Repo:          repo,
		At:            at,
		Size:          size,
		Kind:          kind,
		Digest:        dgst,
		ReservationID: id,
	}
}

// Released constructs a released event for a reservation.
func Released(id, reservationID, repo string, at time.Time) Event {
	return Event{
		ID:            id,
		Seq:           id,
		Type:          EventReleased,
		Repo:          repo,
		At:            at,
		ReservationID: reservationID,
	}
}

// Settled constructs a settled event converting a reservation into usage for
// a (digest, role) natural key.
func Settled(id, reservationID, repo string, dgst digest.Digest, role Role, size int64, at time.Time) Event {
	return Event{
		ID:            id,
		Seq:           id,
		Type:          EventSettled,
		Repo:          repo,
		At:            at,
		Size:          size,
		Digest:        dgst,
		Role:          role,
		ReservationID: reservationID,
	}
}

// SettledReconcile constructs a settled event without an originating
// reservation; it is used by reconciliation to seed or repair ledger state.
func SettledReconcile(id, repo string, dgst digest.Digest, role Role, size int64, at time.Time) Event {
	return Settled(id, "", repo, dgst, role, size, at)
}

// Debited constructs a debited event for a (digest, role) natural key.
func Debited(id, repo string, dgst digest.Digest, role Role, at time.Time) Event {
	return Event{
		ID:     id,
		Seq:    id,
		Type:   EventDebited,
		Repo:   repo,
		At:     at,
		Digest: dgst,
		Role:   role,
	}
}
