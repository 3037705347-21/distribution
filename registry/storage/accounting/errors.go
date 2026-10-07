package accounting

import "fmt"

// Phase identifies the request phase whose quota check failed, for metrics
// and error details.
type Phase string

const (
	PhaseUpload   Phase = "upload"
	PhaseMount    Phase = "mount"
	PhaseManifest Phase = "manifest"
)

// ErrQuotaExceeded is returned when an operation cannot fit within the
// repository budget. It is raised before any irreversible write takes
// place. Callers map it onto the registry QUOTA_EXCEEDED API error (HTTP
// 507).
type ErrQuotaExceeded struct {
	Repository string
	Phase      Phase
	Limit      int64 // -1 when unlimited (not expected on this error path)
	Settled    int64
	Reserved   int64
	Requested  int64
}

func (e *ErrQuotaExceeded) Error() string {
	return fmt.Sprintf("accounting: repository %q quota exceeded: budget %d, settled %d, reserved %d, requested %d (phase %s)",
		e.Repository, e.Limit, e.Settled, e.Reserved, e.Requested, e.Phase)
}

// ErrReservationUnknown is returned when an operation references a
// reservation that no longer exists (e.g. swept after a crash).
type ErrReservationUnknown struct {
	Repository string
	ID         string
}

func (e *ErrReservationUnknown) Error() string {
	return fmt.Sprintf("accounting: reservation %q for repository %q not found", e.ID, e.Repository)
}
