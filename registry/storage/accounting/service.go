package accounting

import (
	"time"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
)

// DefaultReservationTTL is used when no TTL is configured.
const DefaultReservationTTL = 24 * time.Hour

// RuntimeConfig carries accounting behavior toggles that are independent of
// the ledger storage itself.
type RuntimeConfig struct {
	// ReleaseOnUntag makes tag deletion immediately release unreachable
	// revisions and blobs of the repository.
	ReleaseOnUntag bool

	// ReservationTTL is the age after which abandoned reservations may be
	// swept.
	ReservationTTL time.Duration
}

// Service is the entry point used by the storage layer. It embeds Store and
// exposes the resolved budgets and runtime toggles.
type Service struct {
	*Store

	budgets *Budgets
	cfg     RuntimeConfig
}

// NewService creates the accounting Service. The process-wide Prometheus
// sink is attached by default; metrics registration is therefore a
// singleton regardless of how many services are constructed (e.g. tests).
func NewService(driver storagedriver.StorageDriver, budgets *Budgets, cfg RuntimeConfig, opts ...Option) (*Service, error) {
	storeOpts := append([]Option{WithSink(defaultSink)}, opts...)
	store, err := New(driver, budgets, storeOpts...)
	if err != nil {
		return nil, err
	}
	if cfg.ReservationTTL <= 0 {
		cfg.ReservationTTL = DefaultReservationTTL
	}
	return &Service{Store: store, budgets: budgets, cfg: cfg}, nil
}

// Budgets returns the resolved budget table.
func (s *Service) Budgets() *Budgets { return s.budgets }

// ReleaseOnUntag reports whether deleting a tag releases unreachable usage.
func (s *Service) ReleaseOnUntag() bool { return s.cfg.ReleaseOnUntag }

// ReservationTTL returns the abandoned reservation TTL.
func (s *Service) ReservationTTL() time.Duration { return s.cfg.ReservationTTL }
