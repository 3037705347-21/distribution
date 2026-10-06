package revocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// Loader keeps the current revocation Snapshot fresh by polling a Source.
// Reads are lock-free through an atomic pointer; refreshes replace the
// whole snapshot atomically so that every request observes either the
// previous or the new complete state, never a partial merge.
type Loader struct {
	source Source

	current atomic.Pointer[Snapshot]

	// mu guards lastSum. The active snapshot itself is always read
	// through current and needs no lock.
	mu      sync.Mutex
	lastSum string

	cancel context.CancelFunc
	done   chan struct{}
}

// New validates the config, performs the initial synchronous load and
// starts the background polling loop. The initial load must succeed: when
// configured, a registry that cannot obtain its revocation list refuses to
// start instead of running without revocations enforced.
func New(ctx context.Context, config Config) (*Loader, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	var source Source
	if config.Path != "" {
		source = newFileSource(config.Path)
	} else {
		source = newHTTPSource(config.URL, config.Timeout)
	}

	loader := &Loader{
		source: source,
		done:   make(chan struct{}),
	}

	// Initial load is synchronous and failure-closed; no poller is
	// started unless the first snapshot was installed.
	if err := loader.Reload(ctx); err != nil {
		return nil, err
	}

	loadCtx, cancel := context.WithCancel(ctx)
	loader.cancel = cancel
	go loader.run(loadCtx, config.Interval)

	return loader, nil
}

// Current returns the active, immutable snapshot. It is safe for
// concurrent use and never returns nil for a successfully constructed
// Loader.
func (l *Loader) Current() *Snapshot {
	return l.current.Load()
}

// Reload fetches the document and, when it changed, parses and atomically
// installs the new snapshot. Fetch errors and invalid documents leave the
// previous snapshot in effect (last-known-good behavior); conditional
// request validators are committed only after the document is accepted so
// a rejected document is fetched and retried again next time.
func (l *Loader) Reload(ctx context.Context) error {
	data, commit, err := l.source.Fetch(ctx)
	if errors.Is(err, errNotModified) {
		return nil
	}
	if err != nil {
		logrus.Warnf("failed to refresh token revocation list from %s: %v", l.source, err)
		return err
	}

	sum := checksum(data)

	l.mu.Lock()
	unchanged := sum == l.lastSum
	l.mu.Unlock()
	if unchanged {
		// Still activate any refreshed validators.
		if commit != nil {
			commit()
		}
		return nil
	}

	snapshot, err := Parse(data)
	if err != nil {
		logrus.Warnf("keeping previous token revocation list, rejecting update from %s: %v", l.source, err)
		return err
	}

	// Publish the checksum and the pointer back-to-back under the same
	// lock; readers only observe current, which is itself atomic.
	l.mu.Lock()
	l.lastSum = sum
	l.current.Store(snapshot)
	l.mu.Unlock()

	if commit != nil {
		commit()
	}

	logrus.Infof("token revocation list refreshed from %s with %d bytes", l.source, len(data))
	return nil
}

// Close stops the background polling loop and waits for it to exit.
func (l *Loader) Close() error {
	if l.cancel == nil {
		return nil
	}
	l.cancel()
	<-l.done
	return nil
}

func (l *Loader) run(ctx context.Context, interval time.Duration) {
	defer close(l.done)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			func() {
				// A panic in refresh handling must never crash the
				// registry process; the last good snapshot stays put.
				defer func() {
					if recovered := recover(); recovered != nil {
						logrus.Errorf("panic while refreshing token revocation list from %s: %v", l.source, recovered)
					}
				}()
				_ = l.Reload(ctx)
			}()
		}
	}
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
