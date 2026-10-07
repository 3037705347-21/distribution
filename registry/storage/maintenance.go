package storage

import (
	"context"
	"errors"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/accounting"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
)

// expectedLedgerKeys computes the physical reference set of a repository:
// every manifest revision link and every layer/blob link, with descriptor
// sizes obtained from the statters.
func (repo *repository) expectedLedgerKeys(ctx context.Context) ([]accounting.ExpectedKey, error) {
	var keys []accounting.ExpectedKey

	manifests, err := repo.Manifests(ctx)
	if err != nil {
		return nil, err
	}
	ms, ok := manifests.(*manifestStore)
	if !ok {
		return keys, nil
	}
	if err := ms.blobStore.Enumerate(ctx, func(dgst digest.Digest) error {
		desc, err := ms.blobStore.Stat(ctx, dgst)
		if err != nil {
			logrus.WithError(err).WithField("digest", dgst).
				Warn("accounting: cannot stat revision during reconciliation")
			return nil
		}
		keys = append(keys, accounting.ExpectedKey{Digest: dgst, Role: accounting.RoleRevision, Size: desc.Size})
		return nil
	}); err != nil {
		if !errorsIsPathNotFound(err) {
			return nil, err
		}
	}

	blobs := repo.Blobs(ctx)
	layerLBS, ok := blobs.(*linkedBlobStore)
	if !ok {
		return keys, nil
	}
	if err := layerLBS.Enumerate(ctx, func(dgst digest.Digest) error {
		desc, err := layerLBS.Stat(ctx, dgst)
		if err != nil {
			logrus.WithError(err).WithField("digest", dgst).
				Warn("accounting: cannot stat layer link during reconciliation")
			return nil
		}
		keys = append(keys, accounting.ExpectedKey{Digest: dgst, Role: accounting.RoleLayer, Size: desc.Size})
		return nil
	}); err != nil {
		if !errorsIsPathNotFound(err) {
			return nil, err
		}
	}

	return keys, nil
}

// liveUploadIDs returns the set of upload session directories currently
// present for the repository.
func (repo *repository) liveUploadIDs(ctx context.Context) (map[string]bool, error) {
	live := map[string]bool{}
	startedAt, err := pathFor(uploadStartedAtPathSpec{name: repo.Named().Name(), id: ""})
	if err != nil {
		return nil, err
	}
	uploadsRoot := path.Dir(startedAt)
	entries, err := repo.registry.driver.List(ctx, uploadsRoot)
	if err != nil {
		var pnf driver.PathNotFoundError
		if err == pnf || errorsIsPathNotFound(err) {
			return live, nil
		}
		return nil, err
	}
	for _, e := range entries {
		live[path.Base(e)] = true
	}
	return live, nil
}

func errorsIsPathNotFound(err error) bool {
	var pnf driver.PathNotFoundError
	return errors.As(err, &pnf)
}

// reconcileAccounting repairs the repository ledger against its physical
// links and sweeps stale reservations.
func (repo *repository) reconcileAccounting(ctx context.Context, svc *accounting.Service) error {
	name := repo.Named().Name()

	keys, err := repo.expectedLedgerKeys(ctx)
	if err != nil {
		return err
	}
	if err := svc.Correct(ctx, name, keys); err != nil {
		return err
	}

	live, err := repo.liveUploadIDs(ctx)
	if err != nil {
		return err
	}
	cutoff := time.Now().UTC().Add(-svc.ReservationTTL())
	released, err := svc.ExpireReservations(ctx, name, cutoff, live)
	if err != nil {
		return err
	}
	if released > 0 {
		logrus.WithField("repository", name).
			Infof("accounting: released %d stale reservations", released)
	}
	return nil
}

// enumerateReconcileRepositories lists repositories that physically contain
// manifest revision links or layer links. Unlike the catalog this includes
// mount-only repositories that never received a manifest.
func (reg *registry) enumerateReconcileRepositories(ctx context.Context) ([]string, error) {
	root, err := pathFor(repositoriesRootPathSpec{})
	if err != nil {
		return nil, err
	}
	names := map[string]struct{}{}
	err = reg.driver.Walk(ctx, root, func(fi driver.FileInfo) error {
		p := fi.Path()
		base := path.Base(p)
		if base != "_manifests" && base != "_layers" {
			return nil
		}
		rel := strings.TrimPrefix(p, root+"/")
		if strings.HasSuffix(rel, "/"+base) {
			names[strings.TrimSuffix(rel, "/"+base)] = struct{}{}
		}
		return driver.ErrSkipDir
	})
	if err != nil {
		var pnf driver.PathNotFoundError
		if errors.As(err, &pnf) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// ReconcileAccounting runs reconciliation across every repository.
// Per-repository errors are logged and do not abort the sweep.
func (reg *registry) ReconcileAccounting(ctx context.Context) error {
	if reg.accounting == nil {
		return nil
	}
	names, err := reg.enumerateReconcileRepositories(ctx)
	if err != nil {
		return err
	}
	for _, name := range names {
		named, err := reference.WithName(name)
		if err != nil {
			logrus.WithError(err).WithField("repository", name).
				Warn("accounting: skipping repository with invalid name")
			continue
		}
		repo, err := reg.Repository(ctx, named)
		if err != nil {
			logrus.WithError(err).WithField("repository", name).
				Warn("accounting: cannot construct repository for reconciliation")
			continue
		}
		if err := repo.(*repository).reconcileAccounting(ctx, reg.accounting); err != nil {
			logrus.WithError(err).WithField("repository", name).
				Warn("accounting: repository reconciliation failed")
		}
	}
	return nil
}

// RunAccountingMaintenance runs an immediate reconciliation when onStart is
// set, then repeats on every interval tick until ctx is canceled. The
// returned channel is closed when the loop exits.
func (reg *registry) RunAccountingMaintenance(ctx context.Context, onStart bool, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	run := func(stage string) {
		if err := reg.ReconcileAccounting(ctx); err != nil {
			logrus.WithError(err).Warnf("accounting: %s reconciliation failed", stage)
		}
	}
	go func() {
		defer close(done)
		if onStart {
			run("startup")
		}
		if interval <= 0 {
			return
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				run("periodic")
			case <-ctx.Done():
				return
			}
		}
	}()
	return done
}
