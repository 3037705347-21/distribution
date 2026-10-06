package storage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/distribution/distribution/v3/internal/uuid"
	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/reference"
)

// CatalogDisplay holds tenant-maintained presentation information for a
// repository. It lives outside the repository tree, is never derived from
// storage scans, and is preserved across catalog rebuilds — including while
// the repository is temporarily absent.
type CatalogDisplay struct {
	// Title is a short human-readable name for the repository.
	Title string `json:"title,omitempty"`

	// Description is free-form supplementary text.
	Description string `json:"description,omitempty"`

	// Labels holds arbitrary tenant-defined key/value pairs.
	Labels map[string]string `json:"labels,omitempty"`

	// UpdatedAt records the last time the display information was written.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// catalogSnapshot is the serialized form of the catalog projection. A single
// immutable object is published atomically, so readers always observe either
// the previous complete snapshot or the next complete snapshot — never a mix.
type catalogSnapshot struct {
	// Version identifies the snapshot format.
	Version int `json:"version"`

	// GeneratedAt is when the snapshot was built.
	GeneratedAt time.Time `json:"generated_at"`

	// Repositories is the complete repository set in stable component-wise
	// order, with tenant-maintained display information merged in.
	Repositories []catalogSnapshotEntry `json:"repositories"`

	// names is the ordered projection of Repositories names, retained to
	// avoid rebuilding it on every paginated read. Not serialized.
	names []string
}

// catalogSnapshotEntry pairs a repository with its display information.
type catalogSnapshotEntry struct {
	Name    string          `json:"name"`
	Display *CatalogDisplay `json:"display,omitempty"`
}

const catalogSnapshotVersion = 1

// valid reports whether the snapshot is well-formed: the version is current
// and entries are non-empty, unique and sorted. Snapshot builds guarantee
// this; the check also guards against corrupted or partially written objects.
func (s *catalogSnapshot) valid() bool {
	if s.Version != catalogSnapshotVersion {
		return false
	}
	for i := range s.Repositories {
		name := s.Repositories[i].Name
		if name == "" {
			return false
		}
		if i > 0 && !lessPath(s.Repositories[i-1].Name, name) {
			return false
		}
	}
	return true
}

// Repositories fills repos with repository names from the published catalog
// snapshot, starting strictly after last, in stable component-wise order. All
// pages of one call sequence read the same immutable snapshot, so concurrent
// pushes or deletes cannot cause entries to be skipped or duplicated.
func (reg *registry) Repositories(ctx context.Context, repos []string, last string) (int, error) {
	if len(repos) == 0 {
		return 0, errors.New("attempted to list 0 repositories")
	}

	snap, err := reg.snapshotForRead(ctx)
	if err != nil {
		return 0, err
	}

	start := 0
	if last != "" {
		// first entry strictly greater than last
		start = sort.Search(len(snap.Repositories), func(i int) bool {
			return lessPath(last, snap.Repositories[i].Name)
		})
	}

	n := copy(repos, snap.names[start:])
	if start+n < len(snap.Repositories) {
		// There are potentially more repositories to list.
		return n, nil
	}
	return n, io.EOF
}

// Enumerate applies ingester to each repository in the published catalog
// snapshot, in stable order.
func (reg *registry) Enumerate(ctx context.Context, ingester func(string) error) error {
	snap, err := reg.snapshotForRead(ctx)
	if err != nil {
		return err
	}

	for _, entry := range snap.Repositories {
		if err := ingester(entry.Name); err != nil {
			return err
		}
	}
	return nil
}

// RefreshCatalog rebuilds the catalog snapshot from storage and publishes it
// atomically. The previous snapshot keeps serving readers until the new one
// is fully committed; any failure leaves the previous snapshot — and the
// on-disk published object — untouched.
func (reg *registry) RefreshCatalog(ctx context.Context) error {
	reg.catalogBuildMu.Lock()
	defer reg.catalogBuildMu.Unlock()

	snap, err := reg.buildSnapshot(ctx)
	if err != nil {
		return err
	}
	return reg.publishSnapshot(ctx, snap)
}

// CatalogDisplayInfo returns the tenant-maintained display information for
// the named repository, or nil if none has been set.
func (reg *registry) CatalogDisplayInfo(ctx context.Context, name reference.Named) (*CatalogDisplay, error) {
	annotationPath, err := pathFor(catalogAnnotationPathSpec{name: name.Name()})
	if err != nil {
		return nil, err
	}

	p, err := reg.driver.GetContent(ctx, annotationPath)
	if err != nil {
		if _, ok := err.(driver.PathNotFoundError); ok {
			return nil, nil
		}
		return nil, err
	}

	display := &CatalogDisplay{}
	if err := json.Unmarshal(p, display); err != nil {
		return nil, err
	}
	return display, nil
}

// UpdateCatalogDisplay stores tenant-maintained display information for a
// repository. The information is kept outside the repository tree and is
// preserved across catalog rebuilds and repository re-creations. Passing an
// empty CatalogDisplay removes any previously stored information. It appears
// in the catalog view with the next snapshot rebuild.
func (reg *registry) UpdateCatalogDisplay(ctx context.Context, name reference.Named, display CatalogDisplay) error {
	annotationPath, err := pathFor(catalogAnnotationPathSpec{name: name.Name()})
	if err != nil {
		return err
	}

	if display.Title == "" && display.Description == "" && len(display.Labels) == 0 {
		if err := reg.driver.Delete(ctx, annotationPath); err != nil {
			if _, ok := err.(driver.PathNotFoundError); ok {
				return nil
			}
			return err
		}
		return nil
	}

	display.UpdatedAt = time.Now().UTC()
	p, err := json.Marshal(&display)
	if err != nil {
		return err
	}
	return reg.driver.PutContent(ctx, annotationPath, p)
}

// Remove removes a repository from storage. The catalog snapshot converges to
// the removal on its next rebuild.
func (reg *registry) Remove(ctx context.Context, name reference.Named) error {
	root, err := pathFor(repositoriesRootPathSpec{})
	if err != nil {
		return err
	}
	repoDir := path.Join(root, name.Name())
	return reg.driver.Delete(ctx, repoDir)
}

// snapshotForRead returns the snapshot to serve, loading the published
// snapshot or building one on first use, and triggering a rebuild when the
// served snapshot is older than the configured refresh interval. A failed
// rebuild never takes down the view: the last known-good snapshot is served.
func (reg *registry) snapshotForRead(ctx context.Context) (*catalogSnapshot, error) {
	if snap := reg.catalogSnapshot.Load(); snap != nil {
		if reg.catalogRefreshInterval > 0 && time.Since(snap.GeneratedAt) > reg.catalogRefreshInterval {
			if err := reg.RefreshCatalog(ctx); err != nil {
				dcontext.GetLogger(ctx).WithError(err).Warn("catalog snapshot refresh failed; serving previous snapshot")
			} else {
				return reg.catalogSnapshot.Load(), nil
			}
		}
		return snap, nil
	}
	return reg.loadOrBuildSnapshot(ctx)
}

// loadOrBuildSnapshot loads the published snapshot, or builds and publishes
// one when no usable snapshot exists. Empty scans are served but not frozen:
// a fresh registry with no repositories must not pin an empty snapshot that
// would hide the first pushes.
func (reg *registry) loadOrBuildSnapshot(ctx context.Context) (*catalogSnapshot, error) {
	reg.catalogBuildMu.Lock()
	defer reg.catalogBuildMu.Unlock()

	if snap := reg.catalogSnapshot.Load(); snap != nil {
		return snap, nil
	}

	if snap, err := reg.readPublishedSnapshot(ctx); err == nil {
		reg.catalogSnapshot.Store(snap)
		return snap, nil
	}

	snap, err := reg.buildSnapshot(ctx)
	if err != nil {
		return nil, err
	}

	if len(snap.Repositories) == 0 {
		// Ephemeral empty view; do not publish it.
		return snap, nil
	}

	if err := reg.publishSnapshot(ctx, snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// readPublishedSnapshot reads and validates the on-disk published snapshot.
func (reg *registry) readPublishedSnapshot(ctx context.Context) (*catalogSnapshot, error) {
	currentPath, err := pathFor(catalogSnapshotPathSpec{})
	if err != nil {
		return nil, err
	}

	p, err := reg.driver.GetContent(ctx, currentPath)
	if err != nil {
		return nil, err
	}

	snap := &catalogSnapshot{}
	if err := json.Unmarshal(p, snap); err != nil {
		return nil, err
	}
	if !snap.valid() {
		return nil, errors.New("published catalog snapshot is invalid")
	}
	snap.names = make([]string, len(snap.Repositories))
	for i, entry := range snap.Repositories {
		snap.names[i] = entry.Name
	}
	return snap, nil
}

// buildSnapshot performs the full repository scan, merges tenant-maintained
// display information, and assembles the new snapshot. Nothing is published
// by this function, so an interrupted or failed scan cannot affect readers.
func (reg *registry) buildSnapshot(ctx context.Context) (*catalogSnapshot, error) {
	names, err := reg.scanRepositories(ctx)
	if err != nil {
		return nil, err
	}

	slices.SortFunc(names, func(a, b string) int {
		switch {
		case lessPath(a, b):
			return -1
		case lessPath(b, a):
			return 1
		default:
			return 0
		}
	})
	names = slices.Compact(names)

	annotations, err := reg.readAnnotations(ctx)
	if err != nil {
		return nil, err
	}

	entries := make([]catalogSnapshotEntry, len(names))
	for i, name := range names {
		entries[i] = catalogSnapshotEntry{Name: name}
		if display, ok := annotations[name]; ok {
			entries[i].Display = display
		}
	}

	return &catalogSnapshot{
		Version:      catalogSnapshotVersion,
		GeneratedAt:  time.Now().UTC(),
		Repositories: entries,
		names:        names,
	}, nil
}

// publishSnapshot serializes snap to a unique staging object and atomically
// moves it over the published path. Only a fully written staging object is
// ever moved; on any failure the staging object is removed and the previously
// published snapshot remains intact.
func (reg *registry) publishSnapshot(ctx context.Context, snap *catalogSnapshot) error {
	if !snap.valid() {
		return errors.New("refusing to publish invalid catalog snapshot")
	}

	payload, err := json.Marshal(snap)
	if err != nil {
		return err
	}

	stagingDir, err := pathFor(catalogStagingDirPathSpec{})
	if err != nil {
		return err
	}
	stagingPath, err := pathFor(catalogStagingPathSpec{id: uuid.NewString()})
	if err != nil {
		return err
	}
	currentPath, err := pathFor(catalogSnapshotPathSpec{})
	if err != nil {
		return err
	}

	// Remove staging objects left behind by interrupted builds. Staging is
	// never read, so this cannot affect any published view. Drivers disagree
	// on whether List returns bare names or full paths; handle both.
	if remnants, err := reg.driver.List(ctx, stagingDir); err == nil {
		for _, remnant := range remnants {
			remnantPath := remnant
			if !path.IsAbs(remnantPath) {
				remnantPath = path.Join(stagingDir, remnantPath)
			}
			_ = reg.driver.Delete(ctx, remnantPath)
		}
	}

	published := false
	defer func() {
		if !published {
			// Best-effort cleanup of our own staging object. The published
			// path is deliberately never touched here.
			_ = reg.driver.Delete(ctx, stagingPath)
		}
	}()

	if err := reg.driver.PutContent(ctx, stagingPath, payload); err != nil {
		return err
	}

	if err := reg.driver.Move(ctx, stagingPath, currentPath); err != nil {
		return err
	}

	published = true
	reg.catalogSnapshot.Store(snap)
	return nil
}

// scanRepositories walks the repositories tree once and returns the complete
// set of repository names at the time of the walk. A missing repositories
// root means an empty registry, not a storage failure.
func (reg *registry) scanRepositories(ctx context.Context) ([]string, error) {
	root, err := pathFor(repositoriesRootPathSpec{})
	if err != nil {
		return nil, err
	}

	var names []string
	err = reg.driver.Walk(ctx, root, func(fileInfo driver.FileInfo) error {
		return handleRepository(fileInfo, root, "", func(repoPath string) error {
			names = append(names, repoPath)
			return nil
		})
	})
	if err != nil {
		if _, ok := err.(driver.PathNotFoundError); ok {
			return nil, nil
		}
		return nil, err
	}
	return names, nil
}

// readAnnotations reads all tenant-maintained display information. A missing
// annotations directory means no display information has ever been set.
// Annotation files are never deleted here.
func (reg *registry) readAnnotations(ctx context.Context) (map[string]*CatalogDisplay, error) {
	dir, err := pathFor(catalogAnnotationsDirPathSpec{})
	if err != nil {
		return nil, err
	}

	annotations := make(map[string]*CatalogDisplay)
	err = reg.driver.Walk(ctx, dir, func(fi driver.FileInfo) error {
		if fi.IsDir() {
			return nil
		}
		filePath := fi.Path()
		if !strings.HasSuffix(filePath, catalogAnnotationSuffix) {
			return nil
		}

		content, err := reg.driver.GetContent(ctx, filePath)
		if err != nil {
			return err
		}
		display := &CatalogDisplay{}
		if err := json.Unmarshal(content, display); err != nil {
			return err
		}

		name := strings.TrimSuffix(strings.TrimPrefix(filePath, dir+"/"), catalogAnnotationSuffix)
		annotations[name] = display
		return nil
	})
	if err != nil {
		if _, ok := err.(driver.PathNotFoundError); ok {
			return annotations, nil
		}
		return nil, err
	}
	return annotations, nil
}

// lessPath returns true if one path a is less than path b.
//
// A component-wise comparison is done, rather than the lexical comparison of
// strings.
func lessPath(a, b string) bool {
	// we provide this behavior by making separator always sort first.
	return compareReplaceInline(a, b, '/', '\x00') < 0
}

// compareReplaceInline modifies runtime.cmpstring to replace old with new
// during a byte-wise comparison.
func compareReplaceInline(s1, s2 string, old, new byte) int {
	// TODO(stevvooe): We are missing an optimization when the s1 and s2 have
	// exact same slice header. It will make the code unsafe but can
	// provide some extra performance.

	l := min(len(s2), len(s1))

	for i := range l {
		c1, c2 := s1[i], s2[i]
		if c1 == old {
			c1 = new
		}

		if c2 == old {
			c2 = new
		}

		if c1 < c2 {
			return -1
		}

		if c1 > c2 {
			return +1
		}
	}

	if len(s1) < len(s2) {
		return -1
	}

	if len(s1) > len(s2) {
		return +1
	}

	return 0
}

// handleRepository calls function fn with a repository path if fileInfo
// has a path of a repository under root and that it is lexographically
// after last. Otherwise, it will return ErrSkipDir or ErrFilledBuffer.
// These should be used with Walk to do handling with repositories in a
// storage.
func handleRepository(fileInfo driver.FileInfo, root, last string, fn func(repoPath string) error) error {
	filePath := fileInfo.Path()

	// lop the base path off
	repo := filePath[len(root)+1:]

	_, file := path.Split(repo)
	if file == "_manifests" {
		repo = strings.TrimSuffix(repo, "/_manifests")
		if repo != last {
			if err := fn(repo); err != nil {
				return err
			}
		}
		return driver.ErrSkipDir
	} else if strings.HasPrefix(file, "_") {
		return driver.ErrSkipDir
	}

	return nil
}
