package accounting

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/distribution/distribution/v3/registry/storage/driver"
)

// defaultRoot is the ledger root, a sibling of the registry "blobs" and
// "repositories" trees under the v2 storage prefix.
const defaultRoot = "/docker/registry/v2/accounting"

var pathComponentRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// paths maps repository ledger objects onto driver paths:
//
//	<root>/repositories/<repository path components>
//	  ├── events/<event-id>          immutable event objects
//	  └── snapshots/<event-id>       immutable state snapshots
//
// All generated paths satisfy driver.PathRegexp.
type paths struct {
	root string
}

func newPaths(root string) (*paths, error) {
	if root == "" {
		root = defaultRoot
	}
	if !driver.PathRegexp.MatchString(root) {
		return nil, fmt.Errorf("accounting: ledger root %q does not match driver path rules", root)
	}
	return &paths{root: root}, nil
}

func (p *paths) repoDir(repo string) (string, error) {
	components := strings.Split(repo, "/")
	parts := []string{p.root, "repositories"}
	for _, c := range components {
		if !pathComponentRE.MatchString(c) {
			return "", fmt.Errorf("accounting: invalid repository path component %q in %q", c, repo)
		}
		parts = append(parts, c)
	}
	return path.Join(parts...), nil
}

func (p *paths) eventsDir(repo string) (string, error) {
	dir, err := p.repoDir(repo)
	if err != nil {
		return "", err
	}
	return path.Join(dir, "events"), nil
}

func (p *paths) eventObject(repo, id string) (string, error) {
	dir, err := p.eventsDir(repo)
	if err != nil {
		return "", err
	}
	return path.Join(dir, id), nil
}

func (p *paths) snapshotsDir(repo string) (string, error) {
	dir, err := p.repoDir(repo)
	if err != nil {
		return "", err
	}
	return path.Join(dir, "snapshots"), nil
}

func (p *paths) snapshotObject(repo, id string) (string, error) {
	dir, err := p.snapshotsDir(repo)
	if err != nil {
		return "", err
	}
	return path.Join(dir, id), nil
}
