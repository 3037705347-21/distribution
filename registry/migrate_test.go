package registry_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/distribution/distribution/v3/registry"
	_ "github.com/distribution/distribution/v3/registry/storage/driver/filesystem"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// writeFSConfig writes a minimal registry config using the filesystem driver.
func writeFSConfig(t *testing.T, path, root string) {
	t.Helper()
	content := "version: 0.1\nstorage:\n  filesystem:\n    rootdirectory: " + root + "\n    maxthreads: 16\n"
	require.NoError(t, os.WriteFile(filepath.Join(path, "config.yml"), []byte(content), 0o644))
}

func writeBogusConfig(t *testing.T, path string) {
	content := "version: 0.1\nstorage:\n  does-not-exist:\n    whatever: true\n"
	require.NoError(t, os.WriteFile(filepath.Join(path, "bogus.yml"), []byte(content), 0o644))
}

// seedSourceLayout writes one blob plus layer/manifest/tag links directly into
// a filesystem-backed registry root, using the documented v2 layout.
func seedSourceLayout(t *testing.T, root string) (repo string, d digest.Digest) {
	t.Helper()
	repo = "demo"
	content := "cli-e2e-blob-content"
	d = digest.FromString(content)
	put := func(rel, body string) {
		p := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	put(filepath.Join("docker/registry/v2/blobs", d.Algorithm().String(), d.Encoded()[:2], d.Encoded(), "data"), content)
	put(filepath.Join("docker/registry/v2/repositories", repo, "_layers", d.Algorithm().String(), d.Encoded(), "link"), d.String())
	put(filepath.Join("docker/registry/v2/repositories", repo, "_manifests/revisions", d.Algorithm().String(), d.Encoded(), "link"), d.String())
	put(filepath.Join("docker/registry/v2/repositories", repo, "_manifests/tags/v1/current/link"), d.String())
	put(filepath.Join("docker/registry/v2/repositories", repo, "_manifests/tags/v1/index", d.Algorithm().String(), d.Encoded(), "link"), d.String())
	return repo, d
}

func execMigrate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// Repeated Execute calls on the same cobra Command reuse FlagSets, and a
	// previously parsed --help bool would otherwise stick (making every later
	// invocation print help). Reset the builtin help flags like a fresh CLI
	// process would.
	var resetHelp func(c *cobra.Command)
	resetHelp = func(c *cobra.Command) {
		if f := c.Flags().Lookup("help"); f != nil && f.Changed {
			_ = f.Value.Set("false")
			f.Changed = false
		}
		for _, ch := range c.Commands() {
			resetHelp(ch)
		}
	}
	resetHelp(registry.RootCmd)

	buf := &bytes.Buffer{}
	registry.RootCmd.SetOut(buf)
	registry.RootCmd.SetErr(buf)
	registry.RootCmd.SetArgs(args)
	err := registry.RootCmd.Execute()
	return buf.String(), err
}

// ---- TR-7.1: help ------------------------------------------------------------

func TestMigrateHelp(t *testing.T) {
	out, err := execMigrate(t, "migrate", "--help")
	require.NoError(t, err)
	for _, want := range []string{"run", "status", "verify", "cutover", "--source", "--target", "--repo"} {
		require.Contains(t, out, want)
	}
	out, err = execMigrate(t, "migrate", "run", "--help")
	require.NoError(t, err)
	require.Contains(t, out, "--batch-size")
}

// ---- TR-7.2: clear errors ----------------------------------------------------

func TestMigrateFlagErrors(t *testing.T) {
	_, err := execMigrate(t, "migrate", "run")
	require.Error(t, err)
	require.Contains(t, err.Error(), "--source")

	cfgDir := t.TempDir()
	srcDir := t.TempDir()
	writeFSConfig(t, cfgDir, srcDir)
	_, err = execMigrate(t, "migrate", "run", "--source", filepath.Join(cfgDir, "config.yml"), "--target", filepath.Join(cfgDir, "missing.yml"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "load")

	writeBogusConfig(t, cfgDir)
	_, err = execMigrate(t, "migrate", "run", "--source", filepath.Join(cfgDir, "bogus.yml"), "--target", filepath.Join(cfgDir, "config.yml"))
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "driver")
}

// ---- TR-7.3: end-to-end through the cobra command ----------------------------

func TestMigrateCLIFullLifecycle(t *testing.T) {
	cfgDir := t.TempDir()
	srcRoot := t.TempDir()
	dstRoot := t.TempDir()
	writeFSConfig(t, cfgDir, srcRoot)

	// Two config files (one per backend).
	srcCfg := filepath.Join(cfgDir, "src.yml")
	dstCfg := filepath.Join(cfgDir, "dst.yml")
	base, err := os.ReadFile(filepath.Join(cfgDir, "config.yml"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(srcCfg, base, 0o644))
	dstConfig := strings.Replace(string(base), srcRoot, dstRoot, 1)
	require.NoError(t, os.WriteFile(dstCfg, []byte(dstConfig), 0o644))

	repo, d := seedSourceLayout(t, srcRoot)

	out, err := execMigrate(t, "migrate", "run", "--source", srcCfg, "--target", dstCfg, "--lock-ttl", "5s")
	require.NoError(t, err, out)
	require.Contains(t, out, "Converged: YES", out)

	out, err = execMigrate(t, "migrate", "status", "--target", dstCfg)
	require.NoError(t, err)
	require.Contains(t, out, "Converged: YES")

	out, err = execMigrate(t, "migrate", "verify", "--source", srcCfg, "--target", dstCfg)
	require.NoError(t, err)
	require.Contains(t, out, "Verification PASSED")

	out, err = execMigrate(t, "migrate", "cutover", "--source", srcCfg, "--target", dstCfg)
	require.NoError(t, err)
	require.Contains(t, out, "CUTOVER MARKER WRITTEN")

	// The migrated layout exists under the destination root.
	dataPath := filepath.Join(dstRoot, "docker/registry/v2/blobs", d.Algorithm().String(), d.Encoded()[:2], d.Encoded(), "data")
	b, err := os.ReadFile(dataPath)
	require.NoError(t, err)
	require.Equal(t, "cli-e2e-blob-content", string(b))

	tagPath := filepath.Join(dstRoot, "docker/registry/v2/repositories", repo, "_manifests/tags/v1/current/link")
	tb, err := os.ReadFile(tagPath)
	require.NoError(t, err)
	require.Equal(t, d.String(), string(tb))

	// The source layout is untouched: same file set/content as seeded.
	srcData, err := os.ReadFile(filepath.Join(srcRoot, "docker/registry/v2/blobs", d.Algorithm().String(), d.Encoded()[:2], d.Encoded(), "data"))
	require.NoError(t, err)
	require.Equal(t, "cli-e2e-blob-content", string(srcData))
}
