package cli

import (
	"os"
	"path/filepath"
	"testing"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

// The hardcoded ~/.config/incus this replaced is the wrong path on macOS,
// where `incus` keeps its config under os.UserConfigDir() — admin-remote
// detection died on its first step there and every admin command silently
// fell through to the ambient global default remote, which can be a different
// deployment entirely.
func TestGlobalIncusDirPrefersIncusConf(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("INCUS_CONF", dir)
	if got := globalIncusDir(); got != dir {
		t.Fatalf("globalIncusDir() = %q, want INCUS_CONF %q", got, dir)
	}
}

func TestGlobalIncusDirFallsBackToPlatformDir(t *testing.T) {
	t.Setenv("INCUS_CONF", "")
	got := globalIncusDir()
	if platform := scconfig.PlatformIncusDir(); platform != "" {
		if got != platform {
			t.Fatalf("globalIncusDir() = %q, want platform dir %q", got, platform)
		}
		return
	}
	// No platform config on this machine: the SDK's own default is the last
	// resort, never an empty path (which would resolve to "servercerts").
	if got != scconfig.NativeIncusDir() {
		t.Fatalf("globalIncusDir() = %q, want native dir %q", got, scconfig.NativeIncusDir())
	}
	if filepath.Base(got) == "" || !filepath.IsAbs(got) {
		t.Fatalf("globalIncusDir() = %q, want an absolute path", got)
	}
	_ = os.Getenv("INCUS_CONF")
}
