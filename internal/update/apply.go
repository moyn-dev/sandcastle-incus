package update

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BrewBinDir returns Homebrew's bin directory (`brew --prefix` + /bin) or ""
// when brew is not on PATH — which, matching gh and flyctl, means "not a
// Homebrew install".
func BrewBinDir() string {
	brewExe, err := exec.LookPath("brew")
	if err != nil {
		return ""
	}
	out, err := exec.Command(brewExe, "--prefix").Output()
	if err != nil {
		return ""
	}
	prefix := strings.TrimSpace(string(out))
	if prefix == "" {
		return ""
	}
	return prefix
}

// UnderBrewPrefix reports whether the *unresolved* executable path lives in
// Homebrew's bin dir. The unresolved path must be used: the cask's `sc` and
// `sandcastle` names are symlinks in <prefix>/bin pointing into the
// Caskroom, and only the symlink location is stable across brew upgrades.
func UnderBrewPrefix(exePath, brewPrefix string) bool {
	if brewPrefix == "" {
		return false
	}
	binDir := filepath.Join(brewPrefix, "bin") + string(filepath.Separator)
	return strings.HasPrefix(exePath, binDir)
}

// IsBrewManaged reports whether the running binary is Homebrew-managed.
// Brew-managed installs must never be self-replaced — the next `brew
// upgrade` would silently downgrade the mutated Caskroom copy.
//
// Primary check: the unresolved executable path under `brew --prefix`/bin
// (gh/flyctl pattern). os.Executable() is only unresolved on macOS — on
// Linux it reads /proc/self/exe, which is already symlink-resolved and
// would point into the Cellar/Caskroom — so a layout-based complement
// catches resolved paths too.
func IsBrewManaged() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if UnderBrewPrefix(exe, BrewBinDir()) {
		return true
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return false
	}
	sep := string(filepath.Separator)
	return strings.Contains(resolved, sep+"Caskroom"+sep) || strings.Contains(resolved, sep+"Cellar"+sep)
}

// Apply atomically replaces the binary at targetPath (typically the
// unresolved os.Executable()) with newBinary. Symlinks are resolved first so
// the busybox layout survives: `sc` stays a symlink and the real file it
// points at is replaced. The previous binary is kept as <real>.bak for
// manual rollback. Replacement is write-new + rename (never overwrite in
// place), so a running process keeps its old inode and macOS never kills a
// process over mutated executable pages.
//
// It returns the path the new binary now lives at. Run the new binary from
// there, not from a fresh os.Executable(): on Linux that reads /proc/self/exe,
// which follows the running (old) inode to <real>.bak after the swap.
func Apply(targetPath string, newBinary []byte) (string, error) {
	real, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", targetPath, err)
	}
	newPath := real + ".new"
	bakPath := real + ".bak"

	if err := os.WriteFile(newPath, newBinary, 0o755); err != nil {
		return "", fmt.Errorf("stage new binary: %w", err)
	}
	if err := os.Remove(bakPath); err != nil && !os.IsNotExist(err) {
		os.Remove(newPath)
		return "", fmt.Errorf("clear stale backup: %w", err)
	}
	if err := os.Rename(real, bakPath); err != nil {
		os.Remove(newPath)
		return "", fmt.Errorf("back up current binary: %w", err)
	}
	if err := os.Rename(newPath, real); err != nil {
		// Put the old binary back so the install keeps working.
		if rbErr := os.Rename(bakPath, real); rbErr != nil {
			return "", fmt.Errorf("install new binary failed (%v) and rollback failed: %w", err, rbErr)
		}
		os.Remove(newPath)
		return "", fmt.Errorf("install new binary: %w", err)
	}
	return real, nil
}
