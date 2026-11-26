package update

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnderBrewPrefix(t *testing.T) {
	cases := []struct {
		exe, prefix string
		want        bool
	}{
		{"/opt/homebrew/bin/sc", "/opt/homebrew", true},
		{"/opt/homebrew/bin/sandcastle", "/opt/homebrew", true},
		{"/usr/local/bin/sc", "/usr/local", true},
		{"/home/linuxbrew/.linuxbrew/bin/sc", "/home/linuxbrew/.linuxbrew", true},
		{"/usr/local/bin/sc", "/opt/homebrew", false},
		{"/opt/homebrew/binx/sc", "/opt/homebrew", false}, // prefix must end at path separator
		{"/home/user/bin/sc", "/opt/homebrew", false},
		{"/opt/homebrew/bin/sc", "", false},
	}
	for _, c := range cases {
		if got := UnderBrewPrefix(c.exe, c.prefix); got != c.want {
			t.Errorf("UnderBrewPrefix(%q, %q) = %v, want %v", c.exe, c.prefix, got, c.want)
		}
	}
}

// applyFixture builds the busybox layout: a real binary plus the sc symlink
// pointing at it, then applies through the symlink.
func applyFixture(t *testing.T) (dir, real, link string) {
	t.Helper()
	dir = t.TempDir()
	real = filepath.Join(dir, "sandcastle")
	link = filepath.Join(dir, "sc")
	if err := os.WriteFile(real, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	return dir, real, link
}

func TestApplyReplacesSymlinkTargetAndKeepsBak(t *testing.T) {
	_, real, link := applyFixture(t)

	if _, err := Apply(link, []byte("new-binary")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// The symlink still resolves, to the new content.
	got, err := os.ReadFile(link)
	if err != nil || string(got) != "new-binary" {
		t.Fatalf("via symlink: %q err=%v", got, err)
	}
	// The real file was replaced in place (same path), not the symlink.
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("sc is no longer a symlink: %v %v", fi, err)
	}
	direct, _ := os.ReadFile(real)
	if string(direct) != "new-binary" {
		t.Fatalf("real path content %q", direct)
	}
	// Old binary preserved as .bak next to the real file.
	bak, err := os.ReadFile(real + ".bak")
	if err != nil || string(bak) != "old-binary" {
		t.Fatalf(".bak: %q err=%v", bak, err)
	}
	// New binary is executable.
	fi, _ := os.Stat(real)
	if fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("replacement not executable: %v", fi.Mode())
	}
}

func TestApplySecondRunOverwritesStaleBak(t *testing.T) {
	_, real, link := applyFixture(t)
	if _, err := Apply(link, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(link, []byte("v3")); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	got, _ := os.ReadFile(real)
	bak, _ := os.ReadFile(real + ".bak")
	if string(got) != "v3" || string(bak) != "v2" {
		t.Fatalf("got %q bak %q", got, bak)
	}
}

// The second `sc update` stage must run the NEW binary. On Linux a running
// process's os.Executable() follows its inode to <real>.bak after the swap,
// so Apply returns the installed path for the caller to exec instead.
func TestApplyReturnsTheInstalledPathNotTheBackup(t *testing.T) {
	_, real, link := applyFixture(t)
	installed, err := Apply(link, []byte("new-binary"))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want, _ := filepath.EvalSymlinks(real)
	if installed != want {
		t.Fatalf("installed = %q, want the resolved real path %q", installed, want)
	}
	if got, err := os.ReadFile(installed); err != nil || string(got) != "new-binary" {
		t.Fatalf("installed path holds %q (err %v), want the new binary", got, err)
	}
}
