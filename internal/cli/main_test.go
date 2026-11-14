package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain points HOME at a throwaway directory for the whole package. Many
// commands read and write ~/.config/sandcastle, ~/.ssh and ~/.sandcastle; a
// test that forgets useLoginHomeForTest must not reach the developer's real
// files (it once wrote a fake login and SSH key there).
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "sandcastle-cli-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("HOME", home)
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}
