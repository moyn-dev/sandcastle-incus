package localdns

import (
	"os"
	"path/filepath"
	"testing"
)

// stateHome isolates HOME and clears the state override so DefaultStatePath
// resolves the real default under a temp home.
func stateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SANDCASTLE_LOCAL_DNS_STATE", "")
	return home
}

func writeLegacyState(t *testing.T, home string) string {
	t.Helper()
	legacy := filepath.Join(home, ".sandcastle", "dns.yaml")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "tenants:\n- tenant: acme\n  dnsSuffix: acme\n  dnsEndpoint:\n    ip: 10.248.0.3\n    port: 53\n"
	if err := os.WriteFile(legacy, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return legacy
}

func TestDefaultStatePathLivesBesideConfig(t *testing.T) {
	home := stateHome(t)
	want := filepath.Join(home, ".config", "sandcastle", "dns.yaml")
	if got := DefaultStatePath(); got != want {
		t.Fatalf("DefaultStatePath() = %q, want %q", got, want)
	}
}

func TestStateEnvOverrideWinsAndSkipsLegacy(t *testing.T) {
	home := stateHome(t)
	legacy := writeLegacyState(t, home)
	override := filepath.Join(t.TempDir(), "custom.yaml")
	t.Setenv("SANDCASTLE_LOCAL_DNS_STATE", override)
	if got := DefaultStatePath(); got != override {
		t.Fatalf("DefaultStatePath() = %q, want %q", got, override)
	}
	state, err := readState(override)
	if err != nil || len(state.Tenants) != 0 {
		t.Fatalf("override read: state=%+v err=%v", state, err)
	}
	if err := writeState(override, state); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("an explicit override must not touch the legacy file: %v", err)
	}
}

func TestLegacyStateIsReadThenMigratedOnWrite(t *testing.T) {
	home := stateHome(t)
	legacy := writeLegacyState(t, home)
	path := DefaultStatePath()

	state, err := readState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Tenants) != 1 || state.Tenants[0].DNSSuffix != "acme" {
		t.Fatalf("legacy state not read: %+v", state)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a read must not create the new file: %v", err)
	}

	if err := writeState(path, state); err != nil {
		t.Fatal(err)
	}
	migrated, err := readState(path)
	if err != nil || len(migrated.Tenants) != 1 {
		t.Fatalf("new file: state=%+v err=%v", migrated, err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy dns.yaml should be removed after migration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".sandcastle")); !os.IsNotExist(err) {
		t.Fatalf("empty legacy dir should be gone after migration: %v", err)
	}
}

func TestMigrationKeepsNonEmptyLegacyDir(t *testing.T) {
	home := stateHome(t)
	legacy := writeLegacyState(t, home)
	other := filepath.Join(home, ".sandcastle", "keep.txt")
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeState(DefaultStatePath(), State{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy dns.yaml should be removed: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("unrelated file in ~/.sandcastle must survive: %v", err)
	}
}

// A `.sandcastle` selection file in $HOME is not legacy state.
func TestMigrationIgnoresSelectionFileInHome(t *testing.T) {
	home := stateHome(t)
	selection := filepath.Join(home, ".sandcastle")
	if err := os.WriteFile(selection, []byte("remote: alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := DefaultStatePath()
	state, err := readState(path)
	if err != nil || len(state.Tenants) != 0 {
		t.Fatalf("read: state=%+v err=%v", state, err)
	}
	if err := writeState(path, state); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(selection); err != nil || string(content) != "remote: alpha\n" {
		t.Fatalf("selection file changed: %q err=%v", content, err)
	}
}
