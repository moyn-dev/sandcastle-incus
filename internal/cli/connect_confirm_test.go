package cli

import (
	"io"
	"strings"
	"testing"
)

// `sc connect` on a name that does not exist provisions a machine, so a typo
// used to cost a container and a boot. The ensure path now asks first.
func TestConfirmCreateMissingMachine(t *testing.T) {
	terminal := func(io.Reader) bool { return true }

	t.Run("accepting at the prompt allows the create", func(t *testing.T) {
		stderr := &strings.Builder{}
		admin := testAdminConfig()
		admin.Remote, admin.Tenant = "obelix", "acme"
		config := commandConfig{adminConfig: admin, stdin: strings.NewReader("y\n"), stderr: stderr, stdinIsTerminal: terminal}
		if err := confirmCreateMissingMachine(config, false)("web", "dev"); err != nil {
			t.Fatalf("confirmed create rejected: %v", err)
		}
		if !strings.Contains(stderr.String(), "Machine /obelix/acme/web/dev does not exist. Create it? [y/N]") {
			t.Fatalf("prompt %q does not name the machine and project", stderr.String())
		}
	})

	t.Run("declining cancels without creating", func(t *testing.T) {
		config := commandConfig{stdin: strings.NewReader("\n"), stderr: &strings.Builder{}, stdinIsTerminal: terminal}
		err := confirmCreateMissingMachine(config, false)("web", "dev")
		if err == nil || !strings.Contains(err.Error(), "create canceled") {
			t.Fatalf("declining gave %v, want a create canceled error", err)
		}
	})

	t.Run("--yes creates without asking", func(t *testing.T) {
		stderr := &strings.Builder{}
		config := commandConfig{stdin: strings.NewReader(""), stderr: stderr, stdinIsTerminal: terminal}
		if err := confirmCreateMissingMachine(config, true)("web", "dev"); err != nil {
			t.Fatalf("--yes rejected: %v", err)
		}
		if stderr.String() != "" {
			t.Fatalf("--yes still prompted: %q", stderr.String())
		}
	})

	t.Run("without a terminal the missing --yes is an error", func(t *testing.T) {
		config := commandConfig{stdin: strings.NewReader(""), stderr: &strings.Builder{}, stdinIsTerminal: func(io.Reader) bool { return false }}
		err := confirmCreateMissingMachine(config, false)("web", "dev")
		if err == nil || !strings.Contains(err.Error(), "pass --yes to create it") {
			t.Fatalf("non-interactive create gave %v, want the --yes hint", err)
		}
	})
}

// The confirmation names --yes, so the flag has to exist on `sc connect` (and
// therefore on its `sc c` alias) for a non-interactive caller to act on it.
func TestConnectRegistersYesFlag(t *testing.T) {
	root := NewRootCommand(commandConfig{name: "sc"})
	cmd, _, err := root.Find([]string{"connect"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Flags().Lookup("yes") == nil {
		t.Fatal("sc connect does not register --yes")
	}
	if err := cmd.ParseFlags([]string{"--yes"}); err != nil {
		t.Fatalf("sc connect --yes: %v", err)
	}
}
