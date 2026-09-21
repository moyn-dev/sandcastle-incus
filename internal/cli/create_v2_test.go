package cli

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

func TestParseV2MachineReference(t *testing.T) {
	tests := []struct {
		name           string
		reference      string
		currentProject string
		wantSuffix     string
		wantProject    string
		wantMachine    string
		wantErr        bool
	}{
		{"bare machine", "dev", "", "", "default", "dev", false},
		{"machine with current project", "dev", "backend", "", "backend", "dev", false},
		{"explicit project", "web:dev", "backend", "", "web", "dev", false},
		// New grammar (ADR-0020): the leftmost of three colon-separated parts is
		// the install's DNS suffix. `sc c obelix:sc:dev` -> install obelix.
		{"install qualified", "obelix:web:dev", "backend", "obelix", "web", "dev", false},
		{"install qualified with dashes", "obelix-eu:web:dev", "", "obelix-eu", "web", "dev", false},
		// ADR-0020 stage 7: the legacy "tenant/" prefix is dropped — "/" is no
		// longer special, so these now fail validation (slash in project/machine).
		{"slash no longer a tenant separator", "acme/web:dev", "", "", "", "", true},
		{"bare slash reference errors", "other/dev", "", "", "", "", true},
		{"empty machine", "web:", "", "", "", "", true},
		{"too many colons", "a:b:c:d", "", "", "", "", true},
		{"invalid install suffix", "Bad:web:dev", "", "", "", "", true},
		{"invalid machine name", "Bad Name", "", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suffix, project, machine, err := parseV2MachineReference(tt.reference, "acme", tt.currentProject)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got suffix=%q project=%q machine=%q", suffix, project, machine)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if suffix != tt.wantSuffix || project != tt.wantProject || machine != tt.wantMachine {
				t.Fatalf("got %q/%q/%q, want %q/%q/%q", suffix, project, machine, tt.wantSuffix, tt.wantProject, tt.wantMachine)
			}
		})
	}
}

func TestResolveV2MachineReference(t *testing.T) {
	summary := tenant.Summary{
		Tenant:    "acme",
		DNSSuffix: "acme",
		Projects:  []meta.Project{{Name: "default"}, {Name: "test2"}, {Name: "test3"}},
	}

	t.Run("known project passes", func(t *testing.T) {
		project, machine, err := resolveV2MachineReference(summary, "test2:dev", "")
		if err != nil {
			t.Fatal(err)
		}
		if project != "test2" || machine != "dev" {
			t.Fatalf("got %q/%q", project, machine)
		}
	})

	t.Run("install suffix matching the current install passes", func(t *testing.T) {
		project, machine, err := resolveV2MachineReference(summary, "acme:test2:dev", "")
		if err != nil {
			t.Fatal(err)
		}
		if project != "test2" || machine != "dev" {
			t.Fatalf("got %q/%q", project, machine)
		}
	})

	t.Run("install suffix for a different install is a cross-install error", func(t *testing.T) {
		_, _, err := resolveV2MachineReference(summary, "elsewhere:test2:dev", "")
		if err == nil {
			t.Fatal("expected cross-install error")
		}
		for _, want := range []string{"elsewhere", "acme"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q missing %q", err.Error(), want)
			}
		}
	})

	t.Run("unknown project fails with the project list", func(t *testing.T) {
		_, _, err := resolveV2MachineReference(summary, "nosuch:dev", "")
		if err == nil {
			t.Fatal("expected error")
		}
		for _, want := range []string{`project "nosuch" not found`, "default, test2, test3", "sc project create nosuch"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q missing %q", err.Error(), want)
			}
		}
	})

	t.Run("swapped reference suggests project:machine", func(t *testing.T) {
		// the user's real mistake: `sc delete dev:test2` for machine dev in project test2
		_, _, err := resolveV2MachineReference(summary, "dev:test2", "")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), `did you mean "test2:dev"`) {
			t.Fatalf("error %q missing the swap hint", err.Error())
		}
	})
}

// A bare machine name is ambiguous when several projects hold a machine by
// that name — Incus lets them coexist, so `sc delete dev` has to ask rather
// than silently pick the Current Project.
func TestResolveV2MachineTarget(t *testing.T) {
	summary := tenant.Summary{
		Tenant:   "acme",
		Projects: []meta.Project{{Name: "default"}, {Name: "io"}, {Name: "web"}},
	}
	store := fakeMachineStatusStore{machines: []meta.Machine{
		{Project: "io", Name: "dev"},
		{Project: "web", Name: "dev"},
		{Project: "web", Name: "solo"},
	}}
	terminal := func(io.Reader) bool { return true }

	t.Run("explicit project skips the search", func(t *testing.T) {
		config := commandConfig{machineStore: store, stdinIsTerminal: terminal}
		project, machineName, err := resolveV2MachineTarget(context.Background(), config, summary, "io:dev")
		if err != nil {
			t.Fatal(err)
		}
		if project != "io" || machineName != "dev" {
			t.Fatalf("got %q/%q", project, machineName)
		}
	})

	t.Run("single match resolves outside the current project", func(t *testing.T) {
		config := commandConfig{machineStore: store, stdinIsTerminal: terminal}
		config.adminConfig.Project = "default"
		project, machineName, err := resolveV2MachineTarget(context.Background(), config, summary, "solo")
		if err != nil {
			t.Fatal(err)
		}
		if project != "web" || machineName != "solo" {
			t.Fatalf("got %q/%q", project, machineName)
		}
	})

	t.Run("a bare name is the current project's machine when it exists there", func(t *testing.T) {
		config := commandConfig{machineStore: store, stdinIsTerminal: func(io.Reader) bool { return false }}
		config.adminConfig.Project = "io"
		// dev exists in io AND web; no prompt, no error: the current project wins.
		project, machineName, err := resolveV2MachineTarget(context.Background(), config, summary, "dev")
		if err != nil {
			t.Fatal(err)
		}
		if project != "io" || machineName != "dev" {
			t.Fatalf("got %q/%q", project, machineName)
		}
	})

	t.Run("no match falls back to the inferred project", func(t *testing.T) {
		config := commandConfig{machineStore: store, stdinIsTerminal: terminal}
		config.adminConfig.Project = "io"
		project, machineName, err := resolveV2MachineTarget(context.Background(), config, summary, "ghost")
		if err != nil {
			t.Fatal(err)
		}
		if project != "io" || machineName != "ghost" {
			t.Fatalf("got %q/%q", project, machineName)
		}
	})

	t.Run("several matches ask which one is meant", func(t *testing.T) {
		stderr := &strings.Builder{}
		config := commandConfig{
			machineStore:    store,
			stdin:           strings.NewReader("2\n"),
			stderr:          stderr,
			stdinIsTerminal: terminal,
		}
		project, machineName, err := resolveV2MachineTarget(context.Background(), config, summary, "dev")
		if err != nil {
			t.Fatal(err)
		}
		if project != "web" || machineName != "dev" {
			t.Fatalf("got %q/%q", project, machineName)
		}
		for _, want := range []string{`Machine "dev" exists in 2 projects:`, "1) io:dev", "2) web:dev", "Which one? [1-2]"} {
			if !strings.Contains(stderr.String(), want) {
				t.Fatalf("prompt %q missing %q", stderr.String(), want)
			}
		}
	})

	t.Run("several matches without a terminal demand a qualified reference", func(t *testing.T) {
		config := commandConfig{machineStore: store, stdinIsTerminal: func(io.Reader) bool { return false }}
		_, _, err := resolveV2MachineTarget(context.Background(), config, summary, "dev")
		if err == nil {
			t.Fatal("expected error")
		}
		for _, want := range []string{`machine "dev" exists in 2 projects`, "io:dev, web:dev", "project:machine"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error %q missing %q", err.Error(), want)
			}
		}
	})

	t.Run("an answer outside the offered range cancels", func(t *testing.T) {
		config := commandConfig{
			machineStore:    store,
			stdin:           strings.NewReader("9\n"),
			stderr:          &strings.Builder{},
			stdinIsTerminal: terminal,
		}
		_, _, err := resolveV2MachineTarget(context.Background(), config, summary, "dev")
		if err == nil || !strings.Contains(err.Error(), "canceled") {
			t.Fatalf("error = %v", err)
		}
	})
}

// Several installs share one Incus daemon; the enrolled remote's name
// ("sc-<prefix>-<tenant>", or "sc-<tenant>" for the default prefix) is what
// tells the CLI which install's projects to scope tenant lookups to.
// URL-named remotes (sc-<install-label>) carry no prefix in the name; the
// remote's pinned project in the shared incus config is what identifies the
// install. Regression: without the pin lookup, lookups under such remotes ran
// unscoped and `sc list`/`sc incus` under install A showed install B's
// machines (live on majestix, two installs sc+id on one daemon).
func TestInstallPrefixFromRemotePinnedProject(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	incusDir := filepath.Join(home, ".config", "incus")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Mark the native dir Sandcastle-owned so SharedIncusDir resolves to it.
	if err := os.WriteFile(filepath.Join(incusDir, ".sandcastle-owned"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := `remotes:
  sc-majestix-71607f9d-thieso2-dev:
    addr: https://100.92.39.49:8443
    project: sc2-e2edns-default
  sc-majestix2-71607f9d-thieso2-dev:
    addr: https://100.74.64.82:8443
    project: id-e2edns-default
  sc-infra-pin:
    addr: https://100.74.64.82:8443
    project: id2-e2edns
`
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		remote, tenant, want string
	}{
		{"sc-majestix-71607f9d-thieso2-dev", "e2edns", "sc2"},
		{"sc-majestix2-71607f9d-thieso2-dev", "e2edns", "id"},
		{"sc-infra-pin", "e2edns", "id2"},                 // pinned to the infra project
		{"sc-unknown-remote", "e2edns", ""},               // not enrolled: no pin, no legacy shape
		{"sc-majestix-71607f9d-thieso2-dev", "other", ""}, // pin doesn't contain the tenant
	}
	for _, c := range cases {
		if got := installPrefixFromRemoteName(c.remote, c.tenant); got != c.want {
			t.Errorf("installPrefixFromRemoteName(%q, %q) = %q, want %q", c.remote, c.tenant, got, c.want)
		}
	}
}

func TestInstallPrefixFromRemoteName(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no shared incus config: exercise the legacy name-shape fallback
	cases := []struct {
		remote, tenant, want string
	}{
		{"sc-tc3-thieso2", "thieso2", "tc3"},
		{"sc-tc2-thieso2", "thieso2", "tc2"},
		{"sc-thieso2", "thieso2", "sc"},
		{"sc-tc3-foo-bar", "foo-bar", "tc3"},
		{"sc-foo-bar", "foo-bar", "sc"},
		{"custom-remote", "thieso2", ""},
		{"sc-tc3-thieso2", "", ""},
		{"", "thieso2", ""},
	}
	for _, c := range cases {
		if got := installPrefixFromRemoteName(c.remote, c.tenant); got != c.want {
			t.Errorf("installPrefixFromRemoteName(%q, %q) = %q, want %q", c.remote, c.tenant, got, c.want)
		}
	}
}

// Regression for #53: ssh concatenates its trailing arguments with spaces into
// one remote command string, so argv handed to `sc c` must be shell-quoted or
// the remote shell re-splits it (`sh -c 'id -un'` → `sh -c id -un`).
func TestRemoteCommandLineQuotesArgvForSSH(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		command []string
		want    string
	}{
		{name: "interactive", command: nil, want: ""},
		{name: "single word", command: []string{"hostname"}, want: "hostname"},
		{name: "lone arg stays a shell snippet", command: []string{"ls -l /tmp"}, want: "ls -l /tmp"},
		{name: "flags stay attached to their command", command: []string{"id", "-un"}, want: "'id' '-un'"},
		{name: "sh -c script survives as one word", command: []string{"sh", "-c", "echo hi"}, want: "'sh' '-c' 'echo hi'"},
		{name: "redirection and chaining stay inside the script", command: []string{"sh", "-c", "touch /workspace/x && echo ok"}, want: "'sh' '-c' 'touch /workspace/x && echo ok'"},
		{name: "embedded single quotes are escaped", command: []string{"sh", "-c", "echo 'a b'"}, want: `'sh' '-c' 'echo '\''a b'\'''`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := remoteCommandLine(testCase.command); got != testCase.want {
				t.Fatalf("remoteCommandLine(%q) = %q, want %q", testCase.command, got, testCase.want)
			}
		})
	}
}

// The remote sshd hands the joined command line to the login shell, so the real
// contract is: parsing remoteCommandLine's output with a shell must reproduce
// the original argv semantics.
func TestRemoteCommandLineRoundTripsThroughAShell(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		command []string
		want    string
	}{
		{name: "sh -c echo", command: []string{"sh", "-c", "echo hi"}, want: "hi\n"},
		{name: "id -un keeps its flag", command: []string{"printf", "%s-%s", "a", "b"}, want: "a-b"},
		{name: "script with quotes", command: []string{"sh", "-c", "echo 'a b'"}, want: "a b\n"},
		{name: "script with chaining", command: []string{"sh", "-c", "true && echo ok"}, want: "ok\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			line := remoteCommandLine(testCase.command)
			output, err := exec.Command("sh", "-c", line).Output()
			if err != nil {
				t.Fatalf("sh -c %q: %v", line, err)
			}
			if string(output) != testCase.want {
				t.Fatalf("sh -c %q produced %q, want %q", line, output, testCase.want)
			}
		})
	}
}

// `sc connect` to a bare machine opens an Incus exec session instead of SSH:
// there is no user to be and no sshd to answer, so the ssh path could only
// ever end in the cloud-init timeout.
func TestConnectV2BareExecsAShellInsteadOfSSH(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	incusDir := scconfig.RemoteIncusDir("sandcastle-alice")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// ResolveConfigPath only accepts a per-remote dir that holds a config.yml.
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var gotArgs, gotEnv []string
	config := commandConfig{
		name:        "sandcastle",
		adminConfig: scconfig.Admin{Remote: "sandcastle-alice", Tenant: "acme"},
		stdout:      io.Discard,
		stderr:      io.Discard,
		incusRunner: func(ctx context.Context, args []string, env []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
			gotArgs = append([]string{}, args...)
			gotEnv = append([]string{}, env...)
			return nil
		},
	}
	summary := tenant.Summary{Tenant: "acme", InfraProject: "sc2-acme", DNSSuffix: "acme"}
	dialed := dialedV2Machine{bare: true, project: "default", machine: "web"}

	if err := connectV2Bare(context.Background(), config, summary, dialed, nil); err != nil {
		t.Fatal(err)
	}
	// No -t/-T: incus picks the mode from whether stdin/stdout are terminals,
	// which is right for both an interactive prompt and a pipeline.
	want := []string{"exec", "web", "--", "/bin/sh", "-c", bareLoginShellCommand}
	if strings.Join(gotArgs, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v, want %#v", gotArgs, want)
	}
	if !envContains(gotEnv, "INCUS_CONF="+incusDir) {
		t.Fatalf("env missing INCUS_CONF=%s: %#v", incusDir, gotEnv)
	}
	// The machine lives in the tenant's app project, not the infra one.
	if !envContains(gotEnv, "INCUS_PROJECT=sc2-acme-default") {
		t.Fatalf("env missing INCUS_PROJECT=sc2-acme-default: %#v", gotEnv)
	}

	// A trailing command runs instead of the shell, shell-quoted into one line
	// so `sc c web -- ls -l /tmp` does not lose its arguments.
	if err := connectV2Bare(context.Background(), config, summary, dialed, []string{"ls", "-l"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(gotArgs, " "); got != `exec web -- /bin/sh -c 'ls' '-l'` {
		t.Fatalf("args with a command = %q", got)
	}
}

// The fallback shell choice is made IN the machine: a bare machine is whatever
// image the tenant pointed --image at, and bash is not guaranteed.
func TestBareLoginShellCommandFallsBackToSh(t *testing.T) {
	for _, want := range []string{"command -v bash", "exec bash -l", "exec sh -l"} {
		if !strings.Contains(bareLoginShellCommand, want) {
			t.Fatalf("bare login shell command missing %q: %q", want, bareLoginShellCommand)
		}
	}
}
