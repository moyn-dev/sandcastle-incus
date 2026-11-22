package cli

import (
	"io"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

func approvedProjectPoll(projects []string, current string) authapp.DevicePollResult {
	return authapp.DevicePollResult{
		Status:            authapp.DeviceStatusApproved,
		UserKey:           "octocat",
		Token:             "token",
		RemoteName:        "sandcastle-octocat",
		AccessibleTenants: []string{"octocat"},
		Projects:          projects,
		CurrentProject:    current,
	}
}

// A single-project tenant stores that project silently so bare machine
// references (`sc c <machine>`) resolve without --project. This is the reported
// bug: the tenant's one project was named "first", not "default".
func TestLoginStoresSingleProject(t *testing.T) {
	useLoginHomeForTest(t)
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{approvedProjectPoll([]string{"first"}, "first")},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  device,
		loginRemote: &fakeLoginRemoteInstaller{},
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `Default project set to "first".`) {
		t.Fatalf("stdout missing project confirmation:\n%s", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "first" {
		t.Fatalf("Project = %q, want \"first\"", cfg.Project)
	}
}

// Multiple projects with a non-interactive stdin default to the server's
// current project and print a note pointing at `sc config set project`.
func TestLoginMultipleProjectsNonInteractiveDefaults(t *testing.T) {
	useLoginHomeForTest(t)
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{approvedProjectPoll([]string{"first", "web"}, "first")},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  device,
		loginRemote: &fakeLoginRemoteInstaller{},
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Multiple projects available (first, web)",
		`defaulted to "first"`,
		"sc project switch",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "first" {
		t.Fatalf("Project = %q, want \"first\"", cfg.Project)
	}
}

// An interactive terminal prompts for the default; a numeric selection picks the
// matching project.
func TestLoginMultipleProjectsInteractivePrompt(t *testing.T) {
	useLoginHomeForTest(t)
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{approvedProjectPoll([]string{"first", "web"}, "first")},
	}
	stdout, _, err := executeForTestWithConfigAndStderr(t, commandConfig{
		name:            "sandcastle",
		authDevice:      device,
		loginRemote:     &fakeLoginRemoteInstaller{},
		stdin:           strings.NewReader("2\n"),
		stdinIsTerminal: func(io.Reader) bool { return true },
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Select your default project:") {
		t.Fatalf("stdout missing prompt:\n%s", stdout)
	}
	if !strings.Contains(stdout, `Default project set to "web".`) {
		t.Fatalf("stdout missing selection confirmation:\n%s", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "web" {
		t.Fatalf("Project = %q, want \"web\"", cfg.Project)
	}
}

// A returning user whose configured project is still valid keeps it — no prompt,
// no overwrite — even when the tenant now has several projects.
func TestLoginKeepsExistingValidProject(t *testing.T) {
	useLoginHomeForTest(t)
	if err := scconfig.SaveSandcastleConfig(scconfig.DefaultConfigPath(), scconfig.SandcastleConfig{Project: "web"}); err != nil {
		t.Fatal(err)
	}
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{approvedProjectPoll([]string{"first", "web"}, "first")},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  device,
		loginRemote: &fakeLoginRemoteInstaller{},
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `Current project: "web".`) {
		t.Fatalf("stdout missing kept-project line:\n%s", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "web" {
		t.Fatalf("Project = %q, want \"web\" preserved", cfg.Project)
	}
}
