package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
)

func TestInfraFromPinnedProject(t *testing.T) {
	cases := []struct{ pin, tenant, want string }{
		{"sc2-thieso2-first", "thieso2", "sc2-thieso2"},
		{"sc2-thieso2", "thieso2", "sc2-thieso2"},   // infra-shaped pin
		{"id-foo-bar-web", "foo-bar", "id-foo-bar"}, // dashed tenant
		{"sc2-other-x", "thieso2", ""},              // wrong tenant
		{"", "thieso2", ""},
	}
	for _, c := range cases {
		if got := infraFromPinnedProject(c.pin, c.tenant); got != c.want {
			t.Errorf("infraFromPinnedProject(%q,%q) = %q, want %q", c.pin, c.tenant, got, c.want)
		}
	}
}

// ADR-0021: `sc project switch` re-pins the active install's incus remote to the
// new project so raw `incus <remote>:` follows the switch.
func TestProjectSwitchRepinsRemote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// Enroll remote "sc-acme" pinned to sc2-acme-first in the shared incus dir.
	scconfig.AdoptNativeIncusDirIfChosen()
	shared := scconfig.SharedIncusDir()
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgYML := "remotes:\n  sc-acme:\n    addr: https://100.64.0.1:8443\n    protocol: incus\n    project: sc2-acme-first\ndefault-remote: sc-acme\n"
	incusCfg := filepath.Join(shared, "config.yml")
	if err := os.WriteFile(incusCfg, []byte(cfgYML), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "first", Remote: "sc-acme"},
		tenantStore: infoV2ProjectStore("sc2-acme-first", "sc2-acme-web"),
	}, "project", "switch", "web")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Re-pinned remote") {
		t.Fatalf("stdout missing re-pin line:\n%s", stdout)
	}
	data, err := os.ReadFile(incusCfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "project: sc2-acme-web") {
		t.Fatalf("remote pin not updated to sc2-acme-web:\n%s", string(data))
	}
}

func TestProjectSwitchSetsCurrentProject(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Remote: "sc-acme"},
		tenantStore: infoV2ProjectStore("sc2-acme-first", "sc2-acme-web"),
	}, "project", "switch", "web")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `Switched to project "web"`) {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "web" {
		t.Fatalf("Project = %q, want web", cfg.Project)
	}
}

func TestProjectSwitchRejectsUnknownProject(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Remote: "sc-acme"},
		tenantStore: infoV2ProjectStore("sc2-acme-first"),
	}, "project", "switch", "ghost")
	if err == nil || !strings.Contains(err.Error(), "not found in tenant acme") {
		t.Fatalf("err = %v, want not-found", err)
	}
}

func TestProjectSwitchLocalOnlySkipsValidation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// No tenantStore → a validated switch would fail; --local-only must not look.
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Remote: "sc-acme"},
	}, "project", "switch", "web", "--local-only")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `Switched to project "web"`) {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "web" {
		t.Fatalf("Project = %q, want web", cfg.Project)
	}
}

func TestProjectListMarksCurrent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme"},
		tenantStore: infoV2ProjectStore("sc2-acme-first", "sc2-acme-web"),
	}, "project", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "* web") || !strings.Contains(stdout, "  first") {
		t.Fatalf("list should mark current project:\n%s", stdout)
	}
}
