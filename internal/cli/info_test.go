package cli

import (
	"strings"
	"testing"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func infoV2ProjectStore(names ...string) tenant.MemoryStore {
	projects := make([]tenant.IncusProject, 0, len(names))
	for _, name := range names {
		projects = append(projects, tenant.IncusProject{Name: name, Config: map[string]string{
			meta.KeyKind:    meta.KindV2Project,
			meta.KeyVersion: "2",
			meta.KeyTenant:  "acme",
		}})
	}
	return tenant.MemoryStore{Projects: projects}
}

func TestInfoListsProjectsAndMarksCurrent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme"},
		tenantStore: infoV2ProjectStore("sc2-acme-first", "sc2-acme-web"),
	}, "info")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Tenant:   acme",
		"Project:  web",
		"Remote:   sc-acme",
		"Projects in acme:",
		"* web",
		"first",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestInfoConfigOnlyWhenTenantUnreachable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// No tenantStore → v2TenantSummary fails; info must still print config.
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "first", Remote: "sc-acme"},
	}, "info")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Tenant:   acme") {
		t.Fatalf("stdout missing tenant:\n%s", stdout)
	}
	if !strings.Contains(stdout, "showing local config only") {
		t.Fatalf("stdout missing offline note:\n%s", stdout)
	}
}

func TestInfoJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme"},
		tenantStore: infoV2ProjectStore("sc2-acme-first", "sc2-acme-web"),
	}, "info", "--json")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"tenant": "acme"`, `"project": "web"`, `"first"`, `"web"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("json missing %q:\n%s", want, stdout)
		}
	}
}
