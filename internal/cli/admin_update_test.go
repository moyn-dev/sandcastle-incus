package cli

import (
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
)

func fleet() []incusx.ComponentVersion {
	return []incusx.ComponentVersion{
		{Kind: "auth-app", Project: "sc2-infra", Instance: "sc2-auth-app"},
		{Kind: "auth-app", Project: "tc2-infra", Instance: "tc2-auth-app"}, // neighbour install
		{Kind: "auth-app", Project: "infrastructure", Instance: "sc2-auth-app"},
		{Kind: "broker", Project: "sc2-broker", Instance: "sc2-broker"},
		{Kind: "broker", Project: "tc2-broker", Instance: "tc2-broker"}, // neighbour install
		{Kind: "sidecar", Project: "sc2-acme", Instance: "sidecar", Tenant: "acme", TenantManaged: true},
		{Kind: "sidecar", Project: "tc2-acme", Instance: "sidecar", Tenant: "acme", TenantManaged: true}, // neighbour
		{Kind: "sidecar", Project: "sc2-beta", Instance: "sidecar", Tenant: "beta", TenantManaged: true},
	}
}

func TestFilterInstallComponentsScopesByPrefix(t *testing.T) {
	scoped := filterInstallComponents(fleet(), "sc2", "")
	if len(scoped) != 5 {
		t.Fatalf("expected 5 scoped rows, got %d: %+v", len(scoped), scoped)
	}
	for _, c := range scoped {
		if c.Project == "tc2-infra" || c.Project == "tc2-broker" || c.Project == "tc2-acme" {
			t.Fatalf("neighbour install leaked into scope: %+v", c)
		}
	}
}

func TestSelectUpdateTargetsDefaultSkipsSidecars(t *testing.T) {
	scoped := filterInstallComponents(fleet(), "sc2", "")
	targets, err := selectUpdateTargets(scoped, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range targets {
		if tr.Kind == "sidecar" {
			t.Fatalf("sidecar selected without --tenants/--all-tenants: %+v", tr)
		}
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 global targets, got %d", len(targets))
	}
}

func TestSelectUpdateTargetsAllTenants(t *testing.T) {
	scoped := filterInstallComponents(fleet(), "sc2", "")
	targets, err := selectUpdateTargets(scoped, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	sidecars := 0
	for _, tr := range targets {
		if tr.Kind == "sidecar" {
			sidecars++
		}
	}
	if sidecars != 2 {
		t.Fatalf("expected 2 sidecars with --all-tenants, got %d", sidecars)
	}
}

func TestSelectUpdateTargetsUnknownTenantErrors(t *testing.T) {
	scoped := filterInstallComponents(fleet(), "sc2", "")
	if _, err := selectUpdateTargets(scoped, []string{"nosuch"}, false); err == nil {
		t.Fatal("expected error for unknown tenant")
	}
	targets, err := selectUpdateTargets(scoped, []string{"beta"}, false)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tr := range targets {
		if tr.Kind == "sidecar" && tr.Tenant == "beta" {
			found = true
		}
	}
	if !found {
		t.Fatal("beta sidecar not selected")
	}
}
