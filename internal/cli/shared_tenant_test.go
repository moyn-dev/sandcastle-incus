package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
)

type fakeTenantRemoteInstaller struct{ requests []tenantRemoteInstallRequest }

func (f *fakeTenantRemoteInstaller) InstallTenantRemote(_ context.Context, request tenantRemoteInstallRequest) error {
	f.requests = append(f.requests, request)
	return nil
}

func TestTenantSwitchEnrolsSharedTenantRemoteForMember(t *testing.T) {
	useLoginHomeForTest(t)
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant:       "skorfmann",
		Project:      "default",
		Remote:       "skorfmann",
		AuthHostname: "https://auth.example.com",
		AuthToken:    "stored-token",
		Broker:       "https://10.248.2.1:9443",
		Installs:     map[string]string{"skorfmann": "https://auth.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{
		{Tenant: "skorfmann"},
		{Tenant: "moyn-dev", Shared: true, Member: true, DNSSuffix: "moyn", DefaultProject: "default", IncusProject: "sc2-moyn-dev-default", IncusRemoteAddress: "100.64.0.9"},
	}}
	installer := &fakeTenantRemoteInstaller{}
	admin := testAdminConfig()
	admin.Tenant = "skorfmann"
	admin.AuthHostname = "https://auth.example.com"
	admin.AuthToken = "stored-token"
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig:  admin,
		authTenants:  client,
		tenantRemote: installer,
	}, "tenant", "switch", "moyn-dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(installer.requests) != 1 || installer.requests[0] != (tenantRemoteInstallRequest{RemoteName: "moyn", IncusAddress: "100.64.0.9", IncusProject: "sc2-moyn-dev-default"}) {
		t.Fatalf("remote install requests = %#v", installer.requests)
	}
	if !strings.Contains(stdout, `Incus remote "moyn" points at shared tenant moyn-dev`) {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenant != "moyn-dev" || cfg.Remote != "moyn" || cfg.Project != "default" {
		t.Fatalf("config = %#v", cfg)
	}
	if cfg.TenantForRemote("moyn") != "moyn-dev" || cfg.AuthTokenForRemote("moyn") != "stored-token" || cfg.BrokerForRemote("moyn") != "https://10.248.2.1:9443" || cfg.Installs["moyn"] != "https://auth.example.com" {
		t.Fatalf("per-remote records = %#v", cfg)
	}
}

func TestTenantSwitchRefusesMemberWhenSidecarHasNoTailnetAddress(t *testing.T) {
	useLoginHomeForTest(t)
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{Tenant: "skorfmann", AuthHostname: "https://auth.example.com", AuthToken: "stored-token"}); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "moyn-dev", Shared: true, Member: true, DNSSuffix: "moyn"}}}
	installer := &fakeTenantRemoteInstaller{}
	admin := testAdminConfig()
	admin.AuthHostname = "https://auth.example.com"
	admin.AuthToken = "stored-token"
	_, err := executeForTestWithConfig(t, commandConfig{adminConfig: admin, authTenants: client, tenantRemote: installer}, "tenant", "switch", "moyn-dev")
	if err == nil || !strings.Contains(err.Error(), "no Incus Reach address") {
		t.Fatalf("err = %v", err)
	}
	if len(installer.requests) != 0 {
		t.Fatalf("no remote should be enrolled: %#v", installer.requests)
	}
	cfg, _ := scconfig.LoadSandcastleConfig(configPath)
	if cfg.Tenant != "skorfmann" {
		t.Fatalf("config must be untouched: %#v", cfg)
	}
}

func TestTenantListShowsRoleColumn(t *testing.T) {
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{
		{Tenant: "skorfmann"},
		{Tenant: "moyn-dev", Shared: true, Member: true},
	}}
	admin := testAdminConfig()
	admin.Tenant = "moyn-dev"
	admin.AuthHostname = "auth.example.com"
	admin.AuthToken = "stored-token"
	stdout, err := executeForTestWithConfig(t, commandConfig{adminConfig: admin, authTenants: client}, "tenant", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Tenant\tPersonal\tCurrent\tRole", "skorfmann\tno\tno\towner", "moyn-dev\tno\tyes\tmember"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestTenantSwitchUpdatesTheDirectorySelectionForMember(t *testing.T) {
	useLoginHomeForTest(t)
	dir := t.TempDir()
	t.Chdir(dir)
	if _, err := scconfig.SaveDirectoryConfig(scconfig.DirectoryConfig{Remote: "skorfmannsh", Project: "default"}); err != nil {
		t.Fatal(err)
	}
	if err := scconfig.SaveSandcastleConfig(scconfig.DefaultConfigPath(), scconfig.SandcastleConfig{Tenant: "skorfmann", Remote: "skorfmannsh", AuthHostname: "https://auth.example.com", AuthToken: "stored-token"}); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{
		{Tenant: "moyn-dev", Shared: true, Member: true, DNSSuffix: "moyn", DefaultProject: "default", IncusProject: "sc2-moyn-dev-default", IncusRemoteAddress: "100.64.0.9"},
	}}
	admin := testAdminConfig()
	admin.AuthHostname = "https://auth.example.com"
	admin.AuthToken = "stored-token"
	if _, err := executeForTestWithConfig(t, commandConfig{adminConfig: admin, authTenants: client, tenantRemote: &fakeTenantRemoteInstaller{}}, "tenant", "switch", "moyn-dev"); err != nil {
		t.Fatal(err)
	}
	local, path, err := scconfig.LoadDirectoryConfig(dir)
	if err != nil || path == "" {
		t.Fatalf("selection: %v (%q)", err, path)
	}
	// The directory selection overrides the global remote, so the switch must
	// re-point it or every command here would still address skorfmannsh.
	if local.Remote != "moyn" || local.Project != "default" || local.RemoteProjects["moyn"] != "default" {
		t.Fatalf("selection = %#v", local)
	}
}
