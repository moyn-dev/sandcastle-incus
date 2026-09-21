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
	t.Chdir(t.TempDir())
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant:  "skorfmann",
		Project: "default",
		Remote:  "skorfmann",
		// A stale top-level placeholder (an old login left it); the real
		// hostname lives in installs[<remote>], and that is what must be
		// recorded for the shared remote.
		AuthHostname: "https://auth.placeholder.invalid",
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
	admin.Remote = "skorfmann"
	admin.AuthHostname = "https://auth.placeholder.invalid"
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
	t.Chdir(t.TempDir())
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
	for _, want := range []string{"  Tenant\tRole\tPersonal", "  skorfmann\towner\tno", "* moyn-dev\tmember\tno"} {
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
	if local.Remote != "moyn" || local.Project != "default" || local.Tenant != "moyn-dev" || local.RemoteProjects["moyn"] != "default" {
		t.Fatalf("selection = %#v", local)
	}
}

func TestTenantSwitchCreatesTheDirectorySelectionWithTheTenant(t *testing.T) {
	useLoginHomeForTest(t)
	dir := t.TempDir()
	t.Chdir(dir)
	if err := scconfig.SaveSandcastleConfig(scconfig.DefaultConfigPath(), scconfig.SandcastleConfig{
		Tenant: "thieso2", Project: "default", Remote: "thieso2sh", AuthHostname: "https://auth.example.com", AuthToken: "stored-token",
		Installs:      map[string]string{"thieso2sh": "https://auth.example.com", "moyn-dev": "https://auth.example.com"},
		RemoteTenants: map[string]string{"thieso2sh": "thieso2", "moyn-dev": "moyn-dev"},
	}); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "thieso2"}, {Tenant: "moyn-dev", Shared: true, Member: true, DNSSuffix: "moyn-dev", DefaultProject: "default", IncusProject: "sc2-moyn-dev-default", IncusRemoteAddress: "100.64.0.9"}}}
	admin := testAdminConfig()
	admin.Tenant, admin.Remote, admin.AuthHostname, admin.AuthToken = "thieso2", "thieso2sh", "https://auth.example.com", "stored-token"
	// The switch enrols the member remote (fake installer) and writes a NEW
	// selection file here.
	if _, err := executeForTestWithConfig(t, commandConfig{adminConfig: admin, authTenants: client, tenantRemote: &fakeTenantRemoteInstaller{}}, "tenant", "switch", "moyn-dev"); err != nil {
		t.Fatal(err)
	}
	local, path, err := scconfig.LoadDirectoryConfig(dir)
	if err != nil || path == "" {
		t.Fatalf("selection: %v (%q)", err, path)
	}
	if local.Tenant != "moyn-dev" || local.Remote != "moyn-dev" {
		t.Fatalf("selection = %#v", local)
	}
	// And the resolved user config in this directory follows it.
	resolved, err := scconfig.LoadUserWithError()
	if err != nil || resolved.Tenant != "moyn-dev" || resolved.Remote != "moyn-dev" {
		t.Fatalf("resolved = %+v, %v", resolved, err)
	}
}

func TestResolveTenantCIDRPoolPrefersFlagThenConfigThenSiblings(t *testing.T) {
	if got := resolveTenantCIDRPool("10.1.0.0/16", "10.2.0.0/16", []string{"10.123.5.0/24"}); got != "10.1.0.0/16" {
		t.Fatalf("flag: %q", got)
	}
	if got := resolveTenantCIDRPool("", "10.2.0.0/16", []string{"10.123.5.0/24"}); got != "10.2.0.0/16" {
		t.Fatalf("configured: %q", got)
	}
	// An install with tenants: the /16 they occupy, stable across ordering.
	if got := resolveTenantCIDRPool("", "", []string{"10.123.7.0/24", "10.123.5.0/24"}); got != "10.123.0.0/16" {
		t.Fatalf("siblings: %q", got)
	}
	if got := resolveTenantCIDRPool("", "", nil); got != defaultTenantCIDRPool {
		t.Fatalf("default: %q", got)
	}
	// The unconfigured admin default is not "configured": siblings still win.
	if got := resolveTenantCIDRPool("", scconfig.DefaultCIDRPool, []string{"10.123.5.0/24"}); got != "10.123.0.0/16" {
		t.Fatalf("admin default vs siblings: %q", got)
	}
}
