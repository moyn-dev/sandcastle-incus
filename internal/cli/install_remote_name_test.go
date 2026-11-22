package cli

import (
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

func TestInstallRemoteNameKeepsRemotesPerInstall(t *testing.T) {
	cfg := scconfig.SandcastleConfig{Installs: map[string]string{
		"moyn-dev":        "https://obelix.thieso2.dev",
		"thies":           "https://miraculix.moyn.dev",
		"taken-miraculix": "https://obelix.thieso2.dev",
		"taken":           "https://obelix.thieso2.dev",
	}}
	for _, tc := range []struct{ name, host, want string }{
		{"moyn-dev", "https://obelix.thieso2.dev", "moyn-dev"},
		{"moyn-dev", "https://miraculix.moyn.dev", "moyn-dev-miraculix"},
		{"thies", "https://miraculix.moyn.dev", "thies"},
		{"fresh", "https://miraculix.moyn.dev", "fresh"},
		{"taken", "https://miraculix.moyn.dev", "taken-miraculix-moyn-dev"},
	} {
		if got := installRemoteName(cfg, tc.name, tc.host); got != tc.want {
			t.Errorf("installRemoteName(%q, %q) = %q, want %q", tc.name, tc.host, got, tc.want)
		}
	}
}

func TestTenantSwitchDoesNotTakeAnotherInstallsRemote(t *testing.T) {
	useLoginHomeForTest(t)
	t.Chdir(t.TempDir())
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant:           "thies",
		Project:          "default",
		Remote:           "thies",
		AuthHostname:     "https://miraculix.moyn.dev",
		AuthToken:        "miraculix-token",
		Installs:         map[string]string{"thies": "https://miraculix.moyn.dev", "moyn-dev": "https://obelix.thieso2.dev"},
		RemoteTenants:    map[string]string{"moyn-dev": "moyn-dev"},
		RemoteAuthTokens: map[string]string{"moyn-dev": "obelix-token"},
	}); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{
		{Tenant: "thies"},
		{Tenant: "moyn-dev", Shared: true, Member: true, DNSSuffix: "moyn-dev", DefaultProject: "default", IncusProject: "miraculix-moyn-dev-default", IncusRemoteAddress: "100.65.149.78"},
	}}
	installer := &fakeTenantRemoteInstaller{}
	admin := testAdminConfig()
	admin.Tenant = "thies"
	admin.Remote = "thies"
	admin.AuthHostname = "https://miraculix.moyn.dev"
	admin.AuthToken = "miraculix-token"
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig:  admin,
		authTenants:  client,
		tenantRemote: installer,
	}, "tenant", "switch", "moyn-dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(installer.requests) != 1 || installer.requests[0].RemoteName != "moyn-dev-miraculix" {
		t.Fatalf("remote install requests = %#v", installer.requests)
	}
	if !strings.Contains(stdout, "on https://miraculix.moyn.dev") {
		t.Fatalf("switch does not name the install; stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Installs["moyn-dev"] != "https://obelix.thieso2.dev" || cfg.AuthTokenForRemote("moyn-dev") != "obelix-token" {
		t.Fatalf("obelix's moyn-dev remote records changed: installs=%v tokens=%v", cfg.Installs, cfg.RemoteAuthTokens)
	}
	if cfg.Remote != "moyn-dev-miraculix" || cfg.Installs["moyn-dev-miraculix"] != "https://miraculix.moyn.dev" || cfg.AuthTokenForRemote("moyn-dev-miraculix") != "miraculix-token" {
		t.Fatalf("new remote not recorded for miraculix: %#v", cfg)
	}
}
