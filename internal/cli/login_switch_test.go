package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

// `sc login <host>` reuses a saved login for a DIFFERENT install than the active
// one — resolving the token + enrolled remote from the installs/auth_tokens maps
// — and switches to it without opening the browser.
func TestLoginSwitchesToExistingInstallWithoutBrowser(t *testing.T) {
	useLoginHomeForTest(t)

	hostB := "https://home.example.com"
	// Active install is A; a still-valid login for B lives only in the maps.
	if err := scconfig.SaveSandcastleConfig(scconfig.DefaultConfigPath(), scconfig.SandcastleConfig{
		AuthHostname: "https://a.example.com",
		AuthToken:    "token-a",
		Remote:       "sc-a",
		Tenant:       "acme",
		Installs:     map[string]string{"sc-b": hostB},
		AuthTokens:   map[string]string{hostB: "token-b"},
		Brokers:      map[string]string{hostB: "https://10.253.0.1:9443"},
	}); err != nil {
		t.Fatal(err)
	}
	// Enroll remote sc-b in the shared incus dir so ResolveConfigPath finds it.
	scconfig.AdoptNativeIncusDirIfChosen()
	shared := scconfig.SharedIncusDir()
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "config.yml"),
		[]byte("remotes:\n  sc-b:\n    addr: https://100.64.0.1:8443\n    protocol: incus\ndefault-remote: sc-b\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	device := &fakeAuthDeviceClient{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name: "sandcastle",
		adminConfig: scconfig.Admin{
			AuthHostname: "https://a.example.com",
			AuthToken:    "token-a",
			Remote:       "sc-a",
			Tenant:       "acme",
		},
		authTenants:      &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "acme"}}},
		authDevice:       device,
		loginRemoteProbe: func(context.Context, string) error { return nil },
	}, "login", hostB)
	if err != nil {
		t.Fatal(err)
	}
	if device.startCalls != 0 {
		t.Fatalf("device flow started %d times, want 0 (should reuse the saved login)", device.startCalls)
	}
	for _, want := range []string{
		"Already logged in at https://home.example.com",
		"Switched active install to https://home.example.com",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthHostname != hostB || cfg.Remote != "sc-b" || cfg.AuthToken != "token-b" {
		t.Fatalf("active install not switched to B: %#v", cfg)
	}
}
