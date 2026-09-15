package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

func TestUninstallMachineTunnelRemovesOnlySandcastleConnectorAndMetadata(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	remote := "tunnel-test"
	incusDir := scconfig.RemoteIncusDir(remote)
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	config := commandConfig{
		adminConfig: scconfig.Admin{Remote: remote},
		incusRunner: func(_ context.Context, args []string, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			calls = append(calls, append([]string(nil), args...))
			return nil
		},
	}
	if err := uninstallMachineTunnel(context.Background(), config, "sc-acme-web", "web"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want stop/remove and metadata clear", calls)
	}
	if got := strings.Join(calls[0], " "); !strings.Contains(got, "systemctl disable --now sandcastle-cloudflared.service") || !strings.Contains(got, "rm -f /etc/default/sandcastle-cloudflared /etc/systemd/system/sandcastle-cloudflared.service") {
		t.Fatalf("cleanup command = %q", got)
	}
	if got, want := strings.Join(calls[1], " "), "config set web "+meta.KeyV2MachineTunnelHostname+" "; got != want {
		t.Fatalf("metadata command = %q, want %q", got, want)
	}
}

func TestReadMachineTunnelHostnameUsesOnlyTheMachineRecord(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	remote := "tunnel-record"
	incusDir := scconfig.RemoteIncusDir(remote)
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := commandConfig{
		adminConfig: scconfig.Admin{Remote: remote},
		incusRunner: func(_ context.Context, args []string, _ []string, _ io.Reader, output io.Writer, _ io.Writer) error {
			if got, want := strings.Join(args, " "), "config get web "+meta.KeyV2MachineTunnelHostname; got != want {
				t.Fatalf("args = %q, want %q", got, want)
			}
			_, _ = io.WriteString(output, "App.TC42.uk.\n")
			return nil
		},
	}
	name, err := readMachineTunnelHostname(context.Background(), config, tenant.Summary{Tenant: "demo"}, "zp", "web")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := name, "app.tc42.uk"; got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
}
