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

func TestUninstallMachineTunnelRemovesOnlyNamedSandcastleConnector(t *testing.T) {
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
	if err := uninstallMachineTunnel(context.Background(), config, "sc-acme-web", "web", "app.tc42.uk", false); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %v, want named connector cleanup", calls)
	}
	if got := strings.Join(calls[0], " "); !strings.Contains(got, "systemctl disable --now sandcastle-cloudflared-app-tc42-uk.service") || !strings.Contains(got, "rm -f /etc/default/sandcastle-cloudflared-app-tc42-uk") {
		t.Fatalf("cleanup command = %q", got)
	}
}

func TestReadMachineTunnelHostnamesUnionsLegacyAndCollectionRecords(t *testing.T) {
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
			switch got := strings.Join(args, " "); got {
			case "config get web " + meta.KeyV2MachineTunnelHostnames:
				_, _ = io.WriteString(output, "api.tc42.uk,App.TC42.uk.\n")
			case "config get web " + meta.KeyV2MachineTunnelHostname:
				_, _ = io.WriteString(output, "app.tc42.uk\n")
			default:
				t.Fatalf("unexpected args = %q", got)
			}
			return nil
		},
	}
	names, err := readMachineTunnelHostnames(context.Background(), config, tenant.Summary{Tenant: "demo"}, "zp", "web")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(names, ","), "api.tc42.uk,app.tc42.uk"; got != want {
		t.Fatalf("names = %q, want %q", got, want)
	}
}
