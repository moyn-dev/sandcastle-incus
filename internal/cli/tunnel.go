package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Machine Tunnels are deliberately separate from Machine Public Hostnames and
// Public Routes. A connector runs inside the selected Machine and receives
// only its Cloudflare run token, never the account API token used to create it.
func newTunnelCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{Use: "tunnel", Short: "Publish services through a dedicated Cloudflare Tunnel per machine"}
	command.AddCommand(newTunnelPublishCommand(config, opts))
	command.AddCommand(newTunnelUnpublishCommand(config, opts))
	return command
}

func newTunnelPublishCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var port int
	var hostname string
	command := &cobra.Command{
		Use:   "publish [[remote:]project:]machine --port <n> --hostname <fqdn>",
		Short: "Publish a machine port through its own Cloudflare Tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if port < 1 || port > 65535 {
				return fmt.Errorf("--port must be between 1 and 65535")
			}
			name, err := authapp.NormalizeMachineHostname(hostname)
			if err != nil {
				return err
			}
			config, reference, restore, err := rebindForReference(config, args[0])
			if err != nil {
				return err
			}
			defer restore()
			summary, project, machine, err := hostnameTarget(cmd.Context(), config, reference)
			if err != nil {
				return err
			}
			if !projectAuthAppAvailable(config, "") {
				return fmt.Errorf("Machine Tunnels require sc login to an Auth App")
			}
			runTokenResult, err := (authapp.DeviceClient{BaseURL: commandAuthHostname(config, ""), AuthToken: config.adminConfig.AuthToken}).ProvisionMachineTunnel(cmd.Context(), authapp.MachineTunnelRequest{Tenant: summary.Tenant, Project: project, Machine: machine, Hostname: name, Port: port})
			if err != nil {
				return err
			}
			if err := installMachineTunnel(cmd.Context(), config, summary.V2IncusProjectName(project), machine, runTokenResult.Token, name); err != nil {
				return err
			}
			payload := map[string]any{"project": project, "machine": machine, "hostname": name, "port": port, "status": "pending"}
			return writeOutput(config.stdout, opts.output, fmt.Sprintf("Tunnel published: https://%s (connector starting)", name), payload)
		},
	}
	command.Flags().IntVar(&port, "port", 0, "backend port inside the machine (required)")
	command.Flags().StringVar(&hostname, "hostname", "", "public Cloudflare hostname (required)")
	_ = command.MarkFlagRequired("hostname")
	return command
}

func installMachineTunnel(ctx context.Context, config commandConfig, incusProject, machine, token, hostname string) error {
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return fmt.Errorf("no Sandcastle-managed Incus config found for remote %q", config.adminConfig.Remote)
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+incusProject)
	run := func(args []string, in io.Reader) error {
		return runner(ctx, args, env, in, config.stdout, config.stderr)
	}
	if err := run([]string{"exec", machine, "--", "mkdir", "-p", "/etc/default"}, nil); err != nil {
		return fmt.Errorf("prepare machine tunnel: %w", err)
	}
	if err := run([]string{"file", "push", "-", machine + "/etc/default/sandcastle-cloudflared"}, strings.NewReader("TUNNEL_TOKEN="+token+"\n")); err != nil {
		return fmt.Errorf("install machine tunnel token: %w", err)
	}
	unit := "[Unit]\nDescription=Sandcastle Machine Cloudflare Tunnel\nAfter=network-online.target\n\n[Service]\nEnvironmentFile=/etc/default/sandcastle-cloudflared\nExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate run\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := run([]string{"file", "push", "-", machine + "/etc/systemd/system/sandcastle-cloudflared.service"}, strings.NewReader(unit)); err != nil {
		return fmt.Errorf("install machine tunnel service: %w", err)
	}
	script := "set -eu; if ! test -x /usr/local/bin/cloudflared; then case $(dpkg --print-architecture) in amd64) a=amd64;; arm64) a=arm64;; *) echo unsupported architecture >&2; exit 1;; esac; curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$a -o /usr/local/bin/cloudflared; chmod 755 /usr/local/bin/cloudflared; fi; systemctl daemon-reload; systemctl enable --now sandcastle-cloudflared.service"
	if err := run([]string{"exec", machine, "--", "sh", "-ceu", script}, nil); err != nil {
		return fmt.Errorf("start machine tunnel: %w", err)
	}
	if err := run([]string{"config", "set", machine, meta.KeyV2MachineTunnelHostname + "=" + hostname}, nil); err != nil {
		return fmt.Errorf("record machine tunnel: %w", err)
	}
	return nil
}

func newTunnelUnpublishCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var hostname string
	command := &cobra.Command{
		Use:   "unpublish [[remote:]project:]machine --hostname <fqdn>",
		Short: "Remove a machine's dedicated Cloudflare Tunnel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bound, reference, restore, err := rebindForReference(config, args[0])
			if err != nil {
				return err
			}
			defer restore()
			summary, project, machine, err := hostnameTarget(cmd.Context(), bound, reference)
			if err != nil {
				return err
			}
			if !projectAuthAppAvailable(bound, "") {
				return fmt.Errorf("Machine Tunnels require sc login to an Auth App")
			}
			// A Machine owns at most one dedicated connector.  Selection is
			// deliberately against its recorded value, never a zone-wide DNS
			// search, so an omitted hostname cannot affect another Machine.
			if hostname == "" || strings.ContainsAny(hostname, "*?[") {
				recorded, err := readMachineTunnelHostname(cmd.Context(), bound, summary, project, machine)
				if err != nil {
					return err
				}
				if recorded == "" {
					return nil
				}
				matched, err := filepath.Match(allHostnamePattern(hostname), recorded)
				if err != nil {
					return err
				}
				if !matched {
					return nil
				}
				hostname = recorded
			}
			name, err := authapp.NormalizeMachineHostname(hostname)
			if err != nil {
				return err
			}
			client := authapp.DeviceClient{BaseURL: commandAuthHostname(bound, ""), AuthToken: bound.adminConfig.AuthToken}
			if _, err := client.UnprovisionMachineTunnel(cmd.Context(), authapp.MachineTunnelRequest{Tenant: summary.Tenant, Project: project, Machine: machine, Hostname: name}); err != nil {
				return err
			}
			if err := uninstallMachineTunnel(cmd.Context(), bound, summary.V2IncusProjectName(project), machine); err != nil {
				return err
			}
			payload := map[string]any{"project": project, "machine": machine, "hostname": name, "status": "unpublished"}
			return writeOutput(bound.stdout, opts.output, fmt.Sprintf("Tunnel unpublished: https://%s", name), payload)
		},
	}
	command.Flags().StringVar(&hostname, "hostname", "", "public hostname or wildcard to remove (default: all on this Machine)")
	return command
}

func readMachineTunnelHostname(ctx context.Context, config commandConfig, summary tenant.Summary, project, machine string) (string, error) {
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return "", fmt.Errorf("no Sandcastle-managed Incus config found for remote %q; add one with: sc remote add", config.adminConfig.Remote)
	}
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+summary.V2IncusProjectName(project))
	var current bytes.Buffer
	if err := runner(ctx, []string{"config", "get", machine, meta.KeyV2MachineTunnelHostname}, env, config.stdin, &current, config.stderr); err != nil {
		return "", fmt.Errorf("read Machine Tunnel metadata: %w", err)
	}
	name := strings.TrimSpace(current.String())
	if name == "" {
		return "", nil
	}
	return authapp.NormalizeMachineHostname(name)
}

// uninstallMachineTunnel removes only the files Sandcastle owns. The binary is
// intentionally retained: it may predate Sandcastle or serve another local use.
func uninstallMachineTunnel(ctx context.Context, config commandConfig, incusProject, machine string) error {
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return fmt.Errorf("no Sandcastle-managed Incus config found for remote %q", config.adminConfig.Remote)
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+incusProject)
	run := func(args []string, in io.Reader) error {
		return runner(ctx, args, env, in, config.stdout, config.stderr)
	}
	script := "set -eu; systemctl disable --now sandcastle-cloudflared.service >/dev/null 2>&1 || true; rm -f /etc/default/sandcastle-cloudflared /etc/systemd/system/sandcastle-cloudflared.service; systemctl daemon-reload"
	if err := run([]string{"exec", machine, "--", "sh", "-ceu", script}, nil); err != nil {
		return fmt.Errorf("stop machine tunnel: %w", err)
	}
	// An empty value is semantically absent to DecodeMachine and is safe to
	// repeat. Incus rejects `config unset` when an earlier unpublish already
	// removed the key, which would make an otherwise idempotent lifecycle fail.
	if err := run([]string{"config", "set", machine, meta.KeyV2MachineTunnelHostname + "="}, nil); err != nil {
		return fmt.Errorf("clear machine tunnel record: %w", err)
	}
	return nil
}
