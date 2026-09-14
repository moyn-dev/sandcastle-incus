package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/meta"
)

// Machine Tunnels are deliberately separate from Machine Public Hostnames and
// Public Routes. A connector runs inside the selected Machine and receives
// only its Cloudflare run token, never the account API token used to create it.
func newTunnelCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{Use: "tunnel", Short: "Publish services through a dedicated Cloudflare Tunnel per machine"}
	command.AddCommand(newTunnelPublishCommand(config, opts))
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
	if err := run([]string{"config", "set", machine, meta.KeyV2MachineTunnelHostname, hostname}, nil); err != nil {
		return fmt.Errorf("record machine tunnel: %w", err)
	}
	return nil
}
