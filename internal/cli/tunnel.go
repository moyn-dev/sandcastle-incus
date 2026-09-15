package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
			if err := recordMachineTunnelHostname(cmd.Context(), config, summary, project, machine, name, true, false); err != nil {
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
	unitName := machineTunnelUnitName(hostname)
	defaultsPath := "/etc/default/" + unitName
	unitPath := "/etc/systemd/system/" + unitName + ".service"
	if err := run([]string{"exec", machine, "--", "mkdir", "-p", "/etc/default"}, nil); err != nil {
		return fmt.Errorf("prepare machine tunnel: %w", err)
	}
	if err := run([]string{"file", "push", "-", machine + defaultsPath}, strings.NewReader("TUNNEL_TOKEN="+token+"\n")); err != nil {
		return fmt.Errorf("install machine tunnel token: %w", err)
	}
	unit := "[Unit]\nDescription=Sandcastle Machine Cloudflare Tunnel (" + hostname + ")\nAfter=network-online.target\n\n[Service]\nEnvironmentFile=" + defaultsPath + "\nExecStart=/usr/local/bin/cloudflared tunnel --no-autoupdate run\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := run([]string{"file", "push", "-", machine + unitPath}, strings.NewReader(unit)); err != nil {
		return fmt.Errorf("install machine tunnel service: %w", err)
	}
	script := "set -eu; if ! test -x /usr/local/bin/cloudflared; then case $(dpkg --print-architecture) in amd64) a=amd64;; arm64) a=arm64;; *) echo unsupported architecture >&2; exit 1;; esac; curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$a -o /usr/local/bin/cloudflared; chmod 755 /usr/local/bin/cloudflared; fi; systemctl daemon-reload; systemctl enable --now " + unitName + ".service"
	if err := run([]string{"exec", machine, "--", "sh", "-ceu", script}, nil); err != nil {
		return fmt.Errorf("start machine tunnel: %w", err)
	}
	return nil
}

func machineTunnelUnitName(hostname string) string {
	return "sandcastle-cloudflared-" + strings.ReplaceAll(hostname, ".", "-")
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
			// Selection is deliberately against this Machine's recorded values,
			// never a zone-wide DNS search, so omission/wildcards cannot affect a
			// connector owned by another Machine.
			if hostname == "" || strings.ContainsAny(hostname, "*?[") {
				recorded, err := readMachineTunnelHostnames(cmd.Context(), bound, summary, project, machine)
				if err != nil {
					return err
				}
				if len(recorded) == 0 {
					return nil
				}
				return unpublishMachineTunnels(cmd.Context(), bound, opts, summary, project, machine, recorded, hostname)
			}
			name, err := authapp.NormalizeMachineHostname(hostname)
			if err != nil {
				return err
			}
			client := authapp.DeviceClient{BaseURL: commandAuthHostname(bound, ""), AuthToken: bound.adminConfig.AuthToken}
			if _, err := client.UnprovisionMachineTunnel(cmd.Context(), authapp.MachineTunnelRequest{Tenant: summary.Tenant, Project: project, Machine: machine, Hostname: name}); err != nil {
				return err
			}
			legacy, err := machineTunnelLegacyHostname(cmd.Context(), bound, summary, project, machine)
			if err != nil {
				return err
			}
			if err := uninstallMachineTunnel(cmd.Context(), bound, summary.V2IncusProjectName(project), machine, name, legacy == name); err != nil {
				return err
			}
			if err := recordMachineTunnelHostname(cmd.Context(), bound, summary, project, machine, name, false, legacy == name); err != nil {
				return err
			}
			payload := map[string]any{"project": project, "machine": machine, "hostname": name, "status": "unpublished"}
			return writeOutput(bound.stdout, opts.output, fmt.Sprintf("Tunnel unpublished: https://%s", name), payload)
		},
	}
	command.Flags().StringVar(&hostname, "hostname", "", "public hostname or wildcard to remove (default: all on this Machine)")
	return command
}

// unpublishMachineTunnels removes every selected, Machine-owned connector.
// It continues after an individual failure so an omitted hostname converges as
// much of the collection as possible and reports the exact remaining names.
func unpublishMachineTunnels(ctx context.Context, config commandConfig, opts *rootOptions, summary tenant.Summary, project, machine string, recorded []string, pattern string) error {
	selected := make([]string, 0, len(recorded))
	for _, name := range recorded {
		matched, err := matchPublicationHostname(pattern, name)
		if err != nil {
			return err
		}
		if matched {
			selected = append(selected, name)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	client := authapp.DeviceClient{BaseURL: commandAuthHostname(config, ""), AuthToken: config.adminConfig.AuthToken}
	var failed []string
	for _, name := range selected {
		if _, err := client.UnprovisionMachineTunnel(ctx, authapp.MachineTunnelRequest{Tenant: summary.Tenant, Project: project, Machine: machine, Hostname: name}); err != nil {
			failed = append(failed, name+": "+err.Error())
			continue
		}
		legacy, err := machineTunnelLegacyHostname(ctx, config, summary, project, machine)
		if err != nil {
			failed = append(failed, name+": "+err.Error())
			continue
		}
		if err := uninstallMachineTunnel(ctx, config, summary.V2IncusProjectName(project), machine, name, legacy == name); err != nil {
			failed = append(failed, name+": "+err.Error())
			continue
		}
		if err := recordMachineTunnelHostname(ctx, config, summary, project, machine, name, false, legacy == name); err != nil {
			failed = append(failed, name+": "+err.Error())
			continue
		}
		if err := writeOutput(config.stdout, opts.output, fmt.Sprintf("Tunnel unpublished: https://%s", name), map[string]any{"project": project, "machine": machine, "hostname": name, "status": "unpublished"}); err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d tunnel(s) could not be unpublished: %s", len(failed), strings.Join(failed, "; "))
	}
	return nil
}

func readMachineTunnelHostnames(ctx context.Context, config commandConfig, summary tenant.Summary, project, machine string) ([]string, error) {
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return nil, fmt.Errorf("no Sandcastle-managed Incus config found for remote %q; add one with: sc remote add", config.adminConfig.Remote)
	}
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+summary.V2IncusProjectName(project))
	read := func(key string) (string, error) {
		var current bytes.Buffer
		if err := runner(ctx, []string{"config", "get", machine, key}, env, config.stdin, &current, config.stderr); err != nil {
			return "", err
		}
		return current.String(), nil
	}
	list, err := read(meta.KeyV2MachineTunnelHostnames)
	if err != nil {
		return nil, fmt.Errorf("read Machine Tunnel metadata: %w", err)
	}
	legacy, err := read(meta.KeyV2MachineTunnelHostname)
	if err != nil {
		return nil, fmt.Errorf("read Machine Tunnel metadata: %w", err)
	}
	names := meta.ParsePublicHostnames(list + "," + legacy)
	return names, nil
}

func machineTunnelLegacyHostname(ctx context.Context, config commandConfig, summary tenant.Summary, project, machine string) (string, error) {
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return "", fmt.Errorf("no Sandcastle-managed Incus config found for remote %q", config.adminConfig.Remote)
	}
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+summary.V2IncusProjectName(project))
	var out bytes.Buffer
	if err := runner(ctx, []string{"config", "get", machine, meta.KeyV2MachineTunnelHostname}, env, config.stdin, &out, config.stderr); err != nil {
		return "", fmt.Errorf("read legacy Machine Tunnel metadata: %w", err)
	}
	names := meta.ParsePublicHostnames(out.String())
	if len(names) == 0 {
		return "", nil
	}
	return names[0], nil
}

func recordMachineTunnelHostname(ctx context.Context, config commandConfig, summary tenant.Summary, project, machine, hostname string, add, clearLegacy bool) error {
	names, err := readMachineTunnelHostnames(ctx, config, summary, project, machine)
	if err != nil {
		return err
	}
	want := make([]string, 0, len(names)+1)
	for _, name := range names {
		if name != hostname {
			want = append(want, name)
		}
	}
	if add {
		want = append(want, hostname)
	}
	sort.Strings(want)
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return fmt.Errorf("no Sandcastle-managed Incus config found for remote %q", config.adminConfig.Remote)
	}
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+summary.V2IncusProjectName(project))
	args := []string{"config", "set", machine, meta.KeyV2MachineTunnelHostnames + "=" + strings.Join(want, ",")}
	if clearLegacy {
		args = append(args, meta.KeyV2MachineTunnelHostname+"=")
	}
	if err := runner(ctx, args, env, config.stdin, config.stdout, config.stderr); err != nil {
		return fmt.Errorf("record Machine Tunnel collection: %w", err)
	}
	return nil
}

func matchPublicationHostname(pattern, hostname string) (bool, error) {
	if pattern == "" {
		return true, nil
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == hostname, nil
	}
	return filepath.Match(pattern, hostname)
}

// uninstallMachineTunnel removes only the files Sandcastle owns. The binary is
// intentionally retained: it may predate Sandcastle or serve another local use.
func uninstallMachineTunnel(ctx context.Context, config commandConfig, incusProject, machine, hostname string, legacy bool) error {
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
	unit := machineTunnelUnitName(hostname)
	script := "set -eu; systemctl disable --now " + unit + ".service >/dev/null 2>&1 || true; rm -f /etc/default/" + unit + " /etc/systemd/system/" + unit + ".service"
	if legacy {
		script += "; systemctl disable --now sandcastle-cloudflared.service >/dev/null 2>&1 || true; rm -f /etc/default/sandcastle-cloudflared /etc/systemd/system/sandcastle-cloudflared.service"
	}
	script += "; systemctl daemon-reload"
	if err := run([]string{"exec", machine, "--", "sh", "-ceu", script}, nil); err != nil {
		return fmt.Errorf("stop machine tunnel: %w", err)
	}
	return nil
}
