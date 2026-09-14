package incusx

import (
	"context"
	"fmt"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

var _ authapp.TailnetPublisher = ZoneMachineServer{}

// Publish installs one explicit TLS site in the Tenant Sidecar. The upstream
// is always the selected Machine's private HTTPS listener; its port is not a
// user-controlled publication parameter.
func (s ZoneMachineServer) Publish(ctx context.Context, p authapp.TailnetPublication) (string, error) {
	if p.TargetPort != 443 {
		return "", fmt.Errorf("tailnet publication upstream must be port 443")
	}
	machines, err := s.ListZoneMachines(ctx)
	if err != nil {
		return "", err
	}
	var target authapp.ZoneMachine
	for _, machine := range machines {
		if machine.Tenant == p.Tenant && machine.Project == p.Project && machine.Name == p.Machine {
			target = machine
			break
		}
	}
	if target.Name == "" || !target.Running || strings.TrimSpace(target.BridgeIPv4) == "" {
		return "", fmt.Errorf("Machine %s:%s is not running with a private IPv4 address", p.Project, p.Machine)
	}
	summaries, err := tenant.ListForPrefix(ctx, s.Store, s.Prefix)
	if err != nil {
		return "", fmt.Errorf("list tenants: %w", err)
	}
	infra := ""
	suffix := ""
	for _, summary := range summaries {
		if summary.Tenant == p.Tenant {
			infra = summary.InfraProject
			suffix = summary.DNSSuffix
			break
		}
	}
	if infra == "" {
		return "", fmt.Errorf("Tenant %s has no infrastructure project", p.Tenant)
	}
	sidecar := s.Server.UseProject(infra)
	if err := execSidecar(sidecar, naming.V2SidecarInstanceName, "mkdir -p /etc/sandcastle/tailnet-publish /etc/caddy/tailnet-publish"); err != nil {
		return "", fmt.Errorf("prepare Tenant Sidecar publication directories: %w", err)
	}
	for _, file := range []struct {
		path, content string
		mode          int
	}{
		{"/etc/sandcastle/tailnet-publish/" + p.Hostname + "/cert.pem", p.CertPEM, 0o644},
		{"/etc/sandcastle/tailnet-publish/" + p.Hostname + "/key.pem", p.KeyPEM, 0o600},
	} {
		if err := sidecar.CreateInstanceFile(naming.V2SidecarInstanceName, file.path[:strings.LastIndex(file.path, "/")], incus.InstanceFileArgs{Type: "directory", Mode: 0o755}); err != nil {
			return "", fmt.Errorf("create certificate directory in %s: %w", infra, err)
		}
		if err := sidecar.CreateInstanceFile(naming.V2SidecarInstanceName, file.path, incus.InstanceFileArgs{Type: "file", Content: strings.NewReader(file.content), Mode: file.mode, WriteMode: "overwrite"}); err != nil {
			return "", fmt.Errorf("write certificate: %w", err)
		}
	}
	// One fragment per hostname keeps publication additive and makes a repeat
	// publish an atomic replacement of that hostname's site only.
	privateHostname := p.Machine + "." + p.Project + "." + suffix
	fragment := fmt.Sprintf("https://%s {\n\ttls /etc/sandcastle/tailnet-publish/%s/cert.pem /etc/sandcastle/tailnet-publish/%s/key.pem\n\treverse_proxy https://%s:443 {\n\t\theader_up Host %s\n\t\ttransport http {\n\t\t\ttls_server_name %s\n\t\t\ttls_insecure_skip_verify\n\t\t}\n\t}\n}\n", p.Hostname, p.Hostname, p.Hostname, target.BridgeIPv4, privateHostname, privateHostname)
	path := "/etc/caddy/tailnet-publish/" + p.Hostname + ".caddy"
	if err := sidecar.CreateInstanceFile(naming.V2SidecarInstanceName, "/etc/caddy/tailnet-publish", incus.InstanceFileArgs{Type: "directory", Mode: 0o755}); err != nil {
		return "", fmt.Errorf("create Caddy directory: %w", err)
	}
	if err := sidecar.CreateInstanceFile(naming.V2SidecarInstanceName, path, incus.InstanceFileArgs{Type: "file", Content: strings.NewReader(fragment), Mode: 0o644, WriteMode: "overwrite"}); err != nil {
		return "", fmt.Errorf("write Caddy route: %w", err)
	}
	script := "set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq caddy; chown root:caddy /etc/sandcastle/tailnet-publish/" + p.Hostname + "/key.pem; chmod 0640 /etc/sandcastle/tailnet-publish/" + p.Hostname + "/key.pem; printf '%s\\n' '{' ' auto_https off' '}' 'import /etc/caddy/tailnet-publish/*.caddy' > /etc/caddy/Caddyfile; caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; systemctl enable caddy; systemctl restart caddy"
	if err := execSidecar(sidecar, naming.V2SidecarInstanceName, script); err != nil {
		return "", fmt.Errorf("configure sidecar Caddy: %w", err)
	}
	out, err := execSidecarCapture(sidecar, naming.V2SidecarInstanceName, "tailscale ip -4 | head -1")
	if err != nil {
		return "", fmt.Errorf("read Tenant Sidecar Tailscale IPv4: %w", err)
	}
	ip := strings.TrimSpace(out)
	if ip == "" {
		return "", fmt.Errorf("Tenant Sidecar has no Tailscale IPv4")
	}
	return ip, nil
}
