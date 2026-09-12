package cli

import (
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/incusx"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Golden output of `sc create` (spec §2.3). The private-mode lines are the
// pre-ADR-0027 output, byte for byte; the zone-mode variants replace the
// DNS: line with the Public name: line and, for --bare, name Let's Encrypt.
func TestFormatCreateMachineV2Golden(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme"}
	base := func(publicHostname string) incusx.CreateMachineV2Result {
		return incusx.CreateMachineV2Result{Name: "web", Type: "container", Project: "sc2-acme-zp", Image: "images:debian/13/cloud", PrivateIP: "10.249.7.9", LoginUser: "dev", PublicHostname: publicHostname}
	}
	for _, tc := range []struct {
		name    string
		project string
		result  incusx.CreateMachineV2Result
		dryRun  bool
		outcome machineCertificateOutcome
		want    string
	}{
		{
			name: "private with IP", project: "zp", result: base(""),
			want: "Machine web created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9   DNS: web.zp.acme (auto-registers within seconds)\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			name: "private default project alias, still booting", project: "default",
			result: func() incusx.CreateMachineV2Result { r := base(""); r.PrivateIP = ""; return r }(),
			want: "Machine web created (container, project default, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"Still booting — no IP leased yet. Watch it with: sc list\n" +
				"DNS: web.default.acme (also: web.acme) (auto-registers after boot)",
		},
		{
			name: "private dry-run", project: "zp", result: base(""), dryRun: true,
			want: "Machine web would be created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"DNS: web.zp.acme (auto-registers after boot)",
		},
		{
			name: "private bare", project: "zp",
			result: func() incusx.CreateMachineV2Result { r := base(""); r.Bare = true; r.LoginUser = ""; return r }(),
			want: "Machine web created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9   DNS: web.zp.acme (auto-registers within seconds)\n" +
				"HTTPS: https://web.zp.acme   (Caddy with the tenant-CA leaf, proxying to localhost:3000)\n" +
				"Bare: no login user, no sshd — `sc connect` will not work; get a shell with: sc incus exec web -- /bin/sh",
		},
		{
			name: "private dev image", project: "zp",
			result: func() incusx.CreateMachineV2Result { r := base(""); r.DevImage = true; return r }(),
			want: "Machine web created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9   DNS: web.zp.acme (auto-registers within seconds)\n" +
				"Dev Image: no Caddy/TLS ingress — SSH only.\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			name: "zone with IP", project: "zp", result: base("web.baum.hase.de"), outcome: machineCertificateOutcome{State: "pending"},
			want: "Machine web created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status zp)\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			name: "zone still booting, auth app unreachable", project: "zp",
			result:  func() incusx.CreateMachineV2Result { r := base("web.baum.hase.de"); r.PrivateIP = ""; return r }(),
			outcome: machineCertificateOutcome{Reason: "auth-app-unreachable", Message: "timed out"},
			want: "Machine web created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"Still booting — no IP leased yet. Watch it with: sc list\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending: Auth App unreachable — retried by the reconciler)",
		},
		{
			name: "zone rate-limited", project: "zp", result: base("web.baum.hase.de"),
			outcome: machineCertificateOutcome{State: "pending", Reason: "rate-limited", Message: "50 certificates per registered domain per week"},
			want: "Machine web created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending: rate-limited — 50 certificates per registered domain per week)\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			// --dry-run makes no certificate request: the default pending
			// text, whatever outcome a caller might hand in. In the default
			// project the private alias is NOT shown — a zone machine has
			// exactly one name.
			name: "zone dry-run in default project", project: "default", result: base("web.baum.hase.de"), dryRun: true,
			outcome: machineCertificateOutcome{Reason: "auth-app-unreachable"},
			want: "Machine web would be created (container, project default, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status default)",
		},
		{
			name: "zone bare", project: "zp",
			result: func() incusx.CreateMachineV2Result {
				r := base("web.baum.hase.de")
				r.Bare = true
				r.LoginUser = ""
				return r
			}(),
			outcome: machineCertificateOutcome{State: "pending"},
			want: "Machine web created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status zp)\n" +
				"HTTPS: https://web.baum.hase.de   (Let's Encrypt, certificate pending)\n" +
				"Bare: no login user, no sshd — `sc connect` will not work; get a shell with: sc incus exec web -- /bin/sh",
		},
		{
			name: "zone bare dry-run", project: "zp", dryRun: true,
			result: func() incusx.CreateMachineV2Result {
				r := base("web.baum.hase.de")
				r.Bare = true
				r.LoginUser = ""
				return r
			}(),
			want: "Machine web would be created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status zp)\n" +
				"Bare: no login user, no SSH key, no sshd — HTTPS only.",
		},
		{
			// A Dev Image machine has no Caddy: public name, no certificate,
			// and the outcome is irrelevant (no request is made).
			name: "zone dev image", project: "zp",
			result: func() incusx.CreateMachineV2Result { r := base("web.baum.hase.de"); r.DevImage = true; return r }(),
			want: "Machine web created (container, project zp, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"Public name: web.baum.hase.de (A record pending; no Caddy — no certificate)\n" +
				"Dev Image: no Caddy/TLS ingress — SSH only.\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := formatCreateMachineV2(summary, tc.project, tc.result, tc.dryRun, tc.outcome)
			if got != tc.want {
				t.Fatalf("output:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

// The HostKeyAlias `sc connect` hands ssh is the first owned name: the
// Machine Private Hostname for a private machine, the Machine Public
// Hostname — and nothing else — for a zone machine.
func TestV2MachineNamesHostKeyAlias(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme"}
	if names := v2MachineNames(summary, "zp", "web", ""); names[0] != "web.zp.acme" {
		t.Fatalf("private alias = %q", names[0])
	}
	names := v2MachineNames(summary, "zp", "web", "web.baum.hase.de")
	if len(names) != 1 || names[0] != "web.baum.hase.de" {
		t.Fatalf("zone names = %v", names)
	}
}
