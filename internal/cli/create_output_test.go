package cli

import (
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Golden output of `sc create` (spec §2.3, ADR-0028). The private-mode lines
// are the pre-ADR-0027 output, byte for byte; a machine in a domain project
// replaces the DNS: line with one Public name: line per public name and, for
// --bare, names Let's Encrypt; a machine with explicit hostnames in a
// project WITHOUT a domain keeps its DNS: line and adds the Public name:
// lines.
func TestFormatCreateMachineV2Golden(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme", Projects: []meta.Project{
		{Name: "zp", Domain: "baum.hase.de"},
		{Name: "default", Domain: "baum.hase.de"},
		{Name: "plain"},
	}}
	base := func(publicHostnames ...string) incusx.CreateMachineV2Result {
		r := incusx.CreateMachineV2Result{Name: "web", Type: "container", Project: "sc2-acme-zp", Image: "images:debian/13/cloud", PrivateIP: "10.249.7.9", LoginUser: "dev", PublicHostnames: publicHostnames}
		if len(publicHostnames) > 0 {
			r.PublicHostname = publicHostnames[0]
		}
		return r
	}
	pending := map[string]machineCertificateOutcome{"web.baum.hase.de": {State: "pending"}}
	for _, tc := range []struct {
		name     string
		project  string
		result   incusx.CreateMachineV2Result
		dryRun   bool
		outcomes map[string]machineCertificateOutcome
		want     string
	}{
		{
			name: "private with IP", project: "plain", result: base(),
			want: "Machine obelix:acme:plain:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9   DNS: web.plain.acme (auto-registers within seconds)\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			name: "private default project alias, still booting", project: "default",
			result: func() incusx.CreateMachineV2Result { r := base(); r.PrivateIP = ""; return r }(),
			// The default project of THIS summary has a domain, but the
			// machine carries no public name (unstamped): the private line
			// with the short alias is all there is to print.
			want: "Machine obelix:acme:default:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"Still booting — no IP leased yet. Watch it with: sc list\n" +
				"DNS: web.default.acme (also: web.acme) (auto-registers after boot)",
		},
		{
			name: "private dry-run", project: "plain", result: base(), dryRun: true,
			want: "Machine obelix:acme:plain:web would be created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"DNS: web.plain.acme (auto-registers after boot)",
		},
		{
			name: "private bare", project: "plain",
			result: func() incusx.CreateMachineV2Result { r := base(); r.Bare = true; r.LoginUser = ""; return r }(),
			want: "Machine obelix:acme:plain:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9   DNS: web.plain.acme (auto-registers within seconds)\n" +
				"HTTPS: https://web.plain.acme   (Caddy with the tenant-CA leaf, proxying to localhost:3000)\n" +
				"Bare: no login user, no sshd — `sc connect` will not work; get a shell with: sc incus exec web -- /bin/sh",
		},
		{
			name: "private dev image", project: "plain",
			result: func() incusx.CreateMachineV2Result { r := base(); r.DevImage = true; return r }(),
			want: "Machine obelix:acme:plain:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9   DNS: web.plain.acme (auto-registers within seconds)\n" +
				"Dev Image: no Caddy/TLS ingress — SSH only.\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			// ADR-0028: the private DNS: line is printed for every machine;
			// the public names follow it, one line each.
			name: "derived with IP", project: "zp", result: base("web.baum.hase.de"), outcomes: pending,
			want: "Machine obelix:acme:zp:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"DNS: web.zp.acme (auto-registers within seconds)\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status zp)\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			name: "derived still booting, auth app unreachable", project: "zp",
			result:   func() incusx.CreateMachineV2Result { r := base("web.baum.hase.de"); r.PrivateIP = ""; return r }(),
			outcomes: map[string]machineCertificateOutcome{"web.baum.hase.de": {Reason: "auth-app-unreachable", Message: "timed out"}},
			want: "Machine obelix:acme:zp:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"Still booting — no IP leased yet. Watch it with: sc list\n" +
				"DNS: web.zp.acme (auto-registers after boot)\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending: Auth App unreachable — retried by the reconciler)",
		},
		{
			name: "derived rate-limited", project: "zp", result: base("web.baum.hase.de"),
			outcomes: map[string]machineCertificateOutcome{"web.baum.hase.de": {State: "pending", Reason: "rate-limited", Message: "50 certificates per registered domain per week"}},
			want: "Machine obelix:acme:zp:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"DNS: web.zp.acme (auto-registers within seconds)\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending: rate-limited — 50 certificates per registered domain per week)\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			// --dry-run makes no certificate request: the default pending
			// text, whatever outcome a caller might hand in. The default
			// project keeps its short alias — the private name is served
			// whatever public names the machine has.
			name: "derived dry-run in default project", project: "default", result: base("web.baum.hase.de"), dryRun: true,
			outcomes: map[string]machineCertificateOutcome{"web.baum.hase.de": {Reason: "auth-app-unreachable"}},
			want: "Machine obelix:acme:default:web would be created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"DNS: web.default.acme (also: web.acme) (auto-registers after boot)\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status default)",
		},
		{
			// A bare machine serves its private name with the tenant-CA leaf
			// from the first boot and its public names once their
			// certificates land.
			name: "derived bare", project: "zp",
			result: func() incusx.CreateMachineV2Result {
				r := base("web.baum.hase.de")
				r.Bare = true
				r.LoginUser = ""
				return r
			}(),
			outcomes: pending,
			want: "Machine obelix:acme:zp:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"DNS: web.zp.acme (auto-registers within seconds)\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status zp)\n" +
				"HTTPS: https://web.zp.acme   (Caddy with the tenant-CA leaf, proxying to localhost:3000)\n" +
				"HTTPS (public): https://web.baum.hase.de   (Let's Encrypt; served once the certificate lands)\n" +
				"Bare: no login user, no sshd — `sc connect` will not work; get a shell with: sc incus exec web -- /bin/sh",
		},
		{
			name: "derived bare dry-run", project: "zp", dryRun: true,
			result: func() incusx.CreateMachineV2Result {
				r := base("web.baum.hase.de")
				r.Bare = true
				r.LoginUser = ""
				return r
			}(),
			want: "Machine obelix:acme:zp:web would be created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"DNS: web.zp.acme (auto-registers after boot)\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status zp)\n" +
				"Bare: no login user, no SSH key, no sshd — HTTPS only.",
		},
		{
			// A Dev Image machine has no Caddy: public name, no certificate,
			// and the outcome is irrelevant (no request is made).
			name: "derived dev image", project: "zp",
			result: func() incusx.CreateMachineV2Result { r := base("web.baum.hase.de"); r.DevImage = true; return r }(),
			want: "Machine obelix:acme:zp:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"DNS: web.zp.acme (auto-registers within seconds)\n" +
				"Public name: web.baum.hase.de (A record pending; no Caddy — no certificate)\n" +
				"Dev Image: no Caddy/TLS ingress — SSH only.\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			// ADR-0028: derived + explicit names, one line each, in the sorted
			// order the instance records them; each line carries its own
			// certificate outcome (the explicit one came from the claim).
			name: "mixed: derived + explicit hostnames", project: "zp", result: base("web.baum.hase.de", "web12.tc42.uk"),
			outcomes: map[string]machineCertificateOutcome{"web.baum.hase.de": {State: "pending"}, "web12.tc42.uk": {State: "issued"}},
			want: "Machine obelix:acme:zp:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"DNS: web.zp.acme (auto-registers within seconds)\n" +
				"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status zp)\n" +
				"Public name: web12.tc42.uk (A record pending, certificate retained, installing — see: sc project status zp)\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			// Explicit-only: a project without a domain, one explicit name
			// under the DNS: line.
			name: "explicit-only in a private project", project: "plain",
			result: func() incusx.CreateMachineV2Result {
				r := base("web12.tc42.uk")
				r.Project = "sc2-acme-plain"
				return r
			}(),
			outcomes: map[string]machineCertificateOutcome{"web12.tc42.uk": {State: "pending"}},
			want: "Machine obelix:acme:plain:web created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"IP: 10.249.7.9\n" +
				"DNS: web.plain.acme (auto-registers within seconds)\n" +
				"Public name: web12.tc42.uk (A record pending, certificate pending — see: sc project status plain)\n" +
				"SSH: ssh dev@10.249.7.9   (cloud-init may still be installing sshd)",
		},
		{
			name: "explicit-only in a private project, dry-run", project: "plain", dryRun: true,
			result: func() incusx.CreateMachineV2Result {
				r := base("web12.tc42.uk")
				r.Project = "sc2-acme-plain"
				return r
			}(),
			want: "Machine obelix:acme:plain:web would be created (container, image images:debian/13/cloud).\n" +
				"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
				"DNS: web.plain.acme (auto-registers after boot)\n" +
				"Public name: web12.tc42.uk (A record pending, certificate pending — see: sc project status plain)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := formatCreateMachineV2("obelix", summary, tc.project, tc.result, tc.dryRun, tc.outcomes)
			if got != strings.TrimRight(tc.want, "\n") {
				t.Fatalf("output:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

// The default project's short alias is still printed when the project has no
// domain (pre-ADR-0027 output, byte for byte).
func TestFormatCreateMachineV2DefaultProjectAlias(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme"}
	result := incusx.CreateMachineV2Result{Name: "web", Type: "container", Project: "sc2-acme-default", Image: "images:debian/13/cloud", LoginUser: "dev"}
	got := formatCreateMachineV2("obelix", summary, "default", result, false, nil)
	want := "Machine obelix:acme:default:web created (container, image images:debian/13/cloud).\n" +
		"Storage: shared /workspace, machine-local /home (add --home-share for a shared /home).\n" +
		"Still booting — no IP leased yet. Watch it with: sc list\n" +
		"DNS: web.default.acme (also: web.acme) (auto-registers after boot)"
	if got != want {
		t.Fatalf("output:\n%s\nwant:\n%s", got, want)
	}
}

// The HostKeyAlias `sc connect` hands ssh is the first owned name: the
// Machine Private Hostname, whatever public names the machine also carries
// (ADR-0028). The known_hosts line carries the private name(s) then every
// public name — derived-only, explicit-only and mixed alike; the default
// project's short alias sits between them.
func TestV2MachineNamesHostKeyAlias(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme"}
	for _, tc := range []struct {
		project string
		public  []string
		want    string
	}{
		{"zp", nil, "web.zp.acme"},
		{"zp", []string{"web.baum.hase.de"}, "web.zp.acme,web.baum.hase.de"},
		{"plain", []string{"web12.tc42.uk"}, "web.plain.acme,web12.tc42.uk"},
		{"zp", []string{"web.baum.hase.de", "web12.tc42.uk"}, "web.zp.acme,web.baum.hase.de,web12.tc42.uk"},
		{"default", []string{"web.baum.hase.de", " ", "web12.tc42.uk"}, "web.default.acme,web.acme,web.baum.hase.de,web12.tc42.uk"},
	} {
		names := v2MachineNames(summary, tc.project, "web", tc.public)
		if strings.Join(names, ",") != tc.want {
			t.Fatalf("%s %v: names = %v, want %s", tc.project, tc.public, names, tc.want)
		}
		if names[0] != "web."+tc.project+".acme" {
			t.Fatalf("HostKeyAlias = %q, want the private name", names[0])
		}
	}
	// No DNS suffix: no private name, so only the public names remain.
	if names := v2MachineNames(tenant.Summary{Tenant: "acme"}, "zp", "web", []string{"web12.tc42.uk"}); strings.Join(names, ",") != "web12.tc42.uk" {
		t.Fatalf("no-suffix names = %v", names)
	}
}
