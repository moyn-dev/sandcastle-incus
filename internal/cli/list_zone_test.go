package cli

import (
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// A zone-mode machine (ADR-0027) answers at exactly its Machine Public
// Hostname; a private-mode one keeps the ADR-0018 names, alias included.
func TestV2MachineNamesZoneMode(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme"}
	if got := v2MachineNames(summary, "default", "web", ""); strings.Join(got, ",") != "web.default.acme,web.acme" {
		t.Fatalf("private default-project names = %v", got)
	}
	if got := v2MachineNames(summary, "zp", "web", ""); strings.Join(got, ",") != "web.zp.acme" {
		t.Fatalf("private names = %v", got)
	}
	if got := v2MachineNames(summary, "default", "web", "web.baum.hase.de"); strings.Join(got, ",") != "web.baum.hase.de" {
		t.Fatalf("zone names = %v, want only the public hostname", got)
	}
	// A zone name needs no DNS suffix; a private one still does.
	if got := v2MachineNames(tenant.Summary{}, "zp", "web", "web.baum.hase.de"); len(got) != 1 {
		t.Fatalf("zone names without suffix = %v", got)
	}
	if got := v2MachineNames(tenant.Summary{}, "zp", "web", ""); got != nil {
		t.Fatalf("private names without suffix = %v, want nil", got)
	}
}

func TestMachineFQDNZoneMode(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme.sandcastle.dev"}
	if got := machineFQDN(summary, meta.Machine{Project: "zp", Name: "web"}); got != "web.zp.acme.sandcastle.dev" {
		t.Fatalf("private FQDN = %q", got)
	}
	if got := machineFQDN(summary, meta.Machine{Project: "zp", Name: "web", PublicHostname: "web.baum.hase.de"}); got != "web.baum.hase.de" {
		t.Fatalf("zone FQDN = %q", got)
	}
}

// CERT column mapping, spec §1.5: private → "-"; pending/issued (and a zone
// machine the reconciler has not stamped yet) → pending; installed/renewing →
// ok; failed:* → failed.
func TestMachineCertCell(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    meta.Machine
		want string
	}{
		{"private", meta.Machine{}, "-"},
		{"private ignores stray state", meta.Machine{CertState: "installed"}, "-"},
		{"zone unstamped", meta.Machine{PublicHostname: "web.baum.hase.de"}, "pending"},
		{"pending", meta.Machine{PublicHostname: "web.baum.hase.de", CertState: "pending"}, "pending"},
		{"issued", meta.Machine{PublicHostname: "web.baum.hase.de", CertState: "issued"}, "pending"},
		{"installed", meta.Machine{PublicHostname: "web.baum.hase.de", CertState: "installed"}, "ok"},
		{"renewing", meta.Machine{PublicHostname: "web.baum.hase.de", CertState: "renewing"}, "ok"},
		{"failed", meta.Machine{PublicHostname: "web.baum.hase.de", CertState: "failed:rate-limited"}, "failed"},
		{"unknown verbatim", meta.Machine{PublicHostname: "web.baum.hase.de", CertState: "weird"}, "weird"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := machineCertCell(tc.m); got != tc.want {
				t.Fatalf("machineCertCell = %q, want %q", got, tc.want)
			}
		})
	}
}

// Golden table for `sc ls`: an unstamped (private-mode) machine renders
// exactly as before, plus a "-" CERT cell; a stamped zone-mode machine shows
// its public name and certificate state. Same rows, same fixture, through
// every table variant (sc ls, the cross-install sweep, the admin listing).
func TestFormatMachineListZoneModeGolden(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme.sandcastle.dev"}
	private := meta.Machine{Project: "gbrain", Name: "web", Type: "container", PrivateIP: "10.1.0.9", Running: true}
	zone := meta.Machine{Project: "zp", Name: "api", Type: "container", PrivateIP: "10.1.0.12", Running: true,
		PublicHostname: "api.baum.hase.de", CertState: "installed", CertNotAfter: "2026-12-01T00:00:00Z"}

	got := formatMachineList(listPayload{Tenant: summary, AllProjects: true, Machines: []meta.Machine{private, zone}}, listRenderOptions{})
	want := strings.Join([]string{
		"the current install",
		"PROJECT  MACHINE  TYPE  FQDN                            CERT  IP         CREATED  STATE",
		"gbrain   web      CT    web.gbrain.acme.sandcastle.dev  -     10.1.0.9   -        running",
		"zp       api      CT    api.baum.hase.de                ok    10.1.0.12  -        running",
	}, "\n")
	if got != want {
		t.Fatalf("sc ls table:\n%s\nwant:\n%s", got, want)
	}

	multi := formatMultiMachineList(multiListPayload{RemotePattern: "*", Remotes: []listPayload{
		{Remote: "obelix", Tenant: summary, AllProjects: true, Machines: []meta.Machine{private, zone}},
	}})
	for _, line := range []string{
		"REMOTE  PROJECT  MACHINE  TYPE  FQDN                            CERT  IP         CREATED  STATE",
		"obelix  gbrain   web      CT    web.gbrain.acme.sandcastle.dev  -     10.1.0.9   -        running",
		"obelix  zp       api      CT    api.baum.hase.de                ok    10.1.0.12  -        running",
	} {
		if !strings.Contains(multi, line) {
			t.Fatalf("cross-install table missing %q:\n%s", line, multi)
		}
	}

	admin := formatTenantResources(tenantResourcesPayload{Tenant: summary, Machines: []meta.Machine{private, zone}})
	for _, line := range []string{
		"PROJECT  MACHINE  TYPE  FQDN                            CERT  IP         CREATED  STATE",
		"gbrain   web      CT    web.gbrain.acme.sandcastle.dev  -     10.1.0.9   -        running",
		"zp       api      CT    api.baum.hase.de                ok    10.1.0.12  -        running",
	} {
		if !strings.Contains(admin, line) {
			t.Fatalf("admin resources table missing %q:\n%s", line, admin)
		}
	}
}

// The unstamped row must be byte-identical whether or not the machine carries
// a stray cert-state: private mode never shows certificate state.
func TestFormatMachineListPrivateRowUnaffectedByCertKeys(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme.sandcastle.dev"}
	plain := meta.Machine{Project: "gbrain", Name: "web", PrivateIP: "10.1.0.9", Running: true}
	stray := plain
	stray.CertState = "installed"
	a := formatMachineList(listPayload{Tenant: summary, AllProjects: true, Machines: []meta.Machine{plain}}, listRenderOptions{})
	b := formatMachineList(listPayload{Tenant: summary, AllProjects: true, Machines: []meta.Machine{stray}}, listRenderOptions{})
	if a != b {
		t.Fatalf("private row changed by a stray cert-state:\n%s\n---\n%s", a, b)
	}
	if !strings.Contains(a, "web.gbrain.acme.sandcastle.dev  -  ") {
		t.Fatalf("private row lacks the '-' CERT cell:\n%s", a)
	}
}
