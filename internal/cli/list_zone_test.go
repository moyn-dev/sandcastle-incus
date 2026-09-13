package cli

import (
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Every machine answers at its ADR-0018 private names (alias included in the
// default project) AND at every Machine Public Hostname (ADR-0028).
func TestV2MachineNamesZoneMode(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme"}
	if got := v2MachineNames(summary, "default", "web", nil); strings.Join(got, ",") != "web.default.acme,web.acme" {
		t.Fatalf("private default-project names = %v", got)
	}
	if got := v2MachineNames(summary, "zp", "web", nil); strings.Join(got, ",") != "web.zp.acme" {
		t.Fatalf("private names = %v", got)
	}
	if got := v2MachineNames(summary, "default", "web", []string{"web.baum.hase.de"}); strings.Join(got, ",") != "web.default.acme,web.acme,web.baum.hase.de" {
		t.Fatalf("zone names = %v, want private names then the public hostname", got)
	}
	// Public names need no DNS suffix; without one only they remain.
	if got := v2MachineNames(tenant.Summary{}, "zp", "web", []string{"web.baum.hase.de", "web12.tc42.uk"}); strings.Join(got, ",") != "web.baum.hase.de,web12.tc42.uk" {
		t.Fatalf("zone names without suffix = %v", got)
	}
	if got := v2MachineNames(tenant.Summary{}, "zp", "web", nil); got != nil {
		t.Fatalf("private names without suffix = %v, want nil", got)
	}
}

// The FQDN column shows the first public name and "(+N)" for the rest
// (ADR-0028); a machine without public names shows its private name.
func TestMachineFQDNZoneMode(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme.sandcastle.dev"}
	if got := machineFQDN(summary, meta.Machine{Project: "zp", Name: "web"}); got != "web.zp.acme.sandcastle.dev" {
		t.Fatalf("private FQDN = %q", got)
	}
	if got := machineFQDN(summary, meta.Machine{Project: "zp", Name: "web", PublicHostname: "web.baum.hase.de", PublicHostnames: []string{"web.baum.hase.de"}}); got != "web.baum.hase.de" {
		t.Fatalf("zone FQDN = %q", got)
	}
	if got := machineFQDN(summary, meta.Machine{Project: "zp", Name: "web", PublicHostnames: []string{"web.baum.hase.de", "web12.tc42.uk", "www.web12.tc42.uk"}}); got != "web.baum.hase.de (+2)" {
		t.Fatalf("multi-name FQDN = %q", got)
	}
	// A legacy cache payload with only the single field still renders.
	if got := machineFQDN(summary, meta.Machine{Project: "zp", Name: "web", PublicHostname: "web.baum.hase.de"}); got != "web.baum.hase.de" {
		t.Fatalf("single-field FQDN = %q", got)
	}
}

// CERT column mapping, spec §1.5: no public name → "-"; pending/issued (and a
// machine the reconciler has not stamped yet) → pending; installed/renewing →
// ok; failed:* → failed.
func TestMachineCertCell(t *testing.T) {
	zone := func(state string) meta.Machine {
		return meta.Machine{PublicHostname: "web.baum.hase.de", PublicHostnames: []string{"web.baum.hase.de"}, CertState: state}
	}
	for _, tc := range []struct {
		name string
		m    meta.Machine
		want string
	}{
		{"private", meta.Machine{}, "-"},
		{"private ignores stray state", meta.Machine{CertState: "installed"}, "-"},
		{"zone unstamped", zone(""), "pending"},
		{"pending", zone("pending"), "pending"},
		{"issued", zone("issued"), "pending"},
		{"installed", zone("installed"), "ok"},
		{"renewing", zone("renewing"), "ok"},
		{"failed", zone("failed:rate-limited"), "failed"},
		{"unknown verbatim", zone("weird"), "weird"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := machineCertCell(tc.m); got != tc.want {
				t.Fatalf("machineCertCell = %q, want %q", got, tc.want)
			}
		})
	}
}

// Golden table for `sc ls`: an unstamped machine renders exactly as before,
// plus a "-" CERT cell; a machine with public names shows the first and a
// "(+N)" count with its certificate state. Same rows, same fixture, through
// every table variant (sc ls, the cross-install sweep, the admin listing).
func TestFormatMachineListZoneModeGolden(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme.sandcastle.dev"}
	private := meta.Machine{Project: "gbrain", Name: "web", Type: "container", PrivateIP: "10.1.0.9", Running: true}
	zone := meta.Machine{Project: "zp", Name: "api", Type: "container", PrivateIP: "10.1.0.12", Running: true,
		PublicHostname: "api.baum.hase.de", PublicHostnames: []string{"api.baum.hase.de", "api12.tc42.uk"}, CertState: "installed", CertNotAfter: "2026-12-01T00:00:00Z"}

	got := formatMachineList(listPayload{Tenant: summary, AllProjects: true, Machines: []meta.Machine{private, zone}}, listRenderOptions{})
	want := strings.Join([]string{
		"the current install",
		"PROJECT  MACHINE  TYPE  FQDN                            CERT  IP         CREATED  STATE",
		"gbrain   web      CT    web.gbrain.acme.sandcastle.dev  -     10.1.0.9   -        running",
		"zp       api      CT    api.baum.hase.de (+1)           ok    10.1.0.12  -        running",
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
		"obelix  zp       api      CT    api.baum.hase.de (+1)           ok    10.1.0.12  -        running",
	} {
		if !strings.Contains(multi, line) {
			t.Fatalf("cross-install table missing %q:\n%s", line, multi)
		}
	}

	admin := formatTenantResources(tenantResourcesPayload{Tenant: summary, Machines: []meta.Machine{private, zone}})
	for _, line := range []string{
		"PROJECT  MACHINE  TYPE  FQDN                            CERT  IP         CREATED  STATE",
		"gbrain   web      CT    web.gbrain.acme.sandcastle.dev  -     10.1.0.9   -        running",
		"zp       api      CT    api.baum.hase.de (+1)           ok    10.1.0.12  -        running",
	} {
		if !strings.Contains(admin, line) {
			t.Fatalf("admin resources table missing %q:\n%s", line, admin)
		}
	}
}

// The unstamped row must be byte-identical whether or not the machine carries
// a stray cert-state: no public name never shows certificate state.
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
