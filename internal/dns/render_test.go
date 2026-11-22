package dns

import (
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

func TestRenderInitial(t *testing.T) {
	files, err := RenderInitial("Acme.", "10.248.0.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("len(files) = %d, want 4", len(files))
	}
	corefile := fileByPath(t, files, "/etc/coredns/Corefile")
	if !strings.Contains(corefile.Content, "acme:53") {
		t.Fatalf("Corefile content = %q", corefile.Content)
	}
	if !strings.Contains(corefile.Content, "forward . /etc/coredns/upstream-resolv.conf") {
		t.Fatalf("Corefile missing upstream resolver forwarding: %q", corefile.Content)
	}
	if !strings.Contains(corefile.Content, "force_tcp") {
		t.Fatalf("Corefile missing TCP upstream forwarding: %q", corefile.Content)
	}
	// Tailnet clients must get REFUSED (not upstream NXDOMAIN) outside the
	// tenant zone, so their resolver falls through to other tenants' servers
	// and the public upstream. Machines (bridge sources) keep recursion.
	if !strings.Contains(corefile.Content, "block net 100.64.0.0/10") {
		t.Fatalf("Corefile catch-all must REFUSE tailnet clients: %q", corefile.Content)
	}
	// ADR-0018: the zone is the only authority under the suffix — no dnsmasq
	// fallthrough, no gateway forwarding inside the suffix zone.
	if strings.Contains(corefile.Content, "fallthrough") {
		t.Fatalf("Corefile must not fall through to dnsmasq: %q", corefile.Content)
	}
	if strings.Contains(corefile.Content, "forward . 10.248.0.1") {
		t.Fatalf("Corefile must not forward the suffix zone to the gateway: %q", corefile.Content)
	}
	zoneFile := fileByPath(t, files, "/etc/coredns/zones/db.acme")
	if !strings.Contains(zoneFile.Content, "ns IN A 10.248.0.3") {
		t.Fatalf("zone content = %q", zoneFile.Content)
	}
	if strings.Contains(zoneFile.Content, "*") {
		t.Fatalf("initial zone should not contain wildcards: %q", zoneFile.Content)
	}
	resolver := fileByPath(t, files, "/etc/resolv.conf")
	if resolver.Content != "nameserver 127.0.0.1\n" {
		t.Fatalf("self resolver file = %#v", resolver)
	}
	upstream := fileByPath(t, files, "/etc/coredns/upstream-resolv.conf")
	if !strings.Contains(upstream.Content, "nameserver 1.1.1.1") {
		t.Fatalf("upstream resolver file = %#v", upstream)
	}
}

func TestRenderInitialRequiresTenantDNSSuffix(t *testing.T) {
	_, err := RenderInitial("", "10.248.0.3")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRenderTenantRequiresDNSAddress(t *testing.T) {
	_, err := RenderTenant("acme", "", "", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ADR-0018: default-project machines get the canonical Machine Private
// Hostname AND the Default Project Short Hostname, each with a wildcard.
func TestRenderTenantDefaultProjectMachine(t *testing.T) {
	files, err := RenderTenant("acme", "10.248.0.3", "default", []meta.Machine{
		{Project: "default", Name: "codex", PrivateIP: "10.248.0.20"},
	})
	if err != nil {
		t.Fatal(err)
	}
	zone := files[1].Content
	for _, record := range []string{
		"codex.default.acme. IN A 10.248.0.20",
		"*.codex.default.acme. IN A 10.248.0.20",
		"codex.acme. IN A 10.248.0.20",
		"*.codex.acme. IN A 10.248.0.20",
	} {
		if !strings.Contains(zone, record) {
			t.Fatalf("zone missing %q: %q", record, zone)
		}
	}
	if strings.Contains(zone, "*.default.acme") {
		t.Fatalf("zone should not contain project-wide wildcard: %q", zone)
	}
}

// ADR-0018: machines outside the default project get ONLY the canonical name —
// never a short form, regardless of uniqueness.
func TestRenderTenantNonDefaultProjectHasNoShortName(t *testing.T) {
	files, err := RenderTenant("acme", "10.248.0.3", "default", []meta.Machine{
		{Project: "test2", Name: "dev", PrivateIP: "10.248.0.30"},
	})
	if err != nil {
		t.Fatal(err)
	}
	zone := files[1].Content
	if !strings.Contains(zone, "dev.test2.acme. IN A 10.248.0.30") {
		t.Fatalf("zone missing canonical record: %q", zone)
	}
	if !strings.Contains(zone, "*.dev.test2.acme. IN A 10.248.0.30") {
		t.Fatalf("zone missing canonical wildcard: %q", zone)
	}
	if strings.Contains(zone, "dev.acme. IN A") {
		t.Fatalf("non-default machine must not get a short name: %q", zone)
	}
}

// Issue #93: when the tenant's default project is renamed, the short alias
// follows THAT project — not a project literally called "default".
func TestRenderTenantShortNameFollowsRenamedDefaultProject(t *testing.T) {
	files, err := RenderTenant("acme", "10.248.0.3", "web", []meta.Machine{
		{Project: "web", Name: "codex", PrivateIP: "10.248.0.20"},
		{Project: "default", Name: "other", PrivateIP: "10.248.0.30"},
	})
	if err != nil {
		t.Fatal(err)
	}
	zone := files[1].Content
	// the machine in the renamed default project ("web") gets the short alias
	for _, record := range []string{
		"codex.web.acme. IN A 10.248.0.20",
		"codex.acme. IN A 10.248.0.20",
	} {
		if !strings.Contains(zone, record) {
			t.Fatalf("zone missing %q: %q", record, zone)
		}
	}
	// a project literally named "default" is now just an ordinary project — no short alias
	if strings.Contains(zone, "other.acme. IN A") {
		t.Fatalf("literal 'default' project must not get the short alias: %q", zone)
	}
	if !strings.Contains(zone, "other.default.acme. IN A 10.248.0.30") {
		t.Fatalf("zone missing canonical record for the literal default project: %q", zone)
	}
}

// ADR-0018: the short name always belongs to the DEFAULT project's machine,
// deterministically — even when another project reuses the name.
func TestRenderTenantShortNameIsDefaultProjects(t *testing.T) {
	files, err := RenderTenant("acme", "10.248.0.3", "default", []meta.Machine{
		{Project: "aaa", Name: "dev", PrivateIP: "10.248.0.99"}, // sorts before "default"
		{Project: "default", Name: "dev", PrivateIP: "10.248.0.20"},
	})
	if err != nil {
		t.Fatal(err)
	}
	zone := files[1].Content
	if !strings.Contains(zone, "dev.acme. IN A 10.248.0.20") {
		t.Fatalf("short name must resolve to the default project's machine: %q", zone)
	}
	if strings.Contains(zone, "dev.acme. IN A 10.248.0.99") {
		t.Fatalf("short name must not be claimed by another project: %q", zone)
	}
	for _, record := range []string{
		"dev.aaa.acme. IN A 10.248.0.99",
		"dev.default.acme. IN A 10.248.0.20",
	} {
		if !strings.Contains(zone, record) {
			t.Fatalf("zone missing %q: %q", record, zone)
		}
	}
}

func TestPlanApply(t *testing.T) {
	result, err := PlanApply(Tenant{
		Tenant:      "acme",
		DNSSuffix:   "acme",
		PrivateCIDR: "10.248.0.0/24",
	}, []meta.Machine{{Project: "default", Name: "codex", PrivateIP: "10.248.0.20"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.DNSAddress != "10.248.0.3" {
		t.Fatalf("DNSAddress = %q", result.DNSAddress)
	}
	if result.RecordCount != 4 {
		t.Fatalf("RecordCount = %d", result.RecordCount)
	}
}

func fileByPath(t *testing.T, files []File, path string) File {
	t.Helper()
	for _, file := range files {
		if file.Path == path {
			return file
		}
	}
	t.Fatalf("missing file %s in %#v", path, files)
	return File{}
}
