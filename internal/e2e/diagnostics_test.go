package e2e

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestLogTenantDiagnosticsDoesNotFailWithoutMatches(t *testing.T) {
	logTenantDiagnostics(t, context.Background(), tenant.MemoryStore{}, "missing")
}

func TestLogTenantDiagnosticsWithMatch(t *testing.T) {
	store := diagnosticTenantStore(t)
	logTenantDiagnostics(t, context.Background(), store, "e2e-test")
}

func TestTenantDiagnosticLinesIncludeTopology(t *testing.T) {
	store := diagnosticTenantStore(t)
	summaries, err := tenant.List(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	lines := tenantDiagnosticLines(context.Background(), summaries, fakeDiagnosticTopologyStore{
		topology: tenant.Topology{
			PrivateNetworkPresent: true,
			TailscaleInstance:     "sc-tenant-e2e-test",
			DurableVolumes: map[string]bool{
				tenant.HomeVolumeName: true,
				tenant.CAVolumeName:   true,
			},
			Sidecars: map[string]tenant.SidecarStatus{
				"sc-tenant-e2e-test": {Present: true, Running: true, Status: "Running"},
				tenant.DNSName:       {Present: true, Running: false, Status: "Stopped"},
			},
			DiagnosticFiles: []tenant.DiagnosticFile{
				{Instance: tenant.DNSName, Path: "/etc/coredns/Corefile", Content: ".:53 {\n  errors\n}"},
				{Instance: tenant.DNSName, Path: "/etc/coredns/zones/db.tenant-e2e-test", Error: "missing"},
			},
		},
	}, "e2e-test")
	if len(lines) != 1 {
		t.Fatalf("lines = %#v, want one diagnostic line", lines)
	}
	for _, want := range []string{
		"topology:",
		"network:sc-private=ok",
		"volume:sc-home=ok",
		"volume:sc-workspace=missing",
		"sidecar:sc-tenant-e2e-test=ok(Running)",
		"sidecar:sc-dns=stopped(Stopped)",
		"files:",
		"sc-dns:/etc/coredns/Corefile",
		"  errors",
		"sc-dns:/etc/coredns/zones/db.tenant-e2e-test error=missing",
	} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("diagnostic line missing %q:\n%s", want, lines[0])
		}
	}
}

func TestTenantDiagnosticLinesIncludeTopologyErrors(t *testing.T) {
	store := diagnosticTenantStore(t)
	summaries, err := tenant.List(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	lines := tenantDiagnosticLines(context.Background(), summaries, fakeDiagnosticTopologyStore{err: errors.New("boom")}, "e2e-test")
	if len(lines) != 1 {
		t.Fatalf("lines = %#v, want one diagnostic line", lines)
	}
	if !strings.Contains(lines[0], "topology: error=boom") {
		t.Fatalf("diagnostic line missing topology error:\n%s", lines[0])
	}
}

func TestTenantDiagnosticLinesMatchRunIDInDNSSuffix(t *testing.T) {
	summaries, err := tenant.List(context.Background(), tenant.MemoryStore{
		Projects: v2TenantProjects("tenant-e2e-domain-only", "10.248.0.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := tenantDiagnosticLines(context.Background(), summaries, nil, "e2e-domain-only")
	if len(lines) != 1 {
		t.Fatalf("lines = %#v, want one diagnostic line", lines)
	}
	if !strings.Contains(lines[0], "dnsSuffix=tenant-e2e-domain-only") {
		t.Fatalf("diagnostic line missing DNS suffix:\n%s", lines[0])
	}
}

func TestTenantDiagnosticLinesRequireRunID(t *testing.T) {
	store := diagnosticTenantStore(t)
	summaries, err := tenant.List(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	lines := tenantDiagnosticLines(context.Background(), summaries, nil, "")
	if len(lines) != 0 {
		t.Fatalf("lines = %#v, want no diagnostics for empty run id", lines)
	}
	lines = tenantDiagnosticLines(context.Background(), summaries, nil, "   ")
	if len(lines) != 0 {
		t.Fatalf("lines = %#v, want no diagnostics for blank run id", lines)
	}
}

func TestLocalDNSDiagnosticLinesIncludeMatchingState(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "dns.yaml")
	content := "tenants:\n" +
		"- tenant: tenant-e2e-test\n" +
		"  dnsSuffix: tenant-e2e-test\n" +
		"  dnsEndpoint:\n" +
		"    ip: 10.248.0.3\n" +
		"    port: 53\n" +
		"- tenant: other\n" +
		"  dnsSuffix: other\n" +
		"  dnsEndpoint:\n" +
		"    ip: 127.0.0.1\n" +
		"    port: 53542\n"
	if err := os.WriteFile(statePath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	lines, err := localDNSDiagnosticLines(statePath, "e2e-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 {
		t.Fatalf("lines = %#v, want one local DNS diagnostic line", lines)
	}
	for _, want := range []string{
		"local-dns:",
		"tenant-e2e-test",
		"dnsSuffix=tenant-e2e-test",
		"endpoint=10.248.0.3:53",
	} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("local DNS diagnostic line missing %q:\n%s", want, lines[0])
		}
	}
}

func diagnosticTenantStore(t *testing.T) tenant.MemoryStore {
	t.Helper()
	return tenant.MemoryStore{Projects: v2TenantProjects("tenant-e2e-test", "10.248.0.0/24")}
}

// v2TenantProjects builds the two Incus projects (kind=infra + kind=project
// default app project) that make up a v2 tenant, so tenant.List surfaces one
// Summary for it.
func v2TenantProjects(tenantName, cidr string) []tenant.IncusProject {
	return []tenant.IncusProject{
		{
			Name: "sc2-" + tenantName,
			Config: map[string]string{
				meta.KeyKind:    meta.KindInfra,
				meta.KeyTenant:  tenantName,
				meta.KeyVersion: "2",
				meta.KeyV2CIDR:  cidr,
			},
		},
		{
			Name: "sc2-" + tenantName + "-default",
			Config: map[string]string{
				meta.KeyKind:    meta.KindV2Project,
				meta.KeyTenant:  tenantName,
				meta.KeyVersion: "2",
			},
		},
	}
}

type fakeDiagnosticTopologyStore struct {
	topology tenant.Topology
	err      error
}

func (s fakeDiagnosticTopologyStore) GetTopology(ctx context.Context, request tenant.TopologyRequest) (tenant.Topology, error) {
	if s.err != nil {
		return tenant.Topology{}, s.err
	}
	return s.topology, nil
}
