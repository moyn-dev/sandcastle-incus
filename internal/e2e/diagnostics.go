package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/localdns"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
	"gopkg.in/yaml.v2"
)

func logTenantDiagnostics(t *testing.T, ctx context.Context, store tenant.IncusTenantStore, runID string) {
	logTenantDiagnosticsWithTopology(t, ctx, store, nil, runID)
}

func registerTenantDiagnostics(t *testing.T, ctx context.Context, store tenant.IncusTenantStore, topologyStore tenant.TopologyStore, runID string) {
	t.Helper()
	t.Cleanup(func() {
		if t.Failed() {
			logTenantDiagnosticsWithTopology(t, ctx, store, topologyStore, runID)
		}
	})
}

func logTenantDiagnosticsWithTopology(t *testing.T, ctx context.Context, store tenant.IncusTenantStore, topologyStore tenant.TopologyStore, runID string) {
	t.Helper()
	tenants, err := tenant.List(ctx, store)
	if err != nil {
		t.Logf("diagnostics: list tenants failed: %v", err)
		return
	}
	lines := tenantDiagnosticLines(ctx, tenants, topologyStore, runID)
	localDNSLines, err := localDNSDiagnosticLines(localdns.DefaultStatePath(), runID)
	if err != nil {
		t.Logf("diagnostics: local DNS state failed: %v", err)
	}
	lines = append(lines, localDNSLines...)
	if len(lines) == 0 {
		t.Logf("diagnostics: no Sandcastle tenants matched run id %q", runID)
		return
	}
	t.Logf("diagnostics: matching Sandcastle tenants:\n%s", strings.Join(lines, "\n"))
}

func tenantDiagnosticLines(ctx context.Context, tenants []tenant.Summary, topologyStore tenant.TopologyStore, runID string) []string {
	var lines []string
	for _, summary := range tenants {
		if !matchesTenantRun(summary, runID) {
			continue
		}
		line := fmt.Sprintf(
			"%s incus=%s dnsSuffix=%s cidr=%s status=%s",
			summary.Tenant,
			summary.IncusName,
			summary.DNSSuffix,
			summary.PrivateCIDR,
			summary.Status,
		)
		if topologyStore != nil {
			line += "\n  topology: " + tenantTopologyDiagnostics(ctx, topologyStore, summary)
		}
		if tailscaleLine := tenantTailscaleDiagnostics(summary); tailscaleLine != "" {
			line += "\n  tailscale: " + tailscaleLine
		}
		lines = append(lines, line)
	}
	return lines
}

func matchesTenantRun(summary tenant.Summary, runID string) bool {
	if strings.TrimSpace(runID) == "" {
		return false
	}
	return strings.Contains(summary.Tenant, runID) ||
		strings.Contains(summary.IncusName, runID) ||
		strings.Contains(summary.DNSSuffix, runID)
}

func tenantTopologyDiagnostics(ctx context.Context, topologyStore tenant.TopologyStore, summary tenant.Summary) string {
	topology, err := topologyStore.GetTopology(ctx, tenant.TopologyRequest{
		IncusProject: summary.IncusName,
		// Read the infra project off the summary; never derive it from IncusName.
		// Under v2 IncusName is the -default APP project, so the old derivation
		// built "<prefix>-<tenant>-default-infra", which does not exist (cf. #55).
		InfraProject: summary.InfraProject,
		DNSSuffix:    summary.DNSSuffix,
	})
	if err != nil {
		return "error=" + err.Error()
	}
	var parts []string
	for _, check := range tenant.TopologyChecks(topology) {
		value := check.Status
		if check.Detail != "" {
			value += "(" + check.Detail + ")"
		}
		parts = append(parts, check.Name+"="+value)
	}
	output := strings.Join(parts, " ")
	if files := topologyDiagnosticFiles(topology.DiagnosticFiles); files != "" {
		output += "\n  files:\n" + files
	}
	return output
}

func topologyDiagnosticFiles(files []tenant.DiagnosticFile) string {
	var parts []string
	for _, file := range files {
		label := file.Instance + ":" + file.Path
		if file.Error != "" {
			parts = append(parts, "    "+label+" error="+redactDiagnosticValue(file.Error))
			continue
		}
		content := strings.TrimSpace(file.Content)
		if content == "" {
			parts = append(parts, "    "+label+" empty")
			continue
		}
		parts = append(parts, "    "+label+"\n"+indentDiagnosticContent(redactDiagnosticValue(content), "      "))
	}
	return strings.Join(parts, "\n")
}

func indentDiagnosticContent(content string, prefix string) string {
	lines := strings.Split(content, "\n")
	for index := range lines {
		lines[index] = prefix + lines[index]
	}
	return strings.Join(lines, "\n")
}

func tenantTailscaleDiagnostics(summary tenant.Summary) string {
	state := strings.TrimSpace(summary.Tailscale.State)
	tailnet := strings.TrimSpace(summary.Tailscale.Tailnet)
	hostname := strings.TrimSpace(summary.Tailscale.Hostname)
	routes := summary.Tailscale.AdvertisedRoutes
	ips := summary.Tailscale.TailscaleIPs
	checkedAt := strings.TrimSpace(summary.Tailscale.LastCheckedAt)
	if state == "" && tailnet == "" && hostname == "" && len(routes) == 0 && len(ips) == 0 && checkedAt == "" {
		return ""
	}
	parts := []string{}
	if state != "" {
		parts = append(parts, "state="+redactDiagnosticValue(state))
	}
	if tailnet != "" {
		parts = append(parts, "tailnet="+redactDiagnosticValue(tailnet))
	}
	if hostname != "" {
		parts = append(parts, "hostname="+redactDiagnosticValue(hostname))
	}
	if len(routes) > 0 {
		parts = append(parts, "routes="+redactDiagnosticValue(strings.Join(routes, ",")))
	}
	if len(ips) > 0 {
		parts = append(parts, fmt.Sprintf("ips=%d", len(ips)))
	}
	if checkedAt != "" {
		parts = append(parts, "lastCheckedAt="+redactDiagnosticValue(checkedAt))
	}
	return strings.Join(parts, " ")
}

func localDNSDiagnosticLines(statePath string, runID string) ([]string, error) {
	if strings.TrimSpace(runID) == "" {
		return nil, nil
	}
	content, err := os.ReadFile(statePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(content) == 0 {
		return nil, nil
	}
	var state localdns.State
	if err := yaml.Unmarshal(content, &state); err != nil {
		return nil, err
	}
	var lines []string
	for _, entry := range state.Tenants {
		if !matchesLocalDNSRun(entry, runID) {
			continue
		}
		endpoint := "invalid"
		if entry.DNSEndpoint.IP != "" && entry.DNSEndpoint.Port > 0 {
			endpoint = net.JoinHostPort(entry.DNSEndpoint.IP, fmt.Sprint(entry.DNSEndpoint.Port))
		}
		lines = append(lines, fmt.Sprintf(
			"local-dns: %s dnsSuffix=%s endpoint=%s",
			entry.Tenant,
			entry.DNSSuffix,
			endpoint,
		))
	}
	return lines, nil
}

func matchesLocalDNSRun(entry localdns.TenantState, runID string) bool {
	return strings.Contains(entry.Tenant, runID) ||
		strings.Contains(entry.DNSSuffix, runID)
}

func redactDiagnosticValue(value string) string {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "login.tailscale.com") ||
		strings.Contains(lower, "tskey-") ||
		strings.Contains(lower, "authkey") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret") {
		return "<redacted>"
	}
	return value
}
