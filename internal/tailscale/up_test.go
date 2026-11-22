package tailscale

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestPlanUp(t *testing.T) {
	plan, err := PlanUp(context.Background(), config.LoadAdminFromEnv(), tenantStoreForTest(t), UpRequest{
		Reference:     "acme",
		AuthKey:       "tskey-secret",
		AdvertiseTags: []string{" tag:sandcastle,tag:sandcastle "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.InstanceName != "sc2-acme-default" {
		t.Fatalf("InstanceName = %q", plan.InstanceName)
	}
	if len(plan.AdvertiseRoutes) != 1 || plan.AdvertiseRoutes[0] != "10.248.0.0/24" {
		t.Fatalf("AdvertiseRoutes = %#v", plan.AdvertiseRoutes)
	}
	if !plan.HasAuthKey {
		t.Fatal("expected HasAuthKey")
	}
	if len(plan.AdvertiseTags) != 1 || plan.AdvertiseTags[0] != "tag:sandcastle" {
		t.Fatalf("AdvertiseTags = %#v", plan.AdvertiseTags)
	}
	if strings.Contains(strings.Join(plan.Command, " "), "tskey-secret") {
		t.Fatalf("Command leaked auth key: %#v", plan.Command)
	}
	if !strings.Contains(strings.Join(plan.Command, " "), "--timeout="+DefaultUpTimeout) {
		t.Fatalf("Command missing timeout: %#v", plan.Command)
	}
	if !strings.Contains(strings.Join(ExecCommand(plan), " "), "tskey-secret") {
		t.Fatalf("ExecCommand missing auth key")
	}
	if !strings.Contains(strings.Join(ExecCommand(plan), " "), "tailscaled --state=/var/lib/tailscale/tailscaled.state") {
		t.Fatalf("ExecCommand missing tailscaled bootstrap: %#v", ExecCommand(plan))
	}
	if !strings.Contains(strings.Join(ExecCommand(plan), " "), "systemctl unmask tailscaled.service") {
		t.Fatalf("ExecCommand missing tailscaled unmask: %#v", ExecCommand(plan))
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "tskey-secret") {
		t.Fatalf("plan JSON leaked auth key: %s", encoded)
	}
}

func TestPlanUpRejectsInvalidAdvertiseTags(t *testing.T) {
	for _, tag := range []string{"sandcastle", "tag:", "tag:Sandcastle", "tag:sand_castle"} {
		t.Run(tag, func(t *testing.T) {
			_, err := PlanUp(context.Background(), config.LoadAdminFromEnv(), tenantStoreForTest(t), UpRequest{
				Reference:     "acme",
				AdvertiseTags: []string{tag},
			})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "Tailscale advertise tag") {
				t.Fatalf("error = %q", err)
			}
		})
	}
}

func TestPlanUpSupportsCurrentTenant(t *testing.T) {
	admin := config.LoadAdminFromEnv()
	admin.Tenant = "acme"
	plan, err := PlanUp(context.Background(), admin, tenantStoreForTest(t), UpRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reference != "acme" {
		t.Fatalf("Reference = %q", plan.Reference)
	}
}

func TestPlanStatusAndParseStatus(t *testing.T) {
	plan, err := PlanStatus(context.Background(), config.LoadAdminFromEnv(), tenantStoreForTest(t), StatusRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.InstanceName != "sc2-acme-default" {
		t.Fatalf("InstanceName = %q", plan.InstanceName)
	}
	result, err := ParseStatus("acme", plan.Tenant, []byte(`{
		"BackendState": "Running",
		"CurrentTailnet": {"Name": "example.com"},
		"Self": {
			"HostName": "sc-myproject",
			"TailscaleIPs": ["100.80.12.34"],
			"PrimaryRoutes": ["10.248.0.0/24"]
		}
	}`), time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if result.Tailscale.State != "Running" {
		t.Fatalf("State = %q", result.Tailscale.State)
	}
	if result.Tailscale.Tailnet != "example.com" {
		t.Fatalf("Tailnet = %q", result.Tailscale.Tailnet)
	}
	if len(result.Tailscale.TailscaleIPs) != 1 || result.Tailscale.TailscaleIPs[0] != "100.80.12.34" {
		t.Fatalf("TailscaleIPs = %#v", result.Tailscale.TailscaleIPs)
	}
}

func TestParseStatusDoesNotPersistLoginURLs(t *testing.T) {
	result, err := ParseStatus("acme", tenant.Summary{
		Tenant:    "acme",
		IncusName: "sc-acme",
	}, []byte(`{
		"BackendState": "NeedsLogin",
		"AuthURL": "https://login.tailscale.com/a/secret-token",
		"CurrentTailnet": {"MagicDNSSuffix": "tailnet.ts.net"},
		"Self": {
			"DNSName": "sc-myproject.tailnet.ts.net.",
			"LoginURL": "https://login.tailscale.com/b/secret-token",
			"TailscaleIPs": ["100.80.12.34"],
			"PrimaryRoutes": ["10.248.0.0/24"]
		}
	}`), time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if result.Tailscale.State != "running-logged-out" {
		t.Fatalf("State = %q", result.Tailscale.State)
	}
	if result.Tailscale.Tailnet != "tailnet.ts.net" {
		t.Fatalf("Tailnet = %q", result.Tailscale.Tailnet)
	}
	if result.Tailscale.Hostname != "sc-myproject.tailnet.ts.net" {
		t.Fatalf("Hostname = %q", result.Tailscale.Hostname)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"login.tailscale.com", "secret-token"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("status result leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestParseStatusFallsBackToAllowedIPSubnetRoutes(t *testing.T) {
	result, err := ParseStatus("acme", tenant.Summary{
		Tenant:    "acme",
		IncusName: "sc-acme",
	}, []byte(`{
		"BackendState": "Running",
		"CurrentTailnet": {"Name": "example.com"},
		"Self": {
			"HostName": "sc-acme",
			"TailscaleIPs": ["100.80.12.34", "fd7a:115c:a1e0::1"],
			"AllowedIPs": ["100.80.12.34/32", "fd7a:115c:a1e0::1/128", "10.248.0.0/24"]
		}
	}`), time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Tailscale.AdvertisedRoutes) != 1 || result.Tailscale.AdvertisedRoutes[0] != "10.248.0.0/24" {
		t.Fatalf("AdvertisedRoutes = %#v", result.Tailscale.AdvertisedRoutes)
	}
}

func TestPlanDown(t *testing.T) {
	plan, err := PlanDown(context.Background(), config.LoadAdminFromEnv(), tenantStoreForTest(t), DownRequest{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.Command, " ") != "tailscale down" {
		t.Fatalf("Command = %#v", plan.Command)
	}
}

func tenantStoreForTest(t *testing.T) tenant.MemoryStore {
	t.Helper()
	return tenant.MemoryStore{Projects: v2TenantProjectsForTest("acme", "10.248.0.0/24")}
}

// v2TenantProjectsForTest is the v2 fixture for a tenant: a kind=infra project
// carrying its /24, plus one kind=project app project. v1 (kind=tenant)
// projects are no longer surfaced by tenant.List.
func v2TenantProjectsForTest(name, cidr string) []tenant.IncusProject {
	config := func(kind string) map[string]string {
		out := map[string]string{meta.KeyKind: kind, meta.KeyTenant: name, meta.KeyVersion: "2"}
		if kind == meta.KindInfra && cidr != "" {
			out[meta.KeyV2CIDR] = cidr
		}
		return out
	}
	return []tenant.IncusProject{
		{Name: "sc2-" + name, Config: config(meta.KindInfra)},
		{Name: "sc2-" + name + "-default", Config: config(meta.KindV2Project)},
	}
}
