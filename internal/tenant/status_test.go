package tenant

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

func TestGetStatus(t *testing.T) {
	status, err := GetStatus(context.Background(), MemoryStore{Projects: v2ProjectsForTest("acme", "10.248.0.0/24")}, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if status.Summary.IncusName != "sc2-acme-default" {
		t.Fatalf("IncusName = %q", status.Summary.IncusName)
	}
	if len(status.Checks) != 4 {
		t.Fatalf("checks = %d, want 4", len(status.Checks))
	}
	if status.Checks[3].Name != "tailscale:route" || status.Checks[3].Status != "unknown" {
		t.Fatalf("tailscale route check = %#v", status.Checks[3])
	}
}

func TestGetStatusWithTopology(t *testing.T) {
	status, err := GetStatusWithTopology(
		context.Background(),
		MemoryStore{Projects: v2ProjectsForTest("acme", "10.248.0.0/24")},
		fakeTopologyStore{topology: Topology{
			PrivateNetworkPresent: true,
			TailscaleInstance:     "sc-acme",
			DurableVolumes: map[string]bool{
				HomeVolumeName:      true,
				WorkspaceVolumeName: true,
				CAVolumeName:        true,
			},
			Sidecars: map[string]SidecarStatus{
				"sc-acme": {Present: true, Running: false, Status: "Stopped"},
				DNSName:   {Present: true, Running: true, Status: "Running"},
			},
		}},
		TopologyRequest{},
		"acme",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Checks) != 10 {
		t.Fatalf("checks = %d, want 10", len(status.Checks))
	}
	if status.Checks[8].Status != "stopped" {
		t.Fatalf("tailscale check = %#v", status.Checks[8])
	}
	if status.Checks[9].Status != "ok" {
		t.Fatalf("dns check = %#v", status.Checks[9])
	}
}

func TestGetStatusReportsMissingTenant(t *testing.T) {
	_, err := GetStatus(context.Background(), MemoryStore{}, "missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

type fakeTopologyStore struct {
	topology Topology
}

func (s fakeTopologyStore) GetTopology(ctx context.Context, request TopologyRequest) (Topology, error) {
	return s.topology, nil
}

// Regression for #55: a v2 tenant's sidecar lives in the infra project
// (<prefix>-<tenant>), not "<incus project>-infra". The v1 rule produced
// "<prefix>-<tenant>-default-infra", which does not exist, so `sc status`
// reported a topology error on a perfectly healthy tenant.
func TestGetStatusUsesTheSummaryInfraProjectForTopology(t *testing.T) {
	infraConfig := map[string]string{
		meta.KeyKind:    meta.KindInfra,
		meta.KeyTenant:  "alice",
		meta.KeyVersion: "2",
		meta.KeyV2CIDR:  "10.61.0.0/24",
	}
	appConfig := map[string]string{
		meta.KeyKind:    meta.KindV2Project,
		meta.KeyTenant:  "alice",
		meta.KeyVersion: "2",
	}
	recorder := &recordingTopologyStore{}
	_, err := GetStatusWithTopology(
		context.Background(),
		MemoryStore{Projects: []IncusProject{
			{Name: "sc2-alice", Config: infraConfig},
			{Name: "sc2-alice-default", Config: appConfig},
		}},
		recorder,
		TopologyRequest{},
		"alice",
	)
	if err != nil {
		t.Fatal(err)
	}
	if recorder.request.InfraProject != "sc2-alice" {
		t.Fatalf("InfraProject = %q, want %q (the v1 rule gave sc2-alice-default-infra)", recorder.request.InfraProject, "sc2-alice")
	}
}

// The infra project is deliberately not granted to a restricted tenant
// certificate, so the failure is expected rather than broken: report it as
// unknown, not as an error on a healthy tenant.
func TestTopologyPermissionErrorIsUnknown(t *testing.T) {
	summary := Summary{Tenant: "alice", Version: 2, InfraProject: "sc2-alice"}
	check := topologyErrorCheck(summary, errors.New(`User does not have permission for project "sc2-alice"`))
	if check.Status != "unknown" {
		t.Fatalf("status = %q, want unknown (detail=%q)", check.Status, check.Detail)
	}
	if !strings.Contains(check.Detail, "sc2-alice") || !strings.Contains(check.Detail, "admin remote") {
		t.Fatalf("detail = %q", check.Detail)
	}
	if real := topologyErrorCheck(summary, errors.New("sidecar container is missing")); real.Status != "error" {
		t.Fatalf("a real failure must stay an error, got %q", real.Status)
	}
}

// The v2 CIDR is stored only on the infra project, so a tenant certificate
// cannot read it. Absent-because-unreachable is "unknown", not "missing".
func TestCIDRCheckIsUnknownWhenInfraIsUnreadable(t *testing.T) {
	unknown := cidrCheck(Summary{Tenant: "alice", Version: 2, InfraProject: "sc2-alice"})
	if unknown.Status != "unknown" || !strings.Contains(unknown.Detail, "sc2-alice") {
		t.Fatalf("check = %#v", unknown)
	}
	present := cidrCheck(Summary{Tenant: "alice", Version: 2, InfraProject: "sc2-alice", PrivateCIDR: "10.61.0.0/24"})
	if present.Status != "ok" || present.Detail != "10.61.0.0/24" {
		t.Fatalf("check = %#v", present)
	}
}

type recordingTopologyStore struct {
	request TopologyRequest
}

func (s *recordingTopologyStore) GetTopology(ctx context.Context, request TopologyRequest) (Topology, error) {
	s.request = request
	return Topology{}, nil
}
