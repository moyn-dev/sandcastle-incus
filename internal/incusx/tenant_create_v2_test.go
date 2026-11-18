package incusx

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// fakeBridgeServer is a TenantCreateServer whose only implemented method is
// UseProject, returning a fakeBridgeResources that records the network calls
// ensureV2Bridge makes; everything else is embedded-nil (never called).
type fakeBridgeServer struct {
	TenantCreateServer // embedded: only UseProject is implemented below
	res                *fakeBridgeResources
}

func (s *fakeBridgeServer) UseProject(string) TenantResourceServer { return s.res }

// fakeBridgeResources implements only the network methods of TenantResourceServer.
type fakeBridgeResources struct {
	TenantResourceServer // embedded: only the network methods are implemented below
	network              *api.Network
	created              *api.NetworksPost
	updated              *api.NetworkPut
}

func (s *fakeBridgeResources) GetNetwork(string) (*api.Network, string, error) {
	if s.network == nil {
		return nil, "", api.StatusErrorf(http.StatusNotFound, "not found")
	}
	return s.network, "etag", nil
}

func (s *fakeBridgeResources) CreateNetwork(n api.NetworksPost) error {
	s.created = &n
	return nil
}

func (s *fakeBridgeResources) UpdateNetwork(_ string, n api.NetworkPut, _ string) error {
	s.updated = &n
	return nil
}

// A fresh tenant bridge must be created with dns.mode=none. Every project of a
// tenant shares this one bridge, and Incus's managed bridge DNS enforces
// per-network uniqueness of the instance name — so without dns.mode=none,
// h1:t1 and h2:t1 (distinct FQDNs) collide on start with
// "Instance DNS name already used on network".
func TestEnsureV2BridgeCreatesWithDNSModeNone(t *testing.T) {
	res := &fakeBridgeResources{}
	s := &fakeBridgeServer{res: res}
	plan := tenant.CreatePlanV2{Tenant: "acme", Bridge: "sc2-acme", DNSSuffix: "jules", PrivateCIDR: "10.249.7.0/24", DNSAddress: "10.249.7.3"}
	if err := ensureV2Bridge(s, plan, false); err != nil {
		t.Fatalf("ensureV2Bridge: %v", err)
	}
	if res.created == nil {
		t.Fatal("expected a network to be created")
	}
	if got := res.created.Config["dns.mode"]; got != "none" {
		t.Fatalf("dns.mode = %q, want none", got)
	}
}

// A pre-existing bridge left at the managed-DNS default must be converged to
// dns.mode=none on the next idempotent re-provision, not left to collide.
func TestEnsureV2BridgeConvergesExistingToDNSModeNone(t *testing.T) {
	res := &fakeBridgeResources{network: &api.Network{
		Name: "sc2-acme",
		NetworkPut: api.NetworkPut{Config: map[string]string{
			"raw.dnsmasq": "dhcp-option=6,10.249.7.3",
			// dns.mode absent → Incus defaults to "managed" (the buggy state).
		}},
	}}
	s := &fakeBridgeServer{res: res}
	plan := tenant.CreatePlanV2{Tenant: "acme", Bridge: "sc2-acme", DNSAddress: "10.249.7.3"}
	if err := ensureV2Bridge(s, plan, false); err != nil {
		t.Fatalf("ensureV2Bridge: %v", err)
	}
	if res.updated == nil {
		t.Fatal("expected the existing bridge to be updated")
	}
	if got := res.updated.Config["dns.mode"]; got != "none" {
		t.Fatalf("dns.mode = %q, want none", got)
	}
}

// A bridge already carrying dns.mode=none and the CoreDNS resolver option is
// fully converged — ensureV2Bridge must be a no-op (no update call).
func TestEnsureV2BridgeNoopWhenConverged(t *testing.T) {
	res := &fakeBridgeResources{network: &api.Network{
		Name: "sc2-acme",
		NetworkPut: api.NetworkPut{Config: map[string]string{
			"raw.dnsmasq": "dhcp-option=6,10.249.7.3",
			"dns.mode":    "none",
		}},
	}}
	s := &fakeBridgeServer{res: res}
	plan := tenant.CreatePlanV2{Tenant: "acme", Bridge: "sc2-acme", DNSAddress: "10.249.7.3"}
	if err := ensureV2Bridge(s, plan, false); err != nil {
		t.Fatalf("ensureV2Bridge: %v", err)
	}
	if res.updated != nil {
		t.Fatal("converged bridge must not be updated")
	}
}

// Toggling egress on must converge an existing (otherwise fully converged)
// bridge onto the two-option dnsmasq value — CoreDNS resolver plus the
// classless static route steering the CGNAT range and 10.0.0.0/8 at the
// sidecar, default route included (RFC 3442).
func TestEnsureV2BridgeEgressOnAddsClasslessRoute(t *testing.T) {
	res := &fakeBridgeResources{network: &api.Network{
		Name: "sc2-acme",
		NetworkPut: api.NetworkPut{Config: map[string]string{
			"raw.dnsmasq": "dhcp-option=6,10.249.7.3",
			"dns.mode":    "none",
		}},
	}}
	s := &fakeBridgeServer{res: res}
	plan := tenant.CreatePlanV2{Tenant: "acme", Bridge: "sc2-acme", DNSAddress: "10.249.7.3", GatewayAddress: "10.249.7.1"}
	if err := ensureV2Bridge(s, plan, true); err != nil {
		t.Fatalf("ensureV2Bridge: %v", err)
	}
	if res.updated == nil {
		t.Fatal("expected the existing bridge to be updated")
	}
	want := "dhcp-option=6,10.249.7.3\ndhcp-option=121,100.64.0.0/10,10.249.7.3,10.0.0.0/8,10.249.7.3,0.0.0.0/0,10.249.7.1"
	if got := res.updated.Config["raw.dnsmasq"]; got != want {
		t.Fatalf("raw.dnsmasq = %q, want %q", got, want)
	}
}

// Toggling egress off must converge the bridge BACK to the resolver-only
// value — the exact-equality converge removes option 121, it doesn't just add.
func TestEnsureV2BridgeEgressOffRemovesClasslessRoute(t *testing.T) {
	res := &fakeBridgeResources{network: &api.Network{
		Name: "sc2-acme",
		NetworkPut: api.NetworkPut{Config: map[string]string{
			"raw.dnsmasq": "dhcp-option=6,10.249.7.3\ndhcp-option=121,100.64.0.0/10,10.249.7.3,10.0.0.0/8,10.249.7.3,0.0.0.0/0,10.249.7.1",
			"dns.mode":    "none",
		}},
	}}
	s := &fakeBridgeServer{res: res}
	plan := tenant.CreatePlanV2{Tenant: "acme", Bridge: "sc2-acme", DNSAddress: "10.249.7.3", GatewayAddress: "10.249.7.1"}
	if err := ensureV2Bridge(s, plan, false); err != nil {
		t.Fatalf("ensureV2Bridge: %v", err)
	}
	if res.updated == nil {
		t.Fatal("expected the existing bridge to be updated")
	}
	if got := res.updated.Config["raw.dnsmasq"]; got != "dhcp-option=6,10.249.7.3" {
		t.Fatalf("raw.dnsmasq = %q, want resolver-only", got)
	}
}

// A bridge converged by ADR-0026 (CGNAT-only option 121) must be re-converged
// onto the subnet-route steer, so tenants with egress already on gain it.
func TestEnsureV2BridgeEgressOnUpgradesCGNATOnlyRoute(t *testing.T) {
	res := &fakeBridgeResources{network: &api.Network{
		Name: "sc2-acme",
		NetworkPut: api.NetworkPut{Config: map[string]string{
			"raw.dnsmasq": "dhcp-option=6,10.249.7.3\ndhcp-option=121,100.64.0.0/10,10.249.7.3,0.0.0.0/0,10.249.7.1",
			"dns.mode":    "none",
		}},
	}}
	s := &fakeBridgeServer{res: res}
	plan := tenant.CreatePlanV2{Tenant: "acme", Bridge: "sc2-acme", DNSAddress: "10.249.7.3", GatewayAddress: "10.249.7.1"}
	if err := ensureV2Bridge(s, plan, true); err != nil {
		t.Fatalf("ensureV2Bridge: %v", err)
	}
	if res.updated == nil {
		t.Fatal("expected the CGNAT-only bridge to be updated")
	}
	want := "dhcp-option=6,10.249.7.3\ndhcp-option=121,100.64.0.0/10,10.249.7.3,10.0.0.0/8,10.249.7.3,0.0.0.0/0,10.249.7.1"
	if got := res.updated.Config["raw.dnsmasq"]; got != want {
		t.Fatalf("raw.dnsmasq = %q, want %q", got, want)
	}
}

// A bridge already carrying the egress options is fully converged — no update.
func TestEnsureV2BridgeEgressNoopWhenConverged(t *testing.T) {
	res := &fakeBridgeResources{network: &api.Network{
		Name: "sc2-acme",
		NetworkPut: api.NetworkPut{Config: map[string]string{
			"raw.dnsmasq": "dhcp-option=6,10.249.7.3\ndhcp-option=121,100.64.0.0/10,10.249.7.3,10.0.0.0/8,10.249.7.3,0.0.0.0/0,10.249.7.1",
			"dns.mode":    "none",
		}},
	}}
	s := &fakeBridgeServer{res: res}
	plan := tenant.CreatePlanV2{Tenant: "acme", Bridge: "sc2-acme", DNSAddress: "10.249.7.3", GatewayAddress: "10.249.7.1"}
	if err := ensureV2Bridge(s, plan, true); err != nil {
		t.Fatalf("ensureV2Bridge: %v", err)
	}
	if res.updated != nil {
		t.Fatal("converged egress bridge must not be updated")
	}
}

// exitCodeOperation stubs an exec operation whose command exited with a code.
type exitCodeOperation struct {
	fakeOperation
	code float64
}

func (o exitCodeOperation) Get() api.Operation {
	return api.Operation{Metadata: map[string]any{"return": o.code}}
}

// Regression: the SDK's op.Wait() only fails when the OPERATION fails — a
// script that ran and exited nonzero still "succeeds". execSidecar callers
// relied on Wait alone, so every sidecar provisioning failure (apt racing the
// container boot, download errors) was silently swallowed and `tenant create`
// reported success with no CoreDNS/Tailscale installed (caught live on
// majestix). Nonzero command exits must surface as errors.
func TestExecExitErrorSurfacesNonzeroCommandExit(t *testing.T) {
	if err := execExitError(exitCodeOperation{code: 0}, ""); err != nil {
		t.Fatalf("exit 0 must not error: %v", err)
	}
	if err := execExitError(fakeOperation{}, ""); err != nil {
		t.Fatalf("missing metadata must not error: %v", err)
	}
	err := execExitError(exitCodeOperation{code: 2}, "apt-get: temporary failure resolving deb.debian.org")
	if err == nil {
		t.Fatal("exit 2 must error")
	}
	for _, want := range []string{"status 2", "temporary failure"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

// The sidecar accepts other routers' subnet routes exactly while egress is on,
// and an off converge actively restores --accept-routes=false: in every
// `tailscale up` (auth-key join and the interactive unit) and in the
// `tailscale set` run once joined (the already-joined path skips `up`).
func TestV2TailscaleUpAcceptRoutesFollowsEgress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		authKey string
		egress  bool
	}{
		{"auth-key on", "tskey-test", true},
		{"auth-key off", "tskey-test", false},
		{"interactive on", "", true},
		{"interactive off", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource := &fakeBinaryUpdateResource{instance: &api.Instance{}}
			plan := tenant.CreatePlanV2{PrivateCIDR: "10.125.0.0/24", SidecarInstance: "sidecar"}
			if _, _, err := v2TailscaleUp(resource, plan, "sc-test", tc.authKey, "443", tc.egress); err != nil {
				t.Fatalf("v2TailscaleUp: %v", err)
			}
			script := strings.Join(resource.execs, "\n")
			want, unwanted := "--accept-routes=false", "--accept-routes=true"
			if tc.egress {
				want, unwanted = unwanted, want
			}
			if !strings.Contains(script, "tailscale set "+want+"\n") {
				t.Fatalf("missing `tailscale set %s`; script:\n%s", want, script)
			}
			if !strings.Contains(script, "--advertise-tags=tag:sandcastle "+want) {
				t.Fatalf("`tailscale up` does not carry %s; script:\n%s", want, script)
			}
			if strings.Contains(script, unwanted) {
				t.Fatalf("script carries %s; script:\n%s", unwanted, script)
			}
		})
	}
}

// fakeInfraProjectServer implements only the project methods ensureV2Project uses.
type fakeInfraProjectServer struct {
	TenantCreateServer // embedded: only the project methods are implemented below
	project            *api.Project
	getErr             error
	created            *api.ProjectsPost
	updated            *api.ProjectPut
}

func (s *fakeInfraProjectServer) GetProject(string) (*api.Project, string, error) {
	if s.getErr != nil {
		return nil, "", s.getErr
	}
	if s.project == nil {
		return nil, "", api.StatusErrorf(http.StatusNotFound, "not found")
	}
	return s.project, "etag", nil
}

func (s *fakeInfraProjectServer) CreateProject(p api.ProjectsPost) error {
	s.created = &p
	return nil
}

func (s *fakeInfraProjectServer) UpdateProject(_ string, p api.ProjectPut, _ string) error {
	s.updated = &p
	return nil
}

var infraPlan = tenant.CreatePlanV2{Tenant: "acme", InfraProject: "sc2-acme", Bridge: "sc2-acme", PrivateCIDR: "10.249.7.0/24"}

// A tenant created from scratch gets egress on, recorded on the new infra
// project so every later converge (and `sc tailscale egress`) reads it back.
func TestEnsureV2InfraProjectFreshTenantDefaultsEgressOn(t *testing.T) {
	s := &fakeInfraProjectServer{}
	egress, err := ensureV2InfraProject(s, infraPlan)
	if err != nil {
		t.Fatalf("ensureV2InfraProject: %v", err)
	}
	if !egress {
		t.Fatal("fresh tenant: egress = off, want on")
	}
	if s.created == nil {
		t.Fatal("expected the infra project to be created")
	}
	if got := s.created.Config[meta.KeyV2TailnetEgress]; got != "true" {
		t.Fatalf("created %s = %q, want true", meta.KeyV2TailnetEgress, got)
	}
}

// An existing tenant without the key (created before default-on, or switched
// off, which deletes the key) stays off, and the converge must not seed it.
func TestEnsureV2InfraProjectExistingWithoutKeyStaysOff(t *testing.T) {
	s := &fakeInfraProjectServer{project: &api.Project{Name: "sc2-acme", ProjectPut: api.ProjectPut{Config: map[string]string{}}}}
	egress, err := ensureV2InfraProject(s, infraPlan)
	if err != nil {
		t.Fatalf("ensureV2InfraProject: %v", err)
	}
	if egress {
		t.Fatal("existing tenant without key: egress = on, want off")
	}
	if s.created != nil {
		t.Fatal("existing infra project must not be re-created")
	}
	if s.updated == nil {
		t.Fatal("expected the infra metadata to be converged onto the existing project")
	}
	if got, ok := s.updated.Config[meta.KeyV2TailnetEgress]; ok {
		t.Fatalf("converge seeded %s=%q on an existing project", meta.KeyV2TailnetEgress, got)
	}
}

func TestEnsureV2InfraProjectExistingWithKeyIsOn(t *testing.T) {
	s := &fakeInfraProjectServer{project: &api.Project{Name: "sc2-acme", ProjectPut: api.ProjectPut{Config: map[string]string{meta.KeyV2TailnetEgress: "true"}}}}
	egress, err := ensureV2InfraProject(s, infraPlan)
	if err != nil {
		t.Fatalf("ensureV2InfraProject: %v", err)
	}
	if !egress {
		t.Fatal("existing tenant with key true: egress = off, want on")
	}
}

// A project the converge cannot read is not "fresh": egress fails closed.
func TestEnsureV2InfraProjectUnreadableFailsClosed(t *testing.T) {
	s := &fakeInfraProjectServer{getErr: api.StatusErrorf(http.StatusForbidden, "forbidden")}
	egress, err := ensureV2InfraProject(s, infraPlan)
	if err != nil {
		t.Fatalf("ensureV2InfraProject: %v", err)
	}
	if egress {
		t.Fatal("unreadable project: egress = on, want off")
	}
	if s.created != nil {
		if got, ok := s.created.Config[meta.KeyV2TailnetEgress]; ok {
			t.Fatalf("unreadable project seeded %s=%q", meta.KeyV2TailnetEgress, got)
		}
	}
}
