package incusx

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// fakeListServer records which Incus projects were queried and how much of the
// fan-out overlapped in time, so the tests can assert both the scoping and the
// concurrency.
type fakeListServer struct {
	mu       sync.Mutex
	queried  []string
	inFlight int
	peak     int
	delay    time.Duration
}

func (s *fakeListServer) UseProject(name string) HostOverrideResourceServer {
	return &fakeListResource{server: s, projectName: name}
}

type fakeListResource struct {
	server      *fakeListServer
	projectName string
}

func (r *fakeListResource) GetInstancesFull(instanceType api.InstanceType) ([]api.InstanceFull, error) {
	s := r.server
	s.mu.Lock()
	s.queried = append(s.queried, r.projectName)
	s.inFlight++
	if s.inFlight > s.peak {
		s.peak = s.inFlight
	}
	s.mu.Unlock()

	time.Sleep(s.delay)

	s.mu.Lock()
	s.inFlight--
	s.mu.Unlock()

	instance := api.InstanceFull{}
	instance.Name = "box-" + r.projectName
	instance.Type = "container"
	return []api.InstanceFull{instance}, nil
}

func (r *fakeListResource) GetInstances(api.InstanceType) ([]api.Instance, error) { return nil, nil }
func (r *fakeListResource) GetInstance(string) (*api.Instance, string, error) {
	return nil, "", nil
}
func (r *fakeListResource) UpdateInstance(string, api.InstancePut, string) (incus.Operation, error) {
	return nil, nil
}
func (r *fakeListResource) CreateInstanceFile(string, string, incus.InstanceFileArgs) error {
	return nil
}
func (r *fakeListResource) GetStorageVolumeFile(string, string, string, string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	return nil, nil, nil
}
func (r *fakeListResource) ExecInstance(string, api.InstanceExecPost, *incus.InstanceExecArgs) (incus.Operation, error) {
	return nil, nil
}

func listTestSummary() tenant.Summary {
	return tenant.Summary{
		Tenant:       "thieso2",
		InfraProject: "obelix-thieso2",
		Projects: []meta.Project{
			{Name: "docker"}, {Name: "gbrain"}, {Name: "herdr"},
			{Name: "klabauter"}, {Name: "poold"}, {Name: "scraper"}, {Name: "work"},
		},
	}
}

func TestListMachinesQueriesProjectsConcurrently(t *testing.T) {
	server := &fakeListServer{delay: 50 * time.Millisecond}
	manager := HostOverrideManager{Server: server}
	summary := listTestSummary()

	start := time.Now()
	machines, err := manager.ListMachines(context.Background(), summary)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	elapsed := time.Since(start)

	if len(machines) != len(summary.Projects) {
		t.Fatalf("machines = %d, want %d", len(machines), len(summary.Projects))
	}
	if server.peak < 2 {
		t.Fatalf("peak concurrent GetInstancesFull = %d, want the projects fanned out", server.peak)
	}
	// Serialised, seven 50ms calls take 350ms. Fanned out they take ~50ms; the
	// generous bound keeps the test from flaking on a loaded machine while
	// still failing outright if the loop goes back to being sequential.
	if elapsed >= time.Duration(len(summary.Projects))*server.delay {
		t.Fatalf("elapsed = %s, want well under the serialised %s", elapsed, time.Duration(len(summary.Projects))*server.delay)
	}
}

func TestListMachinesPreservesProjectOrder(t *testing.T) {
	server := &fakeListServer{}
	manager := HostOverrideManager{Server: server}
	summary := listTestSummary()

	machines, err := manager.ListMachines(context.Background(), summary)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	for index, project := range summary.Projects {
		if machines[index].Project != project.Name {
			t.Fatalf("machine %d project = %q, want %q (results must follow project order, not completion order)",
				index, machines[index].Project, project.Name)
		}
	}
}

func TestListMachinesInProjectQueriesOnlyThatProject(t *testing.T) {
	server := &fakeListServer{}
	manager := HostOverrideManager{Server: server}
	summary := listTestSummary()

	machines, err := manager.ListMachinesInProject(context.Background(), summary, "klabauter")
	if err != nil {
		t.Fatalf("ListMachinesInProject: %v", err)
	}
	if len(server.queried) != 1 || server.queried[0] != summary.V2IncusProjectName("klabauter") {
		t.Fatalf("queried = %v, want only the klabauter Incus project", server.queried)
	}
	if len(machines) != 1 || machines[0].Project != "klabauter" {
		t.Fatalf("machines = %+v, want a single klabauter machine", machines)
	}
}

func TestListMachinesInProjectUnknownProjectQueriesNothing(t *testing.T) {
	server := &fakeListServer{}
	manager := HostOverrideManager{Server: server}

	machines, err := manager.ListMachinesInProject(context.Background(), listTestSummary(), "nope")
	if err != nil {
		t.Fatalf("ListMachinesInProject: %v", err)
	}
	if len(server.queried) != 0 {
		t.Fatalf("queried = %v, want no Incus calls for an unknown project", server.queried)
	}
	if len(machines) != 0 {
		t.Fatalf("machines = %+v, want none", machines)
	}
}

// The project filter is resolved against the tenant summary — which already
// lists the projects — BEFORE any Incus call. A glob matching no project must
// therefore cost nothing: `sc ls '*:w*:*'` against an install whose only
// project is "home" should not talk to the daemon at all.
func TestListMachinesInProjectGlobIsResolvedWithoutIncusCalls(t *testing.T) {
	server := &fakeListServer{}
	manager := HostOverrideManager{Server: server}
	summary := listTestSummary()

	machines, err := manager.ListMachinesInProject(context.Background(), summary, "zz*")
	if err != nil {
		t.Fatalf("ListMachinesInProject: %v", err)
	}
	if len(server.queried) != 0 {
		t.Fatalf("queried = %v, want no Incus calls for a glob matching no project", server.queried)
	}
	if len(machines) != 0 {
		t.Fatalf("machines = %+v, want none", machines)
	}
}

// …and a glob that matches some projects queries only those.
func TestListMachinesInProjectGlobQueriesOnlyMatchingProjects(t *testing.T) {
	server := &fakeListServer{}
	manager := HostOverrideManager{Server: server}
	summary := listTestSummary()

	if _, err := manager.ListMachinesInProject(context.Background(), summary, "d*"); err != nil {
		t.Fatalf("ListMachinesInProject: %v", err)
	}
	// listTestSummary has docker, gbrain, herdr, klabauter, poold, scraper, work.
	if len(server.queried) != 1 || server.queried[0] != summary.V2IncusProjectName("docker") {
		t.Fatalf("queried = %v, want only the docker Incus project", server.queried)
	}
}

// MachineFromInstance is the one conversion both the live sweep and the
// resource-cache renderer run, so the ADR-0027 keys must be decoded here: an
// unstamped instance stays private (no public name, no cert fields), a
// stamped one carries its Machine Public Hostname and mirrored state.
func TestMachineFromInstanceDecodesZoneMode(t *testing.T) {
	private := api.InstanceFull{}
	private.Name = "web"
	private.Type = "container"
	got, ok := MachineFromInstance("acme", "sc2-acme-default", private)
	if !ok {
		t.Fatal("private instance filtered out")
	}
	if got.PublicHostname != "" || got.CertState != "" || got.CertNotAfter != "" || got.NamingMode() != meta.NamingModePrivate {
		t.Fatalf("unstamped instance decoded as %#v, want private-mode", got)
	}

	zone := api.InstanceFull{}
	zone.Name = "web"
	zone.Type = "container"
	zone.Config = map[string]string{
		meta.KeyV2PublicHostname: "web.baum.hase.de",
		meta.KeyV2CertState:      "installed",
		meta.KeyV2CertNotAfter:   "2026-12-01T00:00:00Z",
	}
	got, ok = MachineFromInstance("acme", "sc2-acme-zp", zone)
	if !ok {
		t.Fatal("zone instance filtered out")
	}
	if got.PublicHostname != "web.baum.hase.de" || got.CertState != "installed" || got.CertNotAfter != "2026-12-01T00:00:00Z" {
		t.Fatalf("zone instance decoded as %#v", got)
	}
	if got.NamingMode() != meta.NamingModeZone {
		t.Fatalf("NamingMode = %q, want zone", got.NamingMode())
	}
}
