package incusx

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

type ensureFakeServer struct {
	TenantCreateServer
	resource *ensureFakeResource
}

func (s ensureFakeServer) UseProject(string) TenantResourceServer { return s.resource }

type ensureFakeResource struct {
	TenantResourceServer
	instance      *api.Instance
	instanceReads atomic.Int32
	stateReads    atomic.Int32
}

func (r *ensureFakeResource) GetProfile(string) (*api.Profile, string, error) {
	return &api.Profile{Name: "default", ProfilePut: api.ProfilePut{Config: map[string]string{
		"cloud-init.user-data": "users:\n  - name: sebastian\n",
	}}}, "", nil
}

func (r *ensureFakeResource) GetInstance(string) (*api.Instance, string, error) {
	r.instanceReads.Add(1)
	if r.instance == nil {
		return nil, "", api.StatusErrorf(http.StatusNotFound, "instance not found")
	}
	return r.instance, "", nil
}

func (r *ensureFakeResource) GetInstanceState(string) (*api.InstanceState, string, error) {
	r.stateReads.Add(1)
	return &api.InstanceState{Network: map[string]api.InstanceStateNetwork{
		"eth0": {Addresses: []api.InstanceStateNetworkAddress{{Family: "inet", Scope: "global", Address: "10.123.1.134", Netmask: "24"}}},
	}}, "", nil
}

func runningInstanceForEnsureTest(config map[string]string) *api.Instance {
	return &api.Instance{
		Name:            "femke",
		StatusCode:      api.Running,
		InstancePut:     api.InstancePut{Config: config},
		ExpandedDevices: map[string]map[string]string{"eth0": {"type": "nic"}},
	}
}

func TestEnsureMachineV2ReadsARunningMachineOnce(t *testing.T) {
	resource := &ensureFakeResource{instance: runningInstanceForEnsureTest(map[string]string{})}
	creator := TenantCreator{Server: ensureFakeServer{resource: resource}}

	ensured, err := creator.EnsureMachineV2(context.Background(), CreateMachineV2Request{IncusProject: "obelix-acme-default", Name: "femke"})
	if err != nil {
		t.Fatal(err)
	}
	if !ensured.FoundUp() || ensured.Bare || ensured.LoginUser != "sebastian" {
		t.Fatalf("ensured = %+v, want an untouched, non-bare machine with login user sebastian", ensured)
	}
	if ensured.PrivateIP != "" {
		t.Fatalf("a machine found up must not have its address resolved by the ensure (got %q)", ensured.PrivateIP)
	}
	if got := resource.stateReads.Load(); got != 0 {
		t.Fatalf("ensure read the instance state %d times, want 0", got)
	}

	ip, cidr := creator.MachineAddressV2(context.Background(), ensured)
	if ip != "10.123.1.134" || cidr != "10.123.1.0/24" {
		t.Fatalf("address = %q %q", ip, cidr)
	}
	if got := resource.instanceReads.Load(); got != 1 {
		t.Fatalf("the instance was fetched %d times across ensure + address, want 1", got)
	}
	if got := resource.stateReads.Load(); got != 1 {
		t.Fatalf("the instance state was read %d times, want 1", got)
	}
}

func TestEnsureMachineV2ReportsABareMachine(t *testing.T) {
	resource := &ensureFakeResource{instance: runningInstanceForEnsureTest(map[string]string{meta.KeyV2Bare: "true"})}
	creator := TenantCreator{Server: ensureFakeServer{resource: resource}}

	ensured, err := creator.EnsureMachineV2(context.Background(), CreateMachineV2Request{IncusProject: "obelix-acme-default", Name: "femke"})
	if err != nil {
		t.Fatal(err)
	}
	if !ensured.Bare {
		t.Fatal("a machine carrying the bare marker must be reported bare")
	}
	if got := resource.instanceReads.Load(); got != 1 {
		t.Fatalf("the instance was fetched %d times, want 1", got)
	}
}
