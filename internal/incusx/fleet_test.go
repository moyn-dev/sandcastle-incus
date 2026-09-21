package incusx

import (
	"context"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// nilInstanceServer satisfies the non-nil Server check; a fleet-fed listing
// must never call it.
type nilInstanceServer struct{ incus.InstanceServer }

func TestListZoneMachinesFromShapesTheFleetWithoutListing(t *testing.T) {
	store := tenant.MemoryStore{Projects: []tenant.IncusProject{
		{Name: "sc2-acme", Config: map[string]string{meta.KeyKind: meta.KindInfra, meta.KeyTenant: "acme", meta.KeyVersion: "2", meta.KeyV2CIDR: "10.249.7.0/24"}},
		{Name: "sc2-acme-default", Config: map[string]string{meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "acme", meta.KeyVersion: "2", meta.KeyV2Domain: "acme.example"}},
	}}
	server := ZoneMachineServer{Server: nilInstanceServer{}, Store: store, Prefix: "sc2"}
	fleet := authapp.InstanceFleet{
		"sc2-acme-default": {{
			Instance: api.Instance{Project: "sc2-acme-default", Name: "web", StatusCode: api.Running, InstancePut: api.InstancePut{Config: map[string]string{meta.KeyV2PublicHostnames: "web.acme.example"}}},
			State:    &api.InstanceState{Network: map[string]api.InstanceStateNetwork{"eth0": {Addresses: []api.InstanceStateNetworkAddress{{Family: "inet", Address: "10.249.7.42"}}}}},
		}},
		"sc2-other-default": {{Instance: api.Instance{Project: "sc2-other-default", Name: "leak"}}},
	}
	machines, err := server.ListZoneMachinesFrom(context.Background(), fleet)
	if err != nil {
		t.Fatal(err)
	}
	if len(machines) != 1 || machines[0].Name != "web" || machines[0].BridgeIPv4 != "10.249.7.42" || machines[0].ProjectDomain != "acme.example" || !machines[0].Running {
		t.Fatalf("machines = %#v", machines)
	}
}

func TestFleetInstancesAbsentProjectIsEmpty(t *testing.T) {
	if got := fleetInstances(authapp.InstanceFleet{"a": nil}, "b"); got != nil {
		t.Fatalf("got %v", got)
	}
	if got := fleetInstances(nil, "b"); got != nil {
		t.Fatalf("got %v", got)
	}
	if got := installProjectPrefix("sc"); got != "sc2-" {
		t.Fatalf("prefix = %q", got)
	}
}
