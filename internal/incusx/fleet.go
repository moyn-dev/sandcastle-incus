package incusx

import (
	"context"
	"fmt"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// FleetServer implements authapp.FleetLister over the mounted host socket:
// ONE all-projects listing per pass instead of one per project per
// reconciler (HANDOFF incusd-polling), scoped to the install's prefix, and a
// single-project re-read for the projects a lifecycle event named.
type FleetServer struct {
	Server incus.InstanceServer
	Prefix string
}

var _ authapp.FleetLister = FleetServer{}

// NewFleetServer builds the lister over an already-connected server.
func NewFleetServer(server incus.InstanceServer, prefix string) FleetServer {
	return FleetServer{Server: server, Prefix: prefix}
}

// installProjectPrefix is "<prefix>-": the namespace every project of the
// install lives under (infra `<prefix>-<tenant>` and apps `<prefix>-<tenant>-<p>`).
func installProjectPrefix(prefix string) string {
	return naming.NormalizeV2Prefix(prefix) + "-"
}

func (f FleetServer) ListFleet(ctx context.Context) (authapp.InstanceFleet, error) {
	if f.Server == nil {
		return nil, fmt.Errorf("fleet lister has no Incus connection")
	}
	instances, err := f.Server.GetInstancesFullAllProjects(api.InstanceTypeAny)
	if err != nil {
		return nil, fmt.Errorf("list instances across projects: %w", err)
	}
	fleet := authapp.InstanceFleet{}
	prefix := installProjectPrefix(f.Prefix)
	for _, instance := range instances {
		if !strings.HasPrefix(instance.Project, prefix) {
			continue
		}
		fleet[instance.Project] = append(fleet[instance.Project], instance)
	}
	return fleet, nil
}

func (f FleetServer) ListProjectInstances(ctx context.Context, project string) ([]api.InstanceFull, error) {
	if f.Server == nil {
		return nil, fmt.Errorf("fleet lister has no Incus connection")
	}
	instances, err := f.Server.UseProject(project).GetInstancesFull(api.InstanceTypeAny)
	if err != nil {
		return nil, fmt.Errorf("list %s instances: %w", project, err)
	}
	return instances, nil
}

// fleetInstances returns a project's instances from the fleet ("" and false
// when the fleet does not carry the project: absent means "no instances",
// which is the same answer a live listing of an empty project gives).
func fleetInstances(fleet authapp.InstanceFleet, project string) []api.InstanceFull {
	if fleet == nil {
		return nil
	}
	return fleet[project]
}
