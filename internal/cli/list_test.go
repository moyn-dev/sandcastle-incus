package cli

import (
	"context"
	"sort"
	"strings"
	"testing"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	machine "github.com/moyn-dev/sandcastle-incus/internal/machine"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// fakeInstallMachineStore returns each install's machines keyed by the
// summary's infra project name (<prefix>-<tenant>), which is what
// distinguishes same-named tenants of different installs.
type fakeInstallMachineStore struct {
	byInfraProject map[string][]meta.Machine
}

func (s fakeInstallMachineStore) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	return s.byInfraProject[summary.InfraProject], nil
}

var _ machine.Store = fakeInstallMachineStore{}

// Two installs share one Incus daemon and both have a tenant named "acme".
// `sc list` must resolve the tenant of the install the configured remote
// belongs to — matching by tenant name alone can land on the OTHER install's
// same-named tenant, making a machine created seconds earlier invisible.
func TestListMachinesScopedToCurrentInstall(t *testing.T) {
	v2Project := func(name string) tenant.IncusProject {
		return tenant.IncusProject{Name: name, Config: map[string]string{
			meta.KeyKind:    meta.KindV2Project,
			meta.KeyVersion: "2",
			meta.KeyTenant:  "acme",
		}}
	}
	store := tenant.MemoryStore{Projects: []tenant.IncusProject{
		// "id"-install tenant sorts ahead of the sc2 one, so an unscoped
		// name-only match would pick it.
		v2Project("id-acme-default"),
		v2Project("sc2-acme-default"),
	}}
	machines := fakeInstallMachineStore{byInfraProject: map[string][]meta.Machine{
		"sc2-acme": {{Name: "web", Project: "default", Running: true}},
		"id-acme":  {},
	}}

	tests := []struct {
		name         string
		remote       string
		wantInfra    string
		wantMachines int
	}{
		{"default-prefix remote sees its own machine", "sc-acme", "sc2-acme", 1},
		{"prefixed remote sees its own (empty) install", "sc-id-acme", "id-acme", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := commandConfig{
				adminConfig:  scconfig.Admin{Tenant: "acme", Remote: tt.remote},
				tenantStore:  store,
				machineStore: machines,
			}
			result, err := listMachines(context.Background(), config, listMachinesRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if result.Tenant.InfraProject != tt.wantInfra {
				t.Fatalf("resolved tenant of install %q, want %q", result.Tenant.InfraProject, tt.wantInfra)
			}
			if len(result.Machines) != tt.wantMachines {
				t.Fatalf("got %d machines, want %d: %+v", len(result.Machines), tt.wantMachines, result.Machines)
			}
		})
	}
}

// listV2Projects builds the tenant-store projects backing a v2 tenant summary.
func listV2Projects(tenantName string, projects ...string) []tenant.IncusProject {
	built := make([]tenant.IncusProject, 0, len(projects))
	for _, project := range projects {
		built = append(built, tenant.IncusProject{
			Name: "sc2-" + tenantName + "-" + project,
			Config: map[string]string{
				meta.KeyKind:    meta.KindV2Project,
				meta.KeyVersion: "2",
				meta.KeyTenant:  tenantName,
			},
		})
	}
	return built
}

// `sc ls` filters on both reference parts, so "g*:d*" is the d* machines of
// every project matching g*.
func TestListMachinesWildcardFilters(t *testing.T) {
	store := tenant.MemoryStore{Projects: listV2Projects("acme", "gbrain", "gadget", "work")}
	machines := fakeInstallMachineStore{byInfraProject: map[string][]meta.Machine{
		"sc2-acme": {
			{Name: "docker", Project: "gbrain"},
			{Name: "dev", Project: "gbrain"},
			{Name: "web", Project: "gbrain"},
			{Name: "dyno", Project: "gadget"},
			{Name: "web", Project: "work"},
		},
	}}
	config := commandConfig{
		adminConfig:  scconfig.Admin{Tenant: "acme", Remote: "sc-acme"},
		tenantStore:  store,
		machineStore: machines,
	}

	tests := []struct {
		name    string
		request listMachinesRequest
		want    []string
	}{
		{"project and machine globs", listMachinesRequest{Project: "g*", Machine: "d*", AllProjects: true},
			[]string{"gadget:dyno", "gbrain:dev", "gbrain:docker"}},
		{"every machine of one project", listMachinesRequest{Project: "gbrain", Machine: "*"},
			[]string{"gbrain:dev", "gbrain:docker", "gbrain:web"}},
		{"one machine name across all projects", listMachinesRequest{Project: "*", Machine: "web", AllProjects: true},
			[]string{"gbrain:web", "work:web"}},
		{"a glob matching nothing lists nothing", listMachinesRequest{Project: "gbrain", Machine: "zzz*"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := listMachines(context.Background(), config, tt.request)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(result.Machines))
			for _, m := range result.Machines {
				got = append(got, m.Project+":"+m.Name)
			}
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("machines = %v, want %v", got, tt.want)
			}
		})
	}
}

// A project GLOB that matches nothing is an empty listing; a literal project
// that does not exist is still an error, so a typo does not read as "no
// machines".
func TestListMachinesProjectGlobVersusTypo(t *testing.T) {
	store := tenant.MemoryStore{Projects: listV2Projects("acme", "gbrain")}
	config := commandConfig{
		adminConfig:  scconfig.Admin{Tenant: "acme", Remote: "sc-acme"},
		tenantStore:  store,
		machineStore: fakeInstallMachineStore{byInfraProject: map[string][]meta.Machine{"sc2-acme": {}}},
	}
	if _, err := listMachines(context.Background(), config, listMachinesRequest{Project: "zzz*"}); err != nil {
		t.Fatalf("project glob matching nothing: %v, want an empty listing", err)
	}
	_, err := listMachines(context.Background(), config, listMachinesRequest{Project: "gbrian"})
	if err == nil || !strings.Contains(err.Error(), "not found in tenant") {
		t.Fatalf("literal typo error = %v, want a project-not-found error", err)
	}
}

// A listing marks bare machines in the TYPE column: it is the column that says
// what the machine IS, and the mark is what explains why `sc connect` opens an
// Incus exec session on that row and an SSH session on the others.
func TestMachineTypeCellMarksBareMachines(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    meta.Machine
		want string
	}{
		{"container", meta.Machine{Type: meta.MachineTypeContainer}, "CT"},
		{"vm", meta.Machine{Type: "virtual-machine"}, "VM"},
		{"bare container", meta.Machine{Type: meta.MachineTypeContainer, Bare: true}, "CT (bare)"},
		{"bare vm", meta.Machine{Type: "virtual-machine", Bare: true}, "VM (bare)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := machineTypeCell(tc.m); got != tc.want {
				t.Fatalf("machineTypeCell = %q, want %q", got, tc.want)
			}
		})
	}
}
