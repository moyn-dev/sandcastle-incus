package cli

import (
	"net/http"
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// scratchMigrateServer serves the tenant projects of a MemoryStore and one
// running container in every app project, enough for scratch-migrate --check.
type scratchMigrateServer struct {
	incusx.TenantCreateServer
	projects []tenant.IncusProject
}

func (s scratchMigrateServer) GetProject(name string) (*api.Project, string, error) {
	for _, project := range s.projects {
		if project.Name == name {
			return &api.Project{Name: name, ProjectPut: api.ProjectPut{Config: project.Config}}, "", nil
		}
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "project not found")
}

func (s scratchMigrateServer) GetProjectNames() ([]string, error) {
	var names []string
	for _, project := range s.projects {
		names = append(names, project.Name)
	}
	return names, nil
}

func (s scratchMigrateServer) SupportsIdmappedMounts() bool { return false }

func (s scratchMigrateServer) UseProject(string) incusx.TenantResourceServer {
	return scratchMigrateResource{}
}

type scratchMigrateResource struct{ incusx.TenantResourceServer }

func (scratchMigrateResource) GetProfile(string) (*api.Profile, string, error) {
	return nil, "", api.StatusErrorf(http.StatusNotFound, "no profile")
}

func (scratchMigrateResource) GetInstances(api.InstanceType) ([]api.Instance, error) {
	return []api.Instance{{Name: "dev", Type: "container", StatusCode: api.Running}}, nil
}

func (scratchMigrateResource) GetStoragePoolVolume(string, string, string) (*api.StorageVolume, string, error) {
	return nil, "", api.StatusErrorf(http.StatusNotFound, "volume not found")
}

func TestScratchMigrateFindsTheInstallOfTheTenant(t *testing.T) {
	projects := v2TenantProjectsWithPrefix("obelix", "thieso2", "10.123.0.0/24", "default")
	config := commandConfig{
		name:          "sc-adm",
		adminConfig:   testAdminConfig(),
		tenantStore:   tenant.MemoryStore{Projects: projects},
		tenantCreator: incusx.TenantCreator{Server: scratchMigrateServer{projects: projects}},
	}
	stdout, stderr, err := executeAdminForTestWithConfigAndStderr(t, config, "tenant", "scratch-migrate", "thieso2", "--check")
	if err != nil {
		t.Fatalf("scratch-migrate on a non-default install: %v", err)
	}
	if !strings.Contains(stdout, "obelix-thieso2-default/dev (container): would attach") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, `lives on install "obelix"`) {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestFormatScratchMigration(t *testing.T) {
	got := formatScratchMigration([]incusx.ScratchMigrationStatus{
		{IncusProject: "sc2-acme-default", Machine: "web", Type: "container", Volume: "web-scratch", State: incusx.ScratchAttachedLive},
		{IncusProject: "sc2-acme-default", Machine: "vm1", Type: "virtual-machine", Volume: "vm1-scratch", State: incusx.ScratchAttachedNextRestart},
		{IncusProject: "sc2-acme-default", Machine: "bad", Type: "container", Volume: "bad-scratch", State: incusx.ScratchFailed, Error: "foreign volume"},
		{IncusProject: "sc2-acme-default", Machine: "edge", Type: "container", State: incusx.ScratchSkippedBare},
	})
	want := "sc2-acme-default/web (container): attached (live) [web-scratch]\n" +
		"sc2-acme-default/vm1 (virtual-machine): attached (VM: restart to mount) [vm1-scratch]\n" +
		"sc2-acme-default/bad (container): FAILED [bad-scratch]: foreign volume\n" +
		"sc2-acme-default/edge (container): skipped (bare machine: re-create it to get scratch)"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}
