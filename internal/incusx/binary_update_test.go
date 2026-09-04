package incusx

import (
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
)

type fakeBinaryUpdateServer struct {
	TenantCreateServer
	project  *api.Project
	resource *fakeBinaryUpdateResource
}

func (s *fakeBinaryUpdateServer) GetProject(string) (*api.Project, string, error) {
	return s.project, "etag-project", nil
}

func (s *fakeBinaryUpdateServer) UseProject(string) TenantResourceServer {
	return s.resource
}

type fakeBinaryUpdateResource struct {
	TenantResourceServer
	instance *api.Instance
	execs    []string
}

func (r *fakeBinaryUpdateResource) GetInstance(string) (*api.Instance, string, error) {
	return r.instance, "etag-instance", nil
}

func (r *fakeBinaryUpdateResource) CreateInstanceFile(string, string, incus.InstanceFileArgs) error {
	return nil
}

func (r *fakeBinaryUpdateResource) UpdateInstance(string, api.InstancePut, string) (incus.Operation, error) {
	return fakeOperation{}, nil
}

func (r *fakeBinaryUpdateResource) ExecInstance(_ string, post api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error) {
	r.execs = append(r.execs, strings.Join(post.Command, " "))
	if args != nil && args.DataDone != nil {
		close(args.DataDone)
	}
	return fakeOperation{}, nil
}

func fullInstance(project, name, kind, tenant, binaryVersion, status string) api.InstanceFull {
	cfg := map[string]string{meta.KeyKind: kind}
	if tenant != "" {
		cfg[meta.KeyTenant] = tenant
	}
	if binaryVersion != "" {
		cfg[meta.KeyBinaryVersion] = binaryVersion
	}
	return api.InstanceFull{Instance: api.Instance{
		Name:        name,
		Project:     project,
		Status:      status,
		InstancePut: api.InstancePut{Config: cfg},
	}}
}

func TestClassifyComponentsFiltersAndMaps(t *testing.T) {
	instances := []api.InstanceFull{
		fullInstance("infrastructure", "sc2-auth-app", "auth-app", "", "v0.2.0", "Running"),
		fullInstance("sc2-broker", "sc2-broker", "broker", "", "", "Stopped"),
		fullInstance("sc2-acme", "sidecar", "sidecar", "acme", "v0.1.0", "Running"),
		fullInstance("sc2-acme-default", "web", "machine", "acme", "", "Running"),
		{Instance: api.Instance{Name: "unrelated", Project: "default", Status: "Running"}},
	}
	got := classifyComponents(instances)
	if len(got) != 3 {
		t.Fatalf("expected 3 components, got %d: %+v", len(got), got)
	}
	authApp := got[0]
	if authApp.Kind != "auth-app" || authApp.Instance != "sc2-auth-app" || authApp.BinaryVersion != "v0.2.0" ||
		authApp.Status != "Running" || authApp.TenantManaged {
		t.Fatalf("auth-app row wrong: %+v", authApp)
	}
	broker := got[1]
	if broker.Kind != "broker" || broker.BinaryVersion != "" || broker.Status != "Stopped" {
		t.Fatalf("broker row wrong: %+v", broker)
	}
	sidecar := got[2]
	if sidecar.Kind != "sidecar" || sidecar.Tenant != "acme" || !sidecar.TenantManaged ||
		sidecar.Project != "sc2-acme" {
		t.Fatalf("sidecar row wrong: %+v", sidecar)
	}
}

func TestUpdateTenantSidecarReconcilesIncusReach(t *testing.T) {
	resource := &fakeBinaryUpdateResource{instance: &api.Instance{InstancePut: api.InstancePut{Config: map[string]string{
		meta.KeyKind: meta.KindSidecar,
	}}}}
	server := &fakeBinaryUpdateServer{
		project: &api.Project{ProjectPut: api.ProjectPut{Config: map[string]string{
			meta.KeyV2CIDR: "10.249.7.0/24",
		}}},
		resource: resource,
	}
	creator := TenantCreator{Server: server}

	if _, err := creator.UpdateTenantSidecar("sc2", "acme", []byte("binary"), "v1.2.3"); err != nil {
		t.Fatalf("UpdateTenantSidecar: %v", err)
	}

	want := "tailscale serve --bg --tcp=8443 tcp://10.249.7.1:8443"
	found := false
	for _, command := range resource.execs {
		if strings.Contains(command, want) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Incus Reach was not reconciled; commands: %q", resource.execs)
	}
}
