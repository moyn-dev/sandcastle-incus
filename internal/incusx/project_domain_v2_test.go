package incusx

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// fakeDomainServer implements the slice of TenantCreateServer the Project
// Domain seam touches: project config and, per project, profiles + instances.
type fakeDomainServer struct {
	TenantCreateServer
	projects  map[string]*api.Project
	resources map[string]*fakeDomainResources
	updates   []string
}

func (s *fakeDomainServer) GetProject(name string) (*api.Project, string, error) {
	project, ok := s.projects[name]
	if !ok {
		return nil, "", api.StatusErrorf(http.StatusNotFound, "Project not found")
	}
	return project, "etag", nil
}

func (s *fakeDomainServer) UpdateProject(name string, put api.ProjectPut, _ string) error {
	project, ok := s.projects[name]
	if !ok {
		return api.StatusErrorf(http.StatusNotFound, "Project not found")
	}
	project.Config = put.Config
	s.updates = append(s.updates, name)
	return nil
}

func (s *fakeDomainServer) UseProject(name string) TenantResourceServer {
	if s.resources[name] == nil {
		s.resources[name] = &fakeDomainResources{profiles: map[string]api.ProfilePut{}, instances: map[string]*api.Instance{}}
	}
	return s.resources[name]
}

type fakeDomainResources struct {
	TenantResourceServer
	profiles  map[string]api.ProfilePut
	instances map[string]*api.Instance
}

func (r *fakeDomainResources) GetProfile(name string) (*api.Profile, string, error) {
	put, ok := r.profiles[name]
	if !ok {
		return nil, "", api.StatusErrorf(http.StatusNotFound, "Profile not found")
	}
	return &api.Profile{Name: name, ProfilePut: put}, "etag", nil
}

func (r *fakeDomainResources) CreateProfile(profile api.ProfilesPost) error {
	r.profiles[profile.Name] = profile.ProfilePut
	return nil
}

func (r *fakeDomainResources) UpdateProfile(name string, put api.ProfilePut, _ string) error {
	r.profiles[name] = put
	return nil
}

func (r *fakeDomainResources) GetInstanceNames(api.InstanceType) ([]string, error) {
	names := []string{}
	for name := range r.instances {
		names = append(names, name)
	}
	return names, nil
}

func (r *fakeDomainResources) GetInstance(name string) (*api.Instance, string, error) {
	instance, ok := r.instances[name]
	if !ok {
		return nil, "", api.StatusErrorf(http.StatusNotFound, "Instance not found")
	}
	return instance, "etag", nil
}

func newFakeDomainServer() *fakeDomainServer {
	return &fakeDomainServer{
		projects: map[string]*api.Project{
			"sc2-acme": {Name: "sc2-acme", ProjectPut: api.ProjectPut{Config: map[string]string{
				keyV2Bridge: "sc2-acme", keyV2Pool: "default", keyV2Suffix: "acme", keyV2CIDR: "10.249.7.0/24",
				keyV2User: "dev", keyV2SSHKey: "ssh-ed25519 AAAA", keyV2Prefix: "sc2",
			}}},
			"sc2-acme-zp": {Name: "sc2-acme-zp", ProjectPut: api.ProjectPut{Config: map[string]string{
				meta.KeyKind: meta.KindV2Project, meta.KeyVersion: "2", meta.KeyTenant: "acme", meta.KeyV2Suffix: "acme",
			}}},
		},
		resources: map[string]*fakeDomainResources{},
	}
}

func instanceWithConfig(config map[string]string) *api.Instance {
	return &api.Instance{InstancePut: api.InstancePut{Config: config, Profiles: []string{"default"}}}
}

func TestSetProjectDomainV2WritesKeyAndRerendersProfile(t *testing.T) {
	server := newFakeDomainServer()
	creator := TenantCreator{Server: server}
	ctx := context.Background()

	if err := creator.SetProjectDomainV2(ctx, "sc2", "acme", "zp", "baum.hase.de"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := server.projects["sc2-acme-zp"].Config[meta.KeyV2Domain]; got != "baum.hase.de" {
		t.Fatalf("KeyV2Domain = %q", got)
	}
	profile := server.resources["sc2-acme-zp"].profiles["default"]
	userData := profile.Config["cloud-init.user-data"]
	// The identity stays the private name; the domain lands in the
	// public-name seed line (ADR-0028).
	if !strings.Contains(userData, "fqdn: {{ v1.local_hostname }}.zp.acme\n") || tenant.PublicHostnamesEnvLineOf(userData) != tenant.PublicHostnamesEnvLine("baum.hase.de") || !strings.Contains(userData, "SIGNER=http://10.249.7.3:9443") || strings.Contains(userData, "MODE=") {
		t.Fatalf("domain profile not rendered:\n%s", userData)
	}
	if _, ok := server.resources["sc2-acme-zp"].profiles["homeshare"]; !ok {
		t.Fatal("homeshare profile not (re-)rendered alongside default")
	}

	// unset: key removed, profile back to private
	if err := creator.SetProjectDomainV2(ctx, "sc2", "acme", "zp", ""); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if _, present := server.projects["sc2-acme-zp"].Config[meta.KeyV2Domain]; present {
		t.Fatal("KeyV2Domain survived unset")
	}
	userData = server.resources["sc2-acme-zp"].profiles["default"].Config["cloud-init.user-data"]
	if !strings.Contains(userData, "fqdn: {{ v1.local_hostname }}.zp.acme\n") || tenant.PublicHostnamesEnvLineOf(userData) != tenant.PublicHostnamesEnvLine("") {
		t.Fatalf("private profile not restored:\n%s", userData)
	}

	// unknown project → ErrProjectNotFound (404 at the Auth App)
	err := creator.SetProjectDomainV2(ctx, "sc2", "acme", "nope", "x.hase.de")
	if !errors.Is(err, projectbroker.ErrProjectNotFound) {
		t.Fatalf("missing project: %v", err)
	}
}

// The broker adapter maps the seam onto the creator (and refuses deletion
// without a deleter).
func TestProjectBrokerCreatorDomainSeam(t *testing.T) {
	server := newFakeDomainServer()
	adapter := ProjectBrokerCreator{Creator: TenantCreator{Server: server}, Prefix: "sc2"}
	ctx := context.Background()
	if err := adapter.SetProjectDomain(ctx, "acme", "zp", "baum.hase.de"); err != nil {
		t.Fatal(err)
	}
	if got := server.projects["sc2-acme-zp"].Config[meta.KeyV2Domain]; got != "baum.hase.de" {
		t.Fatalf("KeyV2Domain = %q", got)
	}
	if err := adapter.DeleteTenantProject(ctx, "acme", "zp"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("delete without deleter: %v", err)
	}
}
