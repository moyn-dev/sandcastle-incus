package incusx

import (
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// fakeHomeShareResource implements only the handful of TenantResourceServer
// methods the homeshare migration touches.
type fakeHomeShareResource struct {
	TenantResourceServer
	defaultDevices map[string]map[string]string
	instances      map[string]*api.Instance
	updated        map[string][]string
}

func (r *fakeHomeShareResource) GetProfile(name string) (*api.Profile, string, error) {
	return &api.Profile{Name: name, ProfilePut: api.ProfilePut{Devices: r.defaultDevices}}, "etag", nil
}

func (r *fakeHomeShareResource) GetInstanceNames(api.InstanceType) ([]string, error) {
	names := []string{}
	for name := range r.instances {
		names = append(names, name)
	}
	return names, nil
}

func (r *fakeHomeShareResource) GetInstance(name string) (*api.Instance, string, error) {
	return r.instances[name], "etag", nil
}

func (r *fakeHomeShareResource) UpdateInstance(name string, put api.InstancePut, etag string) (incus.Operation, error) {
	if r.updated == nil {
		r.updated = map[string][]string{}
	}
	r.updated[name] = put.Profiles
	return fakeOperation{}, nil
}

func instanceWithProfiles(profiles ...string) *api.Instance {
	return &api.Instance{InstancePut: api.InstancePut{Profiles: profiles}}
}

// Machines created before the profile split mounted the shared /home through
// the default profile. Re-rendering default without that device would swap
// their home directory (and the login user's ~/.ssh) for the image's empty
// one, so they are moved onto the homeshare profile first.
func TestMigrateV2MachinesToHomeShare(t *testing.T) {
	resource := &fakeHomeShareResource{
		defaultDevices: map[string]map[string]string{
			"home": {"type": "disk", "source": tenant.V2HomeVolumeName, "path": "/home"},
		},
		instances: map[string]*api.Instance{
			"legacy":  instanceWithProfiles("default"),
			"already": instanceWithProfiles("default", tenant.V2HomeShareProfileName),
			"custom":  instanceWithProfiles("isolated"),
		},
	}

	if err := migrateV2MachinesToHomeShare(resource, func(string) {}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	want := []string{"default", tenant.V2HomeShareProfileName}
	got := resource.updated["legacy"]
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("legacy machine profiles = %v, want %v", got, want)
	}
	if _, ok := resource.updated["already"]; ok {
		t.Fatalf("a machine that already has homeshare must not be updated")
	}
	if _, ok := resource.updated["custom"]; ok {
		t.Fatalf("a machine that does not use the default profile must not be updated")
	}
}

// Once default no longer carries the /home device there is nothing to migrate
// — the pass must not touch machines on every later reconcile.
func TestMigrateV2MachinesToHomeShareSkipsSplitProfile(t *testing.T) {
	resource := &fakeHomeShareResource{
		defaultDevices: map[string]map[string]string{
			"workspace": {"type": "disk", "source": tenant.V2WorkspaceVolumeName, "path": "/workspace"},
		},
		instances: map[string]*api.Instance{"legacy": instanceWithProfiles("default")},
	}

	if err := migrateV2MachinesToHomeShare(resource, func(string) {}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if len(resource.updated) != 0 {
		t.Fatalf("no machine should be updated: %v", resource.updated)
	}
}
