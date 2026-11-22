package incusx

import (
	"testing"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// fakeProfileDetachResource implements only the profile methods the shared
// volume detach touches.
type fakeProfileDetachResource struct {
	TenantDeleteResourceServer
	profiles map[string]map[string]map[string]string
	updated  map[string]map[string]map[string]string
}

func (r *fakeProfileDetachResource) GetProfiles() ([]api.Profile, error) {
	listed := []api.Profile{}
	for name := range r.profiles {
		listed = append(listed, api.Profile{Name: name})
	}
	return listed, nil
}

func (r *fakeProfileDetachResource) GetProfile(name string) (*api.Profile, string, error) {
	devices := map[string]map[string]string{}
	for key, device := range r.profiles[name] {
		copied := map[string]string{}
		for k, v := range device {
			copied[k] = v
		}
		devices[key] = copied
	}
	return &api.Profile{Name: name, ProfilePut: api.ProfilePut{Devices: devices}}, "etag", nil
}

func (r *fakeProfileDetachResource) UpdateProfile(name string, profile api.ProfilePut, etag string) error {
	if r.updated == nil {
		r.updated = map[string]map[string]map[string]string{}
	}
	r.updated[name] = profile.Devices
	return nil
}

// A volume cannot be deleted while ANY profile references it, and /home hangs
// off `homeshare` — so the detach sweep must cover every profile, not just
// `default`.
func TestClearVolumeDevicesFromProfiles(t *testing.T) {
	resource := &fakeProfileDetachResource{profiles: map[string]map[string]map[string]string{
		"default": {
			"root":      {"type": "disk", "pool": "default", "path": "/"},
			"workspace": {"type": "disk", "source": tenant.V2WorkspaceVolumeName, "path": "/workspace"},
		},
		tenant.V2HomeShareProfileName: {
			"home": {"type": "disk", "source": tenant.V2HomeVolumeName, "path": "/home"},
		},
		"untouched": {
			"eth0": {"type": "nic", "parent": "sc2-acme"},
		},
	}}

	err := TenantDeleter{}.clearVolumeDevicesFromProfiles(resource, "sc2-acme-default",
		[]string{tenant.V2HomeVolumeName, tenant.V2WorkspaceVolumeName})
	if err != nil {
		t.Fatalf("detach: %v", err)
	}

	if _, ok := resource.updated[tenant.V2HomeShareProfileName]["home"]; ok {
		t.Fatalf("home must be detached from the homeshare profile: %v", resource.updated)
	}
	if _, ok := resource.updated["default"]["workspace"]; ok {
		t.Fatalf("workspace must be detached from the default profile: %v", resource.updated)
	}
	if _, ok := resource.updated["default"]["root"]; !ok {
		t.Fatalf("the root disk is not a shared volume and must stay: %v", resource.updated)
	}
	if _, ok := resource.updated["untouched"]; ok {
		t.Fatalf("a profile without shared volumes must not be written: %v", resource.updated)
	}
}
