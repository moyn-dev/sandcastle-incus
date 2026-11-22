package incusx

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// fakeScratchServer is an in-memory Incus host with app projects, enough of
// the instance and custom-volume API for the scratch create, delete and
// migration paths.
type fakeScratchServer struct {
	TenantCreateServer
	shifted   bool
	projects  map[string]*api.Project
	resources map[string]*fakeScratchResource
}

func (s *fakeScratchServer) UseProject(name string) TenantResourceServer { return s.resources[name] }
func (s *fakeScratchServer) SupportsIdmappedMounts() bool                { return s.shifted }

func (s *fakeScratchServer) GetProject(name string) (*api.Project, string, error) {
	if project := s.projects[name]; project != nil {
		return project, "etag", nil
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "project not found")
}

func (s *fakeScratchServer) GetProjectNames() ([]string, error) {
	return slices.Sorted(maps.Keys(s.projects)), nil
}

type fakeScratchResource struct {
	TenantResourceServer
	profile   *api.Profile
	instances map[string]*api.Instance
	volumes   map[string]*api.StorageVolume
	// poolVolumeDefaults mimics a pool's volume.* keys, which Incus copies
	// into every empty key of a new volume's config.
	poolVolumeDefaults map[string]string

	createInstanceErr error
	getVolumeErr      error
	updateVolumeErr   error
	deleteVolumeErr   error

	createdInstances []api.InstancesPost
	createdVolumes   []api.StorageVolumesPost
	deletedVolumes   []string
	updatedInstances []string
}

func newFakeScratchResource(pool string) *fakeScratchResource {
	return &fakeScratchResource{
		profile: &api.Profile{Name: "default", ProfilePut: api.ProfilePut{
			Config:  map[string]string{},
			Devices: map[string]map[string]string{"sc-platform": {"type": "disk", "pool": pool, "source": tenant.V2SCPlatformVolumeName, "path": "/.sc/platform"}},
		}},
		instances: map[string]*api.Instance{},
		volumes:   map[string]*api.StorageVolume{},
	}
}

func (r *fakeScratchResource) GetProfile(string) (*api.Profile, string, error) {
	return r.profile, "etag", nil
}

func (r *fakeScratchResource) GetInstance(name string) (*api.Instance, string, error) {
	if instance := r.instances[name]; instance != nil {
		return instance, "etag-" + name, nil
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "instance not found")
}

func (r *fakeScratchResource) GetInstances(api.InstanceType) ([]api.Instance, error) {
	out := []api.Instance{}
	for _, name := range slices.Sorted(maps.Keys(r.instances)) {
		out = append(out, *r.instances[name])
	}
	return out, nil
}

func (r *fakeScratchResource) GetInstanceState(string) (*api.InstanceState, string, error) {
	return nil, "", errors.New("no state")
}

func (r *fakeScratchResource) CreateInstance(post api.InstancesPost) (incus.Operation, error) {
	r.createdInstances = append(r.createdInstances, post)
	if r.createInstanceErr != nil {
		return nil, r.createInstanceErr
	}
	r.instances[post.Name] = &api.Instance{Name: post.Name, Type: string(post.Type), StatusCode: api.Running, InstancePut: post.InstancePut}
	return fakeOperation{}, nil
}

func (r *fakeScratchResource) UpdateInstance(name string, put api.InstancePut, _ string) (incus.Operation, error) {
	r.updatedInstances = append(r.updatedInstances, name)
	r.instances[name].InstancePut = put
	return fakeOperation{}, nil
}

func (r *fakeScratchResource) UpdateInstanceState(string, api.InstanceStatePut, string) (incus.Operation, error) {
	return fakeOperation{}, nil
}

func (r *fakeScratchResource) DeleteInstance(name string) (incus.Operation, error) {
	delete(r.instances, name)
	return fakeOperation{}, nil
}

func (r *fakeScratchResource) GetStoragePoolVolume(_ string, _ string, name string) (*api.StorageVolume, string, error) {
	if r.getVolumeErr != nil {
		return nil, "", r.getVolumeErr
	}
	if volume := r.volumes[name]; volume != nil {
		return volume, "etag-" + name, nil
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "volume not found")
}

func (r *fakeScratchResource) GetStoragePoolVolumes(string) ([]api.StorageVolume, error) {
	out := []api.StorageVolume{}
	for _, name := range slices.Sorted(maps.Keys(r.volumes)) {
		out = append(out, *r.volumes[name])
	}
	return out, nil
}

func (r *fakeScratchResource) CreateStoragePoolVolume(_ string, post api.StorageVolumesPost) error {
	r.createdVolumes = append(r.createdVolumes, post)
	config := maps.Clone(post.Config)
	for key, value := range r.poolVolumeDefaults {
		if config[key] == "" {
			config[key] = value
		}
	}
	r.volumes[post.Name] = &api.StorageVolume{Name: post.Name, Type: post.Type, StorageVolumePut: api.StorageVolumePut{Description: post.Description, Config: config}}
	return nil
}

func (r *fakeScratchResource) UpdateStoragePoolVolume(_ string, _ string, name string, put api.StorageVolumePut, _ string) error {
	if r.updateVolumeErr != nil {
		return r.updateVolumeErr
	}
	r.volumes[name].StorageVolumePut = put
	return nil
}

func (r *fakeScratchResource) DeleteStoragePoolVolume(_ string, _ string, name string) error {
	if r.deleteVolumeErr != nil {
		return r.deleteVolumeErr
	}
	if r.volumes[name] == nil {
		return api.StatusErrorf(http.StatusNotFound, "volume not found")
	}
	r.deletedVolumes = append(r.deletedVolumes, name)
	delete(r.volumes, name)
	return nil
}

func scratchMachineFixture(pool string) (*fakeScratchResource, TenantCreator) {
	resource := newFakeScratchResource(pool)
	scratch := tenant.MachineScratch{Machine: "web", Pool: pool, Size: tenant.DefaultScratchSize}
	resource.instances["web"] = &api.Instance{Name: "web", StatusCode: api.Running, InstancePut: api.InstancePut{
		Devices: map[string]map[string]string{tenant.ScratchDeviceName: scratch.Device()},
	}}
	resource.volumes["web-scratch"] = &api.StorageVolume{Name: "web-scratch", Type: "custom", StorageVolumePut: api.StorageVolumePut{Config: scratch.VolumeConfig(false)}}
	server := &fakeScratchServer{resources: map[string]*fakeScratchResource{"sc-acme-default": resource}}
	return resource, TenantCreator{Server: server}
}

func TestMachineDeleteRemovesItsScratchVolume(t *testing.T) {
	resource, creator := scratchMachineFixture("tank")
	if err := creator.MachineLifecycleV2(context.Background(), "sc-acme-default", "web", "delete"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resource.instances["web"] != nil {
		t.Fatal("instance still exists")
	}
	if resource.volumes["web-scratch"] != nil || !slices.Equal(resource.deletedVolumes, []string{"web-scratch"}) {
		t.Fatalf("scratch volume not deleted: deleted=%v", resource.deletedVolumes)
	}
}

func TestMachineDeleteToleratesAMissingScratchVolume(t *testing.T) {
	resource, creator := scratchMachineFixture("tank")
	delete(resource.volumes, "web-scratch")
	if err := creator.MachineLifecycleV2(context.Background(), "sc-acme-default", "web", "delete"); err != nil {
		t.Fatalf("delete with the scratch volume already gone: %v", err)
	}
}

func TestMachineDeleteLeavesAnUnmarkedVolumeAlone(t *testing.T) {
	resource, creator := scratchMachineFixture("tank")
	resource.volumes["web-scratch"].Config = map[string]string{}
	if err := creator.MachineLifecycleV2(context.Background(), "sc-acme-default", "web", "delete"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resource.volumes["web-scratch"] == nil || len(resource.deletedVolumes) != 0 {
		t.Fatalf("an unmarked volume was deleted: %v", resource.deletedVolumes)
	}
}

func TestMachineDeleteReportsAFailedScratchDelete(t *testing.T) {
	resource, creator := scratchMachineFixture("tank")
	resource.deleteVolumeErr = api.StatusErrorf(http.StatusInternalServerError, "volume busy")
	err := creator.MachineLifecycleV2(context.Background(), "sc-acme-default", "web", "delete")
	if err == nil || !strings.Contains(err.Error(), "scratch volume") || !strings.Contains(err.Error(), "volume busy") {
		t.Fatalf("want an error naming the scratch volume failure, got %v", err)
	}
	if resource.instances["web"] != nil {
		t.Fatal("the instance should be deleted before the volume")
	}
}

func TestProjectDeleteSweepsScratchVolumes(t *testing.T) {
	resource := &fakeDeleteResourceServer{
		instances: map[string]*api.Instance{"web": {Name: "web", StatusCode: api.Stopped}},
		volumes: []api.StorageVolume{
			{Name: "web-scratch", Type: "custom", StorageVolumePut: api.StorageVolumePut{Config: map[string]string{meta.KeyScratch: "true"}}},
			{Name: "data", Type: "custom", StorageVolumePut: api.StorageVolumePut{Config: map[string]string{}}},
			{Name: "web", Type: "container", StorageVolumePut: api.StorageVolumePut{Config: map[string]string{meta.KeyScratch: "true"}}},
		},
	}
	server := &fakeDeleteServer{resourceServer: resource}
	if err := (TenantDeleter{Server: server}).DeleteProjectV2(context.Background(), "sc-acme-default", "tank"); err != nil {
		t.Fatalf("DeleteProjectV2: %v", err)
	}
	if !slices.Contains(resource.deletedVolumes, "web-scratch") {
		t.Fatalf("scratch volume not swept: %v", resource.deletedVolumes)
	}
	if slices.Contains(resource.deletedVolumes, "data") || slices.Contains(resource.deletedVolumes, "web") {
		t.Fatalf("sweep deleted a volume that is not a marked custom volume: %v", resource.deletedVolumes)
	}
	if server.deletedProject != "sc-acme-default" {
		t.Fatalf("project not deleted: %q", server.deletedProject)
	}
}
