package incusx

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func scratchCreateFixture(t *testing.T) (*fakeScratchResource, TenantCreator, context.Context) {
	t.Helper()
	resource := newFakeScratchResource("tank")
	resource.profile.Config["cloud-init.user-data"] = tenant.V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "default", "acme", "http://10.0.0.3:9443")
	server := &fakeScratchServer{shifted: true, resources: map[string]*fakeScratchResource{"sc-acme-default": resource}}
	// A cancelled context ends the post-create IPv4 wait after one pass.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return resource, TenantCreator{Server: server}, ctx
}

func scratchRequest() CreateMachineV2Request {
	return CreateMachineV2Request{IncusProject: "sc-acme-default", Name: "web", Image: "images:debian/13"}
}

func markedScratchVolume(size string) *api.StorageVolume {
	spec := tenant.MachineScratch{Machine: "web", Pool: "tank", Size: size}
	return &api.StorageVolume{Name: spec.VolumeName(), Type: "custom", StorageVolumePut: api.StorageVolumePut{Config: spec.VolumeConfig(true)}}
}

func TestCreateMachineAttachesAScratchVolume(t *testing.T) {
	vm := scratchRequest()
	vm.VM, vm.ScratchSize = true, "20GiB"
	bare := scratchRequest()
	bare.Bare = true
	for name, request := range map[string]CreateMachineV2Request{"container": scratchRequest(), "vm": vm, "bare": bare} {
		t.Run(name, func(t *testing.T) {
			resource, creator, ctx := scratchCreateFixture(t)
			result, err := creator.CreateMachineV2(ctx, request)
			if err != nil {
				t.Fatalf("CreateMachineV2: %v", err)
			}
			size := tenant.DefaultScratchSize
			if request.ScratchSize != "" {
				size = request.ScratchSize
			}
			want := tenant.MachineScratch{Machine: "web", Pool: "tank", Size: size}
			volume := resource.volumes["web-scratch"]
			if volume == nil || !maps.Equal(volume.Config, want.VolumeConfig(true)) {
				t.Fatalf("scratch volume = %+v, want config %v", volume, want.VolumeConfig(true))
			}
			if len(resource.createdInstances) != 1 {
				t.Fatalf("created %d instances, want 1", len(resource.createdInstances))
			}
			devices := resource.createdInstances[0].Devices
			if !maps.Equal(devices[tenant.ScratchDeviceName], want.Device()) {
				t.Fatalf("scratch device = %v, want %v", devices[tenant.ScratchDeviceName], want.Device())
			}
			if request.Bare && (devices["home"]["type"] != "none" || devices["workspace"]["type"] != "none") {
				t.Fatalf("bare machine lost its shared-filesystem masks: %v", devices)
			}
			if result.ScratchVolume != "web-scratch" || result.ScratchSize != size {
				t.Fatalf("result scratch = %q %q", result.ScratchVolume, result.ScratchSize)
			}
		})
	}
}

func TestCreateMachineWithoutScratch(t *testing.T) {
	resource, creator, ctx := scratchCreateFixture(t)
	request := scratchRequest()
	request.NoScratch = true
	result, err := creator.CreateMachineV2(ctx, request)
	if err != nil {
		t.Fatalf("CreateMachineV2: %v", err)
	}
	if len(resource.createdVolumes) != 0 || resource.createdInstances[0].Devices[tenant.ScratchDeviceName] != nil {
		t.Fatalf("--no-scratch created %v and devices %v", resource.createdVolumes, resource.createdInstances[0].Devices)
	}
	if result.ScratchVolume != "" {
		t.Fatalf("result reports scratch volume %q", result.ScratchVolume)
	}
}

func TestCreateMachineRefusesAnUnmarkedSameNameVolume(t *testing.T) {
	resource, creator, ctx := scratchCreateFixture(t)
	resource.volumes["web-scratch"] = &api.StorageVolume{Name: "web-scratch", Type: "custom", StorageVolumePut: api.StorageVolumePut{Config: map[string]string{"size": "5GiB"}}}
	_, err := creator.CreateMachineV2(ctx, scratchRequest())
	if err == nil || !strings.Contains(err.Error(), "not a Sandcastle scratch volume") {
		t.Fatalf("want a refusal to adopt the volume, got %v", err)
	}
	if len(resource.createdInstances) != 0 {
		t.Fatal("an instance was created next to a foreign volume")
	}
	if resource.volumes["web-scratch"].Config[meta.KeyScratch] != "" {
		t.Fatal("the foreign volume was modified")
	}
}

func TestCreateMachineReusesAMarkedVolume(t *testing.T) {
	resource, creator, ctx := scratchCreateFixture(t)
	resource.volumes["web-scratch"] = markedScratchVolume("5GiB")
	resource.volumes["web-scratch"].Config["snapshots.schedule"] = "17 * * * *"
	result, err := creator.CreateMachineV2(ctx, scratchRequest())
	if err != nil {
		t.Fatalf("CreateMachineV2: %v", err)
	}
	if len(resource.createdVolumes) != 0 || len(resource.createdInstances) != 1 {
		t.Fatalf("want the marked volume reused: volumes=%v instances=%d", resource.createdVolumes, len(resource.createdInstances))
	}
	config := resource.volumes["web-scratch"].Config
	if config["size"] != tenant.DefaultScratchSize || result.ScratchSize != tenant.DefaultScratchSize {
		t.Fatalf("reused volume size = %q, reported %q, want both %s", config["size"], result.ScratchSize, tenant.DefaultScratchSize)
	}
	if config["snapshots.schedule"] != "" {
		t.Fatalf("reused volume kept the snapshot schedule %q", config["snapshots.schedule"])
	}
}

func TestCreateMachineFailsWhenAReusedVolumeCannotBeReconciled(t *testing.T) {
	resource, creator, ctx := scratchCreateFixture(t)
	resource.volumes["web-scratch"] = markedScratchVolume("5GiB")
	resource.updateVolumeErr = errors.New("quota below usage")
	_, err := creator.CreateMachineV2(ctx, scratchRequest())
	if err == nil || !strings.Contains(err.Error(), "quota below usage") {
		t.Fatalf("want the quota update error, got %v", err)
	}
	if len(resource.createdInstances) != 0 {
		t.Fatal("the machine was created on a volume with the wrong quota")
	}
}

func TestCreateMachineFailureRemovesTheNewScratchVolume(t *testing.T) {
	resource, creator, ctx := scratchCreateFixture(t)
	resource.createInstanceErr = errors.New("image not found")
	_, err := creator.CreateMachineV2(ctx, scratchRequest())
	if err == nil || !strings.Contains(err.Error(), "image not found") {
		t.Fatalf("want the create error, got %v", err)
	}
	if resource.volumes["web-scratch"] != nil || !slices.Equal(resource.deletedVolumes, []string{"web-scratch"}) {
		t.Fatalf("the scratch volume this create made was not removed: deleted=%v", resource.deletedVolumes)
	}
}

func TestCreateMachineFailureKeepsAReusedScratchVolume(t *testing.T) {
	resource, creator, ctx := scratchCreateFixture(t)
	resource.volumes["web-scratch"] = markedScratchVolume("5GiB")
	resource.createInstanceErr = errors.New("image not found")
	if _, err := creator.CreateMachineV2(ctx, scratchRequest()); err == nil {
		t.Fatal("want the create error")
	}
	if resource.volumes["web-scratch"] == nil {
		t.Fatal("a volume this create did not make was deleted")
	}
}

func TestCreateMachineClearsAPoolInheritedSnapshotSchedule(t *testing.T) {
	resource, creator, ctx := scratchCreateFixture(t)
	resource.poolVolumeDefaults = map[string]string{"snapshots.schedule": "17 * * * *"}
	if _, err := creator.CreateMachineV2(ctx, scratchRequest()); err != nil {
		t.Fatalf("CreateMachineV2: %v", err)
	}
	if schedule := resource.volumes["web-scratch"].Config["snapshots.schedule"]; schedule != "" {
		t.Fatalf("scratch volume kept the pool's snapshot schedule %q", schedule)
	}
}

func TestCreateMachineRejectsAnInvalidScratchSize(t *testing.T) {
	resource, creator, ctx := scratchCreateFixture(t)
	request := scratchRequest()
	request.ScratchSize = "lots"
	if _, err := creator.CreateMachineV2(ctx, request); err == nil {
		t.Fatal("want an invalid size error")
	}
	if len(resource.createdVolumes) != 0 || len(resource.createdInstances) != 0 {
		t.Fatal("an invalid size still created resources")
	}
}
