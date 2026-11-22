package incusx

import (
	"fmt"
	"maps"
	"net/http"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// v2MachineScratch is the scratch spec of a machine about to be created: its
// project's storage pool and the requested (or default) quota.
func v2MachineScratch(project TenantResourceServer, request CreateMachineV2Request) (tenant.MachineScratch, error) {
	size, err := tenant.ParseScratchSize(request.ScratchSize)
	if err != nil {
		return tenant.MachineScratch{}, err
	}
	profile, _, err := project.GetProfile("default")
	if err != nil {
		return tenant.MachineScratch{}, fmt.Errorf("read the default profile of %s for the scratch volume: %w", request.IncusProject, err)
	}
	pool := v2ProfileStoragePool(profile)
	if pool == "" {
		return tenant.MachineScratch{}, fmt.Errorf("project %s: cannot determine the storage pool for the scratch volume from the default profile (re-provision the project, or create the machine with --no-scratch)", request.IncusProject)
	}
	return tenant.MachineScratch{Machine: request.Name, Pool: pool, Size: size}, nil
}

// ensureMachineScratchVolume gets or creates the scratch volume and reports
// whether this call created it. An existing marked volume is reused (a
// leftover of an earlier attempt) once its quota and snapshot schedule match
// what a new one would get; an existing unmarked one is someone else's data
// and is never adopted.
func ensureMachineScratchVolume(server TenantResourceServer, scratch tenant.MachineScratch, shifted bool) (bool, error) {
	name := scratch.VolumeName()
	existing, err := getOrCreateV2Volume(server, scratch.Pool, name, scratch.Description(), scratch.VolumeConfig(shifted))
	if err != nil {
		return false, fmt.Errorf("create scratch volume %s: %w", name, err)
	}
	if existing != nil {
		if !tenant.IsScratchVolume(existing.Config) {
			return false, foreignScratchVolumeError(name)
		}
		return false, reconcileScratchVolume(server, scratch.Pool, name, scratch.Size)
	}
	if err := reconcileScratchVolume(server, scratch.Pool, name, scratch.Size); err != nil {
		if cleanup := ignoreNotFound(server.DeleteStoragePoolVolume(scratch.Pool, "custom", name)); cleanup != nil {
			return false, fmt.Errorf("%w (and could not remove the new volume: %v)", err, cleanup)
		}
		return false, err
	}
	return true, nil
}

func foreignScratchVolumeError(name string) error {
	return fmt.Errorf("custom volume %s already exists and is not a Sandcastle scratch volume (no %s marker): rename it, or create the machine with --no-scratch", name, meta.KeyScratch)
}

// reconcileScratchVolume removes a snapshot schedule the volume inherited
// from its pool and sets its quota to size. Incus fills every empty key of a
// new volume from the pool's volume.* defaults, so an explicit empty
// snapshots.schedule does not survive a pool with volume.snapshots.schedule
// set; a volume reused from an earlier attempt may also carry another quota.
func reconcileScratchVolume(server TenantResourceServer, pool string, name string, size string) error {
	volume, etag, err := server.GetStoragePoolVolume(pool, "custom", name)
	if err != nil {
		return fmt.Errorf("read scratch volume %s: %w", name, err)
	}
	if volume.Config["snapshots.schedule"] == "" && volume.Config["size"] == size {
		return nil
	}
	put := volume.Writable()
	put.Config = maps.Clone(put.Config)
	if put.Config == nil {
		put.Config = map[string]string{}
	}
	delete(put.Config, "snapshots.schedule")
	put.Config["size"] = size
	if err := server.UpdateStoragePoolVolume(pool, "custom", name, put, etag); err != nil {
		return fmt.Errorf("update the quota and snapshot schedule of scratch volume %s: %w", name, err)
	}
	return nil
}

// rollbackMachineScratchVolume removes the scratch volume a failed create
// made, once it is clear the instance does not exist to hold it.
func rollbackMachineScratchVolume(server TenantResourceServer, machine string, scratch tenant.MachineScratch, cause error) error {
	if _, _, err := server.GetInstance(machine); !api.StatusErrorCheck(err, http.StatusNotFound) {
		return cause
	}
	if err := deleteMachineScratchVolume(server, scratch.Pool, scratch.VolumeName()); err != nil {
		return fmt.Errorf("%w (and could not remove its new scratch volume: %v)", cause, err)
	}
	return cause
}

// instanceScratchVolume returns the pool and volume the instance's own
// `scratch` disk device attaches. The device, not a recomputed name, is what
// says which volume belongs to the machine.
func instanceScratchVolume(instance *api.Instance) (pool string, volume string, ok bool) {
	if instance == nil {
		return "", "", false
	}
	device, found := instance.Devices[tenant.ScratchDeviceName]
	if !found || device["type"] != "disk" || device["source"] == "" || device["pool"] == "" {
		return "", "", false
	}
	return device["pool"], device["source"], true
}

type scratchVolumeDeleter interface {
	GetStoragePoolVolume(pool string, volType string, name string) (*api.StorageVolume, string, error)
	DeleteStoragePoolVolume(pool string, volType string, name string) error
}

// deleteMachineScratchVolume deletes a machine's scratch volume once its
// instance is gone. A volume without the scratch marker is left alone: only
// Sandcastle-created scratch data is disposable. A missing volume is fine.
func deleteMachineScratchVolume(server scratchVolumeDeleter, pool string, name string) error {
	volume, _, err := server.GetStoragePoolVolume(pool, "custom", name)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("get scratch volume %s: %w", name, err)
	}
	if !tenant.IsScratchVolume(volume.Config) {
		return nil
	}
	if err := ignoreNotFound(server.DeleteStoragePoolVolume(pool, "custom", name)); err != nil {
		return fmt.Errorf("delete scratch volume %s: %w", name, err)
	}
	return nil
}

// deleteScratchVolumes removes every marked scratch volume left in a project
// whose instances are already deleted, so the project itself can be deleted.
func (d TenantDeleter) deleteScratchVolumes(server TenantDeleteResourceServer, projectName string, pool string) error {
	volumes, err := server.GetStoragePoolVolumes(pool)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) || api.StatusErrorCheck(err, http.StatusForbidden) {
			return nil
		}
		return fmt.Errorf("list volumes in project %s: %w", projectName, err)
	}
	for _, volume := range volumes {
		if volume.Type != "custom" || !tenant.IsScratchVolume(volume.Config) {
			continue
		}
		d.log("delete scratch volume " + volume.Name + " in " + projectName)
		if err := ignoreNotFound(server.DeleteStoragePoolVolume(pool, "custom", volume.Name)); err != nil {
			return fmt.Errorf("delete scratch volume %s in %s: %w", volume.Name, projectName, err)
		}
	}
	return nil
}
