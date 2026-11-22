package incusx

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// ScratchMigrationState is what the scratch migration did, or would do, for
// one machine.
type ScratchMigrationState string

const (
	// ScratchPresent: the machine already has a scratch device; untouched.
	ScratchPresent ScratchMigrationState = "present"
	// ScratchPlanned: --check; the machine would get a volume.
	ScratchPlanned ScratchMigrationState = "would-attach"
	// ScratchAttachedLive: a running container sees /scratch now.
	ScratchAttachedLive ScratchMigrationState = "attached-live"
	// ScratchAttachedNextStart: a stopped machine mounts it when started.
	ScratchAttachedNextStart ScratchMigrationState = "attached-next-start"
	// ScratchAttachedNextRestart: a running VM is reported as needing a
	// restart; Incus may hotplug the share, but only a boot is certain.
	ScratchAttachedNextRestart ScratchMigrationState = "attached-next-restart"
	// ScratchSkippedBare: a --bare machine without scratch is left alone; it
	// has no login for `sc fix` to install the guest unit, so a volume would
	// never carry /tmp.
	ScratchSkippedBare ScratchMigrationState = "skipped-bare"
	// ScratchFailed: the volume or device could not be added, or with --check
	// would not be; Error says why.
	ScratchFailed ScratchMigrationState = "failed"
)

// ScratchMigrationStatus is one machine's row of a scratch migration.
type ScratchMigrationStatus struct {
	IncusProject string                `json:"incusProject"`
	Machine      string                `json:"machine"`
	Type         string                `json:"type"`
	Volume       string                `json:"volume,omitempty"`
	State        ScratchMigrationState `json:"state"`
	Error        string                `json:"error,omitempty"`
}

// MigrateTenantScratch gives every machine of a tenant that has no scratch
// device a default-size scratch volume and attaches it. It never moves or
// deletes data, and a second run changes nothing. With checkOnly nothing is
// written. onlyProjects, when not empty, limits the sweep to those app
// projects, each named short ("default") or in full ("sc2-acme-default").
// Sandcastle infrastructure instances (sidecars and other managed
// non-machine kinds) are skipped. Per-machine failures are reported in their
// row and make the call return an error after every machine was tried.
func (c TenantCreator) MigrateTenantScratch(_ context.Context, installPrefix string, tenantName string, onlyProjects []string, checkOnly bool) ([]ScratchMigrationStatus, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	infraPool, projects, err := v2TenantAppProjects(server, installPrefix, tenantName)
	if err != nil {
		return nil, err
	}
	if len(onlyProjects) > 0 {
		infraProject, err := naming.V2TenantInfraProjectName(naming.NormalizeV2Prefix(installPrefix), tenantName)
		if err != nil {
			return nil, err
		}
		if projects, err = selectAppProjects(projects, infraProject, onlyProjects); err != nil {
			return nil, err
		}
	}
	shifted := server.SupportsIdmappedMounts()
	var statuses []ScratchMigrationStatus
	failed := 0
	for _, projectName := range projects {
		resource := server.UseProject(projectName)
		pool := infraPool
		if profile, _, err := resource.GetProfile("default"); err == nil {
			if fromProfile := v2ProfileStoragePool(profile); fromProfile != "" {
				pool = fromProfile
			}
		}
		instances, err := resource.GetInstances(api.InstanceTypeAny)
		if err != nil {
			return statuses, fmt.Errorf("list machines in %s: %w", projectName, err)
		}
		for _, instance := range instances {
			if !isScratchMigrationCandidate(instance) {
				continue
			}
			scratch := tenant.MachineScratch{Machine: instance.Name, Pool: pool, Size: tenant.DefaultScratchSize}
			status := ScratchMigrationStatus{IncusProject: projectName, Machine: instance.Name, Type: instance.Type, Volume: scratch.VolumeName()}
			switch {
			case hasScratchDevice(instance):
				status.State, status.Volume = ScratchPresent, instance.Devices[tenant.ScratchDeviceName]["source"]
			case instanceIsBareV2(instance.Config):
				status.State, status.Volume = ScratchSkippedBare, ""
			case checkOnly:
				status.State = ScratchPlanned
				if err := checkScratchVolumeAdoptable(resource, scratch); err != nil {
					status.State, status.Error = ScratchFailed, err.Error()
					failed++
				}
			default:
				status.State, err = attachScratch(resource, instance.Name, scratch, shifted)
				if err != nil {
					status.State, status.Error = ScratchFailed, err.Error()
					failed++
				}
			}
			statuses = append(statuses, status)
		}
	}
	if failed > 0 {
		return statuses, fmt.Errorf("%d machine(s) could not get a scratch volume", failed)
	}
	return statuses, nil
}

// selectAppProjects keeps the tenant app projects named in wanted, short or
// full, in their listed order. A name that matches none is an error, so a
// typo never turns into a silent no-op.
func selectAppProjects(projects []string, infraProject string, wanted []string) ([]string, error) {
	keep := map[string]bool{}
	for _, raw := range wanted {
		name := strings.TrimSpace(raw)
		found := false
		for _, project := range projects {
			if project == name || project == infraProject+"-"+name {
				keep[project], found = true, true
			}
		}
		if !found {
			return nil, fmt.Errorf("tenant has no app project %q (have: %s)", name, strings.Join(projects, ", "))
		}
	}
	var selected []string
	for _, project := range projects {
		if keep[project] {
			selected = append(selected, project)
		}
	}
	return selected, nil
}

// isScratchMigrationCandidate keeps Machines, including freeform instances a
// tenant launched by hand, and drops Sandcastle-managed infrastructure.
func isScratchMigrationCandidate(instance api.Instance) bool {
	kind := instance.Config[meta.KeyKind]
	return kind == "" || kind == meta.KindMachine
}

// hasScratchDevice is true for any device named scratch, own or from a
// profile, whatever its type: an existing one is never replaced.
func hasScratchDevice(instance api.Instance) bool {
	_, own := instance.Devices[tenant.ScratchDeviceName]
	_, expanded := instance.ExpandedDevices[tenant.ScratchDeviceName]
	return own || expanded
}

// checkScratchVolumeAdoptable is the read-only half of
// ensureMachineScratchVolume: it fails where that would, on a same-name
// volume without the scratch marker.
func checkScratchVolumeAdoptable(server TenantResourceServer, scratch tenant.MachineScratch) error {
	volume, _, err := server.GetStoragePoolVolume(scratch.Pool, "custom", scratch.VolumeName())
	switch {
	case api.StatusErrorCheck(err, http.StatusNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("read scratch volume %s: %w", scratch.VolumeName(), err)
	case !tenant.IsScratchVolume(volume.Config):
		return foreignScratchVolumeError(scratch.VolumeName())
	default:
		return nil
	}
}

func attachScratch(server TenantResourceServer, machine string, scratch tenant.MachineScratch, shifted bool) (ScratchMigrationState, error) {
	if _, err := ensureMachineScratchVolume(server, scratch, shifted); err != nil {
		return "", err
	}
	instance, etag, err := server.GetInstance(machine)
	if err != nil {
		return "", fmt.Errorf("get machine %s: %w", machine, err)
	}
	put := instance.Writable()
	devices := api.DevicesMap{}
	for name, device := range put.Devices {
		devices[name] = device
	}
	devices[tenant.ScratchDeviceName] = scratch.Device()
	put.Devices = devices
	op, err := server.UpdateInstance(machine, put, etag)
	if err == nil {
		err = op.Wait()
	}
	if err != nil {
		return "", fmt.Errorf("attach scratch volume %s to %s: %w", scratch.VolumeName(), machine, err)
	}
	switch {
	case !instance.IsActive():
		return ScratchAttachedNextStart, nil
	case instance.Type == string(api.InstanceTypeVM):
		return ScratchAttachedNextRestart, nil
	default:
		return ScratchAttachedLive, nil
	}
}
