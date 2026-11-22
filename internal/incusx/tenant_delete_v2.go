package incusx

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lxc/incus/v6/shared/api"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// DeleteTenantV2 tears down a v2 tenant completely: every app project
// (machines, images, shared home/workspace volumes, profiles), the infra
// project (sidecar), and the tenant bridge. v2 deletion is all-or-nothing —
// the shared volumes live inside the app projects, so there is no meaningful
// "runtime only" subset (PlanDeleteV2 enforces --purge).
// resolveDeleteServer connects to the configured Incus remote, or returns the
// injected server (tests).
func (d TenantDeleter) resolveDeleteServer() (TenantDeleteServer, error) {
	if d.Server != nil {
		return d.Server, nil
	}
	loaded, err := LoadCLIConfig(d.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := d.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	instanceServer, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return sdkDeleteServer{inner: instanceServer}, nil
}

func (d TenantDeleter) DeleteTenantV2(ctx context.Context, plan tenant.DeletePlanV2) error {
	server, err := d.resolveDeleteServer()
	if err != nil {
		return err
	}
	for _, project := range plan.AppProjects {
		if err := d.deleteV2AppProject(server, project, plan.StoragePool, plan.DurableVolumes); err != nil {
			return err
		}
	}
	// The infra project holds only the sidecar (and its profile) — no volumes.
	d.log("purge infra project " + plan.InfraProject)
	if err := d.deleteProjectCompletely(server, plan.InfraProject); err != nil {
		return err
	}
	// The tenant bridge lives in the default project; every profile that
	// referenced it is gone with the projects above (a live reference — or a
	// leftover dnsmasq — would hold the gateway IP, see the e2e appendix).
	d.log("delete tenant bridge " + plan.Bridge)
	if err := ignoreNotFound(server.UseProject("default").DeleteNetwork(plan.Bridge)); err != nil {
		return fmt.Errorf("delete tenant bridge %s: %w", plan.Bridge, err)
	}
	// Trust entries outlive their projects (Incus only drops the project
	// references), so a purge that leaves them behind accumulates orphaned
	// standing trust across install/teardown cycles (#113).
	ownProjects := map[string]bool{plan.InfraProject: true}
	for _, project := range plan.AppProjects {
		ownProjects[project] = true
	}
	if err := d.sweepTenantTrustEntries(server, plan.TrustEntry, ownProjects); err != nil {
		return err
	}
	d.log("done")
	return nil
}

// sweepTenantTrustEntries deletes the tenant's restricted client trust entries
// — those named `name` (usertrust.RestrictedInstallName) whose project list is
// empty once this tenant's own projects are discounted. A shared client
// keypair's entry is NAMED after whichever tenant enrolled it first while
// still granting other tenants' projects (shared client identity); such an
// entry stays, it just loses this tenant's projects when Incus drops them.
func (d TenantDeleter) sweepTenantTrustEntries(server TenantDeleteServer, name string, ownProjects map[string]bool) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	certificates, err := server.GetCertificates()
	if err != nil {
		return fmt.Errorf("list trust entries for purge: %w", err)
	}
	for _, cert := range certificates {
		if cert.Name != name || cert.Type != api.CertificateTypeClient || !cert.Restricted {
			continue
		}
		remaining := 0
		for _, project := range cert.Projects {
			if !ownProjects[project] {
				remaining++
			}
		}
		if remaining > 0 {
			continue
		}
		short := cert.Fingerprint
		if len(short) > 12 {
			short = short[:12]
		}
		d.log("delete trust entry " + cert.Name + " (" + short + ")")
		if err := ignoreNotFound(server.DeleteCertificate(cert.Fingerprint)); err != nil {
			return fmt.Errorf("delete trust entry %s (%s): %w", cert.Name, short, err)
		}
	}
	return nil
}

// deleteV2AppProject removes one v2 app project and everything in it. The
// shared volumes are detached from the default profile first — a project
// cannot be deleted while volumes exist, and volumes cannot be deleted while
// a profile references them.
func (d TenantDeleter) deleteV2AppProject(server TenantDeleteServer, projectName string, pool string, volumes []string) error {
	projectServer := server.UseProject(projectName)
	instances, err := projectServer.GetInstances(api.InstanceTypeAny)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) || api.StatusErrorCheck(err, http.StatusForbidden) {
			return nil
		}
		return fmt.Errorf("list instances in project %s: %w", projectName, err)
	}
	for _, instance := range instances {
		d.log("delete instance " + instance.Name + " in " + projectName)
		if err := deleteInstance(projectServer, instance.Name); err != nil {
			return err
		}
	}
	if err := d.clearVolumeDevicesFromProfiles(projectServer, projectName, volumes); err != nil {
		return err
	}
	if err := d.deleteScratchVolumes(projectServer, projectName, pool); err != nil {
		return err
	}
	for _, volume := range volumes {
		d.log("delete shared volume " + volume + " in " + projectName)
		if err := ignoreNotFound(projectServer.DeleteStoragePoolVolume(pool, "custom", volume)); err != nil {
			return fmt.Errorf("delete volume %s in %s: %w", volume, projectName, err)
		}
	}
	return d.deleteProjectCompletely(server, projectName)
}

// clearVolumeDevicesFromProfiles detaches the shared volumes from EVERY
// profile in the project, not just `default`: /home hangs off the opt-in
// `homeshare` profile, and a volume cannot be deleted while any profile
// references it — a default-only sweep left the home volume in use and the
// project undeletable.
func (d TenantDeleter) clearVolumeDevicesFromProfiles(server TenantDeleteResourceServer, projectName string, volumes []string) error {
	named := map[string]bool{}
	for _, volume := range volumes {
		named[volume] = true
	}
	profiles, err := server.GetProfiles()
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("list profiles in project %s: %w", projectName, err)
	}
	for _, listed := range profiles {
		// Re-read for the ETag: GetProfiles carries none, and an unconditional
		// update would race a concurrent profile write.
		profile, etag, err := server.GetProfile(listed.Name)
		if err != nil {
			if api.StatusErrorCheck(err, http.StatusNotFound) {
				continue
			}
			return err
		}
		changed := false
		for key, device := range profile.Devices {
			if device["type"] == "disk" && named[device["source"]] {
				delete(profile.Devices, key)
				changed = true
			}
		}
		if !changed {
			continue
		}
		d.log("detach shared volumes from " + listed.Name + " profile in " + projectName)
		if err := server.UpdateProfile(listed.Name, profile.Writable(), etag); err != nil {
			return err
		}
	}
	return nil
}

// DeleteProjectV2 deletes ONE app project of a v2 tenant: its instances, images,
// custom profiles, shared home/workspace volumes, and the Incus project itself.
//
// `sc project delete` used to only rewrite a `.sandcastle/projects` metadata file
// that nothing read, so the Incus project, its volumes and its machines survived
// — the command reported success and deleted nothing. The tenant's project list
// is derived from its Incus projects, so deleting the project IS the deletion.
func (d TenantDeleter) DeleteProjectV2(_ context.Context, incusProject string, storagePool string) error {
	incusProject = strings.TrimSpace(incusProject)
	if incusProject == "" {
		return fmt.Errorf("incus project is required")
	}
	if strings.TrimSpace(storagePool) == "" {
		storagePool = scconfig.DefaultStoragePool
	}
	server, err := d.resolveDeleteServer()
	if err != nil {
		return err
	}
	return d.deleteV2AppProject(server, incusProject, storagePool, []string{v2HomeVolumeName, v2WorkspaceVolumeName, tenant.V2SCPlatformVolumeName, tenant.V2SCLocalVolumeName})
}
