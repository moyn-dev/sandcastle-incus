package incusx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// SCPayloadProjectStatus reports one app project's /.sc platform-payload state
// from a central sync: the version found on the volume, the version this
// binary ships, and whether the sync (re)wrote the payload.
type SCPayloadProjectStatus struct {
	IncusProject string `json:"incusProject"`
	Before       string `json:"before"`
	Target       string `json:"target"`
	Changed      bool   `json:"changed"`
}

// SyncTenantPlatformPayload converges every app project of a tenant onto the
// platform payload built into this binary — the central update path (#131):
// one volume write per project, never per machine; every running machine
// observes the new payload through its shared /.sc mount, no re-create needed.
// Rollback is the same operation run from the previous binary (the payload —
// and its content-derived version — comes from the binary). With checkOnly the
// volumes are only read, reporting drift per project.
func (c TenantCreator) SyncTenantPlatformPayload(_ context.Context, installPrefix string, tenantName string, checkOnly bool) ([]SCPayloadProjectStatus, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	pool, names, err := v2TenantAppProjects(server, installPrefix, tenantName)
	if err != nil {
		return nil, err
	}
	target := tenant.PlatformPayloadVersion()
	statuses := make([]SCPayloadProjectStatus, 0, 2)
	for _, name := range names {
		resource := server.UseProject(name)
		if !checkOnly {
			// Legacy onboarding (#132): a project provisioned before /.sc has
			// neither the volumes nor the profile devices — create/merge them
			// so the payload write below lands on a mounted volume.
			if err := ensureSCVolumesAndDevices(resource, pool, server.SupportsIdmappedMounts()); err != nil {
				return statuses, fmt.Errorf("onboard %s onto /.sc: %w", name, err)
			}
		}
		status := SCPayloadProjectStatus{
			IncusProject: name,
			Before:       readSCPlatformVersion(resource, pool),
			Target:       target,
		}
		if !checkOnly && status.Before != target {
			changed, err := ensureV2PlatformPayload(resource, pool)
			if err != nil {
				return statuses, fmt.Errorf("sync /.sc payload in %s: %w", name, err)
			}
			status.Changed = changed
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// v2TenantAppProjects returns this install's app projects of a tenant and the
// storage pool its infra project records. Name-scoped to the tenant AND
// metadata-confirmed: a same-named tenant of another install has a different
// prefix, and a non-Sandcastle project fails the kind check.
func v2TenantAppProjects(server TenantCreateServer, installPrefix string, tenantName string) (string, []string, error) {
	if err := naming.ValidateTenantName(tenantName); err != nil {
		return "", nil, err
	}
	infraProject, err := naming.V2TenantInfraProjectName(naming.NormalizeV2Prefix(installPrefix), tenantName)
	if err != nil {
		return "", nil, err
	}
	infra, _, err := server.GetProject(infraProject)
	if err != nil {
		return "", nil, fmt.Errorf("tenant %q infra project %s not found: %w", tenantName, infraProject, err)
	}
	pool := strings.TrimSpace(infra.Config[keyV2Pool])
	if pool == "" {
		pool = "default"
	}
	names, err := server.GetProjectNames()
	if err != nil {
		return "", nil, fmt.Errorf("list Incus projects: %w", err)
	}
	var projects []string
	for _, name := range names {
		if !strings.HasPrefix(name, infraProject+"-") {
			continue
		}
		project, _, err := server.GetProject(name)
		if err != nil {
			return "", nil, fmt.Errorf("get project %s: %w", name, err)
		}
		if isV2AppProjectOfTenant(project.Config, tenantName) {
			projects = append(projects, name)
		}
	}
	if len(projects) == 0 {
		return "", nil, fmt.Errorf("tenant %q has no app projects under install prefix %q", tenantName, installPrefix)
	}
	return pool, projects, nil
}

// EnsureProjectPlatformPayload converges ONE app project's sc-platform volume
// onto this binary's payload — the central half of `sc fix` (#132). The
// tenant's own restricted client certificate may perform it: the volume lives
// inside their project, and platform read-only-ness is a machine-mount
// property, not an API one. The storage pool is read from the project's
// default profile (its sc-platform disk device), so the tenant needs no admin
// configuration. With checkOnly the volume is only read.
func (c TenantCreator) EnsureProjectPlatformPayload(_ context.Context, incusProject string, checkOnly bool) (SCPayloadProjectStatus, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return SCPayloadProjectStatus{}, err
	}
	return ensureProjectPlatformPayload(server, incusProject, checkOnly)
}

// SyncVisiblePlatformPayload is the tenant self-service payload sync behind
// `sc payload-sync`: it converges every app project of the tenant that the
// caller's certificate can see. Unlike the admin path it needs no install
// prefix — a restricted cert only ever lists its granted projects, so the
// target set is the metadata filter alone (an unreadable listing entry on a
// shared host is skipped, never fatal). One volume write per project; the
// machines pick the payload up through their shared /.sc mount.
func (c TenantCreator) SyncVisiblePlatformPayload(_ context.Context, tenantName string, checkOnly bool) ([]SCPayloadProjectStatus, error) {
	if err := naming.ValidateTenantName(tenantName); err != nil {
		return nil, err
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	names, err := server.GetProjectNames()
	if err != nil {
		return nil, fmt.Errorf("list Incus projects: %w", err)
	}
	statuses := make([]SCPayloadProjectStatus, 0, 2)
	for _, name := range names {
		project, _, err := server.GetProject(name)
		if err != nil {
			if api.StatusErrorCheck(err, http.StatusForbidden) {
				continue
			}
			return statuses, fmt.Errorf("get project %s: %w", name, err)
		}
		if !isV2AppProjectOfTenant(project.Config, tenantName) {
			continue
		}
		status, err := ensureProjectPlatformPayload(server, name, checkOnly)
		if err != nil {
			return statuses, err
		}
		statuses = append(statuses, status)
	}
	if len(statuses) == 0 {
		return nil, fmt.Errorf("tenant %q has no app projects visible to this certificate", tenantName)
	}
	return statuses, nil
}

// isV2AppProjectOfTenant reports whether project metadata marks a Sandcastle
// v2 app project of the tenant — the payload-sync target set for both the
// admin (additionally name-scoped) and tenant (cert-scoped) sync paths.
func isV2AppProjectOfTenant(config map[string]string, tenantName string) bool {
	return config[meta.KeyKind] == meta.KindV2Project && config[meta.KeyTenant] == tenantName
}

// ensureProjectPlatformPayload converges ONE app project's sc-platform volume
// onto this binary's payload; the per-project half of every sync path.
func ensureProjectPlatformPayload(server TenantCreateServer, incusProject string, checkOnly bool) (SCPayloadProjectStatus, error) {
	resource := server.UseProject(incusProject)
	profile, _, err := resource.GetProfile("default")
	if err != nil {
		return SCPayloadProjectStatus{}, fmt.Errorf("get default profile of %s: %w", incusProject, err)
	}
	pool := v2ProfileStoragePool(profile)
	if pool == "" {
		return SCPayloadProjectStatus{}, fmt.Errorf("project %s: cannot determine the storage pool from the default profile — re-run `sc login` (or have the admin run `sc-adm tenant payload-sync`)", incusProject)
	}
	if !checkOnly {
		// Legacy onboarding (#132): the tenant's restricted cert may create
		// the volumes and merge the profile devices inside its own project.
		if err := ensureSCVolumesAndDevices(resource, pool, server.SupportsIdmappedMounts()); err != nil {
			return SCPayloadProjectStatus{}, fmt.Errorf("onboard %s onto /.sc: %w", incusProject, err)
		}
	}
	status := SCPayloadProjectStatus{
		IncusProject: incusProject,
		Before:       readSCPlatformVersion(resource, pool),
		Target:       tenant.PlatformPayloadVersion(),
	}
	if !checkOnly && status.Before != status.Target {
		changed, err := ensureV2PlatformPayload(resource, pool)
		if err != nil {
			return status, fmt.Errorf("sync /.sc payload in %s: %w", incusProject, err)
		}
		status.Changed = changed
	}
	return status, nil
}

// v2ProfileStoragePool is an app project's storage pool, read off its default
// profile: whichever shared-volume device exists names it (sc-platform on
// current projects, workspace or root on legacy ones), "" when none does. A
// restricted tenant certificate can read the profile but not the infra
// project that records the pool, so this is the one source every caller has.
func v2ProfileStoragePool(profile *api.Profile) string {
	if profile == nil {
		return ""
	}
	for _, name := range []string{"sc-platform", "workspace", "root"} {
		if device, ok := profile.Devices[name]; ok && device["pool"] != "" {
			return device["pool"]
		}
	}
	return ""
}

// ensureSCVolumesAndDevices onboards a (possibly pre-/.sc) app project: it
// creates the two layer volumes if missing and additively merges their disk
// devices into the project's default profile. Running containers pick a
// profile device change up live; VMs on their next restart. The rest of the
// profile is untouched — full re-renders stay with the provisioning paths.
func ensureSCVolumesAndDevices(resource TenantResourceServer, pool string, shifted bool) error {
	if err := ensureV2SCVolumes(resource, pool, shifted); err != nil {
		return err
	}
	profile, etag, err := resource.GetProfile("default")
	if err != nil {
		return fmt.Errorf("get default profile: %w", err)
	}
	put := profile.Writable()
	changed := false
	for _, v := range tenant.V2SCVolumes() {
		if _, ok := put.Devices[v.DeviceName]; ok {
			continue
		}
		if put.Devices == nil {
			put.Devices = map[string]map[string]string{}
		}
		put.Devices[v.DeviceName] = v.Device(pool)
		changed = true
	}
	if !changed {
		return nil
	}
	if err := resource.UpdateProfile("default", put, etag); err != nil {
		return fmt.Errorf("attach /.sc devices to default profile: %w", err)
	}
	return nil
}

// ensureV2PlatformPayload converges one app project's sc-platform volume onto
// the platform payload built into this binary (ADR-0022). This is the central
// update path: one write per project, never per machine — every machine mounts
// the shared volume, so the guarded shims pick the new payload up on next use.
// Idempotent: a matching VERSION marker is a no-op. Returns whether anything
// was written.
func ensureV2PlatformPayload(server TenantResourceServer, pool string) (bool, error) {
	files, version := tenant.PlatformPayload()
	if current := readSCPlatformVersion(server, pool); current == version {
		return false, nil
	}
	// Parent directories first (the volume file API does not create them).
	dirs := map[string]bool{}
	for _, f := range files {
		for d := path.Dir(f.Path); d != "." && d != "/"; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	ordered := make([]string, 0, len(dirs))
	for d := range dirs {
		ordered = append(ordered, d)
	}
	sort.Strings(ordered) // parents sort before children
	for _, d := range ordered {
		if err := server.CreateStorageVolumeFile(pool, "custom", tenant.V2SCPlatformVolumeName, "/"+d, incus.InstanceFileArgs{
			Type: "directory",
			Mode: 0o755,
		}); err != nil && !strings.Contains(err.Error(), "already exists") {
			return false, fmt.Errorf("create /.sc/platform directory %s: %w", d, err)
		}
	}
	// The builder returns VERSION last, so a partially applied write never
	// advertises the new version — the next sync retries.
	for _, f := range files {
		if err := server.CreateStorageVolumeFile(pool, "custom", tenant.V2SCPlatformVolumeName, "/"+f.Path, incus.InstanceFileArgs{
			Content:   strings.NewReader(f.Content),
			Type:      "file",
			Mode:      f.Mode,
			WriteMode: "overwrite",
		}); err != nil {
			return false, fmt.Errorf("write /.sc/platform/%s: %w", f.Path, err)
		}
	}
	return true, nil
}

// readSCPlatformVersion reports the payload version currently on a project's
// sc-platform volume ("" when none is written yet or the volume is missing).
func readSCPlatformVersion(server TenantResourceServer, pool string) string {
	content, _, err := server.GetStorageVolumeFile(pool, "custom", tenant.V2SCPlatformVolumeName, "/"+tenant.PlatformPayloadVersionFile)
	if err != nil {
		return ""
	}
	defer content.Close()
	data, err := io.ReadAll(content)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
