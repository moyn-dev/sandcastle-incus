package authapp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"sort"
)

// ResourceCacheMachineRenderer converts one cached Incus instance into the
// CLI-facing meta.Machine shape — exactly the conversion
// incusx.MachineFromInstance already performs for the live per-project path
// (internal/incusx/machine_store.go). It is injected (see
// HTTPRunner.ResourceCacheMachineRenderer) rather than called directly
// because incusx imports authapp (for the ResourceCacheServer adapter, see
// resource_cache_server.go) and not the other way around — authapp cannot
// import incusx without a cycle, so it cannot duplicate NIC-address
// resolution or the sidecar-instance filter itself. ok is false when the
// instance must not appear in a listing (e.g. a tenant's own DNS/route
// sidecar).
type ResourceCacheMachineRenderer func(tenantName string, project string, instance api.InstanceFull) (meta.Machine, bool)

// resourceCacheUnavailableMessage is returned, with 503, whenever the
// cache-backed answer is not safe to give: the toggle is off (ResourceCache
// is nil — HTTPRunner never constructs one) or the cache has not finished its
// initial read / lost its event-bus connection (Snapshot().Ready is false).
// `sc ls` (t3) keys its fallback to the live per-project path off the status
// code alone, never off this string — see implementation-notes.md for the
// full response contract.
const resourceCacheUnavailableMessage = "resource cache is not available: toggle is off, or the cache has not finished its initial read / lost its event-bus connection"

// The kinds GET /api/resources?include=… selects. `sc ls` sends the kinds it
// is actually going to render — always "machines", plus one per
// --networks/--storage-pools/--storage-volumes/--profiles/--images flag — so
// the common `sc ls` never pays to ship five resource types it will not print.
// See implementation-notes.md for the measurement that motivated this.
const (
	ResourceKindMachines       = "machines"
	ResourceKindNetworks       = "networks"
	ResourceKindStoragePools   = "storage-pools"
	ResourceKindStorageVolumes = "storage-volumes"
	ResourceKindProfiles       = "profiles"
	ResourceKindImages         = "images"
	// ResourceKindProjects returns the tenant's Incus projects (infra + apps)
	// with their config — what tenant.ListForPrefix builds summaries from —
	// so the CLI's tenant store can be served from the cache.
	ResourceKindProjects = "projects"
	// ResourceKindPayloads returns each matched project's /.sc platform
	// payload version, read over the appliance's local socket (one small file
	// read per project there instead of profile + file reads per project
	// from the client).
	ResourceKindPayloads = "payloads"
	ResourceKindAll      = "all"
)

// resourceInclude is the parsed include= selection. A missing (or empty)
// param means "everything", which is what keeps a pre-include `sc ls` — one
// built before this param existed — seeing exactly the payload it did before.
type resourceInclude map[string]bool

func (i resourceInclude) has(kind string) bool { return i[ResourceKindAll] || i[kind] }

// parseResourceInclude reads the comma-separated include= param. Unknown kinds
// are ignored rather than rejected: the CLI and the appliance are versioned and
// deployed independently, so a newer `sc ls` asking for a kind this appliance
// has never heard of must still get an answer for the kinds it does know —
// a 400 here would silently send that client to the live per-project path,
// which is the exact fallback this endpoint exists to prevent.
func parseResourceInclude(raw string) resourceInclude {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return resourceInclude{ResourceKindAll: true}
	}
	include := resourceInclude{}
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			include[part] = true
		}
	}
	if len(include) == 0 {
		return resourceInclude{ResourceKindAll: true}
	}
	return include
}

// ResourceListResult is the GET /api/resources response: the cache-backed
// counterpart of listMachines() in internal/cli/list.go, extended with the
// resource types docs/shape/admin-server-config-toggled-event-bus-ca8marg.md
// added to the cache. Machines is exactly listPayload.Machines — same
// meta.Machine shape, same sidecar filtering — so a client can drop it
// straight into that shape without re-deriving it; the newly cached resource
// types are exposed in their raw Incus API shapes, since `sc ls` has no
// existing rendering contract for them (t3's job to add one).
type ResourceListResult struct {
	Tenant      tenant.Summary `json:"tenant"`
	Project     string         `json:"project,omitempty"`
	Machine     string         `json:"machine,omitempty"`
	AllProjects bool           `json:"allProjects"`
	Machines    []meta.Machine `json:"machines"`
	Networks    []api.Network  `json:"networks,omitempty"`
	// StoragePools is server-scoped, not per-tenant — Incus storage pools are
	// not tenant data (no live `sc ls` equivalent ever gated them), so unlike
	// every other field here it is never filtered by the project/tenant scope
	// below.
	StoragePools   []api.StoragePool       `json:"storagePools,omitempty"`
	StorageVolumes []api.StorageVolumeFull `json:"storageVolumes,omitempty"`
	Profiles       []api.Profile           `json:"profiles,omitempty"`
	Images         []api.Image             `json:"images,omitempty"`
	// Projects are the tenant's Incus projects (name + config), infra first.
	Projects []tenant.IncusProject `json:"projects,omitempty"`
	// Payloads are the matched projects' /.sc platform payload versions.
	Payloads []PayloadVersion `json:"payloads,omitempty"`
}

// PayloadVersion is one project's /.sc platform payload version ("" when the
// project has no payload volume yet).
type PayloadVersion struct {
	IncusProject string `json:"incusProject"`
	Version      string `json:"version"`
}

// PayloadVersionReader reads a project's /.sc platform payload VERSION over
// the appliance's Incus access. Implemented by incusx.ResourceCacheServer.
type PayloadVersionReader interface {
	ReadPayloadVersion(ctx context.Context, incusProject string, pool string) string
}

// resourcesAPI answers `sc ls` from the event-bus-fed resource cache
// (docs/shape/admin-server-config-toggled-event-bus-ca8marg.md) instead of a
// live per-project Incus sweep. It applies every filter/wildcard `sc ls`
// already supports server-side — project/machine name, glob or literal,
// all-projects — against the cache, scoped to exactly the tenants the
// caller's bearer token already grants live (accessibleTenantSummaries, the
// same scoping tenantsAPI/projectsAPI use). A toggle-off or not-ready cache
// answers 503 (never partial or stale data) so the caller can key its
// live-path fallback off the status code alone.
func (h handler) resourcesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if h.resourceCache == nil || h.resourceCacheRenderer == nil {
		http.Error(w, resourceCacheUnavailableMessage, http.StatusServiceUnavailable)
		return
	}
	snapshot := h.resourceCache.Snapshot()
	if !snapshot.Ready {
		http.Error(w, resourceCacheUnavailableMessage, http.StatusServiceUnavailable)
		return
	}
	summaries, err := h.accessibleTenantSummaries(r, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	tenantName := strings.TrimSpace(r.URL.Query().Get("tenant"))
	summary, ok := selectAccessibleTenant(summaries, tenantName)
	if !ok {
		http.Error(w, fmt.Sprintf("Sandcastle tenant %q not found or not accessible", tenantName), http.StatusForbidden)
		return
	}
	projectFilter := strings.TrimSpace(r.URL.Query().Get("project"))
	machineFilter := strings.TrimSpace(r.URL.Query().Get("machine"))
	if err := validateResourceFilterPart("project", projectFilter); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateResourceFilterPart("machine", machineFilter); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	projects := tenantProjectNames(summary)
	matched := projects
	if projectFilter != "" {
		matched = map[string]string{}
		for raw, short := range projects {
			if naming.MatchName(projectFilter, short) {
				matched[raw] = short
			}
		}
		// A literal project must exist — a typo should say so rather than
		// come back as an empty listing, mirroring listMachines()'s "literal
		// project must exist" rule. A project GLOB matching nothing is just
		// an empty set.
		if !naming.IsPattern(projectFilter) && len(matched) == 0 {
			http.Error(w, fmt.Sprintf("Sandcastle project %s not found in tenant %s", projectFilter, summary.Tenant), http.StatusNotFound)
			return
		}
	}

	include := parseResourceInclude(r.URL.Query().Get("include"))
	result := ResourceListResult{
		Tenant:      summary,
		Project:     projectFilter,
		Machine:     machineFilter,
		AllProjects: projectFilter == "",
		Machines:    []meta.Machine{},
	}
	if include.has(ResourceKindMachines) {
		for _, instance := range snapshot.Instances {
			short, ok := matched[instance.Project]
			if !ok {
				continue
			}
			if machineFilter != "" && !naming.MatchName(machineFilter, instance.Name) {
				continue
			}
			if converted, ok := h.resourceCacheRenderer(summary.Tenant, short, instance); ok {
				result.Machines = append(result.Machines, converted)
			}
		}
	}
	if include.has(ResourceKindNetworks) {
		for _, network := range snapshot.Networks {
			if _, ok := matched[network.Project]; ok {
				result.Networks = append(result.Networks, network)
			}
		}
	}
	if include.has(ResourceKindStoragePools) {
		for _, pool := range snapshot.StoragePools {
			result.StoragePools = append(result.StoragePools, trimStoragePool(pool))
		}
	}
	if include.has(ResourceKindStorageVolumes) {
		for _, volume := range snapshot.StorageVolumes {
			if _, ok := matched[volume.Project]; ok {
				result.StorageVolumes = append(result.StorageVolumes, trimStorageVolume(volume))
			}
		}
	}
	if include.has(ResourceKindProfiles) {
		for _, profile := range snapshot.Profiles {
			if _, ok := matched[profile.Project]; ok {
				result.Profiles = append(result.Profiles, trimProfile(profile))
			}
		}
	}
	if include.has(ResourceKindImages) {
		for _, image := range snapshot.Images {
			if _, ok := matched[image.Project]; ok {
				result.Images = append(result.Images, image)
			}
		}
	}
	if include.has(ResourceKindProjects) {
		// The tenant's whole namespace, regardless of the project filter: a
		// summary needs the infra project's config (CIDR, suffix, members)
		// beside every app project.
		for _, project := range snapshot.Projects {
			if project.Name == summary.InfraProject || strings.HasPrefix(project.Name, summary.InfraProject+"-") {
				result.Projects = append(result.Projects, tenant.IncusProject{Name: project.Name, Config: project.Config})
			}
		}
	}
	if include.has(ResourceKindPayloads) && h.payloadVersions != nil {
		pools := map[string]string{}
		for _, profile := range snapshot.Profiles {
			if profile.Name != "default" {
				continue
			}
			for _, device := range []string{"sc-platform", "workspace", "root"} {
				if d, ok := profile.Devices[device]; ok && d["pool"] != "" {
					pools[profile.Project] = d["pool"]
					break
				}
			}
		}
		names := make([]string, 0, len(matched))
		for raw := range matched {
			names = append(names, raw)
		}
		sort.Strings(names)
		for _, raw := range names {
			result.Payloads = append(result.Payloads, PayloadVersion{IncusProject: raw, Version: h.payloadVersions.ReadPayloadVersion(r.Context(), raw, pools[raw])})
		}
	}
	writeJSON(w, http.StatusOK, result)
}

// trimStorageVolume drops the per-volume snapshot and backup lists from a
// cache-backed answer. `sc ls --storage-volumes` renders only project, name,
// type, and content type (formatStorageVolumesSection in
// internal/cli/list.go), but a volume carrying Sandcastle's hourly autosnaps
// serializes every one of them with its full config: on a one-machine tenant
// four volumes came to 167 KB of JSON, ~95% of it snapshots, which alone
// exceeded `sc ls`'s 3s cache-request budget over a tunnelled Auth Hostname
// and sent every call to the live per-project path — the exact fallback the
// cache exists to avoid. The cache keeps the full objects (it stores what
// Incus returned); only the wire response is trimmed, so a future consumer
// that needs snapshots can expose them behind an explicit query param rather
// than making every `sc ls` pay for them.
func trimStorageVolume(volume api.StorageVolumeFull) api.StorageVolumeFull {
	volume.Snapshots = nil
	volume.Backups = nil
	return volume
}

// trimStoragePool drops a pool's UsedBy list, the same wire-only trim
// trimStorageVolume performs. `sc ls --storage-pools` renders name, driver,
// and status (formatStoragePoolsSection); UsedBy is a URL per instance,
// volume, and image on the pool — 13.7 KB for a single pool on a real install,
// the largest single item in that install's response.
func trimStoragePool(pool api.StoragePool) api.StoragePool {
	pool.UsedBy = nil
	return pool
}

// trimProfile drops a profile's Config and Devices. `sc ls --profiles` renders
// project, name, and the *count* of UsedBy (formatProfilesSection), so UsedBy
// stays and the rest goes: on a real install the 13 profiles' configs came to
// 45 KB, the bulk of a 79 KB response.
func trimProfile(profile api.Profile) api.Profile {
	profile.Config = nil
	profile.Devices = nil
	return profile
}

// selectAccessibleTenant resolves the request's tenant query param against
// the caller's own accessible tenants (never anything wider). An empty param
// defaults to the caller's tenant when it is their only accessible one — the
// common case, since a v2 bearer token's accessible tenants are just the
// caller's own personal tenant — but never guesses across more than one.
func selectAccessibleTenant(summaries []tenant.Summary, tenantName string) (tenant.Summary, bool) {
	if tenantName == "" {
		if len(summaries) == 1 {
			return summaries[0], true
		}
		return tenant.Summary{}, false
	}
	for _, summary := range summaries {
		if summary.Tenant == tenantName {
			return summary, true
		}
	}
	return tenant.Summary{}, false
}

// tenantProjectNames maps every raw Incus project name backing summary (as
// the cache indexes them, e.g. "obelix-thieso2-docker") to its short
// Sandcastle project name ("docker") — the reverse of
// tenant.Summary.V2IncusProjectName. Restricting the cache snapshot to these
// keys is what scopes a cache-backed answer to exactly the caller's own
// tenant, the same guarantee the live per-project path gets for free by only
// ever querying its own tenant's projects.
func tenantProjectNames(summary tenant.Summary) map[string]string {
	projects := summary.Projects
	if len(projects) == 0 {
		projects = []meta.Project{{Name: naming.DefaultProjectName}}
	}
	names := make(map[string]string, len(projects))
	for _, project := range projects {
		names[summary.V2IncusProjectName(project.Name)] = project.Name
	}
	return names
}

// validateResourceFilterPart mirrors internal/cli/machine_selector.go's
// validateNamePart: pattern syntax when value looks like a glob, strict name
// rules otherwise. An empty value (no filter) always passes.
func validateResourceFilterPart(kind string, value string) error {
	if value == "" {
		return nil
	}
	if naming.IsPattern(value) {
		return naming.ValidateNamePattern(kind, value)
	}
	if kind == "project" {
		return naming.ValidateProjectName(value)
	}
	return naming.ValidateMachineName(value)
}
