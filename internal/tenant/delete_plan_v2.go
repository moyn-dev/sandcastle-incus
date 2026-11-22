package tenant

import (
	"context"
	"fmt"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	"github.com/moyn-dev/sandcastle-incus/internal/usertrust"
)

// DeletePlanV2 enumerates everything a v2 tenant owns on the daemon: its app
// projects (machines, images, shared home/workspace volumes, profiles), the
// infra project (sidecar), and the tenant bridge.
type DeletePlanV2 struct {
	Reference      string   `json:"reference"`
	InfraProject   string   `json:"infraProject"`
	AppProjects    []string `json:"appProjects"`
	Bridge         string   `json:"bridge"`
	StoragePool    string   `json:"storagePool"`
	DurableVolumes []string `json:"durableVolumes"`
	// TrustEntry is the install-scoped name of the tenant's restricted client
	// certificate(s) (usertrust.RestrictedInstallName). The purge sweeps trust
	// entries under this name that are left with no projects — without it the
	// daemon accumulates orphaned standing trust across install/teardown
	// cycles (#113).
	TrustEntry string `json:"trustEntry"`
}

// PlanDeleteV2 plans the deletion of a v2 tenant, scoped to the installation
// prefix (same-named tenants of different installs are different tenants).
// Returns ok=false when the reference is not a v2 tenant of this install —
// callers fall back to the v1 delete path.
//
// v2 deletion is all-or-nothing: the shared home/workspace volumes live in
// the app projects and a project cannot be deleted around its volumes, so a
// non-purge "runtime only" delete has no meaningful v2 shape. Callers must
// pass purge; PlanDeleteV2 refuses otherwise rather than leaving the operator
// believing a partial delete happened.
func PlanDeleteV2(ctx context.Context, admin config.Admin, store IncusTenantStore, reference string, purge bool) (DeletePlanV2, bool, error) {
	ref, err := naming.ParseTenantRef(reference)
	if err != nil {
		return DeletePlanV2{}, false, err
	}
	prefix := strings.TrimSpace(admin.IncusProjectPrefix)
	if prefix == "" || prefix == naming.DefaultIncusProjectPrefix {
		prefix = naming.V2IncusProjectPrefix
	}
	summaries, err := ListForPrefix(ctx, store, prefix)
	if err != nil {
		return DeletePlanV2{}, false, err
	}
	for _, summary := range summaries {
		if summary.Tenant != ref.Tenant {
			continue
		}
		if !purge {
			return DeletePlanV2{}, true, fmt.Errorf("v2 tenant deletion is all-or-nothing (machines, shared home/workspace volumes, sidecar, bridge); re-run with --purge")
		}
		appProjects := make([]string, 0, len(summary.Projects))
		for _, project := range summary.Projects {
			appProjects = append(appProjects, summary.V2IncusProjectName(project.Name))
		}
		pool := strings.TrimSpace(admin.StoragePool)
		if pool == "" {
			pool = "default"
		}
		return DeletePlanV2{
			Reference:    ref.Tenant,
			InfraProject: summary.InfraProject,
			AppProjects:  appProjects,
			Bridge:       summary.InfraProject,
			StoragePool:  pool,
			TrustEntry:   usertrust.RestrictedInstallName(prefix, ref.Tenant),
			// v2 shared volumes are named plain "home"/"workspace" (per-app-
			// project), NOT the v1 "sc-home"/"sc-workspace" — the v1 names
			// would 404 (silently ignored) and the project delete then fails
			// with "Only empty projects can be removed". The /.sc layers are
			// per-app-project custom volumes too and block the project delete
			// the same way.
			DurableVolumes: []string{V2HomeVolumeName, V2WorkspaceVolumeName, V2SCPlatformVolumeName, V2SCLocalVolumeName},
		}, true, nil
	}
	return DeletePlanV2{}, false, nil
}

// Deleter executes a v2 tenant deletion plan. v1 had its own DeleteTenant; this
// is the only shape left.
type Deleter interface {
	DeleteTenantV2(context.Context, DeletePlanV2) error
}
