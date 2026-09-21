package authapp

import (
	"net/http"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

type TenantAccessSummary struct {
	Tenant   string `json:"tenant"`
	Personal bool   `json:"personal"`
	// PrivateCIDR is the tenant's /24 (v2) — clients use it to verify the
	// tenant tailnet path without a fresh device login.
	PrivateCIDR string `json:"private_cidr,omitempty"`
	// Shared marks a Shared Tenant (it has Tenant Members); Member marks that
	// the caller is one of them rather than the owner.
	Shared  bool     `json:"shared,omitempty"`
	Member  bool     `json:"member,omitempty"`
	Members []string `json:"members,omitempty"`
	// DNSSuffix, DefaultProject, Projects and IncusProject describe what
	// `sc tenant switch` needs to enrol and pin the tenant's remote: the
	// remote is named after the Tenant DNS Suffix (ADR-0021), pinned to the
	// default project's full Incus name, and pointed at IncusRemoteAddress —
	// the tenant sidecar's tailnet IP (filled in for memberships only).
	DNSSuffix          string   `json:"dns_suffix,omitempty"`
	DefaultProject     string   `json:"default_project,omitempty"`
	Projects           []string `json:"projects,omitempty"`
	IncusProject       string   `json:"incus_project,omitempty"`
	IncusRemoteAddress string   `json:"incus_remote_address,omitempty"`
}

type TenantAccessListResult struct {
	Tenants []TenantAccessSummary `json:"tenants"`
}

func (h handler) tenantsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	summaries, err := h.accessibleTenantSummaries(r, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	result := TenantAccessListResult{}
	normalized := NormalizeGitHubUsername(user.UserKey)
	for _, summary := range summaries {
		result.Tenants = append(result.Tenants, h.tenantAccessSummary(r, summary, normalized))
	}
	writeJSON(w, http.StatusOK, result)
}

// tenantAccessSummary renders one accessible tenant for the CLI. The sidecar
// address is read only for memberships: the owner's remote was enrolled at
// login, while a member enrols the shared tenant's remote on `sc tenant
// switch` and needs the address for it. A sidecar that has not joined its
// tailnet yet leaves the field empty (the CLI reports that).
func (h handler) tenantAccessSummary(r *http.Request, summary tenant.Summary, normalizedUser string) TenantAccessSummary {
	defaultProject := strings.TrimSpace(summary.DefaultProject)
	if defaultProject == "" {
		defaultProject = naming.DefaultProjectName
	}
	view := TenantAccessSummary{
		Tenant:         summary.Tenant,
		Personal:       summary.Personal,
		PrivateCIDR:    summary.PrivateCIDR,
		Shared:         len(summary.Members) > 0,
		Member:         summary.IsMember(normalizedUser) && summary.Tenant != normalizedUser,
		Members:        summary.Members,
		DNSSuffix:      strings.TrimSpace(summary.DNSSuffix),
		DefaultProject: defaultProject,
		Projects:       summary.ProjectShortNames(),
		IncusProject:   summary.V2IncusProjectName(defaultProject),
	}
	if view.Member && h.sidecarAddresses != nil {
		if address, err := h.sidecarAddresses.SidecarTailnetIPV2(r.Context(), h.admin.IncusProjectPrefix, summary.Tenant); err == nil {
			view.IncusRemoteAddress = strings.TrimSpace(address)
		}
	}
	return view
}

func containsNormalizedUser(users []string, userKey string) bool {
	for _, candidate := range users {
		if NormalizeGitHubUsername(candidate) == userKey {
			return true
		}
	}
	return false
}
