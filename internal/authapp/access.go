package authapp

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

type accessTenant struct {
	Tenant   string
	Personal bool
	Users    []string
}

type accessPage struct {
	Users   []User
	Tenants []accessTenant
}

func (h handler) adminTenantAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := h.requireAdmin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	page, err := h.tenantAccessPage(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tenantAccessTemplate.Execute(w, page)
}

func (h handler) adminTenantAccessGrant(w http.ResponseWriter, r *http.Request) {
	h.adminTenantAccessMutation(w, r, "grant")
}

func (h handler) adminTenantAccessRevoke(w http.ResponseWriter, r *http.Request) {
	h.adminTenantAccessMutation(w, r, "revoke")
}

func (h handler) adminTenantAccessMutation(w http.ResponseWriter, r *http.Request, action string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := h.requireAdmin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if h.tenantAccess == nil {
		http.Error(w, "tenant access manager is not configured", http.StatusInternalServerError)
		return
	}
	tenantName := strings.TrimSpace(r.FormValue("tenant"))
	userKey := NormalizeGitHubUsername(r.FormValue("user"))
	if userKey == "" || tenantName == "" {
		http.Error(w, "tenant and user are required", http.StatusBadRequest)
		return
	}
	summary, err := h.findTenantSummary(r, tenantName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The whole membership transition (Shared Tenants): certificate scope over
	// every project, Tenant Metadata membership, profiles, running machines.
	switch action {
	case "grant":
		err = h.grantTenantMembership(r, summary, userKey)
	case "revoke":
		err = h.revokeTenantMembership(r, summary, userKey)
	default:
		http.Error(w, fmt.Sprintf("unsupported tenant access action %q", action), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/admin/access", http.StatusSeeOther)
}

func (h handler) revokeMachineSSHAccess(r *http.Request, tenantName string, userKey string) error {
	if h.machineSSHAccess == nil {
		return nil
	}
	summary, err := h.findTenantSummary(r, tenantName)
	if err != nil {
		return err
	}
	return h.machineSSHAccess.RevokeUserSSHKey(r.Context(), summary, NormalizeGitHubUsername(userKey))
}

func (h handler) findTenantSummary(r *http.Request, tenantName string) (tenant.Summary, error) {
	if h.tenants == nil {
		return tenant.Summary{}, fmt.Errorf("tenant store is not configured")
	}
	summaries, err := tenant.ListForPrefix(r.Context(), h.tenants, h.admin.IncusProjectPrefix)
	if err != nil {
		return tenant.Summary{}, err
	}
	normalized := NormalizeGitHubUsername(tenantName)
	for _, summary := range summaries {
		if summary.Tenant == normalized {
			// tenant.ListForPrefix builds summaries from Incus project state and
			// leaves StorageShares empty. The share reconciler mounts exactly what
			// is in summary.StorageShares, and `shareHealth` counts from it, so a
			// summary without the registry makes a real (non-dry-run) accept mount
			// nothing and `sc status` report zero shares. Read the registry in.
			if h.shareStore != nil {
				shares, err := h.shareStore.GetTenantShares(r.Context(), summary.IncusName)
				if err != nil {
					return tenant.Summary{}, err
				}
				summary.StorageShares = shares
			}
			return summary, nil
		}
	}
	return tenant.Summary{}, fmt.Errorf("Sandcastle tenant %s not found", normalized)
}

func (h handler) tenantAccessPage(r *http.Request) (accessPage, error) {
	if h.tenants == nil {
		return accessPage{}, fmt.Errorf("tenant store is not configured")
	}
	if h.tenantAccess == nil {
		return accessPage{}, fmt.Errorf("tenant access manager is not configured")
	}
	users, err := ListUsers(r.Context(), h.db)
	if err != nil {
		return accessPage{}, err
	}
	summaries, err := tenant.ListForPrefix(r.Context(), h.tenants, h.admin.IncusProjectPrefix)
	if err != nil {
		return accessPage{}, err
	}
	page := accessPage{Users: users}
	for _, summary := range summaries {
		plan, err := usertrust.PlanTenantUsersForRequest(h.admin, usertrust.TenantAccessRequest{Tenant: summary.Tenant, Personal: summary.Personal})
		if err != nil {
			return accessPage{}, err
		}
		result, err := h.tenantAccess.ListTenantUsers(r.Context(), plan)
		if err != nil {
			return accessPage{}, err
		}
		// Tenant Members recorded in Tenant Metadata come first; the
		// certificate-derived list stays as the "who can reach it" view.
		for _, member := range summary.Members {
			if !containsNormalizedUser(result.Users, member) {
				result.Users = append([]string{member}, result.Users...)
			}
		}
		page.Tenants = append(page.Tenants, accessTenant{
			Tenant:   summary.Tenant,
			Personal: summary.Personal,
			Users:    append([]string{}, result.Users...),
		})
	}
	return page, nil
}

var tenantAccessTemplate = template.Must(template.New("tenant-access").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <link rel="stylesheet" href="/style.css">
  <title>Sandcastle Tenant Access</title>
</head>
<body>
  <main>
    <h1>Tenant Access</h1>
    <p><a href="/">Home</a> · <a href="/logs">Activity log</a> · <a href="/admin/allowlist">Login Allowlist</a></p>
    <form method="post" action="/admin/access/grant">
      <label>User <input name="user"></label>
      <label>Tenant <input name="tenant"></label>
      <label>Personal <input type="checkbox" name="personal" value="1"></label>
      <button type="submit">Grant</button>
    </form>
    <form method="post" action="/admin/access/revoke">
      <label>User <input name="user"></label>
      <label>Tenant <input name="tenant"></label>
      <label>Personal <input type="checkbox" name="personal" value="1"></label>
      <button type="submit">Revoke</button>
    </form>
    <h2>Users</h2>
    <table>
      <thead><tr><th>User</th><th>Allowlisted</th><th>Admin</th></tr></thead>
      <tbody>
        {{range .Users}}
        <tr><td>{{.UserKey}}</td><td>{{.Allowlisted}}</td><td>{{.SandcastleAdmin}}</td></tr>
        {{end}}
      </tbody>
    </table>
    <h2>Tenants</h2>
    <table>
      <thead><tr><th>Tenant</th><th>Personal</th><th>Users</th></tr></thead>
      <tbody>
        {{range .Tenants}}
        <tr><td>{{.Tenant}}</td><td>{{.Personal}}</td><td>{{range .Users}}{{.}} {{end}}</td></tr>
        {{end}}
      </tbody>
    </table>
  </main>
</body>
</html>
`))
