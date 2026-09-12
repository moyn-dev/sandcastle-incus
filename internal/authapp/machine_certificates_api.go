package authapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// ProjectDomainResolver answers "which Project Domain, under which Public DNS
// Zone, does this tenant project own?" for POST /api/machine-certificates.
// The Project Domain claims table (spec §3.3) is its production source; a nil
// resolver makes the endpoint answer 501 (the install has no claims yet).
type ProjectDomainResolver interface {
	// ResolveProjectDomain returns the normalized Project Domain and its zone
	// for tenant/project, or ("", "", nil) when the project has no domain.
	ResolveProjectDomain(ctx context.Context, tenant, project string) (domain, zone string, err error)
}

// MachineCertificateRequest is the POST /api/machine-certificates body
// (spec §3.4). Tenant is optional: it defaults to the caller's own tenant and
// is otherwise authorized like the workload endpoints (self or granted).
type MachineCertificateRequest struct {
	Tenant  string `json:"tenant,omitempty"`
	Project string `json:"project"`
	Machine string `json:"machine"`
}

// MachineCertificateView is the endpoint's response: 202 {hostname, state},
// or 409 with Reason "rate-limited" and the message in Error when the zone's
// weekly budget is spent (the row is still recorded; the reconciler tries
// when the window frees).
type MachineCertificateView struct {
	Hostname string `json:"hostname"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Error    string `json:"error,omitempty"`
}

// machineCertificatesAPI is POST /api/machine-certificates (spec §3.4):
// records a pending machine_certificates row for <machine>.<project domain>
// — or reports the retained certificate — for a zone-mode machine `sc create`
// just made. Nothing is ordered here; ordering is the reconciler's.
func (h handler) machineCertificatesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.projectDomains == nil {
		http.Error(w, "machine certificates are not available on this deployment", http.StatusNotImplemented)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var request MachineCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	tenantName := strings.TrimSpace(request.Tenant)
	if tenantName == "" {
		tenantName = user.UserKey
	}
	if err := h.authorizeWorkloadTenant(r.Context(), user.UserKey, tenantName); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	project := strings.TrimSpace(request.Project)
	if err := naming.ValidateProjectName(project); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	machine := strings.TrimSpace(request.Machine)
	if err := naming.ValidateMachineName(machine); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	domain, zone, err := h.projectDomains.ResolveProjectDomain(r.Context(), tenantName, project)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if domain == "" || zone == "" {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("project %q has no project domain", project))
		return
	}
	now := timeNow()
	hostname := strings.ToLower(machine + "." + strings.Trim(domain, "."))
	row, err := requestMachineCertificate(r.Context(), h.db, machineCertificateRequest{
		Hostname:     hostname,
		Tenant:       tenantName,
		Project:      project,
		Machine:      machine,
		Zone:         zone,
		DirectoryURL: h.acmeDirectory,
	}, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	view := MachineCertificateView{Hostname: row.Hostname, State: machineCertificateState(row, h.acmeDirectory, now)}
	w.Header().Set("Content-Type", "application/json")
	if view.State == machineCertStatePending {
		count, err := zoneIssuanceCount(r.Context(), h.db, zone, now.Add(-7*24*time.Hour))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if count >= machineCertZoneWeeklyBudget {
			view.Reason = certFailureRateLimited
			view.Error = fmt.Sprintf("rate-limited — zone %s has used its %d certificates for the last 7 days; the reconciler orders when the window frees", zone, machineCertZoneWeeklyBudget)
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(view)
			return
		}
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(view)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
