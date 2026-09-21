package authapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/svclog"
)

// Project Domain endpoints on the tenant plane (ADR-0027, spec §3.2):
//
//	POST   /api/projects                    {project, domain?, dryRun?}
//	GET    /api/projects/{name}/domain      → {tenant, project, domain, zone}
//	PUT    /api/projects/{name}/domain      {domain, dryRun?}
//	DELETE /api/projects/{name}/domain      ?dryRun=1
//	DELETE /api/projects/{name}             ?dryRun=1
//
// The order inside every mutation is DB first, Incus second: the claim row is
// the reservation and passes the conflict scan under SQLite's write lock; only
// a committed claim is ever stamped onto the Incus project. Error bodies are
// `{"error": "<verbatim §2.2 text>"}` and the CLI prints `error` unchanged.

// TenantProjectDomainManager is the Incus seam behind the Project Domain
// endpoints; satisfied by incusx.ProjectBrokerCreator. A missing project is
// reported by wrapping projectbroker.ErrProjectNotFound.
type TenantProjectDomainManager interface {
	// CreateTenantProjectWithDomain is CreateTenantProject with KeyV2Domain
	// set in the same project-create request (and the profile rendered with
	// the derived-name seed).
	CreateTenantProjectWithDomain(ctx context.Context, tenant, project, clientCertificatePEM, domain string) (projectbroker.ProjectResult, error)
	// SetProjectDomain writes (domain != "") or removes (domain == "")
	// KeyV2Domain on the app project and re-renders its default profile.
	SetProjectDomain(ctx context.Context, tenant, project, domain string) error
	// DeleteTenantProject deletes the app project with its machines, volumes
	// and profiles.
	DeleteTenantProject(ctx context.Context, tenant, project string) error
	// SetMachinePublicHostnames rewrites the machine's KeyV2PublicHostnames
	// list (ADR-0028); an empty list deletes the key. A missing machine is
	// reported by wrapping ErrMachineNotFound.
	SetMachinePublicHostnames(ctx context.Context, tenant, project, machine string, hostnames []string) error
}

// ProjectCreateRequest is the body of POST /api/projects.
type ProjectCreateRequest struct {
	Project string `json:"project"`
	Domain  string `json:"domain,omitempty"`
	DryRun  bool   `json:"dryRun,omitempty"`
}

// ProjectDomainRequest is the body of PUT /api/projects/{name}/domain.
type ProjectDomainRequest struct {
	Domain string `json:"domain"`
	DryRun bool   `json:"dryRun,omitempty"`
}

// ProjectDomainResult is the body of the domain endpoints' successes.
type ProjectDomainResult struct {
	CertState    string   `json:"certState,omitempty"`
	CertNotAfter string   `json:"certNotAfter,omitempty"`
	SANs         []string `json:"sans,omitempty"`
	Tenant       string   `json:"tenant"`
	Project      string   `json:"project"`
	// Domain is the claimed Project Domain ("" after unset-domain).
	Domain string `json:"domain,omitempty"`
	Zone   string `json:"zone,omitempty"`
	// Released is the domain an unset/delete released.
	Released string `json:"released,omitempty"`
	// AlreadyClaimed marks the same-project identical re-claim no-op.
	AlreadyClaimed bool `json:"alreadyClaimed,omitempty"`
	DryRun         bool `json:"dryRun,omitempty"`
}

// projectDomainErrorStatus maps the claim/validation refusals to a status.
func projectDomainErrorStatus(err error) int {
	var claimErr *DomainClaimError
	var validationErr *ProjectDomainError
	switch {
	case errors.As(err, &claimErr):
		return http.StatusConflict
	case errors.As(err, &validationErr):
		return http.StatusBadRequest
	case errors.Is(err, projectbroker.ErrProjectNotFound):
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

const projectDomainsUnavailableMessage = "project domains are not available on this deployment"

// projectCreateWithDomain is the domain branch of POST /api/projects: claim,
// then create with KeyV2Domain in the same Incus request, deleting the claim
// row if Incus fails (compensation). A dry run with no domain only validates
// the project name.
func (h handler) projectCreateWithDomain(w http.ResponseWriter, r *http.Request, user User, project string, request ProjectCreateRequest) {
	tenantName, err := h.requestTenant(r, user)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	domainValue := strings.TrimSpace(request.Domain)
	if domainValue == "" {
		// --dry-run without --domain: the name passed validation above.
		writeJSON(w, http.StatusOK, projectbroker.ProjectResult{Tenant: tenantName, Project: project, DryRun: true})
		return
	}
	if h.projectDomains == nil {
		writeAPIError(w, http.StatusNotImplemented, errors.New(projectDomainsUnavailableMessage))
		return
	}
	if _, err := NormalizeProjectDomain(domainValue); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	claim, _, err := ClaimProjectDomain(r.Context(), h.db, ClaimProjectDomainRequest{
		Domain:          domainValue,
		Tenant:          tenantName,
		Project:         project,
		UserKey:         user.UserKey,
		AuthHostname:    h.authHostname,
		RouteBaseDomain: h.routeBase(),
		AdminView:       user.SandcastleAdmin,
		DryRun:          request.DryRun,
	})
	if err != nil {
		var already *ProjectDomainAlreadyClaimedError
		if errors.As(err, &already) {
			// The project does not exist yet, so a row for it is an orphan the
			// GC would drop; treat it as the exact-conflict it really is.
			err = &DomainClaimError{Domain: already.Domain, Existing: already.Domain, Project: project, Class: DomainClaimConflictExact, SameTenant: true}
		}
		writeAPIError(w, projectDomainErrorStatus(err), err)
		return
	}
	if request.DryRun {
		writeJSON(w, http.StatusOK, projectbroker.ProjectResult{Tenant: tenantName, Project: project, Domain: claim.Domain, Zone: claim.Zone, DryRun: true})
		return
	}
	clientCertificatePEM, _ := GetUserClientCertificate(r.Context(), h.db, user.UserKey)
	var result projectbroker.ProjectResult
	err = svclog.Span(r.Context(), "project.create", func() error {
		var createErr error
		result, createErr = h.projectDomains.CreateTenantProjectWithDomain(r.Context(), tenantName, project, clientCertificatePEM, claim.Domain)
		return createErr
	})
	if err != nil {
		if _, _, releaseErr := ReleaseProjectDomainClaim(r.Context(), h.db, tenantName, project); releaseErr != nil {
			err = fmt.Errorf("%w (and could not release the project domain claim: %v)", err, releaseErr)
		}
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	result.Domain = claim.Domain
	result.Zone = claim.Zone
	h.extendMemberCertificates(r, tenantName, user.UserKey, result.IncusProject)
	h.kickZoneReconcile()
	writeJSON(w, http.StatusOK, result)
}

// projectAPI routes /api/projects/{name} and /api/projects/{name}/domain.
func (h handler) projectAPI(w http.ResponseWriter, r *http.Request) {
	user, err := h.requireBearerUser(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/projects/")
	project, action, _ := strings.Cut(rest, "/")
	project = strings.TrimSpace(project)
	if err := naming.ValidateProjectName(project); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	dryRun := r.URL.Query().Get("dryRun") == "1" || r.URL.Query().Get("dryRun") == "true"
	switch {
	case action == "domain" && r.Method == http.MethodGet:
		h.projectDomainGet(w, r, user, project)
	case action == "domain" && r.Method == http.MethodPut:
		h.projectDomainSet(w, r, user, project)
	case action == "domain" && r.Method == http.MethodDelete:
		h.projectDomainUnset(w, r, user, project, dryRun)
	case action == "" && r.Method == http.MethodDelete:
		h.projectDelete(w, r, user, project, dryRun)
	default:
		writeAPIError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (h handler) projectDomainGet(w http.ResponseWriter, r *http.Request, user User, project string) {
	tenantName, err := h.requestTenant(r, user)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	claim, found, err := GetProjectDomainClaim(r.Context(), h.db, tenantName, project)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	result := ProjectDomainResult{Tenant: tenantName, Project: project}
	if found {
		result.Domain, result.Zone = claim.Domain, claim.Zone
		h.projectCertificateStatus(r.Context(), &result)
	}
	writeJSON(w, http.StatusOK, result)
}

// set-domain and unset-domain are allowed with machines in the project
// (machine-hostnames §7.1): the zone reconciler re-derives every machine's
// `<machine>.<domain>`, converges its public-name list, pushes its hostnames
// file and orders the new name's certificate; the released domain's records
// and certificate rows go with the claim (onProjectDomainReleased).

func (h handler) projectDomainSet(w http.ResponseWriter, r *http.Request, user User, project string) {
	tenantName, err := h.requestTenant(r, user)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	if h.projectDomains == nil {
		writeAPIError(w, http.StatusNotImplemented, errors.New(projectDomainsUnavailableMessage))
		return
	}
	var request ProjectDomainRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeAPIError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	if _, err := NormalizeProjectDomain(request.Domain); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	claim, previous, err := ClaimProjectDomain(r.Context(), h.db, ClaimProjectDomainRequest{
		Domain:          request.Domain,
		Tenant:          tenantName,
		Project:         project,
		UserKey:         user.UserKey,
		AuthHostname:    h.authHostname,
		RouteBaseDomain: h.routeBase(),
		AdminView:       user.SandcastleAdmin,
		DryRun:          request.DryRun,
	})
	result := ProjectDomainResult{Tenant: tenantName, Project: project, DryRun: request.DryRun}
	if err != nil {
		var already *ProjectDomainAlreadyClaimedError
		if errors.As(err, &already) {
			result.Domain, result.Zone, result.AlreadyClaimed = claim.Domain, claim.Zone, true
			h.projectCertificateStatus(r.Context(), &result)
			if !request.DryRun {
				h.kickZoneReconcile()
			}
			writeJSON(w, http.StatusOK, result)
			return
		}
		writeAPIError(w, projectDomainErrorStatus(err), err)
		return
	}
	result.Domain, result.Zone = claim.Domain, claim.Zone
	result.CertState = "pending"
	result.SANs = machineCertificateHostnames(claim.Domain)
	if request.DryRun {
		writeJSON(w, http.StatusOK, result)
		return
	}
	err = svclog.Span(r.Context(), "project.set-domain", func() error {
		return h.projectDomains.SetProjectDomain(r.Context(), tenantName, project, claim.Domain)
	})
	if err != nil {
		// Compensation: the reservation must not outlive a failed Incus write.
		// The previous claim (a replaced domain) is put back best-effort so
		// the project's DB and Incus state stay aligned.
		if _, _, releaseErr := ReleaseProjectDomainClaim(r.Context(), h.db, tenantName, project); releaseErr != nil {
			err = fmt.Errorf("%w (and could not release the project domain claim: %v)", err, releaseErr)
		} else if previous != nil {
			if restoreErr := restoreProjectDomainClaim(r.Context(), h.db, *previous); restoreErr != nil {
				err = fmt.Errorf("%w (and could not restore the previous claim %s: %v)", err, previous.Domain, restoreErr)
			}
		}
		writeAPIError(w, projectDomainErrorStatus(err), err)
		return
	}
	if previous != nil && previous.Domain != claim.Domain {
		// A replaced domain is a released one: its records and certificate
		// rows go, exactly as with unset-domain; the reconciler re-derives
		// every machine's name under the new domain on its next pass.
		if err := onProjectDomainReleased(r.Context(), h.db, *previous); err != nil {
			svclog.Logf(r.Context(), "project domain %s replaced with cleanup errors: %v", previous.Domain, err)
		}
	}
	h.kickZoneReconcile()
	writeJSON(w, http.StatusOK, result)
}

func (h handler) projectDomainUnset(w http.ResponseWriter, r *http.Request, user User, project string, dryRun bool) {
	tenantName, err := h.requestTenant(r, user)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	if h.projectDomains == nil {
		writeAPIError(w, http.StatusNotImplemented, errors.New(projectDomainsUnavailableMessage))
		return
	}
	result := ProjectDomainResult{Tenant: tenantName, Project: project, DryRun: dryRun}
	if dryRun {
		claim, found, err := GetProjectDomainClaim(r.Context(), h.db, tenantName, project)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		if found {
			result.Released = claim.Domain
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	claim, found, err := ReleaseProjectDomainClaim(r.Context(), h.db, tenantName, project)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	if found {
		result.Released = claim.Domain
		if err := onProjectDomainReleased(r.Context(), h.db, claim); err != nil {
			svclog.Logf(r.Context(), "project domain %s released with cleanup errors: %v", claim.Domain, err)
		}
	}
	// Unset the Incus key even without a row: this is how an "Incus key
	// without row" project (logged by the GC) is repaired by its tenant.
	err = svclog.Span(r.Context(), "project.unset-domain", func() error {
		return h.projectDomains.SetProjectDomain(r.Context(), tenantName, project, "")
	})
	if err != nil {
		// The claim is already released; a failure here is repaired by the
		// GC (the key without a row is logged, never re-claimed), never rolled
		// back — the tenant asked for the domain to go.
		writeAPIError(w, projectDomainErrorStatus(err), err)
		return
	}
	h.kickZoneReconcile()
	writeJSON(w, http.StatusOK, result)
}

// projectDelete is the tenant-plane project deletion (spec §3.2): claim →
// [Cloudflare records + certificate rows: onProjectDomainReleased, slice 6] →
// Incus. A failure after the claim is released is repaired by the GC.
func (h handler) projectDelete(w http.ResponseWriter, r *http.Request, user User, project string, dryRun bool) {
	tenantName, err := h.requestTenant(r, user)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	if h.projectDomains == nil {
		writeAPIError(w, http.StatusNotImplemented, errors.New("project deletion is not available on this deployment"))
		return
	}
	if project == naming.DefaultProjectName {
		writeAPIError(w, http.StatusBadRequest, errors.New("default project cannot be deleted"))
		return
	}
	result := ProjectDomainResult{Tenant: tenantName, Project: project, DryRun: dryRun}
	if dryRun {
		claim, found, err := GetProjectDomainClaim(r.Context(), h.db, tenantName, project)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		if found {
			result.Released = claim.Domain
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	claim, found, err := ReleaseProjectDomainClaim(r.Context(), h.db, tenantName, project)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	if found {
		result.Released = claim.Domain
		if err := onProjectDomainReleased(r.Context(), h.db, claim); err != nil {
			svclog.Logf(r.Context(), "project domain %s released with cleanup errors: %v", claim.Domain, err)
		}
	}
	// The project's machines go with it: their explicit Machine Public
	// Hostnames (ADR-0028) are released the same way, before Incus.
	hostnames, err := ReleaseMachineHostnamesOfProject(r.Context(), h.db, tenantName, project)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	for _, hostname := range hostnames {
		if err := onMachineHostnameReleased(r.Context(), h.db, hostname); err != nil {
			svclog.Logf(r.Context(), "machine hostname %s released with cleanup errors: %v", hostname.Hostname, err)
		}
	}
	err = svclog.Span(r.Context(), "project.delete", func() error {
		return h.projectDomains.DeleteTenantProject(r.Context(), tenantName, project)
	})
	if err != nil {
		writeAPIError(w, projectDomainErrorStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
