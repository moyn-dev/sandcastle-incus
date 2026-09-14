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

// Machine Public Hostname endpoints on the tenant plane (ADR-0028, spec
// machine-hostnames §2):
//
//	GET    /api/machines/{project}/{machine}/hostnames            ?tenant=
//	POST   /api/machines/{project}/{machine}/hostnames            {hostname, tenant?, dryRun?, beforeCreate?}
//	DELETE /api/machines/{project}/{machine}/hostnames/{hostname} ?tenant=&dryRun=1
//
// Bearer token, authorized like /api/machine-certificates (the caller's own
// tenant, or one it is granted). The order inside POST is DB first, Incus
// second: the reservation passes the shared conflict scan under SQLite's
// write lock, the pending machine_certificates row is recorded, and only
// then is the instance key `user.sandcastle.v2.public-hostnames` rewritten.
// Error bodies are `{"error": "<verbatim text>"}`; the CLI prints them as is.

// ErrMachineNotFound is what TenantProjectDomainManager.SetMachinePublicHostnames
// wraps when the project exists but the machine does not; the hostnames API
// answers 404 (and, for a claim, releases it again).
var ErrMachineNotFound = errors.New("machine not found")

// MachineHostnameRequest is the POST body.
type MachineHostnameRequest struct {
	// Tenant defaults to the caller's own tenant.
	Tenant   string `json:"tenant,omitempty"`
	Hostname string `json:"hostname"`
	DryRun   bool   `json:"dryRun,omitempty"`
	// BeforeCreate marks a claim made by `sc create --hostname` BEFORE the
	// instance exists: the reservation and the certificate row are recorded,
	// but the instance key is not written — the create call stamps it.
	BeforeCreate bool `json:"beforeCreate,omitempty"`
}

// MachineHostnameView is one public name of a machine.
type MachineHostnameView struct {
	Hostname string `json:"hostname"`
	// Derived marks `<machine>.<Project Domain>` — implied by the project's
	// domain, not a machine_hostnames row, and not removable per machine.
	Derived   bool   `json:"derived,omitempty"`
	Zone      string `json:"zone,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
}

// MachineHostnamesResult is the body of every hostnames endpoint success.
type MachineHostnamesResult struct {
	Tenant  string `json:"tenant"`
	Project string `json:"project"`
	Machine string `json:"machine"`
	// Hostname is the name a POST/DELETE acted on.
	Hostname string `json:"hostname,omitempty"`
	Zone     string `json:"zone,omitempty"`
	// Hostnames is the machine's full public-name set after the call: the
	// derived name (if any) plus every explicit hostname, sorted.
	Hostnames []MachineHostnameView `json:"hostnames"`
	// Released is the hostname a DELETE released.
	Released string `json:"released,omitempty"`
	// AlreadyHeld marks the same-machine identical re-claim no-op.
	AlreadyHeld bool `json:"alreadyHeld,omitempty"`
	DryRun      bool `json:"dryRun,omitempty"`
	// Certificate is the Machine Certificate state recorded by a POST
	// (pending, or issued when a retained certificate is reused).
	Certificate *MachineCertificateView `json:"certificate,omitempty"`
}

// Names lists the result's hostnames as plain strings.
func (r MachineHostnamesResult) Names() []string {
	names := make([]string, 0, len(r.Hostnames))
	for _, h := range r.Hostnames {
		names = append(names, h.Hostname)
	}
	return names
}

const machineHostnamesUnavailableMessage = "machine hostnames are not available on this deployment"

// machineHostnameErrorStatus maps the claim/validation refusals to a status.
func machineHostnameErrorStatus(err error) int {
	var claimErr *HostnameClaimError
	var validationErr *MachineHostnameError
	var notHeld *MachineHostnameNotHeldError
	switch {
	case errors.As(err, &claimErr):
		return http.StatusConflict
	case errors.As(err, &validationErr):
		return http.StatusBadRequest
	case errors.As(err, &notHeld), errors.Is(err, projectbroker.ErrProjectNotFound), errors.Is(err, ErrMachineNotFound):
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

// machinesAPI routes /api/machines/{project}/{machine}/hostnames[/{hostname}].
func (h handler) machinesAPI(w http.ResponseWriter, r *http.Request) {
	user, err := h.requireBearerUser(r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, err)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/machines/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) < 3 || parts[2] != "hostnames" || len(parts) > 4 {
		writeAPIError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	project, machine := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if err := naming.ValidateProjectName(project); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	if err := naming.ValidateMachineName(machine); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	hostname := ""
	if len(parts) == 4 {
		hostname = parts[3]
	}
	dryRun := r.URL.Query().Get("dryRun") == "1" || r.URL.Query().Get("dryRun") == "true"
	switch {
	case r.Method == http.MethodGet && hostname == "":
		h.machineHostnamesList(w, r, user, r.URL.Query().Get("tenant"), project, machine)
	case r.Method == http.MethodPost && hostname == "":
		h.machineHostnameAdd(w, r, user, project, machine)
	case r.Method == http.MethodDelete && hostname != "":
		h.machineHostnameRemove(w, r, user, r.URL.Query().Get("tenant"), project, machine, hostname, dryRun)
	default:
		writeAPIError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// machineHostnameTenant resolves and authorizes the tenant a request acts
// on: the caller's own by default, else one the caller is granted.
func (h handler) machineHostnameTenant(ctx context.Context, user User, requested string) (string, error) {
	tenantName := strings.TrimSpace(requested)
	if tenantName == "" {
		tenantName = user.UserKey
	}
	if err := h.authorizeWorkloadTenant(ctx, user.UserKey, tenantName); err != nil {
		return "", err
	}
	return tenantName, nil
}

// machineHostnamesView assembles the machine's full public-name set.
func (h handler) machineHostnamesView(ctx context.Context, tenantName, project, machine string) ([]MachineHostnameView, error) {
	var views []MachineHostnameView
	claim, found, err := GetProjectDomainClaim(ctx, h.db, tenantName, project)
	if err != nil {
		return nil, err
	}
	if found {
		views = append(views, MachineHostnameView{Hostname: strings.ToLower(machine) + "." + claim.Domain, Derived: true, Zone: claim.Zone})
	}
	held, err := MachineHostnamesOf(ctx, h.db, tenantName, project, machine)
	if err != nil {
		return nil, err
	}
	for _, row := range held {
		views = append(views, MachineHostnameView{Hostname: row.Hostname, Zone: row.Zone, CreatedAt: row.CreatedAt})
	}
	sortMachineHostnameViews(views)
	return views, nil
}

func sortMachineHostnameViews(views []MachineHostnameView) {
	for i := 1; i < len(views); i++ {
		for j := i; j > 0 && views[j].Hostname < views[j-1].Hostname; j-- {
			views[j], views[j-1] = views[j-1], views[j]
		}
	}
}

func (h handler) machineHostnamesList(w http.ResponseWriter, r *http.Request, user User, requestedTenant, project, machine string) {
	tenantName, err := h.machineHostnameTenant(r.Context(), user, requestedTenant)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	views, err := h.machineHostnamesView(r.Context(), tenantName, project, machine)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, MachineHostnamesResult{Tenant: tenantName, Project: project, Machine: machine, Hostnames: views})
}

// machineHostnameAdd is POST: claim → certificate row → instance key.
func (h handler) machineHostnameAdd(w http.ResponseWriter, r *http.Request, user User, project, machine string) {
	if h.projectDomains == nil {
		writeAPIError(w, http.StatusNotImplemented, errors.New(machineHostnamesUnavailableMessage))
		return
	}
	var request MachineHostnameRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeAPIError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	tenantName, err := h.machineHostnameTenant(r.Context(), user, request.Tenant)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	if _, err := NormalizeMachineHostname(request.Hostname); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	if err := RequireMachinePublicationHostnameAvailable(r.Context(), h.db, request.Hostname); err != nil {
		writeAPIError(w, http.StatusConflict, err)
		return
	}
	row, err := ClaimMachineHostname(r.Context(), h.db, ClaimMachineHostnameRequest{
		Hostname:        request.Hostname,
		Tenant:          tenantName,
		Project:         project,
		Machine:         machine,
		UserKey:         user.UserKey,
		AuthHostname:    h.authHostname,
		RouteBaseDomain: h.routeBase(),
		AdminView:       user.SandcastleAdmin,
		DryRun:          request.DryRun,
	})
	result := MachineHostnamesResult{Tenant: tenantName, Project: project, Machine: machine, DryRun: request.DryRun}
	alreadyHeld := false
	if err != nil {
		var already *MachineHostnameAlreadyHeldError
		if !errors.As(err, &already) {
			writeAPIError(w, machineHostnameErrorStatus(err), err)
			return
		}
		alreadyHeld = true
	}
	result.Hostname, result.Zone, result.AlreadyHeld = row.Hostname, row.Zone, alreadyHeld
	if request.DryRun {
		result.Hostnames, err = h.machineHostnamesView(r.Context(), tenantName, project, machine)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		if !alreadyHeld {
			result.Hostnames = append(result.Hostnames, MachineHostnameView{Hostname: row.Hostname, Zone: row.Zone})
			sortMachineHostnameViews(result.Hostnames)
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	// The pending Machine Certificate row rides the same request path
	// `sc create` uses for the derived name; nothing is ordered here.
	now := timeNow()
	certRow, err := requestMachineCertificate(r.Context(), h.db, machineCertificateRequest{
		Hostname:     row.Hostname,
		Tenant:       tenantName,
		Project:      project,
		Machine:      machine,
		Zone:         row.Zone,
		DirectoryURL: h.acmeDirectory,
	}, now)
	if err != nil {
		h.releaseHostnameAfterFailure(r.Context(), tenantName, project, machine, row.Hostname, alreadyHeld)
		writeAPIError(w, http.StatusInternalServerError, fmt.Errorf("record machine certificate: %w", err))
		return
	}
	result.Certificate = &MachineCertificateView{Hostname: certRow.Hostname, State: machineCertificateState(certRow, h.acmeDirectory, now)}
	if !request.BeforeCreate {
		err = svclog.Span(r.Context(), "machine.hostname-add", func() error {
			return h.stampMachinePublicHostnames(r.Context(), tenantName, project, machine)
		})
		if err != nil {
			// Compensation: the reservation must not outlive a failed Incus
			// write (a mistyped machine name would otherwise hold the name).
			h.releaseHostnameAfterFailure(r.Context(), tenantName, project, machine, row.Hostname, alreadyHeld)
			writeAPIError(w, machineHostnameErrorStatus(err), err)
			return
		}
	}
	result.Hostnames, err = h.machineHostnamesView(r.Context(), tenantName, project, machine)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	// Records, the order and the hostnames-file push are the zone
	// reconciler's; ask for a pass now rather than at the next tick.
	h.kickZoneReconcile()
	writeJSON(w, http.StatusOK, result)
}

// releaseHostnameAfterFailure drops a reservation this request created; a
// name the machine already held before the request stays.
func (h handler) releaseHostnameAfterFailure(ctx context.Context, tenantName, project, machine, hostname string, alreadyHeld bool) {
	if alreadyHeld {
		return
	}
	if _, err := ReleaseMachineHostname(ctx, h.db, tenantName, project, machine, hostname); err != nil {
		svclog.Logf(ctx, "machine hostname %s: could not release after a failed write: %v", hostname, err)
	}
}

// stampMachinePublicHostnames rewrites the machine's instance key from the
// registries: derived name + explicit hostnames.
func (h handler) stampMachinePublicHostnames(ctx context.Context, tenantName, project, machine string) error {
	names, err := PublicHostnamesOfMachine(ctx, h.db, tenantName, project, machine)
	if err != nil {
		return err
	}
	return h.projectDomains.SetMachinePublicHostnames(ctx, tenantName, project, machine, names)
}

// machineHostnameRemove is DELETE: release the reservation, run the release
// hook (the name's A and challenge records go; the certificate row stays
// under its own retention), rewrite the instance key, and kick the zone
// reconciler so the shrunken hostnames file reaches the machine now.
func (h handler) machineHostnameRemove(w http.ResponseWriter, r *http.Request, user User, requestedTenant, project, machine, hostname string, dryRun bool) {
	if h.projectDomains == nil {
		writeAPIError(w, http.StatusNotImplemented, errors.New(machineHostnamesUnavailableMessage))
		return
	}
	tenantName, err := h.machineHostnameTenant(r.Context(), user, requestedTenant)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, err)
		return
	}
	norm, err := NormalizeMachineHostname(hostname)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	result := MachineHostnamesResult{Tenant: tenantName, Project: project, Machine: machine, Hostname: norm, DryRun: dryRun}
	if dryRun {
		held, err := MachineHostnamesOf(r.Context(), h.db, tenantName, project, machine)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		found := false
		for _, row := range held {
			if row.Hostname == norm {
				found = true
				result.Released, result.Zone = row.Hostname, row.Zone
			}
		}
		if !found {
			err := &MachineHostnameNotHeldError{Hostname: norm, Project: project, Machine: machine}
			writeAPIError(w, machineHostnameErrorStatus(err), err)
			return
		}
		result.Hostnames, err = h.machineHostnamesView(r.Context(), tenantName, project, machine)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	released, err := ReleaseMachineHostname(r.Context(), h.db, tenantName, project, machine, norm)
	if err != nil {
		writeAPIError(w, machineHostnameErrorStatus(err), err)
		return
	}
	result.Released, result.Zone = released.Hostname, released.Zone
	if err := onMachineHostnameReleased(r.Context(), h.db, released); err != nil {
		svclog.Logf(r.Context(), "machine hostname %s released with cleanup errors: %v", released.Hostname, err)
	}
	if err := HoldMachinePublicationHostname(r.Context(), h.db, released.Hostname); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	err = svclog.Span(r.Context(), "machine.hostname-remove", func() error {
		return h.stampMachinePublicHostnames(r.Context(), tenantName, project, machine)
	})
	if err != nil && !errors.Is(err, ErrMachineNotFound) && !errors.Is(err, projectbroker.ErrProjectNotFound) {
		// The reservation is already released — the tenant asked for the
		// name to go; a stale instance key is converged by the reconciler,
		// never rolled back.
		writeAPIError(w, machineHostnameErrorStatus(err), err)
		return
	}
	result.Hostnames, err = h.machineHostnamesView(r.Context(), tenantName, project, machine)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	h.kickZoneReconcile()
	writeJSON(w, http.StatusOK, result)
}
