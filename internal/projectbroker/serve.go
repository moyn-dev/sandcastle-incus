// Package projectbroker is the Sandcastle Broker's project-lifecycle service
// (ADR-0016). A tenant runs `sc project create <name>`, authenticated by their
// restricted Incus client certificate; the broker (holding admin credentials)
// maps the cert to the tenant, creates the app Incus project + profile, and
// extends the tenant's restricted cert to include it. It reuses the Route
// Broker's client-cert principal pattern.
package projectbroker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/svclog"
	"github.com/thieso2/sandcastle-incus/internal/update"
)

// Principal identifies the caller by their restricted Incus certificate.
type Principal struct {
	Fingerprint string
	Tenant      string
	Projects    []string
}

// TrustMapper resolves a client-certificate fingerprint to its Sandcastle
// principal (tenant + granted projects). Satisfied by incusx.RouteBrokerTrustMapper.
type TrustMapper interface {
	PrincipalForFingerprint(context.Context, string) (TrustPrincipal, error)
}

// ProjectCreator performs the privileged scaffolding: create the app Incus
// project + profile and extend the tenant's restricted cert to include it.
// clientCertificatePEM is the caller's client certificate (empty when unknown):
// with shared client identity the trust entry may be named after another
// tenant's enrollment, and the certificate is how the grant still finds it.
type ProjectCreator interface {
	CreateTenantProject(ctx context.Context, tenant string, project string, clientCertificatePEM string) (ProjectResult, error)
}

// AdminAuthorizer reports whether a client-certificate fingerprint belongs to a
// Sandcastle admin (a trusted, unrestricted client cert). This is the broker's
// admin plane: after the one-time bootstrap, admin tooling talks to the broker
// instead of opening a direct Incus connection.
type AdminAuthorizer interface {
	IsAdmin(context.Context, string) (bool, error)
}

// TenantProvisioner performs the privileged tenant bring-up (ADR-0016) and
// returns the enrollment token — the admin-plane counterpart of ProjectCreator.
type TenantProvisioner interface {
	CreateTenant(context.Context, TenantRequest) (TenantResult, error)
}

// TenantRequest is the admin's create-tenant payload.
type TenantRequest struct {
	Tenant           string `json:"tenant"`
	SSHPublicKey     string `json:"sshPublicKey,omitempty"`
	TailscaleAuthKey string `json:"tailscaleAuthKey,omitempty"`
	// DNSSuffix is the tenant-chosen Tenant DNS Suffix (ADR-0018); empty means
	// the tenant name.
	DNSSuffix string `json:"dnsSuffix,omitempty"`
}

// TenantResult is returned to the admin after a successful tenant bring-up.
type TenantResult struct {
	Tenant         string `json:"tenant"`
	InfraProject   string `json:"infraProject"`
	DefaultProject string `json:"defaultProject"`
	Bridge         string `json:"bridge"`
	DNSSuffix      string `json:"dnsSuffix"`
	Token          string `json:"token,omitempty"`
	// RemoteName is the client-side remote name for this enrollment
	// (sc-<tenant>, or sc-<prefix>-<tenant> for non-default installs).
	RemoteName string `json:"remoteName,omitempty"`
	// TailscaleLoginURL is set when the tenant was created without a Tailscale
	// auth key: the caller shows it so the user can register the sidecar.
	TailscaleLoginURL string `json:"tailscaleLoginURL,omitempty"`
}

// ProjectResult is returned to the caller after a successful create.
type ProjectResult struct {
	Tenant       string `json:"tenant"`
	Project      string `json:"project"`
	IncusProject string `json:"incusProject"`
	Bridge       string `json:"bridge"`
	DNSSuffix    string `json:"dnsSuffix"`
	// Domain is the Project Domain claimed at create time (ADR-0027), empty
	// for a private-mode project.
	Domain string `json:"domain,omitempty"`
	// Zone is the Public DNS Zone the Domain was claimed under.
	Zone string `json:"zone,omitempty"`
	// Image is the default machine image the project was given at creation.
	Image string `json:"image,omitempty"`
	// DryRun marks a validation-only create: nothing was claimed or created.
	DryRun bool `json:"dryRun,omitempty"`
}

// ErrProjectNotFound is returned (wrapped) by the Project Domain seam when the
// tenant has no such app project, so the Auth App can answer 404 instead of
// 500.
var ErrProjectNotFound = errors.New("project not found")

type createRequest struct {
	Project string `json:"project"`
}

// SidecarUpdateResult reports a completed delegated sidecar update (#124 §5).
type SidecarUpdateResult struct {
	Tenant        string `json:"tenant"`
	Project       string `json:"project"`
	Instance      string `json:"instance"`
	BinaryVersion string `json:"binaryVersion"`
}

// SidecarUpdater pushes the service's OWN running binary into the tenant's
// sidecar and restarts the TLS leaf signer — the delegated tenant sidecar
// update (#124 §5). Satisfied by incusx.SidecarSelfUpdater.
type SidecarUpdater interface {
	UpdateTenantSidecar(tenant string) (SidecarUpdateResult, error)
}

// Handler is the broker's HTTP handler. It expects a verified client
// certificate on the request TLS state. The tenant plane (Trust + Creator)
// serves `sc project create`; the admin plane (Admin + Provisioner) serves
// admin operations like `sc-adm tenant create`.
type Handler struct {
	Trust       TrustMapper
	Creator     ProjectCreator
	Admin       AdminAuthorizer
	Provisioner TenantProvisioner
	// Sidecars serves the tenant-triggered sidecar update (nil ⇒ 501).
	Sidecars SidecarUpdater
	// Version is the running binary's release version, sent on every response
	// as the version exchange (#124 §6).
	Version string
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	update.ApplyVersionHeaders(w.Header(), h.Version, update.MinCLIVersion)
	if update.RefuseCLI(r.Header.Get(update.HeaderCLIVersion), update.MinCLIVersion) {
		http.Error(w, update.RefusalMessage(update.MinCLIVersion), http.StatusUpgradeRequired)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	fingerprint := certificateFingerprint(r.TLS.PeerCertificates[0].Raw)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v2/projects":
		h.handleProjectCreate(w, r, fingerprint)
	case r.Method == http.MethodPost && r.URL.Path == "/v2/tenants":
		h.handleTenantCreate(w, r, fingerprint)
	case r.Method == http.MethodPost && r.URL.Path == "/v2/sidecar/update":
		h.handleSidecarUpdate(w, r, fingerprint)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (h Handler) handleProjectCreate(w http.ResponseWriter, r *http.Request, fingerprint string) {
	principal, err := ResolvePrincipal(r.Context(), h.Trust, fingerprint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	project := strings.TrimSpace(req.Project)
	if err := naming.ValidateNewProjectName(project); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	svclog.SetUser(r.Context(), principal.Tenant)
	peerPEM := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peerPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.TLS.PeerCertificates[0].Raw}))
	}
	var result ProjectResult
	err = svclog.Span(r.Context(), "project.create", func() error {
		var createErr error
		result, createErr = h.Creator.CreateTenantProject(r.Context(), principal.Tenant, project, peerPEM)
		return createErr
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func (h Handler) handleTenantCreate(w http.ResponseWriter, r *http.Request, fingerprint string) {
	if h.Admin == nil || h.Provisioner == nil {
		http.Error(w, "admin plane not configured", http.StatusNotFound)
		return
	}
	ok, err := h.Admin.IsAdmin(r.Context(), fingerprint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !ok {
		http.Error(w, "admin privileges required", http.StatusForbidden)
		return
	}
	var req TenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := naming.ValidateTenantName(strings.TrimSpace(req.Tenant)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	svclog.SetUser(r.Context(), strings.TrimSpace(req.Tenant))
	var result TenantResult
	err = svclog.Span(r.Context(), "tenant.create", func() error {
		var createErr error
		result, createErr = h.Provisioner.CreateTenant(r.Context(), req)
		return createErr
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

// handleSidecarUpdate is the tenant plane of #124 §5: the caller's cert maps
// to their tenant, and the broker pushes its own running binary into that
// tenant's sidecar — a tenant can only ever update their own sidecar.
func (h Handler) handleSidecarUpdate(w http.ResponseWriter, r *http.Request, fingerprint string) {
	if h.Sidecars == nil {
		http.Error(w, "sidecar updates not configured", http.StatusNotImplemented)
		return
	}
	principal, err := ResolvePrincipal(r.Context(), h.Trust, fingerprint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	svclog.SetUser(r.Context(), principal.Tenant)
	var result SidecarUpdateResult
	err = svclog.Span(r.Context(), "sidecar.update", func() error {
		var updateErr error
		result, updateErr = h.Sidecars.UpdateTenantSidecar(principal.Tenant)
		return updateErr
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, result)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ResolvePrincipal maps a fingerprint to a broker Principal via the trust mapper.
func ResolvePrincipal(ctx context.Context, mapper TrustMapper, fingerprint string) (Principal, error) {
	if mapper == nil {
		return Principal{}, fmt.Errorf("trust mapper is not configured")
	}
	p, err := mapper.PrincipalForFingerprint(ctx, fingerprint)
	if err != nil {
		return Principal{}, err
	}
	tenant := strings.TrimSpace(p.User)
	if err := naming.ValidateTenantName(tenant); err != nil {
		return Principal{}, fmt.Errorf("certificate %s maps to invalid tenant %q", fingerprint, p.User)
	}
	return Principal{Fingerprint: fingerprint, Tenant: tenant, Projects: p.Projects}, nil
}

func certificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ServePlan describes how to run the broker.
type ServePlan struct {
	Address  string
	CertFile string
	KeyFile  string
}

// Serve runs the broker until ctx is cancelled. TLS requires (but does not
// verify against a CA) a client certificate; the trust mapper is the real
// authorization gate.
func Serve(ctx context.Context, plan ServePlan, handler Handler) error {
	certificate, err := tls.LoadX509KeyPair(plan.CertFile, plan.KeyFile)
	if err != nil {
		return fmt.Errorf("load broker TLS certificate: %w", err)
	}
	address := strings.TrimSpace(plan.Address)
	if address == "" {
		address = ":9443"
	}
	listener, err := tls.Listen("tcp", address, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("listen for project broker on %s: %w", address, err)
	}
	logger := svclog.New("project-broker", os.Stderr, nil)
	server := &http.Server{
		Handler:     logger.HTTP(handler),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
