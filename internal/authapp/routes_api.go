package authapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	svclog "github.com/thieso2/sandcastle-incus/internal/svclog"
)

// Route API (Spec #111). The Auth App is the sole owner of Public Routes:
// token-gated POST/GET/DELETE /api/routes for Tenants, plus an unauthenticated
// GET /api/routes/ask that Caddy's on-demand TLS calls to gate certificate
// issuance to registered Hostnames only.

// RoutePublishRequest is the POST /api/routes body. Hostname (custom) takes
// precedence over Name (subdomain label); when both are empty the Machine name
// is the label. The <tenant> segment is always derived server-side, never from
// this request.
type RoutePublishRequest struct {
	Tenant      string `json:"tenant"`
	Project     string `json:"project"`
	Machine     string `json:"machine"`
	BackendPort int    `json:"backendPort"`
	Name        string `json:"name,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
}

// RouteView is the API representation of a Route.
type RouteView struct {
	Hostname    string `json:"hostname"`
	URL         string `json:"url"`
	Tenant      string `json:"tenant"`
	Project     string `json:"project"`
	Machine     string `json:"machine"`
	MachineFQDN string `json:"machineFqdn,omitempty"` // Machine Private Hostname; empty when the appliance could not resolve it (clients fall back to Machine)
	BackendPort int    `json:"backendPort"`
	Status      string `json:"status"`
}

// RouteListResult is the GET /api/routes response.
type RouteListResult struct {
	Routes []RouteView `json:"routes"`
}

// RouteConfigView is the GET /api/routes/config response: everything a Tenant
// needs to publish a Route without asking the operator — where auto-subdomains
// live, and what a custom Hostname must be CNAME'd onto. The appliance is the
// only party that knows all of it, so `sc route` reads it from here instead of
// documenting a per-install answer that goes stale.
type RouteConfigView struct {
	// Enabled is false on installs without route ingress; the rest is then empty
	// and `sc route` explains how to turn it on rather than failing obscurely.
	Enabled bool `json:"enabled"`
	// Ingress is the route ingress mode: "acme" or "acme-proxied".
	Ingress string `json:"ingress,omitempty"`
	// BaseDomain is what auto-subdomains hang off: <label>.<tenant>.<base>.
	BaseDomain string `json:"baseDomain,omitempty"`
	// CNAMETarget is the front door a custom Hostname must point at. Empty when
	// the operator has not declared one and it cannot be inferred — the CLI then
	// says so plainly instead of inventing a target.
	CNAMETarget string `json:"cnameTarget,omitempty"`
}

const routesUnavailableMessage = "public routes are not available on this install: it has no route ingress. Redeploy with `--route-ingress acme` — or `--route-ingress acme-proxied` when something else already owns the host :80/:443 and an SNI proxy forwards to the appliance (sc-adm install or sc-adm auth-app deploy). Either way it runs beside a Cloudflare-tunnelled login host."

func routeView(rs RouteStatus) RouteView {
	return RouteView{
		Hostname:    rs.Hostname,
		URL:         "https://" + rs.Hostname,
		Tenant:      rs.Tenant,
		Project:     rs.Project,
		Machine:     rs.Machine,
		MachineFQDN: rs.MachineFQDN,
		BackendPort: rs.BackendPort,
		Status:      rs.Status,
	}
}

func (h handler) routesAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.routePublish(w, r)
	case http.MethodGet:
		h.routeGet(w, r)
	case http.MethodDelete:
		h.routeDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// authorizeRouteTenant gates the Route API. A Tenant reaches their own Routes
// exactly as before (authorizeWorkloadTenant); a Sandcastle Admin additionally
// reaches every Tenant's, because operating an install means publishing and
// pulling Routes on a Tenant's behalf — the alternative is hand-editing the
// front door, which is what Public Routes exist to avoid.
//
// Deliberately separate from authorizeWorkloadTenant rather than widening it:
// that one also guards Workload Identity token issuance, where "an admin may
// act as any tenant" would hand out cloud credentials, not a hostname.
func (h handler) authorizeRouteTenant(ctx context.Context, user User, tenantName string) error {
	if user.SandcastleAdmin {
		if strings.TrimSpace(tenantName) == "" {
			return fmt.Errorf("tenant is required")
		}
		return nil
	}
	return h.authorizeWorkloadTenant(ctx, user.UserKey, tenantName)
}

func (h handler) routePublish(w http.ResponseWriter, r *http.Request) {
	manager, ok := h.routeManager()
	if !ok {
		http.Error(w, routesUnavailableMessage, http.StatusNotImplemented)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var request RoutePublishRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	request.Tenant = strings.TrimSpace(request.Tenant)
	request.Project = strings.TrimSpace(request.Project)
	request.Machine = strings.TrimSpace(request.Machine)
	if err := h.authorizeRouteTenant(r.Context(), user, request.Tenant); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if request.BackendPort <= 0 {
		http.Error(w, "a positive backend port is required", http.StatusBadRequest)
		return
	}
	hostname, err := h.routeHostname(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var route Route
	err = svclog.Span(r.Context(), "route.publish", func() error {
		var pubErr error
		route, pubErr = manager.Publish(r.Context(), PublishRequest{
			Hostname:    hostname,
			Tenant:      request.Tenant,
			Project:     request.Project,
			Machine:     request.Machine,
			BackendPort: request.BackendPort,
		})
		return pubErr
	})
	if err != nil {
		var conflict *RouteConflictError
		var inside *RouteInsideProjectDomainError
		if errors.As(err, &conflict) || errors.As(err, &inside) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, routeView(manager.Status(r.Context(), route)))
}

func (h handler) routeGet(w http.ResponseWriter, r *http.Request) {
	manager, ok := h.routeManager()
	if !ok {
		http.Error(w, routesUnavailableMessage, http.StatusNotImplemented)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	tenantName := strings.TrimSpace(r.URL.Query().Get("tenant"))
	hostname := normalizeHostname(r.URL.Query().Get("hostname"))

	if hostname != "" {
		route, found, err := GetRoute(r.Context(), h.db, hostname)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, fmt.Sprintf("route %q is not published", hostname), http.StatusNotFound)
			return
		}
		if err := h.authorizeRouteTenant(r.Context(), user, route.Tenant); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusOK, routeView(manager.Status(r.Context(), route)))
		return
	}

	if err := h.authorizeRouteTenant(r.Context(), user, tenantName); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	routes, err := ListRoutesByTenant(r.Context(), h.db, tenantName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result := RouteListResult{Routes: []RouteView{}}
	for _, route := range routes {
		result.Routes = append(result.Routes, routeView(manager.Status(r.Context(), route)))
	}
	writeJSON(w, http.StatusOK, result)
}

func (h handler) routeDelete(w http.ResponseWriter, r *http.Request) {
	manager, ok := h.routeManager()
	if !ok {
		http.Error(w, routesUnavailableMessage, http.StatusNotImplemented)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	hostname := normalizeHostname(r.URL.Query().Get("hostname"))
	if hostname == "" {
		http.Error(w, "hostname is required", http.StatusBadRequest)
		return
	}
	route, found, err := GetRoute(r.Context(), h.db, hostname)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, fmt.Sprintf("route %q is not published", hostname), http.StatusNotFound)
		return
	}
	if err := h.authorizeRouteTenant(r.Context(), user, route.Tenant); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	err = svclog.Span(r.Context(), "route.delete", func() error {
		return manager.Delete(r.Context(), hostname, route.Tenant)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"hostname": hostname, "status": "deleted"})
}

// routesConfig answers GET /api/routes/config for `sc route`. Unlike the other
// route endpoints it does not 501 when route ingress is off: a Tenant asking
// "how do I publish?" on an install without routes deserves the answer "this
// install has none", which Enabled=false carries.
func (h handler) routesConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := h.requireBearerUser(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	_, enabled := h.routeManager()
	if !enabled {
		writeJSON(w, http.StatusOK, RouteConfigView{Enabled: false})
		return
	}
	writeJSON(w, http.StatusOK, RouteConfigView{
		Enabled:     true,
		Ingress:     h.routeIngress,
		BaseDomain:  h.routeBase(),
		CNAMETarget: h.routeCNAMETarget(),
	})
}

// routeBase is where auto-subdomains live: the configured route base domain,
// else the Auth Hostname.
func (h handler) routeBase() string {
	if base := strings.Trim(strings.TrimSpace(h.routeBaseDomain), "."); base != "" {
		return base
	}
	return strings.Trim(strings.TrimSpace(h.authHostname), ".")
}

// routeCNAMETarget is the front door custom Hostnames must point at. The
// operator declares it (--route-cname-target) because only they know the
// topology: with an SNI front the target is that front's name, not the Auth
// Hostname. It is inferable in exactly one case — the Auth Hostname is itself
// served by this appliance over ACME, so its record already points at the host
// that terminates routes. A Cloudflare-tunnelled Auth Hostname is NOT a valid
// target (the tunnel only carries login), so nothing is guessed there.
func (h handler) routeCNAMETarget() string {
	if target := strings.Trim(strings.TrimSpace(h.routeCNAME), "."); target != "" {
		return target
	}
	if h.authIngressMode == IngressModeACME {
		return strings.Trim(strings.TrimSpace(h.authHostname), ".")
	}
	return ""
}

// routesAsk is Caddy's on-demand-TLS gate: it returns 200 only for Hostnames
// that are registered Routes, so Caddy will not fetch a certificate for an
// arbitrary Hostname under the wildcard. Unauthenticated — Caddy calls it over
// loopback.
func (h handler) routesAsk(w http.ResponseWriter, r *http.Request) {
	domain := normalizeHostname(r.URL.Query().Get("domain"))
	if domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}
	// No real TLS handshake ever presents a literal "*" SNI, so a domain that is
	// itself a wildcard is never a certificate to issue — deny outright.
	if strings.HasPrefix(domain, "*.") {
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}
	// The Auth Hostname itself is a normal (non-on-demand) certificate, but allow
	// it through in case Caddy ever asks.
	if domain == h.authHostname {
		w.WriteHeader(http.StatusOK)
		return
	}
	ok, err := RouteHostnameRegistered(r.Context(), h.db, domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		if wildcard, has := routeCoveringWildcard(domain); has {
			ok, err = RouteHostnameRegistered(r.Context(), h.db, wildcard)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	if !ok {
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// routeCoveringWildcard returns the wildcard Hostname that would cover domain:
// its leftmost label stripped and replaced with "*.". "a.b.example.com" ->
// "*.b.example.com". A domain with fewer than two labels has no label to
// strip, so it has no covering wildcard.
func routeCoveringWildcard(domain string) (string, bool) {
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", false
	}
	return "*." + strings.Join(labels[1:], "."), true
}

// routeHostname resolves the public FQDN for a publish request: a custom
// Hostname verbatim, else <label>.<tenant>.<auth-hostname> with the label
// defaulting to the Machine name. The <tenant> segment is derived here, never
// taken from the client.
func (h handler) routeHostname(request RoutePublishRequest) (string, error) {
	if custom := normalizeHostname(request.Hostname); custom != "" {
		if !isValidPublicHostname(custom) {
			return "", fmt.Errorf("invalid custom hostname %q", request.Hostname)
		}
		return custom, nil
	}
	label := strings.TrimSpace(request.Name)
	if label == "" {
		label = request.Machine
	}
	label = strings.ToLower(strings.TrimSpace(label))
	if !isValidDNSLabel(label) {
		return "", fmt.Errorf("invalid route name %q: use letters, digits, and hyphens", label)
	}
	base := h.routeBaseDomain
	if base == "" {
		base = h.authHostname
	}
	if strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("this install has no route base domain or Auth Hostname configured")
	}
	if strings.TrimSpace(request.Tenant) == "" {
		return "", fmt.Errorf("tenant is required")
	}
	return label + "." + request.Tenant + "." + base, nil
}

func (h handler) routeManager() (RouteManager, bool) {
	if h.routes == nil || h.routeCaddy == nil {
		return RouteManager{}, false
	}
	return RouteManager{
		DB:      h.db,
		Backend: h.routes,
		Caddy:   h.routeCaddy,
		// The publish path has no request logger to hand; stderr is the
		// appliance's journal, which is where an operator looks when a front
		// falls behind.
		Logf:        func(format string, args ...any) { fmt.Fprintf(os.Stderr, "auth-app route: "+format+"\n", args...) },
		Render:      RouteRenderConfig(h.authHostname, h.authIngressMode, h.routeBaseDomain, h.acmeEmail, h.routeTLS, h.routeDNSProvider, h.routeDNSWildcards),
		ResolveHost: h.routeResolveHost,
	}, true
}

func isValidDNSLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for i, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i != 0 && i != len(label)-1:
		default:
			return false
		}
	}
	return true
}

// isValidPublicHostname accepts an exact hostname, or a wildcard hostname
// whose leftmost label is exactly "*" and whose remainder (the rest of the
// name, without the "*." prefix) is itself a valid exact hostname. That base
// check never accepts "*" in a label, so a second/nested wildcard label (e.g.
// "foo.*.example.com" or "*.*.example.com") is rejected the same way any
// other invalid character would be.
func isValidPublicHostname(hostname string) bool {
	if rest, ok := strings.CutPrefix(hostname, "*."); ok {
		return isValidExactHostname(rest)
	}
	return isValidExactHostname(hostname)
}

func isValidExactHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 || !strings.Contains(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if !isValidDNSLabel(label) {
			return false
		}
	}
	return true
}
