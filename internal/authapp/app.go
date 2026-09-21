package authapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/share"
	"github.com/thieso2/sandcastle-incus/internal/svclog"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/update"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
	_ "modernc.org/sqlite"
)

type ServeRequest struct {
	Address             string
	DatabasePath        string
	AuthHostname        string
	GitHubClientID      string
	GitHubClientSecret  string
	BootstrapAdminUsers []string
	DebugDeviceUser     string
	SimulateGitHubToken string
	DefaultUnixUser     string
	TailscaleAuthKey    string
	// ACMEDirectory is the install-level ACME directory URL for Machine
	// Certificates (ADR-0027); empty selects Let's Encrypt production.
	ACMEDirectory string
}

type ServePlan struct {
	Address             string   `json:"address"`
	DatabasePath        string   `json:"databasePath"`
	AuthHostname        string   `json:"authHostname"`
	GitHubClientID      string   `json:"githubClientID,omitempty"`
	GitHubClientSecret  string   `json:"-"`
	BootstrapAdminUsers []string `json:"bootstrapAdminUsers,omitempty"`
	DebugDeviceUser     string   `json:"debugDeviceUser,omitempty"`
	SimulateGitHubToken string   `json:"-"`
	DefaultUnixUser     string   `json:"defaultUnixUser,omitempty"`
	TailscaleAuthKey    string   `json:"-"`
	ACMEDirectory       string   `json:"acmeDirectory,omitempty"`
}

type Runner interface {
	Serve(context.Context, ServePlan) error
}

type RestrictedUserRevoker interface {
	Delete(context.Context, usertrust.UserPlan) error
}

type TenantAccessManager interface {
	Grant(context.Context, usertrust.UserPlan) error
	Revoke(context.Context, usertrust.UserPlan) error
	ListTenantUsers(context.Context, usertrust.TenantUsersPlan) (usertrust.TenantUsersResult, error)
}

type MachineSSHKeyReconciler interface {
	ReconcileUserSSHKey(context.Context, tenant.Summary, string, string) error
}

// TenantMembershipManager maintains a Shared Tenant's Tenant Members in
// Tenant Metadata (meta.KeyV2Members) and re-renders its profiles so new
// machines authorize the members' keys. Implemented by incusx.TenantCreator.
type TenantMembershipManager interface {
	AddTenantMemberV2(ctx context.Context, installPrefix string, tenantName string, userKey string) ([]string, error)
	RemoveTenantMemberV2(ctx context.Context, installPrefix string, tenantName string, userKey string) ([]string, error)
	// RenderTenantProfilesV2 re-renders every app project's profiles from the
	// tenant's current key set (a member rotated their login key).
	RenderTenantProfilesV2(ctx context.Context, installPrefix string, tenantName string) error
}

// SidecarAddressReader reports a tenant sidecar's tailnet address — what a
// Tenant Member's Incus remote must point at (the Incus Reach).
type SidecarAddressReader interface {
	SidecarTailnetIPV2(ctx context.Context, installPrefix string, tenantName string) (string, error)
}

type TenantSSHKeyUpdater interface {
}

type MachineSSHAccessRevoker interface {
	RevokeUserSSHKey(context.Context, tenant.Summary, string) error
}

type ShareReconciler interface {
	ReconcileTenantShares(context.Context, tenant.Summary, bool) (share.ReconcileResult, error)
}

type HTTPRunner struct {
	RestrictedUsers  RestrictedUserRevoker
	Provisioner      PersonalTenantProvisioner
	Admin            config.Admin
	Tenants          tenant.IncusTenantStore
	TenantAccess     TenantAccessManager
	Machines         machine.Store
	MachineSSHKeys   MachineSSHKeyReconciler
	TenantSSHKeys    TenantSSHKeyUpdater
	MachineSSHAccess MachineSSHAccessRevoker
	ShareStore       share.Store
	ShareReconciler  ShareReconciler
	// TenantMembers / SidecarAddresses back Shared Tenants: membership writes
	// on the web grant and member key rotation at login, and the sidecar
	// address /api/tenants hands a member so `sc tenant switch` can enrol the
	// tenant's remote.
	TenantMembers    TenantMembershipManager
	SidecarAddresses SidecarAddressReader
	// Projects performs the privileged project scaffolding for the token-gated
	// POST /api/projects — the tunnel-friendly tenant plane (no broker port).
	Projects TenantProjectCreator
	// ProjectDomains is the Incus seam for Project Domains (ADR-0027); see
	// HandlerOptions.ProjectDomains.
	ProjectDomains TenantProjectDomainManager
	// DNSEvents, when set, is started once and subscribes to instance lifecycle
	// events, calling notify() whenever tenant machine DNS may have changed —
	// the event-driven half of ADR-0018's registration. It should block until
	// ctx is done, reconnecting internally as needed.
	DNSEvents func(ctx context.Context, notify func())
	// DNSReconcile, when set, is invoked periodically to register tenant machine
	// DNS records (auto-registration of freeform `incus launch` machines).
	DNSReconcile func(context.Context) error
	// ZoneMachines, when set (the serving appliance with the mounted socket),
	// is the Incus seam of the Public DNS Zone reconciler (ADR-0027 §4): it
	// runs as the zone stage of the same DNS loop, after DNSReconcile.
	ZoneMachines ZoneMachineServer
	// TailnetPublisher configures the serving Tenant Sidecar for the opt-in
	// tailnet publication endpoint.
	TailnetPublisher TailnetPublisher
	// Routes, when set (ACME-ingress installs only), is the Incus seam for Public
	// Routes: per-Route proxy devices + Machine state. Its presence is what makes
	// `sc route` available on this install.
	Routes RouteBackend
	// RouteCaddy writes the appliance Caddyfile and reloads Caddy for Route
	// changes. Set alongside Routes.
	RouteCaddy CaddyController
	// ACMEEmail is the Let's Encrypt contact email, rendered into the Caddyfile
	// and the contact of the Machine Certificate ACME account (ADR-0027).
	ACMEEmail string
	// ProjectDomains resolves a tenant project's Project Domain + zone for
	// POST /api/machine-certificates (ADR-0027). nil until the install has
	// Project Domain claims: the endpoint then answers 501.
	ProjectDomainResolver ProjectDomainResolver
	// AuthIngressMode is how the Auth Hostname itself is served (acme|cloudflare|
	// none); it governs the login site in the regenerated Caddyfile so routes can
	// coexist with a Cloudflare-tunnelled login hostname.
	AuthIngressMode string
	// RouteBaseDomain is where Public Routes live (<label>.<tenant>.<base>); empty
	// falls back to the Auth Hostname.
	RouteBaseDomain string
	// RouteIngress is the route ingress mode ("acme"|"acme-proxied"), reported to
	// Tenants by GET /api/routes/config.
	RouteIngress string
	// RouteCNAMETarget is the front door a custom route Hostname must be CNAME'd
	// onto. Only the operator knows it when an SNI front sits in front of the
	// appliance; empty means "cannot be stated", not "use the Auth Hostname".
	RouteCNAMETarget string
	// RouteTLS overrides route-site TLS ("internal" = Caddy self-signed, for
	// hermetic tests). Never set in production.
	RouteTLS string
	// RouteDNSProvider enables operator-managed DNS-01 for wildcard Public
	// Routes. Empty preserves per-SNI on-demand issuance.
	RouteDNSProvider string
	// RouteDNSWildcards are the exact leading-wildcard Route hostnames the
	// operator authorizes to use the configured DNS credential.
	RouteDNSWildcards []string
	// RouteEvents, when set, subscribes to instance lifecycle events and calls
	// notify() so the Route reconcile runs within seconds of a Machine change.
	RouteEvents func(ctx context.Context, notify func())
	// Version is the running binary's release version, passed through to the
	// handler for the version exchange and the admin version card.
	Version string
	// Sidecars serves the token-authenticated tenant sidecar update (#124 §5).
	Sidecars projectbroker.SidecarUpdater
	// ResourceCacheEnabled is the admin-server config toggle (default on) for
	// the event-bus-fed Incus resource cache (docs/shape/admin-server-config-
	// toggled-event-bus-ca8marg.md). When false, or when ResourceCacheServer is
	// nil (no mounted host socket — not the serving appliance), the cache is
	// never started and every consumer must fall back to live per-project
	// queries.
	ResourceCacheEnabled bool
	// ResourceCacheServer, when set, is the Incus source RunResourceCache reads
	// from: one full read on startup, then per-project refreshes driven by the
	// event bus. Set alongside DNSEvents/RouteEvents, from the same mounted
	// socket.
	ResourceCacheServer ResourceCacheServer
	// ResourceCacheMachineRenderer converts one cached Incus instance into the
	// CLI-facing meta.Machine shape for GET /api/resources (t2 of the same
	// wish) — set alongside ResourceCacheServer, from
	// incusx.MachineFromInstance, so authapp (which incusx imports, not the
	// other way around) never has to duplicate NIC-address resolution or the
	// sidecar-instance filter.
	ResourceCacheMachineRenderer ResourceCacheMachineRenderer
}

func PlanServe(request ServeRequest) (ServePlan, error) {
	address := strings.TrimSpace(request.Address)
	if address == "" {
		return ServePlan{}, fmt.Errorf("auth app listen address is required")
	}
	databasePath := strings.TrimSpace(request.DatabasePath)
	if databasePath == "" {
		return ServePlan{}, fmt.Errorf("auth database path is required")
	}
	defaultUnixUser := strings.TrimSpace(request.DefaultUnixUser)
	if defaultUnixUser != "" {
		if err := naming.ValidateUnixUsername(defaultUnixUser); err != nil {
			return ServePlan{}, err
		}
	}
	acmeDirectory, err := NormalizeACMEDirectory(request.ACMEDirectory)
	if err != nil {
		return ServePlan{}, err
	}
	return ServePlan{
		ACMEDirectory:       acmeDirectory,
		Address:             address,
		DatabasePath:        databasePath,
		AuthHostname:        strings.Trim(strings.TrimSpace(request.AuthHostname), "."),
		GitHubClientID:      strings.TrimSpace(request.GitHubClientID),
		GitHubClientSecret:  strings.TrimSpace(request.GitHubClientSecret),
		BootstrapAdminUsers: NormalizeGitHubUsernames(request.BootstrapAdminUsers),
		DebugDeviceUser:     NormalizeGitHubUsername(request.DebugDeviceUser),
		SimulateGitHubToken: strings.TrimSpace(request.SimulateGitHubToken),
		DefaultUnixUser:     defaultUnixUser,
		TailscaleAuthKey:    strings.TrimSpace(request.TailscaleAuthKey),
	}, nil
}

func (r HTTPRunner) Serve(ctx context.Context, plan ServePlan) error {
	db, err := OpenDatabase(plan.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()

	// Verbose logging: every request + work span is written to stderr (journald
	// under systemd) and persisted to the logs table via the async sink so the
	// /logs browser can scope them per user.
	sink := newDBSink(db, 0)
	defer sink.Close()
	logger := svclog.New("auth-app", os.Stderr, sink)

	migrateStart := time.Now()
	if err := Migrate(ctx, db); err != nil {
		return err
	}
	logger.Message(ctx, "INFO", "auth database migrated in %dms", time.Since(migrateStart).Milliseconds())
	logger.Message(ctx, "INFO", "machine certificates: acme directory %s", plan.ACMEDirectory)
	if err := BootstrapAdmins(ctx, db, plan.BootstrapAdminUsers); err != nil {
		return err
	}
	provisioner := injectServeDependencies(r.Provisioner, db, plan.DefaultUnixUser)
	// Built before the handler (rather than started alongside DNSReconcile
	// below) so GET /api/resources can be wired to it: a nil cache here is
	// exactly "toggle off, or no mounted host socket" — the same condition
	// that keeps RunResourceCache from ever starting — and the endpoint
	// answers 503 for both without a separate flag.
	var resourceCache *ResourceCache
	if r.ResourceCacheEnabled && r.ResourceCacheServer != nil {
		resourceCache = NewResourceCache(DefaultResourceCacheStaleAfter)
	}
	// The zone stage (ADR-0027 §4) rides the DNS loop: same ticker, same
	// lifecycle-event trigger, so instance-started pushes a certificate
	// within seconds. The certmagic issuer is built here because only Serve
	// holds the database the zone tokens are decrypted from. Built before the
	// handler so the hostname endpoints can kick it.
	var zones *zoneReconciler
	var issuer certIssuer
	if r.ZoneMachines != nil {
		issuer = newACMEIssuer(db, plan.ACMEDirectory, r.ACMEEmail, func(ctx context.Context, zone string) (string, error) {
			return PublicDNSZoneToken(ctx, db, zone)
		})
		zones = newZoneReconciler(db, r.ZoneMachines, issuer, plan.ACMEDirectory, func(level, format string, args ...any) {
			logger.Message(ctx, level, "auth-app "+format, args...)
		})
	}
	server := &http.Server{
		Addr: plan.Address,
		Handler: logger.HTTP(NewHandler(db, HandlerOptions{
			AuthHostname:                 plan.AuthHostname,
			GitHubClientID:               plan.GitHubClientID,
			GitHubClientSecret:           plan.GitHubClientSecret,
			RestrictedUsers:              r.RestrictedUsers,
			Provisioner:                  provisioner,
			Admin:                        r.Admin,
			Tenants:                      r.Tenants,
			TenantAccess:                 r.TenantAccess,
			Machines:                     r.Machines,
			MachineSSHKeys:               r.MachineSSHKeys,
			TenantSSHKeys:                r.TenantSSHKeys,
			MachineSSHAccess:             r.MachineSSHAccess,
			ShareStore:                   r.ShareStore,
			ShareReconciler:              r.ShareReconciler,
			TenantMembers:                r.TenantMembers,
			SidecarAddresses:             r.SidecarAddresses,
			Projects:                     r.Projects,
			ProjectDomains:               r.ProjectDomains,
			DebugDeviceUser:              plan.DebugDeviceUser,
			SimulateGitHubToken:          plan.SimulateGitHubToken,
			TailscaleAuthKey:             plan.TailscaleAuthKey,
			Routes:                       r.Routes,
			RouteCaddy:                   r.RouteCaddy,
			ACMEEmail:                    r.ACMEEmail,
			ACMEDirectory:                plan.ACMEDirectory,
			ProjectDomainResolver:        r.ProjectDomainResolver,
			AuthIngressMode:              r.AuthIngressMode,
			RouteBaseDomain:              r.RouteBaseDomain,
			RouteIngress:                 r.RouteIngress,
			RouteCNAMETarget:             r.RouteCNAMETarget,
			RouteTLS:                     r.RouteTLS,
			RouteDNSProvider:             r.RouteDNSProvider,
			RouteDNSWildcards:            r.RouteDNSWildcards,
			Version:                      r.Version,
			Sidecars:                     r.Sidecars,
			ResourceCache:                resourceCache,
			ResourceCacheMachineRenderer: r.ResourceCacheMachineRenderer,
			ZoneReconcileKick:            zones.RequestPass,
			TailnetPublisher:             r.TailnetPublisher,
			TailnetIssuer:                issuer,
		})),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if r.DNSReconcile != nil || zones != nil {
		go r.runDNSReconcileLoop(ctx, logger, zones)
	}
	if resourceCache != nil {
		go RunResourceCache(ctx, resourceCache, r.ResourceCacheServer, func(format string, args ...any) {
			logger.Message(ctx, "WARN", format, args...)
		})
	}
	if r.Tenants != nil {
		// Garbage-collect DNS-suffix claims orphaned by tenants deleted out-of-band
		// (ADR-0020); `sc-adm tenant delete` runs against Incus and cannot reach the
		// auth database, so a periodic reconcile is the cleanup path. The same
		// loop prunes Project Domain claims of projects deleted out-of-band
		// (ADR-0027 §4.6).
		go r.runSuffixClaimReconcileLoop(ctx, db, logger)
	}
	if r.Routes != nil && r.RouteCaddy != nil {
		// Reconcile Public Routes against live Machine state: prune routes whose
		// Machine was deleted, refresh proxy-device connect on IP change (Spec #111).
		go r.runRouteReconcileLoop(ctx, db, logger, plan.AuthHostname)
	}
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-errCh
	case err := <-errCh:
		return err
	}
}

// runDNSReconcileLoop registers tenant machine DNS records so freeform
// `incus launch` machines resolve without a manual step (ADR-0018): instance
// lifecycle events trigger a reconcile within seconds (with two settle passes
// to catch the DHCP lease landing after the event), and a periodic pass every
// 30s guarantees convergence across missed events and restarts. Errors are
// logged and the loop continues; it stops when ctx is cancelled.
func (r HTTPRunner) runDNSReconcileLoop(ctx context.Context, logger *svclog.Logger, zones *zoneReconciler) {
	const interval = 30 * time.Second
	reconcile := func() {
		if r.DNSReconcile != nil {
			if err := r.DNSReconcile(ctx); err != nil {
				logger.Message(ctx, "ERROR", "auth-app DNS reconcile: %v", err)
			}
		}
		if zones != nil {
			if err := zones.Reconcile(ctx); err != nil {
				logger.Message(ctx, "ERROR", "auth-app zone reconcile: %v", err)
			}
		}
	}
	trigger := make(chan struct{}, 1)
	notify := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	if zones != nil {
		// A finished order (and a hostname add/remove through the API)
		// kicks the loop so the push does not wait for the ticker.
		zones.setKick(notify)
	}
	if r.DNSEvents != nil || zones != nil {
		if r.DNSEvents != nil {
			go r.DNSEvents(ctx, notify)
		}
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-trigger:
					reconcile()
					// The event usually precedes the DHCP lease; settle passes
					// pick up the IP. The reconciler skips unchanged zones, so
					// extra passes are cheap.
					for _, settle := range []time.Duration{3 * time.Second, 8 * time.Second} {
						select {
						case <-ctx.Done():
							return
						case <-time.After(settle):
						}
						select {
						case <-trigger: // coalesce triggers that arrived meanwhile
						default:
						}
						reconcile()
					}
				}
			}
		}()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	reconcile()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

// runRouteReconcileLoop keeps Public Routes in line with live Machine state
// (Spec #111), mirroring runDNSReconcileLoop: instance lifecycle events trigger a
// reconcile within seconds (with settle passes for the DHCP lease after a
// recreate), and a periodic pass guarantees convergence across missed events and
// restarts. Prunes routes whose Machine is gone and refreshes proxy-device
// connect on IP change; never prunes on a transient Incus failure.
func (r HTTPRunner) runRouteReconcileLoop(ctx context.Context, db *sql.DB, logger *svclog.Logger, authHostname string) {
	const interval = 5 * time.Minute
	manager := RouteManager{
		DB:      db,
		Backend: r.Routes,
		Caddy:   r.RouteCaddy,
		Render:  RouteRenderConfig(authHostname, r.AuthIngressMode, r.RouteBaseDomain, r.ACMEEmail, r.RouteTLS, r.RouteDNSProvider, r.RouteDNSWildcards),
		Logf: func(format string, args ...any) {
			logger.Message(ctx, "ERROR", "auth-app route: "+format, args...)
		},
	}
	// Write the coexistence Caddyfile once at startup so the global block, the
	// Auth Hostname site, and any existing route sites are correct before the
	// first publish (routes may run beside a Cloudflare-tunnelled login host).
	if err := manager.SyncCaddy(ctx); err != nil {
		logger.Message(ctx, "ERROR", "auth-app route caddy sync: %v", err)
	}
	reconcile := func() {
		pruned, err := manager.Reconcile(ctx)
		if err != nil {
			logger.Message(ctx, "ERROR", "auth-app route reconcile: %v", err)
			return
		}
		if pruned > 0 {
			logger.Message(ctx, "INFO", "auth-app route reconcile: pruned %d route(s) for absent machines", pruned)
		}
	}
	if r.RouteEvents != nil {
		trigger := make(chan struct{}, 1)
		go r.RouteEvents(ctx, func() {
			select {
			case trigger <- struct{}{}:
			default:
			}
		})
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-trigger:
					reconcile()
					for _, settle := range []time.Duration{3 * time.Second, 8 * time.Second} {
						select {
						case <-ctx.Done():
							return
						case <-time.After(settle):
						}
						select {
						case <-trigger:
						default:
						}
						reconcile()
					}
				}
			}
		}()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	reconcile()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

// injectServeDependencies patches the runtime dependencies only Serve can supply
// into the concrete Provisioner: the auth database (which enables DNS-suffix
// claiming, ADR-0020) and the default Unix user (when the caller left it blank).
// A non-Provisioner value (e.g. a test fake) is returned unchanged.
func injectServeDependencies(provisioner PersonalTenantProvisioner, db *sql.DB, defaultUnixUser string) PersonalTenantProvisioner {
	typed, ok := provisioner.(Provisioner)
	if !ok {
		return provisioner
	}
	typed.DB = db
	if strings.TrimSpace(typed.DefaultUnixUser) == "" {
		typed.DefaultUnixUser = defaultUnixUser
	}
	return typed
}

func OpenDatabase(path string) (*sql.DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("auth database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create auth database directory: %w", err)
	}
	// Pragmas go in the DSN so they apply to EVERY pooled connection, not just
	// the one an Exec happens to run on. WAL + busy_timeout let concurrent
	// writers (device poll, svclog sink, reconcilers) wait instead of failing
	// with SQLITE_BUSY.
	db, err := sql.Open("sqlite", path+
		"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("open auth database: %w", err)
	}
	return db, nil
}

func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("auth database is required")
	}
	if _, err := db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS auth_app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    user_key TEXT PRIMARY KEY,
    github_username TEXT NOT NULL,
    github_username_normalized TEXT NOT NULL UNIQUE,
    github_account_id TEXT NOT NULL DEFAULT '',
    github_email TEXT NOT NULL DEFAULT '',
    ssh_public_key TEXT NOT NULL DEFAULT '',
    ssh_key_fingerprint TEXT NOT NULL DEFAULT '',
    allowlisted INTEGER NOT NULL DEFAULT 0,
    sandcastle_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS web_sessions (
    id TEXT PRIMARY KEY,
    user_key TEXT NOT NULL REFERENCES users(user_key) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cli_tokens (
    id TEXT PRIMARY KEY,
    user_key TEXT NOT NULL REFERENCES users(user_key) ON DELETE CASCADE,
    token_verifier TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_logins (
    device_code TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    user_key TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    provisioned_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_at TEXT NOT NULL DEFAULT '',
    dns_suffix TEXT NOT NULL DEFAULT '',
    initial_project TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS oidc_signing_keys (
    kid TEXT PRIMARY KEY,
    tenant TEXT NOT NULL DEFAULT '',
    alg TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    retired_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS machine_runtime_secrets (
    tenant TEXT NOT NULL,
    project TEXT NOT NULL,
    machine TEXT NOT NULL,
    user_key TEXT NOT NULL,
    github_username TEXT NOT NULL DEFAULT '',
    secret_verifier TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    rotated_at TEXT NOT NULL,
    PRIMARY KEY (tenant, project, machine)
);
CREATE TABLE IF NOT EXISTS cloud_identity_configs (
    id TEXT PRIMARY KEY,
    user_key TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    gcp_audience TEXT NOT NULL DEFAULT '',
    gcp_subject_token_type TEXT NOT NULL DEFAULT '',
    gcp_service_account_impersonation_url TEXT NOT NULL DEFAULT '',
    deleted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_key, tenant, name)
);
CREATE TABLE IF NOT EXISTS logs (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    level TEXT NOT NULL,
    kind TEXT NOT NULL,
    service TEXT NOT NULL,
    event TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    user_key TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS dns_suffix_claims (
    suffix TEXT PRIMARY KEY,
    tenant TEXT NOT NULL UNIQUE,
    user_key TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS routes (
    hostname TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    project TEXT NOT NULL,
    machine TEXT NOT NULL,
    backend_port INTEGER NOT NULL,
    local_port INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS machine_tunnel_publications (
    hostname TEXT PRIMARY KEY,
    tenant TEXT NOT NULL,
    project TEXT NOT NULL,
    machine TEXT NOT NULL,
    port INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS machine_publication_cooldowns (
    hostname TEXT PRIMARY KEY,
    released_at TEXT NOT NULL
);
-- ── Public DNS Zones (ADR-0027, spec §1.3) — slice 2: zone registry ─────────
CREATE TABLE IF NOT EXISTS public_dns_zones (
    zone               TEXT PRIMARY KEY,          -- normalized (lowercase, no trailing dot)
    cloudflare_zone    TEXT NOT NULL DEFAULT '',  -- the Cloudflare zone containing it, resolved at add time ('' = zone itself)
    cloudflare_zone_id TEXT NOT NULL,             -- resolved at add time
    encrypted_token    TEXT NOT NULL,             -- AES-GCM under the public_dns_zone_key deployment key (secrets.go)
    created_by         TEXT NOT NULL DEFAULT '',  -- admin user key
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
-- ── end Public DNS Zones slice 2 ───────────────────────────────────────────
-- ── Public DNS Zones (ADR-0027, spec §1.3) — slice 3: Project Domain claims ──
CREATE TABLE IF NOT EXISTS project_domain_claims (
    domain     TEXT PRIMARY KEY,                  -- normalized Project Domain
    tenant     TEXT NOT NULL,
    project    TEXT NOT NULL,                     -- short project name
    zone       TEXT NOT NULL REFERENCES public_dns_zones(zone),
    user_key   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (tenant, project)                      -- one domain per project
);
-- ── end Public DNS Zones slice 3 ───────────────────────────────────────────
CREATE INDEX IF NOT EXISTS logs_user_ts ON logs(user_key, ts);
CREATE INDEX IF NOT EXISTS logs_ts ON logs(ts);
INSERT INTO auth_app_meta (key, value, updated_at)
VALUES ('schema_version', '1', datetime('now'))
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
`); err != nil {
		return fmt.Errorf("migrate auth database: %w", err)
	}
	if err := ensureColumn(ctx, db, "device_logins", "provisioned_at", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// Browser-chosen Tenant DNS Suffix (ADR-0020 interactive suffix form). Stored
	// at approval; the CLI --dns-suffix flag overrides it at poll time when present.
	if err := ensureColumn(ctx, db, "device_logins", "dns_suffix", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// Browser-chosen initial-project short name (issue #93). Stored at approval;
	// the CLI --default-project flag overrides it at poll time when present.
	if err := ensureColumn(ctx, db, "device_logins", "initial_project", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, db, "users", "ssh_public_key", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, db, "users", "ssh_key_fingerprint", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// The client's shared-identity Incus certificate, recorded at device login
	// so the tenant plane (POST /api/projects) can extend the caller's trust
	// entry by fingerprint when it is named after another tenant's enrollment.
	if err := ensureColumn(ctx, db, "users", "client_certificate_pem", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, db, "oidc_signing_keys", "tenant", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, db, "cloud_identity_configs", "tenant", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := migrateCloudIdentityConfigsTenantScope(ctx, db); err != nil {
		return err
	}
	// Public DNS Zones: a zone may live inside its Cloudflare zone; databases
	// from before the column carry '' and are read as "the zone itself".
	if err := ensureColumn(ctx, db, "public_dns_zones", "cloudflare_zone", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// Public DNS Zones slice 5 (ADR-0027): acme_storage + machine_certificates.
	if err := migrateACME(ctx, db); err != nil {
		return err
	}
	// Machine Public Hostnames (ADR-0028): explicit hostname reservations.
	if err := migrateMachineHostnames(ctx, db); err != nil {
		return err
	}
	return nil
}

func migrateCloudIdentityConfigsTenantScope(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `
SELECT id, gcp_audience
FROM cloud_identity_configs
WHERE tenant = '' AND gcp_audience LIKE '%/workloadIdentityPools/sandcastle-%/providers/%'
`)
	if err != nil {
		return err
	}
	var inferred []struct {
		id     string
		tenant string
	}
	for rows.Next() {
		var id, audience string
		if err := rows.Scan(&id, &audience); err != nil {
			_ = rows.Close()
			return err
		}
		if tenant := inferTenantFromGCPAudience(audience); tenant != "" {
			inferred = append(inferred, struct {
				id     string
				tenant string
			}{id: id, tenant: tenant})
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range inferred {
		if _, err := db.ExecContext(ctx, "UPDATE cloud_identity_configs SET tenant = ? WHERE id = ?", item.tenant, item.id); err != nil {
			return err
		}
	}

	var createSQL string
	err = db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'cloud_identity_configs'").Scan(&createSQL)
	if err != nil {
		return err
	}
	if strings.Contains(createSQL, "UNIQUE(user_key, tenant, name)") {
		return nil
	}
	if _, err := db.ExecContext(ctx, `
CREATE TABLE cloud_identity_configs_new (
    id TEXT PRIMARY KEY,
    user_key TEXT NOT NULL,
    tenant TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    gcp_audience TEXT NOT NULL DEFAULT '',
    gcp_subject_token_type TEXT NOT NULL DEFAULT '',
    gcp_service_account_impersonation_url TEXT NOT NULL DEFAULT '',
    deleted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_key, tenant, name)
);
INSERT INTO cloud_identity_configs_new (
    id, user_key, tenant, name, provider, gcp_audience, gcp_subject_token_type,
    gcp_service_account_impersonation_url, deleted, created_at, updated_at
)
SELECT id, user_key, tenant, name, provider, gcp_audience, gcp_subject_token_type,
    gcp_service_account_impersonation_url, deleted, created_at, updated_at
FROM cloud_identity_configs;
DROP TABLE cloud_identity_configs;
ALTER TABLE cloud_identity_configs_new RENAME TO cloud_identity_configs;
`); err != nil {
		return fmt.Errorf("migrate cloud identity configs tenant scope: %w", err)
	}
	return nil
}

func inferTenantFromGCPAudience(audience string) string {
	const marker = "/workloadIdentityPools/sandcastle-"
	index := strings.Index(audience, marker)
	if index < 0 {
		return ""
	}
	rest := audience[index+len(marker):]
	tenant, _, ok := strings.Cut(rest, "/providers/")
	if !ok {
		return ""
	}
	return strings.TrimSpace(tenant)
}

func ensureColumn(ctx context.Context, db *sql.DB, table string, column string, definition string) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+definition); err != nil {
		return fmt.Errorf("add %s.%s column: %w", table, column, err)
	}
	return nil
}

type HandlerOptions struct {
	AuthHostname       string
	GitHubClientID     string
	GitHubClientSecret string
	GitHub             GitHubClient
	RestrictedUsers    RestrictedUserRevoker
	Provisioner        PersonalTenantProvisioner
	Admin              config.Admin
	Tenants            tenant.IncusTenantStore
	TenantAccess       TenantAccessManager
	Machines           machine.Store
	MachineSSHKeys     MachineSSHKeyReconciler
	TenantSSHKeys      TenantSSHKeyUpdater
	MachineSSHAccess   MachineSSHAccessRevoker
	ShareStore         share.Store
	ShareReconciler    ShareReconciler
	TenantMembers      TenantMembershipManager
	SidecarAddresses   SidecarAddressReader
	// Projects performs the privileged project scaffolding for the token-gated
	// POST /api/projects — the tunnel-friendly tenant plane (no broker port).
	Projects            TenantProjectCreator
	DebugDeviceUser     string
	SimulateGitHubToken string
	TailscaleAuthKey    string
	Routes              RouteBackend
	RouteCaddy          CaddyController
	ACMEEmail           string
	// ACMEDirectory is the running --acme-directory (normalized); it is the
	// directory_url stamped on machine_certificates rows.
	ACMEDirectory         string
	ProjectDomainResolver ProjectDomainResolver
	AuthIngressMode       string
	RouteBaseDomain       string
	RouteIngress          string
	RouteCNAMETarget      string
	RouteTLS              string
	RouteDNSProvider      string
	RouteDNSWildcards     []string
	// RouteResolveHost overrides how a custom hostname's DNS is checked for the
	// awaiting-dns status. Optional; nil uses a real DNS lookup. Injected in tests.
	RouteResolveHost func(ctx context.Context, host string) bool
	// Version is the running binary's release version (vX.Y.Z or the dev
	// sentinel); sent on every response as the version exchange (#124 §6) and
	// shown on the admin version card.
	Version string
	// Sidecars serves the token-authenticated tenant sidecar update (#124 §5)
	// — the tunnel-friendly twin of the broker's /v2/sidecar/update.
	Sidecars projectbroker.SidecarUpdater
	// ReleaseResolver overrides the version card's GitHub lookup. Injected in
	// tests; nil uses the daily-cached releases/latest check.
	ReleaseResolver func(ctx context.Context) (update.Release, error)
	// ResourceCache backs GET /api/resources (t2 of the event-bus-cache wish).
	// nil means the cache never started (toggle off, or not ready yet at
	// construction time) — the endpoint always answers 503 so `sc ls` falls
	// back to its live per-project path.
	ResourceCache *ResourceCache
	// ResourceCacheMachineRenderer converts a cached instance into a
	// meta.Machine; required whenever ResourceCache is set.
	ResourceCacheMachineRenderer ResourceCacheMachineRenderer
	// CloudflareZones validates a Public DNS Zone token at add/set-token
	// (ADR-0027). nil uses the real Cloudflare API; tests inject a fake.
	CloudflareZones CloudflareZoneValidator
	// ProjectDomainClaims answers which Project Domains are claimed under a
	// zone (the remove refusal, the list CLAIMS column). nil uses the
	// project_domain_claims table; tests inject a fake.
	ProjectDomainClaims ProjectDomainClaimSource
	// ProjectDomains is the Incus seam for Project Domains (ADR-0027): it
	// stamps KeyV2Domain + re-renders the profile, creates a project with a
	// domain, deletes a project and rewrites a machine's public-name list.
	// nil means the domain verbs answer 501 ("not available on this
	// deployment").
	ProjectDomains TenantProjectDomainManager
	// ZoneReconcileKick, when set, asks the zone reconciler for a pass soon;
	// the hostname and domain endpoints call it after a change so records,
	// orders and the hostnames-file push do not wait for the 30 s ticker.
	ZoneReconcileKick func()
	// TailnetPublisher installs the opt-in per-Machine HTTPS site on the
	// Tenant Sidecar. Its certificate issuer remains in the Auth App.
	TailnetPublisher TailnetPublisher
	TailnetIssuer    certIssuer
	// CloudflareBaseURL is a test seam; production uses Cloudflare's API.
	CloudflareBaseURL string
}

// TenantProjectCreator creates an app project for a tenant and extends the
// tenant's restricted certificate; satisfied by incusx.ProjectBrokerCreator.
// clientCertificatePEM is the tenant's recorded shared-identity certificate
// ("" when none): with shared client identity the trust entry can be named
// after another tenant's enrollment, and the certificate fingerprint is how
// the extension still finds it.
type TenantProjectCreator interface {
	CreateTenantProject(ctx context.Context, tenant string, project string, clientCertificatePEM string) (projectbroker.ProjectResult, error)
}

func NewHandler(db *sql.DB, options any) http.Handler {
	mux := http.NewServeMux()
	handlerOptions := normalizeHandlerOptions(options)
	app := handler{
		db:                    db,
		authHostname:          strings.Trim(strings.TrimSpace(handlerOptions.AuthHostname), "."),
		githubClient:          handlerOptions.GitHub,
		githubOAuth:           GitHubOAuth{ClientID: handlerOptions.GitHubClientID, ClientSecret: handlerOptions.GitHubClientSecret},
		restricted:            handlerOptions.RestrictedUsers,
		provisioner:           handlerOptions.Provisioner,
		admin:                 handlerOptions.Admin,
		tenants:               handlerOptions.Tenants,
		tenantAccess:          handlerOptions.TenantAccess,
		machines:              handlerOptions.Machines,
		machineSSHKeys:        handlerOptions.MachineSSHKeys,
		tenantSSHKeys:         handlerOptions.TenantSSHKeys,
		machineSSHAccess:      handlerOptions.MachineSSHAccess,
		shareStore:            handlerOptions.ShareStore,
		shareReconciler:       handlerOptions.ShareReconciler,
		tenantMembers:         handlerOptions.TenantMembers,
		sidecarAddresses:      handlerOptions.SidecarAddresses,
		projects:              handlerOptions.Projects,
		debugDeviceUser:       NormalizeGitHubUsername(handlerOptions.DebugDeviceUser),
		simulateToken:         strings.TrimSpace(handlerOptions.SimulateGitHubToken),
		tailscaleAuthKey:      strings.TrimSpace(handlerOptions.TailscaleAuthKey),
		sessionCookie:         "sandcastle_session",
		routes:                handlerOptions.Routes,
		routeCaddy:            handlerOptions.RouteCaddy,
		acmeEmail:             strings.TrimSpace(handlerOptions.ACMEEmail),
		acmeDirectory:         handlerACMEDirectory(handlerOptions.ACMEDirectory),
		projectDomainResolver: handlerOptions.ProjectDomainResolver,
		authIngressMode:       strings.TrimSpace(handlerOptions.AuthIngressMode),
		routeBaseDomain:       strings.Trim(strings.TrimSpace(handlerOptions.RouteBaseDomain), "."),
		routeIngress:          strings.TrimSpace(handlerOptions.RouteIngress),
		routeCNAME:            strings.Trim(strings.TrimSpace(handlerOptions.RouteCNAMETarget), "."),
		routeTLS:              strings.TrimSpace(handlerOptions.RouteTLS),
		routeDNSProvider:      strings.TrimSpace(handlerOptions.RouteDNSProvider),
		routeDNSWildcards:     normalizeRouteDNSWildcards(handlerOptions.RouteDNSWildcards),
		routeResolveHost:      handlerOptions.RouteResolveHost,
		version:               strings.TrimSpace(handlerOptions.Version),
		sidecars:              handlerOptions.Sidecars,
		releases:              &releaseCache{resolve: handlerOptions.ReleaseResolver},
		resourceCache:         handlerOptions.ResourceCache,
		resourceCacheRenderer: handlerOptions.ResourceCacheMachineRenderer,
		cloudflareZones:       handlerOptions.CloudflareZones,
		projectDomainClaims:   handlerOptions.ProjectDomainClaims,
		projectDomains:        handlerOptions.ProjectDomains,
		zoneReconcileKick:     handlerOptions.ZoneReconcileKick,
		tailnetPublisher:      handlerOptions.TailnetPublisher,
		tailnetIssuer:         handlerOptions.TailnetIssuer,
		cloudflareBaseURL:     handlerOptions.CloudflareBaseURL,
	}
	if app.projectDomainResolver == nil && app.db != nil {
		// Slice 3 landed the claims table: it is the production resolver.
		app.projectDomainResolver = sqlProjectDomainClaims{db: app.db}
	}
	if app.githubClient == nil {
		if app.simulateToken != "" {
			// No real GitHub OAuth app: fabricate profiles offline.
			app.githubClient = SimulatedGitHubClient{}
		} else {
			app.githubClient = HTTPGitHubClient{}
		}
	}
	mux.HandleFunc("/", app.status)
	mux.HandleFunc("/healthz", app.health)
	mux.HandleFunc("/style.css", app.styleCSS)
	mux.HandleFunc("/machines", app.machinesWeb)
	mux.HandleFunc("/login/github", app.githubLogin)
	mux.HandleFunc("/oauth/github/callback", app.githubCallback)
	mux.HandleFunc("/admin/allowlist", app.adminAllowlist)
	mux.HandleFunc("/admin/allowlist/remove", app.adminAllowlistRemove)
	mux.HandleFunc("/admin/access", app.adminTenantAccess)
	mux.HandleFunc("/admin/access/grant", app.adminTenantAccessGrant)
	mux.HandleFunc("/admin/access/revoke", app.adminTenantAccessRevoke)
	mux.HandleFunc("/cloud-identities", app.cloudIdentities)
	mux.HandleFunc("/cloud-identities/delete", app.cloudIdentityDelete)
	mux.HandleFunc("/logs", app.logsWeb)
	mux.HandleFunc("/api/cloud-identities", app.cloudIdentitiesAPI)
	mux.HandleFunc("/api/tenants", app.tenantsAPI)
	mux.HandleFunc("/api/projects", app.projectsAPI)
	mux.HandleFunc("/api/projects/", app.projectAPI)
	mux.HandleFunc("/api/machines/", app.machinesAPI)
	mux.HandleFunc("/api/resources", app.resourcesAPI)
	// Tenant Storage Shares are not yet supported on v2 (#70): the registry lives
	// in a user-writable /workspace file a tenant can forge, so every share
	// endpoint is gated off. The handlers (app.sharesAPI, app.shareAcceptAPI, …)
	// and their plumbing stay intact, dormant behind this gate, ready for when the
	// registry moves off the user-writable volume — flip these back then.
	for _, path := range []string{
		"/api/shares", "/api/shares/status", "/api/shares/accept", "/api/shares/decline",
		"/api/shares/revoke", "/api/shares/delete", "/api/shares/reconcile",
	} {
		mux.HandleFunc(path, sharesUnsupportedHandler)
	}
	mux.HandleFunc("/api/sidecar/update", app.sidecarUpdateAPI)
	mux.HandleFunc("/api/device/start", app.deviceStart)
	mux.HandleFunc("/api/device/poll", app.devicePoll)
	mux.HandleFunc("/api/workload/enable", app.workloadEnable)
	mux.HandleFunc("/api/routes", app.routesAPI)
	mux.HandleFunc("/api/machine-tunnels", app.machineTunnelsAPI)
	mux.HandleFunc("/api/tailnet-publications", app.tailnetPublicationsAPI)
	mux.HandleFunc("/api/machine-certificates", app.machineCertificatesAPI)
	mux.HandleFunc("/api/routes/ask", app.routesAsk)
	mux.HandleFunc("/api/routes/config", app.routesConfig)
	mux.HandleFunc("/api/public-dns-zones", app.publicDNSZonesAPI)
	mux.HandleFunc("/api/public-dns-zones/", app.publicDNSZoneAPI)
	mux.HandleFunc("/device", app.deviceApprove)
	if app.debugDeviceUser != "" {
		mux.HandleFunc("/debug/device/approve", app.debugDeviceApprove)
	}
	if app.simulateToken != "" {
		mux.HandleFunc("/oauth/github/simulate", app.simulateLogin)
		log.Printf("auth-app WARNING: simulated GitHub mode ENABLED — /oauth/github/simulate accepts a shared token and auto-allowlists any user; DO NOT run this in production")
	}
	mux.HandleFunc("/.well-known/openid-configuration", app.oidcDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", app.oidcJWKS)
	mux.HandleFunc("/t/", app.tenantOIDC)
	mux.HandleFunc("/internal/workload/token", app.workloadToken)
	return withVersionExchange(mux, app.version)
}

// withVersionExchange stamps every response with the appliance version
// (#124 §6) and, when a breaking release sets update.MinCLIVersion, refuses
// too-old CLIs on the API surface with a clean 426 instead of protocol
// errors. Browser paths are never refused.
func withVersionExchange(next http.Handler, serverVersion string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		update.ApplyVersionHeaders(w.Header(), serverVersion, update.MinCLIVersion)
		if strings.HasPrefix(r.URL.Path, "/api/") &&
			update.RefuseCLI(r.Header.Get(update.HeaderCLIVersion), update.MinCLIVersion) {
			http.Error(w, update.RefusalMessage(update.MinCLIVersion), http.StatusUpgradeRequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeHandlerOptions(value any) HandlerOptions {
	switch typed := value.(type) {
	case HandlerOptions:
		return typed
	case string:
		return HandlerOptions{AuthHostname: typed}
	default:
		return HandlerOptions{}
	}
}

type handler struct {
	db                    *sql.DB
	authHostname          string
	githubClient          GitHubClient
	githubOAuth           GitHubOAuth
	restricted            RestrictedUserRevoker
	provisioner           PersonalTenantProvisioner
	admin                 config.Admin
	tenants               tenant.IncusTenantStore
	tenantAccess          TenantAccessManager
	machines              machine.Store
	machineSSHKeys        MachineSSHKeyReconciler
	tenantSSHKeys         TenantSSHKeyUpdater
	machineSSHAccess      MachineSSHAccessRevoker
	shareStore            share.Store
	shareReconciler       ShareReconciler
	tenantMembers         TenantMembershipManager
	sidecarAddresses      SidecarAddressReader
	projects              TenantProjectCreator
	debugDeviceUser       string
	simulateToken         string
	tailscaleAuthKey      string
	sessionCookie         string
	routes                RouteBackend
	routeCaddy            CaddyController
	acmeEmail             string
	acmeDirectory         string
	projectDomainResolver ProjectDomainResolver
	authIngressMode       string
	routeBaseDomain       string
	routeIngress          string
	routeCNAME            string
	routeTLS              string
	routeDNSProvider      string
	routeDNSWildcards     []string
	routeResolveHost      func(ctx context.Context, host string) bool
	version               string
	sidecars              projectbroker.SidecarUpdater
	releases              *releaseCache
	resourceCache         *ResourceCache
	resourceCacheRenderer ResourceCacheMachineRenderer
	cloudflareZones       CloudflareZoneValidator
	projectDomainClaims   ProjectDomainClaimSource
	projectDomains        TenantProjectDomainManager
	zoneReconcileKick     func()
	tailnetPublisher      TailnetPublisher
	tailnetIssuer         certIssuer
	cloudflareBaseURL     string
}

// kickZoneReconcile asks the zone reconciler for a pass soon (no-op when
// the handler runs without one).
func (h handler) kickZoneReconcile() {
	if h.zoneReconcileKick != nil {
		h.zoneReconcileKick()
	}
}

// projectsAPI is the tunnel-friendly tenant plane for project creation
// (ADR-0016 amended): POST /api/projects {"project": "..."} authenticated by
// the CLI Auth Token. It replaces the broker's host port in tunnel-fronted
// installs — the auth-app performs the same scaffolding + cert extension.
func (h handler) projectsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.projects == nil {
		http.Error(w, "project creation is not available on this deployment", http.StatusNotImplemented)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	var request ProjectCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	project := strings.TrimSpace(request.Project)
	if err := naming.ValidateNewProjectName(project); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Domain) != "" || request.DryRun {
		// The Project Domain path (ADR-0027 §3.2): claim first, then create
		// with KeyV2Domain in the same Incus request; JSON error bodies so the
		// CLI prints the verbatim refusal.
		h.projectCreateWithDomain(w, r, user, project, request)
		return
	}
	tenantName, err := h.requestTenant(r, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	clientCertificatePEM, _ := GetUserClientCertificate(r.Context(), h.db, user.UserKey)
	var result projectbroker.ProjectResult
	err = svclog.Span(r.Context(), "project.create", func() error {
		var createErr error
		result, createErr = h.projects.CreateTenantProject(r.Context(), tenantName, project, clientCertificatePEM)
		return createErr
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// A Shared Tenant's other members must reach the new project too: extend
	// their certificates by their recorded client identity (best effort — a
	// member who never recorded one is covered on their next login).
	h.extendMemberCertificates(r, tenantName, user.UserKey, result.IncusProject)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// sidecarUpdateAPI is the token-authenticated tenant sidecar update (#124
// §5): POST /api/sidecar/update, authenticated by the CLI Auth Token. The
// caller's own sidecar is updated to the auth-app's running binary — the
// tunnel-friendly twin of the broker's mTLS /v2/sidecar/update.
func (h handler) sidecarUpdateAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.sidecars == nil {
		http.Error(w, "sidecar updates are not available on this deployment", http.StatusNotImplemented)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	tenantName, err := h.requestTenant(r, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	var result projectbroker.SidecarUpdateResult
	err = svclog.Span(r.Context(), "sidecar.update", func() error {
		var updateErr error
		result, updateErr = h.sidecars.UpdateTenantSidecar(tenantName)
		return updateErr
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (h handler) health(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/healthz" {
		http.NotFound(w, r)
		return
	}
	if err := h.db.PingContext(r.Context()); err != nil {
		http.Error(w, "auth database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (h handler) status(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if err := h.db.PingContext(r.Context()); err != nil {
		http.Error(w, "auth database unavailable", http.StatusServiceUnavailable)
		return
	}
	if cookie, err := r.Cookie(h.sessionCookie); err == nil {
		if user, err := UserForSession(r.Context(), h.db, cookie.Value, timeNow()); err == nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			routesEnabled := false
			if _, ok := h.routeManager(); ok {
				routesEnabled = true
			}
			_ = onboardingTemplate.Execute(w, onboardingPage{
				User:             user,
				AuthHostname:     h.authHostname,
				LoginCommand:     cliLoginCommand(h.authHostname),
				VersionCard:      h.releases.card(h.version),
				RoutesEnabled:    routesEnabled,
				RouteBaseDomain:  h.routeBase(),
				RouteCNAMETarget: h.routeCNAMETarget(),
			})
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = statusTemplate.Execute(w, struct {
		AuthHostname string
		VersionCard  versionCard
	}{AuthHostname: h.authHostname, VersionCard: h.releases.card(h.version)})
}

type onboardingPage struct {
	User         User
	AuthHostname string
	LoginCommand string
	VersionCard  versionCard
	// Public Routes (Spec #111): shown only where the install has route ingress,
	// so the page never promises a feature this deployment cannot serve. These
	// are the two facts a Tenant cannot derive on their own — where auto
	// subdomains live, and what a custom hostname must be CNAME'd onto.
	RoutesEnabled    bool
	RouteBaseDomain  string
	RouteCNAMETarget string
}

func cliLoginCommand(authHostname string) string {
	host := strings.TrimSpace(authHostname)
	if host == "" {
		return "sandcastle login <auth-host>"
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return "sandcastle login " + strings.TrimRight(host, "/")
	}
	return "sandcastle login https://" + strings.Trim(host, ".")
}

// versionCardHTML is the always-visible version card (#124 §8), shared by
// the status and onboarding pages. Green when current; amber with the
// update command and release-notes link when behind.
const versionCardHTML = `    <section>
      <h2>Version</h2>
      <p>auth-app {{.VersionCard.Version}}{{if .VersionCard.Latest}} &middot; latest {{.VersionCard.Latest}}{{end}}</p>
      {{if .VersionCard.Outdated}}
        <p style="color:#b45309">Update available &mdash; run <code>sc-adm update</code>.{{if .VersionCard.ReleaseURL}} <a href="{{.VersionCard.ReleaseURL}}">Release notes</a>{{end}}</p>
      {{else if .VersionCard.Latest}}
        <p style="color:#15803d">Up to date.</p>
      {{end}}
    </section>
`

var statusTemplate = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <link rel="stylesheet" href="/style.css">
  <title>Sandcastle Auth</title>
</head>
<body>
  <main>
    <h1>Sandcastle Auth</h1>
    <p>Status: ok</p>
    {{if .AuthHostname}}<p>Auth Hostname: {{.AuthHostname}}</p>{{end}}
    <p><a href="/login/github">Sign in with GitHub</a></p>
` + versionCardHTML + `  </main>
</body>
</html>
`))

var onboardingTemplate = template.Must(template.New("onboarding").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <link rel="stylesheet" href="/style.css">
  <title>Sandcastle Onboarding</title>
</head>
<body>
  <main>
    <h1>Sandcastle Onboarding</h1>
` + versionCardHTML + `    <section>
      <p><a href="/machines">View your machines</a></p>
      <p><a href="/logs">Activity log</a></p>
    </section>
    {{if .User.SandcastleAdmin}}
      <section>
        <h2>Sandcastle Admin</h2>
        <p><a href="/admin/allowlist">Login Allowlist</a> &mdash; add or remove GitHub users who may sign in.</p>
        <p><a href="/admin/access">Tenant Access</a> &mdash; grant or revoke Tenant access per user.</p>
      </section>
    {{end}}
    <section>
      <h2>GitHub identity</h2>
      <p>GitHub Username: {{.User.GitHubUsername}}</p>
      <p>Sandcastle User Key: {{.User.UserKey}}</p>
      {{if .User.GitHubEmail}}<p>GitHub Email: {{.User.GitHubEmail}}</p>{{end}}
    </section>
    <section>
      <h2>Allowlist status</h2>
      {{if .User.Allowlisted}}
        <p>Status: allowlisted</p>
      {{else}}
        <p>Status: not allowlisted</p>
        <p>Ask a Sandcastle Admin to add your GitHub Username to the Login Allowlist before running CLI Device Login.</p>
      {{end}}
    </section>
    {{if .User.Allowlisted}}
      <section>
        <h2>Install the CLI</h2>
        <p>Install the Sandcastle CLI for your platform, then run the login command from a terminal.</p>
        <pre><code>mise run build
mise run build:linux-amd64</code></pre>
      </section>
      <section>
        <h2>Login command</h2>
        <pre><code>{{.LoginCommand}}</code></pre>
      </section>
      {{if .RoutesEnabled}}
      <section>
        <h2>Publish a public route</h2>
        <p>Expose a port of one of your machines to the public Internet. The certificate is issued on the first HTTPS request.</p>
        <pre><code>sc route                       # what this install offers, and the DNS you need
sc route publish &lt;machine&gt; --port 3000
sc route list</code></pre>
        {{if .RouteBaseDomain}}<p>Automatic hostnames: <code>&lt;name&gt;.&lt;your-tenant&gt;.{{.RouteBaseDomain}}</code> (<code>--name</code> defaults to the machine name).</p>{{end}}
        {{if .RouteCNAMETarget}}
          <p>Your own hostname: publish with <code>--hostname app.example.com</code> and add the DNS record <code>CNAME app.example.com &rarr; {{.RouteCNAMETarget}}</code>.</p>
        {{else}}
          <p>Your own hostname: publish with <code>--hostname app.example.com</code> and ask a Sandcastle Admin which front door to CNAME it onto.</p>
        {{end}}
      </section>
      {{end}}
    {{end}}
  </main>
</body>
</html>
`))
