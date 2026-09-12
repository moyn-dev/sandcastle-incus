package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/domain"
)

// The project_domain_claims table is the install-wide reservation registry
// for Project Domains (ADR-0027, spec public-dns-zones §1.3/§3.3). A row is
// the reservation; `user.sandcastle.v2.domain` on the app project is the
// operational setting the CLI and the reconciler read. The Auth App writes
// both in one request, DB first, so a claim can never exist on Incus without
// having passed the conflict scan here. Uniqueness is enforced two ways: the
// scan inside a BEGIN IMMEDIATE transaction (which serializes claimers on
// SQLite's write lock) and the `domain` PRIMARY KEY as the last line of
// defence. `UNIQUE (tenant, project)` gives one domain per project.
//
// This is the dns_suffix_claims precedent (ADR-0020) with a richer conflict
// vocabulary: a Project Domain conflicts not only with an identical claim but
// with any claim above or below it, with every Public Route hostname it would
// cover, and with the install's own names.

// ProjectDomainClaim is one row of project_domain_claims.
type ProjectDomainClaim struct {
	Domain    string `json:"domain"`
	Tenant    string `json:"tenant"`
	Project   string `json:"project"`
	Zone      string `json:"zone"`
	UserKey   string `json:"userKey,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
}

// Ref converts a claim to the registry's lighter reference type.
func (c ProjectDomainClaim) Ref() ProjectDomainClaimRef {
	return ProjectDomainClaimRef{Domain: c.Domain, Tenant: c.Tenant, Project: c.Project}
}

// Conflict classes (spec §3.3). Every class blocks regardless of tenant; the
// class only shapes the message.
const (
	DomainClaimConflictExact      = "exact"
	DomainClaimConflictAncestor   = "ancestor"   // the candidate would cover an existing claim
	DomainClaimConflictDescendant = "descendant" // the candidate sits inside an existing claim
	DomainClaimConflictRoute      = "route"      // covers/equals a Public Route hostname
	DomainClaimConflictInstall    = "install"    // covers/equals the Auth Hostname or route base domain
)

// DomainClaimError explains why a claim was refused by a conflict. It mirrors
// SuffixClaimError: handlers map it to 409 and print Error() verbatim. Only the
// same-tenant text names the existing claim — cross-tenant refusals never
// reveal who holds the overlapping domain.
type DomainClaimError struct {
	Domain     string
	Existing   string
	Project    string
	Class      string
	SameTenant bool
}

func (e *DomainClaimError) Error() string {
	switch {
	case e.Class == DomainClaimConflictInstall || e.Class == DomainClaimConflictRoute:
		return fmt.Sprintf("project domain %q is reserved by this install", e.Domain)
	case e.SameTenant:
		return fmt.Sprintf("project domain %q overlaps %q claimed by project %q in this tenant", e.Domain, e.Existing, e.Project)
	default:
		return fmt.Sprintf("project domain %q overlaps a domain already claimed on this install; choose another", e.Domain)
	}
}

// ProjectDomainError is a validation refusal (spec §2.2): the domain is well
// formed but cannot be claimed as given. Handlers map it to 400.
type ProjectDomainError struct {
	Domain string
	// Kind is one of: "no-zone", "apex", "too-long".
	Kind string
	// Zone is the covering zone (apex).
	Zone string
	// Zones is the registered zone list, shown only on the admin roots (no-zone).
	Zones []string
	// AdminView selects the admin wording for no-zone.
	AdminView bool
}

func (e *ProjectDomainError) Error() string {
	switch e.Kind {
	case "no-zone":
		if e.AdminView {
			zones := strings.Join(e.Zones, ", ")
			if zones == "" {
				zones = "(none)"
			}
			return fmt.Sprintf("no Public DNS Zone covers %s; registered zones: %s", e.Domain, zones)
		}
		return fmt.Sprintf("no Public DNS Zone covers %s — ask your admin", e.Domain)
	case "apex":
		return fmt.Sprintf("project domain %q is a zone apex; claim at least one label below %s", e.Domain, e.Zone)
	case "too-long":
		return fmt.Sprintf("project domain %q is too long: \"*.<63-char machine>.<d>\" must fit in 253 characters", e.Domain)
	}
	return fmt.Sprintf("project domain %q: %s", e.Domain, e.Kind)
}

// RouteInsideProjectDomainError is the reverse check of UpsertRoute: a custom
// Public Route hostname may not sit inside a claimed Project Domain.
type RouteInsideProjectDomainError struct {
	Hostname string
	Domain   string
}

func (e *RouteInsideProjectDomainError) Error() string {
	return fmt.Sprintf("route hostname %q is inside project domain %q claimed on this install", e.Hostname, e.Domain)
}

// ErrProjectDomainAlreadyClaimed reports a same-project identical re-claim: a
// no-op the CLI prints as `project domain "<d>" already claimed by this
// project` with exit 0. Wrapped by ProjectDomainAlreadyClaimedError.
type ProjectDomainAlreadyClaimedError struct{ Domain string }

func (e *ProjectDomainAlreadyClaimedError) Error() string {
	return fmt.Sprintf("project domain %q already claimed by this project", e.Domain)
}

// projectDomainMaxLength is the DNS name budget: `*.` + a 63-char machine
// label + `.` + the domain must fit in 253 characters.
const projectDomainMaxLength = 253 - len("*.") - 63 - len(".")

// NormalizeProjectDomain is the shared client/server normalization (§3.3
// step 1): lowercase, trim, one trailing dot, ASCII labels, no `_`/`*` labels.
func NormalizeProjectDomain(value string) (string, error) {
	return domain.NormalizeProjectDomain(value)
}

// ClaimProjectDomainRequest is the input of ClaimProjectDomain.
type ClaimProjectDomainRequest struct {
	Domain  string
	Tenant  string
	Project string
	UserKey string
	// AuthHostname and RouteBaseDomain are the install-reserved names; empty
	// values are skipped.
	AuthHostname    string
	RouteBaseDomain string
	// AdminView selects the admin wording of the no-zone refusal.
	AdminView bool
	// DryRun runs validation and the conflict scan, then rolls back.
	DryRun bool
}

// ClaimProjectDomain reserves req.Domain for req.Tenant/req.Project.
//
// Validation (normalize, zone lookup, apex, length) runs first; then, inside
// one BEGIN IMMEDIATE transaction, the conflict scan and the INSERT. Only after
// COMMIT should the caller touch Incus. A same-project identical re-claim
// returns the existing claim and a *ProjectDomainAlreadyClaimedError (a no-op
// for the caller to report, not a failure). A project that already holds a
// different domain has it replaced in the same transaction (set-domain); the
// previous claim is returned so the caller can restore it if Incus fails.
func ClaimProjectDomain(ctx context.Context, db *sql.DB, req ClaimProjectDomainRequest) (claim ProjectDomainClaim, previous *ProjectDomainClaim, err error) {
	norm, err := NormalizeProjectDomain(req.Domain)
	if err != nil {
		return ProjectDomainClaim{}, nil, err
	}
	tenantName := strings.TrimSpace(req.Tenant)
	project := strings.TrimSpace(req.Project)
	if tenantName == "" || project == "" {
		return ProjectDomainClaim{}, nil, fmt.Errorf("tenant and project are required to claim a project domain")
	}
	zones, err := listPublicDNSZoneNames(ctx, db)
	if err != nil {
		return ProjectDomainClaim{}, nil, err
	}
	zone, err := validateProjectDomain(norm, zones, req.AdminView)
	if err != nil {
		return ProjectDomainClaim{}, nil, err
	}

	// A dedicated connection is the only way database/sql lets us pick the
	// transaction mode: BEGIN IMMEDIATE takes SQLite's write lock up front, so
	// two concurrent claimers scan strictly one after the other.
	conn, err := db.Conn(ctx)
	if err != nil {
		return ProjectDomainClaim{}, nil, fmt.Errorf("claim project domain: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return ProjectDomainClaim{}, nil, fmt.Errorf("claim project domain: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		}
	}()

	existing, err := listProjectDomainClaims(ctx, conn)
	if err != nil {
		return ProjectDomainClaim{}, nil, err
	}
	routeHostnames, err := listRouteHostnames(ctx, conn)
	if err != nil {
		return ProjectDomainClaim{}, nil, err
	}
	for _, c := range existing {
		if c.Tenant == tenantName && c.Project == project {
			prev := c
			previous = &prev
			break
		}
	}
	if previous != nil && previous.Domain == norm {
		return *previous, previous, &ProjectDomainAlreadyClaimedError{Domain: norm}
	}
	if err := scanProjectDomainConflicts(norm, tenantName, project, existing, routeHostnames, req.AuthHostname, req.RouteBaseDomain); err != nil {
		return ProjectDomainClaim{}, nil, err
	}
	claim = ProjectDomainClaim{
		Domain:    norm,
		Tenant:    tenantName,
		Project:   project,
		Zone:      zone,
		UserKey:   strings.TrimSpace(req.UserKey),
		CreatedAt: timeNow().UTC().Format(time.RFC3339),
	}
	if req.DryRun {
		return claim, previous, nil // deferred ROLLBACK
	}
	if previous != nil {
		if _, err := conn.ExecContext(ctx, `DELETE FROM project_domain_claims WHERE tenant = ? AND project = ?`, tenantName, project); err != nil {
			return ProjectDomainClaim{}, nil, fmt.Errorf("replace project domain claim: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, `
INSERT INTO project_domain_claims (domain, tenant, project, zone, user_key, created_at)
VALUES (?, ?, ?, ?, ?, ?)
`, claim.Domain, claim.Tenant, claim.Project, claim.Zone, claim.UserKey, claim.CreatedAt); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY KEY") {
			// The scan ran under the write lock, so this can only be a claim
			// that slipped in between two connections — report it flat.
			return ProjectDomainClaim{}, nil, &DomainClaimError{Domain: norm, Class: DomainClaimConflictExact}
		}
		return ProjectDomainClaim{}, nil, fmt.Errorf("insert project domain claim: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return ProjectDomainClaim{}, nil, fmt.Errorf("claim project domain: commit: %w", err)
	}
	committed = true
	return claim, previous, nil
}

// validateProjectDomain runs §3.3 steps 2–4 on an already-normalized domain:
// unique longest-suffix zone match, apex, length. Returns the covering zone.
func validateProjectDomain(norm string, zones []string, adminView bool) (string, error) {
	zone := ""
	for _, candidate := range zones {
		if norm == candidate || strings.HasSuffix(norm, "."+candidate) {
			if len(candidate) > len(zone) {
				zone = candidate
			}
		}
	}
	if zone == "" {
		return "", &ProjectDomainError{Domain: norm, Kind: "no-zone", Zones: zones, AdminView: adminView}
	}
	if norm == zone {
		return "", &ProjectDomainError{Domain: norm, Kind: "apex", Zone: zone}
	}
	if len(norm) > projectDomainMaxLength {
		return "", &ProjectDomainError{Domain: norm, Kind: "too-long"}
	}
	return zone, nil
}

// scanProjectDomainConflicts classifies d against the install's claims,
// Public Route hostnames and reserved names (spec §3.3). The caller's own
// (tenant, project) row is skipped: replacing one's own claim is set-domain.
// Install-reserved and route conflicts are checked first because their text
// never names an owner; among claim conflicts the first hit wins.
func scanProjectDomainConflicts(d, tenantName, project string, claims []ProjectDomainClaim, routeHostnames []string, authHostname, routeBaseDomain string) error {
	for _, reserved := range []string{authHostname, routeBaseDomain} {
		reserved = normalizeHostname(reserved)
		if reserved == "" {
			continue
		}
		if reserved == d || strings.HasSuffix(reserved, "."+d) {
			return &DomainClaimError{Domain: d, Existing: reserved, Class: DomainClaimConflictInstall}
		}
	}
	for _, hostname := range routeHostnames {
		h := strings.TrimPrefix(normalizeHostname(hostname), "*.")
		if h == "" {
			continue
		}
		if h == d || strings.HasSuffix(h, "."+d) {
			return &DomainClaimError{Domain: d, Existing: h, Class: DomainClaimConflictRoute}
		}
	}
	for _, c := range claims {
		if c.Tenant == tenantName && c.Project == project {
			continue
		}
		class := ""
		switch {
		case c.Domain == d:
			class = DomainClaimConflictExact
		case strings.HasSuffix(c.Domain, "."+d):
			class = DomainClaimConflictAncestor
		case strings.HasSuffix(d, "."+c.Domain):
			class = DomainClaimConflictDescendant
		default:
			continue
		}
		return &DomainClaimError{Domain: d, Existing: c.Domain, Project: c.Project, Class: class, SameTenant: c.Tenant == tenantName}
	}
	return nil
}

// sqlQuerier is what listProjectDomainClaims/listRouteHostnames need — a
// *sql.DB or the *sql.Conn holding the claim transaction.
type sqlQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func listProjectDomainClaims(ctx context.Context, q sqlQuerier) ([]ProjectDomainClaim, error) {
	rows, err := q.QueryContext(ctx, `
SELECT domain, tenant, project, zone, user_key, created_at
FROM project_domain_claims ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("list project domain claims: %w", err)
	}
	defer rows.Close()
	var claims []ProjectDomainClaim
	for rows.Next() {
		var c ProjectDomainClaim
		if err := rows.Scan(&c.Domain, &c.Tenant, &c.Project, &c.Zone, &c.UserKey, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan project domain claim: %w", err)
		}
		claims = append(claims, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate project domain claims: %w", err)
	}
	return claims, nil
}

func listRouteHostnames(ctx context.Context, q sqlQuerier) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT hostname FROM routes`)
	if err != nil {
		return nil, fmt.Errorf("list route hostnames: %w", err)
	}
	defer rows.Close()
	var hostnames []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan route hostname: %w", err)
		}
		hostnames = append(hostnames, h)
	}
	return hostnames, rows.Err()
}

func listPublicDNSZoneNames(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT zone FROM public_dns_zones ORDER BY zone`)
	if err != nil {
		return nil, fmt.Errorf("list public DNS zones: %w", err)
	}
	defer rows.Close()
	var zones []string
	for rows.Next() {
		var zone string
		if err := rows.Scan(&zone); err != nil {
			return nil, err
		}
		zones = append(zones, zone)
	}
	return zones, rows.Err()
}

// ListProjectDomainClaims returns every claim, ordered by domain.
func ListProjectDomainClaims(ctx context.Context, db *sql.DB) ([]ProjectDomainClaim, error) {
	return listProjectDomainClaims(ctx, db)
}

// GetProjectDomainClaim returns the claim held by tenant/project, if any.
func GetProjectDomainClaim(ctx context.Context, db *sql.DB, tenantName, project string) (ProjectDomainClaim, bool, error) {
	var c ProjectDomainClaim
	err := db.QueryRowContext(ctx, `
SELECT domain, tenant, project, zone, user_key, created_at
FROM project_domain_claims WHERE tenant = ? AND project = ?
`, strings.TrimSpace(tenantName), strings.TrimSpace(project)).Scan(&c.Domain, &c.Tenant, &c.Project, &c.Zone, &c.UserKey, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectDomainClaim{}, false, nil
	}
	if err != nil {
		return ProjectDomainClaim{}, false, fmt.Errorf("look up project domain claim: %w", err)
	}
	return c, true, nil
}

// ReleaseProjectDomainClaim frees the domain held by tenant/project and
// returns what was released (false when there was nothing to release).
func ReleaseProjectDomainClaim(ctx context.Context, db *sql.DB, tenantName, project string) (ProjectDomainClaim, bool, error) {
	claim, found, err := GetProjectDomainClaim(ctx, db, tenantName, project)
	if err != nil || !found {
		return ProjectDomainClaim{}, false, err
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM project_domain_claims WHERE tenant = ? AND project = ?`, claim.Tenant, claim.Project); err != nil {
		return ProjectDomainClaim{}, false, fmt.Errorf("release project domain claim: %w", err)
	}
	return claim, true, nil
}

// restoreProjectDomainClaim re-inserts a claim after a failed Incus write
// (compensation for a replaced claim). Best-effort: a conflict that appeared
// in between is reported, not retried.
func restoreProjectDomainClaim(ctx context.Context, db *sql.DB, claim ProjectDomainClaim) error {
	_, err := db.ExecContext(ctx, `
INSERT OR IGNORE INTO project_domain_claims (domain, tenant, project, zone, user_key, created_at)
VALUES (?, ?, ?, ?, ?, ?)
`, claim.Domain, claim.Tenant, claim.Project, claim.Zone, claim.UserKey, claim.CreatedAt)
	if err != nil {
		return fmt.Errorf("restore project domain claim: %w", err)
	}
	return nil
}

// RouteHostnameInsideProjectDomain is the UpsertRoute reverse check (spec
// §3.3): a custom hostname (leading `*.` stripped) that equals or sits under
// any claimed Project Domain is refused.
func RouteHostnameInsideProjectDomain(ctx context.Context, db *sql.DB, hostname string) error {
	h := strings.TrimPrefix(normalizeHostname(hostname), "*.")
	if h == "" {
		return nil
	}
	claims, err := listProjectDomainClaims(ctx, db)
	if err != nil {
		return err
	}
	for _, c := range claims {
		if h == c.Domain || strings.HasSuffix(h, "."+c.Domain) {
			return &RouteInsideProjectDomainError{Hostname: h, Domain: c.Domain}
		}
	}
	return nil
}

// ReconcileProjectDomainClaims is the slow-loop GC (spec §4.6): every claim
// whose <tenant>/<project> is not a live app project is dropped, and released
// is called for each so the slice-6 hook can delete the domain's A records
// and certificate rows. An EMPTY live set is never trusted (same guard as
// pruneOrphanSuffixClaims). Returns the dropped claims.
func ReconcileProjectDomainClaims(ctx context.Context, db *sql.DB, liveProjects map[string][]string, released func(context.Context, ProjectDomainClaim)) ([]ProjectDomainClaim, error) {
	if db == nil || len(liveProjects) == 0 {
		return nil, nil
	}
	claims, err := listProjectDomainClaims(ctx, db)
	if err != nil {
		return nil, err
	}
	var dropped []ProjectDomainClaim
	for _, c := range claims {
		live := false
		for _, p := range liveProjects[c.Tenant] {
			if strings.TrimSpace(p) == c.Project {
				live = true
				break
			}
		}
		if live {
			continue
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM project_domain_claims WHERE domain = ?`, c.Domain); err != nil {
			return dropped, fmt.Errorf("prune project domain claim %s: %w", c.Domain, err)
		}
		dropped = append(dropped, c)
		if released != nil {
			released(ctx, c)
		}
	}
	return dropped, nil
}

// UnclaimedProjectDomains lists live app projects carrying KeyV2Domain with no
// claim row — the "Incus key without row" case the GC logs and never
// auto-claims. liveDomains maps "<tenant>/<project>" to the Incus key value.
func UnclaimedProjectDomains(ctx context.Context, db *sql.DB, liveDomains map[string]string) ([]string, error) {
	claims, err := listProjectDomainClaims(ctx, db)
	if err != nil {
		return nil, err
	}
	claimed := make(map[string]struct{}, len(claims))
	for _, c := range claims {
		claimed[c.Tenant+"/"+c.Project] = struct{}{}
	}
	var unclaimed []string
	for key, domainName := range liveDomains {
		if strings.TrimSpace(domainName) == "" {
			continue
		}
		if _, ok := claimed[key]; !ok {
			unclaimed = append(unclaimed, key+" ("+domainName+")")
		}
	}
	sort.Strings(unclaimed)
	return unclaimed, nil
}

// onProjectDomainReleased is the hook slice 6 fills in: when a claim is
// released (DELETE /api/projects/{name}, or the GC), delete every A record
// under the domain and drop its machine_certificates rows — a released domain
// can be re-claimed by another tenant, so its records and certificates must
// not survive. Nothing to do until the reconciler exists.
func onProjectDomainReleased(context.Context, *sql.DB, ProjectDomainClaim) {}

// sqlProjectDomainClaims is the ProjectDomainClaimSource over the table —
// the default the zone registry consumes (replacing slice 2's stub).
type sqlProjectDomainClaims struct{ db *sql.DB }

func (s sqlProjectDomainClaims) ClaimsUnderZone(ctx context.Context, zone string) ([]ProjectDomainClaimRef, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT domain, tenant, project FROM project_domain_claims WHERE zone = ? ORDER BY domain`, zone)
	if err != nil {
		return nil, fmt.Errorf("list claims under zone %s: %w", zone, err)
	}
	defer rows.Close()
	var refs []ProjectDomainClaimRef
	for rows.Next() {
		var ref ProjectDomainClaimRef
		if err := rows.Scan(&ref.Domain, &ref.Tenant, &ref.Project); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// ResolveProjectDomain implements ProjectDomainResolver over the claims table
// (spec §3.3): the Project Domain and zone for tenant/project, or empty when
// the project has no domain.
func (s sqlProjectDomainClaims) ResolveProjectDomain(ctx context.Context, tenantName, project string) (string, string, error) {
	claim, found, err := GetProjectDomainClaim(ctx, s.db, tenantName, project)
	if err != nil || !found {
		return "", "", err
	}
	return claim.Domain, claim.Zone, nil
}
