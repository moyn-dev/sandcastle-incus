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

// The machine_hostnames table is the install-wide reservation registry for
// explicit Machine Public Hostnames (ADR-0028, spec machine-hostnames §1). A
// row is the reservation of exactly that name plus its wildcard subtree,
// first come, install-wide — it shares the BEGIN IMMEDIATE scan with Project
// Domain claims (project_domain_claims.go) so the two registries and the
// Public Route table can never overlap in either direction. Derived names
// (`<machine>.<Project Domain>`) are NOT rows here: they are implied by the
// project's domain claim, which already reserves its whole subtree.
//
// Only after COMMIT does a handler touch Incus: the instance key
// `user.sandcastle.v2.public-hostnames` is the operational list the CLI
// reads, never the reservation.

const machineHostnamesSchema = `
CREATE TABLE IF NOT EXISTS machine_hostnames (
    hostname   TEXT PRIMARY KEY,                  -- normalized explicit Machine Public Hostname
    tenant     TEXT NOT NULL,
    project    TEXT NOT NULL,                     -- short project name
    machine    TEXT NOT NULL,
    zone       TEXT NOT NULL REFERENCES public_dns_zones(zone),
    user_key   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS machine_hostnames_machine ON machine_hostnames(tenant, project, machine);
`

// migrateMachineHostnames creates the machine_hostnames table (ADR-0028).
func migrateMachineHostnames(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, machineHostnamesSchema); err != nil {
		return fmt.Errorf("migrate machine_hostnames: %w", err)
	}
	return nil
}

// MachineHostname is one row of machine_hostnames.
type MachineHostname struct {
	Hostname  string `json:"hostname"`
	Tenant    string `json:"tenant"`
	Project   string `json:"project"`
	Machine   string `json:"machine"`
	Zone      string `json:"zone"`
	UserKey   string `json:"userKey,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
}

// MachineRef is "project:machine", the CLI's own reference form.
func (h MachineHostname) MachineRef() string { return h.Project + ":" + h.Machine }

// Conflict classes of a hostname claim (spec machine-hostnames §1.3). Every
// class blocks regardless of tenant; the class only shapes the message.
const (
	HostnameClaimConflictExact      = "exact"
	HostnameClaimConflictAncestor   = "ancestor"   // the candidate would cover an existing hostname
	HostnameClaimConflictDescendant = "descendant" // the candidate sits inside an existing hostname
	HostnameClaimConflictDomain     = "domain"     // inside, equal to, or covering a Project Domain
	HostnameClaimConflictRoute      = "route"      // equals or covers a Public Route hostname
	HostnameClaimConflictInstall    = "install"    // equals or covers the Auth Hostname / route base
)

// HostnameClaimError explains why a hostname claim was refused by a conflict.
// It mirrors DomainClaimError: handlers map it to 409 and print Error()
// verbatim; cross-tenant refusals never reveal who holds the overlapping
// name.
type HostnameClaimError struct {
	Hostname string
	Existing string
	// Project/Machine name the holder for same-tenant conflicts: the
	// project of a Project Domain, or project + machine of a hostname.
	Project    string
	Machine    string
	Class      string
	SameTenant bool
}

func (e *HostnameClaimError) Error() string {
	switch {
	case e.Class == HostnameClaimConflictInstall || e.Class == HostnameClaimConflictRoute:
		return fmt.Sprintf("machine hostname %q is reserved by this install", e.Hostname)
	case e.SameTenant && e.Class == HostnameClaimConflictDomain:
		return fmt.Sprintf("machine hostname %q overlaps project domain %q claimed by project %q in this tenant", e.Hostname, e.Existing, e.Project)
	case e.SameTenant:
		return fmt.Sprintf("machine hostname %q overlaps %q held by machine %q in this tenant", e.Hostname, e.Existing, e.Project+":"+e.Machine)
	default:
		return fmt.Sprintf("machine hostname %q overlaps a name already claimed on this install; choose another", e.Hostname)
	}
}

// MachineHostnameError is a validation refusal: well formed, but not
// claimable as given. Handlers map it to 400.
type MachineHostnameError struct {
	Hostname string
	// Kind is one of: "no-zone", "apex", "too-long".
	Kind      string
	Zone      string
	Zones     []string
	AdminView bool
}

func (e *MachineHostnameError) Error() string {
	switch e.Kind {
	case "no-zone":
		if e.AdminView {
			zones := strings.Join(e.Zones, ", ")
			if zones == "" {
				zones = "(none)"
			}
			return fmt.Sprintf("no Public DNS Zone covers %s; registered zones: %s", e.Hostname, zones)
		}
		return fmt.Sprintf("no Public DNS Zone covers %s — ask your admin", e.Hostname)
	case "apex":
		return fmt.Sprintf("machine hostname %q is a zone apex; use at least one label below %s", e.Hostname, e.Zone)
	case "too-long":
		return fmt.Sprintf("machine hostname %q is too long: \"*.<hostname>\" must fit in 253 characters", e.Hostname)
	}
	return fmt.Sprintf("machine hostname %q: %s", e.Hostname, e.Kind)
}

// MachineHostnameAlreadyHeldError reports a same-machine identical re-claim:
// a no-op the CLI prints with exit 0.
type MachineHostnameAlreadyHeldError struct{ Hostname string }

func (e *MachineHostnameAlreadyHeldError) Error() string {
	return fmt.Sprintf("machine hostname %q already held by this machine", e.Hostname)
}

// MachineHostnameNotHeldError reports a release of a name the machine does
// not hold. Handlers map it to 404.
type MachineHostnameNotHeldError struct {
	Hostname string
	Project  string
	Machine  string
}

func (e *MachineHostnameNotHeldError) Error() string {
	return fmt.Sprintf("machine hostname %q is not held by machine %q", e.Hostname, e.Project+":"+e.Machine)
}

// RouteInsideMachineHostnameError is the reverse check of UpsertRoute: a
// custom Public Route hostname may not equal or sit inside a claimed
// Machine Public Hostname.
type RouteInsideMachineHostnameError struct {
	Hostname string
	Existing string
}

func (e *RouteInsideMachineHostnameError) Error() string {
	return fmt.Sprintf("route hostname %q is inside machine hostname %q claimed on this install", e.Hostname, e.Existing)
}

// machineHostnameMaxLength is the DNS name budget: `*.` + the hostname must
// fit in 253 characters (the certificate covers the one-level wildcard).
const machineHostnameMaxLength = 253 - len("*.")

// NormalizeMachineHostname is the shared client/server normalization:
// lowercase, trim, one trailing dot, ASCII labels, no `_`/`*` labels.
func NormalizeMachineHostname(value string) (string, error) {
	return domain.NormalizeMachineHostname(value)
}

// ClaimMachineHostnameRequest is the input of ClaimMachineHostname.
type ClaimMachineHostnameRequest struct {
	Hostname string
	Tenant   string
	Project  string
	Machine  string
	UserKey  string
	// AuthHostname and RouteBaseDomain are the install-reserved names; empty
	// values are skipped.
	AuthHostname    string
	RouteBaseDomain string
	// AdminView selects the admin wording of the no-zone refusal.
	AdminView bool
	// DryRun runs validation and the conflict scan, then rolls back.
	DryRun bool
}

// ClaimMachineHostname reserves req.Hostname for req.Tenant/req.Project/
// req.Machine (spec machine-hostnames §1.3).
//
// Validation (normalize, zone lookup, apex, length) runs first; then, inside
// the same BEGIN IMMEDIATE transaction Project Domain claims use, the
// conflict scan against domains, hostnames, routes and the install's own
// names, and the INSERT. Only after COMMIT should the caller touch Incus. A
// same-machine identical re-claim returns the existing row and a
// *MachineHostnameAlreadyHeldError (a no-op for the caller to report).
func ClaimMachineHostname(ctx context.Context, db *sql.DB, req ClaimMachineHostnameRequest) (MachineHostname, error) {
	norm, err := NormalizeMachineHostname(req.Hostname)
	if err != nil {
		return MachineHostname{}, err
	}
	tenantName := strings.TrimSpace(req.Tenant)
	project := strings.TrimSpace(req.Project)
	machine := strings.TrimSpace(req.Machine)
	if tenantName == "" || project == "" || machine == "" {
		return MachineHostname{}, fmt.Errorf("tenant, project and machine are required to claim a machine hostname")
	}
	zones, err := listPublicDNSZoneNames(ctx, db)
	if err != nil {
		return MachineHostname{}, err
	}
	zone, err := validateMachineHostname(norm, zones, req.AdminView)
	if err != nil {
		return MachineHostname{}, err
	}
	row := MachineHostname{
		Hostname:  norm,
		Tenant:    tenantName,
		Project:   project,
		Machine:   machine,
		Zone:      zone,
		UserKey:   strings.TrimSpace(req.UserKey),
		CreatedAt: timeNow().UTC().Format(time.RFC3339),
	}
	err = withReservationLock(ctx, db, "claim machine hostname", req.DryRun, func(ctx context.Context, conn *sql.Conn) error {
		reg, err := loadInstallReservations(ctx, conn, req.AuthHostname, req.RouteBaseDomain)
		if err != nil {
			return err
		}
		for _, existing := range reg.hostnames {
			if existing.Hostname == norm && existing.Tenant == tenantName && existing.Project == project && existing.Machine == machine {
				row = existing
				return &MachineHostnameAlreadyHeldError{Hostname: norm}
			}
		}
		if err := scanMachineHostnameConflicts(norm, tenantName, reg); err != nil {
			return err
		}
		if req.DryRun {
			return nil
		}
		if _, err := conn.ExecContext(ctx, `
INSERT INTO machine_hostnames (hostname, tenant, project, machine, zone, user_key, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
`, row.Hostname, row.Tenant, row.Project, row.Machine, row.Zone, row.UserKey, row.CreatedAt); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY KEY") {
				return &HostnameClaimError{Hostname: norm, Class: HostnameClaimConflictExact}
			}
			return fmt.Errorf("insert machine hostname: %w", err)
		}
		return nil
	})
	if err != nil {
		var already *MachineHostnameAlreadyHeldError
		if errors.As(err, &already) {
			return row, err
		}
		return MachineHostname{}, err
	}
	return row, nil
}

// validateMachineHostname runs the zone lookup (unique longest-suffix
// match), the apex rule and the length budget on a normalized hostname and
// returns the covering zone. Unlike a Project Domain, a hostname may sit
// directly under the zone apex (`web12.tc42.uk`, ADR-0028 decision 2); only
// the apex itself is refused.
func validateMachineHostname(norm string, zones []string, adminView bool) (string, error) {
	zone := ""
	for _, candidate := range zones {
		if norm == candidate || strings.HasSuffix(norm, "."+candidate) {
			if len(candidate) > len(zone) {
				zone = candidate
			}
		}
	}
	if zone == "" {
		return "", &MachineHostnameError{Hostname: norm, Kind: "no-zone", Zones: zones, AdminView: adminView}
	}
	if norm == zone {
		return "", &MachineHostnameError{Hostname: norm, Kind: "apex", Zone: zone}
	}
	if len(norm) > machineHostnameMaxLength {
		return "", &MachineHostnameError{Hostname: norm, Kind: "too-long"}
	}
	return zone, nil
}

// scanMachineHostnameConflicts classifies h against the install's
// reservations (spec machine-hostnames §1.3): install names and Public Route
// hostnames first (their text never names an owner), then Project Domains
// (equal, above or below), then other hostnames (equal, above or below).
func scanMachineHostnameConflicts(h, tenantName string, reg installReservations) error {
	for _, reserved := range []string{reg.authHostname, reg.routeBaseDomain} {
		reserved = normalizeHostname(reserved)
		if reserved == "" {
			continue
		}
		// Equal or an ancestor of an install name conflicts; a name BELOW the
		// Auth Hostname / route base does not (same rule as Project Domains —
		// a real Public Route collision is caught by the route scan below).
		if reserved == h || strings.HasSuffix(reserved, "."+h) {
			return &HostnameClaimError{Hostname: h, Existing: reserved, Class: HostnameClaimConflictInstall}
		}
	}
	for _, hostname := range reg.routes {
		r := strings.TrimPrefix(normalizeHostname(hostname), "*.")
		if r == "" {
			continue
		}
		if r == h || strings.HasSuffix(r, "."+h) {
			return &HostnameClaimError{Hostname: h, Existing: r, Class: HostnameClaimConflictRoute}
		}
	}
	for _, c := range reg.claims {
		if c.Domain == h || strings.HasSuffix(h, "."+c.Domain) || strings.HasSuffix(c.Domain, "."+h) {
			return &HostnameClaimError{Hostname: h, Existing: c.Domain, Project: c.Project, Class: HostnameClaimConflictDomain, SameTenant: c.Tenant == tenantName}
		}
	}
	for _, existing := range reg.hostnames {
		class := ""
		switch {
		case existing.Hostname == h:
			class = HostnameClaimConflictExact
		case strings.HasSuffix(existing.Hostname, "."+h):
			class = HostnameClaimConflictAncestor
		case strings.HasSuffix(h, "."+existing.Hostname):
			class = HostnameClaimConflictDescendant
		default:
			continue
		}
		return &HostnameClaimError{Hostname: h, Existing: existing.Hostname, Project: existing.Project, Machine: existing.Machine, Class: class, SameTenant: existing.Tenant == tenantName}
	}
	return nil
}

// scanProjectDomainHostnameConflicts is the hostname half of the Project
// Domain scan (the reverse direction): a candidate domain d conflicts with
// every hostname it equals, covers, or sits inside.
func scanProjectDomainHostnameConflicts(d, tenantName string, hostnames []MachineHostname) error {
	for _, existing := range hostnames {
		if existing.Hostname == d || strings.HasSuffix(existing.Hostname, "."+d) || strings.HasSuffix(d, "."+existing.Hostname) {
			return &DomainClaimError{Domain: d, Existing: existing.Hostname, Project: existing.Project, Machine: existing.Machine, Class: DomainClaimConflictHostname, SameTenant: existing.Tenant == tenantName}
		}
	}
	return nil
}

// RouteHostnameInsideMachineHostname is the UpsertRoute reverse check: a
// custom route hostname (leading `*.` stripped) that equals or sits under a
// claimed Machine Public Hostname is refused.
func RouteHostnameInsideMachineHostname(ctx context.Context, db *sql.DB, hostname string) error {
	h := strings.TrimPrefix(normalizeHostname(hostname), "*.")
	if h == "" {
		return nil
	}
	rows, err := listMachineHostnames(ctx, db)
	if err != nil {
		return err
	}
	for _, existing := range rows {
		if h == existing.Hostname || strings.HasSuffix(h, "."+existing.Hostname) {
			return &RouteInsideMachineHostnameError{Hostname: h, Existing: existing.Hostname}
		}
	}
	return nil
}

func listMachineHostnames(ctx context.Context, q sqlQuerier) ([]MachineHostname, error) {
	rows, err := q.QueryContext(ctx, `
SELECT hostname, tenant, project, machine, zone, user_key, created_at
FROM machine_hostnames ORDER BY hostname`)
	if err != nil {
		return nil, fmt.Errorf("list machine hostnames: %w", err)
	}
	defer rows.Close()
	var out []MachineHostname
	for rows.Next() {
		var h MachineHostname
		if err := rows.Scan(&h.Hostname, &h.Tenant, &h.Project, &h.Machine, &h.Zone, &h.UserKey, &h.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan machine hostname: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate machine hostnames: %w", err)
	}
	return out, nil
}

// ListMachineHostnames returns every explicit hostname of the install,
// ordered by hostname.
func ListMachineHostnames(ctx context.Context, db *sql.DB) ([]MachineHostname, error) {
	return listMachineHostnames(ctx, db)
}

// MachineHostnamesOf returns the explicit hostnames held by one machine,
// sorted.
func MachineHostnamesOf(ctx context.Context, db *sql.DB, tenantName, project, machine string) ([]MachineHostname, error) {
	rows, err := db.QueryContext(ctx, `
SELECT hostname, tenant, project, machine, zone, user_key, created_at
FROM machine_hostnames WHERE tenant = ? AND project = ? AND machine = ? ORDER BY hostname`,
		strings.TrimSpace(tenantName), strings.TrimSpace(project), strings.TrimSpace(machine))
	if err != nil {
		return nil, fmt.Errorf("list hostnames of %s/%s:%s: %w", tenantName, project, machine, err)
	}
	defer rows.Close()
	var out []MachineHostname
	for rows.Next() {
		var h MachineHostname
		if err := rows.Scan(&h.Hostname, &h.Tenant, &h.Project, &h.Machine, &h.Zone, &h.UserKey, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ReleaseMachineHostname frees hostname if the machine holds it; a name the
// machine does not hold is a *MachineHostnameNotHeldError (a foreign holder
// is never revealed — the text is the same as for an unknown name).
func ReleaseMachineHostname(ctx context.Context, db *sql.DB, tenantName, project, machine, hostname string) (MachineHostname, error) {
	norm, err := NormalizeMachineHostname(hostname)
	if err != nil {
		return MachineHostname{}, err
	}
	held, err := MachineHostnamesOf(ctx, db, tenantName, project, machine)
	if err != nil {
		return MachineHostname{}, err
	}
	for _, h := range held {
		if h.Hostname != norm {
			continue
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM machine_hostnames WHERE hostname = ?`, norm); err != nil {
			return MachineHostname{}, fmt.Errorf("release machine hostname %s: %w", norm, err)
		}
		return h, nil
	}
	return MachineHostname{}, &MachineHostnameNotHeldError{Hostname: norm, Project: strings.TrimSpace(project), Machine: strings.TrimSpace(machine)}
}

// ReleaseMachineHostnamesOfProject frees every hostname held by machines of
// tenant/project (project delete) and returns them.
func ReleaseMachineHostnamesOfProject(ctx context.Context, db *sql.DB, tenantName, project string) ([]MachineHostname, error) {
	rows, err := listMachineHostnames(ctx, db)
	if err != nil {
		return nil, err
	}
	var released []MachineHostname
	for _, h := range rows {
		if h.Tenant != strings.TrimSpace(tenantName) || h.Project != strings.TrimSpace(project) {
			continue
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM machine_hostnames WHERE hostname = ?`, h.Hostname); err != nil {
			return released, fmt.Errorf("release machine hostname %s: %w", h.Hostname, err)
		}
		released = append(released, h)
	}
	return released, nil
}

// ReconcileMachineHostnames is the slow-loop GC (spec machine-hostnames
// §1.5): every hostname whose machine no longer exists is dropped and
// released is called for it. liveMachines is keyed "<tenant>/<project>/
// <machine>"; liveProjects maps tenant → live project names. A hostname is
// live when its machine is listed; when its project is live but the machine
// listing is unavailable (nil), it is kept. An EMPTY live set is never
// trusted (same guard as pruneOrphanSuffixClaims). Nothing is retained: the
// certificate row's retention is machine_certificates' own concern.
func ReconcileMachineHostnames(ctx context.Context, db *sql.DB, liveProjects map[string][]string, liveMachines map[string]struct{}, released func(context.Context, MachineHostname)) ([]MachineHostname, error) {
	if db == nil || len(liveProjects) == 0 {
		return nil, nil
	}
	rows, err := listMachineHostnames(ctx, db)
	if err != nil {
		return nil, err
	}
	var dropped []MachineHostname
	for _, h := range rows {
		projectLive := false
		for _, p := range liveProjects[h.Tenant] {
			if strings.TrimSpace(p) == h.Project {
				projectLive = true
				break
			}
		}
		if projectLive {
			if liveMachines == nil {
				continue
			}
			if _, ok := liveMachines[h.Tenant+"/"+h.Project+"/"+h.Machine]; ok {
				continue
			}
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM machine_hostnames WHERE hostname = ?`, h.Hostname); err != nil {
			return dropped, fmt.Errorf("prune machine hostname %s: %w", h.Hostname, err)
		}
		dropped = append(dropped, h)
		if released != nil {
			released(ctx, h)
		}
	}
	return dropped, nil
}

// onMachineHostnameReleased runs when an explicit hostname is released
// (DELETE …/hostnames/{h}, project delete, or the GC): it deletes the name's
// A records (base + wildcard) and its _acme-challenge TXT record (spec
// machine-hostnames §7.4). The machine_certificates row is NOT touched — it
// keeps its own retention rule (§4.6), so a re-added name reuses the
// certificate without a new order. A Cloudflare failure is returned for the
// caller to log; the zone reconciler treats records of a released name as
// stale on its next pass, so nothing is lost.
func onMachineHostnameReleased(ctx context.Context, db *sql.DB, hostname MachineHostname) error {
	if db == nil {
		return nil
	}
	return releaseMachineHostnameRecords(ctx, db, hostname)
}

// MachineHostnameRef names one hostname held under a zone — for the zone
// removal refusal.
type MachineHostnameRef struct {
	Hostname string
	Tenant   string
	Project  string
	Machine  string
}

// hostnamesUnderZone lists the explicit hostnames reserved under a zone.
func hostnamesUnderZone(ctx context.Context, db *sql.DB, zone string) ([]MachineHostnameRef, error) {
	rows, err := db.QueryContext(ctx, `SELECT hostname, tenant, project, machine FROM machine_hostnames WHERE zone = ? ORDER BY hostname`, zone)
	if err != nil {
		return nil, fmt.Errorf("list hostnames under zone %s: %w", zone, err)
	}
	defer rows.Close()
	var refs []MachineHostnameRef
	for rows.Next() {
		var ref MachineHostnameRef
		if err := rows.Scan(&ref.Hostname, &ref.Tenant, &ref.Project, &ref.Machine); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, rows.Err()
}

// PublicHostnamesOfMachine is the full set a machine's instance key must
// carry (spec machine-hostnames §1.4): the derived name when the project
// holds a Project Domain, plus every explicit hostname — sorted.
func PublicHostnamesOfMachine(ctx context.Context, db *sql.DB, tenantName, project, machine string) ([]string, error) {
	var names []string
	claim, found, err := GetProjectDomainClaim(ctx, db, tenantName, project)
	if err != nil {
		return nil, err
	}
	if found {
		names = append(names, strings.ToLower(strings.TrimSpace(machine))+"."+claim.Domain)
	}
	held, err := MachineHostnamesOf(ctx, db, tenantName, project, machine)
	if err != nil {
		return nil, err
	}
	for _, h := range held {
		names = append(names, h.Hostname)
	}
	sort.Strings(names)
	return names, nil
}

// ── the shared reservation transaction ───────────────────────────────────────

// installReservations is the snapshot every conflict scan runs against, read
// inside the reservation transaction so two claimers can never both pass.
type installReservations struct {
	claims          []ProjectDomainClaim
	hostnames       []MachineHostname
	routes          []string
	authHostname    string
	routeBaseDomain string
}

func loadInstallReservations(ctx context.Context, q sqlQuerier, authHostname, routeBaseDomain string) (installReservations, error) {
	claims, err := listProjectDomainClaims(ctx, q)
	if err != nil {
		return installReservations{}, err
	}
	hostnames, err := listMachineHostnames(ctx, q)
	if err != nil {
		return installReservations{}, err
	}
	routes, err := listRouteHostnames(ctx, q)
	if err != nil {
		return installReservations{}, err
	}
	return installReservations{claims: claims, hostnames: hostnames, routes: routes, authHostname: authHostname, routeBaseDomain: routeBaseDomain}, nil
}

// withReservationLock runs fn inside a BEGIN IMMEDIATE transaction on a
// dedicated connection — the only way database/sql lets us pick SQLite's
// transaction mode, and what serializes concurrent claimers on the write
// lock. A nil result commits (unless dryRun, which always rolls back); an
// error rolls back and is returned as is.
func withReservationLock(ctx context.Context, db *sql.DB, label string, dryRun bool, fn func(ctx context.Context, conn *sql.Conn) error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("%s: begin: %w", label, err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		}
	}()
	if err := fn(ctx, conn); err != nil {
		return err
	}
	if dryRun {
		return nil // deferred ROLLBACK
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("%s: commit: %w", label, err)
	}
	committed = true
	return nil
}
