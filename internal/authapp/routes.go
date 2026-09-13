package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// The routes table is the per-install registry of published Public Routes
// (Spec #111). Each row maps a public Hostname to a backend port on one of a
// Tenant's Machines, plus the Auth-App loopback port an Incus proxy device
// listens on so Caddy can reach it. The `hostname` PRIMARY KEY is the single
// uniqueness gate and enforces both rules at once:
//
//   - auto-subdomain labels are unique within a Tenant, because the generated
//     FQDN is <label>.<tenant>.<auth-hostname> — a second machine reusing a
//     label produces the same FQDN and conflicts on the PK;
//   - custom Hostnames are globally unique first-come, again via the PK.
//
// The registry is the source of truth read by both the certificate-gating `ask`
// endpoint and Caddyfile regeneration.

// localPortBase is the low end of the loopback port range the Auth App
// allocates per Route for its proxy devices. Kept well above privileged and
// service ports (Caddy on 80/443/8080, auth-app on 9444).
const localPortBase = 20000

// localPortCeiling bounds the range so allocation failure is an explicit error
// rather than an unbounded scan.
const localPortCeiling = 30000

// Route is one published Public Route.
type Route struct {
	Hostname    string
	Tenant      string
	Project     string
	Machine     string
	BackendPort int
	LocalPort   int
	CreatedAt   string
}

// RouteConflictError explains why an UpsertRoute call was rejected. CrossTenant
// means another Tenant already holds the Hostname; otherwise the calling Tenant
// already publishes the Hostname to a different backend (Machine/port).
type RouteConflictError struct {
	Hostname        string
	ExistingTenant  string
	ExistingMachine string
	CrossTenant     bool
}

func (e *RouteConflictError) Error() string {
	if e.CrossTenant {
		return fmt.Sprintf("route hostname %q is already published on this install", e.Hostname)
	}
	return fmt.Sprintf("route hostname %q is already published to machine %q; delete it or choose another --name", e.Hostname, e.ExistingMachine)
}

// normalizeHostname lowercases and trims a Hostname so uniqueness is
// case-insensitive and whitespace-insensitive.
func normalizeHostname(hostname string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(hostname), ".")))
}

// UpsertRoute registers route, allocating a free loopback local port on first
// insert. Re-publishing the exact same (tenant, project, machine, backend_port)
// under the same Hostname is idempotent and returns the stored Route unchanged
// (its local port is preserved). A Hostname held by another Tenant, or pointed
// at a different backend by the same Tenant, is a RouteConflictError.
func UpsertRoute(ctx context.Context, db *sql.DB, route Route) (Route, error) {
	route.Hostname = normalizeHostname(route.Hostname)
	route.Tenant = strings.TrimSpace(route.Tenant)
	route.Project = strings.TrimSpace(route.Project)
	route.Machine = strings.TrimSpace(route.Machine)
	if route.Hostname == "" {
		return Route{}, fmt.Errorf("route hostname is required")
	}
	if route.Tenant == "" {
		return Route{}, fmt.Errorf("tenant is required to publish a route")
	}
	if route.BackendPort <= 0 {
		return Route{}, fmt.Errorf("a positive backend port is required")
	}

	existing, found, err := GetRoute(ctx, db, route.Hostname)
	if err != nil {
		return Route{}, err
	}
	if !found {
		// Reverse of the Project Domain conflict scan (ADR-0027 §3.3): a new
		// custom hostname may not sit inside a claimed Project Domain. The
		// auto-subdomain path cannot collide — the route base domain is
		// install-reserved for claims — so this only ever bites custom names.
		if err := RouteHostnameInsideProjectDomain(ctx, db, route.Hostname); err != nil {
			return Route{}, err
		}
		// Same reverse rule for explicit Machine Public Hostnames (ADR-0028):
		// a hostname reserves itself and its wildcard subtree.
		if err := RouteHostnameInsideMachineHostname(ctx, db, route.Hostname); err != nil {
			return Route{}, err
		}
	}
	if found {
		if existing.Tenant != route.Tenant {
			return Route{}, &RouteConflictError{Hostname: route.Hostname, ExistingTenant: existing.Tenant, ExistingMachine: existing.Machine, CrossTenant: true}
		}
		if existing.Project == route.Project && existing.Machine == route.Machine && existing.BackendPort == route.BackendPort {
			return existing, nil // idempotent re-publish
		}
		return Route{}, &RouteConflictError{Hostname: route.Hostname, ExistingTenant: existing.Tenant, ExistingMachine: existing.Machine}
	}

	localPort, err := allocateLocalPort(ctx, db)
	if err != nil {
		return Route{}, err
	}
	route.LocalPort = localPort
	if _, err := db.ExecContext(ctx, `
INSERT INTO routes (hostname, tenant, project, machine, backend_port, local_port, created_at)
VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
`, route.Hostname, route.Tenant, route.Project, route.Machine, route.BackendPort, route.LocalPort); err != nil {
		return Route{}, fmt.Errorf("insert route: %w", err)
	}
	stored, _, err := GetRoute(ctx, db, route.Hostname)
	if err != nil {
		return Route{}, err
	}
	return stored, nil
}

// allocateLocalPort returns the lowest free loopback port in [localPortBase,
// localPortCeiling) not already held by a Route.
func allocateLocalPort(ctx context.Context, db *sql.DB) (int, error) {
	rows, err := db.QueryContext(ctx, `SELECT local_port FROM routes`)
	if err != nil {
		return 0, fmt.Errorf("list route local ports: %w", err)
	}
	used := map[int]struct{}{}
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan route local port: %w", err)
		}
		used[port] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate route local ports: %w", err)
	}
	rows.Close()
	for port := localPortBase; port < localPortCeiling; port++ {
		if _, taken := used[port]; !taken {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free route local port in [%d,%d)", localPortBase, localPortCeiling)
}

// GetRoute returns the Route for hostname, if any.
func GetRoute(ctx context.Context, db *sql.DB, hostname string) (Route, bool, error) {
	var route Route
	err := db.QueryRowContext(ctx, `
SELECT hostname, tenant, project, machine, backend_port, local_port, created_at
FROM routes WHERE hostname = ?
`, normalizeHostname(hostname)).Scan(&route.Hostname, &route.Tenant, &route.Project, &route.Machine, &route.BackendPort, &route.LocalPort, &route.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Route{}, false, nil
	}
	if err != nil {
		return Route{}, false, fmt.Errorf("look up route: %w", err)
	}
	return route, true, nil
}

// RouteHostnameRegistered reports whether hostname is a published Route. This
// backs the certificate-gating `ask` endpoint, so it is a cheap existence check.
func RouteHostnameRegistered(ctx context.Context, db *sql.DB, hostname string) (bool, error) {
	_, found, err := GetRoute(ctx, db, hostname)
	return found, err
}

// ListRoutes returns every Route, ordered by hostname. Used by the reconcile and
// Caddyfile regeneration.
func ListRoutes(ctx context.Context, db *sql.DB) ([]Route, error) {
	return queryRoutes(ctx, db, `
SELECT hostname, tenant, project, machine, backend_port, local_port, created_at
FROM routes ORDER BY hostname`)
}

// ListRoutesByTenant returns a Tenant's Routes, ordered by hostname. Used by
// `sc route list`.
func ListRoutesByTenant(ctx context.Context, db *sql.DB, tenant string) ([]Route, error) {
	return queryRoutes(ctx, db, `
SELECT hostname, tenant, project, machine, backend_port, local_port, created_at
FROM routes WHERE tenant = ? ORDER BY hostname`, strings.TrimSpace(tenant))
}

func queryRoutes(ctx context.Context, db *sql.DB, query string, args ...any) ([]Route, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	defer rows.Close()
	var routes []Route
	for rows.Next() {
		var route Route
		if err := rows.Scan(&route.Hostname, &route.Tenant, &route.Project, &route.Machine, &route.BackendPort, &route.LocalPort, &route.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan route: %w", err)
		}
		routes = append(routes, route)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate routes: %w", err)
	}
	return routes, nil
}

// DeleteRoute removes a Route the Tenant owns. A missing Route, or one owned by
// another Tenant, is an error so callers can report it. Returns the removed
// Route (for proxy-device teardown).
func DeleteRoute(ctx context.Context, db *sql.DB, hostname, tenant string) (Route, error) {
	hostname = normalizeHostname(hostname)
	tenant = strings.TrimSpace(tenant)
	route, found, err := GetRoute(ctx, db, hostname)
	if err != nil {
		return Route{}, err
	}
	if !found {
		return Route{}, fmt.Errorf("route %q is not published", hostname)
	}
	if tenant != "" && route.Tenant != tenant {
		return Route{}, fmt.Errorf("route %q belongs to another tenant", hostname)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM routes WHERE hostname = ?`, hostname); err != nil {
		return Route{}, fmt.Errorf("delete route: %w", err)
	}
	return route, nil
}

// PruneRoute removes a Route by Hostname regardless of Tenant. Used by the
// reconcile when a backing Machine is gone.
func PruneRoute(ctx context.Context, db *sql.DB, hostname string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM routes WHERE hostname = ?`, normalizeHostname(hostname)); err != nil {
		return fmt.Errorf("prune route: %w", err)
	}
	return nil
}
