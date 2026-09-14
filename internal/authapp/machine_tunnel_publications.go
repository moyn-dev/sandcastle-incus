package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// MachineTunnelPublication is the durable ownership record for a dedicated
// Cloudflare Tunnel. Its hostname primary key prevents a publish from silently
// retargeting a name another Machine already owns.
type MachineTunnelPublication struct {
	Hostname string
	Tenant   string
	Project  string
	Machine  string
	Port     int
}

func GetMachineTunnelPublication(ctx context.Context, db *sql.DB, hostname string) (MachineTunnelPublication, bool, error) {
	var publication MachineTunnelPublication
	err := db.QueryRowContext(ctx, `
SELECT hostname, tenant, project, machine, port
FROM machine_tunnel_publications WHERE hostname = ?
`, normalizeHostname(hostname)).Scan(&publication.Hostname, &publication.Tenant, &publication.Project, &publication.Machine, &publication.Port)
	if errors.Is(err, sql.ErrNoRows) {
		return MachineTunnelPublication{}, false, nil
	}
	if err != nil {
		return MachineTunnelPublication{}, false, fmt.Errorf("look up machine tunnel publication: %w", err)
	}
	return publication, true, nil
}

// ClaimMachineTunnelPublication reserves a hostname before the Cloudflare
// call. An exact retry is safe; every other tuple is a deliberate conflict.
func ClaimMachineTunnelPublication(ctx context.Context, db *sql.DB, publication MachineTunnelPublication) (MachineTunnelPublication, bool, error) {
	publication.Hostname = normalizeHostname(publication.Hostname)
	publication.Tenant = strings.TrimSpace(publication.Tenant)
	publication.Project = strings.TrimSpace(publication.Project)
	publication.Machine = strings.TrimSpace(publication.Machine)
	if publication.Hostname == "" || publication.Tenant == "" || publication.Project == "" || publication.Machine == "" || publication.Port < 1 || publication.Port > 65535 {
		return MachineTunnelPublication{}, false, fmt.Errorf("invalid machine tunnel publication")
	}
	existing, found, err := GetMachineTunnelPublication(ctx, db, publication.Hostname)
	if err != nil {
		return MachineTunnelPublication{}, false, err
	}
	if found {
		if existing.Tenant == publication.Tenant && existing.Project == publication.Project && existing.Machine == publication.Machine && existing.Port == publication.Port {
			return existing, false, nil
		}
		return MachineTunnelPublication{}, false, fmt.Errorf("Machine Tunnel hostname %q is already published by another Machine; unpublish it before reuse", publication.Hostname)
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO machine_tunnel_publications (hostname, tenant, project, machine, port, created_at)
VALUES (?, ?, ?, ?, ?, datetime('now'))
`, publication.Hostname, publication.Tenant, publication.Project, publication.Machine, publication.Port); err != nil {
		return MachineTunnelPublication{}, false, fmt.Errorf("claim machine tunnel publication: %w", err)
	}
	return publication, true, nil
}

// ReleaseMachineTunnelPublication removes only the exact owner record.
func ReleaseMachineTunnelPublication(ctx context.Context, db *sql.DB, publication MachineTunnelPublication) error {
	result, err := db.ExecContext(ctx, `
DELETE FROM machine_tunnel_publications
WHERE hostname = ? AND tenant = ? AND project = ? AND machine = ? AND port = ?
`, normalizeHostname(publication.Hostname), strings.TrimSpace(publication.Tenant), strings.TrimSpace(publication.Project), strings.TrimSpace(publication.Machine), publication.Port)
	if err != nil {
		return fmt.Errorf("release machine tunnel publication: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("release machine tunnel publication: %w", err)
	} else if changed != 1 {
		return fmt.Errorf("Machine Tunnel hostname %q is not published by this Machine", normalizeHostname(publication.Hostname))
	}
	return nil
}
