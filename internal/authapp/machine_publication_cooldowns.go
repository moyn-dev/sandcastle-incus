package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MachinePublicationDNSPropagationCooldown is the mandatory wait after any
// Machine publication unpublish. It prevents a new publication kind from
// reusing a name while resolvers may still hold its previous DNS target.
const MachinePublicationDNSPropagationCooldown = time.Minute

// HoldMachinePublicationHostname starts the durable DNS-propagation hold only
// after the caller has completed its external unpublish cleanup.
func HoldMachinePublicationHostname(ctx context.Context, db *sql.DB, hostname string) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO machine_publication_cooldowns (hostname, released_at) VALUES (?, ?)
ON CONFLICT(hostname) DO UPDATE SET released_at = excluded.released_at
`, normalizeHostname(hostname), timeNow().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("hold machine publication hostname: %w", err)
	}
	return nil
}

// RequireMachinePublicationHostnameAvailable rejects a name still in its DNS
// propagation hold. Call it in a publish preflight, before any Cloudflare or
// machine configuration mutation.
func RequireMachinePublicationHostnameAvailable(ctx context.Context, db *sql.DB, hostname string) error {
	var releasedAt string
	err := db.QueryRowContext(ctx, `SELECT released_at FROM machine_publication_cooldowns WHERE hostname = ?`, normalizeHostname(hostname)).Scan(&releasedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up machine publication cooldown: %w", err)
	}
	released, err := time.Parse(time.RFC3339Nano, releasedAt)
	if err != nil {
		return fmt.Errorf("Machine publication hostname %q is waiting for DNS propagation", normalizeHostname(hostname))
	}
	remaining := MachinePublicationDNSPropagationCooldown - timeNow().Sub(released)
	if remaining > 0 {
		return fmt.Errorf("Machine publication hostname %q is waiting for DNS propagation; retry in %s", normalizeHostname(hostname), remaining.Round(time.Second))
	}
	return nil
}
