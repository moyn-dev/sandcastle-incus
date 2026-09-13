package tenant

import (
	"bufio"
	"fmt"
	"strings"
)

// The machine-side contract of a zone-mode machine (ADR-0027 §5.2–§5.4): the
// paths caddy-setup writes and the Auth App's reconciler reads or pushes.
const (
	// CaddySetupMarkerPath is the Caddy Setup Marker: shell-sourceable
	// KEY=value lines (MODE and FQDN) written last by caddy-setup, once the
	// Caddyfile and the unit drop-ins are in place for that FQDN. The
	// reconciler pushes a certificate only when the marker is present and
	// names the expected Machine Public Hostname.
	CaddySetupMarkerPath = "/etc/sandcastle/caddy.ready"
	// MachineTLSCertPath / MachineTLSKeyPath are where the machine's Caddy
	// reads its certificate and key in both Naming Modes: fetched from the
	// sidecar signer (private) or pushed by the Auth App (zone).
	MachineTLSCertPath = "/etc/sandcastle/tls/cert.pem"
	MachineTLSKeyPath  = "/etc/sandcastle/tls/key.pem"
	// CaddyZoneDropInPath is the systemd drop-in a zone-mode machine gets:
	// ConditionPathExists= on both TLS files, so a start before the first
	// push is skipped (exit 0, logged) rather than crash-looping.
	CaddyZoneDropInPath = "/etc/systemd/system/caddy.service.d/sandcastle-zone.conf"
)

// CaddySetupMarker is the parsed Caddy Setup Marker.
type CaddySetupMarker struct {
	// Mode is the Naming Mode caddy-setup configured ("private" or "zone").
	Mode string
	// FQDN is the site name the Caddyfile serves.
	FQDN string
}

// ParseCaddySetupMarker parses the marker's KEY=value lines. It is strict in
// the way the reconciler needs (spec §5.3): a MODE is required, and a line
// that is not KEY=value is an error — the reconciler treats any error as "no
// marker". Blank lines and #-comments are ignored; values are trimmed.
func ParseCaddySetupMarker(content string) (CaddySetupMarker, error) {
	var marker CaddySetupMarker
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return CaddySetupMarker{}, fmt.Errorf("caddy setup marker: malformed line %q", line)
		}
		switch strings.TrimSpace(key) {
		case "MODE":
			marker.Mode = strings.TrimSpace(value)
		case "FQDN":
			marker.FQDN = strings.TrimSpace(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return CaddySetupMarker{}, fmt.Errorf("caddy setup marker: %w", err)
	}
	if marker.Mode == "" {
		return CaddySetupMarker{}, fmt.Errorf("caddy setup marker: no MODE")
	}
	return marker, nil
}

// ReadyFor reports whether the marker clears the reconciler's push gate for
// publicHostname (spec §4.4 step 1): MODE=zone and an FQDN equal to the
// expected Machine Public Hostname (case-insensitive, trailing dot ignored).
// A private marker, or one naming another host, is "no marker".
func (m CaddySetupMarker) ReadyFor(publicHostname string) bool {
	if m.Mode != "zone" {
		return false
	}
	normalize := func(name string) string {
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	}
	want := normalize(publicHostname)
	return want != "" && normalize(m.FQDN) == want
}
