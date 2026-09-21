package tenant

import (
	"bufio"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The machine-side contract (ADR-0028, spec machine-hostnames §6): the paths
// caddy-setup writes and the Auth App's reconciler reads or pushes. Every
// machine keeps its Machine Private Hostname (Tenant CA leaf at the fixed
// /etc/sandcastle/tls paths) and additionally serves one Caddy site block per
// Machine Public Hostname, each against its own certificate directory.
const (
	// CaddySetupMarkerPath is the Caddy Setup Marker: KEY=value lines written
	// LAST by caddy-setup (and rewritten by every --refresh) once the
	// Caddyfile is in place — PRIVATE=<fqdn>, one PUBLIC=<host> per public
	// site block actually rendered, RENDERED=<unix ts>. Its presence tells
	// the reconciler the machine runs the per-name contract and will honour
	// a per-hostname certificate push followed by --refresh.
	CaddySetupMarkerPath = "/etc/sandcastle/caddy.ready"
	// MachineHostnamesPath lists the machine's Machine Public Hostnames, one
	// per line: seeded at first boot from PUBLIC_HOSTNAMES= in machine.env,
	// pushed whole by the Auth App's reconciler whenever the set changes.
	MachineProjectDomainPath = "/etc/sandcastle/project-domain"
	MachineHostnamesPath     = "/etc/sandcastle/hostnames"
	// MachineTLSDir holds the private leaf (cert.pem/key.pem, from the
	// sidecar signer) and one <hostname>/ directory per public name.
	MachineTLSDir = "/etc/sandcastle/tls"
	// MachineTLSCertPath / MachineTLSKeyPath are the PRIVATE leaf — the
	// Tenant CA certificate for the Machine Private Hostname, fetched from
	// the sidecar signer by caddy-setup. Never a public certificate.
	MachineTLSCertPath = MachineTLSDir + "/cert.pem"
	MachineTLSKeyPath  = MachineTLSDir + "/key.pem"
	// MachineEnvPath is the per-machine environment caddy-setup sources
	// (FQDN, PUBLIC_HOSTNAMES, SIGNER, HOME), baked by cloud-init.
	MachineEnvPath = "/etc/sandcastle/machine.env"
	// CaddySetupCommand is the boot shim every machine carries; with
	// CaddySetupRefreshFlag it re-reads the hostnames file and the per-host
	// certificate directories, re-renders the Caddyfile and reloads Caddy.
	CaddySetupCommand     = "/usr/local/sbin/sandcastle-caddy-setup"
	CaddySetupRefreshFlag = "--refresh"
)

// MachineTLSHostDir is the certificate directory of one Machine Public
// Hostname: /etc/sandcastle/tls/<hostname>/. The name is normalized (lower
// case, no trailing dot) so the reconciler and caddy-setup agree on the path.
func MachineTLSHostDir(hostname string) string {
	return MachineTLSDir + "/" + NormalizePublicHostname(hostname)
}

// MachineTLSHostCertPath / MachineTLSHostKeyPath are the certificate chain and
// key of one Machine Public Hostname, as caddy-setup's site block reads them.
func MachineTLSHostCertPath(hostname string) string { return MachineTLSHostDir(hostname) + "/cert.pem" }
func MachineTLSHostKeyPath(hostname string) string  { return MachineTLSHostDir(hostname) + "/key.pem" }

// NormalizePublicHostname is the one normalization the machine contract
// applies to a hostname: trimmed, lower case, no trailing dot.
func NormalizePublicHostname(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// FormatMachineHostnamesFile renders the /etc/sandcastle/hostnames content
// for a set of Machine Public Hostnames: one normalized name per line,
// sorted, deduplicated, empty names dropped. An empty set renders an empty
// file (a file that exists and is empty means "no public name", which is
// distinct from "never seeded").
func FormatMachineHostnamesFile(names []string) string {
	seen := map[string]bool{}
	var out []string
	for _, name := range names {
		if name = NormalizePublicHostname(name); name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// CaddySetupMarker is the parsed Caddy Setup Marker.
type CaddySetupMarker struct {
	// Private is the Machine Private Hostname the private site block serves.
	Private string
	// Public lists the Machine Public Hostnames caddy-setup rendered a site
	// block for — those whose certificate directory held both files at
	// render time. Sorted, normalized.
	Public []string
	// Rendered is when the marker was written (RENDERED=<unix ts>); zero
	// when the line is absent.
	Rendered time.Time
	// LegacyMode / LegacyFQDN are set for an ADR-0027 marker (MODE=/FQDN=):
	// a machine whose caddy-setup predates the per-name contract. Such a
	// marker never clears the push gate — the machine has no per-hostname
	// directory and no --refresh; it converges once its payload is synced
	// and caddy-setup re-runs (a recreate).
	LegacyMode string
	LegacyFQDN string
}

// ParseCaddySetupMarker parses the marker's KEY=value lines. A line that is
// not KEY=value is an error, as is a marker naming neither PRIVATE= (per-name
// contract) nor MODE= (legacy) — the reconciler treats any error as "no
// marker". Blank lines and #-comments are ignored; values are trimmed and
// hostnames normalized.
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
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "PRIVATE":
			marker.Private = NormalizePublicHostname(value)
		case "PUBLIC":
			if name := NormalizePublicHostname(value); name != "" {
				marker.Public = append(marker.Public, name)
			}
		case "RENDERED":
			if ts, err := strconv.ParseInt(value, 10, 64); err == nil && ts > 0 {
				marker.Rendered = time.Unix(ts, 0).UTC()
			}
		case "MODE":
			marker.LegacyMode = value
		case "FQDN":
			marker.LegacyFQDN = NormalizePublicHostname(value)
		}
	}
	if err := scanner.Err(); err != nil {
		return CaddySetupMarker{}, fmt.Errorf("caddy setup marker: %w", err)
	}
	if marker.Private == "" && marker.LegacyMode == "" {
		return CaddySetupMarker{}, fmt.Errorf("caddy setup marker: no PRIVATE (nor legacy MODE)")
	}
	sort.Strings(marker.Public)
	return marker, nil
}

// Legacy reports an ADR-0027 marker (MODE=/FQDN=, no PRIVATE=).
func (m CaddySetupMarker) Legacy() bool { return m.Private == "" }

// ReadyFor reports whether the marker clears the reconciler's push gate for
// publicHostname: the machine runs the per-name contract (a PRIVATE= marker
// exists, so caddy-setup --refresh is available and a certificate pushed to
// the hostname's directory will be rendered on the next refresh). The
// hostname need not be rendered yet — before its first push it cannot be.
// A legacy marker, whatever it names, is "no marker".
func (m CaddySetupMarker) ReadyFor(publicHostname string) bool {
	return !m.Legacy() && NormalizePublicHostname(publicHostname) != ""
}

// Serves reports whether caddy-setup rendered a site block for the name at
// the last render: the private name, or a public name whose certificate
// directory was complete.
func (m CaddySetupMarker) Serves(hostname string) bool {
	want := NormalizePublicHostname(hostname)
	if want == "" {
		return false
	}
	if want == m.Private {
		return true
	}
	for _, name := range m.Public {
		if name == want {
			return true
		}
	}
	return false
}

// String summarizes the marker for a log line.
func (m CaddySetupMarker) String() string {
	if m.Legacy() {
		return "MODE=" + m.LegacyMode + " FQDN=" + m.LegacyFQDN + " (legacy)"
	}
	public := "-"
	if len(m.Public) > 0 {
		public = strings.Join(m.Public, ",")
	}
	return "PRIVATE=" + m.Private + " PUBLIC=" + public
}
