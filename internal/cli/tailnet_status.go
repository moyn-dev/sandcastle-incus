package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// `sc tailnet publish` only claims the name; the Auth App converges the DNS
// record, the certificate and the Machine Caddy site afterwards. The status
// below is what a caller of the published URL experiences: does the name
// resolve to the machine, is the certificate installed on the machine, and
// does the machine answer HTTPS for the name with a valid certificate.

const (
	tailnetDefaultWaitTimeout = 5 * time.Minute
	tailnetWaitInterval       = 3 * time.Second
	tailnetProbeTimeout       = 4 * time.Second
	tailnetPublicResolver     = "1.1.1.1:53"
)

// tailnetProber is the network seam of `sc tailnet status` and `publish
// --wait`; netTailnetProber in production, a stub in tests.
type tailnetProber interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	ProbeTLS(ctx context.Context, host string) tailnetTLSProbe
}

// tailnetTLSProbe is one HTTPS handshake against the published name.
type tailnetTLSProbe struct {
	// Reachable is false when no TCP connection to :443 could be made —
	// typically because this host is not on the Tenant Tailnet.
	Reachable bool `json:"reachable"`
	OK        bool `json:"ok"`
	// Status is the HTTP status of GET / over the verified connection; 0
	// when no response was read.
	Status   int       `json:"status,omitempty"`
	Issuer   string    `json:"issuer,omitempty"`
	NotAfter time.Time `json:"notAfter,omitempty"`
	// Staging marks a Let's Encrypt STAGING certificate (an install deployed
	// with --acme-directory staging, as the e2e is): valid for the name, but
	// no host trusts its issuer, so OK is judged without the chain.
	Staging bool   `json:"staging,omitempty"`
	Error   string `json:"error,omitempty"`
}

// letsEncryptStagingMark is in the issuer CN of every Let's Encrypt staging
// certificate ("(STAGING) …").
const letsEncryptStagingMark = "(STAGING)"

// netTailnetProber asks the zone's authoritative name servers before any
// caching resolver. A lookup through the local resolver before the record is
// served caches NXDOMAIN there for the zone's negative TTL (30 minutes on
// moyn.dev), so the name stays broken on this host long after it exists.
type netTailnetProber struct {
	lookupNS    func(ctx context.Context, zone string) ([]string, error)
	lookupAt    func(ctx context.Context, server string, host string) ([]string, error)
	lookupLocal func(ctx context.Context, host string) ([]string, error)
}

var errTailnetNameNotServed = errors.New("not served by the zone's name servers yet")

func newNetTailnetProber() netTailnetProber {
	public := resolverAt(tailnetPublicResolver)
	return netTailnetProber{
		lookupNS: func(ctx context.Context, zone string) ([]string, error) {
			records, err := public.LookupNS(ctx, zone)
			hosts := make([]string, 0, len(records))
			for _, record := range records {
				hosts = append(hosts, record.Host)
			}
			return hosts, err
		},
		lookupAt: func(ctx context.Context, server string, host string) ([]string, error) {
			return resolverAt(net.JoinHostPort(strings.TrimSuffix(server, "."), "53")).LookupHost(ctx, host)
		},
		lookupLocal: net.DefaultResolver.LookupHost,
	}
}

func resolverAt(address string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, address)
	}}
}

// LookupHost answers from the authoritative servers while the local resolver
// has not caught up, and never asks the local resolver before the record is
// served. Without known name servers it falls back to the local resolver and
// then a public one.
func (p netTailnetProber) LookupHost(ctx context.Context, host string) ([]string, error) {
	host = absoluteDNSName(host)
	if servers := p.authoritativeServers(ctx, host); len(servers) > 0 {
		var served []string
		for _, server := range servers {
			if addrs, err := p.lookupAt(ctx, server, host); err == nil && len(addrs) > 0 {
				served = addrs
				break
			}
		}
		if len(served) == 0 {
			return nil, errTailnetNameNotServed
		}
		if local, err := p.lookupLocal(ctx, host); err == nil && sameAddressSet(local, served) {
			return local, nil
		}
		return served, nil
	}
	addrs, err := p.lookupLocal(ctx, host)
	if err == nil && len(addrs) > 0 {
		return addrs, nil
	}
	if p.lookupAt != nil {
		if fresh, publicErr := p.lookupAt(ctx, strings.TrimSuffix(tailnetPublicResolver, ":53"), host); publicErr == nil && len(fresh) > 0 {
			return fresh, nil
		}
	}
	return addrs, err
}

// authoritativeServers returns the name servers of the deepest zone that
// publishes NS records above host, walking down from the registrable part.
func (p netTailnetProber) authoritativeServers(ctx context.Context, host string) []string {
	if p.lookupNS == nil || p.lookupAt == nil {
		return nil
	}
	var servers []string
	for _, zone := range dnsZoneCandidates(host) {
		ns, err := p.lookupNS(ctx, zone)
		if err != nil || len(ns) == 0 {
			break
		}
		servers = ns
	}
	return servers
}

// dnsZoneCandidates lists the parents of an absolute name from two labels
// down to its immediate parent: "a.b.moyn.dev." gives "moyn.dev." and
// "b.moyn.dev.".
func dnsZoneCandidates(host string) []string {
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	var zones []string
	for n := 2; n < len(labels); n++ {
		zones = append(zones, strings.Join(labels[len(labels)-n:], ".")+".")
	}
	return zones
}

func sameAddressSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, addr := range a {
		seen[addr]++
	}
	for _, addr := range b {
		if seen[addr] == 0 {
			return false
		}
		seen[addr]--
	}
	return true
}

// absoluteDNSName adds the root dot so the resolver never appends a search
// domain. A hotel network's wildcard search domain otherwise answered a
// not-yet-cached name with its own address, which looked like a real answer
// and skipped the public-resolver fallback.
func absoluteDNSName(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return host
	}
	return host + "."
}

func (p netTailnetProber) ProbeTLS(ctx context.Context, host string) tailnetTLSProbe {
	ctx, cancel := context.WithTimeout(ctx, tailnetProbeTimeout)
	defer cancel()
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return tailnetTLSProbe{Error: err.Error()}
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{ServerName: host})
	staging := false
	if err := conn.HandshakeContext(ctx); err != nil {
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			return tailnetTLSProbe{Reachable: true, Error: err.Error()}
		}
		// Untrusted issuer: accept it only for a Let's Encrypt staging leaf
		// that is valid for the name now; anything else stays an error.
		raw.Close()
		if raw, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443")); err != nil {
			return tailnetTLSProbe{Error: err.Error()}
		}
		defer raw.Close()
		conn = tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
			return verifyStagingLeaf(state, host, time.Now())
		}})
		if herr := conn.HandshakeContext(ctx); herr != nil {
			return tailnetTLSProbe{Reachable: true, Error: err.Error()}
		}
		staging = true
	}
	probe := tailnetTLSProbe{Reachable: true, OK: true, Staging: staging}
	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		probe.Issuer = certs[0].Issuer.CommonName
		if len(certs[0].Issuer.Organization) > 0 {
			probe.Issuer = certs[0].Issuer.Organization[0] + " " + probe.Issuer
		}
		probe.NotAfter = certs[0].NotAfter.UTC()
	}
	_ = conn.SetDeadline(time.Now().Add(tailnetProbeTimeout))
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: sc-tailnet-probe\r\nConnection: close\r\n\r\n", host); err == nil {
		if response, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
			probe.Status = response.StatusCode
			_ = response.Body.Close()
		}
	}
	return probe
}

// verifyStagingLeaf accepts a peer leaf issued by Let's Encrypt staging that
// is valid for host at now.
func verifyStagingLeaf(state tls.ConnectionState, host string, now time.Time) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("no peer certificate")
	}
	leaf := state.PeerCertificates[0]
	if !strings.Contains(leaf.Issuer.CommonName, letsEncryptStagingMark) {
		return fmt.Errorf("issuer %q is not Let's Encrypt staging", leaf.Issuer.CommonName)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("certificate is not valid now")
	}
	return leaf.VerifyHostname(host)
}

func tailnetProberFor(config commandConfig) tailnetProber {
	if config.tailnetProber != nil {
		return config.tailnetProber
	}
	return newNetTailnetProber()
}

// tailnetPublicationStatus is one published name as seen from this host.
type tailnetPublicationStatus struct {
	Hostname     string          `json:"hostname"`
	Machine      string          `json:"machine"`
	PrivateIP    string          `json:"privateIP,omitempty"`
	DNS          []string        `json:"dns,omitempty"`
	DNSReady     bool            `json:"dnsReady"`
	Certificate  string          `json:"certificate"`
	CertNotAfter string          `json:"certNotAfter,omitempty"`
	HTTPS        tailnetTLSProbe `json:"https"`
	Ready        bool            `json:"ready"`
}

// failed reports a certificate the Auth App gave up on; waiting longer does
// not help.
func (s tailnetPublicationStatus) failed() bool {
	return strings.HasPrefix(s.Certificate, "failed")
}

func (s tailnetPublicationStatus) dnsText() string {
	switch {
	case s.DNSReady:
		return strings.Join(s.DNS, ",")
	case len(s.DNS) > 0:
		return strings.Join(s.DNS, ",") + " (want " + s.PrivateIP + ")"
	default:
		return "not resolving"
	}
}

func (s tailnetPublicationStatus) certText() string {
	if s.Certificate == "installed" && s.CertNotAfter != "" {
		if expiry, err := time.Parse(time.RFC3339, s.CertNotAfter); err == nil {
			return "installed, until " + expiry.Format("2006-01-02")
		}
	}
	return s.Certificate
}

func (s tailnetPublicationStatus) httpsText() string {
	switch {
	case !s.DNSReady:
		return "-"
	case s.HTTPS.OK && s.HTTPS.Staging && s.HTTPS.Status != 0:
		return fmt.Sprintf("ok (%d, Let's Encrypt staging certificate)", s.HTTPS.Status)
	case s.HTTPS.OK && s.HTTPS.Staging:
		return "ok (Let's Encrypt staging certificate)"
	case s.HTTPS.OK && s.HTTPS.Status != 0:
		return fmt.Sprintf("ok (%d)", s.HTTPS.Status)
	case s.HTTPS.OK:
		return "ok"
	case !s.HTTPS.Reachable:
		return "not reachable from this host"
	default:
		return "error: " + s.HTTPS.Error
	}
}

// summary is the one-line progress form used by --wait.
func (s tailnetPublicationStatus) summary() string {
	return fmt.Sprintf("DNS %s · certificate %s · HTTPS %s", s.dnsText(), orDash(s.certText()), s.httpsText())
}

// probeTailnetPublication evaluates one name of one machine. Ready means a
// caller on the Tailnet gets a working HTTPS site: the name resolves to the
// machine, its certificate is installed, and the machine does not answer
// HTTPS with an error. An unreachable :443 does not block readiness — the
// CLI host is often not on the Tenant Tailnet itself.
func probeTailnetPublication(ctx context.Context, prober tailnetProber, machine meta.Machine, hostname string) tailnetPublicationStatus {
	status := tailnetPublicationStatus{
		Hostname:  hostname,
		Machine:   machine.Project + ":" + machine.Name,
		PrivateIP: machine.PrivateIP,
	}
	status.Certificate = machine.CertStateOf(hostname)
	if status.Certificate == "installed" {
		status.CertNotAfter = machine.CertNotAfter
	}
	if addrs, err := prober.LookupHost(ctx, hostname); err == nil {
		sort.Strings(addrs)
		status.DNS = addrs
		for _, addr := range addrs {
			if machine.PrivateIP == "" || addr == machine.PrivateIP {
				status.DNSReady = true
			}
		}
	}
	if status.DNSReady {
		status.HTTPS = prober.ProbeTLS(ctx, hostname)
	}
	status.Ready = status.DNSReady && status.Certificate == "installed" && (status.HTTPS.OK || !status.HTTPS.Reachable)
	return status
}

// findTailnetMachine re-reads one machine from Incus, so every poll sees the
// reconciler's latest cert-state mirror.
func findTailnetMachine(ctx context.Context, config commandConfig, summary tenant.Summary, project, name string) (meta.Machine, error) {
	if config.machineStore == nil {
		return meta.Machine{}, errors.New("no machine store configured")
	}
	machines, err := listMachinesScoped(ctx, config.machineStore, summary, project)
	if err != nil {
		return meta.Machine{}, err
	}
	for _, candidate := range machines {
		if candidate.Project == project && candidate.Name == name {
			return candidate, nil
		}
	}
	return meta.Machine{}, fmt.Errorf("machine %s:%s not found", project, name)
}

// tailnetReadyPolls is how many consecutive polls must see the name ready.
// A re-claim makes the reconciler rewrite DNS and reload Caddy, so a single
// ready poll can be the state from before that pass.
const tailnetReadyPolls = 2

// waitForTailnetPublication polls until the name is ready on
// tailnetReadyPolls consecutive polls, the certificate failed, or the
// timeout passes. Progress goes to stderr, one line per change.
func waitForTailnetPublication(ctx context.Context, config commandConfig, summary tenant.Summary, project, machine, hostname string, timeout time.Duration) (tailnetPublicationStatus, error) {
	prober := tailnetProberFor(config)
	interval := config.tailnetWaitInterval
	if interval <= 0 {
		interval = tailnetWaitInterval
	}
	start := time.Now()
	deadline := start.Add(timeout)
	last := ""
	readyPolls := 0
	for {
		var status tailnetPublicationStatus
		current, err := findTailnetMachine(ctx, config, summary, project, machine)
		if err != nil {
			return status, err
		}
		status = probeTailnetPublication(ctx, prober, current, hostname)
		if line := status.summary(); line != last {
			fmt.Fprintf(config.stderr, "tailnet: %s: %s\n", hostname, line)
			last = line
		}
		if status.Ready {
			readyPolls++
		} else {
			readyPolls = 0
		}
		switch {
		case readyPolls >= tailnetReadyPolls:
			fmt.Fprintf(config.stderr, "tailnet: %s ready after %s\n", hostname, time.Since(start).Round(time.Second))
			return status, nil
		case status.failed():
			return status, fmt.Errorf("certificate for %s %s; see sc tailnet status %s:%s", hostname, status.Certificate, project, machine)
		case time.Now().Add(interval).After(deadline):
			return status, fmt.Errorf("timed out after %s waiting for https://%s (%s); the Auth App keeps converging, check with: sc tailnet status %s:%s", timeout, hostname, status.summary(), project, machine)
		}
		select {
		case <-ctx.Done():
			return status, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// tailnetHostHint warns when the app inside the machine turns the new name
// away: after publication it receives the public name in its Host header,
// and frameworks with a host allowlist answer 400/403/421 until the name is
// added there. The TLS probe cannot see the app when this host is not on
// the Tailnet, so that case gets the reminder unconditionally.
func tailnetHostHint(w io.Writer, status tailnetPublicationStatus) {
	switch {
	case !status.HTTPS.Reachable:
		fmt.Fprintf(w, "tailnet: the app behind Caddy now receives Host: %s; if it keeps a host allowlist (Vite server.allowedHosts, Django ALLOWED_HOSTS, …), add the name there\n", status.Hostname)
	case status.HTTPS.Status == http.StatusBadRequest || status.HTTPS.Status == http.StatusForbidden || status.HTTPS.Status == http.StatusMisdirectedRequest:
		fmt.Fprintf(w, "tailnet: warning: the app answers %d for Host: %s — it probably rejects unknown hostnames; add the name to its host allowlist (Vite server.allowedHosts, Django ALLOWED_HOSTS, …)\n", status.HTTPS.Status, status.Hostname)
	}
}

func newTailnetStatusCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:     "status [[remote:]project:]machine",
		Aliases: []string{"ls", "list"},
		Short:   "Show Tailnet publications and whether DNS, certificate and HTTPS are ready",
		Long: `Show every Tailnet publication of a machine, or of all machines in the
tenant when no machine is given, with its DNS answer, the certificate state
the Auth App mirrored onto the machine, and an HTTPS probe from this host.
"not reachable from this host" usually means this host is not on the Tenant
Tailnet; it does not make the publication unready.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bound := config
			var machines []meta.Machine
			if len(args) == 1 {
				var reference string
				var restore func()
				var err error
				bound, reference, restore, err = rebindForReference(config, args[0])
				if err != nil {
					return err
				}
				defer restore()
				summary, project, name, err := hostnameTarget(cmd.Context(), bound, reference)
				if err != nil {
					return err
				}
				found, err := findTailnetMachine(cmd.Context(), bound, summary, project, name)
				if err != nil {
					return err
				}
				machines = []meta.Machine{found}
			} else {
				summary, err := requireV2Tenant(cmd.Context(), bound)
				if err != nil {
					return err
				}
				if bound.machineStore == nil {
					return errors.New("no machine store configured")
				}
				machines, err = listMachinesScoped(cmd.Context(), bound.machineStore, summary, "")
				if err != nil {
					return err
				}
			}
			statuses := probeTailnetMachines(cmd.Context(), tailnetProberFor(bound), machines)
			return writeOutput(bound.stdout, opts.output, formatTailnetStatuses(statuses), statuses)
		},
	}
	return command
}

// probeTailnetMachines probes every published name concurrently; the order
// of the result is machine, then hostname.
func probeTailnetMachines(ctx context.Context, prober tailnetProber, machines []meta.Machine) []tailnetPublicationStatus {
	type job struct {
		machine  meta.Machine
		hostname string
	}
	var jobs []job
	for _, machine := range machines {
		for _, hostname := range machine.TailnetPublications {
			jobs = append(jobs, job{machine: machine, hostname: hostname})
		}
	}
	statuses := make([]tailnetPublicationStatus, len(jobs))
	var group sync.WaitGroup
	for i, j := range jobs {
		group.Add(1)
		go func() {
			defer group.Done()
			statuses[i] = probeTailnetPublication(ctx, prober, j.machine, j.hostname)
		}()
	}
	group.Wait()
	sort.SliceStable(statuses, func(a, b int) bool {
		if statuses[a].Machine != statuses[b].Machine {
			return statuses[a].Machine < statuses[b].Machine
		}
		return statuses[a].Hostname < statuses[b].Hostname
	})
	return statuses
}

func formatTailnetStatuses(statuses []tailnetPublicationStatus) string {
	if len(statuses) == 0 {
		return "No Tailnet publications."
	}
	table := [][]string{{"HOSTNAME", "MACHINE", "DNS", "CERTIFICATE", "HTTPS", "READY"}}
	for _, s := range statuses {
		ready := "no"
		if s.Ready {
			ready = "yes"
		}
		table = append(table, []string{s.Hostname, s.Machine, s.dnsText(), orDash(s.certText()), s.httpsText(), ready})
	}
	return strings.TrimRight(formatAlignedTable(table), "\n")
}
