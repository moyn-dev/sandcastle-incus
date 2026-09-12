package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// ---------------------------------------------------------------------------
// Public DNS Zones — the zone reconciler (ADR-0027, spec §4, slice 6)
//
// The ADR-0018 DNS pass (30s ticker + instance lifecycle events) gains a zone
// stage: for every zone-mode Machine of the install it keeps the public A
// records (base + wildcard) in Cloudflare, orders and renews the Machine
// Certificate through the certIssuer on the row's own schedule (ARI window,
// persisted backoff), pushes cert + key into the Machine once its Caddy Setup
// Marker names the expected hostname, re-pushes on fingerprint drift, and
// mirrors the derived state into instance config so `sc ls` renders it from
// the cache and the live path alike. Every per-Machine error is collected with
// errors.Join; a pass never fails as a whole.
//
// The Incus side is behind ZoneMachineServer (implemented in incusx, which
// imports this package — not the other way round); the DNS side behind a
// libdns provider factory; the ACME side behind certIssuer. Unit tests run
// the whole pass against fakes.
// ---------------------------------------------------------------------------

// ZoneMachine is one instance of an app project as the zone reconciler sees
// it: its Naming Mode record and certificate mirror as currently stamped, its
// project's Incus domain key, and its live state.
type ZoneMachine struct {
	Tenant       string
	Project      string // short project name
	IncusProject string // full Incus project name
	Name         string
	// ProjectDomain is the project's KeyV2Domain ("" for a private project).
	ProjectDomain string
	// PublicHostname is the instance's raw KeyV2PublicHostname: "" when
	// unstamped, meta.NamingModePrivate, or the Machine Public Hostname.
	PublicHostname string
	// BridgeIPv4 is the tenant-bridge address ("" when stopped / no lease).
	BridgeIPv4 string
	Running    bool
	// CertState / CertNotAfter are the current KeyV2CertState /
	// KeyV2CertNotAfter values, compared before mirroring.
	CertState    string
	CertNotAfter string
}

// ErrInstanceFileNotFound is what ZoneMachineServer.ReadInstanceFile returns
// when the instance is reachable but the file does not exist — the drift
// check treats that as "re-push", unlike an unreachable instance (skip).
var ErrInstanceFileNotFound = errors.New("instance file not found")

// ZoneMachineServer is the Incus seam of the zone reconciler.
type ZoneMachineServer interface {
	// ListZoneMachines returns every instance of every app project of the
	// install (prefix-scoped), with the project's domain key.
	ListZoneMachines(ctx context.Context) ([]ZoneMachine, error)
	// StampInstanceConfig merges config into the instance's own config.
	StampInstanceConfig(ctx context.Context, incusProject, name string, config map[string]string) error
	// ReadInstanceFile returns a file's content; ErrInstanceFileNotFound when
	// the instance answered but has no such file.
	ReadInstanceFile(ctx context.Context, incusProject, name, path string) (string, error)
	// PushMachineCertificate writes cert.pem.new / key.pem.new and runs the
	// one mv + reload exec (spec §4.4); start adds `systemctl start caddy`
	// for the first push.
	PushMachineCertificate(ctx context.Context, incusProject, name, certPEM, keyPEM string, start bool) error
}

// zoneDNSProvider is the slice of libdns the reconciler uses: read a zone,
// set A records, delete A/TXT records.
type zoneDNSProvider interface {
	libdns.RecordGetter
	libdns.RecordSetter
	libdns.RecordDeleter
}

// newZoneDNSProvider builds the libdns provider for a zone token — the same
// libdns/cloudflare client the DNS-01 solver uses. Tests replace it.
var newZoneDNSProvider = func(token string) zoneDNSProvider {
	return &cloudflare.Provider{APIToken: token}
}

// Zone reconciler tunables (spec §4.2, §4.3).
const (
	zoneRecordTTL          = 60 * time.Second
	zoneMaxConcurrentOrder = 4
	zoneARIDefaultRetry    = 6 * time.Hour
	acmeChallengeLabel     = "_acme-challenge"
)

// certOrderBackoff is the persisted exponential backoff between order
// attempts, indexed by min(attempts-1, len-1). A rate-limit answer jumps to
// the last step.
var certOrderBackoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour}

// zoneReconciler runs the zone stage. Passes are serialized; orders run in
// goroutines that outlive the pass and hold a per-hostname lock.
type zoneReconciler struct {
	db        *sql.DB
	machines  ZoneMachineServer
	issuer    certIssuer
	directory string
	providers func(token string) zoneDNSProvider
	logf      func(level, format string, args ...any)
	now       func() time.Time
	// kick, when set, asks the loop for another pass soon (an order finished:
	// the push should not wait for the ticker).
	kick func()

	mu sync.Mutex // serializes passes

	inflightMu sync.Mutex
	inflight   map[string]struct{}
	orders     sync.WaitGroup

	loggedMu       sync.Mutex
	markerLogged   map[string]struct{}
	skippedLogged  map[string]struct{}
	providerByZone map[string]zoneDNSProvider
}

func newZoneReconciler(db *sql.DB, machines ZoneMachineServer, issuer certIssuer, directory string, logf func(level, format string, args ...any)) *zoneReconciler {
	if logf == nil {
		logf = func(string, string, ...any) {}
	}
	return &zoneReconciler{
		db:             db,
		machines:       machines,
		issuer:         issuer,
		directory:      directory,
		providers:      func(token string) zoneDNSProvider { return newZoneDNSProvider(token) },
		logf:           logf,
		now:            time.Now,
		inflight:       map[string]struct{}{},
		markerLogged:   map[string]struct{}{},
		skippedLogged:  map[string]struct{}{},
		providerByZone: map[string]zoneDNSProvider{},
	}
}

// zoneTarget is a zone-mode Machine whose project holds a claimed domain —
// the unit of work of the pass.
type zoneTarget struct {
	machine  ZoneMachine
	hostname string
	claim    ProjectDomainClaim
}

// orderCandidate is a target whose row says an order is due.
type orderCandidate struct {
	target zoneTarget
	due    time.Time
}

// Reconcile runs one pass (spec §4.1–§4.7). It returns the joined per-Machine
// errors; only a listing failure aborts the pass.
func (r *zoneReconciler) Reconcile(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.db == nil || r.machines == nil {
		return nil
	}
	now := r.now().UTC()
	machines, err := r.machines.ListZoneMachines(ctx)
	if err != nil {
		return fmt.Errorf("list machines for zone reconcile: %w", err)
	}
	if len(machines) == 0 {
		// An empty fleet is never trusted (same guard as the claim GC): no
		// records are deleted and no rows are dropped on a listing hiccup.
		return nil
	}
	claims, err := ListProjectDomainClaims(ctx, r.db)
	if err != nil {
		return fmt.Errorf("list project domain claims for zone reconcile: %w", err)
	}
	claimByProject := make(map[string]ProjectDomainClaim, len(claims))
	for _, c := range claims {
		claimByProject[c.Tenant+"/"+c.Project] = c
	}
	// A fresh provider per pass and zone: a rotated token is picked up on the
	// next pass, and the libdns/cloudflare zone-id cache lives one pass.
	r.providerByZone = map[string]zoneDNSProvider{}

	var errs []error
	var targets []zoneTarget
	for _, m := range machines {
		target, ok, err := r.classify(ctx, m, claimByProject)
		if err != nil {
			errs = append(errs, err)
		}
		if ok {
			targets = append(targets, target)
		}
	}

	// Public A records: one Cloudflare read per zone per pass (§4.2).
	byZone := map[string][]zoneTarget{}
	for _, t := range targets {
		byZone[t.claim.Zone] = append(byZone[t.claim.Zone], t)
	}
	zones := make([]string, 0, len(byZone))
	for zone := range byZone {
		zones = append(zones, zone)
	}
	sort.Strings(zones)
	for _, zone := range zones {
		if err := r.reconcileZoneRecords(ctx, zone, byZone[zone], claims); err != nil {
			errs = append(errs, err)
		}
	}

	// Certificates: rows, ARI, drift, push, mirror; collect due orders.
	var candidates []orderCandidate
	liveHostnames := map[string]struct{}{}
	for _, t := range targets {
		liveHostnames[t.hostname] = struct{}{}
		candidate, err := r.reconcileTargetCertificate(ctx, t, now)
		if err != nil {
			errs = append(errs, err)
		}
		if candidate != nil {
			candidates = append(candidates, *candidate)
		}
	}
	r.scheduleOrders(ctx, candidates)

	if err := r.gcMachineCertificates(ctx, liveHostnames, now); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// classify stamps the Naming Mode record on first sight (§1.1, §4.1) and
// decides whether the Machine is a zone target: stamped with a Machine Public
// Hostname under its project's claimed domain.
func (r *zoneReconciler) classify(ctx context.Context, m ZoneMachine, claimByProject map[string]ProjectDomainClaim) (zoneTarget, bool, error) {
	projectDomain := strings.ToLower(strings.TrimSpace(m.ProjectDomain))
	claim, claimed := claimByProject[m.Tenant+"/"+m.Project]
	if claimed && projectDomain != "" && claim.Domain != projectDomain {
		// The Incus key and the claim disagree (a set-domain whose Incus
		// write failed half-way): the claim is the truth for records and
		// certificates, but nothing is stamped until they agree.
		r.logOnce(r.skippedLogged, m.IncusProject+"/"+m.Name+"/mismatch/"+projectDomain, "WARN",
			"zone reconcile: project %s/%s carries domain %q but its claim is %q; machines skipped until they agree",
			m.Tenant, m.Project, projectDomain, claim.Domain)
		claimed = false
	}
	stamp := strings.ToLower(strings.TrimSpace(m.PublicHostname))
	if stamp == "" {
		switch {
		case claimed:
			// Freeform Machine in a zone project: stamped on first sight,
			// never rewritten.
			stamp = strings.ToLower(m.Name) + "." + claim.Domain
		case projectDomain == "":
			stamp = meta.NamingModePrivate
		default:
			// KeyV2Domain without a claim (§4.6): logged by the claim GC,
			// treated as private for DNS and certificates — but not stamped,
			// since the stamp is irreversible and the project may still be
			// repaired by its tenant.
			return zoneTarget{}, false, nil
		}
		if err := r.machines.StampInstanceConfig(ctx, m.IncusProject, m.Name, map[string]string{meta.KeyV2PublicHostname: stamp}); err != nil {
			return zoneTarget{}, false, fmt.Errorf("stamp naming mode on %s/%s: %w", m.IncusProject, m.Name, err)
		}
		r.logf("INFO", "zone reconcile: stamped %s/%s %s=%s", m.IncusProject, m.Name, meta.KeyV2PublicHostname, stamp)
		m.PublicHostname = stamp
	}
	if stamp == meta.NamingModePrivate {
		return zoneTarget{}, false, nil
	}
	if !claimed {
		r.logOnce(r.skippedLogged, m.IncusProject+"/"+m.Name+"/unclaimed/"+stamp, "WARN",
			"zone reconcile: %s/%s has public name %s but project %s/%s has no claimed domain; no records, no certificate",
			m.IncusProject, m.Name, stamp, m.Tenant, m.Project)
		return zoneTarget{}, false, nil
	}
	if !strings.HasSuffix(stamp, "."+claim.Domain) {
		r.logOnce(r.skippedLogged, m.IncusProject+"/"+m.Name+"/foreign/"+stamp, "WARN",
			"zone reconcile: %s/%s has public name %s outside project domain %s; skipped",
			m.IncusProject, m.Name, stamp, claim.Domain)
		return zoneTarget{}, false, nil
	}
	return zoneTarget{machine: m, hostname: stamp, claim: claim}, true, nil
}

// provider returns the pass's libdns provider for a zone, built from the
// zone's decrypted token on first use.
func (r *zoneReconciler) provider(ctx context.Context, zone string) (zoneDNSProvider, error) {
	if p, ok := r.providerByZone[zone]; ok {
		return p, nil
	}
	token, err := PublicDNSZoneToken(ctx, r.db, zone)
	if err != nil {
		return nil, fmt.Errorf("zone %s token: %w", zone, err)
	}
	p := r.providers(token)
	r.providerByZone[zone] = p
	return p, nil
}

// libdnsZone is the zone name in libdns' conventional form (trailing dot),
// the same shape certmagic hands the provider.
func libdnsZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".") + "."
}

// desiredZoneRecords are the A records a set of zone targets needs (§4.2):
// base + wildcard per Machine with a bridge address, relative to the zone.
// keep lists every live Machine's relative name, address or not, so a stopped
// Machine's records survive.
func desiredZoneRecords(zone string, targets []zoneTarget) (want map[string]netip.Addr, keep map[string]struct{}) {
	want = map[string]netip.Addr{}
	keep = map[string]struct{}{}
	for _, t := range targets {
		rel := libdns.RelativeName(t.hostname, zone)
		keep[rel] = struct{}{}
		ip, err := netip.ParseAddr(strings.TrimSpace(t.machine.BridgeIPv4))
		if err != nil || !ip.Is4() {
			continue
		}
		want[rel] = ip
		want["*."+rel] = ip
	}
	return want, keep
}

// machineRelativeName strips a leading wildcard label so both records of a
// Machine map onto its relative name.
func machineRelativeName(name string) string {
	return strings.TrimPrefix(name, "*.")
}

// reconcileZoneRecords converges the A records of every claimed domain in
// zone: missing/changed → SetRecords, records under a claimed domain with no
// live Machine → DeleteRecords (covers deleted and out-of-band removed
// Machines). Exactly one GetRecords per zone per pass.
func (r *zoneReconciler) reconcileZoneRecords(ctx context.Context, zone string, targets []zoneTarget, claims []ProjectDomainClaim) error {
	provider, err := r.provider(ctx, zone)
	if err != nil {
		return err
	}
	lz := libdnsZone(zone)
	actual, err := provider.GetRecords(ctx, lz)
	if err != nil {
		return fmt.Errorf("zone %s: list records: %w", zone, err)
	}
	want, keep := desiredZoneRecords(lz, targets)
	var domainSuffixes []string
	for _, c := range claims {
		if c.Zone == zone {
			domainSuffixes = append(domainSuffixes, "."+libdns.RelativeName(c.Domain, lz))
		}
	}
	underClaimedDomain := func(name string) bool {
		for _, suffix := range domainSuffixes {
			if strings.HasSuffix(name, suffix) {
				return true
			}
		}
		return false
	}

	present := map[string]netip.Addr{}
	var stale []libdns.Record
	for _, rec := range actual {
		addr, ok := rec.(libdns.Address)
		if !ok || !addr.IP.Is4() {
			continue
		}
		if _, wanted := want[addr.Name]; wanted {
			present[addr.Name] = addr.IP
			continue
		}
		if !underClaimedDomain(addr.Name) {
			continue
		}
		if _, live := keep[machineRelativeName(addr.Name)]; live {
			continue // stopped Machine: records stay
		}
		stale = append(stale, addr)
	}
	var set []libdns.Record
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if got, ok := present[name]; ok && got == want[name] {
			continue
		}
		set = append(set, libdns.Address{Name: name, TTL: zoneRecordTTL, IP: want[name]})
	}
	var errs []error
	if len(set) > 0 {
		if _, err := provider.SetRecords(ctx, lz, set); err != nil {
			errs = append(errs, fmt.Errorf("zone %s: set %d A record(s): %w", zone, len(set), err))
		} else {
			r.logf("INFO", "zone reconcile: zone %s: set %d A record(s)", zone, len(set))
		}
	}
	if len(stale) > 0 {
		if _, err := provider.DeleteRecords(ctx, lz, stale); err != nil {
			errs = append(errs, fmt.Errorf("zone %s: delete %d stale A record(s): %w", zone, len(stale), err))
		} else {
			r.logf("INFO", "zone reconcile: zone %s: deleted %d stale A record(s)", zone, len(stale))
		}
	}
	return errors.Join(errs...)
}

// reconcileTargetCertificate does the per-Machine certificate work of a pass
// (§4.3–§4.5, §4.7): create the row for a marker-bearing Freeform Machine,
// reset a row from another directory, refresh ARI, detect drift, push, and
// mirror the derived state. It returns a candidate when an order is due.
func (r *zoneReconciler) reconcileTargetCertificate(ctx context.Context, t zoneTarget, now time.Time) (*orderCandidate, error) {
	m := t.machine
	row, err := getMachineCertificate(ctx, r.db, t.hostname)
	hasRow := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%s: read certificate row: %w", t.hostname, err)
	}
	if !hasRow {
		// Rows come from sc create, or from the reconciler for a Freeform /
		// --bare Machine that carries the marker (§4.3). No marker, no row:
		// a Dev Image Machine never orders.
		ready, _ := r.markerReady(ctx, t)
		if !ready {
			return nil, r.mirror(ctx, m, machineCertStatePending, "")
		}
		row, err = requestMachineCertificate(ctx, r.db, machineCertificateRequest{
			Hostname: t.hostname, Tenant: m.Tenant, Project: m.Project, Machine: m.Name,
			Zone: t.claim.Zone, DirectoryURL: r.directory,
		}, now)
		if err != nil {
			return nil, fmt.Errorf("%s: create certificate row: %w", t.hostname, err)
		}
		r.logf("INFO", "zone reconcile: %s: certificate row created for %s/%s", t.hostname, m.IncusProject, m.Name)
	}
	var errs []error
	// The first push also starts Caddy (enabled-inactive until now); a drift
	// re-push clears pushed_serial below, so decide before that.
	firstPush := row.PushedSerial == ""
	if row.hasCertificate() && row.DirectoryURL != r.directory {
		// Staging and production never mix (§3.5): re-order under the
		// running directory.
		if row, err = resetMachineCertificate(ctx, r.db, row.Hostname, r.directory, now); err != nil {
			return nil, fmt.Errorf("%s: reset certificate row for directory change: %w", t.hostname, err)
		}
		r.logf("INFO", "zone reconcile: %s: certificate issued by %s, running %s; re-ordering", t.hostname, row.DirectoryURL, r.directory)
	}
	if row.usable(r.directory, now) && !row.ARICheckAfter.IsZero() && !now.Before(row.ARICheckAfter) {
		if updated, err := r.refreshARI(ctx, row, now); err != nil {
			errs = append(errs, err)
		} else {
			row = updated
		}
	}
	if m.Running && row.hasCertificate() && row.Serial != "" && row.PushedSerial == row.Serial {
		drifted, err := r.driftCheck(ctx, t, row)
		if err != nil {
			errs = append(errs, err)
		} else if drifted {
			if row, err = setMachineCertificatePushedSerial(ctx, r.db, row.Hostname, "", now); err != nil {
				errs = append(errs, fmt.Errorf("%s: record drift: %w", t.hostname, err))
			} else {
				r.logf("WARN", "zone reconcile: %s: certificate on %s/%s differs from the issued one; re-pushing", t.hostname, m.IncusProject, m.Name)
			}
		}
	}
	if m.Running && row.usable(r.directory, now) && row.PushedSerial != row.Serial {
		if pushed, err := r.push(ctx, t, row, firstPush, now); err != nil {
			errs = append(errs, err)
		} else if pushed {
			row.PushedSerial = row.Serial
		}
	}
	state := machineCertificateState(row, r.directory, now)
	notAfter := ""
	if row.hasCertificate() && row.PushedSerial == row.Serial {
		notAfter = formatCertTime(row.NotAfter)
	} else if state == machineCertStateIssued {
		notAfter = strings.TrimSpace(m.CertNotAfter) // the installed one is still serving
	}
	if err := r.mirror(ctx, m, state, notAfter); err != nil {
		errs = append(errs, err)
	}
	var candidate *orderCandidate
	if due, ok := orderDue(row, state, now); ok {
		candidate = &orderCandidate{target: t, due: due}
	}
	return candidate, errors.Join(errs...)
}

// orderDue decides whether the row needs an order now (§4.3): pending or
// failed with next_attempt_at passed, or installed/renewing past renew_after.
func orderDue(row machineCertificate, state string, now time.Time) (time.Time, bool) {
	switch {
	case state == machineCertStatePending || strings.HasPrefix(state, machineCertStateFailed+":"):
		if row.NextAttemptAt.IsZero() || !now.Before(row.NextAttemptAt) {
			return row.NextAttemptAt, true
		}
	case state == machineCertStateInstalled || state == machineCertStateRenewing:
		if !row.RenewAfter.IsZero() && !now.Before(row.RenewAfter) {
			return row.RenewAfter, true
		}
	}
	return time.Time{}, false
}

// refreshARI asks the CA for the renewal window (§4.3). On error the
// fallback renew_after (2/3 of the lifetime) stays and the next check is in
// six hours.
func (r *zoneReconciler) refreshARI(ctx context.Context, row machineCertificate, now time.Time) (machineCertificate, error) {
	renewAfter, retryAfter, err := r.issuer.RenewalInfo(ctx, row.CertPEM)
	next := now.Add(zoneARIDefaultRetry)
	if err != nil {
		if updated, uerr := updateMachineCertificateARI(ctx, r.db, row.Hostname, time.Time{}, next, now); uerr == nil {
			row = updated
		}
		return row, fmt.Errorf("%s: renewal info: %w", row.Hostname, err)
	}
	if !retryAfter.IsZero() && retryAfter.After(now) {
		next = retryAfter
	}
	return updateMachineCertificateARI(ctx, r.db, row.Hostname, renewAfter, next, now)
}

// markerReady reads the Caddy Setup Marker (§4.4 step 1). Absent, unparsable
// or naming another host → false, logged once per instance + marker content.
func (r *zoneReconciler) markerReady(ctx context.Context, t zoneTarget) (bool, error) {
	m := t.machine
	if !m.Running {
		return false, nil
	}
	content, err := r.machines.ReadInstanceFile(ctx, m.IncusProject, m.Name, tenant.CaddySetupMarkerPath)
	if err != nil {
		if errors.Is(err, ErrInstanceFileNotFound) {
			r.logOnce(r.markerLogged, m.IncusProject+"/"+m.Name+"/absent", "INFO",
				"zone reconcile: %s/%s: no caddy setup marker; A record only", m.IncusProject, m.Name)
			return false, nil
		}
		return false, fmt.Errorf("%s: read caddy setup marker: %w", t.hostname, err)
	}
	marker, err := tenant.ParseCaddySetupMarker(content)
	if err != nil || !marker.ReadyFor(t.hostname) {
		r.logOnce(r.markerLogged, m.IncusProject+"/"+m.Name+"/"+content, "INFO",
			"zone reconcile: %s/%s: caddy setup marker does not name %s (MODE=%s FQDN=%s); A record only",
			m.IncusProject, m.Name, t.hostname, marker.Mode, marker.FQDN)
		return false, nil
	}
	return true, nil
}

// driftCheck compares the certificate on the Machine with the row (§4.5).
// A missing file counts as drift (rebuilt Machine); an unreachable Machine
// is an error the caller logs and retries next pass.
func (r *zoneReconciler) driftCheck(ctx context.Context, t zoneTarget, row machineCertificate) (bool, error) {
	m := t.machine
	content, err := r.machines.ReadInstanceFile(ctx, m.IncusProject, m.Name, tenant.MachineTLSCertPath)
	if err != nil {
		if errors.Is(err, ErrInstanceFileNotFound) {
			return true, nil
		}
		return false, fmt.Errorf("%s: drift check: %w", t.hostname, err)
	}
	leaf, err := parseLeafCertificate(content)
	if err != nil {
		return true, nil
	}
	if certificateFingerprint(leaf) != row.Fingerprint {
		return true, nil
	}
	// Same leaf, different file (junk appended, chain edited): Caddy would
	// serve that file, so it counts as drift too.
	return strings.TrimSpace(content) != strings.TrimSpace(row.CertPEM), nil
}

// push installs the row's certificate into the Machine (§4.4). It reports
// whether the push happened; a failed push is an error retried next pass
// without backoff, and a missing marker is neither.
func (r *zoneReconciler) push(ctx context.Context, t zoneTarget, row machineCertificate, firstPush bool, now time.Time) (bool, error) {
	ready, err := r.markerReady(ctx, t)
	if err != nil || !ready {
		return false, err
	}
	keyPEM, err := machineCertificateKeyPEM(ctx, r.db, row)
	if err != nil {
		return false, fmt.Errorf("%s: %w", t.hostname, err)
	}
	m := t.machine
	if err := r.machines.PushMachineCertificate(ctx, m.IncusProject, m.Name, row.CertPEM, keyPEM, firstPush); err != nil {
		return false, fmt.Errorf("%s: push certificate to %s/%s: %w", t.hostname, m.IncusProject, m.Name, err)
	}
	if _, err := setMachineCertificatePushedSerial(ctx, r.db, row.Hostname, row.Serial, now); err != nil {
		return false, fmt.Errorf("%s: record pushed serial: %w", t.hostname, err)
	}
	r.logf("INFO", "zone reconcile: %s: certificate %s installed on %s/%s (not after %s)", t.hostname, row.Serial, m.IncusProject, m.Name, formatCertTime(row.NotAfter))
	return true, nil
}

// mirror writes KeyV2CertState / KeyV2CertNotAfter when they changed (§4.7).
func (r *zoneReconciler) mirror(ctx context.Context, m ZoneMachine, state, notAfter string) error {
	config := map[string]string{}
	if strings.TrimSpace(m.CertState) != state {
		config[meta.KeyV2CertState] = state
	}
	if strings.TrimSpace(m.CertNotAfter) != notAfter {
		config[meta.KeyV2CertNotAfter] = notAfter
	}
	if len(config) == 0 {
		return nil
	}
	if err := r.machines.StampInstanceConfig(ctx, m.IncusProject, m.Name, config); err != nil {
		return fmt.Errorf("mirror certificate state on %s/%s: %w", m.IncusProject, m.Name, err)
	}
	return nil
}

// scheduleOrders starts due orders (§4.3): oldest due first, at most
// zoneMaxConcurrentOrder in flight, never two for one hostname.
func (r *zoneReconciler) scheduleOrders(ctx context.Context, candidates []orderCandidate) {
	if r.issuer == nil || len(candidates) == 0 {
		return
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].due.Before(candidates[j].due)
	})
	r.inflightMu.Lock()
	defer r.inflightMu.Unlock()
	for _, c := range candidates {
		if len(r.inflight) >= zoneMaxConcurrentOrder {
			return
		}
		if _, busy := r.inflight[c.target.hostname]; busy {
			continue
		}
		r.inflight[c.target.hostname] = struct{}{}
		r.orders.Add(1)
		go r.runOrder(ctx, c.target)
	}
}

// runOrder is one order: TXT sweep, Issue, store or record the failure.
func (r *zoneReconciler) runOrder(ctx context.Context, t zoneTarget) {
	defer r.orders.Done()
	defer func() {
		r.inflightMu.Lock()
		delete(r.inflight, t.hostname)
		r.inflightMu.Unlock()
	}()
	err := r.order(ctx, t)
	now := r.now().UTC()
	if err != nil {
		r.logf("ERROR", "zone reconcile: %s: order failed: %v", t.hostname, err)
		if _, ferr := recordMachineCertificateFailure(ctx, r.db, t.hostname, err, now); ferr != nil {
			r.logf("ERROR", "zone reconcile: %s: record order failure: %v", t.hostname, ferr)
		}
	}
	// Either way the row changed: the next pass pushes (success) or mirrors
	// the failure — do not wait for the ticker.
	if r.kick != nil {
		r.kick()
	}
}

func (r *zoneReconciler) order(ctx context.Context, t zoneTarget) error {
	if err := r.sweepChallengeRecords(ctx, t); err != nil {
		return err
	}
	issued, err := r.issuer.Issue(ctx, t.claim.Zone, machineCertificateHostnames(t.hostname))
	if err != nil {
		return err
	}
	row, err := storeIssuedMachineCertificate(ctx, r.db, t.hostname, issued, r.now().UTC())
	if err != nil {
		return fmt.Errorf("store issued certificate: %w", err)
	}
	r.logf("INFO", "zone reconcile: %s: certificate %s issued (not after %s)", t.hostname, row.Serial, formatCertTime(row.NotAfter))
	return nil
}

// sweepChallengeRecords deletes leftover _acme-challenge TXT records for the
// hostname before an order (§4.3) — a crashed pass would otherwise fail the
// next validation. Runs in the order goroutine with its own zone read.
func (r *zoneReconciler) sweepChallengeRecords(ctx context.Context, t zoneTarget) error {
	token, err := PublicDNSZoneToken(ctx, r.db, t.claim.Zone)
	if err != nil {
		return fmt.Errorf("zone %s token: %w", t.claim.Zone, err)
	}
	provider := r.providers(token)
	lz := libdnsZone(t.claim.Zone)
	records, err := provider.GetRecords(ctx, lz)
	if err != nil {
		return fmt.Errorf("zone %s: list records for challenge sweep: %w", t.claim.Zone, err)
	}
	name := acmeChallengeLabel + "." + libdns.RelativeName(t.hostname, lz)
	var stale []libdns.Record
	for _, rec := range records {
		txt, ok := rec.(libdns.TXT)
		if ok && txt.Name == name {
			stale = append(stale, txt)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	if _, err := provider.DeleteRecords(ctx, lz, stale); err != nil {
		return fmt.Errorf("zone %s: sweep %d challenge record(s) for %s: %w", t.claim.Zone, len(stale), t.hostname, err)
	}
	r.logf("INFO", "zone reconcile: %s: swept %d leftover challenge record(s)", t.hostname, len(stale))
	return nil
}

// gcMachineCertificates drops rows of absent Machines once they hold nothing
// worth retaining (§4.6): never issued, expired, or issued by another
// directory. A retained, valid row waits for its Machine to reappear.
func (r *zoneReconciler) gcMachineCertificates(ctx context.Context, live map[string]struct{}, now time.Time) error {
	rows, err := listAllMachineCertificates(ctx, r.db)
	if err != nil {
		return fmt.Errorf("list certificate rows for gc: %w", err)
	}
	var errs []error
	for _, row := range rows {
		if _, ok := live[row.Hostname]; ok {
			continue
		}
		if row.usable(r.directory, now) {
			continue
		}
		if err := deleteMachineCertificate(ctx, r.db, row.Hostname); err != nil {
			errs = append(errs, fmt.Errorf("drop certificate row %s: %w", row.Hostname, err))
			continue
		}
		r.logf("INFO", "zone reconcile: dropped certificate row %s (machine gone, nothing retained)", row.Hostname)
	}
	return errors.Join(errs...)
}

// waitOrders blocks until every in-flight order finished (tests, shutdown).
func (r *zoneReconciler) waitOrders() { r.orders.Wait() }

func (r *zoneReconciler) logOnce(set map[string]struct{}, key, level, format string, args ...any) {
	r.loggedMu.Lock()
	_, seen := set[key]
	if !seen {
		set[key] = struct{}{}
	}
	r.loggedMu.Unlock()
	if !seen {
		r.logf(level, format, args...)
	}
}

// releaseProjectDomainRecords deletes every A record and every
// _acme-challenge TXT record under a released Project Domain (§4.6) — a
// released domain can be re-claimed by another tenant.
func releaseProjectDomainRecords(ctx context.Context, db *sql.DB, claim ProjectDomainClaim) error {
	token, err := PublicDNSZoneToken(ctx, db, claim.Zone)
	if err != nil {
		return fmt.Errorf("zone %s token: %w", claim.Zone, err)
	}
	provider := newZoneDNSProvider(token)
	lz := libdnsZone(claim.Zone)
	records, err := provider.GetRecords(ctx, lz)
	if err != nil {
		return fmt.Errorf("zone %s: list records: %w", claim.Zone, err)
	}
	suffix := "." + libdns.RelativeName(claim.Domain, lz)
	var stale []libdns.Record
	for _, rec := range records {
		rr := rec.RR()
		if !strings.HasSuffix(rr.Name, suffix) {
			continue
		}
		switch rr.Type {
		case "A":
			stale = append(stale, rec)
		case "TXT":
			if strings.HasPrefix(rr.Name, acmeChallengeLabel+".") {
				stale = append(stale, rec)
			}
		}
	}
	if len(stale) == 0 {
		return nil
	}
	if _, err := provider.DeleteRecords(ctx, lz, stale); err != nil {
		return fmt.Errorf("zone %s: delete %d record(s) under %s: %w", claim.Zone, len(stale), claim.Domain, err)
	}
	return nil
}
