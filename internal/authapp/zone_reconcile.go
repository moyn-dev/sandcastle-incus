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
// Public DNS Zones — the zone reconciler (ADR-0027 spec §4, per (machine,
// hostname) since ADR-0028 / spec machine-hostnames §7)
//
// The ADR-0018 DNS pass (30s ticker + instance lifecycle events) gains a zone
// stage. Its unit of work is a (machine, hostname) pair: for every live
// Machine the union of its derived name (`<machine>.<Project Domain>` when
// the project holds a claim) and its explicit machine_hostnames rows. Per
// pair it keeps the public A records (base + wildcard) in Cloudflare, orders
// and renews one Machine Certificate through the certIssuer on the row's own
// schedule (ARI window, persisted backoff), pushes cert + key into the
// hostname's directory on the Machine once its Caddy Setup Marker shows the
// per-name contract, and re-pushes on fingerprint drift. Per Machine it
// converges the public-name list key, pushes /etc/sandcastle/hostnames when
// the set the Machine shows differs, and mirrors the per-hostname state into
// instance config so `sc ls` renders it from the cache and the live path
// alike. Every per-Machine error is collected with errors.Join; a pass never
// fails as a whole.
//
// The Incus side is behind ZoneMachineServer (implemented in incusx, which
// imports this package — not the other way round); the DNS side behind a
// libdns provider factory; the ACME side behind certIssuer. Unit tests run
// the whole pass against fakes.
// ---------------------------------------------------------------------------

// ZoneMachine is one instance of an app project as the zone reconciler sees
// it: its public-name keys as currently stamped, its project's Incus domain
// key, its certificate mirror and its live state.
type ZoneMachine struct {
	Tenant       string
	Project      string // short project name
	IncusProject string // full Incus project name
	Name         string
	// ProjectDomain is the project's KeyV2Domain ("" for a project without
	// a Project Domain).
	ProjectDomain string
	// PublicHostname is the instance's raw LEGACY KeyV2PublicHostname. The
	// reconciler never reads it as a name any more; a non-empty value is
	// deleted when the list key is converged.
	PublicHostname string
	// PublicHostnames is the instance's KeyV2PublicHostnames list (ADR-0028)
	// as stamped; the reconciler converges it to derived + explicit.
	PublicHostnames []string
	// BridgeIPv4 is the tenant-bridge address ("" when stopped / no lease).
	BridgeIPv4 string
	Running    bool
	// CertState / CertNotAfter are the current KeyV2CertState /
	// KeyV2CertNotAfter values, compared before mirroring.
	CertState    string
	CertNotAfter string
}

// key identifies the instance in per-pass caches and log dedupe.
func (m ZoneMachine) key() string { return m.IncusProject + "/" + m.Name }

// ErrInstanceFileNotFound is what ZoneMachineServer.ReadInstanceFile returns
// when the instance is reachable but the file does not exist — the drift
// check treats that as "re-push", unlike an unreachable instance (skip).
var ErrInstanceFileNotFound = errors.New("instance file not found")

// ZoneMachineServer is the Incus seam of the zone reconciler.
type ZoneMachineServer interface {
	// ListZoneMachines returns every instance of every app project of the
	// install (prefix-scoped), with the project's domain key.
	ListZoneMachines(ctx context.Context) ([]ZoneMachine, error)
	// StampInstanceConfig merges config into the instance's own config (an
	// empty value deletes the key).
	StampInstanceConfig(ctx context.Context, incusProject, name string, config map[string]string) error
	// ReadInstanceFile returns a file's content; ErrInstanceFileNotFound when
	// the instance answered but has no such file.
	ReadInstanceFile(ctx context.Context, incusProject, name, path string) (string, error)
	// PushMachineCertificate writes cert.pem.new / key.pem.new into the
	// hostname's directory (tenant.MachineTLSHostDir) and runs the one
	// mv + `sandcastle-caddy-setup --refresh` exec (spec §4.4, per name
	// since ADR-0028); the refresh renders the block and reloads or starts
	// Caddy, so there is no separate first-push start.
	PushMachineCertificate(ctx context.Context, incusProject, name, hostname, certPEM, keyPEM string) error
	// PushMachineHostnames writes the machine's whole public-name set to
	// /etc/sandcastle/hostnames and runs `sandcastle-caddy-setup --refresh`
	// (spec machine-hostnames §5.2), so a removed name's site block goes and
	// a listed name whose certificate is present appears.
	PushMachineHostnames(ctx context.Context, incusProject, name string, hostnames []string) error
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

	// kick, when set, asks the loop for another pass soon (an order
	// finished, a hostname was added or removed: the push should not wait
	// for the ticker). Guarded by kickMu: the API handlers call RequestPass
	// while the loop is still being wired.
	kickMu sync.Mutex
	kick   func()

	mu sync.Mutex // serializes passes

	inflightMu sync.Mutex
	inflight   map[string]struct{}
	orders     sync.WaitGroup

	loggedMu       sync.Mutex
	markerLogged   map[string]struct{}
	skippedLogged  map[string]struct{}
	providerByZone map[string]zoneProvider
	// markerByMachine caches the Caddy Setup Marker read of one pass per
	// instance: several hostnames of one Machine share one read.
	markerByMachine map[string]markerRead
	// namedBefore remembers instances that carried public names in an
	// earlier pass of this process, so the pass after the last name is
	// removed still converges the (now empty) hostnames file on the Machine.
	namedBefore map[string]struct{}
}

func newZoneReconciler(db *sql.DB, machines ZoneMachineServer, issuer certIssuer, directory string, logf func(level, format string, args ...any)) *zoneReconciler {
	if logf == nil {
		logf = func(string, string, ...any) {}
	}
	return &zoneReconciler{
		db:              db,
		machines:        machines,
		issuer:          issuer,
		directory:       directory,
		providers:       func(token string) zoneDNSProvider { return newZoneDNSProvider(token) },
		logf:            logf,
		now:             time.Now,
		inflight:        map[string]struct{}{},
		markerLogged:    map[string]struct{}{},
		skippedLogged:   map[string]struct{}{},
		providerByZone:  map[string]zoneProvider{},
		markerByMachine: map[string]markerRead{},
		namedBefore:     map[string]struct{}{},
	}
}

// setKick installs the loop's trigger.
func (r *zoneReconciler) setKick(kick func()) {
	r.kickMu.Lock()
	defer r.kickMu.Unlock()
	r.kick = kick
}

// RequestPass asks for a pass soon (no-op before the loop is wired). The
// hostname API calls it after an add or remove so records, orders and the
// hostnames-file push do not wait for the ticker.
func (r *zoneReconciler) RequestPass() {
	if r == nil {
		return
	}
	r.kickMu.Lock()
	kick := r.kick
	r.kickMu.Unlock()
	if kick != nil {
		kick()
	}
}

// zoneTarget is one (Machine, Machine Public Hostname) pair — the unit of
// work of the pass. derived marks `<machine>.<Project Domain>`; every other
// target is a machine_hostnames row.
type zoneTarget struct {
	machine  ZoneMachine
	hostname string
	zone     string
	derived  bool
}

// machineTargets is one Machine with every public name it must serve, in
// sorted hostname order. converge is false when the Machine's project state
// is inconsistent (Incus domain key without or against the claim): its
// explicit names are still served, but its list key, mirror and hostnames
// file are left alone until the tenant repairs the project.
type machineTargets struct {
	machine  ZoneMachine
	targets  []zoneTarget
	converge bool
}

// names lists the targets' hostnames (sorted).
func (mt machineTargets) names() []string {
	names := make([]string, 0, len(mt.targets))
	for _, t := range mt.targets {
		names = append(names, t.hostname)
	}
	return names
}

// orderCandidate is a target whose row says an order is due.
type orderCandidate struct {
	target zoneTarget
	due    time.Time
}

// Reconcile runs one pass (spec §4.1–§4.7, machine-hostnames §7). It returns
// the joined per-Machine errors; only a listing failure aborts the pass.
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
	// An empty fleet is a real state, not a listing failure (that returns an
	// error above): once the last Machine is deleted its records must still be
	// GC'd. Records are self-healing (a wrong deletion is re-created by the
	// next pass) and certificate rows are retained on Machine deletion by
	// design, so both passes run on an empty fleet; only the certificate-row
	// GC is skipped, see below.
	claims, err := ListProjectDomainClaims(ctx, r.db)
	if err != nil {
		return fmt.Errorf("list project domain claims for zone reconcile: %w", err)
	}
	claimByProject := make(map[string]ProjectDomainClaim, len(claims))
	for _, c := range claims {
		claimByProject[c.Tenant+"/"+c.Project] = c
	}
	explicit, err := listMachineHostnames(ctx, r.db)
	if err != nil {
		return fmt.Errorf("list machine hostnames for zone reconcile: %w", err)
	}
	explicitByMachine := map[string][]MachineHostname{}
	for _, h := range explicit {
		k := h.Tenant + "/" + h.Project + "/" + h.Machine
		explicitByMachine[k] = append(explicitByMachine[k], h)
	}
	// A fresh provider per pass and zone: a rotated token is picked up on the
	// next pass, and the libdns/cloudflare zone-id cache lives one pass. The
	// marker cache lives one pass too.
	r.providerByZone = map[string]zoneProvider{}
	r.markerByMachine = map[string]markerRead{}

	var errs []error
	var fleet []machineTargets
	for _, m := range machines {
		mt := r.classify(m, claimByProject, explicitByMachine)
		if mt.converge {
			if err := r.convergePublicHostnames(ctx, mt); err != nil {
				errs = append(errs, err)
			}
		}
		fleet = append(fleet, mt)
	}

	// Public A records: one Cloudflare read per zone per pass (§4.2). Every
	// zone with at least one claim or one explicit hostname gets a pass —
	// with an empty target list when nothing under it is live — so the
	// records of the last Machine deleted in a zone are GC'd (§4.6). A
	// registered zone with neither has nothing to converge and is not read.
	byZone := map[string][]zoneTarget{}
	for _, c := range claims {
		byZone[c.Zone] = nil
	}
	for _, h := range explicit {
		byZone[h.Zone] = nil
	}
	for _, mt := range fleet {
		for _, t := range mt.targets {
			byZone[t.zone] = append(byZone[t.zone], t)
		}
	}
	zones := make([]string, 0, len(byZone))
	for zone := range byZone {
		zones = append(zones, zone)
	}
	sort.Strings(zones)
	for _, zone := range zones {
		if err := r.reconcileZoneRecords(ctx, zone, byZone[zone], claims, explicit); err != nil {
			errs = append(errs, err)
		}
	}

	// Per Machine: the hostnames file, then per hostname the certificate
	// (rows, ARI, drift, push), then the mirror; collect due orders.
	var candidates []orderCandidate
	liveHostnames := map[string]struct{}{}
	for _, h := range explicit {
		// A reservation that exists says the tenant still wants the name:
		// its row is never garbage while the reservation stands (the
		// hostname GC drops the reservation of a vanished Machine within 5
		// minutes, and the row follows on the next pass).
		liveHostnames[h.Hostname] = struct{}{}
	}
	for _, mt := range fleet {
		for _, t := range mt.targets {
			liveHostnames[t.hostname] = struct{}{}
		}
		machineCandidates, err := r.reconcileMachine(ctx, mt, now)
		if err != nil {
			errs = append(errs, err)
		}
		candidates = append(candidates, machineCandidates...)
	}
	r.scheduleOrders(ctx, candidates)

	// The row GC is the one step that is not self-healing: a never-issued or
	// expired row dropped on a wrong empty listing takes its persisted
	// backoff and ARI state with it, and a re-created row orders at once.
	// Retained rows survive either way; the GC simply waits for a non-empty
	// fleet (the claim GC in project_domain_claims.go keeps the same guard).
	if len(machines) > 0 {
		if err := r.gcMachineCertificates(ctx, liveHostnames, now); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// classify computes a Machine's targets (machine-hostnames §7.1): the
// derived name when its project holds a claim that agrees with the Incus
// domain key, plus every explicit hostname row of the Machine. A project
// whose Incus key and claim disagree, or that carries a key without a claim
// (§4.6), yields no derived name and no key convergence — logged once — but
// its explicit names are served like any other.
func (r *zoneReconciler) classify(m ZoneMachine, claimByProject map[string]ProjectDomainClaim, explicitByMachine map[string][]MachineHostname) machineTargets {
	mt := machineTargets{machine: m, converge: true}
	projectDomain := strings.ToLower(strings.TrimSpace(m.ProjectDomain))
	claim, claimed := claimByProject[m.Tenant+"/"+m.Project]
	switch {
	case claimed && projectDomain != "" && claim.Domain != projectDomain:
		// The Incus key and the claim disagree (a set-domain whose Incus
		// write failed half-way): the claim is the truth for records and
		// certificates, but nothing is stamped until they agree.
		r.logOnce(r.skippedLogged, m.key()+"/mismatch/"+projectDomain, "WARN",
			"zone reconcile: project %s/%s carries domain %q but its claim is %q; derived name skipped until they agree",
			m.Tenant, m.Project, projectDomain, claim.Domain)
		claimed, mt.converge = false, false
	case !claimed && projectDomain != "":
		// KeyV2Domain without a claim (§4.6): logged by the claim GC, no
		// derived name — and the list key is left alone, since the project
		// may still be repaired by its tenant.
		mt.converge = false
	}
	if claimed {
		mt.targets = append(mt.targets, zoneTarget{machine: m, hostname: strings.ToLower(m.Name) + "." + claim.Domain, zone: claim.Zone, derived: true})
	}
	for _, h := range explicitByMachine[m.Tenant+"/"+m.Project+"/"+m.Name] {
		mt.targets = append(mt.targets, zoneTarget{machine: m, hostname: h.Hostname, zone: h.Zone})
	}
	sort.Slice(mt.targets, func(i, j int) bool { return mt.targets[i].hostname < mt.targets[j].hostname })
	return mt
}

// convergePublicHostnames makes the instance's KeyV2PublicHostnames list
// equal to its targets — the Freeform Machine's first-sight stamp, the
// re-derived name after set-domain / unset-domain, a stale list after a
// failed API write — and deletes the legacy single key on the way (its
// readers would otherwise fall back to it once the list is gone). Nothing
// is written when both already agree.
func (r *zoneReconciler) convergePublicHostnames(ctx context.Context, mt machineTargets) error {
	m := mt.machine
	want := meta.FormatPublicHostnames(mt.names())
	have := meta.FormatPublicHostnames(m.PublicHostnames)
	legacy := strings.TrimSpace(m.PublicHostname)
	if want == have && legacy == "" {
		return nil
	}
	config := map[string]string{}
	if want != have {
		config[meta.KeyV2PublicHostnames] = want
	}
	if legacy != "" {
		config[meta.KeyV2PublicHostname] = ""
	}
	if err := r.machines.StampInstanceConfig(ctx, m.IncusProject, m.Name, config); err != nil {
		return fmt.Errorf("converge public hostnames on %s: %w", m.key(), err)
	}
	if want != have {
		r.logf("INFO", "zone reconcile: stamped %s %s=%s", m.key(), meta.KeyV2PublicHostnames, orNoneString(want))
	}
	return nil
}

func orNoneString(value string) string {
	if value == "" {
		return "(none)"
	}
	return value
}

// zoneProvider is a pass's libdns provider for a Public DNS Zone together
// with the libdns zone name every call must be addressed to: the Cloudflare
// zone containing the Public DNS Zone (equal to it when the zone is a
// Cloudflare zone itself), in libdns form.
type zoneProvider struct {
	provider zoneDNSProvider
	lz       string
}

// provider returns the pass's libdns provider for a zone, built from the
// zone's decrypted token on first use.
func (r *zoneReconciler) provider(ctx context.Context, zone string) (zoneProvider, error) {
	if p, ok := r.providerByZone[zone]; ok {
		return p, nil
	}
	cloudflareZone, token, err := PublicDNSZoneCredentials(ctx, r.db, zone)
	if err != nil {
		return zoneProvider{}, fmt.Errorf("zone %s token: %w", zone, err)
	}
	p := zoneProvider{provider: r.providers(token), lz: libdnsZone(cloudflareZone)}
	r.providerByZone[zone] = p
	return p, nil
}

// libdnsZone is the zone name in libdns' conventional form (trailing dot),
// the same shape certmagic hands the provider. It must always be applied to
// the Cloudflare zone, never to a Public DNS Zone that merely lives inside
// one — Cloudflare knows only its own zones.
func libdnsZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".") + "."
}

// desiredZoneRecords are the A records a set of zone targets needs (§4.2):
// base + wildcard per hostname whose Machine has a bridge address, relative
// to the Cloudflare zone (libdns form).
// keep lists every live target's relative name, address or not, so a stopped
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
// hostname map onto its relative name.
func machineRelativeName(name string) string {
	return strings.TrimPrefix(name, "*.")
}

// reconcileZoneRecords converges the A records of a zone: missing/changed →
// SetRecords; managed records with no live target → DeleteRecords (covers
// deleted and out-of-band removed Machines, for every name they carried).
// Managed means under a claimed Project Domain, or exactly an explicit
// hostname (base or wildcard) reserved in the zone; anything else in the
// zone is never read as stale. Exactly one GetRecords per zone per pass.
// Every record name is relative to the Cloudflare zone containing the
// Public DNS Zone.
func (r *zoneReconciler) reconcileZoneRecords(ctx context.Context, zone string, targets []zoneTarget, claims []ProjectDomainClaim, explicit []MachineHostname) error {
	zp, err := r.provider(ctx, zone)
	if err != nil {
		return err
	}
	provider, lz := zp.provider, zp.lz
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
	reserved := map[string]struct{}{}
	for _, h := range explicit {
		if h.Zone == zone {
			reserved[libdns.RelativeName(h.Hostname, lz)] = struct{}{}
		}
	}
	managed := func(name string) bool {
		for _, suffix := range domainSuffixes {
			if strings.HasSuffix(name, suffix) {
				return true
			}
		}
		_, ok := reserved[machineRelativeName(name)]
		return ok
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
		if !managed(addr.Name) {
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
			if recordsAlreadyGone(err) {
				r.logf("INFO", "zone reconcile: zone %s: %d stale A record(s) already gone (%v)", zone, len(stale), err)
			} else {
				errs = append(errs, fmt.Errorf("zone %s: delete %d stale A record(s): %w", zone, len(stale), err))
			}
		} else {
			r.logf("INFO", "zone reconcile: zone %s: deleted %d stale A record(s)", zone, len(stale))
		}
	}
	return errors.Join(errs...)
}

// recordsAlreadyGone reports a DeleteRecords failure that only says the
// records were removed by someone else first — the project-delete hook and
// the pass GC race for the same stale records, and the loser gets Cloudflare's
// 404 (`HTTP 404: [{Code:81044 Message:Record does not exist.}]` through
// libdns/cloudflare). The desired state holds either way, so the caller logs
// it and does not fail the pass.
func recordsAlreadyGone(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Record does not exist") ||
		strings.Contains(msg, "81044") ||
		strings.Contains(msg, "HTTP 404")
}

// reconcileMachine does the per-Machine work of a pass: the hostnames-file
// push when the Machine's file differs from its set, the certificate of
// every target (§4.3–§4.5), and one mirror write with the per-hostname
// states (§4.7). It returns the targets whose order is due.
func (r *zoneReconciler) reconcileMachine(ctx context.Context, mt machineTargets, now time.Time) ([]orderCandidate, error) {
	m := mt.machine
	var errs []error
	if mt.converge {
		if err := r.convergeHostnamesFile(ctx, mt); err != nil {
			errs = append(errs, err)
		}
	}
	var candidates []orderCandidate
	states := map[string]string{}
	var notAfter time.Time
	for _, t := range mt.targets {
		outcome, err := r.reconcileTargetCertificate(ctx, t, now)
		if err != nil {
			errs = append(errs, err)
		}
		if outcome.state != "" {
			states[t.hostname] = outcome.state
		}
		if !outcome.notAfter.IsZero() && (notAfter.IsZero() || outcome.notAfter.Before(notAfter)) {
			notAfter = outcome.notAfter
		}
		if outcome.candidate != nil {
			candidates = append(candidates, *outcome.candidate)
		}
	}
	if mt.converge {
		if err := r.mirror(ctx, m, states, notAfter); err != nil {
			errs = append(errs, err)
		}
	}
	return candidates, errors.Join(errs...)
}

// convergeHostnamesFile pushes /etc/sandcastle/hostnames (+ --refresh) when
// the file on a running per-name-contract Machine does not list exactly the
// Machine's set (machine-hostnames §5.2): a name added or removed, a
// re-derived name, or a first-boot seed the datasource read left empty. A
// Machine that never had a name in this process's memory and has none now is
// not read at all — the file is only ever wrong on a Machine that had names.
func (r *zoneReconciler) convergeHostnamesFile(ctx context.Context, mt machineTargets) error {
	m := mt.machine
	names := mt.names()
	if len(names) == 0 {
		if _, had := r.namedBefore[m.key()]; !had {
			return nil
		}
	} else {
		r.namedBefore[m.key()] = struct{}{}
	}
	if !m.Running {
		return nil
	}
	marker, ok, err := r.readMarker(ctx, m)
	if err != nil || !ok || marker.Legacy() {
		return err
	}
	want := tenant.FormatMachineHostnamesFile(names)
	content, err := r.machines.ReadInstanceFile(ctx, m.IncusProject, m.Name, tenant.MachineHostnamesPath)
	if err != nil && !errors.Is(err, ErrInstanceFileNotFound) {
		return fmt.Errorf("%s: read hostnames file: %w", m.key(), err)
	}
	if err == nil && tenant.FormatMachineHostnamesFile(strings.Split(content, "\n")) == want {
		if len(names) == 0 {
			delete(r.namedBefore, m.key())
		}
		return nil
	}
	if err := r.machines.PushMachineHostnames(ctx, m.IncusProject, m.Name, names); err != nil {
		return fmt.Errorf("%s: push hostnames file: %w", m.key(), err)
	}
	r.logf("INFO", "zone reconcile: %s: hostnames file pushed (%s)", m.key(), orNoneString(strings.Join(names, ",")))
	if len(names) == 0 {
		delete(r.namedBefore, m.key())
	}
	return nil
}

// targetOutcome is what one target's certificate pass reports for the
// Machine's mirror.
type targetOutcome struct {
	state string
	// notAfter is the expiry of the certificate installed for the name (zero
	// when none is).
	notAfter  time.Time
	candidate *orderCandidate
}

// reconcileTargetCertificate does the per-hostname certificate work of a
// pass (§4.3–§4.5): create the row for a marker-bearing Machine that has
// none (Freeform / --bare, or a re-derived name), reset a row from another
// directory, refresh ARI, detect drift, push, and report the state. It
// returns a candidate when an order is due.
func (r *zoneReconciler) reconcileTargetCertificate(ctx context.Context, t zoneTarget, now time.Time) (targetOutcome, error) {
	m := t.machine
	row, err := getMachineCertificate(ctx, r.db, t.hostname)
	hasRow := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return targetOutcome{state: machineCertStatePending}, fmt.Errorf("%s: read certificate row: %w", t.hostname, err)
	}
	if !hasRow {
		// Rows come from sc create / sc hostname add, or from the reconciler
		// for a Machine that carries the per-name marker (§4.3). No marker,
		// no row: a Dev Image Machine never orders.
		ready, _ := r.markerReady(ctx, t)
		if !ready {
			return targetOutcome{state: machineCertStatePending}, nil
		}
		row, err = requestMachineCertificate(ctx, r.db, machineCertificateRequest{
			Hostname: t.hostname, Tenant: m.Tenant, Project: m.Project, Machine: m.Name,
			Zone: t.zone, DirectoryURL: r.directory,
		}, now)
		if err != nil {
			return targetOutcome{state: machineCertStatePending}, fmt.Errorf("%s: create certificate row: %w", t.hostname, err)
		}
		r.logf("INFO", "zone reconcile: %s: certificate row created for %s", t.hostname, m.key())
	}
	var errs []error
	if row.hasCertificate() && row.DirectoryURL != r.directory {
		// Staging and production never mix (§3.5): re-order under the
		// running directory.
		if row, err = resetMachineCertificate(ctx, r.db, row.Hostname, r.directory, now); err != nil {
			return targetOutcome{state: machineCertStatePending}, fmt.Errorf("%s: reset certificate row for directory change: %w", t.hostname, err)
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
				r.logf("WARN", "zone reconcile: %s: certificate on %s differs from the issued one; re-pushing", t.hostname, m.key())
			}
		}
	}
	if m.Running && row.usable(r.directory, now) && row.PushedSerial != row.Serial {
		if pushed, err := r.push(ctx, t, row, now); err != nil {
			errs = append(errs, err)
		} else if pushed {
			row.PushedSerial = row.Serial
		}
	}
	state := machineCertificateState(row, r.directory, now)
	outcome := targetOutcome{state: state}
	if row.hasCertificate() && row.PushedSerial == row.Serial {
		outcome.notAfter = row.NotAfter
	} else if state == machineCertStateIssued && row.PushedSerial != "" {
		// Renewed but not yet pushed: the previous certificate still serves
		// the name; the Machine's mirrored expiry is the best account of it.
		outcome.notAfter = parseCertTime(strings.TrimSpace(m.CertNotAfter))
	}
	if due, ok := orderDue(row, state, now); ok {
		outcome.candidate = &orderCandidate{target: t, due: due}
	}
	return outcome, errors.Join(errs...)
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

// markerRead is one pass's cached marker read of an instance.
type markerRead struct {
	marker tenant.CaddySetupMarker
	ok     bool // a marker parsed (legacy or per-name)
	err    error
}

// readMarker reads and parses the Caddy Setup Marker of a running instance,
// once per pass. ok is false for an absent or unparsable marker (logged once
// per instance + content); err is an unreachable instance.
func (r *zoneReconciler) readMarker(ctx context.Context, m ZoneMachine) (tenant.CaddySetupMarker, bool, error) {
	if cached, hit := r.markerByMachine[m.key()]; hit {
		return cached.marker, cached.ok, cached.err
	}
	var read markerRead
	content, err := r.machines.ReadInstanceFile(ctx, m.IncusProject, m.Name, tenant.CaddySetupMarkerPath)
	switch {
	case errors.Is(err, ErrInstanceFileNotFound):
		r.logOnce(r.markerLogged, m.key()+"/absent", "INFO",
			"zone reconcile: %s: no caddy setup marker; A record only", m.key())
	case err != nil:
		read.err = fmt.Errorf("%s: read caddy setup marker: %w", m.key(), err)
	default:
		marker, perr := tenant.ParseCaddySetupMarker(content)
		if perr != nil {
			r.logOnce(r.markerLogged, m.key()+"/"+content, "INFO",
				"zone reconcile: %s: caddy setup marker unreadable (%v); A record only", m.key(), perr)
		} else {
			read.marker, read.ok = marker, true
		}
	}
	r.markerByMachine[m.key()] = read
	return read.marker, read.ok, read.err
}

// markerReady is the push gate of one target (§4.4 step 1): the Machine is
// running and its marker is a per-name marker. Absent, unparsable or legacy
// (an ADR-0027 MODE=/FQDN= marker: no per-name contract on that machine) →
// false, logged once per instance + marker content. A per-name marker
// clears the gate for every hostname — the push lands in the name's own
// directory and --refresh renders it.
func (r *zoneReconciler) markerReady(ctx context.Context, t zoneTarget) (bool, error) {
	m := t.machine
	if !m.Running {
		return false, nil
	}
	marker, ok, err := r.readMarker(ctx, m)
	if err != nil {
		return false, fmt.Errorf("%s: %w", t.hostname, err)
	}
	if !ok {
		// Visible in the journal per (instance, hostname): a machine whose
		// caddy-setup never wrote the marker (the live run's dash syntax
		// error) otherwise looks like a machine that is merely slow to boot.
		r.logOnce(r.markerLogged, m.key()+"/not-pushed/"+t.hostname, "INFO",
			"zone reconcile: %s: caddy setup marker missing or unreadable (%s); certificate for %s not pushed",
			m.key(), tenant.CaddySetupMarkerPath, t.hostname)
		return false, nil
	}
	if !marker.ReadyFor(t.hostname) {
		r.logOnce(r.markerLogged, m.key()+"/"+marker.String(), "INFO",
			"zone reconcile: %s: caddy setup marker does not clear the push gate for %s (%s); A record only",
			m.key(), t.hostname, marker)
		return false, nil
	}
	return true, nil
}

// driftCheck compares the certificate on the Machine with the row (§4.5).
// A missing file counts as drift (rebuilt Machine); an unreachable Machine
// is an error the caller logs and retries next pass.
func (r *zoneReconciler) driftCheck(ctx context.Context, t zoneTarget, row machineCertificate) (bool, error) {
	m := t.machine
	content, err := r.machines.ReadInstanceFile(ctx, m.IncusProject, m.Name, tenant.MachineTLSHostCertPath(t.hostname))
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
func (r *zoneReconciler) push(ctx context.Context, t zoneTarget, row machineCertificate, now time.Time) (bool, error) {
	ready, err := r.markerReady(ctx, t)
	if err != nil || !ready {
		return false, err
	}
	keyPEM, err := machineCertificateKeyPEM(ctx, r.db, row)
	if err != nil {
		return false, fmt.Errorf("%s: %w", t.hostname, err)
	}
	m := t.machine
	if err := r.machines.PushMachineCertificate(ctx, m.IncusProject, m.Name, row.Hostname, row.CertPEM, keyPEM); err != nil {
		return false, fmt.Errorf("%s: push certificate to %s: %w", t.hostname, m.key(), err)
	}
	if _, err := setMachineCertificatePushedSerial(ctx, r.db, row.Hostname, row.Serial, now); err != nil {
		return false, fmt.Errorf("%s: record pushed serial: %w", t.hostname, err)
	}
	r.logf("INFO", "zone reconcile: %s: certificate %s installed on %s (not after %s)", t.hostname, row.Serial, m.key(), formatCertTime(row.NotAfter))
	return true, nil
}

// mirror writes KeyV2CertState (per hostname, `host=state,…`) and
// KeyV2CertNotAfter (the earliest installed expiry) when they changed
// (§4.7); a Machine with no state left has both keys deleted.
func (r *zoneReconciler) mirror(ctx context.Context, m ZoneMachine, states map[string]string, notAfter time.Time) error {
	config := map[string]string{}
	if want := meta.FormatCertStates(states); strings.TrimSpace(m.CertState) != want {
		config[meta.KeyV2CertState] = want
	}
	if want := formatCertTime(notAfter); strings.TrimSpace(m.CertNotAfter) != want {
		config[meta.KeyV2CertNotAfter] = want
	}
	if len(config) == 0 {
		return nil
	}
	if err := r.machines.StampInstanceConfig(ctx, m.IncusProject, m.Name, config); err != nil {
		return fmt.Errorf("mirror certificate state on %s: %w", m.key(), err)
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
	r.RequestPass()
}

func (r *zoneReconciler) order(ctx context.Context, t zoneTarget) error {
	if err := r.sweepChallengeRecords(ctx, t); err != nil {
		return err
	}
	issued, err := r.issuer.Issue(ctx, t.zone, machineCertificateHostnames(t.hostname))
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
	cloudflareZone, token, err := PublicDNSZoneCredentials(ctx, r.db, t.zone)
	if err != nil {
		return fmt.Errorf("zone %s token: %w", t.zone, err)
	}
	provider := r.providers(token)
	lz := libdnsZone(cloudflareZone)
	records, err := provider.GetRecords(ctx, lz)
	if err != nil {
		return fmt.Errorf("zone %s: list records for challenge sweep: %w", t.zone, err)
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
		return fmt.Errorf("zone %s: sweep %d challenge record(s) for %s: %w", t.zone, len(stale), t.hostname, err)
	}
	r.logf("INFO", "zone reconcile: %s: swept %d leftover challenge record(s)", t.hostname, len(stale))
	return nil
}

// gcMachineCertificates drops rows of absent hostnames once they hold
// nothing worth retaining (§4.6): never issued, expired, or issued by
// another directory. A retained, valid row waits for its Machine to
// reappear; a row whose hostname is still reserved is live.
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
	suffix := func(lz string) string { return "." + libdns.RelativeName(claim.Domain, lz) }
	return deleteZoneRecords(ctx, db, claim.Zone, func(lz string, rr libdns.RR) bool {
		return strings.HasSuffix(rr.Name, suffix(lz))
	}, "under "+claim.Domain)
}

// releaseMachineHostnameRecords deletes the base and wildcard A records and
// the _acme-challenge TXT record of a released explicit Machine Public
// Hostname (machine-hostnames §7.4). The certificate row is not touched —
// it keeps its own retention rule.
func releaseMachineHostnameRecords(ctx context.Context, db *sql.DB, hostname MachineHostname) error {
	return deleteZoneRecords(ctx, db, hostname.Zone, func(lz string, rr libdns.RR) bool {
		rel := libdns.RelativeName(hostname.Hostname, lz)
		switch rr.Type {
		case "A":
			return rr.Name == rel || rr.Name == "*."+rel
		case "TXT":
			return rr.Name == acmeChallengeLabel+"."+rel
		}
		return false
	}, "of "+hostname.Hostname)
}

// deleteZoneRecords removes every A record and every _acme-challenge TXT
// record of a zone that match, addressed to the containing Cloudflare zone.
func deleteZoneRecords(ctx context.Context, db *sql.DB, zone string, match func(lz string, rr libdns.RR) bool, what string) error {
	cloudflareZone, token, err := PublicDNSZoneCredentials(ctx, db, zone)
	if err != nil {
		return fmt.Errorf("zone %s token: %w", zone, err)
	}
	provider := newZoneDNSProvider(token)
	lz := libdnsZone(cloudflareZone)
	records, err := provider.GetRecords(ctx, lz)
	if err != nil {
		return fmt.Errorf("zone %s: list records: %w", zone, err)
	}
	var stale []libdns.Record
	for _, rec := range records {
		rr := rec.RR()
		if !match(lz, rr) {
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
		if recordsAlreadyGone(err) {
			return nil
		}
		return fmt.Errorf("zone %s: delete %d record(s) %s: %w", zone, len(stale), what, err)
	}
	return nil
}
