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
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// No unit test may reach Cloudflare: the release hooks (DELETE …/domain,
// DELETE …/hostnames/{h}, the GCs) build a provider through
// newZoneDNSProvider, so the package's tests run against an in-memory zone by
// default.
func init() {
	newZoneDNSProvider = newFakeDNS().provider
}

// ---------------------------------------------------------------------------
// Fakes: an in-memory fleet (ZoneMachineServer) and an in-memory libdns zone.
// ---------------------------------------------------------------------------

type fakeZoneFleet struct {
	mu       sync.Mutex
	machines []ZoneMachine
	// files is "<incusProject>/<name>:<path>" → content
	files          map[string]string
	pushes         []fakePush
	hostnamePushes []fakeHostnamesPush
	stamps         []fakeStamp
	listErr        error
	pushErr        error
	// unreachable makes ReadInstanceFile fail with a non-404 error.
	unreachable map[string]bool
}

type fakePush struct {
	Instance string
	Hostname string
	CertPEM  string
	KeyPEM   string
}

type fakeHostnamesPush struct {
	Instance  string
	Hostnames []string
}

type fakeStamp struct {
	Instance string
	Config   map[string]string
}

func newFakeZoneFleet(machines ...ZoneMachine) *fakeZoneFleet {
	return &fakeZoneFleet{machines: machines, files: map[string]string{}, unreachable: map[string]bool{}}
}

func (f *fakeZoneFleet) key(incusProject, name string) string { return incusProject + "/" + name }

func (f *fakeZoneFleet) setFile(incusProject, name, path, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[f.key(incusProject, name)+":"+path] = content
}

func (f *fakeZoneFleet) file(incusProject, name, path string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	content, ok := f.files[f.key(incusProject, name)+":"+path]
	return content, ok
}

func (f *fakeZoneFleet) ListZoneMachines(context.Context) ([]ZoneMachine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]ZoneMachine(nil), f.machines...), nil
}

func (f *fakeZoneFleet) StampInstanceConfig(_ context.Context, incusProject, name string, config map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.machines {
		m := &f.machines[i]
		if m.IncusProject != incusProject || m.Name != name {
			continue
		}
		for k, v := range config {
			switch k {
			case meta.KeyV2PublicHostname:
				m.PublicHostname = v
			case meta.KeyV2PublicHostnames:
				m.PublicHostnames = meta.ParsePublicHostnames(v)
			case meta.KeyV2CertState:
				m.CertState = v
			case meta.KeyV2CertNotAfter:
				m.CertNotAfter = v
			}
		}
		f.stamps = append(f.stamps, fakeStamp{Instance: f.key(incusProject, name), Config: config})
		return nil
	}
	return fmt.Errorf("instance %s/%s not found", incusProject, name)
}

func (f *fakeZoneFleet) ReadInstanceFile(_ context.Context, incusProject, name, path string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unreachable[f.key(incusProject, name)] {
		return "", errors.New("instance agent not reachable")
	}
	content, ok := f.files[f.key(incusProject, name)+":"+path]
	if !ok {
		return "", fmt.Errorf("%s: %w", path, ErrInstanceFileNotFound)
	}
	return content, nil
}

func (f *fakeZoneFleet) PushMachineCertificate(_ context.Context, incusProject, name, hostname, certPEM, keyPEM string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pushErr != nil {
		return f.pushErr
	}
	f.pushes = append(f.pushes, fakePush{Instance: f.key(incusProject, name), Hostname: hostname, CertPEM: certPEM, KeyPEM: keyPEM})
	f.files[f.key(incusProject, name)+":"+tenant.MachineTLSHostCertPath(hostname)] = certPEM
	f.files[f.key(incusProject, name)+":"+tenant.MachineTLSHostKeyPath(hostname)] = keyPEM
	// The install script appends the name to the hostnames file if missing
	// and re-renders: the marker then lists the name.
	hk := f.key(incusProject, name) + ":" + tenant.MachineHostnamesPath
	if !strings.Contains(f.files[hk], hostname+"\n") {
		f.files[hk] = tenant.FormatMachineHostnamesFile(append(strings.Split(f.files[hk], "\n"), hostname))
	}
	return nil
}

func (f *fakeZoneFleet) PushMachineHostnames(_ context.Context, incusProject, name string, hostnames []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pushErr != nil {
		return f.pushErr
	}
	f.hostnamePushes = append(f.hostnamePushes, fakeHostnamesPush{Instance: f.key(incusProject, name), Hostnames: append([]string(nil), hostnames...)})
	f.files[f.key(incusProject, name)+":"+tenant.MachineHostnamesPath] = tenant.FormatMachineHostnamesFile(hostnames)
	return nil
}

func (f *fakeZoneFleet) machine(incusProject, name string) ZoneMachine {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.machines {
		if m.IncusProject == incusProject && m.Name == name {
			return m
		}
	}
	return ZoneMachine{}
}

func (f *fakeZoneFleet) pushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pushes)
}

func (f *fakeZoneFleet) hostnamePushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.hostnamePushes)
}

// pushedHostnames lists the hostnames of every certificate push, sorted.
func (f *fakeZoneFleet) pushedHostnames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, p := range f.pushes {
		out = append(out, p.Hostname)
	}
	sort.Strings(out)
	return out
}

// fakeDNS is one in-memory libdns zone shared by every provider the factory
// hands out (the token is recorded).
type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]libdns.RR // zone → records
	tokens  []string
	gets    int
	sets    int
	deletes int
	getErr  error
}

func newFakeDNS() *fakeDNS { return &fakeDNS{records: map[string][]libdns.RR{}} }

type fakeDNSProvider struct {
	dns   *fakeDNS
	token string
}

func (f *fakeDNS) provider(token string) zoneDNSProvider {
	f.mu.Lock()
	f.tokens = append(f.tokens, token)
	f.mu.Unlock()
	return &fakeDNSProvider{dns: f, token: token}
}

func (f *fakeDNS) add(zone string, rr libdns.RR) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[zone] = append(f.records[zone], rr)
}

func (f *fakeDNS) list(zone string) []libdns.RR {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]libdns.RR(nil), f.records[zone]...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func toTyped(rr libdns.RR) libdns.Record {
	switch rr.Type {
	case "A":
		ip, _ := netip.ParseAddr(rr.Data)
		return libdns.Address{Name: rr.Name, TTL: rr.TTL, IP: ip}
	case "TXT":
		return libdns.TXT{Name: rr.Name, TTL: rr.TTL, Text: rr.Data}
	default:
		return rr
	}
}

func (p *fakeDNSProvider) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	p.dns.mu.Lock()
	defer p.dns.mu.Unlock()
	p.dns.gets++
	if p.dns.getErr != nil {
		return nil, p.dns.getErr
	}
	out := make([]libdns.Record, 0, len(p.dns.records[zone]))
	for _, rr := range p.dns.records[zone] {
		out = append(out, toTyped(rr))
	}
	return out, nil
}

func (p *fakeDNSProvider) SetRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.dns.mu.Lock()
	defer p.dns.mu.Unlock()
	p.dns.sets++
	for _, rec := range recs {
		rr := rec.RR()
		kept := p.dns.records[zone][:0]
		for _, existing := range p.dns.records[zone] {
			if existing.Name == rr.Name && existing.Type == rr.Type {
				continue
			}
			kept = append(kept, existing)
		}
		p.dns.records[zone] = append(kept, rr)
	}
	return recs, nil
}

func (p *fakeDNSProvider) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.dns.mu.Lock()
	defer p.dns.mu.Unlock()
	p.dns.deletes++
	var deleted []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		kept := p.dns.records[zone][:0]
		for _, existing := range p.dns.records[zone] {
			if existing.Name == rr.Name && existing.Type == rr.Type && (rr.Data == "" || existing.Data == rr.Data) {
				deleted = append(deleted, existing)
				continue
			}
			kept = append(kept, existing)
		}
		p.dns.records[zone] = kept
	}
	return deleted, nil
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type zoneHarness struct {
	t      *testing.T
	ctx    context.Context
	db     *sql.DB
	fleet  *fakeZoneFleet
	dns    *fakeDNS
	issuer *fakeCertIssuer
	rec    *zoneReconciler
	now    time.Time
	logs   []string
	logsMu sync.Mutex
}

func newZoneHarness(t *testing.T, machines ...ZoneMachine) *zoneHarness {
	t.Helper()
	return newZoneHarnessInside(t, "hase.de", "hase.de", "baum.hase.de", machines...)
}

// newZoneHarnessInside is newZoneHarness with the Public DNS Zone living
// inside the Cloudflare zone cloudflareZone and domain claimed under it for
// acme/zp. The release hooks use the harness's fake DNS too.
func newZoneHarnessInside(t *testing.T, zone, cloudflareZone, domain string, machines ...ZoneMachine) *zoneHarness {
	t.Helper()
	db := newClaimsTestDB(t)
	addZoneInside(t, db, zone, cloudflareZone)
	claim(t, db, domain, "acme", "zp")
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	h := &zoneHarness{t: t, ctx: context.Background(), db: db, fleet: newFakeZoneFleet(machines...), dns: newFakeDNS(), now: now}
	h.issuer = &fakeCertIssuer{now: now, lifetime: 90 * 24 * time.Hour}
	h.rec = newZoneReconciler(db, h.fleet, h.issuer, LetsEncryptStagingDirectory, func(level, format string, args ...any) {
		h.logsMu.Lock()
		defer h.logsMu.Unlock()
		h.logs = append(h.logs, level+" "+fmt.Sprintf(format, args...))
	})
	h.rec.providers = h.dns.provider
	h.rec.now = func() time.Time { return h.now }
	old := newZoneDNSProvider
	newZoneDNSProvider = h.dns.provider
	t.Cleanup(func() { newZoneDNSProvider = old })
	return h
}

func (h *zoneHarness) pass() error {
	h.t.Helper()
	err := h.rec.Reconcile(h.ctx)
	h.rec.waitOrders()
	return err
}

// passes runs n passes, failing on any error.
func (h *zoneHarness) passes(n int) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		if err := h.pass(); err != nil {
			h.t.Fatalf("pass %d: %v", i, err)
		}
	}
}

func (h *zoneHarness) row(hostname string) machineCertificate {
	h.t.Helper()
	row, err := getMachineCertificate(h.ctx, h.db, hostname)
	if err != nil {
		h.t.Fatalf("row %s: %v", hostname, err)
	}
	return row
}

func (h *zoneHarness) state(hostname string) string {
	return machineCertificateState(h.row(hostname), LetsEncryptStagingDirectory, h.now)
}

func (h *zoneHarness) logged(substr string) int {
	h.logsMu.Lock()
	defer h.logsMu.Unlock()
	n := 0
	for _, line := range h.logs {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// claimHostname reserves an explicit hostname for acme/<project>:<machine>.
func (h *zoneHarness) claimHostname(hostname, project, machine string) MachineHostname {
	h.t.Helper()
	row, err := ClaimMachineHostname(h.ctx, h.db, ClaimMachineHostnameRequest{Hostname: hostname, Tenant: "acme", Project: project, Machine: machine})
	if err != nil {
		h.t.Fatalf("claim %s: %v", hostname, err)
	}
	return row
}

// requestExplicit records the pending row `sc hostname add` leaves.
func (h *zoneHarness) requestExplicit(row MachineHostname) {
	h.t.Helper()
	if _, err := requestMachineCertificate(h.ctx, h.db, machineCertificateRequest{
		Hostname: row.Hostname, Tenant: row.Tenant, Project: row.Project, Machine: row.Machine, Zone: row.Zone, DirectoryURL: LetsEncryptStagingDirectory,
	}, h.now); err != nil {
		h.t.Fatal(err)
	}
}

// zoneMachine is a machine of acme/zp (domain baum.hase.de) stamped by sc
// create with its derived name.
func zoneMachine(name, ip string, running bool) ZoneMachine {
	return ZoneMachine{Tenant: "acme", Project: "zp", IncusProject: "sc2-acme-zp", Name: name,
		ProjectDomain: "baum.hase.de", PublicHostnames: []string{name + ".baum.hase.de"}, BridgeIPv4: ip, Running: running}
}

// privateMachine is a machine of acme/default (no Project Domain).
func privateMachine(name, ip string, running bool) ZoneMachine {
	return ZoneMachine{Tenant: "acme", Project: "default", IncusProject: "sc2-acme-default", Name: name, BridgeIPv4: ip, Running: running}
}

// markerFor is a per-name Caddy Setup Marker (ADR-0028) of a machine whose
// private name is web.zp.acme; the public hostname is what the test expects
// to be pushed, but the gate clears for any name (the block renders after
// the push).
func markerFor(hostname string) string {
	return "PRIVATE=web.zp.acme\nPUBLIC=" + hostname + "\nRENDERED=1757760000\n"
}

// ready gives a machine a per-name marker and a hostnames file listing its
// current names, i.e. the state caddy-setup leaves after a correct seed.
func (h *zoneHarness) ready(incusProject, name string, hostnames ...string) {
	h.fleet.setFile(incusProject, name, tenant.CaddySetupMarkerPath, "PRIVATE="+name+".zp.acme\nRENDERED=1757760000\n")
	h.fleet.setFile(incusProject, name, tenant.MachineHostnamesPath, tenant.FormatMachineHostnamesFile(hostnames))
}

func recordNames(rrs []libdns.RR, typ string) []string {
	var out []string
	for _, rr := range rrs {
		if rr.Type == typ {
			out = append(out, rr.Name+"="+rr.Data)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestZoneReconcile_RecordConvergence(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	stopped := zoneMachine("old", "", false) // stopped: no lease, records stay
	private := privateMachine("p", "10.249.7.3", true)
	private.PublicHostname = meta.NamingModePrivate // a legacy stamp: deleted, never a name
	h := newZoneHarness(t, web, stopped, private)
	h.dns.add("hase.de.", libdns.RR{Name: "old.baum", Type: "A", Data: "10.249.7.5"})
	h.dns.add("hase.de.", libdns.RR{Name: "*.old.baum", Type: "A", Data: "10.249.7.5"})
	h.dns.add("hase.de.", libdns.RR{Name: "gone.baum", Type: "A", Data: "10.249.7.6"})   // deleted machine
	h.dns.add("hase.de.", libdns.RR{Name: "*.gone.baum", Type: "A", Data: "10.249.7.6"}) // deleted machine
	h.dns.add("hase.de.", libdns.RR{Name: "www", Type: "A", Data: "203.0.113.1"})        // not under a claimed domain
	h.dns.add("hase.de.", libdns.RR{Name: "web.baum", Type: "A", Data: "10.249.7.1"})    // stale address

	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	got := recordNames(h.dns.list("hase.de."), "A")
	want := []string{"*.old.baum=10.249.7.5", "*.web.baum=10.249.7.9", "old.baum=10.249.7.5", "web.baum=10.249.7.9", "www=203.0.113.1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("A records = %v, want %v", got, want)
	}
	if h.dns.gets != 1 {
		t.Fatalf("GetRecords calls = %d, want exactly one per zone per pass", h.dns.gets)
	}
	if h.dns.tokens[0] != "tok" {
		t.Fatalf("provider token = %q, want the zone's decrypted token", h.dns.tokens[0])
	}
	// The legacy key is deleted on the private machine; nothing else about
	// it is touched (no records, no mirror).
	if m := h.fleet.machine("sc2-acme-default", "p"); m.PublicHostname != "" || len(m.PublicHostnames) != 0 || m.CertState != "" {
		t.Fatalf("private machine after pass: %+v", m)
	}
	// A second pass with nothing changed makes no writes.
	sets, deletes, stamps := h.dns.sets, h.dns.deletes, len(h.fleet.stamps)
	if err := h.pass(); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if h.dns.sets != sets || h.dns.deletes != deletes || len(h.fleet.stamps) != stamps {
		t.Fatalf("unchanged fleet wrote: sets %d→%d deletes %d→%d stamps %d→%d", sets, h.dns.sets, deletes, h.dns.deletes, stamps, len(h.fleet.stamps))
	}
}

// A Public DNS Zone inside its Cloudflare zone (e2e.sc.tc42.uk in tc42.uk):
// every libdns call is addressed to the Cloudflare zone and every record name
// is relative to it — for convergence, the challenge sweep and the release.
func TestZoneReconcile_ZoneInsideCloudflareZone(t *testing.T) {
	const cf = "tc42.uk."
	web := ZoneMachine{Tenant: "acme", Project: "zp", IncusProject: "sc2-acme-zp", Name: "web",
		ProjectDomain: "baum.e2e.sc.tc42.uk", PublicHostnames: []string{"web.baum.e2e.sc.tc42.uk"}, BridgeIPv4: "10.249.7.9", Running: true}
	h := newZoneHarnessInside(t, "e2e.sc.tc42.uk", "tc42.uk", "baum.e2e.sc.tc42.uk", web)
	h.dns.add(cf, libdns.RR{Name: "gone.baum.e2e.sc", Type: "A", Data: "10.249.7.6"})   // deleted machine under the domain
	h.dns.add(cf, libdns.RR{Name: "*.gone.baum.e2e.sc", Type: "A", Data: "10.249.7.6"}) // deleted machine under the domain
	h.dns.add(cf, libdns.RR{Name: "web.baum.e2e.sc", Type: "A", Data: "10.249.7.1"})    // stale address
	h.dns.add(cf, libdns.RR{Name: "other.e2e.sc", Type: "A", Data: "203.0.113.2"})      // in the zone, not under a claimed domain
	h.dns.add(cf, libdns.RR{Name: "www", Type: "A", Data: "203.0.113.1"})               // Cloudflare zone apex neighbour
	h.dns.add(cf, libdns.RR{Name: "_acme-challenge.web.baum.e2e.sc", Type: "TXT", Data: "left-over"})
	h.dns.add(cf, libdns.RR{Name: "_acme-challenge.web.baum", Type: "TXT", Data: "unrelated"}) // web.baum.tc42.uk, not ours
	if _, err := requestMachineCertificate(h.ctx, h.db, machineCertificateRequest{
		Hostname: "web.baum.e2e.sc.tc42.uk", Tenant: "acme", Project: "zp", Machine: "web", Zone: "e2e.sc.tc42.uk", DirectoryURL: LetsEncryptStagingDirectory,
	}, h.now); err != nil {
		t.Fatal(err)
	}

	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	got := recordNames(h.dns.list(cf), "A")
	want := []string{"*.web.baum.e2e.sc=10.249.7.9", "other.e2e.sc=203.0.113.2", "web.baum.e2e.sc=10.249.7.9", "www=203.0.113.1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("A records in %s = %v, want %v", cf, got, want)
	}
	if len(h.dns.list("e2e.sc.tc42.uk.")) != 0 {
		t.Fatalf("records written to the Public DNS Zone name instead of the Cloudflare zone: %v", h.dns.list("e2e.sc.tc42.uk."))
	}
	gotTXT := recordNames(h.dns.list(cf), "TXT")
	if strings.Join(gotTXT, ",") != "_acme-challenge.web.baum=unrelated" {
		t.Fatalf("TXT after sweep = %v", gotTXT)
	}
	if h.logged("swept 1 leftover challenge record(s)") != 1 {
		t.Fatal("sweep not logged")
	}
	// The issuer is keyed by the Public DNS Zone (that is where the token
	// lives); certmagic finds the Cloudflare zone by itself.
	if len(h.issuer.calls) != 1 || h.issuer.calls[0].Zone != "e2e.sc.tc42.uk" || strings.Join(h.issuer.calls[0].Hostnames, ",") != "web.baum.e2e.sc.tc42.uk,*.web.baum.e2e.sc.tc42.uk" {
		t.Fatalf("issuer calls = %+v", h.issuer.calls)
	}

	// Release: A + challenge records under the domain go, relative to the
	// Cloudflare zone; the neighbours stay.
	h.dns.add(cf, libdns.RR{Name: "_acme-challenge.web.baum.e2e.sc", Type: "TXT", Data: "mid-order"})
	c, found, err := ReleaseProjectDomainClaim(h.ctx, h.db, "acme", "zp")
	if err != nil || !found {
		t.Fatalf("release: %v %v", found, err)
	}
	if err := onProjectDomainReleased(h.ctx, h.db, c); err != nil {
		t.Fatalf("hook: %v", err)
	}
	got = recordNames(h.dns.list(cf), "A")
	if strings.Join(got, ",") != "other.e2e.sc=203.0.113.2,www=203.0.113.1" {
		t.Fatalf("A records after release = %v", got)
	}
	gotTXT = recordNames(h.dns.list(cf), "TXT")
	if strings.Join(gotTXT, ",") != "_acme-challenge.web.baum=unrelated" {
		t.Fatalf("TXT after release = %v", gotTXT)
	}
}

// A Freeform Machine (no list key) in a claimed project is stamped with its
// derived name as a LIST on first sight, gets its records, and — once the
// per-name marker appears — a row, an order and a push. A machine in a
// project without a domain and without names is never stamped.
func TestZoneReconcile_FreeformStampAndRow(t *testing.T) {
	freeform := ZoneMachine{Tenant: "acme", Project: "zp", IncusProject: "sc2-acme-zp", Name: "ff", ProjectDomain: "baum.hase.de", BridgeIPv4: "10.249.7.20", Running: true}
	privateProject := privateMachine("dev", "10.249.7.21", true)
	h := newZoneHarness(t, freeform, privateProject)
	// No marker yet: A record, no row, mirrored pending.
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	ff := h.fleet.machine("sc2-acme-zp", "ff")
	if strings.Join(ff.PublicHostnames, ",") != "ff.baum.hase.de" || ff.PublicHostname != "" {
		t.Fatalf("freeform stamp = %+v", ff)
	}
	if h.logged("stamped sc2-acme-zp/ff "+meta.KeyV2PublicHostnames+"=ff.baum.hase.de") != 1 {
		t.Fatalf("stamp not logged: %v", h.logs)
	}
	if dev := h.fleet.machine("sc2-acme-default", "dev"); dev.PublicHostname != "" || len(dev.PublicHostnames) != 0 || dev.CertState != "" {
		t.Fatalf("private-project machine touched: %+v", dev)
	}
	for _, s := range h.fleet.stamps {
		if s.Instance == "sc2-acme-default/dev" {
			t.Fatalf("private-project machine stamped: %+v", s)
		}
	}
	if _, err := getMachineCertificate(h.ctx, h.db, "ff.baum.hase.de"); err == nil {
		t.Fatal("row created without a marker")
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); len(got) != 2 {
		t.Fatalf("A records = %v, want base + wildcard", got)
	}
	if got := h.fleet.machine("sc2-acme-zp", "ff").CertState; got != "ff.baum.hase.de=pending" {
		t.Fatalf("cert-state = %q, want per-name pending", got)
	}
	if h.logged("no caddy setup marker") != 1 {
		t.Fatalf("marker-absent logged %d times, want once", h.logged("no caddy setup marker"))
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.logged("no caddy setup marker") != 1 {
		t.Fatal("marker-absent logged again on the next pass")
	}
	// Marker appears (seeded file lists the name): row created, order runs,
	// push happens, mirror installed.
	h.ready("sc2-acme-zp", "ff", "ff.baum.hase.de")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(h.issuer.calls) != 1 || h.issuer.calls[0].Zone != "hase.de" || strings.Join(h.issuer.calls[0].Hostnames, ",") != "ff.baum.hase.de,*.ff.baum.hase.de" {
		t.Fatalf("issuer calls = %+v", h.issuer.calls)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.pushCount() != 1 || h.fleet.pushes[0].Hostname != "ff.baum.hase.de" {
		t.Fatalf("pushes = %+v, want one push for ff.baum.hase.de", h.fleet.pushes)
	}
	if h.fleet.hostnamePushCount() != 0 {
		t.Fatalf("a correctly seeded hostnames file was pushed: %+v", h.fleet.hostnamePushes)
	}
	m := h.fleet.machine("sc2-acme-zp", "ff")
	row := h.row("ff.baum.hase.de")
	if m.CertState != "ff.baum.hase.de=installed" || m.CertNotAfter != formatCertTime(row.NotAfter) || row.PushedSerial != row.Serial {
		t.Fatalf("after push: state=%q notAfter=%q pushed=%q serial=%q", m.CertState, m.CertNotAfter, row.PushedSerial, row.Serial)
	}
}

func TestZoneReconcile_PushGateNoMarkerNoPush(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	// Row from sc create: the order runs without any marker (DNS-01 needs
	// no machine) …
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(h.issuer.calls) != 1 {
		t.Fatalf("issuer calls = %d, want 1", len(h.issuer.calls))
	}
	// … but nothing is pushed until a per-name marker is there: absent,
	// legacy (ADR-0027 MODE= markers, whatever they name) or garbage.
	for _, marker := range []string{"", "MODE=private\nFQDN=web.zp.acme\n", "MODE=zone\nFQDN=web.baum.hase.de\n", "garbage"} {
		if marker != "" {
			h.fleet.setFile("sc2-acme-zp", "web", tenant.CaddySetupMarkerPath, marker)
		}
		if err := h.pass(); err != nil {
			t.Fatalf("pass (%q): %v", marker, err)
		}
		if h.fleet.pushCount() != 0 || h.fleet.hostnamePushCount() != 0 {
			t.Fatalf("pushed with marker %q", marker)
		}
		if h.state("web.baum.hase.de") != machineCertStateIssued || h.fleet.machine("sc2-acme-zp", "web").CertState != "web.baum.hase.de=issued" {
			t.Fatalf("state with marker %q = %s / %s, want issued", marker, h.state("web.baum.hase.de"), h.fleet.machine("sc2-acme-zp", "web").CertState)
		}
	}
	if n := h.logged("A record only"); n != 4 {
		t.Fatalf("gate logged %d times, want once per distinct marker (4): %v", n, h.logs)
	}
	// A per-name marker that does not list the hostname yet (its block
	// cannot render before the push) clears the gate.
	h.fleet.setFile("sc2-acme-zp", "web", tenant.CaddySetupMarkerPath, "PRIVATE=web.zp.acme\nRENDERED=1757760000\n")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.pushCount() != 1 {
		t.Fatal("per-name marker did not push")
	}
	push := h.fleet.pushes[0]
	if push.Hostname != "web.baum.hase.de" {
		t.Fatalf("push hostname = %q", push.Hostname)
	}
	if !strings.Contains(push.KeyPEM, "PRIVATE KEY") || !strings.Contains(push.CertPEM, "CERTIFICATE") {
		t.Fatalf("push carried cert=%q key=%q", push.CertPEM[:20], push.KeyPEM[:20])
	}
	// A stopped machine is never pushed to, and stays issued.
	h.fleet.setFile("sc2-acme-zp", "web", tenant.MachineTLSHostCertPath("web.baum.hase.de"), "tampered")
	h.fleet.mu.Lock()
	h.fleet.machines[0].Running = false
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.pushCount() != 1 {
		t.Fatal("pushed to a stopped machine")
	}
}

func TestZoneReconcile_PushFailureRetriesWithoutBackoff(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	h.fleet.pushErr = errors.New("command exited with status 1 (stderr: mv: cannot move)")
	err := h.pass()
	if err == nil || !strings.Contains(err.Error(), "push certificate") {
		t.Fatalf("push failure not reported: %v", err)
	}
	row := h.row("web.baum.hase.de")
	if row.PushedSerial != "" || row.Attempts != 0 || row.LastError != "" {
		t.Fatalf("push failure touched order bookkeeping: %+v", row)
	}
	h.fleet.pushErr = nil
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.pushCount() != 1 || h.state("web.baum.hase.de") != machineCertStateInstalled {
		t.Fatalf("retry did not push: pushes=%d state=%s", h.fleet.pushCount(), h.state("web.baum.hase.de"))
	}
}

func TestZoneReconcile_SchedulingAndBackoff(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.issuer.err = errors.New("acme: authorization failed: challenge invalid")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	row := h.row("web.baum.hase.de")
	if row.Attempts != 1 || !row.NextAttemptAt.Equal(h.now.Add(time.Minute)) || !strings.Contains(row.LastError, "challenge invalid") {
		t.Fatalf("after first failure: %+v", row)
	}
	if got := h.state("web.baum.hase.de"); got != "failed:validation" {
		t.Fatalf("state = %s", got)
	}
	// In backoff: no order; the failure is mirrored (the order finished
	// after the pass mirrored, and kicked the loop for this pass).
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.machine("sc2-acme-zp", "web").CertState != "web.baum.hase.de=failed:validation" {
		t.Fatalf("mirror = %q", h.fleet.machine("sc2-acme-zp", "web").CertState)
	}
	if len(h.issuer.calls) != 1 {
		t.Fatalf("ordered while in backoff: %d calls", len(h.issuer.calls))
	}
	// Walk the ladder: 1m, 5m, 30m, 2h, 6h, 6h.
	wantSteps := []time.Duration{5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 6 * time.Hour}
	for i, step := range wantSteps {
		h.now = h.row("web.baum.hase.de").NextAttemptAt
		if err := h.pass(); err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		row = h.row("web.baum.hase.de")
		if row.Attempts != i+2 || !row.NextAttemptAt.Equal(h.now.Add(step)) {
			t.Fatalf("step %d: attempts=%d next=%s want +%s", i, row.Attempts, row.NextAttemptAt.Sub(h.now), step)
		}
	}
	// Rate limit jumps straight to 6h.
	h.now = h.row("web.baum.hase.de").NextAttemptAt
	h.issuer.err = errors.New("acme: urn:ietf:params:acme:error:rateLimited: too many certificates")
	if _, err := resetMachineCertificate(h.ctx, h.db, "web.baum.hase.de", LetsEncryptStagingDirectory, h.now); err != nil {
		t.Fatal(err)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	row = h.row("web.baum.hase.de")
	if !row.NextAttemptAt.Equal(h.now.Add(6*time.Hour)) || h.state("web.baum.hase.de") != "failed:rate-limited" {
		t.Fatalf("rate limit: next=+%s state=%s", row.NextAttemptAt.Sub(h.now), h.state("web.baum.hase.de"))
	}
	// Success resets the bookkeeping.
	h.now = row.NextAttemptAt
	h.issuer.err = nil
	h.issuer.now = h.now
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	row = h.row("web.baum.hase.de")
	if row.Attempts != 0 || row.LastError != "" || !row.NextAttemptAt.IsZero() || !row.hasCertificate() {
		t.Fatalf("after success: %+v", row)
	}
	if !row.RenewAfter.Equal(h.now.Add(60*24*time.Hour)) || !row.ARICheckAfter.Equal(h.now.Add(6*time.Hour)) {
		t.Fatalf("schedule after issue: renew=%s ari=%s", row.RenewAfter.Sub(h.now), row.ARICheckAfter.Sub(h.now))
	}
}

func TestZoneReconcile_ARIAndRenewalRotatesKey(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", false) // stopped: renews regardless
	h := newZoneHarness(t, web)
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	first := h.row("web.baum.hase.de")
	if !first.hasCertificate() {
		t.Fatal("stopped machine was not ordered for")
	}
	// ARI check due: the CA's window is stored, Retry-After honoured.
	h.now = first.ARICheckAfter
	h.issuer.renewAfter = h.now.Add(48 * time.Hour)
	h.issuer.retryAfter = h.now.Add(2 * time.Hour)
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	row := h.row("web.baum.hase.de")
	if !row.RenewAfter.Equal(h.issuer.renewAfter) || !row.ARICheckAfter.Equal(h.issuer.retryAfter) {
		t.Fatalf("ARI stored: renew=%s ari=%s", row.RenewAfter, row.ARICheckAfter)
	}
	if len(h.issuer.calls) != 1 {
		t.Fatalf("ARI check ordered: %d calls", len(h.issuer.calls))
	}
	// ARI error: fallback window stays, next check in 6h.
	h.now = row.ARICheckAfter
	h.issuer.renewErr = errors.New("ari: 503")
	if err := h.pass(); err == nil || !strings.Contains(err.Error(), "renewal info") {
		t.Fatalf("ARI error not reported: %v", err)
	}
	row = h.row("web.baum.hase.de")
	if !row.RenewAfter.Equal(h.issuer.renewAfter) || !row.ARICheckAfter.Equal(h.now.Add(6*time.Hour)) {
		t.Fatalf("after ARI error: renew=%s ari=%s", row.RenewAfter, row.ARICheckAfter.Sub(h.now))
	}
	h.issuer.renewErr = nil
	// Renewal window: a new order with a fresh key; the old cert stays
	// installed (pushed_serial) until the new one is pushed.
	if _, err := setMachineCertificatePushedSerial(h.ctx, h.db, "web.baum.hase.de", row.Serial, h.now); err != nil {
		t.Fatal(err)
	}
	h.now = row.RenewAfter
	h.issuer.now = h.now
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	renewed := h.row("web.baum.hase.de")
	if len(h.issuer.calls) != 2 || renewed.Serial == row.Serial || renewed.EncryptedKeyPEM == row.EncryptedKeyPEM {
		t.Fatalf("renewal: calls=%d serial %s→%s key rotated=%v", len(h.issuer.calls), row.Serial, renewed.Serial, renewed.EncryptedKeyPEM != row.EncryptedKeyPEM)
	}
	if renewed.PushedSerial != row.Serial || h.state("web.baum.hase.de") != machineCertStateIssued {
		t.Fatalf("renewed row: pushed=%s state=%s", renewed.PushedSerial, h.state("web.baum.hase.de"))
	}
	if err := h.pass(); err != nil { // the kicked pass mirrors the new row
		t.Fatalf("pass: %v", err)
	}
	if m := h.fleet.machine("sc2-acme-zp", "web"); m.CertState != "web.baum.hase.de=issued" {
		t.Fatalf("mirror after renewal = %q", m.CertState)
	}
}

func TestZoneReconcile_ConcurrencyCapAndNoDuplicateOrders(t *testing.T) {
	var machines []ZoneMachine
	for i := 0; i < 6; i++ {
		machines = append(machines, zoneMachine(fmt.Sprintf("m%d", i), fmt.Sprintf("10.249.7.%d", 10+i), true))
	}
	h := newZoneHarness(t, machines...)
	for i := 0; i < 6; i++ {
		if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest(fmt.Sprintf("m%d.baum.hase.de", i)), h.now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	// Orders block until released, so a second pass runs while four are in
	// flight: it must neither exceed the cap nor re-order a busy hostname.
	release := make(chan struct{})
	started := make(chan string, 16)
	blocking := &blockingIssuer{inner: h.issuer, release: release, started: started}
	h.rec.issuer = blocking
	if err := h.rec.Reconcile(h.ctx); err != nil {
		t.Fatalf("pass: %v", err)
	}
	var inFlight []string
	for len(inFlight) < zoneMaxConcurrentOrder {
		select {
		case name := <-started:
			inFlight = append(inFlight, name)
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d orders started", len(inFlight))
		}
	}
	if err := h.rec.Reconcile(h.ctx); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	select {
	case name := <-started:
		t.Fatalf("second pass started %s beyond the cap", name)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	h.rec.waitOrders()
	if err := h.pass(); err != nil {
		t.Fatalf("third pass: %v", err)
	}
	h.rec.waitOrders()
	calls := blocking.calls()
	sort.Strings(calls)
	if strings.Join(calls, ",") != "*.m0.baum.hase.de,*.m1.baum.hase.de,*.m2.baum.hase.de,*.m3.baum.hase.de,*.m4.baum.hase.de,*.m5.baum.hase.de" {
		t.Fatalf("orders = %v, want exactly one per hostname", calls)
	}
}

// blockingIssuer holds every Issue until release is closed.
type blockingIssuer struct {
	inner   *fakeCertIssuer
	release chan struct{}
	started chan string
	mu      sync.Mutex
	names   []string
}

func (b *blockingIssuer) Issue(ctx context.Context, zone string, hostnames []string) (issuedCertificate, error) {
	b.mu.Lock()
	b.names = append(b.names, hostnames[1])
	b.mu.Unlock()
	b.started <- hostnames[0]
	<-b.release
	return b.inner.Issue(ctx, zone, hostnames)
}

func (b *blockingIssuer) RenewalInfo(ctx context.Context, certPEM string) (time.Time, time.Time, error) {
	return b.inner.RenewalInfo(ctx, certPEM)
}

func (b *blockingIssuer) calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.names...)
}

func TestZoneReconcile_TXTSweepBeforeOrder(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.dns.add("hase.de.", libdns.RR{Name: "_acme-challenge.web.baum", Type: "TXT", Data: "left-over-1"})
	h.dns.add("hase.de.", libdns.RR{Name: "_acme-challenge.web.baum", Type: "TXT", Data: "left-over-2"})
	h.dns.add("hase.de.", libdns.RR{Name: "_acme-challenge.other.baum", Type: "TXT", Data: "keep"})
	h.dns.add("hase.de.", libdns.RR{Name: "web.baum", Type: "TXT", Data: "keep-too"})
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	got := recordNames(h.dns.list("hase.de."), "TXT")
	want := []string{"_acme-challenge.other.baum=keep", "web.baum=keep-too"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("TXT after sweep = %v, want %v", got, want)
	}
	if h.logged("swept 2 leftover challenge record(s)") != 1 {
		t.Fatal("sweep not logged")
	}
	if len(h.issuer.calls) != 1 {
		t.Fatalf("order did not run after the sweep: %d", len(h.issuer.calls))
	}
	// A sweep failure aborts the order and counts as an attempt.
	h.dns.getErr = errors.New("cloudflare: 500")
	if _, err := resetMachineCertificate(h.ctx, h.db, "web.baum.hase.de", LetsEncryptStagingDirectory, h.now); err != nil {
		t.Fatal(err)
	}
	if err := h.pass(); err == nil {
		t.Fatal("zone read failure not reported")
	}
	if len(h.issuer.calls) != 1 || h.row("web.baum.hase.de").Attempts != 1 {
		t.Fatalf("order ran despite sweep failure: calls=%d attempts=%d", len(h.issuer.calls), h.row("web.baum.hase.de").Attempts)
	}
}

func TestZoneReconcile_DriftRePush(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.passes(2)
	if h.fleet.pushCount() != 1 {
		t.Fatalf("pushes = %d", h.fleet.pushCount())
	}
	// Matching fingerprint: no re-push.
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.pushCount() != 1 {
		t.Fatal("re-pushed without drift")
	}
	// Manual edit: re-pushed within one pass, no new order.
	h.fleet.setFile("sc2-acme-zp", "web", tenant.MachineTLSHostCertPath("web.baum.hase.de"), h.fleet.pushes[0].CertPEM+"x\n")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.pushCount() != 2 || h.fleet.pushes[1].Hostname != "web.baum.hase.de" {
		t.Fatalf("drift re-push: pushes=%d hostname=%q", h.fleet.pushCount(), h.fleet.pushes[len(h.fleet.pushes)-1].Hostname)
	}
	if len(h.issuer.calls) != 1 {
		t.Fatal("drift caused a new order")
	}
	if h.logged("differs from the issued one") != 1 {
		t.Fatal("drift not logged")
	}
	// Rebuilt machine (file gone) counts as drift too.
	h.fleet.mu.Lock()
	delete(h.fleet.files, "sc2-acme-zp/web:"+tenant.MachineTLSHostCertPath("web.baum.hase.de"))
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.pushCount() != 3 {
		t.Fatalf("missing file did not re-push: %d", h.fleet.pushCount())
	}
	// Unreachable: skipped, retried next pass, no state change.
	h.fleet.unreachable["sc2-acme-zp/web"] = true
	if err := h.pass(); err == nil || !strings.Contains(err.Error(), "drift check") {
		t.Fatalf("unreachable not reported: %v", err)
	}
	if h.fleet.pushCount() != 3 || h.state("web.baum.hase.de") != machineCertStateInstalled {
		t.Fatalf("unreachable changed state: pushes=%d state=%s", h.fleet.pushCount(), h.state("web.baum.hase.de"))
	}
}

func TestZoneReconcile_MirroringWritesOnlyChanges(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	// First sight: the per-name pending state is stamped; the list key
	// (already set by sc create) is not rewritten.
	if len(h.fleet.stamps) != 1 || h.fleet.stamps[0].Config[meta.KeyV2CertState] != "web.baum.hase.de=pending" {
		t.Fatalf("stamps = %+v", h.fleet.stamps)
	}
	for _, key := range []string{meta.KeyV2PublicHostname, meta.KeyV2PublicHostnames} {
		if _, ok := h.fleet.stamps[0].Config[key]; ok {
			t.Fatalf("%s rewritten", key)
		}
	}
	// The order ran in the goroutine; next pass pushes and mirrors installed.
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	m := h.fleet.machine("sc2-acme-zp", "web")
	if m.CertState != "web.baum.hase.de=installed" || m.CertNotAfter == "" {
		t.Fatalf("mirror = %q / %q", m.CertState, m.CertNotAfter)
	}
	stamps := len(h.fleet.stamps)
	h.passes(3)
	if len(h.fleet.stamps) != stamps {
		t.Fatalf("unchanged fleet stamped %d more time(s)", len(h.fleet.stamps)-stamps)
	}
	// Renewing: past renew_after the mirror flips, not-after stays.
	h.now = h.row("web.baum.hase.de").RenewAfter
	h.issuer.err = errors.New("boom")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	m = h.fleet.machine("sc2-acme-zp", "web")
	if m.CertState != "web.baum.hase.de=renewing" || m.CertNotAfter == "" {
		t.Fatalf("renewing mirror = %q / %q", m.CertState, m.CertNotAfter)
	}
	if got := h.state("web.baum.hase.de"); got != machineCertStateRenewing {
		t.Fatalf("state = %s (a failed renewal keeps the installed cert)", got)
	}
}

func TestZoneReconcile_GCRetentionAndReuse(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	// Rows of absent machines that hold nothing: dropped at once.
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("never.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.passes(2)
	if _, err := getMachineCertificate(h.ctx, h.db, "never.baum.hase.de"); err == nil {
		t.Fatal("never-issued row of an absent machine retained")
	}
	issued := h.row("web.baum.hase.de")
	if issued.PushedSerial != issued.Serial {
		t.Fatalf("not installed: %+v", issued)
	}
	// Machine deleted (its rootfs with it): A records go, the row stays with
	// its certificate.
	h.fleet.mu.Lock()
	h.fleet.machines = []ZoneMachine{zoneMachine("other", "10.249.7.10", true)}
	h.fleet.files = map[string]string{}
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); strings.Join(got, ",") != "*.other.baum=10.249.7.10,other.baum=10.249.7.10" {
		t.Fatalf("A records after delete = %v", got)
	}
	retained := h.row("web.baum.hase.de")
	if retained.Serial != issued.Serial {
		t.Fatal("row not retained across delete")
	}
	// Machine reappears as a Freeform Machine with the marker: the retained
	// certificate is pushed, no new order.
	back := zoneMachine("web", "10.249.7.11", true)
	back.PublicHostnames = nil
	h.fleet.mu.Lock()
	h.fleet.machines = append(h.fleet.machines, back)
	h.fleet.mu.Unlock()
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	orders := len(h.issuer.calls)
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(h.issuer.calls) != orders {
		t.Fatal("reappearing machine spent an order")
	}
	if h.fleet.pushCount() != 2 || h.row("web.baum.hase.de").Serial != issued.Serial {
		t.Fatalf("retained certificate not pushed: pushes=%d", h.fleet.pushCount())
	}
	if got := h.fleet.machine("sc2-acme-zp", "web").PublicHostnames; strings.Join(got, ",") != "web.baum.hase.de" {
		t.Fatalf("reappearing machine not stamped: %v", got)
	}
	// Expiry: an absent machine's row is dropped once the certificate is
	// past not_after; a row from another directory goes too.
	h.fleet.mu.Lock()
	h.fleet.machines = []ZoneMachine{zoneMachine("other", "10.249.7.10", true)}
	h.fleet.mu.Unlock()
	if _, err := h.db.ExecContext(h.ctx, `UPDATE machine_certificates SET directory_url = ? WHERE hostname = 'other.baum.hase.de'`, LetsEncryptProductionDirectory); err != nil {
		t.Fatal(err)
	}
	h.now = issued.NotAfter.Add(time.Second)
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if _, err := getMachineCertificate(h.ctx, h.db, "web.baum.hase.de"); err == nil {
		t.Fatal("expired row of an absent machine retained")
	}
	// Empty fleet: the row GC (the one non-self-healing step) is skipped, so
	// a never-issued row of an absent machine is not dropped.
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("ghost.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.fleet.mu.Lock()
	h.fleet.machines = nil
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if _, err := getMachineCertificate(h.ctx, h.db, "ghost.baum.hase.de"); err != nil {
		t.Fatal("empty fleet dropped a row")
	}
}

func TestZoneReconcile_DirectoryMismatchReorders(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if _, err := h.db.ExecContext(h.ctx, `UPDATE machine_certificates SET directory_url = ?`, LetsEncryptProductionDirectory); err != nil {
		t.Fatal(err)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	row := h.row("web.baum.hase.de")
	if len(h.issuer.calls) != 2 || row.DirectoryURL != LetsEncryptStagingDirectory || !row.hasCertificate() {
		t.Fatalf("directory switch: calls=%d row=%+v", len(h.issuer.calls), row)
	}
}

func TestZoneReconcile_OneMachineNeverFailsThePass(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	broken := zoneMachine("broken", "10.249.7.12", true)
	h := newZoneHarness(t, broken, web)
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	h.fleet.unreachable["sc2-acme-zp/broken"] = true
	for _, host := range []string{"web.baum.hase.de", "broken.baum.hase.de"} {
		if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest(host), h.now); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.pass(); err == nil || !strings.Contains(err.Error(), "sc2-acme-zp/broken") {
		t.Fatalf("broken machine not reported: %v", err)
	}
	err := h.pass()
	if err == nil || !strings.Contains(err.Error(), "broken.baum.hase.de") {
		t.Fatalf("broken machine not reported: %v", err)
	}
	if h.fleet.pushCount() != 1 || h.fleet.pushes[0].Instance != "sc2-acme-zp/web" {
		t.Fatalf("healthy machine not served: %+v", h.fleet.pushes)
	}
	// A listing failure aborts the pass without touching anything.
	h.fleet.listErr = errors.New("incus down")
	sets := h.dns.sets
	if err := h.pass(); err == nil || !strings.Contains(err.Error(), "incus down") {
		t.Fatalf("listing failure: %v", err)
	}
	if h.dns.sets != sets {
		t.Fatal("listing failure wrote records")
	}
}

// A project carrying KeyV2Domain without a claim: no derived name, no
// records, no stamps — the tenant may still repair it. An explicit hostname
// of such a machine is served regardless.
func TestZoneReconcile_UnclaimedDomainIsPrivateForDNS(t *testing.T) {
	unclaimed := ZoneMachine{Tenant: "acme", Project: "orphan", IncusProject: "sc2-acme-orphan", Name: "x", ProjectDomain: "loose.hase.de", PublicHostnames: []string{"x.loose.hase.de"}, BridgeIPv4: "10.249.7.30", Running: true}
	h := newZoneHarness(t, unclaimed)
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(h.dns.list("hase.de.")) != 0 || len(h.fleet.stamps) != 0 {
		t.Fatalf("unclaimed project got records/stamps: %v %v", h.dns.list("hase.de."), h.fleet.stamps)
	}
	if got := h.fleet.machine("sc2-acme-orphan", "x").PublicHostnames; strings.Join(got, ",") != "x.loose.hase.de" {
		t.Fatalf("unclaimed project's list rewritten: %v", got)
	}
	h.claimHostname("x12.hase.de", "orphan", "x")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); strings.Join(got, ",") != "*.x12=10.249.7.30,x12=10.249.7.30" {
		t.Fatalf("explicit name of an unclaimed-project machine not served: %v", got)
	}
	if len(h.fleet.stamps) != 0 {
		t.Fatalf("unclaimed project stamped: %+v", h.fleet.stamps)
	}
}

// The last zone-mode Machine of a zone is deleted while Machines remain in
// another zone: the deleted Machine's A records (base + wildcard) are GC'd on
// the next pass — the zone is reconciled because it holds a claim, even with
// no live target (the live e2e bug: records only went with the project).
func TestZoneReconcile_LastMachineInZoneDeletedGCsRecords(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	addZone(t, h.db, "igel.de")
	claim(t, h.db, "dachs.igel.de", "acme", "zp2")
	other := ZoneMachine{Tenant: "acme", Project: "zp2", IncusProject: "sc2-acme-zp2", Name: "api",
		ProjectDomain: "dachs.igel.de", PublicHostnames: []string{"api.dachs.igel.de"}, BridgeIPv4: "10.249.8.4", Running: true}
	h.fleet.mu.Lock()
	h.fleet.machines = append(h.fleet.machines, other)
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); len(got) != 2 {
		t.Fatalf("hase.de A records after first pass = %v", got)
	}
	// sc delete web: the tenant's only machine in hase.de is gone, api stays.
	h.fleet.mu.Lock()
	h.fleet.machines = []ZoneMachine{other}
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); len(got) != 0 {
		t.Fatalf("deleted machine's A records survived: %v", got)
	}
	if got := recordNames(h.dns.list("igel.de."), "A"); strings.Join(got, ",") != "*.api.dachs=10.249.8.4,api.dachs=10.249.8.4" {
		t.Fatalf("other zone's records = %v", got)
	}
	if h.logged("zone hase.de: deleted 2 stale A record(s)") != 1 {
		t.Fatalf("no stale-record deletion logged: %v", h.logs)
	}
}

// The whole fleet is empty after the last Machine is deleted: its A records
// are still GC'd and its valid certificate row is retained for reuse.
func TestZoneReconcile_EmptyFleetGCsRecordsKeepsRetainedRow(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	h.passes(2) // order, then push
	if h.state("web.baum.hase.de") != "installed" {
		t.Fatalf("state = %s, want installed", h.state("web.baum.hase.de"))
	}
	issued := h.row("web.baum.hase.de")
	// sc delete web: the fleet is empty, the rootfs is gone with it.
	h.fleet.mu.Lock()
	h.fleet.machines = nil
	h.fleet.files = map[string]string{}
	h.fleet.mu.Unlock()
	h.now = h.now.Add(time.Minute)
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); len(got) != 0 {
		t.Fatalf("empty fleet left A records: %v", got)
	}
	if h.logged("zone hase.de: deleted 2 stale A record(s)") != 1 {
		t.Fatalf("no stale-record deletion logged: %v", h.logs)
	}
	// The valid certificate row is retained for reuse (not_after is in the
	// future), untouched by the pass.
	if retained := h.row("web.baum.hase.de"); retained.Serial != issued.Serial || !retained.usable(LetsEncryptStagingDirectory, h.now) {
		t.Fatalf("row not retained across the empty fleet: %+v", retained)
	}
}

// A registered zone without a claim or a hostname has nothing to converge:
// no provider is built for it and Cloudflare is not read.
func TestZoneReconcile_ZoneWithoutClaimsIsNotRead(t *testing.T) {
	h := newZoneHarness(t)
	addZone(t, h.db, "igel.de")
	if _, err := h.db.ExecContext(h.ctx, `DELETE FROM project_domain_claims`); err != nil {
		t.Fatal(err)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.dns.gets != 0 || len(h.dns.tokens) != 0 {
		t.Fatalf("zones without claims were read: gets=%d providers=%d", h.dns.gets, len(h.dns.tokens))
	}
}

func TestOnProjectDomainReleased(t *testing.T) {
	h := newZoneHarness(t)
	dns := h.dns
	for _, host := range []string{"web.baum.hase.de", "b1.baum.hase.de"} {
		if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest(host), h.now); err != nil {
			t.Fatal(err)
		}
	}
	claim(t, h.db, "other.hase.de", "beta", "q")
	if _, err := requestMachineCertificate(h.ctx, h.db, machineCertificateRequest{Hostname: "m.other.hase.de", Tenant: "beta", Project: "q", Machine: "m", Zone: "hase.de", DirectoryURL: LetsEncryptStagingDirectory}, h.now); err != nil {
		t.Fatal(err)
	}
	dns.add("hase.de.", libdns.RR{Name: "web.baum", Type: "A", Data: "10.0.0.1"})
	dns.add("hase.de.", libdns.RR{Name: "*.web.baum", Type: "A", Data: "10.0.0.1"})
	dns.add("hase.de.", libdns.RR{Name: "_acme-challenge.web.baum", Type: "TXT", Data: "x"})
	dns.add("hase.de.", libdns.RR{Name: "m.other", Type: "A", Data: "10.0.0.2"})
	dns.add("hase.de.", libdns.RR{Name: "www", Type: "A", Data: "203.0.113.1"})
	c, found, err := ReleaseProjectDomainClaim(h.ctx, h.db, "acme", "zp")
	if err != nil || !found {
		t.Fatalf("release: %v %v", found, err)
	}
	if err := onProjectDomainReleased(h.ctx, h.db, c); err != nil {
		t.Fatalf("hook: %v", err)
	}
	rows, _ := listAllMachineCertificates(h.ctx, h.db)
	if len(rows) != 1 || rows[0].Hostname != "m.other.hase.de" {
		t.Fatalf("rows after release = %+v", rows)
	}
	got := dns.list("hase.de.")
	if len(got) != 2 || got[0].Name != "m.other" || got[1].Name != "www" {
		t.Fatalf("records after release = %+v", got)
	}
}

func TestDesiredZoneRecords(t *testing.T) {
	targets := []zoneTarget{
		{hostname: "web.baum.hase.de", machine: ZoneMachine{BridgeIPv4: "10.1.1.1"}},
		{hostname: "old.baum.hase.de", machine: ZoneMachine{}},
		{hostname: "v6.baum.hase.de", machine: ZoneMachine{BridgeIPv4: "fd00::1"}},
		{hostname: "web12.hase.de", machine: ZoneMachine{BridgeIPv4: "10.1.1.2"}},
	}
	want, keep := desiredZoneRecords("hase.de.", targets)
	if len(want) != 4 || want["web.baum"].String() != "10.1.1.1" || want["*.web.baum"].String() != "10.1.1.1" || want["web12"].String() != "10.1.1.2" || want["*.web12"].String() != "10.1.1.2" {
		t.Fatalf("want = %v", want)
	}
	if len(keep) != 4 {
		t.Fatalf("keep = %v", keep)
	}
	if libdnsZone("Hase.DE") != "hase.de." || libdnsZone("hase.de.") != "hase.de." {
		t.Fatal("libdnsZone")
	}
}

// ---------------------------------------------------------------------------
// ADR-0028: (machine, hostname) pairs — explicit hostnames
// ---------------------------------------------------------------------------

// An explicit hostname added later (`sc hostname add`): its records and its
// own certificate appear, the machine's hostnames file is pushed with the
// grown set, the derived name's certificate is untouched, and the mirror
// carries both names.
func TestZoneReconcile_ExplicitHostnameAddedLater(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.passes(2)
	derived := h.row("web.baum.hase.de")
	if derived.PushedSerial != derived.Serial {
		t.Fatalf("derived not installed: %+v", derived)
	}
	// sc hostname add zp:web shop.hase.de — the API claims, records the
	// pending row and rewrites the list key; the reconciler does the rest.
	row := h.claimHostname("shop.hase.de", "zp", "web")
	h.requestExplicit(row)
	h.fleet.mu.Lock()
	h.fleet.machines[0].PublicHostnames = []string{"shop.hase.de", "web.baum.hase.de"}
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	// Records for the new name (apex-level, relative to the zone).
	got := recordNames(h.dns.list("hase.de."), "A")
	want := []string{"*.shop=10.249.7.9", "*.web.baum=10.249.7.9", "shop=10.249.7.9", "web.baum=10.249.7.9"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("A records = %v, want %v", got, want)
	}
	// The hostnames file no longer matched the set: pushed whole, once.
	if h.fleet.hostnamePushCount() != 1 || strings.Join(h.fleet.hostnamePushes[0].Hostnames, ",") != "shop.hase.de,web.baum.hase.de" {
		t.Fatalf("hostnames pushes = %+v", h.fleet.hostnamePushes)
	}
	// The order for shop ran (its own certificate, name + wildcard); the
	// derived name was not re-ordered.
	if len(h.issuer.calls) != 2 || strings.Join(h.issuer.calls[1].Hostnames, ",") != "shop.hase.de,*.shop.hase.de" {
		t.Fatalf("issuer calls = %+v", h.issuer.calls)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := h.fleet.pushedHostnames(); strings.Join(got, ",") != "shop.hase.de,web.baum.hase.de" {
		t.Fatalf("certificate pushes = %v", got)
	}
	if h.row("web.baum.hase.de").Serial != derived.Serial {
		t.Fatal("adding a hostname reissued the derived name")
	}
	m := h.fleet.machine("sc2-acme-zp", "web")
	if m.CertState != "shop.hase.de=installed,web.baum.hase.de=installed" {
		t.Fatalf("mirror = %q", m.CertState)
	}
	// The earliest expiry is mirrored; both were issued at h.now here.
	if m.CertNotAfter != formatCertTime(h.row("shop.hase.de").NotAfter) {
		t.Fatalf("not-after = %q", m.CertNotAfter)
	}
	// Nothing more to do on the next pass.
	stamps, hp := len(h.fleet.stamps), h.fleet.hostnamePushCount()
	h.passes(2)
	if len(h.fleet.stamps) != stamps || h.fleet.hostnamePushCount() != hp || h.fleet.pushCount() != 2 {
		t.Fatalf("settled fleet kept writing: stamps %d→%d hostnames %d→%d pushes %d", stamps, len(h.fleet.stamps), hp, h.fleet.hostnamePushCount(), h.fleet.pushCount())
	}
}

// Removing an explicit hostname: the release hook deletes its records and
// keeps the row; the reconciler pushes the shrunken hostnames file, drops
// the name from the mirror and never re-creates the records.
func TestZoneReconcile_ExplicitHostnameRemoved(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	web.PublicHostnames = []string{"shop.hase.de", "web.baum.hase.de"}
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "shop.hase.de", "web.baum.hase.de")
	row := h.claimHostname("shop.hase.de", "zp", "web")
	h.requestExplicit(row)
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.passes(2)
	if got := h.fleet.pushedHostnames(); strings.Join(got, ",") != "shop.hase.de,web.baum.hase.de" {
		t.Fatalf("certificate pushes = %v", got)
	}
	shop := h.row("shop.hase.de")
	h.dns.add("hase.de.", libdns.RR{Name: "_acme-challenge.shop", Type: "TXT", Data: "left-over"})
	// sc hostname remove zp:web shop.hase.de
	released, err := ReleaseMachineHostname(h.ctx, h.db, "acme", "zp", "web", "shop.hase.de")
	if err != nil {
		t.Fatal(err)
	}
	if err := onMachineHostnameReleased(h.ctx, h.db, released); err != nil {
		t.Fatalf("hook: %v", err)
	}
	got := recordNames(h.dns.list("hase.de."), "A")
	if strings.Join(got, ",") != "*.web.baum=10.249.7.9,web.baum=10.249.7.9" {
		t.Fatalf("A records after release = %v", got)
	}
	if len(recordNames(h.dns.list("hase.de."), "TXT")) != 0 {
		t.Fatal("challenge record of the released name survived")
	}
	if retained := h.row("shop.hase.de"); retained.Serial != shop.Serial {
		t.Fatalf("row not retained: %+v", retained)
	}
	// The API rewrites the list; the next pass pushes the shrunken file.
	h.fleet.mu.Lock()
	h.fleet.machines[0].PublicHostnames = []string{"web.baum.hase.de"}
	h.fleet.mu.Unlock()
	hp := h.fleet.hostnamePushCount()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if h.fleet.hostnamePushCount() != hp+1 || strings.Join(h.fleet.hostnamePushes[hp].Hostnames, ",") != "web.baum.hase.de" {
		t.Fatalf("hostnames pushes = %+v", h.fleet.hostnamePushes)
	}
	if m := h.fleet.machine("sc2-acme-zp", "web"); m.CertState != "web.baum.hase.de=installed" {
		t.Fatalf("mirror after remove = %q", m.CertState)
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); strings.Join(got, ",") != "*.web.baum=10.249.7.9,web.baum=10.249.7.9" {
		t.Fatalf("released name's records re-created: %v", got)
	}
	// Re-adding the name reuses the retained certificate: no new order.
	orders := len(h.issuer.calls)
	h.requestExplicit(h.claimHostname("shop.hase.de", "zp", "web"))
	h.fleet.mu.Lock()
	h.fleet.machines[0].PublicHostnames = []string{"shop.hase.de", "web.baum.hase.de"}
	h.fleet.mu.Unlock()
	h.passes(2)
	if len(h.issuer.calls) != orders {
		t.Fatal("re-added hostname spent an order")
	}
	if h.row("shop.hase.de").Serial != shop.Serial || h.state("shop.hase.de") != machineCertStateInstalled {
		t.Fatalf("retained certificate not reused: %s", h.state("shop.hase.de"))
	}
}

// After the last explicit name of a machine in a private project goes, the
// machine's hostnames file is pushed empty and its cert keys are deleted.
func TestZoneReconcile_LastHostnameRemovedClearsMachine(t *testing.T) {
	solo := privateMachine("solo", "10.249.7.40", true)
	solo.PublicHostnames = []string{"solo.hase.de"}
	h := newZoneHarness(t, solo)
	h.ready("sc2-acme-default", "solo", "solo.hase.de")
	h.requestExplicit(h.claimHostname("solo.hase.de", "default", "solo"))
	h.passes(2)
	if m := h.fleet.machine("sc2-acme-default", "solo"); m.CertState != "solo.hase.de=installed" || m.CertNotAfter == "" {
		t.Fatalf("mirror = %+v", m)
	}
	released, err := ReleaseMachineHostname(h.ctx, h.db, "acme", "default", "solo", "solo.hase.de")
	if err != nil {
		t.Fatal(err)
	}
	if err := onMachineHostnameReleased(h.ctx, h.db, released); err != nil {
		t.Fatal(err)
	}
	h.fleet.mu.Lock()
	h.fleet.machines[0].PublicHostnames = nil
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if n := h.fleet.hostnamePushCount(); n != 1 || len(h.fleet.hostnamePushes[0].Hostnames) != 0 {
		t.Fatalf("empty hostnames file not pushed: %+v", h.fleet.hostnamePushes)
	}
	if content, ok := h.fleet.file("sc2-acme-default", "solo", tenant.MachineHostnamesPath); !ok || content != "" {
		t.Fatalf("hostnames file = %q", content)
	}
	if m := h.fleet.machine("sc2-acme-default", "solo"); m.CertState != "" || m.CertNotAfter != "" {
		t.Fatalf("cert keys not cleared: %+v", m)
	}
	// Settled: a machine without names is not read again.
	stamps, hp := len(h.fleet.stamps), h.fleet.hostnamePushCount()
	h.passes(2)
	if len(h.fleet.stamps) != stamps || h.fleet.hostnamePushCount() != hp {
		t.Fatal("settled machine kept being written")
	}
}

// An explicit hostname on a machine in a project WITHOUT a domain: no
// derived name, records + certificate for the explicit one, marker gate and
// push like any other; the hostnames file is pushed when the first-boot seed
// left it empty (the datasource read yielded nothing).
func TestZoneReconcile_ExplicitHostnameInPrivateProject(t *testing.T) {
	solo := privateMachine("solo", "10.249.7.40", true)
	solo.PublicHostnames = []string{"solo.hase.de"}
	h := newZoneHarness(t, solo)
	h.ready("sc2-acme-default", "solo") // seeded empty
	h.requestExplicit(h.claimHostname("solo.hase.de", "default", "solo"))
	h.passes(2)
	if got := recordNames(h.dns.list("hase.de."), "A"); strings.Join(got, ",") != "*.solo=10.249.7.40,solo=10.249.7.40" {
		t.Fatalf("A records = %v", got)
	}
	if h.fleet.hostnamePushCount() != 1 || strings.Join(h.fleet.hostnamePushes[0].Hostnames, ",") != "solo.hase.de" {
		t.Fatalf("hostnames pushes = %+v", h.fleet.hostnamePushes)
	}
	if got := h.fleet.pushedHostnames(); strings.Join(got, ",") != "solo.hase.de" {
		t.Fatalf("certificate pushes = %v", got)
	}
	if len(h.issuer.calls) != 1 || strings.Join(h.issuer.calls[0].Hostnames, ",") != "solo.hase.de,*.solo.hase.de" {
		t.Fatalf("issuer calls = %+v", h.issuer.calls)
	}
	m := h.fleet.machine("sc2-acme-default", "solo")
	if m.CertState != "solo.hase.de=installed" || strings.Join(m.PublicHostnames, ",") != "solo.hase.de" {
		t.Fatalf("machine after pass: %+v", m)
	}
}

// Derived + explicit on one machine, mixed states: the mirror carries every
// name with its own state, `cert-not-after` is the earliest installed expiry,
// and a failure of one name never touches the other.
func TestZoneReconcile_MixedNamesMirrorPerHostname(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	web.PublicHostnames = []string{"shop.hase.de", "web.baum.hase.de", "web12.hase.de"}
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "shop.hase.de", "web.baum.hase.de", "web12.hase.de")
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	// The derived name is issued first (an earlier, shorter lifetime).
	h.issuer.lifetime = 30 * 24 * time.Hour
	h.passes(2)
	h.issuer.lifetime = 90 * 24 * time.Hour
	h.requestExplicit(h.claimHostname("shop.hase.de", "zp", "web"))
	h.requestExplicit(h.claimHostname("web12.hase.de", "zp", "web"))
	h.passes(2)
	m := h.fleet.machine("sc2-acme-zp", "web")
	if m.CertState != "shop.hase.de=installed,web.baum.hase.de=installed,web12.hase.de=installed" {
		t.Fatalf("mirror = %q", m.CertState)
	}
	if m.CertNotAfter != formatCertTime(h.row("web.baum.hase.de").NotAfter) {
		t.Fatalf("not-after = %q, want the earliest (%s)", m.CertNotAfter, formatCertTime(h.row("web.baum.hase.de").NotAfter))
	}
	// One name's renewal window opens and its order fails: only its state
	// flips.
	if _, err := h.db.ExecContext(h.ctx, `UPDATE machine_certificates SET renew_after = ? WHERE hostname = 'web12.hase.de'`, formatCertTime(h.now)); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Second)
	h.issuer.err = errors.New("acme: urn:ietf:params:acme:error:rateLimited")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	m = h.fleet.machine("sc2-acme-zp", "web")
	if m.CertState != "shop.hase.de=installed,web.baum.hase.de=installed,web12.hase.de=renewing" {
		t.Fatalf("mirror after one failure = %q", m.CertState)
	}
	// The CLI folds that to the worst state.
	decoded := meta.DecodeMachine(map[string]string{meta.KeyV2PublicHostnames: "shop.hase.de,web.baum.hase.de,web12.hase.de", meta.KeyV2CertState: m.CertState, meta.KeyV2CertNotAfter: m.CertNotAfter}, meta.Machine{})
	if decoded.CertState != meta.CertStateRenewing || decoded.CertStates["shop.hase.de"] != meta.CertStateInstalled || decoded.CertNotAfter != m.CertNotAfter {
		t.Fatalf("decoded = %+v", decoded)
	}
}

// A deleted machine with several names: the records of every name go on the
// next pass (the explicit reservation still stands until the 5-minute GC),
// every row is retained while its certificate is valid.
func TestZoneReconcile_MachineDeletedGCsAllNames(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	web.PublicHostnames = []string{"shop.hase.de", "web.baum.hase.de"}
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "shop.hase.de", "web.baum.hase.de")
	h.requestExplicit(h.claimHostname("shop.hase.de", "zp", "web"))
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.passes(2)
	if got := recordNames(h.dns.list("hase.de."), "A"); len(got) != 4 {
		t.Fatalf("A records = %v", got)
	}
	// incus delete web
	h.fleet.mu.Lock()
	h.fleet.machines = nil
	h.fleet.files = map[string]string{}
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); len(got) != 0 {
		t.Fatalf("deleted machine's records survived: %v", got)
	}
	if h.logged("zone hase.de: deleted 4 stale A record(s)") != 1 {
		t.Fatalf("stale deletion not logged: %v", h.logs)
	}
	for _, host := range []string{"shop.hase.de", "web.baum.hase.de"} {
		if !h.row(host).usable(LetsEncryptStagingDirectory, h.now) {
			t.Fatalf("row %s not retained", host)
		}
	}
	// The hostname GC releases the reservation (machine gone): the hook
	// finds nothing left to delete, and the row still keeps its own
	// retention.
	dropped, err := ReconcileMachineHostnames(h.ctx, h.db, map[string][]string{"acme": {"zp"}}, map[string]struct{}{}, func(ctx context.Context, hostname MachineHostname) {
		if err := onMachineHostnameReleased(ctx, h.db, hostname); err != nil {
			t.Fatalf("hook: %v", err)
		}
	})
	if err != nil || len(dropped) != 1 {
		t.Fatalf("hostname GC: %v %v", dropped, err)
	}
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if _, err := getMachineCertificate(h.ctx, h.db, "shop.hase.de"); err != nil {
		t.Fatal("valid row of a released hostname dropped")
	}
	// Once expired, both rows go.
	h.now = h.row("shop.hase.de").NotAfter.Add(time.Second)
	h.fleet.mu.Lock()
	h.fleet.machines = []ZoneMachine{zoneMachine("other", "10.249.7.10", true)}
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if rows, _ := listAllMachineCertificates(h.ctx, h.db); len(rows) != 0 {
		t.Fatalf("expired rows retained: %+v", rows)
	}
}

// set-domain with machines: the reconciler re-derives every machine's name
// under the new domain — list key, records, a fresh row (marker present),
// hostnames file — while explicit names stay; unset-domain removes the
// derived name and leaves the explicit one.
func TestZoneReconcile_DomainChangeRederivesNames(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	web.PublicHostnames = []string{"shop.hase.de", "web.baum.hase.de"}
	h := newZoneHarness(t, web)
	h.ready("sc2-acme-zp", "web", "shop.hase.de", "web.baum.hase.de")
	h.requestExplicit(h.claimHostname("shop.hase.de", "zp", "web"))
	if _, err := requestMachineCertificate(h.ctx, h.db, testCertRequest("web.baum.hase.de"), h.now); err != nil {
		t.Fatal(err)
	}
	h.passes(2)
	// sc project set-domain zp eiche.hase.de: claim replaced, old records
	// and rows released, Incus key rewritten.
	previous, found, err := ReleaseProjectDomainClaim(h.ctx, h.db, "acme", "zp")
	if err != nil || !found {
		t.Fatal(err)
	}
	if err := onProjectDomainReleased(h.ctx, h.db, previous); err != nil {
		t.Fatal(err)
	}
	claim(t, h.db, "eiche.hase.de", "acme", "zp")
	h.fleet.mu.Lock()
	h.fleet.machines[0].ProjectDomain = "eiche.hase.de"
	h.fleet.mu.Unlock()
	h.passes(2)
	m := h.fleet.machine("sc2-acme-zp", "web")
	if strings.Join(m.PublicHostnames, ",") != "shop.hase.de,web.eiche.hase.de" {
		t.Fatalf("list after set-domain = %v", m.PublicHostnames)
	}
	got := recordNames(h.dns.list("hase.de."), "A")
	want := []string{"*.shop=10.249.7.9", "*.web.eiche=10.249.7.9", "shop=10.249.7.9", "web.eiche=10.249.7.9"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("A records after set-domain = %v, want %v", got, want)
	}
	if last := h.fleet.hostnamePushes[len(h.fleet.hostnamePushes)-1]; strings.Join(last.Hostnames, ",") != "shop.hase.de,web.eiche.hase.de" {
		t.Fatalf("hostnames push after set-domain = %+v", last)
	}
	if h.state("web.eiche.hase.de") != machineCertStateInstalled || m.CertState != "shop.hase.de=installed,web.eiche.hase.de=installed" {
		t.Fatalf("after set-domain: state=%s mirror=%q", h.state("web.eiche.hase.de"), m.CertState)
	}
	if _, err := getMachineCertificate(h.ctx, h.db, "web.baum.hase.de"); err == nil {
		t.Fatal("replaced domain's row survived")
	}
	// sc project unset-domain zp
	c, _, err := ReleaseProjectDomainClaim(h.ctx, h.db, "acme", "zp")
	if err != nil {
		t.Fatal(err)
	}
	if err := onProjectDomainReleased(h.ctx, h.db, c); err != nil {
		t.Fatal(err)
	}
	h.fleet.mu.Lock()
	h.fleet.machines[0].ProjectDomain = ""
	h.fleet.mu.Unlock()
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	m = h.fleet.machine("sc2-acme-zp", "web")
	if strings.Join(m.PublicHostnames, ",") != "shop.hase.de" || m.CertState != "shop.hase.de=installed" {
		t.Fatalf("after unset-domain: %+v", m)
	}
	if got := recordNames(h.dns.list("hase.de."), "A"); strings.Join(got, ",") != "*.shop=10.249.7.9,shop=10.249.7.9" {
		t.Fatalf("A records after unset-domain = %v", got)
	}
	if last := h.fleet.hostnamePushes[len(h.fleet.hostnamePushes)-1]; strings.Join(last.Hostnames, ",") != "shop.hase.de" {
		t.Fatalf("hostnames push after unset-domain = %+v", last)
	}
}

// A stale list key (a failed API write) is converged; a legacy single key
// is deleted in the same write; a machine whose per-name marker is legacy
// gets records but neither a file push nor a certificate.
func TestZoneReconcile_ListKeyConvergenceAndLegacyMachine(t *testing.T) {
	web := zoneMachine("web", "10.249.7.9", true)
	web.PublicHostnames = []string{"web.baum.hase.de", "stale.hase.de"}
	web.PublicHostname = "web.baum.hase.de"
	legacy := zoneMachine("old", "10.249.7.8", true)
	h := newZoneHarness(t, web, legacy)
	h.ready("sc2-acme-zp", "web", "web.baum.hase.de")
	h.fleet.setFile("sc2-acme-zp", "old", tenant.CaddySetupMarkerPath, "MODE=zone\nFQDN=old.baum.hase.de\n")
	if err := h.pass(); err != nil {
		t.Fatalf("pass: %v", err)
	}
	if len(h.fleet.stamps) < 1 {
		t.Fatalf("stamps = %+v", h.fleet.stamps)
	}
	first := h.fleet.stamps[0]
	if first.Instance != "sc2-acme-zp/web" || first.Config[meta.KeyV2PublicHostnames] != "web.baum.hase.de" || first.Config[meta.KeyV2PublicHostname] != "" {
		t.Fatalf("convergence stamp = %+v", first)
	}
	if _, ok := first.Config[meta.KeyV2PublicHostname]; !ok {
		t.Fatal("legacy key not deleted")
	}
	m := h.fleet.machine("sc2-acme-zp", "web")
	if strings.Join(m.PublicHostnames, ",") != "web.baum.hase.de" || m.PublicHostname != "" {
		t.Fatalf("after convergence: %+v", m)
	}
	// The legacy machine: records yes, file push no, row no.
	if got := recordNames(h.dns.list("hase.de."), "A"); len(got) != 4 {
		t.Fatalf("A records = %v", got)
	}
	for _, p := range h.fleet.hostnamePushes {
		if p.Instance == "sc2-acme-zp/old" {
			t.Fatalf("legacy machine got a hostnames push: %+v", p)
		}
	}
	if _, err := getMachineCertificate(h.ctx, h.db, "old.baum.hase.de"); err == nil {
		t.Fatal("legacy machine got a row")
	}
	if h.logged("does not clear the push gate for old.baum.hase.de") != 1 {
		t.Fatalf("legacy gate not logged once: %v", h.logs)
	}
}

// RequestPass is safe before the loop is wired and reaches the kick after.
func TestZoneReconcilerRequestPass(t *testing.T) {
	var r *zoneReconciler
	r.RequestPass() // nil receiver: no-op
	r = newZoneReconciler(nil, nil, nil, "", nil)
	r.RequestPass() // no kick yet
	kicked := 0
	r.setKick(func() { kicked++ })
	r.RequestPass()
	if kicked != 1 {
		t.Fatalf("kicked = %d", kicked)
	}
}
