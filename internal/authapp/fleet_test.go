package authapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type fakeFleetLister struct {
	fleet        InstanceFleet
	listCalls    int
	projectCalls []string
	byProject    map[string][]api.InstanceFull
}

func (f *fakeFleetLister) ListFleet(context.Context) (InstanceFleet, error) {
	f.listCalls++
	out := InstanceFleet{}
	for p, list := range f.fleet {
		out[p] = list
	}
	return out, nil
}

func (f *fakeFleetLister) ListProjectInstances(_ context.Context, project string) ([]api.InstanceFull, error) {
	f.projectCalls = append(f.projectCalls, project)
	return f.byProject[project], nil
}

func inst(project, name string) api.InstanceFull {
	return api.InstanceFull{Instance: api.Instance{Project: project, Name: name}}
}

func TestFleetSourceUsesReadyCacheAndRefreshesDirtyProjectsLive(t *testing.T) {
	cache := NewResourceCache(time.Minute)
	cache.seed([]api.InstanceFull{inst("sc2-a-default", "web"), inst("sc2-b-default", "db")}, nil, nil, nil, nil, nil)
	cache.markStreamConnected()
	lister := &fakeFleetLister{byProject: map[string][]api.InstanceFull{"sc2-a-default": {inst("sc2-a-default", "web"), inst("sc2-a-default", "new")}}}
	dirty := &dirtyProjects{}
	source := fleetSource{cache: cache, lister: lister, dirty: dirty, logf: func(string, string, ...any) {}}

	fleet := source.fleet(context.Background())
	if lister.listCalls != 0 || len(fleet["sc2-b-default"]) != 1 || len(fleet["sc2-a-default"]) != 1 {
		t.Fatalf("ready cache should serve the fleet without listing: calls=%d fleet=%v", lister.listCalls, fleet)
	}
	// An event named sc2-a-default: only that project is re-read live, and
	// the cache learns the result.
	dirty.add("sc2-a-default")
	fleet = source.fleet(context.Background())
	if lister.listCalls != 0 || len(lister.projectCalls) != 1 || lister.projectCalls[0] != "sc2-a-default" {
		t.Fatalf("dirty refresh calls = list %d project %v", lister.listCalls, lister.projectCalls)
	}
	if len(fleet["sc2-a-default"]) != 2 || len(cache.Snapshot().Instances) != 3 {
		t.Fatalf("dirty project not refreshed into fleet/cache: %v", fleet["sc2-a-default"])
	}
	// Not-ready cache: one all-projects listing.
	cache.markStreamDisconnected()
	dirty.clear()
	fleet = source.fleet(context.Background())
	if lister.listCalls != 1 || fleet == nil {
		t.Fatalf("fallback listing calls = %d", lister.listCalls)
	}
	// No lister and no cache: nil (reconcilers list for themselves).
	if got := (fleetSource{logf: func(string, string, ...any) {}}).fleet(context.Background()); got != nil {
		t.Fatalf("expected nil fleet, got %v", got)
	}
}

func TestZoneFileCacheServesRepeatsUntilPushOrEvent(t *testing.T) {
	fleet := newFakeZoneFleet(ZoneMachine{Tenant: "acme", Project: "default", IncusProject: "sc2-acme-default", Name: "web", Running: true})
	fleet.setFile("sc2-acme-default", "web", "/etc/x", "one")
	r := newZoneReconciler(nil, fleet, nil, "", nil)
	r.fileCacheTTL = time.Hour
	now := time.Now()
	r.now = func() time.Time { return now }
	read := func() string {
		content, err := r.readFile(context.Background(), "sc2-acme-default", "web", "/etc/x")
		if err != nil {
			t.Fatal(err)
		}
		return content
	}
	if read() != "one" || read() != "one" {
		t.Fatal("first reads")
	}
	fleet.setFile("sc2-acme-default", "web", "/etc/x", "two")
	if read() != "one" {
		t.Fatal("a quiet machine's read must be served from the cache")
	}
	r.markProjectDirty("sc2-acme-default")
	if read() != "two" {
		t.Fatal("a lifecycle event must drop the cached read")
	}
	fleet.setFile("sc2-acme-default", "web", "/etc/x", "three")
	r.forgetMachineFiles("sc2-acme-default", "web")
	if read() != "three" {
		t.Fatal("a push must drop the cached read")
	}
	fleet.setFile("sc2-acme-default", "web", "/etc/x", "four")
	now = now.Add(2 * time.Hour)
	if read() != "four" {
		t.Fatal("the TTL must expire the cached read")
	}
	// Not-found is cached; an unreachable machine is not.
	if _, err := r.readFile(context.Background(), "sc2-acme-default", "web", "/etc/missing"); !errors.Is(err, ErrInstanceFileNotFound) {
		t.Fatalf("missing: %v", err)
	}
	fleet.setFile("sc2-acme-default", "web", "/etc/missing", "late")
	if _, err := r.readFile(context.Background(), "sc2-acme-default", "web", "/etc/missing"); !errors.Is(err, ErrInstanceFileNotFound) {
		t.Fatalf("not-found should stay cached: %v", err)
	}
	r.fileCacheTTL = 0
	if read() != "four" {
		t.Fatal("TTL 0 bypasses the cache")
	}
}

// cloud-init writes the Caddy Setup Marker with no lifecycle event: an absent
// marker must not stay cached, or the first push waits for the cache TTL.
func TestZoneFileCacheDoesNotKeepAnAbsentMarker(t *testing.T) {
	m := ZoneMachine{Tenant: "acme", Project: "default", IncusProject: "sc2-acme-default", Name: "web", Running: true}
	fleet := newFakeZoneFleet(m)
	r := newZoneReconciler(nil, fleet, nil, "", nil)
	r.fileCacheTTL = time.Hour
	if _, ok, err := r.readMarker(context.Background(), m); ok || err != nil {
		t.Fatalf("booting machine: ok=%v err=%v", ok, err)
	}
	fleet.setFile("sc2-acme-default", "web", tenant.CaddySetupMarkerPath, "PRIVATE=web.default.castle\n")
	r.markerByMachine = map[string]markerRead{} // the next pass
	if marker, ok, err := r.readMarker(context.Background(), m); !ok || err != nil || marker.Private != "web.default.castle" {
		t.Fatalf("marker written after boot not read: %+v ok=%v err=%v", marker, ok, err)
	}
}

func TestLeasePendingAndDirtyRefreshMarksAwaiting(t *testing.T) {
	addressed := func(ip string) *api.InstanceState {
		return &api.InstanceState{Network: map[string]api.InstanceStateNetwork{
			"lo":   {Addresses: []api.InstanceStateNetworkAddress{{Family: "inet", Address: "127.0.0.1", Scope: "local"}}},
			"eth0": {Addresses: []api.InstanceStateNetworkAddress{{Family: "inet", Address: ip, Scope: "global"}}},
		}}
	}
	running := func(name string, state *api.InstanceState) api.InstanceFull {
		i := inst("sc2-a-default", name)
		i.Status, i.StatusCode, i.State = "Running", api.Running, state
		return i
	}
	stopped := inst("sc2-a-default", "off")
	booting := running("web", &api.InstanceState{Network: map[string]api.InstanceStateNetwork{"eth0": {}}})
	leased := running("web", addressed("10.254.0.9"))
	if leasePending([]api.InstanceFull{stopped}) || leasePending([]api.InstanceFull{leased, stopped}) {
		t.Fatal("stopped or addressed instances are not waiting for a lease")
	}
	if !leasePending([]api.InstanceFull{leased, booting}) {
		t.Fatal("a running instance with no global IPv4 is waiting for a lease")
	}

	lister := &fakeFleetLister{byProject: map[string][]api.InstanceFull{"sc2-a-default": {booting}}}
	dirty := &dirtyProjects{}
	source := fleetSource{lister: lister, dirty: dirty, logf: func(string, string, ...any) {}}
	dirty.add("sc2-a-default")
	source.fleet(context.Background())
	if !dirty.awaitingLease() {
		t.Fatal("dirty project with a booting instance must keep the loop passing")
	}
	lister.byProject["sc2-a-default"] = []api.InstanceFull{leased}
	source.fleet(context.Background())
	if dirty.awaitingLease() {
		t.Fatal("the lease landed: no more late passes")
	}
	dirty.setAwaiting("sc2-a-default", true)
	dirty.clear()
	if dirty.awaitingLease() {
		t.Fatal("clear drops the awaiting set")
	}
}
