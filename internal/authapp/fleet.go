package authapp

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/lxc/incus/v6/shared/api"
)

// InstanceFleet is one listing of the install's instances, keyed by Incus
// project, shared by every reconciler of a DNS-loop pass (HANDOFF
// incusd-polling: the DNS and zone reconcilers each swept every project with
// recursion=2 on every 30 s tick, ~200 listings per 90 s on obelix).
type InstanceFleet map[string][]api.InstanceFull

// FleetLister is the Incus side of the shared listing: one all-projects read
// for a full fleet, one project read to refresh what a lifecycle event
// touched. Implemented by incusx.FleetServer.
type FleetLister interface {
	ListFleet(ctx context.Context) (InstanceFleet, error)
	ListProjectInstances(ctx context.Context, project string) ([]api.InstanceFull, error)
}

// fleetFromSnapshot groups a resource-cache snapshot into a fleet: zero Incus
// requests when the event-fed cache is ready.
func fleetFromSnapshot(snapshot ResourceCacheSnapshot) InstanceFleet {
	fleet := InstanceFleet{}
	for _, instance := range snapshot.Instances {
		fleet[instance.Project] = append(fleet[instance.Project], instance)
	}
	return fleet
}

// dirtyProjects collects the projects lifecycle events named since the last
// pass, so the pass re-reads exactly those live (the DHCP lease lands after
// the event; the cache's own refresh ran on the event, before the lease).
type dirtyProjects struct {
	mu       sync.Mutex
	projects map[string]struct{}
}

func (d *dirtyProjects) add(project string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.projects == nil {
		d.projects = map[string]struct{}{}
	}
	d.projects[project] = struct{}{}
}

// take returns the dirty set (sorted) and keeps it for the settle passes;
// clear drops it once the settle passes are through.
func (d *dirtyProjects) take() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.projects))
	for p := range d.projects {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (d *dirtyProjects) clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.projects = nil
}

// fleetSource assembles the pass's fleet: the resource cache when ready, else
// one all-projects listing; dirty projects are always re-read live and the
// cache is updated with the result. A nil lister and a not-ready cache yield
// a nil fleet, which tells the reconcilers to list for themselves (the
// pre-handoff path, kept for installs without a mounted socket).
type fleetSource struct {
	cache  *ResourceCache
	lister FleetLister
	dirty  *dirtyProjects
	logf   func(level, format string, args ...any)
}

func (s fleetSource) fleet(ctx context.Context) InstanceFleet {
	var fleet InstanceFleet
	switch {
	case s.cache != nil && s.cache.Ready():
		fleet = fleetFromSnapshot(s.cache.Snapshot())
	case s.lister != nil:
		listed, err := s.lister.ListFleet(ctx)
		if err != nil {
			s.logf("ERROR", "fleet listing: %v", err)
			return nil
		}
		fleet = listed
	default:
		return nil
	}
	if s.lister == nil || s.dirty == nil {
		return fleet
	}
	for _, project := range s.dirty.take() {
		instances, err := s.lister.ListProjectInstances(ctx, project)
		if err != nil {
			s.logf("WARN", "fleet refresh of %s: %v", project, err)
			continue
		}
		fleet[project] = instances
		if s.cache != nil {
			s.cache.setProjectInstances(project, instances)
		}
	}
	return fleet
}

// dnsLoopInterval is the fallback pass cadence. Events (with settle passes)
// give convergence within seconds; the ticker only backstops missed events
// and restarts, so it no longer has to be tight (HANDOFF incusd-polling).
const dnsLoopInterval = 5 * time.Minute

// zoneFileCacheTTL bounds how long the zone reconciler trusts a file read
// (marker, hostnames file, certificate, key) of a Machine nothing touched:
// our own pushes and lifecycle events invalidate earlier. External drift on
// a quiet Machine is therefore noticed within this window, not per pass.
const zoneFileCacheTTL = 10 * time.Minute
