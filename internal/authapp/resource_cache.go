package authapp

import (
	"sort"
	"sync"
	"time"

	"github.com/lxc/incus/v6/shared/api"
)

// DefaultResourceCacheStaleAfter bounds how long the cache tolerates silence
// from the event stream before treating it as gone stale (see recordHeartbeat
// and implementation-notes.md). Chosen generously relative to how chatty a
// live Incus event bus normally is (state-change events, even on an idle
// install, are rarely more than a minute or two apart) while still being
// short enough that a genuinely dropped connection is caught well within an
// operator's patience for `sc ls` to notice.
const DefaultResourceCacheStaleAfter = 2 * time.Minute

// ResourceCache is the Auth App's in-memory index of Incus resources across
// every project — instances, networks, storage volumes/pools, profiles, and
// images (docs/shape/admin-server-config-toggled-event-bus-ca8marg.md). It is
// seeded by one full read on `auth-app serve` startup and, from then on, kept
// current purely by mutating the affected (kind, project) bucket whenever a
// relevant Incus lifecycle event arrives — there is no periodic resync (a
// deliberate decision; see implementation-notes.md).
//
// Readiness is a single flag covering all five resource types (see "Settled
// without escalation" in the shape doc): not ready until the initial read has
// completed AND the event stream is connected AND at least one event has been
// seen recently enough not to be considered stale. Any caller that needs a
// cache-backed answer must check Ready() and fall back to a live query
// otherwise.
type ResourceCache struct {
	mu sync.RWMutex

	instancesByProject map[string][]api.InstanceFull
	networksByProject  map[string][]api.Network
	volumesByProject   map[string][]api.StorageVolumeFull
	profilesByProject  map[string][]api.Profile
	imagesByProject    map[string][]api.Image
	storagePools       []api.StoragePool
	// projects is the server's whole project list (config included): what a
	// tenant summary is built from, so the CLI's tenant store can be served
	// from here instead of a live GET /1.0/projects on every command.
	projects []api.Project

	initialReadDone bool
	streamConnected bool
	lastEventAt     time.Time
	staleAfter      time.Duration
	now             func() time.Time
}

// ResourceCacheSnapshot is a point-in-time, safe-to-share copy of everything
// the cache holds, plus whether it was ready when taken.
type ResourceCacheSnapshot struct {
	Ready          bool
	Instances      []api.InstanceFull
	Networks       []api.Network
	StorageVolumes []api.StorageVolumeFull
	StoragePools   []api.StoragePool
	Profiles       []api.Profile
	Images         []api.Image
	Projects       []api.Project
}

// NewResourceCache builds an empty, not-ready cache. staleAfter bounds how long
// the cache tolerates silence from the event stream before Ready() reports
// false again — see recordHeartbeat.
func NewResourceCache(staleAfter time.Duration) *ResourceCache {
	return &ResourceCache{
		instancesByProject: map[string][]api.InstanceFull{},
		networksByProject:  map[string][]api.Network{},
		volumesByProject:   map[string][]api.StorageVolumeFull{},
		profilesByProject:  map[string][]api.Profile{},
		imagesByProject:    map[string][]api.Image{},
		staleAfter:         staleAfter,
		now:                time.Now,
	}
}

// Ready reports whether the cache is safe to answer from: the initial read
// completed, the event stream is connected, and it has heard from that stream
// recently enough not to be considered stale.
func (c *ResourceCache) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.readyLocked()
}

func (c *ResourceCache) readyLocked() bool {
	if !c.initialReadDone || !c.streamConnected {
		return false
	}
	if c.staleAfter > 0 && c.now().Sub(c.lastEventAt) > c.staleAfter {
		return false
	}
	return true
}

// Snapshot returns a copy of the cache's contents (sorted by project, then
// name, for deterministic callers/tests) and whether it was ready when taken.
func (c *ResourceCache) Snapshot() ResourceCacheSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := ResourceCacheSnapshot{Ready: c.readyLocked()}
	for _, list := range c.instancesByProject {
		snapshot.Instances = append(snapshot.Instances, list...)
	}
	for _, list := range c.networksByProject {
		snapshot.Networks = append(snapshot.Networks, list...)
	}
	for _, list := range c.volumesByProject {
		snapshot.StorageVolumes = append(snapshot.StorageVolumes, list...)
	}
	for _, list := range c.profilesByProject {
		snapshot.Profiles = append(snapshot.Profiles, list...)
	}
	for _, list := range c.imagesByProject {
		snapshot.Images = append(snapshot.Images, list...)
	}
	snapshot.StoragePools = append(snapshot.StoragePools, c.storagePools...)
	snapshot.Projects = append(snapshot.Projects, c.projects...)

	sort.Slice(snapshot.Instances, func(i, j int) bool {
		return lessProjectName(snapshot.Instances[i].Project, snapshot.Instances[i].Name, snapshot.Instances[j].Project, snapshot.Instances[j].Name)
	})
	sort.Slice(snapshot.Networks, func(i, j int) bool {
		return lessProjectName(snapshot.Networks[i].Project, snapshot.Networks[i].Name, snapshot.Networks[j].Project, snapshot.Networks[j].Name)
	})
	sort.Slice(snapshot.StorageVolumes, func(i, j int) bool {
		return lessProjectName(snapshot.StorageVolumes[i].Project, snapshot.StorageVolumes[i].Name, snapshot.StorageVolumes[j].Project, snapshot.StorageVolumes[j].Name)
	})
	sort.Slice(snapshot.Profiles, func(i, j int) bool {
		return lessProjectName(snapshot.Profiles[i].Project, snapshot.Profiles[i].Name, snapshot.Profiles[j].Project, snapshot.Profiles[j].Name)
	})
	sort.Slice(snapshot.Images, func(i, j int) bool {
		return lessProjectName(snapshot.Images[i].Project, snapshot.Images[i].Fingerprint, snapshot.Images[j].Project, snapshot.Images[j].Fingerprint)
	})
	sort.Slice(snapshot.StoragePools, func(i, j int) bool { return snapshot.StoragePools[i].Name < snapshot.StoragePools[j].Name })
	return snapshot
}

func lessProjectName(projectA, nameA, projectB, nameB string) bool {
	if projectA != projectB {
		return projectA < projectB
	}
	return nameA < nameB
}

// seed replaces the entire cache with one full read's results and marks the
// initial read complete. It does not by itself flip Ready() to true — the
// event stream must also be connected (see markStreamConnected).
func (c *ResourceCache) seed(instances []api.InstanceFull, networks []api.Network, pools []api.StoragePool, volumes []api.StorageVolumeFull, profiles []api.Profile, images []api.Image) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.instancesByProject = groupBy(instances, func(v api.InstanceFull) string { return v.Project })
	c.networksByProject = groupBy(networks, func(v api.Network) string { return v.Project })
	c.volumesByProject = groupBy(volumes, func(v api.StorageVolumeFull) string { return v.Project })
	c.profilesByProject = groupBy(profiles, func(v api.Profile) string { return v.Project })
	c.imagesByProject = groupBy(images, func(v api.Image) string { return v.Project })
	c.storagePools = append([]api.StoragePool(nil), pools...)
	c.initialReadDone = true
}

// setProjectInstances replaces one project's instance list — the mutation
// event handling applies after an instance-affecting lifecycle event, keyed
// only by project (not by name), so a create/update/delete/rename all reduce
// to "refresh what this project's instances look like now" rather than
// needing to parse rename deltas out of the event itself.
func (c *ResourceCache) setProjectInstances(project string, list []api.InstanceFull) {
	c.mu.Lock()
	defer c.mu.Unlock()
	setProjectBucket(c.instancesByProject, project, list)
}

func (c *ResourceCache) setProjectNetworks(project string, list []api.Network) {
	c.mu.Lock()
	defer c.mu.Unlock()
	setProjectBucket(c.networksByProject, project, list)
}

func (c *ResourceCache) setProjectStorageVolumes(project string, list []api.StorageVolumeFull) {
	c.mu.Lock()
	defer c.mu.Unlock()
	setProjectBucket(c.volumesByProject, project, list)
}

func (c *ResourceCache) setProjectProfiles(project string, list []api.Profile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	setProjectBucket(c.profilesByProject, project, list)
}

func (c *ResourceCache) setProjectImages(project string, list []api.Image) {
	c.mu.Lock()
	defer c.mu.Unlock()
	setProjectBucket(c.imagesByProject, project, list)
}

// setProjects replaces the (global) project list.
func (c *ResourceCache) setProjects(projects []api.Project) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.projects = append([]api.Project(nil), projects...)
}

// setStoragePools replaces the (global, not per-project) storage pool list.
func (c *ResourceCache) setStoragePools(pools []api.StoragePool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storagePools = append([]api.StoragePool(nil), pools...)
}

// storagePoolNames returns the currently known pool names, so an event-driven
// per-project volume refresh knows which pools to ask about without a fresh
// GetStoragePools() round trip on every volume event.
func (c *ResourceCache) storagePoolNames() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, len(c.storagePools))
	for i, pool := range c.storagePools {
		names[i] = pool.Name
	}
	return names
}

// markStreamConnected flips the event-stream-connected half of readiness and
// resets the heartbeat clock — a fresh connection has no reason to be
// considered stale yet, even before its first event arrives.
func (c *ResourceCache) markStreamConnected() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streamConnected = true
	c.lastEventAt = c.now()
}

// markStreamDisconnected flips readiness to false immediately — no grace
// period, since a dropped socket means every event since is unaccounted for.
func (c *ResourceCache) markStreamDisconnected() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streamConnected = false
}

// recordHeartbeat is called for every event received on the stream —
// regardless of type or whether it mutated the cache — because the Incus
// event bus has no dedicated liveness ping (see implementation-notes.md for
// the staleness-detection design). Any traffic at all proves the socket is
// still alive.
func (c *ResourceCache) recordHeartbeat() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastEventAt = c.now()
}

func setProjectBucket[T any](buckets map[string][]T, project string, list []T) {
	if len(list) == 0 {
		delete(buckets, project)
		return
	}
	buckets[project] = list
}

func groupBy[T any](items []T, projectOf func(T) string) map[string][]T {
	grouped := map[string][]T{}
	for _, item := range items {
		project := projectOf(item)
		grouped[project] = append(grouped[project], item)
	}
	return grouped
}
