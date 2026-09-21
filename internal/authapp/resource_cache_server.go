package authapp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
)

// ResourceCacheProjectServer is the per-project subset of an Incus server the
// cache uses to refresh a single project's resources after a lifecycle event.
// incus.InstanceServer.UseProject(...) already returns exactly this shape —
// see incusx.ResourceCacheServer for the adapter.
type ResourceCacheProjectServer interface {
	GetInstancesFull(instanceType api.InstanceType) ([]api.InstanceFull, error)
	GetNetworks() ([]api.Network, error)
	GetStoragePoolVolumesFull(pool string) ([]api.StorageVolumeFull, error)
	GetProfiles() ([]api.Profile, error)
	GetImages() ([]api.Image, error)
}

// ResourceCacheServer is the Incus surface the cache engine needs: one
// all-projects read per resource type to seed the cache, the per-project
// re-reads (via UseProject) to refresh a single project after a lifecycle
// event, and the event bus subscription that drives those refreshes.
type ResourceCacheServer interface {
	UseProject(name string) ResourceCacheProjectServer
	GetInstancesFullAllProjects(instanceType api.InstanceType) ([]api.InstanceFull, error)
	GetNetworksAllProjects() ([]api.Network, error)
	GetStoragePools() ([]api.StoragePool, error)
	GetStoragePoolVolumesFullAllProjects(pool string) ([]api.StorageVolumeFull, error)
	GetProfilesAllProjects() ([]api.Profile, error)
	GetImagesAllProjects() ([]api.Image, error)
	GetEventsAllProjects() (*incus.EventListener, error)
}

// resourceCacheProjectLister is the optional project-list half of the seam
// (incusx.ResourceCacheServer has it); a server without it simply leaves the
// cache's project bucket empty and `include=projects` unanswered.
type resourceCacheProjectLister interface {
	GetProjects() ([]api.Project, error)
}

// resourceCacheKind names which per-project bucket a lifecycle action affects.
type resourceCacheKind int

const (
	resourceCacheKindInstance resourceCacheKind = iota
	resourceCacheKindNetwork
	resourceCacheKindStorageVolume
	resourceCacheKindStoragePool
	resourceCacheKindProfile
	resourceCacheKindImage
	resourceCacheKindProject
)

// resourceCacheActions maps each lifecycle action this cache cares about to
// the resource kind it affects. Unlike admin_dns_events.go's DNS reconciler —
// which deliberately excludes noisy actions such as instance-file-retrieved
// and instance-exec because a periodic ticker backstops anything it misses —
// this cache has no such backstop (no periodic resync; see
// implementation-notes.md), so it must include every action that can change a
// field `sc ls` shows, most notably instance-updated (IP/NIC changes). It
// still excludes actions that cannot change any listed field regardless of
// resync strategy: console/exec/file/log/metadata-retrieval and
// snapshot/backup events, none of which alter the parent resource's own
// name, project, state, or address.
var resourceCacheActions = map[string]resourceCacheKind{
	api.EventLifecycleInstanceCreated:   resourceCacheKindInstance,
	api.EventLifecycleInstanceDeleted:   resourceCacheKindInstance,
	api.EventLifecycleInstanceRenamed:   resourceCacheKindInstance,
	api.EventLifecycleInstanceUpdated:   resourceCacheKindInstance,
	api.EventLifecycleInstanceMigrated:  resourceCacheKindInstance,
	api.EventLifecycleInstanceRestarted: resourceCacheKindInstance,
	api.EventLifecycleInstanceRestored:  resourceCacheKindInstance,
	api.EventLifecycleInstanceResumed:   resourceCacheKindInstance,
	api.EventLifecycleInstanceShutdown:  resourceCacheKindInstance,
	api.EventLifecycleInstanceStarted:   resourceCacheKindInstance,
	api.EventLifecycleInstanceStopped:   resourceCacheKindInstance,

	api.EventLifecycleNetworkCreated: resourceCacheKindNetwork,
	api.EventLifecycleNetworkDeleted: resourceCacheKindNetwork,
	api.EventLifecycleNetworkRenamed: resourceCacheKindNetwork,
	api.EventLifecycleNetworkUpdated: resourceCacheKindNetwork,

	api.EventLifecycleStorageVolumeCreated:  resourceCacheKindStorageVolume,
	api.EventLifecycleStorageVolumeDeleted:  resourceCacheKindStorageVolume,
	api.EventLifecycleStorageVolumeRenamed:  resourceCacheKindStorageVolume,
	api.EventLifecycleStorageVolumeUpdated:  resourceCacheKindStorageVolume,
	api.EventLifecycleStorageVolumeRestored: resourceCacheKindStorageVolume,

	api.EventLifecycleStoragePoolCreated: resourceCacheKindStoragePool,
	api.EventLifecycleStoragePoolDeleted: resourceCacheKindStoragePool,
	api.EventLifecycleStoragePoolUpdated: resourceCacheKindStoragePool,

	api.EventLifecycleProfileCreated: resourceCacheKindProfile,
	api.EventLifecycleProfileDeleted: resourceCacheKindProfile,
	api.EventLifecycleProfileRenamed: resourceCacheKindProfile,
	api.EventLifecycleProfileUpdated: resourceCacheKindProfile,

	api.EventLifecycleImageCreated:      resourceCacheKindImage,
	api.EventLifecycleImageDeleted:      resourceCacheKindImage,
	api.EventLifecycleImageUpdated:      resourceCacheKindImage,
	api.EventLifecycleImageRefreshed:    resourceCacheKindImage,
	api.EventLifecycleImageAliasCreated: resourceCacheKindImage,
	api.EventLifecycleImageAliasDeleted: resourceCacheKindImage,
	api.EventLifecycleImageAliasRenamed: resourceCacheKindImage,
	api.EventLifecycleImageAliasUpdated: resourceCacheKindImage,

	api.EventLifecycleProjectCreated: resourceCacheKindProject,
	api.EventLifecycleProjectDeleted: resourceCacheKindProject,
	api.EventLifecycleProjectRenamed: resourceCacheKindProject,
	api.EventLifecycleProjectUpdated: resourceCacheKindProject,
}

// ResourceCacheLogf is a minimal logging seam so RunResourceCache can report
// seed/reconnect failures without pulling svclog into this package; pass nil
// for silent operation (e.g. in tests).
type ResourceCacheLogf func(format string, args ...any)

func (log ResourceCacheLogf) call(format string, args ...any) {
	if log != nil {
		log(format, args...)
	}
}

// seedResourceCache performs the one full, all-projects read across all five
// resource types that populates a freshly started cache.
//
// Storage volumes are read best-effort: a pool whose listing fails is logged
// and skipped rather than failing the whole seed. Every other type here is a
// plain database read, but listing volumes reaches into the storage driver
// per volume, so ONE broken instance anywhere on the host — an Incus record
// whose backing dataset is gone ("cannot open 'rpool/incus/containers/…':
// dataset does not exist") — fails the pool listing for every project. With a
// fatal seed that single dead volume disabled the entire cache permanently:
// RunResourceCache re-seeded every 5s, failed identically every time, and
// `sc ls` fell back to the live path forever, silently. Volumes only feed the
// optional `sc ls --storage-volumes` section, so degrading them is strictly
// better than taking the instance listing down with them — and refusing to
// serve does not conjure the unreadable data either.
func seedResourceCache(cache *ResourceCache, server ResourceCacheServer, log ResourceCacheLogf) error {
	instances, err := server.GetInstancesFullAllProjects(api.InstanceTypeAny)
	if err != nil {
		return fmt.Errorf("list instances across projects: %w", err)
	}
	networks, err := server.GetNetworksAllProjects()
	if err != nil {
		return fmt.Errorf("list networks across projects: %w", err)
	}
	pools, err := server.GetStoragePools()
	if err != nil {
		return fmt.Errorf("list storage pools: %w", err)
	}
	var volumes []api.StorageVolumeFull
	for _, pool := range pools {
		poolVolumes, err := server.GetStoragePoolVolumesFullAllProjects(pool.Name)
		if err != nil {
			log.call("[resource-cache] storage volumes for pool %s are unavailable, continuing without them "+
				"(`sc ls --storage-volumes` will not show that pool; often one instance whose backing dataset is gone): %v", pool.Name, err)
			continue
		}
		volumes = append(volumes, poolVolumes...)
	}
	profiles, err := server.GetProfilesAllProjects()
	if err != nil {
		return fmt.Errorf("list profiles across projects: %w", err)
	}
	images, err := server.GetImagesAllProjects()
	if err != nil {
		return fmt.Errorf("list images across projects: %w", err)
	}
	cache.seed(instances, networks, pools, volumes, profiles, images)
	if lister, ok := server.(resourceCacheProjectLister); ok {
		projects, err := lister.GetProjects()
		if err != nil {
			return fmt.Errorf("list projects: %w", err)
		}
		cache.setProjects(projects)
	}
	return nil
}

// refreshResourceCacheProject re-reads one project's resources for the kind a
// lifecycle event named, and upserts them into the cache. Keying purely off
// (kind, project) — never off the event's resource name — sidesteps having to
// interpret rename event payloads (whether Name is the old or new name is not
// documented) at the cost of one slightly wider re-read per event.
func refreshResourceCacheProject(cache *ResourceCache, server ResourceCacheServer, kind resourceCacheKind, project string, log ResourceCacheLogf) error {
	if kind == resourceCacheKindStoragePool {
		pools, err := server.GetStoragePools()
		if err != nil {
			return fmt.Errorf("refresh storage pools: %w", err)
		}
		cache.setStoragePools(pools)
		return nil
	}
	if kind == resourceCacheKindProject {
		lister, ok := server.(resourceCacheProjectLister)
		if !ok {
			return nil
		}
		projects, err := lister.GetProjects()
		if err != nil {
			return fmt.Errorf("refresh projects: %w", err)
		}
		cache.setProjects(projects)
		return nil
	}
	projectServer := server.UseProject(project)
	switch kind {
	case resourceCacheKindInstance:
		list, err := projectServer.GetInstancesFull(api.InstanceTypeAny)
		if err != nil {
			return fmt.Errorf("refresh instances for project %s: %w", project, err)
		}
		cache.setProjectInstances(project, list)
	case resourceCacheKindNetwork:
		list, err := projectServer.GetNetworks()
		if err != nil {
			return fmt.Errorf("refresh networks for project %s: %w", project, err)
		}
		cache.setProjectNetworks(project, list)
	case resourceCacheKindStorageVolume:
		// Best-effort for the same reason the seed is (see seedResourceCache):
		// a pool the storage driver cannot enumerate must not take the whole
		// refresh — and with it this project's cache entry — down with it.
		var volumes []api.StorageVolumeFull
		var failed int
		for _, pool := range cache.storagePoolNames() {
			poolVolumes, err := projectServer.GetStoragePoolVolumesFull(pool)
			if err != nil {
				failed++
				log.call("[resource-cache] storage volumes for project %s pool %s are unavailable, continuing without them: %v", project, pool, err)
				continue
			}
			volumes = append(volumes, poolVolumes...)
		}
		if failed > 0 && len(volumes) == 0 {
			// Every pool failed: leave the previous entry alone rather than
			// replacing it with an empty list, so a transient storage outage
			// does not blank out volumes that were readable a moment ago.
			return nil
		}
		cache.setProjectStorageVolumes(project, volumes)
	case resourceCacheKindProfile:
		list, err := projectServer.GetProfiles()
		if err != nil {
			return fmt.Errorf("refresh profiles for project %s: %w", project, err)
		}
		cache.setProjectProfiles(project, list)
	case resourceCacheKindImage:
		list, err := projectServer.GetImages()
		if err != nil {
			return fmt.Errorf("refresh images for project %s: %w", project, err)
		}
		cache.setProjectImages(project, list)
	}
	return nil
}

// handleResourceCacheEvent dispatches one lifecycle event to the refresh it
// implies, if any. Events for actions this cache does not track are ignored.
func handleResourceCacheEvent(cache *ResourceCache, server ResourceCacheServer, event api.Event, log ResourceCacheLogf) {
	var lifecycle api.EventLifecycle
	if json.Unmarshal(event.Metadata, &lifecycle) != nil {
		return
	}
	kind, ok := resourceCacheActions[lifecycle.Action]
	if !ok {
		return
	}
	if err := refreshResourceCacheProject(cache, server, kind, event.Project, log); err != nil {
		log.call("[resource-cache] %v", err)
	}
}

// RunResourceCache seeds the cache with one full read, then subscribes to the
// Incus event bus and keeps the cache current until ctx is done, reconnecting
// with backoff whenever the seed fails or the event socket drops — mirroring
// admin_dns_events.go's subscribeInstanceLifecycleEvents. It blocks; call it
// in a goroutine.
func RunResourceCache(ctx context.Context, cache *ResourceCache, server ResourceCacheServer, log ResourceCacheLogf) {
	for ctx.Err() == nil {
		if err := seedResourceCache(cache, server, log); err != nil {
			log.call("[resource-cache] initial read failed: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		runResourceCacheEventLoop(ctx, cache, server, log)
	}
}

// runResourceCacheEventLoop owns exactly one event-bus connection lifecycle:
// connect, mark ready, dispatch until the socket drops or ctx is done, mark
// not-ready. Returning (rather than looping internally) lets RunResourceCache
// re-seed after a drop, since events missed while disconnected can only be
// recovered by a fresh full read.
func runResourceCacheEventLoop(ctx context.Context, cache *ResourceCache, server ResourceCacheServer, log ResourceCacheLogf) {
	listener, err := server.GetEventsAllProjects()
	if err != nil {
		log.call("[resource-cache] event subscription failed: %v", err)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
		return
	}
	// A handler with nil types matches every event, lifecycle or not — the
	// heartbeat only needs proof the socket is alive, not that anything
	// cache-relevant happened (see recordHeartbeat and
	// implementation-notes.md for why: the Incus event bus has no dedicated
	// liveness ping).
	_, _ = listener.AddHandler(nil, func(api.Event) { cache.recordHeartbeat() })
	_, err = listener.AddHandler([]string{api.EventTypeLifecycle}, func(event api.Event) {
		handleResourceCacheEvent(cache, server, event, log)
	})
	if err != nil {
		listener.Disconnect()
		log.call("[resource-cache] event handler registration failed: %v", err)
		return
	}
	cache.markStreamConnected()
	defer cache.markStreamDisconnected()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Disconnect()
		case <-done:
		}
	}()
	_ = listener.Wait()
	close(done)
}
