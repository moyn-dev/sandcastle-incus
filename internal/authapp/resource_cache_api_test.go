package authapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"slices"
)

// resourceCacheAPITestRenderer is a minimal stand-in for
// incusx.MachineFromInstance: the real conversion lives in incusx, which
// imports authapp, so a test in this package cannot call it without an
// import cycle. It carries just enough (name/project/tenant/type) to assert
// the endpoint's filtering and tenant-scoping, which is what this file tests
// — not NIC-address resolution, which incusx's own tests already cover.
func resourceCacheAPITestRenderer(tenantName string, project string, instance api.InstanceFull) (meta.Machine, bool) {
	if meta.IsManaged(instance.Config) && instance.Config[meta.KeyKind] == meta.KindSidecar {
		return meta.Machine{}, false
	}
	return meta.Machine{Tenant: tenantName, Project: project, Name: instance.Name, Type: string(instance.Type)}, true
}

// resourceAPITestHandler builds a handler with two v2 tenants — "alice" (the
// caller, with a "docker" app project beyond the default one) and "bob" (a
// different tenant, used to assert the cache-backed endpoint never leaks
// across tenants) — and returns it plus alice's bearer token.
func resourceAPITestHandler(t *testing.T, cache *ResourceCache) (http.Handler, string) {
	t.Helper()
	db := authDBForTest(t)
	if err := UpsertUser(context.Background(), db, User{UserKey: "alice", GitHubUsername: "alice", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	token, err := CreateCLIToken(context.Background(), db, "alice", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(db, HandlerOptions{
		AuthHostname: "sc2.thieso2.dev",
		Admin:        testAuthAdminConfig(),
		Tenants: tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(
			authTestTenant{Tenant: "alice", UnixUser: "alice", CIDR: "10.248.1.0/24", Projects: []string{"docker"}},
			authTestTenant{Tenant: "bob", UnixUser: "bob", CIDR: "10.248.2.0/24"},
		)},
		TenantAccess:                 &fakeTenantAccessManager{},
		ResourceCache:                cache,
		ResourceCacheMachineRenderer: resourceCacheAPITestRenderer,
	})
	return h, token
}

func readyResourceCacheForTest() *ResourceCache {
	cache := NewResourceCache(time.Minute)
	cache.seed(
		[]api.InstanceFull{
			{Instance: api.Instance{Project: "sc2-alice-default", Name: "web", Type: "container"}},
			{Instance: api.Instance{Project: "sc2-alice-docker", Name: "db", Type: "container"}},
			{Instance: api.Instance{Project: "sc2-bob-default", Name: "secret", Type: "container"}},
		},
		nil, nil, nil, nil, nil,
	)
	cache.markStreamConnected()
	return cache
}

func TestResourcesAPI_ToggleOffAnswers503(t *testing.T) {
	h, token := resourceAPITestHandler(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("toggle off = %d %q, want 503", res.Code, res.Body.String())
	}
}

func TestResourcesAPI_NotReadyAnswers503(t *testing.T) {
	// Seeded is not enough — the event stream must also be connected (t1's
	// single readiness gate). No seed(), no markStreamConnected() here at all:
	// this is "auth-app just started" or "the event stream is down".
	cache := NewResourceCache(time.Minute)
	h, token := resourceAPITestHandler(t, cache)
	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("not ready = %d %q, want 503", res.Code, res.Body.String())
	}
}

func TestResourcesAPI_RequiresBearerToken(t *testing.T) {
	h, _ := resourceAPITestHandler(t, readyResourceCacheForTest())
	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d %q, want 401", res.Code, res.Body.String())
	}
}

func TestResourcesAPI_ReadyReturnsFilteredResultsScopedToCaller(t *testing.T) {
	h, token := resourceAPITestHandler(t, readyResourceCacheForTest())

	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("ready = %d %q, want 200", res.Code, res.Body.String())
	}
	var result ResourceListResult
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Machines) != 2 {
		t.Fatalf("machines = %+v, want 2 (alice's own across both her projects, never bob's)", result.Machines)
	}
	for _, m := range result.Machines {
		if m.Name == "secret" {
			t.Fatalf("leaked bob's instance into alice's listing: %+v", result.Machines)
		}
	}
	if !result.AllProjects {
		t.Fatalf("AllProjects = false with no project filter")
	}
}

func TestResourcesAPI_FiltersByProjectAndMachine(t *testing.T) {
	h, token := resourceAPITestHandler(t, readyResourceCacheForTest())

	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice&project=docker", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("project filter = %d %q", res.Code, res.Body.String())
	}
	var result ResourceListResult
	json.Unmarshal(res.Body.Bytes(), &result)
	if len(result.Machines) != 1 || result.Machines[0].Name != "db" {
		t.Fatalf("project=docker machines = %+v, want just db", result.Machines)
	}
	if result.AllProjects {
		t.Fatalf("AllProjects = true with an explicit project filter")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice&machine=web", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("machine filter = %d %q", res.Code, res.Body.String())
	}
	result = ResourceListResult{}
	json.Unmarshal(res.Body.Bytes(), &result)
	if len(result.Machines) != 1 || result.Machines[0].Name != "web" {
		t.Fatalf("machine=web machines = %+v, want just web", result.Machines)
	}
}

func TestResourcesAPI_UnknownLiteralProjectIs404(t *testing.T) {
	h, token := resourceAPITestHandler(t, readyResourceCacheForTest())
	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice&project=nosuchproject", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("unknown project = %d %q, want 404", res.Code, res.Body.String())
	}
}

func TestResourcesAPI_RejectsCrossTenantRequest(t *testing.T) {
	h, token := resourceAPITestHandler(t, readyResourceCacheForTest())
	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=bob", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant request = %d %q, want 403", res.Code, res.Body.String())
	}
}

func TestResourcesAPI_OmitsVolumeSnapshotsAndBackups(t *testing.T) {
	// A volume carrying Sandcastle's hourly autosnaps serializes every
	// snapshot with its full config — on a real one-machine tenant that was
	// 167 KB of JSON, ~95% snapshots, enough on its own to blow `sc ls`'s 3s
	// cache-request budget and force the live-path fallback the cache exists
	// to avoid. Nothing in `sc ls --storage-volumes` renders them.
	cache := NewResourceCache(time.Minute)
	cache.seed(nil, nil, nil, []api.StorageVolumeFull{{
		StorageVolume: api.StorageVolume{
			Project:     "sc2-alice-default",
			Name:        "sc-local",
			Type:        "custom",
			ContentType: "filesystem",
		},
		Snapshots: []api.StorageVolumeSnapshot{{Name: "autosnap-1"}, {Name: "autosnap-2"}},
		Backups:   []api.StorageVolumeBackup{{Name: "backup-1"}},
	}}, nil, nil)
	cache.markStreamConnected()

	h, token := resourceAPITestHandler(t, cache)
	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("ready = %d %q, want 200", res.Code, res.Body.String())
	}
	var result ResourceListResult
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.StorageVolumes) != 1 {
		t.Fatalf("storage volumes = %+v, want alice's one volume", result.StorageVolumes)
	}
	volume := result.StorageVolumes[0]
	if len(volume.Snapshots) != 0 || len(volume.Backups) != 0 {
		t.Fatalf("volume shipped snapshots=%d backups=%d, want both omitted", len(volume.Snapshots), len(volume.Backups))
	}
	// The fields `sc ls --storage-volumes` actually renders must survive.
	if volume.Name != "sc-local" || volume.Type != "custom" || volume.ContentType != "filesystem" || volume.Project != "sc2-alice-default" {
		t.Fatalf("trimmed away a rendered field: %+v", volume)
	}
	// The cache itself keeps the full objects — only the wire response is trimmed.
	if snapshot := cache.Snapshot(); len(snapshot.StorageVolumes) != 1 || len(snapshot.StorageVolumes[0].Snapshots) != 2 {
		t.Fatalf("cache lost its snapshots: %+v", snapshot.StorageVolumes)
	}
}

// resourceIncludeTestCache holds one item of every resource kind, all in
// alice's default project, so a response can be asserted kind by kind.
func resourceIncludeTestCache() *ResourceCache {
	cache := NewResourceCache(time.Minute)
	cache.seed(
		[]api.InstanceFull{{Instance: api.Instance{Project: "sc2-alice-default", Name: "web", Type: "container"}}},
		[]api.Network{{Name: "sc2br0", Project: "sc2-alice-default"}},
		[]api.StoragePool{{Name: "default", Driver: "zfs", UsedBy: []string{"/1.0/instances/web"}}},
		[]api.StorageVolumeFull{{StorageVolume: api.StorageVolume{Project: "sc2-alice-default", Name: "sc-local"}}},
		[]api.Profile{{
			ProfilePut: api.ProfilePut{
				Config:  map[string]string{"user.big": "payload"},
				Devices: map[string]map[string]string{"root": {"path": "/"}},
			},
			Name:    "default",
			Project: "sc2-alice-default",
			UsedBy:  []string{"/1.0/instances/web"},
		}},
		[]api.Image{{Fingerprint: "abc123", Project: "sc2-alice-default"}},
	)
	cache.markStreamConnected()
	return cache
}

func resourcesAPIResult(t *testing.T, h http.Handler, token string, query string) ResourceListResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/resources?"+query, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("GET ?%s = %d %q, want 200", query, res.Code, res.Body.String())
	}
	var result ResourceListResult
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// include= selects the resource kinds in the response. A plain `sc ls` sends
// include=machines and must not pay to ship the four kinds it will not print
// — the payload size that pushed a real install past `sc ls`'s cache budget.
func TestResourcesAPI_IncludeSelectsResourceKinds(t *testing.T) {
	h, token := resourceAPITestHandler(t, resourceIncludeTestCache())

	machinesOnly := resourcesAPIResult(t, h, token, "tenant=alice&include=machines")
	if len(machinesOnly.Machines) != 1 {
		t.Fatalf("machines = %+v, want alice's one instance", machinesOnly.Machines)
	}
	if len(machinesOnly.Networks) != 0 || len(machinesOnly.StoragePools) != 0 ||
		len(machinesOnly.StorageVolumes) != 0 || len(machinesOnly.Profiles) != 0 || len(machinesOnly.Images) != 0 {
		t.Fatalf("include=machines shipped unrequested kinds: %+v", machinesOnly)
	}

	// StoragePools is the one server-scoped kind (never project-filtered), so
	// it is the one most worth proving include= still gates.
	pools := resourcesAPIResult(t, h, token, "tenant=alice&include=machines,storage-pools")
	if len(pools.StoragePools) != 1 || len(pools.Machines) != 1 {
		t.Fatalf("include=machines,storage-pools = %+v, want both kinds", pools)
	}
	if len(pools.Profiles) != 0 || len(pools.Images) != 0 {
		t.Fatalf("include=machines,storage-pools shipped other kinds: %+v", pools)
	}

	// An unknown kind is ignored, not rejected: a newer CLI naming a kind this
	// appliance has never heard of must still get an answer rather than a 400
	// that silently sends it to the live path.
	forward := resourcesAPIResult(t, h, token, "tenant=alice&include=machines,quantum-widgets")
	if len(forward.Machines) != 1 {
		t.Fatalf("unknown include kind broke the answer: %+v", forward)
	}
}

// No include= at all means "everything", so an `sc ls` built before the param
// existed keeps seeing exactly the payload it did before.
func TestResourcesAPI_NoIncludeParamReturnsEveryKind(t *testing.T) {
	h, token := resourceAPITestHandler(t, resourceIncludeTestCache())
	result := resourcesAPIResult(t, h, token, "tenant=alice")
	if len(result.Machines) != 1 || len(result.Networks) != 1 || len(result.StoragePools) != 1 ||
		len(result.StorageVolumes) != 1 || len(result.Profiles) != 1 || len(result.Images) != 1 {
		t.Fatalf("no include= = %+v, want every kind", result)
	}
}

// The wire-only trims, same rule as trimStorageVolume: drop what no `sc ls`
// section renders, keep what it does.
func TestResourcesAPI_TrimsUnrenderedPoolAndProfileFields(t *testing.T) {
	cache := resourceIncludeTestCache()
	h, token := resourceAPITestHandler(t, cache)
	result := resourcesAPIResult(t, h, token, "tenant=alice&include=storage-pools,profiles")

	pool := result.StoragePools[0]
	if len(pool.UsedBy) != 0 {
		t.Fatalf("pool shipped UsedBy=%v, want it trimmed", pool.UsedBy)
	}
	if pool.Name != "default" || pool.Driver != "zfs" {
		t.Fatalf("trimmed away a rendered pool field: %+v", pool)
	}

	profile := result.Profiles[0]
	if len(profile.Config) != 0 || len(profile.Devices) != 0 {
		t.Fatalf("profile shipped config=%v devices=%v, want both trimmed", profile.Config, profile.Devices)
	}
	// formatProfilesSection renders the UsedBy *count*, so UsedBy must survive.
	if profile.Name != "default" || profile.Project != "sc2-alice-default" || len(profile.UsedBy) != 1 {
		t.Fatalf("trimmed away a rendered profile field: %+v", profile)
	}

	// The cache itself keeps the full objects — only the wire response is trimmed.
	snapshot := cache.Snapshot()
	if len(snapshot.StoragePools[0].UsedBy) != 1 || len(snapshot.Profiles[0].Config) != 1 {
		t.Fatalf("cache lost data to a wire-only trim: %+v %+v", snapshot.StoragePools[0], snapshot.Profiles[0])
	}
}

type fakePayloadVersions struct{ byProject map[string]string }

func (f fakePayloadVersions) ReadPayloadVersion(_ context.Context, project, pool string) string {
	if pool == "" {
		return ""
	}
	return f.byProject[project]
}

func TestResourcesAPIServesProjectsAndPayloadsFromTheCache(t *testing.T) {
	cache := readyResourceCacheForTest()
	cache.setProjects([]api.Project{
		{Name: "sc2-alice", ProjectPut: api.ProjectPut{Config: map[string]string{meta.KeyKind: meta.KindInfra, meta.KeyTenant: "alice", meta.KeyVersion: "2", meta.KeyV2CIDR: "10.248.1.0/24"}}},
		{Name: "sc2-alice-default", ProjectPut: api.ProjectPut{Config: map[string]string{meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "alice", meta.KeyVersion: "2"}}},
		{Name: "sc2-alice-docker", ProjectPut: api.ProjectPut{Config: map[string]string{meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "alice", meta.KeyVersion: "2"}}},
		{Name: "sc2-bob", ProjectPut: api.ProjectPut{Config: map[string]string{meta.KeyKind: meta.KindInfra, meta.KeyTenant: "bob", meta.KeyVersion: "2"}}},
		{Name: "sc2-bob-default"},
	})
	cache.setProjectProfiles("sc2-alice-default", []api.Profile{{Name: "default", Project: "sc2-alice-default", ProfilePut: api.ProfilePut{Devices: map[string]map[string]string{"sc-platform": {"pool": "default"}}}}})
	db := authDBForTest(t)
	if err := UpsertUser(context.Background(), db, User{UserKey: "alice", GitHubUsername: "alice", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	token, err := CreateCLIToken(context.Background(), db, "alice", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(db, HandlerOptions{
		AuthHostname: "sc2.thieso2.dev", Admin: testAuthAdminConfig(),
		Tenants:      tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "alice", CIDR: "10.248.1.0/24", Projects: []string{"docker"}}, authTestTenant{Tenant: "bob"})},
		TenantAccess: &fakeTenantAccessManager{}, ResourceCache: cache, ResourceCacheMachineRenderer: resourceCacheAPITestRenderer,
		PayloadVersions: fakePayloadVersions{byProject: map[string]string{"sc2-alice-default": "sc-payload-1111111111111111"}},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice&project=*&include=projects,payloads", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("resources = %d %q", res.Code, res.Body.String())
	}
	var result ResourceListResult
	if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range result.Projects {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"sc2-alice", "sc2-alice-default", "sc2-alice-docker"}) {
		t.Fatalf("projects = %v (bob's must not leak)", names)
	}
	if result.Projects[0].Config[meta.KeyV2CIDR] != "10.248.1.0/24" {
		t.Fatalf("infra config missing: %#v", result.Projects[0])
	}
	// Payloads: the default project's pool is known → version; docker has no
	// profile in the cache → "".
	got := map[string]string{}
	for _, p := range result.Payloads {
		got[p.IncusProject] = p.Version
	}
	if got["sc2-alice-default"] != "sc-payload-1111111111111111" || got["sc2-alice-docker"] != "" || len(got) != 2 {
		t.Fatalf("payloads = %v", got)
	}
	// The listed projects build a working summary through tenant.ListForPrefix.
	summaries, err := tenant.ListForPrefix(context.Background(), tenant.MemoryStore{Projects: result.Projects}, "sc2")
	if err != nil || len(summaries) != 1 || summaries[0].Tenant != "alice" || summaries[0].PrivateCIDR != "10.248.1.0/24" || len(summaries[0].Projects) != 2 {
		t.Fatalf("summaries = %+v, %v", summaries, err)
	}
}
