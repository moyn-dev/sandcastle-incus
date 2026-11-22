package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// fakeResourceClient is a minimal authResourceClient stand-in: config.authResources
// lets tests inject it directly, the same seam tenantClient()/authTenants uses for
// the sibling /api/tenants client.
type fakeResourceClient struct {
	result      authapp.ResourceListResult
	err         error
	calls       int
	lastRequest authapp.ResourceListRequest
}

func (f *fakeResourceClient) ListResources(ctx context.Context, request authapp.ResourceListRequest) (authapp.ResourceListResult, error) {
	f.calls++
	f.lastRequest = request
	if f.err != nil {
		return authapp.ResourceListResult{}, f.err
	}
	return f.result, nil
}

var _ authResourceClient = (*fakeResourceClient)(nil)

// The resource-cache-not-ready message a real GET /api/resources answers with
// 503 whether the config toggle is off or the cache simply hasn't finished its
// initial read yet — see resourceCacheUnavailableMessage in
// internal/authapp/resource_cache_api.go. sc ls never distinguishes the two; it
// falls back on any non-200 the same way.
const fakeResourceCacheUnavailableErr = "auth app resource list: resource cache is not available: toggle is off, or the cache has not finished its initial read / lost its event-bus connection"

func TestListMachinesViaCache_ReadyReturnsCacheDataIncludingNewResourceTypes(t *testing.T) {
	fake := &fakeResourceClient{result: authapp.ResourceListResult{
		Tenant:      tenant.Summary{Tenant: "acme"},
		AllProjects: true,
		Machines:    []meta.Machine{{Project: "gbrain", Name: "web", PrivateIP: "10.1.0.9", Running: true}},
		Networks:    []api.Network{{Name: "sc2br0", Type: "bridge", Managed: true, Project: "gbrain"}},
		StoragePools: []api.StoragePool{
			{Name: "default", Driver: "zfs"},
		},
		StorageVolumes: []api.StorageVolumeFull{
			{StorageVolume: api.StorageVolume{Name: "web-root", Type: "custom", Project: "gbrain"}},
		},
		Profiles: []api.Profile{{Name: "default", Project: "gbrain"}},
		Images:   []api.Image{{Fingerprint: "0123456789abcdef", Project: "gbrain", Architecture: "x86_64", Type: "container"}},
	}}
	config := commandConfig{
		adminConfig:   scconfig.Admin{Tenant: "acme"},
		authResources: fake,
	}
	renderAll := listRenderOptions{
		ShowNetworks:       true,
		ShowStoragePools:   true,
		ShowStorageVolumes: true,
		ShowProfiles:       true,
		ShowImages:         true,
	}
	result, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{AllProjects: true}, renderAll)
	if !ok {
		t.Fatalf("cache-ready path fell back unexpectedly")
	}
	if fake.calls != 1 {
		t.Fatalf("ListResources called %d times, want 1", fake.calls)
	}
	if len(result.Machines) != 1 || len(result.Networks) != 1 || len(result.StoragePools) != 1 ||
		len(result.StorageVolumes) != 1 || len(result.Profiles) != 1 || len(result.Images) != 1 {
		t.Fatalf("result = %+v, want every cache-backed resource type carried through", result)
	}

	rendered := formatMachineList(result, renderAll)
	for _, want := range []string{
		"NETWORKS", "sc2br0",
		"STORAGE POOLS", "default", "zfs",
		"STORAGE VOLUMES", "web-root",
		"PROFILES",
		"IMAGES", "0123456789ab", // 12-char truncated fingerprint
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered output missing %q:\n%s", want, rendered)
		}
	}
}

func TestListMachinesViaCache_ScopesRequestTenantAndProject(t *testing.T) {
	fake := &fakeResourceClient{result: authapp.ResourceListResult{Tenant: tenant.Summary{Tenant: "acme"}}}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme", Project: "pinned"}, authResources: fake}

	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{}, listRenderOptions{}); !ok {
		t.Fatal("expected cache path to answer")
	}
	if fake.lastRequest.Tenant != "acme" || fake.lastRequest.Project != "pinned" {
		t.Fatalf("request = %+v, want tenant=acme project=pinned (locally pinned project)", fake.lastRequest)
	}

	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{AllProjects: true}, listRenderOptions{}); !ok {
		t.Fatal("expected cache path to answer")
	}
	if fake.lastRequest.Project != "" {
		t.Fatalf("--all-projects request carried project = %q, want empty", fake.lastRequest.Project)
	}

	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{Project: "other/gbrain"}, listRenderOptions{}); !ok {
		t.Fatal("expected cache path to answer")
	}
	if fake.lastRequest.Tenant != "other" || fake.lastRequest.Project != "gbrain" {
		t.Fatalf("scoped tenant/project request = %+v, want tenant=other project=gbrain", fake.lastRequest)
	}
}

func TestListMachinesViaCache_FallsBackWithNoStoredAuthToken(t *testing.T) {
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme"}}
	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{}, listRenderOptions{}); ok {
		t.Fatalf("expected fallback with no stored AuthToken")
	}
}

func TestListMachinesViaCache_FallsBackWhenUnreachable(t *testing.T) {
	fake := &fakeResourceClient{err: errors.New("dial tcp: connection refused")}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme"}, authResources: fake}
	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{}, listRenderOptions{}); ok {
		t.Fatalf("expected fallback when endpoint unreachable")
	}
}

func TestListMachinesViaCache_FallsBackWhenNotReady(t *testing.T) {
	fake := &fakeResourceClient{err: errors.New(fakeResourceCacheUnavailableErr)}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme"}, authResources: fake}
	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{}, listRenderOptions{}); ok {
		t.Fatalf("expected fallback when cache not ready")
	}
}

func TestListMachinesViaCache_FallsBackWhenToggleOff(t *testing.T) {
	// The endpoint answers the exact same 503 for "toggle off" and "not
	// ready" (resourceCacheUnavailableMessage) — sc ls keys its fallback off
	// the failed call alone, never off distinguishing the two.
	fake := &fakeResourceClient{err: errors.New(fakeResourceCacheUnavailableErr)}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme"}, authResources: fake}
	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{}, listRenderOptions{}); ok {
		t.Fatalf("expected fallback when toggle is off")
	}
}

// With the toggle off (or any other fallback trigger), listMachines() — the
// existing live per-project path — runs completely unchanged, and
// formatMachineList's default (no new flags) output must not vary depending
// on whether a cache-backed listPayload happens to carry the new resource
// types. This is the byte-for-byte compatibility acceptance criterion.
func TestFormatMachineList_DefaultOutputUnaffectedByCacheOnlyFields(t *testing.T) {
	base := listPayload{
		Tenant:      tenant.Summary{Tenant: "acme", DNSSuffix: "acme.sandcastle.dev"},
		AllProjects: true,
		Machines:    []meta.Machine{{Project: "gbrain", Name: "web", PrivateIP: "10.1.0.9", Running: true}},
	}
	withExtras := base
	withExtras.Networks = []api.Network{{Name: "sc2br0", Project: "gbrain"}}
	withExtras.StoragePools = []api.StoragePool{{Name: "default"}}
	withExtras.StorageVolumes = []api.StorageVolumeFull{{StorageVolume: api.StorageVolume{Name: "vol", Project: "gbrain"}}}
	withExtras.Profiles = []api.Profile{{Name: "default", Project: "gbrain"}}
	withExtras.Images = []api.Image{{Fingerprint: "abc123", Project: "gbrain"}}

	plain := formatMachineList(base, listRenderOptions{})
	extra := formatMachineList(withExtras, listRenderOptions{})
	if plain != extra {
		t.Fatalf("output differs when cache-only fields are present but no flag requested them:\nplain=%q\nextra=%q", plain, extra)
	}
	for _, marker := range []string{"NETWORKS", "STORAGE POOLS", "STORAGE VOLUMES", "PROFILES", "IMAGES"} {
		if strings.Contains(extra, marker) {
			t.Fatalf("output contains %q section though its flag was not requested:\n%s", marker, extra)
		}
	}
}

// formatMachineList's "no machines found" short-circuit must still fire when
// no flags are set, matching pre-wish behavior exactly, even on an otherwise
// empty result.
func TestFormatMachineList_NoMachinesFoundUnchanged(t *testing.T) {
	result := listPayload{Tenant: tenant.Summary{Tenant: "acme"}, AllProjects: true}
	got := formatMachineList(result, listRenderOptions{})
	want := "No Sandcastle machines found in the current install."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// poisonTenantStore and poisonMachineStore fail the test the instant either is
// touched — the live per-project Incus path (listMachines) is the only caller
// of either interface, so wiring these into `sc ls` end to end is how t4
// proves acceptance criterion 1 ("verify it's not hitting live Incus calls"),
// not just that listMachinesViaCache was invoked (list_cache_test.go's other
// tests already show that at the function level, one layer short of the real
// `sc ls`/RunE dispatch this test goes through instead).
type poisonTenantStore struct{ t *testing.T }

func (p poisonTenantStore) ListProjects(ctx context.Context) ([]tenant.IncusProject, error) {
	p.t.Helper()
	p.t.Fatal("live tenant store touched despite a ready cache-backed answer")
	return nil, nil
}

type poisonMachineStore struct{ t *testing.T }

func (p poisonMachineStore) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	p.t.Helper()
	p.t.Fatal("live machine store touched despite a ready cache-backed answer")
	return nil, nil
}

// TestListCommand_ToggleOnReadyAnswersFromCacheWithoutLiveIncusCall runs `sc
// ls -a` through the real command dispatch (NewRootCommand/RunE), the same
// path an operator invokes, with tenantStore/machineStore wired to fail the
// test if the live per-project path is ever reached. Only a ready cache
// answer (config.authResources returning 200) can make this test pass —
// t4's end-to-end verification of acceptance criterion 1.
func TestListCommand_ToggleOnReadyAnswersFromCacheWithoutLiveIncusCall(t *testing.T) {
	fake := &fakeResourceClient{result: authapp.ResourceListResult{
		Tenant:      tenant.Summary{Tenant: "acme", DNSSuffix: "acme.sandcastle.dev"},
		AllProjects: true,
		Machines:    []meta.Machine{{Project: "gbrain", Name: "web", PrivateIP: "10.1.0.9", Running: true}},
	}}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:          "sandcastle",
		tenantStore:   poisonTenantStore{t: t},
		machineStore:  poisonMachineStore{t: t},
		authResources: fake,
	}, "ls", "-a")
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 {
		t.Fatalf("cache endpoint called %d times, want exactly 1", fake.calls)
	}
	if !strings.Contains(stdout, "gbrain") || !strings.Contains(stdout, "web") {
		t.Fatalf("stdout = %q, want the cache-backed machine listed", stdout)
	}
}

// TestListCommand_FallsBackToLiveWhenCacheUnavailable is the mirror of the
// above at the same full-command layer: with the cache-backed endpoint
// answering as not-ready/toggle-off (the two collapse to the same client-side
// signal — see implementation-notes.md), `sc ls` must fall through to
// tenantStore/machineStore and produce exactly what the pre-wish live path
// would have shown.
func TestListCommand_FallsBackToLiveWhenCacheUnavailable(t *testing.T) {
	fake := &fakeResourceClient{err: errors.New(fakeResourceCacheUnavailableErr)}
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{{
			Tenant: "acme", Project: "default", Name: "codex", Running: true,
		}}},
		authResources: fake,
	}, "list")
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 1 {
		t.Fatalf("cache endpoint called %d times, want exactly 1 (attempted, then fell back)", fake.calls)
	}
	if !strings.Contains(stdout, "default") || !strings.Contains(stdout, "codex") {
		t.Fatalf("stdout = %q, want the live-path machine listed after fallback", stdout)
	}
}

// A plain `sc ls` must ask the cache endpoint for machines and nothing else.
// Shipping the four resource types it will not print is what took a real
// install's response to 79 KB and pushed the round trip past the cache budget,
// sending every listing to the live path the cache exists to replace.
func TestListMachinesViaCache_RequestsOnlyTheRenderedResourceKinds(t *testing.T) {
	fake := &fakeResourceClient{result: authapp.ResourceListResult{Tenant: tenant.Summary{Tenant: "acme"}}}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme"}, authResources: fake}

	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{AllProjects: true}, listRenderOptions{}); !ok {
		t.Fatal("expected cache path to answer")
	}
	if got := strings.Join(fake.lastRequest.Include, ","); got != authapp.ResourceKindMachines {
		t.Fatalf("plain sc ls asked for include=%q, want just %q", got, authapp.ResourceKindMachines)
	}

	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{AllProjects: true}, listRenderOptions{ShowImages: true, ShowProfiles: true}); !ok {
		t.Fatal("expected cache path to answer")
	}
	want := []string{authapp.ResourceKindMachines, authapp.ResourceKindProfiles, authapp.ResourceKindImages}
	if got := strings.Join(fake.lastRequest.Include, ","); got != strings.Join(want, ",") {
		t.Fatalf("--profiles --images asked for include=%q, want %q", got, strings.Join(want, ","))
	}
}

// The budget is overridable for links slower than the default allows, and a
// junk value must not silently disable the cache path by leaving a zero
// timeout behind.
func TestResourceCacheRequestTimeout_EnvOverride(t *testing.T) {
	if got := resourceCacheRequestTimeout(); got != defaultResourceCacheRequestTimeout {
		t.Fatalf("unset = %s, want %s", got, defaultResourceCacheRequestTimeout)
	}
	for raw, want := range map[string]time.Duration{
		"12s":      12 * time.Second,
		"1m":       time.Minute,
		"nonsense": defaultResourceCacheRequestTimeout,
		"0":        defaultResourceCacheRequestTimeout,
		"-5s":      defaultResourceCacheRequestTimeout,
	} {
		t.Setenv(resourceCacheTimeoutEnv, raw)
		if got := resourceCacheRequestTimeout(); got != want {
			t.Fatalf("%s=%q -> %s, want %s", resourceCacheTimeoutEnv, raw, got, want)
		}
	}
}

// A running machine with a blank address is the cache holding its pre-DHCP
// snapshot: the guest got its lease after instance-started, and nothing on the
// Incus event bus reports that, so the project is never re-read. `sc ls` must
// treat such an answer as a miss and go live rather than print an empty IP
// column for a machine that is reachable.
func TestListMachinesViaCache_FallsBackWhenRunningMachineHasNoAddress(t *testing.T) {
	fake := &fakeResourceClient{result: authapp.ResourceListResult{
		Tenant: tenant.Summary{Tenant: "acme"},
		Machines: []meta.Machine{
			{Tenant: "acme", Project: "web", Name: "api", PrivateIP: "10.1.0.7", Running: true},
			{Tenant: "acme", Project: "web", Name: "dev", PrivateIP: "", Running: true},
		},
	}}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme"}, authResources: fake}

	if _, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{AllProjects: true}, listRenderOptions{}); ok {
		t.Fatal("expected a fallback to the live path for a running machine with no address")
	}
}

// A machine that is not running has no address to report, so a blank IP there
// is the truth, not a stale read — falling back on it would bypass the cache
// for every listing that includes a stopped machine.
func TestListMachinesViaCache_StoppedMachineWithoutAddressStillUsesCache(t *testing.T) {
	fake := &fakeResourceClient{result: authapp.ResourceListResult{
		Tenant: tenant.Summary{Tenant: "acme"},
		Machines: []meta.Machine{
			{Tenant: "acme", Project: "web", Name: "api", PrivateIP: "10.1.0.7", Running: true},
			{Tenant: "acme", Project: "web", Name: "archived", PrivateIP: "", Running: false},
		},
	}}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme"}, authResources: fake}

	result, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{AllProjects: true}, listRenderOptions{})
	if !ok {
		t.Fatal("stopped machine without an address must not trigger a fallback")
	}
	if len(result.Machines) != 2 {
		t.Fatalf("Machines = %d, want both carried through", len(result.Machines))
	}
}

func TestRunningWithoutAddress(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		machines []meta.Machine
		want     string // machine name, or "" for none
	}{
		{name: "empty", machines: nil},
		{name: "all addressed", machines: []meta.Machine{{Name: "a", PrivateIP: "10.0.0.1", Running: true}}},
		{name: "stopped and blank", machines: []meta.Machine{{Name: "a", Running: false}}},
		{name: "running and blank", machines: []meta.Machine{{Name: "a", Running: true}}, want: "a"},
		{
			name: "reports the first offender",
			machines: []meta.Machine{
				{Name: "a", PrivateIP: "10.0.0.1", Running: true},
				{Name: "b", Running: true},
				{Name: "c", Running: true},
			},
			want: "b",
		},
		{name: "whitespace is not an address", machines: []meta.Machine{{Name: "a", PrivateIP: "   ", Running: true}}, want: "a"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, found := runningWithoutAddress(testCase.machines)
			if found != (testCase.want != "") {
				t.Fatalf("found = %v, want %v", found, testCase.want != "")
			}
			if found && got.Name != testCase.want {
				t.Fatalf("machine = %q, want %q", got.Name, testCase.want)
			}
		})
	}
}
