package incusx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/share"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type fakeShareReconcileStore struct {
	machines []meta.Machine
}

func (s fakeShareReconcileStore) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	return append([]meta.Machine{}, s.machines...), nil
}

type fakeShareReconcileServer struct {
	resource *fakeShareReconcileResource
}

func (s fakeShareReconcileServer) UseProject(name string) ShareReconcileResourceServer {
	return s.resource
}

type fakeShareReconcileResource struct {
	instance   *api.Instance
	updated    *api.InstancePut
	updateErr  error
	waitErr    error
	pathExists bool
}

func (r *fakeShareReconcileResource) GetInstance(name string) (*api.Instance, string, error) {
	return r.instance, "etag", nil
}

func (r *fakeShareReconcileResource) UpdateInstance(name string, instance api.InstancePut, etag string) (incus.Operation, error) {
	r.updated = &instance
	if r.updateErr != nil {
		return nil, r.updateErr
	}
	return failingOperation{err: r.waitErr}, nil
}

func (r *fakeShareReconcileResource) ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error) {
	if args.Stdout != nil {
		status := "missing"
		if r.pathExists {
			status = "exists"
		}
		_, _ = fmt.Fprintln(args.Stdout, status)
	}
	if args.DataDone != nil {
		close(args.DataDone)
	}
	return failingOperation{}, nil
}

type failingOperation struct {
	err error
}

func (o failingOperation) AddHandler(func(api.Operation)) (*incus.EventTarget, error) {
	return nil, nil
}
func (o failingOperation) Cancel() error                                { return nil }
func (o failingOperation) Get() api.Operation                           { return api.Operation{} }
func (o failingOperation) GetWebsocket(string) (*websocket.Conn, error) { return nil, nil }
func (o failingOperation) RemoveHandler(*incus.EventTarget) error       { return nil }
func (o failingOperation) Refresh() error                               { return nil }
func (o failingOperation) Wait() error                                  { return o.err }
func (o failingOperation) WaitContext(context.Context) error            { return o.err }

func TestShareReconcilerAddsAcceptedShareDevice(t *testing.T) {
	resource := &fakeShareReconcileResource{instance: &api.Instance{
		InstancePut: api.InstancePut{Devices: map[string]map[string]string{
			"root": {"type": "disk", "path": "/"},
		}},
	}}
	result, err := shareReconcilerForTest(resource).ReconcileTenantShares(context.Background(), tenantSummaryWithShare(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Machines) != 1 || result.Machines[0].Status != "updated" || !result.Machines[0].Changed {
		t.Fatalf("result = %#v", result)
	}
	if resource.updated == nil {
		t.Fatal("expected instance update")
	}
	device := resource.updated.Devices[share.DeviceName(acceptedShare())]
	if device["readonly"] != "true" || device["pool"] != "" || device["path"] != "/shared/thieso2/default/docs" {
		t.Fatalf("device = %#v", device)
	}
	if device["source"] != "/var/lib/incus/storage-pools/default/custom/sc2-thieso2-default_workspace/docs" {
		t.Fatalf("device = %#v", device)
	}
}

func TestShareReconcilerIsIdempotent(t *testing.T) {
	storageShare := acceptedShare()
	resource := &fakeShareReconcileResource{instance: &api.Instance{
		InstancePut: api.InstancePut{Devices: map[string]map[string]string{
			share.DeviceName(storageShare): share.DesiredDevice(storageShare, "sc2-thieso2-default", "default", tenant.V2WorkspaceVolumeName),
		}},
	}}
	result, err := shareReconcilerForTest(resource).ReconcileTenantShares(context.Background(), tenantSummaryWithShare(), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Machines[0].Status != "current" || result.Machines[0].Changed {
		t.Fatalf("result = %#v", result)
	}
	if resource.updated != nil {
		t.Fatal("expected no update")
	}
}

func TestShareReconcilerDryRunDoesNotUpdate(t *testing.T) {
	resource := &fakeShareReconcileResource{instance: &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{}}}}
	result, err := shareReconcilerForTest(resource).ReconcileTenantShares(context.Background(), tenantSummaryWithShare(), true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Machines[0].Status != "would-update" || !result.Machines[0].Changed {
		t.Fatalf("result = %#v", result)
	}
	if resource.updated != nil {
		t.Fatal("expected no update")
	}
}

func TestShareReconcilerReportsHotplugFailureWithoutRollback(t *testing.T) {
	resource := &fakeShareReconcileResource{
		instance: &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{}}},
		waitErr:  errors.New("hotplug refused"),
	}
	result, err := shareReconcilerForTest(resource).ReconcileTenantShares(context.Background(), tenantSummaryWithShare(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasFailures() || result.Machines[0].Status != "failed" {
		t.Fatalf("result = %#v", result)
	}
	if resource.updated == nil {
		t.Fatal("expected attempted update")
	}
}

func TestShareReconcilerReportsOccupiedSharePath(t *testing.T) {
	resource := &fakeShareReconcileResource{
		instance: &api.Instance{
			Name:        "default-codex",
			Status:      "Running",
			InstancePut: api.InstancePut{Devices: map[string]map[string]string{}},
		},
		pathExists: true,
	}
	result, err := shareReconcilerForTest(resource).ReconcileTenantShares(context.Background(), tenantSummaryWithShare(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasFailures() || result.Machines[0].Status != "failed" || !strings.Contains(result.Machines[0].Error, "already exists") {
		t.Fatalf("result = %#v", result)
	}
	if resource.updated != nil {
		t.Fatal("expected no update when share path is occupied")
	}
}

func TestShareReconcilerRemovesUnavailableShareDevice(t *testing.T) {
	storageShare := acceptedShare()
	resource := &fakeShareReconcileResource{instance: &api.Instance{
		InstancePut: api.InstancePut{Devices: map[string]map[string]string{
			share.DeviceName(storageShare): share.DesiredDevice(storageShare, "sc2-thieso2-default", "default", tenant.V2WorkspaceVolumeName),
		}},
	}}
	reconciler := shareReconcilerForTest(resource)
	reconciler.ShareStore = fakeShareStatusStore{status: share.SourceStatus{Exists: false, Safe: false}}
	result, err := reconciler.ReconcileTenantShares(context.Background(), tenantSummaryWithShare(), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Machines[0].Status != "updated" || !result.Machines[0].Changed {
		t.Fatalf("result = %#v", result)
	}
	if _, ok := resource.updated.Devices[share.DeviceName(storageShare)]; ok {
		t.Fatalf("share device was not removed: %#v", resource.updated.Devices)
	}
}

func TestShareReconcilerRestoresAvailableShareDevice(t *testing.T) {
	resource := &fakeShareReconcileResource{instance: &api.Instance{
		InstancePut: api.InstancePut{Devices: map[string]map[string]string{}},
	}}
	reconciler := shareReconcilerForTest(resource)
	reconciler.ShareStore = fakeShareStatusStore{status: share.SourceStatus{Exists: true, Safe: true}}
	result, err := reconciler.ReconcileTenantShares(context.Background(), tenantSummaryWithShare(), false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Machines[0].Status != "updated" || !result.Machines[0].Changed {
		t.Fatalf("result = %#v", result)
	}
	if _, ok := resource.updated.Devices[share.DeviceName(acceptedShare())]; !ok {
		t.Fatalf("share device was not restored: %#v", resource.updated.Devices)
	}
}

func shareReconcilerForTest(resource *fakeShareReconcileResource) ShareReconciler {
	return ShareReconciler{
		Admin:  config.Admin{IncusProjectPrefix: config.DefaultIncusProjectPrefix},
		Server: fakeShareReconcileServer{resource: resource},
		Store: fakeShareReconcileStore{machines: []meta.Machine{{
			Tenant:  "skorfman",
			Project: "default",
			Name:    "codex",
			Type:    meta.MachineTypeContainer,
		}}},
	}
}

type fakeShareStatusStore struct {
	status share.SourceStatus
}

func (s fakeShareStatusStore) GetTenantShares(ctx context.Context, incusProjectName string) ([]meta.TenantStorageShare, error) {
	return nil, nil
}

func (s fakeShareStatusStore) SetTenantShares(ctx context.Context, incusProjectName string, shares []meta.TenantStorageShare) error {
	return nil
}

func (s fakeShareStatusStore) SourceDirectoryExists(ctx context.Context, incusProjectName string, workspaceRelativeDir string) (bool, error) {
	return s.status.Exists && s.status.Safe, nil
}

func (s fakeShareStatusStore) SourceDirectoryStatus(ctx context.Context, incusProjectName string, workspaceRelativeDir string) (share.SourceStatus, error) {
	return s.status, nil
}

func tenantSummaryWithShare() tenant.Summary {
	return tenant.Summary{
		Tenant:        "skorfman",
		IncusName:     "sc2-skorfman-default",
		InfraProject:  "sc2-skorfman",
		StorageShares: []meta.TenantStorageShare{acceptedShare()},
	}
}

func acceptedShare() meta.TenantStorageShare {
	return meta.TenantStorageShare{
		SourceTenant:  "thieso2",
		SourceProject: "default",
		SourceDir:     "docs",
		Name:          "docs",
		Availability:  share.AvailabilityAvailable,
		Recipients: []meta.TenantStorageShareRecipient{{
			Tenant: "skorfman",
			State:  share.RecipientStateAccepted,
		}},
	}
}

// recordingShareServer records which Incus project each machine is looked up in,
// and which instance name is asked for.
type recordingShareServer struct {
	resource *recordingShareResource
	projects []string
}

func (s *recordingShareServer) UseProject(name string) ShareReconcileResourceServer {
	s.projects = append(s.projects, name)
	return s.resource
}

type recordingShareResource struct {
	fakeShareReconcileResource
	instances []string
}

func (r *recordingShareResource) GetInstance(name string) (*api.Instance, string, error) {
	r.instances = append(r.instances, name)
	return r.fakeShareReconcileResource.GetInstance(name)
}

func recordingShareReconciler(t *testing.T, machines []meta.Machine) (ShareReconciler, *recordingShareServer) {
	t.Helper()
	resource := &recordingShareResource{fakeShareReconcileResource: fakeShareReconcileResource{
		instance: &api.Instance{InstancePut: api.InstancePut{Devices: map[string]map[string]string{
			"root": {"type": "disk", "path": "/"},
		}}},
	}}
	server := &recordingShareServer{resource: resource}
	return ShareReconciler{
		Admin:  config.Admin{IncusProjectPrefix: config.DefaultIncusProjectPrefix},
		Server: server,
		Store:  fakeShareReconcileStore{machines: machines},
	}, server
}

// Regression: the share reconciler used the v1 "<project>-<machine>" instance
// name inside the tenant's single Incus project. On a v2 tenant that looked up
// "default-web" in sc2-<tenant>-default and reported every container as failed
// ("Instance not found"), which `sc status` then surfaced as an unreconciled
// machine count on a tenant that has no shares at all.
func TestShareReconcilerUsesV2InstanceNamesAndPerProjectIncusProjects(t *testing.T) {
	reconciler, server := recordingShareReconciler(t, []meta.Machine{
		{Tenant: "alice", Project: "default", Name: "web", Type: meta.MachineTypeContainer},
		{Tenant: "alice", Project: "backend", Name: "api", Type: meta.MachineTypeContainer},
	})
	summary := tenant.Summary{Tenant: "alice", Version: 2, InfraProject: "sc2-alice", IncusName: "sc2-alice-default"}
	result, err := reconciler.ReconcileTenantShares(context.Background(), summary, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.HasFailures() {
		t.Fatalf("v2 machines must resolve, got %#v", result.Machines)
	}
	if got := strings.Join(server.projects, ","); got != "sc2-alice-default,sc2-alice-backend" {
		t.Fatalf("incus projects = %q", got)
	}
	if got := strings.Join(server.resource.instances, ","); got != "web,api" {
		t.Fatalf("instance names = %q, want bare v2 names", got)
	}
	for _, machine := range result.Machines {
		if machine.Status != "current" {
			t.Fatalf("a tenant with no shares needs no change: %#v", machine)
		}
	}
}

// v1 keeps the packed instance name inside the tenant's single Incus project.

// The source directory of a share lives in the SOURCE project's own workspace
// volume, and the install prefix must come from the recipient's infra project —
// the user-facing default "sc" maps to the real v2 prefix "sc2", so deriving the
// project name from the admin config missed the real projects. A share from a
// non-default source project must resolve to that project's volume, mounting the
// bare SourceDir (no per-project subdirectory, that was the v1 single-volume
// layout).
func TestShareReconcilerResolvesSourceProjectVolume(t *testing.T) {
	resource := &fakeShareReconcileResource{instance: &api.Instance{
		InstancePut: api.InstancePut{Devices: map[string]map[string]string{"root": {"type": "disk", "path": "/"}}},
	}}
	reconciler := shareReconcilerForTest(resource) // Admin prefix is the default "sc"
	summary := tenant.Summary{
		Tenant:       "skorfman",
		IncusName:    "sc2-skorfman-default",
		InfraProject: "sc2-skorfman", // real prefix is sc2, not the admin "sc"
		StorageShares: []meta.TenantStorageShare{{
			SourceTenant:  "thieso2",
			SourceProject: "backend",
			SourceDir:     "data/sets",
			Name:          "sets",
			Availability:  share.AvailabilityAvailable,
			Recipients:    []meta.TenantStorageShareRecipient{{Tenant: "skorfman", State: share.RecipientStateAccepted}},
		}},
	}
	if _, err := reconciler.ReconcileTenantShares(context.Background(), summary, false); err != nil {
		t.Fatal(err)
	}
	device := resource.updated.Devices[share.DeviceName(summary.StorageShares[0])]
	want := "/var/lib/incus/storage-pools/default/custom/sc2-thieso2-backend_workspace/data/sets"
	if device["source"] != want {
		t.Fatalf("source = %q, want %q", device["source"], want)
	}
}
