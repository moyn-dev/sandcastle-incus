package incusx

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/config"
	machine "github.com/moyn-dev/sandcastle-incus/internal/machine"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	"github.com/moyn-dev/sandcastle-incus/internal/share"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type ShareReconcileServer interface {
	UseProject(name string) ShareReconcileResourceServer
}

type ShareReconcileResourceServer interface {
	GetInstance(name string) (*api.Instance, string, error)
	UpdateInstance(name string, instance api.InstancePut, ETag string) (incus.Operation, error)
	ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error)
}

type ShareReconciler struct {
	Remote     string
	ConfigPath string
	Admin      config.Admin
	Store      machine.Store
	ShareStore share.Store
	Server     ShareReconcileServer
}

func NewShareReconciler(remote string, store machine.Store) ShareReconciler {
	admin := config.LoadAdmin()
	return ShareReconciler{Remote: remote, Store: store, ShareStore: NewTenantSSHKeyManagerWithPool(remote, admin.StoragePool), Admin: admin}
}

func NewShareReconcilerForServer(server incus.InstanceServer, store machine.Store, shareStore share.Store, admin config.Admin) ShareReconciler {
	return ShareReconciler{Server: sdkShareReconcileServer{inner: server}, Store: store, ShareStore: shareStore, Admin: admin}
}

func (r ShareReconciler) ReconcileTenantShares(ctx context.Context, summary tenant.Summary, dryRun bool) (share.ReconcileResult, error) {
	if r.Store == nil {
		return share.ReconcileResult{}, fmt.Errorf("machine store is not configured")
	}
	machines, err := r.Store.ListMachines(ctx, summary)
	if err != nil {
		return share.ReconcileResult{}, err
	}
	result := share.ReconcileResult{Tenant: summary.Tenant, DryRun: dryRun}
	if len(machines) == 0 {
		return result, nil
	}
	server, err := r.server()
	if err != nil {
		return share.ReconcileResult{}, err
	}
	for _, managed := range machines {
		// v1 packs the project into the instance name (<project>-<machine>) inside
		// the tenant's single Incus project; v2 gives each project its own Incus
		// project and keeps the bare machine name. Using the v1 rule on a v2
		// tenant looked up "default-web" and reported every machine as failed.
		projectServer := server.UseProject(shareReconcileIncusProject(summary, managed))
		result.Machines = append(result.Machines, r.reconcileMachine(ctx, projectServer, summary, managed, dryRun))
	}
	return result, nil
}

// shareReconcileIncusProject resolves the Incus project a machine's instance
// lives in.
func shareReconcileIncusProject(summary tenant.Summary, managed meta.Machine) string {
	return summary.V2IncusProjectName(managed.Project)
}

// shareReconcileInstanceName resolves the Incus instance name for a machine.
func shareReconcileInstanceName(summary tenant.Summary, managed meta.Machine) (string, error) {
	return managed.Name, nil
}

func (r ShareReconciler) reconcileMachine(ctx context.Context, server ShareReconcileResourceServer, summary tenant.Summary, managed meta.Machine, dryRun bool) share.MachineReconcileResult {
	machineResult := share.MachineReconcileResult{
		Project: managed.Project,
		Machine: managed.Name,
	}
	if managed.Type != "" && managed.Type != meta.MachineTypeContainer {
		machineResult.Status = "skipped"
		machineResult.Skipped = true
		return machineResult
	}
	instanceName, err := shareReconcileInstanceName(summary, managed)
	if err != nil {
		machineResult.Status = "failed"
		machineResult.Error = err.Error()
		return machineResult
	}
	machineResult.InstanceName = instanceName
	instance, etag, err := server.GetInstance(instanceName)
	if err != nil {
		machineResult.Status = "failed"
		machineResult.Error = fmt.Sprintf("get machine: %v", err)
		return machineResult
	}
	put := instance.Writable()
	current := copyDeviceMap(put.Devices)
	desired, err := r.desiredShareDevices(ctx, summary)
	if err != nil {
		machineResult.Status = "failed"
		machineResult.Error = err.Error()
		return machineResult
	}
	next := copyDeviceMap(current)
	for name, device := range desired {
		if err := ensureShareMountPathAvailable(server, instance, name, device, current); err != nil {
			machineResult.Status = "failed"
			machineResult.Error = err.Error()
			return machineResult
		}
		next[name] = device
	}
	for name := range next {
		if strings.HasPrefix(name, "share-") {
			if _, ok := desired[name]; !ok {
				delete(next, name)
			}
		}
	}
	if reflect.DeepEqual(current, next) {
		machineResult.Status = "current"
		return machineResult
	}
	machineResult.Changed = true
	if dryRun {
		machineResult.Status = "would-update"
		return machineResult
	}
	put.Devices = next
	op, err := server.UpdateInstance(instanceName, put, etag)
	if err != nil {
		machineResult.Status = "failed"
		machineResult.Error = fmt.Sprintf("update machine devices: %v", err)
		return machineResult
	}
	if err := op.Wait(); err != nil {
		machineResult.Status = "failed"
		machineResult.Error = fmt.Sprintf("wait for device update: %v", err)
		return machineResult
	}
	machineResult.Status = "updated"
	return machineResult
}

func (r ShareReconciler) desiredShareDevices(ctx context.Context, summary tenant.Summary) (map[string]map[string]string, error) {
	devices := map[string]map[string]string{}
	// The install prefix must come from live data, not r.Admin.IncusProjectPrefix:
	// the user-facing default "sc" maps to the actual v2 project prefix "sc2"
	// (see v2Summaries), so deriving "sc-<tenant>-<project>" from the admin config
	// misses the real "sc2-<tenant>-<project>" projects. The recipient's own infra
	// project (<prefix>-<recipientTenant>) encodes the real prefix, and shares are
	// within one install, so the source tenant shares it.
	prefix := strings.TrimSuffix(strings.TrimSpace(summary.InfraProject), "-"+summary.Tenant)
	if prefix == "" || prefix == summary.InfraProject {
		prefix = strings.TrimSpace(r.Admin.IncusProjectPrefix)
	}
	if prefix == "" {
		prefix = config.DefaultIncusProjectPrefix
	}
	pool := strings.TrimSpace(r.Admin.StoragePool)
	if pool == "" {
		pool = config.DefaultStoragePool
	}
	for _, storageShare := range summary.StorageShares {
		if !share.IsAcceptedAvailable(storageShare, summary.Tenant) {
			continue
		}
		// The source directory lives in the SOURCE project's own workspace volume,
		// <prefix>-<sourceTenant>-<sourceProject>. The old code derived
		// <prefix>-<sourceTenant> — the infra project, which has no workspace
		// volume — so no accepted share ever mounted.
		sourceIncusProject, err := naming.V2ProjectName(prefix, storageShare.SourceTenant, storageShare.SourceProject)
		if err != nil {
			return nil, err
		}
		if r.ShareStore != nil {
			status, err := sourceShareStatus(ctx, r.ShareStore, sourceIncusProject, storageShare)
			if err != nil {
				return nil, err
			}
			if !status.Exists || !status.Safe {
				continue
			}
		}
		devices[share.DeviceName(storageShare)] = share.DesiredDevice(storageShare, sourceIncusProject, pool, tenant.V2WorkspaceVolumeName)
	}
	return devices, nil
}

func sourceShareStatus(ctx context.Context, store share.Store, sourceIncusProject string, storageShare meta.TenantStorageShare) (share.SourceStatus, error) {
	if typed, ok := store.(share.SourceStatusStore); ok {
		return typed.SourceDirectoryStatus(ctx, sourceIncusProject, storageShare.SourceDir)
	}
	exists, err := store.SourceDirectoryExists(ctx, sourceIncusProject, storageShare.SourceDir)
	if err != nil {
		return share.SourceStatus{}, err
	}
	return share.SourceStatus{Exists: exists, Safe: exists}, nil
}

func (r ShareReconciler) server() (ShareReconcileServer, error) {
	if r.Server != nil {
		return r.Server, nil
	}
	loaded, err := LoadCLIConfig(r.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := r.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	server, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return sdkShareReconcileServer{inner: server}, nil
}

func copyDeviceMap(input map[string]map[string]string) map[string]map[string]string {
	output := make(map[string]map[string]string, len(input))
	for name, device := range input {
		output[name] = map[string]string{}
		for key, value := range device {
			output[name][key] = value
		}
	}
	return output
}

func ensureShareMountPathAvailable(server ShareReconcileResourceServer, instance *api.Instance, desiredName string, desiredDevice map[string]string, current map[string]map[string]string) error {
	desiredPath := strings.TrimSpace(desiredDevice["path"])
	if desiredPath == "" {
		return fmt.Errorf("share device %s has no mount path", desiredName)
	}
	for name, device := range current {
		if name != desiredName && strings.TrimSpace(device["path"]) == desiredPath {
			return fmt.Errorf("share mount path %s is already occupied by device %s", desiredPath, name)
		}
	}
	currentDevice, exists := current[desiredName]
	if exists && strings.TrimSpace(currentDevice["path"]) == desiredPath {
		return nil
	}
	if instance == nil || !instance.IsActive() {
		return nil
	}
	occupied, err := instancePathExists(server, instance.Name, desiredPath)
	if err != nil {
		return fmt.Errorf("check share mount path %s: %w", desiredPath, err)
	}
	if occupied {
		return fmt.Errorf("share mount path %s already exists in machine %s", desiredPath, instance.Name)
	}
	return nil
}

func instancePathExists(server ShareReconcileResourceServer, instanceName string, path string) (bool, error) {
	dataDone := make(chan bool)
	var stdout bytes.Buffer
	op, err := server.ExecInstance(instanceName, api.InstanceExecPost{
		Command:     []string{"/bin/sh", "-lc", "if [ -e \"$SANDCASTLE_SHARE_PATH\" ]; then printf 'exists\\n'; else printf 'missing\\n'; fi"},
		Environment: map[string]string{"SANDCASTLE_SHARE_PATH": path},
		WaitForWS:   true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stdout:   &stdout,
		DataDone: dataDone,
	})
	if err != nil {
		return false, err
	}
	waitErr := op.Wait()
	<-dataDone
	if waitErr != nil {
		return false, waitErr
	}
	switch strings.TrimSpace(stdout.String()) {
	case "exists":
		return true, nil
	case "missing":
		return false, nil
	default:
		return false, fmt.Errorf("unexpected path probe output %q", stdout.String())
	}
}

type sdkShareReconcileServer struct {
	inner incus.InstanceServer
}

func (s sdkShareReconcileServer) UseProject(name string) ShareReconcileResourceServer {
	return sdkShareReconcileResourceServer{inner: s.inner.UseProject(name)}
}

type sdkShareReconcileResourceServer struct {
	inner incus.InstanceServer
}

func (s sdkShareReconcileResourceServer) GetInstance(name string) (*api.Instance, string, error) {
	return s.inner.GetInstance(name)
}

func (s sdkShareReconcileResourceServer) UpdateInstance(name string, instance api.InstancePut, etag string) (incus.Operation, error) {
	return s.inner.UpdateInstance(name, instance, etag)
}

func (s sdkShareReconcileResourceServer) ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error) {
	return s.inner.ExecInstance(instanceName, exec, args)
}
