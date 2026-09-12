package incusx

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	machine "github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

type HostOverrideServer interface {
	UseProject(name string) HostOverrideResourceServer
}

type HostOverrideResourceServer interface {
	GetInstances(instanceType api.InstanceType) ([]api.Instance, error)
	GetInstancesFull(instanceType api.InstanceType) ([]api.InstanceFull, error)
	GetInstance(name string) (*api.Instance, string, error)
	UpdateInstance(name string, instance api.InstancePut, ETag string) (incus.Operation, error)
	CreateInstanceFile(instanceName string, path string, args incus.InstanceFileArgs) error
	GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error)
	ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error)
}

type HostOverrideManager struct {
	Remote     string
	ConfigPath string
	Server     HostOverrideServer
	Log        func(string)
}

func NewHostOverrideManager(remote string) HostOverrideManager {
	return HostOverrideManager{Remote: remote}
}

func NewHostOverrideManagerForServer(server incus.InstanceServer) HostOverrideManager {
	return HostOverrideManager{Server: sdkHostOverrideServer{inner: server}}
}

func NewHostOverrideManagerForSharedRemote(remote *SharedRemote) HostOverrideManager {
	return HostOverrideManager{Server: sharedHostOverrideServer{remote: remote}, Log: remote.Log}
}

func (m HostOverrideManager) WithVerbose(enabled bool, w io.Writer) HostOverrideManager {
	if enabled {
		m.Log = verboseLogger(w)
	}
	return m
}

func (m HostOverrideManager) FindMachine(ctx context.Context, summary tenant.Summary, projectName string, machineName string) (meta.Machine, error) {
	machines, err := m.ListMachinesInProject(ctx, summary, projectName)
	if err != nil {
		return meta.Machine{}, err
	}
	for _, machine := range machines {
		if machine.Name == machineName {
			return machine, nil
		}
	}
	return meta.Machine{}, fmt.Errorf("Sandcastle machine %s/%s/%s not found", summary.Tenant, projectName, machineName)
}

func (m HostOverrideManager) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	return m.listV2Machines(ctx, summary, "")
}

// ListMachinesInProject is the scoped form of ListMachines: it queries only the
// Incus projects whose Sandcastle project name matches projectFilter — a literal
// name, or a shell-style glob. Callers that know which projects they mean
// (`sc list` under a pinned project, a machine lookup, any globbing reference)
// must prefer it: the whole-tenant listing costs one Incus round trip per
// project, and on a tenant with a handful of projects that is most of the
// command's wall clock.
//
// A glob is answered from the tenant summary, which already carries the project
// list — so `sc ls '*:w*:*'` skips an install with no matching project without
// talking to it at all.
func (m HostOverrideManager) ListMachinesInProject(ctx context.Context, summary tenant.Summary, projectFilter string) ([]meta.Machine, error) {
	return m.listV2Machines(ctx, summary, projectFilter)
}

// ListMachinesAndUnmanaged: v2 machines are freeform instances, so every
// instance is a first-class machine and the "unmanaged" bucket is always empty.
func (m HostOverrideManager) ListMachinesAndUnmanaged(ctx context.Context, summary tenant.Summary) ([]meta.Machine, []machine.UnmanagedMachine, error) {
	machines, err := m.listV2Machines(ctx, summary, "")
	return machines, nil, err
}

// ListMachinesAndUnmanagedInProject is ListMachinesAndUnmanaged scoped to the
// Sandcastle projects matching projectFilter. See ListMachinesInProject.
func (m HostOverrideManager) ListMachinesAndUnmanagedInProject(ctx context.Context, summary tenant.Summary, projectFilter string) ([]meta.Machine, []machine.UnmanagedMachine, error) {
	machines, err := m.listV2Machines(ctx, summary, projectFilter)
	return machines, nil, err
}

// listV2Machines lists every instance across a v2 tenant's app projects, or
// across the projects matching projectFilter (a literal name or a glob). In v2
// machines are freeform incus instances (CTs and VMs, no Sandcastle metadata),
// so all of them are first-class machines — there is no unmanaged bucket.
//
// The per-project GetInstancesFull calls are issued CONCURRENTLY. Each one is an
// independent round trip to the Incus daemon that takes seconds on a loaded
// host, so serialising them made every listing cost the sum of the projects
// instead of the slowest one. The connection is established once up front
// (resolveServer → ensureConnected) so the goroutines only share the already
// connected, HTTP-backed client.
func (m HostOverrideManager) listV2Machines(ctx context.Context, summary tenant.Summary, projectFilter string) ([]meta.Machine, error) {
	server, err := m.resolveServer()
	if err != nil {
		return nil, err
	}
	projects := summary.Projects
	if len(projects) == 0 {
		projects = []meta.Project{{Name: naming.DefaultProjectName}}
	}
	if projectFilter = strings.TrimSpace(projectFilter); projectFilter != "" {
		scoped := []meta.Project{}
		for _, project := range projects {
			// MatchName on a literal is an equality check, so one branch
			// serves both a named project and a glob.
			if naming.MatchName(projectFilter, project.Name) {
				scoped = append(scoped, project)
			}
		}
		// No project matches: no machines, and — the point — no Incus calls.
		projects = scoped
	}
	perProject := make([][]meta.Machine, len(projects))
	errors := make([]error, len(projects))
	var group sync.WaitGroup
	for index, project := range projects {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := ctx.Err(); err != nil {
				errors[index] = err
				return
			}
			projectServer := server.UseProject(summary.V2IncusProjectName(project.Name))
			instances, err := projectServer.GetInstancesFull(api.InstanceTypeAny)
			if err != nil {
				errors[index] = fmt.Errorf("list project %s instances: %w", project.Name, err)
				return
			}
			found := make([]meta.Machine, 0, len(instances))
			for _, instance := range instances {
				if converted, ok := MachineFromInstance(summary.Tenant, project.Name, instance); ok {
					found = append(found, converted)
				}
			}
			perProject[index] = found
		}()
	}
	group.Wait()
	// Report the first project's failure in project order, so a flaky project
	// does not make the error message depend on goroutine scheduling.
	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}
	machines := []meta.Machine{}
	for _, found := range perProject {
		machines = append(machines, found...)
	}
	return machines, nil
}

// MachineFromInstance converts a raw Incus instance into the CLI-facing
// meta.Machine shape. It is the one conversion every listing path funnels
// through — the live per-project sweep above (listV2Machines) and the
// event-bus-fed resource cache's `sc ls` endpoint
// (authapp.ResourceCacheMachineRenderer, docs/shape/admin-server-config-
// toggled-event-bus-ca8marg.md) — so the two paths cannot drift on what
// counts as a machine or how its fields are derived. ok is false for
// Sandcastle-managed infrastructure (e.g. a tenant's DNS/route sidecar) that
// must never appear in a machine listing.
func MachineFromInstance(tenantName string, project string, instance api.InstanceFull) (result meta.Machine, ok bool) {
	if meta.IsManaged(instance.Config) && instance.Config[meta.KeyKind] == meta.KindSidecar {
		return meta.Machine{}, false
	}
	// Read from the instance's OWN config, so a project-wide profile key could
	// never mark every machine bare — and likewise for the Naming Mode record
	// and certificate mirror (ADR-0027), which meta.DecodeMachine fills.
	return meta.DecodeMachine(instance.Config, meta.Machine{
		Tenant:    tenantName,
		Project:   project,
		Name:      instance.Name,
		Type:      string(instance.Type),
		PrivateIP: instanceGlobalIPv4(instance),
		CreatedAt: formatInstanceCreatedAt(instance.CreatedAt),
		Running:   instance.IsActive(),
		Bare:      instanceIsBareV2(instance.Config),
	}), true
}

// instanceGlobalIPv4 returns the global IPv4 of the instance's Incus-managed
// NIC from live state — freeform v2 machines lease via DHCP, so there is no
// static ip device to read. In-guest bridges such as docker0 are ignored; see
// instance_ipv4.go.
func instanceGlobalIPv4(instance api.InstanceFull) string {
	if instance.State == nil {
		return ""
	}
	return instanceNICIPv4(instance.ExpandedConfig, instance.ExpandedDevices, instance.State.Network).Address
}

// resolveServer returns the connected server the manager should use (the
// injected one for tests, otherwise a fresh SDK connection to the remote).
func (m HostOverrideManager) resolveServer() (HostOverrideServer, error) {
	server := m.Server
	if server == nil {
		instanceServer, err := connectConfiguredRemote(m.Log, m.ConfigPath, m.Remote)
		if err != nil {
			return nil, err
		}
		server = sdkHostOverrideServer{inner: instanceServer, Log: m.Log}
	}
	if connector, ok := server.(interface{ ensureConnected() error }); ok {
		if err := connector.ensureConnected(); err != nil {
			return nil, err
		}
	}
	return server, nil
}

func formatInstanceCreatedAt(createdAt time.Time) string {
	if createdAt.IsZero() {
		return ""
	}
	return createdAt.UTC().Format(time.RFC3339)
}

func instancePrivateIP(instance api.Instance) string {
	for _, devices := range []map[string]map[string]string{instance.ExpandedDevices, instance.Devices} {
		for _, device := range devices {
			if device["type"] != "nic" {
				continue
			}
			if ip := device["ipv4.address"]; ip != "" && ip != "none" && ip != "auto" {
				return ip
			}
		}
	}
	return ""
}

type sdkHostOverrideServer struct {
	inner incus.InstanceServer
	Log   func(string)
}

func (s sdkHostOverrideServer) UseProject(name string) HostOverrideResourceServer {
	return sdkHostOverrideResourceServer{inner: s.inner.UseProject(name), projectName: name, Log: s.Log}
}

type sdkHostOverrideResourceServer struct {
	inner       incus.InstanceServer
	projectName string
	Log         func(string)
}

func (s sdkHostOverrideResourceServer) GetInstances(instanceType api.InstanceType) ([]api.Instance, error) {
	return logIncusAPICall(s.Log, "GetInstances project="+s.projectName+" type="+string(instanceType), func() ([]api.Instance, error) {
		return s.inner.GetInstances(instanceType)
	})
}

func (s sdkHostOverrideResourceServer) GetInstancesFull(instanceType api.InstanceType) ([]api.InstanceFull, error) {
	return logIncusAPICall(s.Log, "GetInstancesFull project="+s.projectName+" type="+string(instanceType), func() ([]api.InstanceFull, error) {
		return s.inner.GetInstancesFull(instanceType)
	})
}

func (s sdkHostOverrideResourceServer) GetInstance(name string) (*api.Instance, string, error) {
	var instance *api.Instance
	var etag string
	err := logIncusAPICall0(s.Log, "GetInstance project="+s.projectName+" instance="+name, func() error {
		var err error
		instance, etag, err = s.inner.GetInstance(name)
		return err
	})
	return instance, etag, err
}

func (s sdkHostOverrideResourceServer) UpdateInstance(name string, instance api.InstancePut, ETag string) (incus.Operation, error) {
	return logIncusAPICall(s.Log, "UpdateInstance project="+s.projectName+" instance="+name, func() (incus.Operation, error) {
		return s.inner.UpdateInstance(name, instance, ETag)
	})
}

func (s sdkHostOverrideResourceServer) CreateInstanceFile(instanceName string, path string, args incus.InstanceFileArgs) error {
	return logIncusAPICall0(s.Log, "CreateInstanceFile project="+s.projectName+" instance="+instanceName+" path="+path, func() error {
		return s.inner.CreateInstanceFile(instanceName, path, args)
	})
}

func (s sdkHostOverrideResourceServer) GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	var content io.ReadCloser
	var response *incus.InstanceFileResponse
	err := logIncusAPICall0(s.Log, "GetStorageVolumeFile project="+s.projectName+" pool="+pool+" volume="+volumeName+" path="+filePath, func() error {
		var err error
		content, response, err = getStorageVolumeFile(s.inner, s.projectName, pool, volumeType, volumeName, filePath)
		return err
	})
	return content, response, err
}

func (s sdkHostOverrideResourceServer) ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error) {
	return logIncusAPICall(s.Log, "ExecInstance project="+s.projectName+" instance="+instanceName, func() (incus.Operation, error) {
		return s.inner.ExecInstance(instanceName, exec, args)
	})
}

func appendUnique(values []string, additions ...string) []string {
	seen := map[string]bool{}
	output := []string{}
	for _, value := range append(values, additions...) {
		normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		output = append(output, normalized)
	}
	return output
}

func removeValue(values []string, removed string) []string {
	normalizedRemoved := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(removed)), ".")
	output := []string{}
	for _, value := range values {
		normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if normalized == "" || normalized == normalizedRemoved {
			continue
		}
		output = append(output, normalized)
	}
	return output
}
