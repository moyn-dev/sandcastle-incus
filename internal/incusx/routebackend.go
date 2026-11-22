package incusx

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	authapp "github.com/moyn-dev/sandcastle-incus/internal/authapp"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
)

// RouteBackend implements authapp.RouteBackend against a live Incus daemon (the
// auth-app's mounted host socket). It manages per-Route proxy devices on the
// auth-app instance and reports tenant Machine state. Single-host: the proxy
// device's `connect` is dialed from the host namespace, which routes to the
// tenant bridge (Spec #111, ADR-0016).
type RouteBackend struct {
	Server incus.InstanceServer
	// MachinePrefix is the install prefix for tenant app projects
	// (<prefix>-<tenant>-<project>), matching tenant.ListForPrefix.
	MachinePrefix string
	// AuthAppInstance / AuthAppProject locate the auth-app appliance instance
	// whose device map the per-Route proxy devices live on.
	AuthAppInstance string
	AuthAppProject  string
	// Front is the shared front (an sc-edge instance) this install publishes its
	// Route SNI list to; zero value = the install owns the host ports itself and
	// nothing is published. See routefront.go.
	Front FrontTarget
}

var _ authapp.RouteBackend = RouteBackend{}

// routeDevice builds the Incus proxy-device config for a Route. bind=instance so
// the listener is inside the auth-app container (where Caddy dials 127.0.0.1)
// and the connect is dialed from the host namespace.
func routeDevice(localPort int, machineIP string, backendPort int) map[string]string {
	return map[string]string{
		"type":    "proxy",
		"bind":    "instance",
		"listen":  fmt.Sprintf("tcp:127.0.0.1:%d", localPort),
		"connect": fmt.Sprintf("tcp:%s:%d", machineIP, backendPort),
	}
}

func (b RouteBackend) EnsureProxyDevice(ctx context.Context, deviceName string, localPort int, machineIP string, backendPort int) error {
	if b.Server == nil {
		return fmt.Errorf("route backend has no Incus connection")
	}
	project := b.Server.UseProject(b.AuthAppProject)
	instance, etag, err := project.GetInstance(b.AuthAppInstance)
	if err != nil {
		return fmt.Errorf("get auth-app instance %q: %w", b.AuthAppInstance, err)
	}
	put := instance.Writable()
	next := copyDeviceMap(put.Devices)
	next[deviceName] = routeDevice(localPort, machineIP, backendPort)
	if reflect.DeepEqual(put.Devices, next) {
		return nil
	}
	put.Devices = next
	op, err := project.UpdateInstance(b.AuthAppInstance, put, etag)
	if err != nil {
		return fmt.Errorf("add route proxy device: %w", err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("wait for route proxy device: %w", err)
	}
	return nil
}

func (b RouteBackend) RemoveProxyDevice(ctx context.Context, deviceName string) error {
	if b.Server == nil {
		return fmt.Errorf("route backend has no Incus connection")
	}
	project := b.Server.UseProject(b.AuthAppProject)
	instance, etag, err := project.GetInstance(b.AuthAppInstance)
	if err != nil {
		return fmt.Errorf("get auth-app instance %q: %w", b.AuthAppInstance, err)
	}
	if _, present := instance.Devices[deviceName]; !present {
		return nil // already gone
	}
	put := instance.Writable()
	next := copyDeviceMap(put.Devices)
	delete(next, deviceName)
	put.Devices = next
	op, err := project.UpdateInstance(b.AuthAppInstance, put, etag)
	if err != nil {
		return fmt.Errorf("remove route proxy device: %w", err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("wait for route proxy device removal: %w", err)
	}
	return nil
}

func (b RouteBackend) MachineState(ctx context.Context, tenant, project, machine string) (authapp.MachineState, error) {
	if b.Server == nil {
		return authapp.MachineState{}, fmt.Errorf("route backend has no Incus connection")
	}
	incusProject, err := naming.V2ProjectName(b.MachinePrefix, tenant, project)
	if err != nil {
		return authapp.MachineState{}, err
	}
	server := b.Server.UseProject(incusProject)
	instance, _, err := server.GetInstance(machine)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return authapp.MachineState{Present: false}, nil
		}
		// Transient/other failure: surface as an error so the reconcile does not
		// prune (Spec #111).
		return authapp.MachineState{}, fmt.Errorf("get machine %q: %w", machine, err)
	}
	state := authapp.MachineState{Present: true, FQDN: b.machinePrivateHostname(incusProject, project, machine)}
	if instance.StatusCode == api.Running {
		state.Running = true
		state.IPv4 = firstGlobalIPv4(server, machine, instance)
	}
	return state, nil
}

// machinePrivateHostname builds the Machine Private Hostname
// <machine>.<project>.<Tenant DNS Suffix> (ADR-0018) so a Route can name its
// backend the way the Tenant reaches it. The suffix is read from the app
// project's config, where tenant/project create wrote it. Best effort: a failed
// read yields "" and the caller falls back to the bare Machine name rather than
// failing a status or reconcile pass over a cosmetic field.
func (b RouteBackend) machinePrivateHostname(incusProject, project, machine string) string {
	if b.Server == nil {
		return ""
	}
	found, _, err := b.Server.GetProject(incusProject)
	if err != nil || found == nil {
		return ""
	}
	suffix := strings.Trim(strings.TrimSpace(found.Config[meta.KeyV2Suffix]), ".")
	if suffix == "" {
		return ""
	}
	return machine + "." + project + "." + suffix
}

// firstGlobalIPv4 returns a Machine's global IPv4 from live instance state — the
// address a Route's proxy device connects to. Only the instance's Incus-managed
// NIC is considered: publishing a route to an in-guest bridge address such as
// docker0's 172.17.0.1 would point the proxy at nothing. See instance_ipv4.go.
func firstGlobalIPv4(server incus.InstanceServer, machine string, instance *api.Instance) string {
	state, _, err := server.GetInstanceState(machine)
	if err != nil || state == nil || instance == nil {
		return ""
	}
	return instanceNICIPv4(instance.ExpandedConfig, instance.ExpandedDevices, state.Network).Address
}
