package incusx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// ZoneMachineServer is the Incus side of the Public DNS Zone reconciler
// (ADR-0027 §4 / ADR-0028, authapp.ZoneMachineServer): the fleet walk, the
// public-name-list / certificate-state stamps, the marker, hostnames-file
// and certificate reads, and the per-hostname cert + key and hostnames-file
// pushes into a Machine. It runs over the mounted host socket of the serving
// Auth App, scoped to one install's prefix like V2DNSReconciler.
type ZoneMachineServer struct {
	Server incus.InstanceServer
	Store  tenant.IncusTenantStore
	Prefix string
}

var _ authapp.ZoneMachineServer = ZoneMachineServer{}

// NewZoneMachineServer builds the seam over an already-connected server.
func NewZoneMachineServer(server incus.InstanceServer, store tenant.IncusTenantStore, prefix string) ZoneMachineServer {
	return ZoneMachineServer{Server: server, Store: store, Prefix: prefix}
}

// ListZoneMachines walks every app project of every tenant of the install
// (one GetInstancesFull per project — config, state and addresses in one
// call) and returns each non-sidecar instance with its project's domain key,
// its public-name keys (the list, and the legacy single key the reconciler
// only ever deletes), its certificate mirror and its bridge address.
func (s ZoneMachineServer) ListZoneMachines(ctx context.Context) ([]authapp.ZoneMachine, error) {
	return s.listZoneMachines(ctx, nil)
}

// ListZoneMachinesFrom shapes a fleet the loop already listed (authapp
// zoneFleetLister): the project walk stays, the per-project instance
// listing does not.
func (s ZoneMachineServer) ListZoneMachinesFrom(ctx context.Context, fleet authapp.InstanceFleet) ([]authapp.ZoneMachine, error) {
	return s.listZoneMachines(ctx, fleet)
}

func (s ZoneMachineServer) listZoneMachines(ctx context.Context, fleet authapp.InstanceFleet) ([]authapp.ZoneMachine, error) {
	if s.Server == nil || s.Store == nil {
		return nil, nil
	}
	summaries, err := tenant.ListForPrefix(ctx, s.Store, s.Prefix)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	var machines []authapp.ZoneMachine
	for _, summary := range summaries {
		var cidr netip.Prefix
		if summary.PrivateCIDR != "" {
			cidr, _ = netip.ParsePrefix(summary.PrivateCIDR)
		}
		for _, project := range summary.Projects {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			incusProject := summary.V2IncusProjectName(project.Name)
			var instances []api.InstanceFull
			if fleet != nil {
				instances = fleetInstances(fleet, incusProject)
			} else {
				var err error
				if instances, err = s.Server.UseProject(incusProject).GetInstancesFull(api.InstanceTypeAny); err != nil {
					return nil, fmt.Errorf("list %s instances: %w", incusProject, err)
				}
			}
			for _, instance := range instances {
				if meta.IsManaged(instance.Config) && instance.Config[meta.KeyKind] == meta.KindSidecar {
					continue
				}
				ip := ""
				if cidr.IsValid() {
					ip = instanceTenantIPv4(instance, cidr)
				}
				machines = append(machines, authapp.ZoneMachine{
					Tenant:          summary.Tenant,
					Project:         project.Name,
					IncusProject:    incusProject,
					Name:            instance.Name,
					ProjectDomain:   project.Domain,
					PublicHostname:  strings.TrimSpace(instance.Config[meta.KeyV2PublicHostname]),
					PublicHostnames: meta.ParsePublicHostnames(instance.Config[meta.KeyV2PublicHostnames]),
					BridgeIPv4:      ip,
					Running:         instance.IsActive(),
					CertState:       strings.TrimSpace(instance.Config[meta.KeyV2CertState]),
					CertNotAfter:    strings.TrimSpace(instance.Config[meta.KeyV2CertNotAfter]),
				})
			}
		}
	}
	return machines, nil
}

// StampInstanceConfig merges config into the instance's own config (empty
// values delete the key) and waits for the update.
func (s ZoneMachineServer) StampInstanceConfig(ctx context.Context, incusProject, name string, config map[string]string) error {
	return stampInstanceConfig(s.Server.UseProject(incusProject), name, config)
}

// stampInstanceConfig is the seam's write, over the narrow instanceConfigServer
// so a fake can exercise it.
func stampInstanceConfig(server instanceConfigServer, name string, config map[string]string) error {
	inst, etag, err := server.GetInstance(name)
	if err != nil {
		return fmt.Errorf("read instance %s: %w", name, err)
	}
	put := inst.Writable()
	if put.Config == nil {
		put.Config = map[string]string{}
	}
	changed := false
	for key, value := range config {
		if value == "" {
			if _, present := put.Config[key]; present {
				delete(put.Config, key)
				changed = true
			}
			continue
		}
		if put.Config[key] != value {
			put.Config[key] = value
			changed = true
		}
	}
	if !changed {
		return nil
	}
	op, err := server.UpdateInstance(name, put, etag)
	if err != nil {
		return fmt.Errorf("update instance %s config: %w", name, err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("wait for instance %s config update: %w", name, err)
	}
	return nil
}

// ReadInstanceFile returns a file's content from the instance;
// authapp.ErrInstanceFileNotFound when Incus answers 404 for the path.
func (s ZoneMachineServer) ReadInstanceFile(ctx context.Context, incusProject, name, path string) (string, error) {
	content, err := readInstanceFileString(s.Server.UseProject(incusProject), name, path)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return "", fmt.Errorf("%s: %w", path, authapp.ErrInstanceFileNotFound)
		}
		return "", err
	}
	return content, nil
}

// machineCertificatePushServer is what the push needs from Incus.
type machineCertificatePushServer interface {
	CreateInstanceFile(instanceName string, path string, args incus.InstanceFileArgs) error
	ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error)
}

// PushMachineCertificate installs a Machine Certificate for one hostname
// (spec §4.4, per name since ADR-0028): the chain and key land as `.new`
// files in the hostname's directory /etc/sandcastle/tls/<hostname>/ (key
// 0600, both root-owned; Incus creates the directory), then ONE exec swaps
// both into place back to back, makes sure the name is listed in
// /etc/sandcastle/hostnames, and runs `sandcastle-caddy-setup --refresh`,
// which re-renders the Caddyfile with the new block and reloads Caddy
// (starting it when inactive). The private leaf at the fixed
// /etc/sandcastle/tls/{cert,key}.pem is never touched.
func (s ZoneMachineServer) PushMachineCertificate(ctx context.Context, incusProject, name, hostname, certPEM, keyPEM string) error {
	return pushMachineCertificate(s.Server.UseProject(incusProject), name, hostname, certPEM, keyPEM)
}

func pushMachineCertificate(server machineCertificatePushServer, name, hostname, certPEM, keyPEM string) error {
	hostname = tenant.NormalizePublicHostname(hostname)
	if hostname == "" {
		return fmt.Errorf("push certificate: empty hostname")
	}
	// The file API does not create parents: the hostname's directory is
	// created first (a directory push is idempotent).
	if err := server.CreateInstanceFile(name, tenant.MachineTLSHostDir(hostname), incus.InstanceFileArgs{
		Type: "directory",
		Mode: 0o755,
		UID:  0,
		GID:  0,
	}); err != nil {
		return fmt.Errorf("create %s: %w", tenant.MachineTLSHostDir(hostname), err)
	}
	files := []struct {
		path    string
		content string
		mode    int
	}{
		{tenant.MachineTLSHostCertPath(hostname) + ".new", certPEM, 0o644},
		{tenant.MachineTLSHostKeyPath(hostname) + ".new", keyPEM, 0o600},
	}
	for _, file := range files {
		if err := server.CreateInstanceFile(name, file.path, incus.InstanceFileArgs{
			Content:   strings.NewReader(file.content),
			Type:      "file",
			Mode:      file.mode,
			UID:       0,
			GID:       0,
			WriteMode: "overwrite",
		}); err != nil {
			return fmt.Errorf("write %s: %w", file.path, err)
		}
	}
	return execInstanceScript(server, name, machineCertificateInstallScript(hostname), "install certificate")
}

// execInstanceScript runs one /bin/sh -c script in the instance and reports
// a nonzero exit (with stderr) as an error prefixed with what.
func execInstanceScript(server machineCertificatePushServer, name, script, what string) error {
	var stderr strings.Builder
	dataDone := make(chan bool)
	op, err := server.ExecInstance(name, api.InstanceExecPost{
		Command:   []string{"/bin/sh", "-c", script},
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stdout:   io.Discard,
		Stderr:   &stderr,
		DataDone: dataDone,
	})
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("%s: %w (stderr: %s)", what, err, strings.TrimSpace(stderr.String()))
	}
	<-dataDone
	if err := execExitError(op, stderr.String()); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	return nil
}

// machineCertificateInstallScript swaps both files and refreshes Caddy.
// The authoritative hostname list is pushed separately: a certificate storage
// directory (especially a Project Domain) is not an implicit machine hostname.
func machineCertificateInstallScript(hostname string) string {
	return fmt.Sprintf("mv -f %[1]s.new %[1]s && mv -f %[2]s.new %[2]s && %[3]s %[4]s",
		certificateShellPath(tenant.MachineTLSHostCertPath(hostname)), certificateShellPath(tenant.MachineTLSHostKeyPath(hostname)), tenant.CaddySetupCommand, tenant.CaddySetupRefreshFlag)
}

// PushMachineHostnames writes the machine's whole public-name set to
// /etc/sandcastle/hostnames (0644, root) and runs caddy-setup --refresh so
// a removed name's site block disappears and a listed name whose
// certificate is already there appears. The reconciler calls it whenever
// the file on the machine does not list exactly the machine's set.
func (s ZoneMachineServer) PushMachineHostnames(ctx context.Context, incusProject, name string, hostnames []string) error {
	return pushMachineHostnames(s.Server.UseProject(incusProject), name, hostnames)
}

func pushMachineHostnames(server machineCertificatePushServer, name string, hostnames []string) error {
	if err := server.CreateInstanceFile(name, tenant.MachineHostnamesPath, incus.InstanceFileArgs{
		Content:   strings.NewReader(tenant.FormatMachineHostnamesFile(hostnames)),
		Type:      "file",
		Mode:      0o644,
		UID:       0,
		GID:       0,
		WriteMode: "overwrite",
	}); err != nil {
		return fmt.Errorf("write %s: %w", tenant.MachineHostnamesPath, err)
	}
	return execInstanceScript(server, name, tenant.CaddySetupCommand+" "+tenant.CaddySetupRefreshFlag, "refresh caddy")
}

// Project-domain selection is separate from the hostname list: the apex is
// certificate storage, never an implicit public name of each machine.
func (s ZoneMachineServer) PushMachineProjectDomain(ctx context.Context, project, name, domain string) error {
	server := s.Server.UseProject(project)
	if err := server.CreateInstanceFile(name, tenant.MachineProjectDomainPath, incus.InstanceFileArgs{
		Content: strings.NewReader(domain + "\n"), Type: "file", Mode: 0o644, UID: 0, GID: 0, WriteMode: "overwrite",
	}); err != nil {
		return err
	}
	return execInstanceScript(server, name, tenant.CaddySetupCommand+" "+tenant.CaddySetupRefreshFlag, "refresh project certificate selection")
}

func certificateShellPath(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\"'\"'") + "'"
}
