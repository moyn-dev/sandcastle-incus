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
// (ADR-0027 §4, authapp.ZoneMachineServer): the fleet walk, the Naming Mode /
// certificate-state stamps, the marker and certificate reads, and the
// cert + key push into a Machine. It runs over the mounted host socket of the
// serving Auth App, scoped to one install's prefix like V2DNSReconciler.
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
// its Naming Mode record, its certificate mirror and its bridge address.
func (s ZoneMachineServer) ListZoneMachines(ctx context.Context) ([]authapp.ZoneMachine, error) {
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
			instances, err := s.Server.UseProject(incusProject).GetInstancesFull(api.InstanceTypeAny)
			if err != nil {
				return nil, fmt.Errorf("list %s instances: %w", incusProject, err)
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

// PushMachineCertificate installs a Machine Certificate (spec §4.4): the
// chain and key land as `.new` files (key 0600, both root-owned), then ONE
// exec swaps both into place back to back and reloads Caddy — restart when
// the reload fails because Caddy is still enabled-inactive before the first
// push (the drop-in's ConditionPathExists is satisfied now). start appends an
// explicit `systemctl start caddy` for that first push.
func (s ZoneMachineServer) PushMachineCertificate(ctx context.Context, incusProject, name, certPEM, keyPEM string, start bool) error {
	return pushMachineCertificate(s.Server.UseProject(incusProject), name, certPEM, keyPEM, start)
}

func pushMachineCertificate(server machineCertificatePushServer, name, certPEM, keyPEM string, start bool) error {
	files := []struct {
		path    string
		content string
		mode    int
	}{
		{tenant.MachineTLSCertPath + ".new", certPEM, 0o644},
		{tenant.MachineTLSKeyPath + ".new", keyPEM, 0o600},
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
	var stderr strings.Builder
	dataDone := make(chan bool)
	op, err := server.ExecInstance(name, api.InstanceExecPost{
		Command:   []string{"/bin/sh", "-c", machineCertificateInstallScript(start)},
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stdout:   io.Discard,
		Stderr:   &stderr,
		DataDone: dataDone,
	})
	if err != nil {
		return fmt.Errorf("install certificate: %w", err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("install certificate: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	<-dataDone
	if err := execExitError(op, stderr.String()); err != nil {
		return fmt.Errorf("install certificate: %w", err)
	}
	return nil
}

// machineCertificateInstallScript is the one-exec swap + reload of spec §4.4.
func machineCertificateInstallScript(start bool) string {
	script := fmt.Sprintf("mv -f %[1]s.new %[1]s && mv -f %[2]s.new %[2]s && (systemctl reload caddy 2>/dev/null || systemctl restart caddy)",
		tenant.MachineTLSCertPath, tenant.MachineTLSKeyPath)
	if start {
		script += " && systemctl start caddy"
	}
	return script
}
