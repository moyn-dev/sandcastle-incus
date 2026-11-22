package incusx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	machine "github.com/moyn-dev/sandcastle-incus/internal/machine"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type TopologyServer interface {
	UseProject(name string) TopologyResourceServer
}

type TopologyResourceServer interface {
	GetNetwork(name string) (*api.Network, string, error)
	GetStoragePoolVolume(pool string, volType string, name string) (*api.StorageVolume, string, error)
	GetInstance(name string) (*api.Instance, string, error)
	GetInstances(instanceType api.InstanceType) ([]api.Instance, error)
	GetInstanceFile(instanceName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error)
}

type TopologyStore struct {
	Remote     string
	ConfigPath string
	Server     TopologyServer
}

func NewTopologyStore(remote string) TopologyStore {
	return TopologyStore{Remote: remote}
}

func (s TopologyStore) GetTopology(ctx context.Context, request tenant.TopologyRequest) (tenant.Topology, error) {
	server := s.Server
	if server == nil {
		loaded, err := LoadCLIConfig(s.ConfigPath)
		if err != nil {
			return tenant.Topology{}, fmt.Errorf("load Incus config: %w", err)
		}
		remote := s.Remote
		if remote == "" {
			remote = loaded.DefaultRemote
		}
		instanceServer, err := connectInstanceServer(loaded, remote)
		if err != nil {
			return tenant.Topology{}, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
		}
		server = sdkTopologyServer{inner: instanceServer}
	}
	projectServer := server.UseProject(request.IncusProject)
	infraServer := server.UseProject(request.InfraProject)
	tailscaleInstance := tenant.TailscaleInstanceName(request.IncusProject)
	topology := tenant.Topology{
		TailscaleInstance: tailscaleInstance,
		DurableVolumes:    map[string]bool{},
		Sidecars:          map[string]tenant.SidecarStatus{},
	}
	privateNetworkName := tenant.PrivateNetworkName(request.IncusProject)
	if _, _, err := projectServer.GetNetwork(privateNetworkName); err == nil {
		topology.PrivateNetworkPresent = true
	} else if !api.StatusErrorCheck(err, http.StatusNotFound) {
		return tenant.Topology{}, fmt.Errorf("get private network %s: %w", privateNetworkName, err)
	}
	for _, volume := range []string{tenant.HomeVolumeName, tenant.WorkspaceVolumeName, tenant.CAVolumeName} {
		if _, _, err := projectServer.GetStoragePoolVolume(request.IncusProject, "custom", volume); err == nil {
			topology.DurableVolumes[volume] = true
		} else if !api.StatusErrorCheck(err, http.StatusNotFound) {
			return tenant.Topology{}, fmt.Errorf("get durable volume %s: %w", volume, err)
		}
	}
	for _, sidecar := range []string{tailscaleInstance, tenant.DNSName} {
		instance, _, err := infraServer.GetInstance(sidecar)
		if err == nil {
			topology.Sidecars[sidecar] = tenant.SidecarStatus{
				Present: true,
				Running: instance.IsActive(),
				Status:  instance.Status,
			}
		} else if !api.StatusErrorCheck(err, http.StatusNotFound) {
			return tenant.Topology{}, fmt.Errorf("get sidecar %s: %w", sidecar, err)
		}
	}
	topology.DiagnosticFiles = diagnosticFiles(projectServer, infraServer, request)
	return topology, nil
}

func diagnosticFiles(mainServer TopologyResourceServer, infraServer TopologyResourceServer, request tenant.TopologyRequest) []tenant.DiagnosticFile {
	files := []tenant.DiagnosticFile{
		readDiagnosticFile(infraServer, tenant.DNSName, "/etc/coredns/Corefile"),
	}
	domain := strings.Trim(strings.TrimSpace(request.DNSSuffix), ".")
	if domain != "" {
		files = append(files, readDiagnosticFile(infraServer, tenant.DNSName, path.Join("/etc/coredns/zones", "db."+domain)))
	}
	for _, instance := range machineInstances(mainServer) {
		files = append(files, readDiagnosticFile(mainServer, instance.Name, machine.CaddyfilePath))
	}
	return files
}

func machineInstances(server TopologyResourceServer) []api.Instance {
	instances, err := server.GetInstances(api.InstanceTypeContainer)
	if err != nil {
		return nil
	}
	machinees := []api.Instance{}
	for _, instance := range instances {
		if instance.Config[meta.KeyKind] == meta.KindMachine {
			machinees = append(machinees, instance)
		}
	}
	sort.Slice(machinees, func(i, j int) bool {
		return machinees[i].Name < machinees[j].Name
	})
	return machinees
}

func readDiagnosticFile(server TopologyResourceServer, instance string, filePath string) tenant.DiagnosticFile {
	file := tenant.DiagnosticFile{Instance: instance, Path: filePath}
	reader, _, err := server.GetInstanceFile(instance, filePath)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			file.Error = "missing"
		} else {
			file.Error = err.Error()
		}
		return file
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, 8192))
	if err != nil {
		file.Error = err.Error()
		return file
	}
	file.Content = string(content)
	return file
}

type sdkTopologyServer struct {
	inner incus.InstanceServer
}

func (s sdkTopologyServer) UseProject(name string) TopologyResourceServer {
	return s.inner.UseProject(name)
}
