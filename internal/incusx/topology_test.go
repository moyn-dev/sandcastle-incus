package incusx

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	machine "github.com/moyn-dev/sandcastle-incus/internal/machine"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type fakeTopologyServer struct {
	resources map[string]*fakeTopologyResource
}

func (s fakeTopologyServer) UseProject(name string) TopologyResourceServer {
	if r, ok := s.resources[name]; ok {
		return r
	}
	return &fakeTopologyResource{
		networks:  map[string]*api.Network{},
		volumes:   map[string]*api.StorageVolume{},
		instances: map[string]*api.Instance{},
		files:     map[string]string{},
	}
}

type fakeTopologyResource struct {
	networks  map[string]*api.Network
	volumes   map[string]*api.StorageVolume
	instances map[string]*api.Instance
	files     map[string]string
}

func (r fakeTopologyResource) GetNetwork(name string) (*api.Network, string, error) {
	if network := r.networks[name]; network != nil {
		return network, "etag", nil
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "not found")
}

func (r fakeTopologyResource) GetStoragePoolVolume(pool string, volType string, name string) (*api.StorageVolume, string, error) {
	if volume := r.volumes[name]; volume != nil {
		return volume, "etag", nil
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "not found")
}

func (r fakeTopologyResource) GetInstance(name string) (*api.Instance, string, error) {
	if instance := r.instances[name]; instance != nil {
		return instance, "etag", nil
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "not found")
}

func (r fakeTopologyResource) GetInstances(instanceType api.InstanceType) ([]api.Instance, error) {
	instances := make([]api.Instance, 0, len(r.instances))
	for _, instance := range r.instances {
		instances = append(instances, *instance)
	}
	return instances, nil
}

func (r fakeTopologyResource) GetInstanceFile(instanceName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	if content, ok := r.files[instanceName+":"+filePath]; ok {
		return io.NopCloser(strings.NewReader(content)), &incus.InstanceFileResponse{Type: "file"}, nil
	}
	return nil, nil, api.StatusErrorf(http.StatusNotFound, "not found")
}

func TestTopologyStoreGetTopology(t *testing.T) {
	mainResource := &fakeTopologyResource{
		networks: map[string]*api.Network{tenant.PrivateNetworkName("sc-alice-myproject"): {Name: tenant.PrivateNetworkName("sc-alice-myproject")}},
		volumes: map[string]*api.StorageVolume{
			tenant.HomeVolumeName: {Name: tenant.HomeVolumeName},
			tenant.CAVolumeName:   {Name: tenant.CAVolumeName},
		},
		instances: map[string]*api.Instance{
			"default-codex": {
				Name: "default-codex",
				InstancePut: api.InstancePut{
					Config: map[string]string{
						meta.KeyKind:    meta.KindMachine,
						meta.KeyVersion: "1",
					},
				},
			},
			"manual": {
				Name: "manual",
				InstancePut: api.InstancePut{
					Config: map[string]string{
						meta.KeyKind: "manual",
					},
				},
			},
		},
		files: map[string]string{
			"default-codex:" + machine.CaddyfilePath: "codex.default.acme {\n  reverse_proxy localhost:3000\n}\n",
		},
	}
	infraResource := &fakeTopologyResource{
		networks: map[string]*api.Network{},
		volumes:  map[string]*api.StorageVolume{},
		instances: map[string]*api.Instance{
			"sc-alice-myproject": {Name: "sc-alice-myproject", Status: "Stopped", StatusCode: api.Stopped},
			tenant.DNSName:       {Name: tenant.DNSName, Status: "Running", StatusCode: api.Running},
		},
		files: map[string]string{
			tenant.DNSName + ":/etc/coredns/Corefile":      ".:53 {\n  errors\n}\n",
			tenant.DNSName + ":/etc/coredns/zones/db.acme": "$ORIGIN acme.\n",
		},
	}
	store := TopologyStore{Server: fakeTopologyServer{resources: map[string]*fakeTopologyResource{
		"sc-alice-myproject":       mainResource,
		"sc-alice-myproject-infra": infraResource,
	}}}
	topology, err := store.GetTopology(context.Background(), tenant.TopologyRequest{
		IncusProject: "sc-alice-myproject",
		InfraProject: "sc-alice-myproject-infra",
		DNSSuffix:    "acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !topology.PrivateNetworkPresent {
		t.Fatal("private network should be present")
	}
	if !topology.DurableVolumes[tenant.HomeVolumeName] {
		t.Fatal("home volume should be present")
	}
	if topology.DurableVolumes[tenant.WorkspaceVolumeName] {
		t.Fatal("workspace volume should be missing")
	}
	if topology.Sidecars[topology.TailscaleInstance].Running {
		t.Fatal("tailscale sidecar should be stopped")
	}
	if !topology.Sidecars[tenant.DNSName].Running {
		t.Fatal("dns sidecar should be running")
	}
	if len(topology.DiagnosticFiles) != 3 {
		t.Fatalf("DiagnosticFiles = %#v, want CoreDNS files and machine Caddyfile", topology.DiagnosticFiles)
	}
	if topology.DiagnosticFiles[0].Path != "/etc/coredns/Corefile" || !strings.Contains(topology.DiagnosticFiles[0].Content, "errors") {
		t.Fatalf("Corefile diagnostic = %#v", topology.DiagnosticFiles[0])
	}
	if topology.DiagnosticFiles[1].Path != "/etc/coredns/zones/db.acme" || !strings.Contains(topology.DiagnosticFiles[1].Content, "$ORIGIN") {
		t.Fatalf("zone diagnostic = %#v", topology.DiagnosticFiles[1])
	}
	if topology.DiagnosticFiles[2].Instance != "default-codex" || topology.DiagnosticFiles[2].Path != machine.CaddyfilePath || !strings.Contains(topology.DiagnosticFiles[2].Content, "reverse_proxy") {
		t.Fatalf("machine Caddyfile diagnostic = %#v", topology.DiagnosticFiles[2])
	}
}
