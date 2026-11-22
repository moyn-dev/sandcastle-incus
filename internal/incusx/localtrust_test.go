package incusx

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/moyn-dev/sandcastle-incus/internal/localtrust"
)

type fakeLocalTrustServer struct {
	project *fakeLocalTrustTenantResourceServer
}

func (s *fakeLocalTrustServer) UseProject(name string) LocalTrustTenantResourceServer {
	s.project.project = name
	return s.project
}

type fakeLocalTrustTenantResourceServer struct {
	project string
	files   map[string]string
}

func (s *fakeLocalTrustTenantResourceServer) GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	key := volumeName + ":" + filePath
	content, ok := s.files[key]
	if !ok {
		return nil, nil, fmt.Errorf("file not found: %s", key)
	}
	return io.NopCloser(strings.NewReader(content)), nil, nil
}

func (s *fakeLocalTrustTenantResourceServer) CreateStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string, args incus.InstanceFileArgs) error {
	content, _ := io.ReadAll(args.Content)
	s.files[volumeName+":"+filePath] = string(content)
	return nil
}

func (s *fakeLocalTrustTenantResourceServer) GetInstanceFile(instanceName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	return io.NopCloser(strings.NewReader(s.files[instanceName+":"+filePath])), nil, nil
}

type fakeLocalTrustStore struct {
	installed bool
	removed   bool
	certPEM   string
}

func TestLocalTrustManagerReadsInstanceCAForInstall(t *testing.T) {
	projectServer := &fakeLocalTrustTenantResourceServer{files: map[string]string{"sc-caddy:/root.crt": "INFRA CERT"}}
	store := &fakeLocalTrustStore{}
	manager := LocalTrustManager{
		Server: &fakeLocalTrustServer{project: projectServer},
		Store:  store,
	}
	result, err := manager.Install(context.Background(), localtrust.Plan{
		Reference:       "infrastructure",
		IncusProject:    "sc-infra",
		Instance:        "sc-caddy",
		CertificatePath: "/root.crt",
		TrustName:       "Sandcastle infrastructure debug CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "install" {
		t.Fatalf("Action = %q", result.Action)
	}
	if projectServer.project != "sc-infra" {
		t.Fatalf("project = %q", projectServer.project)
	}
	if store.certPEM != "INFRA CERT" {
		t.Fatalf("certPEM = %q", store.certPEM)
	}
}

func (s *fakeLocalTrustStore) InstallCA(ctx context.Context, plan localtrust.Plan, certPEM []byte) (localtrust.Result, error) {
	s.installed = true
	s.certPEM = string(certPEM)
	return localtrust.Result{Reference: plan.Reference, TrustName: plan.TrustName, Action: "install", Platform: "fake"}, nil
}

func (s *fakeLocalTrustStore) UninstallCA(ctx context.Context, plan localtrust.Plan) (localtrust.Result, error) {
	s.removed = true
	return localtrust.Result{Reference: plan.Reference, TrustName: plan.TrustName, Action: "uninstall", Platform: "fake"}, nil
}

func TestLocalTrustManagerReadsProjectCAForInstall(t *testing.T) {
	projectServer := &fakeLocalTrustTenantResourceServer{files: map[string]string{"sc-ca:/ca.crt": "CERT", "sc-ca:/ca.key": "KEY"}}
	store := &fakeLocalTrustStore{}
	t.Setenv("HOME", t.TempDir())
	manager := LocalTrustManager{
		Remote: "sandcastle-alice",
		Server: &fakeLocalTrustServer{project: projectServer},
		Store:  store,
	}
	result, err := manager.Install(context.Background(), localtrust.Plan{
		Reference:       "alice/myproject",
		IncusProject:    "sc-alice-myproject",
		StoragePool:     "default",
		CAVolume:        "sc-ca",
		CertificatePath: "/ca.crt",
		TrustName:       "Sandcastle alice/myproject tenant CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "install" {
		t.Fatalf("Action = %q", result.Action)
	}
	if projectServer.project != "sc-alice-myproject" {
		t.Fatalf("project = %q", projectServer.project)
	}
	if store.certPEM != "CERT" {
		t.Fatalf("certPEM = %q", store.certPEM)
	}
	cachedKey, err := io.ReadAll(mustOpen(t, filepath.Join(persistentTenantCADir("sandcastle-alice", localtrust.Plan{
		IncusProject:    "sc-alice-myproject",
		StoragePool:     "default",
		CAVolume:        "sc-ca",
		CertificatePath: "/ca.crt",
	}), "ca.key")))
	if err != nil {
		t.Fatal(err)
	}
	if string(cachedKey) != "KEY" {
		t.Fatalf("cached key = %q", cachedKey)
	}
}

// TestLocalTrustManagerRestoresCachedProjectCAForInstall verifies the re-provisioning path:
// when the Incus volume is missing/empty (readCA fails) and a local cache exists, the cached
// CA is written back to the volume and used for trust installation.
func TestLocalTrustManagerRestoresCachedProjectCAForInstall(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	plan := localtrust.Plan{
		Reference:       "alice/myproject",
		IncusProject:    "sc-alice-myproject",
		StoragePool:     "default",
		CAVolume:        "sc-ca",
		CertificatePath: "/ca.crt",
		TrustName:       "Sandcastle alice/myproject tenant CA",
	}
	if err := writePersistentTenantCA("sandcastle-alice", plan, tenantCAMaterial{
		certPEM:       []byte("CACHED CERT"),
		privateKeyPEM: []byte("CACHED KEY"),
	}); err != nil {
		t.Fatal(err)
	}
	// Incus volume is empty — readCA will fail (re-provisioning case).
	projectServer := &fakeLocalTrustTenantResourceServer{files: map[string]string{"sc-ca:/ca.key": "CACHED KEY"}}
	store := &fakeLocalTrustStore{}
	manager := LocalTrustManager{
		Remote: "sandcastle-alice",
		Server: &fakeLocalTrustServer{project: projectServer},
		Store:  store,
	}
	_, err := manager.Install(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if store.certPEM != "CACHED CERT" {
		t.Fatalf("certPEM = %q", store.certPEM)
	}
	if got := projectServer.files["sc-ca:/ca.crt"]; got != "CACHED CERT" {
		t.Fatalf("restored cert = %q", got)
	}
}

// TestLocalTrustManagerUsesFreshCertAfterTenantRecreation verifies that when a tenant is
// recreated (Incus returns a different CA cert than the local cache), the fresh cert from
// Incus wins so the new CA is installed in the trust store.
func TestLocalTrustManagerUsesFreshCertAfterTenantRecreation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	plan := localtrust.Plan{
		Reference:       "alice/myproject",
		IncusProject:    "sc-alice-myproject",
		StoragePool:     "default",
		CAVolume:        "sc-ca",
		CertificatePath: "/ca.crt",
		TrustName:       "Sandcastle alice/myproject tenant CA",
	}
	if err := writePersistentTenantCA("sandcastle-alice", plan, tenantCAMaterial{
		certPEM:       []byte("OLD CERT"),
		privateKeyPEM: []byte("OLD KEY"),
	}); err != nil {
		t.Fatal(err)
	}
	// Incus has a new cert (tenant was recreated).
	projectServer := &fakeLocalTrustTenantResourceServer{files: map[string]string{
		"sc-ca:/ca.crt": "NEW CERT",
		"sc-ca:/ca.key": "NEW KEY",
	}}
	store := &fakeLocalTrustStore{}
	manager := LocalTrustManager{
		Remote: "sandcastle-alice",
		Server: &fakeLocalTrustServer{project: projectServer},
		Store:  store,
	}
	_, err := manager.Install(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if store.certPEM != "NEW CERT" {
		t.Fatalf("certPEM = %q, want NEW CERT", store.certPEM)
	}
}

func TestLocalTrustManagerUninstallSkipsIncusRead(t *testing.T) {
	store := &fakeLocalTrustStore{}
	manager := LocalTrustManager{Store: store}
	result, err := manager.Uninstall(context.Background(), localtrust.Plan{
		Reference: "alice/myproject",
		TrustName: "Sandcastle alice/myproject tenant CA",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "uninstall" {
		t.Fatalf("Action = %q", result.Action)
	}
	if !store.removed {
		t.Fatal("expected store uninstall call")
	}
}

func mustOpen(t *testing.T, path string) io.ReadCloser {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return file
}
