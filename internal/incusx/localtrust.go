package incusx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/localtrust"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type LocalTrustServer interface {
	UseProject(name string) LocalTrustTenantResourceServer
}

type LocalTrustTenantResourceServer interface {
	GetInstanceFile(instanceName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error)
	GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error)
	CreateStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string, args incus.InstanceFileArgs) error
}

type LocalTrustManager struct {
	Remote     string
	ConfigPath string
	Server     LocalTrustServer
	Store      localtrust.Store
}

func NewLocalTrustManager(remote string, store localtrust.Store) LocalTrustManager {
	return LocalTrustManager{Remote: remote, Store: store}
}

func (m LocalTrustManager) Install(ctx context.Context, plan localtrust.Plan) (localtrust.Result, error) {
	material, err := m.prepareCA(ctx, plan)
	if err != nil {
		return localtrust.Result{}, err
	}
	store := m.Store
	if store == nil {
		store = localtrust.NewPlatformStore()
	}
	result, err := store.InstallCA(ctx, plan, material.certPEM)
	if err != nil {
		return localtrust.Result{}, err
	}
	if shouldCacheTenantCA(plan) && len(material.privateKeyPEM) > 0 {
		if err := writePersistentTenantCA(m.Remote, plan, material); err != nil {
			return localtrust.Result{}, err
		}
	}
	return result, nil
}

func (m LocalTrustManager) Uninstall(ctx context.Context, plan localtrust.Plan) (localtrust.Result, error) {
	store := m.Store
	if store == nil {
		store = localtrust.NewPlatformStore()
	}
	return store.UninstallCA(ctx, plan)
}

type tenantCAMaterial struct {
	certPEM       []byte
	privateKeyPEM []byte
}

func (m LocalTrustManager) prepareCA(ctx context.Context, plan localtrust.Plan) (tenantCAMaterial, error) {
	if shouldCacheTenantCA(plan) {
		cached, ok, err := loadPersistentTenantCA(m.Remote, plan)
		if err != nil {
			return tenantCAMaterial{}, err
		}
		if ok {
			// Read the live cert from Incus to detect tenant recreation (new CA key pair).
			liveCertPEM, readErr := m.readCA(plan)
			if readErr == nil && !bytes.Equal(liveCertPEM, cached.certPEM) {
				// Tenant was recreated — the cached cert is stale. Use the fresh cert
				// from Incus. The private key is optional: a restricted user cert may not
				// have read access to the CA key. Without the key, trust install still
				// works; only the re-provisioning write-back is skipped.
				keyPEM, _ := m.readTenantCAKey(plan)
				return tenantCAMaterial{certPEM: liveCertPEM, privateKeyPEM: keyPEM}, nil
			}
			// Either the Incus volume is missing/empty (re-provisioning) or the cert
			// matches the cache. Propagate the cached CA back to the volume and use it.
			if err := m.writeTenantCA(plan, cached); err != nil {
				return tenantCAMaterial{}, err
			}
			return cached, nil
		}
	}
	certPEM, err := m.readCA(plan)
	if err != nil {
		return tenantCAMaterial{}, err
	}
	material := tenantCAMaterial{certPEM: certPEM}
	if shouldCacheTenantCA(plan) {
		keyPEM, err := m.readTenantCAKey(plan)
		if err != nil {
			return tenantCAMaterial{}, err
		}
		material.privateKeyPEM = keyPEM
	}
	return material, nil
}

func (m LocalTrustManager) readCA(plan localtrust.Plan) ([]byte, error) {
	server := m.Server
	if server == nil {
		loaded, err := LoadCLIConfig(m.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("load Incus config: %w", err)
		}
		remote := m.Remote
		if remote == "" {
			remote = loaded.DefaultRemote
		}
		instanceServer, err := connectInstanceServer(loaded, remote)
		if err != nil {
			return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
		}
		server = sdkLocalTrustServer{inner: instanceServer}
	}
	projectServer := server.UseProject(plan.IncusProject)
	if plan.Instance != "" {
		content, _, err := projectServer.GetInstanceFile(plan.Instance, plan.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf("read instance CA certificate: %w", err)
		}
		defer content.Close()
		return io.ReadAll(content)
	}
	content, _, err := projectServer.GetStorageVolumeFile(plan.StoragePool, "custom", plan.CAVolume, plan.CertificatePath)
	if err != nil {
		return nil, fmt.Errorf("read tenant CA certificate: %w", err)
	}
	defer content.Close()
	return io.ReadAll(content)
}

func (m LocalTrustManager) readTenantCAKey(plan localtrust.Plan) ([]byte, error) {
	content, err := m.readStorageVolumeFile(plan, tenant.TenantCAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read tenant CA private key: %w", err)
	}
	defer content.Close()
	return io.ReadAll(content)
}

func (m LocalTrustManager) writeTenantCA(plan localtrust.Plan, material tenantCAMaterial) error {
	server, err := m.localTrustServer()
	if err != nil {
		return err
	}
	projectServer := server.UseProject(plan.IncusProject)
	if err := projectServer.CreateStorageVolumeFile(plan.StoragePool, "custom", plan.CAVolume, tenant.TenantCACertPath, incus.InstanceFileArgs{
		Content:   strings.NewReader(string(material.certPEM)),
		Type:      "file",
		Mode:      0o644,
		WriteMode: "overwrite",
	}); err != nil {
		return fmt.Errorf("restore cached tenant CA certificate: %w", err)
	}
	if err := projectServer.CreateStorageVolumeFile(plan.StoragePool, "custom", plan.CAVolume, tenant.TenantCAKeyPath, incus.InstanceFileArgs{
		Content:   strings.NewReader(string(material.privateKeyPEM)),
		Type:      "file",
		Mode:      0o600,
		WriteMode: "overwrite",
	}); err != nil {
		return fmt.Errorf("restore cached tenant CA private key: %w", err)
	}
	return nil
}

func (m LocalTrustManager) readStorageVolumeFile(plan localtrust.Plan, filePath string) (io.ReadCloser, error) {
	server, err := m.localTrustServer()
	if err != nil {
		return nil, err
	}
	content, _, err := server.UseProject(plan.IncusProject).GetStorageVolumeFile(plan.StoragePool, "custom", plan.CAVolume, filePath)
	return content, err
}

func (m LocalTrustManager) localTrustServer() (LocalTrustServer, error) {
	if m.Server != nil {
		return m.Server, nil
	}
	loaded, err := LoadCLIConfig(m.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := m.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	instanceServer, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return sdkLocalTrustServer{inner: instanceServer}, nil
}

// InvalidateTenantCA removes the locally cached CA material for the given Incus project,
// forcing a fresh read from Incus on the next trust install.
func InvalidateTenantCA(remote, incusProject string) {
	plan := localtrust.Plan{IncusProject: incusProject}
	dir := persistentTenantCADir(remote, plan)
	_ = os.Remove(filepath.Join(dir, "ca.crt"))
	_ = os.Remove(filepath.Join(dir, "ca.key"))
}

func shouldCacheTenantCA(plan localtrust.Plan) bool {
	return plan.Instance == "" &&
		strings.TrimSpace(plan.IncusProject) != "" &&
		strings.TrimSpace(plan.StoragePool) != "" &&
		strings.TrimSpace(plan.CAVolume) != "" &&
		plan.CertificatePath == tenant.TenantCACertPath
}

func loadPersistentTenantCA(remote string, plan localtrust.Plan) (tenantCAMaterial, bool, error) {
	dir := persistentTenantCADir(remote, plan)
	certPEM, certErr := os.ReadFile(filepath.Join(dir, "ca.crt"))
	keyPEM, keyErr := os.ReadFile(filepath.Join(dir, "ca.key"))
	if os.IsNotExist(certErr) || os.IsNotExist(keyErr) {
		return tenantCAMaterial{}, false, nil
	}
	if certErr != nil {
		return tenantCAMaterial{}, false, fmt.Errorf("read cached tenant CA certificate: %w", certErr)
	}
	if keyErr != nil {
		return tenantCAMaterial{}, false, fmt.Errorf("read cached tenant CA private key: %w", keyErr)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return tenantCAMaterial{}, false, fmt.Errorf("cached tenant CA material is incomplete")
	}
	return tenantCAMaterial{certPEM: certPEM, privateKeyPEM: keyPEM}, true, nil
}

func writePersistentTenantCA(remote string, plan localtrust.Plan, material tenantCAMaterial) error {
	dir := persistentTenantCADir(remote, plan)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create tenant CA cache: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), material.certPEM, 0o644); err != nil {
		return fmt.Errorf("write cached tenant CA certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), material.privateKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write cached tenant CA private key: %w", err)
	}
	return nil
}

func persistentTenantCADir(remote string, plan localtrust.Plan) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		remote = "default"
	}
	return filepath.Join(scconfig.DefaultConfigDir(), "tenant-ca", pathSafe(remote), pathSafe(plan.IncusProject))
}

func pathSafe(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "_"
	}
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(value)
}

type sdkLocalTrustServer struct {
	inner incus.InstanceServer
}

func (s sdkLocalTrustServer) UseProject(name string) LocalTrustTenantResourceServer {
	return sdkLocalTrustTenantResourceServer{inner: s.inner.UseProject(name), projectName: name}
}

type sdkLocalTrustTenantResourceServer struct {
	inner       incus.InstanceServer
	projectName string
}

func (s sdkLocalTrustTenantResourceServer) GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	return getStorageVolumeFile(s.inner, s.projectName, pool, volumeType, volumeName, filePath)
}

func (s sdkLocalTrustTenantResourceServer) CreateStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string, args incus.InstanceFileArgs) error {
	return createStorageVolumeFile(s.inner, s.projectName, pool, volumeType, volumeName, filePath, args)
}

func (s sdkLocalTrustTenantResourceServer) GetInstanceFile(instanceName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	return s.inner.GetInstanceFile(instanceName, filePath)
}
