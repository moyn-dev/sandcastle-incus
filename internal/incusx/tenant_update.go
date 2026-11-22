package incusx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/share"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type TenantSSHKeyManager struct {
	Remote     string
	ConfigPath string
	Server     TenantMetadataUpdateServer
	// StoragePool is the Incus storage pool holding the tenant's shared volumes.
	// Empty means the deployment default.
	StoragePool string
}

// pool is the storage pool the tenant's shared home/workspace volumes live in.
// The Incus storage-volume file API takes a POOL as its first argument; passing
// the Incus project name there (as this file used to) fails at runtime with
// "Storage pool not found" — but never in tests, whose fake accepts any string.
func (m TenantSSHKeyManager) pool() string {
	if p := strings.TrimSpace(m.StoragePool); p != "" {
		return p
	}
	return config.DefaultStoragePool
}

func NewTenantSSHKeyManager(remote string) TenantSSHKeyManager {
	return TenantSSHKeyManager{Remote: remote}
}

// NewTenantSSHKeyManagerWithPool pins the storage pool holding the tenant's
// shared volumes, rather than relying on the deployment default.
func NewTenantSSHKeyManagerWithPool(remote string, storagePool string) TenantSSHKeyManager {
	return TenantSSHKeyManager{Remote: remote, StoragePool: storagePool}
}

func NewTenantSSHKeyManagerForServer(server incus.InstanceServer) TenantSSHKeyManager {
	return TenantSSHKeyManager{Server: sdkTenantMetadataUpdateServer{inner: server}}
}

type TenantMetadataUpdateServer interface {
	UseProject(name string) TenantMetadataUpdateResourceServer
}

type TenantMetadataUpdateResourceServer interface {
	GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error)
	CreateStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string, args incus.InstanceFileArgs) error
}

func (m TenantSSHKeyManager) GetTenantShares(_ context.Context, incusProjectName string) ([]meta.TenantStorageShare, error) {
	server, err := m.server()
	if err != nil {
		return nil, err
	}
	shares, ok, err := readTenantStorageShares(server.UseProject(incusProjectName), m.pool(), incusProjectName)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return shares, nil
}

func (m TenantSSHKeyManager) SetTenantShares(_ context.Context, incusProjectName string, shares []meta.TenantStorageShare) error {
	data, err := json.Marshal(shares)
	if err != nil {
		return fmt.Errorf("encode storage shares for %s: %w", incusProjectName, err)
	}
	return m.writeTenantMetadataFile(incusProjectName, tenantStorageSharesFile, string(data), "write tenant storage shares metadata")
}

func (m TenantSSHKeyManager) SourceDirectoryExists(ctx context.Context, incusProjectName string, workspaceRelativeDir string) (bool, error) {
	status, err := m.SourceDirectoryStatus(ctx, incusProjectName, workspaceRelativeDir)
	if err != nil {
		return false, err
	}
	return status.Exists && status.Safe, nil
}

// SourceDirectoryStatus inspects a directory inside the source project's own
// workspace volume. incusProjectName is the source app Incus project; the path
// is relative to that project's /workspace volume root (each v2 project has its
// own volume), so it carries no project segment — the v1 layout packed every
// project into one volume under a per-project subdirectory.
func (m TenantSSHKeyManager) SourceDirectoryStatus(_ context.Context, incusProjectName string, workspaceRelativeDir string) (share.SourceStatus, error) {
	server, err := m.server()
	if err != nil {
		return share.SourceStatus{}, err
	}
	resource := server.UseProject(incusProjectName)
	sourcePath := path.Clean(workspaceRelativeDir)
	status, err := validateStorageTree(resource, m.pool(), tenant.V2WorkspaceVolumeName, sourcePath, sourcePath)
	if isMissingTenantMetadata(err) {
		return share.SourceStatus{Exists: false, Safe: false, Reason: "source directory is missing"}, nil
	}
	if err != nil {
		return share.SourceStatus{}, fmt.Errorf("check source directory %s for %s: %w", sourcePath, incusProjectName, err)
	}
	return status, nil
}

func validateStorageTree(resource TenantMetadataUpdateResourceServer, pool string, volumeName string, rootPath string, filePath string) (share.SourceStatus, error) {
	content, response, err := resource.GetStorageVolumeFile(pool, "custom", volumeName, filePath)
	if isMissingTenantMetadata(err) {
		return share.SourceStatus{Exists: false, Safe: false, Reason: "source directory is missing"}, nil
	}
	if err != nil {
		return share.SourceStatus{}, err
	}
	defer closeReader(content)
	if response == nil {
		return share.SourceStatus{Exists: true, Safe: false, Reason: "missing file metadata"}, nil
	}
	switch response.Type {
	case "directory":
		for _, entry := range response.Entries {
			if strings.Contains(entry, "/") || entry == "." || entry == ".." {
				return share.SourceStatus{Exists: true, Safe: false, Reason: "directory entry escapes source path"}, nil
			}
			childStatus, err := validateStorageTree(resource, pool, volumeName, rootPath, path.Join(filePath, entry))
			if err != nil {
				return share.SourceStatus{}, err
			}
			if !childStatus.Exists || !childStatus.Safe {
				return childStatus, nil
			}
		}
		return share.SourceStatus{Exists: true, Safe: true}, nil
	case "symlink":
		if content == nil {
			return share.SourceStatus{Exists: true, Safe: false, Reason: "symlink target is unavailable"}, nil
		}
		targetBytes, _ := io.ReadAll(content)
		if !symlinkTargetStaysWithin(rootPath, filePath, strings.TrimSpace(string(targetBytes))) {
			return share.SourceStatus{Exists: true, Safe: false, Reason: "symlink escapes source directory"}, nil
		}
		return share.SourceStatus{Exists: true, Safe: true}, nil
	case "file":
		if filePath == rootPath {
			return share.SourceStatus{Exists: true, Safe: false, Reason: "source path is not a directory"}, nil
		}
		return share.SourceStatus{Exists: true, Safe: true}, nil
	default:
		return share.SourceStatus{Exists: true, Safe: false, Reason: "unsupported source entry type " + response.Type}, nil
	}
}

func symlinkTargetStaysWithin(rootPath string, linkPath string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || path.IsAbs(target) {
		return false
	}
	linkDir := path.Dir(linkPath)
	resolved := path.Clean(path.Join(linkDir, target))
	root := path.Clean(rootPath)
	return resolved == root || strings.HasPrefix(resolved, root+"/")
}

func closeReader(reader io.ReadCloser) {
	if reader != nil {
		_ = reader.Close()
	}
}

func (m TenantSSHKeyManager) writeTenantMetadataFile(incusProjectName string, filePath string, content string, action string) error {
	server, err := m.server()
	if err != nil {
		return err
	}
	tenantServer := server.UseProject(incusProjectName)
	if err := tenantServer.CreateStorageVolumeFile(m.pool(), "custom", tenant.V2WorkspaceVolumeName, tenantMetadataDir, incus.InstanceFileArgs{
		Type: "directory",
		Mode: 0o755,
	}); err != nil && !api.StatusErrorCheck(err, 409) {
		return fmt.Errorf("create tenant metadata directory: %w", err)
	}
	if err := tenantServer.CreateStorageVolumeFile(m.pool(), "custom", tenant.V2WorkspaceVolumeName, filePath, incus.InstanceFileArgs{
		Content:   strings.NewReader(content),
		Type:      "file",
		Mode:      0o644,
		WriteMode: "overwrite",
	}); err != nil {
		return fmt.Errorf("%s for %s: %w", action, incusProjectName, err)
	}
	return nil
}

func (m TenantSSHKeyManager) server() (TenantMetadataUpdateServer, error) {
	server := m.Server
	if server != nil {
		return server, nil
	}
	loaded, err := LoadCLIConfig(m.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := m.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	loadedServer, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return sdkTenantMetadataUpdateServer{inner: loadedServer}, nil
}

type sdkTenantMetadataUpdateServer struct {
	inner incus.InstanceServer
}

func (s sdkTenantMetadataUpdateServer) UseProject(name string) TenantMetadataUpdateResourceServer {
	return sdkTenantMetadataUpdateResourceServer{inner: s.inner.UseProject(name), projectName: name}
}

type sdkTenantMetadataUpdateResourceServer struct {
	inner       incus.InstanceServer
	projectName string
}

func (s sdkTenantMetadataUpdateResourceServer) GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	return getStorageVolumeFile(s.inner, s.projectName, pool, volumeType, volumeName, filePath)
}

func (s sdkTenantMetadataUpdateResourceServer) CreateStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string, args incus.InstanceFileArgs) error {
	return createStorageVolumeFile(s.inner, s.projectName, pool, volumeType, volumeName, filePath, args)
}
