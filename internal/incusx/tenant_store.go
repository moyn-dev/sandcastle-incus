package incusx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type TenantListServer interface {
	GetProjects() ([]api.Project, error)
}

type TenantMetadataServer interface {
	UseProject(name string) TenantMetadataResourceServer
}

type TenantMetadataResourceServer interface {
	GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error)
}

type TenantStore struct {
	Remote       string
	ConfigPath   string
	Server       TenantListServer
	Log          func(string)
	TenantFilter []string
}

func NewTenantStore(remote string) TenantStore {
	return TenantStore{Remote: remote}
}

func NewTenantStoreForServer(server incus.InstanceServer) TenantStore {
	return TenantStore{Server: server}
}

func NewTenantStoreForSharedRemote(remote *SharedRemote) TenantStore {
	return TenantStore{Server: sharedTenantListServer{remote: remote}, Log: remote.Log}
}

func (s TenantStore) WithTenantFilter(names ...string) tenant.IncusTenantStore {
	s.TenantFilter = append([]string{}, names...)
	return s
}

func (s TenantStore) WithVerbose(enabled bool, w io.Writer) TenantStore {
	if enabled {
		s.Log = func(msg string) { fmt.Fprint(w, msg) }
	}
	return s
}

func (s TenantStore) ListProjects(ctx context.Context) ([]tenant.IncusProject, error) {
	server := s.Server
	if server == nil {
		loadedServer, err := connectConfiguredRemote(s.Log, s.ConfigPath, s.Remote)
		if err != nil {
			return nil, err
		}
		server = loadedServer
	}
	if connector, ok := server.(interface{ ensureConnected() error }); ok {
		if err := connector.ensureConnected(); err != nil {
			return nil, err
		}
	}

	projects, err := logIncusAPICall(s.Log, "GetProjects", server.GetProjects)
	if err != nil {
		return nil, fmt.Errorf("list Incus projects: %w", err)
	}
	output := FromAPIProjects(projects)
	output = filterTenantProjects(output, s.TenantFilter)
	return output, nil
}

func filterTenantProjects(projects []tenant.IncusProject, tenantNames []string) []tenant.IncusProject {
	filter := map[string]struct{}{}
	for _, name := range tenantNames {
		name = strings.TrimSpace(name)
		if name != "" {
			filter[name] = struct{}{}
		}
	}
	if len(filter) == 0 {
		return projects
	}
	output := make([]tenant.IncusProject, 0, len(projects))
	for _, project := range projects {
		if !meta.IsManaged(project.Config) {
			continue
		}
		switch project.Config[meta.KeyKind] {
		case meta.KindV2Project, meta.KindInfra:
			// v2 tenants: the owning tenant is a plain config key. Dropping
			// these made every tenant-filtered lookup report a v2 tenant as
			// "not found" instead of reaching the caller's v2 handling.
			if _, ok := filter[strings.TrimSpace(project.Config[meta.KeyTenant])]; ok {
				output = append(output, project)
			}
		}
	}
	return output
}

func FromAPIProjects(projects []api.Project) []tenant.IncusProject {
	output := make([]tenant.IncusProject, 0, len(projects))
	for _, incusProject := range projects {
		output = append(output, tenant.IncusProject{
			Name:   incusProject.Name,
			Config: map[string]string(incusProject.Config),
		})
	}
	return output
}

const (
	tenantMetadataDir       = "/.sandcastle"
	tenantStorageSharesFile = tenantMetadataDir + "/storage_shares"
)

// readTenantStorageShares reads the tenant's shares from the workspace volume.
// The first argument of GetStorageVolumeFile is a POOL: passing the Incus project
// name there made Incus answer 404 ("Storage pool not found"), which
// isMissingTenantMetadata treats as "no metadata" — so every tenant silently had
// zero shares.
func readTenantStorageShares(server TenantMetadataResourceServer, pool string, incusProjectName string) ([]meta.TenantStorageShare, bool, error) {
	content, _, err := server.GetStorageVolumeFile(pool, "custom", tenant.V2WorkspaceVolumeName, tenantStorageSharesFile)
	if isMissingTenantMetadata(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read tenant storage shares metadata for %s: %w", incusProjectName, err)
	}
	defer content.Close()
	data, err := io.ReadAll(content)
	if err != nil {
		return nil, false, fmt.Errorf("read tenant storage shares metadata for %s: %w", incusProjectName, err)
	}
	var shares []meta.TenantStorageShare
	if err := json.Unmarshal(data, &shares); err != nil {
		return nil, false, fmt.Errorf("parse tenant storage shares metadata for %s: %w", incusProjectName, err)
	}
	return shares, true, nil
}

func isMissingTenantMetadata(err error) bool {
	return api.StatusErrorCheck(err, http.StatusNotFound) ||
		errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, os.ErrPermission)
}

type sdkTenantMetadataServer struct {
	inner incus.InstanceServer
	Log   func(string)
}

func (s sdkTenantMetadataServer) UseProject(name string) TenantMetadataResourceServer {
	return sdkTenantMetadataResourceServer{inner: s.inner.UseProject(name), projectName: name, Log: s.Log}
}

type sdkTenantMetadataResourceServer struct {
	inner       incus.InstanceServer
	projectName string
	Log         func(string)
}

func (s sdkTenantMetadataResourceServer) GetStorageVolumeFile(pool string, volumeType string, volumeName string, filePath string) (io.ReadCloser, *incus.InstanceFileResponse, error) {
	label := "GetStorageVolumeFile project=" + s.projectName + " pool=" + pool + " volume=" + volumeName + " path=" + filePath
	if s.Log == nil {
		return getStorageVolumeFile(s.inner, s.projectName, pool, volumeType, volumeName, filePath)
	}
	start := time.Now()
	content, response, err := getStorageVolumeFile(s.inner, s.projectName, pool, volumeType, volumeName, filePath)
	switch {
	case err == nil:
		s.Log(fmt.Sprintf("[verbose] incus api: %s done (%s)\n", label, formatVerboseDuration(time.Since(start))))
	case isMissingTenantMetadata(err):
		s.Log(fmt.Sprintf("[verbose] incus api: %s missing (%s)\n", label, formatVerboseDuration(time.Since(start))))
	default:
		s.Log(fmt.Sprintf("[verbose] incus api: %s failed (%s)\n", label, formatVerboseDuration(time.Since(start))))
	}
	return content, response, err
}
