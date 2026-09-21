package cli

import (
	"context"
	"os"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// cachedTenantStore is the user CLI's tenant store: it answers ListProjects
// from the Auth App's event-fed resource cache (one HTTPS request) and falls
// back to the live Incus listing (GET /1.0/projects, >1 s on a loaded host)
// on any non-answer — exactly `sc ls`'s cache fallback. Every command that
// starts by building the tenant summary rides it. SANDCASTLE_CONNECT_CACHE=0
// (the client-side cache kill switch) disables it.
type cachedTenantStore struct {
	live   tenant.IncusTenantStore
	client authResourceClient
	tenant string
	log    func(format string, args ...any)
}

var _ tenant.IncusTenantStore = cachedTenantStore{}

// newCachedTenantStore wraps live when the CLI is logged in; otherwise live
// is returned unchanged.
func newCachedTenantStore(config commandConfig, live tenant.IncusTenantStore) tenant.IncusTenantStore {
	if !connectCacheEnabled(os.Getenv(connectCacheEnv)) {
		return live
	}
	client := config.authResources
	tenantName := strings.TrimSpace(config.adminConfig.Tenant)
	if client == nil {
		token := strings.TrimSpace(config.adminConfig.AuthToken)
		baseURL := commandAuthHostname(config, "")
		if token == "" || baseURL == "" || tenantName == "" {
			return live
		}
		client = authapp.DeviceClient{BaseURL: baseURL, AuthToken: token, Tenant: tenantName}
	}
	return cachedTenantStore{live: live, client: client, tenant: tenantName, log: func(format string, args ...any) { verboseCLI(config, format, args...) }}
}

func (s cachedTenantStore) ListProjects(ctx context.Context) ([]tenant.IncusProject, error) {
	cacheCtx, cancel := context.WithTimeout(ctx, resourceCacheRequestTimeout())
	defer cancel()
	result, err := s.client.ListResources(cacheCtx, authapp.ResourceListRequest{Tenant: s.tenant, Include: []string{authapp.ResourceKindProjects}})
	if err == nil && len(result.Projects) > 0 {
		return result.Projects, nil
	}
	if err != nil {
		s.log("tenant store: cache unavailable (%v); listing projects live", err)
	} else {
		s.log("tenant store: cache has no projects for %s; listing live", s.tenant)
	}
	return s.live.ListProjects(ctx)
}
