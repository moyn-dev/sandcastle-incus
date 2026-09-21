package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

func TestCachedTenantStoreServesProjectsFromTheCacheAndFallsBackLive(t *testing.T) {
	live := tenant.MemoryStore{Projects: v2TenantProjects("acme", "10.248.0.0/24", "default")}
	cached := &fakeResourceClient{result: authapp.ResourceListResult{Projects: []tenant.IncusProject{
		{Name: "sc2-acme", Config: map[string]string{meta.KeyKind: meta.KindInfra, meta.KeyTenant: "acme", meta.KeyVersion: "2", meta.KeyV2CIDR: "10.248.0.0/24"}},
		{Name: "sc2-acme-default", Config: map[string]string{meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "acme", meta.KeyVersion: "2"}},
		{Name: "sc2-acme-cachedonly", Config: map[string]string{meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "acme", meta.KeyVersion: "2"}},
	}}}
	admin := testAdminConfig()
	admin.Tenant, admin.AuthHostname, admin.AuthToken = "acme", "https://auth.example.com", "tok"
	store := newCachedTenantStore(commandConfig{adminConfig: admin, authResources: cached}, live)
	projects, err := store.ListProjects(context.Background())
	if err != nil || len(projects) != 3 || cached.calls != 1 {
		t.Fatalf("cache path: %d projects, calls=%d, %v", len(projects), cached.calls, err)
	}
	// Any non-answer falls back to the live store.
	failing := &fakeResourceClient{err: errors.New("503")}
	store = newCachedTenantStore(commandConfig{adminConfig: admin, authResources: failing}, live)
	projects, err = store.ListProjects(context.Background())
	if err != nil || len(projects) != 2 {
		t.Fatalf("fallback: %d projects, %v", len(projects), err)
	}
	// Not logged in (no token): the live store is used unchanged.
	admin.AuthToken = ""
	if _, ok := newCachedTenantStore(commandConfig{adminConfig: admin}, live).(cachedTenantStore); ok {
		t.Fatal("cache wrapper installed without a login")
	}
}
