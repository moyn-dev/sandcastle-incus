package authapp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// Regression for #55: a v2 personal tenant has no v1 tenant-user metadata for
// ListTenantUsers to read, so its own owner was refused — `sc status` showed
// "shares:reconcile: error (user … is not granted access to tenant …)" and the
// auth-app logged POST /api/shares/reconcile status=403 on a healthy tenant.
func TestRequireTenantAccessAllowsTheOwnerOfAV2Tenant(t *testing.T) {
	v2Config := func(kind string) map[string]string {
		return map[string]string{
			meta.KeyKind:    kind,
			meta.KeyTenant:  "alice",
			meta.KeyVersion: "2",
		}
	}
	h := handler{
		admin: testAuthAdminConfig(),
		tenants: tenant.MemoryStore{Projects: []tenant.IncusProject{
			{Name: "sc2-alice", Config: v2Config(meta.KindInfra)},
			{Name: "sc2-alice-default", Config: v2Config(meta.KindV2Project)},
		}},
		// deliberately empty: a v2 tenant has no v1 tenant-user entries at all
		tenantAccess: &fakeTenantAccessManager{usersByTenant: map[string][]string{}},
	}
	request := httptest.NewRequest(http.MethodPost, "/api/shares/reconcile", nil)

	if err := h.requireTenantAccess(request, "alice", "alice"); err != nil {
		t.Fatalf("the owner of a v2 tenant must be granted access: %v", err)
	}
	// ...and nobody else is
	err := h.requireTenantAccess(request, "mallory", "alice")
	if err == nil {
		t.Fatal("expected a non-owner to be refused a v2 tenant")
	}
	if !strings.Contains(err.Error(), "not granted access") {
		t.Fatalf("error = %v", err)
	}
}
