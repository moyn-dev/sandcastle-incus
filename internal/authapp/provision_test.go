package authapp

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

func TestProfileUnixUser(t *testing.T) {
	tests := []struct {
		name          string
		localUnixUser string
		defaultUser   string
		want          string
	}{
		{"client user wins", "thies", "ops", "thies"},
		{"falls back to deployment default", "", "ops", "ops"},
		{"falls back to dev", "", "", "dev"},
		{"root is refused", "root", "", "dev"},
		{"root falls through to default", "root", "ops", "ops"},
		{"invalid name falls through", "Bad Name!", "ops", "ops"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Provisioner{DefaultUnixUser: tt.defaultUser}
			got := p.profileUnixUser(User{LocalUnixUser: tt.localUnixUser})
			if got != tt.want {
				t.Fatalf("profileUnixUser = %q, want %q", got, tt.want)
			}
		})
	}
}

// A login mints (or extends) the device's certificate; it must cover every
// Shared Tenant the user is already a member of, not only the Personal
// Tenant — otherwise a device enrolled after the grant cannot reach the
// shared projects through Incus.
func TestMemberTenantProjectsCoverSharedTenants(t *testing.T) {
	project := func(name, kind, tenantName string, extra map[string]string) tenant.IncusProject {
		cfg := map[string]string{meta.KeyKind: kind, meta.KeyTenant: tenantName, meta.KeyVersion: "2", meta.KeyV2Prefix: "sh"}
		for k, v := range extra {
			cfg[k] = v
		}
		return tenant.IncusProject{Name: name, Config: cfg}
	}
	store := tenant.MemoryStore{Projects: []tenant.IncusProject{
		project("sh-thieso2", meta.KindInfra, "thieso2", nil),
		project("sh-thieso2-default", meta.KindV2Project, "thieso2", nil),
		project("sh-moyn-dev", meta.KindInfra, "moyn-dev", map[string]string{meta.KeyV2Members: "skorfmann,thieso2"}),
		project("sh-moyn-dev-default", meta.KindV2Project, "moyn-dev", nil),
		project("sh-moyn-dev-api", meta.KindV2Project, "moyn-dev", nil),
		project("sh-other", meta.KindInfra, "other", map[string]string{meta.KeyV2Members: "skorfmann"}),
		project("sh-other-default", meta.KindV2Project, "other", nil),
	}}
	p := Provisioner{Tenants: store, Admin: config.Admin{IncusProjectPrefix: "sh"}}
	got := p.memberTenantProjects(context.Background(), "Thieso2")
	sort.Strings(got)
	want := []string{"sh-moyn-dev", "sh-moyn-dev-api", "sh-moyn-dev-default"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("member projects = %v, want %v", got, want)
	}
	if got := p.memberTenantProjects(context.Background(), "nobody"); len(got) != 0 {
		t.Fatalf("non-member got %v", got)
	}
}
