package incusx

import (
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

// The payload-sync target set is metadata-scoped (ADR-0022): v2 app projects
// of the tenant only — never the tenant's infra project, never another
// tenant's app project, never an unmanaged project.
func TestIsV2AppProjectOfTenant(t *testing.T) {
	cases := []struct {
		name   string
		config map[string]string
		tenant string
		want   bool
	}{
		{
			name:   "app project of the tenant",
			config: map[string]string{meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "acme"},
			tenant: "acme",
			want:   true,
		},
		{
			name:   "app project of another tenant",
			config: map[string]string{meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "other"},
			tenant: "acme",
			want:   false,
		},
		{
			name:   "tenant infra project",
			config: map[string]string{meta.KeyKind: meta.KindInfra, meta.KeyTenant: "acme"},
			tenant: "acme",
			want:   false,
		},
		{
			name:   "unmanaged project",
			config: map[string]string{},
			tenant: "acme",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isV2AppProjectOfTenant(tc.config, tc.tenant); got != tc.want {
				t.Fatalf("isV2AppProjectOfTenant(%v, %q) = %v, want %v", tc.config, tc.tenant, got, tc.want)
			}
		})
	}
}
