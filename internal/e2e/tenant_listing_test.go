package e2e

import (
	"context"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestTenantListingSmoke(t *testing.T) {
	config := LoadConfig()
	if !config.Enabled {
		t.Skip("set SANDCASTLE_E2E=1 to run real Incus e2e tests")
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}

	store := incusx.NewTenantStore(config.Remote)
	projects, err := tenant.List(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if projects == nil {
		t.Fatal("projects is nil, want empty or populated slice")
	}
}
