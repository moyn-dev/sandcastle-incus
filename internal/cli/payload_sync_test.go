package cli

import (
	"strings"
	"testing"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

// `sc payload-sync` syncs the current tenant's projects, so it refuses to
// run without one — before touching any Incus connection.
func TestPayloadSyncRequiresTenant(t *testing.T) {
	config := commandConfig{adminConfig: scconfig.Admin{}}
	command := newPayloadSyncCommand(config, &rootOptions{})
	err := command.RunE(command, nil)
	if err == nil || !strings.Contains(err.Error(), "tenant is required") {
		t.Fatalf("payload-sync without a tenant = %v, want a tenant-required error", err)
	}
}
