package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestCreateRejectsBadScratchFlagsBeforeTouchingIncus(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", DNSSuffix: "acme", Projects: []meta.Project{{Name: "default"}}}
	for name, tc := range map[string]struct {
		options createV2Options
		want    string
	}{
		"garbage size": {createV2Options{ScratchSize: "lots"}, "invalid scratch size"},
		"conflict":     {createV2Options{NoScratch: true, ScratchSize: "5GiB"}, "cannot be combined"},
	} {
		err := runCreateMachineV2(context.Background(), commandConfig{}, &rootOptions{}, summary, "default:web", tc.options)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want an error containing %q, got %v", name, tc.want, err)
		}
	}
}
