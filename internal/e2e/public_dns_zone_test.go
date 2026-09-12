package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPublicDNSZonePhase12E2E is e2e Phase 12 (docs/e2e-sc2.md): Public DNS
// Zones end to end against a real Cloudflare zone and Let's Encrypt STAGING.
// It drives scripts/e2e-pdz.sh from an enrolled client (sc login as a
// Sandcastle Admin, on the tenant tailnet) and is gated on
// SANDCASTLE_E2E=1 plus SANDCASTLE_E2E_CLOUDFLARE_TOKEN and
// SANDCASTLE_E2E_PUBLIC_DNS_ZONE — absent, it is skipped, not failed, which is
// what keeps `make e2e-safe` green without the credentials.
func TestPublicDNSZonePhase12E2E(t *testing.T) {
	config := LoadConfig()
	if !config.Enabled {
		t.Skip("set SANDCASTLE_E2E=1 to run real Incus e2e tests")
	}
	if !config.PublicDNSZone.Configured() {
		t.Skip("Phase 12 skipped: set SANDCASTLE_E2E_CLOUDFLARE_TOKEN and SANDCASTLE_E2E_PUBLIC_DNS_ZONE (a real Cloudflare test zone the token can edit) to run the Public DNS Zones phase")
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join("..", "..", "scripts", "e2e-pdz.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("phase 12 driver: %v", err)
	}
	sandcastleBin := config.SandcastleBin
	if sandcastleBin == "" {
		sandcastleBin = buildSandcastleForE2E(t)
	}

	command := exec.Command("bash", script)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = append(os.Environ(),
		"SANDCASTLE_E2E_SANDCASTLE_BIN="+sandcastleBin,
		"SANDCASTLE_E2E_RUN_ID="+config.DisposableRunID(),
		"SANDCASTLE_E2E_PUBLIC_DNS_ZONE="+config.PublicDNSZone.Zone,
	)
	if err := command.Run(); err != nil {
		t.Fatalf("phase 12 (Public DNS Zones) failed: %v", err)
	}
}
