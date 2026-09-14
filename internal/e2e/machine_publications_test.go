package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestMachinePublicationLifecycleE2E drives the fresh-install publication
// contract in docs/e2e-sc2.md. It is deliberately a separately opted-in
// destructive phase: a configured Phase 12 zone alone must not create a
// Cloudflare Tunnel or alter a DNS record.
func TestMachinePublicationLifecycleE2E(t *testing.T) {
	config := LoadConfig()
	if !config.Enabled {
		t.Skip("set SANDCASTLE_E2E=1 to run real Incus e2e tests")
	}
	if !config.MachinePublications.Enabled {
		t.Skip("set SANDCASTLE_E2E_MACHINE_PUBLICATIONS=1 to run the Machine publication lifecycle")
	}
	if !config.MachinePublications.SimulatedGitHub {
		t.Fatal("Machine publication lifecycle requires a fresh Auth App installed with --simulate-github-token; set SANDCASTLE_E2E_SIMULATED_GITHUB=1 only after doing so")
	}
	if !config.PublicDNSZone.Configured() {
		t.Skip("Machine publication lifecycle skipped: set SANDCASTLE_E2E_CLOUDFLARE_TOKEN and SANDCASTLE_E2E_PUBLIC_DNS_ZONE")
	}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}

	script := filepath.Join("..", "..", "scripts", "e2e-machine-publications.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("Machine publication lifecycle driver: %v", err)
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
	)
	if err := command.Run(); err != nil {
		t.Fatalf("Machine publication lifecycle failed: %v", err)
	}
}
