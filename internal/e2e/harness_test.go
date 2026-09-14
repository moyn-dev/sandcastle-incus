package e2e

import (
	"regexp"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
)

func TestLoadConfigDefaultsToDisabledAndSandcastleTag(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E", "0")
	t.Setenv("SANDCASTLE_E2E_TAILSCALE_TAG", "")

	config := LoadConfig()
	if config.Enabled {
		t.Fatal("config.Enabled = true, want false")
	}
	if config.Tailscale.Tag != "tag:sandcastle" {
		t.Fatalf("Tailscale tag = %q, want tag:sandcastle", config.Tailscale.Tag)
	}
	if config.Images.Build {
		t.Fatal("Images.Build = true, want false")
	}
	if config.Images.BuildTool != "docker" {
		t.Fatalf("Images.BuildTool = %q, want docker", config.Images.BuildTool)
	}
	if config.RouteBroker.IncusSocket != scconfig.DefaultRouteBrokerIncusSocket {
		t.Fatalf("RouteBroker.IncusSocket = %q, want %q", config.RouteBroker.IncusSocket, scconfig.DefaultRouteBrokerIncusSocket)
	}
	if config.LocalVM {
		t.Fatal("LocalVM = true, want false")
	}
}

func TestLoadConfigReadsRouteBrokerSocket(t *testing.T) {
	t.Setenv("SANDCASTLE_ROUTE_BROKER_INCUS_SOCKET", "/run/incus/unix.socket")
	config := LoadConfig()
	if config.RouteBroker.IncusSocket != "/run/incus/unix.socket" {
		t.Fatalf("RouteBroker.IncusSocket = %q", config.RouteBroker.IncusSocket)
	}
}

func TestLoadConfigReadsPublicRouteSettings(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E_PUBLIC_DOMAIN", ".routes.example.com")
	t.Setenv("SANDCASTLE_E2E_INFRA_HOST", "198.51.100.10")
	t.Setenv("SANDCASTLE_E2E_LETSENCRYPT_EMAIL", "ops@example.com")
	config := LoadConfig()
	if config.PublicRoutes.Domain != "routes.example.com" {
		t.Fatalf("PublicRoutes.Domain = %q", config.PublicRoutes.Domain)
	}
	if config.PublicRoutes.InfrastructureHost != "198.51.100.10" {
		t.Fatalf("PublicRoutes.InfrastructureHost = %q", config.PublicRoutes.InfrastructureHost)
	}
	if config.PublicRoutes.LetsEncryptEmail != "ops@example.com" {
		t.Fatalf("PublicRoutes.LetsEncryptEmail = %q", config.PublicRoutes.LetsEncryptEmail)
	}
}

func TestLoadConfigReadsLocalVMGate(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E_LOCAL_VM", "1")
	config := LoadConfig()
	if !config.LocalVM {
		t.Fatal("LocalVM = false, want true")
	}
}

func TestValidateFailsClosedWhenE2EDisabled(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E", "")
	config := LoadConfig()
	err := config.Validate()
	if err == nil {
		t.Fatal("expected disabled e2e error")
	}
	if !strings.Contains(err.Error(), "SANDCASTLE_E2E=1") {
		t.Fatalf("error = %q, want SANDCASTLE_E2E hint", err.Error())
	}
}

func TestValidateAcceptsMinimalEnabledConfig(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E", "1")

	config := LoadConfig()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsInvalidTailscaleTag(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E", "1")
	t.Setenv("SANDCASTLE_E2E_TAILSCALE_TAG", "sandcastle")

	config := LoadConfig()
	err := config.Validate()
	if err == nil {
		t.Fatal("expected invalid Tailscale tag error")
	}
	if !strings.Contains(err.Error(), "SANDCASTLE_E2E_TAILSCALE_TAG") || !strings.Contains(err.Error(), "tag:<name>") {
		t.Fatalf("error = %q, want Tailscale tag hint", err.Error())
	}
}

func TestMachinePublicationLifecycleRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E_MACHINE_PUBLICATIONS", "")
	t.Setenv("SANDCASTLE_E2E_SIMULATED_GITHUB", "")
	if LoadConfig().MachinePublications.Enabled {
		t.Fatal("Machine publication lifecycle must be opt-in")
	}

	t.Setenv("SANDCASTLE_E2E_MACHINE_PUBLICATIONS", "1")
	if !LoadConfig().MachinePublications.Enabled {
		t.Fatal("Machine publication lifecycle opt-in was not loaded")
	}
	if LoadConfig().MachinePublications.SimulatedGitHub {
		t.Fatal("simulated GitHub assertion must be explicit")
	}

	t.Setenv("SANDCASTLE_E2E_SIMULATED_GITHUB", "1")
	if !LoadConfig().MachinePublications.SimulatedGitHub {
		t.Fatal("simulated GitHub assertion was not loaded")
	}
}

func TestDisposableRunIDUsesSafeOverride(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E_RUN_ID", "Test_Run.1")
	config := LoadConfig()
	if got := config.DisposableRunID(); got != "test-run-1" {
		t.Fatalf("DisposableRunID = %q, want test-run-1", got)
	}
}

func TestDisposableRunIDDefaultIncludesSubsecondEntropy(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E_RUN_ID", "")
	config := LoadConfig()
	got := config.DisposableRunID()
	if !regexp.MustCompile(`^e2e-[0-9]{8}-[0-9]{6}-[0-9]{9}$`).MatchString(got) {
		t.Fatalf("DisposableRunID = %q, want nanosecond timestamp run id", got)
	}
}
