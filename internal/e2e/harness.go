package e2e

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/tailscale"
)

const enabledEnv = "SANDCASTLE_E2E"

type Config struct {
	Enabled             bool
	Remote              string
	StoragePool         string
	CIDRPool            string
	RunID               string
	Keep                bool
	SandcastleBin       string
	SSHPublicKey        string
	RouteBroker         RouteBrokerConfig
	PublicRoutes        PublicRouteConfig
	LocalVM             bool
	Tailscale           TailscaleConfig
	Images              ImageConfig
	Auth                AuthConfig
	PublicDNSZone       PublicDNSZoneConfig
	MachinePublications MachinePublicationConfig
}

// PublicDNSZoneConfig gates e2e Phase 12 (Public DNS Zones, ADR-0027): a real
// Cloudflare zone the token can edit, ordered against Let's Encrypt STAGING.
// Both values absent → the phase is skipped, never failed.
type PublicDNSZoneConfig struct {
	CloudflareToken string // SANDCASTLE_E2E_CLOUDFLARE_TOKEN
	Zone            string // SANDCASTLE_E2E_PUBLIC_DNS_ZONE
}

// MachinePublicationConfig gates the destructive fresh-install lifecycle
// phase. Public DNS Zone credentials alone must never unexpectedly create
// Cloudflare Tunnels or issue certificates.
type MachinePublicationConfig struct {
	Enabled         bool // SANDCASTLE_E2E_MACHINE_PUBLICATIONS=1
	SimulatedGitHub bool // SANDCASTLE_E2E_SIMULATED_GITHUB=1; records fresh-install auth mode
}

// Configured reports whether both Phase 12 gate variables are set.
func (c PublicDNSZoneConfig) Configured() bool {
	return c.CloudflareToken != "" && c.Zone != ""
}

type AuthConfig struct {
	Host      string // auth app URL for sc login e2e
	DebugUser string // allowlisted user for --debug-device-user on the server
}

type RouteBrokerConfig struct {
	IncusSocket string
}

type PublicRouteConfig struct {
	Domain             string
	InfrastructureHost string
	LetsEncryptEmail   string
}

type TailscaleConfig struct {
	AuthKey string
	Tag     string
}

type ImageConfig struct {
	BaseSource    string
	AISource      string
	Build         bool
	BuildTool     string
	CodexVersion  string
	ClaudeVersion string
	GeminiVersion string
}

func LoadConfig() Config {
	tag := getenv("SANDCASTLE_E2E_TAILSCALE_TAG", tailscale.DefaultAdvertiseTag)
	return Config{
		Enabled:       os.Getenv(enabledEnv) == "1",
		Remote:        getenv("SANDCASTLE_E2E_REMOTE", "local"),
		StoragePool:   getenv("SANDCASTLE_E2E_STORAGE_POOL", "default"),
		CIDRPool:      getenv("SANDCASTLE_E2E_CIDR_POOL", "10.248.0.0/16"),
		RunID:         os.Getenv("SANDCASTLE_E2E_RUN_ID"),
		Keep:          os.Getenv("SANDCASTLE_E2E_KEEP") == "1",
		SandcastleBin: os.Getenv("SANDCASTLE_E2E_SANDCASTLE_BIN"),
		SSHPublicKey:  os.Getenv("SANDCASTLE_E2E_SSH_PUBLIC_KEY"),
		RouteBroker: RouteBrokerConfig{
			IncusSocket: getenv("SANDCASTLE_ROUTE_BROKER_INCUS_SOCKET", config.DefaultRouteBrokerIncusSocket),
		},
		PublicRoutes: PublicRouteConfig{
			Domain:             strings.TrimPrefix(os.Getenv("SANDCASTLE_E2E_PUBLIC_DOMAIN"), "."),
			InfrastructureHost: os.Getenv("SANDCASTLE_E2E_INFRA_HOST"),
			LetsEncryptEmail:   os.Getenv("SANDCASTLE_E2E_LETSENCRYPT_EMAIL"),
		},
		LocalVM: os.Getenv("SANDCASTLE_E2E_LOCAL_VM") == "1",
		Tailscale: TailscaleConfig{
			AuthKey: os.Getenv("SANDCASTLE_E2E_TAILSCALE_AUTHKEY"),
			Tag:     tag,
		},
		Images: ImageConfig{
			BaseSource:    os.Getenv("SANDCASTLE_E2E_BASE_IMAGE_SOURCE"),
			AISource:      os.Getenv("SANDCASTLE_E2E_AI_IMAGE_SOURCE"),
			Build:         os.Getenv("SANDCASTLE_E2E_IMAGE_BUILD") == "1",
			BuildTool:     getenv("SANDCASTLE_E2E_IMAGE_BUILD_TOOL", "docker"),
			CodexVersion:  os.Getenv("SANDCASTLE_E2E_CODEX_VERSION"),
			ClaudeVersion: os.Getenv("SANDCASTLE_E2E_CLAUDE_CODE_VERSION"),
			GeminiVersion: os.Getenv("SANDCASTLE_E2E_GEMINI_CLI_VERSION"),
		},
		Auth: AuthConfig{
			Host:      os.Getenv("SANDCASTLE_E2E_AUTH_HOST"),
			DebugUser: getenv("SANDCASTLE_E2E_DEBUG_USER", "thieso2"),
		},
		PublicDNSZone: PublicDNSZoneConfig{
			CloudflareToken: strings.TrimSpace(os.Getenv("SANDCASTLE_E2E_CLOUDFLARE_TOKEN")),
			Zone:            strings.ToLower(strings.TrimSuffix(strings.TrimSpace(os.Getenv("SANDCASTLE_E2E_PUBLIC_DNS_ZONE")), ".")),
		},
		MachinePublications: MachinePublicationConfig{
			Enabled:         os.Getenv("SANDCASTLE_E2E_MACHINE_PUBLICATIONS") == "1",
			SimulatedGitHub: os.Getenv("SANDCASTLE_E2E_SIMULATED_GITHUB") == "1",
		},
	}
}

func (c Config) Validate() error {
	if !c.Enabled {
		return fmt.Errorf("set %s=1 to enable destructive e2e tests", enabledEnv)
	}
	if c.Remote == "" {
		return fmt.Errorf("SANDCASTLE_E2E_REMOTE is required")
	}
	if c.StoragePool == "" {
		return fmt.Errorf("SANDCASTLE_E2E_STORAGE_POOL is required")
	}
	if c.CIDRPool == "" {
		return fmt.Errorf("SANDCASTLE_E2E_CIDR_POOL is required")
	}
	if c.Tailscale.Tag == "" {
		return fmt.Errorf("SANDCASTLE_E2E_TAILSCALE_TAG is required when e2e is enabled")
	}
	if _, err := tailscale.NormalizeAdvertiseTags([]string{c.Tailscale.Tag}); err != nil {
		return fmt.Errorf("SANDCASTLE_E2E_TAILSCALE_TAG: %w", err)
	}
	return nil
}

func (c Config) DisposableRunID() string {
	if c.RunID != "" {
		return safeToken(c.RunID)
	}
	return "e2e-" + time.Now().UTC().Format("20060102-150405-000000000")
}

func safeToken(value string) string {
	value = strings.ToLower(value)
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
