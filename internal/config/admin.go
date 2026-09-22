package config

import (
	"fmt"
	"strings"

	domainrules "github.com/thieso2/sandcastle-incus/internal/domain"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

const (
	DefaultRemote                = "local"
	DefaultStoragePool           = "default"
	DefaultCIDRPool              = "10.248.0.0/16"
	DefaultIncusProjectPrefix    = "sc"
	DefaultInfrastructureProject = "sc-infra"
	DefaultInfrastructureHost    = ""
	DefaultLetsEncryptEmail      = ""
	DefaultInfrastructureTLSMode = "acme"
	DefaultAuthHostname          = ""
	// Sandcastle requires NO prebuilt images: base and AI both default to the
	// stock upstream image, pulled on demand from the public images: remote.
	// (Set SANDCASTLE_BASE_IMAGE / SANDCASTLE_AI_IMAGE or --*-image to override
	// with a custom image if you have one.)
	DefaultBaseImageAlias = "images:debian/13"
	DefaultAIImageAlias   = "images:debian/13"
	// The Dev Image is a distinct template (Ubuntu 26.04, not Debian 13), so it
	// gets its own stock public images: alias rather than reusing Base/AI's.
	// Not verified against a live Incus images: remote — see implementation-notes.md.
	DefaultDevImageAlias = "images:ubuntu/26.04"
	// DefaultProjectImage is what a NEW project's default machine image is set
	// to at creation when the request names none and the tenant's default
	// project has none to inherit. A project without an image fell back to
	// the CLI's built-in machine image, which surprised users who expected
	// the install's dev image; setting it explicitly at creation keeps it
	// visible (`sc project list -l`) and changeable (`sc project set-image`).
	DefaultProjectImage           = "images:ubuntu/26.04/cloud"
	DefaultRouteBrokerIncusSocket = "/var/lib/incus/unix.socket"
)

type Admin struct {
	DirectoryConfigPath string // nearest .sandcastle read; empty means global fallback
	// PositionLevel is the Current Position's level from the nearest
	// .sandcastle ("root", "remote", "tenant", "project"); empty when no
	// selection file was read, which means the project level.
	PositionLevel string
	Tenant        string
	Project       string
	Remote        string
	AdminRemote   string // Incus remote for admin commands; uses global ~/.config/incus/ config
	// ActiveInstall is the Sandcastle install the user CLI is currently on —
	// the same value `sc ls` resolves (LoadUser). Filled in by ExecuteAdmin,
	// never read from file or env, and empty when the operator named a remote
	// explicitly. Admin commands use it to act on the install the user is
	// looking at rather than on whichever one the ambient Incus default remote
	// happens to host.
	ActiveInstall          string
	ConfigPath             string // path to per-remote Incus config dir; empty = use default ~/.config/incus
	StoragePool            string
	CIDRPool               string
	IncusProjectPrefix     string
	InfrastructureProject  string
	InfrastructureHost     string
	LetsEncryptEmail       string
	InfrastructureTLSMode  string
	AuthHostname           string
	AuthGitHubClientID     string
	AuthGitHubClientSecret string
	AuthAdminGitHubUsers   []string
	AuthDebugDeviceUser    string
	AuthTailscaleAuthKey   string
	// ProjectImage is the image a new project is given at creation
	// (SANDCASTLE_DEFAULT_PROJECT_IMAGE; DefaultProjectImage when unset).
	ProjectImage           string
	AuthToken              string
	Broker                 string // Sandcastle Broker URL for tenant self-service
	RouteBrokerIncusSocket string
	AllowedDomainSuffixes  []string
	DeniedDomainSuffixes   []string
	Images                 Images
}

type Images struct {
	Base string
	AI   string
	Dev  string
}

func LoadAdminFromEnv() Admin {
	env := loadAdminEnv()
	return MergeAdmin(AdminDefaults(), adminOverridesFromEnv(env))
}

func AdminDefaults() Admin {
	return Admin{
		Remote:                 DefaultRemote,
		StoragePool:            DefaultStoragePool,
		CIDRPool:               DefaultCIDRPool,
		IncusProjectPrefix:     DefaultIncusProjectPrefix,
		InfrastructureProject:  DefaultInfrastructureProject,
		InfrastructureTLSMode:  DefaultInfrastructureTLSMode,
		RouteBrokerIncusSocket: DefaultRouteBrokerIncusSocket,
		Images: Images{
			Base: DefaultBaseImageAlias,
			AI:   DefaultAIImageAlias,
			Dev:  DefaultDevImageAlias,
		},
	}
}

func LoadAdminEnvOverrides() Admin {
	return adminOverridesFromEnv(loadAdminEnv())
}

func adminOverridesFromEnv(env map[string]string) Admin {
	return Admin{
		Tenant:                 strings.TrimSpace(env["SANDCASTLE_TENANT"]),
		Project:                strings.TrimSpace(env["SANDCASTLE_PROJECT"]),
		Remote:                 strings.TrimSpace(env["SANDCASTLE_REMOTE"]),
		StoragePool:            strings.TrimSpace(env["SANDCASTLE_STORAGE_POOL"]),
		CIDRPool:               strings.TrimSpace(env["SANDCASTLE_CIDR_POOL"]),
		IncusProjectPrefix:     incusProjectPrefixOverrideFromEnv(env),
		InfrastructureProject:  strings.TrimSpace(env["SANDCASTLE_INFRA_PROJECT"]),
		InfrastructureHost:     strings.TrimSpace(env["SANDCASTLE_INFRA_HOST"]),
		LetsEncryptEmail:       strings.TrimSpace(env["SANDCASTLE_LETSENCRYPT_EMAIL"]),
		InfrastructureTLSMode:  strings.TrimSpace(env["SANDCASTLE_INFRA_TLS_MODE"]),
		AuthHostname:           strings.TrimSpace(env["SANDCASTLE_AUTH_HOSTNAME"]),
		AuthGitHubClientID:     getenvFrom(env, "SANDCASTLE_AUTH_GITHUB_CLIENT_ID", ""),
		AuthGitHubClientSecret: getenvFrom(env, "SANDCASTLE_AUTH_GITHUB_CLIENT_SECRET", ""),
		AuthAdminGitHubUsers:   splitListFrom(env, "SANDCASTLE_AUTH_ADMIN_GITHUB_USERS"),
		AuthDebugDeviceUser:    strings.TrimSpace(env["SANDCASTLE_AUTH_DEBUG_DEVICE_USER"]),
		AuthTailscaleAuthKey:   authTailscaleAuthKeyFromEnv(env),
		AuthToken:              strings.TrimSpace(env["SANDCASTLE_AUTH_TOKEN"]),
		Broker:                 strings.TrimSpace(env["SANDCASTLE_BROKER"]),
		RouteBrokerIncusSocket: strings.TrimSpace(env["SANDCASTLE_ROUTE_BROKER_INCUS_SOCKET"]),
		AllowedDomainSuffixes:  splitListFrom(env, "SANDCASTLE_ALLOWED_DOMAIN_SUFFIXES"),
		DeniedDomainSuffixes:   splitListFrom(env, "SANDCASTLE_DENIED_DOMAIN_SUFFIXES"),
		Images: Images{
			Base: strings.TrimSpace(env["SANDCASTLE_BASE_IMAGE"]),
			AI:   strings.TrimSpace(env["SANDCASTLE_AI_IMAGE"]),
			Dev:  strings.TrimSpace(env["SANDCASTLE_DEV_IMAGE"]),
		},
	}
}

func MergeAdmin(base Admin, overrides Admin) Admin {
	out := base
	if strings.TrimSpace(overrides.Tenant) != "" {
		out.Tenant = strings.TrimSpace(overrides.Tenant)
	}
	if strings.TrimSpace(overrides.Project) != "" {
		out.Project = strings.TrimSpace(overrides.Project)
	}
	if strings.TrimSpace(overrides.Remote) != "" {
		out.Remote = strings.TrimSpace(overrides.Remote)
	}
	if strings.TrimSpace(overrides.AdminRemote) != "" {
		out.AdminRemote = strings.TrimSpace(overrides.AdminRemote)
	}
	if strings.TrimSpace(overrides.ConfigPath) != "" {
		out.ConfigPath = strings.TrimSpace(overrides.ConfigPath)
	}
	if strings.TrimSpace(overrides.StoragePool) != "" {
		out.StoragePool = strings.TrimSpace(overrides.StoragePool)
	}
	if strings.TrimSpace(overrides.CIDRPool) != "" {
		out.CIDRPool = strings.TrimSpace(overrides.CIDRPool)
	}
	if strings.TrimSpace(overrides.IncusProjectPrefix) != "" {
		out.IncusProjectPrefix = strings.TrimSpace(overrides.IncusProjectPrefix)
	}
	if strings.TrimSpace(overrides.InfrastructureProject) != "" {
		out.InfrastructureProject = strings.TrimSpace(overrides.InfrastructureProject)
	}
	if strings.TrimSpace(overrides.InfrastructureHost) != "" {
		out.InfrastructureHost = strings.TrimSpace(overrides.InfrastructureHost)
	}
	if strings.TrimSpace(overrides.LetsEncryptEmail) != "" {
		out.LetsEncryptEmail = strings.TrimSpace(overrides.LetsEncryptEmail)
	}
	if strings.TrimSpace(overrides.InfrastructureTLSMode) != "" {
		out.InfrastructureTLSMode = strings.TrimSpace(overrides.InfrastructureTLSMode)
	}
	if strings.TrimSpace(overrides.AuthHostname) != "" {
		out.AuthHostname = strings.TrimSpace(overrides.AuthHostname)
	}
	if strings.TrimSpace(overrides.AuthGitHubClientID) != "" {
		out.AuthGitHubClientID = strings.TrimSpace(overrides.AuthGitHubClientID)
	}
	if strings.TrimSpace(overrides.AuthGitHubClientSecret) != "" {
		out.AuthGitHubClientSecret = strings.TrimSpace(overrides.AuthGitHubClientSecret)
	}
	if len(overrides.AuthAdminGitHubUsers) > 0 {
		out.AuthAdminGitHubUsers = append([]string{}, overrides.AuthAdminGitHubUsers...)
	}
	if strings.TrimSpace(overrides.AuthDebugDeviceUser) != "" {
		out.AuthDebugDeviceUser = strings.TrimSpace(overrides.AuthDebugDeviceUser)
	}
	if strings.TrimSpace(overrides.AuthTailscaleAuthKey) != "" {
		out.AuthTailscaleAuthKey = strings.TrimSpace(overrides.AuthTailscaleAuthKey)
	}
	if strings.TrimSpace(overrides.AuthToken) != "" {
		out.AuthToken = strings.TrimSpace(overrides.AuthToken)
	}
	if strings.TrimSpace(overrides.Broker) != "" {
		out.Broker = strings.TrimSpace(overrides.Broker)
	}
	if strings.TrimSpace(overrides.RouteBrokerIncusSocket) != "" {
		out.RouteBrokerIncusSocket = strings.TrimSpace(overrides.RouteBrokerIncusSocket)
	}
	if len(overrides.AllowedDomainSuffixes) > 0 {
		out.AllowedDomainSuffixes = append([]string{}, overrides.AllowedDomainSuffixes...)
	}
	if len(overrides.DeniedDomainSuffixes) > 0 {
		out.DeniedDomainSuffixes = append([]string{}, overrides.DeniedDomainSuffixes...)
	}
	if strings.TrimSpace(overrides.Images.Base) != "" {
		out.Images.Base = strings.TrimSpace(overrides.Images.Base)
	}
	if strings.TrimSpace(overrides.Images.AI) != "" {
		out.Images.AI = strings.TrimSpace(overrides.Images.AI)
	}
	if strings.TrimSpace(overrides.Images.Dev) != "" {
		out.Images.Dev = strings.TrimSpace(overrides.Images.Dev)
	}
	return out
}

func authTailscaleAuthKeyFromEnv(env map[string]string) string {
	return firstNonEmpty(
		env["SANDCASTLE_AUTH_TAILSCALE_AUTHKEY"],
		env["SANDCASTLE_TAILSCALE_AUTHKEY"],
		env["SANDCASTLE_E2E_TAILSCALE_AUTHKEY"],
	)
}

func (c Admin) Validate() error {
	if strings.TrimSpace(c.Remote) == "" {
		return fmt.Errorf("remote is required")
	}
	if strings.TrimSpace(c.StoragePool) == "" {
		return fmt.Errorf("storage pool is required")
	}
	if strings.TrimSpace(c.CIDRPool) == "" {
		return fmt.Errorf("CIDR pool is required")
	}
	if strings.TrimSpace(c.IncusProjectPrefix) == "" {
		return fmt.Errorf("incus project prefix is required")
	}
	if err := naming.ValidateIncusProjectPrefix(c.IncusProjectPrefix); err != nil {
		return err
	}
	if strings.TrimSpace(c.InfrastructureProject) == "" {
		return fmt.Errorf("infrastructure project is required")
	}
	if err := naming.ValidateIncusProjectName(c.InfrastructureProject); err != nil {
		return err
	}
	if strings.TrimSpace(c.Images.Base) == "" {
		return fmt.Errorf("base image alias is required")
	}
	if strings.TrimSpace(c.Images.AI) == "" {
		return fmt.Errorf("AI image alias is required")
	}
	if strings.TrimSpace(c.Images.Dev) == "" {
		return fmt.Errorf("dev image alias is required")
	}
	switch strings.TrimSpace(c.InfrastructureTLSMode) {
	case "", "acme", "internal":
	default:
		return fmt.Errorf("infrastructure TLS mode must be acme or internal")
	}
	if err := validateDomainSuffixes("allowed", c.AllowedDomainSuffixes); err != nil {
		return err
	}
	if err := validateDomainSuffixes("denied", c.DeniedDomainSuffixes); err != nil {
		return err
	}
	return nil
}

func validateDomainSuffixes(kind string, suffixes []string) error {
	for _, suffix := range suffixes {
		if strings.TrimSpace(suffix) == "" {
			continue
		}
		if _, err := domainrules.NormalizePolicySuffix(suffix); err != nil {
			return fmt.Errorf("invalid %s domain suffix %q: %w", kind, suffix, err)
		}
	}
	return nil
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(loadAdminEnv()[key])
	if value == "" {
		return fallback
	}
	return value
}

func incusProjectPrefixFromEnv(env map[string]string) string {
	return firstNonEmpty(env["SANDCASTLE_INCUS_PROJECT_PREFIX"], env["SANDCASTLE_PROJECT_PREFIX"], DefaultIncusProjectPrefix)
}

func incusProjectPrefixOverrideFromEnv(env map[string]string) string {
	return firstNonEmpty(env["SANDCASTLE_INCUS_PROJECT_PREFIX"], env["SANDCASTLE_PROJECT_PREFIX"])
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
