package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// SandcastleConfig holds user-facing defaults stored in ~/.config/sandcastle/config.yml.
type SandcastleConfig struct {
	Tenant       string `yaml:"tenant,omitempty"`
	Project      string `yaml:"project,omitempty"`
	Remote       string `yaml:"remote,omitempty"`
	AdminRemote  string `yaml:"admin_remote,omitempty"`
	AuthHostname string `yaml:"auth_hostname,omitempty"`
	AuthToken    string `yaml:"auth_token,omitempty"`
	// Broker is the Sandcastle Broker URL for tenant self-service (project
	// create). Saved by `sc login`, derived from the tenant's private CIDR.
	Broker string `yaml:"broker,omitempty"`
	// Installs maps a Sandcastle Incus remote name to the install's public Auth
	// Hostname (its global URL). Recorded by `sc login` so that switching the
	// active remote (`sc config set remote …`) can re-point the auth plane at
	// the matching install without a re-login: the URL-derived remote name
	// identifies the install, and this map recovers its Auth App URL.
	Installs map[string]string `yaml:"installs,omitempty"`
	// AuthTokens maps an install's Auth Hostname to that install's CLI auth
	// token. The token is minted by ONE install's Auth App and is meaningless
	// (and must not be presented) to another, so switching remotes must swap it
	// along with the hostname.
	AuthTokens map[string]string `yaml:"auth_tokens,omitempty"`
	// Brokers maps an install's Auth Hostname to that install's Broker URL
	// (https://<tenant gateway>:9443). Broker is per-install — it addresses the
	// tenant's gateway on THAT install's CIDR pool — so switching remotes must
	// re-point it too. Keyed by Auth Hostname rather than remote name because
	// that is what `sc login` knows before the remote is enrolled.
	Brokers map[string]string `yaml:"brokers,omitempty"`
	// RemoteAuthTokens maps an enrolled Sandcastle remote name (the Tenant DNS
	// Suffix — unique per (install, tenant) on this client) to that login's CLI
	// auth token. The hostname-keyed AuthTokens map cannot distinguish two
	// tenants of ONE install (the last login's token wins), so remote switching
	// prefers this map — the bearer identity follows the remote (#112).
	RemoteAuthTokens map[string]string `yaml:"remote_auth_tokens,omitempty"`
	// RemoteBrokers likewise maps a remote name to its Broker URL. The Broker
	// addresses the TENANT's own gateway (its /24), so it is per-remote, not
	// just per-install — two tenants of one install have different gateways.
	RemoteBrokers map[string]string `yaml:"remote_brokers,omitempty"`
	// RemoteTenants maps a remote name to the tenant enrolled under it, so
	// switching remotes re-points cfg.Tenant along with the token — the right
	// token with the wrong tenant is still a 403 (#112).
	RemoteTenants map[string]string `yaml:"remote_tenants,omitempty"`
	// SkillReminder is the persisted opt-out for the interactive "agent skill
	// not installed / outdated" hint (`sc config set skill-reminder off`).
	// "" or "on" keeps the hint; "off" silences it.
	SkillReminder string `yaml:"skill_reminder,omitempty"`
}

// SkillReminderEnabled reports whether the interactive agent-skill hint may be
// shown: everything but an explicit "off" (case-insensitive) counts as on.
func (c SandcastleConfig) SkillReminderEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(c.SkillReminder), "off")
}

// TenantForRemote returns the tenant recorded for an enrolled remote, or ""
// when none was recorded (a login predating remote_tenants).
func (c SandcastleConfig) TenantForRemote(remote string) string {
	return recordedValue(c.RemoteTenants, remote)
}

// recordedValue is the shared shape of every per-key record accessor: trimmed
// lookup, "" for an absent key or a map that predates the record.
func recordedValue(records map[string]string, key string) string {
	key = strings.TrimSpace(key)
	if key == "" || records == nil {
		return ""
	}
	return strings.TrimSpace(records[key])
}

// AuthTokenForRemote returns the CLI auth token recorded for an enrolled
// remote, or "" when none was recorded (a login predating remote_auth_tokens).
func (c SandcastleConfig) AuthTokenForRemote(remote string) string {
	return recordedValue(c.RemoteAuthTokens, remote)
}

// BrokerForRemote returns the Broker URL recorded for an enrolled remote, or
// "" when none was recorded (a login predating remote_brokers).
func (c SandcastleConfig) BrokerForRemote(remote string) string {
	return recordedValue(c.RemoteBrokers, remote)
}

// AuthHostnameForRemote returns the recorded Auth Hostname (global URL) for a
// Sandcastle remote, or "" when none was recorded.
func (c SandcastleConfig) AuthHostnameForRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" || c.Installs == nil {
		return ""
	}
	return strings.TrimSpace(c.Installs[remote])
}

// AuthTokenForAuthHostname returns the recorded CLI auth token for an install,
// or "" when none was recorded (a login that predates the auth_tokens map).
func (c SandcastleConfig) AuthTokenForAuthHostname(host string) string {
	return recordedValue(c.AuthTokens, host)
}

// BrokerForAuthHostname returns the recorded Broker URL for an install, or ""
// when none was recorded (a login that predates the brokers map).
func (c SandcastleConfig) BrokerForAuthHostname(host string) string {
	return recordedValue(c.Brokers, host)
}

// DefaultConfigDir returns ~/.config/sandcastle.
func DefaultConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "sandcastle")
}

// DefaultConfigPath returns ~/.config/sandcastle/config.yml.
func DefaultConfigPath() string {
	return filepath.Join(DefaultConfigDir(), "config.yml")
}

// sharedIncusMarker records, inside the native ~/.config/incus dir, that
// Sandcastle has adopted it — so resolution stays on that dir even after
// enrollment writes a client cert into it (which would otherwise look like a
// pre-existing foreign identity on the next call).
const sharedIncusMarker = ".sandcastle-owned"

// NativeIncusDir returns ~/.config/incus — the dir plain `incus` uses with no
// INCUS_CONF set.
func NativeIncusDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "incus")
}

// DedicatedIncusDir returns ~/.config/sandcastle/incus — Sandcastle's own dir,
// used when the native dir must not be touched (it holds an admin/other cert).
func DedicatedIncusDir() string {
	return filepath.Join(DefaultConfigDir(), "incus")
}

// PlatformIncusDir returns the Incus config directory the stock `incus` CLI
// uses with no INCUS_CONF set: os.UserConfigDir()/incus. On Linux that is
// ~/.config/incus (matching the SDK default and NativeIncusDir); on macOS it is
// ~/Library/Application Support/incus — where `incus` actually stores admin
// certs/remotes, and where the SDK's own ~/.config/incus default fails to look.
// Returns "" when the config dir can't be determined or no config.yml lives
// there, so admin callers fall back to the SDK default unchanged. This is why
// it exists separately from NativeIncusDir(): the shared-identity user-plane
// logic keys on the fixed ~/.config/incus path, but admin commands must find
// the real per-OS incus config so they work on macOS without exporting
// INCUS_CONF.
func PlatformIncusDir() string {
	base, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(base) == "" {
		return ""
	}
	dir := filepath.Join(base, "incus")
	if !fileExists(filepath.Join(dir, "config.yml")) {
		return ""
	}
	return dir
}

// SharedIncusDir returns the ONE incus config directory holding every
// sandcastle enrollment (a single client keypair shared across installs; one
// remote per install — sc-<tenant>, sc-<prefix>-<tenant>). It auto-detects:
// prefer the NATIVE ~/.config/incus so plain `incus remote switch` works with
// no wrapper, but only when that dir has no foreign identity to clobber;
// otherwise use the dedicated Sandcastle dir. See SharedIncusDirExplained for
// the reasoning strings.
func SharedIncusDir() string {
	dir, _ := SharedIncusDirExplained()
	return dir
}

// SharedIncusDirExplained resolves the shared incus dir and returns a one-line
// human explanation of the choice, for verbose enrollment output.
func SharedIncusDirExplained() (dir string, reason string) {
	native := NativeIncusDir()
	dedicated := DedicatedIncusDir()
	switch {
	case fileExists(filepath.Join(native, sharedIncusMarker)):
		return native, "native Incus config dir " + native + " (already Sandcastle-managed) — plain `incus` sees your Sandcastle remotes"
	case fileExists(filepath.Join(dedicated, "config.yml")):
		return dedicated, "dedicated Sandcastle dir " + dedicated + " (prior enrollments live here)"
	case fileExists(filepath.Join(native, "client.crt")):
		return dedicated, "dedicated Sandcastle dir " + dedicated + " — " + native + " already holds a client certificate (admin/other identity) that must not be overwritten"
	default:
		return native, "native Incus config dir " + native + " (no existing identity there) — plain `incus remote switch` works with no wrapper"
	}
}

// AdoptNativeIncusDirIfChosen drops the ownership marker when the resolved
// shared dir is the native one, so subsequent resolutions stay on it even after
// enrollment writes a client cert. No-op when the dedicated dir is in use.
// Call this at enrollment BEFORE writing the client cert.
func AdoptNativeIncusDirIfChosen() {
	if SharedIncusDir() != NativeIncusDir() {
		return
	}
	dir := NativeIncusDir()
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, sharedIncusMarker), []byte("Sandcastle shared-identity config — safe to delete to unmanage.\n"), 0o600)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// RemoteIncusDir returns the legacy per-remote incus config directory
// (pre-shared-identity enrollments kept one dir + keypair per remote).
func RemoteIncusDir(remoteName string) string {
	return filepath.Join(DefaultConfigDir(), remoteName, "incus")
}

// remoteListedIn reports whether the incus config at dir knows the remote.
func remoteListedIn(dir string, remoteName string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "config.yml"))
	if err != nil {
		return false
	}
	var cfg struct {
		Remotes map[string]any `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return false
	}
	_, ok := cfg.Remotes[remoteName]
	return ok
}

// LoadSandcastleConfig reads the config file at path. Missing file returns empty config, not an error.
func LoadSandcastleConfig(path string) (SandcastleConfig, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return SandcastleConfig{}, nil
	}
	if err != nil {
		return SandcastleConfig{}, err
	}
	var cfg SandcastleConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return SandcastleConfig{}, err
	}
	return cfg, nil
}

// SaveSandcastleConfig writes cfg to path, creating parent directories as needed.
func SaveSandcastleConfig(path string, cfg SandcastleConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadAdmin merges ~/.config/sandcastle/config.yml with SANDCASTLE_* env vars (env wins).
// ConfigPath is intentionally not set here — admin commands use the global ~/.config/incus/
// which holds admin certificates. User-facing commands call ResolveConfigPath separately.
func LoadAdmin() Admin {
	cfg, _ := LoadSandcastleConfig(DefaultConfigPath())
	return loadAdminFromFileAndEnv(cfg)
}

// LoadUser resolves directory selection and exported environment variables.
// Commands use LoadUserWithError to report invalid local files. Like the legacy
// loader, this convenience wrapper discards load errors. Local .env files are ignored.
func LoadUser() Admin {
	cfg, _ := LoadUserWithError()
	return cfg
}

// SharedIncusDefaultRemote returns the shared incus config dir's current
// remote when it names a Sandcastle enrollment ("sc-…"), else "". This makes
// the incus current remote a legacy fallback when no .sandcastle exists.
// Directory selection and explicit environment overrides take precedence.
// Non-sandcastle remotes (local,
// images, …) are ignored so raw-incus work doesn't hijack sc.
func SharedIncusDefaultRemote() string {
	data, err := os.ReadFile(filepath.Join(SharedIncusDir(), "config.yml"))
	if err != nil {
		return ""
	}
	var cfg struct {
		DefaultRemote string         `yaml:"default-remote"`
		Remotes       map[string]any `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	name := strings.TrimSpace(cfg.DefaultRemote)
	if !strings.HasPrefix(name, "sc-") {
		return ""
	}
	if _, ok := cfg.Remotes[name]; !ok {
		return ""
	}
	return name
}

// SharedIncusRemoteProject returns the project pinned on a remote in the shared
// incus config dir (remotes[name].project), or "" when the remote or its project
// is absent. The pinned project (e.g. tc3-thieso2-default) identifies which
// install the remote targets even when the remote NAME does not encode the
// install prefix (URL-based names like sc-obelix-thieso2-dev).
func SharedIncusRemoteProject(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(SharedIncusDir(), "config.yml"))
	if err != nil {
		return ""
	}
	var cfg struct {
		Remotes map[string]struct {
			Project string `yaml:"project"`
		} `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.Remotes[remote].Project)
}

// SetSharedIncusDefaultRemote points the shared incus config dir's current
// remote at name (the write-through for `sc config set remote`). The remote
// must already be enrolled there.
func SetSharedIncusDefaultRemote(name string) error {
	path := filepath.Join(SharedIncusDir(), "config.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}
	enrolled := false
	switch remotes := cfg["remotes"].(type) {
	case map[string]any: // yaml.v3 shape
		_, enrolled = remotes[name]
	case map[any]any: // yaml.v2 shape
		_, enrolled = remotes[name]
	}
	if !enrolled {
		return fmt.Errorf("remote %q is not enrolled in %s", name, path)
	}
	cfg["default-remote"] = name
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

// loadAdminFromFileAndEnv applies env var overrides on top of a file config.
func loadAdminFromFileAndEnv(cfg SandcastleConfig) Admin {
	env := loadAdminEnv()
	return adminFromConfigAndEnv(cfg, env)
}

func loadUserFromFileAndEnv(cfg SandcastleConfig) Admin {
	env := loadProcessEnv()
	admin := adminFromConfigAndEnv(cfg, env)
	// Legacy global fallback resolution, without directory selection.
	// The shared Incus default precedes the user config remote. Env still wins;
	// config.yml's remote is the fallback when no sandcastle remote is current.
	if getenvFrom(env, "SANDCASTLE_REMOTE", "") == "" {
		if name := SharedIncusDefaultRemote(); name != "" {
			admin.Remote = name
		}
	}
	return admin
}

func adminFromConfigAndEnv(cfg SandcastleConfig, env map[string]string) Admin {
	return MergeAdmin(AdminDefaults(), Admin{
		Tenant:                 firstNonEmpty(strings.TrimSpace(env["SANDCASTLE_TENANT"]), cfg.Tenant),
		Project:                firstNonEmpty(strings.TrimSpace(env["SANDCASTLE_PROJECT"]), cfg.Project),
		Remote:                 firstNonEmpty(getenvFrom(env, "SANDCASTLE_REMOTE", ""), cfg.Remote),
		AdminRemote:            firstNonEmpty(strings.TrimSpace(env["SANDCASTLE_ADMIN_REMOTE"]), cfg.AdminRemote),
		StoragePool:            strings.TrimSpace(env["SANDCASTLE_STORAGE_POOL"]),
		CIDRPool:               strings.TrimSpace(env["SANDCASTLE_CIDR_POOL"]),
		IncusProjectPrefix:     incusProjectPrefixOverrideFromEnv(env),
		InfrastructureProject:  strings.TrimSpace(env["SANDCASTLE_INFRA_PROJECT"]),
		InfrastructureHost:     strings.TrimSpace(env["SANDCASTLE_INFRA_HOST"]),
		LetsEncryptEmail:       strings.TrimSpace(env["SANDCASTLE_LETSENCRYPT_EMAIL"]),
		InfrastructureTLSMode:  strings.TrimSpace(env["SANDCASTLE_INFRA_TLS_MODE"]),
		AuthHostname:           firstNonEmpty(strings.TrimSpace(env["SANDCASTLE_AUTH_HOSTNAME"]), cfg.AuthHostname),
		AuthToken:              firstNonEmpty(strings.TrimSpace(env["SANDCASTLE_AUTH_TOKEN"]), cfg.AuthToken),
		Broker:                 firstNonEmpty(strings.TrimSpace(env["SANDCASTLE_BROKER"]), cfg.Broker),
		AuthGitHubClientID:     getenvFrom(env, "SANDCASTLE_AUTH_GITHUB_CLIENT_ID", ""),
		AuthGitHubClientSecret: getenvFrom(env, "SANDCASTLE_AUTH_GITHUB_CLIENT_SECRET", ""),
		AuthAdminGitHubUsers:   splitListFrom(env, "SANDCASTLE_AUTH_ADMIN_GITHUB_USERS"),
		AuthDebugDeviceUser:    strings.TrimSpace(env["SANDCASTLE_AUTH_DEBUG_DEVICE_USER"]),
		AuthTailscaleAuthKey:   authTailscaleAuthKeyFromEnv(env),
		ProjectImage:           strings.TrimSpace(env["SANDCASTLE_DEFAULT_PROJECT_IMAGE"]),
		RouteBrokerIncusSocket: strings.TrimSpace(env["SANDCASTLE_ROUTE_BROKER_INCUS_SOCKET"]),
		AllowedDomainSuffixes:  splitListFrom(env, "SANDCASTLE_ALLOWED_DOMAIN_SUFFIXES"),
		DeniedDomainSuffixes:   splitListFrom(env, "SANDCASTLE_DENIED_DOMAIN_SUFFIXES"),
		Images: Images{
			Base: strings.TrimSpace(env["SANDCASTLE_BASE_IMAGE"]),
			AI:   strings.TrimSpace(env["SANDCASTLE_AI_IMAGE"]),
			// The user CLI is the ONLY reader of Images.Dev that matters:
			// `sc create` decides a machine takes the Dev Image path (no
			// Caddy, no TLS leaf — ADR-0024) by matching --image against it.
			// Omitting it here pinned the value to DefaultDevImageAlias, so
			// no operator-built dev image could ever be recognized.
			Dev: strings.TrimSpace(env["SANDCASTLE_DEV_IMAGE"]),
		},
	})
}

// ResolveConfigPath returns the Sandcastle incus dir that knows the remote:
// the shared dir first (shared client identity, all installs side by side),
// then the legacy per-remote dir; empty string when the remote is unknown.
func ResolveConfigPath(remote string) string {
	if remote == "" {
		return ""
	}
	if shared := SharedIncusDir(); remoteListedIn(shared, remote) {
		return shared
	}
	dir := RemoteIncusDir(remote)
	if _, err := os.Stat(filepath.Join(dir, "config.yml")); err == nil {
		return dir
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
