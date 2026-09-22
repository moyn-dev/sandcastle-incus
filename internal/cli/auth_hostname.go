package cli

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"gopkg.in/yaml.v2"
)

func normalizeAuthHostname(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimRight(value, "/")
	if value == "" {
		return ""
	}
	return value
}

// recordFor writes value under key in one of the config's record maps,
// allocating the map on first use. Returns whether anything changed.
func recordFor(records *map[string]string, key string, value string) bool {
	if key == "" || value == "" || (*records)[key] == value {
		return false
	}
	if *records == nil {
		*records = map[string]string{}
	}
	(*records)[key] = value
	return true
}

func saveAuthHostnameDefault(raw string) error {
	return saveAuthDefaults(raw, "", "", "")
}

func saveAuthDefaults(rawHostname string, rawToken string, rawRemote string, rawTenant string) error {
	host := normalizeAuthHostname(rawHostname)
	token := strings.TrimSpace(rawToken)
	remote := strings.TrimSpace(rawRemote)
	tenant := strings.TrimSpace(rawTenant)
	if host == "" && token == "" {
		return nil
	}
	path := scconfig.DefaultConfigPath()
	cfg, err := scconfig.LoadSandcastleConfig(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	changed := false
	if host != "" && cfg.AuthHostname != host {
		cfg.AuthHostname = host
		changed = true
	}
	if token != "" && cfg.AuthToken != token {
		cfg.AuthToken = token
		changed = true
	}
	// Record the token against THIS install so switching remotes can swap it.
	// Presenting one install's token to another leaks a credential across a
	// trust boundary (and is simply rejected: 403 "user not found").
	if host != "" && token != "" && recordFor(&cfg.AuthTokens, host, token) {
		changed = true
	}
	// And against the enrolled remote: two tenants of ONE install share the
	// hostname, so only the per-remote record lets `sc remote switch` present
	// the right tenant's token (#112).
	if recordFor(&cfg.RemoteAuthTokens, remote, token) {
		changed = true
	}
	// The tenant too: switching remotes must re-point cfg.Tenant along with the
	// token — the right token with the wrong tenant is still a 403 (#112).
	if recordFor(&cfg.RemoteTenants, remote, tenant) {
		changed = true
	}
	if !changed {
		return nil
	}
	if err := scconfig.SaveSandcastleConfig(path, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// saveProjectDefault records the tenant's current project in the user config so
// bare machine references (`sc c <machine>`) resolve without --project or a
// manual `sc config set project`. Returns whether the stored value changed.
func saveProjectDefault(project string) (bool, error) {
	project = strings.TrimSpace(project)
	if project == "" {
		return false, nil
	}
	path := scconfig.DefaultConfigPath()
	cfg, err := scconfig.LoadSandcastleConfig(path)
	if err != nil {
		return false, fmt.Errorf("load config: %w", err)
	}
	if cfg.Project == project {
		return false, nil
	}
	cfg.Project = project
	if err := scconfig.SaveSandcastleConfig(path, cfg); err != nil {
		return false, fmt.Errorf("save config: %w", err)
	}
	return true, nil
}

// adoptExistingInstall makes an already-enrolled install the active one when
// `sc login` finds a still-valid saved login for it (the idempotent-login
// shortcut). It re-points the active Auth Hostname, CLI token, broker, tenant,
// and Sandcastle remote — and the shared incus current remote — at that
// install, keeping the per-install maps consistent. For the already-active
// install it is a no-op-ish re-write that heals a stale auth_hostname/token.
// It returns whether the active install actually changed (a different Auth
// Hostname or Sandcastle remote than before), so the caller can report a switch.
func adoptExistingInstall(rawHost, rawRemote, rawToken, rawTenant, rawBroker string) (bool, error) {
	host := normalizeAuthHostname(rawHost)
	remote := strings.TrimSpace(rawRemote)
	token := strings.TrimSpace(rawToken)
	tenant := strings.TrimSpace(rawTenant)
	broker := strings.TrimRight(strings.TrimSpace(rawBroker), "/")
	if host == "" || remote == "" {
		return false, nil
	}
	path := scconfig.DefaultConfigPath()
	cfg, err := scconfig.LoadSandcastleConfig(path)
	if err != nil {
		return false, fmt.Errorf("load config: %w", err)
	}
	changed := normalizeAuthHostname(cfg.AuthHostname) != host || strings.TrimSpace(cfg.Remote) != remote
	cfg.AuthHostname = host
	cfg.Remote = remote
	if token != "" {
		cfg.AuthToken = token
		recordFor(&cfg.AuthTokens, host, token)
		recordFor(&cfg.RemoteAuthTokens, remote, token)
	}
	if broker != "" {
		cfg.Broker = broker
		recordFor(&cfg.Brokers, host, broker)
		recordFor(&cfg.RemoteBrokers, remote, broker)
	}
	if tenant != "" {
		cfg.Tenant = tenant
		recordFor(&cfg.RemoteTenants, remote, tenant)
	}
	if cfg.Installs == nil {
		cfg.Installs = map[string]string{}
	}
	cfg.Installs[remote] = host
	if err := scconfig.SaveSandcastleConfig(path, cfg); err != nil {
		return false, fmt.Errorf("save config: %w", err)
	}
	// The shared incus dir's current remote is the source of truth for the
	// active install; write through when the remote is enrolled there. Best
	// effort — the config.yml remote is the fallback when it is not.
	_ = scconfig.SetSharedIncusDefaultRemote(remote)
	return changed, nil
}

// recordInstall maps an enrolled Incus remote name to the install's public Auth
// Hostname (its global URL). It lets `sc config set remote <name>` re-point the
// auth plane at the matching install without a re-login.
func recordInstall(remoteName string, rawHostname string) error {
	name := strings.TrimSpace(remoteName)
	host := normalizeAuthHostname(rawHostname)
	if name == "" || host == "" {
		return nil
	}
	path := scconfig.DefaultConfigPath()
	cfg, err := scconfig.LoadSandcastleConfig(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Installs == nil {
		cfg.Installs = map[string]string{}
	}
	if cfg.Installs[name] == host {
		return nil
	}
	cfg.Installs[name] = host
	if err := scconfig.SaveSandcastleConfig(path, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// saveBrokerDefault records the Sandcastle Broker URL in the user config so
// broker-backed commands (`sc project create`) work without --broker.
//
// It records the URL twice: as the ACTIVE broker, and against this install's
// Auth Hostname. The broker addresses the tenant gateway on the install's own
// CIDR pool, so it is per-install — without the per-install record,
// `sc config set remote` could not re-point it and left the active broker
// aimed at the previously-active install.
func saveBrokerDefault(authHostname string, rawURL string, rawRemote string) error {
	broker := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if broker == "" {
		return nil
	}
	host := normalizeAuthHostname(authHostname)
	remote := strings.TrimSpace(rawRemote)
	path := scconfig.DefaultConfigPath()
	cfg, err := scconfig.LoadSandcastleConfig(path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.Broker == broker &&
		(host == "" || cfg.BrokerForAuthHostname(host) == broker) &&
		(remote == "" || cfg.BrokerForRemote(remote) == broker) {
		return nil
	}
	cfg.Broker = broker
	recordFor(&cfg.Brokers, host, broker)
	// Per-remote too: the Broker is the TENANT's gateway (its own /24), so two
	// tenants of one install have different brokers (#112).
	recordFor(&cfg.RemoteBrokers, remote, broker)
	if err := scconfig.SaveSandcastleConfig(path, cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

func commandAuthHostname(config commandConfig, override string) string {
	if host := normalizeAuthHostname(override); host != "" {
		return host
	}
	if host := normalizeAuthHostname(os.Getenv("SANDCASTLE_AUTH_HOSTNAME")); host != "" {
		return host
	}
	// The install this remote belongs to, recorded at login (remote name → its
	// public Auth Hostname). This is authoritative and, crucially, correct for
	// Cloudflare-ingress installs where the remote's address is the tenant
	// sidecar (which does not serve the auth API) rather than the auth app.
	if host := recordedInstallHostname(config.adminConfig.Remote); host != "" {
		return host
	}
	if host := inferAuthHostnameFromRemote(config.adminConfig.Remote); host != "" {
		return host
	}
	// Admin commands run against the admin remote (the Incus host, e.g.
	// "big"), which is never a login remote and so has no recorded install.
	// The install the user CLI is on does: try it before the top-level
	// auth_hostname, which is only the last login's value and can be a stale
	// placeholder (auth.example.com) on a client with several logins.
	if host := recordedInstallHostname(activeUserRemote(config)); host != "" {
		return host
	}
	return normalizeAuthHostname(config.adminConfig.AuthHostname)
}

// activeUserRemote returns the remote the user CLI is on: the ActiveInstall
// ExecuteAdmin resolved, else the same resolution `sc ls` uses (directory
// selection first, then the global config). Empty when nothing is enrolled.
func activeUserRemote(config commandConfig) string {
	if remote := strings.TrimSpace(config.adminConfig.ActiveInstall); remote != "" {
		return remote
	}
	userConfig, err := scconfig.LoadUserWithError()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(userConfig.Remote)
}

// recordedInstallHostname returns the public Auth Hostname recorded for a remote
// in the installs map (populated by `sc login`), or "" when none is recorded.
func recordedInstallHostname(remote string) string {
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		return ""
	}
	return normalizeAuthHostname(cfg.AuthHostnameForRemote(remote))
}

// installPrefixFromRemotePin derives the install prefix from the enrolled
// remote's pinned Incus project (remotes[<remote>].project in the shared incus
// config). URL-named remotes ("sc-<install-label>", the current naming) carry
// no prefix in the name, but every enrollment pins its remote to one of the
// install's projects — "<prefix>-<tenant>" or "<prefix>-<tenant>-<app>" — so
// the pin identifies the install. Returns "" when the remote has no pin or the
// pin doesn't contain the tenant.
func installPrefixFromRemotePin(remote string, tenantName string) string {
	remote = strings.TrimSpace(remote)
	tenantName = strings.TrimSpace(tenantName)
	if remote == "" || tenantName == "" {
		return ""
	}
	incusDir := resolveIncusDir(remote)
	if incusDir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(incusDir, "config.yml"))
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
	project := strings.TrimSpace(cfg.Remotes[remote].Project)
	if project == "" {
		return ""
	}
	if prefix, ok := strings.CutSuffix(project, "-"+tenantName); ok && prefix != "" {
		return prefix
	}
	if idx := strings.Index(project, "-"+tenantName+"-"); idx > 0 {
		return project[:idx]
	}
	return ""
}

func inferAuthHostnameFromRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}
	incusDir := resolveIncusDir(remote)
	if incusDir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(incusDir, "config.yml"))
	if err != nil {
		return ""
	}
	var cfg struct {
		Remotes map[string]struct {
			Addr string `yaml:"addr"`
		} `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	addr := strings.TrimSpace(cfg.Remotes[remote].Addr)
	if addr == "" {
		return ""
	}
	parsed, err := url.Parse(addr)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	return parsed.Hostname()
}
