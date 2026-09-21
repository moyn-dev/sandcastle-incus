package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"gopkg.in/yaml.v2"
)

func newRemoteCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remote",
		Aliases: []string{"rem"},
		Short:   "Manage Sandcastle remotes",
	}
	cmd.AddCommand(newRemoteAddCommand(config, opts))
	cmd.AddCommand(newRemoteListCommand(config))
	cmd.AddCommand(newRemoteSwitchCommand(config))
	return cmd
}

// newRemoteListCommand lists the enrolled Sandcastle installs (one incus remote
// per install under ADR-0021), marking the active one. The active remote is the
// resolved directory/environment selection — the same value `sc ls`/`sc c` resolve from
// (config.adminConfig.Remote) — so the `*` here always matches what sc operates on.
func newRemoteListCommand(config commandConfig) *cobra.Command {
	var long bool
	command := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List enrolled Sandcastle remotes (installs)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(config.stdout, formatPath(nil))
			cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
			if err != nil {
				fmt.Fprintf(config.stderr, "warning: could not read sandcastle config: %v\n", err)
			}
			incusDir, _ := scconfig.SharedIncusDirExplained()
			remotes, err := readLocalRemotes(incusDir)
			if err != nil {
				return fmt.Errorf("read incus remotes from %s: %w", incusDir, err)
			}
			current := strings.TrimSpace(config.adminConfig.Remote)
			rows := sandcastleRemoteRows(remotes, cfg)
			fmt.Fprintln(config.stdout, selectionSource(config))
			if len(rows) == 0 {
				fmt.Fprintln(config.stdout, "No Sandcastle remotes enrolled. Run `sc login <auth-hostname>` to enroll one.")
				return nil
			}
			if !long {
				for _, r := range rows {
					marker := "  "
					if r.Name == current {
						marker = "* "
					}
					fmt.Fprintln(config.stdout, marker+r.Name)
				}
				return nil
			}
			table := tabwriter.NewWriter(config.stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(table, "\tREMOTE\tPROJECT\tAUTH HOSTNAME")
			for _, r := range rows {
				marker := ""
				if r.Name == current {
					marker = "*"
					r.Project = config.adminConfig.Project
				}
				fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", marker, r.Name, orDash(r.Project), orDash(r.AuthHostname))
			}
			return table.Flush()
		},
	}
	command.Flags().BoolVarP(&long, "long", "l", false, "long listing: REMOTE PROJECT AUTH HOSTNAME table (default: names only)")
	return command
}

// newRemoteSwitchCommand persists only the directory's remote/project selection.
func newRemoteSwitchCommand(config commandConfig) *cobra.Command {
	return &cobra.Command{
		Use:     "switch <name>",
		Aliases: []string{"use"},
		Short:   "Switch the active Sandcastle remote (install)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, project, path, err := switchRemoteSelection(config, strings.TrimSpace(args[0]))
			if err != nil {
				return err
			}
			fmt.Fprintf(config.stdout, "Switched to remote %q (project %q; saved in %s).\n", name, project, path)
			return nil
		},
	}
}

// switchRemoteSelection is `sc remote switch` without the output: it validates
// the remote is enrolled and records it (with its remembered project) in the
// nearest .sandcastle. `sc cd` composes it with the other switches.
func switchRemoteSelection(config commandConfig, name string) (remote string, project string, path string, err error) {
	remote = name
	cfgPath := scconfig.DefaultConfigPath()
	cfg, err := scconfig.LoadSandcastleConfig(cfgPath)
	if err != nil {
		return "", "", "", fmt.Errorf("load config: %w", err)
	}
	// A typo silently pointing sc at a non-existent install is worse than a
	// loud failure, so validate against the enrolled remotes first.
	incusDir, _ := scconfig.SharedIncusDirExplained()
	remotes, err := readLocalRemotes(incusDir)
	if err != nil {
		return "", "", "", fmt.Errorf("read incus remotes from %s: %w", incusDir, err)
	}
	if !remoteNameKnown(remotes, name) {
		known := sandcastleRemoteNames(remotes, cfg)
		hint := "run `sc remote list` to see enrolled installs, or `sc login <auth-hostname>` to enroll"
		if len(known) > 0 {
			hint = "enrolled remotes: " + strings.Join(known, ", ")
		}
		return "", "", "", fmt.Errorf("no enrolled Sandcastle remote %q; %s", name, hint)
	}
	local, err := directorySelection(config)
	if err != nil {
		return "", "", "", err
	}
	cfg.SelectRemote(name)
	project = local.RemoteProjects[name]
	if project == "" {
		project = shortProjectName(scconfig.SharedIncusRemoteProject(name), cfg.Tenant)
	}
	if project == "" {
		project = "default"
	}
	local.Remote, local.Project = name, project
	local.Tenant = strings.TrimSpace(cfg.Tenant)
	local.RemoteProjects[name] = project
	path, err = scconfig.SaveDirectoryConfig(local)
	if err != nil {
		return "", "", "", fmt.Errorf("save selection: %w", err)
	}
	return name, project, path, nil
}

// sandcastleRemoteRow is one row of `sc remote list`.
type sandcastleRemoteRow struct {
	Name         string
	Project      string
	AuthHostname string
}

// sandcastleRemoteRows filters raw incus remotes down to the Sandcastle installs
// — those pinned to a project (every Sandcastle remote is) or recorded in the
// installs map at login — so system remotes (local, images, oci) are excluded.
func sandcastleRemoteRows(remotes []localRemote, cfg scconfig.SandcastleConfig) []sandcastleRemoteRow {
	rows := make([]sandcastleRemoteRow, 0, len(remotes))
	for _, r := range remotes {
		if !isSandcastleRemote(r, cfg) {
			continue
		}
		rows = append(rows, sandcastleRemoteRow{
			Name:         r.Name,
			Project:      strings.TrimSpace(r.Project),
			AuthHostname: cfg.AuthHostnameForRemote(r.Name),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

func sandcastleRemoteNames(remotes []localRemote, cfg scconfig.SandcastleConfig) []string {
	rows := sandcastleRemoteRows(remotes, cfg)
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		names = append(names, r.Name)
	}
	return names
}

// isSandcastleRemote distinguishes an enrolled Sandcastle install from a system
// incus remote (local, images, docker, ghcr): Sandcastle remotes are always
// project-pinned, and also appear in the installs map once logged in.
func isSandcastleRemote(r localRemote, cfg scconfig.SandcastleConfig) bool {
	if strings.TrimSpace(r.Project) != "" {
		return true
	}
	return cfg.AuthHostnameForRemote(r.Name) != ""
}

// repinProjectForRemote sets cfg.Project to the target install's own project,
// derived from that remote's incus project pin (<prefix>-<tenant>-<short>), so
// switching installs doesn't leave a stale pin that makes `sc ls`/`sc c` fail
// ("project X not found in tenant Y"). Returns the short project name it set, or
// "" when the remote has no derivable pin (cfg.Project is then left unchanged).
func repinProjectForRemote(cfg *scconfig.SandcastleConfig, name string) string {
	short := shortProjectName(scconfig.SharedIncusRemoteProject(name), cfg.Tenant)
	if short != "" {
		cfg.Project = short
	}
	return short
}

func remoteNameKnown(remotes []localRemote, name string) bool {
	for _, r := range remotes {
		if r.Name == name {
			return true
		}
	}
	return false
}

// remoteSwitchEffects records what re-pointed when the active remote changed, so
// `sc remote switch` and `sc config set remote` report the switch identically.
type remoteSwitchEffects struct {
	AuthHostname  string
	Broker        string
	BrokerCleared bool
	TokenSynced   bool
	TokenCleared  bool
	Tenant        string
}

// applyRemoteSwitch points cfg at the install named by `name`: it sets cfg.Remote
// and re-points the auth hostname, broker, and CLI auth token to that install
// (recovered from the installs/brokers/auth_tokens maps recorded at login), so
// the Incus remote and the Auth App never drift apart on a host running several
// installs that share one tenant name (ADR-0021: the remote names the install).
// The caller persists cfg and switches the shared incus current-remote.
func applyRemoteSwitch(cfg *scconfig.SandcastleConfig, name string) remoteSwitchEffects {
	before := *cfg
	cfg.SelectRemote(name)
	fx := remoteSwitchEffects{
		BrokerCleared: before.Broker != "" && cfg.Broker == "",
		TokenCleared:  before.AuthToken != "" && cfg.AuthToken == "",
		TokenSynced:   cfg.AuthToken != "" && cfg.AuthToken != before.AuthToken,
	}
	if cfg.AuthHostname != before.AuthHostname {
		fx.AuthHostname = cfg.AuthHostname
	}
	if cfg.Tenant != before.Tenant {
		fx.Tenant = cfg.Tenant
	}
	if cfg.Broker != before.Broker {
		fx.Broker = cfg.Broker
	}

	return fx
}

func printRemoteSwitchEffects(w io.Writer, cfg scconfig.SandcastleConfig, fx remoteSwitchEffects) {
	// These are re-pointing details behind the switch — noise for the common case.
	// Only surface them in verbose mode; the "Switched to remote" line is enough.
	if os.Getenv("VERBOSE") != "1" {
		return
	}
	if fx.AuthHostname != "" {
		fmt.Fprintf(w, "Auth hostname re-pointed to %q for this install.\n", fx.AuthHostname)
	}
	if fx.Broker != "" {
		fmt.Fprintf(w, "Broker re-pointed to %q for this install.\n", fx.Broker)
	}
	if fx.BrokerCleared {
		fmt.Fprintf(w, "Broker cleared: none recorded for this install. Run `sc login %s` to record it.\n", cfg.AuthHostname)
	}
	if fx.Tenant != "" {
		fmt.Fprintf(w, "Tenant re-pointed to %q for this remote.\n", fx.Tenant)
	}
	if fx.TokenSynced {
		fmt.Fprintln(w, "Auth token switched to this install's token.")
	}
	if fx.TokenCleared {
		fmt.Fprintf(w, "Auth token cleared: none recorded for this install. Run `sc login %s` to sign in.\n", cfg.AuthHostname)
	}
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func newRemoteAddCommand(config commandConfig, _ *rootOptions) *cobra.Command {
	var tenant string
	cmd := &cobra.Command{
		Use:   "add <name> <join-token>",
		Short: "Add a Sandcastle remote using an Incus join token",
		Long: `Add a Sandcastle remote.

<join-token> is the token produced by "sandcastle-admin user create" (or
"incus config trust add --generate-certificate" on the server). The token
already contains the server address — no separate address argument is needed.

Incus certs are stored in ~/.config/sandcastle/<name>/incus/ and the remote
is saved as the default in ~/.config/sandcastle/config.yml.

Use --tenant to also set your default tenant name in one step:

  sc remote add sc-acme JOIN_TOKEN --tenant acme`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := addIncusRemoteWithToken(cmd.Context(), remoteAddIO{
				stdin:  config.stdin,
				stdout: config.stdout,
				stderr: config.stderr,
			}, args[0], args[1], tenant, "", "")
			if err != nil {
				return err
			}
			if result.DefaultRemoteSet {
				fmt.Fprintf(config.stdout, "Default remote set to %q\n", result.RemoteName)
			}
			fmt.Fprintf(config.stdout, "Remote %q added. Incus config: %s\n", result.RemoteName, result.IncusConfig)
			if result.Tenant != "" {
				fmt.Fprintf(config.stdout, "Default tenant set to %q\n", result.Tenant)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "Set the default tenant name in ~/.config/sandcastle/config.yml")
	return cmd
}

type remoteAddIO struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

type remoteAddResult struct {
	RemoteName       string
	IncusConfig      string
	Tenant           string
	DefaultRemoteSet bool
}

type incusLoginRemoteInstaller struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (i incusLoginRemoteInstaller) InstallLoginRemote(ctx context.Context, request loginRemoteInstallRequest) (loginRemoteInstallResult, error) {
	result, err := addIncusRemoteWithToken(ctx, remoteAddIO{stdin: i.stdin, stdout: i.stdout, stderr: i.stderr}, request.RemoteName, request.Token, request.Tenant, request.IncusAddress, request.IncusProject)
	if err != nil {
		return loginRemoteInstallResult{}, err
	}
	return loginRemoteInstallResult{RemoteName: result.RemoteName, IncusConfig: result.IncusConfig, Tenant: result.Tenant}, nil
}

// addIncusRemoteWithToken redeems the join token into a per-remote Incus config.
// When incusAddress is set (the sidecar's tailnet IP — ADR-0017), the remote URL
// is pinned to https://<addr>:8443 so the connection rides the tenant tailnet via
// the sidecar proxy; otherwise the address the token advertised is normalized.
func addIncusRemoteWithToken(ctx context.Context, ioConfig remoteAddIO, name string, joinToken string, tenant string, incusAddress string, incusProject string) (remoteAddResult, error) {
	// ONE shared incus config dir for every enrollment: the client keypair in
	// it is the shared identity across installs, and each install is just a
	// remote (`incus remote switch sc-id-<tenant>`). Never wipe the dir —
	// other installs' remotes and the shared keypair live here; replace only
	// THIS remote. The dir is auto-detected (native ~/.config/incus when free,
	// else the dedicated Sandcastle dir); adopt + announce the choice.
	scconfig.AdoptNativeIncusDirIfChosen()
	incusDir, reason := scconfig.SharedIncusDirExplained()
	fmt.Fprintf(ioConfig.stdout, "Incus config: %s\n", reason)
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		return remoteAddResult{}, fmt.Errorf("create incus config dir: %w", err)
	}

	env := append(os.Environ(), "INCUS_CONF="+incusDir)
	// Re-enrolling replaces an existing remote, but the replacement can fail —
	// notably when this daemon already trusts our keypair and no tailnet address
	// is known for the certificate-based fallback below (a SECOND user logging in
	// to the same install from this client). Removing first would then leave the
	// client with no remote at all and every `sc list`/`sc c` broken. So rename
	// the current remote aside and only drop the backup once the new one is in.
	backupName := ""
	if remoteExists(incusDir, name) {
		switchAway := exec.CommandContext(ctx, "incus", "remote", "switch", "local")
		switchAway.Env = env
		_ = switchAway.Run()
		backupName = name + "-sandcastle-previous"
		if remoteExists(incusDir, backupName) {
			staleCmd := exec.CommandContext(ctx, "incus", "remote", "remove", backupName)
			staleCmd.Env = env
			_ = staleCmd.Run()
		}
		renameCmd := exec.CommandContext(ctx, "incus", "remote", "rename", name, backupName)
		renameCmd.Env = env
		renameCmd.Stderr = ioConfig.stderr
		if err := renameCmd.Run(); err != nil {
			return remoteAddResult{}, fmt.Errorf("set aside existing remote %s: %w", name, err)
		}
	}
	// restoreBackup puts the previous remote back when enrollment fails, so a
	// failed re-enrollment is a no-op rather than a lockout.
	restoreBackup := func(cause error) (remoteAddResult, error) {
		if backupName == "" {
			return remoteAddResult{}, cause
		}
		renameBack := exec.CommandContext(ctx, "incus", "remote", "rename", backupName, name)
		renameBack.Env = env
		if err := renameBack.Run(); err != nil {
			return remoteAddResult{}, fmt.Errorf("%w (restoring the previous remote %q also failed: %v; recover with `incus remote rename %s %s`)", cause, name, err, backupName, name)
		}
		fmt.Fprintf(ioConfig.stderr, "Enrollment failed; kept the existing remote %q.\n", name)
		return remoteAddResult{}, cause
	}
	dropBackup := func() {
		if backupName == "" {
			return
		}
		dropCmd := exec.CommandContext(ctx, "incus", "remote", "remove", backupName)
		dropCmd.Env = env
		_ = dropCmd.Run()
		backupName = ""
	}
	addCmd := exec.CommandContext(ctx, "incus", "remote", "add", name, joinToken)
	addCmd.Env = env
	// The join token embeds the sidecar Incus's own https address, which is on the
	// tenant's PRIVATE CIDR — a client that hasn't accepted the tenant subnet route
	// can't reach it, so `incus remote add` prompts "provide alternate server
	// addresses". We already know the sidecar's tailnet endpoint (incusAddress),
	// which every tenant-tailnet client can reach directly, so answer that prompt
	// automatically instead of failing. Falls back to the caller's stdin when no
	// tailnet address is known (v1 / non-sidecar remotes).
	if addr := strings.TrimSpace(incusAddress); addr != "" {
		// The prompt parses each entry as a URL, so it must carry a scheme —
		// a bare host:port fails with "first path segment in URL cannot contain
		// colon".
		addCmd.Stdin = strings.NewReader("https://" + net.JoinHostPort(addr, "8443") + "\n")
	} else {
		addCmd.Stdin = ioConfig.stdin
	}
	addCmd.Stdout = ioConfig.stdout
	var addErr strings.Builder
	addCmd.Stderr = io.MultiWriter(ioConfig.stderr, &addErr)
	if err := addCmd.Run(); err != nil {
		// Shared client identity: when this daemon already trusts our keypair
		// (enrolled by another install on the same host), token redemption is
		// refused with "Client is already trusted" — provisioning has already
		// unioned this install's projects into the trust entry, so add the
		// remote certificate-based (with the SAME project pin) instead.
		if !strings.Contains(addErr.String(), "already trusted") {
			return restoreBackup(fmt.Errorf("incus remote add: %w", err))
		}
		// The sidecar's tailnet address is preferred (ADR-0017), but it is only
		// known once the sidecar has joined the tailnet. Before this fell back to
		// the addresses the token itself advertises, a login whose sidecar had not
		// joined yet died here with a bare `incus remote add: exit status 1`.
		urls := trustedClientRemoteURLs(incusAddress, joinToken)
		if len(urls) == 0 {
			return restoreBackup(fmt.Errorf("this client is already trusted by the daemon, and no address is known to reach it: %w", err))
		}
		added := false
		var lastErr error
		for _, url := range urls {
			certAdd := exec.CommandContext(ctx, "incus", trustedClientRemoteAddArgs(name, url, incusProject)...)
			certAdd.Env = env
			var certErr strings.Builder
			certAdd.Stdout = ioConfig.stdout
			certAdd.Stderr = io.MultiWriter(ioConfig.stderr, &certErr)
			if err := certAdd.Run(); err != nil {
				lastErr = fmt.Errorf("%s: %s", url, strings.TrimSpace(certErr.String()))
				continue
			}
			added = true
			break
		}
		if !added {
			return restoreBackup(fmt.Errorf("incus remote add (trusted client): %w", lastErr))
		}
	}
	dropBackup()

	switchCmd := exec.CommandContext(ctx, "incus", "remote", "switch", name)
	switchCmd.Env = env
	switchCmd.Stdout = ioConfig.stdout
	switchCmd.Stderr = ioConfig.stderr
	if err := switchCmd.Run(); err != nil {
		return remoteAddResult{}, fmt.Errorf("incus remote switch: %w", err)
	}
	if strings.TrimSpace(incusAddress) != "" {
		// Pin the remote at the sidecar's tailnet endpoint; the sidecar proxies it
		// to the host's Incus. Skip the token-address normalization entirely.
		url := "https://" + net.JoinHostPort(strings.TrimSpace(incusAddress), "8443")
		setURLCmd := exec.CommandContext(ctx, "incus", "remote", "set-url", name, url)
		setURLCmd.Env = env
		setURLCmd.Stderr = ioConfig.stderr
		if err := setURLCmd.Run(); err != nil {
			return remoteAddResult{}, fmt.Errorf("incus remote set-url %s: %w", url, err)
		}
	} else if err := normalizeRemoteURL(ctx, name, incusDir, env, ioConfig.stderr); err != nil {
		return remoteAddResult{}, err
	}

	// Pin the remote to this install's default project by writing it into the
	// incus config — no server round-trip (the shared trust cert unions
	// several installs' projects, so the server-side default is ambiguous and
	// `incus list` could otherwise read the other install's project on the
	// shared host daemon).
	if p := strings.TrimSpace(incusProject); p != "" {
		if err := setRemoteProject(filepath.Join(incusDir, "config.yml"), name, p); err != nil {
			return remoteAddResult{}, fmt.Errorf("pin remote %s to project %s: %w", name, p, err)
		}
	}

	cfgPath := scconfig.DefaultConfigPath()
	defaultRemoteSet, tenant, err := saveRemoteDefaults(cfgPath, name, tenant)
	if err != nil {
		return remoteAddResult{}, err
	}
	return remoteAddResult{RemoteName: name, IncusConfig: incusDir, Tenant: tenant, DefaultRemoteSet: defaultRemoteSet}, nil
}

// trustedClientRemoteAddArgs builds the `incus remote add` argv for the
// shared-identity fallback: when this daemon already trusts our keypair (another
// install on the same host enrolled it), the token is refused and we add the
// remote certificate-based instead. The trusted cert can see several installs'
// projects, so without an explicit --project `incus remote add` prompts
// interactively ("Name of the project to use for this remote:") and fails on EOF
// in any non-interactive login. Pin this install's project up front.
func trustedClientRemoteAddArgs(name string, url string, incusProject string) []string {
	args := []string{"remote", "add", name, url, "--auth-type=tls", "--accept-certificate"}
	if p := strings.TrimSpace(incusProject); p != "" {
		args = append(args, "--project", p)
	}
	return args
}

// setRemoteProject writes remotes[name].project into an incus config.yml,
// preserving the rest of the file's remotes/aliases/defaults.
func setRemoteProject(configPath string, name string, project string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	remotes, _ := doc["remotes"].(map[any]any)
	if remotes == nil {
		if m, ok := doc["remotes"].(map[string]any); ok {
			remotes = map[any]any{}
			for k, v := range m {
				remotes[k] = v
			}
			doc["remotes"] = remotes
		}
	}
	if remotes == nil {
		return fmt.Errorf("no remotes in %s", configPath)
	}
	entry, _ := remotes[name].(map[any]any)
	if entry == nil {
		return fmt.Errorf("remote %s not found in %s", name, configPath)
	}
	entry["project"] = project
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, out, 0o600)
}

func remoteExists(incusDir string, name string) bool {
	data, err := os.ReadFile(filepath.Join(incusDir, "config.yml"))
	if err != nil {
		return false
	}
	var config struct {
		Remotes map[string]any `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return false
	}
	_, ok := config.Remotes[name]
	return ok
}

func saveRemoteDefaults(cfgPath string, name string, tenant string) (bool, string, error) {
	cfg, err := scconfig.LoadSandcastleConfig(cfgPath)
	if err != nil {
		return false, "", fmt.Errorf("load sandcastle config: %w", err)
	}
	defaultRemoteSet := false
	if cfg.Remote != name {
		cfg.Remote = name
		defaultRemoteSet = true
	}
	if tenant != "" {
		cfg.Tenant = tenant
	}
	if err := scconfig.SaveSandcastleConfig(cfgPath, cfg); err != nil {
		return false, "", fmt.Errorf("save sandcastle config: %w", err)
	}
	return defaultRemoteSet, cfg.Tenant, nil
}

func normalizeRemoteURL(ctx context.Context, name string, incusDir string, env []string, stderr io.Writer) error {
	configPath := filepath.Join(incusDir, "config.yml")
	certPath := filepath.Join(incusDir, "servercerts", name+".crt")
	normalized, ok, err := normalizedRemoteURL(configPath, name, certPath)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	setURLCmd := exec.CommandContext(ctx, "incus", "remote", "set-url", name, normalized)
	setURLCmd.Env = env
	setURLCmd.Stderr = stderr
	if err := setURLCmd.Run(); err != nil {
		return fmt.Errorf("incus remote set-url: %w", err)
	}
	return nil
}

func normalizedRemoteURL(configPath string, name string, certPath string) (string, bool, error) {
	addr, err := remoteAddress(configPath, name)
	if err != nil {
		return "", false, err
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return "", false, fmt.Errorf("parse remote address %q: %w", addr, err)
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		return "", false, nil
	}
	if net.ParseIP(host) == nil {
		return "", false, nil
	}
	dnsName, err := firstCertificateDNSName(certPath)
	if err != nil {
		return "", false, err
	}
	if dnsName == "" {
		return "", false, nil
	}
	parsed.Host = net.JoinHostPort(dnsName, port)
	return parsed.String(), true, nil
}

func remoteAddress(configPath string, name string) (string, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read incus config: %w", err)
	}
	var cfg struct {
		Remotes map[string]struct {
			Addr string `yaml:"addr"`
		} `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return "", fmt.Errorf("parse incus config: %w", err)
	}
	remote, ok := cfg.Remotes[name]
	if !ok {
		return "", fmt.Errorf("remote %q not found in incus config", name)
	}
	return remote.Addr, nil
}

func firstCertificateDNSName(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read remote server certificate: %w", err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return "", fmt.Errorf("parse remote server certificate: missing PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse remote server certificate: %w", err)
	}
	for _, name := range cert.DNSNames {
		name = strings.TrimSpace(name)
		if name != "" {
			return name, nil
		}
	}
	return "", nil
}

// trustedClientRemoteURLs lists the endpoints to try when the daemon already
// trusts this client's keypair and therefore refuses to redeem the join token.
// The sidecar's tailnet address (ADR-0017) comes first when known; the token's
// own advertised addresses are the fallback, so a login whose sidecar has not
// joined the tailnet yet can still enroll.
func trustedClientRemoteURLs(incusAddress string, joinToken string) []string {
	var urls []string
	seen := map[string]bool{}
	add := func(url string) {
		if url == "" || seen[url] {
			return
		}
		seen[url] = true
		urls = append(urls, url)
	}
	if addr := strings.TrimSpace(incusAddress); addr != "" {
		add("https://" + net.JoinHostPort(addr, "8443"))
	}
	for _, address := range incusTokenAddresses(joinToken) {
		add("https://" + strings.TrimSpace(address))
	}
	return urls
}
