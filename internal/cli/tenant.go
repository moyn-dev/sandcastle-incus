package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/tailscale"
)

type tenantListRow struct {
	Tenant   string `json:"tenant"`
	Personal bool   `json:"personal"`
	Current  bool   `json:"current"`
	// Shared marks a Shared Tenant; Role is "owner" or "member".
	Shared bool   `json:"shared,omitempty"`
	Role   string `json:"role,omitempty"`
}

// tenantRemoteInstaller enrols a Shared Tenant's Incus remote for a member
// (certificate-based: the member's keypair is already trusted, the grant
// extended it with the tenant's projects). Shelled out in production; a fake
// in tests.
type tenantRemoteInstaller interface {
	InstallTenantRemote(ctx context.Context, request tenantRemoteInstallRequest) error
}

type tenantRemoteInstallRequest struct {
	RemoteName   string
	IncusAddress string
	IncusProject string
}

type tenantListOutput struct {
	Tenants []tenantListRow `json:"tenants"`
}

type tenantSwitchOutput struct {
	Tenant     string   `json:"tenant"`
	LocalOnly  bool     `json:"local_only,omitempty"`
	ConfigPath string   `json:"config_path"`
	Message    string   `json:"message"`
	Actions    []string `json:"actions,omitempty"`
}

func newTenantCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:     "tenant",
		Aliases: []string{"t"},
		Short:   "List and select accessible Sandcastle tenants",
	}
	command.AddCommand(newTenantListCommand(config, opts))
	command.AddCommand(newTenantSwitchCommand(config, opts))
	return command
}

func newTenantListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List tenants accessible to the current user",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := tenantClient(config)
			if err != nil {
				return err
			}
			tenants, err := client.ListTenants(cmd.Context())
			if err != nil {
				return err
			}
			output := tenantListOutput{Tenants: tenantListRows(tenants, strings.TrimSpace(config.adminConfig.Tenant))}
			return writeOutput(config.stdout, opts.output, formatTenantAccessList(output), output)
		},
	}
}

func newTenantSwitchCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var localOnly bool
	command := &cobra.Command{
		Use:     "switch tenant",
		Aliases: []string{"sw"},
		Short:   "Select the local Current Tenant",
		Long:    "Select the local Current Tenant. By default this validates Tenant Access through the Auth App; use --local-only to update local config without online validation.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := runTenantSwitch(cmd.Context(), config, strings.TrimSpace(args[0]), localOnly, config.stdout)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatTenantSwitch(result), result)
		},
	}
	command.Flags().BoolVar(&localOnly, "local-only", false, "update local Current Tenant config without Auth App Tenant Access validation")
	return command
}

// runTenantSwitch is `sc tenant switch` without the final output: it validates
// Tenant Access (unless localOnly), enrolls a Shared Tenant's remote when
// needed, and records the tenant in the global config and the nearest
// .sandcastle. Progress notes go to notes. `sc cd` composes it with the other
// switches.
func runTenantSwitch(ctx context.Context, config commandConfig, tenantName string, localOnly bool, notes io.Writer) (tenantSwitchOutput, error) {
	if tenantName == "" {
		return tenantSwitchOutput{}, fmt.Errorf("tenant is required")
	}
	var access authapp.TenantAccessSummary
	if !localOnly {
		var err error
		if access, err = validateTenantAccessForSwitch(ctx, config, tenantName); err != nil {
			return tenantSwitchOutput{}, err
		}
	}
	cfgPath := scconfig.DefaultConfigPath()
	cfg, err := scconfig.LoadSandcastleConfig(cfgPath)
	if err != nil {
		return tenantSwitchOutput{}, fmt.Errorf("load config: %w", err)
	}
	// Shared Tenant, member side: the tenant's machines sit behind ITS
	// sidecar (the Incus Reach), so the member needs an Incus remote at
	// that sidecar's tailnet address, named after the tenant's DNS
	// suffix (ADR-0021) and pinned to its default project. Enrolled once,
	// certificate-based (the grant already extended this keypair), and
	// recorded like a login's remote so `sc remote switch` round-trips.
	enrolled := ""
	switchedRemote := ""
	if access.Member {
		remoteName, err := ensureSharedTenantRemote(ctx, config, &cfg, tenantName, access)
		if err != nil {
			return tenantSwitchOutput{}, err
		}
		enrolled = remoteName
		switchedRemote = remoteName
		cfg.Remote = remoteName
		if access.DefaultProject != "" {
			cfg.Project = access.DefaultProject
		}
		_ = scconfig.SetSharedIncusDefaultRemote(remoteName)
	} else if remote := remoteForTenant(cfg, tenantName); remote != "" && remote != cfg.Remote {
		// A remote already enrolled for this tenant (the owner's login,
		// or an earlier switch): make it the active one so the Incus
		// side follows the Current Tenant.
		applyRemoteSwitch(&cfg, remote)
		repinProjectForRemote(&cfg, remote)
		_ = scconfig.SetSharedIncusDefaultRemote(remote)
		switchedRemote = remote
	}
	cfg.Tenant = tenantName
	if err := scconfig.SaveSandcastleConfig(cfgPath, cfg); err != nil {
		return tenantSwitchOutput{}, fmt.Errorf("save config: %w", err)
	}
	// The tenant is a directory selection like the remote (`.sandcastle`,
	// the file `sc remote switch` writes): record remote, project AND
	// tenant in the nearest selection, creating one here when none
	// exists — otherwise the directory would keep addressing the
	// previous tenant's remote, or the remote's enrolled tenant.
	if !localOnly || switchedRemote != "" {
		local, _, err := scconfig.LoadDirectoryConfig("")
		if err != nil {
			return tenantSwitchOutput{}, err
		}
		if local.RemoteProjects == nil {
			local.RemoteProjects = map[string]string{}
		}
		if local.Remote != "" && local.Project != "" {
			local.RemoteProjects[local.Remote] = local.Project
		}
		local.Remote = firstNonEmptyString(switchedRemote, cfg.Remote, local.Remote)
		local.Project = firstNonEmptyString(cfg.Project, local.RemoteProjects[local.Remote], "default")
		local.Tenant = tenantName
		local.RemoteProjects[local.Remote] = local.Project
		if local.Remote != "" {
			path, err := scconfig.SaveDirectoryConfig(local)
			if err != nil {
				return tenantSwitchOutput{}, fmt.Errorf("save selection: %w", err)
			}
			fmt.Fprintf(notes, "Selection saved in %s (remote %q, project %q, tenant %q).\n", path, local.Remote, local.Project, tenantName)
		}
	}
	if enrolled != "" {
		fmt.Fprintf(notes, "Incus remote %q points at shared tenant %s (project %s).\n", enrolled, tenantName, cfg.Project)
	}
	result := tenantSwitchOutput{
		Tenant:     tenantName,
		LocalOnly:  localOnly,
		ConfigPath: cfgPath,
		Actions:    tenantSwitchSetupActions(ctx, config, tenantName, access.IncusRemoteAddress),
	}
	result.Message = tenantSwitchHint(localOnly, result.Actions)
	return result, nil
}

func tenantClient(config commandConfig) (authTenantClient, error) {
	if config.authTenants != nil {
		return config.authTenants, nil
	}
	if strings.TrimSpace(config.adminConfig.AuthToken) == "" {
		return nil, fmt.Errorf("CLI Auth Token is required; run sc login")
	}
	baseURL := commandAuthHostname(config, "")
	if baseURL == "" {
		return nil, fmt.Errorf("Auth Hostname is required; run sc login")
	}
	return authapp.DeviceClient{BaseURL: baseURL, AuthToken: strings.TrimSpace(config.adminConfig.AuthToken), Tenant: strings.TrimSpace(config.adminConfig.Tenant)}, nil
}

func validateTenantAccessForSwitch(ctx context.Context, config commandConfig, tenantName string) (authapp.TenantAccessSummary, error) {
	client, err := tenantClient(config)
	if err != nil {
		return authapp.TenantAccessSummary{}, err
	}
	tenants, err := client.ListTenants(ctx)
	if err != nil {
		return authapp.TenantAccessSummary{}, err
	}
	for _, candidate := range tenants {
		if candidate.Tenant == tenantName {
			return candidate, nil
		}
	}
	return authapp.TenantAccessSummary{}, fmt.Errorf("tenant %s is not accessible to the current user; use --local-only to update local config without validation", tenantName)
}

// remoteForTenant finds the enrolled remote recorded for a tenant on the
// active install (remote_tenants + installs), "" when none was recorded.
func remoteForTenant(cfg scconfig.SandcastleConfig, tenantName string) string {
	host := normalizeAuthHostname(cfg.AuthHostname)
	fallback := ""
	for remote, recorded := range cfg.RemoteTenants {
		if strings.TrimSpace(recorded) != tenantName {
			continue
		}
		if host != "" && normalizeAuthHostname(cfg.AuthHostnameForRemote(remote)) == host {
			return remote
		}
		if fallback == "" || remote < fallback {
			fallback = remote
		}
	}
	return fallback
}

// ensureSharedTenantRemote enrols (once) and records the member's remote for
// a Shared Tenant; returns the remote name. The remote is named after the
// tenant's DNS suffix like a login's remote (ADR-0021).
func ensureSharedTenantRemote(ctx context.Context, config commandConfig, cfg *scconfig.SandcastleConfig, tenantName string, access authapp.TenantAccessSummary) (string, error) {
	remoteName := strings.TrimSpace(access.DNSSuffix)
	if remoteName == "" {
		remoteName = tenantName
	}
	incusDir, _ := scconfig.SharedIncusDirExplained()
	address := strings.TrimSpace(access.IncusRemoteAddress)
	// Re-point a remote whose recorded address drifted: a sidecar that
	// re-registered on the tailnet gets a new address, and the Auth App
	// reports the live one — the stale node answers nothing but timeouts.
	drifted := false
	if address != "" && remoteExists(incusDir, remoteName) {
		if current, err := remoteAddress(filepath.Join(incusDir, "config.yml"), remoteName); err == nil {
			drifted = strings.TrimSuffix(strings.TrimSpace(current), "/") != "https://"+net.JoinHostPort(address, "8443")
		}
	}
	if cfg.TenantForRemote(remoteName) != tenantName || !remoteExists(incusDir, remoteName) || drifted {
		if address == "" {
			return "", fmt.Errorf("shared tenant %s has no Incus Reach address yet: its sidecar has not joined the tailnet; ask the tenant owner to complete the join (sc login / sc tailscale up), then retry", tenantName)
		}
		if drifted {
			fmt.Fprintf(config.stdout, "Incus remote %q pointed at a previous sidecar address; re-pointing to %s.\n", remoteName, address)
		}
		installer := config.tenantRemote
		if installer == nil {
			installer = incusTenantRemoteInstaller{stdout: config.stdout, stderr: config.stderr}
		}
		fmt.Fprintf(config.stdout, "Enrolling Incus remote %q for shared tenant %s at %s...\n", remoteName, tenantName, address)
		if err := installer.InstallTenantRemote(ctx, tenantRemoteInstallRequest{RemoteName: remoteName, IncusAddress: address, IncusProject: access.IncusProject}); err != nil {
			return "", err
		}
	}
	// The credentials recorded for the shared remote are the CALLER's: the
	// resolved ones (per active remote / directory selection), not the global
	// file's last-login values — on a client with two logins those belong to
	// whoever logged in last, and a later switch would present the wrong
	// user's token.
	token := firstNonEmptyString(config.adminConfig.AuthToken, cfg.AuthToken)
	broker := firstNonEmptyString(config.adminConfig.Broker, cfg.Broker)
	// The Auth Hostname the CLI actually talks to (installs[<active remote>]
	// first), never the top-level config value — that can be a stale
	// placeholder from an old login (auth.example.com), and recording it
	// would make every later switch to this remote ask a host that does not
	// exist.
	authHost := firstNonEmptyString(commandAuthHostname(config, ""), config.adminConfig.AuthHostname, cfg.AuthHostname)
	recordFor(&cfg.RemoteTenants, remoteName, tenantName)
	recordFor(&cfg.RemoteAuthTokens, remoteName, token)
	recordFor(&cfg.RemoteBrokers, remoteName, broker)
	if host := normalizeAuthHostname(authHost); host != "" {
		if cfg.Installs == nil {
			cfg.Installs = map[string]string{}
		}
		cfg.Installs[remoteName] = host
	}
	return remoteName, nil
}

// incusTenantRemoteInstaller adds the remote certificate-based in the shared
// incus config dir (the keypair there is already trusted by the daemon and
// was extended with the tenant's projects by the grant), pins the tenant's
// default project, and re-points an existing same-named remote in place.
type incusTenantRemoteInstaller struct {
	stdout io.Writer
	stderr io.Writer
}

func (i incusTenantRemoteInstaller) InstallTenantRemote(ctx context.Context, request tenantRemoteInstallRequest) error {
	scconfig.AdoptNativeIncusDirIfChosen()
	incusDir, _ := scconfig.SharedIncusDirExplained()
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		return fmt.Errorf("create incus config dir: %w", err)
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir)
	url := "https://" + net.JoinHostPort(request.IncusAddress, "8443")
	var argv []string
	if remoteExists(incusDir, request.RemoteName) {
		argv = []string{"remote", "set-url", request.RemoteName, url}
	} else {
		argv = trustedClientRemoteAddArgs(request.RemoteName, url, request.IncusProject)
	}
	cmd := exec.CommandContext(ctx, "incus", argv...)
	cmd.Env = env
	cmd.Stdout = i.stdout
	var stderr strings.Builder
	cmd.Stderr = io.MultiWriter(i.stderr, &stderr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("incus %s: %w: %s", strings.Join(argv[:2], " "), err, strings.TrimSpace(stderr.String()))
	}
	if p := strings.TrimSpace(request.IncusProject); p != "" {
		if err := setRemoteProject(filepath.Join(incusDir, "config.yml"), request.RemoteName, p); err != nil {
			return fmt.Errorf("pin remote %s to project %s: %w", request.RemoteName, p, err)
		}
	}
	return nil
}

func tenantListRows(tenants []authapp.TenantAccessSummary, currentTenant string) []tenantListRow {
	rows := make([]tenantListRow, 0, len(tenants))
	for _, tenant := range tenants {
		role := "owner"
		if tenant.Member {
			role = "member"
		}
		rows = append(rows, tenantListRow{
			Tenant:   tenant.Tenant,
			Personal: tenant.Personal,
			Current:  tenant.Tenant == currentTenant,
			Shared:   tenant.Shared,
			Role:     role,
		})
	}
	return rows
}

func formatTenantAccessList(output tenantListOutput) string {
	if len(output.Tenants) == 0 {
		return "No accessible tenants"
	}
	var builder strings.Builder
	builder.WriteString("  Tenant\tRole\tPersonal\n")
	for _, tenant := range output.Tenants {
		if tenant.Current {
			builder.WriteString("* ")
		} else {
			builder.WriteString("  ")
		}
		builder.WriteString(tenant.Tenant)
		builder.WriteByte('\t')
		builder.WriteString(tenant.Role)
		builder.WriteByte('\t')
		builder.WriteString(yesNo(tenant.Personal))
		builder.WriteByte('\n')
	}
	return strings.TrimRight(builder.String(), "\n")
}

func formatTenantSwitch(result tenantSwitchOutput) string {
	return fmt.Sprintf("Current Tenant set to %q in %s.\n%s", result.Tenant, result.ConfigPath, result.Message)
}

func tenantSwitchHint(localOnly bool, actions []string) string {
	var prefix string
	if localOnly {
		prefix = "Skipped Auth App Tenant Access validation.\n"
	}
	if len(actions) == 0 {
		return prefix + "No local setup actions needed."
	}
	return prefix + "Local setup actions needed:\n  " + strings.Join(actions, "\n  ")
}

// tenantSwitchSetupActions lists what the user still has to do locally after
// a switch. Only the tailnet matters: private DNS and tenant-CA trust are
// served by Public DNS Zones and real certificates now (the `sc dns setup`
// / `sc trust install` hints were retired). When the switch knows the
// tenant sidecar's tailnet address, reaching it IS the tailnet check — a
// member's restricted certificate cannot read the sidecar's status anyway.
func tenantSwitchSetupActions(ctx context.Context, config commandConfig, tenantName string, sidecarAddress string) []string {
	if address := strings.TrimSpace(sidecarAddress); address != "" {
		if sidecarReachable(address) {
			return nil
		}
		return []string{"sc tailscale up " + tenantName}
	}
	if !tenantSwitchTailscaleReady(ctx, config, tenantName) {
		return []string{"sc tailscale up " + tenantName}
	}
	return nil
}

// sidecarReachable dials the Incus Reach (sidecar tailnet address :8443).
func sidecarReachable(address string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, "8443"), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func tenantSwitchTailscaleReady(ctx context.Context, config commandConfig, tenantName string) bool {
	if config.tenantStore == nil || config.tailscale == nil {
		return false
	}
	plan, err := tailscale.PlanStatus(ctx, config.adminConfig, config.tenantStore, tailscale.StatusRequest{Reference: tenantName})
	if err != nil {
		return false
	}
	result, err := config.tailscale.RunStatus(ctx, plan, tailscale.RunSession{
		Stdin:  config.stdin,
		Stdout: config.stderr,
		Stderr: config.stderr,
	})
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(result.Tailscale.State), "running")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

var _ authTenantClient = authapp.DeviceClient{}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
