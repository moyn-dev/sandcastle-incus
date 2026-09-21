package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/agentskill"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/images"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/localdns"
	"github.com/thieso2/sandcastle-incus/internal/localtrust"
	machine "github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/share"
	"github.com/thieso2/sandcastle-incus/internal/tailscale"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/update"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

// version is the CLI version string. It is a var (not a const) so release
// builds can stamp it via ldflags:
//
//	-X github.com/thieso2/sandcastle-incus/internal/cli.version={{.Version}}
//
// Defaults to a dev sentinel for `go build`/`go test` and un-stamped installs.
var version = "0.0.0-dev"

type outputFormat string

const (
	outputText outputFormat = "text"
	outputJSON outputFormat = "json"
)

type commandConfig struct {
	name            string
	stdin           io.Reader
	stdout          io.Writer
	stderr          io.Writer
	stdinIsTerminal func(io.Reader) bool
	tenantStore     tenant.IncusTenantStore
	adminConfig     scconfig.Admin
	tenantCreator   incusx.TenantCreator
	// tenantMembers maintains Shared Tenant membership and key lists in
	// Tenant Metadata (incusx.TenantCreator in production; a fake in tests).
	tenantMembers      tenantMembershipManager
	projectSettings    projectSettingsUpdater
	projectDeleter     projectDeleter
	tenantDeleter      tenant.Deleter
	imageManager       images.Manager
	imageBuilder       images.Builder
	imageImporter      images.Importer
	imageUploader      images.Uploader
	remoteImageBuilder images.RemoteImageBuilder
	topologyStore      tenant.TopologyStore
	trustManager       usertrust.Manager
	machineStore       machine.Store
	localDNS           localdns.Manager
	tailscale          tailscale.Runner
	localTrust         localtrust.Manager
	authApp            authapp.Runner
	authDevice         authDeviceClient
	authWorkload       authWorkloadClient
	authCloudIdentity  authCloudIdentityClient
	authTenants        authTenantClient
	authProjects       authProjectClient
	authShares         authShareClient
	authRoutes         authRouteClient
	authResources      authResourceClient
	authPublicDNSZones authPublicDNSZoneClient
	// authMachineCertificates overrides the Auth App client `sc create` uses
	// to order a zone-mode machine's certificate (ADR-0027). nil = a
	// DeviceClient for the logged-in Auth Hostname; injected in tests.
	authMachineCertificates authMachineCertificateClient
	// authMachineHostnames overrides the Auth App client `sc create
	// --hostname` and `sc hostname` use for explicit Machine Public
	// Hostnames (ADR-0028). nil = a DeviceClient for the logged-in Auth
	// Hostname; injected in tests.
	authMachineHostnames authMachineHostnameClient
	// authTailnetLegacy removes transition-only Sidecar publications during an
	// explicit migration; nil uses the logged-in Auth App.
	authTailnetLegacy tailnetLegacyClient
	// routeHostResolver overrides the DNS probe `sc route` uses to warn about a
	// missing wildcard. nil = a real lookup; injected in tests so they never
	// touch the network. Mirrors authapp's RouteResolveHost seam.
	routeHostResolver    func(context.Context, string) bool
	shareStore           share.Store
	shareReconciler      tenantShareReconciler
	openBrowser          func(string)
	loginRemote          loginRemoteInstaller
	tenantRemote         tenantRemoteInstaller
	loginTailnet         loginTailnetVerifier
	loginSetup           loginSetupRunner
	loginRemoteProbe     func(context.Context, string) error
	loginTailnetPrecheck func(context.Context) error
	loginRoutingCheck    func(context.Context, io.Writer, string) error
	incusRunner          incusRunner
	gcloudRunner         gcloudRunner
	// skillEnv overrides where `sc skill` and the `sc update` skill refresh
	// resolve agent skill directories (tests point it at a temp home so the
	// real ~/.claude and ~/.codex stay untouched). nil = the real environment.
	skillEnv func() agentskill.Env
}

type tenantShareReconciler interface {
	ReconcileTenantShares(context.Context, tenant.Summary, bool) (share.ReconcileResult, error)
}

type authDeviceClient interface {
	Start(context.Context) (authapp.DeviceStartResult, error)
	Poll(context.Context, string, authapp.DevicePollRequest) (authapp.DevicePollResult, error)
	DebugApprove(context.Context, string) error
	SimulateApprove(ctx context.Context, userCode, username, token string) error
}

type authWorkloadClient interface {
	Start(context.Context) (authapp.DeviceStartResult, error)
	Poll(context.Context, string, authapp.DevicePollRequest) (authapp.DevicePollResult, error)
	DebugApprove(context.Context, string) error
	EnableWorkload(context.Context, authapp.WorkloadEnableRequest) (authapp.WorkloadEnableResult, error)
}

// projectSettingsUpdater persists a v2 project's settings on its Incus project.
type projectSettingsUpdater interface {
	SetProjectCloudIdentity(ctx context.Context, incusProject string, cloudIdentity string) error
	SetProjectDockerAutostart(ctx context.Context, incusProject string, enabled bool) error
	SetProjectImage(ctx context.Context, incusProject string, image string) error
}

// projectDeleter removes one app project of a v2 tenant, with its machines,
// volumes and profiles.
type projectDeleter interface {
	DeleteProjectV2(ctx context.Context, incusProject string, storagePool string) error
}

type authCloudIdentityClient interface {
	UpsertCloudIdentity(context.Context, authapp.CloudIdentityUpsertRequest) (authapp.CloudIdentityConfig, error)
	GetCloudIdentity(context.Context, string, string) (authapp.CloudIdentityConfig, error)
}

type authTenantClient interface {
	ListTenants(context.Context) ([]authapp.TenantAccessSummary, error)
}

// tenantMembershipManager is the admin-plane seam for Shared Tenants.
type tenantMembershipManager interface {
	AddTenantMemberV2(ctx context.Context, installPrefix string, tenantName string, userKey string) ([]string, error)
	RemoveTenantMemberV2(ctx context.Context, installPrefix string, tenantName string, userKey string) ([]string, error)
	AddTenantSSHKeyV2(ctx context.Context, installPrefix string, tenantName string, sshKey string) ([]string, error)
	RemoveTenantSSHKeyV2(ctx context.Context, installPrefix string, tenantName string, sshKey string) ([]string, error)
}

// authResourceClient is the t2 cache-backed GET /api/resources caller `sc ls`
// tries before its live per-project Incus path (internal/cli/list.go). An
// error here — for any reason, network or non-200 — means the caller falls
// back; the interface exists (rather than calling authapp.DeviceClient
// directly) purely so tests can inject a fake without a real HTTP server.
type authResourceClient interface {
	ListResources(context.Context, authapp.ResourceListRequest) (authapp.ResourceListResult, error)
}

// authProjectClient is the token-gated tenant plane for projects: creation
// (with an optional Project Domain, ADR-0027), the domain verbs and deletion.
type authProjectClient interface {
	CreateProject(context.Context, authapp.ProjectCreateRequest) (projectbroker.ProjectResult, error)
	GetProjectDomain(context.Context, string) (authapp.ProjectDomainResult, error)
	SetProjectDomain(ctx context.Context, project, domain string, dryRun bool) (authapp.ProjectDomainResult, error)
	UnsetProjectDomain(ctx context.Context, project string, dryRun bool) (authapp.ProjectDomainResult, error)
	DeleteProject(ctx context.Context, project string, dryRun bool) (authapp.ProjectDomainResult, error)
	SetProjectImage(ctx context.Context, project, image string) (authapp.ProjectImageResult, error)
	RerenderProjectProfiles(ctx context.Context, project string) (authapp.ProjectProfileResult, error)
}

type authRouteClient interface {
	PublishRoute(context.Context, authapp.RoutePublishRequest) (authapp.RouteView, error)
	ListRoutes(context.Context, string) ([]authapp.RouteView, error)
	GetRouteStatus(context.Context, string) (authapp.RouteView, error)
	DeleteRoute(context.Context, string) error
	RouteConfig(context.Context) (authapp.RouteConfigView, error)
}

type authShareClient interface {
	CreateShare(context.Context, authapp.ShareCreateRequest) (share.Result, error)
	ListShares(context.Context, string) ([]meta.TenantStorageShare, error)
	ListInboundShares(context.Context, string) ([]meta.TenantStorageShare, error)
	ListShareOffers(context.Context, string) ([]meta.TenantStorageShare, error)
	GetShare(context.Context, authapp.ShareStatusRequest) (share.Result, error)
	AcceptShare(context.Context, authapp.ShareRecipientRequest) (share.Result, error)
	DeclineShare(context.Context, authapp.ShareRecipientRequest) (share.Result, error)
	RevokeShare(context.Context, authapp.ShareRevokeRequest) (share.Result, error)
	DeleteShare(context.Context, authapp.ShareDeleteRequest) (share.Result, error)
	ReconcileShares(context.Context, authapp.ShareReconcileRequest) (share.ReconcileResult, error)
}

type rootOptions struct {
	output outputFormat
}

// Execute runs the Sandcastle user CLI and returns a process exit code.
// It uses the per-remote Sandcastle Incus config directory (restricted TLS certificate).
// For admin operations use ExecuteAdmin (sandcastle-admin binary).
func Execute(name string, args []string) int {
	adminConfig, loadErr := scconfig.LoadUserWithError()
	if loadErr != nil {
		fmt.Fprintln(os.Stderr, loadErr)
		return 1
	}
	verbose := os.Getenv("VERBOSE") == "1"
	incusx.SetRunningBinaryVersion(version)
	update.DefaultExchange.SetCLIVersion(version)
	refreshedUpdateState := startBackgroundUpdateCheck()

	// Always use the per-remote Sandcastle config dir (restricted cert) for user commands.
	if userPath := scconfig.ResolveConfigPath(adminConfig.Remote); userPath != "" {
		os.Setenv("INCUS_CONF", userPath)
	}

	if verbose {
		incusConf := os.Getenv("INCUS_CONF")
		if incusConf == "" {
			incusConf = "~/.config/incus (default)"
		}
		fmt.Fprintf(os.Stderr, "[verbose] incus config: %s\n[verbose] incus remote: %s\n", incusConf, adminConfig.Remote)
		incusx.SetAPITrace(os.Stderr)
	}
	config := newUserCommandConfig(name, os.Stdin, os.Stdout, os.Stderr, adminConfig)
	cmd := NewRootCommand(config)
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	cmd.SetArgs(args)
	executed, err := cmd.ExecuteContextC(context.Background())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		// Even a partially completed self-update still runs in the old
		// process; its explicit error is more useful than passive skew noise.
		if executed == nil || executed.Name() != "update" {
			maybePrintUpdateNotices(os.Stderr, refreshedUpdateState)
		}
		return 1
	}
	// `sc update` has already printed its authoritative status table. In
	// particular, a self-update cannot change the version of this running
	// process, so a later sidecar request would otherwise produce a misleading
	// CLI↔deployment skew notice after a successful update.
	if executed.Name() != "update" {
		maybePrintUpdateNotices(os.Stderr, refreshedUpdateState)
	}
	// Success only: the skill hint never rides on an error path.
	maybePrintSkillReminder(os.Stderr, cmd, executed, config)
	return 0
}

// newUserCommandConfig builds the user CLI's dependency-injection config with
// every store bound to adminConfig.Remote. Extracted from Execute so the same
// wiring can be rebuilt for another install when a command reference carries a
// "<remote>:" prefix (see rebindForReference).
func newUserCommandConfig(name string, stdin io.Reader, stdout, stderr io.Writer, adminConfig scconfig.Admin) commandConfig {
	verbose := os.Getenv("VERBOSE") == "1"
	remote := adminConfig.Remote
	sharedRemote := incusx.NewSharedRemote(remote).WithVerbose(verbose, stderr)
	config := commandConfig{
		name:               name,
		stdin:              stdin,
		stdout:             stdout,
		stderr:             stderr,
		adminConfig:        adminConfig,
		tenantStore:        incusx.NewTenantStoreForSharedRemote(sharedRemote), // wrapped by the cache below
		tenantCreator:      incusx.NewTenantCreator(remote).WithVerbose(verbose, stderr),
		projectSettings:    incusx.NewTenantCreator(remote).WithVerbose(verbose, stderr),
		tenantDeleter:      incusx.NewTenantDeleter(remote).WithVerbose(verbose, stderr),
		projectDeleter:     incusx.NewTenantDeleter(remote).WithVerbose(verbose, stderr),
		imageManager:       incusx.NewImageManager(remote),
		imageBuilder:       images.LocalBuilder{},
		imageImporter:      images.LocalImporter{},
		imageUploader:      images.LocalUploader{},
		remoteImageBuilder: images.LocalRemoteBuilder{Token: ghcrTokenFromEnv, Stderr: stderr, Verbose: verbose},
		topologyStore:      incusx.NewTopologyStore(remote),
		trustManager:       incusx.NewTrustManager(remote),
		machineStore:       incusx.NewHostOverrideManagerForSharedRemote(sharedRemote),
		localDNS:           localdns.FileManager{},
		tailscale:          incusx.NewTailscaleManager(remote),
		localTrust:         incusx.NewLocalTrustManager(remote, localtrust.NewPlatformStore()),
		openBrowser:        openBrowser,
		loginSetup: realLoginSetupRunner{config: commandConfig{
			stdin:       stdin,
			stdout:      stdout,
			stderr:      stderr,
			adminConfig: adminConfig,
		}},
	}
	// Every command starts by listing projects; serve that from the Auth App
	// cache when logged in (live Incus is the fallback).
	config.tenantStore = newCachedTenantStore(config, config.tenantStore)
	return config
}

// rebindForReference implements the "<remote>:" prefix of the universal
// [[remote:]project:]machine grammar: when a reference's leading segment names
// an ENROLLED remote different from the current one, it rebuilds the command
// config bound to that install (INCUS_CONF + all stores) and returns the
// reference with the prefix stripped, plus a restore func for INCUS_CONF. When
// the leading segment is not an enrolled remote (e.g. "project:machine"), the
// reference is returned untouched — so existing project:machine addressing and
// bare names are unaffected. A prefix naming the current remote is just stripped.
func rebindForReference(base commandConfig, reference string) (commandConfig, string, func(), error) {
	noop := func() {}
	first, rest, ok := strings.Cut(strings.TrimSpace(reference), ":")
	if !ok {
		return base, reference, noop, nil
	}
	first = strings.TrimSpace(first)
	incusDir, _ := scconfig.SharedIncusDirExplained()
	remotes, err := readLocalRemotes(incusDir)
	if err != nil || !remoteNameKnown(remotes, first) {
		// Not an enrolled remote — leave the whole reference (project:machine etc.).
		return base, reference, noop, nil
	}
	if first == strings.TrimSpace(base.adminConfig.Remote) {
		return base, rest, noop, nil
	}
	bound, restore, err := bindConfigToRemote(base, first)
	if err != nil {
		return base, reference, noop, err
	}
	return bound, rest, restore, nil
}

// bindConfigToRemote rebuilds base bound to another enrolled install: it
// re-points the process-wide INCUS_CONF at that remote's config dir (so the
// incus client picks up its restricted certificate), re-pins the project to
// that install's own, and rebuilds every store from the result. The returned
// func unbinds INCUS_CONF and MUST be called — the env var is process-wide, so
// only one install can be bound at a time.
//
// Shared by the "<remote>:" reference prefix (rebindForReference) and the
// remote-glob fan-out (remoteFanout.forEachRemoteScope).
func bindConfigToRemote(base commandConfig, remote string) (commandConfig, func(), error) {
	noop := func() {}
	remote = strings.TrimSpace(remote)
	dir := scconfig.ResolveConfigPath(remote)
	if dir == "" {
		return base, noop, fmt.Errorf("no incus config for remote %q", remote)
	}
	prev, had := os.LookupEnv("INCUS_CONF")
	os.Setenv("INCUS_CONF", dir)
	restore := func() {
		if had {
			os.Setenv("INCUS_CONF", prev)
		} else {
			os.Unsetenv("INCUS_CONF")
		}
	}
	adminConfig := base.adminConfig
	adminConfig.Remote = remote
	if short := shortProjectName(scconfig.SharedIncusRemoteProject(remote), adminConfig.Tenant); short != "" {
		adminConfig.Project = short
	}
	return newUserCommandConfig(base.name, base.stdin, base.stdout, base.stderr, adminConfig), restore, nil
}

// NewRootCommand builds the Sandcastle command tree.
func NewRootCommand(config commandConfig) *cobra.Command {
	if config.name == "" {
		config.name = "sandcastle"
	}
	if config.stdout == nil {
		config.stdout = io.Discard
	}
	if config.stdin == nil {
		config.stdin = strings.NewReader("")
	}
	if config.stderr == nil {
		config.stderr = io.Discard
	}
	if config.tenantStore == nil {
		config.tenantStore = tenant.MemoryStore{}
	}
	var loadErr error
	if config.adminConfig.Remote == "" {
		config.adminConfig, loadErr = scconfig.LoadUserWithError()
	}

	opts := &rootOptions{output: outputText}
	var jsonOutput bool
	root := &cobra.Command{
		Use:           config.name,
		Short:         "Manage Incus-backed Sandcastle development machines",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if loadErr != nil {
				return loadErr
			}
			if !jsonOutput {
				return nil
			}
			if cmd.Root().PersistentFlags().Changed("output") && opts.output != outputJSON {
				return fmt.Errorf("--json cannot be combined with --output %s", opts.output)
			}
			opts.output = outputJSON
			return nil
		},
	}
	root.PersistentFlags().Var(&opts.output, "output", "output format: text or json")
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "write JSON output")

	root.AddCommand(newVersionCommand(config, opts))
	root.AddCommand(newUpdateCommand(config, opts))
	root.AddCommand(newListCommand(config, opts))
	root.AddCommand(newStatusCommand(config, opts))
	root.AddCommand(newInfoCommand(config, opts))
	root.AddCommand(newCreateCommand(config, opts))
	root.AddCommand(newImageCommand(config, opts))
	root.AddCommand(newConnectCommand(config, opts))
	root.AddCommand(newConnectV2Command(config, opts))
	root.AddCommand(newFixCommand(config, opts))
	root.AddCommand(newPayloadSyncCommand(config, opts))
	root.AddCommand(newMachineLifecycleCommand(config, opts, "start", machine.ActionStart, false))
	root.AddCommand(newMachineLifecycleCommand(config, opts, "stop", machine.ActionStop, false))
	root.AddCommand(newMachineLifecycleCommand(config, opts, "restart", machine.ActionRestart, false))
	root.AddCommand(newMachineLifecycleCommand(config, opts, "delete", machine.ActionDelete, true))
	root.AddCommand(newProjectCommand(config, opts))
	root.AddCommand(newHostnameCommand(config, opts))
	root.AddCommand(newDNSCommand(config, opts))
	root.AddCommand(newDNSProxyCommand(config, opts))
	root.AddCommand(newTailscaleCommand(config, opts))
	root.AddCommand(newTrustCommand(config, opts))
	root.AddCommand(newRemoteCommand(config, opts))
	root.AddCommand(newIncusCommand(config, opts))
	root.AddCommand(newIncusInfraCommand(config, opts))
	root.AddCommand(newLoginCommand(config, opts))
	root.AddCommand(newConfigCommand(config, opts))
	root.AddCommand(newSkillCommand(config, opts))
	root.AddCommand(newTenantCommand(config, opts))
	root.AddCommand(newCloudIdentityCommand(config, opts))
	root.AddCommand(newShareCommand(config, opts))
	root.AddCommand(newRouteCommand(config, opts))
	root.AddCommand(newTunnelCommand(config, opts))
	root.AddCommand(newTailnetCommand(config, opts))
	root.AddCommand(newSSHKeyCommand(config, opts))

	return root
}

func (f *outputFormat) Set(value string) error {
	switch outputFormat(value) {
	case outputText, outputJSON:
		*f = outputFormat(value)
		return nil
	default:
		return fmt.Errorf("unsupported output format %q", value)
	}
}

func (f outputFormat) String() string {
	if f == "" {
		return string(outputText)
	}
	return string(f)
}

func (f outputFormat) Type() string {
	return "format"
}

// globalIncusDir returns the directory holding the admin Incus config and its
// servercerts/: INCUS_CONF when set (ExecuteAdmin defaults it to the real
// per-OS dir), then the platform dir, and only then the SDK's hardcoded
// ~/.config/incus. Reading ~/.config/incus unconditionally is what silently
// broke admin-remote detection on macOS, where `incus` keeps its config under
// ~/Library/Application Support/incus and ~/.config/incus does not exist at
// all — the scan below then failed on the very first step, and every admin
// command fell through to "whatever the global default remote is".
func globalIncusDir() string {
	if dir := strings.TrimSpace(os.Getenv("INCUS_CONF")); dir != "" {
		return dir
	}
	if dir := scconfig.PlatformIncusDir(); dir != "" {
		return dir
	}
	return scconfig.NativeIncusDir()
}

// detectAdminRemote finds the global Incus remote (~/.config/incus/) that points to the same
// server as the user's per-remote Sandcastle incus config, by comparing server TLS certificates.
// This is more reliable than address comparison (which can fail when one config uses an IP and
// the other uses a hostname).
func detectAdminRemote(userRemote string, verbose bool) string {
	userDir := scconfig.ResolveConfigPath(userRemote)
	if userDir == "" {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: no per-remote config dir for %q\n", userRemote)
		}
		return ""
	}

	// Read the server certificate stored in the per-remote config dir.
	userCertPath := filepath.Join(userDir, "servercerts", userRemote+".crt")
	userCert, err := os.ReadFile(userCertPath)
	if err != nil || len(userCert) == 0 {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: no server cert at %s, trying address match\n", userCertPath)
		}
		return detectAdminRemoteByAddr(userRemote, userDir, verbose)
	}

	// Load global config to know which remotes actually exist (cert files can be stale).
	globalCfg, err := incusx.LoadCLIConfig("")
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: cannot load global incus config: %v\n", err)
		}
		return ""
	}

	// Scan global incus servercerts/ for a matching certificate.
	globalCertsDir := filepath.Join(globalIncusDir(), "servercerts")
	entries, err := os.ReadDir(globalCertsDir)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: cannot read %s: %v, trying address match\n", globalCertsDir, err)
		}
		return detectAdminRemoteByAddr(userRemote, userDir, verbose)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		remoteName := strings.TrimSuffix(entry.Name(), ".crt")
		// Skip stale cert files that have no corresponding remote in the config.
		if _, ok := globalCfg.Remotes[remoteName]; !ok {
			continue
		}
		globalCert, err := os.ReadFile(filepath.Join(globalCertsDir, entry.Name()))
		if err != nil {
			continue
		}
		if bytes.Equal(userCert, globalCert) {
			return remoteName
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: no active global remote cert matches %s, trying IP address match\n", userCertPath)
	}
	// No active remote has a cert file that matches — fall back to DNS-based IP matching.
	// (This happens when a remote was renamed: the old cert file is orphaned but the server is the same.)
	return detectAdminRemoteByAddr(userRemote, userDir, verbose)
}

// detectAdminRemoteByAddr matches the per-remote user config's server against global config
// remotes using DNS resolution so hostname vs IP differences don't cause mismatches.
func detectAdminRemoteByAddr(userRemote string, userDir string, verbose bool) string {
	userCfg, err := incusx.LoadCLIConfig(filepath.Join(userDir, "config.yml"))
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: cannot load user config from %s: %v\n", userDir, err)
		}
		return ""
	}
	userRemoteInfo, ok := userCfg.Remotes[userRemote]
	if !ok {
		if verbose {
			fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: remote %q not found in %s/config.yml\n", userRemote, userDir)
		}
		return ""
	}
	userHost, userPort := addrHostPort(userRemoteInfo.Addr)
	userIPs := resolveToIPs(userHost)
	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: user remote %s addr=%s resolved=%v\n", userRemote, userRemoteInfo.Addr, userIPs)
	}

	globalCfg, err := incusx.LoadCLIConfig("")
	if err != nil {
		return ""
	}
	for name, remote := range globalCfg.Remotes {
		if strings.HasPrefix(remote.Addr, "unix:") || remote.Public {
			continue
		}
		globalHost, globalPort := addrHostPort(remote.Addr)
		if globalPort != userPort {
			continue
		}
		globalIPs := resolveToIPs(globalHost)
		for _, ip := range globalIPs {
			for _, uip := range userIPs {
				if ip == uip {
					if verbose {
						fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: IP match: %s (%s) == %s (%s)\n", name, ip, userRemote, uip)
					}
					return name
				}
			}
		}
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] admin remote detection: no IP match for %s (IPs: %v)\n", userRemote, userIPs)
	}
	return ""
}

// addrHostPort extracts the host and port from a remote address like https://host:8443.
func addrHostPort(addr string) (host, port string) {
	u, err := url.Parse(addr)
	if err != nil {
		return addr, ""
	}
	h, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		return u.Host, ""
	}
	return h, p
}

// resolveToIPs resolves a hostname to its IP addresses. If the input is already an IP
// or resolution fails, it returns the input unchanged.
func resolveToIPs(host string) []string {
	if net.ParseIP(host) != nil {
		return []string{host}
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return []string{host}
	}
	return addrs
}
