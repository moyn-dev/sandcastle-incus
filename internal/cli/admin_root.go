package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/images"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/localtrust"
	"github.com/thieso2/sandcastle-incus/internal/svclog"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

// ExecuteAdmin runs the Sandcastle admin CLI and returns a process exit code.
// It uses the global Incus config with admin TLS certificates. INCUS_CONF is
// not pinned to a Sandcastle dir; when unset it is defaulted to the real
// per-OS incus config dir (os.UserConfigDir()/incus — ~/.config/incus on Linux,
// ~/Library/Application Support/incus on macOS) so admin remotes resolve
// without the operator exporting INCUS_CONF.
func ExecuteAdmin(name string, args []string) int {
	adminConfig := scconfig.LoadAdmin()
	verbose := os.Getenv("VERBOSE") == "1"
	incusx.SetRunningBinaryVersion(version)

	// Admin commands use the global Incus config (admin TLS certs) via the OS
	// default INCUS_CONF. The SDK's built-in default is ~/.config/incus, which
	// is wrong on macOS, where `incus` stores its config under os.UserConfigDir
	// (~/Library/Application Support/incus) — so a bare `sc-adm`/`sc admin`
	// there finds no admin remotes and falls back to the "local" unix socket
	// ("Can't connect to a local server on a non-Linux system"). When
	// INCUS_CONF is unset, point it at the dir the real `incus` CLI uses so
	// remote resolution below reads the actual admin config. No-op on Linux
	// (UserConfigDir == ~/.config) and where no such config exists.
	if strings.TrimSpace(os.Getenv("INCUS_CONF")) == "" {
		if dir := scconfig.PlatformIncusDir(); dir != "" {
			os.Setenv("INCUS_CONF", dir)
			if verbose {
				fmt.Fprintf(os.Stderr, "[verbose] INCUS_CONF defaulted to native incus config dir: %s\n", dir)
			}
		}
	}

	explicitRemote := strings.TrimSpace(os.Getenv("SANDCASTLE_REMOTE")) != "" || strings.TrimSpace(adminConfig.AdminRemote) != ""

	// activeInstall is the Sandcastle install the USER CLI is pointed at —
	// resolved exactly the way `sc ls` resolves it (scconfig.LoadUser, which
	// prefers directory selection, with global defaults as fallback). Admin
	// commands must act on that same install: `sc admin update` following a
	// different deployment than `sc ls` lists is how an operator updates the
	// wrong sandcastle without noticing. Skipped entirely when the operator
	// named a remote explicitly — an explicit choice always wins.
	activeInstall := ""
	if !explicitRemote {
		userConfig, err := scconfig.LoadUserWithError()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		activeInstall = strings.TrimSpace(userConfig.Remote)
	}

	// Prefer explicit admin_remote; then cert/IP-based auto-detection; then the
	// remote that actually hosts the active install; only then the global Incus
	// default remote.
	adminRemote := adminConfig.AdminRemote
	if adminRemote == "" && !explicitRemote {
		adminRemote = detectAdminRemote(adminConfig.Remote, verbose)
		if verbose && adminRemote != "" {
			fmt.Fprintf(os.Stderr, "[verbose] admin remote auto-detected: %s\n", adminRemote)
		}
	}
	if adminRemote == "" && activeInstall != "" {
		// Cert/address matching cannot resolve a v2 install: the user remote
		// points at the tenant sidecar on the tailnet, not at the Incus host
		// (ADR-0017). Ask each enrolled admin remote which installs it hosts
		// instead — the install name is the identifier both planes share.
		adminRemote = incusx.FindRemoteHostingInstall(activeInstall, verboseLogger(verbose))
		if adminRemote != "" && verbose {
			fmt.Fprintf(os.Stderr, "[verbose] admin remote %q hosts the active install %q\n", adminRemote, activeInstall)
		}
	}
	if adminRemote == "" && !explicitRemote {
		if globalCfg, err := incusx.LoadCLIConfig(""); err == nil {
			adminRemote = globalCfg.DefaultRemote
			if adminRemote != "" {
				// Always visible, not just under VERBOSE: this is a guess, and
				// the guess may well be a different deployment than the one the
				// user CLI is on. Every admin command downstream then reports
				// what it found there ("targeting install X…") in a tone that
				// reads like confirmation, so the uncertainty has to be said
				// out loud here or it is never said at all.
				fmt.Fprintf(os.Stderr, "warning: could not tell which Incus remote hosts %s; falling back to the global incus default remote %q. "+
					"Set SANDCASTLE_REMOTE (or admin_remote in config.yml) to be sure.\n",
					describeActiveInstall(activeInstall), adminRemote)
			}
		}
	}
	if adminRemote != "" {
		adminConfig.Remote = adminRemote
	}
	adminConfig.ActiveInstall = activeInstall
	// INCUS_CONF is not pinned to a Sandcastle dir → the global incus config
	// (admin certs) applies, defaulted above to the real per-OS incus dir.

	if verbose {
		incusConf := os.Getenv("INCUS_CONF")
		if incusConf == "" {
			incusConf = "~/.config/incus (default)"
		}
		fmt.Fprintf(os.Stderr, "[verbose] incus config: %s\n[verbose] incus remote: %s\n", incusConf, adminConfig.Remote)
		incusx.SetAPITrace(os.Stderr)
	}

	sharedRemote := incusx.NewSharedRemote(adminConfig.Remote).WithVerbose(verbose, os.Stderr)
	authAppTenants := incusx.NewTenantStoreForSharedRemote(sharedRemote)
	authAppMachines := incusx.NewHostOverrideManagerForSharedRemote(sharedRemote)
	authAppCreator := incusx.NewTenantCreator(adminConfig.Remote).WithVerbose(verbose, os.Stderr)
	authAppDeleter := incusx.NewTenantDeleter(adminConfig.Remote).WithVerbose(verbose, os.Stderr)
	authAppTrust := incusx.NewTrustManager(adminConfig.Remote)
	authAppSSHKeys := incusx.NewMachineSSHKeyReconciler(adminConfig.Remote, authAppMachines)
	authAppMetadataUpdater := incusx.TenantSSHKeyManager{Remote: adminConfig.Remote}
	authAppShareReconciler := incusx.NewShareReconciler(adminConfig.Remote, authAppMachines)
	authAppShareReconciler.Admin = adminConfig
	adminShareStore := incusx.NewTenantSSHKeyManagerWithPool(adminConfig.Remote, adminConfig.StoragePool)
	adminShareReconciler := incusx.NewShareReconciler(adminConfig.Remote, incusx.NewHostOverrideManagerForSharedRemote(sharedRemote))
	adminShareReconciler.Admin = adminConfig
	var authAppSocketServer incus.InstanceServer
	// Declared as the authapp interface (not incusx.ResourceCacheServer) and
	// left nil outside the branch below: a zero-value incusx.ResourceCacheServer{}
	// assigned unconditionally would box into a non-nil interface even with a
	// nil inner server, defeating HTTPRunner's `ResourceCacheServer != nil` gate.
	var authAppResourceCache authapp.ResourceCacheServer
	// Same nil-interface care for the Public DNS Zone reconciler seam
	// (ADR-0027 §4): only the serving appliance runs it.
	var authAppZoneMachines authapp.ZoneMachineServer
	var authAppTailnetPublisher authapp.TailnetPublisher
	if authAppServeArgs(args) {
		if socketServer, err := adminSocketServer(); err == nil && socketServer != nil {
			authAppSocketServer = socketServer
			authAppTenants = incusx.NewTenantStoreForServer(socketServer)
			zoneMachines := incusx.NewZoneMachineServer(socketServer, authAppTenants, adminConfig.IncusProjectPrefix)
			authAppZoneMachines = zoneMachines
			authAppTailnetPublisher = zoneMachines
			authAppMachines = incusx.NewHostOverrideManagerForServer(socketServer)
			authAppCreator = incusx.NewTenantCreatorForServer(socketServer).WithVerbose(verbose, os.Stderr)
			authAppDeleter = incusx.NewTenantDeleterForServer(socketServer).WithVerbose(verbose, os.Stderr)
			authAppTrust = incusx.NewTrustManagerForServer(socketServer)
			authAppSSHKeys = incusx.NewMachineSSHKeyReconcilerForServer(socketServer, authAppMachines)
			authAppMetadataUpdater = incusx.NewTenantSSHKeyManagerForServer(socketServer)
			authAppShareReconciler = incusx.NewShareReconcilerForServer(socketServer, authAppMachines, authAppMetadataUpdater, adminConfig)
			adminShareStore = authAppMetadataUpdater
			adminShareReconciler = incusx.NewShareReconcilerForServer(socketServer, incusx.NewHostOverrideManagerForServer(socketServer), adminShareStore, adminConfig)
			authAppResourceCache = incusx.NewResourceCacheServer(socketServer).WithVerbose(verbose, os.Stderr)
		} else if err != nil && verbose {
			fmt.Fprintf(os.Stderr, "[verbose] auth app unix socket unavailable: %v\n", err)
		}
	}

	// Public Routes (Spec #111) are available when native-ACME route ingress is
	// enabled — either SANDCASTLE_ROUTE_INGRESS=acme (Caddy binds host :80/:443)
	// or =acme-proxied (an upstream SNI proxy owns the host ports and forwards
	// here). Both terminate route TLS in this appliance's Caddy, and both are
	// independent of the Auth Hostname's own ingress mode — so routes can coexist
	// with a Cloudflare-tunnelled login host. Otherwise `sc route` returns a clear
	// "no public ingress" error.
	var authAppRoutes authapp.RouteBackend
	var authAppRouteCaddy authapp.CaddyController
	if authAppSocketServer != nil && routeIngressEnabled(os.Getenv("SANDCASTLE_ROUTE_INGRESS")) {
		v2Prefix := installV2Prefix(adminConfig.IncusProjectPrefix)
		// A shared front (an sc-edge holding the host ports) is told which route
		// hostnames to forward by the auth-app itself; a bad value is fatal here
		// rather than silently unpublished.
		front, frontErr := incusx.ParseFrontTarget(os.Getenv("SANDCASTLE_ROUTE_FRONT"))
		if frontErr != nil {
			fmt.Fprintln(os.Stderr, frontErr)
			return 1
		}
		authAppRoutes = incusx.RouteBackend{
			Server:          authAppSocketServer,
			MachinePrefix:   adminConfig.IncusProjectPrefix,
			AuthAppInstance: v2Prefix + "-auth-app",
			AuthAppProject:  v2Prefix + "-infra",
			Front:           front,
		}
		authAppRouteCaddy = authapp.LocalCaddyController{}
	}

	cmd := NewAdminRootCommand(commandConfig{
		name:               name,
		stdin:              os.Stdin,
		stdout:             os.Stdout,
		stderr:             os.Stderr,
		adminConfig:        adminConfig,
		tenantStore:        incusx.NewTenantStoreForSharedRemote(sharedRemote),
		tenantCreator:      incusx.NewTenantCreator(adminConfig.Remote).WithVerbose(verbose, os.Stderr),
		projectSettings:    incusx.NewTenantCreator(adminConfig.Remote).WithVerbose(verbose, os.Stderr),
		tenantDeleter:      incusx.NewTenantDeleter(adminConfig.Remote).WithVerbose(verbose, os.Stderr),
		projectDeleter:     incusx.NewTenantDeleter(adminConfig.Remote).WithVerbose(verbose, os.Stderr),
		imageManager:       incusx.NewImageManager(adminConfig.Remote),
		imageBuilder:       images.LocalBuilder{},
		imageImporter:      images.LocalImporter{},
		imageUploader:      images.LocalUploader{},
		remoteImageBuilder: images.LocalRemoteBuilder{Token: ghcrTokenFromEnv, Stderr: os.Stderr, Verbose: verbose},
		topologyStore:      incusx.NewTopologyStore(adminConfig.Remote),
		trustManager:       incusx.NewTrustManager(adminConfig.Remote),
		localTrust:         incusx.NewLocalTrustManager(adminConfig.Remote, localtrust.NewPlatformStore()),
		machineStore:       incusx.NewHostOverrideManagerForSharedRemote(sharedRemote),
		tailscale:          incusx.NewTailscaleManager(adminConfig.Remote),
		authApp: authapp.HTTPRunner{
			Version:          version,
			Sidecars:         incusx.SidecarSelfUpdater{Creator: authAppCreator, Admin: adminConfig},
			RestrictedUsers:  authAppTrust,
			Admin:            adminConfig,
			Tenants:          authAppTenants,
			TenantAccess:     authAppTrust,
			Machines:         authAppMachines,
			MachineSSHKeys:   authAppSSHKeys,
			TenantSSHKeys:    authAppMetadataUpdater,
			MachineSSHAccess: authAppSSHKeys,
			ShareStore:       authAppMetadataUpdater,
			ShareReconciler:  authAppShareReconciler,
			DNSReconcile: func(ctx context.Context) error {
				if authAppSocketServer == nil {
					return nil // no mounted socket (not the serving appliance) — nothing to reconcile
				}
				return authAppDNSReconciler(authAppSocketServer, authAppTenants, adminConfig.IncusProjectPrefix).Reconcile(ctx)
			},
			ZoneMachines:     authAppZoneMachines,
			TailnetPublisher: authAppTailnetPublisher,
			Projects: incusx.ProjectBrokerCreator{
				Creator: authAppCreator,
				Trust:   authAppTrust,
				Prefix:  adminConfig.IncusProjectPrefix,
			},
			// The Project Domain seam (ADR-0027): the same scaffolder, plus a
			// deleter for the tenant-plane DELETE /api/projects/{name}.
			ProjectDomains: incusx.ProjectBrokerCreator{
				Creator: authAppCreator,
				Trust:   authAppTrust,
				Prefix:  adminConfig.IncusProjectPrefix,
				Deleter: &authAppDeleter,
			},
			DNSEvents: func(ctx context.Context, notify func()) {
				if authAppSocketServer == nil {
					return
				}
				subscribeInstanceLifecycleEvents(ctx, authAppSocketServer, notify)
			},
			Routes:            authAppRoutes,
			RouteCaddy:        authAppRouteCaddy,
			ACMEEmail:         strings.TrimSpace(os.Getenv("SANDCASTLE_AUTH_ACME_EMAIL")),
			AuthIngressMode:   strings.TrimSpace(os.Getenv("SANDCASTLE_AUTH_INGRESS_MODE")),
			RouteBaseDomain:   strings.TrimSpace(os.Getenv("SANDCASTLE_ROUTE_BASE_DOMAIN")),
			RouteIngress:      strings.TrimSpace(os.Getenv("SANDCASTLE_ROUTE_INGRESS")),
			RouteCNAMETarget:  strings.TrimSpace(os.Getenv("SANDCASTLE_ROUTE_CNAME_TARGET")),
			RouteTLS:          strings.TrimSpace(os.Getenv("SANDCASTLE_ROUTE_TLS")),
			RouteDNSProvider:  strings.TrimSpace(os.Getenv("SANDCASTLE_ROUTE_DNS_PROVIDER")),
			RouteDNSWildcards: splitCommaList(os.Getenv("SANDCASTLE_ROUTE_DNS_WILDCARDS")),
			RouteEvents: func(ctx context.Context, notify func()) {
				if authAppSocketServer == nil {
					return
				}
				subscribeInstanceLifecycleEvents(ctx, authAppSocketServer, notify)
			},
			Provisioner: authapp.Provisioner{
				Admin:   adminConfig,
				Tenants: authAppTenants,
				Trust:   authAppTrust,
				// Login provisioning creates the tenant's default project +
				// sidecar directly over the mounted host socket (the auth app
				// has it, like the broker).
				V2Create: authAppV2Create(adminConfig, authAppCreator),
			},
			ResourceCacheEnabled:         resourceCacheEnabled(os.Getenv("SANDCASTLE_RESOURCE_CACHE")),
			ResourceCacheServer:          authAppResourceCache,
			ResourceCacheMachineRenderer: incusx.MachineFromInstance,
		},
		shareStore:      adminShareStore,
		shareReconciler: adminShareReconciler,
	})
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// routeIngressEnabled reports whether SANDCASTLE_ROUTE_INGRESS turns Public
// Routes on. Both native-ACME modes qualify: "acme" (the appliance owns the
// host :80/:443) and "acme-proxied" (an upstream SNI proxy forwards them here).
// They differ only in who binds the host ports at deploy time — the serving side
// is identical, so the route wiring keys off either.
func routeIngressEnabled(value string) bool {
	mode := strings.TrimSpace(value)
	return strings.EqualFold(mode, incusx.IngressACME) || strings.EqualFold(mode, incusx.IngressACMEProxied)
}

// resourceCacheEnabled reports whether the Auth App's event-bus-fed Incus
// resource cache (docs/shape/admin-server-config-toggled-event-bus-ca8marg.md)
// should start. It defaults to ON — opt-out, not opt-in — matching the shape
// doc's decision: once a deployment upgrades to a binary with the cache, `sc
// ls` is meant to benefit from it automatically. An operator sets
// SANDCASTLE_RESOURCE_CACHE to one of the disabling values below to fall back
// to today's live per-project-query behavior everywhere.
func resourceCacheEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "off", "disable", "disabled":
		return false
	default:
		return true
	}
}

// verboseLogger adapts the admin tree's verbose flag to the func(string) sink
// incusx helpers take, so their progress lines land on stderr under VERBOSE=1
// and cost nothing otherwise. The sink writes messages verbatim — incusx
// callers format their own "[verbose] …\n" line (see incusx/api_log.go), so
// adding a prefix here would double it.
func verboseLogger(verbose bool) func(string) {
	if !verbose {
		return nil
	}
	return func(message string) {
		fmt.Fprint(os.Stderr, message)
	}
}

// describeActiveInstall renders the subject of the "could not tell which
// remote hosts this" warning. Naming the install is far more useful than the
// generic phrasing, but the user CLI may not be enrolled anywhere at all (a
// pure operator workstation), in which case there is no install to name.
func describeActiveInstall(activeInstall string) string {
	if strings.TrimSpace(activeInstall) == "" {
		return "the active Sandcastle install"
	}
	return fmt.Sprintf("the active Sandcastle install %q", activeInstall)
}

func authAppServeArgs(args []string) bool {
	if len(args) < 2 {
		return false
	}
	return args[0] == "auth-app" && args[1] == "serve"
}

// authAppV2Create returns the login-provisioning closure. The closure creates
// the tenant's default project + sidecar directly over the mounted host socket;
// the sidecar image comes from the plan (SANDCASTLE_BASE_IMAGE).
func authAppV2Create(admin scconfig.Admin, creator incusx.TenantCreator) func(context.Context, tenant.CreatePlanV2, string) (authapp.V2CreateResult, error) {
	return func(ctx context.Context, plan tenant.CreatePlanV2, tailscaleAuthKey string) (authapp.V2CreateResult, error) {
		// The tenant's own key wins (BYO tailnet); the service-level key is an
		// optional default for single-user deployments. Both empty is fine —
		// the sidecar starts an interactive join and the login URL flows back.
		key := strings.TrimSpace(tailscaleAuthKey)
		if key == "" {
			key = strings.TrimSpace(admin.AuthTailscaleAuthKey)
		}
		// Name the sidecar's tailnet device after the install + tenant
		// (sc-<install>-<tenant>), so it is globally unique on the tailnet even
		// though the Incus instance is a plain project-scoped "sidecar". The
		// install label comes from the Auth Hostname (the same URL the client's
		// Incus remote is named after); empty auth hostname → the creator falls
		// back to the infra project name.
		var tailnetHostname string
		if remote := usertrust.RemoteNameForAuthHostname(admin.AuthHostname); remote != "" {
			tailnetHostname = remote + "-" + plan.Tenant
		}
		// Stream the tenant bring-up's per-phase progress into svclog so it lands
		// in the login's /logs view (ctx carries the request record from the
		// device poll). Each c.log phase becomes a message entry for this user.
		c := creator
		c.Log = func(msg string) { svclog.Logf(ctx, "%s", msg) }
		var result authapp.V2CreateResult
		err := c.CreateTenantV2(ctx, plan, incusx.CreateV2Options{
			TailscaleAuthKey:       key,
			SidecarTailnetHostname: tailnetHostname,
			OnSidecarTailnetIP:     func(ip string) { result.SidecarTailnetIP = ip },
			OnTailscaleLoginURL:    func(url string) { result.TailscaleLoginURL = url },
		})
		return result, err
	}
}

// NewAdminRootCommand builds the Sandcastle admin command tree with all admin
// subcommands promoted to the top level (no "admin" prefix).
func NewAdminRootCommand(config commandConfig) *cobra.Command {
	if config.name == "" {
		config.name = "sandcastle-admin"
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
	if config.adminConfig.Remote == "" {
		config.adminConfig = scconfig.LoadAdmin()
	}
	if config.tenantStore == nil {
		config.tenantStore = tenant.MemoryStore{}
	}

	opts := &rootOptions{output: outputText}
	var jsonOutput bool
	root := &cobra.Command{
		Use:           config.name,
		Short:         "Manage Sandcastle shared infrastructure and user accounts",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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

	root.AddCommand(newAdminVersionCommand(config, opts))
	root.AddCommand(newAdminUpdateCommand(config))
	root.AddCommand(newAdminMachineListCommand(config, opts))
	root.AddCommand(newAdminTenantCommand(config, opts))
	root.AddCommand(newAdminUserCommand(config, opts))
	root.AddCommand(newAdminImageCommand(config, opts))
	root.AddCommand(newAdminTLDCommand(config, opts))
	root.AddCommand(newAdminProjectCommand(config, opts))
	root.AddCommand(newAdminBootstrapCommand(config))
	root.AddCommand(newAdminInstallCommand(config))
	root.AddCommand(newAdminInstallIncusCommand(config))
	root.AddCommand(newAdminAuthAppCommand(config))
	root.AddCommand(newPublicDNSZoneCommand(config, opts))
	root.AddCommand(newAdminMachineWorkloadCommand(config, opts))
	root.AddCommand(newConfigCommand(config, opts))
	root.AddCommand(newSidecarCommand())

	return root
}

// adminSocketServer connects to the local Incus unix socket. It was named
// routeBrokerSocketServer when the v1 route broker was its first caller; the
// auth-app serve path is now the only one.
func adminSocketServer() (incus.InstanceServer, error) {
	if _, err := os.Stat("/var/lib/incus/unix.socket"); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	server, err := incus.ConnectIncusUnix("/var/lib/incus/unix.socket", nil)
	if err != nil {
		return nil, err
	}
	return incusx.TraceInstanceServer(server), nil
}
