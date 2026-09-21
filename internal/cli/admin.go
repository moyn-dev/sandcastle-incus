package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"context"
	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/domain"
	"github.com/thieso2/sandcastle-incus/internal/images"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/share"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
	_ "modernc.org/sqlite"
	"slices"
	"sort"
)

func newAdminCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	admin := &cobra.Command{
		Use:   "admin",
		Short: "Run Sandcastle administrator commands",
	}
	admin.AddCommand(newAdminVersionCommand(config, opts))
	admin.AddCommand(newAdminTenantCommand(config, opts))
	admin.AddCommand(newAdminUserCommand(config, opts))
	admin.AddCommand(newAdminImageCommand(config, opts))
	admin.AddCommand(newAdminTLDCommand(config, opts))
	admin.AddCommand(newAdminAuthAppCommand(config))
	admin.AddCommand(newPublicDNSZoneCommand(config, opts))
	return admin
}

func newAdminVersionCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Sandcastle admin command version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			payload := versionPayload{Name: config.name, Version: version}
			return writeOutput(config.stdout, opts.output, version, payload)
		},
	}
}

func newAdminTenantCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "tenant",
		Short: "Manage Sandcastle tenants",
	}
	command.AddCommand(newAdminTenantListCommand(config, opts))
	command.AddCommand(newAdminTenantStatusCommand(config, opts))
	command.AddCommand(newAdminTenantCreateV2Command(config, opts))
	command.AddCommand(newAdminTenantDeleteCommand(config, opts))
	command.AddCommand(newAdminTenantGrantCommand(config, opts))
	command.AddCommand(newAdminTenantRevokeCommand(config, opts))
	command.AddCommand(newAdminTenantUsersCommand(config, opts))
	command.AddCommand(newAdminTenantSetSSHKeyCommand(config))
	command.AddCommand(newAdminTenantAddSSHKeyCommand(config))
	command.AddCommand(newAdminTenantRemoveSSHKeyCommand(config))
	command.AddCommand(newAdminTenantPayloadSyncCommand(config, opts))
	return command
}

func newAdminTenantListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list [tenant]",
		Short: "List Sandcastle tenants, or all resources in a specific tenant",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenants, err := listTenants(cmd.Context(), config.tenantStore)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				payload := tenantListPayload{Tenants: tenants}
				return writeOutput(config.stdout, opts.output, formatTenantList(tenants), payload)
			}
			ref := strings.TrimSpace(args[0])
			// Listing every install's tenants is useful; resolving ONE by name is
			// not — scope it, or a same-named tenant of another install wins.
			scoped, err := tenant.ListForPrefix(cmd.Context(), config.tenantStore, config.adminConfig.IncusProjectPrefix)
			if err != nil {
				return err
			}
			var summary tenant.Summary
			found := false
			for _, t := range scoped {
				if t.Tenant == ref {
					summary = t
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("Sandcastle tenant %s not found", ref)
			}
			if config.machineStore == nil {
				return fmt.Errorf("machine metadata store is not configured")
			}
			machines, unmanaged, err := listMachinesAndUnmanaged(cmd.Context(), config.machineStore, summary, "")
			if err != nil {
				return err
			}
			result := tenantResourcesPayload{
				Tenant:    summary,
				Machines:  machines,
				Unmanaged: unmanaged,
			}
			return writeOutput(config.stdout, opts.output, formatTenantResources(result), result)
		},
	}
}

func newAdminTenantStatusCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "status tenant",
		Short: "Show Sandcastle tenant status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Several installs share one Incus daemon, so a same-named tenant may
			// exist once per install. Scope to THIS install's prefix, or
			// `sc-adm tenant status e2edns` reports the other install's tenant.
			status, err := tenant.GetStatusWithTopologyForPrefix(
				cmd.Context(),
				config.tenantStore,
				config.topologyStore,
				tenant.TopologyRequest{},
				args[0],
				config.adminConfig.IncusProjectPrefix,
			)
			if err != nil {
				return err
			}
			// Tenant Storage Shares are not yet supported on v2 (#70); no share
			// health is reported.
			return writeOutput(config.stdout, opts.output, formatTenantStatus(status), status)
		},
	}
}

func newAdminTenantCreateV2Command(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	var sshKeys []string
	var members []string
	var tailscaleAuthKey string
	var sidecarImage string
	var cidrPool string
	var unixUser string
	var dnsSuffix string
	var initialProject string
	var broker, brokerCert, brokerKey string
	command := &cobra.Command{
		Use:   "create tenant",
		Short: "Create a Sandcastle tenant",
		Long: "Create a Sandcastle tenant. A tenant with --member is a Shared Tenant: each member " +
			"must already have logged in to this install (their Personal Tenant carries the login SSH key " +
			"the shared machines authorize); members then run `sc tenant switch <tenant>`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sshKey := strings.Join(sshKeys, "\n")
			memberList := meta.ParseMembers(strings.Join(members, ","))
			// Broker plane: route the create through the broker's admin API
			// instead of opening a direct Incus connection (ADR-0016).
			if strings.TrimSpace(broker) != "" {
				certFile, keyFile := adminClientCert(brokerCert, brokerKey)
				var result struct {
					Tenant, InfraProject, DefaultProject, Bridge, DNSSuffix, Token string
					RemoteName                                                     string
					TailscaleLoginURL                                              string
				}
				if err := brokerPost(cmd.Context(), broker, "/v2/tenants", certFile, keyFile, map[string]string{
					"tenant":           args[0],
					"sshPublicKey":     sshKey,
					"tailscaleAuthKey": tailscaleAuthKey,
					"members":          strings.Join(memberList, ","),
					"dnsSuffix":        strings.TrimSpace(dnsSuffix),
				}, &result); err != nil {
					return err
				}
				fmt.Fprintf(config.stdout, "Tenant: %s\nInfra project: %s\nDefault project: %s\nBridge: %s\nDNS suffix: %s\n",
					result.Tenant, result.InfraProject, result.DefaultProject, result.Bridge, result.DNSSuffix)
				if result.Token != "" {
					remoteName := result.RemoteName
					if remoteName == "" {
						remoteName = usertrust.RemoteInstallName("", result.Tenant)
					}
					fmt.Fprintf(config.stdout, "\nEnrollment:\n  sc enroll %s --token %s --remote-name %s\n", result.Tenant, result.Token, remoteName)
				}
				printTailscaleLoginURL(config.stdout, result.TailscaleLoginURL)
				return nil
			}
			admin := config.adminConfig
			var reuse tenant.ProvisionReuse
			if config.tenantStore != nil {
				var err error
				if reuse, err = tenant.ProvisionReuseInputs(cmd.Context(), config.tenantStore, admin.IncusProjectPrefix, args[0]); err != nil {
					return fmt.Errorf("list allocated CIDRs: %w", err)
				}
			}
			// The pool the tenant's /24 comes from: an explicit flag, else the
			// configured pool (SANDCASTLE_CIDR_POOL / seed), else the /16 this
			// install's existing tenants already occupy — so a create on a
			// running install lands beside its siblings without the operator
			// having to look the pool up — and only then the built-in default.
			admin.CIDRPool = resolveTenantCIDRPool(cidrPool, admin.CIDRPool, reuse.OccupiedCIDRs)
			if strings.TrimSpace(cidrPool) == "" {
				fmt.Fprintf(config.stderr, "CIDR pool: %s\n", admin.CIDRPool)
			}
			plan, err := tenant.PlanCreateV2(admin, tenant.CreateRequest{
				Reference:              args[0],
				SSHPublicKey:           sshKey,
				UnixUser:               unixUser,
				OccupiedCIDRs:          reuse.OccupiedCIDRs,
				PreferredCIDR:          reuse.OwnCIDR,
				DNSSuffix:              dnsSuffix,
				ExistingDNSSuffix:      reuse.DNSSuffix,
				InitialProject:         strings.TrimSpace(initialProject),
				ExistingDefaultProject: reuse.DefaultProject,
				ExistingUnixUser:       reuse.UnixUser,
				ExistingSSHKey:         reuse.SSHPublicKey,
				ExistingProjects:       reuse.Projects,
				Members:                memberList,
				ExistingMembers:        reuse.Members,
			})
			if err != nil {
				return err
			}
			// Shared Tenant prerequisite: every member has a Personal Tenant on
			// this install — that is where their login SSH key comes from. A
			// missing member is refused up front rather than producing machines
			// nobody can log in to. A shared tenant with no key of its own is
			// fine: the members' keys are the authorized set.
			if len(plan.Members) > 0 && config.tenantStore != nil {
				missing, err := missingMemberTenants(cmd.Context(), config.tenantStore, admin.IncusProjectPrefix, plan.Members)
				if err != nil {
					return err
				}
				if len(missing) > 0 {
					return fmt.Errorf("member(s) %s have no Personal Tenant on this install; they must run `sc login` here first", strings.Join(missing, ", "))
				}
			} else if len(plan.Members) == 0 && strings.TrimSpace(plan.SSHPublicKey) == "" {
				return fmt.Errorf("--ssh-key is required (or --member for a Shared Tenant, whose members' keys are used)")
			}
			if dryRun {
				return writeOutput(config.stdout, opts.output, formatCreatePlanV2(plan), plan)
			}
			creator := config.tenantCreator
			var tailscaleLoginURL string
			if err := creator.CreateTenantV2(cmd.Context(), plan, incusx.CreateV2Options{
				TailscaleAuthKey:    strings.TrimSpace(tailscaleAuthKey),
				SidecarImage:        strings.TrimSpace(sidecarImage),
				OnTailscaleLoginURL: func(u string) { tailscaleLoginURL = u },
			}); err != nil {
				return err
			}
			// Shared Tenant: each member's existing restricted certificate (from
			// their own login) is extended with the tenant's projects; the
			// enrollment token below is only for a tenant-named identity.
			for _, member := range plan.Members {
				if config.trustManager == nil {
					break
				}
				memberPlan, err := usertrust.PlanTenantGrant(admin, usertrust.TenantAccessRequest{
					Tenant: plan.Tenant, User: member, AppProjects: []string{plan.DefaultProjectShort},
				})
				if err != nil {
					return err
				}
				if err := usertrust.GrantMember(cmd.Context(), config.trustManager, admin, memberPlan, member); err != nil {
					fmt.Fprintf(config.stderr, "Warning: could not extend %s's certificate with %s: %v\n", member, plan.Tenant, err)
					continue
				}
				fmt.Fprintf(config.stdout, "Member %s granted %v; they can now run: sc tenant switch %s\n", member, memberPlan.Projects, plan.Tenant)
			}
			// Mint a restricted Incus Certificate Add Token scoped to the tenant's
			// projects. The tenant redeems it with their own client, so the private
			// key never leaves them (ADR-0016).
			if config.trustManager != nil && len(plan.Members) == 0 {
				tok, err := config.trustManager.CreateToken(cmd.Context(), usertrust.UserPlan{
					User:            plan.Tenant,
					CertificateName: usertrust.RestrictedInstallName(plan.Prefix, plan.Tenant),
					RemoteName:      usertrust.RemoteInstallName(plan.Prefix, plan.Tenant),
					Restricted:      true,
					Projects:        plan.RestrictedProjects,
					Description:     "Sandcastle v2 tenant " + plan.Tenant,
				})
				if err != nil {
					fmt.Fprintf(config.stderr, "Warning: trust token creation failed: %v\n", err)
				} else {
					fmt.Fprintf(config.stdout, "\nTenant enrollment (restricted to %v):\n  sc enroll %s --token %s --remote-name %s\n",
						tok.Projects, plan.Tenant, tok.Token, tok.RemoteName)
				}
			}
			printTailscaleLoginURL(config.stdout, tailscaleLoginURL)
			return writeOutput(config.stdout, opts.output, formatCreatePlanV2(plan), plan)
		},
	}
	command.Flags().StringArrayVar(&sshKeys, "ssh-key", nil, "SSH public key baked into the tenant's default project profile (repeatable; the first is the tenant's own login key)")
	command.Flags().StringArrayVar(&members, "member", nil, "GitHub username granted Tenant Access to this Shared Tenant (repeatable; each must have logged in to this install already)")
	command.Flags().StringVar(&tailscaleAuthKey, "tailscale-authkey", "", "the tenant's Tailscale auth key (joins the sidecar to the tenant's tailnet)")
	command.Flags().StringVar(&sidecarImage, "sidecar-image", "", "system-container base image (alias or fingerprint) for the sidecar; defaults to the configured base")
	command.Flags().StringVar(&cidrPool, "cidr-pool", "", "CIDR pool to allocate the tenant's /24 from (default: the configured pool, else the /16 this install's tenants already occupy, else 10.249.0.0/16)")
	command.Flags().StringVar(&unixUser, "unix-user", "", "login user baked into the default-project profile (default \"dev\"); matches the login path's client username")
	command.Flags().StringVar(&dnsSuffix, "dns-suffix", "", "Tenant DNS Suffix — the single-label final part of machine hostnames <machine>.<project>.<suffix> (default: the tenant name; immutable once created)")
	command.Flags().StringVar(&initialProject, "initial-project", "", "name for the tenant's initial project — the middle part of machine hostnames <machine>.<project>.<suffix> (default: default)")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the v2 plan without mutating Incus")
	command.Flags().StringVar(&broker, "broker", "", "route through the Sandcastle Broker admin API (e.g. https://big.thieso2.dev:9443) instead of direct Incus")
	command.Flags().StringVar(&brokerCert, "broker-cert", "", "admin client cert for the broker (default: admin incus config)")
	command.Flags().StringVar(&brokerKey, "broker-key", "", "admin client key for the broker (default: admin incus config)")
	return command
}

func newAdminProjectCreateV2Command(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "create tenant project",
		Short: "Create a project for a tenant (broker scaffolding)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			creator := config.tenantCreator
			result, err := creator.CreateProjectV2(cmd.Context(), config.adminConfig.IncusProjectPrefix, args[0], args[1])
			if err != nil {
				return err
			}
			banner := fmt.Sprintf("Tenant: %s\nProject: %s\nIncus project: %s\nBridge: %s\nDNS suffix: %s",
				result.Tenant, result.Project, result.IncusProject, result.Bridge, result.DNSSuffix)
			return writeOutput(config.stdout, opts.output, banner, result)
		},
	}
	return command
}

// newAdminProjectDeleteV2Command is the only working path to delete a v2 app
// project: the tenant plane exposes POST /api/projects but no delete, and a
// tenant's restricted certificate may not delete an Incus project.
func newAdminProjectDeleteV2Command(config commandConfig, opts *rootOptions) *cobra.Command {
	var yes bool
	command := &cobra.Command{
		Use:   "delete tenant project",
		Short: "Delete a project of a tenant (machines, volumes, profiles, Incus project)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				confirmed, err := confirmMissingYes(config, fmt.Sprintf("Delete project %s of tenant %s, with its machines and volumes?", args[1], args[0]), "refusing to delete project without --yes")
				if err != nil {
					return err
				}
				if !confirmed {
					return fmt.Errorf("delete canceled")
				}
			}
			summaries, err := tenant.ListForPrefix(cmd.Context(), config.tenantStore, config.adminConfig.IncusProjectPrefix)
			if err != nil {
				return err
			}
			summary, ok := findTenantSummaryForCleanup(summaries, args[0])
			if !ok {
				return fmt.Errorf("Sandcastle tenant %s not found", args[0])
			}
			if args[1] == naming.DefaultProjectName {
				return fmt.Errorf("refusing to delete the default project of tenant %s; delete the tenant instead", summary.Tenant)
			}
			incusProject := summary.V2IncusProjectName(args[1])
			if config.projectDeleter == nil {
				return fmt.Errorf("project deleter is not configured")
			}
			if err := config.projectDeleter.DeleteProjectV2(cmd.Context(), incusProject, config.adminConfig.StoragePool); err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, "deleted project "+args[1]+" ("+incusProject+")", map[string]string{
				"tenant": summary.Tenant, "project": args[1], "incusProject": incusProject,
			})
		},
	}
	command.Flags().BoolVar(&yes, "yes", false, "confirm project deletion")
	return command
}

func newAdminBootstrapCommand(config commandConfig) *cobra.Command {
	var baseImage, sidecarImage, binaryPath, bridge, storagePool, hostname, cidrPool, port string
	command := &cobra.Command{
		Use:   "bootstrap",
		Short: "Deploy the Sandcastle broker as an appliance on the Incus host (ADR-0016)",
		Long: "Run once on (or against) the Incus host. Launches the broker appliance with the host " +
			"admin unix socket mounted, so the broker talks to Incus with full rights over that socket — " +
			"no TLS/remote/cert for the server side. Exposes the broker on the host port (:9443).",
		RunE: func(cmd *cobra.Command, args []string) error {
			creator := config.tenantCreator
			if strings.TrimSpace(binaryPath) == "" {
				exe, err := os.Executable()
				if err != nil {
					return fmt.Errorf("resolve sandcastle-admin binary (pass --binary): %w", err)
				}
				binaryPath = exe
			}
			if strings.TrimSpace(sidecarImage) == "" {
				sidecarImage = strings.TrimSpace(baseImage)
			}
			if err := creator.BootstrapV2(cmd.Context(), incusx.BootstrapV2Request{
				BaseImage:    strings.TrimSpace(baseImage),
				BinaryPath:   strings.TrimSpace(binaryPath),
				Bridge:       strings.TrimSpace(bridge),
				StoragePool:  strings.TrimSpace(storagePool),
				Hostname:     strings.TrimSpace(hostname),
				CIDRPool:     strings.TrimSpace(cidrPool),
				SidecarImage: strings.TrimSpace(sidecarImage),
				PublicPort:   strings.TrimSpace(port),
			}); err != nil {
				return err
			}
			fmt.Fprintf(config.stdout, "broker deployed: %s (project %s)\nreach it at https://%s:%s\n",
				incusx.BrokerInstanceName, incusx.BrokerProjectName, hostname, port)
			return nil
		},
	}
	command.Flags().StringVar(&baseImage, "base-image", incusx.DefaultApplianceImage, "system-container base image (a stock systemd image; the fat binary is copied in)")
	command.Flags().StringVar(&sidecarImage, "sidecar-image", "", "system-container base for tenant sidecars (default: --base-image)")
	command.Flags().StringVar(&binaryPath, "binary", "", "path to the sandcastle-admin binary to push (default: this binary)")
	command.Flags().StringVar(&bridge, "bridge", "incusbr0", "bridge the appliance NIC attaches to")
	command.Flags().StringVar(&storagePool, "storage-pool", "default", "storage pool for the appliance root disk")
	command.Flags().StringVar(&hostname, "hostname", "", "broker DNS name (cert SAN + reported URL)")
	command.Flags().StringVar(&cidrPool, "cidr-pool", "10.249.0.0/16", "v2 CIDR pool the broker allocates tenant /24s from")
	command.Flags().StringVar(&port, "port", "9443", "host port to expose the broker on")
	return command
}

func newAdminProjectCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "project",
		Short: "Admin project operations (v2)",
	}
	command.AddCommand(newAdminProjectCreateV2Command(config, opts))
	command.AddCommand(newAdminProjectDeleteV2Command(config, opts))
	command.AddCommand(newAdminProjectBrokerServeCommand(config))
	return command
}

func newAdminProjectBrokerServeCommand(config commandConfig) *cobra.Command {
	var listen, certFile, keyFile, sidecarImage string
	command := &cobra.Command{
		Use:   "broker-serve",
		Short: "Run the Sandcastle broker (tenant + admin plane over :9443; ADR-0016)",
		RunE: func(cmd *cobra.Command, args []string) error {
			creator := config.tenantCreator
			handler := projectbroker.Handler{
				// tenant plane
				Trust:   incusx.NewRouteBrokerTrustMapper(config.adminConfig.Remote),
				Creator: incusx.ProjectBrokerCreator{Creator: creator, Trust: config.trustManager, Prefix: config.adminConfig.IncusProjectPrefix},
				// admin plane
				Admin: incusx.NewAdminAuthorizer(config.adminConfig.Remote),
				Provisioner: incusx.TenantProvisionerAdapter{
					Creator:      creator,
					Trust:        config.trustManager,
					Admin:        config.adminConfig,
					SidecarImage: strings.TrimSpace(sidecarImage),
					Tenants:      config.tenantStore,
				},
				Sidecars: incusx.SidecarSelfUpdater{Creator: creator, Admin: config.adminConfig},
				Version:  version,
			}
			fmt.Fprintf(config.stderr, "broker listening on %s (tenant + admin plane)\n", listen)
			return projectbroker.Serve(cmd.Context(), projectbroker.ServePlan{
				Address: listen, CertFile: certFile, KeyFile: keyFile,
			}, handler)
		},
	}
	command.Flags().StringVar(&listen, "listen", ":9443", "broker listen address")
	command.Flags().StringVar(&certFile, "cert", "", "broker TLS certificate file")
	command.Flags().StringVar(&keyFile, "key", "", "broker TLS key file")
	command.Flags().StringVar(&sidecarImage, "sidecar-image", "", "system-container base image for tenant sidecars (admin plane)")
	return command
}

// printTailscaleLoginURL surfaces the sidecar's interactive Tailscale login URL
// (set only when the tenant was created without a --tailscale-authkey) so the
// operator can register the sidecar into their tailnet.
func printTailscaleLoginURL(w io.Writer, url string) {
	if strings.TrimSpace(url) == "" {
		return
	}
	fmt.Fprintf(w, "\nTailscale: no auth key was given, so the sidecar is not on a tailnet yet.\n"+
		"Register it by opening this URL and approving the machine:\n  %s\n"+
		"Then re-run this same command once: it completes the Incus Reach on the joined sidecar\n"+
		"(members' `sc tenant switch` also completes it on first use).\n", url)
}

func formatCreatePlanV2(plan tenant.CreatePlanV2) string {
	return fmt.Sprintf("Tenant: %s\nInfra project: %s\nDefault project: %s\nBridge: %s\nCIDR: %s\nDNS suffix: %s\nSidecar: %s (dns %s, gateway %s)",
		plan.Tenant, plan.InfraProject, plan.DefaultProject, plan.Bridge, plan.PrivateCIDR, plan.DNSSuffix, plan.SidecarInstance, plan.DNSAddress, plan.GatewayAddress)
}

func newAdminTenantDeleteCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var yes bool
	var purge bool
	command := &cobra.Command{
		Use:   "delete tenant",
		Short: "Delete a Sandcastle tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				confirmed, err := confirmMissingYes(config, "Delete tenant "+args[0]+"?", "refusing to delete without --yes")
				if err != nil {
					return err
				}
				if !confirmed {
					return fmt.Errorf("delete canceled")
				}
			}
			planV2, found, err := tenant.PlanDeleteV2(cmd.Context(), config.adminConfig, config.tenantStore, args[0], purge)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("Sandcastle tenant %s not found", args[0])
			}
			if config.tenantDeleter == nil {
				return fmt.Errorf("tenant deletion executor is not configured")
			}
			// Storage-share cleanup used to hang off the v1 delete path only, so a
			// v2 `tenant delete --purge` left the tenant's shares behind. It runs
			// for v2 now.
			if config.shareStore != nil {
				if _, err := share.CleanupTenantDeletion(cmd.Context(), config.tenantStore, config.shareStore, share.TenantCleanupRequest{Tenant: args[0]}); err != nil {
					return err
				}
			}
			if err := config.tenantDeleter.DeleteTenantV2(cmd.Context(), planV2); err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatDeletePlanV2(planV2), planV2)
		},
	}
	command.Flags().BoolVar(&yes, "yes", false, "confirm tenant deletion")
	command.Flags().BoolVar(&purge, "purge", false, "delete durable tenant volumes and the Incus project")
	return command
}

func findTenantSummaryForCleanup(summaries []tenant.Summary, tenantName string) (tenant.Summary, bool) {
	for _, summary := range summaries {
		if summary.Tenant == tenantName {
			return summary, true
		}
	}
	return tenant.Summary{}, false
}

func newAdminTenantSetSSHKeyCommand(config commandConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "set-ssh-key tenant key",
		Short: "Set or update the SSH public key for a Sandcastle tenant",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The key lives in the infra project's config and is rendered into
			// each app project's default profile. Resolve the tenant's real
			// projects rather than deriving a single Incus project name.
			summaries, err := tenant.ListForPrefix(cmd.Context(), config.tenantStore, config.adminConfig.IncusProjectPrefix)
			if err != nil {
				return err
			}
			summary, ok := findTenantSummaryForCleanup(summaries, args[0])
			if !ok {
				return fmt.Errorf("Sandcastle tenant %s not found", args[0])
			}
			projects := make([]string, 0, len(summary.Projects))
			for _, project := range summary.Projects {
				projects = append(projects, project.Name)
			}
			if len(projects) == 0 {
				projects = []string{naming.DefaultProjectName}
			}
			if err := config.tenantCreator.SetTenantSSHKeyV2(cmd.Context(), config.adminConfig.IncusProjectPrefix, summary.Tenant, args[1], projects); err != nil {
				return err
			}
			fmt.Fprintf(config.stdout, "Updated the SSH key for tenant %s across project(s): %s\n", summary.Tenant, strings.Join(projects, ", "))
			fmt.Fprintf(config.stdout, "Existing machines keep their current key; recreate them, or rotate a running machine through the Auth App.\n")
			return nil
		},
	}
}

func newAdminTenantGrantCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "grant tenant user",
		Short: "Grant tenant access to a restricted user",
		Args:  cobra.ExactArgs(2),
		Long: "Grant tenant access to a restricted user. The user's certificate is extended with the " +
			"tenant's infra project and every app project; on a v2 tenant the user is also recorded as a " +
			"Tenant Member (Shared Tenants), which re-renders the tenant's profiles with the member's login " +
			"key. The member must have logged in to this install already; they then run `sc tenant switch`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			request := usertrust.TenantAccessRequest{Tenant: args[0], User: args[1]}
			summary, found := adminTenantSummary(cmd.Context(), config, args[0])
			if found {
				request.AppProjects = summary.ProjectShortNames()
				request.Personal = naming.ValidateTenantName(summary.Tenant) != nil
			}
			plan, err := usertrust.PlanTenantGrant(config.adminConfig, request)
			if err != nil {
				return err
			}
			if !dryRun {
				if config.trustManager == nil {
					return fmt.Errorf("restricted user grant executor is not configured")
				}
				if err := usertrust.GrantMember(cmd.Context(), config.trustManager, config.adminConfig, plan, args[1]); err != nil {
					return err
				}
				if found && config.tenantMembers != nil && summary.Tenant != strings.ToLower(strings.TrimSpace(args[1])) {
					members, err := config.tenantMembers.AddTenantMemberV2(cmd.Context(), config.adminConfig.IncusProjectPrefix, summary.Tenant, args[1])
					if err != nil {
						return err
					}
					fmt.Fprintf(config.stdout, "Tenant %s members: %s\n", summary.Tenant, strings.Join(members, ", "))
					fmt.Fprintf(config.stdout, "Next for %s: sc tenant switch %s\n", strings.ToLower(strings.TrimSpace(args[1])), summary.Tenant)
				}
			}
			return writeOutput(config.stdout, opts.output, formatUserPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the grant plan without mutating trust state")
	return command
}

func newAdminTenantRevokeCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "revoke tenant user",
		Short: "Revoke tenant access from a restricted user",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			request := usertrust.TenantAccessRequest{Tenant: args[0], User: args[1]}
			summary, found := adminTenantSummary(cmd.Context(), config, args[0])
			if found {
				request.AppProjects = summary.ProjectShortNames()
				request.Personal = naming.ValidateTenantName(summary.Tenant) != nil
			}
			plan, err := usertrust.PlanTenantRevoke(config.adminConfig, request)
			if err != nil {
				return err
			}
			if !dryRun {
				if config.trustManager == nil {
					return fmt.Errorf("restricted user revoke executor is not configured")
				}
				if err := usertrust.RevokeMember(cmd.Context(), config.trustManager, config.adminConfig, plan, args[1]); err != nil {
					return err
				}
				if found && config.tenantMembers != nil && summary.IsMember(args[1]) {
					members, err := config.tenantMembers.RemoveTenantMemberV2(cmd.Context(), config.adminConfig.IncusProjectPrefix, summary.Tenant, args[1])
					if err != nil {
						return err
					}
					fmt.Fprintf(config.stdout, "Tenant %s members: %s\n", summary.Tenant, orNone(strings.Join(members, ", ")))
				}
			}
			return writeOutput(config.stdout, opts.output, formatUserPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the revoke plan without mutating trust state")
	return command
}

func newAdminTenantUsersCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "users tenant",
		Short: "List restricted users with tenant access",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := usertrust.PlanTenantUsers(config.adminConfig, args[0])
			if err != nil {
				return err
			}
			if config.trustManager == nil {
				return fmt.Errorf("restricted user list executor is not configured")
			}
			result, err := config.trustManager.ListTenantUsers(cmd.Context(), plan)
			if err != nil {
				return err
			}
			if summary, found := adminTenantSummary(cmd.Context(), config, args[0]); found {
				for _, member := range summary.Members {
					if !slices.Contains(result.Users, member) {
						result.Users = append(result.Users, member)
					}
				}
				sort.Strings(result.Users)
			}
			return writeOutput(config.stdout, opts.output, formatTenantUsers(result), result)
		},
	}
}

func formatTenantUsers(result usertrust.TenantUsersResult) string {
	if len(result.Users) == 0 {
		return fmt.Sprintf("Tenant: %s\nUsers: none", result.Tenant)
	}
	return fmt.Sprintf("Tenant: %s\nUsers: %s", result.Tenant, strings.Join(result.Users, ", "))
}

func formatDeletePlanV2(plan tenant.DeletePlanV2) string {
	return fmt.Sprintf("Deleted v2 tenant %s: projects %s + %s, shared volumes, sidecar, bridge %s.",
		plan.Reference, strings.Join(plan.AppProjects, ", "), plan.InfraProject, plan.Bridge)
}

func newAdminImageCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	imageCommand := &cobra.Command{
		Use:   "image",
		Short: "Manage Sandcastle image aliases",
	}
	imageCommand.AddCommand(newAdminImageBuildCommand(config, opts))
	imageCommand.AddCommand(newAdminImageBuildRemoteCommand(config, opts))
	imageCommand.AddCommand(newAdminImageImportCommand(config, opts))
	imageCommand.AddCommand(newAdminImageSyncCommand(config, opts))
	imageCommand.AddCommand(newAdminImageBuilderCommand(config, opts))
	return imageCommand
}

// ghcrTokenFromEnv supplies the Image Registry push token to the remote image
// builder. It is read lazily and only when a build pushes, so it never sits in
// the plan or on argv.
func ghcrTokenFromEnv() (string, error) {
	return os.Getenv("SANDCASTLE_GHCR_TOKEN"), nil
}

func newAdminImageBuildRemoteCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var (
		ghcrRepo       string
		ghcrUser       string
		remote         string
		platform       string
		codexVersion   string
		claudeVersion  string
		geminiVersion  string
		requireClean   bool
		noPush         bool
		noImport       bool
		rebuildBuilder bool
		dryRun         bool
	)
	command := &cobra.Command{
		Use:   "build-remote base|ai|dev|all",
		Short: "Build Sandcastle Images in the Image Builder appliance and publish to GHCR",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			templates, err := remoteBuildTemplates(args[0])
			if err != nil {
				return err
			}
			for _, template := range templates {
				plan, err := images.PlanRemoteBuild(config.adminConfig, images.RemoteBuildRequest{
					Template:       template,
					Remote:         remote,
					GHCRRepo:       ghcrRepo,
					GHCRUser:       ghcrUser,
					Platform:       platform,
					CodexVersion:   codexVersion,
					ClaudeVersion:  claudeVersion,
					GeminiVersion:  geminiVersion,
					RequireClean:   requireClean,
					NoPush:         noPush,
					NoImport:       noImport,
					RebuildBuilder: rebuildBuilder,
				})
				if err != nil {
					return err
				}
				if dryRun {
					if err := writeOutput(config.stdout, opts.output, formatRemoteBuildPlan(plan), plan); err != nil {
						return err
					}
					continue
				}
				if config.remoteImageBuilder == nil {
					return fmt.Errorf("remote image builder is not configured")
				}
				result, err := config.remoteImageBuilder.BuildRemote(cmd.Context(), plan)
				if err != nil {
					return err
				}
				if err := writeOutput(config.stdout, opts.output, formatRemoteBuildResult(result), result); err != nil {
					return err
				}
			}
			return nil
		},
	}
	command.Flags().StringVar(&ghcrRepo, "ghcr-repo", os.Getenv("SANDCASTLE_GHCR_REPO"), "GHCR owner/repo prefix, defaulting to "+images.DefaultGHCRRepo)
	command.Flags().StringVar(&ghcrUser, "ghcr-user", os.Getenv("SANDCASTLE_GHCR_USER"), "GHCR username for podman login, defaulting to the repo owner")
	command.Flags().StringVar(&remote, "remote", "", "Incus remote to publish into, defaulting to the configured remote")
	command.Flags().StringVar(&platform, "platform", "", "OCI build platform, for example linux/amd64")
	command.Flags().StringVar(&codexVersion, "codex-version", "", "pinned Codex CLI version for AI images")
	command.Flags().StringVar(&claudeVersion, "claude-version", "", "pinned Claude Code version for AI images")
	command.Flags().StringVar(&geminiVersion, "gemini-version", "", "pinned Gemini CLI version for AI images")
	command.Flags().BoolVar(&requireClean, "require-clean", false, "refuse to build when the working tree is dirty")
	command.Flags().BoolVar(&noPush, "no-push", false, "build without logging in or pushing to GHCR")
	command.Flags().BoolVar(&noImport, "no-import", false, "skip copying the published image into the Incus alias")
	command.Flags().BoolVar(&rebuildBuilder, "rebuild-builder", false, "recreate the Image Builder appliance before building")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the remote build plan without running it")
	return command
}

func remoteBuildTemplates(arg string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "base":
		return []string{"base"}, nil
	case "ai":
		return []string{"ai"}, nil
	case "dev":
		return []string{"dev"}, nil
	case "all":
		return []string{"base", "ai", "dev"}, nil
	default:
		return nil, fmt.Errorf("unknown image template %q (want base, ai, dev, or all)", arg)
	}
}

func newAdminImageBuilderCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	builderCommand := &cobra.Command{
		Use:   "builder",
		Short: "Manage the Image Builder appliance",
	}

	var provisionRemote string
	provisionCommand := &cobra.Command{
		Use:   "provision",
		Short: "Create and provision the Image Builder appliance (so builds skip provisioning)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			app, err := images.PlanBuilderAppliance(config.adminConfig, provisionRemote)
			if err != nil {
				return err
			}
			if config.remoteImageBuilder == nil {
				return fmt.Errorf("remote image builder is not configured")
			}
			if err := config.remoteImageBuilder.ProvisionBuilder(cmd.Context(), app); err != nil {
				return err
			}
			fmt.Fprintf(config.stdout, "Provisioned Image Builder %s in %s:%s\n", app.Instance, app.Remote, app.Project)
			return nil
		},
	}
	provisionCommand.Flags().StringVar(&provisionRemote, "remote", "", "Incus remote, defaulting to the configured remote")

	var statusRemote string
	statusCommand := &cobra.Command{
		Use:   "status",
		Short: "Show Image Builder appliance state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			app, err := images.PlanBuilderAppliance(config.adminConfig, statusRemote)
			if err != nil {
				return err
			}
			if config.remoteImageBuilder == nil {
				return fmt.Errorf("remote image builder is not configured")
			}
			status, err := config.remoteImageBuilder.BuilderStatus(cmd.Context(), app)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, status, app)
		},
	}
	statusCommand.Flags().StringVar(&statusRemote, "remote", "", "Incus remote, defaulting to the configured remote")

	var destroyYes bool
	var destroyRemote string
	var keepCache bool
	destroyCommand := &cobra.Command{
		Use:   "destroy",
		Short: "Tear down the Image Builder appliance and its project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			app, err := images.PlanBuilderAppliance(config.adminConfig, destroyRemote)
			if err != nil {
				return err
			}
			if !destroyYes {
				confirmed, err := confirmMissingYes(config, "Destroy Image Builder "+app.Instance+" in "+app.Remote+":"+app.Project+"?", "refusing to destroy the Image Builder without --yes")
				if err != nil {
					return err
				}
				if !confirmed {
					return nil
				}
			}
			if config.remoteImageBuilder == nil {
				return fmt.Errorf("remote image builder is not configured")
			}
			if err := config.remoteImageBuilder.BuilderDestroy(cmd.Context(), app, keepCache); err != nil {
				return err
			}
			fmt.Fprintf(config.stdout, "Destroyed Image Builder %s in %s:%s\n", app.Instance, app.Remote, app.Project)
			return nil
		},
	}
	destroyCommand.Flags().BoolVar(&destroyYes, "yes", false, "confirm Image Builder teardown")
	destroyCommand.Flags().StringVar(&destroyRemote, "remote", "", "Incus remote, defaulting to the configured remote")
	destroyCommand.Flags().BoolVar(&keepCache, "keep-cache", false, "preserve the podman layer-cache volume and project")

	builderCommand.AddCommand(provisionCommand)
	builderCommand.AddCommand(statusCommand)
	builderCommand.AddCommand(destroyCommand)
	return builderCommand
}

func formatRemoteBuildPlan(plan images.RemoteBuildPlan) string {
	lines := []string{
		"Template: " + plan.Template,
		"Image: " + plan.ImageVersncRef + " (+ :latest)",
		"Builder: " + plan.Builder.Remote + ":" + plan.Builder.Project + "/" + plan.Builder.Instance + " (" + plan.Builder.Image + ")",
	}
	if plan.BaseRef != "" {
		lines = append(lines, "Base: "+plan.BaseRef)
	}
	if !plan.NoImport {
		lines = append(lines, "Import: "+strings.Join(plan.ImportCommand, " "))
	}
	return strings.Join(lines, "\n")
}

func formatRemoteBuildResult(result images.RemoteBuildResult) string {
	return fmt.Sprintf("Image: %s\nTemplate: %s\nPushed: %t\nImported: %t", result.ImageVersncRef, result.Template, result.Pushed, result.Imported)
}

func newAdminImageBuildCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var tag string
	var tool string
	var platform string
	var codexVersion string
	var claudeVersion string
	var geminiVersion string
	var dryRun bool
	command := &cobra.Command{
		Use:   "build base|ai|dev",
		Short: "Build a Sandcastle OCI image",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := images.PlanBuild(config.adminConfig, images.BuildRequest{
				Template:      args[0],
				Tag:           tag,
				Tool:          tool,
				Platform:      platform,
				CodexVersion:  codexVersion,
				ClaudeVersion: claudeVersion,
				GeminiVersion: geminiVersion,
			})
			if err != nil {
				return err
			}
			if dryRun {
				return writeOutput(config.stdout, opts.output, formatImageBuildPlan(plan), plan)
			}
			if config.imageBuilder == nil {
				return fmt.Errorf("image build executor is not configured")
			}
			result, err := config.imageBuilder.BuildImage(cmd.Context(), plan)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatImageBuildResult(result), result)
		},
	}
	command.Flags().StringVar(&tag, "tag", "", "image tag to build, defaulting to the configured Sandcastle image alias")
	command.Flags().StringVar(&tool, "tool", "docker", "OCI image build tool")
	command.Flags().StringVar(&platform, "platform", "", "OCI image build platform, for example linux/amd64")
	command.Flags().StringVar(&codexVersion, "codex-version", "", "pinned Codex CLI version for AI images")
	command.Flags().StringVar(&claudeVersion, "claude-version", "", "pinned Claude Code version for AI images")
	command.Flags().StringVar(&geminiVersion, "gemini-version", "", "pinned Gemini CLI version for AI images")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the image build command without running it")
	return command
}

func newAdminImageSyncCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "sync image-ref",
		Short: "Sync an imported image into a Sandcastle image alias",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := images.PlanSync(config.adminConfig, images.SyncRequest{SourceRef: args[0]})
			if err != nil {
				return err
			}
			if dryRun {
				return writeOutput(config.stdout, opts.output, formatImageSyncPlan(plan), plan)
			}
			if config.imageManager == nil {
				return fmt.Errorf("image sync executor is not configured")
			}
			result, err := config.imageManager.SyncImage(cmd.Context(), plan)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatImageSyncResult(result), result)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the image sync plan without mutating aliases")
	return command
}

func newAdminImageImportCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var tool string
	var dryRun bool
	command := &cobra.Command{
		Use:   "import base|ai|dev source-ref",
		Short: "Import an OCI image into Incus and set the Sandcastle alias",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := images.PlanImport(config.adminConfig, images.ImportRequest{
				Template:  args[0],
				SourceRef: args[1],
				Tool:      tool,
			})
			if err != nil {
				return err
			}
			if dryRun {
				return writeOutput(config.stdout, opts.output, formatImageImportPlan(plan), plan)
			}
			if config.imageImporter == nil {
				return fmt.Errorf("image import executor is not configured")
			}
			result, err := config.imageImporter.ImportImage(cmd.Context(), plan)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatImageImportResult(result), result)
		},
	}
	command.Flags().StringVar(&tool, "tool", "incus", "Incus CLI executable")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the image import command without running it")
	return command
}

func formatImageBuildPlan(plan images.BuildPlan) string {
	return fmt.Sprintf("Image: %s\nTemplate: %s\nCommand: %s", plan.Tag, plan.Template, strings.Join(plan.Command, " "))
}

func formatImageBuildResult(result images.BuildResult) string {
	return fmt.Sprintf("Image: %s\nTemplate: %s\nBuilt: %t", result.Tag, result.Template, result.Built)
}

func formatImageImportPlan(plan images.ImportPlan) string {
	return fmt.Sprintf("Import: %s\nTemplate: %s\nAlias: %s\nCommand: %s", plan.SourceRef, plan.Template, plan.Alias, strings.Join(plan.Command, " "))
}

func formatImageImportResult(result images.ImportResult) string {
	return fmt.Sprintf("Import: %s\nAlias: %s\nImported: %t", result.SourceRef, result.Alias, result.Imported)
}

func formatImageSyncPlan(plan images.SyncPlan) string {
	return fmt.Sprintf("Image: %s\nTemplate: %s\nAlias: %s", plan.SourceRef, plan.Template, plan.Alias)
}

func formatImageSyncResult(result images.SyncResult) string {
	return fmt.Sprintf("Image: %s\nAlias: %s\nFingerprint: %s\nAction: %s", result.SourceRef, result.Alias, result.Fingerprint, result.Action)
}

func newAdminTLDCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	tldCommand := &cobra.Command{
		Use:   "tld",
		Short: "Manage tenant suffix deny-list snapshots",
	}
	tldCommand.AddCommand(newAdminTLDRefreshCommand(config, opts))
	return tldCommand
}

func newAdminTLDRefreshCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var sourceURL string
	var outputPath string
	var specialUseSourceURL string
	var specialUseOutputPath string
	var dryRun bool
	command := &cobra.Command{
		Use:   "refresh",
		Short: "Refresh embedded public TLD and special-use deny-list snapshots",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := domain.RefreshDenyListSnapshots(cmd.Context(), nil, domain.DenyListRefreshRequest{
				TLDSourceURL:         sourceURL,
				TLDOutputPath:        outputPath,
				SpecialUseSourceURL:  specialUseSourceURL,
				SpecialUseOutputPath: specialUseOutputPath,
				DryRun:               dryRun,
			})
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatTLDRefreshResult(result), result)
		},
	}
	command.Flags().StringVar(&sourceURL, "source-url", domain.IANAAlphaTLDURL, "IANA alpha TLD list URL")
	command.Flags().StringVar(&outputPath, "output-file", domain.DefaultTLDSnapshotOutput, "generated Go source output path")
	command.Flags().StringVar(&specialUseSourceURL, "special-use-source-url", domain.IANASpecialUseDomainCSVURL, "IANA special-use domain CSV URL")
	command.Flags().StringVar(&specialUseOutputPath, "special-use-output-file", domain.DefaultSpecialUseSnapshotOutputPath, "generated special-use Go source output path")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "fetch and validate without writing the generated snapshot")
	return command
}

func formatTLDRefreshResult(result domain.DenyListRefreshResult) string {
	if result.TLD.Written || result.SpecialUse.Written {
		return fmt.Sprintf(
			"Refreshed %d public TLDs from %s into %s and %d special-use domains from %s into %s",
			result.TLD.Count,
			result.TLD.SourceURL,
			result.TLD.OutputPath,
			result.SpecialUse.Count,
			result.SpecialUse.SourceURL,
			result.SpecialUse.OutputPath,
		)
	}
	return fmt.Sprintf(
		"Validated %d public TLDs from %s and %d special-use domains from %s; %s and %s were not written",
		result.TLD.Count,
		result.TLD.SourceURL,
		result.SpecialUse.Count,
		result.SpecialUse.SourceURL,
		result.TLD.OutputPath,
		result.SpecialUse.OutputPath,
	)
}

func newAdminUserCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	user := &cobra.Command{
		Use:   "user",
		Short: "Manage Sandcastle restricted users",
	}
	user.AddCommand(newAdminUserCreateCommand(config, opts))
	user.AddCommand(newAdminUserDeleteCommand(config, opts))
	user.AddCommand(newAdminUserTokenCommand(config, opts))
	return user
}

func newAdminUserCreateCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	var tenants []string
	command := &cobra.Command{
		Use:   "create user",
		Short: "Create a restricted Sandcastle user certificate token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := planUserToken(config, args[0], tenants)
			if err != nil {
				return err
			}
			if !dryRun {
				if config.trustManager == nil {
					return fmt.Errorf("restricted user certificate executor is not configured")
				}
				result, err := config.trustManager.CreateToken(cmd.Context(), plan)
				if err != nil {
					return err
				}
				return writeOutput(config.stdout, opts.output, formatTokenResult(config, result), result)
			}
			return writeOutput(config.stdout, opts.output, formatUserPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the restricted user plan without mutating trust state")
	command.Flags().StringSliceVar(&tenants, "tenant", nil, "tenant to pre-grant in the generated certificate token (repeatable)")
	return command
}

func newAdminUserDeleteCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var yes bool
	var dryRun bool
	command := &cobra.Command{
		Use:   "delete user",
		Short: "Delete a restricted Sandcastle user certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes && !dryRun {
				confirmed, err := confirmMissingYes(config, "Delete restricted user "+args[0]+"?", "refusing to delete user without --yes")
				if err != nil {
					return err
				}
				if !confirmed {
					return nil
				}
			}
			plan, err := usertrust.PlanDeleteUser(args[0])
			if err != nil {
				return err
			}
			if !dryRun {
				if config.trustManager == nil {
					return fmt.Errorf("restricted user delete executor is not configured")
				}
				if err := config.trustManager.Delete(cmd.Context(), plan); err != nil {
					return err
				}
				return writeOutput(config.stdout, opts.output, formatUserDelete(plan), plan)
			}
			return writeOutput(config.stdout, opts.output, formatUserPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&yes, "yes", false, "confirm user certificate deletion")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the delete plan without deleting a certificate")
	return command
}

func newAdminUserTokenCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	var tenants []string
	command := &cobra.Command{
		Use:   "token user",
		Short: "Create a restricted certificate add token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := planUserToken(config, args[0], tenants)
			if err != nil {
				return err
			}
			if !dryRun {
				if config.trustManager == nil {
					return fmt.Errorf("restricted user token executor is not configured")
				}
				result, err := config.trustManager.CreateToken(cmd.Context(), plan)
				if err != nil {
					return err
				}
				return writeOutput(config.stdout, opts.output, formatTokenResult(config, result), result)
			}
			return writeOutput(config.stdout, opts.output, formatUserPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the token plan without creating a trust token")
	command.Flags().StringSliceVar(&tenants, "tenant", nil, "tenant to pre-grant in the generated certificate token (repeatable)")
	return command
}

func planUserToken(config commandConfig, user string, tenants []string) (usertrust.UserPlan, error) {
	if len(tenants) > 0 {
		return usertrust.PlanGrant(config.adminConfig, usertrust.GrantRequest{
			User:     user,
			Projects: tenants,
		})
	}
	return usertrust.PlanToken(user)
}

func formatUserPlan(plan usertrust.UserPlan) string {
	projects := "none"
	if len(plan.Projects) > 0 {
		projects = strings.Join(plan.Projects, ", ")
	}
	return fmt.Sprintf("User: %s\nCertificate: %s\nRemote: %s\nRestricted: %t\nProjects: %s", plan.User, plan.CertificateName, plan.RemoteName, plan.Restricted, projects)
}

func formatUserDelete(plan usertrust.UserPlan) string {
	return fmt.Sprintf("Deleted restricted user certificate: %s", plan.CertificateName)
}

func formatTokenResult(config commandConfig, result usertrust.TokenResult) string {
	remoteName := result.RemoteName
	if remoteName == "" {
		remoteName = usertrust.RestrictedName(result.User)
	}
	bootstrap := fmt.Sprintf("sc remote add %s %s", remoteName, result.Token)
	tenant := bootstrapTenant(config, result)
	if tenant != "" {
		bootstrap += " --tenant " + tenant
	}
	output := fmt.Sprintf(
		"User: %s\nCertificate: %s\nRemote: %s\nToken: %s\nBootstrap:\n  %s",
		result.User,
		result.CertificateName,
		remoteName,
		result.Token,
		bootstrap,
	)
	if tenant == "" {
		output += "\nAfter tenant access is granted, set the default tenant with:\n  sc config set tenant <tenant>"
	}
	return output
}

func bootstrapTenant(config commandConfig, result usertrust.TokenResult) string {
	if len(result.Projects) == 0 {
		return ""
	}
	prefix := config.adminConfig.IncusProjectPrefix
	if prefix == "" {
		prefix = "sc"
	}
	if tenant, ok := strings.CutPrefix(result.Projects[0], prefix+"-"); ok {
		return tenant
	}
	return ""
}

func newAdminAuthAppCommand(config commandConfig) *cobra.Command {
	auth := &cobra.Command{
		Use:   "auth-app",
		Short: "Manage the Sandcastle Auth App",
	}
	auth.AddCommand(newAdminAuthAppServeCommand(config))
	auth.AddCommand(newAdminAuthAppDeployCommand(config))
	return auth
}

func newAdminAuthAppServeCommand(config commandConfig) *cobra.Command {
	var listen string
	var databasePath string
	var authHostname string
	var githubClientID string
	var githubClientSecret string
	var adminGitHubUsers string
	var debugDeviceUser string
	var simulateGitHubToken string
	var defaultUnixUser string
	var tailscaleAuthKey string
	var acmeDirectory string
	command := &cobra.Command{
		Use:   "serve",
		Short: "Serve the Sandcastle Auth App",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := authapp.PlanServe(authapp.ServeRequest{
				Address:             listen,
				DatabasePath:        databasePath,
				AuthHostname:        authHostname,
				GitHubClientID:      githubClientID,
				GitHubClientSecret:  githubClientSecret,
				BootstrapAdminUsers: strings.Split(adminGitHubUsers, ","),
				DebugDeviceUser:     debugDeviceUser,
				SimulateGitHubToken: simulateGitHubToken,
				DefaultUnixUser:     defaultUnixUser,
				TailscaleAuthKey:    tailscaleAuthKey,
				ACMEDirectory:       acmeDirectory,
			})
			if err != nil {
				return err
			}
			if config.authApp == nil {
				return fmt.Errorf("auth app server is not configured")
			}
			return config.authApp.Serve(cmd.Context(), plan)
		},
	}
	command.Flags().StringVar(&listen, "listen", ":9444", "auth app listen address")
	command.Flags().StringVar(&databasePath, "database", "", "SQLite auth database path")
	command.Flags().StringVar(&authHostname, "auth-hostname", "", "public Auth Hostname")
	command.Flags().StringVar(&githubClientID, "github-client-id", "", "GitHub OAuth client id")
	command.Flags().StringVar(&githubClientSecret, "github-client-secret", "", "GitHub OAuth client secret")
	command.Flags().StringVar(&adminGitHubUsers, "admin-github-users", "", "comma-separated initial Sandcastle Admin GitHub usernames")
	command.Flags().StringVar(&debugDeviceUser, "debug-device-user", "", "enable debug device approval as this allowlisted GitHub username")
	command.Flags().StringVar(&simulateGitHubToken, "simulate-github-token", "", "DEV ONLY: enable simulated GitHub auth gated by this shared secret (no real OAuth app needed); serves /oauth/github/simulate")
	command.Flags().StringVar(&defaultUnixUser, "default-unix-user", "", "default Unix username for newly provisioned Personal Tenant machines")
	command.Flags().StringVar(&tailscaleAuthKey, "tailscale-auth-key", "", "Tailscale auth key returned to approved CLI device logins for unattended tenant attachment")
	command.Flags().StringVar(&acmeDirectory, "acme-directory", "", "ACME directory URL for Machine Certificates (Public DNS Zones); default Let's Encrypt production, "+authapp.LetsEncryptStagingDirectory+" for staging")
	_ = command.MarkFlagRequired("database")
	return command
}

func newAdminMachineCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "machine",
		Short: "Manage Sandcastle machines",
	}
	cmd.AddCommand(newAdminMachineWorkloadCommand(config, opts))
	return cmd
}

func newAdminMachineWorkloadCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workload",
		Short: "Manage workload identity for machines",
	}
	return cmd
}

// adminTenantSummary resolves a tenant's live summary for the admin grant
// family (project list, membership); not found is not an error here — the
// certificate grant still works from the name alone.
func adminTenantSummary(ctx context.Context, config commandConfig, tenantName string) (tenant.Summary, bool) {
	if config.tenantStore == nil {
		return tenant.Summary{}, false
	}
	summaries, err := tenant.ListForPrefix(ctx, config.tenantStore, config.adminConfig.IncusProjectPrefix)
	if err != nil {
		return tenant.Summary{}, false
	}
	return findTenantSummaryForCleanup(summaries, tenantName)
}

// missingMemberTenants reports which members have no Personal Tenant on this
// install (the Shared Tenant prerequisite: they must `sc login` first).
func missingMemberTenants(ctx context.Context, store tenant.IncusTenantStore, prefix string, members []string) ([]string, error) {
	summaries, err := tenant.ListForPrefix(ctx, store, prefix)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, member := range members {
		if _, found := findTenantSummaryForCleanup(summaries, member); !found {
			missing = append(missing, member)
		}
	}
	return missing, nil
}

func orNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return value
}

func newAdminTenantAddSSHKeyCommand(config commandConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "add-ssh-key tenant key",
		Short: "Add an SSH public key to a Sandcastle tenant (keeps the existing keys)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if config.tenantMembers == nil {
				return fmt.Errorf("tenant key manager is not configured")
			}
			keys, err := config.tenantMembers.AddTenantSSHKeyV2(cmd.Context(), config.adminConfig.IncusProjectPrefix, args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintf(config.stdout, "Tenant %s now authorizes %d key(s) on new machines.\n", args[0], len(keys))
			fmt.Fprintf(config.stdout, "Existing machines keep their current keys; enrol on a running machine with `sc fix --only ssh-key`.\n")
			return nil
		},
	}
}

func newAdminTenantRemoveSSHKeyCommand(config commandConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "remove-ssh-key tenant key",
		Short: "Remove an SSH public key from a Sandcastle tenant (matched on the key, not its comment)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if config.tenantMembers == nil {
				return fmt.Errorf("tenant key manager is not configured")
			}
			keys, err := config.tenantMembers.RemoveTenantSSHKeyV2(cmd.Context(), config.adminConfig.IncusProjectPrefix, args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintf(config.stdout, "Tenant %s now authorizes %d key(s) on new machines.\n", args[0], len(keys))
			return nil
		},
	}
}

// defaultTenantCIDRPool is the last-resort pool when neither a flag, the
// configuration, nor an existing tenant of the install names one.
const defaultTenantCIDRPool = "10.249.0.0/16"

// resolveTenantCIDRPool picks the pool for `tenant create`: explicit flag >
// configured pool > the /16 of the install's occupied /24s (the first one,
// sorted, so it is stable) > the built-in default.
func resolveTenantCIDRPool(flag string, configured string, occupied []string) string {
	if v := strings.TrimSpace(flag); v != "" {
		return v
	}
	// The admin defaults carry a built-in pool even when nothing configured
	// one; only an explicitly set pool (env / seed / flag) counts as configured.
	if v := strings.TrimSpace(configured); v != "" && v != config.DefaultCIDRPool {
		return v
	}
	sorted := append([]string{}, occupied...)
	sort.Strings(sorted)
	for _, cidr := range sorted {
		ip, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil || ip.To4() == nil {
			continue
		}
		v4 := ip.To4()
		return fmt.Sprintf("%d.%d.0.0/16", v4[0], v4[1])
	}
	return defaultTenantCIDRPool
}
