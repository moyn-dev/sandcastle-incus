package cli

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/localtrust"
	"github.com/spf13/cobra"
)

func newTrustCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "trust",
		Short: "Manage local tenant CA trust",
	}
	command.AddCommand(newTrustInstallCommand(config, opts))
	command.AddCommand(newTrustUninstallCommand(config, opts))
	return command
}

func newTrustInstallCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "install [tenant]",
		Short: "Install a tenant CA into local trust",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reference := optionalReference(args)
			plan, planErr := localtrust.PlanInstall(cmd.Context(), config.adminConfig, config.tenantStore, trustRequest(config, reference))
			if planErr == nil && dryRun {
				return writeOutput(config.stdout, opts.output, formatTrustPlan("Install", plan), plan)
			}
			if planErr == nil && config.localTrust != nil {
				if err := writeTrustWarning(config, opts, plan); err != nil {
					return err
				}
				if result, err := config.localTrust.Install(cmd.Context(), plan); err == nil {
					return writeOutput(config.stdout, opts.output, formatTrustResult(result), result)
				}
			}
			// v2 fallback: v2 tenants have no sc-ca volume — the CA is served by the
			// sidecar leaf signer (ADR-0011). Fetch it over the tenant subnet route.
			if err := trustInstallFromSigner(cmd.Context(), config, plan.Reference, reference); err != nil {
				if planErr != nil {
					return fmt.Errorf("%v (v2 signer fallback: %v)", planErr, err)
				}
				return err
			}
			return nil
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the trust install plan without changing local trust")
	return command
}

func newTrustUninstallCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "uninstall [tenant]",
		Short: "Remove a tenant CA from local trust",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := localtrust.PlanUninstall(cmd.Context(), config.adminConfig, config.tenantStore, trustRequest(config, optionalReference(args)))
			if err != nil {
				return err
			}
			if dryRun {
				return writeOutput(config.stdout, opts.output, formatTrustPlan("Uninstall", plan), plan)
			}
			if config.localTrust == nil {
				return fmt.Errorf("local trust executor is not configured")
			}
			result, err := config.localTrust.Uninstall(cmd.Context(), plan)
			if err != nil {
				return err
			}
			if !result.Removed && opts.output == outputText {
				fmt.Fprintf(config.stdout, "No trusted CA named %q was installed; nothing to remove.\n", plan.TrustName)
				return nil
			}
			return writeOutput(config.stdout, opts.output, formatTrustResult(result), result)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the trust uninstall plan without changing local trust")
	return command
}

// trustInstallFromSigner installs the tenant CA by fetching it from the sidecar
// leaf signer (v2 path). The signer sits at the tenant subnet's .3; the tenant
// gateway (.1) is recoverable from the saved broker URL in config.
func trustInstallFromSigner(ctx context.Context, config commandConfig, planTenant, argTenant string) error {
	tenant := strings.TrimSpace(planTenant)
	if tenant == "" {
		tenant = strings.TrimSpace(argTenant)
	}
	if tenant == "" {
		tenant = strings.TrimSpace(config.adminConfig.Tenant)
	}
	if tenant == "" {
		return fmt.Errorf("a tenant is required")
	}
	cfg, _ := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	dnsAddr, err := signerAddrFromBroker(cfg.Broker)
	if err != nil {
		return fmt.Errorf("cannot locate the tenant CA signer: %w", err)
	}
	return fetchAndInstallTenantCAFromSigner(ctx, config.stdout, tenant, dnsAddr)
}

// signerAddrFromBroker derives the sidecar signer address (.3) from the saved
// broker URL (its host is the tenant gateway .1).
func signerAddrFromBroker(broker string) (netip.Addr, error) {
	broker = strings.TrimSpace(broker)
	if broker == "" {
		return netip.Addr{}, fmt.Errorf("no broker URL in config to derive the tenant subnet (log in first)")
	}
	u, err := url.Parse(broker)
	if err != nil {
		return netip.Addr{}, err
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err != nil {
		return netip.Addr{}, fmt.Errorf("broker host %q is not an IP", host)
	}
	return signerAddrFromCIDR(host + "/24")
}

func optionalReference(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func formatTrustPlan(action string, plan localtrust.Plan) string {
	return fmt.Sprintf("%s tenant CA trust: %s\nCA: %s:%s%s\nWarning: %s", action, plan.Reference, plan.IncusProject, plan.CAVolume, plan.CertificatePath, plan.Warning)
}

// trustRequest scopes the tenant lookup to the install the active remote belongs
// to. Several installs can share one Incus daemon with a same-named tenant, and
// each has its own DNS suffix — which is what names the tenant CA. Unscoped, the
// plan could name the OTHER install's CA.
func trustRequest(config commandConfig, reference string) localtrust.Request {
	name := strings.TrimSpace(reference)
	if name == "" {
		name = strings.TrimSpace(config.adminConfig.Tenant)
	}
	return localtrust.Request{Reference: reference, InstallPrefix: installPrefixForRemote(config, name)}
}

func formatTrustResult(result localtrust.Result) string {
	if result.Target == "" {
		return fmt.Sprintf("%s tenant CA trust: %s", result.Action, result.Reference)
	}
	return fmt.Sprintf("%s tenant CA trust: %s\nTarget: %s", result.Action, result.Reference, result.Target)
}

func writeTrustWarning(config commandConfig, opts *rootOptions, plan localtrust.Plan) error {
	if opts.output != outputText || plan.Warning == "" {
		return nil
	}
	_, err := fmt.Fprintf(config.stdout, "Warning: %s\n", plan.Warning)
	return err
}
