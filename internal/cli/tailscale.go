package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/tailscale"
)

func newTailscaleCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "tailscale",
		Short: "Manage tenant Tailscale attachment",
	}
	command.AddCommand(newTailscaleUpCommand(config, opts))
	command.AddCommand(newTailscaleStatusCommand(config, opts))
	command.AddCommand(newTailscaleDownCommand(config, opts))
	command.AddCommand(newTailscaleEgressCommand(config, opts))
	return command
}

func newTailscaleEgressCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "egress [tenant] [on|off]",
		Short: "Show or toggle tailnet egress (machines reach tailnet peers via the sidecar)",
		Long: "Tailnet egress (ADR-0026, ADR-0033) routes machine traffic for tailnet peers\n" +
			"through the tenant sidecar, masqueraded onto its tailnet IP: node addresses\n" +
			"(100.64.0.0/10) and subnet routes other tailnet routers advertise inside\n" +
			"10.0.0.0/8 (e.g. another Sandcastle install's machines; the sidecar accepts\n" +
			"routes while egress is on).\n" +
			"Without arguments the current setting is shown. Toggling records the setting;\n" +
			"the mechanics are applied by the next idempotent tenant converge\n" +
			"(`sc-adm tenant create` or the tenant's next `sc login`), and machines pick up\n" +
			"the route on their next DHCP renewal. The tailnet ACL must additionally allow\n" +
			"the sidecar's tag (tag:sandcastle) to reach the intended peers.",
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var reference, mode string
			rest := args
			if len(rest) > 0 {
				switch last := strings.ToLower(rest[len(rest)-1]); last {
				case "on", "off":
					mode = last
					rest = rest[:len(rest)-1]
				}
			}
			switch len(rest) {
			case 0:
			case 1:
				reference = rest[0]
			default:
				return fmt.Errorf("tailnet egress mode %q: must be on or off", args[len(args)-1])
			}
			plan, err := tailscale.PlanEgress(cmd.Context(), config.adminConfig, config.tenantStore, tailscale.EgressRequest{
				Reference: reference,
				Mode:      mode,
			})
			if err != nil {
				return err
			}
			if config.tailscale == nil {
				return fmt.Errorf("tailscale executor is not configured")
			}
			runner, ok := config.tailscale.(tailscale.EgressRunner)
			if !ok {
				return fmt.Errorf("tailscale executor does not support egress")
			}
			result, err := runner.RunEgress(cmd.Context(), plan)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatTailscaleEgress(result), result)
		},
	}
}

func newTailscaleUpCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	var authKey string
	var advertiseTags []string
	command := &cobra.Command{
		Use:   "up [tenant]",
		Short: "Attach a tenant Tailscale sidecar",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var reference string
			if len(args) > 0 {
				reference = args[0]
			}
			plan, err := tailscale.PlanUp(cmd.Context(), config.adminConfig, config.tenantStore, tailscale.UpRequest{
				Reference:     reference,
				AuthKey:       authKey,
				AdvertiseTags: advertiseTags,
			})
			if err != nil {
				return err
			}
			if !dryRun {
				if config.tailscale == nil {
					return fmt.Errorf("tailscale executor is not configured")
				}
				if err := config.tailscale.RunUp(cmd.Context(), plan, tailscale.RunSession{
					Stdin:  config.stdin,
					Stdout: config.stdout,
					Stderr: config.stderr,
				}); err != nil {
					return err
				}
			}
			return writeOutput(config.stdout, opts.output, formatTailscaleUp(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the Tailscale up plan without running tailscale")
	command.Flags().StringVar(&authKey, "auth-key", "", "Tailscale auth key for unattended attachment")
	command.Flags().StringSliceVar(&advertiseTags, "advertise-tag", defaultAdvertiseTags(), "Tailscale tags to advertise")
	return command
}

func newTailscaleStatusCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "status [tenant]",
		Short: "Check tenant Tailscale sidecar status",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var reference string
			if len(args) > 0 {
				reference = args[0]
			}
			plan, err := tailscale.PlanStatus(cmd.Context(), config.adminConfig, config.tenantStore, tailscale.StatusRequest{Reference: reference})
			if err != nil {
				return err
			}
			if config.tailscale == nil {
				return fmt.Errorf("tailscale executor is not configured")
			}
			result, err := config.tailscale.RunStatus(cmd.Context(), plan, tailscale.RunSession{
				Stdin:  config.stdin,
				Stdout: config.stdout,
				Stderr: config.stderr,
			})
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatTailscaleStatus(result), result)
		},
	}
}

func newTailscaleDownCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "down [tenant]",
		Short: "Detach a tenant Tailscale sidecar",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var reference string
			if len(args) > 0 {
				reference = args[0]
			}
			plan, err := tailscale.PlanDown(cmd.Context(), config.adminConfig, config.tenantStore, tailscale.DownRequest{Reference: reference})
			if err != nil {
				return err
			}
			if !dryRun {
				if config.tailscale == nil {
					return fmt.Errorf("tailscale executor is not configured")
				}
				if err := config.tailscale.RunDown(cmd.Context(), plan, tailscale.RunSession{
					Stdin:  config.stdin,
					Stdout: config.stdout,
					Stderr: config.stderr,
				}); err != nil {
					return err
				}
			}
			return writeOutput(config.stdout, opts.output, formatTailscaleDown(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the Tailscale down plan without running tailscale")
	return command
}

func formatTailscaleUp(plan tailscale.UpPlan) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Tailscale: %s\n", plan.Reference)
	fmt.Fprintf(&builder, "Sidecar: %s\n", plan.InstanceName)
	fmt.Fprintf(&builder, "Advertise routes: %s", strings.Join(plan.AdvertiseRoutes, ","))
	if len(plan.AdvertiseTags) > 0 {
		fmt.Fprintf(&builder, "\nAdvertise tags: %s", strings.Join(plan.AdvertiseTags, ","))
	}
	if plan.HasAuthKey {
		fmt.Fprint(&builder, "\nAuth key: <redacted>")
	}
	return builder.String()
}

func formatTailscaleStatus(result tailscale.StatusResult) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Tailscale: %s\n", result.Reference)
	fmt.Fprintf(&builder, "State: %s", result.Tailscale.State)
	if result.Tailscale.Tailnet != "" {
		fmt.Fprintf(&builder, "\nTailnet: %s", result.Tailscale.Tailnet)
	}
	if len(result.Tailscale.TailscaleIPs) > 0 {
		fmt.Fprintf(&builder, "\nIPs: %s", strings.Join(result.Tailscale.TailscaleIPs, ","))
	}
	if len(result.Tailscale.AdvertisedRoutes) > 0 {
		fmt.Fprintf(&builder, "\nAdvertised routes: %s", strings.Join(result.Tailscale.AdvertisedRoutes, ","))
	}
	return builder.String()
}

func formatTailscaleEgress(result tailscale.EgressResult) string {
	state := "off"
	if result.Enabled {
		state = "on"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "Tailnet egress: %s (%s)", state, result.Reference)
	if result.Changed {
		fmt.Fprint(&builder, "\nRecorded. Apply it with the next tenant converge (`sc-adm tenant create` or the tenant's next `sc login`); machines pick up the route on DHCP renewal.")
		if result.Enabled {
			fmt.Fprint(&builder, "\nRemember: the tailnet ACL must allow the sidecar's tag (tag:sandcastle) to reach the intended peers.")
		}
	}
	return builder.String()
}

func formatTailscaleDown(plan tailscale.DownPlan) string {
	return fmt.Sprintf("Tailscale down: %s", plan.Reference)
}

func defaultAdvertiseTags() []string {
	value := strings.TrimSpace(os.Getenv("SANDCASTLE_E2E_TAILSCALE_TAG"))
	if value == "" {
		value = tailscale.DefaultAdvertiseTag
	}
	return []string{value}
}
