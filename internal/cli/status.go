package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

func newStatusCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:     "status [tenant]",
		Aliases: []string{"st"},
		Short:   "Show Sandcastle tenant status",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// `sc status <machine>` was the v1 per-machine status. v2 has no
			// per-machine status, so the argument is always a tenant name.
			reference := config.adminConfig.Tenant
			if len(args) == 1 {
				reference = args[0]
			}
			status, err := tenant.GetStatusWithTopologyForPrefix(
				cmd.Context(),
				config.tenantStore,
				config.topologyStore,
				tenant.TopologyRequest{},
				reference,
				installPrefixForRemote(config, reference),
			)
			if err != nil {
				return err
			}
			// Tenant Storage Shares are not yet supported on v2 (#70), so `sc
			// status` reports no share health or counts.
			return writeOutput(config.stdout, opts.output, formatTenantStatus(status), status)
		},
	}
}

func formatTenantStatus(status tenant.Status) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Tenant: %s\n", status.Summary.Tenant)
	fmt.Fprintf(&builder, "Incus project: %s\n", status.Summary.IncusName)
	fmt.Fprintf(&builder, "DNS suffix: %s\n", status.Summary.DNSSuffix)
	fmt.Fprintf(&builder, "Private CIDR: %s\n", status.Summary.PrivateCIDR)
	for _, publicRoute := range status.Summary.PublicRoutes {
		fmt.Fprintf(&builder, "Route: %s -> %s/%s:%d\n", publicRoute.Hostname, publicRoute.Project, publicRoute.Machine, publicRoute.RoutePort)
	}
	for _, check := range status.Checks {
		if check.Detail == "" {
			fmt.Fprintf(&builder, "%s: %s\n", check.Name, check.Status)
			continue
		}
		fmt.Fprintf(&builder, "%s: %s (%s)\n", check.Name, check.Status, check.Detail)
	}
	return strings.TrimRight(builder.String(), "\n")
}
