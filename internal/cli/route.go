package cli

import (
	"context"
	"fmt"
	"net"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	authapp "github.com/thieso2/sandcastle-incus/internal/authapp"
)

// newRouteCommand assembles `sc route`: publish a Machine's local port to the
// public Internet through the Auth App's Caddy (Spec #111). Available only on
// installs configured with public ingress.
func newRouteCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "route",
		Short: "Publish a machine's local port to the public Internet",
		// Bare `sc route` answers "how do I publish, and what DNS do I need?"
		// from the install itself. That answer is per-install (base domain, CNAME
		// target, whether routes are enabled at all), so it cannot live in static
		// help text — and a Tenant has nowhere else to look it up.
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			summary, err := requireV2Tenant(cmd.Context(), config)
			if err != nil {
				return err
			}
			client, err := routeClient(config)
			if err != nil {
				return err
			}
			view, err := client.RouteConfig(cmd.Context())
			if err != nil {
				return err
			}
			autoResolves := true
			if view.Enabled {
				resolve := config.routeHostResolver
				if resolve == nil {
					resolve = routeHostResolves
				}
				autoResolves = resolve(cmd.Context(),
					"wildcard-probe."+summary.Tenant+"."+strings.Trim(strings.TrimSpace(view.BaseDomain), "."))
			}
			payload := map[string]any{
				"enabled": view.Enabled, "ingress": view.Ingress,
				"baseDomain": view.BaseDomain, "cnameTarget": view.CNAMETarget,
				"autoHostnameResolves": autoResolves,
			}
			return writeOutput(config.stdout, opts.output, formatRouteGuide(view, summary.Tenant, autoResolves), payload)
		},
	}
	command.AddCommand(newRoutePublishCommand(config, opts))
	command.AddCommand(newRouteListCommand(config, opts))
	command.AddCommand(newRouteStatusCommand(config, opts))
	command.AddCommand(newRouteDeleteCommand(config, opts))
	return command
}

func newRoutePublishCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var port int
	var name string
	var hostname string
	var dryRun bool
	var tenantOverride string
	command := &cobra.Command{
		Use:   "publish [[remote:]project:]machine --port <n>",
		Short: "Publish a machine's local port to the public Internet",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if port <= 0 {
				return fmt.Errorf("--port is required (the backend port inside the machine, e.g. --port 3000)")
			}
			// --tenant publishes on another Tenant's behalf (Sandcastle Admins
			// only; the Auth App enforces that). The local machine lookup is
			// skipped: an admin's restricted certificate cannot see another
			// Tenant's Incus projects, so the reference is parsed textually and
			// the Auth App — which does hold the rights — validates the machine.
			var tenantName, project, machine string
			if override := strings.TrimSpace(tenantOverride); override != "" {
				tenantName = override
				project, machine = splitRouteMachineReference(args[0], "default")
			} else {
				summary, err := requireV2Tenant(cmd.Context(), config)
				if err != nil {
					return err
				}
				tenantName = summary.Tenant
				reference, resolveErr := resolveSingleMachineReference(cmd.Context(), config, summary, args[0])
				if resolveErr != nil {
					return resolveErr
				}
				project, machine, resolveErr = resolveV2MachineReference(summary, reference, config.adminConfig.Project)
				if resolveErr != nil {
					return resolveErr
				}
			}
			if dryRun {
				plan := map[string]any{
					"tenant": tenantName, "project": project, "machine": machine,
					"backendPort": port, "url": "https://" + previewRouteHostname(config, tenantName, name, hostname, machine),
					"dryRun": true,
				}
				return writeOutput(config.stdout, opts.output, formatRoutePlan(machine, port, plan["url"].(string)), plan)
			}
			client, err := routeClient(config)
			if err != nil {
				return err
			}
			view, err := client.PublishRoute(cmd.Context(), authapp.RoutePublishRequest{
				Tenant:      tenantName,
				Project:     project,
				Machine:     machine,
				BackendPort: port,
				Name:        strings.TrimSpace(name),
				Hostname:    strings.TrimSpace(hostname),
			})
			if err != nil {
				return err
			}
			text := formatRoutePublished(view)
			if view.Status == authapp.RouteStatusAwaitingDNS {
				text += routeCNAMEHint(cmd.Context(), client, view.Hostname)
			}
			return writeOutput(config.stdout, opts.output, text, view)
		},
	}
	command.Flags().IntVar(&port, "port", 0, "backend port inside the machine (required), e.g. 3000")
	command.Flags().StringVar(&name, "name", "", "subdomain label; defaults to the machine name")
	command.Flags().StringVar(&hostname, "hostname", "", "custom public hostname instead of the auto-subdomain (CNAME it onto the auth host yourself)")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "show the plan without publishing")
	command.Flags().StringVar(&tenantOverride, "tenant", "", "publish for another tenant (Sandcastle Admins only); the machine reference is then [project:]machine, project defaulting to \"default\"")
	return command
}

// splitRouteMachineReference parses a "[project:]machine" reference without
// consulting local Incus state. Used for --tenant, where the caller's
// restricted certificate cannot see the target Tenant's projects and the Auth
// App does the real validation.
func splitRouteMachineReference(reference, defaultProject string) (project, machine string) {
	reference = strings.TrimSpace(reference)
	if index := strings.LastIndex(reference, ":"); index >= 0 {
		return strings.TrimSpace(reference[:index]), strings.TrimSpace(reference[index+1:])
	}
	return defaultProject, reference
}

// previewRouteHostname derives the public hostname a publish would produce, for
// --dry-run. Mirrors the server's rule: a custom --hostname verbatim, else
// <label>.<tenant>.<auth-hostname> with the label defaulting to the machine name.
func previewRouteHostname(config commandConfig, tenant, name, hostname, machine string) string {
	if custom := strings.TrimSpace(hostname); custom != "" {
		return strings.ToLower(custom)
	}
	label := strings.TrimSpace(name)
	if label == "" {
		label = machine
	}
	authHost := strings.Trim(commandAuthHostname(config, ""), ".")
	if authHost == "" {
		return strings.ToLower(label + "." + tenant)
	}
	return strings.ToLower(label + "." + tenant + "." + authHost)
}

func formatRoutePlan(machine string, port int, url string) string {
	return fmt.Sprintf("Would publish %s:%d  ->  %s\n(dry run; not published)\n", machine, port, url)
}

// formatRouteGuide renders `sc route` with no subcommand: what this install
// gives a Tenant and exactly which DNS record they need. autoResolves reports
// whether the auto-subdomain pattern actually resolves — an install can have
// route ingress but no wildcard for <tenant>.<base>, and silently handing out a
// hostname that will never resolve is the failure this guide exists to prevent.
func formatRouteGuide(view authapp.RouteConfigView, tenant string, autoResolves bool) string {
	var b strings.Builder
	if !view.Enabled {
		b.WriteString("Public routes are not available on this install.\n\n")
		b.WriteString("  Ask your Sandcastle admin to redeploy with `--route-ingress acme`\n")
		b.WriteString("  (or `acme-proxied` when an existing edge owns the host's :80/:443).\n")
		return b.String()
	}
	base := strings.Trim(strings.TrimSpace(view.BaseDomain), ".")
	auto := "<name>." + tenant + "." + base

	b.WriteString("Publish a machine's port to the public Internet.\n\n")
	fmt.Fprintf(&b, "  sc route publish <machine> --port 3000\n")
	fmt.Fprintf(&b, "      -> https://%s   (--name overrides <name>, default: the machine name)\n\n", auto)
	fmt.Fprintf(&b, "  sc route publish <machine> --port 3000 --hostname app.example.com\n")
	if target := strings.Trim(strings.TrimSpace(view.CNAMETarget), "."); target != "" {
		fmt.Fprintf(&b, "      -> https://app.example.com, once you add:  CNAME app.example.com -> %s\n\n", target)
	} else {
		b.WriteString("      -> a hostname you own; ask your Sandcastle admin what to CNAME it onto\n" +
			"         (this install has not declared a public front door).\n\n")
	}
	b.WriteString("Certificates issue automatically on the first HTTPS request, so that request is slow.\n")
	if !autoResolves {
		fmt.Fprintf(&b, "\nHeads up: %s does not resolve, so auto hostnames under it will sit at\n", "*."+tenant+"."+base)
		b.WriteString("  status awaiting-dns. Use --hostname with a name you control, or ask your\n" +
			"  Sandcastle admin for the wildcard record.\n")
	}
	b.WriteString("\n  sc route list | sc route status <hostname> | sc route delete <hostname> --yes\n")
	return b.String()
}

// routeHostResolves reports whether host resolves, bounded so `sc route` never
// hangs on a slow resolver. Used to warn about a missing wildcard, so "no
// answer" is the honest, conservative reading of any failure.
func routeHostResolves(ctx context.Context, host string) bool {
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(lookupCtx, host)
	return err == nil && len(addrs) > 0
}

// routeCNAMEHint is the line printed beside an awaiting-dns route: the exact
// record that makes it live. Empty when the install declares no front door —
// better silent than pointing a Tenant at the wrong target.
func routeCNAMEHint(ctx context.Context, client authRouteClient, hostname string) string {
	view, err := client.RouteConfig(ctx)
	if err != nil {
		return ""
	}
	target := strings.Trim(strings.TrimSpace(view.CNAMETarget), ".")
	if target == "" {
		return ""
	}
	return fmt.Sprintf("  add this DNS record:  CNAME %s -> %s\n", hostname, target)
}

func newRouteListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var tenantOverride string
	command := &cobra.Command{
		Use:   "list",
		Short: "List published routes for the current tenant",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tenantName := strings.TrimSpace(tenantOverride)
			if tenantName == "" {
				summary, err := requireV2Tenant(cmd.Context(), config)
				if err != nil {
					return err
				}
				tenantName = summary.Tenant
			}
			client, err := routeClient(config)
			if err != nil {
				return err
			}
			routes, err := client.ListRoutes(cmd.Context(), tenantName)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatRouteList(routes), map[string]any{"routes": routes})
		},
	}
	command.Flags().StringVar(&tenantOverride, "tenant", "", "list another tenant's routes (Sandcastle Admins only)")
	return command
}

func newRouteStatusCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "status <hostname>",
		Short: "Show a published route's backend, certificate, and health",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := routeClient(config)
			if err != nil {
				return err
			}
			view, err := client.GetRouteStatus(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			text := formatRouteStatus(view)
			if view.Status == authapp.RouteStatusAwaitingDNS {
				text += routeCNAMEHint(cmd.Context(), client, view.Hostname)
			}
			return writeOutput(config.stdout, opts.output, text, view)
		},
	}
}

func newRouteDeleteCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var yes bool
	command := &cobra.Command{
		Use:   "delete <hostname>",
		Short: "Delete a published route",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostname := strings.TrimSpace(args[0])
			if !yes {
				confirmed, err := confirmMissingYes(config, "Delete route "+hostname+"?", "refusing to delete route without --yes")
				if err != nil {
					return err
				}
				if !confirmed {
					return nil
				}
			}
			client, err := routeClient(config)
			if err != nil {
				return err
			}
			if err := client.DeleteRoute(cmd.Context(), hostname); err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, "Deleted route "+hostname+"\n", map[string]any{"hostname": hostname, "status": "deleted"})
		},
	}
	command.Flags().BoolVar(&yes, "yes", false, "confirm route deletion")
	return command
}

func routeClient(config commandConfig) (authRouteClient, error) {
	if config.authRoutes != nil {
		return config.authRoutes, nil
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

func formatRoutePublished(view authapp.RouteView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Published %s\n\n", view.Hostname)
	fmt.Fprintf(&b, "  %s   ->   %s:%d\n", view.URL, routeMachineLabel(view), view.BackendPort)
	if view.Status == authapp.RouteStatusAwaitingDNS {
		fmt.Fprintf(&b, "  awaiting DNS/certificate — the certificate issues on first request once DNS points here.\n")
	}
	return b.String()
}

func formatRouteStatus(view authapp.RouteView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Hostname:  %s\n", view.Hostname)
	fmt.Fprintf(&b, "URL:       %s\n", view.URL)
	fmt.Fprintf(&b, "Tenant:    %s\n", view.Tenant)
	fmt.Fprintf(&b, "Backend:   %s:%d\n", routeMachineLabel(view), view.BackendPort)
	fmt.Fprintf(&b, "Status:    %s\n", view.Status)
	return b.String()
}

func formatRouteList(routes []authapp.RouteView) string {
	if len(routes) == 0 {
		return "No published routes.\n"
	}
	var b strings.Builder
	writer := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "HOSTNAME\tMACHINE\tPORT\tSTATUS")
	for _, route := range routes {
		fmt.Fprintf(writer, "%s\t%s\t%d\t%s\n", route.Hostname, routeMachineLabel(route), route.BackendPort, route.Status)
	}
	writer.Flush()
	return b.String()
}

// routeMachineLabel names a Route's backend the way the Tenant reaches it: the
// Machine Private Hostname (<machine>.<project>.<Tenant DNS Suffix>), which is
// what `sc ls` prints as FQDN. Appliances that don't report it — older ones, or
// one that could not read the suffix — leave it empty, so the bare Machine name
// stands in rather than the row losing its backend entirely.
func routeMachineLabel(view authapp.RouteView) string {
	if fqdn := strings.TrimSpace(view.MachineFQDN); fqdn != "" {
		return fqdn
	}
	return view.Machine
}
