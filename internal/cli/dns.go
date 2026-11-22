package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/dns"
	"github.com/moyn-dev/sandcastle-incus/internal/localdns"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
	"github.com/spf13/cobra"
)

func newDNSCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "dns",
		Short: "Manage tenant DNS",
	}
	command.AddCommand(newDNSTeardownCommand(config, opts))
	command.AddCommand(newDNSUninstallCommand(config, opts))
	command.AddCommand(newDNSApplyElevatedCommand())
	return command
}

// newDNSApplyElevatedCommand is the hidden worker that runElevatedDNSPlan
// invokes under sudo. It reads a fully-resolved localdns.Plan as JSON on stdin
// and executes it verbatim — no tenant-store lookup — so the CIDR/suffix the
// unprivileged parent resolved survive the privilege boundary.
func newDNSApplyElevatedCommand() *cobra.Command {
	var action string
	command := &cobra.Command{
		Use:    "apply-elevated",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return err
			}
			var plan localdns.Plan
			if err := json.Unmarshal(data, &plan); err != nil {
				return fmt.Errorf("decode plan: %w", err)
			}
			_, err = runLocalDNSAction(cmd.Context(), localdns.FileManager{}, action, plan)
			return err
		},
	}
	command.Flags().StringVar(&action, "action", "install", "install|refresh|uninstall")
	return command
}

type dnsSetupResult struct {
	Reference string                    `json:"reference"`
	Apply     dns.ApplyResult           `json:"apply"`
	Install   localdns.Result           `json:"install"`
	Refresh   localdns.Result           `json:"refresh"`
	Elevated  []dnsElevatedActionResult `json:"elevated,omitempty"`
}

type dnsTeardownResult struct {
	Reference string                    `json:"reference"`
	Uninstall localdns.Result           `json:"uninstall"`
	Elevated  []dnsElevatedActionResult `json:"elevated,omitempty"`
}

type dnsElevatedActionResult struct {
	Action string `json:"action"`
}

// installV2LocalResolver installs the client-side split-DNS resolver for a v2
// tenant from values the login flow already holds (the device response carries
// the tenant CIDR; the Tenant DNS Suffix is visible on the app projects). This
// is what makes `<machine>.<project>.<suffix>` resolve on the client without a
// manual Tailscale Split DNS entry. Best-effort: a failure (no privileges, an
// unsupported resolver) is reported but does not fail the login — the tenant
// can still fall back to a Tailscale Split DNS entry.
func installV2LocalResolver(ctx context.Context, config commandConfig, out io.Writer, tenant string, privateCIDR string) {
	if config.localDNS == nil {
		return
	}
	suffix := strings.TrimSpace(tenant)
	if summary, err := findTenantSummary(ctx, config, tenant); err == nil && strings.TrimSpace(summary.DNSSuffix) != "" {
		suffix = strings.TrimSpace(summary.DNSSuffix)
	}
	installPlan, err := localdns.PlanForV2(tenant, suffix, privateCIDR)
	if err != nil {
		fmt.Fprintf(out, "  ⚠ local resolver skipped: %v (use a Tailscale Split DNS entry for *.%s)\n", err, suffix)
		return
	}
	if _, _, err := runLocalDNSWithSudoFallback(ctx, config, "install", installPlan); err != nil {
		fmt.Fprintf(out, "  ⚠ local resolver not configured: %v\n     names still resolve via `dig @%s` or a Tailscale Split DNS entry for *.%s\n", err, installPlan.DNSEndpoint, suffix)
		return
	}
	fmt.Fprintf(out, "  ✓ local resolver: *.%s → tenant CoreDNS at %s\n", suffix, installPlan.DNSEndpoint)
}

func newDNSTeardownCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "teardown [tenant]",
		Short: "Remove local resolver config for a tenant",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reference := optionalArg(args)
			uninstallPlan, err := localdns.PlanUninstall(cmd.Context(), config.adminConfig, config.tenantStore, localdns.Request{Reference: reference})
			if err != nil {
				return err
			}
			if config.localDNS == nil {
				return fmt.Errorf("local DNS executor is not configured")
			}
			uninstallResult, uninstallElevated, err := runLocalDNSWithSudoFallback(cmd.Context(), config, "uninstall", uninstallPlan)
			if err != nil {
				return err
			}
			result := dnsTeardownResult{
				Reference: uninstallPlan.Reference,
				Uninstall: uninstallResult,
				Elevated:  elevatedActions([]string{"uninstall"}, uninstallElevated),
			}
			return writeOutput(config.stdout, opts.output, formatDNSTeardown(result), result)
		},
	}
	return command
}

func newDNSUninstallCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "uninstall [tenant]",
		Short: "Remove local resolver state for a tenant",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := localdns.PlanUninstall(cmd.Context(), config.adminConfig, config.tenantStore, localdns.Request{Reference: optionalReference(args)})
			if err != nil {
				return err
			}
			if dryRun {
				return writeOutput(config.stdout, opts.output, formatLocalDNSPlan("Uninstall", plan), plan)
			}
			if config.localDNS == nil {
				return fmt.Errorf("local DNS executor is not configured")
			}
			result, err := config.localDNS.Uninstall(cmd.Context(), plan)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatLocalDNSResult(result), result)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the local DNS uninstall plan without changing local resolver state")
	return command
}

func findTenantSummary(ctx context.Context, config commandConfig, reference string) (tenant.Summary, error) {
	ref, err := naming.ParseTenantRef(reference)
	if err != nil {
		return tenant.Summary{}, err
	}
	tenants, err := scopedListTenants(ctx, config, ref.Tenant)
	if err != nil {
		return tenant.Summary{}, err
	}
	for _, summary := range tenants {
		if summary.Tenant == ref.Tenant {
			return summary, nil
		}
	}
	return tenant.Summary{}, fmt.Errorf("Sandcastle tenant %s not found", ref.String())
}

func formatDNSApply(result dns.ApplyResult) string {
	return fmt.Sprintf("DNS records for %s: %d", result.Tenant.Tenant, result.RecordCount)
}

func formatLocalDNSPlan(action string, plan localdns.Plan) string {
	output := fmt.Sprintf("%s local DNS: %s\nDNS suffix: %s\nTenant DNS: %s\nResolver: %s", action, plan.Reference, plan.DNSSuffix, plan.DNSEndpoint, plan.ResolverStrategy)
	if len(plan.ResolverCommands) > 0 {
		output += "\nResolver commands:"
		for _, command := range plan.ResolverCommands {
			output += "\n  " + strings.Join(command.Args, " ")
		}
	}
	return output
}

func formatLocalDNSResult(result localdns.Result) string {
	return fmt.Sprintf("%s local DNS: %s\nState: %s\nResolver: %s", result.Action, result.Reference, result.StatePath, result.ResolverPath)
}

func formatDNSSetup(result dnsSetupResult) string {
	output := fmt.Sprintf("DNS setup: %s\nDNS records: %d\nResolver: %s\nState: %s", result.Reference, result.Apply.RecordCount, result.Install.ResolverPath, result.Install.StatePath)
	if len(result.Elevated) > 0 {
		actions := make([]string, 0, len(result.Elevated))
		for _, action := range result.Elevated {
			actions = append(actions, action.Action)
		}
		output += "\nElevated: " + strings.Join(actions, ", ")
	}
	return output
}

func formatDNSTeardown(result dnsTeardownResult) string {
	output := fmt.Sprintf("DNS teardown: %s\nResolver: %s\nState: %s", result.Reference, result.Uninstall.ResolverPath, result.Uninstall.StatePath)
	if len(result.Elevated) > 0 {
		actions := make([]string, 0, len(result.Elevated))
		for _, action := range result.Elevated {
			actions = append(actions, action.Action)
		}
		output += "\nElevated: " + strings.Join(actions, ", ")
	}
	return output
}

func dnsProject(summary tenant.Summary) dns.Tenant {
	return dns.Tenant{
		IncusName:      summary.IncusName,
		InfraProject:   summary.InfraProject,
		Tenant:         summary.Tenant,
		DNSSuffix:      summary.DNSSuffix,
		DefaultProject: summary.DefaultProject,
		PrivateCIDR:    summary.PrivateCIDR,
	}
}

func runLocalDNSWithSudoFallback(ctx context.Context, config commandConfig, action string, plan localdns.Plan) (localdns.Result, bool, error) {
	result, err := runLocalDNSAction(ctx, config.localDNS, action, plan)
	if err == nil {
		return result, false, nil
	}
	if !isPermissionError(err) {
		return localdns.Result{}, false, err
	}
	if err := runElevatedDNSPlan(ctx, config, action, plan); err != nil {
		return localdns.Result{}, false, fmt.Errorf("%s local DNS requires privileges and sudo failed: %w", action, err)
	}
	return localdns.Result{
		Reference:    plan.Reference,
		Action:       action,
		StatePath:    plan.StatePath,
		ResolverPath: plan.ResolverPath,
	}, true, nil
}

func runLocalDNSAction(ctx context.Context, manager localdns.Manager, action string, plan localdns.Plan) (localdns.Result, error) {
	switch action {
	case "install":
		return manager.Install(ctx, plan)
	case "refresh":
		return manager.Refresh(ctx, plan)
	case "uninstall":
		return manager.Uninstall(ctx, plan)
	default:
		return localdns.Result{}, fmt.Errorf("unknown local DNS action %q", action)
	}
}

func isPermissionError(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "permission denied")
}

// runElevatedDNSPlan re-runs the *exact* plan under sudo. The elevated child
// must NOT re-derive the plan from the tenant store: a v2 restricted client
// can't see its infra project, so a store-derived plan has an empty CIDR (the
// same reason `sc dns setup` can't stand alone). Instead the parent serializes
// the fully-resolved plan and the hidden `dns apply-elevated` command executes
// it verbatim.
func runElevatedDNSPlan(ctx context.Context, config commandConfig, action string, plan localdns.Plan) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	args := []string{"env"}
	for _, entry := range sudoPassthroughEnv(config) {
		args = append(args, entry)
	}
	args = append(args, executable, "dns", "apply-elevated", "--action", action)
	command := exec.CommandContext(ctx, "sudo", args...)
	command.Stdin = bytes.NewReader(planJSON)
	if config.stderr != nil {
		command.Stdout = config.stderr
		command.Stderr = config.stderr
	}
	return command.Run()
}

func sudoPassthroughEnv(config commandConfig) []string {
	env := []string{}
	add := func(key string, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			env = append(env, key+"="+value)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		add("HOME", home)
	}
	add("SANDCASTLE_REMOTE", config.adminConfig.Remote)
	add("SANDCASTLE_TENANT", config.adminConfig.Tenant)
	add("SANDCASTLE_PROJECT", config.adminConfig.Project)
	add("SANDCASTLE_ADMIN_REMOTE", config.adminConfig.AdminRemote)
	for _, key := range []string{
		"INCUS_CONF",
		"SANDCASTLE_LOCAL_DNS_STATE",
		"SANDCASTLE_RESOLVER_DIR",
		"SANDCASTLE_BIN",
	} {
		add(key, os.Getenv(key))
	}
	return env
}

func elevatedActions(names []string, flags ...bool) []dnsElevatedActionResult {
	results := []dnsElevatedActionResult{}
	for index, elevated := range flags {
		if !elevated {
			continue
		}
		name := "local-dns"
		if index < len(names) {
			name = names[index]
		}
		results = append(results, dnsElevatedActionResult{Action: name})
	}
	return results
}
