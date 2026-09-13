package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/hostkeys"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

type sshKeyPurgePayload struct {
	Tenant  string   `json:"tenant"`
	Changes []string `json:"changes"`
	Applied bool     `json:"applied"`
}

func newSSHKeyPurgeCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var allTenants bool
	var assumeYes bool
	var dryRun bool
	command := &cobra.Command{
		Use:   "purge",
		Short: "Reconcile ~/.ssh/known_hosts against live machines and drop stale Sandcastle entries",
		Long: "Reads every live machine's SSH host key over the Incus API, rewrites the entries " +
			"Sandcastle owns, removes entries for machines that no longer exist, and removes " +
			"untagged entries for private IPs inside the tenant's own CIDR.\n\n" +
			"Entries Sandcastle did not write are never removed, except literal IP addresses " +
			"inside the tenant CIDR — those are recycled DHCP leases with no lasting owner.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			summaries, err := purgeTargetTenants(cmd.Context(), config, allTenants)
			if err != nil {
				return err
			}
			var payloads []sshKeyPurgePayload
			for _, summary := range summaries {
				payload, err := purgeTenantHostKeys(cmd.Context(), config, summary, assumeYes, dryRun)
				if err != nil {
					return err
				}
				payloads = append(payloads, payload)
			}
			return writeOutput(config.stdout, opts.output, formatSSHKeyPurge(payloads), payloads)
		},
	}
	command.Flags().BoolVar(&allTenants, "all", false, "purge every v2 tenant this install knows, not just the current one")
	command.Flags().BoolVar(&assumeYes, "yes", false, "apply without asking for confirmation")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "report the changes without touching known_hosts")
	return command
}

// purgeTargetTenants resolves which tenants to reconcile. Host-key management
// is a v2 mechanism; v1 machines keep their own per-tenant known_hosts file.
func purgeTargetTenants(ctx context.Context, config commandConfig, allTenants bool) ([]tenant.Summary, error) {
	summary, isV2, err := v2TenantSummary(ctx, config)
	if err != nil {
		return nil, err
	}
	if !allTenants {
		if !isV2 {
			return nil, fmt.Errorf("ssh-key purge requires a v2 tenant")
		}
		return []tenant.Summary{summary}, nil
	}
	tenants, err := tenant.ListForPrefix(ctx, config.tenantStore, installPrefixForRemote(config, config.adminConfig.Tenant))
	if err != nil {
		return nil, err
	}
	var v2Tenants []tenant.Summary
	for _, candidate := range tenants {
		if candidate.Version == 2 {
			v2Tenants = append(v2Tenants, candidate)
		}
	}
	if len(v2Tenants) == 0 {
		return nil, fmt.Errorf("no v2 tenants found on remote %s", config.adminConfig.Remote)
	}
	return v2Tenants, nil
}

func purgeTenantHostKeys(ctx context.Context, config commandConfig, summary tenant.Summary, assumeYes bool, dryRun bool) (sshKeyPurgePayload, error) {
	refs, err := config.tenantCreator.ListMachinesV2(ctx, summary.InfraProject)
	if err != nil {
		return sshKeyPurgePayload{}, err
	}
	machines := make([]hostkeys.Machine, 0, len(refs))
	privateCIDR := ""
	for _, ref := range refs {
		// A zone-mode machine (ADR-0027) owns exactly its Machine Public
		// Hostname in known_hosts; a private one its ADR-0018 names. Either
		// way the names are claimed so the purge never mistakes them for
		// orphans and rewrites them like any other owned entry.
		names := v2MachineNames(summary, ref.Project, ref.Name, ref.PublicHostname)
		if len(names) == 0 {
			continue
		}
		incusProject := summary.V2IncusProjectName(ref.Project)
		machine := hostkeys.Machine{Names: names}
		// An unreadable machine (VM with no agent, mid-boot) keeps whatever is
		// recorded: its names stay claimed so its lines are not mistaken for
		// orphans, but nothing is rewritten.
		if keys, err := config.tenantCreator.MachineHostKeysV2(ctx, incusProject, ref.Name); err == nil {
			machine.Keys = toHostKeys(keys)
		} else {
			verboseCLI(config, "host key: %s unreadable, leaving its entries alone: %v", ref.Name, err)
		}
		// Any running machine can tell us the tenant subnet; the bridge itself
		// is invisible to a restricted certificate.
		if privateCIDR == "" {
			if cidr, err := config.tenantCreator.MachineSubnetV2(ctx, incusProject, ref.Name); err == nil {
				privateCIDR = cidr
			}
		}
		machines = append(machines, machine)
	}

	keysConfig := hostKeysConfig(config, summary, privateCIDR)
	if keysConfig.Path == "" {
		return sshKeyPurgePayload{}, fmt.Errorf("cannot locate ~/.ssh/known_hosts")
	}
	plan, err := keysConfig.Purge(machines)
	if err != nil {
		return sshKeyPurgePayload{}, err
	}
	payload := sshKeyPurgePayload{Tenant: summary.Tenant}
	for _, change := range plan.Changes {
		payload.Changes = append(payload.Changes, change.String())
	}
	if config.stderr != nil {
		subnet := "no private CIDR"
		if keysConfig.CIDR.IsValid() {
			subnet = keysConfig.CIDR.String()
		}
		fmt.Fprintf(config.stderr, "tenant %s (%s, %d live machines):\n", summary.Tenant, subnet, len(machines))
		for _, warning := range plan.Warnings {
			fmt.Fprintf(config.stderr, "  warning: %s\n", warning)
		}
		if !keysConfig.CIDR.IsValid() {
			fmt.Fprintln(config.stderr, "  note: no running machine could report the tenant subnet; skipping recycled-IP purge")
		}
		if plan.PurgeSkipped != "" {
			fmt.Fprintf(config.stderr, "  note: %s\n", plan.PurgeSkipped)
		}
		for _, change := range plan.Changes {
			fmt.Fprintf(config.stderr, "  %s\n", change)
		}
	}
	if plan.Empty() {
		if config.stderr != nil {
			fmt.Fprintln(config.stderr, "  nothing to do")
		}
		return payload, nil
	}
	if dryRun {
		return payload, nil
	}
	if !assumeYes {
		if _, err := confirmMissingYesNamed(config,
			fmt.Sprintf("Apply %d change(s) to %s?", len(plan.Changes), keysConfig.Path),
			"refusing to modify known_hosts without --yes", "purge canceled"); err != nil {
			return sshKeyPurgePayload{}, err
		}
	}
	if err := plan.Apply(); err != nil {
		return sshKeyPurgePayload{}, err
	}
	payload.Applied = true
	return payload, nil
}

func formatSSHKeyPurge(payloads []sshKeyPurgePayload) string {
	total := 0
	for _, payload := range payloads {
		total += len(payload.Changes)
	}
	if total == 0 {
		return "known_hosts is already current"
	}
	applied := 0
	for _, payload := range payloads {
		if payload.Applied {
			applied++
		}
	}
	if applied == 0 {
		return fmt.Sprintf("%d change(s) reported, none applied", total)
	}
	return fmt.Sprintf("%d change(s) applied across %d tenant(s)", total, applied)
}
