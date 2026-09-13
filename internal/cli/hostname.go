package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Explicit Machine Public Hostnames (ADR-0028, spec machine-hostnames §3):
// `sc create <p>:<m> --hostname <fqdn>` and `sc hostname add|remove|list`.
// Every mutation rides the Auth App's token-gated
// /api/machines/{project}/{machine}/hostnames; the CLI only normalizes and
// rejects the obviously malformed, and prints the server's refusal verbatim.

// authMachineHostnameClient is the seam to the hostnames endpoints;
// authapp.DeviceClient satisfies it, tests inject a stub.
type authMachineHostnameClient interface {
	ListMachineHostnames(ctx context.Context, tenant, project, machine string) (authapp.MachineHostnamesResult, error)
	AddMachineHostname(ctx context.Context, request authapp.MachineHostnameRequest, project, machine string) (authapp.MachineHostnamesResult, error)
	RemoveMachineHostname(ctx context.Context, tenant, project, machine, hostname string, dryRun bool) (authapp.MachineHostnamesResult, error)
}

var _ authMachineHostnameClient = authapp.DeviceClient{}

// hostnameVerbsUnavailable is the broker-only / not-logged-in refusal — one
// sentence for the create flag and the verbs alike, since the cause is the
// same (no Auth App to claim through).
const hostnameVerbsUnavailable = "--hostname is not available on this install (log in to an Auth App with sc login)"

// hostnameAuthClient returns the injected client (tests) or a DeviceClient at
// the resolved Auth Hostname; ok is false when the CLI has no login.
func hostnameAuthClient(config commandConfig) (authMachineHostnameClient, bool) {
	if config.authMachineHostnames != nil {
		return config.authMachineHostnames, true
	}
	if !projectAuthAppAvailable(config, "") {
		return nil, false
	}
	return authapp.DeviceClient{BaseURL: commandAuthHostname(config, ""), AuthToken: config.adminConfig.AuthToken}, true
}

// normalizeHostnameFlags normalizes and deduplicates the --hostname values
// client-side, preserving the server's texts for the obviously malformed.
func normalizeHostnameFlags(values []string) ([]string, error) {
	seen := map[string]struct{}{}
	var names []string
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		name, err := authapp.NormalizeMachineHostname(value)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// claimedHostname is one name `sc create --hostname` reserved before the
// instance existed, with the certificate outcome the Auth App reported.
type claimedHostname struct {
	Hostname string
	Zone     string
	Outcome  machineCertificateOutcome
}

// claimMachineHostnamesBeforeCreate reserves every hostname for the machine
// about to be created (beforeCreate: the reservation and the pending
// certificate row are recorded, the instance key is stamped by the create
// call). The first refusal releases what was already claimed and is
// returned verbatim — nothing is created.
func claimMachineHostnamesBeforeCreate(ctx context.Context, client authMachineHostnameClient, tenantName, project, machine string, hostnames []string, dryRun bool) ([]claimedHostname, error) {
	var claimed []claimedHostname
	for _, hostname := range hostnames {
		result, err := client.AddMachineHostname(ctx, authapp.MachineHostnameRequest{Tenant: tenantName, Hostname: hostname, DryRun: dryRun, BeforeCreate: true}, project, machine)
		if err != nil {
			if !dryRun {
				releaseMachineHostnames(ctx, client, tenantName, project, machine, claimed)
			}
			return nil, err
		}
		entry := claimedHostname{Hostname: result.Hostname, Zone: result.Zone}
		if result.Certificate != nil {
			entry.Outcome = machineCertificateOutcome{State: result.Certificate.State, Reason: result.Certificate.Reason, Message: result.Certificate.Error}
		}
		claimed = append(claimed, entry)
	}
	return claimed, nil
}

// releaseMachineHostnames frees reservations after a failed create. Best
// effort: a release that fails is reported on stderr by the caller's error,
// and the slow-loop GC drops the row once it sees no such machine.
func releaseMachineHostnames(ctx context.Context, client authMachineHostnameClient, tenantName, project, machine string, claimed []claimedHostname) []error {
	var errs []error
	for _, entry := range claimed {
		if _, err := client.RemoveMachineHostname(ctx, tenantName, project, machine, entry.Hostname, false); err != nil {
			errs = append(errs, fmt.Errorf("release %s: %w", entry.Hostname, err))
		}
	}
	return errs
}

// ── sc hostname ──────────────────────────────────────────────────────────────

func newHostnameCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "hostname",
		Short: "Manage a machine's explicit public hostnames (ADR-0028)",
		Long: `Add, remove or list the explicit Machine Public Hostnames of a machine.
A hostname is any name under a Public DNS Zone the admin registered (apex-level
names like web12.tc42.uk included); it reserves itself and its wildcard subtree
install-wide, first come, and never overlaps a Project Domain, another
hostname or a Public Route. The derived <machine>.<project domain> name is
listed too but cannot be removed per machine — it goes with the project's
domain. Every verb needs sc login; mutations take --dry-run.`,
	}
	command.AddCommand(newHostnameAddCommand(config, opts))
	command.AddCommand(newHostnameRemoveCommand(config, opts))
	command.AddCommand(newHostnameListCommand(config, opts))
	return command
}

// hostnameTarget resolves "<project>:<machine>" against the current tenant.
// The machine must be named exactly (no wildcard), and it must exist unless
// mustExist is false.
func hostnameTarget(ctx context.Context, config commandConfig, reference string) (tenant.Summary, string, string, error) {
	summary, err := requireV2Tenant(ctx, config)
	if err != nil {
		return tenant.Summary{}, "", "", err
	}
	project, machine, err := resolveV2MachineTarget(ctx, config, summary, reference)
	if err != nil {
		return tenant.Summary{}, "", "", err
	}
	return summary, project, machine, nil
}

func newHostnameAddCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "add [[remote:]project:]machine fqdn",
		Short: "Claim an explicit public hostname for a machine",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, reference, restore, err := rebindForReference(config, args[0])
			if err != nil {
				return err
			}
			defer restore()
			hostname, err := authapp.NormalizeMachineHostname(args[1])
			if err != nil {
				return err
			}
			client, ok := hostnameAuthClient(config)
			if !ok {
				return errors.New(hostnameVerbsUnavailable)
			}
			summary, project, machine, err := hostnameTarget(cmd.Context(), config, reference)
			if err != nil {
				return err
			}
			result, err := client.AddMachineHostname(cmd.Context(), authapp.MachineHostnameRequest{Tenant: summary.Tenant, Hostname: hostname, DryRun: dryRun}, project, machine)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatHostnameResult("add", result), result)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "validate the claim (zone, conflicts) without changing anything")
	return command
}

func newHostnameRemoveCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:     "remove [[remote:]project:]machine fqdn",
		Aliases: []string{"rm"},
		Short:   "Release an explicit public hostname of a machine",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, reference, restore, err := rebindForReference(config, args[0])
			if err != nil {
				return err
			}
			defer restore()
			hostname, err := authapp.NormalizeMachineHostname(args[1])
			if err != nil {
				return err
			}
			client, ok := hostnameAuthClient(config)
			if !ok {
				return errors.New(hostnameVerbsUnavailable)
			}
			summary, project, machine, err := hostnameTarget(cmd.Context(), config, reference)
			if err != nil {
				return err
			}
			result, err := client.RemoveMachineHostname(cmd.Context(), summary.Tenant, project, machine, hostname, dryRun)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatHostnameResult("remove", result), result)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "check the release without changing anything")
	return command
}

func newHostnameListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:     "list [[remote:]project:]machine",
		Aliases: []string{"ls"},
		Short:   "List a machine's public hostnames (derived and explicit)",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, reference, restore, err := rebindForReference(config, args[0])
			if err != nil {
				return err
			}
			defer restore()
			client, ok := hostnameAuthClient(config)
			if !ok {
				return errors.New(hostnameVerbsUnavailable)
			}
			summary, project, machine, err := hostnameTarget(cmd.Context(), config, reference)
			if err != nil {
				return err
			}
			result, err := client.ListMachineHostnames(cmd.Context(), summary.Tenant, project, machine)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatHostnameResult("list", result), result)
		},
	}
}

// formatHostnameResult renders the verbs' text output: one line for what
// happened, then the machine's full public-name set.
func formatHostnameResult(verb string, result authapp.MachineHostnamesResult) string {
	var builder strings.Builder
	ref := result.Project + ":" + result.Machine
	switch {
	case verb == "add" && result.DryRun:
		fmt.Fprintf(&builder, "[dry-run] would have: claimed %s for machine %s", result.Hostname, ref)
		if result.Zone != "" {
			fmt.Fprintf(&builder, " (zone %s)", result.Zone)
		}
		fmt.Fprintln(&builder)
	case verb == "add" && result.AlreadyHeld:
		fmt.Fprintf(&builder, "machine hostname %q already held by this machine\n", result.Hostname)
	case verb == "add":
		fmt.Fprintf(&builder, "Public name: %s (%s)\n", result.Hostname, hostnameCertificateDetail(result))
	case verb == "remove" && result.DryRun:
		fmt.Fprintf(&builder, "[dry-run] would have: released %s from machine %s\n", result.Released, ref)
	case verb == "remove":
		fmt.Fprintf(&builder, "Released %s from machine %s.\n", result.Released, ref)
	}
	if len(result.Hostnames) == 0 {
		fmt.Fprintf(&builder, "Machine %s has no public name.", ref)
		return builder.String()
	}
	table := [][]string{{"PUBLIC NAME", "KIND", "ZONE"}}
	for _, h := range result.Hostnames {
		kind := "explicit"
		if h.Derived {
			kind = "derived"
		}
		table = append(table, []string{h.Hostname, kind, orDash(h.Zone)})
	}
	fmt.Fprint(&builder, formatAlignedTable(table))
	return strings.TrimRight(builder.String(), "\n")
}

// hostnameCertificateDetail is the parenthesis of a fresh add: what the Auth
// App recorded for the name's certificate.
func hostnameCertificateDetail(result authapp.MachineHostnamesResult) string {
	if result.Certificate == nil {
		return "certificate pending"
	}
	switch {
	case result.Certificate.Reason != "":
		detail := "certificate pending: " + result.Certificate.Reason
		if message := strings.TrimSpace(result.Certificate.Error); message != "" {
			detail += " — " + message
		}
		return detail
	case result.Certificate.State == "issued":
		return "certificate retained, installing"
	}
	return "certificate pending"
}
