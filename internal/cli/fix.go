package cli

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// machineFixup is a named, idempotent repair applied to a running machine over
// SSH (as the login user, via sudo). apply mutates; check is read-only. Both
// return a root /bin/sh script fed to the machine on stdin.
type machineFixup struct {
	name    string
	summary string
	apply   func() string
	check   func() string
	// central runs through the Machine's restricted Incus API rather than SSH.
	// It is used for bootstrap repairs that must work when SSH is the failure.
	central func(context.Context, commandConfig, tenant.Summary, string, bool) error
	// requiresPayload: this fixup's scripts consume the shared /.sc platform
	// payload, so `sc fix` converges it (via the Incus API, once per project)
	// before the per-machine script runs.
	requiresPayload bool
}

func anyFixupRequiresPayload(fixups []machineFixup) bool {
	for _, f := range fixups {
		if f.requiresPayload {
			return true
		}
	}
	return false
}

// machineFixups is the registry `sc fix` iterates. Add an entry when a change
// ships in cloud-init that older machines also need backfilled.
//
// requiresPayload marks fixups whose scripts consume the /.sc platform payload
// (ADR-0022): before running them, `sc fix` converges the project's shared
// sc-platform volume via the tenant's own Incus API — once per project, so the
// per-machine script only has to install the stable shims.
var machineFixups = []machineFixup{
	{
		name:    "ssh-key",
		summary: "reconcile the current CLI SSH key through Incus (works when SSH is locked out)",
		central: reconcileMachineSSHKeyFix,
	},
	{
		name:            "agent-forwarding",
		summary:         "forwarded SSH agent survives herdr/tmux panes (stable /.sc shims + shared payload)",
		apply:           tenant.SSHAgentForwardBackfillScript,
		check:           tenant.SSHAgentForwardCheckScript,
		requiresPayload: true,
	},
	{
		name:            "caddy-publications",
		summary:         "refresh Machine Caddy readiness for Tailnet and public-hostname certificates",
		apply:           tenant.CaddyPublicationsBackfillScript,
		check:           tenant.CaddyPublicationsCheckScript,
		requiresPayload: true,
	},
	{
		name:    "cloudflared",
		summary: "restore an already-installed Machine Cloudflare Tunnel connector",
		apply:   tenant.CloudflaredBackfillScript,
		check:   tenant.CloudflaredCheckScript,
	},
}

func newFixCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var checkOnly bool
	var only []string
	command := &cobra.Command{
		Use:   "fix [[remote:]project:]machine",
		Short: "Apply idempotent fixups to a Sandcastle machine",
		Long: `Apply idempotent maintenance fixups to a running machine over SSH.

Machines built before a fixup shipped in cloud-init never receive it — cloud-init
runs only at first boot — so "sc fix" backfills the change in place. It runs as
the machine's login user via sudo. With --check it only reports status and
changes nothing; --only limits it to the named fixup(s).

Fixups:
  ssh-key              reconcile the current CLI SSH key through Incus
  agent-forwarding     forwarded SSH agent survives herdr/tmux panes
  caddy-publications   refresh Caddy readiness for Tailnet/public certificates
  cloudflared          restore an already-installed Cloudflare connector`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			selected, err := selectFixups(only)
			if err != nil {
				return err
			}
			return withResolvedV2Machine(cmd, config, args[0], func(ctx context.Context, config commandConfig, summary tenant.Summary, reference string) error {
				return runFixV2(ctx, config, summary, reference, selected, checkOnly)
			})
		},
	}
	command.Flags().BoolVar(&checkOnly, "check", false, "report fixup status without changing anything")
	command.Flags().StringSliceVar(&only, "only", nil, "apply only the named fixup(s) (default: all; known: "+knownFixupNames()+")")
	return command
}

// selectFixups resolves the --only list against the registry, or returns all
// fixups when the list is empty.
func selectFixups(only []string) ([]machineFixup, error) {
	if len(only) == 0 {
		return machineFixups, nil
	}
	byName := make(map[string]machineFixup, len(machineFixups))
	for _, f := range machineFixups {
		byName[f.name] = f
	}
	out := make([]machineFixup, 0, len(only))
	for _, name := range only {
		f, ok := byName[strings.TrimSpace(name)]
		if !ok {
			return nil, fmt.Errorf("unknown fixup %q (known: %s)", name, knownFixupNames())
		}
		out = append(out, f)
	}
	return out, nil
}

func knownFixupNames() string {
	names := make([]string, 0, len(machineFixups))
	for _, f := range machineFixups {
		names = append(names, f.name)
	}
	return strings.Join(names, ", ")
}

// runFixV2 dials the machine and runs each selected fixup's script as root via
// `sudo sh -s`, feeding the script on stdin so there is nothing to shell-quote.
func runFixV2(ctx context.Context, config commandConfig, summary tenant.Summary, reference string, fixups []machineFixup, checkOnly bool) error {
	var central, sshFixups []machineFixup
	for _, fixup := range fixups {
		if fixup.central != nil {
			central = append(central, fixup)
		} else {
			sshFixups = append(sshFixups, fixup)
		}
	}
	var failed []string
	for _, fixup := range central {
		fmt.Fprintf(config.stdout, "\n[%s] %s\n", fixup.name, fixup.summary)
		if err := fixup.central(ctx, config, summary, reference, checkOnly); err != nil {
			failed = append(failed, fixup.name)
			fmt.Fprintln(config.stderr, err)
		}
	}
	if len(sshFixups) == 0 {
		if len(failed) > 0 {
			return fmt.Errorf("fixup(s) failed: %s", strings.Join(failed, ", "))
		}
		return nil
	}
	dialed, err := dialV2Machine(ctx, config, summary, reference, launchV2Options{})
	if err != nil {
		return err
	}
	// Every fixup here is about the interactive half of a machine — the /.sc
	// shell shims, the forwarded agent, sshd. A bare machine has none of it by
	// design, so there is nothing to fix rather than something broken.
	if dialed.bare {
		return fmt.Errorf("machine %s was created with --bare: it has no login user, no sshd and no shell setup, so there is nothing for `sc fix` to install", dialed.machine)
	}
	verb := "Fixing"
	if checkOnly {
		verb = "Checking"
	}
	fmt.Fprintf(config.stdout, "%s %s (%s@%s)\n", verb, dialed.machine, dialed.loginUser, dialed.privateIP)

	// Central half first (ADR-0022): the payload lives on the project's shared
	// /.sc volume, so it is converged once over the Incus API — the per-machine
	// scripts below only install the stable shims that source it.
	if anyFixupRequiresPayload(sshFixups) {
		status, err := config.tenantCreator.EnsureProjectPlatformPayload(ctx, summary.V2IncusProjectName(dialed.project), checkOnly)
		if err != nil {
			// --check stays report-only: surface the problem, keep checking.
			fmt.Fprintf(config.stderr, "/.sc payload: %v\n", err)
			if !checkOnly {
				failed = append(failed, "sc-payload")
			}
		} else {
			fmt.Fprintf(config.stdout, "/.sc payload: %s\n", formatSCPayloadStatus(status))
		}
	}
	for _, f := range sshFixups {
		script := f.apply()
		if checkOnly {
			script = f.check()
		}
		fmt.Fprintf(config.stdout, "\n[%s] %s\n", f.name, f.summary)
		// The login user has sudo NOPASSWD; `sh -s` reads the script from stdin,
		// so there is nothing to shell-quote. Command mode allocates no PTY, so
		// stdin pipes cleanly.
		sshArgs := append(append([]string{}, dialed.sshArgs...), "sudo", "sh", "-s")
		sshCmd := exec.CommandContext(ctx, "ssh", sshArgs...)
		sshCmd.Stdin = strings.NewReader(script)
		sshCmd.Stdout = config.stdout
		sshCmd.Stderr = config.stderr
		if err := sshCmd.Run(); err != nil {
			failed = append(failed, f.name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("fixup(s) failed: %s", strings.Join(failed, ", "))
	}
	return nil
}

func reconcileMachineSSHKeyFix(ctx context.Context, config commandConfig, summary tenant.Summary, reference string, checkOnly bool) error {
	key, err := prepareLoginSSHKey(loginSSHKeyRequest{})
	if err != nil {
		return err
	}
	project, machine, err := resolveV2MachineReference(summary, reference, config.adminConfig.Project)
	if err != nil {
		return err
	}
	if checkOnly {
		fmt.Fprintf(config.stdout, "  current CLI key: %s\nssh-key: READY (run without --check to reconcile %s)\n", key.Fingerprint, project)
		return nil
	}
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return fmt.Errorf("no Sandcastle-managed Incus config found for remote %q", config.adminConfig.Remote)
	}
	reconciler := incusx.MachineSSHKeyReconciler{
		Remote:     config.adminConfig.Remote,
		ConfigPath: incusDir + "/config.yml",
		Store:      config.machineStore,
	}
	enrolled, err := reconciler.ReconcileMachineUserSSHKey(ctx, summary, project, machine, defaultLocalUnixUsername(), key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Fprintf(config.stdout, "  enrolled %s for project %s (additive: no existing key was removed)\n", key.Fingerprint, project)
	if len(enrolled) > 0 {
		fmt.Fprintf(config.stdout, "  authorized_keys on %s:\n", machine)
		for _, line := range enrolled {
			marker := ""
			if strings.Contains(line, key.Fingerprint) {
				marker = "   <- current CLI key"
			}
			fmt.Fprintf(config.stdout, "    %s%s\n", line, marker)
		}
	}
	fmt.Fprintln(config.stdout, "ssh-key: installed")
	return nil
}
