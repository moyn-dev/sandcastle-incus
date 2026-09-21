package cli

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// withResolvedV2Machine runs action against the install and summary that own the
// referenced machine, handling both the enrolled-remote prefix (rebind) and the
// cross-install DNS-suffix switch (ADR-0020). It is shared by `sc connect` and
// `sc fix` so both resolve `[[remote:]project:]machine` identically.
func withResolvedV2Machine(cmd *cobra.Command, config commandConfig, ref string, action func(ctx context.Context, config commandConfig, summary tenant.Summary, reference string) error) error {
	// A globbed install part is narrowed to a concrete remote name FIRST —
	// rebindForReference needs a literal one, and this command runs against a
	// single install. References that do not glob it pass through untouched.
	ref, err := narrowRemoteGlob(cmd.Context(), config, defaultRemoteFanout(), ref)
	if err != nil {
		return err
	}
	// Universal [[remote:]project:]machine: a leading enrolled-remote prefix
	// rebinds the whole command to that install (all stores); the reference
	// then continues as project:machine below.
	config, reference, restore, err := rebindForReference(config, ref)
	if err != nil {
		return err
	}
	defer restore()
	summary, err := requireV2Tenant(cmd.Context(), config)
	if err != nil {
		return err
	}
	// Cross-install (ADR-0020): if the reference names another install by its DNS
	// suffix, switch to that install's remote (and re-fetch its summary) first. A
	// same-install reference falls through unchanged.
	if dnsSuffix, project, machine, perr := parseV2MachineReference(reference, summary.Tenant, config.adminConfig.Project); perr == nil {
		switchTo, terr := resolveConnectTarget(dnsSuffix, summary.DNSSuffix, localRemoteExists)
		if terr != nil {
			return terr
		}
		if switchTo != "" {
			switched := switchConfigToRemote(config, switchTo, project)
			targetSummary, err := requireV2Tenant(cmd.Context(), switched)
			if err != nil {
				return err
			}
			return action(cmd.Context(), switched, targetSummary, project+":"+machine)
		}
	}
	return action(cmd.Context(), config, summary, reference)
}

func newConnectCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var useVM bool
	var homeShare bool
	var assumeYes bool
	command := &cobra.Command{
		Use:               "connect [[remote:]project:]machine [-- command...]",
		Aliases:           []string{"c"},
		Short:             "Connect to a Sandcastle machine",
		Args:              cobra.MinimumNArgs(1),
		ValidArgsFunction: pathCompletion(config, levelMachine),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Cache-first happy path: the machine is cached running with an
			// address and known_hosts already pins the identity its sshd
			// presents — one auth-app request + one keyscan, no live Incus
			// round trips. Any doubt falls through to the live path below.
			if dialed, ok := dialV2MachineViaCache(cmd.Context(), config, args[0]); ok {
				return runSSHSession(cmd.Context(), config, dialed, args[1:])
			}
			return withResolvedV2Machine(cmd, config, args[0], func(ctx context.Context, config commandConfig, summary tenant.Summary, reference string) error {
				return runConnectV2(ctx, config, summary, reference, args[1:], launchV2Options{
					VM:            useVM,
					HomeShare:     homeShare,
					ConfirmCreate: confirmCreateMissingMachine(config, assumeYes),
				})
			})
		},
	}
	command.Flags().BoolVar(&useVM, "vm", false, "when the machine has to be created first, launch a virtual machine instead of a container")
	command.Flags().BoolVar(&homeShare, "home-share", false, "when the machine has to be created first, mount the project's shared /home (homeshare profile)")
	command.Flags().BoolVar(&assumeYes, "yes", false, "create the machine without asking, when it does not exist yet")
	return command
}

// confirmCreateMissingMachine is the ConfirmCreate hook `sc connect` hands to
// the ensure path. Connecting to a name that is not there yet provisions a
// machine and waits for it to boot, which is a lot to hand a typo — so the
// creation branch asks first. --yes (or a non-interactive caller that passes
// it) keeps the old straight-through behaviour; without a terminal there is
// nobody to ask, so the missing --yes is an error rather than a silent create.
func confirmCreateMissingMachine(config commandConfig, assumeYes bool) func(project string, machine string) error {
	return func(project string, machine string) error {
		if assumeYes {
			return nil
		}
		path := currentMachinePath(config, project, machine)
		_, err := confirmMissingYesNamed(config,
			fmt.Sprintf("Machine %s does not exist. Create it?", path),
			fmt.Sprintf("machine %s does not exist; pass --yes to create it", path),
			"create canceled")
		return err
	}
}

// probeSSHPort reports whether the machine is accepting SSH yet. Kept from the
// deleted v1 connect path: runConnectV2 waits on it after creating a machine.
func probeSSHPort(host string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "22"), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
