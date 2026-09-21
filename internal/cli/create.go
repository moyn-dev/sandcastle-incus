package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newCreateCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	var detach bool
	var image string
	var vm bool
	var homeShare bool
	var bare bool
	var hostnames []string
	var aliases []string
	command := &cobra.Command{
		Use:               "create [[remote:]project:]machine",
		Aliases:           []string{"new"},
		Short:             "Create a Sandcastle container machine",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: pathCompletion(config, levelMachine),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, reference, restore, err := rebindForReference(config, args[0])
			if err != nil {
				return err
			}
			defer restore()
			if err := requireProjectPosition(config, reference, "create"); err != nil {
				return err
			}
			summary, err := requireV2Tenant(cmd.Context(), config)
			if err != nil {
				return err
			}
			return runCreateMachineV2(cmd.Context(), config, opts, summary, reference, createV2Options{
				Image:     image,
				VM:        vm,
				DryRun:    dryRun,
				HomeShare: homeShare,
				Bare:      bare,
				Hostnames: hostnames,
				Aliases:   aliases,
			})
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the machine creation plan without creating a container")
	// --detach/--background are accepted no-ops: v2 machine creation never
	// attaches, and the e2e protocol passes --detach throughout.
	command.Flags().BoolVar(&detach, "detach", false, "deprecated no-op; machine creation never attaches")
	command.Flags().BoolVar(&detach, "background", false, "deprecated no-op; machine creation never attaches")
	command.Flags().StringVar(&image, "image", "", "image to launch (default "+v2DefaultMachineImage+")")
	command.Flags().BoolVar(&vm, "vm", false, "launch a virtual machine instead of a container")
	// Profiles are only applied at create time, so this is a create-time
	// decision: /workspace is shared for every machine, /home only on request.
	command.Flags().BoolVar(&homeShare, "home-share", false, "mount the project's shared /home (adds the homeshare profile); without it the machine gets a local /home")
	// A bare machine has no way in, by design — say so on the flag itself,
	// because `sc connect` to one can only ever time out waiting for sshd.
	command.Flags().BoolVar(&bare, "bare", false, "no login user, no SSH key, no sshd — just the machine's hostname and a Caddy serving its tenant-CA leaf (sc connect will not work)")
	// Explicit Machine Public Hostnames (ADR-0028): claimed through the Auth
	// App BEFORE the instance exists, released again if the create fails.
	// Both flags append to ONE list (a plain StringArrayVar per flag would
	// let the second flag's first value replace the first flag's), so
	// --hostname and --fqdn mix freely.
	command.Flags().Var(&appendStringFlag{target: &aliases}, "alias", "one-label alias under the Project Domain (repeatable; uses the project certificate)")
	command.Flags().Var(&appendStringFlag{target: &hostnames}, "hostname", "explicit public hostname under a registered Public DNS Zone (repeatable; alias --fqdn); claimed before the machine is created")
	command.Flags().Var(&appendStringFlag{target: &hostnames}, "fqdn", "alias of --hostname")
	return command
}

// appendStringFlag is a repeatable string flag whose every occurrence appends
// to a shared slice — the shape that lets two flag names feed one list.
type appendStringFlag struct{ target *[]string }

func (f *appendStringFlag) String() string {
	if f.target == nil {
		return "[]"
	}
	return fmt.Sprintf("%v", *f.target)
}

func (f *appendStringFlag) Set(value string) error {
	*f.target = append(*f.target, value)
	return nil
}

func (f *appendStringFlag) Type() string { return "stringArray" }
