package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
)

type scratchMigratePayload struct {
	Tenant   string                          `json:"tenant"`
	Check    bool                            `json:"check"`
	Projects []string                        `json:"projects,omitempty"`
	Machines []incusx.ScratchMigrationStatus `json:"machines"`
}

// sc-adm tenant scratch-migrate: give the machines created before scratch
// volumes existed their own /scratch volume (#210).
func newAdminTenantScratchMigrateCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var checkOnly bool
	var projects []string
	command := &cobra.Command{
		Use:   "scratch-migrate tenant",
		Short: "Attach a scratch volume to every machine of a tenant that has none",
		Long: `Create the default-size scratch volume <machine>-scratch for every machine of
the tenant that has no scratch device yet, and attach it at /scratch. It never
moves or deletes data, and a second run changes nothing. Running containers
see /scratch at once; a stopped machine on its next start; a running VM is
reported as attached at its next restart. Inside the machine, /tmp and
/var/tmp move onto /scratch once the sc-scratch unit runs: run
"sc fix <machine> --only scratch" on machines created before the unit
shipped, then restart them. A --bare machine has no login for sc fix and is
skipped; re-create it to get scratch. With --check it only lists what it
would do, including the machines a same-name foreign volume would fail.
--project limits the run to one app project (short name such as "default", or
the full Incus project name); repeat it for several.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenantName := strings.TrimSpace(args[0])
			config, err := detectAdminPrefix(cmd.Context(), config, tenantName)
			if err != nil {
				return err
			}
			statuses, err := config.tenantCreator.MigrateTenantScratch(cmd.Context(), config.adminConfig.IncusProjectPrefix, tenantName, projects, checkOnly)
			if statuses != nil {
				if writeErr := writeOutput(config.stdout, opts.output, formatScratchMigration(statuses), scratchMigratePayload{Tenant: tenantName, Check: checkOnly, Projects: projects, Machines: statuses}); writeErr != nil {
					return writeErr
				}
			}
			return err
		},
	}
	command.Flags().BoolVar(&checkOnly, "check", false, "list the machines that would get a scratch volume without changing anything")
	command.Flags().StringArrayVar(&projects, "project", nil, "only this app project, short or full Incus name (repeatable)")
	return command
}

func formatScratchMigration(statuses []incusx.ScratchMigrationStatus) string {
	if len(statuses) == 0 {
		return "no machines"
	}
	lines := make([]string, 0, len(statuses))
	for _, s := range statuses {
		line := s.IncusProject + "/" + s.Machine + " (" + s.Type + "): " + scratchMigrationLabel(s.State)
		if s.Volume != "" {
			line += " [" + s.Volume + "]"
		}
		if s.Error != "" {
			line += ": " + s.Error
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func scratchMigrationLabel(state incusx.ScratchMigrationState) string {
	switch state {
	case incusx.ScratchPresent:
		return "already has scratch"
	case incusx.ScratchPlanned:
		return "would attach"
	case incusx.ScratchAttachedLive:
		return "attached (live)"
	case incusx.ScratchAttachedNextStart:
		return "attached (mounted at next start)"
	case incusx.ScratchAttachedNextRestart:
		return "attached (VM: restart to mount)"
	case incusx.ScratchSkippedBare:
		return "skipped (bare machine: re-create it to get scratch)"
	case incusx.ScratchFailed:
		return "FAILED"
	default:
		return string(state)
	}
}
