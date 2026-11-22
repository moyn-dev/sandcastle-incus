package cli

import (
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	"github.com/spf13/cobra"
)

func newAdminMachineListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "list tenant[/project]",
		Short: "List Sandcastle machines in a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, projectName, err := adminMachineListConfig(config, args[0])
			if err != nil {
				return err
			}
			result, err := listMachines(cmd.Context(), cfg, listMachinesRequest{
				Project:     projectName,
				AllProjects: projectName == "",
			})
			if err != nil {
				return err
			}
			return writeOutput(cfg.stdout, opts.output, formatMachineList(result, listRenderOptions{}), result)
		},
	}
	return command
}

func adminMachineListConfig(config commandConfig, reference string) (commandConfig, string, error) {
	if strings.Contains(reference, "/") {
		ref, err := naming.ParseProjectRef(reference)
		if err != nil {
			return commandConfig{}, "", err
		}
		config.adminConfig.Tenant = ref.Tenant
		config.adminConfig.Project = ""
		return config, ref.Project, nil
	}
	ref, err := naming.ParseTenantRef(reference)
	if err != nil {
		return commandConfig{}, "", err
	}
	config.adminConfig.Tenant = ref.Tenant
	config.adminConfig.Project = ""
	return config, "", nil
}
