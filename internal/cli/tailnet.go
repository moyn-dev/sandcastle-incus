package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
)

// Tailnet publication is intentionally separate from `sc tunnel publish`:
// it publishes the Machine's existing private HTTPS endpoint only to its
// Tenant Tailnet, using a DNS-only A record rather than Cloudflare ingress.
func newTailnetCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{Use: "tailnet", Short: "Publish machine HTTPS services to a Tenant Tailnet"}
	command.AddCommand(newTailnetPublishCommand(config, opts))
	return command
}

func newTailnetPublishCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var hostname string
	command := &cobra.Command{
		Use:   "publish [[remote:]project:]machine --hostname <fqdn>",
		Short: "Publish a machine's private HTTPS endpoint on its Tenant Tailnet",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := authapp.NormalizeMachineHostname(hostname)
			if err != nil {
				return err
			}
			bound, reference, restore, err := rebindForReference(config, args[0])
			if err != nil {
				return err
			}
			defer restore()
			summary, project, machine, err := hostnameTarget(cmd.Context(), bound, reference)
			if err != nil {
				return err
			}
			if !projectAuthAppAvailable(bound, "") {
				return fmt.Errorf("Tailnet publication requires sc login to an Auth App")
			}
			result, err := (authapp.DeviceClient{BaseURL: commandAuthHostname(bound, ""), AuthToken: bound.adminConfig.AuthToken, Verbose: os.Getenv("VERBOSE") == "1"}).PublishTailnetService(cmd.Context(), authapp.TailnetPublicationRequest{Tenant: summary.Tenant, Project: project, Machine: machine, Hostname: name})
			if err != nil {
				return err
			}
			for _, step := range result.Trace {
				verboseCLI(bound, "tailnet: %s", step)
			}
			payload := map[string]any{"project": project, "machine": machine, "hostname": result.Hostname, "targetPort": result.TargetPort, "tailnetIPv4": result.TailnetIPv4}
			return writeOutput(bound.stdout, opts.output, fmt.Sprintf("Tailnet HTTPS published: https://%s → %s:443", result.Hostname, machine), payload)
		},
	}
	command.Flags().StringVar(&hostname, "hostname", "", "DNS-only public hostname for Tailnet access (required)")
	_ = command.MarkFlagRequired("hostname")
	return command
}
