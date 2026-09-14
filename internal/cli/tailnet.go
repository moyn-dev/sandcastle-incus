package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

type tailnetLegacyClient interface {
	UnpublishTailnetService(context.Context, authapp.TailnetPublicationRequest) (authapp.TailnetPublicationResult, error)
}

var _ tailnetLegacyClient = authapp.DeviceClient{}

func legacyTailnetClient(config commandConfig) (tailnetLegacyClient, bool) {
	if config.authTailnetLegacy != nil {
		return config.authTailnetLegacy, true
	}
	if !projectAuthAppAvailable(config, "") {
		return nil, false
	}
	return authapp.DeviceClient{BaseURL: commandAuthHostname(config, ""), AuthToken: config.adminConfig.AuthToken}, true
}

// Tailnet publication is intentionally separate from `sc tunnel publish`:
// it gives the Machine's private HTTPS endpoint a DNS-only Machine Public
// Hostname. The normal hostname reconciler owns the direct bridge A record,
// DNS-01 certificate and Machine Caddy site; it is never a Sidecar proxy.
func newTailnetCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{Use: "tailnet", Short: "Publish machine HTTPS services to a Tenant Tailnet"}
	command.AddCommand(newTailnetPublishCommand(config, opts))
	command.AddCommand(newTailnetUnpublishCommand(config, opts))
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
			client, ok := hostnameAuthClient(bound)
			if !ok {
				return errors.New("Tailnet publication requires sc login to an Auth App")
			}
			verboseCLI(bound, "tailnet: claiming Machine Public Hostname; the Auth App will converge direct-Machine DNS, certificate, and Caddy")
			result, err := client.AddMachineHostname(cmd.Context(), authapp.MachineHostnameRequest{Tenant: summary.Tenant, Hostname: name}, project, machine)
			if err != nil {
				return err
			}
			if err := setTailnetPublicationMetadata(cmd.Context(), bound, summary, project, machine, result.Hostname, true); err != nil {
				return err
			}
			return writeOutput(bound.stdout, opts.output, fmt.Sprintf("Tailnet HTTPS published: https://%s → %s:443", result.Hostname, machine), result)
		},
	}
	command.Flags().StringVar(&hostname, "hostname", "", "DNS-only public hostname for Tailnet access (required)")
	_ = command.MarkFlagRequired("hostname")
	return command
}

func newTailnetUnpublishCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var hostname string
	command := &cobra.Command{
		Use:   "unpublish [[remote:]project:]machine --hostname <fqdn>",
		Short: "Remove a machine HTTPS publication from its Tenant Tailnet",
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
			client, ok := hostnameAuthClient(bound)
			if !ok {
				return errors.New("Tailnet publication requires sc login to an Auth App")
			}
			verboseCLI(bound, "tailnet: releasing Machine Public Hostname; the Auth App will remove direct-Machine DNS and Caddy state")
			result, err := client.ListMachineHostnames(cmd.Context(), summary.Tenant, project, machine)
			if err != nil {
				return err
			}
			held := false
			for _, entry := range result.Hostnames {
				if !entry.Derived && entry.Hostname == name {
					held = true
					break
				}
			}
			if held {
				result, err = client.RemoveMachineHostname(cmd.Context(), summary.Tenant, project, machine, name, false)
				if err != nil {
					return err
				}
			} else {
				marked, err := tailnetPublicationMarked(cmd.Context(), bound, summary, project, machine, name)
				if err != nil {
					return err
				}
				if !marked {
					return writeOutput(bound.stdout, opts.output, fmt.Sprintf("Tailnet HTTPS unpublished: https://%s", name), result)
				}
				legacy, available := legacyTailnetClient(bound)
				if !available {
					return errors.New("Tailnet publication requires sc login to an Auth App")
				}
				if _, err := legacy.UnpublishTailnetService(cmd.Context(), authapp.TailnetPublicationRequest{Tenant: summary.Tenant, Project: project, Machine: machine, Hostname: name}); err != nil {
					return err
				}
				result.Released = name
			}
			if err := setTailnetPublicationMetadata(cmd.Context(), bound, summary, project, machine, result.Released, false); err != nil {
				return err
			}
			return writeOutput(bound.stdout, opts.output, fmt.Sprintf("Tailnet HTTPS unpublished: https://%s", result.Released), result)
		},
	}
	command.Flags().StringVar(&hostname, "hostname", "", "DNS-only public hostname to remove (required)")
	_ = command.MarkFlagRequired("hostname")
	return command
}

func tailnetPublicationMarked(ctx context.Context, config commandConfig, summary tenant.Summary, project, machine, hostname string) (bool, error) {
	names, err := readTailnetPublicationMetadata(ctx, config, summary, project, machine)
	if err != nil {
		return false, err
	}
	for _, name := range names {
		if name == hostname {
			return true, nil
		}
	}
	return false, nil
}

func readTailnetPublicationMetadata(ctx context.Context, config commandConfig, summary tenant.Summary, project, machine string) ([]string, error) {
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return nil, fmt.Errorf("no Sandcastle-managed Incus config found for remote %q; add one with: sc remote add", config.adminConfig.Remote)
	}
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+summary.V2IncusProjectName(project))
	var current bytes.Buffer
	if err := runner(ctx, []string{"config", "get", machine, meta.KeyV2TailnetPublications}, env, config.stdin, &current, config.stderr); err != nil {
		return nil, fmt.Errorf("read Tailnet publication metadata: %w", err)
	}
	return meta.ParsePublicHostnames(current.String()), nil
}

// setTailnetPublicationMetadata maintains the additive display-only marker
// consumed by `sc ls`. The Machine Public Hostname API remains the authority
// for DNS, certificates and Caddy; this key only distinguishes names the
// tenant chose to publish through the Tailnet verb from other public names.
func setTailnetPublicationMetadata(ctx context.Context, config commandConfig, summary tenant.Summary, project, machine, hostname string, published bool) error {
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return fmt.Errorf("no Sandcastle-managed Incus config found for remote %q; add one with: sc remote add", config.adminConfig.Remote)
	}
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+summary.V2IncusProjectName(project))
	names, err := readTailnetPublicationMetadata(ctx, config, summary, project, machine)
	if err != nil {
		return err
	}
	if published {
		names = append(names, hostname)
	} else {
		kept := names[:0]
		for _, existing := range names {
			if existing != hostname {
				kept = append(kept, existing)
			}
		}
		names = kept
	}
	value := meta.FormatPublicHostnames(names)
	args := []string{"config", "set", machine, meta.KeyV2TailnetPublications, value}
	if strings.TrimSpace(value) == "" {
		args = []string{"config", "unset", machine, meta.KeyV2TailnetPublications}
	}
	if err := runner(ctx, args, env, config.stdin, config.stdout, config.stderr); err != nil {
		return fmt.Errorf("record Tailnet publication metadata: %w", err)
	}
	return nil
}
