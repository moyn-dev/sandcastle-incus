package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
)

// `public-dns-zone add|list|remove|set-token` — the Public DNS Zone registry
// (ADR-0027, spec public-dns-zones §2.1). Mounted on BOTH admin roots
// (`sc admin public-dns-zone …` and `sc-adm public-dns-zone …`). Every verb is
// a thin client of /api/public-dns-zones using the admin's CLI Auth Token, so
// it works through a tunnel and needs no appliance restart or redeploy.

// authPublicDNSZoneClient is the seam tests fill with a fake; production uses
// authapp.DeviceClient.
type authPublicDNSZoneClient interface {
	ListPublicDNSZones(context.Context) ([]authapp.PublicDNSZone, error)
	AddPublicDNSZone(ctx context.Context, zone, token string, dryRun bool) (authapp.PublicDNSZoneResult, error)
	SetPublicDNSZoneToken(ctx context.Context, zone, token string, dryRun bool) (authapp.PublicDNSZoneResult, error)
	RemovePublicDNSZone(ctx context.Context, zone string, dryRun bool) (authapp.PublicDNSZoneResult, error)
}

var _ authPublicDNSZoneClient = authapp.DeviceClient{}

const publicDNSZoneTokenScopeHelp = `Required Cloudflare API token scope, on that zone only:
  Zone > DNS > Edit    (runtime: A records and the DNS-01 challenge TXT records)
  Zone > Zone > Read   (used only at add / set-token to resolve the zone id)
Cloudflare tokens cannot be scoped below zone level — dedicate a zone to Sandcastle.`

func newPublicDNSZoneCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "public-dns-zone",
		Short: "Register the Public DNS Zones tenants may claim Project Domains under",
		Long: `Manage the install's Public DNS Zones (Cloudflare zones the Auth App holds a
token for). Tenants claim Project Domains under a registered zone, and every
Machine in such a project gets a Machine Public Hostname with a Let's Encrypt
certificate. Zones may not nest. Sandcastle Admin only.

` + publicDNSZoneTokenScopeHelp,
	}
	command.AddCommand(newPublicDNSZoneAddCommand(config, opts))
	command.AddCommand(newPublicDNSZoneListCommand(config, opts))
	command.AddCommand(newPublicDNSZoneRemoveCommand(config, opts))
	command.AddCommand(newPublicDNSZoneSetTokenCommand(config, opts))
	return command
}

func publicDNSZoneClient(config commandConfig) (authPublicDNSZoneClient, error) {
	if config.authPublicDNSZones != nil {
		return config.authPublicDNSZones, nil
	}
	if strings.TrimSpace(config.adminConfig.AuthToken) == "" {
		return nil, fmt.Errorf("CLI Auth Token is required; run sc login as a Sandcastle Admin")
	}
	baseURL := commandAuthHostname(config, "")
	if baseURL == "" {
		return nil, fmt.Errorf("Auth Hostname is required; run sc login")
	}
	return authapp.DeviceClient{BaseURL: baseURL, AuthToken: strings.TrimSpace(config.adminConfig.AuthToken), Tenant: strings.TrimSpace(config.adminConfig.Tenant)}, nil
}

// addTokenFlags wires the three ways a token reaches add/set-token.
func addTokenFlags(command *cobra.Command, token *string, tokenFile *string) {
	command.Flags().StringVar(token, "token", "", "Cloudflare API token (prefer --token-file or stdin so it stays out of shell history)")
	command.Flags().StringVar(tokenFile, "token-file", "", "read the Cloudflare API token from this file")
}

// readZoneToken resolves the token from --token, --token-file, or stdin, in
// that order; exactly one source must yield a non-empty token.
func readZoneToken(config commandConfig, token, tokenFile string) (string, error) {
	if strings.TrimSpace(token) != "" && strings.TrimSpace(tokenFile) != "" {
		return "", fmt.Errorf("use either --token or --token-file, not both")
	}
	if strings.TrimSpace(token) != "" {
		return strings.TrimSpace(token), nil
	}
	if strings.TrimSpace(tokenFile) != "" {
		data, err := os.ReadFile(strings.TrimSpace(tokenFile))
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		if value := strings.TrimSpace(string(data)); value != "" {
			return value, nil
		}
		return "", fmt.Errorf("token file %s is empty", tokenFile)
	}
	if config.stdin != nil {
		if config.stdinIsTerminal != nil && config.stdinIsTerminal(config.stdin) {
			fmt.Fprint(config.stderr, "Cloudflare API token (input hidden if piped): ")
		}
		data, err := io.ReadAll(io.LimitReader(config.stdin, 1<<16))
		if err != nil {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		if value := strings.TrimSpace(string(data)); value != "" {
			return value, nil
		}
	}
	return "", fmt.Errorf("a Cloudflare API token is required: pass --token, --token-file, or pipe it on stdin")
}

func newPublicDNSZoneAddCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var token, tokenFile string
	var dryRun bool
	command := &cobra.Command{
		Use:   "add <zone>",
		Short: "Register a Cloudflare zone (validates the token, stores it encrypted)",
		Long: `Register a Public DNS Zone. The Auth App validates the token against
Cloudflare (the zone must be visible to it, and DNS readable) before anything
is stored; a rejected token stores nothing. Registering a zone that is an
ancestor or descendant of a registered zone is refused: zones may not nest.

The token is read from --token, --token-file, or stdin.

` + publicDNSZoneTokenScopeHelp,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			zone, err := authapp.NormalizePublicDNSZone(args[0])
			if err != nil {
				return err
			}
			value, err := readZoneToken(config, token, tokenFile)
			if err != nil {
				return err
			}
			client, err := publicDNSZoneClient(config)
			if err != nil {
				return err
			}
			result, err := client.AddPublicDNSZone(cmd.Context(), zone, value, dryRun)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatPublicDNSZoneResult("Registered public DNS zone", result), result)
		},
	}
	addTokenFlags(command, &token, &tokenFile)
	command.Flags().BoolVar(&dryRun, "dry-run", false, "validate the zone and token against Cloudflare without storing anything")
	return command
}

func newPublicDNSZoneSetTokenCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var token, tokenFile string
	var dryRun bool
	command := &cobra.Command{
		Use:   "set-token <zone>",
		Short: "Rotate a registered zone's Cloudflare token in place",
		Long: `Replace the token of a registered Public DNS Zone. The new token is validated
against Cloudflare exactly like at add; a rejected token changes nothing.

The token is read from --token, --token-file, or stdin.

` + publicDNSZoneTokenScopeHelp,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			zone, err := authapp.NormalizePublicDNSZone(args[0])
			if err != nil {
				return err
			}
			value, err := readZoneToken(config, token, tokenFile)
			if err != nil {
				return err
			}
			client, err := publicDNSZoneClient(config)
			if err != nil {
				return err
			}
			result, err := client.SetPublicDNSZoneToken(cmd.Context(), zone, value, dryRun)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatPublicDNSZoneResult("Rotated token for public DNS zone", result), result)
		},
	}
	addTokenFlags(command, &token, &tokenFile)
	command.Flags().BoolVar(&dryRun, "dry-run", false, "validate the new token against Cloudflare without storing it")
	return command
}

func newPublicDNSZoneRemoveCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "remove <zone>",
		Short: "Unregister a zone (refused while any Project Domain is claimed under it)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			zone, err := authapp.NormalizePublicDNSZone(args[0])
			if err != nil {
				return err
			}
			client, err := publicDNSZoneClient(config)
			if err != nil {
				return err
			}
			result, err := client.RemovePublicDNSZone(cmd.Context(), zone, dryRun)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatPublicDNSZoneResult("Removed public DNS zone", result), result)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "check that the zone could be removed without removing it")
	return command
}

func newPublicDNSZoneListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered zones (token shown as a fingerprint only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := publicDNSZoneClient(config)
			if err != nil {
				return err
			}
			zones, err := client.ListPublicDNSZones(cmd.Context())
			if err != nil {
				return err
			}
			if zones == nil {
				zones = []authapp.PublicDNSZone{}
			}
			return writeOutput(config.stdout, opts.output, formatPublicDNSZoneList(zones), zones)
		},
	}
}

func formatPublicDNSZoneResult(verb string, result authapp.PublicDNSZoneResult) string {
	line := fmt.Sprintf("%s %s", verb, result.Zone)
	switch {
	case result.CloudflareZone != "" && result.CloudflareZone != result.Zone:
		line += fmt.Sprintf(" (inside Cloudflare zone %s, id %s)", result.CloudflareZone, result.CloudflareZoneID)
	case result.CloudflareZoneID != "":
		line += fmt.Sprintf(" (Cloudflare zone id %s)", result.CloudflareZoneID)
	}
	if result.DryRun {
		line = "[dry-run] would have: " + line
	}
	return line
}

func formatPublicDNSZoneList(zones []authapp.PublicDNSZone) string {
	var buffer bytes.Buffer
	writer := tabwriter.NewWriter(&buffer, 0, 8, 2, ' ', 0)
	fmt.Fprintln(writer, "ZONE\tCLOUDFLARE-ZONE\tCLOUDFLARE-ID\tTOKEN\tCLAIMS\tCREATED-BY\tCREATED")
	for _, zone := range zones {
		cloudflareZone := zone.CloudflareZone
		if cloudflareZone == "" {
			cloudflareZone = zone.Zone
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			zone.Zone, cloudflareZone, zone.CloudflareZoneID, zone.TokenFingerprint, zone.Claims, zone.CreatedBy, zone.CreatedAt)
	}
	_ = writer.Flush()
	return strings.TrimRight(buffer.String(), "\n")
}
