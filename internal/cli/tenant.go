package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/localdns"
	"github.com/thieso2/sandcastle-incus/internal/localtrust"
	"github.com/thieso2/sandcastle-incus/internal/tailscale"
)

type tenantListRow struct {
	Tenant   string `json:"tenant"`
	Personal bool   `json:"personal"`
	Current  bool   `json:"current"`
}

type tenantListOutput struct {
	Tenants []tenantListRow `json:"tenants"`
}

type tenantSwitchOutput struct {
	Tenant     string   `json:"tenant"`
	LocalOnly  bool     `json:"local_only,omitempty"`
	ConfigPath string   `json:"config_path"`
	Message    string   `json:"message"`
	Actions    []string `json:"actions,omitempty"`
}

func newTenantCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "tenant",
		Short: "List and select accessible Sandcastle tenants",
	}
	command.AddCommand(newTenantListCommand(config, opts))
	command.AddCommand(newTenantSwitchCommand(config, opts))
	return command
}

func newTenantListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List tenants accessible to the current user",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := tenantClient(config)
			if err != nil {
				return err
			}
			tenants, err := client.ListTenants(cmd.Context())
			if err != nil {
				return err
			}
			output := tenantListOutput{Tenants: tenantListRows(tenants, strings.TrimSpace(config.adminConfig.Tenant))}
			return writeOutput(config.stdout, opts.output, formatTenantAccessList(output), output)
		},
	}
}

func newTenantSwitchCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var localOnly bool
	command := &cobra.Command{
		Use:   "switch tenant",
		Short: "Select the local Current Tenant",
		Long:  "Select the local Current Tenant. By default this validates Tenant Access through the Auth App; use --local-only to update local config without online validation.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenantName := strings.TrimSpace(args[0])
			if tenantName == "" {
				return fmt.Errorf("tenant is required")
			}
			if !localOnly {
				if err := validateTenantAccessForSwitch(cmd.Context(), config, tenantName); err != nil {
					return err
				}
			}
			cfgPath := scconfig.DefaultConfigPath()
			cfg, err := scconfig.LoadSandcastleConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			cfg.Tenant = tenantName
			if err := scconfig.SaveSandcastleConfig(cfgPath, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			result := tenantSwitchOutput{
				Tenant:     tenantName,
				LocalOnly:  localOnly,
				ConfigPath: cfgPath,
				Actions:    tenantSwitchSetupActions(cmd.Context(), config, tenantName),
			}
			result.Message = tenantSwitchHint(localOnly, result.Actions)
			return writeOutput(config.stdout, opts.output, formatTenantSwitch(result), result)
		},
	}
	command.Flags().BoolVar(&localOnly, "local-only", false, "update local Current Tenant config without Auth App Tenant Access validation")
	return command
}

func tenantClient(config commandConfig) (authTenantClient, error) {
	if config.authTenants != nil {
		return config.authTenants, nil
	}
	if strings.TrimSpace(config.adminConfig.AuthToken) == "" {
		return nil, fmt.Errorf("CLI Auth Token is required; run sc login")
	}
	baseURL := commandAuthHostname(config, "")
	if baseURL == "" {
		return nil, fmt.Errorf("Auth Hostname is required; run sc login")
	}
	return authapp.DeviceClient{BaseURL: baseURL, AuthToken: strings.TrimSpace(config.adminConfig.AuthToken)}, nil
}

func validateTenantAccessForSwitch(ctx context.Context, config commandConfig, tenantName string) error {
	client, err := tenantClient(config)
	if err != nil {
		return err
	}
	tenants, err := client.ListTenants(ctx)
	if err != nil {
		return err
	}
	for _, candidate := range tenants {
		if candidate.Tenant == tenantName {
			return nil
		}
	}
	return fmt.Errorf("tenant %s is not accessible to the current user; use --local-only to update local config without validation", tenantName)
}

func tenantListRows(tenants []authapp.TenantAccessSummary, currentTenant string) []tenantListRow {
	rows := make([]tenantListRow, 0, len(tenants))
	for _, tenant := range tenants {
		rows = append(rows, tenantListRow{
			Tenant:   tenant.Tenant,
			Personal: tenant.Personal,
			Current:  tenant.Tenant == currentTenant,
		})
	}
	return rows
}

func formatTenantAccessList(output tenantListOutput) string {
	if len(output.Tenants) == 0 {
		return "No accessible tenants"
	}
	var builder strings.Builder
	builder.WriteString("Tenant\tPersonal\tCurrent\n")
	for _, tenant := range output.Tenants {
		builder.WriteString(tenant.Tenant)
		builder.WriteByte('\t')
		builder.WriteString(yesNo(tenant.Personal))
		builder.WriteByte('\t')
		builder.WriteString(yesNo(tenant.Current))
		builder.WriteByte('\n')
	}
	return strings.TrimRight(builder.String(), "\n")
}

func formatTenantSwitch(result tenantSwitchOutput) string {
	return fmt.Sprintf("Current Tenant set to %q in %s.\n%s", result.Tenant, result.ConfigPath, result.Message)
}

func tenantSwitchHint(localOnly bool, actions []string) string {
	var prefix string
	if localOnly {
		prefix = "Skipped Auth App Tenant Access validation.\n"
	}
	if len(actions) == 0 {
		return prefix + "No local setup actions needed."
	}
	return prefix + "Local setup actions needed:\n  " + strings.Join(actions, "\n  ")
}

func tenantSwitchSetupActions(ctx context.Context, config commandConfig, tenantName string) []string {
	var actions []string
	if !tenantSwitchDNSReady(ctx, config, tenantName) {
		actions = append(actions, "sc dns setup "+tenantName)
	}
	if !tenantSwitchTrustReady(ctx, config, tenantName) {
		actions = append(actions, "sc trust install "+tenantName)
	}
	if !tenantSwitchTailscaleReady(ctx, config, tenantName) {
		actions = append(actions, "sc tailscale up "+tenantName)
	}
	return actions
}

func tenantSwitchDNSReady(ctx context.Context, config commandConfig, tenantName string) bool {
	if config.tenantStore == nil {
		return false
	}
	plan, err := localdns.PlanInstall(ctx, config.adminConfig, config.tenantStore, localdns.Request{Reference: tenantName})
	if err != nil {
		return false
	}
	content, err := os.ReadFile(plan.ResolverPath)
	if err != nil {
		return false
	}
	host, port, err := net.SplitHostPort(plan.DNSEndpoint)
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "nameserver "+host) && strings.Contains(string(content), "port "+port)
}

func tenantSwitchTrustReady(ctx context.Context, config commandConfig, tenantName string) bool {
	if config.tenantStore == nil {
		return false
	}
	plan, err := localtrust.PlanInstall(ctx, config.adminConfig, config.tenantStore, trustRequest(config, tenantName))
	if err != nil {
		return false
	}
	if dir := strings.TrimSpace(os.Getenv("SANDCASTLE_TRUST_DIR")); dir != "" {
		return fileExists(filepath.Join(dir, localtrust.CertFilename(plan)))
	}
	switch runtime.GOOS {
	case "darwin":
		keychain := strings.TrimSpace(os.Getenv("SANDCASTLE_DARWIN_TRUST_KEYCHAIN"))
		if keychain == "" {
			if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
				keychain = filepath.Join(home, "Library", "Keychains", "login.keychain-db")
			}
		}
		args := []string{"find-certificate", "-c", plan.TrustName}
		if keychain != "" {
			args = append(args, keychain)
		}
		return exec.CommandContext(ctx, "security", args...).Run() == nil
	case "linux":
		return fileExists(filepath.Join(localtrust.DetectLinuxTrustLayout().Dir, localtrust.CertFilename(plan)))
	default:
		return false
	}
}

func tenantSwitchTailscaleReady(ctx context.Context, config commandConfig, tenantName string) bool {
	if config.tenantStore == nil || config.tailscale == nil {
		return false
	}
	plan, err := tailscale.PlanStatus(ctx, config.adminConfig, config.tenantStore, tailscale.StatusRequest{Reference: tenantName})
	if err != nil {
		return false
	}
	result, err := config.tailscale.RunStatus(ctx, plan, tailscale.RunSession{
		Stdin:  config.stdin,
		Stdout: config.stderr,
		Stderr: config.stderr,
	})
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(result.Tailscale.State), "running")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

var _ authTenantClient = authapp.DeviceClient{}
