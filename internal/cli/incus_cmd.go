package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

type incusRunner func(context.Context, []string, []string, io.Reader, io.Writer, io.Writer) error

func newIncusCommand(config commandConfig, _ *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:                "incus [args...]",
		Short:              "Run incus with the active Sandcastle remote's Incus config",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIncusWithProject(cmd, config, args,
				func(summary tenant.Summary) string { return summary.V2IncusProjectName(config.adminConfig.Project) })
		},
	}
}

func newIncusInfraCommand(config commandConfig, _ *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:                "incus-infra [args...]",
		Short:              "Run incus scoped to the tenant's infra (sidecars) Incus project",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIncusWithProject(cmd, config, args,
				func(summary tenant.Summary) string { return summary.InfraProject })
		},
	}
}

func runIncusWithProject(cmd *cobra.Command, config commandConfig, args []string, v2ProjectFn func(tenant.Summary) string) error {
	incusDir := resolveIncusDir(config.adminConfig.Remote)
	if incusDir == "" {
		return fmt.Errorf("no Sandcastle-managed Incus config found for remote %q; add one with: sc remote add", config.adminConfig.Remote)
	}
	runner := config.incusRunner
	if runner == nil {
		runner = runIncusCLI
	}
	// The Incus project name is read off the live tenant, never derived from the
	// tenant name: derivation is what produced the v1 `<project>-infra` shape.
	summary, err := requireV2Tenant(cmd.Context(), config)
	if err != nil {
		return err
	}
	projectName := v2ProjectFn(summary)
	env := append(os.Environ(), "INCUS_CONF="+incusDir, "INCUS_PROJECT="+projectName, "INCUS_REMOTE="+config.adminConfig.Remote)
	envOverrides := []string{"INCUS_CONF=" + incusDir, "INCUS_PROJECT=" + projectName, "INCUS_REMOTE=" + config.adminConfig.Remote}
	if os.Getenv("VERBOSE") == "1" {
		fmt.Fprintf(config.stderr, "[verbose] sc incus env: %s\n", strings.Join(envOverrides, " "))
		fmt.Fprintf(config.stderr, "[verbose] sc incus command: %s\n", shellCommandLine(append([]string{"incus"}, args...)))
	}
	return runner(cmd.Context(), args, env, config.stdin, config.stdout, config.stderr)
}

func runIncusCLI(ctx context.Context, args []string, env []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	incusCmd := exec.CommandContext(ctx, "incus", args...)
	incusCmd.Env = env
	incusCmd.Stdin = stdin
	incusCmd.Stdout = stdout
	incusCmd.Stderr = stderr
	return incusCmd.Run()
}

// resolveIncusDir returns the per-remote Incus config dir if it exists, otherwise empty string.
func resolveIncusDir(remote string) string {
	if remote == "" {
		return ""
	}
	dir := scconfig.ResolveConfigPath(remote)
	if _, err := os.Stat(dir); err == nil {
		return dir
	}
	return ""
}

func shellCommandLine(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "" || strings.ContainsAny(arg, " \t\n\"'\\$`") {
			quoted = append(quoted, strconv.Quote(arg))
			continue
		}
		quoted = append(quoted, arg)
	}
	return strings.Join(quoted, " ")
}
