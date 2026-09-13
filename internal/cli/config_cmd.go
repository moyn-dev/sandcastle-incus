package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
)

func newConfigCommand(config commandConfig, _ *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or modify Sandcastle configuration",
	}
	cmd.AddCommand(newConfigShowCommand(config))
	cmd.AddCommand(newConfigSetCommand(config))
	cmd.AddCommand(newConfigUnsetCommand(config))
	return cmd
}

func newConfigShowCommand(config commandConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the resolved Sandcastle configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfgPath := scconfig.DefaultConfigPath()
			fileCfg, err := scconfig.LoadSandcastleConfig(cfgPath)
			if err != nil {
				fmt.Fprintf(config.stderr, "warning: could not read %s: %v\n", cfgPath, err)
			}
			fmt.Fprintf(config.stdout, "config file:  %s\n", cfgPath)
			fmt.Fprintf(config.stdout, "  file.tenant:  %q\n", fileCfg.Tenant)
			fmt.Fprintf(config.stdout, "  file.project: %q\n", fileCfg.Project)
			fmt.Fprintf(config.stdout, "  file.remote:  %q\n", fileCfg.Remote)
			fmt.Fprintf(config.stdout, "  file.auth.hostname: %q\n", fileCfg.AuthHostname)
			userPath := scconfig.ResolveConfigPath(config.adminConfig.Remote)
			fmt.Fprintf(config.stdout, "\nresolved:\n")
			fmt.Fprintf(config.stdout, "  tenant:       %q\n", config.adminConfig.Tenant)
			fmt.Fprintf(config.stdout, "  project:      %q\n", config.adminConfig.Project)
			fmt.Fprintf(config.stdout, "  remote:       %q\n", config.adminConfig.Remote)
			fmt.Fprintf(config.stdout, "  auth.hostname: %q\n", config.adminConfig.AuthHostname)
			fmt.Fprintf(config.stdout, "  auth.hostname.effective: %q\n", commandAuthHostname(config, ""))
			fmt.Fprintf(config.stdout, "  admin_remote: %q  (used by sc admin; SANDCASTLE_ADMIN_REMOTE overrides)\n", config.adminConfig.AdminRemote)
			fmt.Fprintf(config.stdout, "  user incus config:  %q\n", userPath)
			fmt.Fprintf(config.stdout, "  admin incus config: ~/.config/incus/ (global default)\n")
			return nil
		},
	}
}

func newConfigSetCommand(_ commandConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a value in ~/.config/sandcastle/config.yml",
		Long: `Set a configuration value. Supported keys:
  tenant        default tenant name (e.g. acme)
  project       default project name (e.g. default)
  remote        default Sandcastle user remote name (e.g. sc-alice)
  auth.hostname public Auth App hostname (e.g. big.example.dev)
  admin_remote  Incus remote for sc admin commands in global ~/.config/incus/ (e.g. big)
  skill-reminder  on|off — the once-a-day interactive hint that the agent skill is not installed or outdated`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]
			cfgPath := scconfig.DefaultConfigPath()
			cfg, err := scconfig.LoadSandcastleConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			// Switching the active remote re-points the auth plane at the same
			// install (auth hostname/broker/token from the installs maps recorded
			// at login), so the Incus remote and the Auth App never drift apart on
			// a host running several installs sharing one tenant name. Shared with
			// `sc remote switch`, which is the intent-named alias for this.
			var fx remoteSwitchEffects
			if key == "remote" {
				fx = applyRemoteSwitch(&cfg, value)
				// Re-pin the project to the target install's own, so the switch
				// doesn't leave a stale pin that fails `sc ls`/`sc c`.
				repinProjectForRemote(&cfg, value)
			} else if err := setConfigValue(&cfg, key, value); err != nil {
				return err
			}
			if err := scconfig.SaveSandcastleConfig(cfgPath, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Set %s = %q in %s\n", key, value, cfgPath)
			printRemoteSwitchEffects(cmd.OutOrStdout(), cfg, fx)
			// The shared incus dir's current remote is the source of truth for
			// the user CLI's remote — write through so `sc config set remote`
			// and `incus remote switch` never disagree.
			if key == "remote" {
				if err := scconfig.SetSharedIncusDefaultRemote(value); err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "Note: incus current remote not switched: %v\n", err)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "Switched incus current remote to %q.\n", value)
				}
			}
			return nil
		},
	}
}

func newConfigUnsetCommand(_ commandConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "unset <key>",
		Short: "Unset a value in ~/.config/sandcastle/config.yml",
		Long: `Unset a configuration value. Supported keys:
  tenant        default tenant name
  project       default project name
  remote        default Sandcastle user remote name
  auth.hostname public Auth App hostname
  admin_remote  Incus remote for sc admin commands in global ~/.config/incus/
  skill-reminder  back to the default (on)`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			cfgPath := scconfig.DefaultConfigPath()
			cfg, err := scconfig.LoadSandcastleConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			if err := setConfigValue(&cfg, key, ""); err != nil {
				return err
			}
			if err := scconfig.SaveSandcastleConfig(cfgPath, cfg); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Unset %s in %s\n", key, cfgPath)
			return nil
		},
	}
}

func setConfigValue(cfg *scconfig.SandcastleConfig, key string, value string) error {
	switch key {
	case "tenant":
		cfg.Tenant = value
	case "project":
		cfg.Project = value
	case "remote":
		cfg.Remote = value
	case "admin_remote":
		cfg.AdminRemote = value
	case "auth.hostname", "auth_hostname":
		cfg.AuthHostname = value
	case "skill-reminder", "skill_reminder":
		switch v := strings.ToLower(strings.TrimSpace(value)); v {
		case "", "on", "off":
			cfg.SkillReminder = v
		default:
			return fmt.Errorf("skill-reminder must be on or off, got %q", value)
		}
	default:
		return fmt.Errorf("unknown config key %q; supported keys: tenant, project, remote, auth.hostname, admin_remote, skill-reminder", key)
	}
	return nil
}
