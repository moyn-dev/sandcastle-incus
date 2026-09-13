package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/agentskill"
)

// skillTarget is one place `sc skill` acts on: an agent/scope pair, or the
// explicit --dir location (Agent/Scope empty, shown as "dir").
type skillTarget struct {
	agentskill.Target
	explicit bool // the agent was named on the command line; never skipped
}

func (t skillTarget) label() string {
	if t.Agent == "" {
		return "dir"
	}
	return fmt.Sprintf("%s (%s)", t.Agent, t.Scope)
}

func (t skillTarget) agentName() string {
	if t.Agent == "" {
		return "dir"
	}
	return string(t.Agent)
}

func (t skillTarget) scopeName() string {
	if t.Scope == "" {
		return "-"
	}
	return string(t.Scope)
}

// skillEnv returns the environment for target resolution. Tests override it
// via commandConfig.skillEnv to keep the real ~/.claude and ~/.codex out of
// reach; production resolves the git toplevel lazily for project scope.
func skillEnv(config commandConfig, scope agentskill.Scope) agentskill.Env {
	if config.skillEnv != nil {
		return config.skillEnv()
	}
	env := agentskill.Env{}
	if scope == agentskill.ScopeProject {
		env.RepoRoot = gitToplevelOrCwd()
	}
	return env
}

// gitToplevelOrCwd is the project-scope base: the git repository root when
// inside one, else the current directory.
func gitToplevelOrCwd() string {
	if out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output(); err == nil {
		if top := strings.TrimSpace(string(out)); top != "" {
			return top
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func skillHome(config commandConfig) string {
	if config.skillEnv != nil {
		if env := config.skillEnv(); env.Home != "" {
			return env.Home
		}
	}
	home, _ := os.UserHomeDir()
	return home
}

// resolveSkillTargets turns the shared --agent/--scope/--dir flags into
// targets. --dir wins and ignores agent/scope.
func resolveSkillTargets(config commandConfig, agentFlag, scopeFlag, dir string, agentChanged bool) ([]skillTarget, error) {
	if strings.TrimSpace(dir) != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		return []skillTarget{{Target: agentskill.Target{Root: abs, Dir: filepath.Join(abs, agentskill.Name)}, explicit: true}}, nil
	}
	agents, err := agentskill.ParseAgents(agentFlag)
	if err != nil {
		return nil, err
	}
	scope, err := agentskill.ParseScope(scopeFlag)
	if err != nil {
		return nil, err
	}
	explicit := agentChanged && strings.TrimSpace(strings.ToLower(agentFlag)) != "all"
	targets, err := agentskill.Targets(agents, scope, skillEnv(config, scope))
	if err != nil {
		return nil, err
	}
	out := make([]skillTarget, 0, len(targets))
	for _, t := range targets {
		out = append(out, skillTarget{Target: t, explicit: explicit})
	}
	return out, nil
}

func newSkillCommand(config commandConfig, _ *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skill",
		Short: "Install the Sandcastle agent skill for Claude Code and Codex",
		Long: `Install, inspect, or remove the Sandcastle agent skill — the SKILL.md and
reference files that teach Claude Code and Codex how to drive sc/sc-adm. The
skill is embedded in this binary; each install carries a .sc-skill-version
marker so sc can refresh or remove only copies it wrote.

Locations (--scope user is the default):
  claude  user     $CLAUDE_CONFIG_DIR/skills/sandcastle  (default ~/.claude/skills/sandcastle)
  codex   user     $CODEX_HOME/skills/sandcastle         (default ~/.codex/skills/sandcastle)
  claude  project  <repo>/.claude/skills/sandcastle
  codex   project  <repo>/.agents/skills/sandcastle      (Codex's repository skill root)

<repo> is the git toplevel of the current directory (else the directory
itself). --dir installs into an explicit directory instead.`,
	}
	cmd.AddCommand(newSkillInstallCommand(config))
	cmd.AddCommand(newSkillStatusCommand(config))
	cmd.AddCommand(newSkillUninstallCommand(config))
	cmd.AddCommand(newSkillShowCommand(config))
	return cmd
}

func addSkillTargetFlags(cmd *cobra.Command, agent, scope, dir *string) {
	cmd.Flags().StringVar(agent, "agent", "all", "which agent: claude, codex, or all")
	cmd.Flags().StringVar(scope, "scope", "user", "where: user (the agent's home config) or project (the current repo)")
	cmd.Flags().StringVar(dir, "dir", "", "explicit skills directory (the skill lands at <dir>/sandcastle); ignores --agent/--scope")
}

func newSkillInstallCommand(config commandConfig) *cobra.Command {
	var agent, scope, dir string
	var force, dryRun bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install or refresh the skill (idempotent)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			targets, err := resolveSkillTargets(config, agent, scope, dir, cmd.Flags().Changed("agent"))
			if err != nil {
				return err
			}
			home := skillHome(config)
			var failed []string
			for _, t := range targets {
				if !t.Installed() && !t.explicit {
					fmt.Fprintf(config.stdout, "%s: not installed (no %s), skipped\n", t.Agent, t.ConfigDirHint(home))
					continue
				}
				res, err := agentskill.Install(t.Dir, agentskill.InstallOptions{CLIVersion: cliVersionTag(), Force: force, DryRun: dryRun})
				if err != nil {
					if errors.Is(err, agentskill.ErrUnmanaged) {
						fmt.Fprintf(config.stdout, "%s  %s: unmanaged (no %s); refusing to overwrite, pass --force\n", t.label(), agentskill.DisplayPath(t.Dir, home), agentskill.MarkerFile)
					} else {
						fmt.Fprintf(config.stdout, "%s  %s: error: %v\n", t.label(), agentskill.DisplayPath(t.Dir, home), err)
					}
					failed = append(failed, t.label())
					continue
				}
				fmt.Fprintln(config.stdout, formatSkillResult(t, res, home))
			}
			if len(failed) > 0 {
				return fmt.Errorf("skill install failed for %s", strings.Join(failed, ", "))
			}
			if !dryRun {
				// A fresh install clears the reminder throttle so a copy that
				// goes outdated later is reported at once, not after 24h.
				clearSkillReminderState(skillReminderStatePath(config))
			}
			return nil
		},
	}
	addSkillTargetFlags(cmd, &agent, &scope, &dir)
	cmd.Flags().BoolVar(&force, "force", false, "replace a directory that exists without the sc marker (a hand-placed copy)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would happen without writing")
	return cmd
}

// formatSkillResult renders one install/uninstall outcome line, e.g.
// "claude (user)  ~/.claude/skills/sandcastle: up to date (v1a2b3c4d5e6f)".
func formatSkillResult(t skillTarget, res agentskill.Result, home string) string {
	prefix := ""
	if res.DryRun && res.Action != agentskill.ActionUpToDate && res.Action != agentskill.ActionMissing && res.Action != agentskill.ActionSkipped {
		prefix = "would be "
	}
	detail := "v" + agentskill.Version()
	switch res.Action {
	case agentskill.ActionUpdated:
		if res.Before.InstalledVersion != "" {
			detail = "v" + res.Before.InstalledVersion + " → v" + agentskill.Version()
		} else {
			detail = "replaced unmanaged copy, v" + agentskill.Version()
		}
	case agentskill.ActionRemoved:
		detail = "was v" + res.Before.InstalledVersion
	case agentskill.ActionMissing:
		detail = "nothing to remove"
	case agentskill.ActionSkipped:
		detail = "unmanaged, left alone"
	}
	return fmt.Sprintf("%s  %s: %s%s (%s)", t.label(), agentskill.DisplayPath(t.Dir, home), prefix, res.Action, detail)
}

func newSkillStatusCommand(config commandConfig) *cobra.Command {
	var agent, scope, dir string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show where the skill is installed and whether it is current",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			targets, err := resolveSkillTargets(config, agent, scope, dir, cmd.Flags().Changed("agent"))
			if err != nil {
				return err
			}
			rows, err := skillStatusRows(targets, skillHome(config))
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(config.stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"version": agentskill.Version(), "targets": rows})
			}
			w := tabwriter.NewWriter(config.stdout, 2, 8, 2, ' ', 0)
			fmt.Fprintln(w, "AGENT\tSCOPE\tPATH\tSTATE")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Agent, r.Scope, r.DisplayPath, r.StateText)
			}
			return w.Flush()
		},
	}
	addSkillTargetFlags(cmd, &agent, &scope, &dir)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the status as JSON")
	return cmd
}

// skillStatusRow is one line of `sc skill status` (and its JSON shape).
type skillStatusRow struct {
	Agent            string `json:"agent"`
	Scope            string `json:"scope"`
	Path             string `json:"path"`
	DisplayPath      string `json:"-"`
	State            string `json:"state"`
	StateText        string `json:"-"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	InstalledCLI     string `json:"installedCli,omitempty"`
	AgentInstalled   bool   `json:"agentInstalled"`
}

func skillStatusRows(targets []skillTarget, home string) ([]skillStatusRow, error) {
	rows := make([]skillStatusRow, 0, len(targets))
	for _, t := range targets {
		st, err := agentskill.Inspect(t.Dir)
		if err != nil {
			return nil, err
		}
		row := skillStatusRow{
			Agent:            t.agentName(),
			Scope:            t.scopeName(),
			Path:             t.Dir,
			DisplayPath:      agentskill.DisplayPath(t.Dir, home),
			State:            string(st.State),
			StateText:        string(st.State),
			InstalledVersion: st.InstalledVersion,
			InstalledCLI:     st.InstalledCLI,
			AgentInstalled:   t.Installed(),
		}
		switch st.State {
		case agentskill.StateOutdated:
			row.StateText = fmt.Sprintf("outdated (v%s → v%s)", st.InstalledVersion, agentskill.Version())
		case agentskill.StateUpToDate:
			row.StateText = fmt.Sprintf("up to date (v%s)", st.InstalledVersion)
		case agentskill.StateMissing:
			if !t.Installed() {
				row.StateText = fmt.Sprintf("missing (agent not installed: no %s)", t.ConfigDirHint(home))
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func newSkillUninstallCommand(config commandConfig) *cobra.Command {
	var agent, scope, dir string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove copies of the skill that sc installed (unmanaged copies are left alone)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			targets, err := resolveSkillTargets(config, agent, scope, dir, cmd.Flags().Changed("agent"))
			if err != nil {
				return err
			}
			home := skillHome(config)
			for _, t := range targets {
				res, err := agentskill.Uninstall(t.Dir, dryRun)
				if err != nil {
					return fmt.Errorf("%s %s: %w", t.label(), t.Dir, err)
				}
				fmt.Fprintln(config.stdout, formatSkillResult(t, res, home))
			}
			return nil
		},
	}
	addSkillTargetFlags(cmd, &agent, &scope, &dir)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be removed without removing")
	return cmd
}

func newSkillShowCommand(config commandConfig) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the embedded SKILL.md to stdout",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := config.stdout.Write(agentskill.SkillMD())
			return err
		},
	}
}

// cliVersionTag is the CLI version as recorded in skill markers ("v1.2.3",
// "v0.0.0-dev").
func cliVersionTag() string {
	return "v" + strings.TrimPrefix(version, "v")
}

// --- sc update integration -------------------------------------------------

// managedSkillTargets returns the user-scope copies `sc update` looks after:
// every agent whose managed copy exists (missing and unmanaged copies are
// not sc's to touch). Resolution errors are swallowed — the update command
// must never fail because of the skill.
func managedSkillTargets(config commandConfig) []skillTarget {
	targets, err := resolveSkillTargets(config, "all", "user", "", false)
	if err != nil {
		return nil
	}
	var out []skillTarget
	for _, t := range targets {
		st, err := agentskill.Inspect(t.Dir)
		if err != nil {
			continue
		}
		if st.State == agentskill.StateUpToDate || st.State == agentskill.StateOutdated {
			out = append(out, t)
		}
	}
	return out
}

// skillUpdateRow is one `skill (claude, user)` line of the sc update table.
type skillUpdateRow struct {
	target   skillTarget
	current  string
	wanted   string
	outdated bool
}

func skillUpdateRows(targets []skillTarget) []skillUpdateRow {
	var rows []skillUpdateRow
	for _, t := range targets {
		st, err := agentskill.Inspect(t.Dir)
		if err != nil || (st.State != agentskill.StateUpToDate && st.State != agentskill.StateOutdated) {
			continue
		}
		rows = append(rows, skillUpdateRow{
			target:   t,
			current:  "v" + st.InstalledVersion,
			wanted:   "v" + agentskill.Version(),
			outdated: st.State == agentskill.StateOutdated,
		})
	}
	return rows
}

func (r skillUpdateRow) name() string {
	return fmt.Sprintf("skill (%s, %s)", r.target.agentName(), r.target.scopeName())
}

func (r skillUpdateRow) status() string {
	if r.outdated {
		return "outdated"
	}
	return "current"
}

// refreshManagedSkills rewrites every outdated managed copy in rows and
// prints one line per copy. Failures are reported, never returned: the CLI
// and sidecar updates that ran before must not look failed because a skill
// directory was unwritable.
func refreshManagedSkills(stdout, stderr io.Writer, rows []skillUpdateRow, home string) {
	for _, r := range rows {
		if !r.outdated {
			continue
		}
		res, err := agentskill.Install(r.target.Dir, agentskill.InstallOptions{CLIVersion: cliVersionTag()})
		if err != nil {
			fmt.Fprintf(stderr, "note: %s: refresh failed: %v\n", r.name(), err)
			continue
		}
		fmt.Fprintf(stdout, "%s: %s %s (%s → v%s)\n", r.name(), res.Action, agentskill.DisplayPath(r.target.Dir, home), r.current, agentskill.Version())
	}
}
