package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/thieso2/sandcastle-incus/internal/agentskill"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
)

// SkillReminderEnv silences the agent-skill hint for one shell when set to
// 0/false/off/no — the env-side twin of `sc config set skill-reminder off`,
// mirroring SANDCASTLE_NO_UPDATE_NOTIFIER for the update notice.
const SkillReminderEnv = "SANDCASTLE_SKILL_REMINDER"

// skillReminderInterval throttles the hint to once per day, the same clock
// the update notice runs on (#124 §2).
const skillReminderInterval = 24 * time.Hour

// skillReminderStatePath is the hint's throttle file, beside the update
// notice's update-state.json in the sandcastle config dir. Tests point it
// elsewhere through commandConfig.skillEnv's Home.
func skillReminderStatePath(config commandConfig) string {
	dir := scconfig.DefaultConfigDir()
	if config.skillEnv != nil {
		if env := config.skillEnv(); env.Home != "" {
			dir = filepath.Join(env.Home, ".config", "sandcastle")
		}
	}
	return filepath.Join(dir, "skill-reminder-state.json")
}

// skillReminderState is the persisted throttle: when the hint last printed.
type skillReminderState struct {
	NoticedAt time.Time `json:"noticed_at,omitzero"`
}

// loadSkillReminderState is failure-tolerant like update.LoadState: a
// missing or corrupt file is a zero state (the hint may print).
func loadSkillReminderState(path string) skillReminderState {
	data, err := os.ReadFile(path)
	if err != nil {
		return skillReminderState{}
	}
	var st skillReminderState
	if err := json.Unmarshal(data, &st); err != nil {
		return skillReminderState{}
	}
	return st
}

func saveSkillReminderState(path string, st skillReminderState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// clearSkillReminderState forgets the last-printed time so the next
// interactive run re-evaluates immediately. Best effort: the hint's state
// must never fail a command.
func clearSkillReminderState(path string) {
	_ = os.Remove(path)
}

// skillReminderInput is everything the hint decision reads, injected so the
// tests can vary each gate without a terminal or a real home directory.
type skillReminderInput struct {
	rootName    string // the invoked tree's name: "sc", "sc-adm", "sc admin"
	commandPath string // the executed leaf's path, e.g. "sc skill install"
	jsonOutput  bool   // --json / --output json was in effect
	tty         bool   // stdout AND stderr are terminals
	getenv      func(string) string
	cfg         scconfig.SandcastleConfig
	statePath   string
	targets     []agentskill.Target // user-scope targets; absent agents are skipped
	now         time.Time
}

// skillReminderLine decides whether the hint is due and returns it ("" when
// not). It touches only the local filesystem — no network, no locks — and
// when it does return a line it records now in the state file so the next
// day is the earliest repeat.
func skillReminderLine(in skillReminderInput) string {
	if !in.tty || in.jsonOutput || isAdminRootName(in.rootName) || isSkillCommandPath(in.commandPath) {
		return ""
	}
	if in.getenv != nil && skillReminderEnvOff(in.getenv(SkillReminderEnv)) {
		return ""
	}
	if !in.cfg.SkillReminderEnabled() {
		return ""
	}
	if st := loadSkillReminderState(in.statePath); !st.NoticedAt.IsZero() && in.now.Sub(st.NoticedAt) < skillReminderInterval {
		return ""
	}
	var missing, outdated []string
	for _, t := range in.targets {
		if !t.Installed() {
			continue
		}
		st, err := agentskill.Inspect(t.Dir)
		if err != nil {
			continue
		}
		switch st.State {
		case agentskill.StateMissing:
			missing = append(missing, agentDisplayName(t.Agent))
		case agentskill.StateOutdated:
			outdated = append(outdated, agentDisplayName(t.Agent))
		}
	}
	if len(missing) == 0 && len(outdated) == 0 {
		return ""
	}
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "is not installed for "+joinAnd(missing))
	}
	if len(outdated) > 0 {
		parts = append(parts, "is outdated for "+joinAnd(outdated))
	}
	line := fmt.Sprintf("hint: the Sandcastle agent skill %s — run: sc skill install   (silence: sc config set skill-reminder off)",
		strings.Join(parts, " and "))
	_ = saveSkillReminderState(in.statePath, skillReminderState{NoticedAt: in.now})
	return line
}

// isAdminRootName reports whether the tree is the admin one: the
// sc-adm/sandcastle-admin binaries or the "<name> admin" tree main.go builds
// for `sc admin …`. ExecuteAdmin never calls the hint anyway; the check keeps
// the decision self-contained (and testable) rather than relying on the
// caller.
func isAdminRootName(name string) bool {
	name = strings.TrimSpace(name)
	return name == "sc-adm" || name == "sandcastle-admin" || strings.HasSuffix(name, " admin")
}

// isSkillCommandPath matches `sc skill …` itself: the user is already
// looking at the skill, so a hint would be noise.
func isSkillCommandPath(path string) bool {
	fields := strings.Fields(path)
	return len(fields) >= 2 && fields[1] == "skill"
}

func skillReminderEnvOff(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

func agentDisplayName(a agentskill.Agent) string {
	switch a {
	case agentskill.AgentClaude:
		return "Claude Code"
	case agentskill.AgentCodex:
		return "Codex"
	}
	return string(a)
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func stdoutIsTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// skillReminderInputFor derives the hint's input from a finished user-CLI
// run: root is the tree that ran, executed the leaf cobra dispatched to.
// The --json/--output state is read back from the root's persistent flags
// (PersistentPreRunE folds --json into --output).
func skillReminderInputFor(root, executed *cobra.Command, config commandConfig, tty bool, getenv func(string) string, now time.Time) skillReminderInput {
	in := skillReminderInput{
		rootName:  root.Name(),
		tty:       tty,
		getenv:    getenv,
		statePath: skillReminderStatePath(config),
		now:       now,
	}
	if executed != nil {
		in.commandPath = executed.CommandPath()
	}
	if f := root.PersistentFlags().Lookup("output"); f != nil && f.Value.String() == string(outputJSON) {
		in.jsonOutput = true
	}
	if f := root.PersistentFlags().Lookup("json"); f != nil && f.Value.String() == "true" {
		in.jsonOutput = true
	}
	if cfg, err := scconfig.LoadSandcastleConfig(filepath.Join(filepath.Dir(in.statePath), "config.yml")); err == nil {
		in.cfg = cfg
	}
	in.targets, _ = agentskill.Targets(agentskill.AllAgents, agentskill.ScopeUser, skillEnv(config, agentskill.ScopeUser))
	return in
}

// maybePrintSkillReminder prints the one-line agent-skill hint on stderr
// after a successful interactive `sc` run. Execute calls it only when the
// command returned nil, so it never rides on an error path.
func maybePrintSkillReminder(stderr io.Writer, root, executed *cobra.Command, config commandConfig) {
	if !stdoutIsTerminal() || !stderrIsTerminal() {
		return
	}
	if line := skillReminderLine(skillReminderInputFor(root, executed, config, true, os.Getenv, time.Now())); line != "" {
		fmt.Fprintln(stderr, line)
	}
}
