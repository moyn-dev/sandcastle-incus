package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/agentskill"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
)

var reminderNow = time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

// reminderInput builds a fully-enabled interactive input for a fake home
// with the given agent config dirs present. Every gate is open unless the
// test closes one.
func reminderInput(t *testing.T, mkdirs ...string) (skillReminderInput, string) {
	t.Helper()
	config, home := skillTestConfig(t, mkdirs...)
	targets, err := agentskill.Targets(agentskill.AllAgents, agentskill.ScopeUser, config.skillEnv())
	if err != nil {
		t.Fatal(err)
	}
	return skillReminderInput{
		rootName:    "sc",
		commandPath: "sc version",
		tty:         true,
		getenv:      func(string) string { return "" },
		statePath:   skillReminderStatePath(config),
		targets:     targets,
		now:         reminderNow,
	}, home
}

func installSkillAt(t *testing.T, home, agentDir, version string) {
	t.Helper()
	dir := filepath.Join(home, agentDir, "skills", agentskill.Name)
	if _, err := agentskill.Install(dir, agentskill.InstallOptions{CLIVersion: "v0.0.0-test"}); err != nil {
		t.Fatal(err)
	}
	if version != "" && version != agentskill.Version() {
		marker := "# written by `sc skill install`; do not edit\nversion=" + version + "\ncli=v0.0.0-test\n"
		if err := os.WriteFile(filepath.Join(dir, agentskill.MarkerFile), []byte(marker), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSkillReminderMissingForBothAgents(t *testing.T) {
	in, _ := reminderInput(t, ".claude", ".codex")
	want := "hint: the Sandcastle agent skill is not installed for Claude Code and Codex — run: sc skill install   (silence: sc config set skill-reminder off)"
	if got := skillReminderLine(in); got != want {
		t.Fatalf("line:\n%s\nwant:\n%s", got, want)
	}
	if _, err := os.Stat(in.statePath); err != nil {
		t.Fatalf("state file not written: %v", err)
	}
}

func TestSkillReminderOnlyForAgentsPresent(t *testing.T) {
	in, _ := reminderInput(t, ".codex")
	if got := skillReminderLine(in); !strings.Contains(got, "is not installed for Codex —") || strings.Contains(got, "Claude") {
		t.Fatalf("line: %q", got)
	}
	in, _ = reminderInput(t) // no agent on the box: nothing to say
	if got := skillReminderLine(in); got != "" {
		t.Fatalf("no agents: %q", got)
	}
	if _, err := os.Stat(in.statePath); !os.IsNotExist(err) {
		t.Fatal("state written although nothing printed")
	}
}

func TestSkillReminderOutdatedAndUpToDate(t *testing.T) {
	in, home := reminderInput(t, ".claude", ".codex")
	installSkillAt(t, home, ".claude", "0000000000ff")
	installSkillAt(t, home, ".codex", agentskill.Version())
	want := "hint: the Sandcastle agent skill is outdated for Claude Code — run: sc skill install   (silence: sc config set skill-reminder off)"
	if got := skillReminderLine(in); got != want {
		t.Fatalf("line:\n%s\nwant:\n%s", got, want)
	}

	// Mixed: one missing, one outdated.
	in, home = reminderInput(t, ".claude", ".codex")
	installSkillAt(t, home, ".codex", "0000000000ff")
	want = "hint: the Sandcastle agent skill is not installed for Claude Code and is outdated for Codex — run: sc skill install   (silence: sc config set skill-reminder off)"
	if got := skillReminderLine(in); got != want {
		t.Fatalf("line:\n%s\nwant:\n%s", got, want)
	}

	// Both current (or unmanaged): silent.
	in, home = reminderInput(t, ".claude", ".codex")
	installSkillAt(t, home, ".claude", agentskill.Version())
	if err := os.MkdirAll(filepath.Join(home, ".codex", "skills", agentskill.Name), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := skillReminderLine(in); got != "" {
		t.Fatalf("up to date + unmanaged: %q", got)
	}
}

func TestSkillReminderRateLimit(t *testing.T) {
	in, _ := reminderInput(t, ".claude")
	if got := skillReminderLine(in); got == "" {
		t.Fatal("first run should print")
	}
	in.now = reminderNow.Add(23 * time.Hour)
	if got := skillReminderLine(in); got != "" {
		t.Fatalf("within 24h: %q", got)
	}
	in.now = reminderNow.Add(25 * time.Hour)
	if got := skillReminderLine(in); got == "" {
		t.Fatal("after 24h should print again")
	}
	// Clearing the state (what `sc skill install` does) re-arms it at once.
	clearSkillReminderState(in.statePath)
	in.now = reminderNow.Add(25*time.Hour + time.Minute)
	if got := skillReminderLine(in); got == "" {
		t.Fatal("after clear should print again")
	}
}

func TestSkillReminderGates(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*skillReminderInput)
	}{
		{"not a tty", func(in *skillReminderInput) { in.tty = false }},
		{"json output", func(in *skillReminderInput) { in.jsonOutput = true }},
		{"sc skill subtree", func(in *skillReminderInput) { in.commandPath = "sc skill status" }},
		{"sc skill install", func(in *skillReminderInput) { in.commandPath = "sc skill install" }},
		{"sc-adm", func(in *skillReminderInput) { in.rootName = "sc-adm" }},
		{"sandcastle-admin", func(in *skillReminderInput) { in.rootName = "sandcastle-admin" }},
		{"sc admin", func(in *skillReminderInput) { in.rootName = "sc admin"; in.commandPath = "sc admin tenant list" }},
		{"env 0", func(in *skillReminderInput) {
			in.getenv = func(k string) string {
				if k == SkillReminderEnv {
					return "0"
				}
				return ""
			}
		}},
		{"env off", func(in *skillReminderInput) {
			in.getenv = func(k string) string {
				if k == SkillReminderEnv {
					return "off"
				}
				return ""
			}
		}},
		{"config off", func(in *skillReminderInput) { in.cfg.SkillReminder = "off" }},
		{"config OFF", func(in *skillReminderInput) { in.cfg.SkillReminder = "OFF" }},
	}
	for _, c := range cases {
		in, _ := reminderInput(t, ".claude", ".codex")
		c.mutate(&in)
		if got := skillReminderLine(in); got != "" {
			t.Errorf("%s: printed %q", c.name, got)
		}
		if _, err := os.Stat(in.statePath); !os.IsNotExist(err) {
			t.Errorf("%s: state written although silenced", c.name)
		}
	}
	// Sanity: env "1" and config "on" keep it on.
	in, _ := reminderInput(t, ".claude")
	in.getenv = func(string) string { return "1" }
	in.cfg.SkillReminder = "on"
	if got := skillReminderLine(in); got == "" {
		t.Fatal("env=1 / config on should print")
	}
}

// runRootForReminder executes args on a user root tree built for config and
// returns the reminder input derived the way Execute derives it.
func runRootForReminder(t *testing.T, config commandConfig, args ...string) (skillReminderInput, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	config.stdout, config.stderr = &stdout, &stderr
	if config.adminConfig.Remote == "" {
		config.adminConfig = testAdminConfig()
	}
	root := NewRootCommand(config)
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)
	executed, err := root.ExecuteContextC(context.Background())
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, stderr.String())
	}
	return skillReminderInputFor(root, executed, config, true, func(string) string { return "" }, reminderNow), stdout.String()
}

func TestSkillReminderWiringFromCommandTree(t *testing.T) {
	config, _ := skillTestConfig(t, ".claude")

	in, _ := runRootForReminder(t, config, "version")
	if got := skillReminderLine(in); !strings.HasPrefix(got, "hint: the Sandcastle agent skill is not installed for Claude Code —") {
		t.Fatalf("sc version: %q", got)
	}

	// --json and --output json keep stderr clean; stdout stays valid JSON.
	for _, args := range [][]string{{"version", "--json"}, {"--output", "json", "version"}} {
		in, out := runRootForReminder(t, config, args...)
		if !in.jsonOutput {
			t.Fatalf("%v: jsonOutput not detected", args)
		}
		if got := skillReminderLine(in); got != "" {
			t.Fatalf("%v: printed %q", args, got)
		}
		if !strings.HasPrefix(strings.TrimSpace(out), "{") {
			t.Fatalf("%v: stdout not JSON: %s", args, out)
		}
	}

	// sc skill … never reminds about itself.
	in, _ = runRootForReminder(t, config, "skill", "status")
	if in.commandPath != "sc skill status" {
		t.Fatalf("commandPath = %q", in.commandPath)
	}
	if got := skillReminderLine(in); got != "" {
		t.Fatalf("sc skill status: %q", got)
	}

	// The admin tree name (what main.go passes for `sc admin …`) is silent.
	adminConfig := config
	adminConfig.name = "sc admin"
	in, _ = runRootForReminder(t, adminConfig, "version")
	if got := skillReminderLine(in); got != "" {
		t.Fatalf("sc admin: %q", got)
	}
	adminConfig.name = "sc-adm"
	in, _ = runRootForReminder(t, adminConfig, "version")
	if got := skillReminderLine(in); got != "" {
		t.Fatalf("sc-adm: %q", got)
	}
}

func TestSkillReminderConfigOptOutPersisted(t *testing.T) {
	config, home := skillTestConfig(t, ".claude")
	t.Setenv("HOME", home) // sc config set writes ~/.config/sandcastle/config.yml
	if _, err := executeForTestWithConfig(t, config, "config", "set", "skill-reminder", "off"); err != nil {
		t.Fatal(err)
	}
	cfg, err := scconfig.LoadSandcastleConfig(filepath.Join(home, ".config", "sandcastle", "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SkillReminder != "off" || cfg.SkillReminderEnabled() {
		t.Fatalf("persisted %+v", cfg.SkillReminder)
	}
	in, _ := runRootForReminder(t, config, "version")
	if in.cfg.SkillReminderEnabled() {
		t.Fatal("wiring did not pick up the persisted opt-out from the fake home's config.yml")
	}
	if got := skillReminderLine(in); got != "" {
		t.Fatalf("config off: %q", got)
	}

	if _, err := executeForTestWithConfig(t, config, "config", "set", "skill-reminder", "on"); err != nil {
		t.Fatal(err)
	}
	in, _ = runRootForReminder(t, config, "version")
	if got := skillReminderLine(in); got == "" {
		t.Fatal("config on should re-enable")
	}

	if _, err := executeForTestWithConfig(t, config, "config", "set", "skill-reminder", "maybe"); err == nil || !strings.Contains(err.Error(), "must be on or off") {
		t.Fatalf("bad value accepted: %v", err)
	}
	if _, err := executeForTestWithConfig(t, config, "config", "unset", "skill-reminder"); err != nil {
		t.Fatal(err)
	}
}

func TestSkillInstallClearsReminderState(t *testing.T) {
	config, _ := skillTestConfig(t, ".claude")
	in, _ := reminderInput(t)
	in.statePath = skillReminderStatePath(config)
	if err := saveSkillReminderState(in.statePath, skillReminderState{NoticedAt: reminderNow}); err != nil {
		t.Fatal(err)
	}
	if _, err := executeForTestWithConfig(t, config, "skill", "install"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(in.statePath); !os.IsNotExist(err) {
		t.Fatal("sc skill install left the reminder state in place")
	}
	// --dry-run leaves it alone.
	if err := saveSkillReminderState(in.statePath, skillReminderState{NoticedAt: reminderNow}); err != nil {
		t.Fatal(err)
	}
	if _, err := executeForTestWithConfig(t, config, "skill", "install", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(in.statePath); err != nil {
		t.Fatal("--dry-run cleared the reminder state")
	}
}
