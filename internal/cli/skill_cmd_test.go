package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/agentskill"
)

// skillTestConfig fakes the home directory so no test can reach the real
// ~/.claude or ~/.codex. mkdirs lists the agent config dirs to pre-create
// ("installed" agents).
func skillTestConfig(t *testing.T, mkdirs ...string) (commandConfig, string) {
	t.Helper()
	home := t.TempDir()
	for _, d := range mkdirs {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	config := commandConfig{name: "sc", skillEnv: func() agentskill.Env {
		return agentskill.Env{Home: home, Getenv: func(string) string { return "" }, RepoRoot: filepath.Join(home, "repo")}
	}}
	return config, home
}

func TestSkillInstallDefaultsSkipAbsentAgents(t *testing.T) {
	config, home := skillTestConfig(t, ".claude")
	out, err := executeForTestWithConfig(t, config, "skill", "install")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	want := "claude (user)  ~/.claude/skills/sandcastle: installed (v" + agentskill.Version() + ")\n" +
		"codex: not installed (no ~/.codex), skipped\n"
	if out != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out, want)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "sandcastle", "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex")); !os.IsNotExist(err) {
		t.Fatal("skipped agent's config dir was created")
	}

	// Idempotent.
	out, err = executeForTestWithConfig(t, config, "skill", "install", "--agent", "claude")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "claude (user)  ~/.claude/skills/sandcastle: up to date (v"+agentskill.Version()+")") {
		t.Fatalf("second install: %s", out)
	}
}

func TestSkillInstallExplicitAgentCreatesMissingHome(t *testing.T) {
	config, home := skillTestConfig(t)
	out, err := executeForTestWithConfig(t, config, "skill", "install", "--agent", "codex")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.HasPrefix(out, "codex (user)  ~/.codex/skills/sandcastle: installed") {
		t.Fatalf("output: %s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "skills", "sandcastle", agentskill.MarkerFile)); err != nil {
		t.Fatal(err)
	}
}

func TestSkillInstallOutdatedUpdatedAndUnmanagedRefused(t *testing.T) {
	config, home := skillTestConfig(t, ".claude", ".codex")
	claudeDir := filepath.Join(home, ".claude", "skills", "sandcastle")
	if _, err := agentskill.Install(claudeDir, agentskill.InstallOptions{CLIVersion: "v0"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, agentskill.MarkerFile), []byte("version=deadbeefcafe\ncli=v0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	codexDir := filepath.Join(home, ".codex", "skills", "sandcastle")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}

	out, err := executeForTestWithConfig(t, config, "skill", "install")
	if err == nil {
		t.Fatalf("expected failure for the unmanaged codex copy; output:\n%s", out)
	}
	if !strings.Contains(out, "claude (user)  ~/.claude/skills/sandcastle: updated (vdeadbeefcafe → v"+agentskill.Version()+")") {
		t.Fatalf("claude row: %s", out)
	}
	if !strings.Contains(out, "codex (user)  ~/.codex/skills/sandcastle: unmanaged (no .sc-skill-version); refusing to overwrite, pass --force") {
		t.Fatalf("codex row: %s", out)
	}
	if _, err := os.Stat(filepath.Join(codexDir, "SKILL.md")); !os.IsNotExist(err) {
		t.Fatal("unmanaged directory was written")
	}

	out, err = executeForTestWithConfig(t, config, "skill", "install", "--agent", "codex", "--force")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "codex (user)  ~/.codex/skills/sandcastle: updated (replaced unmanaged copy, v"+agentskill.Version()+")") {
		t.Fatalf("forced: %s", out)
	}
}

func TestSkillInstallDryRun(t *testing.T) {
	config, home := skillTestConfig(t, ".claude")
	out, err := executeForTestWithConfig(t, config, "skill", "install", "--agent", "claude", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "would be installed") {
		t.Fatalf("dry run: %s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "skills")); !os.IsNotExist(err) {
		t.Fatal("dry run wrote files")
	}
}

func TestSkillStatusTableGolden(t *testing.T) {
	config, home := skillTestConfig(t, ".claude")
	claudeDir := filepath.Join(home, ".claude", "skills", "sandcastle")
	if _, err := agentskill.Install(claudeDir, agentskill.InstallOptions{CLIVersion: "v0"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, agentskill.MarkerFile), []byte("version=deadbeefcafe\ncli=v0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repoCodex := filepath.Join(home, "repo", ".agents", "skills", "sandcastle")
	if err := os.MkdirAll(repoCodex, 0o755); err != nil {
		t.Fatal(err)
	}
	repoClaude := filepath.Join(home, "repo", ".claude", "skills", "sandcastle")
	if _, err := agentskill.Install(repoClaude, agentskill.InstallOptions{CLIVersion: "v1"}); err != nil {
		t.Fatal(err)
	}

	out, err := executeForTestWithConfig(t, config, "skill", "status")
	if err != nil {
		t.Fatal(err)
	}
	v := agentskill.Version()
	want := strings.Join([]string{
		"AGENT   SCOPE  PATH                         STATE",
		"claude  user   ~/.claude/skills/sandcastle  outdated (vdeadbeefcafe → v" + v + ")",
		"codex   user   ~/.codex/skills/sandcastle   missing (agent not installed: no ~/.codex)",
		"",
	}, "\n")
	if out != want {
		t.Fatalf("user status:\n%s\nwant:\n%s", out, want)
	}

	out, err = executeForTestWithConfig(t, config, "skill", "status", "--scope", "project")
	if err != nil {
		t.Fatal(err)
	}
	want = strings.Join([]string{
		"AGENT   SCOPE    PATH                              STATE",
		"claude  project  ~/repo/.claude/skills/sandcastle  up to date (v" + v + ")",
		"codex   project  ~/repo/.agents/skills/sandcastle  unmanaged",
		"",
	}, "\n")
	if out != want {
		t.Fatalf("project status:\n%s\nwant:\n%s", out, want)
	}

	out, err = executeForTestWithConfig(t, config, "skill", "status", "--agent", "claude", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Version string
		Targets []skillStatusRow
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if parsed.Version != v || len(parsed.Targets) != 1 || parsed.Targets[0].State != "outdated" ||
		parsed.Targets[0].InstalledVersion != "deadbeefcafe" || parsed.Targets[0].Path != claudeDir || !parsed.Targets[0].AgentInstalled {
		t.Fatalf("json shape: %+v", parsed)
	}
}

func TestSkillUninstallOnlyManaged(t *testing.T) {
	config, home := skillTestConfig(t, ".claude", ".codex")
	claudeDir := filepath.Join(home, ".claude", "skills", "sandcastle")
	if _, err := agentskill.Install(claudeDir, agentskill.InstallOptions{CLIVersion: "v0"}); err != nil {
		t.Fatal(err)
	}
	codexDir := filepath.Join(home, ".codex", "skills", "sandcastle")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := executeForTestWithConfig(t, config, "skill", "uninstall")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := "claude (user)  ~/.claude/skills/sandcastle: removed (was v" + agentskill.Version() + ")\n" +
		"codex (user)  ~/.codex/skills/sandcastle: skipped (unmanaged, left alone)\n"
	if out != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out, want)
	}
	if _, err := os.Stat(claudeDir); !os.IsNotExist(err) {
		t.Fatal("managed copy survived")
	}
	if _, err := os.Stat(codexDir); err != nil {
		t.Fatal("unmanaged copy removed")
	}
	out, err = executeForTestWithConfig(t, config, "skill", "uninstall", "--agent", "claude")
	if err != nil || !strings.Contains(out, "missing (nothing to remove)") {
		t.Fatalf("second uninstall: %v %s", err, out)
	}
}

func TestSkillInstallDirIgnoresAgentAndScope(t *testing.T) {
	config, _ := skillTestConfig(t)
	dir := t.TempDir()
	out, err := executeForTestWithConfig(t, config, "skill", "install", "--dir", dir, "--agent", "codex", "--scope", "project")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.HasPrefix(out, "dir  "+filepath.Join(dir, "sandcastle")+": installed") {
		t.Fatalf("output: %s", out)
	}
	out, err = executeForTestWithConfig(t, config, "skill", "status", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "dir    -      "+filepath.Join(dir, "sandcastle")+"  up to date") {
		t.Fatalf("status: %s", out)
	}
}

func TestSkillShowPrintsEmbeddedSkillMD(t *testing.T) {
	out, err := executeForTest(t, "sc", "skill", "show")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(agentskill.SkillMD()) {
		t.Fatal("show output differs from the embedded SKILL.md")
	}
}

func TestSkillEnvOverridesResolvePaths(t *testing.T) {
	home := t.TempDir()
	claudeCfg := filepath.Join(home, "cfg-claude")
	codexCfg := filepath.Join(home, "cfg-codex")
	for _, d := range []string{claudeCfg, codexCfg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	config := commandConfig{name: "sc", skillEnv: func() agentskill.Env {
		return agentskill.Env{Home: home, Getenv: func(key string) string {
			switch key {
			case "CLAUDE_CONFIG_DIR":
				return claudeCfg
			case "CODEX_HOME":
				return codexCfg
			}
			return ""
		}}
	}}
	out, err := executeForTestWithConfig(t, config, "skill", "install")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, cfg := range []string{claudeCfg, codexCfg} {
		if _, err := os.Stat(filepath.Join(cfg, "skills", "sandcastle", "SKILL.md")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); !os.IsNotExist(err) {
		t.Fatal("default location used despite CLAUDE_CONFIG_DIR")
	}
}

// The `sc update` hook: managed copies show up as rows; outdated ones are
// refreshed, missing and unmanaged ones are left alone.
func TestUpdateSkillRowsAndRefresh(t *testing.T) {
	config, home := skillTestConfig(t, ".claude", ".codex")
	claudeDir := filepath.Join(home, ".claude", "skills", "sandcastle")
	if _, err := agentskill.Install(claudeDir, agentskill.InstallOptions{CLIVersion: "v0"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, agentskill.MarkerFile), []byte("version=deadbeefcafe\ncli=v0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// codex: missing → not sc's to touch.
	targets := managedSkillTargets(config)
	if len(targets) != 1 || targets[0].Agent != agentskill.AgentClaude {
		t.Fatalf("managed targets: %+v", targets)
	}
	rows := skillUpdateRows(targets)
	if len(rows) != 1 || rows[0].name() != "skill (claude, user)" || rows[0].current != "vdeadbeefcafe" || rows[0].status() != "outdated" {
		t.Fatalf("rows: %+v", rows)
	}
	var stdout, stderr bytes.Buffer
	refreshManagedSkills(&stdout, &stderr, rows, home)
	if stderr.Len() != 0 {
		t.Fatalf("stderr: %s", stderr.String())
	}
	want := "skill (claude, user): updated ~/.claude/skills/sandcastle (vdeadbeefcafe → v" + agentskill.Version() + ")\n"
	if stdout.String() != want {
		t.Fatalf("refresh output:\n%s\nwant:\n%s", stdout.String(), want)
	}
	rows = skillUpdateRows(managedSkillTargets(config))
	if len(rows) != 1 || rows[0].status() != "current" {
		t.Fatalf("after refresh: %+v", rows)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "skills")); !os.IsNotExist(err) {
		t.Fatal("refresh created a copy for an agent that had none")
	}
}
