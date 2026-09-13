package agentskill

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func mustInspect(t *testing.T, dir string) Status {
	t.Helper()
	st, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestInstallFreshThenUpToDate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), Name)
	if st := mustInspect(t, dir); st.State != StateMissing {
		t.Fatalf("fresh state %q", st.State)
	}
	res, err := Install(dir, InstallOptions{CLIVersion: "v1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionInstalled {
		t.Fatalf("action %q", res.Action)
	}
	for _, f := range Files() {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(f.Data) {
			t.Fatalf("%s differs after install", f.Path)
		}
	}
	m, ok, err := ReadMarker(dir)
	if err != nil || !ok {
		t.Fatalf("marker: ok=%v err=%v", ok, err)
	}
	if m.Version != Version() || m.CLI != "v1.2.3" {
		t.Fatalf("marker %+v", m)
	}
	if st := mustInspect(t, dir); st.State != StateUpToDate || st.InstalledCLI != "v1.2.3" {
		t.Fatalf("state after install %+v", st)
	}
	res, err = Install(dir, InstallOptions{CLIVersion: "v9"})
	if err != nil || res.Action != ActionUpToDate {
		t.Fatalf("second install: %+v %v", res, err)
	}
	// No staging leftovers.
	entries, _ := os.ReadDir(filepath.Dir(dir))
	if len(entries) != 1 {
		t.Fatalf("leftover entries next to the skill: %v", entries)
	}
}

func TestInstallOutdatedIsUpdatedAndStaleFilesRemoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), Name)
	if _, err := Install(dir, InstallOptions{CLIVersion: "v0"}); err != nil {
		t.Fatal(err)
	}
	// Simulate an older content version plus a file the skill no longer ships.
	if err := os.WriteFile(filepath.Join(dir, MarkerFile), []byte("version=000000000000\ncli=v0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "reference", "gone.md")
	if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := mustInspect(t, dir); st.State != StateOutdated || st.InstalledVersion != "000000000000" {
		t.Fatalf("state %+v", st)
	}
	res, err := Install(dir, InstallOptions{CLIVersion: "v1"})
	if err != nil || res.Action != ActionUpdated {
		t.Fatalf("update: %+v %v", res, err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale file survived the update: %v", err)
	}
	if st := mustInspect(t, dir); st.State != StateUpToDate || st.InstalledCLI != "v1" {
		t.Fatalf("state after update %+v", st)
	}
}

func TestInstallRefusesUnmanagedUnlessForced(t *testing.T) {
	dir := filepath.Join(t.TempDir(), Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("hand-edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := mustInspect(t, dir); st.State != StateUnmanaged {
		t.Fatalf("state %q", st.State)
	}
	if _, err := Install(dir, InstallOptions{}); !errors.Is(err, ErrUnmanaged) {
		t.Fatalf("expected ErrUnmanaged, got %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "SKILL.md")); string(got) != "hand-edited" {
		t.Fatal("refused install still touched the directory")
	}
	res, err := Install(dir, InstallOptions{Force: true, CLIVersion: "v1"})
	if err != nil || res.Action != ActionUpdated {
		t.Fatalf("forced install: %+v %v", res, err)
	}
	if st := mustInspect(t, dir); st.State != StateUpToDate {
		t.Fatalf("state after force %q", st.State)
	}
}

func TestInstallDryRunTouchesNothing(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, Name)
	res, err := Install(dir, InstallOptions{DryRun: true})
	if err != nil || res.Action != ActionInstalled || !res.DryRun {
		t.Fatalf("dry run: %+v %v", res, err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("dry run wrote %v", entries)
	}
}

func TestUninstallOnlyManaged(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "a", Name)
	if _, err := Install(managed, InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	unmanaged := filepath.Join(root, "b", Name)
	if err := os.MkdirAll(unmanaged, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(root, "c", Name)

	if res, err := Uninstall(managed, true); err != nil || res.Action != ActionRemoved {
		t.Fatalf("dry-run uninstall: %+v %v", res, err)
	}
	if _, err := os.Stat(managed); err != nil {
		t.Fatal("dry-run uninstall removed the directory")
	}
	if res, err := Uninstall(managed, false); err != nil || res.Action != ActionRemoved {
		t.Fatalf("uninstall: %+v %v", res, err)
	}
	if _, err := os.Stat(managed); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("managed copy not removed")
	}
	if res, err := Uninstall(unmanaged, false); err != nil || res.Action != ActionSkipped {
		t.Fatalf("unmanaged: %+v %v", res, err)
	}
	if _, err := os.Stat(unmanaged); err != nil {
		t.Fatal("unmanaged directory was removed")
	}
	if res, err := Uninstall(missing, false); err != nil || res.Action != ActionMissing {
		t.Fatalf("missing: %+v %v", res, err)
	}
}

func TestResolveTargets(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "home", "u")
	env := Env{Home: home, Getenv: func(string) string { return "" }, RepoRoot: "/repo"}
	cases := []struct {
		agent Agent
		scope Scope
		dir   string
		cfg   string
	}{
		{AgentClaude, ScopeUser, filepath.Join(home, ".claude", "skills", Name), filepath.Join(home, ".claude")},
		{AgentCodex, ScopeUser, filepath.Join(home, ".codex", "skills", Name), filepath.Join(home, ".codex")},
		{AgentClaude, ScopeProject, filepath.Join("/repo", ".claude", "skills", Name), ""},
		{AgentCodex, ScopeProject, filepath.Join("/repo", ".agents", "skills", Name), ""},
	}
	for _, c := range cases {
		got, err := Resolve(c.agent, c.scope, env)
		if err != nil {
			t.Fatal(err)
		}
		if got.Dir != c.dir || got.ConfigDir != c.cfg {
			t.Fatalf("%s/%s: dir=%q cfg=%q, want %q %q", c.agent, c.scope, got.Dir, got.ConfigDir, c.dir, c.cfg)
		}
	}
}

func TestResolveHonoursEnvOverrides(t *testing.T) {
	env := Env{Home: "/home/u", Getenv: func(key string) string {
		switch key {
		case "CLAUDE_CONFIG_DIR":
			return "/cfg/claude"
		case "CODEX_HOME":
			return "/cfg/codex"
		}
		return ""
	}}
	claude, err := Resolve(AgentClaude, ScopeUser, env)
	if err != nil || claude.Dir != filepath.Join("/cfg/claude", "skills", Name) {
		t.Fatalf("claude: %+v %v", claude, err)
	}
	codex, err := Resolve(AgentCodex, ScopeUser, env)
	if err != nil || codex.Dir != filepath.Join("/cfg/codex", "skills", Name) {
		t.Fatalf("codex: %+v %v", codex, err)
	}
	if DisplayPath("/home/u/.codex/skills", "/home/u") != "~/.codex/skills" {
		t.Fatal("DisplayPath")
	}
}

func TestParseAgentsAndScope(t *testing.T) {
	if got, _ := ParseAgents("all"); len(got) != 2 || got[0] != AgentClaude {
		t.Fatalf("all → %v", got)
	}
	if got, _ := ParseAgents("codex,claude,codex"); len(got) != 2 || got[0] != AgentClaude || got[1] != AgentCodex {
		t.Fatalf("ordered/deduped → %v", got)
	}
	if _, err := ParseAgents("cursor"); err == nil {
		t.Fatal("unknown agent accepted")
	}
	if s, err := ParseScope(""); err != nil || s != ScopeUser {
		t.Fatalf("default scope %q %v", s, err)
	}
	if _, err := ParseScope("global"); err == nil {
		t.Fatal("unknown scope accepted")
	}
}
