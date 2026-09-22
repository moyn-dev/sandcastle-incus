package tenant

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestInstallAgenticScriptShipsInThePayloadAndParses(t *testing.T) {
	files, _ := PlatformPayload()
	var found *PlatformPayloadFile
	for i := range files {
		if files[i].Path == SCPayloadInstallAgenticPath {
			found = &files[i]
		}
	}
	if found == nil || found.Mode != 0o755 {
		t.Fatalf("install-agentic.sh missing or not executable: %+v", found)
	}
	for _, want := range []string{"https://mise.run", "herdr", "claude", "codex", "mise use -g"} {
		if !strings.Contains(found.Content, want) {
			t.Fatalf("script lacks %q", want)
		}
	}
	if _, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(found.Content)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sh -n: %v\n%s", err, out)
		}
	}
	// The shell rc puts the payload's bin and mise on PATH.
	if !strings.Contains(sshAgentConsumeSnippet, "/.sc/platform/bin") || !strings.Contains(sshAgentConsumeSnippet, "mise/shims") {
		t.Fatal("shell rc does not add /.sc/platform/bin and mise shims to PATH")
	}
	if _, err := exec.LookPath("bash"); err == nil {
		// Non-interactive (PS1 empty): PATH gains the three entries and mise is
		// NOT activated (which would prepend the host's own tool paths).
		out, err := exec.Command("bash", "--noprofile", "--norc", "-c", "hostname() { echo m.default.t; }; id() { echo t; }; PS1=; HOME=/tmp/h; PATH=/usr/bin:/bin; "+sshAgentConsumeSnippet+"\nprintf '%s' \"$PATH\"").Output()
		if err != nil || string(out) != "/tmp/h/.local/share/mise/shims:/tmp/h/.local/bin:/.sc/platform/bin:/usr/bin:/bin" {
			t.Fatalf("PATH = %q (%v)", out, err)
		}
	}
}

func TestInstallAgenticSeedsHerdrConfigAndIntegrations(t *testing.T) {
	files, _ := PlatformPayload()
	byPath := map[string]PlatformPayloadFile{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	cfg, ok := byPath[SCPayloadHerdrConfigPath]
	if !ok || cfg.Mode != 0o644 || cfg.Content != herdrConfigTOML {
		t.Fatalf("herdr config missing from payload: %+v", cfg)
	}
	for _, want := range []string{`prefix = "ctrl+space"`, `new_cwd = "follow"`, `window_title = "{hostname}: {workspace}"`} {
		if !strings.Contains(herdrConfigTOML, want) {
			t.Fatalf("herdr config lacks %q", want)
		}
	}
	if !strings.Contains(installAgenticScript, SCPlatformPath+"/"+SCPayloadHerdrConfigPath) {
		t.Fatal("install-agentic.sh does not read the payload's herdr config")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}

	// Run the script with stub mise/herdr/id: it seeds the config once, keeps a
	// user's own on re-run, and installs one integration per selected agent.
	dir := t.TempDir()
	home, bin := dir+"/home", dir+"/bin"
	src := dir + "/default.toml"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(home, 0o755))
	must(os.MkdirAll(bin, 0o755))
	must(os.WriteFile(src, []byte(herdrConfigTOML), 0o644))
	stub := func(name, body string) { must(os.WriteFile(bin+"/"+name, []byte("#!/bin/sh\n"+body+"\n"), 0o755)) }
	stub("id", "echo 1000")
	stub("mise", `echo "mise $*" >> "$HOME/calls"`)
	stub("herdr", `echo "herdr $*" >> "$HOME/calls"`)
	run := func(tools string) string {
		cmd := exec.Command("sh", "-c", installAgenticScript)
		cmd.Env = []string{"HOME=" + home, "PATH=" + bin + ":/usr/bin:/bin", "SC_HERDR_CONFIG=" + src, "SC_AGENTIC_TOOLS=" + tools}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("install-agentic.sh: %v\n%s", err, out)
		}
		return string(out)
	}
	userCfg := home + "/.config/herdr/config.toml"

	run("herdr claude")
	got, err := os.ReadFile(userCfg)
	must(err)
	if string(got) != herdrConfigTOML {
		t.Fatal("herdr config not seeded from the payload")
	}
	calls, err := os.ReadFile(home + "/calls")
	must(err)
	if !strings.Contains(string(calls), "herdr integration install claude") || strings.Contains(string(calls), "install codex") {
		t.Fatalf("integrations = %q, want claude only", calls)
	}

	must(os.WriteFile(userCfg, []byte("onboarding = false\n"), 0o644))
	if out := run("herdr"); !strings.Contains(out, "keeping your") {
		t.Fatalf("re-run did not report the kept config:\n%s", out)
	}
	if got, _ := os.ReadFile(userCfg); string(got) != "onboarding = false\n" {
		t.Fatal("re-run overwrote the user's herdr config")
	}

	must(os.Remove(userCfg))
	run("claude codex")
	if _, err := os.Stat(userCfg); err == nil {
		t.Fatal("herdr config seeded although herdr was not selected")
	}
}
