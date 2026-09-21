package tenant

import (
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
