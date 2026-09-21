package tenant

import (
	"os/exec"
	"strings"
	"testing"
)

// The payload's shell rc sets the prompt from the machine's FQDN and login
// user: user@fqdn, or just the fqdn when the user is the tenant (the FQDN
// ends in ".<user>"). Exercised under real bash with hostname/id stubbed.
func TestShellRCPromptUsesFQDNAndDropsARedundantTenantUser(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	// Like a real login: the rc runs first, then the stock ~/.bashrc sets
	// Debian's PS1, then the first prompt fires PROMPT_COMMAND.
	run := func(fqdn, user string) string {
		script := "unset PROMPT_COMMAND; PATH=/nonexistent; HOME=/tmp/h; hostname() { echo " + fqdn + "; }; id() { echo " + user + "; }; PS1='x'; " + sshAgentConsumeSnippet +
			"\nPS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '; eval \"$PROMPT_COMMAND\"; printf '%s' \"$PS1\""
		out, err := exec.Command("bash", "--noprofile", "--norc", "-c", script).Output()
		if err != nil {
			t.Fatalf("bash: %v", err)
		}
		return string(out)
	}
	if got := run("web.default.moyn-dev", "moyn-dev"); got != `web.default.moyn-dev:\w\$ ` {
		t.Fatalf("tenant user prompt = %q", got)
	}
	if got := run("web.default.moyn-dev", "sebastian"); got != `sebastian@web.default.moyn-dev:\w\$ ` {
		t.Fatalf("other user prompt = %q", got)
	}
	if got := run("web.default.thieso2", "dev"); !strings.HasPrefix(got, "dev@web.default.thieso2:") {
		t.Fatalf("legacy dev user prompt = %q", got)
	}
	// A prompt the user chose (no \u@\h in it) is left alone, and the hook
	// removes itself after the first prompt.
	script := "unset PROMPT_COMMAND; PATH=/nonexistent; HOME=/tmp/h; hostname() { echo m.default.t; }; id() { echo t; }; PS1='x'; " + sshAgentConsumeSnippet +
		"\nPS1='mine> '; eval \"$PROMPT_COMMAND\"; printf '%s|%s' \"$PS1\" \"$PROMPT_COMMAND\""
	out, err := exec.Command("bash", "--noprofile", "--norc", "-c", script).Output()
	if err != nil || string(out) != "mine> |" {
		t.Fatalf("custom prompt: %q (%v)", out, err)
	}
}
