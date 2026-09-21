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
	run := func(fqdn, user string) string {
		script := "hostname() { echo " + fqdn + "; }; id() { echo " + user + "; }; PS1='x'; " + sshAgentConsumeSnippet + "\nprintf '%s' \"$PS1\""
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
}
