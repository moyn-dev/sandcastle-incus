package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpsertSSHConfigBlockPrependsAndPreservesForeignContent(t *testing.T) {
	existing := "\nHost *\n\tIdentityAgent \"~/agent.sock\"\n"
	tag := sshConfigBlockTag("obelix", "butler", "thies")
	block := renderSSHConfigBlock(tag, []string{"thies.butler.obelix", "butler.tc42.uk"}, "10.123.0.149", "thies", "~/.ssh/sandcastle_ed25519")
	updated, changed := upsertSSHConfigBlock(existing, tag, block)
	if !changed {
		t.Fatal("first upsert must change the file")
	}
	if !strings.HasPrefix(updated, sshConfigBeginMarker(tag)+"\n") {
		t.Fatalf("managed block must come first (first-match precedence over Host *):\n%s", updated)
	}
	for _, want := range []string{
		"Host thies.butler.obelix butler.tc42.uk 10.123.0.149\n",
		"    User thies\n",
		"    IdentityFile ~/.ssh/sandcastle_ed25519\n",
		"    IdentitiesOnly yes\n",
		"    HostKeyAlias thies.butler.obelix\n",
		"Host *\n\tIdentityAgent \"~/agent.sock\"\n",
	} {
		if !strings.Contains(updated, want) {
			t.Fatalf("missing %q in:\n%s", want, updated)
		}
	}
	// Idempotent: a second run with the same block is a no-op.
	again, changed := upsertSSHConfigBlock(updated, tag, block)
	if changed || again != updated {
		t.Fatalf("second upsert must be a no-op:\n%s", again)
	}
	// A changed IP replaces ONLY the managed block; the user's content stays.
	moved := renderSSHConfigBlock(tag, []string{"thies.butler.obelix"}, "10.123.0.7", "thies", "~/.ssh/sandcastle_ed25519")
	replaced, changed := upsertSSHConfigBlock(updated, tag, moved)
	if !changed || strings.Contains(replaced, "10.123.0.149") || !strings.Contains(replaced, "10.123.0.7") {
		t.Fatalf("stale block not replaced:\n%s", replaced)
	}
	if strings.Count(replaced, sshConfigBeginMarker(tag)) != 1 || !strings.Contains(replaced, "IdentityAgent") {
		t.Fatalf("foreign content lost or block duplicated:\n%s", replaced)
	}
	// Another machine's block is left alone.
	other := renderSSHConfigBlock(sshConfigBlockTag("obelix", "wordpress", "web2"), []string{"web2.wordpress.obelix"}, "10.123.0.250", "thies", "~/.ssh/sandcastle_ed25519")
	both, _ := upsertSSHConfigBlock(replaced, sshConfigBlockTag("obelix", "wordpress", "web2"), other)
	if strings.Count(both, sshConfigMarkerPrefix) != 4 {
		t.Fatalf("expected two managed blocks:\n%s", both)
	}
}

func TestSyncLocalSSHConfigCreatesCheckReportsAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssh", "config")
	tag := sshConfigBlockTag("r", "p", "m")
	block := renderSSHConfigBlock(tag, []string{"m.p.r"}, "10.0.0.2", "dev", "~/.ssh/k")
	if status, err := syncLocalSSHConfig(path, tag, block, true); err != nil || status != "NEEDS FIX" {
		t.Fatalf("check on missing file = %q, %v", status, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("--check must not create the file")
	}
	if status, err := syncLocalSSHConfig(path, tag, block, false); err != nil || status != "updated" {
		t.Fatalf("apply = %q, %v", status, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, %v", info, err)
	}
	if status, err := syncLocalSSHConfig(path, tag, block, false); err != nil || status != "current" {
		t.Fatalf("second apply = %q, %v", status, err)
	}
	if status, err := syncLocalSSHConfig(path, tag, block, true); err != nil || status != "current" {
		t.Fatalf("check after apply = %q, %v", status, err)
	}
}
