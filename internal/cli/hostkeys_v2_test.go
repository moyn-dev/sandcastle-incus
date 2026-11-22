package cli

import (
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/hostkeys"
)

func TestHostKeyDisagreement(t *testing.T) {
	ed := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAAed"}
	ecdsa := hostkeys.Key{Type: "ecdsa-sha2-nistp256", Key: "AAAAecdsa"}
	rsa := hostkeys.Key{Type: "ssh-rsa", Key: "AAAArsa"}

	cases := []struct {
		name          string
		authoritative []hostkeys.Key
		scanned       []hostkeys.Key
		wantContains  string
	}{
		{
			name:          "settled machine agrees",
			authoritative: []hostkeys.Key{ed, ecdsa, rsa},
			scanned:       []hostkeys.Key{ed, ecdsa, rsa},
		},
		{
			name:          "sshd offering fewer types is not a disagreement",
			authoritative: []hostkeys.Key{ed, ecdsa, rsa},
			scanned:       []hostkeys.Key{ed},
		},
		{
			// cloud-init regenerated the keys after the API read.
			name:          "rotated key",
			authoritative: []hostkeys.Key{ed},
			scanned:       []hostkeys.Key{{Type: "ssh-ed25519", Key: "AAAAother"}},
			wantContains:  "not the one in /etc/ssh",
		},
		{
			// Read straddling cloud-init's delete: the rsa file was already gone.
			name:          "partial read misses a type sshd serves",
			authoritative: []hostkeys.Key{ed, ecdsa},
			scanned:       []hostkeys.Key{ed, ecdsa, rsa},
			wantContains:  "did not yield",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := hostKeyDisagreement(testCase.authoritative, testCase.scanned)
			if testCase.wantContains == "" {
				if got != "" {
					t.Fatalf("expected agreement, got %q", got)
				}
				return
			}
			if !strings.Contains(got, testCase.wantContains) {
				t.Fatalf("expected disagreement containing %q, got %q", testCase.wantContains, got)
			}
		})
	}
}

func TestServedHostKeysRecordsOnlyWhatSSHDOffers(t *testing.T) {
	ed := hostkeys.Key{Type: "ssh-ed25519", Key: "AAAA_ed"}
	ecdsa := hostkeys.Key{Type: "ecdsa-sha2-nistp256", Key: "AAAA_ecdsa"}
	rsa := hostkeys.Key{Type: "ssh-rsa", Key: "AAAA_rsa"}
	onDisk := []hostkeys.Key{ed, ecdsa, rsa}

	if got := servedHostKeys(onDisk, []hostkeys.Key{ed}); len(got) != 1 || got[0] != ed {
		t.Fatalf("sshd serves only ed25519, recorded %v", got)
	}
	if got := servedHostKeys(onDisk, []hostkeys.Key{rsa, ed, ecdsa}); len(got) != 3 || got[0] != ed || got[2] != rsa {
		t.Fatalf("all served keys are kept in authoritative order, got %v", got)
	}
	if got := servedHostKeys(onDisk, nil); len(got) != 3 {
		t.Fatalf("a scan that confirms nothing must not empty the record, got %v", got)
	}
}
