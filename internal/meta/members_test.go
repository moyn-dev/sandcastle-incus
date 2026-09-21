package meta

import (
	"slices"
	"testing"
)

func TestParseAndFormatMembersNormalizeSortAndDedupe(t *testing.T) {
	got := ParseMembers(" Skorfmann, thieso2,skorfmann\n\tbob ,")
	if want := []string{"bob", "skorfmann", "thieso2"}; !slices.Equal(got, want) {
		t.Fatalf("ParseMembers = %v, want %v", got, want)
	}
	if got := FormatMembers([]string{"Thieso2", "", "thieso2", "alice"}); got != "alice,thieso2" {
		t.Fatalf("FormatMembers = %q", got)
	}
	if got := ParseMembers(""); len(got) != 0 {
		t.Fatalf("ParseMembers(\"\") = %v", got)
	}
}

func TestParseAndFormatSSHKeysKeepOrderDropBlanksAndDuplicates(t *testing.T) {
	value := "ssh-ed25519 AAAA owner\n\n  ssh-ed25519 BBBB extra  \nssh-ed25519 AAAA owner\n"
	got := ParseSSHKeys(value)
	if want := []string{"ssh-ed25519 AAAA owner", "ssh-ed25519 BBBB extra"}; !slices.Equal(got, want) {
		t.Fatalf("ParseSSHKeys = %v", got)
	}
	if got := FormatSSHKeys(got); got != "ssh-ed25519 AAAA owner\nssh-ed25519 BBBB extra" {
		t.Fatalf("FormatSSHKeys = %q", got)
	}
}
