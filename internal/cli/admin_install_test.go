package cli

import (
	"strings"
	"testing"
)

func TestApplianceBridgeNameFitsLinuxInterfaceLimit(t *testing.T) {
	const longPrefix = "e2epub0915115128"
	got := applianceBridgeName(longPrefix)
	if len(got) > 15 {
		t.Fatalf("bridge name %q has length %d; Linux bridge interfaces permit at most 15 characters", got, len(got))
	}
	if got == longPrefix+"-net" {
		t.Fatalf("long prefix retained the invalid bridge name %q", got)
	}
	if again := applianceBridgeName(longPrefix); got != again {
		t.Fatalf("bridge name must be deterministic: first %q, second %q", got, again)
	}
	if !strings.HasSuffix(got, "-net") {
		t.Fatalf("bridge name %q must retain the bridge suffix", got)
	}
}

func TestApplianceBridgeNamePreservesShortPrefix(t *testing.T) {
	if got, want := applianceBridgeName("sc2"), "sc2-net"; got != want {
		t.Fatalf("applianceBridgeName(sc2) = %q, want %q", got, want)
	}
}
