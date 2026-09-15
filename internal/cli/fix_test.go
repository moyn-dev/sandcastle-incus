package cli

import "testing"

func TestSelectFixupsDefaultsToAll(t *testing.T) {
	got, err := selectFixups(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(machineFixups) {
		t.Fatalf("selectFixups(nil) = %d fixups, want all %d", len(got), len(machineFixups))
	}
}

func TestSelectFixupsFiltersByName(t *testing.T) {
	got, err := selectFixups([]string{"caddy-publications", "cloudflared"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].name != "caddy-publications" || got[1].name != "cloudflared" {
		t.Fatalf("selectFixups(caddy-publications, cloudflared) = %+v, want both requested fixups", got)
	}
}

func TestSelectFixupsRejectsUnknown(t *testing.T) {
	if _, err := selectFixups([]string{"nope"}); err == nil {
		t.Fatal("selectFixups should reject an unknown fixup name")
	}
}

// Every registered fixup must supply both an apply and a check script — `sc fix`
// dereferences both (check for --check, apply otherwise).
func TestMachineFixupsAreComplete(t *testing.T) {
	for _, f := range machineFixups {
		if f.name == "" || f.summary == "" {
			t.Fatalf("fixup %+v missing name/summary", f)
		}
		if f.apply == nil || f.check == nil {
			t.Fatalf("fixup %q missing apply/check script", f.name)
		}
		if f.apply() == "" || f.check() == "" {
			t.Fatalf("fixup %q produced an empty script", f.name)
		}
	}
}
