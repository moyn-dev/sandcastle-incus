package cli

import "testing"

// ADR-0021: collapse a tenant's per-install remotes to a single `<suffix>` —
// rename one primary (the default-project one) and remove the same-install rest.
func TestPlanRemoteMigration(t *testing.T) {
	const endpoint = "https://10.61.1.3:8443"
	remotes := []localRemote{
		{Name: "thieso2-io", Endpoint: endpoint, Project: "sc2-thieso2-io"},                           // extra -> remove
		{Name: "sc-majestix-thieso2", Endpoint: endpoint, Project: "sc2-thieso2-default"},             // default -> becomes "castle"
		{Name: "castle-web", Endpoint: endpoint, Project: "sc2-thieso2-web"},                          // extra -> remove
		{Name: "sc-thieso2-infra", Endpoint: endpoint, Project: "sc2-thieso2"},                        // infra -> skip
		{Name: "thieso2-io-elsewhere", Endpoint: "https://10.99.0.9:8443", Project: "sc2-thieso2-io"}, // other install -> skip
	}
	m := planRemoteMigration(remotes, "thieso2", "castle", endpoint)

	if len(m.Renames) != 1 || m.Renames[0].From != "sc-majestix-thieso2" || m.Renames[0].To != "castle" {
		t.Fatalf("want one rename sc-majestix-thieso2 -> castle, got %+v", m.Renames)
	}
	removes := map[string]bool{}
	for _, r := range m.Removes {
		removes[r] = true
	}
	if len(m.Removes) != 2 || !removes["thieso2-io"] || !removes["castle-web"] {
		t.Fatalf("want removes {thieso2-io, castle-web}, got %+v", m.Removes)
	}
	if removes["sc-thieso2-infra"] {
		t.Fatal("infra-pinned remote must be skipped")
	}
	if removes["thieso2-io-elsewhere"] {
		t.Fatal("a different install's remote must never be touched")
	}
}

// An already-`<suffix>`-named remote is the primary (no rename); extras collapse.
func TestPlanRemoteMigrationAlreadyPrimary(t *testing.T) {
	const endpoint = "https://10.61.1.3:8443"
	remotes := []localRemote{
		{Name: "castle", Endpoint: endpoint, Project: "sc2-thieso2-first"},
		{Name: "castle-h2", Endpoint: endpoint, Project: "sc2-thieso2-h2"},
	}
	m := planRemoteMigration(remotes, "thieso2", "castle", endpoint)
	if len(m.Renames) != 0 {
		t.Fatalf("no rename expected, got %+v", m.Renames)
	}
	if len(m.Removes) != 1 || m.Removes[0] != "castle-h2" {
		t.Fatalf("want remove castle-h2, got %+v", m.Removes)
	}
}

// A single already-named remote is a no-op (idempotent).
func TestPlanRemoteMigrationIdempotent(t *testing.T) {
	const endpoint = "https://10.61.1.3:8443"
	remotes := []localRemote{{Name: "castle", Endpoint: endpoint, Project: "sc2-thieso2-first"}}
	m := planRemoteMigration(remotes, "thieso2", "castle", endpoint)
	if len(m.Renames) != 0 || len(m.Removes) != 0 {
		t.Fatalf("fully-migrated input must be a no-op, got %+v", m)
	}
}

func TestPlanRemoteMigration_NoopWhenInputsMissing(t *testing.T) {
	remotes := []localRemote{{Name: "thieso2-io", Endpoint: "e", Project: "sc2-thieso2-io"}}
	if m := planRemoteMigration(remotes, "thieso2", "", "e"); len(m.Renames)+len(m.Removes) != 0 {
		t.Fatalf("empty suffix must produce no plan, got %+v", m)
	}
	if m := planRemoteMigration(remotes, "", "castle", "e"); len(m.Renames)+len(m.Removes) != 0 {
		t.Fatalf("empty tenant must produce no plan, got %+v", m)
	}
	// The safety property: an unknown install endpoint must migrate NOTHING —
	// never widen scope to another install's same-named remotes.
	if m := planRemoteMigration(remotes, "thieso2", "castle", ""); len(m.Renames)+len(m.Removes) != 0 {
		t.Fatalf("empty endpoint must produce no plan (fail safe), got %+v", m)
	}
}
