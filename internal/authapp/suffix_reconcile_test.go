package authapp

import (
	"context"
	"errors"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type fakeReconcileStore struct {
	projects []tenant.IncusProject
	err      error
}

func (f fakeReconcileStore) ListProjects(ctx context.Context) ([]tenant.IncusProject, error) {
	return f.projects, f.err
}

func TestPruneOrphanSuffixClaims_PrunesAbsentTenants(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	if _, err := ClaimDNSSuffix(ctx, db, "castle", "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimDNSSuffix(ctx, db, "ghost", "bob", "bob"); err != nil {
		t.Fatal(err)
	}
	pruned, err := pruneOrphanSuffixClaims(ctx, db, []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}
	if _, found, _ := GetDNSSuffixClaimByTenant(ctx, db, "bob"); found {
		t.Fatal("bob's orphan claim should be pruned")
	}
	if _, found, _ := GetDNSSuffixClaimByTenant(ctx, db, "alice"); !found {
		t.Fatal("alice's live claim must survive")
	}
}

// The critical safety property: an empty live set must NEVER wipe the registry
// (a transient tenant-listing hiccup would otherwise delete every claim).
func TestPruneOrphanSuffixClaims_EmptyLiveSetNeverPrunes(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	if _, err := ClaimDNSSuffix(ctx, db, "castle", "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	pruned, err := pruneOrphanSuffixClaims(ctx, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 0 {
		t.Fatalf("pruned = %d, want 0 — an empty live set must not prune", pruned)
	}
	if _, found, _ := GetDNSSuffixClaimByTenant(ctx, db, "alice"); !found {
		t.Fatal("claim must survive an empty live set")
	}
}

func TestReconcileSuffixClaimsOnce_ListingErrorAbortsWithoutPruning(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	if _, err := ClaimDNSSuffix(ctx, db, "castle", "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	r := HTTPRunner{
		Tenants: fakeReconcileStore{err: errors.New("incus unreachable")},
		Admin:   config.Admin{IncusProjectPrefix: "sc2"},
	}
	if _, err := r.reconcileSuffixClaimsOnce(ctx, db); err == nil {
		t.Fatal("a listing error must be returned, not swallowed")
	}
	// A hard listing error must never be read as "no tenants" and prune.
	if _, found, _ := GetDNSSuffixClaimByTenant(ctx, db, "alice"); !found {
		t.Fatal("claim must survive a listing error")
	}
}

func TestReconcileSuffixClaimsOnce_EmptyInstallDoesNotPrune(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	if _, err := ClaimDNSSuffix(ctx, db, "castle", "alice", "alice"); err != nil {
		t.Fatal(err)
	}
	r := HTTPRunner{
		Tenants: fakeReconcileStore{projects: nil}, // no projects -> no live tenants
		Admin:   config.Admin{IncusProjectPrefix: "sc2"},
	}
	pruned, err := r.reconcileSuffixClaimsOnce(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 0 {
		t.Fatalf("pruned = %d, want 0", pruned)
	}
	if _, found, _ := GetDNSSuffixClaimByTenant(ctx, db, "alice"); !found {
		t.Fatal("claim must survive an empty install listing")
	}
}
