package authapp

import (
	"context"
	"testing"
)

func TestClaimMachineTunnelPublicationMakesOwnershipImmutable(t *testing.T) {
	db := authDBForTest(t)
	ctx := context.Background()
	publication, created, err := ClaimMachineTunnelPublication(ctx, db, MachineTunnelPublication{Hostname: "App.Hase.de.", Tenant: "acme", Project: "web", Machine: "app", Port: 3000})
	if err != nil || !created || publication.Hostname != "app.hase.de" {
		t.Fatalf("first claim = %+v, %t, %v", publication, created, err)
	}
	if _, created, err := ClaimMachineTunnelPublication(ctx, db, publication); err != nil || created {
		t.Fatalf("same claim = created %t, err %v", created, err)
	}
	if _, _, err := ClaimMachineTunnelPublication(ctx, db, MachineTunnelPublication{Hostname: "app.hase.de", Tenant: "acme", Project: "web", Machine: "other", Port: 3000}); err == nil {
		t.Fatal("different machine claim succeeded")
	}
	if err := ReleaseMachineTunnelPublication(ctx, db, publication); err != nil {
		t.Fatal(err)
	}
	if _, found, err := GetMachineTunnelPublication(ctx, db, "app.hase.de"); err != nil || found {
		t.Fatalf("published after release = %t, %v", found, err)
	}
}
