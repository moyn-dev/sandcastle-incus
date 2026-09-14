package authapp

import (
	"context"
	"strings"
	"testing"
	"time"
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

func TestMachineTunnelPublicationRequiresDNSCooldownBeforeReuse(t *testing.T) {
	db := authDBForTest(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	oldNow := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = oldNow })
	publication, _, err := ClaimMachineTunnelPublication(ctx, db, MachineTunnelPublication{Hostname: "app.hase.de", Tenant: "acme", Project: "web", Machine: "app", Port: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if err := ReleaseMachineTunnelPublication(ctx, db, publication); err != nil {
		t.Fatal(err)
	}
	if err := HoldMachinePublicationHostname(ctx, db, publication.Hostname); err != nil {
		t.Fatal(err)
	}
	if err := RequireMachinePublicationHostnameAvailable(ctx, db, publication.Hostname); err == nil || !strings.Contains(err.Error(), "DNS propagation") {
		t.Fatalf("reuse during cooldown = %v", err)
	}
	now = now.Add(MachinePublicationDNSPropagationCooldown)
	if err := RequireMachinePublicationHostnameAvailable(ctx, db, publication.Hostname); err != nil {
		t.Fatalf("reuse after cooldown = %v", err)
	}
}
