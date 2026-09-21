package tenant

import (
	"slices"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/meta"
)

func TestMergeTenantSSHKeysRotatesOwnerKeyKeepsExtras(t *testing.T) {
	existing := "ssh-ed25519 OLD owner\nssh-ed25519 EXTRA added"
	if got := MergeTenantSSHKeys("ssh-ed25519 NEW owner", existing); got != "ssh-ed25519 NEW owner\nssh-ed25519 EXTRA added" {
		t.Fatalf("rotation = %q", got)
	}
	if got := MergeTenantSSHKeys("", existing); got != existing {
		t.Fatalf("blank request = %q, want stored keys kept", got)
	}
	if got := MergeTenantSSHKeys("ssh-ed25519 A\nssh-ed25519 B", "ssh-ed25519 A\nssh-ed25519 B"); got != "ssh-ed25519 A\nssh-ed25519 B" {
		t.Fatalf("idempotent re-run = %q", got)
	}
}

func TestV2ProfileUserDataRendersEveryAuthorizedKey(t *testing.T) {
	userData := V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA thies\nssh-ed25519 BBBB sebastian", "default", "moyn-dev", "http://10.249.7.3:9443")
	want := "    ssh_authorized_keys:\n      - ssh-ed25519 AAAA thies\n      - ssh-ed25519 BBBB sebastian\npackages:"
	if !strings.Contains(userData, want) {
		t.Fatalf("profile lacks the key list:\n%s", userData)
	}
	dev := V2DevUserData("dev", "ssh-ed25519 AAAA thies\nssh-ed25519 BBBB sebastian", "default.moyn-dev")
	if !strings.Contains(dev, "      - ssh-ed25519 AAAA thies\n      - ssh-ed25519 BBBB sebastian\n") {
		t.Fatalf("dev user-data lacks the key list:\n%s", dev)
	}
}

func TestSummaryAccessibleOwnerAndMembers(t *testing.T) {
	summary := Summary{Tenant: "moyn-dev", Members: []string{"skorfmann", "thieso2"}}
	for _, user := range []string{"thieso2", "Skorfmann"} {
		if !summary.Accessible(user) {
			t.Fatalf("%s should be accessible", user)
		}
	}
	if summary.Accessible("mallory") || summary.IsMember("moyn-dev") {
		t.Fatal("non-member accessible")
	}
	personal := Summary{Tenant: "thieso2"}
	if !personal.Accessible("thieso2") || personal.Accessible("skorfmann") {
		t.Fatal("personal tenant access rule broken")
	}
}

func TestPlanCreateV2CarriesMembersAndRefusesOwnerAsMember(t *testing.T) {
	admin := v2TestAdmin()
	plan, err := PlanCreateV2(admin, CreateRequest{
		Reference:       "moyn-dev",
		SSHPublicKey:    "ssh-ed25519 AAAA thies",
		Members:         []string{"Thieso2"},
		ExistingMembers: []string{"skorfmann"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Members, []string{"skorfmann", "thieso2"}) {
		t.Fatalf("Members = %v", plan.Members)
	}
	if _, err := PlanCreateV2(admin, CreateRequest{Reference: "thieso2", SSHPublicKey: "ssh-ed25519 AAAA", Members: []string{"thieso2"}}); err == nil || !strings.Contains(err.Error(), "names the tenant itself") {
		t.Fatalf("owner-as-member err = %v", err)
	}
	if got := meta.FormatMembers(plan.Members); got != "skorfmann,thieso2" {
		t.Fatalf("FormatMembers = %q", got)
	}
}

func TestPlanCreateV2DefaultsTheUnixUserToTheTenantName(t *testing.T) {
	plan, err := PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "moyn-dev", SSHPublicKey: "ssh-ed25519 AAAA"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultProfileUser != "moyn-dev" {
		t.Fatalf("DefaultProfileUser = %q", plan.DefaultProfileUser)
	}
	// Explicit and stored users still win; an invalid tenant-name user falls back.
	plan, _ = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "moyn-dev", SSHPublicKey: "k", UnixUser: "sebastian"})
	if plan.DefaultProfileUser != "sebastian" {
		t.Fatalf("explicit user = %q", plan.DefaultProfileUser)
	}
	plan, _ = PlanCreateV2(v2TestAdmin(), CreateRequest{Reference: "moyn-dev", SSHPublicKey: "k", ExistingUnixUser: "dev"})
	if plan.DefaultProfileUser != "dev" {
		t.Fatalf("stored user = %q", plan.DefaultProfileUser)
	}
	if got := DefaultUnixUserForTenant("1octocat"); got != DefaultV2UnixUser {
		t.Fatalf("invalid-name fallback = %q", got)
	}
}
