package incusx

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// fakeMembersServer is fakeDomainServer plus the project listing the
// membership manager uses to find a tenant's app projects.
type fakeMembersServer struct {
	*fakeDomainServer
}

func (s *fakeMembersServer) GetProjectNames() ([]string, error) {
	names := make([]string, 0, len(s.projects))
	for name := range s.projects {
		names = append(names, name)
	}
	return names, nil
}

func newFakeMembersServer() *fakeMembersServer {
	server := newFakeDomainServer()
	// Two Personal Tenants whose login keys a Shared Tenant renders.
	server.projects["sc2-thieso2"] = &api.Project{Name: "sc2-thieso2", ProjectPut: api.ProjectPut{Config: map[string]string{
		meta.KeyKind: meta.KindInfra, meta.KeyVersion: "2", meta.KeyTenant: "thieso2", keyV2SSHKey: "ssh-ed25519 THIES thies", keyV2Prefix: "sc2",
	}}}
	server.projects["sc2-skorfmann"] = &api.Project{Name: "sc2-skorfmann", ProjectPut: api.ProjectPut{Config: map[string]string{
		meta.KeyKind: meta.KindInfra, meta.KeyVersion: "2", meta.KeyTenant: "skorfmann", keyV2SSHKey: "ssh-ed25519 SEB sebastian", keyV2Prefix: "sc2",
	}}}
	return &fakeMembersServer{fakeDomainServer: server}
}

func profileKeys(t *testing.T, server *fakeMembersServer, project string) string {
	t.Helper()
	res := server.resources[project]
	if res == nil {
		t.Fatalf("project %s was not rendered", project)
	}
	return v2ProfileSSHKeys(res.profiles["default"].Config["cloud-init.user-data"])
}

func TestAddTenantMemberV2RecordsMembershipAndRendersMemberKeys(t *testing.T) {
	server := newFakeMembersServer()
	creator := TenantCreator{Server: server}
	ctx := context.Background()

	members, err := creator.AddTenantMemberV2(ctx, "sc2", "acme", "Thieso2")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(members, []string{"thieso2"}) {
		t.Fatalf("members = %v", members)
	}
	if got := server.projects["sc2-acme"].Config[keyV2Members]; got != "thieso2" {
		t.Fatalf("KeyV2Members = %q", got)
	}
	// The tenant's own key stays first; the member's Personal Tenant key follows.
	if got := profileKeys(t, server, "sc2-acme-zp"); got != "ssh-ed25519 AAAA\nssh-ed25519 THIES thies" {
		t.Fatalf("rendered keys = %q", got)
	}
	// Idempotent, and a second member joins the set.
	if _, err := creator.AddTenantMemberV2(ctx, "sc2", "acme", "thieso2"); err != nil {
		t.Fatal(err)
	}
	members, err = creator.AddTenantMemberV2(ctx, "sc2", "acme", "skorfmann")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(members, []string{"skorfmann", "thieso2"}) {
		t.Fatalf("members = %v", members)
	}
	if got := profileKeys(t, server, "sc2-acme-zp"); got != "ssh-ed25519 AAAA\nssh-ed25519 SEB sebastian\nssh-ed25519 THIES thies" {
		t.Fatalf("rendered keys = %q", got)
	}
	// Removal drops the key again and empties the metadata key when last.
	if _, err := creator.RemoveTenantMemberV2(ctx, "sc2", "acme", "thieso2"); err != nil {
		t.Fatal(err)
	}
	members, err = creator.RemoveTenantMemberV2(ctx, "sc2", "acme", "skorfmann")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Fatalf("members after removal = %v", members)
	}
	if _, ok := server.projects["sc2-acme"].Config[keyV2Members]; ok {
		t.Fatal("KeyV2Members should be deleted when the last member leaves")
	}
	if got := profileKeys(t, server, "sc2-acme-zp"); got != "ssh-ed25519 AAAA" {
		t.Fatalf("rendered keys = %q", got)
	}
}

func TestAddTenantMemberV2RefusesMemberWithoutPersonalTenant(t *testing.T) {
	server := newFakeMembersServer()
	creator := TenantCreator{Server: server}
	_, err := creator.AddTenantMemberV2(context.Background(), "sc2", "acme", "mallory")
	if err == nil || !strings.Contains(err.Error(), "must run `sc login`") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := server.projects["sc2-acme"].Config[keyV2Members]; ok {
		t.Fatal("membership must not be recorded for a refused member")
	}
}

func TestTenantSSHKeyListAddRemoveAndLastKeyGuard(t *testing.T) {
	server := newFakeMembersServer()
	creator := TenantCreator{Server: server}
	ctx := context.Background()
	keys, err := creator.AddTenantSSHKeyV2(ctx, "sc2", "acme", "ssh-ed25519 BBBB laptop")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(keys, []string{"ssh-ed25519 AAAA", "ssh-ed25519 BBBB laptop"}) {
		t.Fatalf("keys = %v", keys)
	}
	if got := profileKeys(t, server, "sc2-acme-zp"); got != "ssh-ed25519 AAAA\nssh-ed25519 BBBB laptop" {
		t.Fatalf("rendered keys = %q", got)
	}
	// Removal matches the key material, not the comment.
	keys, err = creator.RemoveTenantSSHKeyV2(ctx, "sc2", "acme", "ssh-ed25519 BBBB other-comment")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(keys, []string{"ssh-ed25519 AAAA"}) {
		t.Fatalf("keys = %v", keys)
	}
	if _, err := creator.RemoveTenantSSHKeyV2(ctx, "sc2", "acme", "ssh-ed25519 AAAA"); err == nil || !strings.Contains(err.Error(), "last SSH key") {
		t.Fatalf("last-key guard err = %v", err)
	}
}

func TestTenantV2AuthorizedKeysUnionsOwnAndMemberKeys(t *testing.T) {
	server := newFakeMembersServer()
	config := map[string]string{keyV2SSHKey: "ssh-ed25519 AAAA\nssh-ed25519 BBBB laptop", keyV2Members: "skorfmann,thieso2,mallory", keyV2Prefix: "sc2"}
	got := tenantV2AuthorizedKeys(server, "sc2", config)
	// Own keys first, then members' Personal Tenant keys in member order; a
	// member without a Personal Tenant (mallory) contributes nothing.
	if got != "ssh-ed25519 AAAA\nssh-ed25519 BBBB laptop\nssh-ed25519 SEB sebastian\nssh-ed25519 THIES thies" {
		t.Fatalf("authorized keys = %q", got)
	}
	_, missing := MemberSSHKeysV2(server, "sc2", []string{"thieso2", "mallory"})
	if !slices.Equal(missing, []string{"mallory"}) {
		t.Fatalf("missing = %v", missing)
	}
}

func TestV2ProfileSSHKeysReadsTheWholeList(t *testing.T) {
	userData := tenant.V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA a\nssh-ed25519 BBBB b", "default", "acme", "http://10.249.7.3:9443")
	if got := v2ProfileSSHKeys(userData); got != "ssh-ed25519 AAAA a\nssh-ed25519 BBBB b" {
		t.Fatalf("v2ProfileSSHKeys = %q", got)
	}
}
