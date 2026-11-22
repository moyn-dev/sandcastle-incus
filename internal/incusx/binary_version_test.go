package incusx

import (
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

type fakeStampServer struct {
	instances map[string]*api.Instance
	updated   map[string]api.InstancePut
}

func (s *fakeStampServer) GetInstance(name string) (*api.Instance, string, error) {
	inst, ok := s.instances[name]
	if !ok {
		return nil, "", api.StatusErrorf(404, "not found")
	}
	return inst, "etag-1", nil
}

func (s *fakeStampServer) UpdateInstance(name string, put api.InstancePut, etag string) (incus.Operation, error) {
	if s.updated == nil {
		s.updated = map[string]api.InstancePut{}
	}
	s.updated[name] = put
	return fakeOperation{}, nil
}

func TestStampBinaryVersionWritesNormalizedTag(t *testing.T) {
	server := &fakeStampServer{instances: map[string]*api.Instance{
		"sc2-auth-app": {InstancePut: api.InstancePut{Config: map[string]string{
			meta.KeyKind: "auth-app",
		}}},
	}}
	if err := stampBinaryVersion(server, "sc2-auth-app", "0.2.0"); err != nil {
		t.Fatalf("stampBinaryVersion: %v", err)
	}
	put, ok := server.updated["sc2-auth-app"]
	if !ok {
		t.Fatal("instance not updated")
	}
	if got := put.Config[meta.KeyBinaryVersion]; got != "v0.2.0" {
		t.Fatalf("stamp = %q, want v0.2.0", got)
	}
	if got := put.Config[meta.KeyKind]; got != "auth-app" {
		t.Fatalf("existing config clobbered: kind = %q", got)
	}
}

func TestStampBinaryVersionSkipsEmptyVersion(t *testing.T) {
	server := &fakeStampServer{instances: map[string]*api.Instance{"x": {}}}
	if err := stampBinaryVersion(server, "x", ""); err != nil {
		t.Fatalf("stampBinaryVersion: %v", err)
	}
	if len(server.updated) != 0 {
		t.Fatal("expected no update for empty version")
	}
}
