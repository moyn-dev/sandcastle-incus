package incusx

import (
	"context"
	"net/http"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/config"
	scimages "github.com/moyn-dev/sandcastle-incus/internal/images"
)

// customImageAdminForTest sets the custom Sandcastle image aliases the image
// feature is meant to build; the package defaults are stock upstream images.
func customImageAdminForTest() config.Admin {
	cfg := config.LoadAdminFromEnv()
	cfg.Images = config.Images{Base: "sandcastle/base:latest", AI: "sandcastle/ai:latest", Dev: "sandcastle/dev:latest"}
	return cfg
}

type fakeImageServer struct {
	images       map[string]*api.Image
	aliases      map[string]*api.ImageAliasesEntry
	createdAlias *api.ImageAliasesPost
	updatedAlias *api.ImageAliasesEntryPut
}

func (s *fakeImageServer) GetImage(ref string) (*api.Image, string, error) {
	if image := s.images[ref]; image != nil {
		return image, "etag", nil
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "not found")
}

func (s *fakeImageServer) GetImageAlias(name string) (*api.ImageAliasesEntry, string, error) {
	if alias := s.aliases[name]; alias != nil {
		return alias, "etag", nil
	}
	return nil, "", api.StatusErrorf(http.StatusNotFound, "not found")
}

func (s *fakeImageServer) CreateImageAlias(alias api.ImageAliasesPost) error {
	s.createdAlias = &alias
	s.aliases[alias.Name] = &alias.ImageAliasesEntry
	return nil
}

func (s *fakeImageServer) UpdateImageAlias(name string, alias api.ImageAliasesEntryPut, etag string) error {
	s.updatedAlias = &alias
	s.aliases[name] = &api.ImageAliasesEntry{Name: name, ImageAliasesEntryPut: alias}
	return nil
}

func TestImageManagerCreatesAliasForImage(t *testing.T) {
	server := &fakeImageServer{
		images:  map[string]*api.Image{"sandcastle/base:debian-13": {Fingerprint: "abc123"}},
		aliases: map[string]*api.ImageAliasesEntry{},
	}
	plan, err := scimages.PlanSync(customImageAdminForTest(), scimages.SyncRequest{SourceRef: "sandcastle/base:debian-13"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (ImageManager{Server: server}).SyncImage(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "created" {
		t.Fatalf("Action = %q", result.Action)
	}
	if server.createdAlias == nil {
		t.Fatal("expected alias creation")
	}
	if server.createdAlias.Name != "sandcastle/base:latest" || server.createdAlias.Target != "abc123" {
		t.Fatalf("created alias = %#v", server.createdAlias)
	}
}

func TestImageManagerUpdatesExistingAlias(t *testing.T) {
	server := &fakeImageServer{
		images: map[string]*api.Image{"sandcastle/ai:debian-13": {Fingerprint: "def456"}},
		aliases: map[string]*api.ImageAliasesEntry{
			"sandcastle/ai:latest": {Name: "sandcastle/ai:latest", ImageAliasesEntryPut: api.ImageAliasesEntryPut{Target: "old"}},
		},
	}
	plan, err := scimages.PlanSync(customImageAdminForTest(), scimages.SyncRequest{SourceRef: "sandcastle/ai:debian-13"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (ImageManager{Server: server}).SyncImage(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "updated" {
		t.Fatalf("Action = %q", result.Action)
	}
	if server.updatedAlias == nil || server.updatedAlias.Target != "def456" {
		t.Fatalf("updated alias = %#v", server.updatedAlias)
	}
}

func TestImageManagerResolvesSourceAlias(t *testing.T) {
	server := &fakeImageServer{
		images: map[string]*api.Image{"abc123": {Fingerprint: "abc123"}},
		aliases: map[string]*api.ImageAliasesEntry{
			"sandcastle/base:debian-13": {Name: "sandcastle/base:debian-13", ImageAliasesEntryPut: api.ImageAliasesEntryPut{Target: "abc123"}},
		},
	}
	plan, err := scimages.PlanSync(customImageAdminForTest(), scimages.SyncRequest{SourceRef: "sandcastle/base:debian-13"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (ImageManager{Server: server}).SyncImage(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Fingerprint != "abc123" {
		t.Fatalf("Fingerprint = %q", result.Fingerprint)
	}
}
