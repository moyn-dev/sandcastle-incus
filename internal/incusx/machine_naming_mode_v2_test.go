package incusx

import (
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// The Naming Mode record (ADR-0027 §1.1) rides the instance-create config:
// the Machine Public Hostname for a zone-mode machine, the literal "private"
// otherwise — including for a machine whose caller passed no config at all.
func TestV2InstanceConfigWithNamingMode(t *testing.T) {
	private := v2InstanceConfigWithNamingMode(nil, "")
	if got := private[meta.KeyV2PublicHostname]; got != meta.NamingModePrivate {
		t.Fatalf("private stamp = %q", got)
	}
	if meta.PublicHostnameFromConfig(private) != "" {
		t.Fatalf("private stamp must read back as private mode")
	}
	zone := v2InstanceConfigWithNamingMode(api.ConfigMap{"cloud-init.user-data": "x", meta.KeyV2Bare: "true"}, " web.baum.hase.de ")
	if got := zone[meta.KeyV2PublicHostname]; got != "web.baum.hase.de" {
		t.Fatalf("zone stamp = %q", got)
	}
	if meta.PublicHostnameFromConfig(zone) != "web.baum.hase.de" {
		t.Fatalf("zone stamp must read back as the public hostname")
	}
	// The stamp is added beside the caller's config, never replacing it.
	if zone["cloud-init.user-data"] != "x" || zone[meta.KeyV2Bare] != "true" {
		t.Fatalf("stamp clobbered the instance config: %v", zone)
	}
	if namingModeRecord("") != meta.NamingModePrivate || namingModeRecord("a.b") != "a.b" {
		t.Fatalf("namingModeRecord mapping")
	}
}

// A --bare machine's machine.env follows the profile's Naming Mode: a zone
// project's profile carries MODE=zone, so the bare document does too — same
// FQDN domain, same mode, so caddy-setup on it waits for the pushed
// certificate instead of asking the signer. A private profile yields the
// unchanged bare document.
func TestBareInstanceConfigFollowsProfileNamingMode(t *testing.T) {
	zoneProfile := tenant.V2ProfileUserData("dev", "ssh-ed25519 AAAA", "zp", "acme", "baum.hase.de", "http://10.249.7.3:9443")
	if got := firstSubmatch(v2ProfileModePattern, zoneProfile); got != "zone" {
		t.Fatalf("mode read off the zone profile = %q", got)
	}
	bare := tenant.V2BareUserDataForMode(
		firstSubmatch(v2ProfileFQDNPattern, zoneProfile),
		firstSubmatch(v2ProfileSignerPattern, zoneProfile),
		firstSubmatch(v2ProfileModePattern, zoneProfile),
	)
	if !strings.Contains(bare, "      FQDN={{ v1.local_hostname }}.baum.hase.de\n      MODE=zone\n      SIGNER=http://10.249.7.3:9443\n") {
		t.Fatalf("bare zone machine.env:\n%s", bare)
	}

	privateProfile := tenant.V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "backend", "acme.example", "http://10.249.7.3:9443")
	if got := firstSubmatch(v2ProfileModePattern, privateProfile); got != "" {
		t.Fatalf("mode read off a private profile = %q, want none", got)
	}
	legacy := tenant.V2BareUserData(firstSubmatch(v2ProfileFQDNPattern, privateProfile), firstSubmatch(v2ProfileSignerPattern, privateProfile))
	if got := tenant.V2BareUserDataForMode(firstSubmatch(v2ProfileFQDNPattern, privateProfile), firstSubmatch(v2ProfileSignerPattern, privateProfile), ""); got != legacy {
		t.Fatalf("private bare document drifted:\n%s", got)
	}
}

// fakeRefListServer / fakeRefListResources implement the two calls ListMachinesV2
// makes: the project listing and, per app project, the instance listing with
// each instance's own config.
type fakeRefListServer struct {
	TenantCreateServer
	projects map[string][]api.Instance
}

func (s *fakeRefListServer) GetProjectNames() ([]string, error) {
	names := make([]string, 0, len(s.projects))
	for name := range s.projects {
		names = append(names, name)
	}
	return names, nil
}

func (s *fakeRefListServer) UseProject(name string) TenantResourceServer {
	return &fakeRefListResources{instances: s.projects[name]}
}

type fakeRefListResources struct {
	TenantResourceServer
	instances []api.Instance
}

func (r *fakeRefListResources) GetInstances(api.InstanceType) ([]api.Instance, error) {
	return r.instances, nil
}

// ListMachinesV2 carries each machine's Naming Mode record so the host-key
// purge claims a zone machine's public name like any owned name.
func TestListMachinesV2CarriesPublicHostname(t *testing.T) {
	server := &fakeRefListServer{projects: map[string][]api.Instance{
		"sc2-acme": nil, // the infra project itself is not an app project
		"sc2-acme-zp": {
			{Name: "web", InstancePut: api.InstancePut{Config: map[string]string{meta.KeyV2PublicHostname: "web.baum.hase.de"}}},
			{Name: "old"},
		},
		"sc2-acme-default": {
			{Name: "dev", InstancePut: api.InstancePut{Config: map[string]string{meta.KeyV2PublicHostname: meta.NamingModePrivate}}},
		},
		"sc2-other-default": {{Name: "foreign"}},
	}}
	creator := TenantCreator{Server: server}
	refs, err := creator.ListMachinesV2(t.Context(), "sc2-acme")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, ref := range refs {
		got[ref.Project+":"+ref.Name] = ref.PublicHostname
	}
	want := map[string]string{"zp:web": "web.baum.hase.de", "zp:old": "", "default:dev": ""}
	if len(got) != len(want) {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	for key, hostname := range want {
		if got[key] != hostname {
			t.Fatalf("%s public hostname = %q, want %q (all: %v)", key, got[key], hostname, got)
		}
	}
}
