package incusx

import (
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// The public-name set (ADR-0028) rides the instance-create config as the
// sorted KeyV2PublicHostnames list; a machine without public names gets no
// key at all (never the legacy single key) — including one whose caller
// passed no config.
func TestV2InstanceConfigWithPublicHostnames(t *testing.T) {
	private := v2InstanceConfigWithPublicHostnames(nil, nil)
	if _, ok := private[meta.KeyV2PublicHostnames]; ok {
		t.Fatalf("empty set stamped a list key: %v", private)
	}
	if _, ok := private[meta.KeyV2PublicHostname]; ok {
		t.Fatalf("the legacy single key must never be written: %v", private)
	}
	if meta.PublicHostnamesFromConfig(private) != nil {
		t.Fatalf("no key must read back as no public names")
	}
	zone := v2InstanceConfigWithPublicHostnames(api.ConfigMap{"cloud-init.user-data": "x", meta.KeyV2Bare: "true"}, []string{" Web12.tc42.uk ", "web.baum.hase.de", "web12.tc42.uk"})
	if got := zone[meta.KeyV2PublicHostnames]; got != "web.baum.hase.de,web12.tc42.uk" {
		t.Fatalf("list stamp = %q", got)
	}
	if _, ok := zone[meta.KeyV2PublicHostname]; ok {
		t.Fatalf("the legacy single key must never be written: %v", zone)
	}
	if got := meta.PublicHostnamesFromConfig(zone); strings.Join(got, ",") != "web.baum.hase.de,web12.tc42.uk" {
		t.Fatalf("list stamp read back = %v", got)
	}
	// The stamp is added beside the caller's config, never replacing it.
	if zone["cloud-init.user-data"] != "x" || zone[meta.KeyV2Bare] != "true" {
		t.Fatalf("stamp clobbered the instance config: %v", zone)
	}
	if firstPublicHostname(nil) != "" || firstPublicHostname([]string{"a.b", "c.d"}) != "a.b" {
		t.Fatalf("firstPublicHostname mapping")
	}
}

// A --bare machine's machine.env follows the profile's public-name seed
// (ADR-0028): a project with a domain renders the derived name into its
// PUBLIC_HOSTNAMES line, and the bare document copies that line verbatim —
// same private FQDN, same seed. A private profile yields the default bare
// document.
func TestBareInstanceConfigFollowsProfilePublicHostnames(t *testing.T) {
	domainProfile := tenant.V2ProfileUserData("dev", "ssh-ed25519 AAAA", "zp", "acme", "baum.hase.de", "http://10.249.7.3:9443")
	if got := firstSubmatch(v2ProfileFQDNPattern, domainProfile); got != "zp.acme" {
		t.Fatalf("fqdn domain read off the profile = %q, want the private zp.acme", got)
	}
	seed := tenant.PublicHostnamesEnvLineOf(domainProfile)
	if seed != tenant.PublicHostnamesEnvLine("baum.hase.de") {
		t.Fatalf("seed read off the profile = %q", seed)
	}
	server := newFakeDomainServer()
	server.resources["sc2-acme-zp"] = &fakeDomainResources{profiles: map[string]api.ProfilePut{"default": {Config: map[string]string{"cloud-init.user-data": domainProfile}}}, instances: map[string]*api.Instance{}}
	config, err := v2BareInstanceConfig(server.UseProject("sc2-acme-zp"), "sc2-acme-zp")
	if err != nil {
		t.Fatal(err)
	}
	bare := config["cloud-init.user-data"]
	if !strings.Contains(bare, "      FQDN={{ v1.local_hostname }}.zp.acme\n      "+seed+"\n      SIGNER=http://10.249.7.3:9443\n") {
		t.Fatalf("bare machine.env:\n%s", bare)
	}
	if strings.Contains(bare, "MODE=") || config[meta.KeyV2Bare] != "true" {
		t.Fatalf("bare config: %v", config)
	}

	privateProfile := tenant.V2DefaultProfileUserData("dev", "ssh-ed25519 AAAA", "backend", "acme.example", "http://10.249.7.3:9443")
	plain := tenant.V2BareUserData(firstSubmatch(v2ProfileFQDNPattern, privateProfile), firstSubmatch(v2ProfileSignerPattern, privateProfile))
	if got := tenant.V2BareUserDataWithPublicHostnames(firstSubmatch(v2ProfileFQDNPattern, privateProfile), firstSubmatch(v2ProfileSignerPattern, privateProfile), tenant.PublicHostnamesEnvLineOf(privateProfile)); got != plain {
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

// ListMachinesV2 carries each machine's public names — from the list key or
// the legacy single key — so the host-key purge claims them like any owned
// name.
func TestListMachinesV2CarriesPublicHostname(t *testing.T) {
	server := &fakeRefListServer{projects: map[string][]api.Instance{
		"sc2-acme": nil, // the infra project itself is not an app project
		"sc2-acme-zp": {
			{Name: "web", InstancePut: api.InstancePut{Config: map[string]string{meta.KeyV2PublicHostname: "web.baum.hase.de"}}},
			{Name: "api", InstancePut: api.InstancePut{Config: map[string]string{meta.KeyV2PublicHostnames: "api.baum.hase.de,web12.tc42.uk"}}},
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
		got[ref.Project+":"+ref.Name] = strings.Join(ref.PublicHostnames, ",")
		if ref.PublicHostname != firstPublicHostname(ref.PublicHostnames) {
			t.Fatalf("%s: PublicHostname %q is not the first of %v", ref.Name, ref.PublicHostname, ref.PublicHostnames)
		}
	}
	want := map[string]string{"zp:web": "web.baum.hase.de", "zp:api": "api.baum.hase.de,web12.tc42.uk", "zp:old": "", "default:dev": ""}
	if len(got) != len(want) {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	for key, hostname := range want {
		if got[key] != hostname {
			t.Fatalf("%s public hostname = %q, want %q (all: %v)", key, got[key], hostname, got)
		}
	}
}
