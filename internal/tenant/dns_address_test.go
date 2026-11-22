package tenant

import (
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

// The sidecar's address is host .3 of the tenant's private /24. Every path that
// re-renders an app project's default profile must supply it: the profile's
// cloud-init embeds it as the machine Caddy's TLS signer URL, and an empty value
// renders "http://:9443" — the machine then serves no HTTPS at all, silently.
func TestDNSAddressForCIDR(t *testing.T) {
	cases := map[string]string{
		"10.61.0.0/24": "10.61.0.3",
		"10.61.1.0/24": "10.61.1.3",
		"10.62.0.0/24": "10.62.0.3",
	}
	for input, want := range cases {
		got, err := DNSAddressForCIDR(input)
		if err != nil {
			t.Fatalf("DNSAddressForCIDR(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("DNSAddressForCIDR(%q) = %q, want %q", input, got, want)
		}
	}
	for _, bad := range []string{"", "   ", "not-a-cidr", "10.61.0.1"} {
		if _, err := DNSAddressForCIDR(bad); err == nil {
			t.Fatalf("DNSAddressForCIDR(%q) succeeded; it must fail closed", bad)
		}
	}
}

// A project's settings must round-trip: they are stored on the project's own
// Incus project and read back into Summary.Projects. Before, they were written
// to a workspace metadata file that nothing ever read, so
// `sc project set-cloud-identity` appeared to work and changed nothing.
func TestV2SummaryReadsProjectSettings(t *testing.T) {
	projects := []IncusProject{
		{Name: "sc2-acme", Config: map[string]string{
			meta.KeyKind: meta.KindInfra, meta.KeyTenant: "acme", meta.KeyVersion: "2",
			meta.KeyV2CIDR: "10.61.0.0/24",
		}},
		{Name: "sc2-acme-default", Config: map[string]string{
			meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "acme", meta.KeyVersion: "2",
			meta.KeyV2CloudIdentity: "gcp", meta.KeyV2DockerAutostart: "true",
		}},
		{Name: "sc2-acme-plain", Config: map[string]string{
			meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "acme", meta.KeyVersion: "2",
		}},
	}
	summaries := v2Summaries(projects, "sc2")
	if len(summaries) != 1 {
		t.Fatalf("summaries = %#v", summaries)
	}
	found := map[string]meta.Project{}
	for _, project := range summaries[0].Projects {
		found[project.Name] = project
	}
	if got := found["default"]; got.CloudIdentity != "gcp" || !got.DockerAutostart {
		t.Fatalf("default project = %#v", got)
	}
	if got := found["plain"]; got.CloudIdentity != "" || got.DockerAutostart {
		t.Fatalf("plain project = %#v", got)
	}
}
