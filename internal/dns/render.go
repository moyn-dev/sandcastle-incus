package dns

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
)

type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    int    `json:"mode"`
}

const (
	SelfResolverPath        = "/etc/resolv.conf"
	SelfResolverContent     = "nameserver 127.0.0.1\n"
	UpstreamResolverPath    = "/etc/coredns/upstream-resolv.conf"
	UpstreamResolverContent = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
)

func RenderInitial(suffix string, dnsAddress string) ([]File, error) {
	return RenderTenant(suffix, dnsAddress, "", nil)
}

// RenderTenant builds the CoreDNS config for a tenant. The tenant zone is the
// ONLY authority for names under the Tenant DNS Suffix (ADR-0018): there is no
// fallthrough to the bridge dnsmasq, because lease names are guest-asserted
// and single-label (they cannot express the project). Names outside the suffix
// forward upstream.
//
// Record shape per machine (ADR-0018):
//   - canonical Machine Private Hostname <machine>.<project>.<suffix> plus its
//     wildcard, for every machine whose project is known;
//   - the Default Project Short Hostname <machine>.<suffix> (plus wildcard)
//     ONLY for machines in the tenant's default project — never first-wins across
//     projects, never uniqueness-dependent;
//   - a machine with no known project (legacy callers) gets the short form only.
//
// defaultProject is the short name of the tenant's default project (issue #93);
// it defaults to "default" when empty, so the short alias follows a renamed
// initial project instead of a project literally called "default".
func RenderTenant(domain string, dnsAddress string, defaultProject string, machines []meta.Machine) ([]File, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil, fmt.Errorf("tenant DNS suffix is required")
	}
	if dnsAddress == "" {
		return nil, fmt.Errorf("DNS address is required")
	}
	defaultProject = strings.TrimSpace(defaultProject)
	if defaultProject == "" {
		defaultProject = naming.DefaultProjectName
	}

	zonePath := path.Join("/etc/coredns/zones", "db."+domain)
	zone := fmt.Sprintf(`$ORIGIN %s.
$TTL 60
@ IN SOA ns.%s. hostmaster.%s. 1 3600 600 604800 60
@ IN NS ns.%s.
ns IN A %s
`, domain, domain, domain, domain, dnsAddress)
	sort.Slice(machines, func(i, j int) bool {
		if machines[i].Project == machines[j].Project {
			return machines[i].Name < machines[j].Name
		}
		return machines[i].Project < machines[j].Project
	})
	for _, machine := range machines {
		if machine.Name == "" || machine.PrivateIP == "" {
			continue
		}
		if machine.Project == "" || machine.Project == defaultProject {
			short := machine.Name + "." + domain + "."
			zone += fmt.Sprintf("%s IN A %s\n*.%s IN A %s\n", short, machine.PrivateIP, short, machine.PrivateIP)
		}
		if machine.Project != "" {
			record := machine.Name + "." + machine.Project + "." + domain + "."
			zone += fmt.Sprintf("%s IN A %s\n*.%s IN A %s\n", record, machine.PrivateIP, record, machine.PrivateIP)
		}
	}
	return []File{
		{
			Path: "/etc/coredns/Corefile",
			Mode: 0o644,
			// The catch-all recursion exists for tenant MACHINES (this server
			// is their only DNS). Tailnet clients (100.64/10) must get REFUSED
			// for names outside the tenant zone instead: their local resolver
			// merges every tenant's server into one flat list and only falls
			// through to the next server on REFUSED — an upstream-forwarded
			// NXDOMAIN for another tenant's name (or a public name) would end
			// the lookup and mask the answering server. The zone block above
			// still answers tailnet queries for this tenant's own names.
			Content: fmt.Sprintf(`%s:53 {
    errors
    file %s %s
}
.:53 {
    errors
    acl {
        block net 100.64.0.0/10
    }
    forward . %s {
        force_tcp
    }
}
`, domain, zonePath, domain, UpstreamResolverPath),
		},
		{
			Path:    zonePath,
			Mode:    0o644,
			Content: zone,
		},
		{
			Path:    SelfResolverPath,
			Mode:    0o644,
			Content: SelfResolverContent,
		},
		{
			Path:    UpstreamResolverPath,
			Mode:    0o644,
			Content: UpstreamResolverContent,
		},
	}, nil
}
