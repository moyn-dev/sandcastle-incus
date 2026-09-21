package tenant

import (
	"context"
	"net/netip"
	"sort"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/cidr"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

type IncusProject struct {
	Name   string
	Config map[string]string
}

type IncusTenantStore interface {
	ListProjects(ctx context.Context) ([]IncusProject, error)
}

type Summary struct {
	IncusName    string `json:"incusName"`
	InfraProject string `json:"infraProject"`
	Tenant       string `json:"tenant"`
	Version      int    `json:"version,omitempty"`
	Personal     bool   `json:"personal,omitempty"`
	UnixUser     string `json:"unixUser,omitempty"`
	DNSSuffix    string `json:"dnsSuffix,omitempty"`
	// DefaultProject is the short name of the tenant's initial project (issue
	// #93), read from the kind=infra project metadata. Empty ⇒ "default".
	DefaultProject  string `json:"defaultProject,omitempty"`
	PrivateCIDR     string `json:"privateCIDR,omitempty"`
	DNSAddress      string `json:"dnsAddress,omitempty"`
	DefaultTemplate string `json:"defaultTemplate,omitempty"`
	SSHPublicKey    string `json:"sshPublicKey,omitempty"`
	// Members are the Tenant Members of a Shared Tenant (normalized user
	// keys, meta.KeyV2Members on the infra project); empty for a Personal
	// Tenant, which belongs to the user whose key names it.
	Members       []string                  `json:"members,omitempty"`
	Projects      []meta.Project            `json:"projects,omitempty"`
	Status        string                    `json:"status"`
	Tailscale     meta.Tailscale            `json:"tailscale,omitempty"`
	PublicRoutes  []meta.PublicRoute        `json:"publicRoutes,omitempty"`
	StorageShares []meta.TenantStorageShare `json:"storageShares,omitempty"`
}

func List(ctx context.Context, store IncusTenantStore) ([]Summary, error) {
	return ListForPrefix(ctx, store, "")
}

// ListForPrefix scopes the v2 tenant summaries to one installation prefix —
// several sandcastles share an Incus host (--prefix), and same-named tenants
// of different installs are different tenants. Empty prefix = no scoping
// (restricted tenant certs only see their own projects anyway; admin-socket
// callers like the auth-app MUST pass their install's prefix).
func ListForPrefix(ctx context.Context, store IncusTenantStore, installPrefix string) ([]Summary, error) {
	projects, err := store.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	// THE SEAM. This was the only place a Summary was ever minted with
	// Version 1 (from a kind=tenant project). v1 is gone, so every Summary in
	// the process is v2 — which is what lets every version gate collapse.
	summaries := v2Summaries(projects, installPrefix)
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Tenant < summaries[j].Tenant
	})
	return summaries, nil
}

// v2Summaries builds tenant summaries from v2 per-project Incus projects
// (<prefix>-<tenant>-<project>, kind=project version=2). This is the view a
// tenant's restricted certificate has of its own namespace — the kind=infra
// project (sidecar, CIDR) is usually not visible to it, so the summary is
// assembled from the app projects alone: DNS suffix defaults to the tenant
// name (the v2 default) and the CIDR stays empty.
func v2Summaries(projects []IncusProject, installPrefix string) []Summary {
	installPrefix = strings.TrimSpace(installPrefix)
	if installPrefix == naming.DefaultIncusProjectPrefix {
		installPrefix = naming.V2IncusProjectPrefix
	}
	// The kind=infra projects (visible to admin-socket callers like the
	// auth-app, usually not to restricted tenant certs) carry the tenant's
	// /24 — collect them so the summaries can report it. Keyed by the
	// installation's infra project name (<prefix>-<tenant>): same-named
	// tenants of different installs are different tenants.
	cidrByInfra := map[string]string{}
	suffixByInfra := map[string]string{}
	userByInfra := map[string]string{}
	defaultProjectByInfra := map[string]string{}
	membersByInfra := map[string][]string{}
	for _, incusProject := range projects {
		if meta.IsManaged(incusProject.Config) && incusProject.Config[meta.KeyKind] == meta.KindInfra {
			cidrByInfra[incusProject.Name] = strings.TrimSpace(incusProject.Config[meta.KeyV2CIDR])
			suffixByInfra[incusProject.Name] = strings.TrimSpace(incusProject.Config[meta.KeyV2Suffix])
			userByInfra[incusProject.Name] = strings.TrimSpace(incusProject.Config[meta.KeyV2User])
			defaultProjectByInfra[incusProject.Name] = strings.TrimSpace(incusProject.Config[meta.KeyV2DefaultProject])
			membersByInfra[incusProject.Name] = meta.ParseMembers(incusProject.Config[meta.KeyV2Members])
		}
	}
	byInfra := map[string]*Summary{}
	order := []string{}
	for _, incusProject := range projects {
		if !meta.IsManaged(incusProject.Config) {
			continue
		}
		if incusProject.Config[meta.KeyKind] != meta.KindV2Project || incusProject.Config[meta.KeyVersion] != "2" {
			continue
		}
		tenantName := strings.TrimSpace(incusProject.Config[meta.KeyTenant])
		if tenantName == "" {
			continue
		}
		marker := "-" + tenantName + "-"
		idx := strings.Index(incusProject.Name, marker)
		if idx <= 0 {
			continue
		}
		shortName := incusProject.Name[idx+len(marker):]
		if shortName == "" {
			continue
		}
		projectPrefix := incusProject.Name[:idx]
		if installPrefix != "" && projectPrefix != installPrefix {
			continue
		}
		infraName := incusProject.Name[:idx+len("-"+tenantName)]
		if suffix := strings.TrimSpace(incusProject.Config[meta.KeyV2Suffix]); suffix != "" {
			if suffixByInfra[infraName] == "" {
				suffixByInfra[infraName] = suffix
			}
			if existing := byInfra[infraName]; existing != nil && existing.DNSSuffix == tenantName {
				existing.DNSSuffix = suffix
			}
		}
		summary, seen := byInfra[infraName]
		if !seen {
			summary = &Summary{
				Tenant:         tenantName,
				Version:        2,
				InfraProject:   infraName,
				UnixUser:       userByInfra[infraName],
				DNSSuffix:      firstNonEmptyString(suffixByInfra[infraName], tenantName),
				DefaultProject: defaultProjectByInfra[infraName],
				Members:        membersByInfra[infraName],
				PrivateCIDR:    cidrByInfra[infraName],
				DNSAddress:     dnsAddressFromCIDR(cidrByInfra[infraName]),
				Status:         "managed",
			}
			byInfra[infraName] = summary
			order = append(order, infraName)
		}
		if shortName == naming.DefaultProjectName || summary.IncusName == "" {
			summary.IncusName = incusProject.Name
		}
		summary.Projects = append(summary.Projects, meta.Project{
			Name:            shortName,
			CloudIdentity:   strings.TrimSpace(incusProject.Config[meta.KeyV2CloudIdentity]),
			DockerAutostart: strings.TrimSpace(incusProject.Config[meta.KeyV2DockerAutostart]) == "true",
			Domain:          strings.TrimSpace(incusProject.Config[meta.KeyV2Domain]),
			Image:           strings.TrimSpace(incusProject.Config[meta.KeyV2Image]),
		})
	}
	summaries := make([]Summary, 0, len(order))
	for _, infraName := range order {
		summary := byInfra[infraName]
		sort.Slice(summary.Projects, func(i, j int) bool { return summary.Projects[i].Name < summary.Projects[j].Name })
		summaries = append(summaries, *summary)
	}
	return summaries
}

// IsMember reports whether userKey (normalized) is a Tenant Member of a
// Shared Tenant — granted Tenant Access without being the tenant's owner.
func (s Summary) IsMember(userKey string) bool {
	userKey = strings.ToLower(strings.TrimSpace(userKey))
	if userKey == "" {
		return false
	}
	for _, member := range s.Members {
		if member == userKey {
			return true
		}
	}
	return false
}

// Accessible reports whether userKey holds Tenant Access: a Personal Tenant
// belongs to the user whose key names it, and a Shared Tenant admits its
// Tenant Members. This is THE access rule the Auth App applies to every
// tenant-plane request and to `sc tenant list`/`switch`.
func (s Summary) Accessible(userKey string) bool {
	userKey = strings.ToLower(strings.TrimSpace(userKey))
	if userKey == "" {
		return false
	}
	return s.Tenant == userKey || s.IsMember(userKey)
}

// ProjectShortNames lists the tenant's app project short names, sorted.
func (s Summary) ProjectShortNames() []string {
	names := make([]string, 0, len(s.Projects))
	for _, project := range s.Projects {
		if name := strings.TrimSpace(project.Name); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// V2IncusProjectName maps a v2 tenant summary and a short project name to the
// full Incus project name, reusing the prefix baked into the summary's
// InfraProject (<prefix>-<tenant>).
func (s Summary) V2IncusProjectName(project string) string {
	project = strings.TrimSpace(project)
	if project == "" {
		project = naming.DefaultProjectName
	}
	return s.InfraProject + "-" + project
}

// AllocatedCIDRs returns every tenant private CIDR currently allocated on the
// host, spanning BOTH v1 tenants (kind=tenant, CIDR in tenant metadata) and v2
// tenants (kind=infra, CIDR in the v2 metadata key). The CIDR allocator feeds
// this in as OccupiedCIDRs so a new tenant never reuses a /24 whose bridge
// already exists — OccupiedCIDRs(List(...)) alone misses v2 tenants, since List
// only surfaces kind=tenant projects.
func AllocatedCIDRs(ctx context.Context, store IncusTenantStore) ([]string, error) {
	_, all, err := CIDRAllocationInputs(ctx, store, "")
	return all, err
}

// CIDRAllocationInputs scans all managed projects and splits allocated CIDRs
// into the target tenant's OWN /24 (empty if it doesn't exist yet) and every
// OTHER tenant's /24. Create uses `own` as PreferredCIDR (so re-provisioning is
// idempotent) and `others` as OccupiedCIDRs (so a fresh tenant avoids
// collisions). Covers both v1 (kind=tenant) and v2 (kind=infra) tenants.
// ProvisionReuse is what an idempotent re-provision must carry over from live
// state: the tenant's own /24 and Tenant DNS Suffix (immutable, ADR-0018), the
// stored default-project short name, the stored login unix user + SSH key
// (#134 — a re-run without explicit flags must NOT clobber them back to
// defaults), and the other tenants' CIDRs the allocator must avoid.
type ProvisionReuse struct {
	OwnCIDR        string
	DNSSuffix      string
	DefaultProject string
	UnixUser       string
	SSHPublicKey   string
	// Members are the tenant's stored Tenant Members (meta.KeyV2Members).
	Members       []string
	OccupiedCIDRs []string
	// Projects is the tenant's EXISTING app projects (full Incus names,
	// <prefix>-<tenant>-<short>), sorted. A re-login's enrollment token must be
	// scoped to ALL of them, not just the default project — otherwise a fresh
	// client certificate only ever sees the default project, while older
	// certificates were extended project-by-project as each was created.
	Projects []string
}

// ProvisionReuseInputs gathers a ProvisionReuse from live Incus state. "Own"
// is scoped to the INSTALLATION prefix: several sandcastles share one Incus
// host (--prefix), and another install's same-named tenant is a foreign
// tenant, not this one — its CIDR is occupied, its stored settings irrelevant.
func ProvisionReuseInputs(ctx context.Context, store IncusTenantStore, installPrefix string, tenantName string) (ProvisionReuse, error) {
	projects, err := store.ListProjects(ctx)
	if err != nil {
		return ProvisionReuse{}, err
	}
	tenantName = strings.TrimSpace(tenantName)
	installPrefix = strings.TrimSpace(installPrefix)
	if installPrefix == "" || installPrefix == naming.DefaultIncusProjectPrefix {
		installPrefix = naming.V2IncusProjectPrefix
	}
	var reuse ProvisionReuse
	for _, incusProject := range projects {
		if !meta.IsManaged(incusProject.Config) {
			continue
		}
		var cidr string
		own := false
		switch incusProject.Config[meta.KeyKind] {
		case meta.KindV2Project:
			// The tenant's own app projects: collect their full Incus names so a
			// re-provision can scope the enrollment token to every one of them.
			// Ownership follows the same name anatomy v2Summaries parses:
			// <prefix>-<tenant>-<short>.
			owner := strings.TrimSpace(incusProject.Config[meta.KeyTenant])
			if tenantName == "" || owner != tenantName {
				continue
			}
			marker := "-" + tenantName + "-"
			idx := strings.Index(incusProject.Name, marker)
			if idx <= 0 || incusProject.Name[idx+len(marker):] == "" {
				continue
			}
			if incusProject.Name[:idx] != installPrefix {
				continue
			}
			reuse.Projects = append(reuse.Projects, incusProject.Name)
			continue
		case legacyTenantKind:
			// v1 is removed and nothing creates kind=tenant projects any more,
			// but a host upgraded from it can still carry orphaned ones whose
			// bridge (and its dnsmasq on the gateway IP) is live. Their /24 stays
			// OCCUPIED so the allocator never re-picks it — reusing one dies with
			// "dnsmasq: Address already in use" at bridge creation. Read the raw
			// key: no v1 metadata parsing. Never "own".
			cidr = strings.TrimSpace(incusProject.Config[meta.KeyPrivateCIDR])
		case meta.KindInfra:
			cidr = strings.TrimSpace(incusProject.Config[meta.KeyV2CIDR])
			owner := strings.TrimSpace(incusProject.Config[meta.KeyTenant])
			projectPrefix := strings.TrimSpace(incusProject.Config[meta.KeyV2Prefix])
			if projectPrefix == "" {
				projectPrefix = naming.V2IncusProjectPrefix
			}
			own = tenantName != "" && owner == tenantName && projectPrefix == installPrefix
			if own {
				reuse.DNSSuffix = strings.TrimSpace(incusProject.Config[meta.KeyV2Suffix])
				reuse.DefaultProject = strings.TrimSpace(incusProject.Config[meta.KeyV2DefaultProject])
				reuse.UnixUser = strings.TrimSpace(incusProject.Config[meta.KeyV2User])
				reuse.SSHPublicKey = strings.TrimSpace(incusProject.Config[meta.KeyV2SSHKey])
				reuse.Members = meta.ParseMembers(incusProject.Config[meta.KeyV2Members])
			}
		default:
			continue
		}
		if cidr == "" {
			continue
		}
		if own {
			reuse.OwnCIDR = cidr
		} else {
			reuse.OccupiedCIDRs = append(reuse.OccupiedCIDRs, cidr)
		}
	}
	sort.Strings(reuse.Projects)
	return reuse, nil
}

func CIDRAllocationInputs(ctx context.Context, store IncusTenantStore, tenantName string) (own string, others []string, err error) {
	projects, err := store.ListProjects(ctx)
	if err != nil {
		return "", nil, err
	}
	tenantName = strings.TrimSpace(tenantName)
	for _, incusProject := range projects {
		if !meta.IsManaged(incusProject.Config) {
			continue
		}
		var cidr, owner string
		switch incusProject.Config[meta.KeyKind] {
		case legacyTenantKind:
			// See CIDRAllocationInputs: an orphaned v1 project's /24 is still
			// allocated on this host even though v1 itself is gone.
			cidr = strings.TrimSpace(incusProject.Config[meta.KeyPrivateCIDR])
			owner = strings.TrimSpace(incusProject.Config[meta.KeyTenant])
		case meta.KindInfra:
			cidr = strings.TrimSpace(incusProject.Config[meta.KeyV2CIDR])
			owner = strings.TrimSpace(incusProject.Config[meta.KeyTenant])
		default:
			continue
		}
		if cidr == "" {
			continue
		}
		if tenantName != "" && owner == tenantName {
			own = cidr
		} else {
			others = append(others, cidr)
		}
	}
	return own, others, nil
}

func OccupiedCIDRs(tenants []Summary) []string {
	cidrs := make([]string, 0, len(tenants))
	for _, summary := range tenants {
		if summary.PrivateCIDR != "" {
			cidrs = append(cidrs, summary.PrivateCIDR)
		}
	}
	return cidrs
}

func dnsAddressFromCIDR(privateCIDR string) string {
	prefix, err := netip.ParsePrefix(privateCIDR)
	if err != nil {
		return ""
	}
	addr, err := cidr.RoleAddress(prefix, cidr.DNSHostOctet)
	if err != nil {
		return ""
	}
	return addr.String()
}

type MemoryStore struct {
	Projects []IncusProject
}

func (s MemoryStore) ListProjects(ctx context.Context) ([]IncusProject, error) {
	return s.Projects, nil
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// legacyTenantKind is the metadata kind of a pre-v2 ("v1") Incus project. v1 is
// removed and nothing constructs these, but an upgraded host can still carry
// orphaned ones with live bridges, so the CIDR allocator must keep treating
// their /24 as occupied.
const legacyTenantKind = "tenant"
