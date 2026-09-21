package incusx

import (
	"context"
	"fmt"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// CreateProjectV2Result reports the Incus project created for a v2 tenant
// project, plus the shared settings inherited from the tenant's infra project.
type CreateProjectV2Result struct {
	Tenant       string `json:"tenant"`
	Project      string `json:"project"`
	IncusProject string `json:"incusProject"`
	Bridge       string `json:"bridge"`
	DNSSuffix    string `json:"dnsSuffix"`
}

// CreateProjectV2 creates a new app Incus project (sc2-<tenant>-<project>) for
// an existing v2 tenant, wiring it to the shared bridge and installing the
// tenant's default profile (shared-bridge NIC + cloud-init login). It reads the
// tenant's shared settings from the infra project metadata, so the caller only
// supplies tenant + project names. This is the scaffolding the Sandcastle Broker
// performs on a tenant's `sc project create` (ADR-0016); it does not itself
// extend the tenant's restricted cert (the broker/admin layer does that).
func (c TenantCreator) CreateProjectV2(ctx context.Context, installPrefix string, tenantName string, project string) (CreateProjectV2Result, error) {
	return c.CreateProjectV2WithDomain(ctx, installPrefix, tenantName, project, "")
}

// CreateProjectV2WithDomain is CreateProjectV2 for a project with a Project
// Domain (ADR-0027): KeyV2Domain is set in the same project-create request
// and the default profile is rendered in zone mode. The caller (the Auth App)
// has already claimed the domain; this never validates it. domain == "" is a
// plain private project.
func (c TenantCreator) CreateProjectV2WithDomain(ctx context.Context, installPrefix string, tenantName string, project string, domain string) (CreateProjectV2Result, error) {
	domain = strings.TrimSpace(domain)
	if err := naming.ValidateTenantName(tenantName); err != nil {
		return CreateProjectV2Result{}, err
	}
	if err := naming.ValidateNewProjectName(project); err != nil {
		return CreateProjectV2Result{}, err
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return CreateProjectV2Result{}, err
	}
	installPrefix = strings.TrimSpace(installPrefix)
	if installPrefix == "" || installPrefix == naming.DefaultIncusProjectPrefix {
		installPrefix = naming.V2IncusProjectPrefix
	}
	infraProject, err := naming.V2TenantInfraProjectName(installPrefix, tenantName)
	if err != nil {
		return CreateProjectV2Result{}, err
	}
	infra, _, err := server.GetProject(infraProject)
	if err != nil {
		return CreateProjectV2Result{}, fmt.Errorf("tenant %q infra project %s not found: %w", tenantName, infraProject, err)
	}
	cfg := infra.Config
	prefix := cfg[keyV2Prefix]
	if prefix == "" {
		prefix = naming.V2IncusProjectPrefix
	}
	incusProject, err := naming.V2ProjectName(prefix, tenantName, project)
	if err != nil {
		return CreateProjectV2Result{}, err
	}

	extra := map[string]string{meta.KeyV2Suffix: cfg[keyV2Suffix]}
	if domain != "" {
		extra[meta.KeyV2Domain] = domain
	}
	c.log("ensure app project " + incusProject)
	if err := ensureV2Project(server, incusProject, "Sandcastle v2 project "+project+" for "+tenantName, "project", tenantName, true, extra); err != nil {
		return CreateProjectV2Result{}, err
	}
	// The sidecar address must be derived from the tenant CIDR. Omitting it
	// rendered the machine Caddy's signer URL as "http://:9443", so every machine
	// in a project created after the tenant served no HTTPS at all.
	dnsAddress, err := tenant.DNSAddressForCIDR(cfg[keyV2CIDR])
	if err != nil {
		return CreateProjectV2Result{}, fmt.Errorf("tenant %q: %w", tenantName, err)
	}
	profilePlan := tenant.CreatePlanV2{
		Tenant:             tenantName,
		DefaultProject:     incusProject,
		Bridge:             cfg[keyV2Bridge],
		StoragePool:        cfg[keyV2Pool],
		DefaultProfileUser: cfg[keyV2User],
		SSHPublicKey:       tenantV2AuthorizedKeys(server, prefix, cfg),
		DNSSuffix:          cfg[keyV2Suffix],
		DNSAddress:         dnsAddress,
		ProjectDomain:      domain,
		SCVolumes:          tenant.V2SCVolumes(),
	}
	if profilePlan.DefaultProfileUser == "" {
		profilePlan.DefaultProfileUser = tenant.DefaultV2UnixUser
	}
	// The profile below references the project's shared volumes, so they must
	// exist first (previously only tenant create made them — a fresh app
	// project's profile pointed at volumes that were never created).
	c.log("ensure shared /workspace + /home volumes in " + incusProject)
	if err := ensureV2ProjectVolumes(server.UseProject(incusProject), profilePlan.StoragePool, tenantName, server.SupportsIdmappedMounts()); err != nil {
		return CreateProjectV2Result{}, err
	}
	c.log("ensure /.sc platform payload in " + incusProject)
	if _, err := ensureV2PlatformPayload(server.UseProject(incusProject), profilePlan.StoragePool); err != nil {
		return CreateProjectV2Result{}, err
	}
	c.log("ensure default + homeshare profiles " + incusProject)
	if err := ensureV2AppProfiles(server.UseProject(incusProject), profilePlan, project, c.log); err != nil {
		return CreateProjectV2Result{}, err
	}
	return CreateProjectV2Result{
		Tenant:       tenantName,
		Project:      project,
		IncusProject: incusProject,
		Bridge:       cfg[keyV2Bridge],
		DNSSuffix:    cfg[keyV2Suffix],
	}, nil
}
