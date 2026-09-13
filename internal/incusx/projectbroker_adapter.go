package incusx

import (
	"context"
	"fmt"
	"strings"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

// ProjectBrokerCreator implements projectbroker.ProjectCreator: it performs the
// privileged v2 project scaffolding (CreateProjectV2) and extends the tenant's
// restricted certificate to include the new project so the tenant's native
// incus client can immediately use it.
type ProjectBrokerCreator struct {
	Creator TenantCreator
	Trust   usertrust.Manager
	// Prefix is the installation prefix this broker/auth-app serves; it scopes
	// the infra-project lookup and the certificate/remote names so several
	// sandcastles can share one Incus host.
	Prefix string
	// Deleter backs DeleteTenantProject (the tenant-plane DELETE
	// /api/projects/{name}, ADR-0027); nil means deletion is unavailable.
	Deleter *TenantDeleter
}

func (p ProjectBrokerCreator) CreateTenantProject(ctx context.Context, tenant string, project string, clientCertificatePEM string) (projectbroker.ProjectResult, error) {
	return p.CreateTenantProjectWithDomain(ctx, tenant, project, clientCertificatePEM, "")
}

// CreateTenantProjectWithDomain implements authapp.TenantProjectDomainManager:
// CreateTenantProject with KeyV2Domain stamped in the same project-create
// request (domain == "" is a private project).
func (p ProjectBrokerCreator) CreateTenantProjectWithDomain(ctx context.Context, tenant string, project string, clientCertificatePEM string, domain string) (projectbroker.ProjectResult, error) {
	res, err := p.Creator.CreateProjectV2WithDomain(ctx, p.Prefix, tenant, project, domain)
	if err != nil {
		return projectbroker.ProjectResult{}, err
	}
	if p.Trust != nil {
		plan := usertrust.UserPlan{
			User:            tenant,
			CertificateName: usertrust.RestrictedInstallName(p.Prefix, tenant),
			RemoteName:      usertrust.RemoteInstallName(p.Prefix, tenant),
			Restricted:      true,
			Projects:        []string{res.IncusProject},
			Description:     "Sandcastle v2 tenant " + tenant,
		}
		// The tenant's project namespace root (`<prefix>-<tenant>`), from the
		// canonical naming home. Prefix defaulting mirrors PlanDeleteV2.
		prefix := strings.TrimSpace(p.Prefix)
		if prefix == "" || prefix == naming.DefaultIncusProjectPrefix {
			prefix = naming.V2IncusProjectPrefix
		}
		tenantNamespace, err := naming.V2TenantInfraProjectName(prefix, tenant)
		if err != nil {
			return projectbroker.ProjectResult{}, fmt.Errorf("derive tenant namespace: %w", err)
		}
		if err := extendTenantCertificate(ctx, p.Trust, plan, clientCertificatePEM, tenantNamespace); err != nil {
			return projectbroker.ProjectResult{}, fmt.Errorf("extend tenant certificate for %s: %w", res.IncusProject, err)
		}
	}
	return projectbroker.ProjectResult{
		Tenant:       res.Tenant,
		Project:      res.Project,
		IncusProject: res.IncusProject,
		Bridge:       res.Bridge,
		DNSSuffix:    res.DNSSuffix,
		Domain:       strings.TrimSpace(domain),
	}, nil
}

// SetProjectDomain implements authapp.TenantProjectDomainManager.
func (p ProjectBrokerCreator) SetProjectDomain(ctx context.Context, tenant string, project string, domain string) error {
	return p.Creator.SetProjectDomainV2(ctx, p.Prefix, tenant, project, domain)
}

// SetMachinePublicHostnames implements authapp.TenantProjectDomainManager
// (ADR-0028): the machine's public-name list on its own instance config.
func (p ProjectBrokerCreator) SetMachinePublicHostnames(ctx context.Context, tenant string, project string, machine string, hostnames []string) error {
	return p.Creator.SetMachinePublicHostnamesV2(ctx, p.Prefix, tenant, project, machine, hostnames)
}

// DeleteTenantProject implements authapp.TenantProjectDomainManager: the app
// project goes with its machines, volumes and profiles (DeleteProjectV2). The
// storage pool is read off the tenant's infra project, like every other
// shared setting.
func (p ProjectBrokerCreator) DeleteTenantProject(ctx context.Context, tenant string, project string) error {
	if p.Deleter == nil {
		return fmt.Errorf("project deletion is not configured")
	}
	incusProject, cfg, err := p.Creator.v2AppProject(p.Prefix, tenant, project)
	if err != nil {
		return err
	}
	return p.Deleter.DeleteProjectV2(ctx, incusProject, cfg[keyV2Pool])
}

// extendTenantCertificate grants plan.Projects to the tenant's restricted
// certificate(s). FINGERPRINT-FIRST (#115): when the caller's certificate is
// recorded, extend exactly that entry (EnsureClientCertificate) — a name-based
// grant extends EVERY entry sharing the name, silently re-arming dead keypairs
// whose tenant/project names recurred. The tenant's other live devices (same
// name, already holding a tenant project) are then synced via GrantTenantFleet.
// The name-based Grant remains only as the legacy path: no recorded
// certificate (a login predating cacd832), or a stale record the daemon no
// longer trusts. It also covers shared client identity — an entry named after
// another tenant is reached by fingerprint even though the name would miss.
func extendTenantCertificate(ctx context.Context, trust usertrust.Manager, plan usertrust.UserPlan, clientCertificatePEM string, tenantNamespace string) error {
	if pem := strings.TrimSpace(clientCertificatePEM); pem != "" {
		ensurer, ok := trust.(interface {
			EnsureClientCertificate(context.Context, string, usertrust.UserPlan) (bool, error)
		})
		if ok {
			found, err := ensurer.EnsureClientCertificate(ctx, pem, plan)
			if err != nil {
				return err
			}
			if found {
				if fleet, ok := trust.(interface {
					GrantTenantFleet(context.Context, usertrust.UserPlan, string) error
				}); ok {
					return fleet.GrantTenantFleet(ctx, plan, tenantNamespace)
				}
				return nil
			}
		}
	}
	return trust.Grant(ctx, plan)
}

// TenantProvisionerAdapter implements projectbroker.TenantProvisioner: the
// broker's admin plane drives the full v2 tenant bring-up + mints the
// enrollment token, using the admin Incus credentials the broker holds.
type TenantProvisionerAdapter struct {
	Creator      TenantCreator
	Trust        usertrust.Manager
	Admin        config.Admin
	SidecarImage string
	// Tenants lists existing tenants so the CIDR allocator skips /24s already in
	// use; without it the allocator always returns the pool's first /24 and every
	// tenant after the first collides on its bridge gateway.
	Tenants tenant.IncusTenantStore
}

func (a TenantProvisionerAdapter) CreateTenant(ctx context.Context, req projectbroker.TenantRequest) (projectbroker.TenantResult, error) {
	var reuse tenant.ProvisionReuse
	if a.Tenants != nil {
		var err error
		reuse, err = tenant.ProvisionReuseInputs(ctx, a.Tenants, a.Admin.IncusProjectPrefix, req.Tenant)
		if err != nil {
			return projectbroker.TenantResult{}, fmt.Errorf("list allocated CIDRs: %w", err)
		}
	}
	plan, err := tenant.PlanCreateV2(a.Admin, tenant.CreateRequest{
		Reference:              req.Tenant,
		SSHPublicKey:           req.SSHPublicKey,
		OccupiedCIDRs:          reuse.OccupiedCIDRs,
		PreferredCIDR:          reuse.OwnCIDR,
		DNSSuffix:              req.DNSSuffix,
		ExistingDNSSuffix:      reuse.DNSSuffix,
		ExistingDefaultProject: reuse.DefaultProject,
		ExistingUnixUser:       reuse.UnixUser,
		ExistingSSHKey:         reuse.SSHPublicKey,
		ExistingProjects:       reuse.Projects,
	})
	if err != nil {
		return projectbroker.TenantResult{}, err
	}
	var tailscaleLoginURL string
	if err := a.Creator.CreateTenantV2(ctx, plan, CreateV2Options{
		TailscaleAuthKey:    req.TailscaleAuthKey,
		SidecarImage:        a.SidecarImage,
		OnTailscaleLoginURL: func(u string) { tailscaleLoginURL = u },
	}); err != nil {
		return projectbroker.TenantResult{}, err
	}
	result := projectbroker.TenantResult{
		Tenant:            plan.Tenant,
		InfraProject:      plan.InfraProject,
		DefaultProject:    plan.DefaultProject,
		Bridge:            plan.Bridge,
		DNSSuffix:         plan.DNSSuffix,
		TailscaleLoginURL: tailscaleLoginURL,
	}
	if a.Trust != nil {
		tok, err := a.Trust.CreateToken(ctx, usertrust.UserPlan{
			User:            plan.Tenant,
			CertificateName: usertrust.RestrictedInstallName(plan.Prefix, plan.Tenant),
			RemoteName:      usertrust.RemoteInstallName(plan.Prefix, plan.Tenant),
			Restricted:      true,
			Projects:        plan.RestrictedProjects,
			Description:     "Sandcastle v2 tenant " + plan.Tenant,
		})
		if err != nil {
			return projectbroker.TenantResult{}, fmt.Errorf("mint enrollment token: %w", err)
		}
		result.Token = tok.Token
		result.RemoteName = tok.RemoteName
	}
	return result, nil
}

// AdminAuthorizer implements projectbroker.AdminAuthorizer by treating any
// trusted, unrestricted client certificate on the Incus server as an admin.
type AdminAuthorizer struct {
	Remote     string
	ConfigPath string
	Server     RouteBrokerTrustServer
}

func NewAdminAuthorizer(remote string) AdminAuthorizer {
	return AdminAuthorizer{Remote: remote}
}

func (a AdminAuthorizer) IsAdmin(ctx context.Context, fingerprint string) (bool, error) {
	server := a.Server
	if server == nil {
		loaded, err := LoadCLIConfig(a.ConfigPath)
		if err != nil {
			return false, fmt.Errorf("load Incus config: %w", err)
		}
		remote := a.Remote
		if remote == "" {
			remote = loaded.DefaultRemote
		}
		instanceServer, err := connectInstanceServer(loaded, remote)
		if err != nil {
			return false, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
		}
		server = instanceServer
	}
	certificates, err := server.GetCertificates()
	if err != nil {
		return false, fmt.Errorf("list Incus certificates: %w", err)
	}
	want := normalizeFingerprint(fingerprint)
	for _, c := range certificates {
		if normalizeFingerprint(c.Fingerprint) != want {
			continue
		}
		return c.Type == api.CertificateTypeClient && !c.Restricted, nil
	}
	return false, nil
}
