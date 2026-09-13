package incusx

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Project Domain operations on an app project (ADR-0027 §3.2/§5.1). The Auth
// App calls these only AFTER the claim row is committed: KeyV2Domain on the
// Incus project is the operational setting, never the reservation.

// v2AppProject resolves a tenant's app project name and returns the infra
// project's shared settings. A missing app project is reported by wrapping
// projectbroker.ErrProjectNotFound so the Auth App can answer 404.
func (c TenantCreator) v2AppProject(installPrefix string, tenantName string, project string) (string, map[string]string, error) {
	if err := naming.ValidateTenantName(tenantName); err != nil {
		return "", nil, err
	}
	if err := naming.ValidateProjectName(project); err != nil {
		return "", nil, err
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return "", nil, err
	}
	installPrefix = strings.TrimSpace(installPrefix)
	if installPrefix == "" || installPrefix == naming.DefaultIncusProjectPrefix {
		installPrefix = naming.V2IncusProjectPrefix
	}
	infraProject, err := naming.V2TenantInfraProjectName(installPrefix, tenantName)
	if err != nil {
		return "", nil, err
	}
	infra, _, err := server.GetProject(infraProject)
	if err != nil {
		return "", nil, fmt.Errorf("tenant %q infra project %s not found: %w", tenantName, infraProject, err)
	}
	cfg := map[string]string{}
	for k, v := range infra.Config {
		cfg[k] = v
	}
	prefix := cfg[keyV2Prefix]
	if prefix == "" {
		prefix = naming.V2IncusProjectPrefix
	}
	incusProject, err := naming.V2ProjectName(prefix, tenantName, project)
	if err != nil {
		return "", nil, err
	}
	if _, _, err := server.GetProject(incusProject); err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return "", nil, fmt.Errorf("%w: %s/%s", projectbroker.ErrProjectNotFound, tenantName, project)
		}
		return "", nil, fmt.Errorf("project %s: %w", incusProject, err)
	}
	return incusProject, cfg, nil
}

// SetProjectDomainV2 writes (domain != "") or removes (domain == "")
// KeyV2Domain on the app project, then re-renders its default profile so
// Machines created from now on boot in the project's Naming Mode (§5.1).
// Existing Machines never re-run cloud-init, so they keep their machine.env —
// consistent with Naming Mode being fixed at creation.
func (c TenantCreator) SetProjectDomainV2(_ context.Context, installPrefix string, tenantName string, project string, domain string) error {
	domain = strings.TrimSpace(domain)
	incusProject, cfg, err := c.v2AppProject(installPrefix, tenantName, project)
	if err != nil {
		return err
	}
	if err := c.updateProjectConfig(incusProject, meta.KeyV2Domain, domain); err != nil {
		return err
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	dnsAddress, err := tenant.DNSAddressForCIDR(cfg[keyV2CIDR])
	if err != nil {
		return fmt.Errorf("tenant %q: %w", tenantName, err)
	}
	plan := tenant.CreatePlanV2{
		Tenant:             tenantName,
		DefaultProject:     incusProject,
		Bridge:             cfg[keyV2Bridge],
		StoragePool:        cfg[keyV2Pool],
		DefaultProfileUser: cfg[keyV2User],
		SSHPublicKey:       cfg[keyV2SSHKey],
		DNSSuffix:          cfg[keyV2Suffix],
		DNSAddress:         dnsAddress,
		ProjectDomain:      domain,
	}
	if plan.DefaultProfileUser == "" {
		plan.DefaultProfileUser = tenant.DefaultV2UnixUser
	}
	c.log("re-render default + homeshare profiles of " + incusProject + " (project domain: " + orNone(domain) + ")")
	if err := ensureV2AppProfiles(server.UseProject(incusProject), plan, project, c.log); err != nil {
		return fmt.Errorf("update profiles of %s: %w", incusProject, err)
	}
	return nil
}

// ListZoneModeMachinesV2 names the app project's instances that carry a
// DERIVED Machine Public Hostname — a public name under the project's
// current Project Domain (read from either public-name key, ADR-0028). These
// are what block set-domain/unset-domain until slice 3 of #172 teaches the
// reconciler to re-derive names; explicit hostnames in a project without a
// domain never block, so `set-domain` stays possible for such a project.
func (c TenantCreator) ListZoneModeMachinesV2(_ context.Context, installPrefix string, tenantName string, project string) ([]string, error) {
	incusProject, _, err := c.v2AppProject(installPrefix, tenantName, project)
	if err != nil {
		return nil, err
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	appProject, _, err := server.GetProject(incusProject)
	if err != nil {
		return nil, fmt.Errorf("read project %s: %w", incusProject, err)
	}
	domain := ""
	if appProject != nil {
		domain = strings.ToLower(strings.TrimSpace(appProject.Config[meta.KeyV2Domain]))
	}
	if domain == "" {
		return nil, nil
	}
	scoped := server.UseProject(incusProject)
	names, err := scoped.GetInstanceNames(api.InstanceTypeAny)
	if err != nil {
		return nil, fmt.Errorf("list machines of %s: %w", incusProject, err)
	}
	var zoneMode []string
	for _, name := range names {
		instance, _, err := scoped.GetInstance(name)
		if err != nil {
			return nil, fmt.Errorf("read machine %s in %s: %w", name, incusProject, err)
		}
		if instance == nil {
			continue
		}
		for _, hostname := range meta.PublicHostnamesFromConfig(instance.Config) {
			if strings.HasSuffix(hostname, "."+domain) {
				zoneMode = append(zoneMode, name)
				break
			}
		}
	}
	return zoneMode, nil
}

// SetMachinePublicHostnamesV2 rewrites a machine's KeyV2PublicHostnames list
// (ADR-0028) on its own instance config; an empty set deletes the key. A
// missing machine wraps authapp.ErrMachineNotFound so the hostnames API can
// answer 404 and release the reservation again.
func (c TenantCreator) SetMachinePublicHostnamesV2(_ context.Context, installPrefix string, tenantName string, project string, machine string, hostnames []string) error {
	if err := naming.ValidateMachineName(machine); err != nil {
		return err
	}
	incusProject, _, err := c.v2AppProject(installPrefix, tenantName, project)
	if err != nil {
		return err
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	scoped := server.UseProject(incusProject)
	if _, _, err := scoped.GetInstance(machine); err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return fmt.Errorf("%w: %s/%s:%s", authapp.ErrMachineNotFound, tenantName, project, machine)
		}
		return fmt.Errorf("read machine %s in %s: %w", machine, incusProject, err)
	}
	value := meta.FormatPublicHostnames(hostnames)
	c.log("stamp " + meta.KeyV2PublicHostnames + "=" + orNone(value) + " on " + incusProject + "/" + machine)
	return stampInstanceConfig(scoped, machine, map[string]string{meta.KeyV2PublicHostnames: value})
}

func orNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(none)"
	}
	return value
}
