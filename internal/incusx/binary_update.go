package incusx

import (
	"fmt"
	"os"
	"sort"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/update"
)

// SandcastleBinaryPath is where the fat binary lives inside every appliance
// and sidecar (deployed as sandcastle-admin).
const SandcastleBinaryPath = "/usr/local/bin/sandcastle-admin"

// TLSSignUnit is the sidecar's leaf-signer service — the only unit a sidecar
// update restarts (sub-second; CoreDNS/tailscaled untouched, #124 §5).
const TLSSignUnit = "sandcastle-tls-sign.service"

// ComponentVersion is one row of the fleet version table (#124 §4): a
// binary-carrying instance and the version stamped at its last binary push.
type ComponentVersion struct {
	Kind          string `json:"kind"` // auth-app | broker | sidecar
	Project       string `json:"project"`
	Instance      string `json:"instance"`
	Tenant        string `json:"tenant,omitempty"` // sidecars: owning tenant
	BinaryVersion string `json:"binaryVersion"`    // "" = unknown ⇒ outdated
	Status        string `json:"status"`           // Incus instance status
	Architecture  string `json:"architecture"`     // download-arch token (amd64/arm64)
	TenantManaged bool   `json:"tenantManaged"`    // sidecars: tenant updates via sc update
}

// ListBinaryVersions reads every binary-carrying component's stamp in one
// all-projects Incus listing — cheap, and it works for stopped instances.
func (c TenantCreator) ListBinaryVersions() ([]ComponentVersion, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	instances, err := server.GetInstancesFullAllProjects(api.InstanceTypeAny)
	if err != nil {
		return nil, fmt.Errorf("list instances across projects: %w", err)
	}
	return classifyComponents(instances), nil
}

// classifyComponents filters an all-projects instance listing down to the
// binary-carrying components, ordered auth-app, broker, then sidecars by
// tenant.
func classifyComponents(instances []api.InstanceFull) []ComponentVersion {
	rank := map[string]int{meta.KindAuthApp: 0, meta.KindBroker: 1, meta.KindSidecar: 2}
	var components []ComponentVersion
	for _, inst := range instances {
		kind := inst.Config[meta.KeyKind]
		if _, ok := rank[kind]; !ok {
			continue
		}
		components = append(components, ComponentVersion{
			Kind:          kind,
			Project:       inst.Project,
			Instance:      inst.Name,
			Tenant:        inst.Config[meta.KeyTenant],
			BinaryVersion: inst.Config[meta.KeyBinaryVersion],
			Status:        inst.Status,
			Architecture:  downloadArch(inst.Architecture),
			TenantManaged: kind == meta.KindSidecar,
		})
	}
	sort.SliceStable(components, func(i, j int) bool {
		if rank[components[i].Kind] != rank[components[j].Kind] {
			return rank[components[i].Kind] < rank[components[j].Kind]
		}
		if components[i].Tenant != components[j].Tenant {
			return components[i].Tenant < components[j].Tenant
		}
		return components[i].Project < components[j].Project
	})
	return components
}

// UpdateApplianceBinary replaces the sandcastle binary inside an existing
// appliance instance (auth-app or broker), restarts its service units, and
// stamps the new version. Idempotent — re-running repairs a partial update.
func (c TenantCreator) UpdateApplianceBinary(project, instance string, binary []byte, binaryVersion string, units ...string) error {
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	psrv := server.UseProject(project)
	if _, _, err := psrv.GetInstance(instance); err != nil {
		return fmt.Errorf("appliance %s/%s: %w", project, instance, err)
	}
	c.log("push binary into " + project + "/" + instance)
	if err := writeApplianceFile(psrv, instance, applianceFile{SandcastleBinaryPath, binary, 0o755}); err != nil {
		return fmt.Errorf("push binary into %s/%s: %w", project, instance, err)
	}
	if err := stampBinaryVersion(psrv, instance, binaryVersion); err != nil {
		return err
	}
	for _, unit := range units {
		c.log("restart " + unit + " in " + instance)
		if err := execSidecar(psrv, instance, restartUnitScript(unit)); err != nil {
			return fmt.Errorf("restart %s in %s/%s: %w", unit, project, instance, err)
		}
	}
	return nil
}

// restartUnitScript restarts a unit and verifies it came back active.
func restartUnitScript(unit string) string {
	return "systemctl restart " + unit + " && sleep 1 && systemctl is-active " + unit
}

// UpdateTenantSidecar pushes the given binary into the tenant's sidecar,
// restarts the TLS leaf signer, restores Incus Reach, verifies both operations,
// and stamps the version. Unlike the create path there is no "binary already
// exists" skip — updates push unconditionally (#124 §7).
func (c TenantCreator) UpdateTenantSidecar(prefix, tenantName string, binary []byte, binaryVersion string) (ComponentVersion, error) {
	infraProject, err := naming.V2TenantInfraProjectName(prefix, tenantName)
	if err != nil {
		return ComponentVersion{}, err
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return ComponentVersion{}, err
	}
	psrv := server.UseProject(infraProject)
	instance := naming.V2SidecarInstanceName
	if _, _, err := psrv.GetInstance(instance); err != nil {
		return ComponentVersion{}, fmt.Errorf("sidecar of tenant %s (%s/%s): %w", tenantName, infraProject, instance, err)
	}
	project, _, err := server.GetProject(infraProject)
	if err != nil {
		return ComponentVersion{}, fmt.Errorf("read tenant network for sidecar of %s: %w", tenantName, err)
	}
	privateCIDR := project.Config[meta.KeyV2CIDR]
	gateway, err := gatewayIPFromCIDR(privateCIDR)
	if err != nil {
		return ComponentVersion{}, fmt.Errorf("read tenant network for sidecar of %s: %w", tenantName, err)
	}
	c.log("push binary into sidecar " + infraProject + "/" + instance)
	if err := writeApplianceFile(psrv, instance, applianceFile{SandcastleBinaryPath, binary, 0o755}); err != nil {
		return ComponentVersion{}, fmt.Errorf("push binary into sidecar %s: %w", infraProject, err)
	}
	if err := stampBinaryVersion(psrv, instance, binaryVersion); err != nil {
		return ComponentVersion{}, err
	}
	c.log("restart " + TLSSignUnit)
	if err := execSidecar(psrv, instance, restartUnitScript(TLSSignUnit)); err != nil {
		return ComponentVersion{}, fmt.Errorf("restart %s on sidecar of %s: %w", TLSSignUnit, tenantName, err)
	}
	c.log("ensure Incus Reach on sidecar " + infraProject + "/" + instance)
	if err := execSidecar(psrv, instance, "tailscale serve --bg --tcp=8443 tcp://"+gateway+":8443"); err != nil {
		return ComponentVersion{}, fmt.Errorf("ensure Incus Reach on sidecar of %s: %w", tenantName, err)
	}
	version := update.NormalizeTag(binaryVersion)
	return ComponentVersion{
		Kind:          meta.KindSidecar,
		Project:       infraProject,
		Instance:      instance,
		Tenant:        tenantName,
		BinaryVersion: version,
		Status:        "Running",
		TenantManaged: true,
	}, nil
}

// SidecarSelfUpdater implements the broker/auth-app side of the delegated
// tenant sidecar update (#124 §5): it pushes its OWN running binary
// (os.Executable) into the tenant's sidecar — so sidecars can never run
// ahead of the deployment, and no GitHub access is needed on this path.
type SidecarSelfUpdater struct {
	Creator TenantCreator
	Admin   config.Admin
}

// UpdateTenantSidecar satisfies projectbroker.SidecarUpdater (also used by
// the auth-app's token-authenticated variant).
func (u SidecarSelfUpdater) UpdateTenantSidecar(tenantName string) (projectbroker.SidecarUpdateResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return projectbroker.SidecarUpdateResult{}, fmt.Errorf("locate running binary: %w", err)
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		return projectbroker.SidecarUpdateResult{}, fmt.Errorf("read running binary: %w", err)
	}
	component, err := u.Creator.UpdateTenantSidecar(naming.NormalizeV2Prefix(u.Admin.IncusProjectPrefix), tenantName, binary, runningBinaryVersion)
	if err != nil {
		return projectbroker.SidecarUpdateResult{}, err
	}
	return projectbroker.SidecarUpdateResult{
		Tenant:        component.Tenant,
		Project:       component.Project,
		Instance:      component.Instance,
		BinaryVersion: component.BinaryVersion,
	}, nil
}

// downloadArch maps an Incus instance architecture to the release-asset
// arch token ("" when unknown — the caller falls back to the host arch).
func downloadArch(incusArch string) string {
	switch incusArch {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return ""
	}
}
