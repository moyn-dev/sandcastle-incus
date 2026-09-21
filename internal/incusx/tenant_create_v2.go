package incusx

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// CreateV2Options carries per-run inputs that must not live in the persisted
// plan — chiefly the tenant's Tailscale auth key (a secret) and the sidecar
// image override (must be a *system-container* base image; the raw OCI base
// launches as an application container with no systemd).
type CreateV2Options struct {
	TailscaleAuthKey string
	SidecarImage     string
	// OnTailscaleLoginURL, when set, is invoked with the sidecar's interactive
	// `tailscale up` login URL when no auth key was supplied. The caller shows it
	// to the user, who visits it to register the sidecar into their tailnet.
	OnTailscaleLoginURL func(url string)
	// OnSidecarTailnetIP, when set, is invoked with the sidecar's tailnet IPv4
	// once it joins (auth-key path only). The client's Incus remote is pointed at
	// this address:8443 — the sidecar proxies it to the host's Incus (ADR-0017).
	OnSidecarTailnetIP func(ip string)
	// SidecarTailnetHostname overrides the sidecar's tailnet device hostname.
	// The Incus instance is a plain "sidecar" (unique only within the tenant's
	// infra project), but its tailnet name lives in a global namespace and must
	// be unique across every tenant and install — the auth-app supplies the
	// install-scoped name (sc-<install>-<tenant>). Empty falls back to the infra
	// project name, preserving the pre-rename behavior for callers that don't set it.
	SidecarTailnetHostname string
}

// CreateTenantV2 executes a CreatePlanV2 against Incus, reproducing the v2 MVP
// topology proven manually on `big` (see PROGRESS.md): a shared per-tenant
// bridge in the default project, an infra project holding one sidecar
// (CoreDNS + Tailscale subnet-router), and a seeded default app project whose
// default profile carries the shared bridge NIC + cloud-init login.
func (c TenantCreator) CreateTenantV2(ctx context.Context, plan tenant.CreatePlanV2, opts CreateV2Options) error {
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	sidecarImage := strings.TrimSpace(opts.SidecarImage)
	if sidecarImage == "" {
		sidecarImage = plan.SidecarImage
	}

	// The tailnet-egress toggle lives on the infra project (ADR-0026), written
	// only by `sc tailscale egress`; on a first create the project doesn't exist
	// yet, which reads as "off". Resolved before the bridge so one converge
	// applies both the DHCP option and the sidecar NAT consistently.
	egress := v2TailnetEgressEnabled(server, plan.InfraProject)
	c.log("ensure shared bridge " + plan.Bridge + " (in default, tailnet egress " + onOff(egress) + ")")
	if err := ensureV2Bridge(server, plan, egress); err != nil {
		return err
	}
	c.log("ensure infra project " + plan.InfraProject)
	if err := ensureV2Project(server, plan.InfraProject, "Sandcastle v2 infra for "+plan.Tenant, "infra", plan.Tenant, false, v2InfraMetadata(plan)); err != nil {
		return err
	}
	c.log("ensure app project " + plan.DefaultProject)
	if err := ensureV2Project(server, plan.DefaultProject, "Sandcastle v2 project default for "+plan.Tenant, "project", plan.Tenant, true, map[string]string{meta.KeyV2Suffix: plan.DNSSuffix}); err != nil {
		return err
	}
	shifted := server.SupportsIdmappedMounts()
	if !shifted {
		c.log("WARNING: this host's kernel offers no idmapped mounts (container-hosted incus?) — " +
			"the opt-in `homeshare` profile will not work across CT + VM (a VM sees the CT's shifted " +
			"owners on /home/<user> and sshd's StrictModes refuses key auth); /workspace stays shared. " +
			"Enable idmapped mounts (e.g. a zfs/btrfs storage pool) for a shared /home across CT + VM.")
	}
	c.log("ensure shared /workspace + /home volumes in " + plan.DefaultProject)
	if err := ensureV2ProjectVolumes(server.UseProject(plan.DefaultProject), plan.StoragePool, plan.Tenant, shifted); err != nil {
		return err
	}
	c.log("ensure /.sc platform payload in " + plan.DefaultProject)
	if _, err := ensureV2PlatformPayload(server.UseProject(plan.DefaultProject), plan.StoragePool); err != nil {
		return err
	}
	c.log("ensure default + homeshare profiles " + plan.DefaultProject)
	if err := ensureV2AppProfiles(server.UseProject(plan.DefaultProject), withTenantAuthorizedKeys(server, plan), plan.DefaultProjectShort, c.log); err != nil {
		return err
	}
	c.log("ensure sidecar profile")
	if err := ensureV2SidecarProfile(server.UseProject(plan.InfraProject), plan); err != nil {
		return err
	}
	c.log("launch sidecar " + plan.SidecarInstance + " (image " + sidecarImage + ")")
	if err := ensureV2Sidecar(server.UseProject(plan.InfraProject), plan, sidecarImage); err != nil {
		return err
	}
	c.log("install CoreDNS + Tailscale on sidecar (stock base image)")
	if err := installV2SidecarPackages(server.UseProject(plan.InfraProject), plan); err != nil {
		return err
	}
	c.log("configure sidecar network + CoreDNS")
	if err := configureV2Sidecar(server.UseProject(plan.InfraProject), plan); err != nil {
		return err
	}
	c.log("ensure sidecar tailnet egress " + onOff(egress))
	if err := ensureV2SidecarEgress(server.UseProject(plan.InfraProject), plan, egress); err != nil {
		return err
	}
	c.log("configure tenant TLS leaf signer")
	if err := configureV2TLSSigner(server.UseProject(plan.InfraProject), plan); err != nil {
		return err
	}
	// The sidecar's tailnet hostname must be globally unique (it is a tailnet
	// device name), so it carries the install+tenant identity even though the
	// Incus instance is a plain "sidecar". Fall back to the infra project name
	// (the pre-rename hostname) when the caller supplies none.
	tailnetHostname := strings.TrimSpace(opts.SidecarTailnetHostname)
	if tailnetHostname == "" {
		tailnetHostname = plan.InfraProject
	}
	c.log("tailscale up (advertise " + plan.PrivateCIDR + ", hostname " + tailnetHostname + ")")
	loginURL, sidecarIP, err := v2TailscaleUp(server.UseProject(plan.InfraProject), plan, tailnetHostname, strings.TrimSpace(opts.TailscaleAuthKey))
	if err != nil {
		return err
	}
	if loginURL != "" {
		c.log("tailscale: sidecar not on a tailnet yet — register it at " + loginURL)
		if opts.OnTailscaleLoginURL != nil {
			opts.OnTailscaleLoginURL(loginURL)
		}
	}
	if sidecarIP != "" {
		c.log("sidecar tailnet IP " + sidecarIP + " (Incus Reach)")
		if opts.OnSidecarTailnetIP != nil {
			opts.OnSidecarTailnetIP(sidecarIP)
		}
		// Route approval is the tenant's job, on the tenant's tailnet: approve
		// the advertised CIDR in the Tailscale admin console, or use a
		// tag:sandcastle autoApprovers ACL rule for zero-touch approval.
	}
	c.log("done")
	return nil
}

func (c TenantCreator) resolveV2Server() (TenantCreateServer, error) {
	if c.Server != nil {
		return c.Server, nil
	}
	loaded, err := LoadCLIConfig(c.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := c.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	instanceServer, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return sdkTenantCreateServer{inner: instanceServer}, nil
}

// ensureV2Bridge creates the shared per-tenant bridge in the default project.
// An existing bridge is converged onto the CoreDNS DHCP resolver option so
// pre-ADR-0018 tenants pick it up on their next idempotent re-provision.
func ensureV2Bridge(server TenantCreateServer, plan tenant.CreatePlanV2, egress bool) error {
	def := server.UseProject(naming.DefaultProjectName)
	// With egress on, guests additionally get a classless static route steering
	// the tailnet CGNAT range at the sidecar (ADR-0026). The exact-equality
	// converge below applies AND removes it on existing bridges; machines pick
	// the change up on their next DHCP renewal.
	wantDNSmasq := tenant.BridgeDHCPOptions(plan.DNSAddress, plan.GatewayAddress, egress)
	if bridge, etag, err := def.GetNetwork(plan.Bridge); err == nil {
		if bridge.Config["raw.dnsmasq"] == wantDNSmasq && bridge.Config["dns.mode"] == "none" {
			return nil
		}
		put := bridge.Writable()
		put.Config["raw.dnsmasq"] = wantDNSmasq
		// Disable the bridge's built-in managed DNS. It is already bypassed for
		// resolution (guests get the sidecar CoreDNS via dhcp-option=6), but while
		// left at its "managed" default it enforces per-network uniqueness of the
		// instance DNS name — and every project of a tenant shares this one bridge,
		// so two machines with the same name in different projects (e.g. h1:t1 and
		// h2:t1, distinct as t1.h1.<suffix> vs t1.h2.<suffix>) would collide with
		// "Instance DNS name already used on network". CoreDNS is the sole authority.
		put.Config["dns.mode"] = "none"
		if err := def.UpdateNetwork(plan.Bridge, put, etag); err != nil {
			return fmt.Errorf("update bridge %s DHCP resolver: %w", plan.Bridge, err)
		}
		return nil
	} else if !api.StatusErrorCheck(err, http.StatusNotFound) {
		return fmt.Errorf("get bridge %s: %w", plan.Bridge, err)
	}
	return def.CreateNetwork(api.NetworksPost{
		Name: plan.Bridge,
		Type: "bridge",
		NetworkPut: api.NetworkPut{
			Description: "Sandcastle v2 shared bridge for " + plan.Tenant,
			Config: api.ConfigMap{
				"ipv4.address": gatewayCIDR(plan.PrivateCIDR),
				"ipv4.nat":     "true",
				"ipv6.address": "none",
				"dns.domain":   plan.DNSSuffix,
				// The sidecar CoreDNS is the ONLY DNS authority for the suffix
				// (ADR-0018): hand it to guests as their DHCP resolver instead of
				// the bridge dnsmasq, whose lease names are guest-asserted and
				// cannot express the project label.
				"raw.dnsmasq": wantDNSmasq,
				// Disable the bridge's managed DNS entirely. All of a tenant's
				// projects share this one bridge, and managed DNS enforces
				// per-network uniqueness of the instance name — so h1:t1 and h2:t1
				// (distinct FQDNs t1.h1.<suffix> / t1.h2.<suffix>) would otherwise
				// collide on start with "Instance DNS name already used on network".
				"dns.mode":          "none",
				meta.KeyKind:        "network",
				meta.KeyTenant:      plan.Tenant,
				meta.KeyPrivateCIDR: plan.PrivateCIDR,
				meta.KeyVersion:     "2",
			},
		},
	})
}

// v2TailnetEgressEnabled reads the tenant's tailnet-egress toggle off the
// infra project (ADR-0026). The project may not exist yet (first create) or be
// unreadable — both read as "off": egress must fail closed.
func v2TailnetEgressEnabled(server TenantCreateServer, infraProject string) bool {
	project, _, err := server.GetProject(infraProject)
	if err != nil || project == nil {
		return false
	}
	return project.Config[meta.KeyV2TailnetEgress] == "true"
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

// V2 sidecar tailnet-egress artifacts (ADR-0026): a oneshot unit enabling
// forwarding and masquerading machine→tailnet traffic onto tailscale0, so
// tailnet peers see the sidecar's tailnet IP and need no --accept-routes.
const (
	sidecarEgressRulesPath  = "/etc/sandcastle-egress.nft"
	sidecarEgressScriptPath = "/usr/local/sbin/sandcastle-sidecar-egress"
	sidecarEgressUnitPath   = "/etc/systemd/system/sandcastle-sidecar-egress.service"
)

// ensureV2SidecarEgress converges the sidecar's egress NAT onto the toggle:
// enabled writes rules + script + unit and (re)starts the oneshot; disabled
// tears all of it down. Both directions are idempotent.
func ensureV2SidecarEgress(server TenantResourceServer, plan tenant.CreatePlanV2, egress bool) error {
	if !egress {
		script := strings.Join([]string{
			"systemctl disable --now sandcastle-sidecar-egress.service 2>/dev/null || true",
			"rm -f " + sidecarEgressUnitPath + " " + sidecarEgressScriptPath + " " + sidecarEgressRulesPath,
			"systemctl daemon-reload 2>/dev/null || true",
			// ip_forward stays on — the tailscaled subnet router needs it anyway.
			"nft delete table ip sandcastle-egress 2>/dev/null || true",
		}, "\n")
		if err := execSidecar(server, plan.SidecarInstance, script); err != nil {
			return fmt.Errorf("remove sidecar tailnet egress: %w", err)
		}
		return nil
	}
	files := []struct {
		path    string
		content string
		mode    int
	}{
		{sidecarEgressRulesPath, tenant.SidecarEgressNftRuleset(plan.PrivateCIDR), 0o644},
		{sidecarEgressScriptPath, tenant.SidecarEgressScript(), 0o755},
		{sidecarEgressUnitPath, tenant.SidecarEgressUnit(), 0o644},
	}
	for _, f := range files {
		if err := server.CreateInstanceFile(plan.SidecarInstance, f.path, incus.InstanceFileArgs{
			Content:   strings.NewReader(f.content),
			Type:      "file",
			Mode:      f.mode,
			WriteMode: "overwrite",
		}); err != nil {
			return fmt.Errorf("write %s to sidecar: %w", f.path, err)
		}
	}
	script := strings.Join([]string{
		"set -eu",
		"export DEBIAN_FRONTEND=noninteractive",
		// Stock Debian sidecars carry no nft; CoreDNS is live by now, so apt
		// resolves normally (unlike installV2SidecarPackages' bootstrap phase).
		"command -v nft >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq nftables; }",
		"systemctl daemon-reload",
		"systemctl enable sandcastle-sidecar-egress.service",
		// restart, not start: a converge with a changed CIDR must re-apply.
		"systemctl restart sandcastle-sidecar-egress.service",
		"systemctl is-active sandcastle-sidecar-egress.service",
	}, "\n")
	if err := execSidecar(server, plan.SidecarInstance, script); err != nil {
		return fmt.Errorf("enable sidecar tailnet egress: %w", err)
	}
	return nil
}

// EnsureApplianceBridge creates the per-install bridge the appliances
// (auth-app, broker) attach to, so an install owns its own network object
// instead of sharing incusbr0. It is NATed (appliances only need outbound —
// image pulls, cloudflared, tailscale; provisioning rides the mounted host
// socket, not L3), and its subnet is auto-picked by Incus (ipv4.address=auto)
// so it can't overlap the tenant pool, incusbr0, or another install's bridge.
// Idempotent: a bridge that already exists is left as-is. Tagged with the
// install prefix so teardown can find it.
func (c TenantCreator) EnsureApplianceBridge(ctx context.Context, name string, installPrefix string) error {
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	def := server.UseProject(naming.DefaultProjectName)
	if _, _, err := def.GetNetwork(name); err == nil {
		return nil
	} else if !api.StatusErrorCheck(err, http.StatusNotFound) {
		return fmt.Errorf("get appliance bridge %s: %w", name, err)
	}
	return def.CreateNetwork(api.NetworksPost{
		Name: name,
		Type: "bridge",
		NetworkPut: api.NetworkPut{
			Description: "Sandcastle appliance bridge for install " + installPrefix,
			Config: api.ConfigMap{
				"ipv4.address":   "auto",
				"ipv4.nat":       "true",
				"ipv6.address":   "none",
				meta.KeyKind:     "appliance-network",
				meta.KeyV2Prefix: installPrefix,
				meta.KeyVersion:  "2",
			},
		},
	})
}

// ensureV2Project creates an infra or app project that references the shared
// bridge via features.networks=false. Infra shares the default image store
// (features.images=false) to avoid copying the base; app projects keep their
// own image store so tenants can pull their own images.
// v2 infra-project metadata keys. The infra project is the durable record of a
// tenant's shared settings so a later project-create (broker) can rebuild an app
// project + profile without the operator re-supplying them.
const (
	keyV2Bridge         = "user.sandcastle.v2.bridge"
	keyV2Pool           = "user.sandcastle.v2.pool"
	keyV2Suffix         = meta.KeyV2Suffix
	keyV2CIDR           = "user.sandcastle.v2.cidr"
	keyV2User           = meta.KeyV2User
	keyV2SSHKey         = meta.KeyV2SSHKey
	keyV2Members        = meta.KeyV2Members
	keyV2Prefix         = meta.KeyV2Prefix
	keyV2DefaultProject = meta.KeyV2DefaultProject
)

func v2InfraMetadata(plan tenant.CreatePlanV2) map[string]string {
	config := map[string]string{
		keyV2Bridge:         plan.Bridge,
		keyV2Pool:           plan.StoragePool,
		keyV2Suffix:         plan.DNSSuffix,
		keyV2CIDR:           plan.PrivateCIDR,
		keyV2User:           plan.DefaultProfileUser,
		keyV2SSHKey:         plan.SSHPublicKey,
		keyV2Prefix:         plan.Prefix,
		keyV2DefaultProject: plan.DefaultProjectShort,
	}
	// A Shared Tenant records its Tenant Members; a Personal Tenant writes no
	// members key at all (the owner is implied by the tenant name).
	if members := meta.FormatMembers(plan.Members); members != "" {
		config[keyV2Members] = members
	}
	return config
}

func ensureV2Project(server TenantCreateServer, name string, description string, kind string, tenantName string, ownImages bool, extra map[string]string) error {
	if existing, etag, err := server.GetProject(name); err == nil {
		// Converge missing metadata onto pre-existing projects (additive only)
		// so idempotent re-provisioning can teach old projects new keys, e.g.
		// the client-visible Tenant DNS Suffix (ADR-0018).
		changed := false
		put := existing.Writable()
		for k, v := range extra {
			if put.Config[k] != v {
				put.Config[k] = v
				changed = true
			}
		}
		if !changed {
			return nil
		}
		if err := server.UpdateProject(name, put, etag); err != nil {
			return fmt.Errorf("update project %s metadata: %w", name, err)
		}
		return nil
	} else if !api.StatusErrorCheck(err, http.StatusNotFound) && !api.StatusErrorCheck(err, http.StatusForbidden) {
		return fmt.Errorf("get project %s: %w", name, err)
	}
	config := api.ConfigMap{
		"features.networks":        "false",
		"features.images":          boolStr(ownImages),
		"features.profiles":        "true",
		"features.storage.volumes": "true",
		meta.KeyKind:               kind,
		meta.KeyTenant:             tenantName,
		meta.KeyVersion:            "2",
	}
	for k, v := range extra {
		config[k] = v
	}
	return server.CreateProject(api.ProjectsPost{
		Name: name,
		ProjectPut: api.ProjectPut{
			Description: description,
			Config:      config,
		},
	})
}

// v2WorkspaceVolumeName / v2HomeVolumeName are the per-project custom
// filesystem volumes mounted at /workspace and /home on every machine in a
// tenant's project, so CTs and VMs in the same project share a working
// directory AND their home directories (attach-many is fine for a filesystem
// volume; incus shares it into VMs via virtiofs; concurrent writes are the
// workload's concern). /home is the whole directory: cloud-init creates the
// login user's home on the first machine and every later machine sees it.
const (
	v2WorkspaceVolumeName = tenant.V2WorkspaceVolumeName
	v2HomeVolumeName      = tenant.V2HomeVolumeName
)

// ensureV2ProjectVolumes creates the project's shared volumes if missing.
// /workspace is owned by the profile login user (UID/GID 2000, ADR-0014) so it
// is writable out of the box; /home keeps the standard root-owned 0755 (the
// per-user directory inside it is created by cloud-init with user ownership).
// security.shifted is REQUIRED on both: a CT writes through its idmap, so
// without it a VM sharing the volume sees raw shifted owners (e.g. 1002000
// instead of 2000) — which broke VM sshd (StrictModes rejects a foreign-owned
// ~). Shifted volumes give every consumer the unshifted UIDs.
func ensureV2ProjectVolumes(server TenantResourceServer, pool string, tenantName string, shifted bool) error {
	workspaceConfig := map[string]string{"initial.uid": "2000", "initial.gid": "2000", "initial.mode": "0775"}
	homeConfig := map[string]string{}
	if shifted {
		// Requires kernel idmapped-mount support on the incus host; a
		// container-hosted daemon lacks it and volume attachment would fail
		// with "idmapping abilities are required but aren't supported".
		workspaceConfig["security.shifted"] = "true"
		homeConfig["security.shifted"] = "true"
	}
	if err := ensureV2SharedVolume(server, pool, v2WorkspaceVolumeName, "Shared /workspace for Sandcastle v2 tenant "+tenantName, workspaceConfig); err != nil {
		return err
	}
	if err := ensureV2SCVolumes(server, pool, shifted); err != nil {
		return err
	}
	return ensureV2SharedVolume(server, pool, v2HomeVolumeName, "Shared /home for Sandcastle v2 tenant "+tenantName, homeConfig)
}

// ensureV2SCVolumes creates the /.sc layer volumes (spec #127) if missing:
// local is tenant-writable from machines (like /workspace, owned by the
// UID-2000 login user); platform keeps root-owned 0755 — machines additionally
// mount it read-only at the device level. Shared by tenant/project creation
// and the payload-sync legacy onboarding.
func ensureV2SCVolumes(server TenantResourceServer, pool string, shifted bool) error {
	scPlatformConfig := map[string]string{}
	scLocalConfig := map[string]string{"initial.uid": "2000", "initial.gid": "2000", "initial.mode": "0775"}
	if shifted {
		scPlatformConfig["security.shifted"] = "true"
		scLocalConfig["security.shifted"] = "true"
	}
	if err := ensureV2SharedVolume(server, pool, tenant.V2SCPlatformVolumeName, "Shared /.sc/platform scripts (Sandcastle v2)", scPlatformConfig); err != nil {
		return err
	}
	return ensureV2SharedVolume(server, pool, tenant.V2SCLocalVolumeName, "Shared /.sc/local scripts (Sandcastle v2)", scLocalConfig)
}

func ensureV2SharedVolume(server TenantResourceServer, pool string, name string, description string, config map[string]string) error {
	if _, _, err := server.GetStoragePoolVolume(pool, "custom", name); err == nil {
		return nil
	} else if !api.StatusErrorCheck(err, http.StatusNotFound) {
		return fmt.Errorf("get %s volume: %w", name, err)
	}
	return server.CreateStoragePoolVolume(pool, api.StorageVolumesPost{
		Name: name,
		Type: "custom",
		StorageVolumePut: api.StorageVolumePut{
			Description: description,
			Config:      config,
		},
	})
}

// ensureV2AppProfiles installs an app project's profile pair: `homeshare`
// first, then `default`. The order matters — default no longer carries the
// /home device, so machines that relied on it are migrated onto homeshare in
// between, while the profile still exists to migrate from.
func ensureV2AppProfiles(server TenantResourceServer, plan tenant.CreatePlanV2, projectShort string, log func(string)) error {
	if err := ensureV2HomeShareProfile(server, plan); err != nil {
		return err
	}
	if err := migrateV2MachinesToHomeShare(server, log); err != nil {
		return err
	}
	return ensureV2AppProfile(server, plan, projectShort)
}

// migrateV2MachinesToHomeShare keeps the /home of machines created before the
// profile split. Those machines mounted the shared volume through `default`;
// re-rendering default without the device would silently swap their home
// directory for the image's empty one (and with it the login user's ~/.ssh,
// breaking key auth). So when the live default profile still has the device,
// every instance using default is moved onto the homeshare profile first.
// Per-instance failures are logged, not fatal: a machine that cannot hotplug
// the device is not a reason to abort a tenant/project reconcile.
func migrateV2MachinesToHomeShare(server TenantResourceServer, log func(string)) error {
	current, _, err := server.GetProfile("default")
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil // fresh project: no machines, nothing to migrate
		}
		return fmt.Errorf("get default profile: %w", err)
	}
	if _, shared := current.Devices["home"]; !shared {
		return nil
	}
	names, err := server.GetInstanceNames(api.InstanceTypeAny)
	if err != nil {
		return fmt.Errorf("list machines for the homeshare migration: %w", err)
	}
	for _, name := range names {
		instance, etag, err := server.GetInstance(name)
		if err != nil || instance == nil {
			continue
		}
		if !slices.Contains(instance.Profiles, "default") || slices.Contains(instance.Profiles, tenant.V2HomeShareProfileName) {
			continue
		}
		put := instance.Writable()
		put.Profiles = append(append([]string{}, instance.Profiles...), tenant.V2HomeShareProfileName)
		log("migrate " + name + " onto the homeshare profile (it had a shared /home)")
		op, err := server.UpdateInstance(name, put, etag)
		if err == nil {
			err = op.Wait()
		}
		if err != nil {
			log("WARNING: could not add the homeshare profile to " + name + ": " + err.Error() +
				" — its /home will fall back to machine-local storage")
		}
	}
	return nil
}

func ensureV2AppProfile(server TenantResourceServer, plan tenant.CreatePlanV2, projectShort string) error {
	// The profile's cloud-init embeds http://<DNSAddress>:<port> as the machine
	// Caddy's TLS signer. An empty address renders "http://:9443" and the machine
	// serves no HTTPS — fail here instead of writing a profile that cannot work.
	if strings.TrimSpace(plan.DNSAddress) == "" {
		return fmt.Errorf("refusing to render the default profile of %s with an empty sidecar DNS address", plan.DefaultProject)
	}
	desired := api.ProfilePut{
		Description: "Sandcastle v2 default profile for " + plan.Tenant,
		Config: api.ConfigMap{
			"cloud-init.user-data": tenant.V2ProfileUserData(plan.DefaultProfileUser, plan.SSHPublicKey, projectShort, plan.DNSSuffix, plan.ProjectDomain, fmt.Sprintf("http://%s:%d", plan.DNSAddress, SidecarTLSSignPort)),
			meta.KeyKind:           "profile",
			meta.KeyTenant:         plan.Tenant,
			meta.KeyVersion:        "2",
		},
		Devices: v2AppProfileDevices(plan),
	}
	return ensureExactProfile(server, "default", desired)
}

// ensureV2HomeShareProfile installs the opt-in `homeshare` profile: the shared
// /home volume and nothing else, so it composes with default. Machines created
// with it (`sc create --home-share`) share the project's home directory; the
// default profile shares /workspace only. Split out of default because a
// shared /home makes every machine in a project see one dotfile/state tree —
// fine when that is what you want, surprising when it is not (and on hosts
// without idmapped mounts it breaks VM sshd, see ensureV2ProjectVolumes).
func ensureV2HomeShareProfile(server TenantResourceServer, plan tenant.CreatePlanV2) error {
	desired := api.ProfilePut{
		Description: "Sandcastle v2 shared /home profile for " + plan.Tenant,
		Config: api.ConfigMap{
			meta.KeyKind:    "profile",
			meta.KeyTenant:  plan.Tenant,
			meta.KeyVersion: "2",
		},
		Devices: v2HomeShareProfileDevices(plan),
	}
	return ensureExactProfile(server, tenant.V2HomeShareProfileName, desired)
}

// v2HomeShareProfileDevices builds the homeshare profile's device map.
func v2HomeShareProfileDevices(plan tenant.CreatePlanV2) api.DevicesMap {
	return api.DevicesMap{
		"home": {"type": "disk", "pool": plan.StoragePool, "source": v2HomeVolumeName, "path": "/home"},
	}
}

// v2AppProfileDevices builds the default profile's device map — pure, so the
// volume attachments (and the /.sc layers' per-device writability) are unit
// testable without a fake server. /home is deliberately absent: it lives in
// the opt-in `homeshare` profile (v2HomeShareProfileDevices).
func v2AppProfileDevices(plan tenant.CreatePlanV2) api.DevicesMap {
	devices := api.DevicesMap{
		"root":      {"type": "disk", "pool": plan.StoragePool, "path": "/"},
		"eth0":      {"type": "nic", "nictype": "bridged", "parent": plan.Bridge},
		"workspace": {"type": "disk", "pool": plan.StoragePool, "source": v2WorkspaceVolumeName, "path": "/workspace"},
	}
	// The /.sc shared-scripts layers (spec #127). readonly on the platform
	// device is the tenant-facing writability contract: machines (CT and VM)
	// mount the layer read-only, so a tenant cannot accidentally delete a
	// script the fleet depends on; central updates go through the volume API.
	scVolumes := plan.SCVolumes
	if len(scVolumes) == 0 {
		// Plans built outside PlanCreateV2 (profile re-renders) carry no
		// SCVolumes; the built-in set is the same contract.
		scVolumes = tenant.V2SCVolumes()
	}
	for _, v := range scVolumes {
		devices[v.DeviceName] = v.Device(plan.StoragePool)
	}
	return devices
}

func ensureV2SidecarProfile(server TenantResourceServer, plan tenant.CreatePlanV2) error {
	desired := api.ProfilePut{
		Description: "Sandcastle v2 sidecar profile for " + plan.Tenant,
		Config: api.ConfigMap{
			meta.KeyKind:    "sidecar",
			meta.KeyTenant:  plan.Tenant,
			meta.KeyVersion: "2",
		},
		Devices: api.DevicesMap{
			"root": {"type": "disk", "pool": plan.StoragePool, "path": "/"},
			"eth0": {"type": "nic", "nictype": "bridged", "parent": plan.Bridge, "ipv4.address": plan.DNSAddress},
		},
	}
	return ensureExactProfile(server, "sidecar", desired)
}

func ensureV2Sidecar(server TenantResourceServer, plan tenant.CreatePlanV2, image string) error {
	if existing, _, err := server.GetInstance(plan.SidecarInstance); err == nil {
		// The sidecar already exists. If it is not running (a prior provisioning
		// was interrupted, or its bridge was briefly missing so it stopped),
		// START it — otherwise the package-install and config steps below fail
		// with "Instance is not running".
		if existing.StatusCode != api.Running {
			op, err := server.UpdateInstanceState(plan.SidecarInstance, api.InstanceStatePut{Action: "start", Timeout: -1}, "")
			if err != nil {
				return fmt.Errorf("start existing sidecar %s: %w", plan.SidecarInstance, err)
			}
			if err := op.Wait(); err != nil && !isAlreadyRunning(err) {
				return fmt.Errorf("wait for sidecar %s start: %w", plan.SidecarInstance, err)
			}
		}
		if err := waitInstanceRunning(server, plan.SidecarInstance, 60*time.Second); err != nil {
			return err
		}
		return waitV2SidecarBoot(server, plan.SidecarInstance)
	} else if !api.StatusErrorCheck(err, http.StatusNotFound) {
		return fmt.Errorf("get sidecar %s: %w", plan.SidecarInstance, err)
	}
	// Accept a public-remote ref (images:debian/13), a fingerprint, or a local alias.
	source := imageInstanceSource(image)
	op, err := server.CreateInstance(api.InstancesPost{
		Name:   plan.SidecarInstance,
		Type:   "container",
		Start:  true,
		Source: source,
		InstancePut: api.InstancePut{
			Description: "Sandcastle v2 sidecar (CoreDNS + Tailscale + Caddy)",
			Config: api.ConfigMap{
				meta.KeyKind:    meta.KindSidecar,
				meta.KeyTenant:  plan.Tenant,
				meta.KeyVersion: "2",
			},
			Profiles: []string{"sidecar"},
		},
	})
	if err != nil {
		return fmt.Errorf("create sidecar %s: %w", plan.SidecarInstance, err)
	}
	if err := op.Wait(); err != nil && !isAlreadyRunning(err) {
		return fmt.Errorf("wait for sidecar %s: %w", plan.SidecarInstance, err)
	}
	// Start:true returns before the guest is actually up; wait for RUNNING so
	// the subsequent exec/file-push steps don't race the boot ("Not Found").
	if err := waitInstanceRunning(server, plan.SidecarInstance, 60*time.Second); err != nil {
		return err
	}
	return waitV2SidecarBoot(server, plan.SidecarInstance)
}

// waitV2SidecarBoot blocks until the sidecar has actually BOOTED: systemd
// settled and eth0 holding its tenant DHCP address. Incus RUNNING is only
// "processes exist" — with a cached image the container reaches RUNNING within
// a second and the package-install exec then raced the boot: apt had no
// network yet and failed. That failure was invisible while exec exit codes
// were swallowed (see execSidecar), which is how `tenant create` shipped
// sidecars with no CoreDNS/Tailscale at all (caught live on majestix).
func waitV2SidecarBoot(server TenantResourceServer, instance string) error {
	script := strings.Join([]string{
		"s=offline",
		"for i in $(seq 1 60); do",
		"  s=$(systemctl is-system-running 2>/dev/null || true)",
		"  case \"$s\" in running|degraded) break;; esac",
		"  sleep 2",
		"done",
		"case \"$s\" in running|degraded) ;; *) echo \"sidecar systemd not ready after 120s (state: $s)\" >&2; exit 1;; esac",
		"for i in $(seq 1 60); do",
		"  ip -4 -o addr show eth0 2>/dev/null | grep -q ' inet 10\\.' && exit 0",
		"  sleep 2",
		"done",
		"echo 'sidecar eth0 got no tenant IPv4 (DHCP) after 120s' >&2",
		"exit 1",
	}, "\n")
	if err := execSidecar(server, instance, script); err != nil {
		return fmt.Errorf("wait for sidecar boot: %w", err)
	}
	return nil
}

// waitInstanceRunning blocks until the instance reports RUNNING (or timeout).
// CreateInstance{Start:true} returns as soon as the start is requested, not
// when the guest is ready — exec/CreateInstanceFile against a not-yet-running
// instance fail with a spurious "Not Found".
func waitInstanceRunning(server TenantResourceServer, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		state, _, err := server.GetInstanceState(name)
		if err == nil && state != nil && state.StatusCode == api.Running {
			return nil
		}
		if !time.Now().Before(deadline) {
			if err != nil {
				return fmt.Errorf("wait for %s to run: %w", name, err)
			}
			return fmt.Errorf("instance %s did not reach RUNNING within %s", name, timeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// coreDNSVersion is the CoreDNS release fetched onto stock-Debian sidecars
// (CoreDNS is not packaged in Debian apt, so we install the release binary).
const coreDNSVersion = "1.14.3"

// installV2SidecarPackages makes a stock Debian system container into a usable
// sidecar: it installs the CoreDNS release binary (not in apt) and Tailscale
// (via Tailscale's official apt repo). Idempotent — skips work already done, so
// re-running create is cheap. This replaces the prebuilt sandcastle/base image.
func installV2SidecarPackages(server TenantResourceServer, plan tenant.CreatePlanV2) error {
	script := strings.Join([]string{
		"set -eu",
		"export DEBIAN_FRONTEND=noninteractive",
		// Bootstrap resolver: the bridge's DHCP resolver is the sidecar's OWN
		// CoreDNS (ADR-0018), which doesn't exist until this install finishes.
		// Until CoreDNS is live, resolve the package downloads via upstream
		// directly; configureV2Sidecar switches to 127.0.0.1 afterwards.
		"systemctl is-active coredns >/dev/null 2>&1 || printf 'nameserver 1.1.1.1\\nnameserver 8.8.8.8\\n' > /etc/resolv.conf",
		"need_apt=0",
		"command -v curl >/dev/null 2>&1 || need_apt=1",
		"command -v tailscale >/dev/null 2>&1 || need_apt=1",
		"if [ \"$need_apt\" = 1 ]; then apt-get update -qq && apt-get install -y -qq curl ca-certificates gnupg tar; fi",
		// CoreDNS release binary (arch-matched; dpkg arch names == coredns arch names).
		"if [ ! -x /usr/local/bin/coredns ]; then " +
			"ARCH=$(dpkg --print-architecture); " +
			"curl -fsSL \"https://github.com/coredns/coredns/releases/download/v" + coreDNSVersion +
			"/coredns_" + coreDNSVersion + "_linux_${ARCH}.tgz\" -o /tmp/coredns.tgz && " +
			"tar -xzf /tmp/coredns.tgz -C /usr/local/bin coredns && chmod 0755 /usr/local/bin/coredns && rm -f /tmp/coredns.tgz; fi",
		// Tailscale via its official apt repo (keyed to the container's codename).
		"if ! command -v tailscale >/dev/null 2>&1; then " +
			". /etc/os-release; " +
			"curl -fsSL \"https://pkgs.tailscale.com/stable/debian/${VERSION_CODENAME}.noarmor.gpg\" -o /usr/share/keyrings/tailscale-archive-keyring.gpg && " +
			"curl -fsSL \"https://pkgs.tailscale.com/stable/debian/${VERSION_CODENAME}.tailscale-keyring.list\" -o /etc/apt/sources.list.d/tailscale.list && " +
			"apt-get update -qq && apt-get install -y -qq tailscale; fi",
		"command -v /usr/local/bin/coredns >/dev/null && command -v tailscale >/dev/null",
	}, "\n")
	if err := execSidecar(server, plan.SidecarInstance, script); err != nil {
		return fmt.Errorf("install sidecar packages (CoreDNS+Tailscale): %w", err)
	}
	return nil
}

// configureV2Sidecar pins the sidecar's static IP (the base image does not DHCP
// eth0), writes the CoreDNS config, and starts CoreDNS. Tailscale is handled
// separately so the auth key can be omitted when re-running.
func configureV2Sidecar(server TenantResourceServer, plan tenant.CreatePlanV2) error {
	gateway, err := gatewayIPFromCIDR(plan.PrivateCIDR)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(plan.PrivateCIDR)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", plan.PrivateCIDR, err)
	}
	ipWithPrefix := fmt.Sprintf("%s/%d", plan.DNSAddress, prefix.Bits())

	// Static network: apply now + a systemd oneshot for reboot persistence.
	netScript := strings.Join([]string{
		"install -d -m 0755 /usr/local/sbin /etc/systemd/system/multi-user.target.wants",
		"printf '%s\\n' '#!/bin/sh' 'set -eu' '/usr/sbin/ip link set eth0 up' '/usr/sbin/ip addr replace " + ipWithPrefix + " dev eth0' '/usr/sbin/ip route replace default via " + gateway + "' > /usr/local/sbin/sandcastle-sidecar-network",
		"chmod 0755 /usr/local/sbin/sandcastle-sidecar-network",
		"printf '%s\\n' '[Unit]' 'Description=Sandcastle sidecar static network' 'Before=network-online.target' '' '[Service]' 'Type=oneshot' 'ExecStart=/usr/local/sbin/sandcastle-sidecar-network' 'RemainAfterExit=yes' '' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/sandcastle-sidecar-network.service",
		"ln -sf /etc/systemd/system/sandcastle-sidecar-network.service /etc/systemd/system/multi-user.target.wants/sandcastle-sidecar-network.service",
		"systemctl daemon-reload 2>/dev/null || true",
		"/usr/local/sbin/sandcastle-sidecar-network",
	}, " && ")
	if err := execSidecar(server, plan.SidecarInstance, netScript); err != nil {
		return fmt.Errorf("configure sidecar network: %w", err)
	}

	// Write CoreDNS files from the plan.
	for _, f := range plan.DNSFiles {
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := writeInstanceDir(server, plan.SidecarInstance, f.Path); err != nil {
			return err
		}
		if err := server.CreateInstanceFile(plan.SidecarInstance, f.Path, incus.InstanceFileArgs{
			Content:   strings.NewReader(f.Content),
			Type:      "file",
			Mode:      int(mode),
			WriteMode: "overwrite",
		}); err != nil {
			return fmt.Errorf("write %s to sidecar: %w", f.Path, err)
		}
	}

	// Start CoreDNS (free :53 from systemd-resolved first).
	coredns := strings.Join([]string{
		"systemctl stop systemd-resolved.service 2>/dev/null || true",
		"systemctl mask systemd-resolved.service 2>/dev/null || true",
		"printf '%s\\n' '[Unit]' 'Description=CoreDNS tenant resolver' 'After=network-online.target' '' '[Service]' 'ExecStart=/usr/local/bin/coredns -conf /etc/coredns/Corefile' 'Restart=on-failure' '' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/coredns.service",
		"systemctl daemon-reload",
		"systemctl enable --now coredns.service",
		"sleep 1",
		"systemctl is-active coredns.service",
	}, " && ")
	if err := execSidecar(server, plan.SidecarInstance, coredns); err != nil {
		return fmt.Errorf("start CoreDNS: %w", err)
	}
	return nil
}

// SidecarTLSSignPort is the tenant-bridge port the leaf signer listens on (on
// the sidecar's DNS address). Reachable by machines (bridge) and by the client
// (tenant subnet route).
const SidecarTLSSignPort = 9443

// sidecarFileExists reports whether path is a regular file inside the sidecar.
func sidecarFileExists(server TenantResourceServer, instance, path string) bool {
	out, err := execSidecarCapture(server, instance, "test -f "+path+" && echo yes || echo no")
	return err == nil && strings.TrimSpace(out) == "yes"
}

// configureV2TLSSigner stands up the tenant-CA leaf signer on the sidecar
// (ADR-0011): it persists the tenant CA (once — so re-provisioning does not
// rotate it), ships the Sandcastle binary if missing, and runs
// `sandcastle-admin sidecar tls-sign` under systemd on the tenant bridge.
func configureV2TLSSigner(server TenantResourceServer, plan tenant.CreatePlanV2) error {
	// The signer self-generates the tenant CA on first start (CA key lives only
	// on the sidecar; clients and machines fetch the cert from /tls/ca), so
	// nothing CA-related needs pushing here.

	// 1. Sandcastle binary (the running one — matches the sidecar's amd64) —
	// ship if missing. Version updates are handled by removing it and re-running.
	if !sidecarFileExists(server, plan.SidecarInstance, "/usr/local/bin/sandcastle-admin") {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate sandcastle binary: %w", err)
		}
		data, err := os.ReadFile(exe)
		if err != nil {
			return fmt.Errorf("read sandcastle binary: %w", err)
		}
		if err := server.CreateInstanceFile(plan.SidecarInstance, "/usr/local/bin/sandcastle-admin", incus.InstanceFileArgs{
			Content:   strings.NewReader(string(data)),
			Type:      "file",
			Mode:      0o755,
			WriteMode: "overwrite",
		}); err != nil {
			return fmt.Errorf("push sandcastle binary to sidecar: %w", err)
		}
		// Stamp only on an actual push: an already-present (possibly older)
		// binary keeps its previous stamp — or none, which reads as "unknown".
		if err := stampBinaryVersion(server, plan.SidecarInstance, runningBinaryVersion); err != nil {
			return err
		}
	}

	// 3. systemd unit for the signer, bound to the tenant bridge address.
	listen := fmt.Sprintf("%s:%d", plan.DNSAddress, SidecarTLSSignPort)
	exec := "/usr/local/bin/sandcastle-admin sidecar tls-sign" +
		" --ca-cert /etc/sandcastle/ca/ca.crt --ca-key /etc/sandcastle/ca/ca.key" +
		" --suffix " + plan.DNSSuffix + " --listen " + listen
	unit := strings.Join([]string{
		"printf '%s\\n'",
		"'[Unit]'", "'Description=Sandcastle tenant TLS leaf signer'", "'After=sandcastle-sidecar-network.service'",
		"''", "'[Service]'", "'ExecStart=" + exec + "'", "'Restart=on-failure'", "'RestartSec=2'",
		"''", "'[Install]'", "'WantedBy=multi-user.target'",
		"> /etc/systemd/system/sandcastle-tls-sign.service",
	}, " ")
	script := strings.Join([]string{
		unit,
		"systemctl daemon-reload",
		"systemctl enable --now sandcastle-tls-sign.service",
		"sleep 1",
		"systemctl is-active sandcastle-tls-sign.service",
	}, " && ")
	if err := execSidecar(server, plan.SidecarInstance, script); err != nil {
		return fmt.Errorf("start tenant TLS signer: %w", err)
	}
	return nil
}

// v2TailscaleUp brings the sidecar onto the tenant's tailnet. With an auth key it
// joins non-interactively and hard-gates on getting a tailnet IP. Without one it
// starts an interactive `tailscale up` as a detached unit (which blocks waiting for
// the user) and returns the login URL it prints, so the caller can show it; the
// sidecar joins once the user visits that URL. Returns "" when a key was used or the
// sidecar is already registered.
// v2TailscaleUp brings the sidecar onto the tenant's tailnet and, on the auth-key
// path, sets up the Incus Reach (ADR-0017): a raw-TCP `tailscale serve` forwarding
// the sidecar's tailnet :8443 to the host's Incus gateway, plus it returns the
// sidecar's tailnet IPv4 (the address the client's Incus remote points at).
// Returns (interactiveLoginURL, sidecarTailnetIP, error).
// sidecarTailnetTag tags every sidecar so the tenant's advertised subnet route
// is auto-approved by a Tailscale `autoApprovers` ACL rule (routes → this tag),
// removing the need for manual admin approval or a Tailscale API key.
const sidecarTailnetTag = "tag:sandcastle"

func v2TailscaleUp(server TenantResourceServer, plan tenant.CreatePlanV2, tailnetHostname string, authKey string) (string, string, error) {
	base := "--advertise-routes=" + plan.PrivateCIDR + " --hostname=" + tailnetHostname + " --accept-dns=false --advertise-tags=" + sidecarTailnetTag
	gateway, err := gatewayIPFromCIDR(plan.PrivateCIDR)
	if err != nil {
		return "", "", err
	}
	// finish = the Incus Reach (ADR-0017): proxy the host's Incus API onto the
	// tenant tailnet (raw TCP, so the host cert is pinned) and emit the
	// sidecar's tailnet IPv4 for the caller. Shared by both branches so a
	// BYO-tailnet interactive join completes the Reach on the next
	// provisioning pass (login re-polls until this reports an IP).
	finish := "tailscale serve --bg --tcp=8443 tcp://" + gateway + ":8443\n" +
		"printf 'TSIP=%s\\n' \"$(tailscale ip -4 | head -1)\""
	if authKey == "" {
		const log = "/var/lib/sandcastle-tsup.log"
		script := strings.Join([]string{
			"set -e",
			"systemctl unmask tailscaled.service 2>/dev/null || true",
			"systemctl enable --now tailscaled.service",
			// Wait for the daemon socket. `status --json` answers as soon as
			// tailscaled is up even while logged out — plain `status` exits
			// non-zero in NeedsLogin and would burn the whole 30s on every
			// awaiting-tailnet poll.
			"for i in $(seq 1 30); do tailscale status --json >/dev/null 2>&1 && break; sleep 1; done",
			// Already authenticated (the user completed the interactive login,
			// or an earlier run joined): finish the Reach and report the IP.
			"if tailscale ip -4 >/dev/null 2>&1; then\n" + finish + "\nexit 0\nfi",
			// `tailscale up` blocks until the user authenticates, so it runs as a
			// detached transient unit that writes its login URL to a log. The URL
			// must survive re-ensure passes and `sc login` re-runs, so a healthy
			// waiting unit is left alone (its log is never truncated); the unit is
			// (re)started only when it is not running or its log lost the URL.
			"if ! systemctl is-active sandcastle-tsup.service >/dev/null 2>&1 || ! grep -qF 'https://login.tailscale.com/' " + log + " 2>/dev/null; then " +
				"systemctl stop sandcastle-tsup.service 2>/dev/null || true; " +
				"printf '#!/bin/sh\\nexec tailscale up " + base + " > " + log + " 2>&1\\n' > /usr/local/bin/sandcastle-tsup.sh; " +
				"chmod +x /usr/local/bin/sandcastle-tsup.sh; " +
				": > " + log + "; " +
				"systemctl reset-failed sandcastle-tsup.service 2>/dev/null || true; " +
				"systemd-run --unit=sandcastle-tsup --collect /usr/local/bin/sandcastle-tsup.sh >/dev/null 2>&1 || true; " +
				"fi",
			// Report the newest URL in the log (each `tailscale up` mints a fresh one).
			"for i in $(seq 1 30); do url=$(grep -Eo 'https://login\\.tailscale\\.com/[A-Za-z0-9._/-]+' " + log + " 2>/dev/null | tail -n 1); [ -n \"$url\" ] && { printf 'TSLOGINURL=%s\\n' \"$url\"; exit 0; }; sleep 1; done",
			"exit 0",
		}, "\n")
		out, err := execSidecarCapture(server, plan.SidecarInstance, script)
		if err != nil {
			return "", "", fmt.Errorf("tailscale up (interactive): %w", err)
		}
		return parseTailscaleLoginURL(out), parseTailnetIP(out), nil
	}
	upCmd := "tailscale up --auth-key='" + authKey + "' " + base + " --timeout=60s"
	up := strings.Join([]string{
		"set -e",
		"systemctl unmask tailscaled.service 2>/dev/null || true",
		"systemctl enable --now tailscaled.service",
		// Wait for tailscaled to accept commands before bringing the link up —
		// on a freshly apt-installed sidecar the daemon socket lags the unit.
		"for i in $(seq 1 30); do tailscale status >/dev/null 2>&1 && break; sleep 1; done",
		// Bring up and confirm we actually got a tailnet IP (a bare `up` can
		// exit 0 without connecting); retry a couple of times if not.
		"for attempt in 1 2 3; do " + upCmd + " || true; tailscale ip -4 >/dev/null 2>&1 && break; sleep 3; done",
		// Hard gate: fail the create if the sidecar is not on the tailnet.
		"tailscale ip -4 >/dev/null 2>&1 || { echo 'tailscale did not connect' >&2; tailscale status >&2; exit 1; }",
		// Incus Reach (ADR-0017): proxy the host's Incus API onto the tenant
		// tailnet — raw TCP, TLS passes through so the host cert is pinned.
		"tailscale serve --bg --tcp=8443 tcp://" + gateway + ":8443",
		// Emit the sidecar's tailnet IPv4 for the caller (the client's remote addr).
		"printf 'TSIP=%s\\n' \"$(tailscale ip -4 | head -1)\"",
	}, "\n")
	out, err := execSidecarCapture(server, plan.SidecarInstance, up)
	if err != nil {
		return "", "", fmt.Errorf("tailscale up: %w", err)
	}
	return "", parseTailnetIP(out), nil
}

// parseTailnetIP extracts the `TSIP=<ipv4>` line emitted by the sidecar setup.
func parseTailnetIP(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "TSIP="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseTailscaleLoginURL extracts the URL emitted by the interactive up script.
func parseTailscaleLoginURL(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if url, ok := strings.CutPrefix(strings.TrimSpace(line), "TSLOGINURL="); ok {
			return strings.TrimSpace(url)
		}
	}
	return ""
}

// writeInstanceDir prepares filePath for an Incus file push: it creates the
// parent directory and clears any symlink at the path itself. The file API
// follows symlinks, and pushing through a dangling one fails with a spurious
// "Not Found" — /etc/resolv.conf on a stock image links to systemd-resolved's
// stub under /run, which does not exist until resolved has started.
func writeInstanceDir(server applianceExecServer, instance string, filePath string) error {
	dir := filePath[:strings.LastIndex(filePath, "/")]
	if dir == "" {
		return nil
	}
	return execSidecar(server, instance, "mkdir -p "+dir+" && { [ ! -L "+filePath+" ] || rm -f "+filePath+"; }")
}

// execSidecarCapture runs a script in the sidecar and returns its stdout.
func execSidecarCapture(server applianceExecServer, instance string, script string) (string, error) {
	var stdout, stderr strings.Builder
	dataDone := make(chan bool)
	op, err := server.ExecInstance(instance, api.InstanceExecPost{
		Command:   []string{"/bin/sh", "-c", script},
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stdout:   &stdout,
		Stderr:   &stderr,
		DataDone: dataDone,
	})
	if err != nil {
		return "", err
	}
	if err := op.Wait(); err != nil {
		return "", fmt.Errorf("%w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	<-dataDone
	if err := execExitError(op, stderr.String()); err != nil {
		return "", err
	}
	return stdout.String(), nil
}

// execExitError surfaces a nonzero command exit code from an exec operation.
// The SDK's op.Wait() only fails when the OPERATION fails (spawn error) — a
// script that ran and exited nonzero still "succeeds", which silently masked
// every sidecar provisioning failure (caught live on majestix: `tenant
// create` returned success with the whole package install failed).
func execExitError(op incus.Operation, stderr string) error {
	metadata := op.Get().Metadata
	if metadata == nil {
		return nil
	}
	code, ok := metadata["return"].(float64)
	if !ok || code == 0 {
		return nil
	}
	detail := strings.TrimSpace(stderr)
	if detail == "" {
		detail = "no stderr"
	}
	return fmt.Errorf("command exited with status %d (stderr: %s)", int(code), detail)
}

func execSidecar(server applianceExecServer, instance string, script string) error {
	var stderr strings.Builder
	dataDone := make(chan bool)
	op, err := server.ExecInstance(instance, api.InstanceExecPost{
		Command:   []string{"/bin/sh", "-c", script},
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stderr:   &stderr,
		DataDone: dataDone,
	})
	if err != nil {
		return err
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("%w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}
	<-dataDone
	return execExitError(op, stderr.String())
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func looksLikeFingerprint(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 12 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
