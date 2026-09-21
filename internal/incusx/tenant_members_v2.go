package incusx

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Shared Tenants (spec docs/spec/shared-tenants.md): a tenant's Tenant Members
// live on its infra project as meta.KeyV2Members, and every member's own
// login keys (read off the member's Personal Tenant, meta.KeyV2SSHKey) are
// rendered into the tenant's app-project profiles next to the tenant's own
// keys. Membership and keys are Tenant Metadata, so the admin CLI (direct
// Incus) and the Auth App (web grant, login-time key rotation) converge on the
// same state without a shared database.

// normalizeInstallPrefix maps the admin-facing prefix ("" / "sc") onto the
// v2 project prefix, mirroring every other v2 entry point.
func normalizeInstallPrefix(installPrefix string) string {
	installPrefix = strings.TrimSpace(installPrefix)
	if installPrefix == "" || installPrefix == naming.DefaultIncusProjectPrefix {
		return naming.V2IncusProjectPrefix
	}
	return installPrefix
}

// tenantV2Infra reads a tenant's infra project: its name, the project and the
// ETag a subsequent UpdateProject must present.
func tenantV2Infra(server TenantCreateServer, installPrefix string, tenantName string) (string, *api.Project, string, error) {
	if err := naming.ValidateTenantName(tenantName); err != nil {
		return "", nil, "", err
	}
	infraProject, err := naming.V2TenantInfraProjectName(normalizeInstallPrefix(installPrefix), tenantName)
	if err != nil {
		return "", nil, "", err
	}
	infra, etag, err := server.GetProject(infraProject)
	if err != nil {
		return "", nil, "", fmt.Errorf("tenant %q infra project %s not found: %w", tenantName, infraProject, err)
	}
	return infraProject, infra, etag, nil
}

// tenantV2AppProjects lists the short names of a tenant's app projects
// (<infra>-<short>), sorted.
func tenantV2AppProjects(server TenantCreateServer, infraProject string) ([]string, error) {
	names, err := server.GetProjectNames()
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	var projects []string
	for _, name := range names {
		if short, ok := strings.CutPrefix(name, infraProject+"-"); ok && short != "" {
			projects = append(projects, short)
		}
	}
	sort.Strings(projects)
	return projects, nil
}

// MemberSSHKeysV2 returns each member's login keys as recorded on their
// Personal Tenant (meta.KeyV2SSHKey of <prefix>-<member>), keyed by member.
// Members without a Personal Tenant on this install are reported in `missing`
// rather than failing the whole read: a Shared Tenant's prerequisite is that
// every member has logged in here, and callers turn a missing member into the
// "run sc login first" refusal or a warning as suits them.
func MemberSSHKeysV2(server TenantCreateServer, installPrefix string, members []string) (keys map[string]string, missing []string) {
	keys = map[string]string{}
	prefix := normalizeInstallPrefix(installPrefix)
	for _, member := range meta.ParseMembers(strings.Join(members, ",")) {
		infraProject, err := naming.V2TenantInfraProjectName(prefix, member)
		if err != nil {
			missing = append(missing, member)
			continue
		}
		infra, _, err := server.GetProject(infraProject)
		if err != nil || !meta.IsManaged(infra.Config) || infra.Config[meta.KeyKind] != meta.KindInfra {
			missing = append(missing, member)
			continue
		}
		keys[member] = meta.FormatSSHKeys(meta.ParseSSHKeys(infra.Config[keyV2SSHKey]))
	}
	return keys, missing
}

// tenantV2AuthorizedKeys is THE key set a tenant's machines authorize: the
// tenant's own keys (infra config, one per line) followed by every Tenant
// Member's Personal Tenant keys. Members missing on this install contribute
// nothing (and are reported by MemberSSHKeysV2 to the callers that care).
func tenantV2AuthorizedKeys(server TenantCreateServer, installPrefix string, infraConfig map[string]string) string {
	keys := meta.ParseSSHKeys(infraConfig[keyV2SSHKey])
	memberKeys, _ := MemberSSHKeysV2(server, firstNonEmpty(infraConfig[keyV2Prefix], installPrefix), meta.ParseMembers(infraConfig[keyV2Members]))
	members := make([]string, 0, len(memberKeys))
	for member := range memberKeys {
		members = append(members, member)
	}
	sort.Strings(members)
	for _, member := range members {
		keys = append(keys, meta.ParseSSHKeys(memberKeys[member])...)
	}
	return meta.FormatSSHKeys(keys)
}

// withTenantAuthorizedKeys returns the plan with SSHPublicKey widened to the
// full authorized set (own keys + members'); used wherever a profile is
// rendered from a CreatePlanV2 that only carries the tenant's own keys.
func withTenantAuthorizedKeys(server TenantCreateServer, plan tenant.CreatePlanV2) tenant.CreatePlanV2 {
	if len(plan.Members) == 0 {
		return plan
	}
	plan.SSHPublicKey = tenantV2AuthorizedKeys(server, plan.Prefix, map[string]string{
		keyV2SSHKey:  plan.SSHPublicKey,
		keyV2Members: meta.FormatMembers(plan.Members),
		keyV2Prefix:  plan.Prefix,
	})
	return plan
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// renderTenantProfilesV2 re-renders the default + homeshare profiles of the
// given app projects (short names; all of the tenant's when nil) from the
// infra project's stored settings, so machines created from now on authorize
// the tenant's current key set. Each project's Project Domain is read off the
// app project itself (meta.KeyV2Domain) — a re-render must not drop the
// public-name seed a `sc project create --domain` baked in.
func (c TenantCreator) renderTenantProfilesV2(server TenantCreateServer, tenantName string, infraProject string, config map[string]string, projects []string) error {
	prefix := config[keyV2Prefix]
	if prefix == "" {
		prefix = naming.V2IncusProjectPrefix
	}
	if len(projects) == 0 {
		var err error
		if projects, err = tenantV2AppProjects(server, infraProject); err != nil {
			return err
		}
	}
	// Re-rendering the profile rebuilds its cloud-init, which embeds the machine
	// Caddy's signer URL. Derive the sidecar address or we would silently replace
	// a working signer with "http://:9443".
	dnsAddress, err := tenant.DNSAddressForCIDR(config[keyV2CIDR])
	if err != nil {
		return fmt.Errorf("tenant %q: %w", tenantName, err)
	}
	authorizedKeys := tenantV2AuthorizedKeys(server, prefix, config)
	for _, project := range projects {
		project = strings.TrimSpace(project)
		if project == "" {
			continue
		}
		incusProject, err := naming.V2ProjectName(prefix, tenantName, project)
		if err != nil {
			return err
		}
		domain := ""
		if app, _, err := server.GetProject(incusProject); err == nil {
			domain = strings.TrimSpace(app.Config[meta.KeyV2Domain])
		}
		plan := tenant.CreatePlanV2{
			Tenant:             tenantName,
			Prefix:             prefix,
			DefaultProject:     incusProject,
			Bridge:             config[keyV2Bridge],
			StoragePool:        config[keyV2Pool],
			DefaultProfileUser: config[keyV2User],
			SSHPublicKey:       authorizedKeys,
			DNSSuffix:          config[keyV2Suffix],
			DNSAddress:         dnsAddress,
			ProjectDomain:      domain,
			SCVolumes:          tenant.V2SCVolumes(),
		}
		if plan.DefaultProfileUser == "" {
			plan.DefaultProfileUser = tenant.DefaultV2UnixUser
		}
		// Re-render both profiles: the same pass backfills the opt-in homeshare
		// profile into projects created before it existed (it carries no key
		// material of its own).
		c.log("re-render default + homeshare profiles of " + incusProject)
		if err := ensureV2AppProfiles(server.UseProject(incusProject), plan, project, c.log); err != nil {
			return fmt.Errorf("update profiles of %s: %w", incusProject, err)
		}
	}
	return nil
}

// updateTenantInfraV2 rewrites one infra-project config key (deleting it for
// an empty value) and re-renders every app project's profiles from the result.
func (c TenantCreator) updateTenantInfraV2(server TenantCreateServer, tenantName string, infraProject string, infra *api.Project, etag string, key string, value string) (map[string]string, error) {
	config := map[string]string{}
	for k, v := range infra.Config {
		config[k] = v
	}
	if strings.TrimSpace(value) == "" {
		delete(config, key)
	} else {
		config[key] = value
	}
	c.log("update " + key + " on " + infraProject)
	if err := server.UpdateProject(infraProject, api.ProjectPut{Config: config, Description: infra.Description}, etag); err != nil {
		return nil, fmt.Errorf("store %s on %s: %w", key, infraProject, err)
	}
	return config, c.renderTenantProfilesV2(server, tenantName, infraProject, config, nil)
}

// GetTenantMembersV2 reads a tenant's Tenant Members.
func (c TenantCreator) GetTenantMembersV2(_ context.Context, installPrefix string, tenantName string) ([]string, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	_, infra, _, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return nil, err
	}
	return meta.ParseMembers(infra.Config[keyV2Members]), nil
}

// SetTenantMembersV2 replaces a tenant's Tenant Members and re-renders its
// profiles so new machines authorize exactly the resulting key set.
func (c TenantCreator) SetTenantMembersV2(_ context.Context, installPrefix string, tenantName string, members []string) error {
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	infraProject, infra, etag, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return err
	}
	for _, member := range meta.ParseMembers(strings.Join(members, ",")) {
		if member == strings.ToLower(strings.TrimSpace(tenantName)) {
			return fmt.Errorf("user %s owns tenant %s; a Personal Tenant needs no member entry for its owner", member, tenantName)
		}
	}
	_, err = c.updateTenantInfraV2(server, tenantName, infraProject, infra, etag, keyV2Members, meta.FormatMembers(members))
	return err
}

// AddTenantMemberV2 grants userKey Tenant Membership (idempotent) and returns
// the resulting member list. It refuses a member without a Personal Tenant on
// this install: their login key is unknown, so the machines could never admit
// them — the prerequisite is `sc login` first.
func (c TenantCreator) AddTenantMemberV2(ctx context.Context, installPrefix string, tenantName string, userKey string) ([]string, error) {
	userKey = strings.ToLower(strings.TrimSpace(userKey))
	if err := naming.ValidateGitHubUsernameTenantName(userKey); err != nil {
		return nil, fmt.Errorf("tenant member %q: %w", userKey, err)
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	_, infra, _, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return nil, err
	}
	if _, missing := MemberSSHKeysV2(server, firstNonEmpty(infra.Config[keyV2Prefix], installPrefix), []string{userKey}); len(missing) > 0 {
		return nil, fmt.Errorf("user %s has no Personal Tenant on this install (no login SSH key to enrol); they must run `sc login` here before being added to %s", userKey, tenantName)
	}
	members := append(meta.ParseMembers(infra.Config[keyV2Members]), userKey)
	if err := c.SetTenantMembersV2(ctx, installPrefix, tenantName, members); err != nil {
		return nil, err
	}
	return meta.ParseMembers(strings.Join(members, ",")), nil
}

// RemoveTenantMemberV2 revokes userKey's Tenant Membership (idempotent) and
// returns the resulting member list.
func (c TenantCreator) RemoveTenantMemberV2(ctx context.Context, installPrefix string, tenantName string, userKey string) ([]string, error) {
	userKey = strings.ToLower(strings.TrimSpace(userKey))
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	_, infra, _, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return nil, err
	}
	var members []string
	for _, member := range meta.ParseMembers(infra.Config[keyV2Members]) {
		if member != userKey {
			members = append(members, member)
		}
	}
	if err := c.SetTenantMembersV2(ctx, installPrefix, tenantName, members); err != nil {
		return nil, err
	}
	return members, nil
}

// AddTenantSSHKeyV2 appends an authorized key to the tenant's own key list
// (idempotent) and re-renders the profiles; returns the resulting list.
func (c TenantCreator) AddTenantSSHKeyV2(_ context.Context, installPrefix string, tenantName string, sshKey string) ([]string, error) {
	sshKey = strings.TrimSpace(sshKey)
	if sshKey == "" {
		return nil, fmt.Errorf("ssh key is required")
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	infraProject, infra, etag, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return nil, err
	}
	keys := append(meta.ParseSSHKeys(infra.Config[keyV2SSHKey]), meta.ParseSSHKeys(sshKey)...)
	if _, err := c.updateTenantInfraV2(server, tenantName, infraProject, infra, etag, keyV2SSHKey, meta.FormatSSHKeys(keys)); err != nil {
		return nil, err
	}
	return meta.ParseSSHKeys(meta.FormatSSHKeys(keys)), nil
}

// RemoveTenantSSHKeyV2 drops an authorized key from the tenant's own key list
// (matched on the key material, ignoring the comment) and re-renders the
// profiles; returns the resulting list. The tenant's last key cannot be
// removed — machines with no way in are worse than machines with a stale key.
func (c TenantCreator) RemoveTenantSSHKeyV2(_ context.Context, installPrefix string, tenantName string, sshKey string) ([]string, error) {
	target := sshKeyMaterial(sshKey)
	if target == "" {
		return nil, fmt.Errorf("ssh key is required")
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	infraProject, infra, etag, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, key := range meta.ParseSSHKeys(infra.Config[keyV2SSHKey]) {
		if sshKeyMaterial(key) != target {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("refusing to remove the last SSH key of tenant %s; set a replacement first (sc-adm tenant set-ssh-key)", tenantName)
	}
	if _, err := c.updateTenantInfraV2(server, tenantName, infraProject, infra, etag, keyV2SSHKey, meta.FormatSSHKeys(keys)); err != nil {
		return nil, err
	}
	return keys, nil
}

// sshKeyMaterial is "<type> <base64>" — the key without its comment — so
// removal matches the same key however it was labelled when added.
func sshKeyMaterial(key string) string {
	fields := strings.Fields(key)
	if len(fields) < 2 {
		return strings.TrimSpace(key)
	}
	return fields[0] + " " + fields[1]
}

// SidecarTailnetIPV2 returns the tenant sidecar's tailnet IPv4 — the address a
// member's Incus remote must point at (the Incus Reach, ADR-0017) — or "" when
// the sidecar has not joined a tailnet yet. It also (idempotently) completes
// the Reach itself: a sidecar joined through the interactive login URL of
// `sc-adm tenant create` has an address but no `tailscale serve` yet, because
// that step only runs on a provisioning pass AFTER the join and the admin
// create does not re-poll the way login does. Without it a member's
// `sc tenant switch` fails with "connection refused" on :8443.
func (c TenantCreator) SidecarTailnetIPV2(_ context.Context, installPrefix string, tenantName string) (string, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return "", err
	}
	infraProject, infra, _, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return "", err
	}
	script := "tailscale ip -4 2>/dev/null | head -1"
	if gateway, err := gatewayIPFromCIDR(infra.Config[keyV2CIDR]); err == nil && gateway != "" {
		script = "if tailscale ip -4 >/dev/null 2>&1; then " +
			"tailscale serve status 2>/dev/null | grep -q ':8443' || tailscale serve --bg --tcp=8443 tcp://" + gateway + ":8443 >/dev/null 2>&1; " +
			"fi; " + script
	}
	out, err := execSidecarCapture(server.UseProject(infraProject), naming.V2SidecarInstanceName, script)
	if err != nil {
		return "", fmt.Errorf("read sidecar tailnet address of %s: %w", tenantName, err)
	}
	return strings.TrimSpace(out), nil
}

// RenderTenantProfilesV2 re-renders every app project's profiles from the
// tenant's current stored settings and key set (own keys + members' keys).
func (c TenantCreator) RenderTenantProfilesV2(_ context.Context, installPrefix string, tenantName string) error {
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	infraProject, infra, _, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return err
	}
	return c.renderTenantProfilesV2(server, tenantName, infraProject, infra.Config, nil)
}
