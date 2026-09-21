package tenant

import (
	"crypto/sha1"
	"encoding/hex"
	"net/netip"

	"github.com/thieso2/sandcastle-incus/internal/cidr"
)

const (
	HomeVolumeName      = "sc-home"
	WorkspaceVolumeName = "sc-workspace"
	CAVolumeName        = "sc-ca"
	TenantCACertPath    = "/ca.crt"
	TenantCAKeyPath     = "/ca.key"
	DNSName             = "sc-dns"

	// v2 shared volumes are per-app-project and named plain "home"/
	// "workspace" (the project scopes them; no sc- prefix).
	V2HomeVolumeName      = "home"
	V2WorkspaceVolumeName = "workspace"

	// The /.sc shared-scripts volume layers (spec #127), modeled on
	// home/workspace: per-app-project custom volumes attached to every machine.
	// Platform is mounted read-only in machines (centrally updated scripts);
	// local is tenant-writable from any machine, like /workspace.
	V2SCPlatformVolumeName = "sc-platform"
	V2SCLocalVolumeName    = "sc-local"

	// V2HomeShareProfileName is the opt-in profile that attaches the project's
	// shared /home volume. The default profile shares /workspace only; a
	// machine gets the shared home directory by being created with this
	// profile alongside default (`sc create --home-share`).
	V2HomeShareProfileName = "homeshare"
)

// TailscaleInstanceName returns the Incus instance name for the tenant's Tailscale sidecar.
// It uses the Incus project name so the host appears with the tenant identity in the Tailnet.
func TailscaleInstanceName(incusProjectName string) string {
	return incusProjectName
}

// PrivateNetworkName returns the bridge network name for a tenant. Bridge networks are subject to
// Linux's 15-char IFNAMSIZ-1 limit, so long project names use a stable hashed name instead of a
// truncation that can collide across tenants.
func PrivateNetworkName(incusProjectName string) string {
	if len(incusProjectName) <= 15 {
		return incusProjectName
	}
	sum := sha1.Sum([]byte(incusProjectName))
	return "sc-" + hex.EncodeToString(sum[:])[:12]
}

type CreateRequest struct {
	Reference     string
	SSHPublicKey  string
	OccupiedCIDRs []string
	// PreferredCIDR, when set, is used verbatim instead of allocating from the
	// pool — so re-provisioning an existing tenant reuses its /24 (idempotent)
	// rather than picking a fresh one that wouldn't match the existing bridge.
	PreferredCIDR string
	Personal      bool
	CreatedBy     string
	UnixUser      string
	// DNSSuffix is the tenant-chosen Tenant DNS Suffix (single label; defaults
	// to the tenant name). ExistingDNSSuffix carries the live tenant's stored
	// suffix on idempotent re-provisioning — the suffix is immutable (ADR-0018),
	// so a differing explicit DNSSuffix is rejected.
	DNSSuffix         string
	ExistingDNSSuffix string
	// InitialProject is the short name the user chose for their tenant's one
	// project at first login (issue #93; single label, defaults to "default").
	// ExistingDefaultProject carries the live tenant's stored default-project
	// short name on idempotent re-provisioning, so a re-login reuses it instead
	// of re-creating a duplicate "-default" project. Unlike the DNS suffix the
	// name is not immutable — the stored value is simply the reuse fallback.
	InitialProject         string
	ExistingDefaultProject string
	// ExistingUnixUser / ExistingSSHKey carry the live tenant's stored login
	// user and SSH public key on idempotent re-provisioning (#134). Like the
	// default project they are reuse fallbacks, not immutable: a blank request
	// reuses the stored value; only an explicit request replaces it. Without
	// them an admin `tenant create` re-run silently clobbered the user back to
	// "dev" and the key to empty across every app project's default profile.
	ExistingUnixUser string
	ExistingSSHKey   string
	// ExistingProjects carries the live tenant's app projects (full Incus
	// names) on idempotent re-provisioning. RestrictedProjects unions them with
	// the default project so a re-login's enrollment token — and the shared-
	// certificate extension it drives — grants EVERY project the tenant already
	// has, not just the default. Without this a fresh client certificate saw
	// only the default project while older certificates (extended one-by-one at
	// each `sc project create`) saw them all.
	ExistingProjects []string
	// Members are the Tenant Members of a Shared Tenant (normalized user keys
	// granted Tenant Access at creation, `sc-adm create tenant --member`).
	// ExistingMembers carries the live tenant's stored members on idempotent
	// re-provisioning; the plan unions both, so a re-run never drops a member
	// granted later with `sc-adm tenant grant`.
	Members         []string
	ExistingMembers []string
}

type SidecarPlan struct {
	Name       string            `json:"name"`
	Role       string            `json:"role"`
	Address    string            `json:"address"`
	ImageAlias string            `json:"imageAlias"`
	Config     map[string]string `json:"config"`
	Devices    map[string]Device `json:"devices"`
	Start      bool              `json:"start"`
}

type Device map[string]string

type TenantCA struct {
	CertificatePath string `json:"certificatePath"`
	PrivateKeyPath  string `json:"privateKeyPath"`
	CertificatePEM  []byte `json:"-"`
	PrivateKeyPEM   []byte `json:"-"`
}

func uniqueImageAliases(aliases ...string) []string {
	output := make([]string, 0, len(aliases))
	seen := map[string]bool{}
	for _, alias := range aliases {
		if alias == "" || seen[alias] {
			continue
		}
		seen[alias] = true
		output = append(output, alias)
	}
	return output
}

func roleAddress(prefix netip.Prefix, hostOctet byte) (netip.Addr, error) {
	addr, err := cidr.RoleAddress(prefix, hostOctet)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}
