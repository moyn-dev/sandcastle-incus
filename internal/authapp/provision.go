package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

type PersonalTenantProvisioner interface {
	EnsurePersonalTenant(context.Context, User, ProvisionOptions) (PersonalTenantResult, error)
}

// ProvisionOptions carries the tenant's own inputs into provisioning. The
// Tailscale auth key is the TENANT's (BYO tailnet, ADR-0017): the sidecar joins
// the tenant's tailnet, so the key travels with the login, not the service
// config (which may hold at most an optional default).
type ProvisionOptions struct {
	TailscaleAuthKey string
	// ClientCertificatePEM is the client's EXISTING shared-identity certificate
	// (if it has one): when it is already trusted by this Incus daemon (any
	// install), provisioning unions this install's projects into that trust
	// entry — token redemption alone cannot, because Incus keys trust by
	// fingerprint and the client will connect already-authenticated.
	ClientCertificatePEM string
	// DNSSuffix is the tenant-chosen Tenant DNS Suffix for first-login
	// provisioning (ADR-0018); empty means the tenant name. Immutable — a
	// re-login with a different value fails provisioning.
	DNSSuffix string
	// InitialProject is the short name the user chose for their tenant's one
	// project at first login (issue #93); empty means "default" (or the stored
	// name on re-login). Not immutable.
	InitialProject string
}

type PersonalTenantResult struct {
	UserKey           string
	Tenant            string
	IncusProject      string
	AccessibleTenants []string
	Token             string
	RemoteName        string
	// DNSSuffix is the tenant's resolved, immutable Tenant DNS Suffix — the stem
	// of the incus remote name (ADR-0020). Returned so the client can name the
	// remote and so re-login echoes the stored value.
	DNSSuffix           string
	IncusRemoteAddress  string
	TenantPrivateCIDR   string
	Projects            []string
	CurrentProject      string
	DefaultProjectReady bool
	TenantTailnetReady  bool
	// TailscaleLoginURL is the sidecar's interactive tailnet-join URL when no
	// auth key was available — the client prints it and re-polls until the
	// sidecar has a tailnet IP.
	TailscaleLoginURL string
	Message           string
}

type TrustTokenCreator interface {
	CreateToken(context.Context, usertrust.UserPlan) (usertrust.TokenResult, error)
}

// V2CreateResult is what the v2 provisioning closure reports back: the
// sidecar's tailnet IP once joined (the client's Incus Reach address), or the
// interactive login URL while the tenant hasn't joined it to a tailnet yet.
type V2CreateResult struct {
	SidecarTailnetIP  string
	TailscaleLoginURL string
}

type Provisioner struct {
	Admin           config.Admin
	Tenants         tenant.IncusTenantStore
	Trust           TrustTokenCreator
	DefaultUnixUser string
	// DB is the per-install auth database, injected by Serve. When set, first-login
	// provisioning reserves the tenant's DNS suffix in the dns_suffix_claims registry
	// (ADR-0020); nil disables the claim (e.g. unit tests without a database).
	DB *sql.DB

	// V2Create, when set, routes login provisioning through the v2 flow
	// (default project + sidecar) instead of the v1 Personal Tenant path.
	// The caller supplies the closure so this package need not import incusx.
	// The tailscaleAuthKey is the tenant's own key (may be empty → interactive
	// join, login URL returned in the result).
	V2Create func(ctx context.Context, plan tenant.CreatePlanV2, tailscaleAuthKey string) (V2CreateResult, error)
}

// ensurePersonalTenantV2 provisions (or re-ensures) the caller's v2 tenant via
// V2Create and mints a restricted enrollment token scoped to its default
// project. The SSH key is applied separately by the device flow after approval.
func (p Provisioner) ensurePersonalTenantV2(ctx context.Context, userKey string, sshPublicKey string, unixUser string, tailscaleAuthKey string, dnsSuffix string, initialProject string, clientCertificatePEM string) (PersonalTenantResult, error) {
	if p.Trust == nil {
		return PersonalTenantResult{}, fmt.Errorf("trust manager is not configured")
	}
	// Reuse this tenant's existing /24 if it was already provisioned (idempotent
	// re-login); otherwise allocate one that avoids other tenants' CIDRs. Uses
	// CIDRAllocationInputs — List+OccupiedCIDRs only surfaces v1 kind=tenant
	// projects, so it would miss every v2 tenant and let the allocator collide.
	// The stored default-project short name is reused too, so a re-login pins the
	// same project instead of re-creating a duplicate "-default" (issue #93).
	var reuse tenant.ProvisionReuse
	if p.Tenants != nil {
		if got, err := tenant.ProvisionReuseInputs(ctx, p.Tenants, p.Admin.IncusProjectPrefix, userKey); err == nil {
			reuse = got
		}
	}
	plan, err := tenant.PlanCreateV2(p.Admin, tenant.CreateRequest{
		Reference:              userKey,
		SSHPublicKey:           strings.TrimSpace(sshPublicKey),
		UnixUser:               unixUser,
		OccupiedCIDRs:          reuse.OccupiedCIDRs,
		PreferredCIDR:          reuse.OwnCIDR,
		DNSSuffix:              strings.TrimSpace(dnsSuffix),
		ExistingDNSSuffix:      reuse.DNSSuffix,
		InitialProject:         strings.TrimSpace(initialProject),
		ExistingDefaultProject: reuse.DefaultProject,
		ExistingUnixUser:       reuse.UnixUser,
		ExistingSSHKey:         reuse.SSHPublicKey,
		ExistingProjects:       reuse.Projects,
	})
	if err != nil {
		return PersonalTenantResult{}, err
	}
	// Reserve the tenant's DNS suffix in the per-install uniqueness registry
	// before provisioning commits (ADR-0020). The suffix is immutable per tenant,
	// so a taken suffix is bad user input — surface it as terminal (no retry).
	// Same-tenant re-login re-claims idempotently.
	if p.DB != nil {
		if _, err := ClaimDNSSuffix(ctx, p.DB, plan.DNSSuffix, plan.Tenant, userKey); err != nil {
			var claimErr *SuffixClaimError
			if errors.As(err, &claimErr) {
				return PersonalTenantResult{}, tenant.TerminalProvisionError{Err: err}
			}
			return PersonalTenantResult{}, err
		}
	}
	created, err := p.V2Create(ctx, plan, strings.TrimSpace(tailscaleAuthKey))
	if err != nil {
		return PersonalTenantResult{}, err
	}
	// The client-facing remote name is the tenant's DNS suffix + default project
	// ("<suffix>", ADR-0021: one remote per install) — the suffix is unique per
	// install (the claim registry) and tenant-chosen, so it disambiguates installs
	// without the GitHub username (identical everywhere); the project is an
	// orthogonal pin, not part of the name. Fall back to the legacy install-label,
	// then the tenant-based name, for older/suffix-less installs. The certificate
	// name stays prefix-keyed (server-side trust identity).
	remoteName := usertrust.RemoteNameForSuffix(plan.DNSSuffix)
	if remoteName == "" {
		remoteName = usertrust.RemoteNameForAuthHostname(p.Admin.AuthHostname)
	}
	if remoteName == "" {
		remoteName = usertrust.RemoteInstallName(plan.Prefix, plan.Tenant)
	}
	tokenPlan := usertrust.UserPlan{
		User:            plan.Tenant,
		CertificateName: usertrust.RestrictedInstallName(plan.Prefix, plan.Tenant),
		RemoteName:      remoteName,
		Restricted:      true,
		Projects:        append(plan.RestrictedProjects, p.memberTenantProjects(ctx, userKey)...),
		Description:     "Sandcastle v2 tenant " + plan.Tenant,
	}
	// Shared client identity: if the client's existing certificate is already
	// trusted (enrolled by any install on this daemon), extend it with this
	// install's projects — the token below then goes unused by the client.
	if pem := strings.TrimSpace(clientCertificatePEM); pem != "" {
		if ensurer, ok := p.Trust.(interface {
			EnsureClientCertificate(context.Context, string, usertrust.UserPlan) (bool, error)
		}); ok {
			if _, err := ensurer.EnsureClientCertificate(ctx, pem, tokenPlan); err != nil {
				return PersonalTenantResult{}, fmt.Errorf("extend shared client certificate: %w", err)
			}
		}
	}
	tok, err := p.Trust.CreateToken(ctx, tokenPlan)
	if err != nil {
		return PersonalTenantResult{}, err
	}
	message := "v2 tenant " + plan.Tenant + " is ready."
	if created.SidecarTailnetIP == "" {
		message = "v2 tenant " + plan.Tenant + " is provisioned; its sidecar is waiting to join your tailnet."
	}
	return PersonalTenantResult{
		UserKey:            userKey,
		Tenant:             plan.Tenant,
		IncusProject:       plan.DefaultProject,
		AccessibleTenants:  []string{plan.Tenant},
		Token:              tok.Token,
		RemoteName:         tok.RemoteName,
		DNSSuffix:          plan.DNSSuffix,
		IncusRemoteAddress: created.SidecarTailnetIP,
		TenantPrivateCIDR:  plan.PrivateCIDR,
		// The user-facing project list is SHORT names — the CLI pins one into
		// config.Project and resolves it back to the full Incus name via
		// Summary.V2IncusProjectName. tok.Projects are the full cert-grant names
		// (<prefix>-<tenant>-<short>); returning those verbatim made the client
		// pin "obelix-thieso2-work" instead of "work", which then failed to
		// resolve against the tenant's short project list.
		Projects:            shortProjectNames(tok.Projects, plan.DefaultProject, plan.DefaultProjectShort),
		CurrentProject:      plan.DefaultProjectShort,
		DefaultProjectReady: true,
		TenantTailnetReady:  created.SidecarTailnetIP != "",
		TailscaleLoginURL:   created.TailscaleLoginURL,
		Message:             message,
	}, nil
}

// shortProjectNames maps full Incus project names (<prefix>-<tenant>-<short>) to
// the short names the CLI pins and displays. The install/tenant prefix is
// derived from the default project's full/short pair so it also works for
// multi-project tenants (every project shares that prefix). Names that don't
// carry the prefix (or when the pair is unavailable) pass through unchanged.
func shortProjectNames(fullNames []string, defaultFull, defaultShort string) []string {
	prefix := ""
	if defaultShort != "" && strings.HasSuffix(defaultFull, "-"+defaultShort) {
		prefix = strings.TrimSuffix(defaultFull, defaultShort) // "<prefix>-<tenant>-"
	}
	out := make([]string, 0, len(fullNames))
	for _, name := range fullNames {
		if prefix != "" {
			name = strings.TrimPrefix(name, prefix)
		}
		out = append(out, name)
	}
	return out
}

func (p Provisioner) EnsurePersonalTenant(ctx context.Context, user User, options ProvisionOptions) (PersonalTenantResult, error) {
	userKey := NormalizeGitHubUsername(user.UserKey)
	if userKey == "" {
		userKey = NormalizeGitHubUsername(user.GitHubUsernameNormalized)
	}
	if err := naming.ValidateGitHubUsernameTenantName(userKey); err != nil {
		return PersonalTenantResult{}, err
	}
	if p.V2Create == nil {
		return PersonalTenantResult{}, fmt.Errorf("v2 provisioning is not configured")
	}
	return p.ensurePersonalTenantV2(ctx, userKey, user.SSHPublicKey, p.profileUnixUser(user), options.TailscaleAuthKey, options.DNSSuffix, options.InitialProject, options.ClientCertificatePEM)
}

// profileUnixUser picks the login user baked into the tenant's default profile:
// the client's Unix username from device login when it is usable, else the
// deployment default, else the built-in "dev". root and invalid names fall
// through rather than failing the login — a root-driven CI client must not
// produce a root profile user or block provisioning.
func (p Provisioner) profileUnixUser(user User) string {
	for _, candidate := range []string{strings.TrimSpace(user.LocalUnixUser), strings.TrimSpace(p.DefaultUnixUser)} {
		if candidate == "" || candidate == "root" {
			continue
		}
		if err := naming.ValidateUnixUsername(candidate); err != nil {
			continue
		}
		return candidate
	}
	return tenant.DefaultV2UnixUser
}

func (r PersonalTenantResult) normalizedMessage() string {
	if strings.TrimSpace(r.Message) != "" {
		return r.Message
	}
	if r.Tenant != "" {
		return "Personal tenant " + r.Tenant + " is ready."
	}
	return "Personal tenant is ready."
}

// memberTenantProjects lists the Incus projects of every Shared Tenant the
// user is already a member of: its infra project and every app project. A
// login is where a device's certificate is minted (the token) or extended
// (a shared client identity), and a certificate that covered only the
// Personal Tenant left a member unable to reach a tenant they were granted
// before this device existed — `sc tunnel publish` in the shared project
// answered "User does not have permission" although `sc tenant list` showed
// the membership. Unreadable tenant state degrades to the personal set.
func (p Provisioner) memberTenantProjects(ctx context.Context, userKey string) []string {
	if p.Tenants == nil {
		return nil
	}
	summaries, err := tenant.ListForPrefix(ctx, p.Tenants, p.Admin.IncusProjectPrefix)
	if err != nil {
		return nil
	}
	normalized := strings.ToLower(strings.TrimSpace(userKey))
	projects := []string{}
	for _, summary := range summaries {
		if summary.Tenant == normalized || !summary.IsMember(normalized) {
			continue
		}
		projects = append(projects, summary.InfraProject)
		for _, short := range summary.ProjectShortNames() {
			projects = append(projects, summary.V2IncusProjectName(short))
		}
	}
	return projects
}
