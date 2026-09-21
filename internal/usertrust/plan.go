package usertrust

import (
	"context"
	"fmt"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

const CertificateNamePrefix = "sandcastle-"

type UserPlan struct {
	User            string   `json:"user"`
	CertificateName string   `json:"certificateName"`
	RemoteName      string   `json:"remoteName"`
	Restricted      bool     `json:"restricted"`
	Projects        []string `json:"projects"`
	Description     string   `json:"description"`
}

type GrantRequest struct {
	User     string
	Projects []string
	Personal bool
	// AppProjects are the tenant's app project SHORT names to grant beside the
	// infra project. Empty means the historical default project only; pass the
	// live tenant's list (tenant.Summary.ProjectShortNames) so a grant covers
	// every project the tenant has, whatever its initial project was named.
	AppProjects []string
}

type TenantAccessRequest struct {
	Tenant   string
	User     string
	Personal bool
	// AppProjects: see GrantRequest.AppProjects.
	AppProjects []string
}

type TenantUsersPlan struct {
	Tenant       string `json:"tenant"`
	IncusProject string `json:"incusProject"`
}

type TenantUsersResult struct {
	Tenant       string   `json:"tenant"`
	IncusProject string   `json:"incusProject"`
	Users        []string `json:"users"`
}

type TokenResult struct {
	User            string   `json:"user"`
	CertificateName string   `json:"certificateName"`
	RemoteName      string   `json:"remoteName"`
	Restricted      bool     `json:"restricted"`
	Projects        []string `json:"projects"`
	Token           string   `json:"token"`
}

type Manager interface {
	Grant(context.Context, UserPlan) error
	Revoke(context.Context, UserPlan) error
	Delete(context.Context, UserPlan) error
	ListTenantUsers(context.Context, TenantUsersPlan) (TenantUsersResult, error)
	CreateToken(context.Context, UserPlan) (TokenResult, error)
}

func PlanCreateUser(user string) (UserPlan, error) {
	if err := validateUser(user); err != nil {
		return UserPlan{}, err
	}
	return UserPlan{
		User:            user,
		CertificateName: RestrictedName(user),
		RemoteName:      RestrictedName(user),
		Restricted:      true,
		Projects:        []string{},
		Description:     "Sandcastle restricted user " + user,
	}, nil
}

func PlanGrant(admin config.Admin, request GrantRequest) (UserPlan, error) {
	base, err := PlanCreateUser(request.User)
	if err != nil {
		return UserPlan{}, err
	}
	if err := admin.Validate(); err != nil {
		return UserPlan{}, err
	}
	// The trust entry a device login enrolled is named per install
	// (sandcastle-<prefix>-<user> on a --prefix install); the default install
	// keeps the historical sandcastle-<user>, so this is a no-op there.
	base.CertificateName = RestrictedInstallName(admin.IncusProjectPrefix, request.User)
	seenProjects := map[string]bool{}
	projects := make([]string, 0, len(request.Projects))
	for _, raw := range request.Projects {
		name, err := grantProjectName(admin, raw, request.Personal)
		if err != nil {
			return UserPlan{}, err
		}
		for _, project := range tenantAccessProjects(name, request.AppProjects) {
			if seenProjects[project] {
				continue
			}
			seenProjects[project] = true
			projects = append(projects, project)
		}
	}
	if len(projects) == 0 {
		return UserPlan{}, fmt.Errorf("at least one tenant is required")
	}
	base.Projects = projects
	return base, nil
}

// tenantAccessProjects lists the Incus projects a tenant's restricted user cert
// may touch. Under v2 `<prefix>-<tenant>` is the tenant's infra project, and its
// apps live in `<prefix>-<tenant>-<project>`. The v1 shape granted
// `<project>-infra` and `<project>-native` as well; neither project exists in a
// v2 tenant, so granting them made Incus reject the whole restriction list.
func tenantAccessProjects(infraProject string, appProjects []string) []string {
	projects := []string{infraProject}
	if len(appProjects) == 0 {
		return append(projects, infraProject+"-"+naming.DefaultProjectName)
	}
	for _, short := range appProjects {
		if short = strings.TrimSpace(short); short != "" {
			projects = append(projects, infraProject+"-"+short)
		}
	}
	return projects
}

func PlanTenantGrant(admin config.Admin, request TenantAccessRequest) (UserPlan, error) {
	return planTenantAccess(admin, request)
}

func PlanTenantRevoke(admin config.Admin, request TenantAccessRequest) (UserPlan, error) {
	return planTenantAccess(admin, request)
}

func PlanTenantUsers(admin config.Admin, tenant string) (TenantUsersPlan, error) {
	return PlanTenantUsersForRequest(admin, TenantAccessRequest{Tenant: tenant})
}

func PlanTenantUsersForRequest(admin config.Admin, request TenantAccessRequest) (TenantUsersPlan, error) {
	if err := admin.Validate(); err != nil {
		return TenantUsersPlan{}, err
	}
	incusProject, err := grantProjectName(admin, request.Tenant, request.Personal)
	if err != nil {
		return TenantUsersPlan{}, err
	}
	return TenantUsersPlan{Tenant: request.Tenant, IncusProject: incusProject}, nil
}

func PlanToken(user string) (UserPlan, error) {
	return PlanCreateUser(user)
}

func PlanDeleteUser(user string) (UserPlan, error) {
	return PlanCreateUser(user)
}

func RestrictedName(user string) string {
	return CertificateNamePrefix + user
}

// RestrictedInstallName returns the restricted certificate/remote name for a
// tenant of the given installation prefix. The default installation keeps the
// historical sandcastle-<tenant>; any other prefix qualifies the name
// (sandcastle-<prefix>-<tenant>) so several sandcastles sharing one Incus
// host — and their enrollments sharing one client — cannot collide on
// certificate or remote names (--prefix installs).
// RemoteInstallName is the client-side Incus remote name for a tenant
// enrollment: sc-<tenant> for the default installation, sc-<prefix>-<tenant>
// otherwise. All enrollments share one incus config dir (and one client
// keypair), so plain `incus remote switch` moves between sandcastles.
func RemoteInstallName(prefix string, user string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "sc" || prefix == naming.V2IncusProjectPrefix {
		return "sc-" + user
	}
	return "sc-" + prefix + "-" + user
}

func RestrictedInstallName(prefix string, user string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == "sc" || prefix == naming.V2IncusProjectPrefix {
		return RestrictedName(user)
	}
	return RestrictedName(prefix + "-" + user)
}

// InstallLabelFromAuthHostname derives a stable per-install label from the
// install's public Auth Hostname (its "global URL"). The label identifies the
// *install*, not the tenant: the GitHub username (tenant) is identical across
// every install on a shared host, so it cannot tell them apart — the URL can.
// The whole host is lowercased and sanitized to an Incus-safe token, with the
// scheme/port/path stripped and every non-alphanumeric run collapsed to a
// single dash: "https://obelix.thieso2.dev" -> "obelix-thieso2-dev".
func InstallLabelFromAuthHostname(authHostname string) string {
	host := strings.ToLower(strings.TrimSpace(authHostname))
	if host == "" {
		return ""
	}
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	if idx := strings.IndexAny(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.IndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	var b strings.Builder
	lastDash := true // avoids a leading dash
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// RemoteNameForAuthHostname is the client-side Incus remote name for an install
// identified by its Auth Hostname: "sc-<install-label>", e.g.
// "sc-obelix-thieso2-dev". It returns "" for a blank hostname so callers can
// fall back to the legacy tenant-based RemoteInstallName.
func RemoteNameForAuthHostname(authHostname string) string {
	label := InstallLabelFromAuthHostname(authHostname)
	if label == "" {
		return ""
	}
	return "sc-" + label
}

// RemoteNameForSuffix is the client-side incus remote name under ADR-0021: the
// install's DNS suffix alone (e.g. suffix "jules" -> "jules"), one remote per
// install. The project is no longer part of the name — it is an orthogonal pin
// that follows `sc project switch`. Returns "" for a blank suffix so callers can
// fall back to the legacy install-label / tenant naming.
func RemoteNameForSuffix(suffix string) string {
	return strings.ToLower(strings.TrimSpace(suffix))
}

// RemoteNameForSuffixProject is the SUPERSEDED (ADR-0020) client-side incus
// remote name "<dns-suffix>-<project>". Retained for migration/tests that reason
// about the old scheme; new enrollment uses RemoteNameForSuffix (ADR-0021).
func RemoteNameForSuffixProject(suffix string, project string) string {
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	project = strings.ToLower(strings.TrimSpace(project))
	if suffix == "" || project == "" {
		return ""
	}
	return suffix + "-" + project
}

func validateUser(user string) error {
	if err := naming.ValidateGitHubUsernameTenantName(user); err != nil {
		return fmt.Errorf("invalid user %q", user)
	}
	return nil
}

func grantProjectName(admin config.Admin, raw string, personal bool) (string, error) {
	if personal {
		return naming.PersonalTenantIncusProjectNameWithPrefix(admin.IncusProjectPrefix, raw)
	}
	ref, err := naming.ParseTenantRef(raw)
	if err != nil {
		return "", err
	}
	return naming.TenantIncusProjectNameWithPrefix(admin.IncusProjectPrefix, ref)
}

func planTenantAccess(admin config.Admin, request TenantAccessRequest) (UserPlan, error) {
	if err := validateUser(request.User); err != nil {
		return UserPlan{}, err
	}
	return PlanGrant(admin, GrantRequest{
		User:        request.User,
		Projects:    []string{request.Tenant},
		Personal:    request.Personal,
		AppProjects: request.AppProjects,
	})
}

// TenantMemberManager is the optional grant/revoke variant for Tenant Members
// of a Shared Tenant: it addresses the member's live device certificates by
// name OR, under shared client identity, by the member's own Personal Tenant
// projects (memberNamespace = <prefix>-<member>). Implemented by
// incusx.TrustManager.
type TenantMemberManager interface {
	GrantTenantMember(ctx context.Context, plan UserPlan, memberNamespace string) error
	RevokeTenantMember(ctx context.Context, plan UserPlan, memberNamespace string) error
}

// MemberNamespace is the infra project of a member's Personal Tenant on an
// install — the anchor by which the member's device certificates are found.
func MemberNamespace(admin config.Admin, member string) string {
	ns, err := naming.V2TenantInfraProjectName(naming.NormalizeV2Prefix(admin.IncusProjectPrefix), strings.ToLower(strings.TrimSpace(member)))
	if err != nil {
		return ""
	}
	return ns
}

// GrantMember grants via TenantMemberManager when the manager offers it,
// else the plain name-based Grant.
func GrantMember(ctx context.Context, manager interface {
	Grant(context.Context, UserPlan) error
}, admin config.Admin, plan UserPlan, member string) error {
	if mm, ok := manager.(TenantMemberManager); ok {
		return mm.GrantTenantMember(ctx, plan, MemberNamespace(admin, member))
	}
	return manager.Grant(ctx, plan)
}

// RevokeMember is GrantMember's counterpart.
func RevokeMember(ctx context.Context, manager interface {
	Revoke(context.Context, UserPlan) error
}, admin config.Admin, plan UserPlan, member string) error {
	if mm, ok := manager.(TenantMemberManager); ok {
		return mm.RevokeTenantMember(ctx, plan, MemberNamespace(admin, member))
	}
	return manager.Revoke(ctx, plan)
}
