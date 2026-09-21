package authapp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/svclog"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

// TenantHeader carries the CLI's Current Tenant on every tenant-plane request
// (docs/spec/shared-tenants.md). Absent, a request acts on the caller's
// Personal Tenant — exactly the pre-Shared-Tenant behaviour — so a client
// that never sends it is unaffected.
const TenantHeader = "X-Sandcastle-Tenant"

// requestTenantHint returns the request's Current Tenant, or fallback when
// the client sent none. It does NOT authorize; requestTenant does.
func (h handler) requestTenantHint(r *http.Request, fallback string) string {
	if v := strings.TrimSpace(r.Header.Get(TenantHeader)); v != "" {
		return v
	}
	return fallback
}

// requestTenant resolves and authorizes the tenant a tenant-plane request
// acts on: the X-Sandcastle-Tenant header when present (a Shared Tenant the
// caller is a member of, or their own), else the caller's Personal Tenant.
func (h handler) requestTenant(r *http.Request, user User) (string, error) {
	tenantName := h.requestTenantHint(r, "")
	if tenantName == "" {
		return user.UserKey, nil
	}
	if err := h.authorizeWorkloadTenant(r.Context(), user.UserKey, tenantName); err != nil {
		return "", err
	}
	return tenantName, nil
}

// tenantGrantPlan is the certificate grant for one user on one tenant,
// covering the tenant's infra project and EVERY app project it has today
// (not just "default": a tenant's initial project may carry another name,
// and later projects exist beside it).
func (h handler) tenantGrantPlan(summary tenant.Summary, userKey string) (usertrust.UserPlan, error) {
	// GitHub-username tenants may start with a digit, which the strict tenant
	// reference rejects; the Personal (GitHub username) naming accepts them
	// and yields the same <prefix>-<tenant> project name.
	personal := summary.Personal || naming.ValidateTenantName(summary.Tenant) != nil
	return usertrust.PlanTenantGrant(h.admin, usertrust.TenantAccessRequest{
		Tenant:      summary.Tenant,
		User:        userKey,
		Personal:    personal,
		AppProjects: summary.ProjectShortNames(),
	})
}

// grantCertificate extends the user's restricted certificate with the plan's
// projects, fingerprint-first: the client certificate a device login recorded
// is the one live identity, so extend exactly that entry when it is known and
// fall back to the name-based grant otherwise (a login predating the record).
func (h handler) grantCertificate(ctx context.Context, plan usertrust.UserPlan, userKey string) error {
	if h.db != nil {
		if pem, _ := GetUserClientCertificate(ctx, h.db, userKey); strings.TrimSpace(pem) != "" {
			if ensurer, ok := h.tenantAccess.(interface {
				EnsureClientCertificate(context.Context, string, usertrust.UserPlan) (bool, error)
			}); ok {
				if found, err := ensurer.EnsureClientCertificate(ctx, pem, plan); err != nil {
					return err
				} else if found {
					return nil
				}
			}
		}
	}
	return usertrust.GrantMember(ctx, h.tenantAccess, h.admin, plan, userKey)
}

// grantTenantMembership is the whole "add a Tenant Member" transition:
// certificate scope, membership metadata (which re-renders the profiles), and
// the member's login key on every running machine. It is idempotent.
func (h handler) grantTenantMembership(r *http.Request, summary tenant.Summary, userKey string) error {
	ctx := r.Context()
	userKey = NormalizeGitHubUsername(userKey)
	if summary.Tenant == userKey {
		return fmt.Errorf("user %s owns tenant %s; nothing to grant", userKey, summary.Tenant)
	}
	plan, err := h.tenantGrantPlan(summary, userKey)
	if err != nil {
		return err
	}
	if err := h.grantCertificate(ctx, plan, userKey); err != nil {
		return err
	}
	if h.tenantMembers != nil {
		if _, err := h.tenantMembers.AddTenantMemberV2(ctx, h.admin.IncusProjectPrefix, summary.Tenant, userKey); err != nil {
			return err
		}
	}
	return h.reconcileMemberKeyOnMachines(ctx, summary, userKey)
}

// revokeTenantMembership reverses grantTenantMembership: certificate scope,
// membership metadata, and the member's key on running machines.
func (h handler) revokeTenantMembership(r *http.Request, summary tenant.Summary, userKey string) error {
	ctx := r.Context()
	userKey = NormalizeGitHubUsername(userKey)
	plan, err := h.tenantGrantPlan(summary, userKey)
	if err != nil {
		return err
	}
	if err := usertrust.RevokeMember(ctx, h.tenantAccess, h.admin, plan, userKey); err != nil {
		return err
	}
	if h.tenantMembers != nil {
		if _, err := h.tenantMembers.RemoveTenantMemberV2(ctx, h.admin.IncusProjectPrefix, summary.Tenant, userKey); err != nil {
			return err
		}
	}
	return h.revokeMachineSSHAccess(r, summary.Tenant, userKey)
}

// reconcileMemberKeyOnMachines enrols the member's recorded login key on the
// tenant's running machines (new machines get it from the re-rendered
// profile). No recorded key — a login predating key upload — is not an error.
func (h handler) reconcileMemberKeyOnMachines(ctx context.Context, summary tenant.Summary, userKey string) error {
	if h.machineSSHKeys == nil || h.db == nil {
		return nil
	}
	key, err := GetUserSSHKey(ctx, h.db, userKey)
	if err != nil || strings.TrimSpace(key.PublicKey) == "" {
		return nil
	}
	if err := h.machineSSHKeys.ReconcileUserSSHKey(ctx, summary, userKey, key.PublicKey); err != nil {
		return fmt.Errorf("reconcile User SSH Public Key of %s on tenant %s: %w", userKey, summary.Tenant, err)
	}
	return nil
}

// reconcileMemberSSHKeys runs at device login, after the user's key was
// stored: every Shared Tenant the user is a member of re-renders its profiles
// (the member's Personal Tenant now carries the rotated key) and enrols the
// key on its running machines. Best effort per tenant; the first failure is
// returned after the others were attempted.
func (h handler) reconcileMemberSSHKeys(ctx context.Context, userKey string, publicKey string) error {
	if h.tenants == nil || strings.TrimSpace(publicKey) == "" {
		return nil
	}
	summaries, err := tenant.ListForPrefix(ctx, h.tenants, h.admin.IncusProjectPrefix)
	if err != nil {
		return fmt.Errorf("list tenants for member SSH key reconciliation: %w", err)
	}
	userKey = NormalizeGitHubUsername(userKey)
	var firstErr error
	for _, summary := range summaries {
		if summary.Tenant == userKey || !summary.IsMember(userKey) {
			continue
		}
		if h.tenantMembers != nil {
			if err := h.tenantMembers.RenderTenantProfilesV2(ctx, h.admin.IncusProjectPrefix, summary.Tenant); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("re-render profiles of shared tenant %s: %w", summary.Tenant, err)
			}
		}
		if h.machineSSHKeys != nil {
			if err := h.machineSSHKeys.ReconcileUserSSHKey(ctx, summary, userKey, publicKey); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("reconcile User SSH Public Key on shared tenant %s: %w", summary.Tenant, err)
			}
		}
	}
	return firstErr
}

// extendMemberCertificates grants a freshly created project to every OTHER
// Tenant Member's recorded certificate, so `sc project create` by one member
// is usable by all. Failures are logged, not fatal: the project exists, and a
// member without a recorded certificate is covered by their next login.
func (h handler) extendMemberCertificates(r *http.Request, tenantName string, actor string, incusProject string) {
	if h.tenantAccess == nil || h.tenants == nil || strings.TrimSpace(incusProject) == "" {
		return
	}
	summary, err := h.findTenantSummary(r, tenantName)
	if err != nil || len(summary.Members) == 0 {
		return
	}
	actor = NormalizeGitHubUsername(actor)
	for _, member := range append([]string{summary.Tenant}, summary.Members...) {
		if member == actor {
			continue
		}
		plan := usertrust.UserPlan{
			User:            member,
			CertificateName: usertrust.RestrictedInstallName(h.admin.IncusProjectPrefix, member),
			RemoteName:      usertrust.RemoteInstallName(h.admin.IncusProjectPrefix, member),
			Restricted:      true,
			Projects:        []string{incusProject},
			Description:     "Sandcastle v2 tenant " + summary.Tenant,
		}
		if err := h.grantCertificate(r.Context(), plan, member); err != nil {
			svclog.Logf(r.Context(), "shared tenant %s: could not extend %s's certificate with %s: %v", summary.Tenant, member, incusProject, err)
		}
	}
}
