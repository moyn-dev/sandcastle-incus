package incusx

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/usertrust"
)

// fakeExtendTrust fakes usertrust.Manager (+ the EnsureClientCertificate /
// GrantTenantFleet extensions) for the tenant-plane cert-extension flow.
type fakeExtendTrust struct {
	grantErr       error
	grantCalls     int
	ensureCalls    int
	ensurePEM      string
	ensureFound    bool
	ensureErr      error
	fleetCalls     int
	fleetNamespace string
	fleetErr       error
}

func (f *fakeExtendTrust) Grant(ctx context.Context, plan usertrust.UserPlan) error {
	f.grantCalls++
	return f.grantErr
}
func (f *fakeExtendTrust) Revoke(context.Context, usertrust.UserPlan) error { return nil }
func (f *fakeExtendTrust) Delete(context.Context, usertrust.UserPlan) error { return nil }
func (f *fakeExtendTrust) ListTenantUsers(context.Context, usertrust.TenantUsersPlan) (usertrust.TenantUsersResult, error) {
	return usertrust.TenantUsersResult{}, nil
}
func (f *fakeExtendTrust) CreateToken(context.Context, usertrust.UserPlan) (usertrust.TokenResult, error) {
	return usertrust.TokenResult{}, nil
}
func (f *fakeExtendTrust) EnsureClientCertificate(ctx context.Context, pem string, plan usertrust.UserPlan) (bool, error) {
	f.ensureCalls++
	f.ensurePEM = pem
	return f.ensureFound, f.ensureErr
}
func (f *fakeExtendTrust) GrantTenantFleet(ctx context.Context, plan usertrust.UserPlan, tenantNamespace string) error {
	f.fleetCalls++
	f.fleetNamespace = tenantNamespace
	return f.fleetErr
}

var errNameMiss = fmt.Errorf("restricted certificate %q not found; create a token first and add the client certificate: %w", "sandcastle-octocat", errRestrictedCertificateNotFound)

// #115: with the caller's certificate recorded, the extension must target it by
// FINGERPRINT and never run the name-bucket Grant — a name-based grant extends
// every entry sharing the name, silently re-arming dead keypairs whose project
// names recur. The tenant's other live devices are synced via GrantTenantFleet
// (name match + already holding a tenant project) instead.
func TestExtendTenantCertificateFingerprintFirst(t *testing.T) {
	trust := &fakeExtendTrust{ensureFound: true}
	err := extendTenantCertificate(context.Background(), trust, usertrust.UserPlan{User: "octocat"}, "PEM", "sc2-octocat")
	if err != nil {
		t.Fatal(err)
	}
	if trust.ensureCalls != 1 || trust.ensurePEM != "PEM" {
		t.Fatalf("expected the fingerprint union first, got ensures=%d pem=%q", trust.ensureCalls, trust.ensurePEM)
	}
	if trust.grantCalls != 0 {
		t.Fatalf("the name-bucket Grant must NOT run when the caller's certificate was extended (#115)")
	}
	if trust.fleetCalls != 1 || trust.fleetNamespace != "sc2-octocat" {
		t.Fatalf("expected one fleet sync scoped to the tenant namespace, got calls=%d ns=%q", trust.fleetCalls, trust.fleetNamespace)
	}
}

// The live-caught cacd832 defect stays fixed: a shared keypair named after
// another tenant is reached by fingerprint even though the name would miss.
func TestExtendTenantCertificateSharedIdentityStillWorks(t *testing.T) {
	trust := &fakeExtendTrust{grantErr: errNameMiss, ensureFound: true}
	if err := extendTenantCertificate(context.Background(), trust, usertrust.UserPlan{User: "octocat"}, "PEM", "sc2-octocat"); err != nil {
		t.Fatalf("expected fingerprint union to succeed, got %v", err)
	}
	if trust.grantCalls != 0 || trust.ensureCalls != 1 {
		t.Fatalf("grants=%d ensures=%d, want 0/1", trust.grantCalls, trust.ensureCalls)
	}
}

// A recorded-but-untrusted certificate (stale record) falls back to the legacy
// name-based Grant rather than failing project create outright.
func TestExtendTenantCertificateUntrustedRecordFallsBackToGrant(t *testing.T) {
	trust := &fakeExtendTrust{ensureFound: false}
	if err := extendTenantCertificate(context.Background(), trust, usertrust.UserPlan{}, "PEM", "sc2-octocat"); err != nil {
		t.Fatal(err)
	}
	if trust.grantCalls != 1 {
		t.Fatalf("expected the legacy Grant fallback, got grants=%d", trust.grantCalls)
	}
}

// No recorded certificate (a login predating cacd832): legacy name-based Grant,
// including its not-found error surfacing.
func TestExtendTenantCertificateWithoutPEMUsesLegacyGrant(t *testing.T) {
	trust := &fakeExtendTrust{grantErr: errNameMiss}
	err := extendTenantCertificate(context.Background(), trust, usertrust.UserPlan{}, "", "sc2-octocat")
	if !errors.Is(err, errRestrictedCertificateNotFound) {
		t.Fatalf("expected the not-found error to surface, got %v", err)
	}
	if trust.ensureCalls != 0 {
		t.Fatalf("no fingerprint union without a recorded certificate")
	}
}

func TestExtendTenantCertificateEnsureErrorSurfaces(t *testing.T) {
	trust := &fakeExtendTrust{ensureErr: errors.New("boom")}
	if err := extendTenantCertificate(context.Background(), trust, usertrust.UserPlan{}, "PEM", "ns"); err == nil {
		t.Fatal("expected the union error to surface")
	}
}

// The Grant name miss must stay a recognizable sentinel for the legacy path.
func TestGrantNotFoundErrorIsSentinel(t *testing.T) {
	server := &fakeTrustServer{}
	m := TrustManager{Server: server}
	err := m.Grant(context.Background(), usertrust.UserPlan{CertificateName: "sandcastle-ghost"})
	if !errors.Is(err, errRestrictedCertificateNotFound) {
		t.Fatalf("Grant name miss must wrap errRestrictedCertificateNotFound, got %v", err)
	}
}

// GrantTenantFleet syncs the tenant's OTHER enrolled devices: same-named
// entries already holding one of the tenant's projects. Entries with no
// overlap — dead keypairs emptied by a teardown whose name recurred (#115), or
// same-named entries granting only foreign projects — are never re-armed.
func TestGrantTenantFleetSkipsDeadAndForeignEntries(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{
		// live fleet device: holds the tenant's default project → extended
		{Fingerprint: "aaa", CertificatePut: api.CertificatePut{Name: "sandcastle-octocat", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc2-octocat-default"}}},
		// holds the infra project → part of the fleet too
		{Fingerprint: "bbb", CertificatePut: api.CertificatePut{Name: "sandcastle-octocat", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc2-octocat"}}},
		// dead keypair (emptied by teardown, name recurred): NOT extended (#115)
		{Fingerprint: "ccc", CertificatePut: api.CertificatePut{Name: "sandcastle-octocat", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{}}},
		// same name but only another tenant's projects: NOT extended
		{Fingerprint: "ddd", CertificatePut: api.CertificatePut{Name: "sandcastle-octocat", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc2-other-default"}}},
		// prefix trap: sc2-octocat2-default is NOT in sc2-octocat's namespace
		{Fingerprint: "eee", CertificatePut: api.CertificatePut{Name: "sandcastle-octocat", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc2-octocat2-default"}}},
		// different name: untouched
		{Fingerprint: "fff", CertificatePut: api.CertificatePut{Name: "sandcastle-other", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc2-octocat-default"}}},
	}}
	m := TrustManager{Server: server}
	plan := usertrust.UserPlan{CertificateName: "sandcastle-octocat", Projects: []string{"sc2-octocat-api2"}, Description: "d"}
	if err := m.GrantTenantFleet(context.Background(), plan, "sc2-octocat"); err != nil {
		t.Fatal(err)
	}
	if len(server.updatedFingerprints) != 2 || server.updatedFingerprints[0] != "aaa" || server.updatedFingerprints[1] != "bbb" {
		t.Fatalf("updated = %v, want [aaa bbb]", server.updatedFingerprints)
	}
}

// An empty fleet (the caller is the tenant's only device) is a no-op, not an
// error — the caller's own certificate was already extended by fingerprint.
func TestGrantTenantFleetNoMatchesIsNoop(t *testing.T) {
	server := &fakeTrustServer{}
	m := TrustManager{Server: server}
	if err := m.GrantTenantFleet(context.Background(), usertrust.UserPlan{CertificateName: "sandcastle-octocat", Projects: []string{"p"}}, "sc2-octocat"); err != nil {
		t.Fatal(err)
	}
	if len(server.updatedFingerprints) != 0 {
		t.Fatalf("updated = %v, want none", server.updatedFingerprints)
	}
}
