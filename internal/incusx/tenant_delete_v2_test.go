package incusx

import (
	"testing"

	"github.com/lxc/incus/v6/shared/api"
)

// fakeTrustDeleteServer stubs TenantDeleteServer for the trust sweep; the
// project/instance methods are unused by sweepTenantTrustEntries.
type fakeTrustDeleteServer struct {
	certificates []api.Certificate
	deleted      []string
}

func (f *fakeTrustDeleteServer) GetProjects() ([]api.Project, error) { return nil, nil }
func (f *fakeTrustDeleteServer) DeleteProject(string) error          { return nil }
func (f *fakeTrustDeleteServer) DeleteStoragePool(string) error      { return nil }
func (f *fakeTrustDeleteServer) UseProject(string) TenantDeleteResourceServer {
	return nil
}
func (f *fakeTrustDeleteServer) GetCertificates() ([]api.Certificate, error) {
	return f.certificates, nil
}
func (f *fakeTrustDeleteServer) DeleteCertificate(fingerprint string) error {
	f.deleted = append(f.deleted, fingerprint)
	return nil
}

// #113: purging a tenant must delete the tenant's restricted trust entries —
// but ONLY those left with no projects once this tenant's are gone. A shared
// client keypair's entry can be NAMED after this tenant while still granting
// another tenant's projects (shared client identity); that entry must survive.
func TestSweepTenantTrustEntries(t *testing.T) {
	server := &fakeTrustDeleteServer{certificates: []api.Certificate{
		// orphaned by this delete: named for the tenant, no projects left
		{Fingerprint: "aaa", CertificatePut: api.CertificatePut{Name: "sandcastle-acme", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{}}},
		// Incus not yet caught up: still lists only this tenant's own projects
		{Fingerprint: "bbb", CertificatePut: api.CertificatePut{Name: "sandcastle-acme", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc2-acme-default", "sc2-acme"}}},
		// shared identity: named for this tenant but still granting another tenant
		{Fingerprint: "ccc", CertificatePut: api.CertificatePut{Name: "sandcastle-acme", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc2-acme-default", "sc2-other-default"}}},
		// another tenant's entry: untouched even though its projects are empty
		{Fingerprint: "ddd", CertificatePut: api.CertificatePut{Name: "sandcastle-other", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{}}},
		// non-client / unrestricted entries: never touched
		{Fingerprint: "eee", CertificatePut: api.CertificatePut{Name: "sandcastle-acme", Type: "metrics", Restricted: true, Projects: []string{}}},
		{Fingerprint: "fff", CertificatePut: api.CertificatePut{Name: "sandcastle-acme", Type: api.CertificateTypeClient, Restricted: false, Projects: []string{}}},
	}}
	d := TenantDeleter{}
	err := d.sweepTenantTrustEntries(server, "sandcastle-acme", map[string]bool{
		"sc2-acme":         true,
		"sc2-acme-default": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(server.deleted) != 2 || server.deleted[0] != "aaa" || server.deleted[1] != "bbb" {
		t.Fatalf("deleted = %v, want [aaa bbb]", server.deleted)
	}
}

// An empty trust-entry name (no plan data) must be a no-op, not a sweep of
// unnamed certificates.
func TestSweepTenantTrustEntriesNoName(t *testing.T) {
	server := &fakeTrustDeleteServer{certificates: []api.Certificate{
		{Fingerprint: "aaa", CertificatePut: api.CertificatePut{Name: "", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{}}},
	}}
	d := TenantDeleter{}
	if err := d.sweepTenantTrustEntries(server, "", nil); err != nil {
		t.Fatal(err)
	}
	if len(server.deleted) != 0 {
		t.Fatalf("deleted = %v, want none", server.deleted)
	}
}
