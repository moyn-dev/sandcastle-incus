package incusx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/usertrust"
)

// selfSignedClientCert returns a fresh client certificate as PEM plus the
// SHA-256-of-DER fingerprint Incus keys its trust store by.
func selfSignedClientCert(t *testing.T) (pemText string, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "thies@laptop"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

// Regression for the obelix live incident (2026-07-17): a tenant's restricted
// certificate is trusted under a name from a DIFFERENT install prefix than the
// broker now uses — cert `sandcastle-tc2-thieso2`, but the broker (prefix
// `obelix`) plans for `sandcastle-obelix-thieso2`. The name-based Grant can
// never find that name; EnsureClientCertificate must reach the real entry BY
// FINGERPRINT regardless of the name mismatch, union the new project in, and
// report found=true (so extendTenantCertificate skips the failing name Grant).
//
// This method was previously only ever faked (projectbroker_adapter_test.go);
// nothing pinned that a real name-mismatched entry is matched by fingerprint.
func TestEnsureClientCertificateMatchesByFingerprintAcrossNameDrift(t *testing.T) {
	certPEM, fingerprint := selfSignedClientCert(t)
	server := &fakeTrustServer{certificates: []api.Certificate{{
		Fingerprint: fingerprint,
		CertificatePut: api.CertificatePut{
			Name:       "sandcastle-tc2-thieso2", // enrolled under the tc2 prefix
			Type:       api.CertificateTypeClient,
			Restricted: true,
			Projects:   []string{"obelix-thieso2-work"},
		},
	}}}
	manager := TrustManager{Server: server}

	found, err := manager.EnsureClientCertificate(context.Background(), certPEM, usertrust.UserPlan{
		User:            "thieso2",
		CertificateName: "sandcastle-obelix-thieso2", // broker's prefix-derived name — NOT in the store
		Restricted:      true,
		Projects:        []string{"obelix-thieso2-scraper"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("found = false; the fingerprint match must succeed despite the certificate-name drift")
	}
	if server.updated == nil {
		t.Fatal("expected the matched certificate to be updated with the new project")
	}
	if server.updated.Name != "sandcastle-tc2-thieso2" {
		t.Fatalf("update renamed the entry to %q; the stored (fingerprint-matched) name must be preserved", server.updated.Name)
	}
	if !containsProject(server.updated.Projects, "obelix-thieso2-work") ||
		!containsProject(server.updated.Projects, "obelix-thieso2-scraper") {
		t.Fatalf("Projects = %#v, want the existing work project plus the new scraper project unioned in", server.updated.Projects)
	}
}

// The counterpart: when no trusted entry carries the caller's fingerprint (a
// stale/rotated keypair), EnsureClientCertificate reports found=false without
// touching the store — extendTenantCertificate then takes the legacy name Grant.
func TestEnsureClientCertificateReportsNotFoundForUntrustedFingerprint(t *testing.T) {
	certPEM, _ := selfSignedClientCert(t)
	other, otherFP := selfSignedClientCert(t)
	_ = other
	server := &fakeTrustServer{certificates: []api.Certificate{{
		Fingerprint:    otherFP, // some other keypair, not the caller's
		CertificatePut: api.CertificatePut{Name: "sandcastle-thieso2", Type: api.CertificateTypeClient, Restricted: true},
	}}}
	manager := TrustManager{Server: server}

	found, err := manager.EnsureClientCertificate(context.Background(), certPEM, usertrust.UserPlan{
		CertificateName: "sandcastle-obelix-thieso2",
		Projects:        []string{"obelix-thieso2-scraper"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("found = true for an untrusted fingerprint; want false so the legacy Grant path runs")
	}
	if len(server.updatedFingerprints) != 0 {
		t.Fatalf("updated = %v, want no writes when the fingerprint is not trusted", server.updatedFingerprints)
	}
}
