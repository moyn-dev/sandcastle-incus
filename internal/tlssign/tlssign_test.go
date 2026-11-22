package tlssign

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/certs"
)

func testCA(t *testing.T) certs.KeyPair {
	t.Helper()
	ca, err := certs.GenerateCA("test tenant CA", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestHandlerLeafSignedByCAWithWildcard(t *testing.T) {
	ca := testCA(t)
	srv := httptest.NewServer(Handler(ca.CertificatePEM, ca.PrivateKeyPEM, "idefix", nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/tls/leaf?fqdn=ct1.default.idefix")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out leafResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(out.Cert))
	if block == nil {
		t.Fatal("no cert PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// SANs cover the machine and its wildcard.
	got := map[string]bool{}
	for _, n := range leaf.DNSNames {
		got[n] = true
	}
	if !got["ct1.default.idefix"] || !got["*.ct1.default.idefix"] {
		t.Fatalf("SANs = %v, want ct1.default.idefix + *.ct1.default.idefix", leaf.DNSNames)
	}
	// Chains to the CA.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertificatePEM) {
		t.Fatal("append CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "foo.ct1.default.idefix"}); err != nil {
		t.Fatalf("wildcard verify: %v", err)
	}
}

func TestHandlerRejectsOutOfZone(t *testing.T) {
	ca := testCA(t)
	srv := httptest.NewServer(Handler(ca.CertificatePEM, ca.PrivateKeyPEM, "idefix", nil))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/tls/leaf?fqdn=www.google.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for out-of-zone name", resp.StatusCode)
	}
}

func TestHandlerServesCA(t *testing.T) {
	ca := testCA(t)
	srv := httptest.NewServer(Handler(ca.CertificatePEM, ca.PrivateKeyPEM, "idefix", nil))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/tls/ca")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, len(ca.CertificatePEM))
	_, _ = resp.Body.Read(body)
	if string(body) != string(ca.CertificatePEM) {
		t.Fatal("CA endpoint did not return the CA cert")
	}
}
