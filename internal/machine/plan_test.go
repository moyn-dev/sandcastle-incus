package machine

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/certs"
)

// The v1 machine planner is gone; these helpers survive because the v2 sidecar
// leaf signer and the DNS/hostname paths use them.
func TestMachineHostname(t *testing.T) {
	if got := MachineHostname("web", "default", "castle"); got != "web.default.castle" {
		t.Fatalf("MachineHostname = %q", got)
	}
	if got := ShortMachineHostname("web", "default"); got != "web.default" {
		t.Fatalf("ShortMachineHostname = %q", got)
	}
}

func TestIssueCertificateFilesCoversMachineAndWildcard(t *testing.T) {
	caCert, caKey := testCA(t)
	files, err := IssueCertificateFiles("web", "default", "castle", caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("expected certificate files")
	}
	var leaf *x509.Certificate
	for _, f := range files {
		if block, _ := pem.Decode(f.Content); block != nil && block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil && !c.IsCA {
				leaf = c
			}
		}
	}
	if leaf == nil {
		t.Fatal("no leaf certificate issued")
	}
	names := strings.Join(leaf.DNSNames, ",")
	if !strings.Contains(names, "web.default.castle") {
		t.Fatalf("SANs = %q, want the machine FQDN", names)
	}
}

func testCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	ca, err := certs.GenerateCA("Sandcastle castle tenant CA", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca.CertificatePEM, ca.PrivateKeyPEM
}
