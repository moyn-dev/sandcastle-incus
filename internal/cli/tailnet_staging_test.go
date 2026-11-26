package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func stagingTestLeaf(t *testing.T, issuerCN, dnsName string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: issuerCN},
		Issuer:       pkix.Name{CommonName: issuerCN},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestVerifyStagingLeafAcceptsOnlyAValidLetsEncryptStagingLeaf(t *testing.T) {
	now := time.Now()
	state := func(c *x509.Certificate) tls.ConnectionState {
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	}
	host := "tailnet-x.moyn-dev.net"
	if err := verifyStagingLeaf(state(stagingTestLeaf(t, "(STAGING) Pseudo Plum E5", host, now.Add(time.Hour))), host, now); err != nil {
		t.Fatalf("staging leaf for the name: %v", err)
	}
	for name, leaf := range map[string]*x509.Certificate{
		"not staging":  stagingTestLeaf(t, "Some Private CA", host, now.Add(time.Hour)),
		"another name": stagingTestLeaf(t, "(STAGING) Pseudo Plum E5", "other.moyn-dev.net", now.Add(time.Hour)),
		"expired":      stagingTestLeaf(t, "(STAGING) Pseudo Plum E5", host, now.Add(-time.Minute)),
	} {
		if err := verifyStagingLeaf(state(leaf), host, now); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := verifyStagingLeaf(tls.ConnectionState{}, host, now); err == nil {
		t.Fatal("no peer certificate accepted")
	}
}
