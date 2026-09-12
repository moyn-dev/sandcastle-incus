package authapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// fakeCertIssuer is the test certIssuer: it mints a self-signed certificate
// carrying exactly the requested SANs (or fails with err) and records calls.
type fakeCertIssuer struct {
	mu       sync.Mutex
	calls    []fakeIssueCall
	err      error
	lifetime time.Duration
	now      time.Time

	renewAfter time.Time
	retryAfter time.Time
	renewErr   error
}

type fakeIssueCall struct {
	Zone      string
	Hostnames []string
}

var _ certIssuer = (*fakeCertIssuer)(nil)

func (f *fakeCertIssuer) Issue(_ context.Context, zone string, hostnames []string) (issuedCertificate, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fakeIssueCall{Zone: zone, Hostnames: append([]string(nil), hostnames...)})
	f.mu.Unlock()
	if f.err != nil {
		return issuedCertificate{}, f.err
	}
	now := f.now
	if now.IsZero() {
		now = time.Now()
	}
	lifetime := f.lifetime
	if lifetime == 0 {
		lifetime = 90 * 24 * time.Hour
	}
	return mintTestCertificate(hostnames, now, now.Add(lifetime))
}

func (f *fakeCertIssuer) RenewalInfo(context.Context, string) (time.Time, time.Time, error) {
	return f.renewAfter, f.retryAfter, f.renewErr
}

// mintTestCertificate self-signs a certificate for hostnames with a fresh
// P-256 key — the shape a real order returns, minus the chain.
func mintTestCertificate(hostnames []string, notBefore, notAfter time.Time) (issuedCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issuedCertificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		return issuedCertificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostnames[0]},
		DNSNames:     hostnames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return issuedCertificate{}, err
	}
	keyPEM, err := certmagic.PEMEncodePrivateKey(key)
	if err != nil {
		return issuedCertificate{}, err
	}
	return issuedCertificate{
		CertPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:    string(keyPEM),
		NotBefore: notBefore.UTC(),
		NotAfter:  notAfter.UTC(),
	}, nil
}

func TestFakeIssuerMintsBothSANs(t *testing.T) {
	fake := &fakeCertIssuer{}
	issued, err := fake.Issue(context.Background(), "hase.de", machineCertificateHostnames("web.baum.hase.de"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := parseLeafCertificate(issued.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"web.baum.hase.de", "*.web.baum.hase.de"}; !reflect.DeepEqual(leaf.DNSNames, want) {
		t.Fatalf("SANs = %v, want %v", leaf.DNSNames, want)
	}
	if _, err := certmagic.PEMDecodePrivateKey([]byte(issued.KeyPEM)); err != nil {
		t.Fatalf("key PEM: %v", err)
	}
	if len(fake.calls) != 1 || fake.calls[0].Zone != "hase.de" {
		t.Fatalf("calls = %+v", fake.calls)
	}
	fake.err = errors.New("urn:ietf:params:acme:error:rateLimited: too many certificates")
	if _, err := fake.Issue(context.Background(), "hase.de", nil); err == nil {
		t.Fatal("configured error not returned")
	}
}

func TestMachineCertificateCSR(t *testing.T) {
	csr, key, err := machineCertificateCSR([]string{" Web.baum.hase.de ", "*.web.baum.hase.de"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"web.baum.hase.de", "*.web.baum.hase.de"}; !reflect.DeepEqual(csr.DNSNames, want) {
		t.Fatalf("CSR SANs = %v, want %v", csr.DNSNames, want)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("key curve = %v, want P-256", key.Curve.Params().Name)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if _, _, err := machineCertificateCSR(nil); err == nil {
		t.Fatal("empty hostnames accepted")
	}
	if got := machineCertificateHostnames("Web.baum.hase.de"); !reflect.DeepEqual(got, []string{"web.baum.hase.de", "*.web.baum.hase.de"}) {
		t.Fatalf("machineCertificateHostnames = %v", got)
	}
}

func TestNormalizeACMEDirectory(t *testing.T) {
	if got, err := NormalizeACMEDirectory(""); err != nil || got != LetsEncryptProductionDirectory {
		t.Fatalf("empty = %q, %v", got, err)
	}
	if got, err := NormalizeACMEDirectory(" " + LetsEncryptStagingDirectory + " "); err != nil || got != LetsEncryptStagingDirectory {
		t.Fatalf("staging = %q, %v", got, err)
	}
	for _, bad := range []string{"acme-v02.api.letsencrypt.org/directory", "ftp://x/y", "https://"} {
		if _, err := NormalizeACMEDirectory(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if got := handlerACMEDirectory("garbage"); got != LetsEncryptProductionDirectory {
		t.Fatalf("handlerACMEDirectory(garbage) = %q", got)
	}
}

// The certmagic issuer is configured per spec §3.5: the install directory as
// CA (and TestCA, so a retry can never switch environments), the account
// contact, DNS-01 only through libdns/cloudflare with the zone's token, and
// one cached issuer per zone over one shared Storage.
func TestACMEIssuerPerZoneConfiguration(t *testing.T) {
	db := newClaimsTestDB(t)
	tokens := map[string]string{"hase.de": "cf-token-hase", "igel.de": "cf-token-igel"}
	lookups := 0
	issuer := newACMEIssuer(db, LetsEncryptStagingDirectory, "ops@example.com", func(_ context.Context, zone string) (string, error) {
		lookups++
		token, ok := tokens[zone]
		if !ok {
			return "", errors.New("unknown zone")
		}
		return token, nil
	})

	first, err := issuer.issuerForZone(context.Background(), "Hase.DE")
	if err != nil {
		t.Fatal(err)
	}
	if first.CA != LetsEncryptStagingDirectory || first.TestCA != LetsEncryptStagingDirectory {
		t.Fatalf("CA/TestCA = %q/%q", first.CA, first.TestCA)
	}
	if first.Email != "ops@example.com" || !first.Agreed {
		t.Fatalf("Email/Agreed = %q/%v", first.Email, first.Agreed)
	}
	if !first.DisableHTTPChallenge || !first.DisableTLSALPNChallenge {
		t.Fatal("HTTP-01/TLS-ALPN-01 must be disabled: DNS-01 only")
	}
	solver, ok := first.DNS01Solver.(*certmagic.DNS01Solver)
	if !ok {
		t.Fatalf("DNS01Solver = %T", first.DNS01Solver)
	}
	provider, ok := solver.DNSProvider.(*cloudflare.Provider)
	if !ok || provider.APIToken != "cf-token-hase" {
		t.Fatalf("provider = %#v", solver.DNSProvider)
	}
	if solver.TTL != 60*time.Second {
		t.Fatalf("TTL = %v", solver.TTL)
	}
	if _, ok := issuer.config.Storage.(*sqliteStorage); !ok {
		t.Fatalf("Storage = %T, want sqliteStorage", issuer.config.Storage)
	}

	again, err := issuer.issuerForZone(context.Background(), "hase.de")
	if err != nil || again != first {
		t.Fatalf("second lookup = %p, %v; want cached %p", again, err, first)
	}
	if lookups != 1 {
		t.Fatalf("token lookups = %d, want 1 (cached)", lookups)
	}
	other, err := issuer.issuerForZone(context.Background(), "igel.de")
	if err != nil || other == first {
		t.Fatalf("igel.de issuer = %p, %v", other, err)
	}
	if _, err := issuer.issuerForZone(context.Background(), "nosuch.example"); err == nil || !strings.Contains(err.Error(), "unknown zone") {
		t.Fatalf("unknown zone = %v", err)
	}
	issuer.forgetZone("hase.de")
	if _, err := issuer.issuerForZone(context.Background(), "hase.de"); err != nil || lookups != 4 {
		t.Fatalf("after forgetZone: err=%v lookups=%d", err, lookups)
	}

	noTokens := newACMEIssuer(db, LetsEncryptStagingDirectory, "", nil)
	if _, err := noTokens.Issue(context.Background(), "hase.de", machineCertificateHostnames("web.baum.hase.de")); err == nil {
		t.Fatal("Issue without a token source must fail before any ACME call")
	}
}
