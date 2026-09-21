package authapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ---------------------------------------------------------------------------
// Public DNS Zones — ACME issuer (ADR-0027, spec §3.5, slice 5)
//
// certmagic is used as an issuer library: one ACMEIssuer per zone (the
// libdns/cloudflare provider is token-bound), all sharing one certmagic
// Config whose Storage is the acme_storage table, so the ACME account (one
// per install per directory URL, contact = --acme-email) is shared across
// zones. Every order is ONE CSR carrying <m>.<pd> and *.<m>.<pd>, handed to
// ACMEIssuer.Issue — never ManageSync/ManageAsync, which would order one
// certificate per name and spend the zone budget twice per machine.
// ---------------------------------------------------------------------------

// Let's Encrypt ACME directories (spec §2.6, §6). Production is the default
// for --acme-directory; e2e passes staging.
const (
	LetsEncryptProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingDirectory    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// NormalizeACMEDirectory resolves the install-level --acme-directory setting:
// empty selects Let's Encrypt production; anything else must be an absolute
// http(s) URL (a directory URL is the only thing an ACME client dials).
func NormalizeACMEDirectory(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return LetsEncryptProductionDirectory, nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return "", fmt.Errorf("acme directory %q must be an absolute http(s) URL", value)
	}
	return value, nil
}

// handlerACMEDirectory is NormalizeACMEDirectory for handler construction,
// where the value was already validated by PlanServe (or is a test's): an
// invalid value falls back to production rather than failing NewHandler.
func handlerACMEDirectory(value string) string {
	directory, err := NormalizeACMEDirectory(value)
	if err != nil {
		return LetsEncryptProductionDirectory
	}
	return directory
}

// issuedCertificate is what an order yields: the full PEM chain, the PEM
// private key (ECDSA P-256, generated on the appliance) and the leaf's
// validity.
type issuedCertificate struct {
	CertPEM   string
	KeyPEM    string
	NotBefore time.Time
	NotAfter  time.Time
}

// certIssuer is the ACME seam (spec §3.5): the certmagic-backed acmeIssuer
// is the only production implementation; unit tests use a fake.
type certIssuer interface {
	// Issue orders one certificate for hostnames (base + wildcard of one
	// Machine Public Hostname) validated by DNS-01 in zone.
	Issue(ctx context.Context, zone string, hostnames []string) (issuedCertificate, error)
	// RenewalInfo asks the CA's ARI endpoint for the certificate's suggested
	// renewal window start and the Retry-After for the next ARI check (zero
	// when the CA sent none).
	RenewalInfo(ctx context.Context, certPEM string) (renewAfter, retryAfter time.Time, err error)
}

// zoneTokenSource yields the Cloudflare API token of a registered Public DNS
// Zone (decrypted from public_dns_zones). Injected so the issuer does not own
// the zone registry.
type zoneTokenSource func(ctx context.Context, zone string) (string, error)

// acmeIssuer is the certmagic-backed certIssuer.
type acmeIssuer struct {
	directory string
	email     string
	config    *certmagic.Config
	tokens    zoneTokenSource
	logger    *zap.Logger

	mu      sync.Mutex
	issuers map[string]*certmagic.ACMEIssuer
}

var _ certIssuer = (*acmeIssuer)(nil)

// newACMEIssuer builds the issuer over the auth database: acme_storage is
// its certmagic Storage, directory the install's --acme-directory, email the
// --acme-email account contact. Per-zone ACMEIssuers are created lazily by
// issuerForZone and cached.
func newACMEIssuer(db *sql.DB, directory, email string, tokens zoneTokenSource) *acmeIssuer {
	logger := acmeLogger()
	return &acmeIssuer{
		directory: directory,
		email:     strings.TrimSpace(email),
		config:    &certmagic.Config{Storage: newSQLiteStorage(db), Logger: logger},
		tokens:    tokens,
		logger:    logger,
		issuers:   map[string]*certmagic.ACMEIssuer{},
	}
}

// acmeLogger is certmagic's mandatory zap logger, writing to stderr (journald
// under systemd) like the rest of the Auth App.
func acmeLogger() *zap.Logger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(zapcore.NewConsoleEncoder(encoderConfig), zapcore.Lock(zapcore.AddSync(os.Stderr)), zap.InfoLevel)
	return zap.New(core).Named("auth-app.acme")
}

// acmeIssuerTemplate is the per-zone ACMEIssuer configuration (spec §3.5):
// DNS-01 only, through libdns/cloudflare with the zone's token, TTL 60s, and
// certmagic's authoritative-nameserver propagation wait (never a fixed
// sleep). TestCA is pinned to the same directory so a certmagic retry can
// never silently switch a production install to staging or vice versa.
func acmeIssuerTemplate(directory, email, zoneToken string, logger *zap.Logger) certmagic.ACMEIssuer {
	return certmagic.ACMEIssuer{
		CA:                      directory,
		TestCA:                  directory,
		Email:                   email,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider: &cloudflare.Provider{APIToken: zoneToken},
			TTL:         60 * time.Second,
			Logger:      logger,
		}},
		Logger: logger,
	}
}

// issuerForZone returns the cached ACMEIssuer for zone, creating it on first
// use with the zone's current token.
func (a *acmeIssuer) issuerForZone(ctx context.Context, zone string) (*certmagic.ACMEIssuer, error) {
	zone = strings.ToLower(strings.TrimSpace(zone))
	if zone == "" {
		return nil, fmt.Errorf("acme: zone is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if issuer, ok := a.issuers[zone]; ok {
		return issuer, nil
	}
	if a.tokens == nil {
		return nil, fmt.Errorf("acme: no zone token source configured")
	}
	token, err := a.tokens(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("acme: token for zone %s: %w", zone, err)
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("acme: zone %s has no token", zone)
	}
	issuer := certmagic.NewACMEIssuer(a.config, acmeIssuerTemplate(a.directory, a.email, token, a.logger))
	a.issuers[zone] = issuer
	return issuer, nil
}

// forgetZone drops the cached issuer for a zone (token rotated or zone
// removed); the next order rebuilds it.
func (a *acmeIssuer) forgetZone(zone string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.issuers, strings.ToLower(strings.TrimSpace(zone)))
}

// Issue orders one certificate for hostnames via ACMEIssuer.Issue with a
// single CSR carrying every name. The key never leaves the appliance except
// inside the encrypted machine_certificates row and the push to the machine.
func (a *acmeIssuer) Issue(ctx context.Context, zone string, hostnames []string) (issuedCertificate, error) {
	issuer, err := a.issuerForZone(ctx, zone)
	if err != nil {
		return issuedCertificate{}, err
	}
	csr, key, err := machineCertificateCSR(hostnames)
	if err != nil {
		return issuedCertificate{}, err
	}
	issued, err := issuer.Issue(ctx, csr)
	if err != nil {
		return issuedCertificate{}, err
	}
	keyPEM, err := certmagic.PEMEncodePrivateKey(key)
	if err != nil {
		return issuedCertificate{}, fmt.Errorf("encode machine certificate key: %w", err)
	}
	leaf, err := parseLeafCertificate(string(issued.Certificate))
	if err != nil {
		return issuedCertificate{}, err
	}
	return issuedCertificate{
		CertPEM:   string(issued.Certificate),
		KeyPEM:    string(keyPEM),
		NotBefore: leaf.NotBefore.UTC(),
		NotAfter:  leaf.NotAfter.UTC(),
	}, nil
}

// RenewalInfo fetches ARI for the certificate. ARI needs no account and no
// solver, so it goes through a token-less issuer for the directory.
func (a *acmeIssuer) RenewalInfo(ctx context.Context, certPEM string) (time.Time, time.Time, error) {
	leaf, err := parseLeafCertificate(certPEM)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	issuer := certmagic.NewACMEIssuer(a.config, certmagic.ACMEIssuer{CA: a.directory, TestCA: a.directory, Email: a.email, Agreed: true, Logger: a.logger})
	info, err := issuer.GetRenewalInfo(ctx, certmagic.Certificate{Certificate: tls.Certificate{Leaf: leaf}})
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	var retryAfter time.Time
	if info.RetryAfter != nil {
		retryAfter = info.RetryAfter.UTC()
	}
	return info.SuggestedWindow.Start.UTC(), retryAfter, nil
}

// machineCertificateCSR generates a fresh ECDSA P-256 key and a CSR whose
// SANs are exactly hostnames — the one two-SAN order per machine.
func machineCertificateCSR(hostnames []string) (*x509.CertificateRequest, *ecdsa.PrivateKey, error) {
	names := make([]string, 0, len(hostnames))
	for _, name := range hostnames {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("acme: at least one hostname is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate machine certificate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate request: %w", err)
	}
	return csr, key, nil
}

// machineCertificateHostnames are the SANs of one Machine Certificate: the
// Machine Public Hostname and its one-level wildcard (spec §3.5).
func machineCertificateHostnames(publicHostname string) []string {
	publicHostname = strings.ToLower(strings.TrimSpace(publicHostname))
	if strings.HasPrefix(publicHostname, "*.") {
		return []string{publicHostname}
	}
	return []string{publicHostname, "*." + publicHostname}
}
