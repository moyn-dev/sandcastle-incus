package authapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Public DNS Zones — Machine Certificates (ADR-0027, spec §1.3 / §1.5, slice 5)
//
// One row per Machine Public Hostname, retained across machine delete so a
// recreated machine is served the retained certificate instead of spending
// the 5-per-identifier-set weekly budget again. Rows are created by
// POST /api/machine-certificates (sc create) — ordering, pushing and renewal
// are the reconciler's (slice 6). The Machine Certificate state is derived
// from the row (machineCertificateState), never stored.
// ---------------------------------------------------------------------------

const machineCertificatesSchema = `
CREATE TABLE IF NOT EXISTS machine_certificates (
    hostname        TEXT PRIMARY KEY,
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    machine         TEXT NOT NULL,
    zone            TEXT NOT NULL,
    directory_url   TEXT NOT NULL,
    cert_pem        TEXT NOT NULL DEFAULT '',
    key_pem         TEXT NOT NULL DEFAULT '',
    serial          TEXT NOT NULL DEFAULT '',
    fingerprint     TEXT NOT NULL DEFAULT '',
    not_before      TEXT NOT NULL DEFAULT '',
    not_after       TEXT NOT NULL DEFAULT '',
    renew_after     TEXT NOT NULL DEFAULT '',
    ari_check_after TEXT NOT NULL DEFAULT '',
    pushed_serial   TEXT NOT NULL DEFAULT '',
    last_error      TEXT NOT NULL DEFAULT '',
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL DEFAULT '',
    requested_at    TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS machine_certificates_tenant_project ON machine_certificates(tenant, project);
`

// migrateACME creates the ACME tables (spec §1.3). Kept apart from the main
// migration block so the Public DNS Zone slices merge without touching each
// other's schema.
func migrateACME(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, acmeStorageSchema+machineCertificatesSchema); err != nil {
		return fmt.Errorf("migrate acme tables: %w", err)
	}
	return nil
}

// Machine Certificate states (spec §1.5). failed carries a reason suffix:
// machineCertStateFailed + ":" + reason.
const (
	machineCertStatePending   = "pending"
	machineCertStateIssued    = "issued"
	machineCertStateInstalled = "installed"
	machineCertStateRenewing  = "renewing"
	machineCertStateFailed    = "failed"
)

// Fixed-vocabulary failure reasons (spec §1.5). The raw error stays in
// last_error; the reason is what the CLI shows in the CERT column detail.
const (
	certFailureRateLimited        = "rate-limited"
	certFailureDNSPropagation     = "dns-propagation"
	certFailureCloudflareRejected = "cloudflare-rejected"
	certFailureValidation         = "validation"
	certFailureAuthAppUnreachable = "auth-app-unreachable"
	certFailureExpired            = "expired"
	certFailureOther              = "other"
)

// machineCertZoneWeeklyBudget is Let's Encrypt's new-certificates-per-
// registered-domain limit (spec §6); POST /api/machine-certificates answers
// 409 rate-limited once a zone's rolling 7-day count reaches it.
const machineCertZoneWeeklyBudget = 50

// machineCertificate is one machine_certificates row. Zero times stand for
// the empty-string columns.
type machineCertificate struct {
	Hostname     string
	Tenant       string
	Project      string
	Machine      string
	Zone         string
	DirectoryURL string
	CertPEM      string
	// EncryptedKeyPEM is the key_pem column: the ECDSA P-256 private key PEM,
	// AES-GCM encrypted under the machine_cert_key (spec §1.4). Decrypt with
	// machineCertificateKeyPEM.
	EncryptedKeyPEM string
	Serial          string
	Fingerprint     string
	NotBefore       time.Time
	NotAfter        time.Time
	RenewAfter      time.Time
	ARICheckAfter   time.Time
	PushedSerial    string
	LastError       string
	Attempts        int
	NextAttemptAt   time.Time
	RequestedAt     time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// hasCertificate reports whether the row holds an issued certificate.
func (c machineCertificate) hasCertificate() bool {
	return strings.TrimSpace(c.CertPEM) != ""
}

// usable reports whether the row's certificate can still serve a machine:
// issued by the running directory (staging and production never mix, spec
// §3.5) and not yet expired.
func (c machineCertificate) usable(directoryURL string, now time.Time) bool {
	return c.hasCertificate() && c.DirectoryURL == directoryURL && c.NotAfter.After(now)
}

// machineCertificateState derives the Machine Certificate state (spec §1.5)
// for a row under the running directory URL. A row issued by another
// directory is treated as absent, i.e. pending re-order.
func machineCertificateState(row machineCertificate, directoryURL string, now time.Time) string {
	if row.hasCertificate() && row.DirectoryURL != directoryURL {
		return machineCertStatePending
	}
	if !row.hasCertificate() {
		if strings.TrimSpace(row.LastError) == "" {
			return machineCertStatePending
		}
		return machineCertStateFailed + ":" + acmeFailureReason(row.LastError)
	}
	if !row.NotAfter.After(now) {
		return machineCertStateFailed + ":" + certFailureExpired
	}
	if row.PushedSerial != row.Serial {
		return machineCertStateIssued
	}
	if !row.RenewAfter.IsZero() && !now.Before(row.RenewAfter) {
		return machineCertStateRenewing
	}
	return machineCertStateInstalled
}

// acmeFailureReason maps a raw order error onto the fixed reason vocabulary.
func acmeFailureReason(rawError string) string {
	lower := strings.ToLower(rawError)
	switch {
	case strings.TrimSpace(lower) == "":
		return ""
	case strings.Contains(lower, "ratelimited") || strings.Contains(lower, "rate limit") || strings.Contains(lower, "too many"):
		return certFailureRateLimited
	case strings.Contains(lower, "propagat") || strings.Contains(lower, "not yet visible") || strings.Contains(lower, "waiting for dns"):
		return certFailureDNSPropagation
	case strings.Contains(lower, "cloudflare"):
		return certFailureCloudflareRejected
	case strings.Contains(lower, "unauthorized") || strings.Contains(lower, "validation") || strings.Contains(lower, "challenge") || strings.Contains(lower, "authorization"):
		return certFailureValidation
	case strings.Contains(lower, "unreachable") || strings.Contains(lower, "connection refused") || strings.Contains(lower, "no such host") || strings.Contains(lower, "timeout"):
		return certFailureAuthAppUnreachable
	default:
		return certFailureOther
	}
}

// machineCertificateRequest is what POST /api/machine-certificates records.
type machineCertificateRequest struct {
	Hostname     string
	Tenant       string
	Project      string
	Machine      string
	Zone         string
	DirectoryURL string
}

// requestMachineCertificate upserts the row for a hostname (spec §3.4):
//
//   - no row: a fresh pending row, requested_at = now;
//   - a retained row whose certificate is still usable: kept, with
//     pushed_serial cleared so it counts as issued and is pushed once the
//     recreated machine carries its Caddy Setup Marker (spec §4.6) — no order;
//   - any other row (never issued, expired, or issued by another directory):
//     reset to pending so the reconciler orders again.
//
// It returns the row as stored.
func requestMachineCertificate(ctx context.Context, db *sql.DB, request machineCertificateRequest, now time.Time) (machineCertificate, error) {
	hostname := strings.ToLower(strings.TrimSpace(request.Hostname))
	if hostname == "" || request.Tenant == "" || request.Project == "" || request.Machine == "" || request.Zone == "" || request.DirectoryURL == "" {
		return machineCertificate{}, fmt.Errorf("machine certificate request is incomplete")
	}
	stamp := formatCertTime(now)
	existing, err := getMachineCertificate(ctx, db, hostname)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = db.ExecContext(ctx, `
INSERT INTO machine_certificates (hostname, tenant, project, machine, zone, directory_url, requested_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`, hostname, request.Tenant, request.Project, request.Machine, request.Zone, request.DirectoryURL, stamp, stamp, stamp)
	case err != nil:
		return machineCertificate{}, err
	case existing.usable(request.DirectoryURL, now):
		_, err = db.ExecContext(ctx, `
UPDATE machine_certificates
SET tenant = ?, project = ?, machine = ?, zone = ?, pushed_serial = '', requested_at = ?, updated_at = ?
WHERE hostname = ?
`, request.Tenant, request.Project, request.Machine, request.Zone, stamp, stamp, hostname)
	default:
		_, err = db.ExecContext(ctx, `
UPDATE machine_certificates
SET tenant = ?, project = ?, machine = ?, zone = ?, directory_url = ?,
    cert_pem = '', key_pem = '', serial = '', fingerprint = '', not_before = '', not_after = '',
    renew_after = '', ari_check_after = '', pushed_serial = '', last_error = '', attempts = 0,
    next_attempt_at = '', requested_at = ?, updated_at = ?
WHERE hostname = ?
`, request.Tenant, request.Project, request.Machine, request.Zone, request.DirectoryURL, stamp, stamp, hostname)
	}
	if err != nil {
		return machineCertificate{}, err
	}
	return getMachineCertificate(ctx, db, hostname)
}

const machineCertificateColumns = `hostname, tenant, project, machine, zone, directory_url, cert_pem, key_pem, serial, fingerprint,
not_before, not_after, renew_after, ari_check_after, pushed_serial, last_error, attempts, next_attempt_at,
requested_at, created_at, updated_at`

type machineCertificateScanner interface {
	Scan(dest ...any) error
}

func scanMachineCertificate(row machineCertificateScanner) (machineCertificate, error) {
	var c machineCertificate
	var notBefore, notAfter, renewAfter, ariCheckAfter, nextAttemptAt, requestedAt, createdAt, updatedAt string
	if err := row.Scan(&c.Hostname, &c.Tenant, &c.Project, &c.Machine, &c.Zone, &c.DirectoryURL, &c.CertPEM, &c.EncryptedKeyPEM,
		&c.Serial, &c.Fingerprint, &notBefore, &notAfter, &renewAfter, &ariCheckAfter, &c.PushedSerial, &c.LastError,
		&c.Attempts, &nextAttemptAt, &requestedAt, &createdAt, &updatedAt); err != nil {
		return machineCertificate{}, err
	}
	c.NotBefore = parseCertTime(notBefore)
	c.NotAfter = parseCertTime(notAfter)
	c.RenewAfter = parseCertTime(renewAfter)
	c.ARICheckAfter = parseCertTime(ariCheckAfter)
	c.NextAttemptAt = parseCertTime(nextAttemptAt)
	c.RequestedAt = parseCertTime(requestedAt)
	c.CreatedAt = parseCertTime(createdAt)
	c.UpdatedAt = parseCertTime(updatedAt)
	return c, nil
}

// getMachineCertificate returns the row for a hostname; sql.ErrNoRows when
// there is none.
func getMachineCertificate(ctx context.Context, db *sql.DB, hostname string) (machineCertificate, error) {
	row := db.QueryRowContext(ctx, "SELECT "+machineCertificateColumns+" FROM machine_certificates WHERE hostname = ?",
		strings.ToLower(strings.TrimSpace(hostname)))
	return scanMachineCertificate(row)
}

// listMachineCertificates returns every row for a tenant project, oldest
// request first.
func listMachineCertificates(ctx context.Context, db *sql.DB, tenantName, project string) ([]machineCertificate, error) {
	rows, err := db.QueryContext(ctx, "SELECT "+machineCertificateColumns+
		" FROM machine_certificates WHERE tenant = ? AND project = ? ORDER BY requested_at, hostname", tenantName, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []machineCertificate
	for rows.Next() {
		c, err := scanMachineCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// zoneIssuanceCount is the zone's rolling count of successful issuances
// since `since` (spec §3.4: not_before > now-7d).
func zoneIssuanceCount(ctx context.Context, db *sql.DB, zone string, since time.Time) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, "SELECT count(*) FROM machine_certificates WHERE zone = ? AND not_before <> '' AND not_before > ?",
		zone, formatCertTime(since)).Scan(&n)
	return n, err
}

// storeIssuedMachineCertificate records a successful order on the row:
// certificate chain, encrypted key, serial, fingerprint, validity, and the
// ARI fallback renew_after (2/3 of the lifetime elapsed, spec §4.3). It
// resets the failure bookkeeping. The reconciler overrides renew_after and
// ari_check_after from ARI when it can.
func storeIssuedMachineCertificate(ctx context.Context, db *sql.DB, hostname string, issued issuedCertificate, now time.Time) (machineCertificate, error) {
	leaf, err := parseLeafCertificate(issued.CertPEM)
	if err != nil {
		return machineCertificate{}, err
	}
	key, err := machineCertEncryptionKey(ctx, db)
	if err != nil {
		return machineCertificate{}, err
	}
	encryptedKey, err := encryptOIDCPrivateKey(key, []byte(issued.KeyPEM))
	if err != nil {
		return machineCertificate{}, fmt.Errorf("encrypt machine certificate key: %w", err)
	}
	notBefore, notAfter := leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
	renewAfter := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3)
	result, err := db.ExecContext(ctx, `
UPDATE machine_certificates
SET cert_pem = ?, key_pem = ?, serial = ?, fingerprint = ?, not_before = ?, not_after = ?, renew_after = ?,
    ari_check_after = ?, last_error = '', attempts = 0, next_attempt_at = '', updated_at = ?
WHERE hostname = ?
`, issued.CertPEM, encryptedKey, certificateSerial(leaf), certificateFingerprint(leaf), formatCertTime(notBefore),
		formatCertTime(notAfter), formatCertTime(renewAfter), formatCertTime(now.Add(6*time.Hour)), formatCertTime(now),
		strings.ToLower(strings.TrimSpace(hostname)))
	if err != nil {
		return machineCertificate{}, err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return machineCertificate{}, fmt.Errorf("machine certificate row for %s does not exist", hostname)
	}
	return getMachineCertificate(ctx, db, hostname)
}

// machineCertificateKeyPEM decrypts the row's private key.
func machineCertificateKeyPEM(ctx context.Context, db *sql.DB, row machineCertificate) (string, error) {
	if strings.TrimSpace(row.EncryptedKeyPEM) == "" {
		return "", fmt.Errorf("machine certificate %s has no key", row.Hostname)
	}
	key, err := machineCertEncryptionKey(ctx, db)
	if err != nil {
		return "", err
	}
	plain, err := decryptOIDCPrivateKey(key, row.EncryptedKeyPEM)
	if err != nil {
		return "", fmt.Errorf("decrypt machine certificate key: %w", err)
	}
	return string(plain), nil
}

// machineCertEncryptionKeyKey is the auth_app_meta key holding the AES key
// machine private keys are sealed under (spec §1.4). Same mechanism as the
// OIDC signing keys, separate purpose-labelled key.
const machineCertEncryptionKeyKey = "machine_cert_key"

// machineCertEncryptionKey returns the machine_cert_key, creating it on first
// use exactly like oidcEncryptionKey does for its purpose.
func machineCertEncryptionKey(ctx context.Context, db *sql.DB) ([]byte, error) {
	return purposeEncryptionKey(ctx, db, machineCertEncryptionKeyKey)
}

func purposeEncryptionKey(ctx context.Context, db *sql.DB, metaKey string) ([]byte, error) {
	var encoded string
	err := db.QueryRowContext(ctx, "SELECT value FROM auth_app_meta WHERE key = ?", metaKey).Scan(&encoded)
	if err == nil {
		key, err := decodeEncryptionKey(encoded)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", metaKey, err)
		}
		return key, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	fresh, err := newEncryptionKey()
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `
INSERT INTO auth_app_meta (key, value, updated_at) VALUES (?, ?, datetime('now'))
ON CONFLICT(key) DO NOTHING
`, metaKey, fresh); err != nil {
		return nil, err
	}
	return purposeEncryptionKey(ctx, db, metaKey)
}

func newEncryptionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func decodeEncryptionKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode encryption key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key has invalid length %d", len(key))
	}
	return key, nil
}

// parseLeafCertificate returns the first certificate of a PEM chain.
func parseLeafCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate PEM has no CERTIFICATE block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	return leaf, nil
}

func certificateSerial(leaf *x509.Certificate) string {
	return strings.ToLower(leaf.SerialNumber.Text(16))
}

// certificateFingerprint is the sha256 of the leaf DER (spec §1.3), hex.
func certificateFingerprint(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:])
}

func formatCertTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseCertTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
