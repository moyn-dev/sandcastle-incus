package authapp

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func testCertRequest(hostname string) machineCertificateRequest {
	return machineCertificateRequest{
		Hostname:     hostname,
		Tenant:       "acme",
		Project:      "baum",
		Machine:      strings.SplitN(hostname, ".", 2)[0],
		Zone:         "hase.de",
		DirectoryURL: LetsEncryptStagingDirectory,
	}
}

func TestMachineCertificateRowLifecycle(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

	if _, err := getMachineCertificate(ctx, db, "web.baum.hase.de"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("get missing = %v, want sql.ErrNoRows", err)
	}
	if _, err := requestMachineCertificate(ctx, db, machineCertificateRequest{Hostname: "x"}, now); err == nil {
		t.Fatal("incomplete request accepted")
	}

	// A fresh request is a pending row.
	row, err := requestMachineCertificate(ctx, db, testCertRequest("Web.baum.hase.de"), now)
	if err != nil {
		t.Fatal(err)
	}
	if row.Hostname != "web.baum.hase.de" || row.Tenant != "acme" || row.Project != "baum" || row.Machine != "Web" || row.Zone != "hase.de" {
		t.Fatalf("row = %+v", row)
	}
	if row.DirectoryURL != LetsEncryptStagingDirectory || !row.RequestedAt.Equal(now) || !row.CreatedAt.Equal(now) {
		t.Fatalf("row = %+v", row)
	}
	if got := machineCertificateState(row, LetsEncryptStagingDirectory, now); got != machineCertStatePending {
		t.Fatalf("state = %q, want pending", got)
	}
	if n, _ := zoneIssuanceCount(ctx, db, "hase.de", now.Add(-7*24*time.Hour)); n != 0 {
		t.Fatalf("issuance count = %d before any issuance", n)
	}

	// The reconciler records an order: cert, encrypted key, serial,
	// fingerprint, validity, fallback renew_after at 2/3 of the lifetime.
	fake := &fakeCertIssuer{now: now, lifetime: 90 * 24 * time.Hour}
	issued, err := fake.Issue(ctx, "hase.de", machineCertificateHostnames("web.baum.hase.de"))
	if err != nil {
		t.Fatal(err)
	}
	row, err = storeIssuedMachineCertificate(ctx, db, "web.baum.hase.de", issued, now)
	if err != nil {
		t.Fatal(err)
	}
	if row.CertPEM != issued.CertPEM || row.Serial == "" || len(row.Fingerprint) != 64 {
		t.Fatalf("issued row = %+v", row)
	}
	if row.EncryptedKeyPEM == issued.KeyPEM || strings.Contains(row.EncryptedKeyPEM, "PRIVATE KEY") {
		t.Fatal("key_pem must be encrypted at rest")
	}
	if keyPEM, err := machineCertificateKeyPEM(ctx, db, row); err != nil || keyPEM != issued.KeyPEM {
		t.Fatalf("decrypted key mismatch: %v", err)
	}
	if !row.NotBefore.Equal(now) || !row.NotAfter.Equal(now.Add(90*24*time.Hour)) {
		t.Fatalf("validity = %v..%v", row.NotBefore, row.NotAfter)
	}
	if want := now.Add(60 * 24 * time.Hour); !row.RenewAfter.Equal(want) {
		t.Fatalf("renew_after = %v, want %v (2/3 elapsed)", row.RenewAfter, want)
	}
	if want := now.Add(6 * time.Hour); !row.ARICheckAfter.Equal(want) {
		t.Fatalf("ari_check_after = %v, want %v", row.ARICheckAfter, want)
	}
	if got := machineCertificateState(row, LetsEncryptStagingDirectory, now); got != machineCertStateIssued {
		t.Fatalf("state = %q, want issued (not pushed yet)", got)
	}
	if n, _ := zoneIssuanceCount(ctx, db, "hase.de", now.Add(-7*24*time.Hour)); n != 1 {
		t.Fatalf("issuance count = %d, want 1", n)
	}
	if n, _ := zoneIssuanceCount(ctx, db, "hase.de", now.Add(time.Hour)); n != 0 {
		t.Fatalf("issuance count with a later window = %d, want 0", n)
	}
	if _, err := storeIssuedMachineCertificate(ctx, db, "nosuch.baum.hase.de", issued, now); err == nil {
		t.Fatal("storing on a missing row must fail")
	}

	// Pushed: installed until renew_after, renewing after.
	if _, err := db.ExecContext(ctx, "UPDATE machine_certificates SET pushed_serial = serial WHERE hostname = ?", "web.baum.hase.de"); err != nil {
		t.Fatal(err)
	}
	row, _ = getMachineCertificate(ctx, db, "web.baum.hase.de")
	if got := machineCertificateState(row, LetsEncryptStagingDirectory, now); got != machineCertStateInstalled {
		t.Fatalf("state = %q, want installed", got)
	}
	if got := machineCertificateState(row, LetsEncryptStagingDirectory, now.Add(61*24*time.Hour)); got != machineCertStateRenewing {
		t.Fatalf("state = %q, want renewing", got)
	}
	if got := machineCertificateState(row, LetsEncryptStagingDirectory, now.Add(91*24*time.Hour)); got != "failed:expired" {
		t.Fatalf("state = %q, want failed:expired", got)
	}
	// Staging and production never mix: under another directory the row
	// reads as pending (absent).
	if got := machineCertificateState(row, LetsEncryptProductionDirectory, now); got != machineCertStatePending {
		t.Fatalf("state under other directory = %q, want pending", got)
	}

	// The machine is deleted and recreated: the retained, still-valid
	// certificate is reused — pushed_serial cleared, nothing else touched.
	recreated, err := requestMachineCertificate(ctx, db, testCertRequest("web.baum.hase.de"), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if recreated.CertPEM != issued.CertPEM || recreated.Serial != row.Serial || recreated.PushedSerial != "" {
		t.Fatalf("retained row not reused: %+v", recreated)
	}
	if !recreated.RequestedAt.Equal(now.Add(24*time.Hour)) || !recreated.CreatedAt.Equal(now) {
		t.Fatalf("timestamps = requested %v created %v", recreated.RequestedAt, recreated.CreatedAt)
	}
	if got := machineCertificateState(recreated, LetsEncryptStagingDirectory, now.Add(24*time.Hour)); got != machineCertStateIssued {
		t.Fatalf("state after reuse = %q, want issued", got)
	}

	// A request under a different directory (install switched staging →
	// production) treats the row as absent: reset to a fresh pending row.
	switched := testCertRequest("web.baum.hase.de")
	switched.DirectoryURL = LetsEncryptProductionDirectory
	reset, err := requestMachineCertificate(ctx, db, switched, now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if reset.CertPEM != "" || reset.EncryptedKeyPEM != "" || reset.Serial != "" || reset.DirectoryURL != LetsEncryptProductionDirectory {
		t.Fatalf("row not reset: %+v", reset)
	}
	if got := machineCertificateState(reset, LetsEncryptProductionDirectory, now.Add(48*time.Hour)); got != machineCertStatePending {
		t.Fatalf("state after reset = %q", got)
	}

	rows, err := listMachineCertificates(ctx, db, "acme", "baum")
	if err != nil || len(rows) != 1 || rows[0].Hostname != "web.baum.hase.de" {
		t.Fatalf("list = %+v, %v", rows, err)
	}
}

func TestMachineCertificateFailedStates(t *testing.T) {
	now := time.Now()
	cases := map[string]string{
		"":                                       machineCertStatePending,
		"urn:ietf:params:acme:error:rateLimited": "failed:rate-limited",
		"waiting for DNS propagation timed out":  "failed:dns-propagation",
		"cloudflare: 403 forbidden":              "failed:cloudflare-rejected",
		"authorization failed: invalid response": "failed:validation",
		"dial tcp: connection refused":           "failed:auth-app-unreachable",
		"something else entirely":                "failed:other",
	}
	for lastError, want := range cases {
		row := machineCertificate{DirectoryURL: LetsEncryptStagingDirectory, LastError: lastError}
		if got := machineCertificateState(row, LetsEncryptStagingDirectory, now); got != want {
			t.Errorf("last_error %q → %q, want %q", lastError, got, want)
		}
	}
}

func TestMachineCertEncryptionKeyIsStableAndSeparate(t *testing.T) {
	ctx := context.Background()
	db := newClaimsTestDB(t)
	first, err := machineCertEncryptionKey(ctx, db)
	if err != nil || len(first) != 32 {
		t.Fatalf("key = %d bytes, %v", len(first), err)
	}
	second, err := machineCertEncryptionKey(ctx, db)
	if err != nil || string(second) != string(first) {
		t.Fatalf("key not stable: %v", err)
	}
	oidcKey, err := oidcEncryptionKey(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if string(oidcKey) == string(first) {
		t.Fatal("machine_cert_key must be a separate purpose-labelled key")
	}
}
