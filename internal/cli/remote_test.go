package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

func TestTrustedClientRemoteAddArgsPinsProject(t *testing.T) {
	// Shared identity across installs: the cert-based fallback MUST pass
	// --project, or `incus remote add` prompts interactively for the project
	// (the trusted cert can see several installs' projects) and fails on EOF in
	// a non-interactive login. Regression for the sc-id enrollment hang.
	args := trustedClientRemoteAddArgs("sc-id-e2edns", "https://100.122.93.37:8443", "id-e2edns-default")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--project id-e2edns-default") {
		t.Fatalf("cert-based remote add must pin the project, got: %q", joined)
	}
	if !strings.Contains(joined, "--auth-type=tls") || !strings.Contains(joined, "--accept-certificate") {
		t.Fatalf("cert-based remote add must use the trusted-cert path, got: %q", joined)
	}
}

func TestTrustedClientRemoteAddArgsOmitsEmptyProject(t *testing.T) {
	args := trustedClientRemoteAddArgs("sc-acme", "https://10.0.0.2:8443", "  ")
	if strings.Contains(strings.Join(args, " "), "--project") {
		t.Fatalf("no project pin when none is given, got: %v", args)
	}
}

func TestNormalizedRemoteURLUsesCertificateDNSNameForIPRemote(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	certPath := filepath.Join(dir, "servercerts", "sandcastle-alice.crt")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`remotes:
  sandcastle-alice:
    addr: https://65.21.132.31:8443
`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeTestCertificate(t, certPath, []string{"big.thieso2.dev"})

	got, ok, err := normalizedRemoteURL(configPath, "sandcastle-alice", certPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected remote URL normalization")
	}
	if got != "https://big.thieso2.dev:8443" {
		t.Fatalf("normalized URL = %q", got)
	}
}

func TestNormalizedRemoteURLLeavesDNSRemoteUntouched(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yml")
	certPath := filepath.Join(dir, "servercerts", "sandcastle-alice.crt")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`remotes:
  sandcastle-alice:
    addr: https://big.thieso2.dev:8443
`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeTestCertificate(t, certPath, []string{"big.thieso2.dev"})

	_, ok, err := normalizedRemoteURL(configPath, "sandcastle-alice", certPath)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("did not expect remote URL normalization")
	}
}

func TestSaveRemoteDefaultsReplacesStaleRemote(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant: "thies",
		Remote: "sandcastle-thies",
	}); err != nil {
		t.Fatal(err)
	}

	remoteSet, tenant, err := saveRemoteDefaults(configPath, "sandcastle-thieso2", "thieso2")
	if err != nil {
		t.Fatal(err)
	}
	if !remoteSet {
		t.Fatal("expected stale remote to be replaced")
	}
	if tenant != "thieso2" {
		t.Fatalf("tenant = %q", tenant)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Remote != "sandcastle-thieso2" || cfg.Tenant != "thieso2" {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestSaveRemoteDefaultsKeepsRemoteWhenAlreadyCurrent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant: "thieso2",
		Remote: "sandcastle-thieso2",
	}); err != nil {
		t.Fatal(err)
	}

	remoteSet, tenant, err := saveRemoteDefaults(configPath, "sandcastle-thieso2", "")
	if err != nil {
		t.Fatal(err)
	}
	if remoteSet {
		t.Fatal("did not expect current remote to be rewritten")
	}
	if tenant != "thieso2" {
		t.Fatalf("tenant = %q", tenant)
	}
}

func TestRemoteExistsReadsIncusConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte(`remotes:
  sandcastle-thieso2:
    addr: https://big.thieso2.dev:8443
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !remoteExists(dir, "sandcastle-thieso2") {
		t.Fatal("expected existing remote")
	}
	if remoteExists(dir, "missing") {
		t.Fatal("did not expect missing remote")
	}
}

func writeTestCertificate(t *testing.T, path string, dnsNames []string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	content := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSetRemoteProject(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfg, []byte("remotes:\n  sc-id-acme:\n    addr: https://x:8443\n    protocol: incus\naliases: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setRemoteProject(cfg, "sc-id-acme", "id-acme-default"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(cfg)
	if !strings.Contains(string(data), "project: id-acme-default") {
		t.Fatalf("project not written:\n%s", data)
	}
	// unrelated fields preserved
	if !strings.Contains(string(data), "addr: https://x:8443") {
		t.Fatalf("addr lost:\n%s", data)
	}
	if err := setRemoteProject(cfg, "missing", "x"); err == nil {
		t.Fatal("expected error for missing remote")
	}
}
