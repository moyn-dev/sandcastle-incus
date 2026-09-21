package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
)

func TestIncusEndpointFromBrokerExplicit(t *testing.T) {
	got, err := incusEndpointFromBroker("https://big.example:8443", "https://big.example:9443")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://big.example:8443" {
		t.Fatalf("got %q", got)
	}
}

func TestIncusEndpointFromBrokerDerived(t *testing.T) {
	got, err := incusEndpointFromBroker("", "https://65.21.132.31:9443")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://65.21.132.31:8443" {
		t.Fatalf("got %q, want the broker host on :8443", got)
	}
}

func TestIncusEndpointFromBrokerDerivedHostname(t *testing.T) {
	got, err := incusEndpointFromBroker("", "https://big:9443")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://big:8443" {
		t.Fatalf("got %q", got)
	}
}

func TestIncusEndpointFromBrokerNoHost(t *testing.T) {
	if _, err := incusEndpointFromBroker("", "not a url"); err == nil {
		t.Fatal("expected error for URL without host")
	}
}

func TestShortProjectName(t *testing.T) {
	if got := shortProjectName("sc2-demo-backend", "demo"); got != "backend" {
		t.Fatalf("got %q, want backend", got)
	}
	if got := shortProjectName("sc2-demo-default", "demo"); got != "default" {
		t.Fatalf("got %q, want default", got)
	}
	// not this tenant's project → skip
	if got := shortProjectName("sc2-other-x", "demo"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestBrokerURLForTenantCIDR(t *testing.T) {
	if got := brokerURLForTenantCIDR("10.253.0.0/24"); got != "https://10.253.0.1:9443" {
		t.Fatalf("got %q, want the tenant gateway on :9443", got)
	}
	if got := brokerURLForTenantCIDR(""); got != "" {
		t.Fatalf("got %q, want empty for no CIDR (v1 tenant)", got)
	}
	if got := brokerURLForTenantCIDR("not-a-cidr"); got != "" {
		t.Fatalf("got %q, want empty for a bad CIDR", got)
	}
}

// writeEnrolledRemote fakes what `sc login` leaves behind for a remote:
// ~/.config/sandcastle/<remote>/incus/{client.crt,client.key,config.yml}.
// Returns the incus dir. HOME must already point at a temp dir.
func writeEnrolledRemote(t *testing.T, remote string) string {
	t.Helper()
	dir := scconfig.RemoteIncusDir(remote)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestClientKeyPair(t, filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"))
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeTestClientKeyPair(t *testing.T, certPath string, keyPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tenant-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResolveBrokerConnectionFlagsWin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	admin := scconfig.Admin{Broker: "https://from-config:9443", Remote: "sandcastle-demo"}
	conn, err := resolveBrokerConnection(admin, "https://from-flag:9443", "/tmp/c.crt", "/tmp/c.key", "/tmp/conf")
	if err != nil {
		t.Fatal(err)
	}
	if conn.Broker != "https://from-flag:9443" || conn.CertFile != "/tmp/c.crt" || conn.KeyFile != "/tmp/c.key" || conn.IncusConf != "/tmp/conf" {
		t.Fatalf("flags must win, got %+v", conn)
	}
}

func TestResolveBrokerConnectionDefaultsFromLogin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := writeEnrolledRemote(t, "sandcastle-demo")
	admin := scconfig.Admin{Broker: "https://10.253.0.1:9443", Remote: "sandcastle-demo"}
	conn, err := resolveBrokerConnection(admin, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if conn.Broker != "https://10.253.0.1:9443" {
		t.Fatalf("broker not taken from config: %+v", conn)
	}
	if conn.CertFile != filepath.Join(dir, "client.crt") || conn.KeyFile != filepath.Join(dir, "client.key") {
		t.Fatalf("cert/key not defaulted from the enrolled remote: %+v", conn)
	}
	if conn.IncusConf != dir {
		t.Fatalf("incus conf should default to the enrolled remote dir, got %q", conn.IncusConf)
	}
}

func TestResolveBrokerConnectionNoBroker(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := resolveBrokerConnection(scconfig.Admin{Remote: "sandcastle-demo"}, "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "sc login") {
		t.Fatalf("want guidance to re-run sc login, got %v", err)
	}
}

func TestResolveBrokerConnectionNoCert(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	admin := scconfig.Admin{Broker: "https://10.253.0.1:9443", Remote: "sandcastle-demo"}
	_, err := resolveBrokerConnection(admin, "", "", "", "")
	if err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("want a missing-certificate error, got %v", err)
	}
}

// fake broker plumbing for the round-trip test.
type staticTrustMapper struct{ tenant string }

func (m staticTrustMapper) PrincipalForFingerprint(context.Context, string) (projectbroker.TrustPrincipal, error) {
	return projectbroker.TrustPrincipal{User: m.tenant}, nil
}

type recordingCreator struct{ tenant, project string }

func (c *recordingCreator) CreateTenantProject(_ context.Context, tenant string, project string, _ string) (projectbroker.ProjectResult, error) {
	c.tenant, c.project = tenant, project
	return projectbroker.ProjectResult{Tenant: tenant, Project: project, IncusProject: "sc2-" + tenant + "-" + project}, nil
}

// TestProjectCreateFlaglessRoundTrip proves the papercut fix end-to-end in
// process: after a login has recorded the broker URL and enrolled a remote,
// `sc project create <name>` with NO flags authenticates to a live TLS broker
// (client cert required at handshake) and creates the project.
func TestProjectCreateFlaglessRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "") // no incus on PATH: the per-project remote step must degrade to a note
	writeEnrolledRemote(t, "sandcastle-demo")

	creator := &recordingCreator{}
	server := httptest.NewUnstartedServer(projectbroker.Handler{
		Trust:   staticTrustMapper{tenant: "demo"},
		Creator: creator,
	})
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	command := newProjectCreateV2Command(commandConfig{
		adminConfig: scconfig.Admin{Broker: server.URL, Remote: "sandcastle-demo", Tenant: "demo"},
		stdout:      &stdout,
		stderr:      &stderr,
	}, &rootOptions{output: outputText})
	command.SetArgs([]string{"web"})
	if err := command.Execute(); err != nil {
		t.Fatalf("flagless project create failed: %v (stderr: %s)", err, stderr.String())
	}
	if creator.tenant != "demo" || creator.project != "web" {
		t.Fatalf("broker did not receive the create: %+v", creator)
	}
	if !strings.Contains(stdout.String(), "sc2-demo-web") {
		t.Fatalf("expected the created incus project in output, got %q", stdout.String())
	}
}

// stubAuthProjects is the recording fake of the Auth App project plane: every
// verb appends "<verb> <args>" to calls; fail short-circuits with an error
// (the verbatim refusal text, as the real client returns it).
type stubAuthProjects struct {
	tenant, project string
	domain          string
	calls           []string
	fail            error
	zone            string
	released        string
	alreadyClaimed  bool
}

func (s *stubAuthProjects) CreateProject(_ context.Context, request authapp.ProjectCreateRequest) (projectbroker.ProjectResult, error) {
	s.project = request.Project
	s.domain = request.Domain
	s.calls = append(s.calls, "create "+request.Project+" "+request.Domain+" "+boolString(request.DryRun))
	if s.fail != nil {
		return projectbroker.ProjectResult{}, s.fail
	}
	zone := s.zone
	if zone == "" && request.Domain != "" {
		zone = "hase.de"
	}
	return projectbroker.ProjectResult{Tenant: "demo", Project: request.Project, IncusProject: "id-demo-" + request.Project, Domain: request.Domain, Zone: zone, DryRun: request.DryRun}, nil
}

func (s *stubAuthProjects) GetProjectDomain(_ context.Context, project string) (authapp.ProjectDomainResult, error) {
	s.calls = append(s.calls, "get-domain "+project)
	if s.fail != nil {
		return authapp.ProjectDomainResult{}, s.fail
	}
	return authapp.ProjectDomainResult{Tenant: "demo", Project: project, Domain: s.domain, Zone: s.zone}, nil
}

func (s *stubAuthProjects) SetProjectDomain(_ context.Context, project, domain string, dryRun bool) (authapp.ProjectDomainResult, error) {
	s.calls = append(s.calls, "set-domain "+project+" "+domain+" "+boolString(dryRun))
	if s.fail != nil {
		return authapp.ProjectDomainResult{}, s.fail
	}
	return authapp.ProjectDomainResult{Tenant: "demo", Project: project, Domain: domain, Zone: "hase.de", DryRun: dryRun, AlreadyClaimed: s.alreadyClaimed}, nil
}

func (s *stubAuthProjects) UnsetProjectDomain(_ context.Context, project string, dryRun bool) (authapp.ProjectDomainResult, error) {
	s.calls = append(s.calls, "unset-domain "+project+" "+boolString(dryRun))
	if s.fail != nil {
		return authapp.ProjectDomainResult{}, s.fail
	}
	return authapp.ProjectDomainResult{Tenant: "demo", Project: project, Released: s.released, DryRun: dryRun}, nil
}

func (s *stubAuthProjects) SetProjectImage(_ context.Context, project, image string) (authapp.ProjectImageResult, error) {
	s.calls = append(s.calls, "image:"+project+"="+image)
	return authapp.ProjectImageResult{Tenant: s.tenant, Project: project, Image: image}, s.fail
}

func (s *stubAuthProjects) RerenderProjectProfiles(_ context.Context, project string) (authapp.ProjectProfileResult, error) {
	s.calls = append(s.calls, "rerender:"+project)
	return authapp.ProjectProfileResult{Tenant: s.tenant, Project: project}, s.fail
}

func (s *stubAuthProjects) DeleteProject(_ context.Context, project string, dryRun bool) (authapp.ProjectDomainResult, error) {
	s.calls = append(s.calls, "delete "+project+" "+boolString(dryRun))
	if s.fail != nil {
		return authapp.ProjectDomainResult{}, s.fail
	}
	return authapp.ProjectDomainResult{Tenant: "demo", Project: project, Released: s.released, DryRun: dryRun}, nil
}

// After login, `sc project create` prefers the auth-app token API (works over
// the tunnel, no broker port, no client cert) — the broker path is only used
// with --broker or when no login token is saved.
func TestProjectCreatePrefersAuthApp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")
	stub := &stubAuthProjects{}
	var stdout, stderr bytes.Buffer
	command := newProjectCreateV2Command(commandConfig{
		adminConfig:  scconfig.Admin{AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
		authProjects: stub,
		stdout:       &stdout,
		stderr:       &stderr,
	}, &rootOptions{output: outputText})
	command.SetArgs([]string{"web"})
	if err := command.Execute(); err != nil {
		t.Fatalf("auth-app project create failed: %v (stderr: %s)", err, stderr.String())
	}
	if stub.project != "web" {
		t.Fatalf("auth-app client not used: %+v", stub)
	}
	if !strings.Contains(stdout.String(), "id-demo-web") {
		t.Fatalf("expected incus project in output, got %q", stdout.String())
	}
}
