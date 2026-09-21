package authapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeProjectDomainResolver is the test ProjectDomainResolver: tenant/project →
// (domain, zone).
type fakeProjectDomainResolver struct {
	domains map[string][2]string
	err     error
}

func (f fakeProjectDomainResolver) ResolveProjectDomain(_ context.Context, tenant, project string) (string, string, error) {
	if f.err != nil {
		return "", "", f.err
	}
	entry := f.domains[tenant+"/"+project]
	return entry[0], entry[1], nil
}

func machineCertTestHandler(t *testing.T, resolver ProjectDomainResolver) (http.Handler, *sql.DB, string) {
	t.Helper()
	db := newClaimsTestDB(t)
	if err := UpsertUser(context.Background(), db, User{UserKey: "acme", GitHubUsername: "acme", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	token, err := CreateCLIToken(context.Background(), db, "acme", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(db, HandlerOptions{
		AuthHostname:          "sc2.thieso2.dev",
		ACMEDirectory:         LetsEncryptStagingDirectory,
		ProjectDomainResolver: resolver,
	})
	return h, db, token
}

func postMachineCertificate(h http.Handler, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/machine-certificates", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	return res
}

func TestMachineCertificatesAPI_ProjectDoesNotCreateMachineRow(t *testing.T) {
	h, db, token := machineCertTestHandler(t, fakeProjectDomainResolver{domains: map[string][2]string{
		"acme/baum": {"baum.hase.de", "hase.de"},
	}})

	res := postMachineCertificate(h, token, `{"project":"baum","machine":"web"}`)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d %q", res.Code, res.Body.String())
	}
	var view MachineCertificateView
	if err := json.Unmarshal(res.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Hostname != "web.baum.hase.de" || view.State != "project" || view.Reason != "" {
		t.Fatalf("view = %+v", view)
	}
	if _, err := getMachineCertificate(context.Background(), db, "web.baum.hase.de"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unexpected machine row: %v", err)
	}

	// Requesting again for the same hostname is idempotent (still one row).
	if res := postMachineCertificate(h, token, `{"project":"baum","machine":"web"}`); res.Code != http.StatusAccepted {
		t.Fatalf("second request = %d %q", res.Code, res.Body.String())
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM machine_certificates").Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows = %d, %v", n, err)
	}
}

func TestMachineCertificatesAPI_RetainedCertificateIsReported(t *testing.T) {
	h, db, token := machineCertTestHandler(t, fakeProjectDomainResolver{domains: map[string][2]string{
		"acme/baum": {"baum.hase.de", "hase.de"},
	}})
	ctx := context.Background()
	now := timeNow()
	if _, err := requestMachineCertificate(ctx, db, testCertRequest("web.baum.hase.de"), now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	issued, err := (&fakeCertIssuer{now: now.Add(-48 * time.Hour)}).Issue(ctx, "hase.de", machineCertificateHostnames("web.baum.hase.de"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storeIssuedMachineCertificate(ctx, db, "web.baum.hase.de", issued, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE machine_certificates SET pushed_serial = serial"); err != nil {
		t.Fatal(err)
	}

	res := postMachineCertificate(h, token, `{"project":"baum","machine":"web"}`)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status = %d %q", res.Code, res.Body.String())
	}
	var view MachineCertificateView
	_ = json.Unmarshal(res.Body.Bytes(), &view)
	if view.State != "project" {
		t.Fatalf("state = %q, want issued (retained certificate, no order)", view.State)
	}
	row, _ := getMachineCertificate(ctx, db, "web.baum.hase.de")
	if row.CertPEM != issued.CertPEM || row.PushedSerial != row.Serial {
		t.Fatalf("retained row = %+v", row)
	}
}

func TestMachineCertificatesAPI_RateLimited(t *testing.T) {
	h, db, token := machineCertTestHandler(t, fakeProjectDomainResolver{domains: map[string][2]string{
		"acme/baum": {"baum.hase.de", "hase.de"},
	}})
	ctx := context.Background()
	now := timeNow()
	// 50 successful issuances in the zone this week.
	for i := 0; i < machineCertZoneWeeklyBudget; i++ {
		hostname := fmt.Sprintf("m%02d.baum.hase.de", i)
		if _, err := requestMachineCertificate(ctx, db, testCertRequest(hostname), now); err != nil {
			t.Fatal(err)
		}
		issued, err := (&fakeCertIssuer{now: now.Add(-time.Hour)}).Issue(ctx, "hase.de", machineCertificateHostnames(hostname))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := storeIssuedMachineCertificate(ctx, db, hostname, issued, now); err != nil {
			t.Fatal(err)
		}
	}

	res := postMachineCertificate(h, token, `{"project":"baum","machine":"web"}`)
	if res.Code != http.StatusAccepted {
		t.Fatalf("status=%d %s", res.Code, res.Body.String())
	}
	var view MachineCertificateView
	_ = json.Unmarshal(res.Body.Bytes(), &view)
	if view.State != "project" || view.Reason != "" {
		t.Fatalf("view=%+v", view)
	}
	if _, err := getMachineCertificate(ctx, db, "web.baum.hase.de"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unexpected machine row: %v", err)
	}

}

func TestMachineCertificatesAPI_Refusals(t *testing.T) {
	resolver := fakeProjectDomainResolver{domains: map[string][2]string{
		"acme/baum":  {"baum.hase.de", "hase.de"},
		"other/zulu": {"zulu.hase.de", "hase.de"},
	}}
	h, _, token := machineCertTestHandler(t, resolver)

	if res := postMachineCertificate(h, "", `{"project":"baum","machine":"web"}`); res.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d", res.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/machine-certificates", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d", res.Code)
	}
	if res := postMachineCertificate(h, token, `{"project":"","machine":"web"}`); res.Code != http.StatusBadRequest {
		t.Fatalf("empty project = %d", res.Code)
	}
	if res := postMachineCertificate(h, token, `{"project":"baum","machine":"Bad Name"}`); res.Code != http.StatusBadRequest {
		t.Fatalf("bad machine = %d", res.Code)
	}
	if res := postMachineCertificate(h, token, `not json`); res.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d", res.Code)
	}
	// A project without a domain: nothing to order.
	res = postMachineCertificate(h, token, `{"project":"private","machine":"web"}`)
	if res.Code != http.StatusNotFound || !strings.Contains(res.Body.String(), `has no project domain`) {
		t.Fatalf("no domain = %d %q", res.Code, res.Body.String())
	}
	// Another tenant's project: the caller is not authorized for that tenant.
	if res := postMachineCertificate(h, token, `{"tenant":"other","project":"zulu","machine":"web"}`); res.Code != http.StatusForbidden {
		t.Fatalf("other tenant = %d %q", res.Code, res.Body.String())
	}

	// Resolver failure surfaces as 500.
	failing, _, failingToken := machineCertTestHandler(t, fakeProjectDomainResolver{err: errors.New("claims unavailable")})
	if res := postMachineCertificate(failing, failingToken, `{"project":"baum","machine":"web"}`); res.Code != http.StatusInternalServerError {
		t.Fatalf("resolver error = %d", res.Code)
	}
	// No injected resolver: the handler defaults to the Project Domain claims
	// table (slice 3), which has no claim for baum, so the answer is 404.
	none, _, noneToken := machineCertTestHandler(t, nil)
	if res := postMachineCertificate(none, noneToken, `{"project":"baum","machine":"web"}`); res.Code != http.StatusNotFound {
		t.Fatalf("nil resolver = %d", res.Code)
	}
}

// The CLI client maps 202 and 409 rate-limited to a view, anything else to
// an error.
func TestDeviceClientRequestMachineCertificate(t *testing.T) {
	h, _, token := machineCertTestHandler(t, fakeProjectDomainResolver{domains: map[string][2]string{
		"acme/baum": {"baum.hase.de", "hase.de"},
	}})
	server := httptest.NewServer(h)
	defer server.Close()

	client := DeviceClient{BaseURL: server.URL, AuthToken: token}
	view, err := client.RequestMachineCertificate(context.Background(), MachineCertificateRequest{Project: "baum", Machine: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if view.Hostname != "web.baum.hase.de" || view.State != "project" {
		t.Fatalf("view = %+v", view)
	}
	if _, err := client.RequestMachineCertificate(context.Background(), MachineCertificateRequest{Project: "private", Machine: "web"}); err == nil || !strings.Contains(err.Error(), "no project domain") {
		t.Fatalf("no-domain error = %v", err)
	}
	if _, err := (DeviceClient{BaseURL: server.URL, AuthToken: "bogus"}).RequestMachineCertificate(context.Background(), MachineCertificateRequest{Project: "baum", Machine: "web"}); err == nil {
		t.Fatal("bogus token accepted")
	}
}
