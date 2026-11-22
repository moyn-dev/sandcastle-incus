package authapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func getDeviceFormForTest(t *testing.T, handler http.Handler, cookie *http.Cookie, userCode string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/device?user_code="+userCode, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device form GET = %d %q", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// A first login (no tenant yet) shows the DNS-suffix and initial-project inputs.
func TestDeviceFormShowsInputsForFirstLogin(t *testing.T) {
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	handler := NewHandler(db, HandlerOptions{AuthHostname: "auth.example.com"})

	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	html := getDeviceFormForTest(t, handler, cookie, login.UserCode)
	for _, want := range []string{`name="dns_suffix"`, `name="initial_project"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("first-login form missing input %q:\n%s", want, html)
		}
	}
}

// Once the tenant exists, its immutable suffix and existing projects are shown
// read-only and the first-login inputs are gone.
func TestDeviceFormHidesInputsForExistingTenant(t *testing.T) {
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	handler := NewHandler(db, HandlerOptions{
		AuthHostname: "auth.example.com",
		Tenants: tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{
			Tenant:   "admin",
			CIDR:     "10.248.1.0/24",
			Suffix:   "castle",
			Projects: []string{"web"},
		})},
	})

	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	html := getDeviceFormForTest(t, handler, cookie, login.UserCode)

	for _, absent := range []string{`name="dns_suffix"`, `name="initial_project"`} {
		if strings.Contains(html, absent) {
			t.Fatalf("existing-tenant form should not render input %q:\n%s", absent, html)
		}
	}
	for _, want := range []string{"castle", "<code>default</code>", "<code>web</code>"} {
		if !strings.Contains(html, want) {
			t.Fatalf("existing-tenant form missing %q:\n%s", want, html)
		}
	}
}
