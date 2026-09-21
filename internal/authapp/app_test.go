package authapp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
	"golang.org/x/crypto/ssh"
)

func TestPlanServeRequiresDatabasePath(t *testing.T) {
	_, err := PlanServe(ServeRequest{Address: ":9444"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPlanServeAcceptsDefaultUnixUser(t *testing.T) {
	plan, err := PlanServe(ServeRequest{Address: ":9444", DatabasePath: "/tmp/auth.db", DefaultUnixUser: "localuser"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DefaultUnixUser != "localuser" {
		t.Fatalf("DefaultUnixUser = %q", plan.DefaultUnixUser)
	}
}

func TestHealthAndStatusUseSQLiteDatabase(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	assertSchemaVersion(t, db)
	handler := NewHandler(db, "auth.example.com")

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || strings.TrimSpace(health.Body.String()) != "ok" {
		t.Fatalf("health = %d %q", health.Code, health.Body.String())
	}

	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/", nil))
	if status.Code != http.StatusOK ||
		!strings.Contains(status.Body.String(), "Sandcastle Auth") ||
		!strings.Contains(status.Body.String(), "auth.example.com") ||
		!strings.Contains(status.Body.String(), `href="/login/github"`) ||
		!strings.Contains(status.Body.String(), "Sign in with GitHub") {
		t.Fatalf("status = %d %q", status.Code, status.Body.String())
	}
}

func TestBootstrapAdminsCreatesAllowlistedAdminUsers(t *testing.T) {
	db := authDBForTest(t)
	if err := BootstrapAdmins(context.Background(), db, []string{"OctoCat", "octocat", "hubot"}); err != nil {
		t.Fatal(err)
	}
	user := findUserForTest(t, db, "octocat")
	if user.UserKey != "octocat" || !user.Allowlisted || !user.SandcastleAdmin {
		t.Fatalf("user = %#v", user)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("users = %d, want 2", count)
	}
}

func TestGitHubOAuthCallbackCreatesSessionForAllowlistedUser(t *testing.T) {
	db := authDBForTest(t)
	if err := BootstrapAdmins(context.Background(), db, []string{"OctoCat"}); err != nil {
		t.Fatal(err)
	}
	state := createStateForTest(t, db)
	provisioner := &fakePersonalTenantProvisioner{}
	handler := NewHandler(db, HandlerOptions{
		AuthHostname:       "auth.example.com",
		GitHubClientID:     "client",
		GitHubClientSecret: "secret",
		GitHub: fakeGitHubClient{
			token: "token",
			profile: GitHubProfile{
				Login: "OctoCat",
				ID:    "583231",
				Email: "octo@example.com",
			},
		},
		Provisioner: provisioner,
	})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=abc&state="+state, nil))
	if response.Code != http.StatusFound {
		t.Fatalf("callback = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Location") != "/" {
		t.Fatalf("callback location = %q", response.Header().Get("Location"))
	}
	if len(response.Result().Cookies()) != 1 || response.Result().Cookies()[0].Name != "sandcastle_session" {
		t.Fatalf("cookies = %#v", response.Result().Cookies())
	}
	onboardingRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	onboardingRequest.AddCookie(response.Result().Cookies()[0])
	onboarding := httptest.NewRecorder()
	handler.ServeHTTP(onboarding, onboardingRequest)
	if onboarding.Code != http.StatusOK {
		t.Fatalf("onboarding = %d %q", onboarding.Code, onboarding.Body.String())
	}
	for _, want := range []string{
		"Sandcastle Onboarding",
		"GitHub Username: OctoCat",
		"Status: allowlisted",
		"Install the CLI",
		"sandcastle login https://auth.example.com",
	} {
		if !strings.Contains(onboarding.Body.String(), want) {
			t.Fatalf("onboarding missing %q:\n%s", want, onboarding.Body.String())
		}
	}
	user := findUserForTest(t, db, "octocat")
	if user.GitHubAccountID != "583231" || user.GitHubEmail != "octo@example.com" {
		t.Fatalf("user metadata = %#v", user)
	}
	var sessions int
	if err := db.QueryRow("SELECT count(*) FROM web_sessions WHERE user_key = 'octocat'").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("sessions = %d", sessions)
	}
	if provisioner.calls != 0 {
		t.Fatalf("browser-only login provisioner calls = %d", provisioner.calls)
	}
	assertNoPersonalTenantProvisioningTables(t, db)
}

func TestGitHubOAuthCallbackRejectsNonAllowlistedUser(t *testing.T) {
	db := authDBForTest(t)
	state := createStateForTest(t, db)
	handler := NewHandler(db, HandlerOptions{
		GitHubClientID:     "client",
		GitHubClientSecret: "secret",
		GitHub: fakeGitHubClient{
			token:   "token",
			profile: GitHubProfile{Login: "notallowed", ID: "123"},
		},
	})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=abc&state="+state, nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("callback = %d %q", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "not allowlisted") {
		t.Fatalf("callback body = %q", response.Body.String())
	}
	var sessions int
	if err := db.QueryRow("SELECT count(*) FROM web_sessions").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("sessions = %d", sessions)
	}
}

func TestGitHubRenameBlocksLogin(t *testing.T) {
	db := authDBForTest(t)
	if err := BootstrapAdmins(context.Background(), db, []string{"oldname"}); err != nil {
		t.Fatal(err)
	}
	state := createStateForTest(t, db)
	handler := NewHandler(db, HandlerOptions{
		GitHubClientID:     "client",
		GitHubClientSecret: "secret",
		GitHub: fakeGitHubClient{
			token:   "token",
			profile: GitHubProfile{Login: "newname", ID: "583231"},
		},
	})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oauth/github/callback?code=abc&state="+state, nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("callback = %d %q", response.Code, response.Body.String())
	}
}

func TestGitHubLoginRedirectsOnlyToGitHub(t *testing.T) {
	db := authDBForTest(t)
	handler := NewHandler(db, HandlerOptions{GitHubClientID: "client"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login/github", nil))
	if response.Code != http.StatusFound {
		t.Fatalf("login = %d %q", response.Code, response.Body.String())
	}
	location := response.Header().Get("Location")
	if !strings.HasPrefix(location, "https://github.com/login/oauth/authorize?") || !strings.Contains(location, "client_id=client") {
		t.Fatalf("Location = %q", location)
	}
}

func TestPasswordLoginPathDoesNotExist(t *testing.T) {
	db := authDBForTest(t)
	handler := NewHandler(db, HandlerOptions{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/login/password", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("password login = %d %q", response.Code, response.Body.String())
	}
}

func TestDeviceClientDefaultTimeoutAllowsSlowProvisioningPoll(t *testing.T) {
	client := DeviceClient{}.client()
	if client.Timeout != defaultDeviceClientTimeout {
		t.Fatalf("timeout = %s, want %s", client.Timeout, defaultDeviceClientTimeout)
	}
	if client.Timeout < time.Minute {
		t.Fatalf("timeout too short for first-run provisioning: %s", client.Timeout)
	}
}

func TestOnboardingPageShowsRemovedAllowlistStatusWithoutLoginCommand(t *testing.T) {
	db := authDBForTest(t)
	if _, err := AllowlistGitHubUser(context.Background(), db, GitHubProfile{Login: "OctoCat", ID: "1", Email: "octo@example.com"}); err != nil {
		t.Fatal(err)
	}
	sessionID, err := CreateSession(context.Background(), db, "octocat", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveAllowlistedUser(context.Background(), db, "octocat"); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(db, HandlerOptions{AuthHostname: "auth.example.com"})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: "sandcastle_session", Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("onboarding = %d %q", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Status: not allowlisted") || !strings.Contains(response.Body.String(), "Login Allowlist") {
		t.Fatalf("onboarding body = %q", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "sandcastle login https://auth.example.com") {
		t.Fatalf("non-allowlisted onboarding included login command:\n%s", response.Body.String())
	}
}

func TestAllowlistAdminCanAddGitHubUser(t *testing.T) {
	db := authDBForTest(t)
	adminCookie := adminSessionCookieForTest(t, db)
	handler := NewHandler(db, HandlerOptions{
		GitHub: fakeGitHubClient{
			verified: GitHubProfile{Login: "NewUser", ID: "42"},
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/admin/allowlist", strings.NewReader("github_username=NewUser"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminCookie)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("allowlist add = %d %q", response.Code, response.Body.String())
	}
	user := findUserForTest(t, db, "newuser")
	if !user.Allowlisted || user.SandcastleAdmin || user.GitHubAccountID != "42" {
		t.Fatalf("user = %#v", user)
	}
}

func TestAllowlistDuplicateUpdatesSingleUser(t *testing.T) {
	db := authDBForTest(t)
	if _, err := AllowlistGitHubUser(context.Background(), db, GitHubProfile{Login: "OctoCat", ID: "1"}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/allowlist", strings.NewReader("github_username=octocat"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminSessionCookieForTest(t, db))
	response := httptest.NewRecorder()
	NewHandler(db, HandlerOptions{GitHub: fakeGitHubClient{verified: GitHubProfile{Login: "octocat", ID: "1"}}}).ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("allowlist add = %d %q", response.Code, response.Body.String())
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM users WHERE github_username_normalized = 'octocat'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("octocat rows = %d", count)
	}
}

func TestAllowlistRejectsInvalidUsername(t *testing.T) {
	db := authDBForTest(t)
	request := httptest.NewRequest(http.MethodPost, "/admin/allowlist", strings.NewReader("github_username=-bad"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminSessionCookieForTest(t, db))
	response := httptest.NewRecorder()
	NewHandler(db, HandlerOptions{GitHub: fakeGitHubClient{}}).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("allowlist add = %d %q", response.Code, response.Body.String())
	}
}

func TestAllowlistRejectsNonAdmin(t *testing.T) {
	db := authDBForTest(t)
	if err := UpsertUser(context.Background(), db, User{
		UserKey:                  "alice",
		GitHubUsername:           "alice",
		GitHubUsernameNormalized: "alice",
		Allowlisted:              true,
	}); err != nil {
		t.Fatal(err)
	}
	sessionID, err := CreateSession(context.Background(), db, "alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/allowlist", nil)
	request.AddCookie(&http.Cookie{Name: "sandcastle_session", Value: sessionID})
	response := httptest.NewRecorder()

	NewHandler(db, HandlerOptions{}).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("allowlist = %d %q", response.Code, response.Body.String())
	}
}

func TestAllowlistAddRejectsOrganization(t *testing.T) {
	db := authDBForTest(t)
	request := httptest.NewRequest(http.MethodPost, "/admin/allowlist", strings.NewReader("github_username=acme"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminSessionCookieForTest(t, db))
	response := httptest.NewRecorder()

	NewHandler(db, HandlerOptions{
		GitHub: fakeGitHubClient{verifyErr: errors.New("GitHub login acme is Organization, want User")},
	}).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("allowlist add = %d %q", response.Code, response.Body.String())
	}
}

func TestAllowlistRemoveBlocksLoginAndRevokesRestrictedCertificate(t *testing.T) {
	db := authDBForTest(t)
	if _, err := AllowlistGitHubUser(context.Background(), db, GitHubProfile{Login: "alice", ID: "123"}); err != nil {
		t.Fatal(err)
	}
	revoker := &fakeRestrictedRevoker{}
	sshAccess := &fakeMachineSSHKeyReconciler{}
	request := httptest.NewRequest(http.MethodPost, "/admin/allowlist/remove", strings.NewReader("github_username=alice"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminSessionCookieForTest(t, db))
	response := httptest.NewRecorder()

	NewHandler(db, HandlerOptions{
		RestrictedUsers: revoker,
		Tenants: tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(
			authTestTenant{Tenant: "alice", CIDR: "10.248.1.0/24"},
			authTestTenant{Tenant: "acme", CIDR: "10.248.2.0/24"},
		)},
		MachineSSHAccess: sshAccess,
	}).ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("allowlist remove = %d %q", response.Code, response.Body.String())
	}
	user := findUserForTest(t, db, "alice")
	if user.Allowlisted {
		t.Fatalf("user still allowlisted = %#v", user)
	}
	if len(revoker.deleted) != 1 || revoker.deleted[0] != "alice" {
		t.Fatalf("deleted users = %#v", revoker.deleted)
	}
	if len(sshAccess.revokes) != 2 || sshAccess.revokes[0].user != "alice" || sshAccess.revokes[1].user != "alice" {
		t.Fatalf("ssh access revokes = %#v", sshAccess.revokes)
	}
	if _, err := FindLoginUser(context.Background(), db, "alice"); err == nil {
		t.Fatal("expected removed user to be blocked from login")
	}
}

func TestTenantAccessAdminRequiresSandcastleAdmin(t *testing.T) {
	db := authDBForTest(t)
	if err := UpsertUser(context.Background(), db, User{
		UserKey:                  "alice",
		GitHubUsername:           "alice",
		GitHubUsernameNormalized: "alice",
		Allowlisted:              true,
	}); err != nil {
		t.Fatal(err)
	}
	sessionID, err := CreateSession(context.Background(), db, "alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/admin/access", nil)
	request.AddCookie(&http.Cookie{Name: "sandcastle_session", Value: sessionID})
	response := httptest.NewRecorder()

	NewHandler(db, HandlerOptions{}).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("tenant access = %d %q", response.Code, response.Body.String())
	}
}

func TestTenantAccessAdminListsUsersTenantsAndGrants(t *testing.T) {
	db := authDBForTest(t)
	if _, err := AllowlistGitHubUser(context.Background(), db, GitHubProfile{Login: "alice", ID: "123"}); err != nil {
		t.Fatal(err)
	}
	access := &fakeTenantAccessManager{usersByTenant: map[string][]string{"acme": []string{"alice"}}}
	handler := NewHandler(db, HandlerOptions{
		Admin:        testAuthAdminConfig(),
		Tenants:      tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "acme", CIDR: "10.248.0.0/24"})},
		TenantAccess: access,
	})

	request := httptest.NewRequest(http.MethodGet, "/admin/access", nil)
	request.AddCookie(adminSessionCookieForTest(t, db))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "alice") || !strings.Contains(response.Body.String(), "acme") {
		t.Fatalf("tenant access list = %d %q", response.Code, response.Body.String())
	}

	grantRequest := httptest.NewRequest(http.MethodPost, "/admin/access/grant", strings.NewReader("tenant=acme&user=alice"))
	grantRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	grantRequest.AddCookie(adminSessionCookieForTest(t, db))
	grantResponse := httptest.NewRecorder()
	handler.ServeHTTP(grantResponse, grantRequest)
	if grantResponse.Code != http.StatusSeeOther {
		t.Fatalf("grant = %d %q", grantResponse.Code, grantResponse.Body.String())
	}
	if len(access.grants) != 1 || access.grants[0].User != "alice" || !slices.Equal(access.grants[0].Projects, []string{"sc-acme", "sc-acme-default"}) {
		t.Fatalf("grants = %#v", access.grants)
	}
}

func TestTenantAccessAPIRequiresCLIToken(t *testing.T) {
	db := authDBForTest(t)
	handler := NewHandler(db, HandlerOptions{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/tenants", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("tenant list = %d %q", response.Code, response.Body.String())
	}
}

func TestTenantAccessAdminRevokesPersonalTenantAccess(t *testing.T) {
	db := authDBForTest(t)
	access := &fakeTenantAccessManager{}
	sshAccess := &fakeMachineSSHKeyReconciler{}
	handler := NewHandler(db, HandlerOptions{
		Admin:            testAuthAdminConfig(),
		Tenants:          tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "1octocat", CIDR: "10.248.1.0/24"})},
		TenantAccess:     access,
		MachineSSHAccess: sshAccess,
	})

	request := httptest.NewRequest(http.MethodPost, "/admin/access/revoke", strings.NewReader("tenant=1octocat&user=1octocat&personal=1"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(adminSessionCookieForTest(t, db))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("revoke = %d %q", response.Code, response.Body.String())
	}
	if len(access.revokes) != 1 || access.revokes[0].User != "1octocat" || !slices.Equal(access.revokes[0].Projects, []string{"sc-1octocat", "sc-1octocat-default"}) {
		t.Fatalf("revokes = %#v", access.revokes)
	}
	if len(sshAccess.revokes) != 1 || sshAccess.revokes[0].tenant != "1octocat" || sshAccess.revokes[0].user != "1octocat" {
		t.Fatalf("ssh access revokes = %#v", sshAccess.revokes)
	}
}

func TestDeviceLoginLifecycle(t *testing.T) {
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	handler := NewHandler(db, HandlerOptions{AuthHostname: "auth.example.com"})

	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/api/device/start", nil))
	if start.Code != http.StatusOK {
		t.Fatalf("start = %d %q", start.Code, start.Body.String())
	}
	var started deviceStartResponse
	if err := json.Unmarshal(start.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if started.DeviceCode == "" || started.UserCode == "" || !strings.Contains(started.VerificationURI, started.UserCode) {
		t.Fatalf("started = %#v", started)
	}

	pending := pollDeviceForTest(t, handler, started.DeviceCode)
	if pending.Status != DeviceStatusPending {
		t.Fatalf("pending = %#v", pending)
	}

	approveRequest := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader("user_code="+started.UserCode+"&action=approve"))
	approveRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveRequest.AddCookie(cookie)
	approve := httptest.NewRecorder()
	handler.ServeHTTP(approve, approveRequest)
	if approve.Code != http.StatusOK {
		t.Fatalf("approve = %d %q", approve.Code, approve.Body.String())
	}
	if !strings.Contains(approve.Body.String(), "Return to the terminal") {
		t.Fatalf("approve body = %q", approve.Body.String())
	}

	approved := pollDeviceForTest(t, handler, started.DeviceCode)
	if approved.Status != DeviceStatusApproved || approved.UserKey != "admin" {
		t.Fatalf("approved = %#v", approved)
	}
}

func TestDevicePollProvisionsPersonalTenantOnceAfterApproval(t *testing.T) {
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	provisioner := &fakePersonalTenantProvisioner{}
	reconciler := &fakeMachineSSHKeyReconciler{}
	tenantSSHKeys := &fakeTenantSSHKeyUpdater{}
	handler := NewHandler(db, HandlerOptions{
		AuthHostname:   "auth.example.com",
		Tenants:        tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "admin", CIDR: "10.248.1.0/24"})},
		Provisioner:    provisioner,
		MachineSSHKeys: reconciler,
		TenantSSHKeys:  tenantSSHKeys,
	})

	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	approveRequest := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader("user_code="+login.UserCode+"&action=approve"))
	approveRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveRequest.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), approveRequest)

	approved := pollDeviceBodyForTest(t, handler, `{"device_code":"`+login.DeviceCode+`","local_unix_user":"loginuser"}`)
	if approved.Status != DeviceStatusApproved || approved.UserKey != "admin" || approved.Token != "token-admin" || !strings.Contains(approved.Message, "Personal tenant admin is ready") {
		t.Fatalf("approved = %#v", approved)
	}
	if len(provisioner.users) != 1 || provisioner.users[0].LocalUnixUser != "loginuser" {
		t.Fatalf("provisioner users = %#v", provisioner.users)
	}
	if strings.Contains(strings.ToLower(approved.raw), "private_key") || strings.Contains(strings.ToLower(approved.raw), "client_key") {
		t.Fatalf("poll response leaked private key material: %s", approved.raw)
	}
	approved = pollDeviceForTest(t, handler, login.DeviceCode)
	if provisioner.calls != 1 {
		t.Fatalf("provisioner calls = %d, want 1", provisioner.calls)
	}
}

func TestDevicePollSSHKeyReconcileFailureWarnsButApproves(t *testing.T) {
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	provisioner := &fakePersonalTenantProvisioner{}
	reconciler := &fakeMachineSSHKeyReconciler{reconcileErr: errors.New("reconcile User SSH Public Key on machine test2: script exited 1")}
	handler := NewHandler(db, HandlerOptions{
		AuthHostname:   "auth.example.com",
		Tenants:        tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "admin", CIDR: "10.248.1.0/24"})},
		Provisioner:    provisioner,
		MachineSSHKeys: reconciler,
	})

	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	approveRequest := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader("user_code="+login.UserCode+"&action=approve"))
	approveRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveRequest.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), approveRequest)

	// One pre-existing machine that cannot take the key (e.g. built from a
	// non-Sandcastle image) must not block enrolling this device: the poll
	// still approves with the enrollment token, and the failure is surfaced
	// as a warning instead.
	approved := pollDeviceWithSSHKeyForTest(t, handler, login.DeviceCode, validAuthAuthorizedKeyForTest(t))
	if approved.Status != DeviceStatusApproved || approved.Token != "token-admin" {
		t.Fatalf("approved = %#v", approved)
	}
	if len(reconciler.calls) != 1 {
		t.Fatalf("reconciler calls = %#v", reconciler.calls)
	}
	if !strings.Contains(approved.Warning, "script exited 1") || !strings.Contains(approved.Warning, "SSH key was saved") {
		t.Fatalf("warning = %q", approved.Warning)
	}
}

func TestDevicePollRetriesPersonalTenantProvisioningFailure(t *testing.T) {
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	provisioner := &fakePersonalTenantProvisioner{failures: 1}
	handler := NewHandler(db, HandlerOptions{Provisioner: provisioner})
	login, err := CreateDeviceLogin(context.Background(), db, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	approveRequest := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader("user_code="+login.UserCode+"&action=approve"))
	approveRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveRequest.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), approveRequest)

	failed := pollDeviceForTest(t, handler, login.DeviceCode)
	if failed.Status != DeviceStatusPending || !strings.Contains(failed.Message, "provisioning failed") {
		t.Fatalf("failed poll = %#v", failed)
	}
	approved := pollDeviceForTest(t, handler, login.DeviceCode)
	if approved.Status != DeviceStatusApproved || provisioner.calls != 2 {
		t.Fatalf("approved poll = %#v calls=%d", approved, provisioner.calls)
	}
}

// A terminal provisioning error (bad user input, e.g. an immutable-suffix
// conflict) must DENY the device login so the client fails fast with the
// message — not stay pending and re-attempt provisioning on every poll until
// the client times out.
func TestDevicePollDeniesLoginOnTerminalProvisioningError(t *testing.T) {
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	provisioner := &fakePersonalTenantProvisioner{
		terminalErr: tenant.TerminalProvisionError{Err: errors.New(`the Tenant DNS Suffix is immutable: tenant x already uses "castle" (requested "other")`)},
	}
	handler := NewHandler(db, HandlerOptions{Provisioner: provisioner})
	login, err := CreateDeviceLogin(context.Background(), db, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	approveRequest := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader("user_code="+login.UserCode+"&action=approve"))
	approveRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveRequest.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), approveRequest)

	denied := pollDeviceForTest(t, handler, login.DeviceCode)
	if denied.Status != DeviceStatusDenied || !strings.Contains(denied.Message, "immutable") {
		t.Fatalf("terminal-error poll = %#v", denied)
	}
	// The denial is durable: the next poll must NOT re-attempt provisioning.
	again := pollDeviceForTest(t, handler, login.DeviceCode)
	if again.Status != DeviceStatusDenied || provisioner.calls != 1 {
		t.Fatalf("second poll = %#v calls=%d", again, provisioner.calls)
	}
}

func TestDeviceApprovalRequiresGitHubSession(t *testing.T) {
	db := authDBForTest(t)
	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader("user_code="+login.UserCode+"&action=approve"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	NewHandler(db, HandlerOptions{}).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("approve = %d %q", response.Code, response.Body.String())
	}
}

func TestDebugDeviceApprovalWhenConfigured(t *testing.T) {
	db := authDBForTest(t)
	if err := BootstrapAdmins(context.Background(), db, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(db, HandlerOptions{DebugDeviceUser: "admin"})
	request := httptest.NewRequest(http.MethodPost, "/debug/device/approve", strings.NewReader("user_code="+login.UserCode))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("debug approve = %d %q", response.Code, response.Body.String())
	}
	approved := pollDeviceForTest(t, handler, login.DeviceCode)
	if approved.Status != DeviceStatusApproved || approved.UserKey != "admin" {
		t.Fatalf("approved = %#v", approved)
	}
}

func TestDevicePollReturnsConfiguredTailscaleAuthKeyOnlyAfterApproval(t *testing.T) {
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	handler := NewHandler(db, HandlerOptions{TailscaleAuthKey: "tskey-server"})
	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pending := pollDeviceForTest(t, handler, login.DeviceCode)
	if pending.TailscaleAuthKey != "" || strings.Contains(pending.raw, "tskey-server") {
		t.Fatalf("pending poll leaked auth key: %#v raw=%s", pending, pending.raw)
	}
	approveRequest := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader("user_code="+login.UserCode+"&action=approve"))
	approveRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveRequest.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), approveRequest)
	approved := pollDeviceForTest(t, handler, login.DeviceCode)
	if approved.TailscaleAuthKey != "tskey-server" {
		t.Fatalf("tailscale auth key = %q", approved.TailscaleAuthKey)
	}
}

func TestDebugDeviceApprovalRouteAbsentByDefault(t *testing.T) {
	db := authDBForTest(t)
	response := httptest.NewRecorder()
	NewHandler(db, HandlerOptions{}).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/debug/device/approve", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("debug route = %d %q", response.Code, response.Body.String())
	}
}

func TestDeviceCodeExpires(t *testing.T) {
	db := authDBForTest(t)
	login, err := CreateDeviceLogin(context.Background(), db, "", time.Now().Add(-20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	result, err := PollDeviceLogin(context.Background(), db, login.DeviceCode, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != DeviceStatusExpired {
		t.Fatalf("status = %q", result.Status)
	}
}

func assertSchemaVersion(t *testing.T, db *sql.DB) {
	t.Helper()
	var version string
	if err := db.QueryRow("SELECT value FROM auth_app_meta WHERE key = 'schema_version'").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "1" {
		t.Fatalf("schema version = %q", version)
	}
}

func authDBForTest(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func findUserForTest(t *testing.T, db *sql.DB, normalized string) User {
	t.Helper()
	row := db.QueryRow(`
SELECT user_key, github_username, github_username_normalized, github_account_id, github_email, allowlisted, sandcastle_admin
FROM users
WHERE github_username_normalized = ?
`, normalized)
	var user User
	var allowlisted int
	var admin int
	if err := row.Scan(&user.UserKey, &user.GitHubUsername, &user.GitHubUsernameNormalized, &user.GitHubAccountID, &user.GitHubEmail, &allowlisted, &admin); err != nil {
		t.Fatal(err)
	}
	user.Allowlisted = allowlisted == 1
	user.SandcastleAdmin = admin == 1
	return user
}

func createStateForTest(t *testing.T, db *sql.DB) string {
	t.Helper()
	state, err := createOAuthState(context.Background(), db, timeNowForTest())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func timeNowForTest() time.Time {
	return time.Now()
}

func assertNoPersonalTenantProvisioningTables(t *testing.T, db *sql.DB) {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name LIKE '%tenant%'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("browser-only login created tenant-related auth tables, count = %d", count)
	}
}

type devicePollPayloadForTest struct {
	devicePollResponse
	raw string
}

func pollDeviceForTest(t *testing.T, handler http.Handler, deviceCode string) devicePollPayloadForTest {
	t.Helper()
	body := `{"device_code":"` + deviceCode + `"}`
	return pollDeviceBodyForTest(t, handler, body)
}

func pollDeviceWithSSHKeyForTest(t *testing.T, handler http.Handler, deviceCode string, publicKey string) devicePollPayloadForTest {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"device_code":    deviceCode,
		"ssh_public_key": publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pollDeviceBodyForTest(t, handler, string(body))
}

func pollDeviceBodyForTest(t *testing.T, handler http.Handler, body string) devicePollPayloadForTest {
	t.Helper()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/device/poll", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("poll = %d %q", response.Code, response.Body.String())
	}
	var payload devicePollPayloadForTest
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	payload.raw = response.Body.String()
	return payload
}

func validAuthAuthorizedKeyForTest(t *testing.T) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublicKey)))
}

type fakeGitHubClient struct {
	token     string
	profile   GitHubProfile
	verified  GitHubProfile
	verifyErr error
}

func (c fakeGitHubClient) ExchangeCode(ctx context.Context, oauth GitHubOAuth, code string) (string, error) {
	return c.token, nil
}

func (c fakeGitHubClient) Profile(ctx context.Context, accessToken string) (GitHubProfile, error) {
	return c.profile, nil
}

func (c fakeGitHubClient) VerifyUsername(ctx context.Context, username string) (GitHubProfile, error) {
	if c.verifyErr != nil {
		return GitHubProfile{}, c.verifyErr
	}
	if c.verified.Login != "" {
		return c.verified, nil
	}
	return GitHubProfile{Login: username, ID: "1"}, nil
}

func adminSessionCookieForTest(t *testing.T, db *sql.DB) *http.Cookie {
	t.Helper()
	if err := BootstrapAdmins(context.Background(), db, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	sessionID, err := CreateSession(context.Background(), db, "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "sandcastle_session", Value: sessionID}
}

type fakeRestrictedRevoker struct {
	deleted []string
}

func (r *fakeRestrictedRevoker) Delete(ctx context.Context, plan usertrust.UserPlan) error {
	r.deleted = append(r.deleted, plan.User)
	return nil
}

type fakeTenantAccessManager struct {
	usersByTenant map[string][]string
	grants        []usertrust.UserPlan
	revokes       []usertrust.UserPlan
}

func (m *fakeTenantAccessManager) Grant(ctx context.Context, plan usertrust.UserPlan) error {
	m.grants = append(m.grants, plan)
	return nil
}

func (m *fakeTenantAccessManager) Revoke(ctx context.Context, plan usertrust.UserPlan) error {
	m.revokes = append(m.revokes, plan)
	return nil
}

func (m *fakeTenantAccessManager) ListTenantUsers(ctx context.Context, plan usertrust.TenantUsersPlan) (usertrust.TenantUsersResult, error) {
	return usertrust.TenantUsersResult{Tenant: plan.Tenant, IncusProject: plan.IncusProject, Users: append([]string{}, m.usersByTenant[plan.Tenant]...)}, nil
}

type fakeMachineSSHKeyReconciler struct {
	calls []struct {
		tenant string
		user   string
		key    string
	}
	revokes []struct {
		tenant string
		user   string
	}
	reconcileErr error
}

func (r *fakeMachineSSHKeyReconciler) ReconcileUserSSHKey(ctx context.Context, summary tenant.Summary, userKey string, publicKey string) error {
	r.calls = append(r.calls, struct {
		tenant string
		user   string
		key    string
	}{tenant: summary.Tenant, user: userKey, key: publicKey})
	return r.reconcileErr
}

func (r *fakeMachineSSHKeyReconciler) RevokeUserSSHKey(ctx context.Context, summary tenant.Summary, userKey string) error {
	r.revokes = append(r.revokes, struct {
		tenant string
		user   string
	}{tenant: summary.Tenant, user: userKey})
	return nil
}

type fakeTenantSSHKeyUpdater struct {
	calls []struct {
		project string
		key     string
	}
}

func (u *fakeTenantSSHKeyUpdater) SetTenantSSHKey(ctx context.Context, incusProjectName string, sshKey string) error {
	u.calls = append(u.calls, struct {
		project string
		key     string
	}{project: incusProjectName, key: sshKey})
	return nil
}

// authTestTenant describes a v2 tenant fixture. A v2 tenant is TWO or more
// Incus projects: one kind=infra project (<prefix>-<tenant>) carrying the
// CIDR/suffix/Unix-user metadata, plus one kind=project app project per short
// name (<prefix>-<tenant>-<name>, always including "default").
type authTestTenant struct {
	Tenant   string
	UnixUser string
	CIDR     string
	Suffix   string
	Projects []string // extra app-project short names beyond "default"
	Members  []string // Tenant Members of a Shared Tenant (meta.KeyV2Members)
}

// v2TenantProjectsForAuthTest builds the v2 Incus projects backing one or more
// tenants, as tenant.ListForPrefix now reads them (kind=infra + kind=project,
// version=2). It replaces the old v1 kind=tenant single-project fixture.
func v2TenantProjectsForAuthTest(tenants ...authTestTenant) []tenant.IncusProject {
	var projects []tenant.IncusProject
	for _, tt := range tenants {
		infraName := naming.V2IncusProjectPrefix + "-" + tt.Tenant
		infraConfig := map[string]string{
			meta.KeyKind:    meta.KindInfra,
			meta.KeyTenant:  tt.Tenant,
			meta.KeyVersion: "2",
		}
		if tt.CIDR != "" {
			infraConfig[meta.KeyV2CIDR] = tt.CIDR
		}
		if tt.Suffix != "" {
			infraConfig[meta.KeyV2Suffix] = tt.Suffix
		}
		if tt.UnixUser != "" {
			infraConfig[meta.KeyV2User] = tt.UnixUser
		}
		if len(tt.Members) > 0 {
			infraConfig[meta.KeyV2Members] = meta.FormatMembers(tt.Members)
		}
		projects = append(projects, tenant.IncusProject{Name: infraName, Config: infraConfig})
		for _, short := range append([]string{naming.DefaultProjectName}, tt.Projects...) {
			projects = append(projects, tenant.IncusProject{
				Name: infraName + "-" + short,
				Config: map[string]string{
					meta.KeyKind:    meta.KindV2Project,
					meta.KeyTenant:  tt.Tenant,
					meta.KeyVersion: "2",
				},
			})
		}
	}
	return projects
}

func testAuthAdminConfig() config.Admin {
	return config.LoadAdminFromEnv()
}

type fakePersonalTenantProvisioner struct {
	calls       int
	failures    int
	terminalErr error
	users       []User
}

func (p *fakePersonalTenantProvisioner) EnsurePersonalTenant(ctx context.Context, user User, options ProvisionOptions) (PersonalTenantResult, error) {
	p.calls++
	p.users = append(p.users, user)
	if p.terminalErr != nil {
		return PersonalTenantResult{}, p.terminalErr
	}
	if p.calls <= p.failures {
		return PersonalTenantResult{}, errors.New("boom")
	}
	return PersonalTenantResult{
		UserKey:           user.UserKey,
		Tenant:            user.UserKey,
		IncusProject:      "sc-" + user.UserKey,
		AccessibleTenants: []string{user.UserKey},
		Token:             "token-" + user.UserKey,
		RemoteName:        "sandcastle-" + user.UserKey,
		Projects:          []string{"sc-" + user.UserKey},
	}, nil
}

// Regression: the device poll failed live with "database is locked (5)
// (SQLITE_BUSY)" once the svclog sink started writing request rows
// concurrently with user writes — OpenDatabase configured pragmas via a
// one-off Exec, which only applied to a single pooled connection and left the
// default rollback journal with no busy timeout. The pragmas must hold on
// every pooled connection.
func TestOpenDatabaseConfiguresWALAndBusyTimeoutOnEveryConnection(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)

	ctx := context.Background()
	for i := 0; i < 4; i++ {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var mode string
		if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
			t.Fatal(err)
		}
		if !strings.EqualFold(mode, "wal") {
			t.Fatalf("conn %d journal_mode = %q, want wal", i, mode)
		}
		var timeout int
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout); err != nil {
			t.Fatal(err)
		}
		if timeout < 1000 {
			t.Fatalf("conn %d busy_timeout = %d, want >= 1000", i, timeout)
		}
		var fk int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Fatal(err)
		}
		if fk != 1 {
			t.Fatalf("conn %d foreign_keys = %d, want 1", i, fk)
		}
	}
}

// A Cloudflare tunnel gives the origin ~100s before it answers the client 524.
// Provisioning used to run INSIDE the poll request, so a slow tenant bring-up
// (142s measured for a second tenant on majestix) made every poll 524 and the
// login failed. The poll must return "pending" quickly and let the client poll
// again while provisioning continues in the background.
func TestDevicePollDoesNotBlockOnSlowProvisioning(t *testing.T) {
	previous := devicePollProvisionWait
	devicePollProvisionWait = 50 * time.Millisecond
	t.Cleanup(func() { devicePollProvisionWait = previous })

	release := make(chan struct{})
	provisioner := &blockingPersonalTenantProvisioner{release: release}
	db := authDBForTest(t)
	cookie := adminSessionCookieForTest(t, db)
	handler := NewHandler(db, HandlerOptions{
		AuthHostname: "auth.example.com",
		Tenants:      tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "admin", CIDR: "10.248.1.0/24"})},
		Provisioner:  provisioner,
	})
	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	approve := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader("user_code="+login.UserCode+"&action=approve"))
	approve.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approve.AddCookie(cookie)
	handler.ServeHTTP(httptest.NewRecorder(), approve)

	// first poll: provisioning is still running, so it must answer promptly
	start := time.Now()
	pending := pollDeviceBodyForTest(t, handler, `{"device_code":"`+login.DeviceCode+`"}`)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("poll blocked for %s — it must not wait out the provision", elapsed)
	}
	if pending.Status != DeviceStatusPending {
		t.Fatalf("status = %q, want pending while provisioning: %#v", pending.Status, pending)
	}
	if pending.CLIAuthToken != "" || pending.Token != "" {
		t.Fatal("no token may be issued before provisioning completes")
	}

	// a poll arriving while provisioning is in flight must also not block
	start = time.Now()
	stillPending := pollDeviceBodyForTest(t, handler, `{"device_code":"`+login.DeviceCode+`"}`)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("concurrent poll queued behind the provision for %s", elapsed)
	}
	if stillPending.Status != DeviceStatusPending {
		t.Fatalf("status = %q, want pending", stillPending.Status)
	}
	if provisioner.calls() != 1 {
		t.Fatalf("provisioner calls = %d, want exactly 1 in flight", provisioner.calls())
	}

	// let provisioning finish; the next poll returns the approved login
	close(release)
	var approved devicePollPayloadForTest
	for i := 0; i < 100; i++ {
		approved = pollDeviceBodyForTest(t, handler, `{"device_code":"`+login.DeviceCode+`"}`)
		if approved.Status == DeviceStatusApproved {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if approved.Status != DeviceStatusApproved || approved.Token != "token-admin" {
		t.Fatalf("approved = %#v", approved)
	}
}

type blockingPersonalTenantProvisioner struct {
	release chan struct{}
	mu      sync.Mutex
	count   int
}

func (p *blockingPersonalTenantProvisioner) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

func (p *blockingPersonalTenantProvisioner) EnsurePersonalTenant(ctx context.Context, user User, options ProvisionOptions) (PersonalTenantResult, error) {
	p.mu.Lock()
	p.count++
	p.mu.Unlock()
	select {
	case <-p.release:
	case <-ctx.Done():
		return PersonalTenantResult{}, ctx.Err()
	}
	return PersonalTenantResult{
		UserKey:           user.UserKey,
		Tenant:            user.UserKey,
		IncusProject:      "sc-" + user.UserKey,
		AccessibleTenants: []string{user.UserKey},
		Token:             "token-" + user.UserKey,
		RemoteName:        "sandcastle-" + user.UserKey,
	}, nil
}
