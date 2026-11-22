package authapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestEnableMachineWorkloadIdentityRotatesSecretAndStoresVerifierOnly(t *testing.T) {
	db := authDBForTest(t)
	first, err := EnableMachineWorkloadIdentity(context.Background(), db, "auth.example.com", MachineRuntimeSecretRequest{
		Tenant:         "acme",
		Project:        "default",
		Machine:        "codex",
		UserKey:        "octocat",
		GitHubUsername: "OctoCat",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnableMachineWorkloadIdentity(context.Background(), db, "auth.example.com", MachineRuntimeSecretRequest{
		Tenant:         "acme",
		Project:        "default",
		Machine:        "codex",
		UserKey:        "octocat",
		GitHubUsername: "OctoCat",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.RuntimeSecret == "" || second.RuntimeSecret == "" || first.RuntimeSecret == second.RuntimeSecret {
		t.Fatalf("secrets were not rotated: %#v %#v", first, second)
	}
	if first.TokenEndpoint != "https://auth.example.com/internal/workload/token" {
		t.Fatalf("token endpoint = %q", first.TokenEndpoint)
	}
	var stored string
	if err := db.QueryRow("SELECT secret_verifier FROM machine_runtime_secrets WHERE tenant = 'acme' AND project = 'default' AND machine = 'codex'").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, first.RuntimeSecret) || strings.Contains(stored, second.RuntimeSecret) {
		t.Fatalf("stored verifier leaked runtime secret: %q", stored)
	}
}

func TestWorkloadTokenEndpointMintsClaimsAndRejectsBadSecret(t *testing.T) {
	db := authDBForTest(t)
	enabled, err := EnableMachineWorkloadIdentity(context.Background(), db, "auth.example.com", MachineRuntimeSecretRequest{
		Tenant:         "acme",
		Project:        "default",
		Machine:        "codex",
		UserKey:        "octocat",
		GitHubUsername: "OctoCat",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(db, HandlerOptions{
		AuthHostname: "auth.example.com",
		Tenants:      tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "acme", CIDR: "10.248.0.0/24"})},
		Machines:     fakeWorkloadMachineStore{machines: []meta.Machine{{Tenant: "acme", Project: "default", Name: "codex"}}},
	})
	requestBody := `{"tenant":"acme","project":"default","machine":"codex","runtime_secret":"` + enabled.RuntimeSecret + `","audience":"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sandcastle-acme/providers/sandcastle"}`
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/internal/workload/token", strings.NewReader(requestBody))
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("token = %d %q", response.Code, response.Body.String())
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ExpiresIn != int((15 * time.Minute).Seconds()) {
		t.Fatalf("expires_in = %d", payload.ExpiresIn)
	}
	claims := jwtClaimsForTest(t, payload.AccessToken)
	for key, want := range map[string]string{
		"iss":                 "https://auth.example.com/t/acme",
		"aud":                 "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sandcastle-acme/providers/sandcastle",
		"tenant":              "acme",
		"project":             "default",
		"machine":             "codex",
		"sandcastle_user_key": "octocat",
		"github_username":     "OctoCat",
	} {
		if claims[key] != want {
			t.Fatalf("claim %s = %#v, want %q in %#v", key, claims[key], want, claims)
		}
	}
	if _, ok := claims["sandbox"]; ok {
		t.Fatalf("claims contain legacy sandbox vocabulary: %#v", claims)
	}

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodPost, "/internal/workload/token", strings.NewReader(`{"tenant":"acme","project":"default","machine":"codex","runtime_secret":"bad","audience":"aud"}`)))
	if bad.Code != http.StatusForbidden {
		t.Fatalf("bad secret = %d %q", bad.Code, bad.Body.String())
	}

	missingAudience := httptest.NewRecorder()
	handler.ServeHTTP(missingAudience, httptest.NewRequest(http.MethodPost, "/internal/workload/token", strings.NewReader(`{"tenant":"acme","project":"default","machine":"codex","runtime_secret":"`+enabled.RuntimeSecret+`"}`)))
	if missingAudience.Code != http.StatusBadRequest {
		t.Fatalf("missing audience = %d %q", missingAudience.Code, missingAudience.Body.String())
	}
}

func TestWorkloadTokenEndpointRejectsDisabledAndDeletedMachine(t *testing.T) {
	db := authDBForTest(t)
	enabled, err := EnableMachineWorkloadIdentity(context.Background(), db, "auth.example.com", MachineRuntimeSecretRequest{
		Tenant:  "acme",
		Project: "default",
		Machine: "codex",
		UserKey: "octocat",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE machine_runtime_secrets SET enabled = 0 WHERE tenant = 'acme'"); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(db, HandlerOptions{AuthHostname: "auth.example.com", Tenants: tenant.MemoryStore{}, Machines: fakeWorkloadMachineStore{}})
	body := `{"tenant":"acme","project":"default","machine":"codex","runtime_secret":"` + enabled.RuntimeSecret + `","audience":"aud"}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/internal/workload/token", strings.NewReader(body)))
	if response.Code != http.StatusForbidden {
		t.Fatalf("disabled = %d %q", response.Code, response.Body.String())
	}

	if _, err := db.Exec("UPDATE machine_runtime_secrets SET enabled = 1 WHERE tenant = 'acme'"); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/internal/workload/token", strings.NewReader(body)))
	if response.Code != http.StatusForbidden {
		t.Fatalf("deleted = %d %q", response.Code, response.Body.String())
	}
}

func TestWorkloadEnableAPIUsesApprovedDeviceAndCloudConfig(t *testing.T) {
	db := authDBForTest(t)
	if err := UpsertUser(context.Background(), db, User{UserKey: "octocat", GitHubUsername: "octocat", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpsertCloudIdentityConfig(context.Background(), db, CloudIdentityConfig{
		UserKey:                           "octocat",
		Tenant:                            "octocat",
		Name:                              "gcp",
		GCPAudience:                       "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sandcastle-acme/providers/sandcastle",
		GCPServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@example.iam.gserviceaccount.com:generateAccessToken",
	}); err != nil {
		t.Fatal(err)
	}
	login, err := CreateDeviceLogin(context.Background(), db, "auth.example.com", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := ApproveDeviceLogin(context.Background(), db, login.UserCode, "octocat", "", "", timeNow()); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(db, HandlerOptions{
		AuthHostname: "auth.example.com",
		Tenants:      tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "octocat", CIDR: "10.248.0.0/24"})},
		Machines:     fakeWorkloadMachineStore{machines: []meta.Machine{{Tenant: "octocat", Project: "default", Name: "codex"}}},
	})
	body := `{"device_code":"` + login.DeviceCode + `","tenant":"octocat","project":"default","machine":"codex","cloud_identity_config":"gcp"}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/workload/enable", strings.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("enable = %d %q", response.Code, response.Body.String())
	}
	var payload WorkloadEnableResult
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.RuntimeSecret == "" || payload.TokenEndpoint != "https://auth.example.com/internal/workload/token" || payload.Issuer != "https://auth.example.com/t/octocat" {
		t.Fatalf("payload = %#v", payload)
	}
	if payload.GCPAudience == "" || payload.GCPServiceAccountImpersonationURL == "" {
		t.Fatalf("missing GCP config in payload: %#v", payload)
	}
	var storedUser string
	if err := db.QueryRow("SELECT user_key FROM machine_runtime_secrets WHERE tenant = 'octocat' AND project = 'default' AND machine = 'codex'").Scan(&storedUser); err != nil {
		t.Fatal(err)
	}
	if storedUser != "octocat" {
		t.Fatalf("stored user = %q", storedUser)
	}
}

func TestWorkloadEnableAPIAcceptsCLIToken(t *testing.T) {
	db := authDBForTest(t)
	if err := UpsertUser(context.Background(), db, User{UserKey: "octocat", GitHubUsername: "octocat", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	token, err := CreateCLIToken(context.Background(), db, "octocat", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(db, HandlerOptions{
		AuthHostname: "auth.example.com",
		Tenants:      tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(authTestTenant{Tenant: "octocat", CIDR: "10.248.0.0/24"})},
		Machines:     fakeWorkloadMachineStore{machines: []meta.Machine{{Tenant: "octocat", Project: "default", Name: "codex"}}},
	})
	body := `{"tenant":"octocat","project":"default","machine":"codex"}`
	request := httptest.NewRequest(http.MethodPost, "/api/workload/enable", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("enable = %d %q", response.Code, response.Body.String())
	}
	var payload WorkloadEnableResult
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.RuntimeSecret == "" || payload.Issuer != "https://auth.example.com/t/octocat" {
		t.Fatalf("payload = %#v", payload)
	}
}

type fakeWorkloadMachineStore struct {
	machines []meta.Machine
}

func (s fakeWorkloadMachineStore) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	return append([]meta.Machine{}, s.machines...), nil
}

func jwtClaimsForTest(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
