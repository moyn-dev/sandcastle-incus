package authapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestMachineSSHUserPrefersUnixUserNotTenantName(t *testing.T) {
	cases := []struct {
		name    string
		summary tenant.Summary
		machine meta.Machine
		want    string
	}{
		{
			name:    "v2 uses the profile login user, not the tenant name",
			summary: tenant.Summary{Tenant: "thieso2", Version: 2, UnixUser: "thies"},
			machine: meta.Machine{PrivateIP: "10.0.0.5"},
			want:    "thies",
		},
		{
			name:    "v2 without a recorded user falls back to the v2 default, never the tenant name",
			summary: tenant.Summary{Tenant: "thieso2", Version: 2},
			machine: meta.Machine{PrivateIP: "10.0.0.5"},
			want:    tenant.DefaultV2UnixUser,
		},
		{
			name:    "explicit machine Linux user wins",
			summary: tenant.Summary{Tenant: "thieso2", Version: 2, UnixUser: "thies"},
			machine: meta.Machine{PrivateIP: "10.0.0.5", LinuxUser: "root"},
			want:    "root",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := machineSSHUser(tc.summary, tc.machine); got != tc.want {
				t.Fatalf("machineSSHUser = %q, want %q", got, tc.want)
			}
			url := string(machineSSHURL(tc.summary, tc.machine))
			if want := "ssh://" + tc.want + "@10.0.0.5"; url != want {
				t.Fatalf("machineSSHURL = %q, want %q", url, want)
			}
			if strings.Contains(url, "thieso2@") {
				t.Fatalf("SSH URL must not use the tenant name as the user: %q", url)
			}
		})
	}
}

func TestMachinesWebRedirectsWhenNotLoggedIn(t *testing.T) {
	db := authDBForTest(t)
	request := httptest.NewRequest(http.MethodGet, "/machines", nil)
	response := httptest.NewRecorder()

	NewHandler(db, HandlerOptions{}).ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/" {
		t.Fatalf("machines redirect = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestMachinesWebListsAccessibleMachinesWithSSHLink(t *testing.T) {
	db := authDBForTest(t)
	if err := UpsertUser(context.Background(), db, User{UserKey: "alice", GitHubUsername: "alice", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	sessionID, err := CreateSession(context.Background(), db, "alice", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	handler := NewHandler(db, HandlerOptions{
		Admin: testAuthAdminConfig(),
		// v2 access is by tenant name == user key (machines_web.go): alice can
		// see the tenant named "alice", never a foreign tenant, so the accessible
		// tenant is alice's own and the inaccessible one belongs to someone else.
		Tenants: tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(
			authTestTenant{Tenant: "alice", UnixUser: "alice", CIDR: "10.248.1.0/24"},
			authTestTenant{Tenant: "other", CIDR: "10.248.2.0/24"},
		)},
		TenantAccess: &fakeTenantAccessManager{usersByTenant: map[string][]string{"alice": {"alice"}}},
		Machines: fakeMachinesByTenant{machines: map[string][]meta.Machine{
			"alice": {{Tenant: "alice", Project: "default", Name: "dev", PrivateIP: "10.248.1.20", Running: true}},
			"other": {{Tenant: "other", Project: "default", Name: "secret", PrivateIP: "10.248.2.9"}},
		}},
	})

	request := httptest.NewRequest(http.MethodGet, "/machines", nil)
	request.AddCookie(&http.Cookie{Name: "sandcastle_session", Value: sessionID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("machines = %d %q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "ssh://alice@10.248.1.20") {
		t.Fatalf("expected ssh link for accessible machine, got:\n%s", body)
	}
	if !strings.Contains(body, "dev.default.alice") {
		t.Fatalf("expected FQDN for accessible machine, got:\n%s", body)
	}
	if strings.Contains(body, "10.248.2.9") || strings.Contains(body, "secret") {
		t.Fatalf("leaked machine from inaccessible tenant:\n%s", body)
	}
}

type fakeMachinesByTenant struct {
	machines map[string][]meta.Machine
}

func (s fakeMachinesByTenant) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	return append([]meta.Machine{}, s.machines[summary.Tenant]...), nil
}
