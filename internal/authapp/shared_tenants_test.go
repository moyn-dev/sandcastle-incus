package authapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

type fakeTenantMembershipManager struct {
	added, removed []string
	rendered       []string
}

func (m *fakeTenantMembershipManager) AddTenantMemberV2(_ context.Context, _ string, tenantName string, userKey string) ([]string, error) {
	m.added = append(m.added, tenantName+":"+userKey)
	return []string{userKey}, nil
}

func (m *fakeTenantMembershipManager) RemoveTenantMemberV2(_ context.Context, _ string, tenantName string, userKey string) ([]string, error) {
	m.removed = append(m.removed, tenantName+":"+userKey)
	return nil, nil
}

func (m *fakeTenantMembershipManager) RenderTenantProfilesV2(_ context.Context, _ string, tenantName string) error {
	m.rendered = append(m.rendered, tenantName)
	return nil
}

type fakeSidecarAddressReader struct{ byTenant map[string]string }

func (r fakeSidecarAddressReader) SidecarTailnetIPV2(_ context.Context, _ string, tenantName string) (string, error) {
	return r.byTenant[tenantName], nil
}

type fakeTenantProjectCreator struct {
	created []string
	images  []string
}

func (c *fakeTenantProjectCreator) SetProjectImage(_ context.Context, tenantName, project, image string) error {
	c.images = append(c.images, tenantName+"/"+project+"="+image)
	return nil
}
func (c *fakeTenantProjectCreator) CreateTenantProjectWithDomain(_ context.Context, tenantName, project, _, domain string) (projectbroker.ProjectResult, error) {
	return projectbroker.ProjectResult{Tenant: tenantName, Project: project, Domain: domain}, nil
}
func (c *fakeTenantProjectCreator) RerenderProjectProfiles(_ context.Context, tenantName, project string) error {
	c.images = append(c.images, "rerender:"+tenantName+"/"+project)
	return nil
}

func (c *fakeTenantProjectCreator) SetProjectDomain(context.Context, string, string, string) error {
	return nil
}
func (c *fakeTenantProjectCreator) SetMachinePublicHostnames(context.Context, string, string, string, []string) error {
	return nil
}
func (c *fakeTenantProjectCreator) DeleteTenantProject(context.Context, string, string) error {
	return nil
}

func (c *fakeTenantProjectCreator) CreateTenantProject(_ context.Context, tenantName, project, _ string) (projectbroker.ProjectResult, error) {
	c.created = append(c.created, tenantName+"/"+project)
	return projectbroker.ProjectResult{Tenant: tenantName, Project: project, IncusProject: "sc2-" + tenantName + "-" + project}, nil
}

// sharedTenantHandler: two Personal Tenants (thieso2, skorfmann) plus the
// Shared Tenant moyn-dev owned by nobody in particular, with both as members.
func sharedTenantHandler(t *testing.T, members *fakeTenantMembershipManager, projects *fakeTenantProjectCreator) (http.Handler, map[string]string) {
	t.Helper()
	db := authDBForTest(t)
	tokens := map[string]string{}
	for _, user := range []string{"thieso2", "skorfmann", "mallory"} {
		if err := UpsertUser(context.Background(), db, User{UserKey: user, GitHubUsername: user, Allowlisted: true}); err != nil {
			t.Fatal(err)
		}
		token, err := CreateCLIToken(context.Background(), db, user, timeNow())
		if err != nil {
			t.Fatal(err)
		}
		tokens[user] = token
	}
	handler := NewHandler(db, HandlerOptions{
		AuthHostname: "sc2.thieso2.dev",
		Admin:        testAuthAdminConfig(),
		Tenants: tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(
			authTestTenant{Tenant: "thieso2", CIDR: "10.248.1.0/24"},
			authTestTenant{Tenant: "skorfmann", CIDR: "10.248.2.0/24"},
			authTestTenant{Tenant: "moyn-dev", CIDR: "10.248.3.0/24", Suffix: "moyn", Projects: []string{"web"}, Members: []string{"thieso2", "skorfmann"}},
		)},
		TenantAccess:     &fakeTenantAccessManager{},
		TenantMembers:    members,
		SidecarAddresses: fakeSidecarAddressReader{byTenant: map[string]string{"moyn-dev": "100.64.0.9"}},
		Projects:         projects,
		ProjectDomains:   projects,
	})
	return handler, tokens
}

func TestProjectImageAPIWritesThroughTheAdminSeamForTheRequestTenant(t *testing.T) {
	projects := &fakeTenantProjectCreator{}
	handler, tokens := sharedTenantHandler(t, &fakeTenantMembershipManager{}, projects)
	req := httptest.NewRequest(http.MethodPut, "/api/projects/web/image", strings.NewReader(`{"image":"images:ubuntu/26.04/cloud"}`))
	req.Header.Set("Authorization", "Bearer "+tokens["skorfmann"])
	req.Header.Set(TenantHeader, "moyn-dev")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("set image = %d %q", res.Code, res.Body.String())
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/projects/web/image", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["skorfmann"])
	req.Header.Set(TenantHeader, "moyn-dev")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !slices.Equal(projects.images, []string{"moyn-dev/web=images:ubuntu/26.04/cloud", "moyn-dev/web="}) {
		t.Fatalf("unset = %d images = %v", res.Code, projects.images)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/projects/web/profile", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["skorfmann"])
	req.Header.Set(TenantHeader, "moyn-dev")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || projects.images[len(projects.images)-1] != "rerender:moyn-dev/web" {
		t.Fatalf("rerender = %d images = %v", res.Code, projects.images)
	}
	req = httptest.NewRequest(http.MethodPut, "/api/projects/web/image", strings.NewReader(`{"image":"bad ref"}`))
	req.Header.Set("Authorization", "Bearer "+tokens["thieso2"])
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("bad ref = %d", res.Code)
	}
}

func TestTenantsAPIListsSharedTenantMembershipWithRemoteDetails(t *testing.T) {
	handler, tokens := sharedTenantHandler(t, &fakeTenantMembershipManager{}, &fakeTenantProjectCreator{})
	req := httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["skorfmann"])
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("tenants = %d %q", res.Code, res.Body.String())
	}
	var payload TenantAccessListResult
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var names []string
	var shared TenantAccessSummary
	for _, tenantView := range payload.Tenants {
		names = append(names, tenantView.Tenant)
		if tenantView.Tenant == "moyn-dev" {
			shared = tenantView
		}
	}
	if !slices.Equal(names, []string{"moyn-dev", "skorfmann"}) {
		t.Fatalf("accessible tenants = %v", names)
	}
	if !shared.Shared || !shared.Member || shared.DNSSuffix != "moyn" || shared.DefaultProject != "default" ||
		shared.IncusProject != "sc2-moyn-dev-default" || shared.IncusRemoteAddress != "100.64.0.9" ||
		!slices.Equal(shared.Projects, []string{"default", "web"}) || !slices.Equal(shared.Members, []string{"skorfmann", "thieso2"}) {
		t.Fatalf("shared tenant view = %#v", shared)
	}
	// A non-member sees only their own tenant.
	req = httptest.NewRequest(http.MethodGet, "/api/tenants", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["mallory"])
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if strings.Contains(res.Body.String(), "moyn-dev") {
		t.Fatalf("non-member sees the shared tenant: %s", res.Body.String())
	}
}

func TestProjectsAPIActsOnTheRequestTenantForMembersOnly(t *testing.T) {
	projects := &fakeTenantProjectCreator{}
	handler, tokens := sharedTenantHandler(t, &fakeTenantMembershipManager{}, projects)
	post := func(user, tenantHeader string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/projects", strings.NewReader(`{"project":"api"}`))
		req.Header.Set("Authorization", "Bearer "+tokens[user])
		if tenantHeader != "" {
			req.Header.Set(TenantHeader, tenantHeader)
		}
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	if res := post("skorfmann", "moyn-dev"); res.Code != http.StatusOK {
		t.Fatalf("member create = %d %q", res.Code, res.Body.String())
	}
	if res := post("thieso2", ""); res.Code != http.StatusOK {
		t.Fatalf("own create = %d %q", res.Code, res.Body.String())
	}
	if res := post("mallory", "moyn-dev"); res.Code != http.StatusForbidden {
		t.Fatalf("non-member create = %d %q, want 403", res.Code, res.Body.String())
	}
	if !slices.Equal(projects.created, []string{"moyn-dev/api", "thieso2/api"}) {
		t.Fatalf("created = %v", projects.created)
	}
}

func TestAdminGrantAndRevokeMaintainTenantMembership(t *testing.T) {
	members := &fakeTenantMembershipManager{}
	db := authDBForTest(t)
	access := &fakeTenantAccessManager{}
	handler := NewHandler(db, HandlerOptions{
		Admin: testAuthAdminConfig(),
		Tenants: tenant.MemoryStore{Projects: v2TenantProjectsForAuthTest(
			authTestTenant{Tenant: "moyn-dev", CIDR: "10.248.3.0/24", Projects: []string{"web"}, Members: []string{"thieso2"}},
		)},
		TenantAccess:  access,
		TenantMembers: members,
	})
	form := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(adminSessionCookieForTest(t, db))
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res
	}
	if res := form("/admin/access/grant", "tenant=moyn-dev&user=skorfmann"); res.Code != http.StatusSeeOther {
		t.Fatalf("grant = %d %q", res.Code, res.Body.String())
	}
	// The certificate grant spans every app project the tenant has, and the
	// membership is recorded in Tenant Metadata.
	if len(access.grants) != 1 || !slices.Equal(access.grants[0].Projects, []string{"sc-moyn-dev", "sc-moyn-dev-default", "sc-moyn-dev-web"}) {
		t.Fatalf("grants = %#v", access.grants)
	}
	if !slices.Equal(members.added, []string{"moyn-dev:skorfmann"}) {
		t.Fatalf("added = %v", members.added)
	}
	if res := form("/admin/access/revoke", "tenant=moyn-dev&user=thieso2"); res.Code != http.StatusSeeOther {
		t.Fatalf("revoke = %d %q", res.Code, res.Body.String())
	}
	if len(access.revokes) != 1 || !slices.Equal(members.removed, []string{"moyn-dev:thieso2"}) {
		t.Fatalf("revokes = %#v removed = %v", access.revokes, members.removed)
	}
}
