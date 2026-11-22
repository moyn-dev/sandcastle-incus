package tenant

import (
	"context"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

func TestPlanCreateProjectAddsNamespace(t *testing.T) {
	admin := config.LoadAdminFromEnv()
	admin.Tenant = "acme"
	plan, err := PlanCreateProject(context.Background(), admin, tenantStoreForUpdateTest(t, "default"), ProjectMutationRequest{Name: "website"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "create" || plan.Project.Name != "website" || len(plan.Projects) != 2 {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanCreateProjectAcceptsLeadingDigit(t *testing.T) {
	admin := config.LoadAdminFromEnv()
	admin.Tenant = "acme"
	plan, err := PlanCreateProject(context.Background(), admin, tenantStoreForUpdateTest(t, "default"), ProjectMutationRequest{Name: "7ed"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Project.Name != "7ed" {
		t.Fatalf("project name = %q", plan.Project.Name)
	}
}

func TestPlanCreateProjectRejectsDefault(t *testing.T) {
	admin := config.LoadAdminFromEnv()
	admin.Tenant = "acme"
	_, err := PlanCreateProject(context.Background(), admin, tenantStoreForUpdateTest(t, "default"), ProjectMutationRequest{Name: "default"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error = %q", err)
	}
}

func TestPlanDeleteProjectRejectsNonEmpty(t *testing.T) {
	admin := config.LoadAdminFromEnv()
	admin.Tenant = "acme"
	_, err := PlanDeleteProject(context.Background(), admin, tenantStoreForUpdateTest(t, "default", "website"), ProjectMutationRequest{
		Name:     "website",
		Machines: []meta.Machine{{Project: "website", Name: "codex"}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "still contains machine") {
		t.Fatalf("error = %q", err)
	}
}

func TestPlanDeleteProjectRemovesNamespace(t *testing.T) {
	admin := config.LoadAdminFromEnv()
	admin.Tenant = "acme"
	plan, err := PlanDeleteProject(context.Background(), admin, tenantStoreForUpdateTest(t, "default", "website"), ProjectMutationRequest{Name: "website"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "delete" || len(plan.Projects) != 1 || plan.Projects[0].Name != "default" {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanSetProjectCloudIdentityUpdatesDefaultProject(t *testing.T) {
	admin := config.LoadAdminFromEnv()
	admin.Tenant = "acme"
	plan, err := PlanSetProjectCloudIdentity(context.Background(), admin, tenantStoreForUpdateTest(t, "default"), ProjectMutationRequest{
		Name:          "default",
		CloudIdentity: "gcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != "set cloud identity on" || plan.Project.Name != "default" || plan.Project.CloudIdentity != "gcp" {
		t.Fatalf("plan = %#v", plan)
	}
	if len(plan.Projects) != 1 || plan.Projects[0].CloudIdentity != "gcp" {
		t.Fatalf("projects = %#v", plan.Projects)
	}
}

func tenantStoreForUpdateTest(t *testing.T, names ...string) MemoryStore {
	t.Helper()
	return MemoryStore{Projects: v2ProjectsForTest("acme", "10.248.0.0/24", names...)}
}
