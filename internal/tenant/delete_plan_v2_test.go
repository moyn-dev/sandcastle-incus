package tenant

import (
	"context"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

// sc-adm tenant delete on a v2 tenant used to build a v1-shaped plan (sc-<t>
// names that don't exist), delete nothing, and print success. PlanDeleteV2
// must find the v2 tenant scoped to the install prefix, enumerate all its app
// projects + infra project + bridge, and refuse a non-purge delete (the
// shared volumes live in the app projects — there is no runtime-only subset).
func TestPlanDeleteV2(t *testing.T) {
	v2Project := func(name string, tenantName string) IncusProject {
		return IncusProject{Name: name, Config: map[string]string{
			meta.KeyKind:    meta.KindV2Project,
			meta.KeyVersion: "2",
			meta.KeyTenant:  tenantName,
		}}
	}
	store := MemoryStore{Projects: []IncusProject{
		v2Project("sc2-acme-default", "acme"),
		v2Project("sc2-acme-backend", "acme"),
		// same-named tenant of ANOTHER install must not be touched
		v2Project("id-acme-default", "acme"),
	}}
	admin := config.Admin{}

	t.Run("refuses without purge", func(t *testing.T) {
		_, isV2, err := PlanDeleteV2(context.Background(), admin, store, "acme", false)
		if !isV2 || err == nil || !strings.Contains(err.Error(), "--purge") {
			t.Fatalf("isV2=%v err=%v", isV2, err)
		}
	})

	t.Run("plans the current install's projects only", func(t *testing.T) {
		plan, isV2, err := PlanDeleteV2(context.Background(), admin, store, "acme", true)
		if err != nil || !isV2 {
			t.Fatalf("isV2=%v err=%v", isV2, err)
		}
		if plan.InfraProject != "sc2-acme" || plan.Bridge != "sc2-acme" {
			t.Fatalf("plan = %+v", plan)
		}
		if len(plan.AppProjects) != 2 || plan.AppProjects[0] != "sc2-acme-backend" || plan.AppProjects[1] != "sc2-acme-default" {
			t.Fatalf("app projects = %v", plan.AppProjects)
		}
		for _, project := range plan.AppProjects {
			if strings.HasPrefix(project, "id-") {
				t.Fatalf("must not plan the other install's project: %v", plan.AppProjects)
			}
		}
		// The /.sc layers are per-app-project custom volumes like
		// home/workspace: leaving them out makes the project delete fail with
		// "Only empty projects can be removed".
		durable := strings.Join(plan.DurableVolumes, ",")
		for _, volume := range []string{V2HomeVolumeName, V2WorkspaceVolumeName, V2SCPlatformVolumeName, V2SCLocalVolumeName} {
			if !strings.Contains(","+durable+",", ","+volume+",") {
				t.Fatalf("DurableVolumes = %v, missing %s", plan.DurableVolumes, volume)
			}
		}
	})

	t.Run("prefixed install scopes to its own tenant", func(t *testing.T) {
		prefixed := admin
		prefixed.IncusProjectPrefix = "id"
		plan, isV2, err := PlanDeleteV2(context.Background(), prefixed, store, "acme", true)
		if err != nil || !isV2 {
			t.Fatalf("isV2=%v err=%v", isV2, err)
		}
		if plan.InfraProject != "id-acme" || len(plan.AppProjects) != 1 || plan.AppProjects[0] != "id-acme-default" {
			t.Fatalf("plan = %+v", plan)
		}
	})

	t.Run("v1 or unknown tenant falls through", func(t *testing.T) {
		_, isV2, err := PlanDeleteV2(context.Background(), admin, store, "nosuch", true)
		if err != nil || isV2 {
			t.Fatalf("isV2=%v err=%v", isV2, err)
		}
	})
}

// #113: the purge must also sweep the tenant's Incus trust entries, so the
// plan carries the install-scoped certificate name to sweep.
func TestPlanDeleteV2CarriesTrustEntry(t *testing.T) {
	v2Project := func(name string, tenantName string) IncusProject {
		return IncusProject{Name: name, Config: map[string]string{
			meta.KeyKind:    meta.KindV2Project,
			meta.KeyVersion: "2",
			meta.KeyTenant:  tenantName,
		}}
	}
	store := MemoryStore{Projects: []IncusProject{
		v2Project("sc2-acme-default", "acme"),
		v2Project("id-acme-default", "acme"),
	}}

	plan, _, err := PlanDeleteV2(context.Background(), config.Admin{}, store, "acme", true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.TrustEntry != "sandcastle-acme" {
		t.Fatalf("TrustEntry = %q, want sandcastle-acme (default install)", plan.TrustEntry)
	}

	prefixed := config.Admin{IncusProjectPrefix: "id"}
	plan, _, err = PlanDeleteV2(context.Background(), prefixed, store, "acme", true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.TrustEntry != "sandcastle-id-acme" {
		t.Fatalf("TrustEntry = %q, want sandcastle-id-acme (prefixed install)", plan.TrustEntry)
	}
}
