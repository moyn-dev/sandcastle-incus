package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	machine "github.com/moyn-dev/sandcastle-incus/internal/machine"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

// fakeSelectorStore serves a fixed machine set and records whether the CLI
// scoped the query to one project (ProjectScopedStore) or asked for the whole
// tenant.
type fakeSelectorStore struct {
	machines      []meta.Machine
	scopedTo      []string
	wholeTenantOf int
}

func (s *fakeSelectorStore) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	s.wholeTenantOf++
	return append([]meta.Machine{}, s.machines...), nil
}

func (s *fakeSelectorStore) ListMachinesInProject(ctx context.Context, summary tenant.Summary, projectFilter string) ([]meta.Machine, error) {
	s.scopedTo = append(s.scopedTo, projectFilter)
	found := []meta.Machine{}
	for _, candidate := range s.machines {
		if naming.MatchName(projectFilter, candidate.Project) {
			found = append(found, candidate)
		}
	}
	return found, nil
}

var (
	_ machine.Store              = (*fakeSelectorStore)(nil)
	_ machine.ProjectScopedStore = (*fakeSelectorStore)(nil)
)

// The fixture install: tenant "acme" on remote "sc-acme", whose projects
// resolve through the same install-prefix inversion the real CLI uses (see
// TestListMachinesScopedToCurrentInstall), so requireV2Tenant works against it.
func selectorFixture() (tenant.Summary, *fakeSelectorStore) {
	summary := tenant.Summary{
		Tenant:       "acme",
		InfraProject: "sc2-acme",
		Projects: []meta.Project{
			{Name: "gbrain"}, {Name: "gadget"}, {Name: "work"},
		},
	}
	store := &fakeSelectorStore{machines: []meta.Machine{
		{Tenant: "acme", Project: "gbrain", Name: "docker"},
		{Tenant: "acme", Project: "gbrain", Name: "dev"},
		{Tenant: "acme", Project: "gbrain", Name: "web"},
		{Tenant: "acme", Project: "gadget", Name: "dyno"},
		{Tenant: "acme", Project: "work", Name: "web"},
	}}
	return summary, store
}

func selectorConfig(store machine.Store, currentProject string) commandConfig {
	return commandConfig{
		adminConfig:  scconfig.Admin{Tenant: "acme", Remote: "sc-acme", Project: currentProject},
		tenantStore:  tenant.MemoryStore{Projects: listV2Projects("acme", "gbrain", "gadget", "work")},
		machineStore: store,
	}
}

// singleRemoteFanout is the fan-out of a host with exactly one enrolled
// install — the fixture's. Binding to another one is a test failure: nothing
// here should be reaching past the current install.
func singleRemoteFanout() remoteFanout {
	return remoteFanout{
		names: func() ([]string, error) { return []string{"sc-acme"}, nil },
		bind: func(base commandConfig, remote string) (commandConfig, func(), error) {
			return base, func() {}, fmt.Errorf("unexpected bind to remote %q", remote)
		},
	}
}

func TestSelectMachines(t *testing.T) {
	tests := []struct {
		name           string
		reference      string
		currentProject string
		want           []string
	}{
		{"project wildcard", "gbrain:*", "", []string{"gbrain:dev", "gbrain:docker", "gbrain:web"}},
		{"both parts wildcard", "g*:d*", "", []string{"gadget:dyno", "gbrain:dev", "gbrain:docker"}},
		{"machine wildcard across projects", "*:web", "", []string{"gbrain:web", "work:web"}},
		{"literal reference selects one", "gbrain:dev", "", []string{"gbrain:dev"}},
		{"bare wildcard uses the current project", "d*", "gbrain", []string{"gbrain:dev", "gbrain:docker"}},
		{"wildcard matching nothing is an empty set", "gbrain:zzz*", "", nil},
		{"character class", "gbrain:[dw]*", "", []string{"gbrain:dev", "gbrain:docker", "gbrain:web"}},
		{"single-character wildcard", "gbrain:de?", "", []string{"gbrain:dev"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary, store := selectorFixture()
			selector, err := parseMachineSelector(tt.reference, tt.currentProject)
			if err != nil {
				t.Fatalf("parseMachineSelector(%q): %v", tt.reference, err)
			}
			matched, err := selectMachines(context.Background(), selectorConfig(store, tt.currentProject), summary, selector)
			if err != nil {
				t.Fatalf("selectMachines(%q): %v", tt.reference, err)
			}
			got := machineTargets(matched)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("selectMachines(%q) = %v, want %v", tt.reference, got, tt.want)
			}
		})
	}
}

// The project part is pushed into the store whether it is a name or a glob —
// the tenant summary already lists the projects, so no Incus call is needed to
// work out which ones a glob can match. Falling back to a whole-tenant query
// for a glob costs one round trip per project the glob was going to discard.
func TestSelectMachinesPushesTheProjectFilterIntoTheStore(t *testing.T) {
	for _, tt := range []struct {
		reference string
		wantScope string
	}{
		{"gbrain:*", "gbrain"},
		{"g*:*", "g*"},
		{"*:web", "*"},
	} {
		t.Run(tt.reference, func(t *testing.T) {
			summary, store := selectorFixture()
			selector, err := parseMachineSelector(tt.reference, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := selectMachines(context.Background(), selectorConfig(store, ""), summary, selector); err != nil {
				t.Fatal(err)
			}
			if len(store.scopedTo) != 1 || store.scopedTo[0] != tt.wantScope {
				t.Fatalf("scoped queries = %v, want [%q]", store.scopedTo, tt.wantScope)
			}
			if store.wholeTenantOf != 0 {
				t.Fatalf("fell back to a whole-tenant query %d times, want 0", store.wholeTenantOf)
			}
		})
	}
}

// A mistyped literal project must say the project does not exist rather than
// return an empty listing that reads as "no machines".
func TestSelectMachinesRejectsUnknownLiteralProject(t *testing.T) {
	summary, store := selectorFixture()
	selector, err := parseMachineSelector("nope:*", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = selectMachines(context.Background(), selectorConfig(store, ""), summary, selector)
	if err == nil || !strings.Contains(err.Error(), `project "nope" not found`) {
		t.Fatalf("error = %v, want a project-not-found error", err)
	}
}

func TestParseMachineSelector(t *testing.T) {
	tests := []struct {
		reference             string
		wantRemote            string
		wantProject           string
		wantMachine           string
		wantPattern           bool
		wantErrorMentioning   string
		currentProjectDefault string
	}{
		{reference: "web", wantProject: "default", wantMachine: "web"},
		{reference: "gbrain:*", wantProject: "gbrain", wantMachine: "*", wantPattern: true},
		{reference: "g*:d*", wantProject: "g*", wantMachine: "d*", wantPattern: true},
		{reference: "*", wantProject: "default", wantMachine: "*", wantPattern: true},
		{reference: "obelix:gbrain:d*", wantRemote: "obelix", wantProject: "gbrain", wantMachine: "d*", wantPattern: true},
		// The install part globs too — it expands to the enrolled installs
		// matching it (remote_scope.go).
		{reference: "o*:gbrain:web", wantRemote: "o*", wantProject: "gbrain", wantMachine: "web", wantPattern: true},
		// A pattern that path.Match cannot compile is a never-match, not a
		// syntax error, unless it is caught here.
		{reference: "gbrain:[abc", wantErrorMentioning: "invalid machine pattern"},
		{reference: "gbrain:we$b", wantErrorMentioning: "invalid machine"},
	}
	for _, tt := range tests {
		t.Run(tt.reference, func(t *testing.T) {
			selector, err := parseMachineSelector(tt.reference, tt.currentProjectDefault)
			if tt.wantErrorMentioning != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrorMentioning) {
					t.Fatalf("error = %v, want one mentioning %q", err, tt.wantErrorMentioning)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if selector.Remote != tt.wantRemote || selector.Project != tt.wantProject || selector.Machine != tt.wantMachine {
				t.Fatalf("= (%q,%q,%q), want (%q,%q,%q)",
					selector.Remote, selector.Project, selector.Machine, tt.wantRemote, tt.wantProject, tt.wantMachine)
			}
			if selector.HasPattern() != tt.wantPattern {
				t.Fatalf("HasPattern() = %v, want %v", selector.HasPattern(), tt.wantPattern)
			}
		})
	}
}

// A wildcard is a way to SELECT the single machine a one-target command acts
// on; it must never silently pick one of several.
func TestResolveSingleMachineReference(t *testing.T) {
	summary, store := selectorFixture()
	config := selectorConfig(store, "")

	got, err := resolveSingleMachineReference(context.Background(), config, summary, "gbrain:doc*")
	if err != nil {
		t.Fatal(err)
	}
	if got != "gbrain:docker" {
		t.Fatalf("= %q, want %q", got, "gbrain:docker")
	}

	// A literal passes through unresolved — `sc connect` creates machines that
	// do not exist yet, and this helper must not pre-empt that.
	if got, err := resolveSingleMachineReference(context.Background(), config, summary, "gbrain:brand-new"); err != nil || got != "gbrain:brand-new" {
		t.Fatalf("= (%q,%v), want the reference passed through", got, err)
	}

	if _, err := resolveSingleMachineReference(context.Background(), config, summary, "gbrain:zzz*"); err == nil ||
		!strings.Contains(err.Error(), "no machines match") {
		t.Fatalf("error = %v, want a no-match error", err)
	}

	_, err = resolveSingleMachineReference(context.Background(), config, summary, "gbrain:*")
	if err == nil || !strings.Contains(err.Error(), "matches 3 machines") {
		t.Fatalf("error = %v, want an ambiguity error naming the candidates", err)
	}
}
