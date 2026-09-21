package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// multiInstallFanout fakes a host with several enrolled installs, each with its
// own machines. bound records the order installs were entered in, and unbound
// records that each was left again — the INCUS_CONF binding is process-wide, so
// a scope that is entered and never left would corrupt every later command.
type multiInstallFanout struct {
	installs map[string][]meta.Machine
	// projects is each install's OWN project set — they differ in practice,
	// which is exactly what a cross-install sweep has to cope with.
	projects map[string][]string
	names    []string
	bound    []string
	unbound  []string
	failing  map[string]error
}

func newMultiInstallFanout() *multiInstallFanout {
	return &multiInstallFanout{
		names: []string{"idefix", "obelix"},
		installs: map[string][]meta.Machine{
			"idefix": {
				{Tenant: "acme", Project: "gbrain", Name: "dev"},
				{Tenant: "acme", Project: "work", Name: "dev"},
			},
			"obelix": {
				{Tenant: "acme", Project: "gbrain", Name: "dev"},
				{Tenant: "acme", Project: "gbrain", Name: "web"},
			},
		},
		projects: map[string][]string{
			"idefix": {"gbrain", "work"},
			"obelix": {"gbrain", "work"},
		},
		failing: map[string]error{},
	}
}

func (f *multiInstallFanout) fanout() remoteFanout {
	return remoteFanout{
		names: func() ([]string, error) { return f.names, nil },
		bind: func(base commandConfig, remote string) (commandConfig, func(), error) {
			if err := f.failing[remote]; err != nil {
				return base, func() {}, err
			}
			f.bound = append(f.bound, remote)
			scoped := base
			scoped.adminConfig.Remote = remote
			scoped.tenantStore = tenant.MemoryStore{Projects: listV2Projects("acme", f.projects[remote]...)}
			scoped.machineStore = &fakeSelectorStore{machines: f.installs[remote]}
			return scoped, func() { f.unbound = append(f.unbound, remote) }, nil
		},
	}
}

// configFor returns a config whose CURRENT remote is `current`, so the fan-out
// exercises both the bind path and the no-bind path for the current install.
func (f *multiInstallFanout) configFor(current string) commandConfig {
	return commandConfig{
		adminConfig:  scconfig.Admin{Tenant: "acme", Remote: current, Project: ""},
		tenantStore:  tenant.MemoryStore{Projects: listV2Projects("acme", f.projects[current]...)},
		machineStore: &fakeSelectorStore{machines: f.installs[current]},
	}
}

func TestForEachRemoteScopeEntersAndLeavesEachInstall(t *testing.T) {
	fake := newMultiInstallFanout()
	visited := []string{}
	err := fake.fanout().forEachRemoteScope(fake.configFor("obelix"), "*", func(remote string, config commandConfig) error {
		visited = append(visited, remote)
		if config.adminConfig.Remote != remote {
			t.Fatalf("scope %q got a config bound to %q", remote, config.adminConfig.Remote)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(visited, ",") != "idefix,obelix" {
		t.Fatalf("visited = %v, want both installs in name order", visited)
	}
	// "obelix" is the current install, so it is used in place and never bound.
	if strings.Join(fake.bound, ",") != "idefix" || strings.Join(fake.unbound, ",") != "idefix" {
		t.Fatalf("bound=%v unbound=%v, want idefix bound and released, obelix used in place", fake.bound, fake.unbound)
	}
}

// An empty pattern is the overwhelmingly common case and must not bind
// anything: `sc stop web` should not go anywhere near the other installs.
func TestForEachRemoteScopeEmptyPatternStaysOnCurrentInstall(t *testing.T) {
	fake := newMultiInstallFanout()
	visited := []string{}
	err := fake.fanout().forEachRemoteScope(fake.configFor("obelix"), "", func(remote string, config commandConfig) error {
		visited = append(visited, remote)
		return nil
	})
	if err != nil || strings.Join(visited, ",") != "obelix" {
		t.Fatalf("visited = %v (err %v), want only the current install", visited, err)
	}
	if len(fake.bound) != 0 {
		t.Fatalf("bound = %v, want no binding at all", fake.bound)
	}
}

// One unreachable install must not truncate the sweep silently: the others are
// still visited and the failure is reported, named.
func TestForEachRemoteScopeReportsFailuresWithoutTruncating(t *testing.T) {
	fake := newMultiInstallFanout()
	fake.failing["idefix"] = errors.New("connection refused")
	visited := []string{}
	err := fake.fanout().forEachRemoteScope(fake.configFor("obelix"), "*", func(remote string, config commandConfig) error {
		visited = append(visited, remote)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "idefix: connection refused") {
		t.Fatalf("error = %v, want the failing install named", err)
	}
	if strings.Join(visited, ",") != "obelix" {
		t.Fatalf("visited = %v, want the reachable install still swept", visited)
	}
}

func TestForEachRemoteScopeRejectsAPatternMatchingNoInstall(t *testing.T) {
	fake := newMultiInstallFanout()
	err := fake.fanout().forEachRemoteScope(fake.configFor("obelix"), "zz*", func(string, commandConfig) error {
		t.Fatal("fn must not run when no install matches")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), `no enrolled Sandcastle remote matches "zz*"`) {
		t.Fatalf("error = %v, want a no-matching-install error", err)
	}
	if !strings.Contains(err.Error(), "idefix, obelix") {
		t.Fatalf("error = %v, want it to list the enrolled installs", err)
	}
}

// The whole point: "*:*:dev" selects the dev machine of every project of every
// enrolled install.
func TestSelectMachinesAcrossRemotes(t *testing.T) {
	fake := newMultiInstallFanout()
	selector, err := parseMachineSelector("*:*:dev", "")
	if err != nil {
		t.Fatal(err)
	}
	matches, err := selectMachinesAcrossRemotes(context.Background(), fake.configFor("obelix"), fake.fanout(), selector)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(matchTargets(fake.configFor("obelix"), matches), ",")
	want := "/idefix/acme/gbrain/dev,/idefix/acme/work/dev,/obelix/acme/gbrain/dev"
	if got != want {
		t.Fatalf("matches = %s, want %s", got, want)
	}
}

// Selecting across installs must carry each install's OWN tenant summary — the
// Incus project naming and DNS suffix differ per install, so reusing one
// summary would address the wrong project.
func TestSelectMachinesAcrossRemotesCarriesPerInstallSummary(t *testing.T) {
	fake := newMultiInstallFanout()
	selector, err := parseMachineSelector("*:gbrain:web", "")
	if err != nil {
		t.Fatal(err)
	}
	matches, err := selectMachinesAcrossRemotes(context.Background(), fake.configFor("obelix"), fake.fanout(), selector)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %v, want exactly obelix:gbrain:web", matchTargets(fake.configFor("obelix"), matches))
	}
	if matches[0].Summary.Tenant != "acme" || matches[0].Remote != "obelix" {
		t.Fatalf("match = %+v, want the obelix install's summary", matches[0])
	}
}

// A cross-install glob narrowing to one machine is how single-target commands
// (connect, image save) accept it.
func TestNarrowRemoteGlob(t *testing.T) {
	fake := newMultiInstallFanout()
	got, err := narrowRemoteGlob(context.Background(), fake.configFor("obelix"), fake.fanout(), "*:gbrain:web")
	if err != nil {
		t.Fatal(err)
	}
	if got != "obelix:gbrain:web" {
		t.Fatalf("= %q, want a fully qualified obelix:gbrain:web", got)
	}

	// Ambiguous across installs: never a guess.
	_, err = narrowRemoteGlob(context.Background(), fake.configFor("obelix"), fake.fanout(), "*:*:dev")
	if err == nil || !strings.Contains(err.Error(), "matches 3 machines") {
		t.Fatalf("error = %v, want an ambiguity error", err)
	}
	if err != nil && !strings.Contains(err.Error(), "/idefix/acme/gbrain/dev") {
		t.Fatalf("error = %v, want the candidates qualified by install", err)
	}

	// A reference that does not glob the install part is passed through
	// untouched — no sweep, no binding.
	fake = newMultiInstallFanout()
	got, err = narrowRemoteGlob(context.Background(), fake.configFor("obelix"), fake.fanout(), "gbrain:d*")
	if err != nil || got != "gbrain:d*" {
		t.Fatalf("= (%q,%v), want the reference passed through", got, err)
	}
	if len(fake.bound) != 0 {
		t.Fatalf("bound = %v, want no install binding for a single-install reference", fake.bound)
	}
}

func TestListMachinesAcrossRemotes(t *testing.T) {
	fake := newMultiInstallFanout()
	payload, err := listMachinesAcrossRemotes(context.Background(), fake.configFor("obelix"), fake.fanout(), "*",
		listMachinesRequest{Project: "*", Machine: "dev", AllProjects: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Remotes) != 2 {
		t.Fatalf("sections = %d, want one per install", len(payload.Remotes))
	}
	total := 0
	for _, section := range payload.Remotes {
		total += len(section.Machines)
	}
	if total != 3 {
		t.Fatalf("machines = %d, want 3 (2 on idefix, 1 on obelix)", total)
	}
	text := formatMultiMachineList(payload)
	if !strings.Contains(text, "REMOTE") || !strings.Contains(text, "idefix") || !strings.Contains(text, "obelix") {
		t.Fatalf("text output missing the REMOTE column or an install:\n%s", text)
	}
}

// A listing survives a broken install: it warns and shows the rest, rather than
// failing whole. (The lifecycle verbs do the opposite — see lifecycleTargets.)
func TestListMachinesAcrossRemotesWarnsOnUnreachableInstall(t *testing.T) {
	fake := newMultiInstallFanout()
	fake.failing["idefix"] = errors.New("connection refused")
	payload, err := listMachinesAcrossRemotes(context.Background(), fake.configFor("obelix"), fake.fanout(), "*",
		listMachinesRequest{Project: "*", Machine: "*", AllProjects: true})
	if err != nil {
		t.Fatalf("a partly-reachable sweep must not fail: %v", err)
	}
	if len(payload.Warnings) != 1 || !strings.Contains(payload.Warnings[0], "idefix") {
		t.Fatalf("warnings = %v, want the unreachable install named", payload.Warnings)
	}
	if len(payload.Remotes) != 1 || payload.Remotes[0].Remote != "obelix" {
		t.Fatalf("sections = %+v, want the reachable install's machines", payload.Remotes)
	}
	if !strings.Contains(formatMultiMachineList(payload), "warning: idefix") {
		t.Fatal("text output must carry the warning")
	}
}

// Installs have different project sets, so a literal project that is absent on
// one install is not an error for a cross-install sweep — it just means there
// is nothing to match there. Failing whole would make "*:web:api" unusable the
// moment one install has no "web".
func TestSelectMachinesAcrossRemotesToleratesProjectMissingOnSomeInstalls(t *testing.T) {
	fake := newMultiInstallFanout()
	// Only idefix has a "work" project; obelix has never heard of it.
	fake.projects["obelix"] = []string{"gbrain"}
	fake.installs["idefix"] = []meta.Machine{{Tenant: "acme", Project: "work", Name: "api"}}
	fake.installs["obelix"] = []meta.Machine{{Tenant: "acme", Project: "gbrain", Name: "api"}}
	selector, err := parseMachineSelector("*:work:api", "")
	if err != nil {
		t.Fatal(err)
	}
	matches, err := selectMachinesAcrossRemotes(context.Background(), fake.configFor("obelix"), fake.fanout(), selector)
	if err != nil {
		t.Fatalf("sweep failed because one install lacks the project: %v", err)
	}
	if got := strings.Join(matchTargets(fake.configFor("obelix"), matches), ","); got != "/idefix/acme/work/api" {
		t.Fatalf("matches = %q, want only the install that has the project, named", got)
	}
}

// …but a project no install has is still a typo, and must say so rather than
// come back as "no machines match".
func TestSelectMachinesAcrossRemotesRejectsProjectMissingEverywhere(t *testing.T) {
	fake := newMultiInstallFanout()
	selector, err := parseMachineSelector("*:nosuch:api", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = selectMachinesAcrossRemotes(context.Background(), fake.configFor("obelix"), fake.fanout(), selector)
	if err == nil || !strings.Contains(err.Error(), `project "nosuch" not found`) {
		t.Fatalf("error = %v, want a project-not-found error", err)
	}
}
