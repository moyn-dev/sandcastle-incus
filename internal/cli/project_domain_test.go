package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// ── sc project create --domain ───────────────────────────────────────────────

func TestProjectCreateWithDomainRidesTheAuthApp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")
	stub := &stubAuthProjects{}
	var stdout, stderr bytes.Buffer
	command := newProjectCreateV2Command(commandConfig{
		adminConfig:  scconfig.Admin{AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
		authProjects: stub,
		stdout:       &stdout,
		stderr:       &stderr,
	}, &rootOptions{output: outputText})
	command.SetArgs([]string{"zp", "--domain", "Baum.Hase.DE."})
	if err := command.Execute(); err != nil {
		t.Fatalf("create --domain: %v (stderr: %s)", err, stderr.String())
	}
	// Normalized client-side, claimed server-side.
	if strings.Join(stub.calls, ",") != "create zp baum.hase.de false" {
		t.Fatalf("calls = %v", stub.calls)
	}
	if !strings.Contains(stdout.String(), "Project zp created") || !strings.Contains(stdout.String(), "Project domain: baum.hase.de (zone hase.de)") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestProjectCreateDomainRejectsMalformedLocally(t *testing.T) {
	stub := &stubAuthProjects{}
	for _, domain := range []string{"_acme.hase.de", "*.hase.de", "bad domain"} {
		var stdout, stderr bytes.Buffer
		command := newProjectCreateV2Command(commandConfig{
			adminConfig:  scconfig.Admin{AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
			authProjects: stub,
			stdout:       &stdout,
			stderr:       &stderr,
		}, &rootOptions{output: outputText})
		command.SetArgs([]string{"zp", "--domain", domain})
		err := command.Execute()
		if err == nil || !strings.HasPrefix(err.Error(), "invalid project domain") {
			t.Fatalf("%s: err = %v", domain, err)
		}
	}
	if len(stub.calls) != 0 {
		t.Fatalf("malformed domain reached the server: %v", stub.calls)
	}
}

func TestProjectCreateDomainDryRunAndVerbatimRefusal(t *testing.T) {
	stub := &stubAuthProjects{}
	var stdout, stderr bytes.Buffer
	config := commandConfig{
		adminConfig:  scconfig.Admin{AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
		authProjects: stub,
		stdout:       &stdout,
		stderr:       &stderr,
	}
	command := newProjectCreateV2Command(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"zp", "--domain", "baum.hase.de", "--dry-run"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stub.calls, ",") != "create zp baum.hase.de true" || !strings.Contains(stdout.String(), "[dry-run] would have: created project zp with project domain baum.hase.de (zone hase.de)") {
		t.Fatalf("dry run: calls=%v stdout=%q", stub.calls, stdout.String())
	}

	// The server's refusal text is printed as-is, nothing prepended.
	refusal := `project domain "baum.hase.de" overlaps a domain already claimed on this install; choose another`
	stub.fail = errors.New(refusal)
	command = newProjectCreateV2Command(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"zp", "--domain", "baum.hase.de"})
	err := command.Execute()
	if err == nil || err.Error() != refusal {
		t.Fatalf("refusal: %v", err)
	}
}

// Broker-only installs (no Auth App login) cannot claim a domain; the verb
// says so instead of silently creating a private project.
func TestProjectCreateDomainUnavailableWithoutAuthApp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	command := newProjectCreateV2Command(commandConfig{
		adminConfig: scconfig.Admin{Broker: "https://broker.example:9443", Tenant: "demo"},
		stdout:      &stdout,
		stderr:      &stderr,
	}, &rootOptions{output: outputText})
	command.SetArgs([]string{"zp", "--domain", "baum.hase.de"})
	err := command.Execute()
	if err == nil || err.Error() != "--domain is not available on this install" {
		t.Fatalf("err = %v", err)
	}
	// --broker forces the broker path even when a login exists.
	stub := &stubAuthProjects{}
	command = newProjectCreateV2Command(commandConfig{
		adminConfig:  scconfig.Admin{AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
		authProjects: stub,
		stdout:       &stdout,
		stderr:       &stderr,
	}, &rootOptions{output: outputText})
	command.SetArgs([]string{"zp", "--domain", "baum.hase.de", "--broker", "https://broker.example:9443"})
	err = command.Execute()
	if err == nil || err.Error() != "--domain is not available on this install" || len(stub.calls) != 0 {
		t.Fatalf("--broker: err = %v, calls = %v", err, stub.calls)
	}
}

// ── set-domain / unset-domain ────────────────────────────────────────────────

func TestProjectSetDomainWiring(t *testing.T) {
	stub := &stubAuthProjects{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  scconfig.Admin{Remote: "sc-demo", AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
	}, "project", "set-domain", "zp", "Baum.hase.de")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(stub.calls, ",") != "set-domain zp baum.hase.de false" {
		t.Fatalf("calls = %v", stub.calls)
	}
	if strings.TrimSpace(stdout) != "claimed project domain baum.hase.de (zone hase.de) for project zp — one project certificate for baum.hase.de, *.baum.hase.de" {
		t.Fatalf("stdout = %q", stdout)
	}

	// --dry-run is forwarded and rendered.
	stub.calls = nil
	stdout, err = executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  scconfig.Admin{Remote: "sc-demo", AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
	}, "project", "set-domain", "zp", "baum.hase.de", "--dry-run")
	if err != nil || strings.Join(stub.calls, ",") != "set-domain zp baum.hase.de true" || !strings.HasPrefix(stdout, "[dry-run] would have: claimed project domain baum.hase.de") {
		t.Fatalf("dry run: %v %v %q", err, stub.calls, stdout)
	}

	// The same-project identical re-claim is a no-op with exit 0.
	stub.alreadyClaimed = true
	stdout, err = executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  scconfig.Admin{Remote: "sc-demo", AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
	}, "project", "set-domain", "zp", "baum.hase.de")
	if err != nil || strings.TrimSpace(stdout) != `project domain "baum.hase.de" already claimed by this project` {
		t.Fatalf("re-claim: %v %q", err, stdout)
	}

	// Refusals come through verbatim.
	stub.fail = errors.New(`project domain "baum.hase.de" overlaps a domain already claimed on this install; choose another`)
	_, err = executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  scconfig.Admin{Remote: "sc-demo", AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
	}, "project", "set-domain", "zp", "baum.hase.de")
	if err == nil || err.Error() != stub.fail.Error() {
		t.Fatalf("refusal: %v", err)
	}

	// Malformed domains never leave the client.
	stub.calls = nil
	_, err = executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  scconfig.Admin{Remote: "sc-demo", AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
	}, "project", "set-domain", "zp", "_x.hase.de")
	if err == nil || !strings.HasPrefix(err.Error(), "invalid project domain") || len(stub.calls) != 0 {
		t.Fatalf("malformed: %v %v", err, stub.calls)
	}
}

func TestProjectUnsetDomainWiring(t *testing.T) {
	stub := &stubAuthProjects{released: "baum.hase.de"}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  scconfig.Admin{Remote: "sc-demo", AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
	}, "project", "unset-domain", "zp")
	if err != nil || strings.Join(stub.calls, ",") != "unset-domain zp false" || strings.TrimSpace(stdout) != "released project domain baum.hase.de from project zp — drop project certificate" {
		t.Fatalf("unset: %v %v %q", err, stub.calls, stdout)
	}
	stub.calls, stub.released = nil, ""
	stdout, err = executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  scconfig.Admin{Remote: "sc-demo", AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo"},
	}, "project", "unset-domain", "zp", "--dry-run")
	if err != nil || strings.Join(stub.calls, ",") != "unset-domain zp true" || strings.TrimSpace(stdout) != "[dry-run] would have: project zp has no project domain to release" {
		t.Fatalf("dry run: %v %v %q", err, stub.calls, stdout)
	}
}

func TestProjectDomainVerbsUnavailableWithoutLogin(t *testing.T) {
	for _, args := range [][]string{{"project", "set-domain", "zp", "baum.hase.de"}, {"project", "unset-domain", "zp"}} {
		_, err := executeForTestWithConfig(t, commandConfig{name: "sandcastle"}, args...)
		if err == nil || err.Error() != "--domain is not available on this install" {
			t.Fatalf("%v: err = %v", args, err)
		}
	}
}

// ── sc project status ────────────────────────────────────────────────────────

func TestProjectStatusShowsDomainNoneForPrivateProject(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		tenantStore:  tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{{Tenant: "acme", Project: "website", Name: "codex"}}},
	}, "project", "status", "website")
	if err != nil {
		t.Fatal(err)
	}
	want := "Project: website\nTenant: acme\nMachines: 1\nDomain: (none)"
	if strings.TrimSpace(stdout) != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
}

func TestProjectStatusRendersDomainAndMachineTable(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "zp")
	projects[2].Config[meta.KeyV2Domain] = "baum.hase.de"
	stub := &stubAuthProjects{domain: "baum.hase.de", zone: "hase.de"}
	config := commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  scconfig.Admin{Remote: "sc-acme", StoragePool: "default", AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "acme"},
		tenantStore:  tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{
			// Derived + explicit (ADR-0028): one row per name, the mirror per
			// name; NOT AFTER is the machine's earliest installed expiry.
			{Tenant: "acme", Project: "zp", Name: "web", PublicHostname: "shop.tc42.uk", PublicHostnames: []string{"shop.tc42.uk", "web.baum.hase.de"},
				CertStates: map[string]string{"shop.tc42.uk": "installed", "web.baum.hase.de": "issued"}, CertState: "issued", CertNotAfter: "2026-12-11T09:14:00Z"},
			// A legacy cache payload with the single folded state still renders.
			{Tenant: "acme", Project: "zp", Name: "api", PublicHostname: "api.baum.hase.de"},
			{Tenant: "acme", Project: "zp", Name: "old"},
			{Tenant: "acme", Project: "zp", Name: "bad", PublicHostname: "bad.baum.hase.de", CertState: "failed:rate-limited"},
			{Tenant: "acme", Project: "default", Name: "shell"},
		}},
	}
	stdout, err := executeForTestWithConfig(t, config, "project", "status", "zp")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"Project: zp",
		"Tenant: acme",
		"Machines: 4",
		"Domain: baum.hase.de   (zone hase.de)",
		"MACHINE  PUBLIC NAME       CERT       NOT AFTER             DETAIL",
		"web      shop.tc42.uk      installed  2026-12-11T09:14:00Z",
		"web      web.baum.hase.de  issued     -",
		"api      api.baum.hase.de  pending    -",
		"old      -                 -          -                     private name only",
		"bad      bad.baum.hase.de  failed     -                     rate-limited",
	}, "\n")
	if strings.TrimSpace(stdout) != want {
		t.Fatalf("stdout =\n%s\nwant\n%s", stdout, want)
	}
	if strings.Join(stub.calls, ",") != "get-domain zp,get-domain zp" {
		t.Fatalf("calls = %v", stub.calls)
	}

	stdout, err = executeForTestWithConfig(t, config, "--output", "json", "project", "status", "zp")
	if err != nil {
		t.Fatal(err)
	}
	var payload projectStatusPayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Domain != "baum.hase.de" || payload.Zone != "hase.de" || len(payload.Machines) != 5 || payload.Machines[0].PublicHostname != "shop.tc42.uk" || payload.Machines[0].CertState != "installed" || payload.Machines[1].CertState != "issued" || payload.Machines[4].Detail != "rate-limited" {
		t.Fatalf("payload = %#v", payload)
	}

	// A project without a domain shows the table once a machine carries an
	// explicit hostname — and only then.
	projects[1].Config[meta.KeyV2Domain] = ""
	stdout, err = executeForTestWithConfig(t, config, "project", "status", "default")
	if err != nil || !strings.HasSuffix(strings.TrimSpace(stdout), "Domain: (none)") {
		t.Fatalf("private project without hostnames: %v %q", err, stdout)
	}
	config.machineStore = fakeMachineStatusStore{machines: []meta.Machine{
		{Tenant: "acme", Project: "default", Name: "solo", PublicHostnames: []string{"solo.tc42.uk"}, CertStates: map[string]string{"solo.tc42.uk": "installed"}, CertState: "installed", CertNotAfter: "2026-12-01T00:00:00Z"},
		{Tenant: "acme", Project: "default", Name: "shell"},
	}}
	stdout, err = executeForTestWithConfig(t, config, "project", "status", "default")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"Domain: (none)",
		"MACHINE  PUBLIC NAME   CERT       NOT AFTER             DETAIL",
		"solo     solo.tc42.uk  installed  2026-12-01T00:00:00Z",
		"shell    -             -          -                     private name only",
	} {
		if !strings.Contains(stdout, line) {
			t.Fatalf("private project with a hostname lacks %q:\n%s", line, stdout)
		}
	}

	// Without a login the zone is simply omitted — the status never fails on it.
	stdout, err = executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		tenantStore:  tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{},
	}, "project", "status", "zp")
	if err != nil || !strings.Contains(stdout, "Domain: baum.hase.de\n") || strings.Contains(stdout, "zone") {
		t.Fatalf("no login: %v %q", err, stdout)
	}
}

// ── sc project delete ────────────────────────────────────────────────────────

func TestProjectDeletePrefersTheAuthAppEndpoint(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	// PlanDeleteProject validates the full admin config; start from the test
	// default and add the login.
	admin := testAdminConfig()
	admin.AuthHostname, admin.AuthToken = "https://idefix.example.dev", "tok"
	stub := &stubAuthProjects{released: "baum.hase.de"}
	deleter := &fakeProjectDeleter{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:           "sandcastle",
		authProjects:   stub,
		projectDeleter: deleter,
		adminConfig:    admin,
		tenantStore:    tenant.MemoryStore{Projects: projects},
		machineStore:   fakeMachineStatusStore{},
	}, "project", "delete", "website", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(stub.calls, ",") != "delete website false" || deleter.incusProject != "" {
		t.Fatalf("calls = %v, direct delete = %q", stub.calls, deleter.incusProject)
	}
	if strings.TrimSpace(stdout) != "deleted project website and released project domain baum.hase.de" {
		t.Fatalf("stdout = %q", stdout)
	}
	// A non-empty project is still refused client-side, before any call.
	stub.calls = nil
	_, err = executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authProjects: stub,
		adminConfig:  admin,
		tenantStore:  tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{{Tenant: "acme", Project: "website", Name: "codex"}}},
	}, "project", "delete", "website", "--yes")
	if err == nil || !strings.Contains(err.Error(), "still contains machine codex") || len(stub.calls) != 0 {
		t.Fatalf("non-empty: %v %v", err, stub.calls)
	}
	// A deployment without the endpoint falls back to the direct path.
	stub.fail = errors.New("project deletion is not available on this deployment")
	if _, err := executeForTestWithConfig(t, commandConfig{
		name:           "sandcastle",
		authProjects:   stub,
		projectDeleter: deleter,
		adminConfig:    admin,
		tenantStore:    tenant.MemoryStore{Projects: projects},
		machineStore:   fakeMachineStatusStore{},
	}, "project", "delete", "website", "--yes"); err != nil {
		t.Fatal(err)
	}
	if deleter.incusProject != "sc2-acme-website" {
		t.Fatalf("fallback did not delete directly: %q", deleter.incusProject)
	}
}

// formatProjectDomainResult covers every verb's phrasing, including dry runs.
func TestFormatProjectDomainResult(t *testing.T) {
	cases := []struct {
		verb   string
		result authapp.ProjectDomainResult
		want   string
	}{
		{"set-domain", authapp.ProjectDomainResult{Project: "zp", Domain: "baum.hase.de", Zone: "hase.de"}, "claimed project domain baum.hase.de (zone hase.de) for project zp — one project certificate for baum.hase.de, *.baum.hase.de"},
		{"set-domain", authapp.ProjectDomainResult{Project: "zp", Domain: "baum.hase.de", Zone: "hase.de", DryRun: true}, "[dry-run] would have: claimed project domain baum.hase.de (zone hase.de) for project zp — one project certificate for baum.hase.de, *.baum.hase.de"},
		{"set-domain", authapp.ProjectDomainResult{Project: "zp", Domain: "baum.hase.de", AlreadyClaimed: true}, `project domain "baum.hase.de" already claimed by this project`},
		{"unset-domain", authapp.ProjectDomainResult{Project: "zp", Released: "baum.hase.de"}, "released project domain baum.hase.de from project zp — drop project certificate"},
		{"delete", authapp.ProjectDomainResult{Project: "zp"}, "deleted project zp"},
		{"delete", authapp.ProjectDomainResult{Project: "zp", Released: "baum.hase.de", DryRun: true}, "[dry-run] would have: deleted project zp and released project domain baum.hase.de"},
	}
	for _, tc := range cases {
		if got := formatProjectDomainResult(tc.verb, tc.result); got != tc.want {
			t.Fatalf("%s %+v: %q, want %q", tc.verb, tc.result, got, tc.want)
		}
	}
}
