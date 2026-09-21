package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// stubAuthHostnames is the test authMachineHostnameClient: it records every
// call and can refuse a given hostname with a server-shaped error.
type stubAuthHostnames struct {
	calls   []string
	refuse  map[string]error
	held    map[string][]string // "project:machine" → explicit names
	derived string
}

func (s *stubAuthHostnames) result(project, machine string) authapp.MachineHostnamesResult {
	result := authapp.MachineHostnamesResult{Tenant: "demo", Project: project, Machine: machine}
	if s.derived != "" {
		result.Hostnames = append(result.Hostnames, authapp.MachineHostnameView{Hostname: machine + "." + s.derived, Derived: true, Zone: "hase.de"})
	}
	for _, name := range s.held[project+":"+machine] {
		result.Hostnames = append(result.Hostnames, authapp.MachineHostnameView{Hostname: name, Zone: "tc42.uk"})
	}
	return result
}

func (s *stubAuthHostnames) ListMachineHostnames(_ context.Context, tenantName, project, machine string) (authapp.MachineHostnamesResult, error) {
	s.calls = append(s.calls, "list "+tenantName+" "+project+":"+machine)
	if err := s.refuse["list"]; err != nil {
		return authapp.MachineHostnamesResult{}, err
	}
	return s.result(project, machine), nil
}

func (s *stubAuthHostnames) AddMachineHostname(_ context.Context, request authapp.MachineHostnameRequest, project, machine string) (authapp.MachineHostnamesResult, error) {
	s.calls = append(s.calls, "add "+request.Tenant+" "+project+":"+machine+" "+request.Hostname+" dry="+boolString(request.DryRun)+" before="+boolString(request.BeforeCreate))
	if err := s.refuse[request.Hostname]; err != nil {
		return authapp.MachineHostnamesResult{}, err
	}
	if !request.DryRun {
		if s.held == nil {
			s.held = map[string][]string{}
		}
		s.held[project+":"+machine] = append(s.held[project+":"+machine], request.Hostname)
	}
	result := s.result(project, machine)
	result.Hostname, result.Zone, result.DryRun = request.Hostname, "tc42.uk", request.DryRun
	result.Certificate = &authapp.MachineCertificateView{Hostname: request.Hostname, State: "pending"}
	if request.DryRun {
		result.Hostnames = append(result.Hostnames, authapp.MachineHostnameView{Hostname: request.Hostname, Zone: "tc42.uk"})
	}
	return result, nil
}

func (s *stubAuthHostnames) RemoveMachineHostname(_ context.Context, tenantName, project, machine, hostname string, dryRun bool) (authapp.MachineHostnamesResult, error) {
	s.calls = append(s.calls, "remove "+tenantName+" "+project+":"+machine+" "+hostname+" dry="+boolString(dryRun))
	if err := s.refuse["remove:"+hostname]; err != nil {
		return authapp.MachineHostnamesResult{}, err
	}
	if !dryRun && s.held != nil {
		var kept []string
		for _, name := range s.held[project+":"+machine] {
			if name != hostname {
				kept = append(kept, name)
			}
		}
		s.held[project+":"+machine] = kept
	}
	result := s.result(project, machine)
	result.Hostname, result.Released, result.Zone, result.DryRun = hostname, hostname, "tc42.uk", dryRun
	return result, nil
}

// hostnameTestConfig wires a tenant with one project and one machine so the
// verbs resolve "zp:web" without touching Incus.
func hostnameTestConfig(t *testing.T, stub *stubAuthHostnames) (commandConfig, *bytes.Buffer) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", "")
	var stdout bytes.Buffer
	return commandConfig{
		adminConfig:          scconfig.Admin{AuthHostname: "https://idefix.example.dev", AuthToken: "tok", Tenant: "demo", Project: "zp"},
		authMachineHostnames: stub,
		tenantStore:          tenant.MemoryStore{Projects: listV2Projects("demo", "zp", "default")},
		machineStore:         fakeInstallMachineStore{byInfraProject: map[string][]meta.Machine{"sc2-demo": {{Tenant: "demo", Project: "zp", Name: "web"}}}},
		stdout:               &stdout,
		stderr:               &bytes.Buffer{},
	}, &stdout
}

func TestHostnameAddRemoveListRideTheAuthApp(t *testing.T) {
	stub := &stubAuthHostnames{derived: "baum.hase.de"}
	config, stdout := hostnameTestConfig(t, stub)
	opts := &rootOptions{output: outputText}

	add := newHostnameCommand(config, opts)
	add.SetArgs([]string{"add", "zp:web", "Web12.TC42.uk."})
	if err := add.Execute(); err != nil {
		t.Fatalf("add: %v", err)
	}
	if strings.Join(stub.calls, ",") != "add demo zp:web web12.tc42.uk dry=false before=false" {
		t.Fatalf("calls = %v", stub.calls)
	}
	want := "Public name: web12.tc42.uk (certificate pending)\n" +
		"PUBLIC NAME       KIND      ZONE\n" +
		"web.baum.hase.de  derived   hase.de\n" +
		"web12.tc42.uk     explicit  tc42.uk\n"
	if stdout.String() != want {
		t.Fatalf("add output:\n%s\nwant:\n%s", stdout.String(), want)
	}

	stdout.Reset()
	stub.calls = nil
	list := newHostnameCommand(config, opts)
	list.SetArgs([]string{"list", "zp:web"})
	if err := list.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}
	if strings.Join(stub.calls, ",") != "list demo zp:web" || !strings.Contains(stdout.String(), "web12.tc42.uk     explicit  tc42.uk") {
		t.Fatalf("list: calls=%v stdout=%q", stub.calls, stdout.String())
	}

	stdout.Reset()
	stub.calls = nil
	remove := newHostnameCommand(config, opts)
	remove.SetArgs([]string{"remove", "zp:web", "web12.tc42.uk", "--dry-run"})
	if err := remove.Execute(); err != nil {
		t.Fatalf("remove dry run: %v", err)
	}
	if strings.Join(stub.calls, ",") != "remove demo zp:web web12.tc42.uk dry=true" || !strings.HasPrefix(stdout.String(), "[dry-run] would have: released web12.tc42.uk from machine zp:web; project certificate unchanged, per-name certificate retained\n") {
		t.Fatalf("remove dry run: calls=%v stdout=%q", stub.calls, stdout.String())
	}
	stdout.Reset()
	remove = newHostnameCommand(config, opts)
	remove.SetArgs([]string{"rm", "zp:web", "web12.tc42.uk"})
	if err := remove.Execute(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	want = "Released web12.tc42.uk from machine zp:web.\n" +
		"PUBLIC NAME       KIND     ZONE\n" +
		"web.baum.hase.de  derived  hase.de\n"
	if stdout.String() != want {
		t.Fatalf("remove output:\n%s\nwant:\n%s", stdout.String(), want)
	}

	// JSON carries the full set.
	stdout.Reset()
	list = newHostnameCommand(config, &rootOptions{output: outputJSON})
	list.SetArgs([]string{"list", "zp:web"})
	if err := list.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"hostname": "web.baum.hase.de",
      "derived": true,
      "zone": "hase.de"`) {
		t.Fatalf("json = %s", stdout.String())
	}
}

func TestHostnameVerbsRefuseMalformedLocallyAndPrintServerErrorsVerbatim(t *testing.T) {
	stub := &stubAuthHostnames{refuse: map[string]error{"web12.tc42.uk": errors.New(`machine hostname "web12.tc42.uk" overlaps a name already claimed on this install; choose another`)}}
	config, _ := hostnameTestConfig(t, stub)
	opts := &rootOptions{output: outputText}
	for _, hostname := range []string{"_x.tc42.uk", "*.*.tc42.uk", "bad name"} {
		add := newHostnameCommand(config, opts)
		add.SetArgs([]string{"add", "zp:web", hostname})
		if err := add.Execute(); err == nil || !strings.HasPrefix(err.Error(), "invalid machine hostname") {
			t.Fatalf("%s: err = %v", hostname, err)
		}
	}
	if len(stub.calls) != 0 {
		t.Fatalf("malformed hostnames reached the server: %v", stub.calls)
	}
	add := newHostnameCommand(config, opts)
	add.SetArgs([]string{"add", "zp:web", "web12.tc42.uk"})
	err := add.Execute()
	if err == nil || err.Error() != `machine hostname "web12.tc42.uk" overlaps a name already claimed on this install; choose another` {
		t.Fatalf("server refusal: %v", err)
	}
	// Without a login the verbs print the one unavailable sentence.
	config.authMachineHostnames = nil
	config.adminConfig.AuthToken = ""
	list := newHostnameCommand(config, opts)
	list.SetArgs([]string{"list", "zp:web"})
	if err := list.Execute(); err == nil || err.Error() != hostnameVerbsUnavailable {
		t.Fatalf("no login: %v", err)
	}
}

// `sc create --hostname`: every name is claimed BEFORE the instance exists
// (beforeCreate), a refusal releases what was already claimed and creates
// nothing, and a failed create releases every claim.
func TestCreateHostnamesClaimBeforeCreateAndReleaseOnFailure(t *testing.T) {
	ctx := context.Background()
	stub := &stubAuthHostnames{refuse: map[string]error{"taken.tc42.uk": errors.New(`machine hostname "taken.tc42.uk" is reserved by this install`)}}
	names, err := normalizeHostnameFlags([]string{" Web12.TC42.uk. ", "web12.tc42.uk", "", "api.tc42.uk"})
	if err != nil || strings.Join(names, ",") != "api.tc42.uk,web12.tc42.uk" {
		t.Fatalf("normalize: %v, %v", names, err)
	}
	if _, err := normalizeHostnameFlags([]string{"_x.tc42.uk"}); err == nil {
		t.Fatal("malformed --hostname accepted")
	}

	claimed, err := claimMachineHostnamesBeforeCreate(ctx, stub, "demo", "zp", "web", []string{"api.tc42.uk", "taken.tc42.uk", "web12.tc42.uk"}, false)
	if err == nil || err.Error() != `machine hostname "taken.tc42.uk" is reserved by this install` || claimed != nil {
		t.Fatalf("refusal: %v, %v", claimed, err)
	}
	if strings.Join(stub.calls, "|") != "add demo zp:web api.tc42.uk dry=false before=true|add demo zp:web taken.tc42.uk dry=false before=true|remove demo zp:web api.tc42.uk dry=false" {
		t.Fatalf("calls = %v", stub.calls)
	}

	stub.calls = nil
	claimed, err = claimMachineHostnamesBeforeCreate(ctx, stub, "demo", "zp", "web", []string{"api.tc42.uk", "web12.tc42.uk"}, false)
	if err != nil || len(claimed) != 2 || claimed[0].Hostname != "api.tc42.uk" || claimed[1].Outcome.State != "pending" {
		t.Fatalf("claims: %+v, %v", claimed, err)
	}
	if errs := releaseMachineHostnames(ctx, stub, "demo", "zp", "web", claimed); len(errs) != 0 {
		t.Fatalf("release: %v", errs)
	}
	if strings.Join(stub.calls, "|") != "add demo zp:web api.tc42.uk dry=false before=true|add demo zp:web web12.tc42.uk dry=false before=true|remove demo zp:web api.tc42.uk dry=false|remove demo zp:web web12.tc42.uk dry=false" {
		t.Fatalf("calls = %v", stub.calls)
	}

	// A dry run validates server-side and releases nothing.
	stub.calls = nil
	if _, err := claimMachineHostnamesBeforeCreate(ctx, stub, "demo", "zp", "web", []string{"api.tc42.uk", "taken.tc42.uk"}, true); err == nil {
		t.Fatal("dry run must surface the refusal")
	}
	if strings.Join(stub.calls, "|") != "add demo zp:web api.tc42.uk dry=true before=true|add demo zp:web taken.tc42.uk dry=true before=true" {
		t.Fatalf("dry-run calls = %v", stub.calls)
	}
}

// `sc create --hostname` / `--fqdn` are one repeatable list, and the flags
// are refused without a login before anything is created.
func TestCreateHostnameFlagsAreOneListAndNeedALogin(t *testing.T) {
	stub := &stubAuthHostnames{}
	config, _ := hostnameTestConfig(t, stub)
	config.authMachineHostnames = nil
	config.adminConfig.AuthToken = ""
	command := newCreateCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"zp:web", "--hostname", "web12.tc42.uk", "--fqdn", "api.tc42.uk", "--dry-run"})
	err := command.Execute()
	if err == nil || err.Error() != hostnameVerbsUnavailable {
		t.Fatalf("create without login: %v", err)
	}
	flag := command.Flags().Lookup("hostname")
	if flag == nil || flag.Value.String() != "[web12.tc42.uk api.tc42.uk]" {
		t.Fatalf("--hostname/--fqdn list = %v", flag)
	}
}

func TestCreateAliasesDryRunAndValidation(t *testing.T) {
	stub := &stubAuthHostnames{}
	config, stdout := hostnameTestConfig(t, stub)
	summary := tenant.Summary{Tenant: "demo", Projects: []meta.Project{{Name: "zp", Domain: "baum.hase.de"}}}
	opts := &rootOptions{output: outputText}
	err := runCreateMachineV2(context.Background(), config, opts, summary, "zp:new", createV2Options{DryRun: true, Aliases: []string{"admin-new", "console-new"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(stub.calls) != 2 || !strings.Contains(stub.calls[0], "admin-new.baum.hase.de dry=true before=true") || !strings.Contains(stub.calls[1], "console-new.baum.hase.de dry=true before=true") {
		t.Fatalf("claims: %v", stub.calls)
	}
	if !strings.Contains(stdout.String(), "served by project certificate") {
		t.Fatalf("plan: %s", stdout.String())
	}
	for _, label := range []string{"a.b", "*", ""} {
		if err := runCreateMachineV2(context.Background(), config, opts, summary, "zp:new", createV2Options{DryRun: true, Aliases: []string{label}}); err == nil {
			t.Fatalf("invalid alias accepted: %q", label)
		}
	}
	summary.Projects[0].Domain = ""
	if err := runCreateMachineV2(context.Background(), config, opts, summary, "zp:new", createV2Options{DryRun: true, Aliases: []string{"admin"}}); err == nil {
		t.Fatal("alias without domain accepted")
	}
}
