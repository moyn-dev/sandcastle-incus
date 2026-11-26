package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
)

// The ADR-0032 client: seven remotes on three installs. obelix and idefix are
// both an install and a remote name; moyn-dev is a tenant of obelix and of
// miraculix.
var adrRemotes = []struct{ remote, host, tenant string }{
	{"asterix", "https://obelix.thieso2.dev", "skorfmann"},
	{"obelix", "https://obelix.thieso2.dev", "thieso2"},
	{"moyn-dev", "https://obelix.thieso2.dev", "moyn-dev"},
	{"sevenhaven", "https://obelix.thieso2.dev", "sevenhaven"},
	{"idefix", "https://idefix.thieso2.dev", "thieso2"},
	{"thies", "https://miraculix.moyn.dev", "thies"},
	{"moyn-dev-miraculix", "https://miraculix.moyn.dev", "moyn-dev"},
}

func adrConfig() scconfig.SandcastleConfig {
	cfg := scconfig.SandcastleConfig{Remote: "obelix", Tenant: "thieso2", Project: "default", AuthHostname: "https://obelix.thieso2.dev",
		Installs: map[string]string{}, RemoteTenants: map[string]string{}, RemoteAuthTokens: map[string]string{}, AuthTokens: map[string]string{}}
	for _, r := range adrRemotes {
		cfg.Installs[r.remote] = r.host
		cfg.RemoteTenants[r.remote] = r.tenant
		cfg.RemoteAuthTokens[r.remote] = "token-" + r.remote
		cfg.AuthTokens[r.host] = "token-" + r.host
	}
	return cfg
}

// seedADRClient writes the fixture's user and Incus config into a temporary
// HOME and moves into an empty directory.
func seedADRClient(t *testing.T) {
	t.Helper()
	useLoginHomeForTest(t)
	for _, key := range []string{"SANDCASTLE_REMOTE", "SANDCASTLE_PROJECT", "SANDCASTLE_TENANT", "SANDCASTLE_AUTH_TOKEN", "SANDCASTLE_AUTH_HOSTNAME", "SANDCASTLE_BROKER"} {
		t.Setenv(key, "")
	}
	t.Setenv("INCUS_CONF", "")
	os.Unsetenv("INCUS_CONF")
	t.Chdir(t.TempDir())
	if err := scconfig.SaveSandcastleConfig(scconfig.DefaultConfigPath(), adrConfig()); err != nil {
		t.Fatal(err)
	}
	shared := scconfig.SharedIncusDir()
	if err := os.MkdirAll(shared, 0700); err != nil {
		t.Fatal(err)
	}
	incusData := "default-remote: obelix\nremotes:\n"
	for _, r := range adrRemotes {
		incusData += "  " + r.remote + ":\n    addr: https://" + r.remote + ".test:8443\n    project: sc2-" + r.tenant + "-default\n"
	}
	if err := os.WriteFile(filepath.Join(shared, "config.yml"), []byte(incusData), 0600); err != nil {
		t.Fatal(err)
	}
	for _, r := range adrRemotes {
		if err := os.MkdirAll(scconfig.ResolveConfigPath(r.remote), 0700); err != nil {
			t.Fatal(err)
		}
	}
}

func adrCommandConfig(t *testing.T, tenants *fakeAuthTenantClient) commandConfig {
	t.Helper()
	admin, err := scconfig.LoadUserWithError()
	if err != nil {
		t.Fatal(err)
	}
	return commandConfig{adminConfig: admin, authTenants: tenants}
}

func TestInstallIndexFromADRClient(t *testing.T) {
	ix := buildInstallIndex(adrConfig())
	if got, want := ix.names(), []string{"idefix", "miraculix", "obelix"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("installs = %v, want %v", got, want)
	}
	for _, tt := range []struct{ install, tenant, remote string }{
		{"miraculix", "moyn-dev", "moyn-dev-miraculix"},
		{"obelix", "moyn-dev", "moyn-dev"},
		{"obelix", "skorfmann", "asterix"},
		{"obelix", "thieso2", "obelix"},
		{"idefix", "thieso2", "idefix"},
		{"miraculix", "sevenhaven", ""},
	} {
		if got := ix.remoteFor(tt.install, tt.tenant); got != tt.remote {
			t.Errorf("remoteFor(%s, %s) = %q, want %q", tt.install, tt.tenant, got, tt.remote)
		}
	}
	if got := ix.installNameOf("asterix"); got != "obelix" {
		t.Fatalf("installNameOf(asterix) = %q", got)
	}
}

// Two installs sharing a first label both take their full Install Label. An
// Auth Hostname with a token but no remote is still an install.
func TestInstallIndexFirstLabelClash(t *testing.T) {
	ix := buildInstallIndex(scconfig.SandcastleConfig{
		Installs:      map[string]string{"a": "https://obelix.thieso2.dev", "b": "https://obelix.moyn.dev/"},
		RemoteTenants: map[string]string{"a": "thieso2", "b": "moyn-dev"},
		AuthTokens:    map[string]string{"https://obelix.thieso2.dev": "t1", "https://idefix.thieso2.dev": "t2"},
	})
	if got, want := ix.names(), []string{"idefix", "obelix-moyn-dev", "obelix-thieso2-dev"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("installs = %v, want %v", got, want)
	}
	if got := ix.remoteFor("obelix-moyn-dev", "moyn-dev"); got != "b" {
		t.Fatalf("remoteFor = %q", got)
	}
}

func TestInstallPathsResolveToTheEnrolledRemote(t *testing.T) {
	seedADRClient(t)
	var notes strings.Builder
	config := adrCommandConfig(t, nil)
	config.stderr = &notes
	for _, tt := range []struct{ arg, want, note string }{
		{"/miraculix/moyn-dev/default/smoke", "moyn-dev-miraculix:default:smoke", ""},
		{"/obelix/moyn-dev/default/smoke", "moyn-dev:default:smoke", ""},
		{"/obelix/skorfmann/default/smoke", "asterix:default:smoke", ""},
		// obelix is an install and a remote: the install reading wins, and
		// reaches the same tenant the remote did.
		{"/obelix/thieso2/default/smoke", "obelix:default:smoke", ""},
		{"/idefix/thieso2/default/smoke", "idefix:default:smoke", ""},
		{"/moyn-dev-miraculix/moyn-dev/default/smoke", "moyn-dev-miraculix:default:smoke", "note: /moyn-dev-miraculix/moyn-dev/default/smoke is /miraculix/moyn-dev/default/smoke"},
		{"/asterix/skorfmann/default/smoke", "asterix:default:smoke", "note: /asterix/skorfmann/default/smoke is /obelix/skorfmann/default/smoke"},
		{"/miraculix/moyn*/default/smoke", "moyn-dev-miraculix:default:smoke", ""},
		{"/*/*/default/smoke", "*:default:smoke", ""},
		{"/**/smoke", "*:*:smoke", ""},
	} {
		notes.Reset()
		got, err := pathToMachineReference(config, tt.arg)
		if err != nil {
			t.Fatalf("%s: %v", tt.arg, err)
		}
		if got != tt.want {
			t.Errorf("pathToMachineReference(%s) = %q, want %q", tt.arg, got, tt.want)
		}
		if note := strings.TrimSpace(notes.String()); (tt.note == "") != (note == "") || !strings.Contains(note, tt.note) {
			t.Errorf("%s: note %q, want %q", tt.arg, note, tt.note)
		}
	}
	for arg, want := range map[string]string{
		"/miraculix/sevenhaven/default/smoke":     "`sc cd /miraculix/sevenhaven` enrols it",
		"/nowhere/thieso2/default/smoke":          `no install "nowhere"; installs: idefix, miraculix, obelix`,
		"/obelix/*/default/smoke":                 "spans 4 tenants",
		"/moyn-dev-miraculix/thies/default/smoke": `remote "moyn-dev-miraculix" serves tenant "moyn-dev", not "thies"`,
	} {
		if _, err := pathToMachineReference(config, arg); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", arg, err, want)
		}
	}
}

func TestLsListsInstallsThenTheAuthAppTenants(t *testing.T) {
	seedADRClient(t)
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{
		{Tenant: "thieso2", Personal: true}, {Tenant: "skorfmann"}, {Tenant: "moyn-dev", Member: true, Shared: true}, {Tenant: "sevenhaven", Member: true, Shared: true},
	}}
	config := adrCommandConfig(t, client)
	if out, err := executeForTestWithConfig(t, config, "ls", "/"); err != nil || strings.TrimSpace(out) != "/\nidefix\nmiraculix\nobelix" {
		t.Fatalf("ls /: %q %v", out, err)
	}
	if out, err := executeForTestWithConfig(t, config, "ls", "/obelix"); err != nil || strings.TrimSpace(out) != "/obelix\nmoyn-dev\nsevenhaven\nskorfmann\nthieso2" {
		t.Fatalf("ls /obelix: %q %v", out, err)
	}
	out, err := executeForTestWithConfig(t, config, "ls", "-l", "/obelix")
	if err != nil || !strings.Contains(out, "SHARED") || !strings.Contains(out, "moyn-dev    member  yes     moyn-dev") || !strings.Contains(out, "skorfmann   owner   no      asterix") {
		t.Fatalf("ls -l /obelix: %q %v", out, err)
	}
}

func TestLsInstallOfflineFallsBackToEnrolledTenants(t *testing.T) {
	seedADRClient(t)
	config := adrCommandConfig(t, &fakeAuthTenantClient{err: errors.New("auth app unreachable")})
	stdout, stderr, err := executeForTestWithConfigAndStderr(t, config, "ls", "/miraculix")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout) != "/miraculix\nmoyn-dev\nthies" {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "auth app unreachable") || !strings.Contains(stderr, "may be incomplete") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestCdIntoAnUnenrolledTenantEnrolsItsRemote(t *testing.T) {
	seedADRClient(t)
	installer := &fakeTenantRemoteInstaller{}
	config := adrCommandConfig(t, &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{
		{Tenant: "thies", Personal: true},
		{Tenant: "moyn-dev", Member: true, Shared: true},
		{Tenant: "sevenhaven", Shared: true, Member: true, DNSSuffix: "sevenhaven", DefaultProject: "default", IncusProject: "sc2-sevenhaven-default", IncusRemoteAddress: "100.64.0.7"},
	}})
	config.tenantRemote = installer
	stdout, _, err := executeForTestWithConfigAndStderr(t, config, "cd", "/miraculix/sevenhaven")
	if err != nil {
		t.Fatalf("cd: %v\n%s", err, stdout)
	}
	if !strings.HasSuffix(strings.TrimSpace(stdout), "/miraculix/sevenhaven") {
		t.Fatalf("stdout = %q", stdout)
	}
	// "sevenhaven" is obelix's remote, so miraculix's tenant gets its own.
	if len(installer.requests) != 1 || installer.requests[0].RemoteName != "sevenhaven-miraculix" {
		t.Fatalf("enrolled %#v", installer.requests)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Installs["sevenhaven-miraculix"] != "https://miraculix.moyn.dev" || cfg.TenantForRemote("sevenhaven-miraculix") != "sevenhaven" || cfg.TenantForRemote("sevenhaven") != "sevenhaven" {
		t.Fatalf("config = %#v", cfg)
	}
	local, _, err := scconfig.LoadDirectoryConfig("")
	if err != nil || local.Remote != "sevenhaven-miraculix" || local.Tenant != "sevenhaven" || local.Level != scconfig.PositionTenant || local.Previous != "/obelix/thieso2/default" {
		t.Fatalf("selection = %+v %v", local, err)
	}
	if got, err := pathToMachineReference(adrCommandConfig(t, nil), "/miraculix/sevenhaven/default/smoke"); err != nil || got != "sevenhaven-miraculix:default:smoke" {
		t.Fatalf("after enrolment: %q %v", got, err)
	}

	if _, err := runCd(context.Background(), config, "/miraculix/nope", false); err == nil || !strings.Contains(err.Error(), `install miraculix does not list tenant "nope"`) {
		t.Fatalf("unlisted tenant: %v", err)
	}
}

func TestCdWritesTheInstallLevelAndReadsOldSelections(t *testing.T) {
	seedADRClient(t)
	// An old selection in every sense: the pre-ADR-0032 level and remote-form
	// previous, under the pre-2026-11-26 file name .sandcastle.
	if err := os.WriteFile(".sandcastle", []byte("remote: moyn-dev-miraculix\nproject: default\ntenant: moyn-dev\nlevel: remote\nprevious: /asterix/skorfmann/default\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := adrCommandConfig(t, nil)
	if out, err := executeForTestWithConfig(t, config, "pwd"); err != nil || strings.TrimSpace(out) != "/miraculix" {
		t.Fatalf("pwd at level remote: %q %v", out, err)
	}
	var notes strings.Builder
	config.stderr = &notes
	out, err := runCd(context.Background(), config, "-", true)
	if err != nil || out.Path != "/obelix/skorfmann/default" || out.Remote != "asterix" || out.Install != "obelix" {
		t.Fatalf("cd - to an old previous: %+v %v", out, err)
	}
	if !strings.Contains(notes.String(), "/asterix/skorfmann/default is /obelix/skorfmann/default") {
		t.Fatalf("notes = %q", notes.String())
	}
	out, err = runCd(context.Background(), adrCommandConfig(t, nil), "/obelix", true)
	if err != nil || out.Path != "/obelix" || out.Level != "install" {
		t.Fatalf("cd /obelix: %+v %v", out, err)
	}
	local, _, err := scconfig.LoadDirectoryConfig("")
	if err != nil || local.Level != scconfig.PositionInstall || local.Remote != "asterix" || local.Previous != "/obelix/skorfmann/default" {
		t.Fatalf("selection = %+v %v", local, err)
	}
	if _, err := os.Stat(scconfig.DirectoryConfigFile); err != nil {
		t.Fatalf("cd did not move the selection to %s: %v", scconfig.DirectoryConfigFile, err)
	}
	if _, err := os.Lstat(".sandcastle"); !os.IsNotExist(err) {
		t.Fatalf("legacy .sandcastle left behind: %v", err)
	}
}

func TestMachineJSONCarriesBothPaths(t *testing.T) {
	seedADRClient(t)
	result := listPayload{Remote: "moyn-dev-miraculix", Machines: []meta.Machine{{Name: "smoke", Project: "default"}}}
	result.Tenant.Tenant = "moyn-dev"
	stampMachinePaths("", &result)
	data, err := json.Marshal(result.Machines[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"path":"/miraculix/moyn-dev/default/smoke"`) || !strings.Contains(string(data), `"remote_path":"/moyn-dev-miraculix/moyn-dev/default/smoke"`) {
		t.Fatalf("json = %s", data)
	}
}

func TestPathCompletionOffersInstallsThenTenants(t *testing.T) {
	seedADRClient(t)
	config := adrCommandConfig(t, &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "thieso2"}, {Tenant: "sevenhaven"}, {Tenant: "skorfmann"}}})
	complete := pathCompletion(config, levelProject)
	for word, want := range map[string][]string{
		"/":          {"/idefix/", "/miraculix/", "/obelix/"},
		"/mi":        {"/miraculix/"},
		"/obelix/s":  {"/obelix/sevenhaven/", "/obelix/skorfmann/"},
		"/obelix/th": {"/obelix/thieso2/"},
	} {
		got, _ := complete(nil, nil, word)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("complete(%q) = %v, want %v", word, got, want)
		}
	}
}
