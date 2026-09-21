package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

func TestIsPathReference(t *testing.T) {
	for arg, want := range map[string]bool{
		"/obelix/acme/web/dev": true, "..": true, ".": true, "-": true, "~": true, "~/web": true, "../*dev": true, "./dev": true,
		"dev": false, "web:dev": false, "obelix:web:dev": false, "acme@obelix:web:dev": false, "g*:d*": false, "": false,
	} {
		if got := isPathReference(arg); got != want {
			t.Errorf("isPathReference(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestResolvePathAgainstPosition(t *testing.T) {
	at := func(level string) commandConfig {
		return commandConfig{adminConfig: scconfig.Admin{Remote: "obelix", Tenant: "acme", Project: "web", PositionLevel: level}}
	}
	tests := []struct {
		name   string
		config commandConfig
		arg    string
		want   string
	}{
		{"absolute", at(""), "/asterix/acme/api/dev", "/asterix/acme/api/dev"},
		{"relative machine", at(""), "dev", "/obelix/acme/web/dev"},
		{"dot machine", at(""), "./dev", "/obelix/acme/web/dev"},
		{"parent", at(""), "..", "/obelix/acme"},
		{"sibling glob", at(""), "../*dev", "/obelix/acme/*dev"},
		{"up twice", at(""), "../..", "/obelix"},
		{"above root stays root", at(""), "../../../../..", "/"},
		{"tenant level", at(scconfig.PositionTenant), "api", "/obelix/acme/api"},
		{"root level", at(scconfig.PositionRoot), "obelix/acme", "/obelix/acme"},
		{"trailing slash", at(""), "/obelix/acme/", "/obelix/acme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments, err := resolvePath(tt.config, tt.arg)
			if err != nil {
				t.Fatal(err)
			}
			if got := formatPath(segments); got != tt.want {
				t.Fatalf("resolvePath(%q) = %s, want %s", tt.arg, got, tt.want)
			}
		})
	}
	if _, err := resolvePath(at(""), "/a/b/c/d/e"); err == nil || !strings.Contains(err.Error(), "deeper than a machine") {
		t.Fatalf("expected depth error, got %v", err)
	}
	// The position defaults to the project level and the default project.
	segments, err := resolvePath(commandConfig{adminConfig: scconfig.Admin{Remote: "obelix", Tenant: "acme"}}, ".")
	if err != nil || formatPath(segments) != "/obelix/acme/default" {
		t.Fatalf("default project position: %v %v", segments, err)
	}
}

// seedEnrolledRemotes writes a global config and an incus config with two
// enrolled installs, the way the directory-selection tests do.
func seedEnrolledRemotes(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	for _, key := range []string{"SANDCASTLE_REMOTE", "SANDCASTLE_PROJECT", "SANDCASTLE_TENANT", "SANDCASTLE_AUTH_TOKEN", "SANDCASTLE_BROKER"} {
		t.Setenv(key, "")
	}
	global := scconfig.SandcastleConfig{Remote: "alpha", Project: "default", Tenant: "acme", Installs: map[string]string{"alpha": "a.test", "beta": "b.test"}, RemoteTenants: map[string]string{"alpha": "acme", "beta": "globex"}, RemoteAuthTokens: map[string]string{"alpha": "alpha-secret", "beta": "beta-secret"}}
	if err := scconfig.SaveSandcastleConfig(scconfig.DefaultConfigPath(), global); err != nil {
		t.Fatal(err)
	}
	shared := scconfig.SharedIncusDir()
	if err := os.MkdirAll(shared, 0700); err != nil {
		t.Fatal(err)
	}
	incusData := "default-remote: alpha\nremotes:\n  alpha:\n    addr: https://a.test\n    project: sc-acme-default\n  beta:\n    addr: https://b.test\n    project: sc-globex-backend\n"
	if err := os.WriteFile(filepath.Join(shared, "config.yml"), []byte(incusData), 0600); err != nil {
		t.Fatal(err)
	}
	for _, remote := range []string{"alpha", "beta"} {
		if err := os.MkdirAll(scconfig.ResolveConfigPath(remote), 0700); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPathToMachineReference(t *testing.T) {
	seedEnrolledRemotes(t)
	config := commandConfig{adminConfig: scconfig.Admin{Remote: "alpha", Tenant: "acme", Project: "web"}}
	tests := []struct {
		arg  string
		want string
	}{
		{"/alpha/acme/web/dev", "alpha:web:dev"},
		{"./dev", "alpha:web:dev"},
		{"../api/dev", "alpha:api:dev"},
		{"/beta/globex/backend/d*", "beta:backend:d*"},
		{"/*/*/*/dev", "*:*:dev"},
		{"/**/dev", "*:*:dev"},
		{"/alpha/**/dev", "alpha:*:dev"},
		{"/alpha/acme/**", "alpha:*:*"},
		{"/alpha/acme/web/**", "alpha:web:*"},
	}
	for _, tt := range tests {
		got, err := pathToMachineReference(config, tt.arg)
		if err != nil {
			t.Fatalf("%s: %v", tt.arg, err)
		}
		if got != tt.want {
			t.Fatalf("pathToMachineReference(%q) = %q, want %q", tt.arg, got, tt.want)
		}
	}
	for arg, want := range map[string]string{
		"..":                     "names a tenant",
		"/gamma/acme/web/dev":    "no enrolled Sandcastle remote",
		"/beta/acme/backend/dev": "serves tenant",
	} {
		if _, err := pathToMachineReference(config, arg); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want error containing %q", arg, err, want)
		}
	}
	// The colon grammar passes through normalizeReference untouched.
	if got, err := normalizeReference(config, "web:dev"); err != nil || got != "web:dev" {
		t.Fatalf("normalizeReference(colon) = %q, %v", got, err)
	}
}

// cd writes the same .sandcastle the switch commands write, plus the level
// and the previous position; pwd reads it back; ls at the tenant level lists
// projects.
func TestCdPwdLsAcrossLevels(t *testing.T) {
	seedEnrolledRemotes(t)
	dir := t.TempDir()
	t.Chdir(dir)
	store := infoV2ProjectStore("sc2-acme-default", "sc2-acme-web", "sc2-acme-webdev", "sc2-acme-api")
	run := func(args ...string) string {
		t.Helper()
		cfg, err := scconfig.LoadUserWithError()
		if err != nil {
			t.Fatal(err)
		}
		out, err := executeForTestWithConfig(t, commandConfig{adminConfig: cfg, tenantStore: store, machineStore: fakeInstallMachineStore{byInfraProject: map[string][]meta.Machine{
			"sc2-acme": {{Name: "dev", Project: "web", Running: true}, {Name: "ci", Project: "web"}},
		}}}, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(out)
	}
	if out := run("pwd"); out != "/alpha/acme/default" {
		t.Fatalf("pwd before cd: %q", out)
	}
	if out := run("cd", "web"); out != "/alpha/acme/web" {
		t.Fatalf("cd web: %q", out)
	}
	if out := run("cd", ".."); out != "/alpha/acme" {
		t.Fatalf("cd ..: %q", out)
	}
	local, path, err := scconfig.LoadDirectoryConfig("")
	if err != nil || path == "" {
		t.Fatalf("selection: %v %q", err, path)
	}
	if local.Level != scconfig.PositionTenant || local.Project != "web" || local.Previous != "/alpha/acme/web" {
		t.Fatalf("selection after cd ..: %+v", local)
	}
	if out := run("pwd"); out != "/alpha/acme" {
		t.Fatalf("pwd at tenant: %q", out)
	}
	if out := run("ls"); out != "/alpha/acme\napi\ndefault\nweb\nwebdev" {
		t.Fatalf("ls at tenant level: %q", out)
	}
	if out := run("ls", "-d", "*web*"); out != "/alpha/acme/web\n/alpha/acme/webdev" {
		t.Fatalf("ls -d glob: %q", out)
	}
	if out := run("ls", "-l", "web"); !strings.HasPrefix(out, "/alpha/acme/web\nMACHINE") || !strings.Contains(out, "running") {
		t.Fatalf("ls -l web: %q", out)
	}
	if out := run("ls", "web", "api"); !strings.Contains(out, "/alpha/acme/web\nci\ndev") || !strings.Contains(out, "\n\n/alpha/acme/api") {
		t.Fatalf("ls two dirs: %q", out)
	}
	if out := run("cd", "-"); out != "/alpha/acme/web" {
		t.Fatalf("cd -: %q", out)
	}
	if out := run("ls", "../*dev"); out != "/alpha/acme/webdev" {
		t.Fatalf("ls ../*dev: %q", out)
	}
	if out := run("ls", "-d", "/alpha/acme/**/*dev*"); out != "/alpha/acme/webdev\n/alpha/acme/web/dev" {
		t.Fatalf("ls -d globstar: %q", out)
	}
	if out := run("ls", "-d", "../**"); out != "/alpha/acme\n/alpha/acme/api\n/alpha/acme/default\n/alpha/acme/web\n/alpha/acme/web/ci\n/alpha/acme/web/dev\n/alpha/acme/webdev" {
		t.Fatalf("ls -d ../**: %q", out)
	}
	if out := run("ls", "-d", "/alpha/acme/**/web/*"); out != "/alpha/acme/web/ci\n/alpha/acme/web/dev" {
		t.Fatalf("ls -d /alpha/acme/**/web/*: %q", out)
	}
	if out := run("cd", "--local-only", "/beta/globex/backend"); out != "/beta/globex/backend" {
		t.Fatalf("cd other remote: %q", out)
	}
	if out := run("pwd", "--json"); !strings.Contains(out, `"remote": "beta"`) || !strings.Contains(out, `"previous": "/alpha/acme/web"`) {
		t.Fatalf("pwd json: %s", out)
	}
	if out := run("cd", "--local-only"); out != "/alpha/acme/default" {
		t.Fatalf("cd home: %q", out)
	}
	if out := run("cd", "/"); out != "/" {
		t.Fatalf("cd /: %q", out)
	}
	if out := run("ls"); out != "/\nalpha\nbeta" {
		t.Fatalf("ls at root: %q", out)
	}
	if out := run("ls", "-l"); !strings.HasPrefix(out, "/\nREMOTE") || !strings.Contains(out, "globex") {
		t.Fatalf("ls -l at root: %q", out)
	}
}

func TestCdRefusesMachinesAndPatterns(t *testing.T) {
	seedEnrolledRemotes(t)
	t.Chdir(t.TempDir())
	config := commandConfig{adminConfig: scconfig.Admin{Remote: "alpha", Tenant: "acme", Project: "web"}}
	if _, err := runCd(context.Background(), config, "./dev", true); err == nil || !strings.Contains(err.Error(), "is a machine") {
		t.Fatalf("machine cd: %v", err)
	}
	if _, err := runCd(context.Background(), config, "../*", true); err == nil || !strings.Contains(err.Error(), "not the pattern") {
		t.Fatalf("pattern cd: %v", err)
	}
	if _, err := runCd(context.Background(), config, "-", true); err == nil || !strings.Contains(err.Error(), "no previous position") {
		t.Fatalf("cd - without history: %v", err)
	}
}

func TestCreateRefusesAboveProjectWithoutProject(t *testing.T) {
	config := commandConfig{adminConfig: scconfig.Admin{Remote: "alpha", Tenant: "acme", PositionLevel: scconfig.PositionTenant}}
	if err := requireProjectPosition(config, "dev", "create"); err == nil || !strings.Contains(err.Error(), "not in a project") {
		t.Fatalf("bare name above project: %v", err)
	}
	if err := requireProjectPosition(config, "web:dev", "create"); err != nil {
		t.Fatalf("qualified reference: %v", err)
	}
	if err := requireProjectPosition(commandConfig{adminConfig: scconfig.Admin{Remote: "alpha", Tenant: "acme", Project: "web"}}, "dev", "create"); err != nil {
		t.Fatalf("project level: %v", err)
	}
}

var _ = tenant.MemoryStore{}
