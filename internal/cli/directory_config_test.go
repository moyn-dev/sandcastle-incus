package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
)

func TestDirectorySwitchesAreIsolatedAndRememberProjects(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, key := range []string{"SANDCASTLE_REMOTE", "SANDCASTLE_PROJECT", "SANDCASTLE_TENANT", "SANDCASTLE_AUTH_TOKEN", "SANDCASTLE_BROKER"} {
		t.Setenv(key, "")
	}
	root := t.TempDir()
	a, b := filepath.Join(root, "checkout-a"), filepath.Join(root, "checkout-b")
	for _, dir := range []string{a, b, filepath.Join(a, "src")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	global := scconfig.SandcastleConfig{Remote: "alpha", Project: "default", Tenant: "acme", Installs: map[string]string{"alpha": "a.test", "beta": "b.test"}, RemoteTenants: map[string]string{"alpha": "acme", "beta": "acme"}, RemoteAuthTokens: map[string]string{"alpha": "alpha-secret", "beta": "beta-secret"}}
	if err := scconfig.SaveSandcastleConfig(scconfig.DefaultConfigPath(), global); err != nil {
		t.Fatal(err)
	}
	shared := scconfig.SharedIncusDir()
	if err := os.MkdirAll(shared, 0700); err != nil {
		t.Fatal(err)
	}
	incusPath := filepath.Join(shared, "config.yml")
	incusData := "default-remote: alpha\nremotes:\n  alpha:\n    addr: https://a.test\n    project: sc-acme-default\n  beta:\n    addr: https://b.test\n    project: sc-acme-backend\n"
	if err := os.WriteFile(incusPath, []byte(incusData), 0600); err != nil {
		t.Fatal(err)
	}
	globalBefore, _ := os.ReadFile(scconfig.DefaultConfigPath())
	t.Chdir(a)
	run := func(args ...string) string {
		t.Helper()
		cfg, err := scconfig.LoadUserWithError()
		if err != nil {
			t.Fatal(err)
		}
		out, err := executeForTestWithConfig(t, commandConfig{adminConfig: cfg, tenantStore: infoV2ProjectStore("sc2-acme-default", "sc2-acme-web", "sc2-acme-backend")}, args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	path := filepath.Join(a, ".sandcastle")
	if out := run("project", "switch", "web", "--local-only"); !strings.Contains(out, path) {
		t.Fatalf("write path missing: %s", out)
	}
	t.Chdir(filepath.Join(a, "src"))
	if out := run("remote", "switch", "beta"); !strings.Contains(out, path) || !strings.Contains(out, `project "backend"`) {
		t.Fatalf("remote switch: %s", out)
	}
	run("project", "switch", "web", "--local-only")
	run("remote", "switch", "alpha")
	if cfg, _, err := scconfig.LoadDirectoryConfig(""); err != nil || cfg.Project != "web" {
		t.Fatalf("alpha project not restored: %+v %v", cfg, err)
	}
	run("remote", "switch", "beta")
	if cfg, _, err := scconfig.LoadDirectoryConfig(""); err != nil || cfg.Project != "web" {
		t.Fatalf("beta project not remembered: %+v %v", cfg, err)
	}
	for _, command := range []string{"project", "remote"} {
		if out := run(command, "list"); !strings.Contains(out, path) {
			t.Fatalf("%s list missing source: %s", command, out)
		}
	}
	if out := run("project", "list", "--json"); !strings.Contains(out, `"config_path": "`+path+`"`) {
		t.Fatalf("JSON source missing: %s", out)
	}
	if _, err := os.Stat(filepath.Join(a, "src", ".sandcastle")); !os.IsNotExist(err) {
		t.Fatalf("created child file: %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "secret") {
		t.Fatal("credentials persisted locally")
	}
	t.Chdir(b)
	cfg, err := scconfig.LoadUserWithError()
	if err != nil || cfg.Remote != "alpha" || cfg.Project != "default" {
		t.Fatalf("other checkout affected: %+v %v", cfg, err)
	}
	if out := run("remote", "list"); !strings.Contains(out, "global fallback") {
		t.Fatalf("fallback not shown: %s", out)
	}
	run("project", "switch", "backend", "--local-only")
	if _, err := os.Stat(filepath.Join(b, ".sandcastle")); err != nil {
		t.Fatal(err)
	}
	globalAfter, _ := os.ReadFile(scconfig.DefaultConfigPath())
	incusAfter, _ := os.ReadFile(incusPath)
	if string(globalAfter) != string(globalBefore) || string(incusAfter) != incusData {
		t.Fatal("global defaults modified")
	}
}
