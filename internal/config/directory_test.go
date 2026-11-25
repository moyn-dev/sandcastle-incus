package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectorySelectionWalkAndWrite(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "app", "src")
	if err := os.MkdirAll(child, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	path, err := SaveDirectoryConfig(DirectoryConfig{Remote: "alpha", Project: "web"})
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	cfg, readPath, err := LoadDirectoryConfig("")
	if err != nil || readPath != path || cfg.Remote != "alpha" {
		t.Fatalf("load: %+v %s %v", cfg, readPath, err)
	}
	cfg.Project = "api"
	written, err := SaveDirectoryConfig(cfg)
	if err != nil || written != path {
		t.Fatalf("write: %s %v", written, err)
	}
	if _, err := os.Stat(filepath.Join(child, ".sandcastle")); !os.IsNotExist(err) {
		t.Fatalf("unexpected child file: %v", err)
	}
	// A nearer file completely shadows its parent, including project history.
	if err := os.WriteFile(filepath.Join(child, ".sandcastle"), []byte("remote: beta\nproject: docs\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, readPath, err = LoadDirectoryConfig("")
	if err != nil || readPath == path || cfg.Remote != "beta" || cfg.Project != "docs" {
		t.Fatalf("nearest: %+v %s %v", cfg, readPath, err)
	}
}

func TestDirectorySelectionInvalidFileStopsLookup(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if _, err := SaveDirectoryConfig(DirectoryConfig{Remote: "alpha", Project: "web"}); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	for _, contents := range []string{"[broken", "remote: beta\n", "remote: beta\nproject: web\nauth_token: secret\n"} {
		if err := os.WriteFile(".sandcastle", []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, path, err := LoadDirectoryConfig(""); err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("invalid file silently ignored: %s %v", path, err)
		}
	}
	if err := os.Remove(".sandcastle"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(".sandcastle", 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDirectoryConfig(""); err == nil {
		t.Fatal("directory should fail")
	}
}

// Older sc login runs on Linux left local DNS state in ~/.sandcastle/dns.yaml.
// Until localdns migrates it, that directory must not break every command run
// below $HOME, and a switch from $HOME must say why it cannot save.
func TestDirectorySelectionSkipsHomeStateDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".sandcastle"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".sandcastle", "dns.yaml"), []byte("suffixes: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(home, "src")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	if _, path, err := LoadDirectoryConfig(""); err != nil || path != "" {
		t.Fatalf("home state dir: path=%q err=%v", path, err)
	}
	t.Chdir(home)
	if _, path, err := LoadDirectoryConfig(""); err != nil || path != "" {
		t.Fatalf("from home: path=%q err=%v", path, err)
	}
	// A first switch from $HOME has nowhere to write: the name is taken.
	_, err := SaveDirectoryConfig(DirectoryConfig{Remote: "alpha", Project: "web"})
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("save over the state dir: want a clear is-a-directory error, got %v", err)
	}
}

func TestLoadUserDirectoryPrecedenceAndIdentity(t *testing.T) {
	clearAdminEnvForTest(t)
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	global := SandcastleConfig{
		Remote: "alpha", Project: "global", Tenant: "alice", AuthHostname: "https://a.test", AuthToken: "a-token", Broker: "a-broker",
		Installs:         map[string]string{"alpha": "https://a.test", "beta": "https://b.test"},
		RemoteTenants:    map[string]string{"alpha": "alice", "beta": "bob"},
		RemoteAuthTokens: map[string]string{"alpha": "a-token", "beta": "b-token"},
		RemoteBrokers:    map[string]string{"alpha": "a-broker", "beta": "b-broker"},
	}
	if err := SaveSandcastleConfig(DefaultConfigPath(), global); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(DefaultConfigPath())
	cfg, err := LoadUserWithError()
	if err != nil || cfg.Remote != "alpha" || cfg.Project != "global" || cfg.DirectoryConfigPath != "" {
		t.Fatalf("fallback: %+v %v", cfg, err)
	}
	path, err := SaveDirectoryConfig(DirectoryConfig{Remote: "beta", Project: "api"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadUserWithError()
	if err != nil || cfg.Remote != "beta" || cfg.Project != "api" || cfg.Tenant != "bob" || cfg.AuthToken != "b-token" || cfg.Broker != "b-broker" || cfg.AuthHostname != "https://b.test" || cfg.DirectoryConfigPath != path {
		t.Fatalf("local: %+v %v", cfg, err)
	}
	// Admin configuration continues using its own global defaults.
	if admin := LoadAdmin(); admin.Remote != "alpha" {
		t.Fatalf("admin affected: %+v", admin)
	}
	t.Setenv("SANDCASTLE_REMOTE", "alpha")
	t.Setenv("SANDCASTLE_PROJECT", "env-project")
	cfg, err = LoadUserWithError()
	if err != nil || cfg.Remote != "alpha" || cfg.Project != "env-project" || cfg.AuthToken != "a-token" || cfg.Tenant != "alice" {
		t.Fatalf("env: %+v %v", cfg, err)
	}
	after, _ := os.ReadFile(DefaultConfigPath())
	if string(before) != string(after) {
		t.Fatal("global config changed")
	}
}

func TestDirectoryUnknownRemoteDoesNotBorrowGlobalCredentials(t *testing.T) {
	clearAdminEnvForTest(t)
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	if err := SaveSandcastleConfig(DefaultConfigPath(), SandcastleConfig{Remote: "alpha", Tenant: "alice", AuthHostname: "a.test", AuthToken: "a-token", Broker: "a-broker"}); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDirectoryConfig(DirectoryConfig{Remote: "unknown", Project: "web"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadUserWithError()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthToken != "" || cfg.AuthHostname != "" || cfg.Broker != "" || cfg.Tenant != "" {
		t.Fatalf("borrowed identity: %+v", cfg)
	}
}

func TestDirectoryOverridesSharedIncusFallback(t *testing.T) {
	clearAdminEnvForTest(t)
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	if err := SaveSandcastleConfig(DefaultConfigPath(), SandcastleConfig{Remote: "file-remote", Project: "global"}); err != nil {
		t.Fatal(err)
	}
	shared := SharedIncusDir()
	if err := os.MkdirAll(shared, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "config.yml"), []byte("default-remote: sc-fallback\nremotes:\n  sc-fallback: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadUserWithError()
	if err != nil || cfg.Remote != "sc-fallback" || cfg.Project != "global" {
		t.Fatalf("global fallback: %+v %v", cfg, err)
	}
	if _, err := SaveDirectoryConfig(DirectoryConfig{Remote: "local-choice", Project: "web"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadUserWithError()
	if err != nil || cfg.Remote != "local-choice" || cfg.Project != "web" {
		t.Fatalf("local overridden by Incus default: %+v %v", cfg, err)
	}
}

func TestDirectorySelectionFileSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "selection.yml")
	if err := os.WriteFile(target, []byte("remote: alpha\nproject: api\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	if err := os.Symlink(target, ".sandcastle"); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDirectoryConfig(DirectoryConfig{Remote: "beta", Project: "web"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(".sandcastle"); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || !strings.Contains(string(data), "remote: beta") {
		t.Fatalf("target not updated: %s %v", data, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDirectoryConfig(""); err == nil {
		t.Fatal("dangling file symlink silently ignored")
	}
}

// ADR-0032 renamed the install level; a selection written before it reads
// as the same level.
func TestDirectoryLevelInstallAndRemoteAlias(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, level := range []string{PositionInstall, PositionRemote} {
		if err := os.WriteFile(".sandcastle", []byte("remote: obelix\nproject: default\nlevel: "+level+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := LoadDirectoryConfig("")
		if err != nil {
			t.Fatalf("level %s: %v", level, err)
		}
		if depth := PositionDepth(cfg.PositionLevel()); depth != 1 {
			t.Fatalf("level %s: depth %d, want 1", level, depth)
		}
	}
}
