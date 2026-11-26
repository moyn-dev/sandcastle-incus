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
	if _, err := os.Stat(filepath.Join(child, DirectoryConfigFile)); !os.IsNotExist(err) {
		t.Fatalf("unexpected child file: %v", err)
	}
	// A nearer file completely shadows its parent, including project history.
	if err := os.WriteFile(filepath.Join(child, DirectoryConfigFile), []byte("remote: beta\nproject: docs\n"), 0600); err != nil {
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
		if err := os.WriteFile(DirectoryConfigFile, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, path, err := LoadDirectoryConfig(""); err == nil || !strings.Contains(err.Error(), path) {
			t.Fatalf("invalid file silently ignored: %s %v", path, err)
		}
	}
	if err := os.Remove(DirectoryConfigFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(DirectoryConfigFile, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDirectoryConfig(""); err == nil {
		t.Fatal("directory should fail")
	}
}

// The pre-2026-11-26 name: a legacy .sandcastle FILE is still read (the new
// name wins in the same directory) and the next save moves it; a .sandcastle
// DIRECTORY (~/.sandcastle/, the local DNS state) is no Directory Config.
func TestDirectoryLegacyFileReadAndMovedOnSave(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(root, legacyDirectoryConfigFile)
	if err := os.WriteFile(legacy, []byte("remote: alpha\nproject: web\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The DNS-state directory in the child does not stop the walk.
	if err := os.MkdirAll(filepath.Join(child, legacyDirectoryConfigFile), 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(child)
	cfg, path, err := LoadDirectoryConfig("")
	if err != nil || path != legacy || cfg.Remote != "alpha" {
		t.Fatalf("legacy file not read past the directory: %+v %s %v", cfg, path, err)
	}
	cfg.Project = "api"
	written, err := SaveDirectoryConfig(cfg)
	if want := filepath.Join(root, DirectoryConfigFile); err != nil || written != want {
		t.Fatalf("save: %s %v, want %s", written, err, want)
	}
	if _, err := os.Lstat(legacy); !os.IsNotExist(err) {
		t.Fatalf("legacy file not removed after the move: %v", err)
	}
	if cfg, path, err := LoadDirectoryConfig(""); err != nil || path != written || cfg.Project != "api" {
		t.Fatalf("after the move: %+v %s %v", cfg, path, err)
	}
	// In one directory the new name wins over a legacy file.
	if err := os.WriteFile(legacy, []byte("remote: beta\nproject: web\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if cfg, _, err := LoadDirectoryConfig(""); err != nil || cfg.Remote != "alpha" {
		t.Fatalf("legacy file shadowed the new one: %+v %v", cfg, err)
	}
	// An invalid legacy file is an error, like an invalid new one.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, legacyDirectoryConfigFile), []byte("[broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDirectoryConfig(other); err == nil {
		t.Fatal("invalid legacy file silently ignored")
	}
	// A save where only the DNS-state directory exists creates the new file.
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, legacyDirectoryConfigFile), 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(home)
	if written, err := SaveDirectoryConfig(DirectoryConfig{Remote: "alpha", Project: "web"}); err != nil || written != filepath.Join(home, DirectoryConfigFile) {
		t.Fatalf("save at $HOME: %s %v", written, err)
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
	if err := os.Symlink(target, DirectoryConfigFile); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveDirectoryConfig(DirectoryConfig{Remote: "beta", Project: "web"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(DirectoryConfigFile); err != nil || info.Mode()&os.ModeSymlink == 0 {
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
		if err := os.WriteFile(DirectoryConfigFile, []byte("remote: obelix\nproject: default\nlevel: "+level+"\n"), 0600); err != nil {
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
