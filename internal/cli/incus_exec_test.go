package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lxc/incus/v6/shared/api"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/incusx"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestParseNativeIncusExec(t *testing.T) {
	env := func(key string) string {
		if key == "TERM" {
			return "xterm-256color"
		}
		return ""
	}
	tests := []struct {
		name          string
		args          []string
		stdinTTY      bool
		stdoutTTY     bool
		wantNative    bool
		wantRemote    string
		wantInstance  string
		wantProject   string
		wantCommand   []string
		wantNoStdin   bool
		wantPostCheck func(t *testing.T, post api.InstanceExecPost)
	}{
		{
			name:       "issue 250 shape",
			args:       []string{"exec", "acme:web", "--project", "sc2-acme-default", "--", "head", "-c", "1000000", "/f"},
			wantNative: true, wantRemote: "acme", wantInstance: "web", wantProject: "sc2-acme-default",
			wantCommand: []string{"head", "-c", "1000000", "/f"},
		},
		{
			name:       "no remote, command without --",
			args:       []string{"exec", "web", "ls", "/tmp"},
			wantNative: true, wantInstance: "web", wantCommand: []string{"ls", "/tmp"},
		},
		{
			name:     "flags and values",
			args:     []string{"exec", "web", "-nT", "--env", "A=1", "--env=B=two", "--cwd", "/srv", "--user=1000", "--group", "1000", "--", "id"},
			stdinTTY: true, stdoutTTY: true,
			wantNative: true, wantInstance: "web", wantNoStdin: true, wantCommand: []string{"id"},
			wantPostCheck: func(t *testing.T, post api.InstanceExecPost) {
				want := map[string]string{"TERM": "xterm-256color", "A": "1", "B": "two"}
				if !reflect.DeepEqual(post.Environment, want) || post.Cwd != "/srv" || post.User != 1000 || post.Group != 1000 {
					t.Fatalf("post = %+v", post)
				}
			},
		},
		{
			name:       "auto mode, piped stdout",
			args:       []string{"exec", "web", "--", "cat", "/f"},
			stdinTTY:   true,
			wantNative: true, wantInstance: "web", wantCommand: []string{"cat", "/f"},
		},
		{
			name:     "--mode non-interactive at a terminal",
			args:     []string{"exec", "web", "--mode", "non-interactive", "--", "sh"},
			stdinTTY: true, stdoutTTY: true,
			wantNative: true, wantInstance: "web", wantCommand: []string{"sh"},
		},
		{name: "auto mode at a terminal stays with incus", args: []string{"exec", "web", "--", "bash"}, stdinTTY: true, stdoutTTY: true},
		{name: "-t stays with incus", args: []string{"exec", "web", "-t", "--", "bash"}},
		{name: "--mode interactive stays with incus", args: []string{"exec", "web", "--mode=interactive", "--", "bash"}},
		{name: "unknown flag stays with incus", args: []string{"exec", "web", "--debug", "--", "ls"}},
		{name: "-t with -T stays with incus", args: []string{"exec", "web", "-tT", "--", "ls"}},
		{name: "--mode with -T stays with incus", args: []string{"exec", "web", "--mode", "auto", "-T", "--", "ls"}},
		{name: "bad --user stays with incus", args: []string{"exec", "web", "--user", "root", "--", "ls"}},
		{name: "dash-word in a command without -- stays with incus", args: []string{"exec", "web", "ls", "-la"}},
		{name: "no command", args: []string{"exec", "web"}},
		{name: "other subcommand", args: []string{"list"}},
		{name: "global flag before exec", args: []string{"--project", "p", "exec", "web", "--", "ls"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseNativeIncusExec(tt.args, tt.stdinTTY, tt.stdoutTTY, env)
			if ok != tt.wantNative {
				t.Fatalf("native = %v, want %v (%+v)", ok, tt.wantNative, got)
			}
			if !ok {
				return
			}
			if got.remote != tt.wantRemote || got.instance != tt.wantInstance || got.project != tt.wantProject || got.disableStdin != tt.wantNoStdin {
				t.Fatalf("parsed = %+v", got)
			}
			if !reflect.DeepEqual(got.post.Command, tt.wantCommand) {
				t.Fatalf("command = %#v, want %#v", got.post.Command, tt.wantCommand)
			}
			if tt.wantPostCheck != nil {
				tt.wantPostCheck(t, got.post)
			}
		})
	}
}

func incusExecTestConfig(t *testing.T) (commandConfig, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	incusDir := scconfig.RemoteIncusDir("sandcastle-alice")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return commandConfig{
		name:        "sandcastle",
		adminConfig: scconfig.Admin{Remote: "sandcastle-alice", Tenant: "acme", IncusProjectPrefix: "sc"},
		tenantStore: tenant.MemoryStore{Projects: v2TenantProjects("acme", "10.248.0.0/24", "default")},
		incusRunner: func(context.Context, []string, []string, io.Reader, io.Writer, io.Writer) error {
			t.Fatal("non-interactive exec must not go through the incus CLI")
			return nil
		},
	}, incusDir
}

func TestIncusExecNonInteractiveRunsNatively(t *testing.T) {
	config, incusDir := incusExecTestConfig(t)
	var gotDir, gotRemote, gotProject, gotInstance string
	var gotPost api.InstanceExecPost
	config.incusExec = func(configDir, remote, project, instance string, req api.InstanceExecPost, streams incusx.ExecStreams) (int, error) {
		gotDir, gotRemote, gotProject, gotInstance, gotPost = configDir, remote, project, instance, req
		_, _ = streams.Stdout.Write([]byte("all of it"))
		return 0, nil
	}
	stdout, err := executeForTestWithConfig(t, config, "incus", "exec", "web", "--", "head", "-c", "10", "/f")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "all of it" {
		t.Fatalf("stdout = %q", stdout)
	}
	if gotDir != incusDir || gotRemote != "sandcastle-alice" || gotProject != "sc2-acme-default" || gotInstance != "web" {
		t.Fatalf("dir=%q remote=%q project=%q instance=%q", gotDir, gotRemote, gotProject, gotInstance)
	}
	if strings.Join(gotPost.Command, " ") != "head -c 10 /f" {
		t.Fatalf("command = %#v", gotPost.Command)
	}
}

func TestIncusExecExplicitRemoteAndProjectWin(t *testing.T) {
	config, _ := incusExecTestConfig(t)
	var gotRemote, gotProject string
	config.incusExec = func(_, remote, project, _ string, _ api.InstanceExecPost, _ incusx.ExecStreams) (int, error) {
		gotRemote, gotProject = remote, project
		return 0, nil
	}
	if _, err := executeForTestWithConfig(t, config, "incus", "exec", "other:web", "--project", "sc2-other-x", "--", "true"); err != nil {
		t.Fatal(err)
	}
	if gotRemote != "other" || gotProject != "sc2-other-x" {
		t.Fatalf("remote=%q project=%q", gotRemote, gotProject)
	}
}

func TestIncusExecNonZeroStatusIsAnError(t *testing.T) {
	config, _ := incusExecTestConfig(t)
	config.incusExec = func(string, string, string, string, api.InstanceExecPost, incusx.ExecStreams) (int, error) {
		return 3, nil
	}
	_, err := executeForTestWithConfig(t, config, "incus", "exec", "web", "--", "false")
	if err == nil || err.Error() != "exit status 3" {
		t.Fatalf("err = %v, want exit status 3", err)
	}
}

func TestIncusExecInteractiveStaysWithIncusCLI(t *testing.T) {
	config, _ := incusExecTestConfig(t)
	var gotArgs []string
	config.incusRunner = func(_ context.Context, args []string, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
		gotArgs = args
		return nil
	}
	config.incusExec = func(string, string, string, string, api.InstanceExecPost, incusx.ExecStreams) (int, error) {
		t.Fatal("an interactive exec must go through the incus CLI")
		return 0, nil
	}
	if _, err := executeForTestWithConfig(t, config, "incus", "exec", "web", "-t", "--", "bash"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(gotArgs, " ") != "exec web -t -- bash" {
		t.Fatalf("args = %#v", gotArgs)
	}
}
