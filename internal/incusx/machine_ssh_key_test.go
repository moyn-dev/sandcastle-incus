package incusx

import (
	"context"
	"errors"
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

func TestMachineSSHKeyReconcilerSkipsWhenNoMachinesExist(t *testing.T) {
	server := &fakeMachineSSHKeyServer{}
	reconciler := MachineSSHKeyReconciler{
		Store:  fakeMachineSSHKeyStore{},
		Server: server,
	}
	if err := reconciler.ReconcileUserSSHKey(context.Background(), tenant.Summary{Tenant: "alice", IncusName: "sc-alice"}, "alice", "ssh-ed25519 key"); err != nil {
		t.Fatal(err)
	}
	if len(server.resources) != 0 {
		t.Fatalf("server resources = %#v", server.resources)
	}
}

type fakeMachineSSHKeyStore struct {
	machines []meta.Machine
}

func (s fakeMachineSSHKeyStore) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	return append([]meta.Machine{}, s.machines...), nil
}

type fakeMachineSSHKeyServer struct {
	resource  *fakeMachineSSHKeyResource
	resources []string
}

func (s *fakeMachineSSHKeyServer) UseProject(name string) MachineSSHKeyResourceServer {
	s.resources = append(s.resources, name)
	if s.resource == nil {
		s.resource = &fakeMachineSSHKeyResource{}
	}
	return s.resource
}

type fakeMachineSSHKeyResource struct {
	execs    []fakeMachineSSHKeyExec
	failAt   int
	failWith func(instanceName string) error
	exitCode func(instanceName string) int
	stdout   string
}

type fakeMachineSSHKeyExec struct {
	instance    string
	command     []string
	environment map[string]string
}

func (r *fakeMachineSSHKeyResource) ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error) {
	r.execs = append(r.execs, fakeMachineSSHKeyExec{
		instance:    instanceName,
		command:     append([]string{}, exec.Command...),
		environment: exec.Environment,
	})
	if r.failWith != nil {
		if err := r.failWith(instanceName); err != nil {
			return nil, err
		}
	}
	if r.failAt > 0 && len(r.execs) == r.failAt {
		return nil, errors.New("boom")
	}
	if args != nil && args.Stdout != nil && r.stdout != "" {
		_, _ = args.Stdout.Write([]byte(r.stdout))
	}
	if args != nil && args.DataDone != nil {
		go func() { args.DataDone <- true }()
	}
	if r.exitCode != nil {
		return staticOperation{op: api.Operation{Metadata: map[string]any{"return": float64(r.exitCode(instanceName))}}}, nil
	}
	return staticOperation{}, nil
}

// Regression for #51: rotating the login key must reach machines that ALREADY
// exist. v2 machines carry the bare machine name and live in per-project Incus
// projects (<prefix>-<tenant>-<project>); the v1 "<project>-<machine>" name in
// the tenant's single project is what made this reconcile unusable for v2, so it
// was skipped entirely and rotation locked users out of every existing machine.
func TestMachineSSHKeyReconcilerV2UsesBareNamesAndPerProjectIncusProjects(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{}
	server := &fakeMachineSSHKeyServer{resource: resource}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "default", Name: "web", Running: true},
			{Tenant: "alice", Project: "backend", Name: "api", Running: true},
		}},
		Server: server,
	}
	summary := v2Summary()
	if err := reconciler.ReconcileUserSSHKey(context.Background(), summary, "alice", "ssh-ed25519 rotated"); err != nil {
		t.Fatal(err)
	}
	wantProjects := []string{"sc2-alice-default", "sc2-alice-backend"}
	if strings.Join(server.resources, ",") != strings.Join(wantProjects, ",") {
		t.Fatalf("incus projects = %#v, want %#v", server.resources, wantProjects)
	}
	if len(resource.execs) != 2 || resource.execs[0].instance != "web" || resource.execs[1].instance != "api" {
		t.Fatalf("execs = %#v (v2 instance names are bare)", resource.execs)
	}
	// The Unix login user comes from the tenant, NOT from the GitHub user key:
	// writing to /home/<github-user> silently wrote nowhere.
	for _, exec := range resource.execs {
		if exec.environment["SANDCASTLE_USER"] != "sc" {
			t.Fatalf("SANDCASTLE_USER = %q, want the tenant Unix user %q", exec.environment["SANDCASTLE_USER"], "sc")
		}
		if exec.environment["SANDCASTLE_SSH_PUBLIC_KEY"] != "ssh-ed25519 rotated" {
			t.Fatalf("environment = %#v", exec.environment)
		}
	}
}

func TestMachineSSHKeyReconcilerScopesConnectionRepairToOneMachine(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{}
	server := &fakeMachineSSHKeyServer{resource: resource}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "default", Name: "web", Running: true},
			{Tenant: "alice", Project: "wordpress", Name: "test", Running: true},
		}},
		Server: server,
	}
	if _, err := reconciler.ReconcileMachineUserSSHKey(context.Background(), v2Summary(), "wordpress", "test", "alice", "ssh-ed25519 current"); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(server.resources, ","), "sc2-alice-wordpress"; got != want {
		t.Fatalf("projects = %q, want %q", got, want)
	}
	if len(resource.execs) != 1 || resource.execs[0].instance != "test" {
		t.Fatalf("execs = %#v, want only wordpress:test", resource.execs)
	}
}

// The connection repair is ADDITIVE: it must never drop a key that is already
// in authorized_keys — neither a hand-added one nor an older Sandcastle key —
// and it reports every enrolled key so the operator can see what is there.
func TestMachineSSHKeyReconcilerIsAdditiveAndListsEnrolledKeys(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{stdout: "256 SHA256:aaa no comment (ED25519)\n256 SHA256:bbb no comment (ED25519)\n\n"}
	server := &fakeMachineSSHKeyServer{resource: resource}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "wordpress", Name: "test", Running: true},
		}},
		Server: server,
	}
	enrolled, err := reconciler.ReconcileMachineUserSSHKey(context.Background(), v2Summary(), "wordpress", "test", "alice", "ssh-ed25519 current")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(enrolled, "|"), "256 SHA256:aaa no comment (ED25519)|256 SHA256:bbb no comment (ED25519)"; got != want {
		t.Fatalf("enrolled = %q, want %q", got, want)
	}
	if len(resource.execs) != 1 || len(resource.execs[0].command) != 3 {
		t.Fatalf("execs = %#v", resource.execs)
	}
	script := resource.execs[0].command[2]
	for _, want := range []string{
		`grep -qxF "$key" "$auth"`,                // present anywhere → untouched
		`'# sandcastle user ssh key end' "$auth"`, // otherwise inserted into the managed block
		`ssh-keygen -lf "$auth"`,                  // and the whole file is listed
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script lacks %q:\n%s", want, script)
		}
	}
	// The old script filtered the managed block out with awk before rewriting
	// it; an additive script has no reason to skip any existing line.
	if strings.Contains(script, "!skip") || strings.Contains(script, "skip=1") {
		t.Fatalf("script still strips existing keys:\n%s", script)
	}
}

// A v2 project's machines share ONE home volume, so authorized_keys is a single
// file per project: one running machine is enough, and stopped machines are not
// even exec'd (they read the same file when they next boot).
func TestMachineSSHKeyReconcilerV2WritesOncePerProjectAndSkipsStopped(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "default", Name: "stopped", Running: false},
			{Tenant: "alice", Project: "default", Name: "running", Running: true},
			{Tenant: "alice", Project: "default", Name: "also-running", Running: true},
		}},
		Server: &fakeMachineSSHKeyServer{resource: resource},
	}
	if err := reconciler.ReconcileUserSSHKey(context.Background(), v2Summary(), "alice", "ssh-ed25519 rotated"); err != nil {
		t.Fatal(err)
	}
	if len(resource.execs) != 1 || resource.execs[0].instance != "running" {
		t.Fatalf("expected exactly one write to the shared home, got %#v", resource.execs)
	}
}

// Every machine stopped: nothing to write, and the login must still succeed —
// the key is already in the profile and lands when one next boots.
func TestMachineSSHKeyReconcilerV2ToleratesAnEntirelyStoppedProject(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "default", Name: "a", Running: false},
			{Tenant: "alice", Project: "default", Name: "b", Running: false},
		}},
		Server: &fakeMachineSSHKeyServer{resource: resource},
	}
	if err := reconciler.ReconcileUserSSHKey(context.Background(), v2Summary(), "alice", "ssh-ed25519 rotated"); err != nil {
		t.Fatalf("an all-stopped project must not fail the login: %v", err)
	}
	if len(resource.execs) != 0 {
		t.Fatalf("stopped machines must not be exec'd: %#v", resource.execs)
	}
}

// A machine that cannot be written must not be reported as reconciled. The other
// running machine in the project is tried instead.
func TestMachineSSHKeyReconcilerV2FallsBackToAnotherRunningMachine(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{
		failWith: func(instanceName string) error {
			if instanceName == "agentless-vm" {
				return errors.New("Failed to connect to agent")
			}
			return nil
		},
	}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "default", Name: "agentless-vm", Running: true},
			{Tenant: "alice", Project: "default", Name: "ct", Running: true},
		}},
		Server: &fakeMachineSSHKeyServer{resource: resource},
	}
	if err := reconciler.ReconcileUserSSHKey(context.Background(), v2Summary(), "alice", "ssh-ed25519 rotated"); err != nil {
		t.Fatalf("a second running machine should have carried the write: %v", err)
	}
	if len(resource.execs) != 2 || resource.execs[1].instance != "ct" {
		t.Fatalf("execs = %#v", resource.execs)
	}
}

// When NO running machine in the project could be written, the failure surfaces
// rather than silently reporting success.
func TestMachineSSHKeyReconcilerV2SurfacesRealFailures(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{
		failWith: func(string) error { return errors.New("permission denied writing authorized_keys") },
	}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "default", Name: "web", Running: true},
		}},
		Server: &fakeMachineSSHKeyServer{resource: resource},
	}
	err := reconciler.ReconcileUserSSHKey(context.Background(), v2Summary(), "alice", "ssh-ed25519 rotated")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %v", err)
	}
}

// A project that cannot be written (e.g. its machines lack the login user)
// must not block key distribution to the projects AFTER it: the old early
// return skipped every remaining project, so one hand-made stock-image machine
// silently locked the rotated key out of the rest of the tenant (observed live
// on obelix 2026-08-22: herdr's failure kept wordpress & co. on the old key).
// The failure still surfaces — as part of a joined error, not instead of work.
func TestMachineSSHKeyReconcilerV2ContinuesPastBrokenProject(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{
		// The broken project's machine fails with a script exit (the no-such-
		// user shape); the later project's machine succeeds.
		exitCode: func(instanceName string) int {
			if instanceName == "no-user" {
				return 1
			}
			return 0
		},
	}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "herdr", Name: "no-user", Running: true},
			{Tenant: "alice", Project: "wordpress", Name: "dev", Running: true},
		}},
		Server: &fakeMachineSSHKeyServer{resource: resource},
	}
	err := reconciler.ReconcileUserSSHKey(context.Background(), v2Summary(), "alice", "ssh-ed25519 rotated")
	if err == nil || !strings.Contains(err.Error(), "no-user") {
		t.Fatalf("error = %v, want the broken project's failure surfaced", err)
	}
	if len(resource.execs) != 2 || resource.execs[1].instance != "dev" {
		t.Fatalf("execs = %#v, want the later project still written", resource.execs)
	}
}

// Same continue-past-failure contract for revocation: an unrevokable project
// must not leave the key standing in every project ordered after it.
func TestMachineSSHKeyReconcilerRevokeContinuesPastBrokenProject(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{
		exitCode: func(instanceName string) int {
			if instanceName == "no-user" {
				return 1
			}
			return 0
		},
	}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "herdr", Name: "no-user", Running: true},
			{Tenant: "alice", Project: "wordpress", Name: "dev", Running: true},
		}},
		Server: &fakeMachineSSHKeyServer{resource: resource},
	}
	err := reconciler.RevokeUserSSHKey(context.Background(), v2Summary(), "alice")
	if err == nil || !strings.Contains(err.Error(), "no-user") {
		t.Fatalf("error = %v, want the broken project's failure surfaced", err)
	}
	if len(resource.execs) != 2 || resource.execs[1].instance != "dev" {
		t.Fatalf("execs = %#v, want the later project still revoked", resource.execs)
	}
}

// incus exec reports a non-zero SCRIPT exit in the operation metadata, not from
// op.Wait(). Without reading it, a write that failed inside the machine (e.g.
// the target Unix user does not exist) looked exactly like success — which is
// how the broken v2 path went unnoticed.
func TestMachineSSHKeyReconcilerSurfacesNonZeroScriptExit(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{exitCode: func(string) int { return 1 }}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "default", Name: "web", Running: true},
		}},
		Server: &fakeMachineSSHKeyServer{resource: resource},
	}
	err := reconciler.ReconcileUserSSHKey(context.Background(), v2Summary(), "alice", "ssh-ed25519 rotated")
	if err == nil || !strings.Contains(err.Error(), "script exited 1") {
		t.Fatalf("error = %v", err)
	}
}

func v2Summary() tenant.Summary {
	return tenant.Summary{
		Tenant:       "alice",
		Version:      2,
		InfraProject: "sc2-alice",
		IncusName:    "sc2-alice-default",
		UnixUser:     "sc",
	}
}

// Revoking a user's SSH access must reach v2 machines: bare instance names,
// per-project Incus projects, one write per project (machines share /home).
func TestMachineSSHKeyReconcilerRevokeUsesV2NamesAndWritesOncePerProject(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{}
	server := &fakeMachineSSHKeyServer{resource: resource}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "default", Name: "stopped", Running: false},
			{Tenant: "alice", Project: "default", Name: "web", Running: true},
			{Tenant: "alice", Project: "backend", Name: "api", Running: true},
		}},
		Server: server,
	}
	if err := reconciler.RevokeUserSSHKey(context.Background(), v2Summary(), "alice"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(server.resources, ","); got != "sc2-alice-default,sc2-alice-backend" {
		t.Fatalf("incus projects = %q", got)
	}
	if len(resource.execs) != 2 || resource.execs[0].instance != "web" || resource.execs[1].instance != "api" {
		t.Fatalf("execs = %#v (bare v2 names, stopped machine skipped)", resource.execs)
	}
	for _, exec := range resource.execs {
		if exec.environment["SANDCASTLE_USER"] != "sc" {
			t.Fatalf("SANDCASTLE_USER = %q, want the tenant Unix user", exec.environment["SANDCASTLE_USER"])
		}
		if strings.Contains(strings.Join(exec.command, " "), "SANDCASTLE_SSH_PUBLIC_KEY") {
			t.Fatal("revoke must not write a key")
		}
	}
}
