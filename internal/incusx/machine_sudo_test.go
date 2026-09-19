package incusx

import (
	"context"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/meta"
)

func TestReconcileMachineSudoRunsAsRootOverIncusAndReportsState(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{stdout: "updated\nwrote 'alice ALL=(ALL) NOPASSWD:ALL' to /etc/sudoers.d/90-cloud-init-users\n"}
	server := &fakeMachineSSHKeyServer{resource: resource}
	reconciler := MachineSSHKeyReconciler{
		Store: fakeMachineSSHKeyStore{machines: []meta.Machine{
			{Tenant: "alice", Project: "wordpress", Name: "test", Running: true},
		}},
		Server: server,
	}
	status, err := reconciler.ReconcileMachineSudo(context.Background(), v2Summary(), "wordpress", "test", "alice", false)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "updated" || !strings.Contains(status.Detail, "90-cloud-init-users") {
		t.Fatalf("status = %#v", status)
	}
	if got := strings.Join(server.resources, ","); got != "sc2-alice-wordpress" {
		t.Fatalf("projects = %q", got)
	}
	exec := resource.execs[0]
	if exec.instance != "test" || exec.environment["SANDCASTLE_USER"] != "sc" || exec.environment["SANDCASTLE_CHECK_ONLY"] != "" {
		t.Fatalf("exec = %#v", exec)
	}
	script := exec.command[2]
	for _, want := range []string{"NOPASSWD:ALL", "/etc/sudoers.d/90-cloud-init-users", "visudo -cf", "usermod -aG sudo", "sudo -n true"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script lacks %q", want)
		}
	}
}

func TestReconcileMachineSudoCheckOnlyPassesFlagAndSurfacesFailure(t *testing.T) {
	resource := &fakeMachineSSHKeyResource{stdout: "needs-fix\nalice is not in group sudo\n"}
	reconciler := MachineSSHKeyReconciler{
		Store:  fakeMachineSSHKeyStore{machines: []meta.Machine{{Tenant: "alice", Project: "default", Name: "web", Running: true}}},
		Server: &fakeMachineSSHKeyServer{resource: resource},
	}
	status, err := reconciler.ReconcileMachineSudo(context.Background(), v2Summary(), "default", "web", "alice", true)
	if err != nil || status.State != "needs-fix" || status.Detail != "alice is not in group sudo" {
		t.Fatalf("status = %#v, err = %v", status, err)
	}
	if resource.execs[0].environment["SANDCASTLE_CHECK_ONLY"] != "1" {
		t.Fatalf("check flag not passed: %#v", resource.execs[0].environment)
	}
	failing := &fakeMachineSSHKeyResource{exitCode: func(string) int { return 4 }}
	reconciler.Server = &fakeMachineSSHKeyServer{resource: failing}
	if _, err := reconciler.ReconcileMachineSudo(context.Background(), v2Summary(), "default", "web", "alice", false); err == nil || !strings.Contains(err.Error(), "exited 4") {
		t.Fatalf("expected script failure, got %v", err)
	}
	stopped := MachineSSHKeyReconciler{
		Store:  fakeMachineSSHKeyStore{machines: []meta.Machine{{Tenant: "alice", Project: "default", Name: "web"}}},
		Server: &fakeMachineSSHKeyServer{resource: &fakeMachineSSHKeyResource{}},
	}
	if _, err := stopped.ReconcileMachineSudo(context.Background(), v2Summary(), "default", "web", "alice", false); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("stopped machine must be refused, got %v", err)
	}
}
