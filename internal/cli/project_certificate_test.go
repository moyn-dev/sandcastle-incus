package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/machine"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type projectCertificateClientStub struct{ *stubAuthProjects }

func (s projectCertificateClientStub) GetProjectDomain(_ context.Context, project string) (authapp.ProjectDomainResult, error) {
	return authapp.ProjectDomainResult{Project: project, Domain: "baum.hase.de", CertState: "installed", CertNotAfter: "2026-12-11T10:00:00Z", SANs: []string{"baum.hase.de", "*.baum.hase.de"}}, nil
}

func TestListResolvesProjectCertificateStateAndExpiry(t *testing.T) {
	config := commandConfig{authProjects: projectCertificateClientStub{&stubAuthProjects{}}}
	result := listPayload{Tenant: tenant.Summary{Projects: []meta.Project{{Name: "zp", Domain: "baum.hase.de"}}}, Machines: []meta.Machine{{Project: "zp", Name: "web", PublicHostnames: []string{"web.baum.hase.de", "admin-web.baum.hase.de"}, CertState: "project"}}}
	enrichProjectCertificates(context.Background(), config, &result)
	m := result.Machines[0]
	if m.CertState != "installed" || m.CertNotAfter != "2026-12-11T10:00:00Z" || m.CertStateOf("admin-web.baum.hase.de") != "installed" {
		t.Fatalf("machine: %+v", m)
	}
	if cell := machineCertCell(m); !strings.Contains(cell, "project installed") || !strings.Contains(cell, m.CertNotAfter) {
		t.Fatalf("cell: %s", cell)
	}
}

func TestMachineDeleteDryRunDoesNotNeedConfirmationOrController(t *testing.T) {
	config, out := hostnameTestConfig(t, &stubAuthHostnames{})
	command := newMachineLifecycleCommand(config, &rootOptions{output: outputText}, "delete", machine.ActionDelete, true)
	command.SetArgs([]string{"zp:web", "--dry-run"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "[dry-run]") || !strings.Contains(out.String(), "certificate") {
		t.Fatalf("plan: %s", out.String())
	}
}

func TestSetDomainUsesCurrentProject(t *testing.T) {
	config, _ := hostnameTestConfig(t, &stubAuthHostnames{})
	stub := &stubAuthProjects{}
	config.authProjects = stub
	command := newProjectSetDomainCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"baum.hase.de", "--dry-run"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stub.calls, ",") != "set-domain zp baum.hase.de true" {
		t.Fatalf("calls: %v", stub.calls)
	}
}

// The cache-backed `sc ls` path carries the raw mirror ("project"); it must
// resolve the Project Certificate like the live path, not print "project".
func TestListViaCacheResolvesProjectCertificateState(t *testing.T) {
	fake := &fakeResourceClient{result: authapp.ResourceListResult{
		Tenant:   tenant.Summary{Tenant: "acme", Projects: []meta.Project{{Name: "zp", Domain: "baum.hase.de"}}},
		Machines: []meta.Machine{{Project: "zp", Name: "web", PrivateIP: "10.1.0.9", Running: true, PublicHostnames: []string{"web.baum.hase.de"}, CertState: "project"}},
	}}
	config := commandConfig{adminConfig: scconfig.Admin{Tenant: "acme"}, authResources: fake, authProjects: projectCertificateClientStub{&stubAuthProjects{}}}
	result, ok := listMachinesViaCache(context.Background(), config, listMachinesRequest{Project: "zp"}, listRenderOptions{})
	if !ok {
		t.Fatal("cache path fell back")
	}
	if m := result.Machines[0]; m.CertState != "installed" || m.CertStateOf("web.baum.hase.de") != "installed" || m.CertNotAfter != "2026-12-11T10:00:00Z" {
		t.Fatalf("machine: %+v", m)
	}
}
