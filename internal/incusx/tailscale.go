package incusx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/moyn-dev/sandcastle-incus/internal/tailscale"
)

type TailscaleServer interface {
	UseProject(name string) TailscaleResourceServer
	GetProject(name string) (*api.Project, string, error)
	UpdateProject(name string, project api.ProjectPut, ETag string) error
}

type TailscaleResourceServer interface {
	ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error)
}

type TailscaleManager struct {
	Remote     string
	ConfigPath string
	Server     TailscaleServer
}

func NewTailscaleManager(remote string) TailscaleManager {
	return TailscaleManager{Remote: remote}
}

func (m TailscaleManager) RunUp(ctx context.Context, plan tailscale.UpPlan, session tailscale.RunSession) error {
	server := m.Server
	if server == nil {
		loaded, err := LoadCLIConfig(m.ConfigPath)
		if err != nil {
			return fmt.Errorf("load Incus config: %w", err)
		}
		remote := m.Remote
		if remote == "" {
			remote = loaded.DefaultRemote
		}
		instanceServer, err := connectInstanceServer(loaded, remote)
		if err != nil {
			return fmt.Errorf("connect to Incus remote %q: %w", remote, err)
		}
		server = sdkTailscaleServer{inner: instanceServer}
	}
	projectServer := server.UseProject(plan.Tenant.InfraProject)
	dataDone := make(chan bool)
	op, err := projectServer.ExecInstance(plan.InstanceName, api.InstanceExecPost{
		Command:   tailscale.ExecCommand(plan),
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stdout:   writerOrDiscard(session.Stdout),
		Stderr:   writerOrDiscard(session.Stderr),
		DataDone: dataDone,
	})
	if err != nil {
		return fmt.Errorf("run tailscale up in %s: %w", plan.InstanceName, err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("wait for tailscale up in %s: %w", plan.InstanceName, err)
	}
	<-dataDone
	result, err := runTailscaleStatus(ctx, server, tailscale.StatusPlan{
		Reference:    plan.Reference,
		Tenant:       plan.Tenant,
		InstanceName: plan.InstanceName,
		Command:      []string{"tailscale", "status", "--json"},
	}, tailscale.RunSession{Stderr: session.Stderr})
	if err != nil {
		return err
	}
	if err := validateTailscaleUpResult(plan, result); err != nil {
		return err
	}
	return nil
}

func (m TailscaleManager) RunStatus(ctx context.Context, plan tailscale.StatusPlan, session tailscale.RunSession) (tailscale.StatusResult, error) {
	server, err := m.server()
	if err != nil {
		return tailscale.StatusResult{}, err
	}
	return runTailscaleStatus(ctx, server, plan, session)
}

func runTailscaleStatus(ctx context.Context, server TailscaleServer, plan tailscale.StatusPlan, session tailscale.RunSession) (tailscale.StatusResult, error) {
	projectServer := server.UseProject(plan.Tenant.InfraProject)
	var stdout bytes.Buffer
	dataDone := make(chan bool)
	op, err := projectServer.ExecInstance(plan.InstanceName, api.InstanceExecPost{
		Command:   plan.Command,
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stdout:   &stdout,
		Stderr:   writerOrDiscard(session.Stderr),
		DataDone: dataDone,
	})
	if err != nil {
		return tailscale.StatusResult{}, fmt.Errorf("run tailscale status in %s: %w", plan.InstanceName, err)
	}
	if err := op.Wait(); err != nil {
		return tailscale.StatusResult{}, fmt.Errorf("wait for tailscale status in %s: %w", plan.InstanceName, err)
	}
	<-dataDone
	result, err := tailscale.ParseStatus(plan.Reference, plan.Tenant, stdout.Bytes(), time.Now().UTC())
	if err != nil {
		return tailscale.StatusResult{}, err
	}
	// v1 stamped the tailnet state onto the tenant project metadata.
	// Summary.Tailscale is a v1-only field and a v2 (kind=infra) project has no
	// such metadata, so nothing is persisted; the status is returned as read.
	return result, nil
}

func validateTailscaleUpResult(plan tailscale.UpPlan, result tailscale.StatusResult) error {
	if !strings.EqualFold(result.Tailscale.State, "running") {
		return fmt.Errorf("tailscale up in %s did not authenticate sidecar: state %s", plan.InstanceName, result.Tailscale.State)
	}
	if len(result.Tailscale.TailscaleIPs) == 0 {
		return fmt.Errorf("tailscale up in %s did not assign a Tailscale IP", plan.InstanceName)
	}
	return nil
}

func isRestrictedCertificateError(err error) bool {
	if api.StatusErrorCheck(err, http.StatusForbidden) {
		return true
	}
	return strings.Contains(err.Error(), "Certificate is restricted")
}

func (m TailscaleManager) RunDown(ctx context.Context, plan tailscale.DownPlan, session tailscale.RunSession) error {
	server, err := m.server()
	if err != nil {
		return err
	}
	projectServer := server.UseProject(plan.Tenant.InfraProject)
	dataDone := make(chan bool)
	op, err := projectServer.ExecInstance(plan.InstanceName, api.InstanceExecPost{
		Command:   plan.Command,
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stdout:   writerOrDiscard(session.Stdout),
		Stderr:   writerOrDiscard(session.Stderr),
		DataDone: dataDone,
	})
	if err != nil {
		return fmt.Errorf("run tailscale down in %s: %w", plan.InstanceName, err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("wait for tailscale down in %s: %w", plan.InstanceName, err)
	}
	<-dataDone
	return nil
}

func (m TailscaleManager) server() (TailscaleServer, error) {
	if m.Server != nil {
		return m.Server, nil
	}
	loaded, err := LoadCLIConfig(m.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := m.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	instanceServer, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return sdkTailscaleServer{inner: instanceServer}, nil
}

func writerOrDiscard(writer io.Writer) io.Writer {
	if writer == nil {
		return io.Discard
	}
	return writer
}

type sdkTailscaleServer struct {
	inner incus.InstanceServer
}

func (s sdkTailscaleServer) UseProject(name string) TailscaleResourceServer {
	return sdkTailscaleResourceServer{inner: s.inner.UseProject(name)}
}

func (s sdkTailscaleServer) GetProject(name string) (*api.Project, string, error) {
	return s.inner.GetProject(name)
}

func (s sdkTailscaleServer) UpdateProject(name string, project api.ProjectPut, etag string) error {
	return s.inner.UpdateProject(name, project, etag)
}

type sdkTailscaleResourceServer struct {
	inner incus.InstanceServer
}

func (s sdkTailscaleResourceServer) ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error) {
	return s.inner.ExecInstance(instanceName, exec, args)
}
