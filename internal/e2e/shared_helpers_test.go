package e2e

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/cliconfig"
)

// Shared e2e helpers extracted from the removed v1 test files.
func e2eInstanceServer(remote string) (incus.InstanceServer, error) {
	loaded, err := cliconfig.LoadConfig("")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(remote) == "" {
		remote = loaded.DefaultRemote
	}
	return loaded.GetInstanceServer(remote)
}

func assertInstanceExists(t *testing.T, server incus.InstanceServer, name string) {
	t.Helper()
	if _, _, err := server.GetInstance(name); err != nil {
		t.Fatalf("expected instance %s: %v", name, err)
	}
}

func buildSandcastleForE2E(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandcastle")
	command := exec.Command("go", "build", "-o", path, "github.com/moyn-dev/sandcastle-incus/cmd/sandcastle")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sandcastle e2e binary: %v\n%s", err, strings.TrimSpace(string(output)))
	}
	return path
}

func buildSandcastleForRemote(t *testing.T, remote string) string {
	t.Helper()
	goarch := remoteGOARCH(t, remote)
	path := filepath.Join(t.TempDir(), "sandcastle-linux-"+goarch)
	command := exec.Command("go", "build", "-o", path, "github.com/moyn-dev/sandcastle-incus/cmd/sandcastle")
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sandcastle e2e binary (linux/%s): %v\n%s", goarch, err, strings.TrimSpace(string(output)))
	}
	return path
}

func buildSandcastleAdminForE2E(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandcastle-admin")
	command := exec.Command("go", "build", "-o", path, "github.com/moyn-dev/sandcastle-incus/cmd/sandcastle-admin")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sandcastle-admin e2e binary: %v\n%s", err, strings.TrimSpace(string(output)))
	}
	return path
}

func buildSandcastleAdminForRemote(t *testing.T, remote string) string {
	t.Helper()
	goarch := remoteGOARCH(t, remote)
	path := filepath.Join(t.TempDir(), "sandcastle-admin-linux-"+goarch)
	command := exec.Command("go", "build", "-o", path, "github.com/moyn-dev/sandcastle-incus/cmd/sandcastle-admin")
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build sandcastle-admin e2e binary (linux/%s): %v\n%s", goarch, err, strings.TrimSpace(string(output)))
	}
	return path
}

func remoteGOARCH(t *testing.T, remote string) string {
	t.Helper()
	server, err := e2eInstanceServer(remote)
	if err != nil {
		t.Fatalf("connect to incus remote %q: %v", remote, err)
	}
	info, _, err := server.GetServer()
	if err != nil {
		t.Fatalf("get incus server info for %q: %v", remote, err)
	}
	switch info.Environment.KernelArchitecture {
	case "x86_64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l":
		return "arm"
	default:
		return "amd64"
	}
}

func hostPort(host string, defaultPort string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, defaultPort)
}
