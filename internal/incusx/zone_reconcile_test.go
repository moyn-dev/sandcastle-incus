package incusx

import (
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
)

type fakeCertPushServer struct {
	files map[string]incus.InstanceFileArgs
	body  map[string]string
	execs []string
	exit  float64
}

func (f *fakeCertPushServer) CreateInstanceFile(_ string, path string, args incus.InstanceFileArgs) error {
	if f.files == nil {
		f.files = map[string]incus.InstanceFileArgs{}
		f.body = map[string]string{}
	}
	var sb strings.Builder
	if args.Content != nil {
		buf := make([]byte, 4096)
		for {
			n, err := args.Content.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
	}
	f.files[path] = args
	f.body[path] = sb.String()
	return nil
}

func (f *fakeCertPushServer) ExecInstance(_ string, post api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error) {
	f.execs = append(f.execs, strings.Join(post.Command, " "))
	if args != nil && args.DataDone != nil {
		close(args.DataDone)
	}
	return fakeExitOperation{code: f.exit}, nil
}

// fakeExitOperation reports an exec return code the way the SDK does: in the
// operation metadata, not through Wait.
type fakeExitOperation struct {
	fakeOperation
	code float64
}

func (o fakeExitOperation) Get() api.Operation {
	return api.Operation{Metadata: map[string]any{"return": o.code}}
}

// The push lands in the hostname's own directory (created first — the file
// API makes no parents), swaps both files in one exec, lists the name and
// runs caddy-setup --refresh. The private leaf paths are never written.
func TestPushMachineCertificate_FilesAndOneExec(t *testing.T) {
	server := &fakeCertPushServer{}
	if err := pushMachineCertificate(server, "web", "Web12.TC42.uk.", "CERT\n", "KEY\n"); err != nil {
		t.Fatal(err)
	}
	dir := server.files["/etc/sandcastle/tls/web12.tc42.uk"]
	cert := server.files["/etc/sandcastle/tls/web12.tc42.uk/cert.pem.new"]
	key := server.files["/etc/sandcastle/tls/web12.tc42.uk/key.pem.new"]
	if dir.Type != "directory" || dir.Mode != 0o755 || cert.Mode != 0o644 || key.Mode != 0o600 || cert.WriteMode != "overwrite" || key.UID != 0 || key.GID != 0 {
		t.Fatalf("file args: dir=%+v cert=%+v key=%+v", dir, cert, key)
	}
	if server.body["/etc/sandcastle/tls/web12.tc42.uk/cert.pem.new"] != "CERT\n" || server.body["/etc/sandcastle/tls/web12.tc42.uk/key.pem.new"] != "KEY\n" {
		t.Fatalf("bodies = %+v", server.body)
	}
	for path := range server.files {
		if path == "/etc/sandcastle/tls/cert.pem.new" || path == "/etc/sandcastle/tls/key.pem.new" {
			t.Fatalf("push wrote the private leaf path %s", path)
		}
	}
	if len(server.execs) != 1 {
		t.Fatalf("execs = %v, want one", server.execs)
	}
	want := "/bin/sh -c mv -f '/etc/sandcastle/tls/web12.tc42.uk/cert.pem'.new '/etc/sandcastle/tls/web12.tc42.uk/cert.pem' && mv -f '/etc/sandcastle/tls/web12.tc42.uk/key.pem'.new '/etc/sandcastle/tls/web12.tc42.uk/key.pem' && /usr/local/sbin/sandcastle-caddy-setup --refresh"
	if server.execs[0] != want {
		t.Fatalf("exec = %q\nwant  %q", server.execs[0], want)
	}
	if err := pushMachineCertificate(server, "web", " ", "CERT\n", "KEY\n"); err == nil {
		t.Fatal("empty hostname accepted")
	}
	// A nonzero exit is an error (op.Wait alone would not report it).
	server.exit = 1
	if err := pushMachineCertificate(server, "web", "web12.tc42.uk", "CERT\n", "KEY\n"); err == nil || !strings.Contains(err.Error(), "status 1") {
		t.Fatalf("exit 1 not reported: %v", err)
	}
}

// The hostnames push writes the normalized, sorted set whole and refreshes.
func TestPushMachineHostnames_FileAndRefresh(t *testing.T) {
	server := &fakeCertPushServer{}
	if err := pushMachineHostnames(server, "web", []string{"Web12.TC42.uk.", "api.tc42.uk", "web12.tc42.uk"}); err != nil {
		t.Fatal(err)
	}
	file := server.files["/etc/sandcastle/hostnames"]
	if file.Mode != 0o644 || file.WriteMode != "overwrite" || server.body["/etc/sandcastle/hostnames"] != "api.tc42.uk\nweb12.tc42.uk\n" {
		t.Fatalf("hostnames file: %+v %q", file, server.body["/etc/sandcastle/hostnames"])
	}
	if len(server.execs) != 1 || server.execs[0] != "/bin/sh -c /usr/local/sbin/sandcastle-caddy-setup --refresh" {
		t.Fatalf("execs = %v", server.execs)
	}
}

func TestStampInstanceConfig_MergesAndSkipsUnchanged(t *testing.T) {
	server := &fakeStampServer{instances: map[string]*api.Instance{
		"web": {InstancePut: api.InstancePut{Config: map[string]string{
			meta.KeyV2PublicHostname: "web.baum.hase.de",
			meta.KeyV2CertState:      "pending",
			"user.other":             "keep",
		}}},
	}}
	if err := stampInstanceConfig(server, "web", map[string]string{meta.KeyV2CertState: "pending"}); err != nil {
		t.Fatal(err)
	}
	if len(server.updated) != 0 {
		t.Fatal("unchanged config was written")
	}
	if err := stampInstanceConfig(server, "web", map[string]string{meta.KeyV2CertState: "installed", meta.KeyV2CertNotAfter: "2026-12-11T10:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	put := server.updated["web"]
	if put.Config[meta.KeyV2CertState] != "installed" || put.Config[meta.KeyV2CertNotAfter] != "2026-12-11T10:00:00Z" ||
		put.Config[meta.KeyV2PublicHostname] != "web.baum.hase.de" || put.Config["user.other"] != "keep" {
		t.Fatalf("merged config = %v", put.Config)
	}
	if err := stampInstanceConfig(server, "missing", map[string]string{meta.KeyV2CertState: "x"}); err == nil {
		t.Fatal("missing instance accepted")
	}
}
