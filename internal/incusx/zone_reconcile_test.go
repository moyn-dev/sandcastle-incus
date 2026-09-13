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

func TestPushMachineCertificate_FilesAndOneExec(t *testing.T) {
	server := &fakeCertPushServer{}
	if err := pushMachineCertificate(server, "web", "CERT\n", "KEY\n", true); err != nil {
		t.Fatal(err)
	}
	cert := server.files["/etc/sandcastle/tls/cert.pem.new"]
	key := server.files["/etc/sandcastle/tls/key.pem.new"]
	if cert.Mode != 0o644 || key.Mode != 0o600 || cert.WriteMode != "overwrite" || key.UID != 0 || key.GID != 0 {
		t.Fatalf("file args: cert=%+v key=%+v", cert, key)
	}
	if server.body["/etc/sandcastle/tls/cert.pem.new"] != "CERT\n" || server.body["/etc/sandcastle/tls/key.pem.new"] != "KEY\n" {
		t.Fatalf("bodies = %+v", server.body)
	}
	if len(server.execs) != 1 {
		t.Fatalf("execs = %v, want one", server.execs)
	}
	want := "/bin/sh -c mv -f /etc/sandcastle/tls/cert.pem.new /etc/sandcastle/tls/cert.pem && mv -f /etc/sandcastle/tls/key.pem.new /etc/sandcastle/tls/key.pem && (systemctl reload caddy 2>/dev/null || systemctl restart caddy) && systemctl start caddy"
	if server.execs[0] != want {
		t.Fatalf("exec = %q\nwant  %q", server.execs[0], want)
	}
	if strings.HasSuffix(machineCertificateInstallScript(false), "systemctl start caddy") {
		t.Fatal("a non-first push must not append systemctl start")
	}
	// A nonzero exit is an error (op.Wait alone would not report it).
	server.exit = 1
	if err := pushMachineCertificate(server, "web", "CERT\n", "KEY\n", false); err == nil || !strings.Contains(err.Error(), "status 1") {
		t.Fatalf("exit 1 not reported: %v", err)
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
