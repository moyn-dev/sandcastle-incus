package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

func writeMirrorTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func useNativeMirrorHomeForTest(t *testing.T) (native, dedicated string) {
	t.Helper()
	useLoginHomeForTest(t)
	t.Setenv(scconfig.NativeMirrorEnv, "")
	native, dedicated = scconfig.NativeIncusDir(), scconfig.DedicatedIncusDir()
	writeMirrorTestFile(t, filepath.Join(native, "config.yml"), "remotes:\n  sc-b:\n    addr: https://admin.example:8443\n    protocol: incus\n")
	writeMirrorTestFile(t, filepath.Join(dedicated, "client.key"), "key\n")
	writeTestCertificate(t, filepath.Join(native, "client.crt"), []string{"admin"})
	writeTestCertificate(t, filepath.Join(dedicated, "client.crt"), []string{"sandcastle"})
	return native, dedicated
}

func TestSyncNativeIncusMirrorReportsChangesAndSkips(t *testing.T) {
	native, dedicated := useNativeMirrorHomeForTest(t)
	writeMirrorTestFile(t, filepath.Join(dedicated, "config.yml"), "remotes:\n  sc-a:\n    addr: https://100.64.0.1:8443\n    protocol: incus\n  sc-b:\n    addr: https://100.64.0.2:8443\n    protocol: incus\n")

	var out strings.Builder
	syncNativeIncusMirror(&out)
	want := "Plain `incus` remotes in " + native + ": added sc-a.\nNote: not mirroring sc-b: " + native + " already has a remote of that name\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}

	out.Reset()
	syncNativeIncusMirror(&out)
	if out.String() != "Note: not mirroring sc-b: "+native+" already has a remote of that name\n" {
		t.Fatalf("second run output = %q", out.String())
	}
}

func TestSyncNativeIncusMirrorFailureOnlyWarns(t *testing.T) {
	_, dedicated := useNativeMirrorHomeForTest(t)
	writeMirrorTestFile(t, filepath.Join(dedicated, "config.yml"), "remotes: [not a map\n")

	var out strings.Builder
	syncNativeIncusMirror(&out)
	if !strings.HasPrefix(out.String(), "warning: could not mirror Sandcastle remotes into ") {
		t.Fatalf("output = %q, want a warning", out.String())
	}
}
