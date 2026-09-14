package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
)

// The Tailnet verbs deliberately use the Machine Public Hostname seam.  That
// keeps DNS, certificate delivery and Caddy configuration Machine-owned; the
// command must not call the legacy Sidecar publication endpoint.
func TestTailnetPublishAndUnpublishUseMachineHostnameLifecycle(t *testing.T) {
	stub := &stubAuthHostnames{}
	config, stdout := hostnameTestConfig(t, stub)
	config.adminConfig.Remote = "sandcastle-demo"
	incusDir := scconfig.RemoteIncusDir(config.adminConfig.Remote)
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var incusCalls []string
	publicationValue := "existing.tc42.uk"
	config.incusRunner = func(_ context.Context, args []string, _ []string, _ io.Reader, output io.Writer, _ io.Writer) error {
		incusCalls = append(incusCalls, strings.Join(args, " "))
		switch args[1] {
		case "get":
			_, _ = io.WriteString(output, publicationValue+"\n")
		case "set":
			publicationValue = args[4]
		case "unset":
			publicationValue = ""
		}
		return nil
	}
	opts := &rootOptions{output: outputText}

	publish := newTailnetCommand(config, opts)
	publish.SetArgs([]string{"publish", "zp:web", "--hostname", "Internal.TC42.uk."})
	if err := publish.Execute(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got, want := strings.Join(stub.calls, "|"), "add demo zp:web internal.tc42.uk dry=false before=false"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if got, want := stdout.String(), "Tailnet HTTPS published: https://internal.tc42.uk → web:443\n"; got != want {
		t.Fatalf("publish output = %q, want %q", got, want)
	}
	if got, want := strings.Join(incusCalls, "|"), "config get web "+meta.KeyV2TailnetPublications+"|config set web "+meta.KeyV2TailnetPublications+" existing.tc42.uk,internal.tc42.uk"; got != want {
		t.Fatalf("publish metadata calls = %q, want %q", got, want)
	}

	stdout.Reset()
	stub.calls = nil
	incusCalls = nil
	unpublish := newTailnetCommand(config, opts)
	unpublish.SetArgs([]string{"unpublish", "zp:web", "--hostname", "internal.tc42.uk"})
	if err := unpublish.Execute(); err != nil {
		t.Fatalf("unpublish: %v", err)
	}
	if got, want := strings.Join(stub.calls, "|"), "list demo zp:web|remove demo zp:web internal.tc42.uk dry=false"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if got, want := stdout.String(), "Tailnet HTTPS unpublished: https://internal.tc42.uk\n"; got != want {
		t.Fatalf("unpublish output = %q, want %q", got, want)
	}
	if got, want := strings.Join(incusCalls, "|"), "config get web "+meta.KeyV2TailnetPublications+"|config set web "+meta.KeyV2TailnetPublications+" existing.tc42.uk"; got != want {
		t.Fatalf("unpublish metadata calls = %q, want %q", got, want)
	}
}

func TestTailnetUnpublishIsIdempotentWhenHostnameIsAlreadyReleased(t *testing.T) {
	stub := &stubAuthHostnames{}
	config, stdout := hostnameTestConfig(t, stub)
	config.adminConfig.Remote = "sandcastle-demo"
	incusDir := scconfig.RemoteIncusDir(config.adminConfig.Remote)
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.incusRunner = func(_ context.Context, args []string, _ []string, _ io.Reader, output io.Writer, _ io.Writer) error {
		if args[1] == "get" {
			_, _ = io.WriteString(output, "internal.tc42.uk\n")
		}
		return nil
	}

	command := newTailnetCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"unpublish", "zp:web", "--hostname", "internal.tc42.uk"})
	if err := command.Execute(); err != nil {
		t.Fatalf("unpublish absent hostname: %v", err)
	}
	if got, want := strings.Join(stub.calls, "|"), "list demo zp:web"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if got, want := stdout.String(), "Tailnet HTTPS unpublished: https://internal.tc42.uk\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestTailnetVerbsRequireAuthApp(t *testing.T) {
	stub := &stubAuthHostnames{}
	config, _ := hostnameTestConfig(t, stub)
	config.authMachineHostnames = nil
	config.adminConfig.AuthToken = ""

	command := newTailnetCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"publish", "zp:web", "--hostname", "internal.tc42.uk"})
	err := command.Execute()
	if err == nil || err.Error() != "Tailnet publication requires sc login to an Auth App" {
		t.Fatalf("error = %v", err)
	}
}
