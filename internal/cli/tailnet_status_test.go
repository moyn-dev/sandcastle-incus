package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// stubTailnetProber answers DNS from dns (host → addresses) and HTTPS from
// tls (host → probe); a missing entry is NXDOMAIN / unreachable.
type stubTailnetProber struct {
	mu  sync.Mutex
	dns map[string][]string
	tls map[string]tailnetTLSProbe
}

func (s *stubTailnetProber) LookupHost(_ context.Context, host string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if addrs, ok := s.dns[host]; ok {
		return addrs, nil
	}
	return nil, errors.New("no such host")
}

func (s *stubTailnetProber) ProbeTLS(_ context.Context, host string) tailnetTLSProbe {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tls[host]
}

// sequenceMachineStore returns the next snapshot on each listing and keeps
// returning the last one — the reconciler's progress as seen by --wait.
type sequenceMachineStore struct {
	mu        sync.Mutex
	snapshots [][]meta.Machine
	calls     int
	onList    func(call int)
}

func (s *sequenceMachineStore) ListMachines(context.Context, tenant.Summary) ([]meta.Machine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.onList != nil {
		s.onList(s.calls)
	}
	index := s.calls - 1
	if index >= len(s.snapshots) {
		index = len(s.snapshots) - 1
	}
	return s.snapshots[index], nil
}

func tailnetWebMachine(certState string) meta.Machine {
	config := map[string]string{
		meta.KeyV2PublicHostnames:     "internal.tc42.uk",
		meta.KeyV2TailnetPublications: "internal.tc42.uk",
	}
	if certState != "" {
		config[meta.KeyV2CertState] = "internal.tc42.uk=" + certState
		config[meta.KeyV2CertNotAfter] = "2026-12-24T15:31:35Z"
	}
	return meta.DecodeMachine(config, meta.Machine{Tenant: "demo", Project: "zp", Name: "web", PrivateIP: "10.123.0.7"})
}

func tailnetWaitTestConfig(t *testing.T, store *sequenceMachineStore, prober *stubTailnetProber) (commandConfig, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	config, stdout := hostnameTestConfig(t, &stubAuthHostnames{})
	stderr := &bytes.Buffer{}
	config.stderr = stderr
	config.machineStore = store
	config.tailnetProber = prober
	config.tailnetWaitInterval = time.Millisecond
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
			_, _ = io.WriteString(output, "\n")
		}
		return nil
	}
	return config, stdout, stderr
}

// publish must not report success while the name still fails for a caller:
// it waits through a missing A record, a pending certificate and a TLS
// handshake error (Caddy not yet reloaded) until HTTPS answers cleanly.
func TestTailnetPublishWaitsUntilDNSCertificateAndHTTPSAreReady(t *testing.T) {
	prober := &stubTailnetProber{dns: map[string][]string{}, tls: map[string]tailnetTLSProbe{}}
	// Listing 1 is publish resolving the target address; the wait loop polls
	// from listing 2 on.
	store := &sequenceMachineStore{snapshots: [][]meta.Machine{
		{tailnetWebMachine("pending")},
		{tailnetWebMachine("pending")},
		{tailnetWebMachine("pending")},
		{tailnetWebMachine("installed")},
	}}
	store.onList = func(call int) {
		prober.mu.Lock()
		defer prober.mu.Unlock()
		switch call {
		case 3:
			prober.dns["internal.tc42.uk"] = []string{"10.123.0.7"}
		case 4:
			prober.tls["internal.tc42.uk"] = tailnetTLSProbe{Reachable: true, Error: "remote error: tls: internal error"}
		case 5:
			prober.tls["internal.tc42.uk"] = tailnetTLSProbe{Reachable: true, OK: true, Status: 403, Issuer: "Let's Encrypt YE1"}
		}
	}
	config, stdout, stderr := tailnetWaitTestConfig(t, store, prober)

	command := newTailnetCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"publish", "zp:web", "--hostname", "internal.tc42.uk"})
	if err := command.Execute(); err != nil {
		t.Fatalf("publish: %v\nstderr:\n%s", err, stderr)
	}
	if got, want := stdout.String(), "Tailnet HTTPS published: https://internal.tc42.uk → web:443\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	progress := stderr.String()
	for _, want := range []string{
		"DNS not resolving · certificate pending",
		"HTTPS error: remote error: tls: internal error",
		"certificate installed, until 2026-12-24 · HTTPS ok (403)",
		"internal.tc42.uk ready after",
		"the app answers 403 for Host: internal.tc42.uk",
	} {
		if !strings.Contains(progress, want) {
			t.Errorf("stderr lacks %q:\n%s", want, progress)
		}
	}
	// ready on listing 5, confirmed on listing 6
	if store.calls != 6 {
		t.Errorf("listings = %d, want 6", store.calls)
	}
}

// A CLI host outside the Tenant Tailnet cannot reach the private address;
// that must not hold --wait hostage once DNS and certificate are done.
func TestTailnetPublishWaitAcceptsUnreachableHTTPSFromOutsideTheTailnet(t *testing.T) {
	prober := &stubTailnetProber{dns: map[string][]string{"internal.tc42.uk": {"10.123.0.7"}}, tls: map[string]tailnetTLSProbe{}}
	store := &sequenceMachineStore{snapshots: [][]meta.Machine{{tailnetWebMachine("installed")}}}
	config, _, stderr := tailnetWaitTestConfig(t, store, prober)

	command := newTailnetCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"publish", "zp:web", "--hostname", "internal.tc42.uk"})
	if err := command.Execute(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !strings.Contains(stderr.String(), "HTTPS not reachable from this host") || !strings.Contains(stderr.String(), "receives Host: internal.tc42.uk") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestTailnetPublishWaitStopsOnFailedCertificateAndOnTimeout(t *testing.T) {
	for _, test := range []struct {
		name    string
		state   string
		timeout string
		want    string
	}{
		{name: "failed", state: "failed:rate-limited", timeout: "1m", want: "certificate for internal.tc42.uk failed:rate-limited"},
		{name: "timeout", state: "pending", timeout: "20ms", want: "timed out after 20ms waiting for https://internal.tc42.uk"},
	} {
		t.Run(test.name, func(t *testing.T) {
			prober := &stubTailnetProber{dns: map[string][]string{"internal.tc42.uk": {"10.123.0.7"}}}
			store := &sequenceMachineStore{snapshots: [][]meta.Machine{{tailnetWebMachine(test.state)}}}
			config, _, _ := tailnetWaitTestConfig(t, store, prober)
			command := newTailnetCommand(config, &rootOptions{output: outputText})
			command.SetArgs([]string{"publish", "zp:web", "--hostname", "internal.tc42.uk", "--wait-timeout", test.timeout})
			err := command.Execute()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestTailnetStatusListsPublicationsWithReadiness(t *testing.T) {
	other := meta.DecodeMachine(map[string]string{
		meta.KeyV2PublicHostnames:     "api.tc42.uk",
		meta.KeyV2TailnetPublications: "api.tc42.uk",
		meta.KeyV2CertState:           "api.tc42.uk=pending",
	}, meta.Machine{Tenant: "demo", Project: "zp", Name: "api", PrivateIP: "10.123.0.8"})
	private := meta.Machine{Tenant: "demo", Project: "zp", Name: "db", PrivateIP: "10.123.0.9"}
	prober := &stubTailnetProber{
		dns: map[string][]string{"internal.tc42.uk": {"10.123.0.7"}, "api.tc42.uk": {"10.123.0.99"}},
		tls: map[string]tailnetTLSProbe{"internal.tc42.uk": {Reachable: true, OK: true, Status: 200}},
	}
	store := &sequenceMachineStore{snapshots: [][]meta.Machine{{tailnetWebMachine("installed"), other, private}}}
	config, stdout, _ := tailnetWaitTestConfig(t, store, prober)

	command := newTailnetCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"ls"})
	if err := command.Execute(); err != nil {
		t.Fatalf("ls: %v", err)
	}
	want := "HOSTNAME          MACHINE  DNS                            CERTIFICATE                  HTTPS     READY\n" +
		"api.tc42.uk       zp:api   10.123.0.99 (want 10.123.0.8)  pending                      -         no\n" +
		"internal.tc42.uk  zp:web   10.123.0.7                     installed, until 2026-12-24  ok (200)  yes\n"
	if got := stdout.String(); got != want {
		t.Fatalf("output =\n%s\nwant\n%s", got, want)
	}

	stdout.Reset()
	command = newTailnetCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"status", "zp:web"})
	if err := command.Execute(); err != nil {
		t.Fatalf("status: %v", err)
	}
	if got := stdout.String(); !strings.Contains(got, "internal.tc42.uk") || strings.Contains(got, "api.tc42.uk") {
		t.Fatalf("status zp:web =\n%s", got)
	}
}

// Command groups below the root must reject an unknown subcommand instead of
// printing help and exiting 0; a bare group still prints help.
func TestUnknownSubcommandOfAGroupIsAnError(t *testing.T) {
	var stdout bytes.Buffer
	root := NewRootCommand(commandConfig{stdout: &stdout, stderr: &bytes.Buffer{}, adminConfig: scconfig.Admin{Remote: "demo"}})
	root.SetOut(&stdout)
	root.SetArgs([]string{"tailnet", "frobnicate"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), `unknown command "frobnicate" for "sandcastle tailnet"`) {
		t.Fatalf("error = %v", err)
	}

	root = NewRootCommand(commandConfig{stdout: &stdout, stderr: &bytes.Buffer{}, adminConfig: scconfig.Admin{Remote: "demo"}})
	root.SetOut(&stdout)
	root.SetArgs([]string{"tailnet", "unpublsh"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "Did you mean this?\n\tunpublish") {
		t.Fatalf("error = %v", err)
	}

	stdout.Reset()
	root = NewRootCommand(commandConfig{stdout: &stdout, stderr: &bytes.Buffer{}, adminConfig: scconfig.Admin{Remote: "demo"}})
	root.SetOut(&stdout)
	root.SetArgs([]string{"tailnet"})
	if err := root.Execute(); err != nil {
		t.Fatalf("bare group: %v", err)
	}
	if !strings.Contains(stdout.String(), "Available Commands:") {
		t.Fatalf("bare group output = %q", stdout.String())
	}
}

// One ready poll followed by a reconciler pass that drops the record again
// must not end the wait: readiness has to hold on consecutive polls.
func TestTailnetPublishWaitRequiresConsecutiveReadyPolls(t *testing.T) {
	prober := &stubTailnetProber{
		dns: map[string][]string{"internal.tc42.uk": {"10.123.0.7"}},
		tls: map[string]tailnetTLSProbe{"internal.tc42.uk": {Reachable: true, OK: true, Status: 200}},
	}
	store := &sequenceMachineStore{snapshots: [][]meta.Machine{{tailnetWebMachine("installed")}}}
	store.onList = func(call int) {
		prober.mu.Lock()
		defer prober.mu.Unlock()
		switch call {
		case 3: // ready on listing 2, then the record flaps away
			delete(prober.dns, "internal.tc42.uk")
		case 4:
			prober.dns["internal.tc42.uk"] = []string{"10.123.0.7"}
		}
	}
	config, _, stderr := tailnetWaitTestConfig(t, store, prober)
	command := newTailnetCommand(config, &rootOptions{output: outputText})
	command.SetArgs([]string{"publish", "zp:web", "--hostname", "internal.tc42.uk"})
	if err := command.Execute(); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if store.calls != 5 {
		t.Fatalf("listings = %d, want 5\n%s", store.calls, stderr)
	}
	if strings.Contains(stderr.String(), "receives Host") || strings.Contains(stderr.String(), "warning") {
		t.Fatalf("a 200 from the app must not print a host hint:\n%s", stderr)
	}
}

func TestAbsoluteDNSNameStopsSearchDomainExpansion(t *testing.T) {
	for in, want := range map[string]string{
		"internal.tc42.uk":  "internal.tc42.uk.",
		"internal.tc42.uk.": "internal.tc42.uk.",
		"10.125.0.17":       "10.125.0.17",
		"":                  "",
	} {
		if got := absoluteDNSName(in); got != want {
			t.Errorf("absoluteDNSName(%q) = %q, want %q", in, got, want)
		}
	}
}
