package localtrust

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

func TestPlanInstallFindsManagedTenant(t *testing.T) {
	plan, err := PlanInstall(context.Background(), scconfig.LoadAdminFromEnv(), tenant.MemoryStore{Projects: v2AcmeProjects()}, Request{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.IncusProject != "sc2-acme-default" {
		t.Fatalf("IncusProject = %q", plan.IncusProject)
	}
	if plan.CAVolume != tenant.CAVolumeName || plan.CertificatePath != tenant.TenantCACertPath {
		t.Fatalf("CA location = %s:%s", plan.CAVolume, plan.CertificatePath)
	}
	if !strings.Contains(plan.Warning, "mint certificates") {
		t.Fatalf("Warning = %q", plan.Warning)
	}
}

func TestPlanInstallSupportsCurrentTenant(t *testing.T) {
	admin := scconfig.LoadAdminFromEnv()
	admin.Tenant = "acme"
	plan, err := PlanInstall(context.Background(), admin, tenant.MemoryStore{Projects: v2AcmeProjects()}, Request{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reference != "acme" {
		t.Fatalf("Reference = %q", plan.Reference)
	}
}

func TestPlanInstallRejectsMissingTenant(t *testing.T) {
	_, err := PlanInstall(context.Background(), scconfig.LoadAdminFromEnv(), tenant.MemoryStore{}, Request{Reference: "missing"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFileStoreInstallAndUninstall(t *testing.T) {
	dir := t.TempDir()
	store := FileStore{Dir: dir}
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	result, err := store.InstallCA(context.Background(), plan, []byte("CERT"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "install" {
		t.Fatalf("Action = %q", result.Action)
	}
	content, err := os.ReadFile(filepath.Join(dir, CertFilename(plan)))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "CERT" {
		t.Fatalf("content = %q", content)
	}
	result, err = store.UninstallCA(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "uninstall" {
		t.Fatalf("Action = %q", result.Action)
	}
	if _, err := os.Stat(filepath.Join(dir, CertFilename(plan))); !os.IsNotExist(err) {
		t.Fatalf("expected cert removal, stat err = %v", err)
	}
}

func TestCommandStoreRejectsEmptyCA(t *testing.T) {
	_, err := (CommandStore{GOOS: "linux", LinuxDir: t.TempDir()}).InstallCA(context.Background(), Plan{
		Reference: "acme",
		TrustName: "Sandcastle acme tenant CA",
	}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "certificate is empty") {
		t.Fatalf("error = %q", err)
	}
}

func TestCommandStoreInstallLinuxCreatesTrustDirectoryAndUpdates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca-certificates")
	var commands []string
	store := CommandStore{
		GOOS:     "linux",
		LinuxDir: dir,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, name)
			return []byte("ok"), nil
		},
	}
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	result, err := store.InstallCA(context.Background(), plan, []byte("CERT"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Platform != "linux" || result.Action != "install" {
		t.Fatalf("result = %#v", result)
	}
	content, err := os.ReadFile(filepath.Join(dir, CertFilename(plan)))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "CERT" {
		t.Fatalf("content = %q", content)
	}
	if len(commands) != 1 || commands[0] != "update-ca-certificates" {
		t.Fatalf("commands = %#v", commands)
	}
}

func TestCommandStoreInstallDarwinUsesLoginKeychain(t *testing.T) {
	keychain := filepath.Join(t.TempDir(), "login.keychain-db")
	t.Setenv("SANDCASTLE_DARWIN_TRUST_KEYCHAIN", keychain)
	var commandName string
	var commandArgs []string
	store := CommandStore{
		GOOS: "darwin",
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commandName = name
			commandArgs = append([]string{}, args...)
			return []byte("ok"), nil
		},
	}
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	result, err := store.InstallCA(context.Background(), plan, []byte("CERT"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Platform != "darwin" || result.Action != "install" {
		t.Fatalf("result = %#v", result)
	}
	if commandName != "security" {
		t.Fatalf("commandName = %q", commandName)
	}
	if len(commandArgs) == 0 || commandArgs[0] != "add-trusted-cert" {
		t.Fatalf("commandArgs = %#v", commandArgs)
	}
	if !slices.Contains(commandArgs, keychain) {
		t.Fatalf("commandArgs missing login keychain: %#v", commandArgs)
	}
	if slices.Contains(commandArgs, "-d") {
		t.Fatalf("commandArgs should use user trust settings, got %#v", commandArgs)
	}
}

func TestCommandStoreInstallDarwinUsesSecurityDirectlyWhenRoot(t *testing.T) {
	var commandName string
	var commandArgs []string
	store := CommandStore{
		GOOS:         "darwin",
		EffectiveUID: func() int { return 0 },
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commandName = name
			commandArgs = append([]string{}, args...)
			return []byte("ok"), nil
		},
	}
	_, err := store.InstallCA(context.Background(), Plan{
		Reference: "acme",
		TrustName: "Sandcastle acme tenant CA",
	}, []byte("CERT"))
	if err != nil {
		t.Fatal(err)
	}
	if commandName != "security" {
		t.Fatalf("commandName = %q", commandName)
	}
	if len(commandArgs) == 0 || commandArgs[0] != "add-trusted-cert" {
		t.Fatalf("commandArgs = %#v", commandArgs)
	}
}

func TestCommandStoreInstallDarwinSkipsExistingCertificate(t *testing.T) {
	keychain := filepath.Join(t.TempDir(), "login.keychain-db")
	t.Setenv("SANDCASTLE_DARWIN_TRUST_KEYCHAIN", keychain)
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n")
	var commands []string
	store := CommandStore{
		GOOS: "darwin",
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, strings.Join(append([]string{name}, args...), " "))
			if len(args) > 0 && args[0] == "find-certificate" {
				return certPEM, nil
			}
			t.Fatalf("unexpected mutating command: %s %#v", name, args)
			return nil, nil
		},
	}
	result, err := store.InstallCA(context.Background(), Plan{
		Reference: "infrastructure",
		TrustName: "Sandcastle infrastructure debug CA",
	}, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if result.Target != keychain {
		t.Fatalf("Target = %q", result.Target)
	}
	if len(commands) != 1 || !strings.Contains(commands[0], "find-certificate -a -p") {
		t.Fatalf("commands = %#v", commands)
	}
}

func TestCommandStoreUninstallLinuxRemovesTrustFileAndUpdates(t *testing.T) {
	dir := t.TempDir()
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	target := filepath.Join(dir, CertFilename(plan))
	if err := os.WriteFile(target, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	var commands []string
	store := CommandStore{
		GOOS:     "linux",
		LinuxDir: dir,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, name)
			return []byte("ok"), nil
		},
	}
	result, err := store.UninstallCA(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Platform != "linux" || result.Action != "uninstall" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("expected cert removal, stat err = %v", err)
	}
	if len(commands) != 1 || commands[0] != "update-ca-certificates" {
		t.Fatalf("commands = %#v", commands)
	}
}

func TestPlanDoesNotSerializePEM(t *testing.T) {
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "PRIVATE KEY") {
		t.Fatalf("payload leaked key material: %s", payload)
	}
}

// Regression for #56: the system trust directory is root-owned, but `sc` runs as
// the user. Only the privileged operations escalate; the rest of the command
// keeps the caller's $HOME so the login config stays reachable.
func TestCommandStoreInstallLinuxEscalatesOnPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the direct write succeeds and never escalates")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "ca-certificates")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil { // read-only: writes hit fs.ErrPermission
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	var commands [][]string
	store := CommandStore{
		GOOS:     "linux",
		LinuxDir: dir,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, append([]string{name}, args...))
			return []byte("ok"), nil
		},
	}
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	result, err := store.InstallCA(context.Background(), plan, []byte("CERT"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "install" || result.Platform != "linux" {
		t.Fatalf("result = %#v", result)
	}
	if len(commands) != 2 {
		t.Fatalf("commands = %#v", commands)
	}
	install := commands[0]
	if install[0] != "sudo" || install[1] != "install" {
		t.Fatalf("expected a sudo install, got %#v", install)
	}
	if install[len(install)-1] != filepath.Join(dir, CertFilename(plan)) {
		t.Fatalf("install target = %q", install[len(install)-1])
	}
	// the follow-up must run with the same privileges, or it silently no-ops
	if got := strings.Join(commands[1], " "); got != "sudo update-ca-certificates" {
		t.Fatalf("update command = %q", got)
	}
}

func TestCommandStoreUninstallLinuxEscalatesOnPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the direct remove succeeds and never escalates")
	}
	dir := t.TempDir()
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	target := filepath.Join(dir, CertFilename(plan))
	if err := os.WriteFile(target, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil { // unlink needs write on the directory
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	var commands [][]string
	store := CommandStore{
		GOOS:     "linux",
		LinuxDir: dir,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, append([]string{name}, args...))
			return []byte("ok"), nil
		},
	}
	if _, err := store.UninstallCA(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || commands[0][0] != "sudo" || commands[0][1] != "rm" {
		t.Fatalf("commands = %#v", commands)
	}
	if got := strings.Join(commands[1], " "); got != "sudo update-ca-certificates" {
		t.Fatalf("update command = %q", got)
	}
}

// A missing CA is not an error and must not escalate.
func TestCommandStoreUninstallLinuxAbsentCertDoesNotEscalate(t *testing.T) {
	dir := t.TempDir()
	var commands [][]string
	store := CommandStore{
		GOOS:     "linux",
		LinuxDir: dir,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, append([]string{name}, args...))
			return []byte("ok"), nil
		},
	}
	if _, err := store.UninstallCA(context.Background(), Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || commands[0][0] != "update-ca-certificates" {
		t.Fatalf("commands = %#v", commands)
	}
}

// update-ca-certificates lives in /usr/sbin, which is not on an unprivileged
// PATH, so exec reports "not found" rather than "permission denied". Treat that
// as a privilege symptom and retry under sudo, or the install half-completes:
// the CA is written but the system bundle is never rebuilt.
func TestCommandStoreRetriesUpdateUnderSudoWhenNotOnPath(t *testing.T) {
	dir := t.TempDir()
	var commands [][]string
	store := CommandStore{
		GOOS:     "linux",
		LinuxDir: dir,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, append([]string{name}, args...))
			if name == "update-ca-certificates" {
				return nil, &exec.Error{Name: name, Err: exec.ErrNotFound}
			}
			return []byte("ok"), nil
		},
	}
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	if _, err := store.InstallCA(context.Background(), plan, []byte("CERT")); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"update-ca-certificates"}, {"sudo", "update-ca-certificates"}}
	if len(commands) != len(want) {
		t.Fatalf("commands = %#v", commands)
	}
	for i := range want {
		if strings.Join(commands[i], " ") != strings.Join(want[i], " ") {
			t.Fatalf("commands[%d] = %q, want %q", i, commands[i], want[i])
		}
	}
}

// A genuine failure (not a privilege symptom) must surface, not silently retry.
func TestCommandStoreDoesNotRetryUpdateOnRealFailure(t *testing.T) {
	dir := t.TempDir()
	var calls int
	store := CommandStore{
		GOOS:     "linux",
		LinuxDir: dir,
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			calls++
			return []byte("boom"), errors.New("bundle corrupt")
		},
	}
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	_, err := store.InstallCA(context.Background(), plan, []byte("CERT"))
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected a single attempt, got %d", calls)
	}
	if !strings.Contains(err.Error(), "bundle corrupt") {
		t.Fatalf("error = %q", err)
	}
}

// Regression for #61: a v2 tenant's CA is minted by the sidecar signer with
// CN="Sandcastle <suffix> tenant CA", and install names the local trust entry
// after that CN. Deriving the name from the TENANT (the v1 rule) produced a
// filename that never matched, so uninstall removed nothing and said "success".
func TestPlanNamesAV2TrustEntryAfterTheDNSSuffix(t *testing.T) {
	v2 := func(kind string) map[string]string {
		config := map[string]string{
			meta.KeyKind:    kind,
			meta.KeyTenant:  "alice",
			meta.KeyVersion: "2",
		}
		if kind == meta.KindInfra {
			config[meta.KeyV2Suffix] = "castle"
		}
		return config
	}
	store := tenant.MemoryStore{Projects: []tenant.IncusProject{
		{Name: "sc2-alice", Config: v2(meta.KindInfra)},
		{Name: "sc2-alice-default", Config: v2(meta.KindV2Project)},
	}}
	plan, err := PlanUninstall(context.Background(), scconfig.LoadAdminFromEnv(), store, Request{Reference: "alice", InstallPrefix: "sc2"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.TrustName != "Sandcastle castle tenant CA" {
		t.Fatalf("TrustName = %q, want the signer's CN %q", plan.TrustName, "Sandcastle castle tenant CA")
	}
	if got := CertFilename(plan); got != "sandcastle-castle-tenant-ca.crt" {
		t.Fatalf("CertFilename = %q — must match what install wrote", got)
	}
}

// An uninstall that found nothing must say so rather than report success.
func TestUninstallReportsWhenNothingWasRemoved(t *testing.T) {
	dir := t.TempDir()
	store := CommandStore{
		GOOS:       "linux",
		LinuxDir:   dir,
		RunCommand: func(context.Context, string, ...string) ([]byte, error) { return []byte("ok"), nil },
	}
	plan := Plan{Reference: "alice", TrustName: "Sandcastle castle tenant CA"}

	absent, err := store.UninstallCA(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if absent.Removed {
		t.Fatal("Removed = true, but no CA was installed")
	}

	if _, err := store.InstallCA(context.Background(), plan, []byte("CERT")); err != nil {
		t.Fatal(err)
	}
	present, err := store.UninstallCA(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !present.Removed {
		t.Fatal("Removed = false after uninstalling an installed CA")
	}
	if _, err := os.Stat(filepath.Join(dir, CertFilename(plan))); !os.IsNotExist(err) {
		t.Fatalf("cert still present: %v", err)
	}
}

// v2AcmeProjects is the v2 fixture for tenant "acme": a kind=infra project
// carrying the /24, plus one kind=project app project. v1 (kind=tenant)
// projects are no longer surfaced by tenant.List.
func v2AcmeProjects() []tenant.IncusProject {
	config := func(kind string) map[string]string {
		out := map[string]string{
			meta.KeyKind:    kind,
			meta.KeyTenant:  "acme",
			meta.KeyVersion: "2",
		}
		if kind == meta.KindInfra {
			out[meta.KeyV2CIDR] = "10.248.0.0/24"
		}
		return out
	}
	return []tenant.IncusProject{
		{Name: "sc2-acme", Config: config(meta.KindInfra)},
		{Name: "sc2-acme-default", Config: config(meta.KindV2Project)},
	}
}

// Arch (and Fedora) use p11-kit: anchors in their own directory, refreshed by
// update-ca-trust. Writing Debian's /usr/local/share/ca-certificates there is
// silently ignored, and update-ca-certificates does not exist.
func TestDetectLinuxTrustLayout(t *testing.T) {
	cases := []struct {
		name string
		dirs []string
		want LinuxTrustLayout
	}{
		{"arch", []string{"/etc/ca-certificates/trust-source/anchors", "/usr/local/share/ca-certificates"}, LinuxTrustLayout{"/etc/ca-certificates/trust-source/anchors", "update-ca-trust"}},
		{"fedora", []string{"/etc/pki/ca-trust/source/anchors"}, LinuxTrustLayout{"/etc/pki/ca-trust/source/anchors", "update-ca-trust"}},
		{"opensuse", []string{"/etc/pki/trust/anchors"}, LinuxTrustLayout{"/etc/pki/trust/anchors", "update-ca-certificates"}},
		{"debian", []string{"/usr/local/share/ca-certificates"}, LinuxTrustLayout{"/usr/local/share/ca-certificates", "update-ca-certificates"}},
		{"unknown", nil, LinuxTrustLayout{"/usr/local/share/ca-certificates", "update-ca-certificates"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectLinuxTrustLayout(func(path string) bool {
				for _, dir := range tc.dirs {
					if dir == path {
						return true
					}
				}
				return false
			})
			if got != tc.want {
				t.Fatalf("layout = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestCommandStoreInstallLinuxRunsLayoutUpdateCommand(t *testing.T) {
	dir := t.TempDir()
	var commands [][]string
	store := CommandStore{
		GOOS:        "linux",
		LinuxDir:    dir,
		LinuxUpdate: "update-ca-trust",
		RunCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, append([]string{name}, args...))
			if name == "update-ca-trust" {
				return nil, &exec.Error{Name: name, Err: fs.ErrPermission}
			}
			return []byte("ok"), nil
		},
	}
	plan := Plan{Reference: "acme", TrustName: "Sandcastle acme tenant CA"}
	result, err := store.InstallCA(context.Background(), plan, []byte("CERT"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Target != filepath.Join(dir, CertFilename(plan)) {
		t.Fatalf("Target = %q", result.Target)
	}
	want := "update-ca-trust | sudo update-ca-trust"
	var got []string
	for _, c := range commands {
		got = append(got, strings.Join(c, " "))
	}
	if strings.Join(got, " | ") != want {
		t.Fatalf("commands = %q, want %q", got, want)
	}
}
