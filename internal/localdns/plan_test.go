package localdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type recordingServiceRunner struct {
	commands [][]string
}

func (r *recordingServiceRunner) Run(ctx context.Context, args []string) error {
	r.commands = append(r.commands, append([]string(nil), args...))
	return nil
}

func TestPlanInstallUsesTenantDNSRoleAddress(t *testing.T) {
	t.Setenv("SANDCASTLE_LOCAL_DNS_STATE", filepath.Join(t.TempDir(), "dns.yaml"))
	t.Setenv("SANDCASTLE_RESOLVER_DIR", t.TempDir())
	plan, err := PlanInstall(context.Background(), scconfig.LoadAdminFromEnv(), storeForTest(t), Request{Reference: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.DNSEndpoint != "10.248.0.3:53" {
		t.Fatalf("DNSEndpoint = %q", plan.DNSEndpoint)
	}
	if !strings.HasSuffix(plan.ResolverPath, "acme") {
		t.Fatalf("ResolverPath = %q", plan.ResolverPath)
	}
}

func TestPlanInstallSupportsCurrentTenant(t *testing.T) {
	admin := scconfig.LoadAdminFromEnv()
	admin.Tenant = "acme"
	t.Setenv("SANDCASTLE_LOCAL_DNS_STATE", filepath.Join(t.TempDir(), "dns.yaml"))
	t.Setenv("SANDCASTLE_RESOLVER_DIR", t.TempDir())
	plan, err := PlanInstall(context.Background(), admin, storeForTest(t), Request{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Reference != "acme" {
		t.Fatalf("Reference = %q", plan.Reference)
	}
}

func TestFileManagerInstallRefreshAndUninstall(t *testing.T) {
	dir := t.TempDir()
	plan := Plan{
		Reference:    "acme",
		DNSSuffix:    "acme",
		DNSEndpoint:  "10.248.0.3:53",
		StatePath:    filepath.Join(dir, "state", "dns.yaml"),
		ResolverPath: filepath.Join(dir, "resolver", "acme"),
	}
	manager := FileManager{}
	result, err := manager.Install(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "install" {
		t.Fatalf("Action = %q", result.Action)
	}
	state, err := os.ReadFile(plan.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(state), "dnsEndpoint:") || !strings.Contains(string(state), "10.248.0.3") {
		t.Fatalf("state = %s", state)
	}
	resolver, err := os.ReadFile(plan.ResolverPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolver) != "nameserver 10.248.0.3\nport 53\n" {
		t.Fatalf("resolver = %q", resolver)
	}
	plan.DNSEndpoint = "10.248.1.3:53"
	result, err = manager.Refresh(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "refresh" {
		t.Fatalf("Action = %q", result.Action)
	}
	state, err = os.ReadFile(plan.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(state), "10.248.1.3") || strings.Contains(string(state), "10.248.0.3") {
		t.Fatalf("state = %s", state)
	}
	result, err = manager.Uninstall(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "uninstall" {
		t.Fatalf("Action = %q", result.Action)
	}
	if _, err := os.Stat(plan.ResolverPath); !os.IsNotExist(err) {
		t.Fatalf("expected resolver removal, stat err = %v", err)
	}
}

func TestFileManagerInstallWritesUnitAndEnablesIt(t *testing.T) {
	t.Setenv("SANDCASTLE_RESOLVER_DIR", "")
	dir := t.TempDir()
	runner := &recordingServiceRunner{}
	manager := FileManager{Runner: runner}
	plan := Plan{
		Reference:        "acme",
		DNSSuffix:        "acme",
		DNSEndpoint:      "10.248.0.3:53",
		StatePath:        filepath.Join(dir, "state", "dns.yaml"),
		ResolverPath:     filepath.Join(dir, "system", "sandcastle-dns-acme.service"),
		ResolverStrategy: StrategySystemdResolve,
	}
	if _, err := manager.Install(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl daemon-reload",
		"systemctl enable sandcastle-dns-acme.service",
		"systemctl restart sandcastle-dns-acme.service",
	}
	if len(runner.commands) != len(want) {
		t.Fatalf("commands = %#v", runner.commands)
	}
	for index, command := range runner.commands {
		if joinArgs(command) != want[index] {
			t.Fatalf("command[%d] = %q, want %q", index, joinArgs(command), want[index])
		}
	}
	content, err := os.ReadFile(plan.ResolverPath)
	if err != nil {
		t.Fatal(err)
	}
	link := resolvedLinkName("acme")
	if !strings.Contains(string(content), "dns-proxy --link "+link) ||
		!strings.Contains(string(content), "--domain acme --upstream 10.248.0.3:53") {
		t.Fatalf("unit content = %q", content)
	}
}

func TestFileManagerUninstallStopsUnitAndRemovesIt(t *testing.T) {
	t.Setenv("SANDCASTLE_RESOLVER_DIR", "")
	dir := t.TempDir()
	runner := &recordingServiceRunner{}
	manager := FileManager{Runner: runner}
	first := linuxResolverPlan(dir, "alpha", "alpha", "10.248.0.3:53")
	second := linuxResolverPlan(dir, "beta", "beta", "10.248.1.3:53")
	if _, err := manager.Install(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Install(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	if _, err := manager.Uninstall(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	// alpha's unit is stopped (tearing down its link scope) BEFORE its file is
	// removed; beta's survives; systemd re-reads unit files.
	if _, err := os.Stat(first.ResolverPath); !os.IsNotExist(err) {
		t.Fatalf("alpha unit should be removed, stat err = %v", err)
	}
	if _, err := os.Stat(second.ResolverPath); err != nil {
		t.Fatalf("beta unit should survive: %v", err)
	}
	want := []string{
		"systemctl disable --now sandcastle-dns-alpha.service",
		"systemctl daemon-reload",
	}
	if len(runner.commands) != len(want) {
		t.Fatalf("commands = %#v", runner.commands)
	}
	for index, command := range runner.commands {
		if joinArgs(command) != want[index] {
			t.Fatalf("command[%d] = %q, want %q", index, joinArgs(command), want[index])
		}
	}
}

func linuxResolverPlan(dir string, reference string, domain string, endpoint string) Plan {
	return Plan{
		Reference:        reference,
		DNSSuffix:        domain,
		DNSEndpoint:      endpoint,
		StatePath:        filepath.Join(dir, "state", "dns.yaml"),
		ResolverPath:     filepath.Join(dir, "resolver", domain),
		ResolverStrategy: StrategySystemdResolve,
		ResolverCommands: []Command{{Args: []string{"resolvectl", "dns", "lo", endpoint}}},
	}
}

func storeForTest(t *testing.T) tenant.MemoryStore {
	t.Helper()
	// v2 fixture: a kind=infra project carrying the tenant's /24, plus one
	// kind=project app project. v1 (kind=tenant) projects are no longer listed.
	v2 := func(kind string) map[string]string {
		config := map[string]string{
			meta.KeyKind:    kind,
			meta.KeyTenant:  "acme",
			meta.KeyVersion: "2",
		}
		if kind == meta.KindInfra {
			config[meta.KeyV2CIDR] = "10.248.0.0/24"
		}
		return config
	}
	return tenant.MemoryStore{Projects: []tenant.IncusProject{
		{Name: "sc2-acme", Config: v2(meta.KindInfra)},
		{Name: "sc2-acme-default", Config: v2(meta.KindV2Project)},
	}}
}
