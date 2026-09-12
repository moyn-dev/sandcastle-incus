package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
)

type fakePublicDNSZoneClient struct {
	zones   []authapp.PublicDNSZone
	fail    error
	adds    []string // "zone token dryRun"
	sets    []string
	removes []string
}

func (f *fakePublicDNSZoneClient) ListPublicDNSZones(context.Context) ([]authapp.PublicDNSZone, error) {
	return f.zones, f.fail
}

func (f *fakePublicDNSZoneClient) AddPublicDNSZone(_ context.Context, zone, token string, dryRun bool) (authapp.PublicDNSZoneResult, error) {
	f.adds = append(f.adds, zone+" "+token+" "+boolString(dryRun))
	if f.fail != nil {
		return authapp.PublicDNSZoneResult{}, f.fail
	}
	return authapp.PublicDNSZoneResult{Zone: zone, CloudflareZoneID: "cf-" + zone, DryRun: dryRun}, nil
}

func (f *fakePublicDNSZoneClient) SetPublicDNSZoneToken(_ context.Context, zone, token string, dryRun bool) (authapp.PublicDNSZoneResult, error) {
	f.sets = append(f.sets, zone+" "+token+" "+boolString(dryRun))
	if f.fail != nil {
		return authapp.PublicDNSZoneResult{}, f.fail
	}
	return authapp.PublicDNSZoneResult{Zone: zone, CloudflareZoneID: "cf-" + zone, DryRun: dryRun}, nil
}

func (f *fakePublicDNSZoneClient) RemovePublicDNSZone(_ context.Context, zone string, dryRun bool) (authapp.PublicDNSZoneResult, error) {
	f.removes = append(f.removes, zone+" "+boolString(dryRun))
	if f.fail != nil {
		return authapp.PublicDNSZoneResult{}, f.fail
	}
	return authapp.PublicDNSZoneResult{Zone: zone, DryRun: dryRun}, nil
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// runZoneOnBothRoots executes the same verb as `sc admin public-dns-zone …`
// and as `sc-adm public-dns-zone …` and returns both outputs. main.go routes
// `sc admin …` to ExecuteAdmin("sc admin", …), i.e. the admin root under the
// user binary's name — so both roots are NewAdminRootCommand with a different
// config.name.
func runZoneOnBothRoots(t *testing.T, config commandConfig, args ...string) (userOut string, userErr error, adminOut string, adminErr error) {
	t.Helper()
	userConfig := config
	userConfig.name = "sc admin"
	userOut, userErr = executeAdminForTestWithConfig(t, userConfig, append([]string{"public-dns-zone"}, args...)...)
	adminConfig := config
	adminConfig.name = "sc-adm"
	adminOut, adminErr = executeAdminForTestWithConfig(t, adminConfig, append([]string{"public-dns-zone"}, args...)...)
	return
}

// executeScAdminForTest runs `sc admin public-dns-zone …`.
func executeScAdminForTest(t *testing.T, config commandConfig, args ...string) (string, error) {
	t.Helper()
	config.name = "sc admin"
	return executeAdminForTestWithConfig(t, config, append([]string{"public-dns-zone"}, args...)...)
}

func TestPublicDNSZoneIsInTheLegacyAdminSubcommandTree(t *testing.T) {
	admin := newAdminCommand(commandConfig{}, &rootOptions{output: outputText})
	cmd, _, err := admin.Find([]string{"public-dns-zone", "add"})
	if err != nil || cmd == nil || cmd.Name() != "add" {
		t.Fatalf("public-dns-zone add not under the admin subcommand tree: %v", err)
	}
	for _, verb := range []string{"list", "remove", "set-token"} {
		if cmd, _, err := admin.Find([]string{"public-dns-zone", verb}); err != nil || cmd.Name() != verb {
			t.Fatalf("missing verb %s: %v", verb, err)
		}
	}
	// The user root never carries it directly — only via `sc admin`.
	if cmd, _, _ := NewRootCommand(commandConfig{}).Find([]string{"public-dns-zone"}); cmd != nil && cmd.Name() == "public-dns-zone" {
		t.Fatal("public-dns-zone must not be a top-level user command")
	}
}

func TestPublicDNSZoneAddIsMountedOnBothRoots(t *testing.T) {
	client := &fakePublicDNSZoneClient{}
	config := commandConfig{authPublicDNSZones: client}
	userOut, userErr, adminOut, adminErr := runZoneOnBothRoots(t, config, "add", "Hase.DE.", "--token", "tok")
	if userErr != nil || adminErr != nil {
		t.Fatalf("errors: %v / %v", userErr, adminErr)
	}
	want := "Registered public DNS zone hase.de (Cloudflare zone id cf-hase.de)"
	if !strings.Contains(userOut, want) || !strings.Contains(adminOut, want) {
		t.Fatalf("outputs:\n%s\n---\n%s", userOut, adminOut)
	}
	if len(client.adds) != 2 || client.adds[0] != "hase.de tok false" || client.adds[1] != "hase.de tok false" {
		t.Fatalf("adds = %v", client.adds)
	}
}

func TestPublicDNSZoneTokenSources(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &fakePublicDNSZoneClient{}
	if _, err := executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: client}, "public-dns-zone", "add", "hase.de", "--token-file", file); err != nil {
		t.Fatal(err)
	}
	if _, err := executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: client, stdin: strings.NewReader("from-stdin\n")}, "public-dns-zone", "set-token", "hase.de"); err != nil {
		t.Fatal(err)
	}
	if _, err := executeScAdminForTest(t, commandConfig{authPublicDNSZones: client, stdin: strings.NewReader("from-stdin-user\n")}, "add", "igel.de"); err != nil {
		t.Fatal(err)
	}
	if len(client.adds) != 2 || client.adds[0] != "hase.de from-file false" || client.adds[1] != "igel.de from-stdin-user false" {
		t.Fatalf("adds = %v", client.adds)
	}
	if len(client.sets) != 1 || client.sets[0] != "hase.de from-stdin false" {
		t.Fatalf("sets = %v", client.sets)
	}

	// no token anywhere → refused before the API is touched
	before := len(client.adds)
	_, err := executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: client, stdin: strings.NewReader("")}, "public-dns-zone", "add", "hase.de")
	if err == nil || !strings.Contains(err.Error(), "a Cloudflare API token is required") {
		t.Fatalf("missing token: %v", err)
	}
	_, err = executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: client}, "public-dns-zone", "add", "hase.de", "--token", "a", "--token-file", file)
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("both sources: %v", err)
	}
	if len(client.adds) != before {
		t.Fatalf("API touched for a refused add: %v", client.adds)
	}
}

func TestPublicDNSZoneDryRunOnMutatingVerbs(t *testing.T) {
	client := &fakePublicDNSZoneClient{}
	config := commandConfig{authPublicDNSZones: client}
	out, err := executeAdminForTestWithConfig(t, config, "public-dns-zone", "add", "hase.de", "--token", "t", "--dry-run")
	if err != nil || !strings.Contains(out, "[dry-run] would have: Registered public DNS zone hase.de") {
		t.Fatalf("add dry-run: %v\n%s", err, out)
	}
	out, err = executeScAdminForTest(t, config, "set-token", "hase.de", "--token", "t", "--dry-run")
	if err != nil || !strings.Contains(out, "[dry-run] would have: Rotated token for public DNS zone hase.de") {
		t.Fatalf("set-token dry-run: %v\n%s", err, out)
	}
	out, err = executeAdminForTestWithConfig(t, config, "public-dns-zone", "remove", "hase.de", "--dry-run")
	if err != nil || !strings.Contains(out, "[dry-run] would have: Removed public DNS zone hase.de") {
		t.Fatalf("remove dry-run: %v\n%s", err, out)
	}
	if client.adds[0] != "hase.de t true" || client.sets[0] != "hase.de t true" || client.removes[0] != "hase.de true" {
		t.Fatalf("dry-run not forwarded: %v %v %v", client.adds, client.sets, client.removes)
	}
}

func TestPublicDNSZoneListTableAndJSON(t *testing.T) {
	client := &fakePublicDNSZoneClient{zones: []authapp.PublicDNSZone{
		{Zone: "hase.de", CloudflareZoneID: "cf-1", TokenFingerprint: "abcd1234", Claims: 2, CreatedBy: "root", CreatedAt: "2026-09-12T10:00:00Z"},
	}}
	userOut, userErr, adminOut, adminErr := runZoneOnBothRoots(t, commandConfig{authPublicDNSZones: client}, "list")
	if userErr != nil || adminErr != nil {
		t.Fatalf("errors: %v / %v", userErr, adminErr)
	}
	for _, out := range []string{userOut, adminOut} {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 2 {
			t.Fatalf("list output:\n%s", out)
		}
		if strings.Join(strings.Fields(lines[0]), " ") != "ZONE CLOUDFLARE-ID TOKEN CLAIMS CREATED-BY CREATED" {
			t.Fatalf("header = %q", lines[0])
		}
		if strings.Join(strings.Fields(lines[1]), " ") != "hase.de cf-1 abcd1234 2 root 2026-09-12T10:00:00Z" {
			t.Fatalf("row = %q", lines[1])
		}
	}
	jsonOut, err := executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: client}, "public-dns-zone", "list", "--output", "json")
	if err != nil || !strings.Contains(jsonOut, `"tokenFingerprint": "abcd1234"`) || strings.Contains(jsonOut, "encrypted") {
		t.Fatalf("json list: %v\n%s", err, jsonOut)
	}
	empty, err := executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: &fakePublicDNSZoneClient{}}, "public-dns-zone", "list", "--output", "json")
	if err != nil || strings.TrimSpace(empty) != "[]" {
		t.Fatalf("empty json list: %v %q", err, empty)
	}
}

func TestPublicDNSZoneServerErrorsPrintVerbatim(t *testing.T) {
	client := &fakePublicDNSZoneClient{fail: errors.New("public DNS zone hase.de overlaps registered zone sc.hase.de; zones may not nest")}
	_, err := executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: client}, "public-dns-zone", "add", "hase.de", "--token", "t")
	if err == nil || err.Error() != "public DNS zone hase.de overlaps registered zone sc.hase.de; zones may not nest" {
		t.Fatalf("error = %v", err)
	}
	client.fail = errors.New("public DNS zone hase.de still has claimed project domains: baum.hase.de (acme/baum); unset them first")
	_, err = executeScAdminForTest(t, commandConfig{authPublicDNSZones: client}, "remove", "hase.de")
	if err == nil || err.Error() != client.fail.Error() {
		t.Fatalf("error = %v", err)
	}
	// remove takes no --force
	_, err = executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: client}, "public-dns-zone", "remove", "hase.de", "--force")
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Fatalf("--force must not exist: %v", err)
	}
}

func TestPublicDNSZoneRejectsMalformedZoneLocally(t *testing.T) {
	client := &fakePublicDNSZoneClient{}
	for _, bad := range []string{"de", "-hase.de", "*.hase.de"} {
		_, err := executeAdminForTestWithConfig(t, commandConfig{authPublicDNSZones: client}, "public-dns-zone", "add", bad, "--token", "t")
		if err == nil {
			t.Fatalf("add %q: expected error", bad)
		}
	}
	if len(client.adds) != 0 {
		t.Fatalf("API touched for malformed zones: %v", client.adds)
	}
}

func TestPublicDNSZoneRequiresLogin(t *testing.T) {
	admin := testAdminConfig()
	admin.AuthToken = ""
	_, err := executeAdminForTestWithConfig(t, commandConfig{adminConfig: admin}, "public-dns-zone", "list")
	if err == nil || !strings.Contains(err.Error(), "CLI Auth Token is required") {
		t.Fatalf("error = %v", err)
	}
}
