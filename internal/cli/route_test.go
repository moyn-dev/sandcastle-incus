package cli

import (
	"context"
	"regexp"
	"strings"
	"testing"

	authapp "github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

// fakeRouteClient captures the request the CLI builds and returns scripted views.
type fakeRouteClient struct {
	published authapp.RoutePublishRequest
	view      authapp.RouteView
	listed    []authapp.RouteView
	deleted   string
	config    authapp.RouteConfigView
}

func (f *fakeRouteClient) RouteConfig(context.Context) (authapp.RouteConfigView, error) {
	return f.config, nil
}

func (f *fakeRouteClient) PublishRoute(_ context.Context, req authapp.RoutePublishRequest) (authapp.RouteView, error) {
	f.published = req
	if f.view.Hostname == "" {
		f.view = authapp.RouteView{Hostname: req.Machine + "." + req.Tenant + ".sc2.dev", URL: "https://" + req.Machine + "." + req.Tenant + ".sc2.dev", Machine: req.Machine, BackendPort: req.BackendPort, Status: "live"}
	}
	return f.view, nil
}
func (f *fakeRouteClient) ListRoutes(context.Context, string) ([]authapp.RouteView, error) {
	return f.listed, nil
}
func (f *fakeRouteClient) GetRouteStatus(context.Context, string) (authapp.RouteView, error) {
	return f.view, nil
}
func (f *fakeRouteClient) DeleteRoute(_ context.Context, hostname string) error {
	f.deleted = hostname
	return nil
}

// DeviceClient must satisfy the CLI's route client interface.
var _ authRouteClient = authapp.DeviceClient{}

func TestRoutePublishBuildsRequestFromArgs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakeRouteClient{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		tenantStore: infoV2ProjectStore("sc2-acme-web"),
		authRoutes:  fake,
	}, "route", "publish", "web:api", "--port", "3000", "--name", "myapp")
	if err != nil {
		t.Fatal(err)
	}
	if fake.published.Tenant != "acme" {
		t.Errorf("tenant = %q, want acme (from summary, not the arg)", fake.published.Tenant)
	}
	if fake.published.Project != "web" || fake.published.Machine != "api" {
		t.Errorf("project/machine = %q/%q, want web/api", fake.published.Project, fake.published.Machine)
	}
	if fake.published.BackendPort != 3000 {
		t.Errorf("port = %d, want 3000", fake.published.BackendPort)
	}
	if fake.published.Name != "myapp" {
		t.Errorf("name = %q, want myapp", fake.published.Name)
	}
	if !strings.Contains(stdout, "Published") {
		t.Errorf("stdout missing published line:\n%s", stdout)
	}
}

func TestRoutePublishRequiresPort(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		authRoutes:  &fakeRouteClient{},
	}, "route", "publish", "web:api")
	if err == nil || !strings.Contains(err.Error(), "--port is required") {
		t.Fatalf("expected --port required error, got %v", err)
	}
}

func TestRoutePublishDryRunDoesNotCallClient(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakeRouteClient{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		tenantStore: infoV2ProjectStore("sc2-acme-web"),
		authRoutes:  fake,
	}, "route", "publish", "web:api", "--port", "3000", "--name", "myapp", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if fake.published.Machine != "" {
		t.Fatalf("dry-run must not call the client, but it published %+v", fake.published)
	}
	if !strings.Contains(stdout, "dry run") || !strings.Contains(stdout, "myapp.acme") {
		t.Fatalf("dry-run output missing plan/hostname:\n%s", stdout)
	}
}

func TestRoutePublishCustomHostname(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakeRouteClient{}
	_, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		tenantStore: infoV2ProjectStore("sc2-acme-web"),
		authRoutes:  fake,
	}, "route", "publish", "web:api", "--port", "3000", "--hostname", "app.customer.com")
	if err != nil {
		t.Fatal(err)
	}
	if fake.published.Hostname != "app.customer.com" {
		t.Errorf("hostname = %q, want app.customer.com", fake.published.Hostname)
	}
}

func TestRouteListFormatsTable(t *testing.T) {
	out := formatRouteList([]authapp.RouteView{
		{Hostname: "web.acme.sc2.dev", Machine: "web", MachineFQDN: "web.default.acme.sc2.dev", BackendPort: 3000, Status: "live"},
		// No MachineFQDN (older appliance, or the suffix could not be read):
		// the bare Machine name stands in.
		{Hostname: "api.acme.sc2.dev", Machine: "api", BackendPort: 8080, Status: "unhealthy"},
	})
	for _, want := range []string{"HOSTNAME", "web.acme.sc2.dev", "web.default.acme.sc2.dev", "3000", "live", "unhealthy"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
	if !regexp.MustCompile(`(?m)^api\.acme\.sc2\.dev\s+api\s+8080\s`).MatchString(out) {
		t.Errorf("route without a MachineFQDN should fall back to the machine name:\n%s", out)
	}
	if empty := formatRouteList(nil); !strings.Contains(empty, "No published routes") {
		t.Errorf("empty list = %q", empty)
	}
}

func TestRouteStatusFormat(t *testing.T) {
	out := formatRouteStatus(authapp.RouteView{Hostname: "web.acme.sc2.dev", URL: "https://web.acme.sc2.dev", Tenant: "acme", Machine: "web", MachineFQDN: "web.default.acme.sc2.dev", BackendPort: 3000, Status: "live"})
	for _, want := range []string{"web.acme.sc2.dev", "Tenant:    acme", "web.default.acme.sc2.dev:3000", "live"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

// Caught live (majestix 2026-07-17): the --yes flag was registered but never
// read, so a non-interactive `sc route delete <host> --yes` refused with
// "refusing to delete route without --yes".
func TestRouteDeleteHonorsYesWithoutTTY(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakeRouteClient{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		authRoutes:  fake,
	}, "route", "delete", "api.acme.sc2.dev", "--yes")
	if err != nil {
		t.Fatalf("route delete --yes must not prompt or refuse: %v", err)
	}
	if fake.deleted != "api.acme.sc2.dev" {
		t.Errorf("deleted = %q, want api.acme.sc2.dev", fake.deleted)
	}
	if !strings.Contains(stdout, "Deleted route") {
		t.Errorf("stdout missing deletion line:\n%s", stdout)
	}
}

func TestRouteDeleteWithoutYesRefusesNonInteractive(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakeRouteClient{}
	_, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		authRoutes:  fake,
	}, "route", "delete", "api.acme.sc2.dev")
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("expected the --yes refusal, got %v", err)
	}
	if fake.deleted != "" {
		t.Errorf("delete must not reach the client without confirmation")
	}
}

// `sc route` with no subcommand is the discovery surface: it must state the
// install's own base domain and the exact CNAME target, because a Tenant has no
// other way to learn either.
func TestRouteGuideReportsBaseDomainAndCNAMETarget(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakeRouteClient{config: authapp.RouteConfigView{
		Enabled:     true,
		Ingress:     "acme-proxied",
		BaseDomain:  "sc2.dev",
		CNAMETarget: "edge.sc2.dev",
	}}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig:       scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		tenantStore:       infoV2ProjectStore("sc2-acme-web"),
		authRoutes:        fake,
		routeHostResolver: func(context.Context, string) bool { return true },
	}, "route")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "<name>.acme.sc2.dev") {
		t.Errorf("guide should show the tenant's auto-hostname pattern, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "CNAME app.example.com -> edge.sc2.dev") {
		t.Errorf("guide should show the exact CNAME record, got:\n%s", stdout)
	}
	if strings.Contains(stdout, "does not resolve") {
		t.Errorf("resolving wildcard must not warn, got:\n%s", stdout)
	}
}

// A wildcard that does not resolve is the trap this guide exists to catch: the
// publish would succeed and then sit at awaiting-dns forever.
func TestRouteGuideWarnsWhenWildcardMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakeRouteClient{config: authapp.RouteConfigView{Enabled: true, BaseDomain: "sc2.dev"}}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig:       scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		tenantStore:       infoV2ProjectStore("sc2-acme-web"),
		authRoutes:        fake,
		routeHostResolver: func(context.Context, string) bool { return false },
	}, "route")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "*.acme.sc2.dev does not resolve") {
		t.Errorf("guide should warn about the missing wildcard, got:\n%s", stdout)
	}
	// No CNAME target declared → say so rather than inventing one.
	if strings.Contains(stdout, "CNAME app.example.com ->") {
		t.Errorf("guide must not invent a CNAME target, got:\n%s", stdout)
	}
}

func TestRouteGuideOnInstallWithoutRoutes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakeRouteClient{config: authapp.RouteConfigView{Enabled: false}}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: scconfig.Admin{Tenant: "acme", Project: "web", Remote: "sc-acme", AuthToken: "x"},
		tenantStore: infoV2ProjectStore("sc2-acme-web"),
		authRoutes:  fake,
	}, "route")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "not available on this install") {
		t.Errorf("guide should explain routes are off, got:\n%s", stdout)
	}
}
