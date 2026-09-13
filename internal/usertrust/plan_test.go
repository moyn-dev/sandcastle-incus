package usertrust

import (
	"slices"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/config"
)

func TestPlanCreateUser(t *testing.T) {
	plan, err := PlanCreateUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if plan.CertificateName != "sandcastle-alice" {
		t.Fatalf("CertificateName = %q", plan.CertificateName)
	}
	if plan.RemoteName != "sandcastle-alice" {
		t.Fatalf("RemoteName = %q", plan.RemoteName)
	}
	if !plan.Restricted {
		t.Fatal("Restricted = false, want true")
	}
	if len(plan.Projects) != 0 {
		t.Fatalf("Projects = %#v, want empty", plan.Projects)
	}
}

func TestPlanDeleteUser(t *testing.T) {
	plan, err := PlanDeleteUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if plan.CertificateName != "sandcastle-alice" || !plan.Restricted {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanGrant(t *testing.T) {
	plan, err := PlanGrant(config.LoadAdminFromEnv(), GrantRequest{
		User:     "alice",
		Projects: []string{"acme"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Projects, []string{"sc-acme", "sc-acme-default"}) {
		t.Fatalf("Projects = %#v", plan.Projects)
	}
}

func TestPlanGrantPersonalTenantAllowsGitHubUsernameNames(t *testing.T) {
	plan, err := PlanGrant(config.LoadAdminFromEnv(), GrantRequest{
		User:     "1octocat",
		Projects: []string{"1octocat"},
		Personal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.CertificateName != "sandcastle-1octocat" || !slices.Equal(plan.Projects, []string{"sc-1octocat", "sc-1octocat-default"}) {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanGrantDeduplicatesProjects(t *testing.T) {
	plan, err := PlanGrant(config.LoadAdminFromEnv(), GrantRequest{
		User:     "alice",
		Projects: []string{"acme", "acme"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Projects, []string{"sc-acme", "sc-acme-default"}) {
		t.Fatalf("Projects = %#v", plan.Projects)
	}
}

func TestPlanGrantRequiresProject(t *testing.T) {
	_, err := PlanGrant(config.LoadAdminFromEnv(), GrantRequest{User: "alice"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPlanGrantRejectsInvalidTenant(t *testing.T) {
	_, err := PlanGrant(config.LoadAdminFromEnv(), GrantRequest{
		User:     "alice",
		Projects: []string{"bob/project"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPlanTenantGrant(t *testing.T) {
	plan, err := PlanTenantGrant(config.LoadAdminFromEnv(), TenantAccessRequest{Tenant: "acme", User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.User != "alice" || !slices.Equal(plan.Projects, []string{"sc-acme", "sc-acme-default"}) {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestPlanTenantUsers(t *testing.T) {
	plan, err := PlanTenantUsers(config.LoadAdminFromEnv(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Tenant != "acme" || plan.IncusProject != "sc-acme" {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestRestrictedInstallName(t *testing.T) {
	if got := RestrictedInstallName("", "acme"); got != "sandcastle-acme" {
		t.Fatalf("got %q", got)
	}
	if got := RestrictedInstallName("sc", "acme"); got != "sandcastle-acme" {
		t.Fatalf("got %q", got)
	}
	if got := RestrictedInstallName("sc2", "acme"); got != "sandcastle-acme" {
		t.Fatalf("got %q", got)
	}
	// non-default installs qualify the name so two sandcastles on one host
	// (and one client) cannot collide on certificates or remotes
	if got := RestrictedInstallName("id", "acme"); got != "sandcastle-id-acme" {
		t.Fatalf("got %q", got)
	}
}

func TestRemoteInstallName(t *testing.T) {
	if got := RemoteInstallName("", "acme"); got != "sc-acme" {
		t.Fatalf("got %q", got)
	}
	if got := RemoteInstallName("sc", "acme"); got != "sc-acme" {
		t.Fatalf("got %q", got)
	}
	if got := RemoteInstallName("sc2", "acme"); got != "sc-acme" {
		t.Fatalf("got %q", got)
	}
	if got := RemoteInstallName("id", "acme"); got != "sc-id-acme" {
		t.Fatalf("got %q", got)
	}
}

func TestInstallLabelFromAuthHostname(t *testing.T) {
	cases := map[string]string{
		"https://obelix.thieso2.dev":  "obelix-thieso2-dev",
		"https://idefix.thieso2.dev/": "idefix-thieso2-dev",
		"http://big.example.com:8443": "big-example-com",
		"obelix.thieso2.dev":          "obelix-thieso2-dev",
		"https://Obelix.Thieso2.DEV":  "obelix-thieso2-dev",
		"https://my-host.example.dev": "my-host-example-dev",
		"":                            "",
		"https://":                    "",
	}
	for in, want := range cases {
		if got := InstallLabelFromAuthHostname(in); got != want {
			t.Errorf("InstallLabelFromAuthHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRemoteNameForAuthHostname(t *testing.T) {
	if got := RemoteNameForAuthHostname("https://obelix.thieso2.dev"); got != "sc-obelix-thieso2-dev" {
		t.Errorf("RemoteNameForAuthHostname = %q, want sc-obelix-thieso2-dev", got)
	}
	if got := RemoteNameForAuthHostname(""); got != "" {
		t.Errorf("RemoteNameForAuthHostname(\"\") = %q, want empty", got)
	}
}

func TestRemoteNameForSuffixProject(t *testing.T) {
	cases := []struct {
		suffix, project, want string
	}{
		{"obelix", "web", "obelix-web"},
		{"obelix", "default", "obelix-default"}, // no omission (ADR-0020)
		{"obelix-eu", "db", "obelix-eu-db"},     // dashes in the suffix survive
		{"  Castle ", "SC", "castle-sc"},        // normalized
		{"", "web", ""},                         // blank suffix -> caller falls back
		{"obelix", "", ""},                      // blank project -> caller falls back
	}
	for _, c := range cases {
		if got := RemoteNameForSuffixProject(c.suffix, c.project); got != c.want {
			t.Errorf("RemoteNameForSuffixProject(%q,%q) = %q, want %q", c.suffix, c.project, got, c.want)
		}
	}
}

func TestRemoteNameForSuffix(t *testing.T) {
	cases := []struct{ suffix, want string }{
		{"jules", "jules"},         // ADR-0021: the install's suffix alone
		{"obelix-eu", "obelix-eu"}, // dashes survive
		{"  Castle ", "castle"},    // normalized
		{"", ""},                   // blank -> caller falls back
	}
	for _, c := range cases {
		if got := RemoteNameForSuffix(c.suffix); got != c.want {
			t.Errorf("RemoteNameForSuffix(%q) = %q, want %q", c.suffix, got, c.want)
		}
	}
}
