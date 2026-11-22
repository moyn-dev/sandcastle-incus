package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
)

type recordingAuthAppRunner struct {
	plan authapp.ServePlan
}

func (r *recordingAuthAppRunner) Serve(_ context.Context, plan authapp.ServePlan) error {
	r.plan = plan
	return nil
}

func TestAuthAppServePassesOIDCLoginFlags(t *testing.T) {
	runner := &recordingAuthAppRunner{}
	_, err := executeAdminForTestWithConfig(t, commandConfig{name: "sc-adm", authApp: runner},
		"auth-app", "serve", "--database", t.TempDir()+"/auth.db", "--auth-hostname", "auth.example.com",
		"--oidc-issuer", "https://ring.example.com", "--oidc-client-id", "sandcastle",
		"--oidc-client-secret", "s3cret", "--oidc-display-name", "Ring",
		"--bootstrap-oidc-admin", "Thies=thies@example.com", "--bootstrap-oidc-admin", "")
	if err != nil {
		t.Fatal(err)
	}
	plan := runner.plan
	if plan.OIDCIssuer != "https://ring.example.com" || plan.OIDCClientID != "sandcastle" || plan.OIDCClientSecret != "s3cret" || plan.OIDCDisplayName != "Ring" {
		t.Fatalf("plan OIDC = %#v", plan)
	}
	if len(plan.BootstrapOIDCAdmins) != 1 || plan.BootstrapOIDCAdmins[0] != (authapp.OIDCAdmin{UserKey: "thies", Email: "thies@example.com"}) {
		t.Fatalf("bootstrap OIDC admins = %#v", plan.BootstrapOIDCAdmins)
	}
}

func TestAuthAppServeWithoutOIDCFlagsLeavesOIDCOff(t *testing.T) {
	runner := &recordingAuthAppRunner{}
	if _, err := executeAdminForTestWithConfig(t, commandConfig{name: "sc-adm", authApp: runner},
		"auth-app", "serve", "--database", t.TempDir()+"/auth.db", "--github-client-id", "id"); err != nil {
		t.Fatal(err)
	}
	if runner.plan.OIDCIssuer != "" || len(runner.plan.BootstrapOIDCAdmins) != 0 {
		t.Fatalf("plan OIDC = %#v", runner.plan)
	}
}

func TestAuthAppDeployRejectsIncompleteOIDCBeforeAnyWork(t *testing.T) {
	for args, want := range map[string]string{
		"--oidc-issuer https://ring.example.com": "--oidc-client-id is required",
		"--oidc-client-id sandcastle":            "need --oidc-issuer",
		"--oidc-issuer https://ring.example.com --oidc-client-id c --bootstrap-oidc-admin bad": "want <user_key>=<email>",
		"--oidc-issuer https://ring.example.com --oidc-client-id c --github-client-id gh":      "go together",
	} {
		_, err := executeAdminForTestWithConfig(t, commandConfig{name: "sc-adm"},
			append([]string{"auth-app", "deploy", "--binary", "/bin/true", "--auth-hostname", "auth.example.com"}, strings.Fields(args)...)...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err = %v, want %q", args, err, want)
		}
	}
}
