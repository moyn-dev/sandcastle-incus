package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
)

// oidcLoginFlags are the opt-in OIDC login settings shared by `auth-app
// serve`, `auth-app deploy` and `install`. They are never prompted for.
type oidcLoginFlags struct {
	issuer          string
	clientID        string
	clientSecret    string
	displayName     string
	bootstrapAdmins []string
}

func (f *oidcLoginFlags) register(command *cobra.Command) {
	flags := command.Flags()
	flags.StringVar(&f.issuer, "oidc-issuer", "", "OPTIONAL OIDC Identity Provider issuer URL for browser login beside GitHub (e.g. https://ring-oidc.jot.moyn.dev)")
	flags.StringVar(&f.clientID, "oidc-client-id", "", "OIDC client id (required with --oidc-issuer)")
	flags.StringVar(&f.clientSecret, "oidc-client-secret", "", "OIDC client secret; empty makes the Auth App a public client (PKCE only)")
	flags.StringVar(&f.displayName, "oidc-display-name", "", "OIDC login button label (default \"SSO\")")
	flags.StringSliceVar(&f.bootstrapAdmins, "bootstrap-oidc-admin", nil, "initial Sandcastle Admin who signs in through OIDC, as <user_key>=<email> (repeat or comma-separate)")
}

func (f *oidcLoginFlags) configured() bool {
	return strings.TrimSpace(f.issuer) != ""
}

func (f *oidcLoginFlags) admins() []string {
	var out []string
	for _, value := range f.bootstrapAdmins {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

// validate catches what the appliance would refuse at startup, before any
// appliance work.
func (f *oidcLoginFlags) validate() error {
	if !f.configured() {
		if strings.TrimSpace(f.clientID) != "" || len(f.admins()) > 0 {
			return fmt.Errorf("--oidc-client-id and --bootstrap-oidc-admin need --oidc-issuer")
		}
		return nil
	}
	if strings.TrimSpace(f.clientID) == "" {
		return fmt.Errorf("--oidc-client-id is required with --oidc-issuer")
	}
	for _, value := range f.admins() {
		if _, err := authapp.ParseOIDCAdmin(value); err != nil {
			return err
		}
	}
	return nil
}

// checkGitHubWithOIDC: with OIDC configured GitHub is optional, but half a
// GitHub OAuth app would serve a login button that always fails.
func checkGitHubWithOIDC(clientID, clientSecret string) error {
	if (strings.TrimSpace(clientID) == "") != (strings.TrimSpace(clientSecret) == "") {
		return fmt.Errorf("github-client-id and github-client-secret go together")
	}
	return nil
}
