package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

// newConnectV2Command implements `sc connect-v2 <tenant>` (ADR-0016): it
// (re)generates the tenant's local Incus config from scratch in an isolated
// config dir — enrolling the tenant's own cert from an enrollment token (first
// time) and adding one cert-pinned remote per project the cert can see. Re-runs
// are idempotent: pass no token to just refresh the per-project remotes after
// new projects were created.
func newConnectV2Command(config commandConfig, opts *rootOptions) *cobra.Command {
	var token, endpoint, configDir, remoteName string
	command := &cobra.Command{
		Use:   "enroll tenant",
		Short: "Enroll a tenant locally from a token (regenerates local incus config + per-project remotes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant := strings.TrimSpace(args[0])
			if err := naming.ValidateTenantName(tenant); err != nil {
				return err
			}
			name := strings.TrimSpace(remoteName)
			if name == "" {
				name = usertrust.RemoteInstallName("", tenant)
			}
			dir := strings.TrimSpace(configDir)
			if dir == "" {
				scconfig.AdoptNativeIncusDirIfChosen()
				var reason string
				dir, reason = scconfig.SharedIncusDirExplained()
				fmt.Fprintf(config.stdout, "Incus config: %s\n", reason)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("create config dir: %w", err)
			}
			if _, err := exec.LookPath("incus"); err != nil {
				return fmt.Errorf("incus CLI not found on PATH")
			}

			// 1. Enroll the base remote from the token (only if not already enrolled).
			if !remoteExists(dir, name) {
				if strings.TrimSpace(token) == "" {
					return fmt.Errorf("tenant %q is not enrolled here; pass --token from `sc-adm tenant create`", tenant)
				}
				err := runIncus(cmd.Context(), dir, "remote", "add", name, strings.TrimSpace(token))
				if err != nil && strings.Contains(err.Error(), "already trusted") {
					// Shared client identity: this daemon already trusts our keypair
					// (another install on the same host enrolled it), so it refuses to
					// redeem a second token. The token carries the daemon's addresses,
					// so add the remote certificate-based instead. Without this, a
					// second install could never be enrolled with `sc enroll`.
					err = enrollTrustedClientRemote(cmd.Context(), dir, name, strings.TrimSpace(token), config.stderr)
				}
				if err != nil {
					return fmt.Errorf("enroll tenant remote: %w", err)
				}
			}

			// 2. Pin the single install remote to a project (ADR-0021: one remote
			// per install; the project is an orthogonal pin that `sc project switch`
			// moves — no per-project remotes). Prefer the default project, else the
			// first project the cert can see.
			projects, err := listRemoteProjects(cmd.Context(), dir, name)
			if err != nil {
				return fmt.Errorf("list projects: %w", err)
			}
			pin := ""
			for _, incusProject := range projects {
				if shortProjectName(incusProject, tenant) == naming.DefaultProjectName {
					pin = incusProject
					break
				}
			}
			if pin == "" {
				for _, incusProject := range projects {
					if shortProjectName(incusProject, tenant) != "" {
						pin = incusProject
						break
					}
				}
			}
			if pin == "" {
				return fmt.Errorf("enrolled the tenant remote but its certificate can see no project to pin it to")
			}
			if err := setRemoteProject(filepath.Join(dir, "config.yml"), name, pin); err != nil {
				return fmt.Errorf("pin remote %q to %q: %w", name, pin, err)
			}
			fmt.Fprintf(config.stdout, "  %s → %s\n", name, pin)
			// Persist the tenant + remote as the local defaults so every other
			// sc command (list, create, connect, incus, …) resolves this tenant
			// without SANDCASTLE_TENANT — the login path does the same.
			if _, _, err := saveRemoteDefaults(scconfig.DefaultConfigPath(), name, tenant); err != nil {
				fmt.Fprintf(config.stderr, "Note: could not save local defaults: %v\n", err)
			}
			syncNativeIncusMirror(config.stderr)
			fmt.Fprintf(config.stdout, "connected tenant %q — config at %s (remote %q → %s)\n", tenant, dir, name, pin)
			fmt.Fprintf(config.stdout, "use it with:  `sc project switch <name>` moves it; raw:  INCUS_CONF=%s incus list %s:\n", dir, name)
			return nil
		},
	}
	command.Flags().StringVar(&token, "token", "", "enrollment token from `sc-adm tenant create` (first enroll only)")
	// No default: the endpoint is read off the base remote the token just created.
	// It used to default to a hardcoded developer host, so on any other install
	// every project remote was added against the wrong Incus daemon (or failed
	// with `EOF`) while enroll still reported success.
	command.Flags().StringVar(&endpoint, "incus-endpoint", "", "Incus HTTPS endpoint for per-project remotes (default: the address the enrollment token resolved to)")
	command.Flags().StringVar(&configDir, "config-dir", "", "incus config dir to enroll into (default: the shared ~/.config/sandcastle/incus)")
	command.Flags().StringVar(&remoteName, "remote-name", "", "remote name (default sc-<tenant>; prefix installs use sc-<prefix>-<tenant> — copy it from `sc-adm tenant create`)")
	return command
}

// incusTokenAddresses decodes the addresses an Incus certificate add token
// advertises. The token is base64-encoded JSON; a token we cannot parse simply
// yields no addresses rather than an error, since every caller has a fallback.
func incusTokenAddresses(token string) []string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return nil
	}
	var decoded struct {
		Addresses []string `json:"addresses"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	return decoded.Addresses
}

// enrollTrustedClientRemote adds the tenant remote certificate-based, for the
// case where the daemon already trusts this client's keypair and therefore
// refuses to redeem the token. It tries each address the token advertises,
// because only some of them are reachable from any given client.
func enrollTrustedClientRemote(ctx context.Context, dir string, name string, token string, stderr io.Writer) error {
	addresses := incusTokenAddresses(token)
	if len(addresses) == 0 {
		return fmt.Errorf("client is already trusted, and the token advertises no address to connect to")
	}
	var lastErr error
	for _, address := range addresses {
		url := "https://" + address
		if err := runIncus(ctx, dir, trustedClientRemoteAddArgs(name, url, "")...); err != nil {
			lastErr = err
			continue
		}
		fmt.Fprintf(stderr, "Note: this client is already trusted; added remote %q at %s using the existing certificate.\n", name, url)
		return nil
	}
	return fmt.Errorf("client is already trusted, but no advertised address accepted the certificate (last error: %v)", lastErr)
}

func runIncus(ctx context.Context, incusConf string, args ...string) error {
	cmd := exec.CommandContext(ctx, "incus", args...)
	cmd.Env = append(os.Environ(), "INCUS_CONF="+incusConf)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

// listRemoteProjects returns the Incus project names the tenant's cert can see.
func listRemoteProjects(ctx context.Context, incusConf string, remote string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "incus", "project", "list", remote+":", "--format", "csv", "-c", "n")
	cmd.Env = append(os.Environ(), "INCUS_CONF="+incusConf)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var projects []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name := strings.TrimSpace(strings.TrimSuffix(line, " (current)"))
		if name != "" {
			projects = append(projects, name)
		}
	}
	return projects, nil
}

// shortProjectName turns <prefix>-<tenant>-<project> into <project>.
//
// The install prefix is whatever `sc-adm install --prefix` chose, so it cannot be
// hardcoded: matching only the default `sc2-` meant that enrolling against an
// install created with e.g. `--prefix id` filtered out every project, added no
// project remotes, and still exited 0 ("0 project remote(s)"). Anchor on the
// tenant segment instead, which is the one part we know.
//
// The tenant's infra project (`<prefix>-<tenant>`, no trailing project segment)
// deliberately yields "" — it gets no project remote.
func shortProjectName(incusProject string, tenant string) string {
	marker := "-" + tenant + "-"
	index := strings.Index(incusProject, marker)
	if index < 0 {
		return ""
	}
	return incusProject[index+len(marker):]
}
