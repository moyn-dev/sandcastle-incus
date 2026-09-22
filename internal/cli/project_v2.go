package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
)

// newProjectCreateV2Command is the tenant-facing `sc project create-v2` client
// for the Sandcastle Broker (ADR-0016). It authenticates to the broker with the
// tenant's restricted Incus client certificate; the broker creates the app
// project + profile and extends the tenant's cert. After it returns, the tenant
// can `incus launch` into sc2-<tenant>-<project> natively.
func newProjectCreateV2Command(config commandConfig, opts *rootOptions) *cobra.Command {
	var broker, certFile, keyFile string
	var writeRemote, dryRun bool
	var incusEndpoint, incusConf, remoteName, domainFlag string
	command := &cobra.Command{
		Use:   "create name",
		Short: "Create a project in the current tenant (self-service via the Auth App or the broker)",
		Long: `Create a project in the current tenant. After sc login the request rides the
Auth App's token-gated API; pass --broker to use the client-certificate broker.

--domain <domain> claims a Project Domain under a registered Public DNS Zone
(ADR-0027): every machine created in the project gets the Machine Public
Hostname <machine>.<domain> with a Let's Encrypt certificate. The domain must
sit at least one label below a registered zone and may not overlap another
claim, a Public Route hostname, or the install's own names. Only the Auth App
path can claim a domain.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			project := strings.TrimSpace(args[0])
			if err := naming.ValidateNewProjectName(project); err != nil {
				return err
			}
			domainValue := strings.TrimSpace(domainFlag)
			if domainValue != "" {
				normalized, err := authapp.NormalizeProjectDomain(domainValue)
				if err != nil {
					return err
				}
				domainValue = normalized
			}
			// Preferred tenant plane: the auth-app API over the public
			// hostname, authenticated by the saved login token — works through
			// a tunnel, needs no broker port and no client certificate. The
			// broker path below remains for --broker/BYO setups.
			if projectAuthAppAvailable(config, broker) {
				return runProjectCreateViaAuthApp(cmd.Context(), config, opts, authapp.ProjectCreateRequest{Project: project, Domain: domainValue, DryRun: dryRun}, writeRemote, incusEndpoint, incusConf, remoteName)
			}
			if domainValue != "" {
				return fmt.Errorf("--domain is not available on this install")
			}
			if dryRun {
				fmt.Fprintf(config.stdout, "[dry-run] would have: created project %s via the broker\n", project)
				return nil
			}
			conn, err := resolveBrokerConnection(config.adminConfig, broker, certFile, keyFile, incusConf)
			if err != nil {
				return err
			}
			broker, certFile, keyFile, incusConf = conn.Broker, conn.CertFile, conn.KeyFile, conn.IncusConf
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return fmt.Errorf("load client certificate: %w", err)
			}
			client := &http.Client{
				Timeout: 60 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						Certificates:       []tls.Certificate{cert},
						InsecureSkipVerify: true, // broker identity is pinned out-of-band; auth is by client cert
						MinVersion:         tls.VersionTLS12,
					},
				},
			}
			body, _ := json.Marshal(map[string]string{"project": project})
			url := strings.TrimRight(broker, "/") + "/v2/projects"
			resp, err := client.Post(url, "application/json", bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("contact broker: %w", err)
			}
			defer resp.Body.Close()
			payload, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("broker rejected request (%d): %s", resp.StatusCode, strings.TrimSpace(string(payload)))
			}
			var result struct {
				Path         string `json:"path"`
				Tenant       string `json:"tenant"`
				Project      string `json:"project"`
				IncusProject string `json:"incusProject"`
			}
			_ = json.Unmarshal(payload, &result)
			if result.Project == "" {
				result.Project = project
			}
			result.Path = scopePath(config.adminConfig.Remote, firstNonEmptyString(result.Tenant, config.adminConfig.Tenant), result.Project)
			text := fmt.Sprintf("Project %s created.", result.Path)
			if result.IncusProject != "" {
				text = fmt.Sprintf("Project %s created (Incus project %s).", result.Path, result.IncusProject)
			}
			if err := writeOutput(config.stdout, opts.output, text, result); err != nil {
				return err
			}

			// By default, drop a ready-to-use per-project incus remote so the tenant
			// can `incus <cmd> <tenant>-<project>:` with no --project flag.
			if writeRemote && result.IncusProject != "" {
				name := strings.TrimSpace(remoteName)
				if name == "" {
					name = result.Tenant + "-" + result.Project
				}
				endpoint, err := incusEndpointFromBroker(incusEndpoint, broker)
				if err != nil {
					fmt.Fprintf(config.stderr, "Note: skipped per-project remote: %v\n", err)
					return nil
				}
				if err := addProjectRemote(cmd.Context(), name, endpoint, result.IncusProject, incusConf); err != nil {
					fmt.Fprintf(config.stderr, "Note: created project but could not add remote %q: %v\n", name, err)
					return nil
				}
				fmt.Fprintf(config.stdout, "added incus remote %q → project %s (try: incus list %s:)\n", name, result.IncusProject, name)
			}
			return nil
		},
	}
	command.Flags().StringVar(&broker, "broker", "", "Sandcastle Broker URL (default: recorded by sc login, or SANDCASTLE_BROKER)")
	command.Flags().StringVar(&certFile, "cert", "", "tenant client certificate file (default: the enrolled remote's client.crt)")
	command.Flags().StringVar(&keyFile, "key", "", "tenant client key file (default: the enrolled remote's client.key)")
	command.Flags().BoolVar(&writeRemote, "write-remote", false, "also add a separate per-project incus remote (ADR-0021: off by default — the install's single remote plus `sc project switch` covers projects; use this only for an extra directly-addressable remote)")
	command.Flags().StringVar(&incusEndpoint, "incus-endpoint", "", "Incus HTTPS endpoint for the remote (default: broker host on :8443)")
	command.Flags().StringVar(&incusConf, "incus-conf", "", "INCUS_CONF dir to write the remote into (default: $INCUS_CONF or the incus default)")
	command.Flags().StringVar(&remoteName, "remote-name", "", "name for the per-project remote (default: <tenant>-<project>)")
	command.Flags().StringVar(&domainFlag, "domain", "", "claim this Project Domain for the project (one label or more below a registered Public DNS Zone; Auth App path only)")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "validate (including the domain claim) without creating anything")
	return command
}

// projectAuthAppAvailable reports whether project verbs can ride the Auth
// App's token-gated tenant plane: no --broker override, a saved login token
// and a resolvable Auth Hostname (or an injected client, in tests).
func projectAuthAppAvailable(config commandConfig, broker string) bool {
	if strings.TrimSpace(broker) != "" {
		return false
	}
	if config.authProjects != nil {
		return true
	}
	return strings.TrimSpace(config.adminConfig.AuthToken) != "" && commandAuthHostname(config, "") != ""
}

// projectAuthClient returns the Auth App project client — the injected one
// (tests) or a DeviceClient at the resolved Auth Hostname. Resolve the Auth
// Hostname the same way the rest of the CLI does: flag → env →
// installs[<current-remote>] (recorded by sc login) → inferred → top-level
// config fallback. This tracks the active install after `incus remote switch`
// instead of trusting the raw top-level config.AuthHostname, which is a stale
// placeholder on installs where login recorded the real hostname only in the
// installs map.
func projectAuthClient(config commandConfig) authProjectClient {
	if config.authProjects != nil {
		return config.authProjects
	}
	return authapp.DeviceClient{BaseURL: commandAuthHostname(config, ""), AuthToken: config.adminConfig.AuthToken, Tenant: strings.TrimSpace(config.adminConfig.Tenant)}
}

// runProjectCreateViaAuthApp creates the project through the auth-app's
// token-gated /api/projects and drops the per-project incus remote, reusing
// the enrolled tenant remote's endpoint (the sidecar Incus Reach).
func runProjectCreateViaAuthApp(ctx context.Context, config commandConfig, opts *rootOptions, request authapp.ProjectCreateRequest, writeRemote bool, incusEndpoint, incusConf, remoteName string) error {
	result, err := projectAuthClient(config).CreateProject(ctx, request)
	if err != nil {
		return err
	}
	if request.DryRun {
		what := "created project " + request.Project
		if result.Domain != "" {
			what += " with project domain " + result.Domain + " (zone " + result.Zone + ") — one project certificate for " + result.Domain + ", *." + result.Domain
		}
		return writeOutput(config.stdout, opts.output, "[dry-run] would have: "+what, result)
	}
	// Text names the project by its Sandcastle Path; JSON carries the Auth
	// App's result plus that path (it used to dump the raw JSON in text mode).
	path := scopePath(config.adminConfig.Remote, result.Tenant, result.Project)
	text := fmt.Sprintf("Project %s created.", path)
	if result.IncusProject != "" {
		text = fmt.Sprintf("Project %s created (Incus project %s).", path, result.IncusProject)
	}
	if result.Domain != "" {
		text += fmt.Sprintf("\nProject domain: %s (zone %s) — machines created in %s get the public name <machine>.%s", result.Domain, result.Zone, result.Project, result.Domain)
	}
	if err := writeOutput(config.stdout, opts.output, text, struct {
		Path string `json:"path"`
		projectbroker.ProjectResult
	}{path, result}); err != nil {
		return err
	}
	if writeRemote && result.IncusProject != "" {
		name := strings.TrimSpace(remoteName)
		if name == "" {
			name = result.Tenant + "-" + result.Project
		}
		endpoint := strings.TrimSpace(incusEndpoint)
		conf := strings.TrimSpace(incusConf)
		enrolled := strings.TrimSpace(config.adminConfig.Remote)
		if endpoint == "" && enrolled != "" {
			endpoint = enrolledRemoteEndpoint(enrolled)
		}
		if conf == "" && enrolled != "" {
			conf = scconfig.ResolveConfigPath(enrolled)
		}
		if endpoint == "" {
			fmt.Fprintln(config.stderr, "Note: skipped per-project remote: no enrolled tenant remote to derive the Incus endpoint from")
			return nil
		}
		if err := addProjectRemote(ctx, name, endpoint, result.IncusProject, conf); err != nil {
			fmt.Fprintf(config.stderr, "Note: created project but could not add remote %q: %v\n", name, err)
			return nil
		}
		fmt.Fprintf(config.stdout, "added incus remote %q → project %s (try: incus list %s:)\n", name, result.IncusProject, name)
	}
	return nil
}

// enrolledRemoteEndpoint reads the enrolled remote's Incus endpoint (the
// sidecar Incus Reach URL) from the per-remote incus config.
func enrolledRemoteEndpoint(remote string) string {
	dir := scconfig.ResolveConfigPath(remote)
	if dir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.yml"))
	if err != nil {
		return ""
	}
	var cfg struct {
		Remotes map[string]struct {
			Addr string `yaml:"addr"`
		} `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.Remotes[remote].Addr)
}

// brokerConnection is the resolved broker dial config for tenant self-service.
type brokerConnection struct {
	Broker    string
	CertFile  string
	KeyFile   string
	IncusConf string
}

// resolveBrokerConnection fills in the broker URL and client-certificate
// paths for `sc project create`: explicit flags win; otherwise the broker URL
// comes from the saved login config (or SANDCASTLE_BROKER) and the cert/key
// from the enrolled remote's per-remote incus dir — so a logged-in tenant
// needs no flags at all.
func resolveBrokerConnection(admin scconfig.Admin, flagBroker, flagCert, flagKey, flagIncusConf string) (brokerConnection, error) {
	conn := brokerConnection{
		Broker:    strings.TrimSpace(flagBroker),
		CertFile:  strings.TrimSpace(flagCert),
		KeyFile:   strings.TrimSpace(flagKey),
		IncusConf: strings.TrimSpace(flagIncusConf),
	}
	if conn.Broker == "" {
		conn.Broker = strings.TrimSpace(admin.Broker)
	}
	if conn.Broker == "" {
		return conn, fmt.Errorf("no broker URL is known — re-run `sc login` (it records the broker URL),\n" +
			"set SANDCASTLE_BROKER, or pass --broker https://host:9443")
	}
	remoteDir := ""
	if remote := strings.TrimSpace(admin.Remote); remote != "" {
		remoteDir = scconfig.ResolveConfigPath(remote)
	}
	if conn.CertFile == "" || conn.KeyFile == "" {
		if remoteDir == "" {
			return conn, fmt.Errorf("no tenant client certificate is known — run `sc login`, or pass --cert/--key")
		}
		certPath := filepath.Join(remoteDir, "client.crt")
		keyPath := filepath.Join(remoteDir, "client.key")
		if _, err := os.Stat(certPath); err != nil {
			return conn, fmt.Errorf("no tenant client certificate at %s — run `sc login`, or pass --cert/--key", certPath)
		}
		if conn.CertFile == "" {
			conn.CertFile = certPath
		}
		if conn.KeyFile == "" {
			conn.KeyFile = keyPath
		}
	}
	// Default the per-project remote into the enrolled remote's incus config,
	// where the login remotes already live — not the global ~/.config/incus.
	if conn.IncusConf == "" && remoteDir != "" {
		if _, err := os.Stat(filepath.Join(remoteDir, "config.yml")); err == nil {
			conn.IncusConf = remoteDir
		}
	}
	return conn, nil
}

// incusEndpointFromBroker returns the explicit endpoint if set, else derives it
// from the broker URL's host on the Incus API port (8443) — the broker and the
// Incus daemon share a host in the v2 MVP.
func incusEndpointFromBroker(explicit string, brokerURL string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), nil
	}
	u, err := neturl.Parse(brokerURL)
	if err != nil {
		return "", fmt.Errorf("parse broker URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("broker URL has no host")
	}
	return "https://" + net.JoinHostPort(host, "8443"), nil
}

// addProjectRemote shells out to `incus remote add` (matching v1's remote
// handling). No token is needed — the tenant's client cert is already trusted;
// --accept-certificate pins the server cert so an IP endpoint validates, and
// --project pins the remote's default project.
func addProjectRemote(ctx context.Context, name string, endpoint string, project string, incusConf string) error {
	if _, err := exec.LookPath("incus"); err != nil {
		return fmt.Errorf("incus CLI not found on PATH")
	}
	args := []string{"remote", "add", name, endpoint, "--auth-type=tls", "--accept-certificate", "--project", project}
	cmd := exec.CommandContext(ctx, "incus", args...)
	cmd.Env = os.Environ()
	if strings.TrimSpace(incusConf) != "" {
		cmd.Env = append(cmd.Env, "INCUS_CONF="+strings.TrimSpace(incusConf))
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(msg, "already exists") {
			return nil // idempotent
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
