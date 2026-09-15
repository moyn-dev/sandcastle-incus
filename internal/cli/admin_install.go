package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// installV2Prefix maps the install prefix to the v2 Incus project prefix, the
// same rule PlanCreateV2 applies: the default "sc" becomes "sc2", anything else
// is used verbatim.
func installV2Prefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || prefix == naming.DefaultIncusProjectPrefix {
		return naming.V2IncusProjectPrefix
	}
	return prefix
}

// applianceBridgeName returns the default, per-install bridge name. Linux
// network-interface names are limited to 15 characters; retain the familiar
// <prefix>-net form when it fits and use a stable, collision-resistant name
// for longer install prefixes.
func applianceBridgeName(prefix string) string {
	const maxInterfaceNameLength = 15
	candidate := prefix + "-net"
	if len(candidate) <= maxInterfaceNameLength {
		return candidate
	}
	digest := sha256.Sum256([]byte(prefix))
	return fmt.Sprintf("sc-%x-net", digest[:4])
}

// newAdminInstallCommand implements `sc-adm install`: the ONE command that puts
// a complete sandcastle on the local Incus host — the Auth App appliance and
// the broker appliance — with a shared tenant CIDR pool. It refuses to run when
// an installation under the same --prefix already exists.
func newAdminInstallCommand(config commandConfig) *cobra.Command {
	var (
		prefix, cidrPool, baseImage, binaryPath, bridge, storagePool           string
		hostname, githubClientID, githubClientSecret, adminUsers               string
		defaultUnixUser, tailscaleAuthKey                                      string
		simulateGitHubToken, tlsMode, brokerPort                               string
		ingressMode, acmeEmail, acmeDirectory, tunnelToken, cloudflareAPIToken string
		routeIngress, routeBaseDomain, routeCNAMETarget, routeFront, routeTLS  string
		routeDNSCloudflareAPIToken                                             string
		routeDNSCloudflareWildcards                                            []string
	)
	command := &cobra.Command{
		Use:   "install",
		Short: "Install a complete sandcastle (auth-app + broker) on this Incus host",
		Long: "One command for the whole server-side install: deploys the Auth App appliance " +
			"(GitHub login + tenant provisioning) and the broker appliance, sharing one tenant " +
			"CIDR pool. Front the Auth Hostname via sc-edge afterwards. Refuses to run when an " +
			"installation under the same --prefix already exists on this host.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			creator := config.tenantCreator
			v2Prefix := installV2Prefix(prefix)
			authAppInstance := v2Prefix + "-auth-app"
			brokerName := v2Prefix + "-broker"
			infraProject := v2Prefix + "-infra"

			// Preflight 1: refuse when this prefix is already installed.
			if existing := detectExistingInstall(cmd.Context(), config, v2Prefix, authAppInstance, brokerName); len(existing) > 0 {
				return fmt.Errorf("a sandcastle installation with prefix %q already exists on this host:\n    %s\n"+
					"  Install side-by-side with a different --prefix, or tear the existing one down first.",
					prefix, strings.Join(existing, "\n    "))
			}
			// Preflight 2: warn when the tenant pool overlaps an address this
			// host already has — the allocator only avoids other TENANTS, so an
			// overlapping local bridge fails later with dnsmasq address-in-use
			// (or silently shadows traffic).
			if warn := cidrPoolOverlapsHost(cidrPool); warn != "" {
				fmt.Fprintf(config.stderr, "WARNING: %s\n", warn)
			}

			if strings.TrimSpace(binaryPath) == "" {
				exe, err := os.Executable()
				if err != nil {
					return fmt.Errorf("resolve binary (pass --binary): %w", err)
				}
				binaryPath = exe
			}
			simulate := strings.TrimSpace(simulateGitHubToken) != ""
			in := bufio.NewReader(config.stdin)
			hostname = promptIfBlank(config.stdout, in, hostname, "Auth Hostname (e.g. sc2.thieso2.dev)")
			if !simulate {
				githubClientID = promptIfBlank(config.stdout, in, githubClientID, "GitHub OAuth client id")
				githubClientSecret = promptIfBlank(config.stdout, in, githubClientSecret, "GitHub OAuth client secret")
			}
			adminUsers = promptIfBlank(config.stdout, in, adminUsers, "Admin GitHub users (comma-separated)")
			if strings.TrimSpace(hostname) == "" || strings.TrimSpace(adminUsers) == "" {
				return fmt.Errorf("auth-hostname and admin-github-users are required")
			}
			if !simulate && (strings.TrimSpace(githubClientID) == "" || strings.TrimSpace(githubClientSecret) == "") {
				return fmt.Errorf("github-client-id and github-client-secret are required (or use --simulate-github-token for dev)")
			}

			// Ingress: resolve the tunnel token (cloudflare mode) and preflight
			// the host ports (acme mode) before any appliance work.
			ingressMode = strings.TrimSpace(ingressMode)
			switch ingressMode {
			case "", incusx.IngressNone:
				ingressMode = incusx.IngressNone
			case incusx.IngressACME:
				if busy := hostPortsBusy(80, 443); len(busy) > 0 {
					return fmt.Errorf("acme ingress needs the host ports %v, but they are already in use", busy)
				}
			case incusx.IngressCloudflare:
				if strings.TrimSpace(tunnelToken) == "" && strings.TrimSpace(cloudflareAPIToken) == "" {
					return fmt.Errorf("cloudflare ingress needs --cloudflare-tunnel-token (dashboard-created tunnel) or --cloudflare-api-token (fully automated)")
				}
				if strings.TrimSpace(tunnelToken) == "" {
					fmt.Fprintf(config.stdout, "[0/2] creating Cloudflare tunnel + DNS for %s via the API...\n", hostname)
					token, err := ensureCloudflareTunnel(cmd.Context(), cloudflareAPIToken, hostname)
					if err != nil {
						return fmt.Errorf("cloudflare tunnel setup: %w", err)
					}
					tunnelToken = token
				}
			default:
				return fmt.Errorf("unknown --ingress %q (none, acme, cloudflare)", ingressMode)
			}
			// Public Route ingress (Spec #111 coexistence): native ACME for route
			// hostnames, independent of the Auth Hostname's mode. "acme" needs host
			// :80/:443 — preflight them here too when the acme branch above didn't.
			// "acme-proxied" deliberately skips the preflight: there the host ports
			// are *expected* to be held by the upstream SNI proxy that forwards to
			// the appliance.
			routeIngress = strings.TrimSpace(routeIngress)
			if routeIngress != "" && routeIngress != incusx.IngressACME && routeIngress != incusx.IngressACMEProxied {
				return fmt.Errorf("unknown --route-ingress %q (acme, acme-proxied, or empty to disable)", routeIngress)
			}
			if routeIngress == incusx.IngressACME && ingressMode != incusx.IngressACME {
				if busy := hostPortsBusy(80, 443); len(busy) > 0 {
					return fmt.Errorf("route ingress needs the host ports %v, but they are already in use", busy)
				}
			}
			normalizedACMEDirectory, err := authapp.NormalizeACMEDirectory(acmeDirectory)
			if err != nil {
				return err
			}
			acmeDirectory = normalizedACMEDirectory
			routeDNSProvider, err := routeDNSProviderForCloudflare(routeIngress, routeDNSCloudflareAPIToken, routeDNSCloudflareWildcards)
			if err != nil {
				return err
			}

			// Appliance bridge: by default each install creates and owns its own
			// bridge (<prefix>-net), so nothing but the daemon is shared with v1
			// or with other installs. --bridge overrides to an existing bridge
			// (e.g. incusbr0) for operators who want the appliances on the host
			// bridge.
			applianceBridge := strings.TrimSpace(bridge)
			if applianceBridge == "" {
				applianceBridge = applianceBridgeName(v2Prefix)
				fmt.Fprintf(config.stdout, "[0/2] creating appliance bridge %s (own, NATed)...\n", applianceBridge)
				if err := creator.EnsureApplianceBridge(cmd.Context(), applianceBridge, v2Prefix); err != nil {
					return fmt.Errorf("create appliance bridge %s: %w", applianceBridge, err)
				}
			} else {
				fmt.Fprintf(config.stdout, "  appliance bridge: using existing %s (--bridge)\n", applianceBridge)
			}

			fmt.Fprintf(config.stdout, "[1/2] deploying auth-app appliance %s...\n", authAppInstance)
			if err := creator.BootstrapAuthApp(cmd.Context(), incusx.BootstrapAuthAppRequest{
				Project:                    infraProject,
				Instance:                   authAppInstance,
				BaseImage:                  baseImage,
				BinaryPath:                 binaryPath,
				Bridge:                     applianceBridge,
				StoragePool:                storagePool,
				Hostname:                   hostname,
				GitHubClientID:             githubClientID,
				GitHubClientSecret:         githubClientSecret,
				AdminGitHubUsers:           splitCommaList(adminUsers),
				DefaultUnixUser:            defaultUnixUser,
				TailscaleAuthKey:           tailscaleAuthKey,
				SimulateGitHubToken:        simulateGitHubToken,
				CIDRPool:                   cidrPool,
				ProjectPrefix:              prefix,
				TLSMode:                    tlsMode,
				IngressMode:                ingressMode,
				ACMEEmail:                  acmeEmail,
				ACMEDirectory:              acmeDirectory,
				TunnelToken:                tunnelToken,
				RouteIngress:               routeIngress,
				RouteBaseDomain:            routeBaseDomain,
				RouteCNAMETarget:           routeCNAMETarget,
				RouteFront:                 routeFront,
				RouteTLS:                   routeTLS,
				RouteDNSProvider:           routeDNSProvider,
				RouteDNSWildcards:          routeDNSCloudflareWildcards,
				RouteDNSCloudflareAPIToken: routeDNSCloudflareAPIToken,
			}); err != nil {
				return fmt.Errorf("auth-app deploy: %w", err)
			}
			// The broker appliance is only reachable — and therefore only useful
			// — when it has a host port (acme/none ingress). With a Cloudflare
			// tunnel there is no inbound host port and no tunnel route to it, and
			// the tenant plane rides the auth-app's /api/projects, so the broker
			// would be dead weight. Skip it entirely.
			deployBroker := ingressMode != incusx.IngressCloudflare
			if deployBroker {
				fmt.Fprintf(config.stdout, "[2/2] deploying broker appliance %s...\n", brokerName)
				if err := creator.BootstrapV2(cmd.Context(), incusx.BootstrapV2Request{
					BaseImage:     baseImage,
					BinaryPath:    binaryPath,
					Bridge:        applianceBridge,
					StoragePool:   storagePool,
					Hostname:      hostname,
					CIDRPool:      cidrPool,
					PublicPort:    brokerPort,
					Project:       brokerName,
					Instance:      brokerName,
					ProjectPrefix: installV2Prefix(prefix),
				}); err != nil {
					return fmt.Errorf("broker bootstrap: %w", err)
				}
			} else {
				fmt.Fprintf(config.stdout, "[2/2] skipping broker appliance (Cloudflare ingress: tenant plane is the auth-app /api/projects; no reachable broker)\n")
			}
			fmt.Fprintf(config.stdout, "sandcastle installed (prefix %q):\n", prefix)
			fmt.Fprintf(config.stdout, "  auth-app: %s (project %s), serving :9444 internally\n", authAppInstance, infraProject)
			if deployBroker {
				fmt.Fprintf(config.stdout, "  broker:   %s (project %s), :%s\n", brokerName, brokerName, brokerPort)
			} else {
				fmt.Fprintf(config.stdout, "  broker:   (not deployed — Cloudflare ingress uses the auth-app tenant plane)\n")
			}
			if strings.TrimSpace(bridge) == "" {
				fmt.Fprintf(config.stdout, "  appliance bridge: %s (own, NATed — nothing shared with other installs or v1)\n", applianceBridge)
			} else {
				fmt.Fprintf(config.stdout, "  appliance bridge: %s (existing, via --bridge)\n", applianceBridge)
			}
			fmt.Fprintf(config.stdout, "  tenant CIDR pool: %s (shared; the allocator avoids other tenants' /24s)\n", cidrPool)

			// Inventory of what this install created, so the operator can see —
			// and later tear down — exactly what belongs to this install. Deleting
			// the infra project cascades to the auth-app instance, its profiles,
			// and volumes; the bridge is separate.
			resources := []string{
				fmt.Sprintf("incus project    %s", infraProject),
				fmt.Sprintf("incus instance   %s (project %s)", authAppInstance, infraProject),
			}
			if strings.TrimSpace(bridge) == "" {
				resources = append(resources, fmt.Sprintf("incus network    %s (bridge)", applianceBridge))
			}
			if deployBroker {
				resources = append(resources,
					fmt.Sprintf("incus project    %s", brokerName),
					fmt.Sprintf("incus instance   %s (project %s)", brokerName, brokerName))
			}
			if ingressMode == incusx.IngressCloudflare && strings.TrimSpace(cloudflareAPIToken) != "" {
				resources = append(resources, fmt.Sprintf("cloudflare       tunnel + ingress rule + proxied DNS for %s", hostname))
			}
			fmt.Fprintf(config.stdout, "resources created by this install (prefix %q):\n", prefix)
			for _, r := range resources {
				fmt.Fprintf(config.stdout, "  - %s\n", r)
			}
			fmt.Fprintf(config.stdout, "  (to remove this install: delete the project(s) above + the bridge; nothing else is touched)\n")
			switch ingressMode {
			case incusx.IngressACME:
				fmt.Fprintf(config.stdout, "  ingress: Let's Encrypt on host :80/:443 for https://%s\n", hostname)
				fmt.Fprintf(config.stdout, "  (DNS: make sure an A record points %s at this host's public IP)\n", hostname)
				fmt.Fprintln(config.stdout, "Users run: sc login https://"+hostname)
			case incusx.IngressCloudflare:
				fmt.Fprintf(config.stdout, "  ingress: Cloudflare tunnel for https://%s (no inbound ports)\n", hostname)
				fmt.Fprintln(config.stdout, "Users run: sc login https://"+hostname)
			default:
				fmt.Fprintf(config.stdout, "Next: front https://%s via sc-edge (reverse_proxy to the auth-app IP :9444),\n", hostname)
				fmt.Fprintln(config.stdout, "then users run: sc login https://"+hostname)
			}
			return nil
		},
	}
	command.Flags().StringVar(&prefix, "prefix", naming.DefaultIncusProjectPrefix, "installation prefix: scopes tenant project names and appliance names; lets several sandcastles share one Incus host")
	command.Flags().StringVar(&cidrPool, "cidr-pool", "10.248.0.0/16", "tenant CIDR pool shared by auth-app and broker (optional; keep pools distinct across installations that share a tailnet)")
	command.Flags().StringVar(&hostname, "auth-hostname", "", "public Auth Hostname; prompted if empty")
	command.Flags().StringVar(&githubClientID, "github-client-id", "", "GitHub OAuth client id; prompted if empty")
	command.Flags().StringVar(&githubClientSecret, "github-client-secret", "", "GitHub OAuth client secret; prompted if empty")
	command.Flags().StringVar(&adminUsers, "admin-github-users", "", "comma-separated admin GitHub usernames; prompted if empty")
	command.Flags().StringVar(&simulateGitHubToken, "simulate-github-token", "", "DEV ONLY: simulated-GitHub mode gated by this shared secret (no real OAuth app)")
	command.Flags().StringVar(&defaultUnixUser, "default-unix-user", "", "default Unix login for provisioned machines")
	command.Flags().StringVar(&tailscaleAuthKey, "tailscale-auth-key", "", "OPTIONAL default Tailscale auth key for tenants that don't bring their own (tenants normally supply theirs at sc login)")
	command.Flags().StringVar(&baseImage, "base-image", incusx.DefaultApplianceImage, "system-container base image for the appliances")
	command.Flags().StringVar(&binaryPath, "binary", "", "path to the fat binary to push (default: this binary)")
	command.Flags().StringVar(&bridge, "bridge", "", "existing bridge for the appliance NICs; empty (default) creates a per-install bridge <prefix>-net so nothing is shared with other installs or v1")
	command.Flags().StringVar(&storagePool, "storage-pool", "default", "storage pool for the appliance root disks")
	command.Flags().StringVar(&tlsMode, "infra-tls-mode", "acme", "infrastructure TLS mode")
	command.Flags().StringVar(&brokerPort, "broker-port", "9443", "host port the broker listens on")
	command.Flags().StringVar(&ingressMode, "ingress", "none", "public ingress for the Auth Hostname: none (BYO edge), acme (host :80/:443 + Let's Encrypt), or cloudflare (outbound tunnel, no inbound ports)")
	command.Flags().StringVar(&acmeEmail, "acme-email", "", "Let's Encrypt contact email (acme or route ingress; also the ACME account contact for Machine Certificates)")
	command.Flags().StringVar(&acmeDirectory, "acme-directory", "", "ACME directory URL for Machine Certificates (Public DNS Zones); default Let's Encrypt production, "+authapp.LetsEncryptStagingDirectory+" for staging")
	command.Flags().StringVar(&routeIngress, "route-ingress", "", "public ingress for `sc route`: acme (host :80/:443 + Let's Encrypt) or acme-proxied (same, but an upstream SNI proxy owns the host ports and forwards to the appliance), independent of --ingress so routes can run beside a cloudflare login host; empty disables")
	command.Flags().StringVar(&routeBaseDomain, "route-base-domain", "", "domain published routes live under (<label>.<tenant>.<base>); defaults to the Auth Hostname")
	command.Flags().StringVar(&routeCNAMETarget, "route-cname-target", "", "public front door a tenant CNAMEs a custom route hostname onto (e.g. the SNI proxy's hostname); reported by `sc route`. Defaults to the Auth Hostname only when it is itself ACME-served here")
	command.Flags().StringVar(&routeFront, "route-front", "", "shared front instance to publish the route SNI list to, as <project>/<instance> (e.g. infrastructure/sc-edge); the auth-app writes a caddy-l4 fragment there and reloads it on every route change. Empty = this appliance owns the host ports")
	command.Flags().StringVar(&routeTLS, "route-tls", "", "TEST ONLY: 'internal' makes route sites use Caddy's self-signed CA instead of on-demand Let's Encrypt (hermetic e2e, no public DNS/ACME)")
	_ = command.Flags().MarkHidden("route-tls")
	command.Flags().StringVar(&routeDNSCloudflareAPIToken, "route-dns-cloudflare-api-token", "", "Cloudflare API token with zone DNS edit access; wildcard public routes use one DNS-01 certificate instead of issuing a certificate per subdomain")
	command.Flags().StringSliceVar(&routeDNSCloudflareWildcards, "route-dns-cloudflare-wildcard", nil, "exact leading-wildcard Public Route hostname authorized for Cloudflare DNS-01 (repeat for multiple hostnames)")
	command.Flags().StringVar(&tunnelToken, "cloudflare-tunnel-token", "", "connector token of a dashboard-created Cloudflare tunnel routing the hostname to http://localhost:8080 (cloudflare ingress)")
	command.Flags().StringVar(&cloudflareAPIToken, "cloudflare-api-token", "", "Cloudflare API token (Tunnel:Edit + DNS:Edit + Zone:Read): install creates the tunnel, ingress rule, and proxied DNS record itself (cloudflare ingress)")
	return command
}

func routeDNSProviderForCloudflare(routeIngress, token string, wildcards []string) (string, error) {
	hasToken := strings.TrimSpace(token) != ""
	hasWildcards := len(wildcards) > 0
	if !hasToken && !hasWildcards {
		return "", nil
	}
	if strings.TrimSpace(routeIngress) == "" {
		return "", fmt.Errorf("Cloudflare route DNS-01 requires --route-ingress")
	}
	if !hasToken {
		return "", fmt.Errorf("--route-dns-cloudflare-wildcard requires --route-dns-cloudflare-api-token")
	}
	if !hasWildcards {
		return "", fmt.Errorf("--route-dns-cloudflare-api-token requires at least one --route-dns-cloudflare-wildcard")
	}
	return incusx.RouteDNSProviderCloudflare, nil
}

// detectExistingInstall lists the components of an installation under the given
// prefix that already exist on this host: the appliances and any tenant
// projects using the prefix.
func detectExistingInstall(ctx context.Context, config commandConfig, v2Prefix string, authAppInstance string, brokerName string) []string {
	found := []string{}
	if config.tenantStore != nil {
		if projects, err := config.tenantStore.ListProjects(ctx); err == nil {
			for _, project := range projects {
				if project.Name == brokerName {
					found = append(found, "broker project "+project.Name)
					continue
				}
				if strings.HasPrefix(project.Name, v2Prefix+"-") {
					found = append(found, "tenant project "+project.Name)
				}
			}
		}
	}
	if instance := detectInstance(config, v2Prefix+"-infra", authAppInstance); instance != "" {
		found = append(found, instance)
	}
	return found
}

// detectInstance reports "auth-app instance <name>" when the instance exists in
// the project, using the tenant creator's server access.
func detectInstance(config commandConfig, project string, instance string) string {
	if config.tenantCreator.InstanceExists(project, instance) {
		return "auth-app instance " + instance + " (project " + project + ")"
	}
	return ""
}

// hostPortsBusy reports which of the given TCP ports are already bound on the
// host (acme ingress needs :80/:443 for caddy).
func hostPortsBusy(ports ...int) []int {
	busy := []int{}
	for _, port := range ports {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			busy = append(busy, port)
			continue
		}
		_ = listener.Close()
	}
	return busy
}

// cidrPoolOverlapsHost warns when a host interface address falls inside the
// tenant pool.
func cidrPoolOverlapsHost(pool string) string {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(pool))
	if err != nil {
		return ""
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipNet.IP.To4())
		if !ok {
			continue
		}
		if prefix.Contains(ip) {
			return fmt.Sprintf("tenant CIDR pool %s overlaps this host's own address %s — tenant /24s from this pool can collide with existing networks; consider a different --cidr-pool", pool, ip)
		}
	}
	return ""
}
