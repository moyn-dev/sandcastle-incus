package incusx

import (
	"strings"
	"testing"
)

func TestAuthAppDevices_RouteIngressBindsHostPorts(t *testing.T) {
	// Cloudflare login (no host ports for the auth hostname) BUT route ingress on
	// → the appliance must still bind host :80/:443 for route certs.
	devices := authAppDevices(BootstrapAuthAppRequest{
		Bridge:       "sc2-net",
		StoragePool:  "local",
		IngressMode:  IngressCloudflare,
		RouteIngress: IngressACME,
	})
	for _, name := range []string{"http", "https"} {
		if _, ok := devices[name]; !ok {
			t.Fatalf("route ingress should bind host device %q, devices=%v", name, devices)
		}
	}
}

func TestAuthAppDevices_ProxiedRouteIngressLeavesHostPorts(t *testing.T) {
	// acme-proxied: an upstream SNI proxy owns the host :80/:443 and forwards to
	// the appliance, so the appliance must not try to claim them (it would fail to
	// bind against the proxy that is already there).
	devices := authAppDevices(BootstrapAuthAppRequest{
		Bridge:       "sc2-net",
		StoragePool:  "local",
		IngressMode:  IngressCloudflare,
		RouteIngress: IngressACMEProxied,
	})
	for _, name := range []string{"http", "https"} {
		if _, ok := devices[name]; ok {
			t.Fatalf("acme-proxied route ingress must not bind host device %q, devices=%v", name, devices)
		}
	}
}

func TestAuthAppDevices_NoIngressNoHostPorts(t *testing.T) {
	devices := authAppDevices(BootstrapAuthAppRequest{
		Bridge:      "sc2-net",
		StoragePool: "local",
		IngressMode: IngressCloudflare,
	})
	if _, ok := devices["https"]; ok {
		t.Fatalf("cloudflare-only (no route ingress) must not bind host :443, devices=%v", devices)
	}
}

// --acme-directory (ADR-0027) is stored on the appliance like --acme-email
// and handed to `auth-app serve` by the unit.
func TestAuthAppEnvAndUnitCarryACMEDirectory(t *testing.T) {
	out := authAppEnv(BootstrapAuthAppRequest{ACMEDirectory: " https://acme-staging-v02.api.letsencrypt.org/directory "})
	if !strings.Contains(out, "SANDCASTLE_AUTH_ACME_DIRECTORY='https://acme-staging-v02.api.letsencrypt.org/directory'") {
		t.Fatalf("auth-app env missing the ACME directory:\n%s", out)
	}
	if !strings.Contains(authAppEnv(BootstrapAuthAppRequest{}), "SANDCASTLE_AUTH_ACME_DIRECTORY=''") {
		t.Fatal("auth-app env must always define SANDCASTLE_AUTH_ACME_DIRECTORY (empty = production)")
	}
	if !strings.Contains(authAppUnit(), " --acme-directory ${SANDCASTLE_AUTH_ACME_DIRECTORY}") {
		t.Fatalf("auth-app unit does not pass --acme-directory:\n%s", authAppUnit())
	}
}

func TestAuthAppEnvConfiguresCloudflareDNS01WithoutEmbeddingItsToken(t *testing.T) {
	req := BootstrapAuthAppRequest{
		RouteDNSProvider:           RouteDNSProviderCloudflare,
		RouteDNSWildcards:          []string{"*.JOT.moyn.dev."},
		RouteDNSCloudflareAPIToken: "route-dns-secret",
	}
	out := authAppEnv(req)
	if !strings.Contains(out, "SANDCASTLE_ROUTE_DNS_PROVIDER='cloudflare'") {
		t.Fatalf("auth-app env missing route DNS provider:\n%s", out)
	}
	if strings.Contains(out, "route-dns-secret") {
		t.Fatalf("auth-app env must not contain the route DNS token")
	}
	if !strings.Contains(out, "SANDCASTLE_ROUTE_DNS_WILDCARDS='*.jot.moyn.dev'") {
		t.Fatalf("auth-app env missing normalized route DNS wildcard:\n%s", out)
	}
	secretEnv := authAppRouteDNSEnv(req)
	if secretEnv != "SANDCASTLE_ROUTE_DNS_CLOUDFLARE_API_TOKEN='route-dns-secret'\n" {
		t.Fatalf("route DNS env = %q", secretEnv)
	}
}

func TestValidateRouteDNSConfig(t *testing.T) {
	tests := []struct {
		name    string
		req     BootstrapAuthAppRequest
		wantErr bool
	}{
		{name: "disabled"},
		{name: "configured", req: BootstrapAuthAppRequest{RouteIngress: IngressACMEProxied, RouteDNSProvider: RouteDNSProviderCloudflare, RouteDNSWildcards: []string{"*.jot.moyn.dev"}, RouteDNSCloudflareAPIToken: "secret"}},
		{name: "missing route ingress", req: BootstrapAuthAppRequest{RouteDNSProvider: RouteDNSProviderCloudflare, RouteDNSWildcards: []string{"*.jot.moyn.dev"}, RouteDNSCloudflareAPIToken: "secret"}, wantErr: true},
		{name: "missing token", req: BootstrapAuthAppRequest{RouteIngress: IngressACMEProxied, RouteDNSProvider: RouteDNSProviderCloudflare, RouteDNSWildcards: []string{"*.jot.moyn.dev"}}, wantErr: true},
		{name: "missing wildcard", req: BootstrapAuthAppRequest{RouteIngress: IngressACMEProxied, RouteDNSProvider: RouteDNSProviderCloudflare, RouteDNSCloudflareAPIToken: "secret"}, wantErr: true},
		{name: "invalid wildcard", req: BootstrapAuthAppRequest{RouteIngress: IngressACMEProxied, RouteDNSProvider: RouteDNSProviderCloudflare, RouteDNSWildcards: []string{"foo.*.moyn.dev"}, RouteDNSCloudflareAPIToken: "secret"}, wantErr: true},
		{name: "unknown provider", req: BootstrapAuthAppRequest{RouteIngress: IngressACMEProxied, RouteDNSProvider: "other", RouteDNSWildcards: []string{"*.jot.moyn.dev"}, RouteDNSCloudflareAPIToken: "secret"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteDNSConfig(tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
