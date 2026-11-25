package localdns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/cidr"
	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type Request struct {
	Reference string
}

type Plan struct {
	Reference    string `json:"reference"`
	IncusProject string `json:"incusProject"`
	DNSSuffix    string `json:"dnsSuffix"`
	DNSEndpoint  string `json:"dnsEndpoint"`
	StatePath    string `json:"statePath"`
	ResolverPath string `json:"resolverPath"`
	Platform     string `json:"platform"`

	ResolverStrategy string    `json:"resolverStrategy"`
	ResolverCommands []Command `json:"resolverCommands,omitempty"`
}

type Result struct {
	Reference    string `json:"reference"`
	Action       string `json:"action"`
	StatePath    string `json:"statePath"`
	ResolverPath string `json:"resolverPath"`
}

type Manager interface {
	Install(context.Context, Plan) (Result, error)
	Refresh(context.Context, Plan) (Result, error)
	Uninstall(context.Context, Plan) (Result, error)
}

func PlanInstall(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request Request) (Plan, error) {
	return plan(ctx, admin, store, request)
}

func PlanRefresh(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request Request) (Plan, error) {
	return plan(ctx, admin, store, request)
}

func PlanUninstall(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request Request) (Plan, error) {
	return plan(ctx, admin, store, request)
}

// PlanForV2 builds an install/uninstall plan from values the caller already
// holds, rather than reading them from the tenant store. A v2 restricted client
// cannot see its infra project, so `tenant.List` reports an empty PrivateCIDR
// (see internal/tenant/list.go) — but `sc login` receives the CIDR in the device
// response and the Tenant DNS Suffix is visible on the app projects, so the
// login flow can drive the local resolver directly. This is what makes tenant
// machine names resolve on the client without a manual Tailscale Split DNS entry.
func PlanForV2(reference string, dnsSuffix string, privateCIDR string) (Plan, error) {
	ref, err := naming.ParseTenantRef(reference)
	if err != nil {
		return Plan{}, err
	}
	suffix := strings.TrimSuffix(strings.TrimSpace(dnsSuffix), ".")
	if suffix == "" {
		return Plan{}, fmt.Errorf("empty DNS suffix for tenant %q", ref.Tenant)
	}
	endpoint, err := dnsEndpoint(privateCIDR)
	if err != nil {
		return Plan{}, err
	}
	platform := runtime.GOOS
	return Plan{
		Reference:        ref.String(),
		DNSSuffix:        suffix,
		DNSEndpoint:      endpoint,
		StatePath:        statePath(),
		ResolverPath:     ResolverPath(platform, suffix),
		Platform:         platform,
		ResolverStrategy: ResolverStrategy(platform),
		ResolverCommands: ResolverCommands(platform, suffix, endpoint),
	}, nil
}

func plan(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request Request) (Plan, error) {
	if err := admin.Validate(); err != nil {
		return Plan{}, err
	}
	ref, err := tenantRef(request.Reference, admin.Tenant)
	if err != nil {
		return Plan{}, err
	}
	summaries, err := tenant.List(ctx, store)
	if err != nil {
		return Plan{}, err
	}
	for _, summary := range summaries {
		if summary.Tenant == ref.Tenant {
			endpoint, err := dnsEndpoint(summary.PrivateCIDR)
			if err != nil {
				return Plan{}, err
			}
			platform := runtime.GOOS
			return Plan{
				Reference:        ref.String(),
				IncusProject:     summary.IncusName,
				DNSSuffix:        summary.DNSSuffix,
				DNSEndpoint:      endpoint,
				StatePath:        statePath(),
				ResolverPath:     ResolverPath(platform, summary.DNSSuffix),
				Platform:         platform,
				ResolverStrategy: ResolverStrategy(platform),
				ResolverCommands: ResolverCommands(platform, summary.DNSSuffix, endpoint),
			}, nil
		}
	}
	return Plan{}, fmt.Errorf("tenant %q not found", ref.String())
}

func tenantRef(reference string, currentTenant string) (naming.TenantRef, error) {
	value := strings.TrimSpace(reference)
	if value == "" {
		value = strings.TrimSpace(currentTenant)
	}
	if value == "" {
		return naming.TenantRef{}, fmt.Errorf("tenant reference is required")
	}
	return naming.ParseTenantRef(value)
}

func dnsEndpoint(privateCIDR string) (string, error) {
	prefix, err := netipPrefix(privateCIDR)
	if err != nil {
		return "", err
	}
	addr, err := cidr.RoleAddress(prefix, cidr.DNSHostOctet)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(addr.String(), "53"), nil
}

func netipPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return prefix, nil
}

func statePath() string {
	return DefaultStatePath()
}

func DefaultStatePath() string {
	if path := os.Getenv("SANDCASTLE_LOCAL_DNS_STATE"); path != "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".", "sandcastle-dns.yaml")
	}
	return filepath.Join(config.DefaultConfigDir(), "dns.yaml")
}

// legacyStatePath returns ~/.sandcastle/dns.yaml, where local DNS state lived
// before it moved beside config.yml, when path is the default state path. The
// old location collided with the `.sandcastle` directory-selection file, so a
// state dir in $HOME blocked `sc remote switch` there. It returns "" for an
// explicit SANDCASTLE_LOCAL_DNS_STATE or any other path: nothing to migrate.
func legacyStatePath(path string) string {
	if os.Getenv("SANDCASTLE_LOCAL_DNS_STATE") != "" || path != DefaultStatePath() {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".sandcastle", "dns.yaml")
}

func resolverDir() string {
	return DefaultResolverDir()
}

func DefaultResolverDir() string {
	if dir := resolverDirOverride(); dir != "" {
		return dir
	}
	if runtime.GOOS == "darwin" {
		return "/etc/resolver"
	}
	return "/etc/sandcastle/resolver"
}

func resolverDirOverride() string {
	return os.Getenv("SANDCASTLE_RESOLVER_DIR")
}
