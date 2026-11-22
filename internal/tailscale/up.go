package tailscale

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

const (
	DefaultAdvertiseTag = "tag:sandcastle"
	DefaultUpTimeout    = "60s"
)

type UpRequest struct {
	Reference     string
	AuthKey       string
	AdvertiseTags []string
}

type UpPlan struct {
	Reference       string         `json:"reference"`
	Tenant          tenant.Summary `json:"tenant"`
	InstanceName    string         `json:"instanceName"`
	AdvertiseRoutes []string       `json:"advertiseRoutes"`
	AdvertiseTags   []string       `json:"advertiseTags,omitempty"`
	HasAuthKey      bool           `json:"hasAuthKey"`
	AuthKey         string         `json:"-"`
	Command         []string       `json:"command"`
}

type RunSession struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type Runner interface {
	RunUp(context.Context, UpPlan, RunSession) error
	RunStatus(context.Context, StatusPlan, RunSession) (StatusResult, error)
	RunDown(context.Context, DownPlan, RunSession) error
}

func PlanUp(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request UpRequest) (UpPlan, error) {
	if err := admin.Validate(); err != nil {
		return UpPlan{}, err
	}
	ref, err := tenantRef(request.Reference, admin.Tenant)
	if err != nil {
		return UpPlan{}, err
	}
	summary, err := findTenant(ctx, store, ref)
	if err != nil {
		return UpPlan{}, err
	}
	tags, err := NormalizeAdvertiseTags(request.AdvertiseTags)
	if err != nil {
		return UpPlan{}, err
	}
	plan := UpPlan{
		Reference:       ref.String(),
		Tenant:          summary,
		InstanceName:    tenant.TailscaleInstanceName(summary.IncusName),
		AdvertiseRoutes: []string{summary.PrivateCIDR},
		AdvertiseTags:   tags,
		HasAuthKey:      strings.TrimSpace(request.AuthKey) != "",
		AuthKey:         strings.TrimSpace(request.AuthKey),
	}
	plan.Command = command(plan, true)
	return plan, nil
}

func ExecCommand(plan UpPlan) []string {
	return command(plan, false)
}

func command(plan UpPlan, redact bool) []string {
	args := []string{"tailscale", "up", "--timeout=" + DefaultUpTimeout, "--advertise-routes=" + strings.Join(plan.AdvertiseRoutes, ",")}
	if len(plan.AdvertiseTags) > 0 {
		args = append(args, "--advertise-tags="+strings.Join(plan.AdvertiseTags, ","))
	}
	if plan.AuthKey != "" {
		authKey := plan.AuthKey
		if redact {
			authKey = "<redacted>"
		}
		args = append(args, "--auth-key="+authKey)
	}
	if redact {
		return args
	}
	return []string{"/bin/sh", "-lc", tailscaledBootstrapScript() + "; exec " + strings.Join(shellQuoteArgs(args), " ")}
}

func tailscaledBootstrapScript() string {
	return strings.Join([]string{
		"install -d /run/tailscale /var/lib/tailscale",
		"systemctl unmask tailscaled.service >/dev/null 2>&1 || true",
		"ethtool -K eth0 rx-udp-gro-forwarding on rx-gro-list off 2>/dev/null || true",
		"if ! pgrep -x tailscaled >/dev/null 2>&1; then tailscaled --state=/var/lib/tailscale/tailscaled.state >/var/log/tailscaled.log 2>&1 & fi",
		"for i in $(seq 1 50); do tailscale status >/dev/null 2>&1 && break; sleep 0.1; done",
	}, "; ")
}

func shellQuoteArgs(args []string) []string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
	}
	return quoted
}

func NormalizeAdvertiseTags(values []string) ([]string, error) {
	seen := map[string]bool{}
	output := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			tag := strings.TrimSpace(part)
			if tag == "" || seen[tag] {
				continue
			}
			if err := validateAdvertiseTag(tag); err != nil {
				return nil, err
			}
			seen[tag] = true
			output = append(output, tag)
		}
	}
	return output, nil
}

func validateAdvertiseTag(tag string) error {
	if !strings.HasPrefix(tag, "tag:") || len(tag) == len("tag:") {
		return fmt.Errorf("Tailscale advertise tag %q must use tag:<name>", tag)
	}
	name := strings.TrimPrefix(tag, "tag:")
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("Tailscale advertise tag %q must contain only lowercase letters, digits, or hyphens after tag:", tag)
		}
	}
	return nil
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

func findTenant(ctx context.Context, store tenant.IncusTenantStore, ref naming.TenantRef) (tenant.Summary, error) {
	tenants, err := tenant.List(ctx, store)
	if err != nil {
		return tenant.Summary{}, err
	}
	for _, summary := range tenants {
		if summary.Tenant == ref.Tenant {
			if summary.PrivateCIDR == "" {
				return tenant.Summary{}, fmt.Errorf("Sandcastle tenant %s has no private CIDR", ref.String())
			}
			return summary, nil
		}
	}
	return tenant.Summary{}, fmt.Errorf("Sandcastle tenant %s not found", ref.String())
}
