package tailscale

import (
	"context"
	"fmt"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type EgressRequest struct {
	Reference string
	Mode      string // "" (show), "on", "off"
}

type EgressPlan struct {
	Reference string         `json:"reference"`
	Tenant    tenant.Summary `json:"tenant"`
	Mode      string         `json:"mode,omitempty"`
}

type EgressResult struct {
	Reference string         `json:"reference"`
	Tenant    tenant.Summary `json:"tenant"`
	Enabled   bool           `json:"enabled"`
	Changed   bool           `json:"changed"`
}

// EgressRunner is implemented by executors that can read and toggle the
// per-tenant tailnet-egress setting (ADR-0026). Separate from Runner so
// existing Runner implementations stay valid.
type EgressRunner interface {
	RunEgress(context.Context, EgressPlan) (EgressResult, error)
}

func PlanEgress(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request EgressRequest) (EgressPlan, error) {
	mode := strings.ToLower(strings.TrimSpace(request.Mode))
	switch mode {
	case "", "on", "off":
	default:
		return EgressPlan{}, fmt.Errorf("tailnet egress mode %q: must be on or off", request.Mode)
	}
	summary, reference, err := tenantSummary(ctx, admin, store, request.Reference)
	if err != nil {
		return EgressPlan{}, err
	}
	return EgressPlan{Reference: reference, Tenant: summary, Mode: mode}, nil
}
