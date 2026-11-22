package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

type StatusRequest struct {
	Reference string
}

type StatusPlan struct {
	Reference    string         `json:"reference"`
	Tenant       tenant.Summary `json:"tenant"`
	InstanceName string         `json:"instanceName"`
	Command      []string       `json:"command"`
}

type StatusResult struct {
	Reference string         `json:"reference"`
	Tenant    tenant.Summary `json:"tenant"`
	Tailscale meta.Tailscale `json:"tailscale"`
}

type DownRequest struct {
	Reference string
}

type DownPlan struct {
	Reference    string         `json:"reference"`
	Tenant       tenant.Summary `json:"tenant"`
	InstanceName string         `json:"instanceName"`
	Command      []string       `json:"command"`
}

func PlanStatus(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request StatusRequest) (StatusPlan, error) {
	summary, reference, err := tenantSummary(ctx, admin, store, request.Reference)
	if err != nil {
		return StatusPlan{}, err
	}
	return StatusPlan{
		Reference:    reference,
		Tenant:       summary,
		InstanceName: tenant.TailscaleInstanceName(summary.IncusName),
		Command:      []string{"tailscale", "status", "--json"},
	}, nil
}

func PlanDown(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, request DownRequest) (DownPlan, error) {
	summary, reference, err := tenantSummary(ctx, admin, store, request.Reference)
	if err != nil {
		return DownPlan{}, err
	}
	return DownPlan{
		Reference:    reference,
		Tenant:       summary,
		InstanceName: tenant.TailscaleInstanceName(summary.IncusName),
		Command:      []string{"tailscale", "down"},
	}, nil
}

func ParseStatus(reference string, summary tenant.Summary, data []byte, now time.Time) (StatusResult, error) {
	var payload statusPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return StatusResult{}, fmt.Errorf("parse tailscale status JSON: %w", err)
	}
	state := payload.BackendState
	if state == "" {
		state = "unknown"
	}
	state = normalizeState(state)
	tailnet := payload.CurrentTailnet.Name
	if tailnet == "" {
		tailnet = payload.CurrentTailnet.MagicDNSSuffix
	}
	hostname := payload.Self.HostName
	if hostname == "" {
		hostname = strings.TrimSuffix(payload.Self.DNSName, ".")
	}
	advertisedRoutes := append([]string{}, payload.Self.PrimaryRoutes...)
	if len(advertisedRoutes) == 0 {
		advertisedRoutes = advertisedRoutesFromAllowedIPs(payload.Self.AllowedIPs, payload.Self.TailscaleIPs)
	}
	return StatusResult{
		Reference: reference,
		Tenant:    summary,
		Tailscale: meta.Tailscale{
			State:            state,
			Tailnet:          tailnet,
			Hostname:         hostname,
			AdvertisedRoutes: advertisedRoutes,
			TailscaleIPs:     append([]string{}, payload.Self.TailscaleIPs...),
			LastCheckedAt:    now.UTC().Format(time.RFC3339),
		},
	}, nil
}

func advertisedRoutesFromAllowedIPs(allowedIPs []string, tailscaleIPs []string) []string {
	self := make(map[string]struct{}, len(tailscaleIPs)*2)
	for _, ip := range tailscaleIPs {
		if strings.Contains(ip, ":") {
			self[ip+"/128"] = struct{}{}
		} else {
			self[ip+"/32"] = struct{}{}
		}
	}
	var routes []string
	for _, allowed := range allowedIPs {
		if _, ok := self[allowed]; ok {
			continue
		}
		if !strings.Contains(allowed, "/") {
			continue
		}
		routes = append(routes, allowed)
	}
	return routes
}

func normalizeState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "needslogin", "needsmachineauth":
		return meta.TailscaleStateRunningLoggedOut
	default:
		return state
	}
}

func tenantSummary(ctx context.Context, admin config.Admin, store tenant.IncusTenantStore, reference string) (tenant.Summary, string, error) {
	if err := admin.Validate(); err != nil {
		return tenant.Summary{}, "", err
	}
	ref, err := tenantRef(reference, admin.Tenant)
	if err != nil {
		return tenant.Summary{}, "", err
	}
	summary, err := findTenant(ctx, store, ref)
	if err != nil {
		return tenant.Summary{}, "", err
	}
	return summary, ref.String(), nil
}

type statusPayload struct {
	BackendState   string `json:"BackendState"`
	CurrentTailnet struct {
		Name           string `json:"Name"`
		MagicDNSSuffix string `json:"MagicDNSSuffix"`
	} `json:"CurrentTailnet"`
	Self struct {
		DNSName       string   `json:"DNSName"`
		HostName      string   `json:"HostName"`
		AllowedIPs    []string `json:"AllowedIPs"`
		TailscaleIPs  []string `json:"TailscaleIPs"`
		PrimaryRoutes []string `json:"PrimaryRoutes"`
	} `json:"Self"`
}
