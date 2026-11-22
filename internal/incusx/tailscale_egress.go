package incusx

import (
	"context"
	"fmt"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/tailscale"
)

// RunEgress reads or toggles the tenant's tailnet-egress setting on the infra
// project (ADR-0026). It only moves the toggle — the mechanics (bridge DHCP
// option 121, sidecar NAT unit) are applied exclusively by the CreateTenantV2
// converge, so there is a single code path that can drift nowhere. The caller
// tells the operator to converge (sc-adm tenant create / next sc login).
func (m TailscaleManager) RunEgress(ctx context.Context, plan tailscale.EgressPlan) (tailscale.EgressResult, error) {
	server, err := m.server()
	if err != nil {
		return tailscale.EgressResult{}, err
	}
	project, etag, err := server.GetProject(plan.Tenant.InfraProject)
	if err != nil {
		return tailscale.EgressResult{}, fmt.Errorf("get infra project %s: %w", plan.Tenant.InfraProject, err)
	}
	enabled := project.Config[meta.KeyV2TailnetEgress] == "true"
	result := tailscale.EgressResult{Reference: plan.Reference, Tenant: plan.Tenant, Enabled: enabled}
	if plan.Mode == "" {
		return result, nil
	}
	want := plan.Mode == "on"
	if want == enabled {
		return result, nil
	}
	put := project.Writable()
	if put.Config == nil {
		put.Config = map[string]string{}
	}
	if want {
		put.Config[meta.KeyV2TailnetEgress] = "true"
	} else {
		delete(put.Config, meta.KeyV2TailnetEgress)
	}
	if err := server.UpdateProject(plan.Tenant.InfraProject, put, etag); err != nil {
		return result, fmt.Errorf("update infra project %s: %w", plan.Tenant.InfraProject, err)
	}
	result.Enabled = want
	result.Changed = true
	return result, nil
}
