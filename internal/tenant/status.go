package tenant

import (
	"context"
	"fmt"
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
)

type Status struct {
	Summary Summary     `json:"summary"`
	Checks  []Check     `json:"checks"`
	Shares  ShareHealth `json:"shares"`
}

type ShareHealth struct {
	OutboundShareCount       int `json:"outboundShareCount"`
	InboundAcceptedCount     int `json:"inboundAcceptedCount"`
	PendingInboundOfferCount int `json:"pendingInboundOfferCount"`
	UnreconciledMachineCount int `json:"unreconciledMachineCount"`
}

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type TopologyStore interface {
	GetTopology(ctx context.Context, request TopologyRequest) (Topology, error)
}

type TopologyRequest struct {
	IncusProject string
	InfraProject string
	DNSSuffix    string
}

type Topology struct {
	PrivateNetworkPresent bool
	TailscaleInstance     string
	DurableVolumes        map[string]bool
	Sidecars              map[string]SidecarStatus
	DiagnosticFiles       []DiagnosticFile
}

type SidecarStatus struct {
	Present bool
	Running bool
	Status  string
}

type DiagnosticFile struct {
	Instance string `json:"instance"`
	Path     string `json:"path"`
	Content  string `json:"content,omitempty"`
	Error    string `json:"error,omitempty"`
}

func GetStatus(ctx context.Context, store IncusTenantStore, reference string) (Status, error) {
	return GetStatusWithTopology(ctx, store, nil, TopologyRequest{}, reference)
}

func GetStatusWithTopology(ctx context.Context, store IncusTenantStore, topologyStore TopologyStore, topologyRequest TopologyRequest, reference string) (Status, error) {
	return GetStatusWithTopologyForPrefix(ctx, store, topologyStore, topologyRequest, reference, "")
}

// GetStatusWithTopologyForPrefix scopes the tenant lookup to one installation
// prefix — same-named tenants of different installs sharing an Incus daemon
// are different tenants (see ListForPrefix). Empty prefix = no scoping.
func GetStatusWithTopologyForPrefix(ctx context.Context, store IncusTenantStore, topologyStore TopologyStore, topologyRequest TopologyRequest, reference string, installPrefix string) (Status, error) {
	ref, err := naming.ParseTenantRef(reference)
	if err != nil {
		return Status{}, err
	}
	tenants, err := ListForPrefix(ctx, store, installPrefix)
	if err != nil {
		return Status{}, err
	}
	for _, summary := range tenants {
		if summary.Tenant == ref.Tenant {
			status := Status{
				Summary: summary,
				Shares:  shareHealth(summary, tenants),
				Checks: []Check{
					{Name: "metadata", Status: "ok", Detail: "Sandcastle tenant metadata is present"},
					cidrCheck(summary),
					{Name: "dns", Status: checkPresent(summary.DNSSuffix), Detail: summary.DNSSuffix},
					tailscaleRouteCheck(summary),
				},
			}
			if topologyStore != nil {
				topologyRequest.IncusProject = summary.IncusName
				// The infra project is on the summary already. Recomputing it as
				// "<incus project>-infra" is the v1 rule, and under v2 the current
				// project is an APP project (<prefix>-<tenant>-<project>), so it
				// produced the nonexistent "<prefix>-<tenant>-default-infra".
				topologyRequest.InfraProject = summary.InfraProject
				topologyRequest.DNSSuffix = summary.DNSSuffix
				topology, err := topologyStore.GetTopology(ctx, topologyRequest)
				if err != nil {
					status.Checks = append(status.Checks, topologyErrorCheck(summary, err))
					return status, nil
				}
				status.Checks = append(status.Checks, TopologyChecks(topology)...)
			}
			return status, nil
		}
	}
	return Status{}, fmt.Errorf("Sandcastle tenant %s not found", ref.String())
}

func shareHealth(summary Summary, tenants []Summary) ShareHealth {
	health := ShareHealth{}
	localByID := map[string]string{}
	for _, storageShare := range summary.StorageShares {
		id := storageShare.SourceTenant + "/" + storageShare.SourceProject + "/" + storageShare.Name
		if storageShare.SourceTenant == summary.Tenant {
			health.OutboundShareCount++
			continue
		}
		state := recipientStateForTenant(storageShare, summary.Tenant)
		localByID[id] = state
		if state == "accepted" {
			health.InboundAcceptedCount++
		}
	}
	for _, source := range tenants {
		if source.Tenant == summary.Tenant {
			continue
		}
		for _, storageShare := range source.StorageShares {
			if !shareOfferedToTenant(storageShare, summary.Tenant) {
				continue
			}
			id := storageShare.SourceTenant + "/" + storageShare.SourceProject + "/" + storageShare.Name
			if localByID[id] == "" {
				health.PendingInboundOfferCount++
			}
		}
	}
	return health
}

func shareOfferedToTenant(storageShare meta.TenantStorageShare, tenant string) bool {
	for _, recipient := range storageShare.Recipients {
		if recipient.Tenant == tenant {
			return true
		}
	}
	return false
}

func recipientStateForTenant(storageShare meta.TenantStorageShare, tenant string) string {
	for _, recipient := range storageShare.Recipients {
		if recipient.Tenant == tenant {
			return recipient.State
		}
	}
	return ""
}

func tailscaleRouteCheck(summary Summary) Check {
	if summary.Tailscale.State == "" {
		return Check{Name: "tailscale:route", Status: "unknown", Detail: "no Tailscale status recorded"}
	}
	if summary.Tailscale.State == meta.TailscaleStateRunningLoggedOut {
		return Check{Name: "tailscale:route", Status: "unknown", Detail: "Tailscale sidecar is running but not authenticated"}
	}
	for _, route := range summary.Tailscale.AdvertisedRoutes {
		if route == summary.PrivateCIDR {
			return Check{Name: "tailscale:route", Status: "ok", Detail: route}
		}
	}
	return Check{Name: "tailscale:route", Status: "missing", Detail: summary.PrivateCIDR}
}

func checkPresent(value string) string {
	if value == "" {
		return "missing"
	}
	return "ok"
}

// cidrCheck reports the tenant's private /24. A v2 tenant stores it only on the
// kind=infra project, which a restricted tenant certificate cannot read — the
// value is absent because it is out of reach, not because the tenant is broken,
// so say "unknown" rather than "missing".
func cidrCheck(summary Summary) Check {
	if summary.PrivateCIDR != "" {
		return Check{Name: "cidr", Status: "ok", Detail: summary.PrivateCIDR}
	}
	return Check{
		Name:   "cidr",
		Status: "unknown",
		Detail: "stored on the infra project " + summary.InfraProject + ", which a tenant certificate cannot read",
	}
}

// topologyErrorCheck downgrades the one failure that is expected rather than
// broken: a v2 tenant's sidecar lives in the infra project, and a restricted
// tenant certificate is not granted that project. Reading topology needs an
// admin remote.
func topologyErrorCheck(summary Summary, err error) Check {
	if isProjectPermissionError(err) {
		return Check{
			Name:   "topology",
			Status: "unknown",
			Detail: "infra project " + summary.InfraProject + " is not visible to this tenant certificate; run from an admin remote to check topology",
		}
	}
	return Check{Name: "topology", Status: "error", Detail: err.Error()}
}

// isProjectPermissionError matches the Incus daemon's refusal to expose a
// project a certificate is not granted ("User does not have permission for
// project \"x\""). Incus returns the same error for a project that does not
// exist, which is exactly the ambiguity a restricted client cannot resolve.
func isProjectPermissionError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "does not have permission for project")
}

// TopologyChecks returns stable tenant resource checks for status and diagnostics output.
func TopologyChecks(topology Topology) []Check {
	checks := []Check{
		{Name: "network:sc-private", Status: presentStatus(topology.PrivateNetworkPresent)},
	}
	for _, volume := range []string{HomeVolumeName, WorkspaceVolumeName, CAVolumeName} {
		checks = append(checks, Check{Name: "volume:" + volume, Status: presentStatus(topology.DurableVolumes[volume])})
	}
	for _, sidecar := range []string{topology.TailscaleInstance, DNSName} {
		status := topology.Sidecars[sidecar]
		check := Check{Name: "sidecar:" + sidecar, Status: presentStatus(status.Present), Detail: status.Status}
		if status.Present && !status.Running {
			check.Status = "stopped"
		}
		if status.Present && status.Running {
			check.Status = "ok"
		}
		checks = append(checks, check)
	}
	return checks
}

func presentStatus(present bool) string {
	if present {
		return "ok"
	}
	return "missing"
}
