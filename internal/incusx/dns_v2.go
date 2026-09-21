package incusx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/dns"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// ReconcileV2TenantsDNS registers DNS A-records for every machine in each v2
// tenant's app projects into that tenant's sidecar CoreDNS zone: the canonical
// <name>.<project>.<suffix> plus the default project's short alias (ADR-0018).
// The zone is the only DNS authority for the suffix, so freeform `incus launch`
// machines resolve with no manual step. It is idempotent — a machine that
// vanished is dropped on the next pass.
//
// v2 tenants are the `kind=infra` projects (they hold the sidecar + the tenant's
// CIDR/suffix); the machines run in the sibling `<infra>-<project>` projects.
func ReconcileV2TenantsDNS(ctx context.Context, server incus.InstanceServer, store tenant.IncusTenantStore) error {
	return (&V2DNSReconciler{Server: server, Store: store}).Reconcile(ctx)
}

// V2DNSReconciler is the stateful form of ReconcileV2TenantsDNS: it remembers
// each tenant's last-written zone body and skips the sidecar file write +
// CoreDNS reload when nothing changed, which makes the event-driven trigger
// path (several reconcile passes per instance event) cheap. Safe for
// concurrent use; passes are serialized.
type V2DNSReconciler struct {
	Server incus.InstanceServer
	Store  tenant.IncusTenantStore
	// Prefix scopes the sweep to this installation's tenants — several
	// sandcastles share one Incus host, and each install's auth-app must only
	// touch its own sidecars.
	Prefix string

	mu       sync.Mutex
	lastZone map[string]string
}

func (r *V2DNSReconciler) Reconcile(ctx context.Context) error {
	return r.ReconcileFleet(ctx, nil)
}

// ReconcileFleet is Reconcile over a fleet the loop listed once; a nil fleet
// lists per project (the pre-handoff path).
func (r *V2DNSReconciler) ReconcileFleet(ctx context.Context, fleet authapp.InstanceFleet) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Server == nil {
		return nil
	}
	if r.lastZone == nil {
		r.lastZone = map[string]string{}
	}
	projects, err := r.Store.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("list projects for DNS reconcile: %w", err)
	}

	installPrefix := strings.TrimSpace(r.Prefix)
	if installPrefix == "" || installPrefix == "sc" {
		installPrefix = "sc2"
	}
	var errs []string
	for _, project := range projects {
		if !meta.IsManaged(project.Config) || project.Config[meta.KeyKind] != meta.KindInfra {
			continue
		}
		projectPrefix := strings.TrimSpace(project.Config[keyV2Prefix])
		if projectPrefix == "" {
			projectPrefix = "sc2"
		}
		if projectPrefix != installPrefix {
			continue
		}
		suffix := strings.TrimSpace(project.Config[keyV2Suffix])
		cidr := strings.TrimSpace(project.Config[keyV2CIDR])
		defaultProject := strings.TrimSpace(project.Config[keyV2DefaultProject])
		if suffix == "" || cidr == "" {
			continue
		}
		instancesOf := func(projectName string) ([]api.InstanceFull, error) {
			if fleet != nil {
				return fleetInstances(fleet, projectName), nil
			}
			return r.Server.UseProject(projectName).GetInstancesFull(api.InstanceTypeAny)
		}
		if err := reconcileOneV2TenantDNS(r.Server, project.Name, suffix, cidr, defaultProject, r.lastZone, instancesOf); err != nil {
			errs = append(errs, project.Name+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("DNS reconcile: %s", strings.Join(errs, "; "))
	}
	return nil
}

func reconcileOneV2TenantDNS(server incus.InstanceServer, infraProject, suffix, cidr, defaultProject string, lastZone map[string]string, instancesOf func(project string) ([]api.InstanceFull, error)) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}

	// Every app project of the tenant is named <infraProject>-<project>; scan
	// them all so machines get their canonical <name>.<project>.<suffix>
	// records (ADR-0018) — the renderer adds the short alias for default.
	projectNames, err := server.GetProjectNames()
	if err != nil {
		return fmt.Errorf("list projects: %w", err)
	}
	machines := []meta.Machine{}
	for _, projectName := range projectNames {
		shortProject, ok := strings.CutPrefix(projectName, infraProject+"-")
		if !ok || shortProject == "" {
			continue
		}
		instances, err := instancesOf(projectName)
		if err != nil {
			return fmt.Errorf("list %s instances: %w", projectName, err)
		}
		for _, instance := range instances {
			ip := instanceTenantIPv4(instance, prefix)
			if ip == "" {
				continue
			}
			machines = append(machines, meta.Machine{Name: instance.Name, Project: shortProject, PrivateIP: ip, Running: instance.IsActive()})
		}
	}

	result, err := dns.PlanApply(dns.Tenant{
		IncusName:      infraProject,
		InfraProject:   infraProject,
		DNSSuffix:      suffix,
		DefaultProject: defaultProject,
		PrivateCIDR:    cidr,
	}, machines)
	if err != nil {
		return err
	}
	// The v2 sidecar instance is named "sidecar" inside the tenant's infra
	// project (naming.V2SidecarInstanceName).
	sidecar := server.UseProject(infraProject)
	sidecarName := naming.V2SidecarInstanceName

	// Skip the sidecar write + CoreDNS reload only when the sidecar's ACTUAL zone
	// already matches the rendered one (both serial-normalized). The in-memory
	// lastZone cache alone is unsafe: a sidecar can restart and lose its zone
	// (back to SOA+ns) while the auth-app — and its cache — keep running, so a
	// pure cache check would leave that sidecar stuck on the stale/empty zone
	// forever. Comparing against the live file lets an external reset self-heal.
	desired, zonePath := "", ""
	for _, file := range result.Files {
		if strings.Contains(file.Path, "/zones/db.") {
			desired, zonePath = file.Content, file.Path
		}
	}
	if zonePath != "" {
		if actual, err := readInstanceFileString(sidecar, sidecarName, zonePath); err == nil {
			if normalizeZoneSerialToOne(actual, suffix) == desired {
				if lastZone != nil {
					lastZone[infraProject] = desired
				}
				return nil
			}
		}
	}
	for _, dir := range []string{"/etc/coredns", "/etc/coredns/zones"} {
		if err := sidecar.CreateInstanceFile(sidecarName, dir, incus.InstanceFileArgs{Type: "directory", Mode: 0o755}); err != nil && !api.StatusErrorCheck(err, http.StatusConflict) {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	// CoreDNS's file plugin only reloads a zone when its SOA serial INCREASES.
	// RenderTenant emits serial 1, so make it monotonic (seconds since epoch).
	serial := time.Now().Unix()
	for _, file := range result.Files {
		// Only (re)write the CoreDNS config; the resolver files (/etc/resolv.conf,
		// upstream-resolv.conf) are static, set once at provisioning.
		if !strings.HasPrefix(file.Path, "/etc/coredns") {
			continue
		}
		content := file.Content
		if strings.Contains(file.Path, "/zones/db.") {
			content = strings.Replace(content,
				"hostmaster."+suffix+". 1 ",
				fmt.Sprintf("hostmaster.%s. %d ", suffix, serial), 1)
		}
		if err := sidecar.CreateInstanceFile(sidecarName, file.Path, incus.InstanceFileArgs{
			Content:   strings.NewReader(content),
			Type:      "file",
			Mode:      file.Mode,
			WriteMode: "overwrite",
		}); err != nil {
			return fmt.Errorf("write %s: %w", file.Path, err)
		}
	}
	// Reload CoreDNS to pick up the new zone. Capture stderr and check the
	// command's exit code: op.Wait() alone succeeds even when the command
	// fails (SDK semantics), and a silently-missed reload leaves CoreDNS
	// serving the stale zone until its file-plugin timer (~1min) — seen live
	// on majestix as flaky "record in the zone file but not resolving".
	var reloadStderr strings.Builder
	dataDone := make(chan bool)
	op, err := sidecar.ExecInstance(sidecarName, api.InstanceExecPost{
		Command:   []string{"/bin/sh", "-c", "systemctl reload coredns 2>/dev/null || systemctl restart coredns"},
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stderr:   &reloadStderr,
		DataDone: dataDone,
	})
	if err != nil {
		return fmt.Errorf("reload coredns: %w", err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("reload coredns: %w (stderr: %s)", err, strings.TrimSpace(reloadStderr.String()))
	}
	<-dataDone
	if err := execExitError(op, reloadStderr.String()); err != nil {
		return fmt.Errorf("reload coredns: %w", err)
	}
	if lastZone != nil {
		lastZone[infraProject] = desired
	}
	return nil
}

// readInstanceFileString reads a file from an instance into a string.
func readInstanceFileString(server incus.InstanceServer, instance, path string) (string, error) {
	reader, _, err := server.GetInstanceFile(instance, path)
	if err != nil {
		return "", err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// normalizeZoneSerialToOne rewrites the SOA serial back to 1 so a zone written
// with a monotonic (unix-time) serial compares equal to the freshly rendered
// zone (which always carries serial 1). Only the digits immediately after
// `hostmaster.<suffix>. ` are touched.
func normalizeZoneSerialToOne(zone, suffix string) string {
	marker := "hostmaster." + suffix + ". "
	idx := strings.Index(zone, marker)
	if idx < 0 {
		return zone
	}
	start := idx + len(marker)
	end := start
	for end < len(zone) && zone[end] >= '0' && zone[end] <= '9' {
		end++
	}
	if end == start {
		return zone
	}
	return zone[:start] + "1" + zone[end:]
}

// instanceTenantIPv4 returns the instance's eth0 IPv4 that falls inside the tenant
// CIDR (skips loopback/tailnet/other addresses), or "" if none.
func instanceTenantIPv4(instance api.InstanceFull, cidr netip.Prefix) string {
	if instance.State == nil {
		return ""
	}
	for name, iface := range instance.State.Network {
		if name == "lo" {
			continue
		}
		for _, addr := range iface.Addresses {
			if addr.Family != "inet" {
				continue
			}
			ip, err := netip.ParseAddr(addr.Address)
			if err == nil && cidr.Contains(ip) {
				return addr.Address
			}
		}
	}
	return ""
}
