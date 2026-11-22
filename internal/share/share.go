package share

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	tenantpkg "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

const (
	RecipientStatePending   = "pending"
	RecipientStateAccepted  = "accepted"
	RecipientStateDeclined  = "declined"
	AvailabilityAvailable   = "available"
	AvailabilityUnavailable = "unavailable"
)

type Store interface {
	GetTenantShares(ctx context.Context, incusProjectName string) ([]meta.TenantStorageShare, error)
	SetTenantShares(ctx context.Context, incusProjectName string, shares []meta.TenantStorageShare) error
	// SourceDirectoryExists checks a directory inside the source project's OWN
	// workspace volume. incusProjectName is the source app Incus project
	// (<prefix>-<tenant>-<project>) — each v2 project has its own workspace
	// volume mounted at /workspace, so workspaceRelativeDir is relative to that
	// volume's root, with no project segment.
	SourceDirectoryExists(ctx context.Context, incusProjectName string, workspaceRelativeDir string) (bool, error)
}

type SourceStatus struct {
	Exists bool   `json:"exists"`
	Safe   bool   `json:"safe"`
	Reason string `json:"reason,omitempty"`
}

type SourceStatusStore interface {
	SourceDirectoryStatus(ctx context.Context, incusProjectName string, workspaceRelativeDir string) (SourceStatus, error)
}

type CreateRequest struct {
	SourceTenant string   `json:"source_tenant,omitempty"`
	Source       string   `json:"source"`
	Recipients   []string `json:"recipients"`
	Name         string   `json:"name,omitempty"`
	Actor        string   `json:"actor,omitempty"`
	DryRun       bool     `json:"dry_run,omitempty"`
	Now          string   `json:"now,omitempty"`
}

type ListRequest struct {
	Tenant   string `json:"tenant"`
	Outbound bool   `json:"outbound"`
	Inbound  bool   `json:"inbound"`
	Offers   bool   `json:"offers"`
}

type StatusRequest struct {
	Tenant  string `json:"tenant"`
	Project string `json:"project"`
	Name    string `json:"name"`
}

type RevokeRequest struct {
	SourceTenant    string `json:"source_tenant"`
	SourceProject   string `json:"source_project"`
	Name            string `json:"name"`
	RecipientTenant string `json:"recipient_tenant"`
	DryRun          bool   `json:"dry_run,omitempty"`
}

type DeleteRequest struct {
	SourceTenant  string `json:"source_tenant"`
	SourceProject string `json:"source_project"`
	Name          string `json:"name"`
	DryRun        bool   `json:"dry_run,omitempty"`
}

type TenantCleanupRequest struct {
	Tenant string `json:"tenant"`
	DryRun bool   `json:"dry_run,omitempty"`
}

type RecipientRequest struct {
	Tenant        string `json:"tenant"`
	SourceTenant  string `json:"source_tenant"`
	SourceProject string `json:"source_project"`
	Name          string `json:"name"`
	Actor         string `json:"actor,omitempty"`
	State         string `json:"state"`
	DryRun        bool   `json:"dry_run,omitempty"`
	Now           string `json:"now,omitempty"`
}

type Result struct {
	Share              meta.TenantStorageShare   `json:"share,omitempty"`
	Shares             []meta.TenantStorageShare `json:"shares,omitempty"`
	DryRun             bool                      `json:"dry_run,omitempty"`
	Reconcile          *ReconcileResult          `json:"reconcile,omitempty"`
	Reconciles         []ReconcileResult         `json:"reconciles,omitempty"`
	AffectedRecipients []string                  `json:"affected_recipients,omitempty"`
}

type TenantCleanupResult struct {
	Tenant             string            `json:"tenant"`
	DryRun             bool              `json:"dry_run,omitempty"`
	AffectedRecipients []string          `json:"affected_recipients,omitempty"`
	AffectedSources    []string          `json:"affected_sources,omitempty"`
	RecipientSummaries map[string]string `json:"recipient_summaries,omitempty"`
	SourceSummaries    map[string]string `json:"source_summaries,omitempty"`
}

type ReconcileResult struct {
	Tenant   string                   `json:"tenant"`
	DryRun   bool                     `json:"dry_run,omitempty"`
	Machines []MachineReconcileResult `json:"machines,omitempty"`
}

type MachineReconcileResult struct {
	Project      string `json:"project"`
	Machine      string `json:"machine"`
	InstanceName string `json:"instance_name"`
	Status       string `json:"status,omitempty"`
	Changed      bool   `json:"changed,omitempty"`
	Skipped      bool   `json:"skipped,omitempty"`
	Error        string `json:"error,omitempty"`
}

func (r ReconcileResult) HasFailures() bool {
	for _, machine := range r.Machines {
		if strings.TrimSpace(machine.Error) != "" {
			return true
		}
	}
	return false
}

func PlanCreate(ctx context.Context, tenants tenantpkg.IncusTenantStore, store Store, request CreateRequest) (Result, error) {
	if tenants == nil {
		return Result{}, fmt.Errorf("tenant store is required")
	}
	if store == nil {
		return Result{}, fmt.Errorf("share store is required")
	}
	sourceTenant := strings.TrimSpace(request.SourceTenant)
	if sourceTenant == "" {
		return Result{}, fmt.Errorf("source tenant is required")
	}
	if err := naming.ValidateTenantName(sourceTenant); err != nil {
		return Result{}, err
	}
	summaries, err := tenantpkg.List(ctx, tenants)
	if err != nil {
		return Result{}, err
	}
	source, ok := findTenant(summaries, sourceTenant)
	if !ok {
		return Result{}, fmt.Errorf("source tenant %s not found", sourceTenant)
	}
	project, dir, err := parseSource(request.Source)
	if err != nil {
		return Result{}, err
	}
	if !tenantHasProject(source, project) {
		return Result{}, fmt.Errorf("Sandcastle project %s not found in tenant %s", project, source.Tenant)
	}
	name := strings.TrimSpace(request.Name)
	if name == "" {
		name = path.Base(dir)
		if err := ValidateShareName(name); err != nil {
			return Result{}, fmt.Errorf("source directory basename %q is not a valid share name; pass --name", name)
		}
	} else if err := ValidateShareName(name); err != nil {
		return Result{}, err
	}
	recipients, err := normalizeRecipients(request.Recipients, sourceTenant, summaries)
	if err != nil {
		return Result{}, err
	}
	// The source directory lives in the SOURCE project's own workspace volume,
	// not the tenant's default project: each v2 project has its own volume
	// mounted at /workspace.
	status, err := sourceDirectoryStatus(ctx, store, source.V2IncusProjectName(project), dir)
	if err != nil {
		return Result{}, err
	}
	if !status.Exists {
		return Result{}, fmt.Errorf("source directory %s:/workspace/%s does not exist", project, dir)
	}
	if !status.Safe {
		return Result{}, fmt.Errorf("source directory %s:/workspace/%s is not safe to share: %s", project, dir, status.Reason)
	}
	existing, err := store.GetTenantShares(ctx, source.IncusName)
	if err != nil {
		return Result{}, err
	}
	for _, candidate := range existing {
		if candidate.SourceProject == project && candidate.Name == name {
			return Result{}, fmt.Errorf("Tenant Storage Share %s/%s already exists in tenant %s", project, name, source.Tenant)
		}
	}
	now := strings.TrimSpace(request.Now)
	if now == "" {
		now = time.Now().UTC().Format(time.RFC3339)
	}
	actor := strings.TrimSpace(request.Actor)
	recipientsState := make([]meta.TenantStorageShareRecipient, 0, len(recipients))
	for _, recipient := range recipients {
		recipientsState = append(recipientsState, meta.TenantStorageShareRecipient{
			Tenant:    recipient,
			State:     RecipientStatePending,
			OfferedBy: actor,
			OfferedAt: now,
		})
	}
	created := meta.TenantStorageShare{
		SourceTenant:  source.Tenant,
		SourceProject: project,
		SourceDir:     dir,
		Name:          name,
		Availability:  AvailabilityAvailable,
		CreatedBy:     actor,
		CreatedAt:     now,
		Recipients:    recipientsState,
	}
	output := append([]meta.TenantStorageShare{}, existing...)
	output = append(output, created)
	sortShares(output)
	if !request.DryRun {
		if err := store.SetTenantShares(ctx, source.IncusName, output); err != nil {
			return Result{}, err
		}
	}
	return Result{Share: created, DryRun: request.DryRun}, nil
}

func ListOutbound(ctx context.Context, tenants tenantpkg.IncusTenantStore, store Store, request ListRequest) (Result, error) {
	summary, err := resolveTenant(ctx, tenants, request.Tenant)
	if err != nil {
		return Result{}, err
	}
	shares, err := store.GetTenantShares(ctx, summary.IncusName)
	if err != nil {
		return Result{}, err
	}
	shares, err = withAvailability(ctx, store, summary, shares)
	if err != nil {
		return Result{}, err
	}
	sortShares(shares)
	return Result{Shares: shares}, nil
}

func ListInbound(ctx context.Context, tenants tenantpkg.IncusTenantStore, store Store, request ListRequest) (Result, error) {
	recipient, err := resolveTenant(ctx, tenants, request.Tenant)
	if err != nil {
		return Result{}, err
	}
	summaries, err := tenantpkg.List(ctx, tenants)
	if err != nil {
		return Result{}, err
	}
	local, err := store.GetTenantShares(ctx, recipient.IncusName)
	if err != nil {
		return Result{}, err
	}
	localByID := map[string]meta.TenantStorageShare{}
	for _, candidate := range local {
		localByID[shareID(candidate.SourceTenant, candidate.SourceProject, candidate.Name)] = candidate
	}
	var output []meta.TenantStorageShare
	for _, source := range summaries {
		if source.Tenant == recipient.Tenant {
			continue
		}
		sourceShares, err := store.GetTenantShares(ctx, source.IncusName)
		if err != nil {
			return Result{}, err
		}
		sourceShares, err = withAvailability(ctx, store, source, sourceShares)
		if err != nil {
			return Result{}, err
		}
		for _, offered := range sourceShares {
			if !shareOfferedTo(offered, recipient.Tenant) {
				continue
			}
			state := RecipientStatePending
			if localShare, ok := localByID[shareID(offered.SourceTenant, offered.SourceProject, offered.Name)]; ok {
				state = recipientState(localShare, recipient.Tenant, state)
			}
			if request.Offers && state != RecipientStatePending {
				continue
			}
			if !request.Offers && state == RecipientStatePending {
				continue
			}
			copy := offered
			copy.Recipients = []meta.TenantStorageShareRecipient{{Tenant: recipient.Tenant, State: state}}
			output = append(output, copy)
		}
	}
	sortShares(output)
	return Result{Shares: output}, nil
}

func SetRecipientState(ctx context.Context, tenants tenantpkg.IncusTenantStore, store Store, request RecipientRequest) (Result, error) {
	if request.State != RecipientStateAccepted && request.State != RecipientStateDeclined {
		return Result{}, fmt.Errorf("unsupported recipient state %q", request.State)
	}
	recipient, err := resolveTenant(ctx, tenants, request.Tenant)
	if err != nil {
		return Result{}, err
	}
	source, err := resolveTenant(ctx, tenants, request.SourceTenant)
	if err != nil {
		return Result{}, err
	}
	sourceShares, err := store.GetTenantShares(ctx, source.IncusName)
	if err != nil {
		return Result{}, err
	}
	var offered meta.TenantStorageShare
	found := false
	for _, candidate := range sourceShares {
		if candidate.SourceProject == request.SourceProject && candidate.Name == request.Name {
			offered = candidate
			found = true
			break
		}
	}
	if !found {
		return Result{}, fmt.Errorf("Tenant Storage Share %s/%s not found in tenant %s", request.SourceProject, request.Name, source.Tenant)
	}
	if !shareOfferedTo(offered, recipient.Tenant) {
		return Result{}, fmt.Errorf("Tenant Storage Share %s/%s is not offered to tenant %s", request.SourceProject, request.Name, recipient.Tenant)
	}
	now := strings.TrimSpace(request.Now)
	if now == "" {
		now = time.Now().UTC().Format(time.RFC3339)
	}
	localShares, err := store.GetTenantShares(ctx, recipient.IncusName)
	if err != nil {
		return Result{}, err
	}
	updated := upsertRecipientShare(localShares, offered, recipient.Tenant, request.State, request.Actor, now)
	sortShares(updated)
	resultShare := offered
	resultShare.Recipients = []meta.TenantStorageShareRecipient{recipientEntry(recipient.Tenant, request.State, request.Actor, now)}
	if !request.DryRun {
		if err := store.SetTenantShares(ctx, recipient.IncusName, updated); err != nil {
			return Result{}, err
		}
	}
	return Result{Share: resultShare, DryRun: request.DryRun}, nil
}

func RevokeRecipient(ctx context.Context, tenants tenantpkg.IncusTenantStore, store Store, request RevokeRequest) (Result, error) {
	source, err := resolveTenant(ctx, tenants, request.SourceTenant)
	if err != nil {
		return Result{}, err
	}
	recipient, err := resolveTenant(ctx, tenants, request.RecipientTenant)
	if err != nil {
		return Result{}, err
	}
	project := strings.TrimSpace(request.SourceProject)
	if err := naming.ValidateProjectName(project); err != nil {
		return Result{}, err
	}
	name := strings.TrimSpace(request.Name)
	if err := ValidateShareName(name); err != nil {
		return Result{}, err
	}
	sourceShares, err := store.GetTenantShares(ctx, source.IncusName)
	if err != nil {
		return Result{}, err
	}
	found, index := findShareIndex(sourceShares, source.Tenant, project, name)
	if index < 0 {
		return Result{}, fmt.Errorf("Tenant Storage Share %s/%s not found in tenant %s", project, name, source.Tenant)
	}
	if !shareOfferedTo(found, recipient.Tenant) {
		return Result{}, fmt.Errorf("Tenant Storage Share %s/%s is not offered to tenant %s", project, name, recipient.Tenant)
	}
	if len(found.Recipients) <= 1 {
		return Result{}, fmt.Errorf("cannot revoke the last recipient from Tenant Storage Share %s/%s; delete the share instead", project, name)
	}
	updatedShare := found
	updatedShare.Recipients = removeRecipient(updatedShare.Recipients, recipient.Tenant)
	updatedSourceShares := append([]meta.TenantStorageShare{}, sourceShares...)
	updatedSourceShares[index] = updatedShare
	sortShares(updatedSourceShares)
	localShares, err := store.GetTenantShares(ctx, recipient.IncusName)
	if err != nil {
		return Result{}, err
	}
	updatedLocalShares := RemoveShare(localShares, source.Tenant, project, name)
	if !request.DryRun {
		if err := store.SetTenantShares(ctx, source.IncusName, updatedSourceShares); err != nil {
			return Result{}, err
		}
		if err := store.SetTenantShares(ctx, recipient.IncusName, updatedLocalShares); err != nil {
			return Result{}, err
		}
	}
	return Result{
		Share:              updatedShare,
		DryRun:             request.DryRun,
		AffectedRecipients: []string{recipient.Tenant},
	}, nil
}

func DeleteOutbound(ctx context.Context, tenants tenantpkg.IncusTenantStore, store Store, request DeleteRequest) (Result, error) {
	source, err := resolveTenant(ctx, tenants, request.SourceTenant)
	if err != nil {
		return Result{}, err
	}
	project := strings.TrimSpace(request.SourceProject)
	if err := naming.ValidateProjectName(project); err != nil {
		return Result{}, err
	}
	name := strings.TrimSpace(request.Name)
	if err := ValidateShareName(name); err != nil {
		return Result{}, err
	}
	sourceShares, err := store.GetTenantShares(ctx, source.IncusName)
	if err != nil {
		return Result{}, err
	}
	found, index := findShareIndex(sourceShares, source.Tenant, project, name)
	if index < 0 {
		return Result{}, fmt.Errorf("Tenant Storage Share %s/%s not found in tenant %s", project, name, source.Tenant)
	}
	updatedSourceShares := append([]meta.TenantStorageShare{}, sourceShares[:index]...)
	updatedSourceShares = append(updatedSourceShares, sourceShares[index+1:]...)
	sortShares(updatedSourceShares)
	recipients := shareRecipients(found)
	if !request.DryRun {
		if err := store.SetTenantShares(ctx, source.IncusName, updatedSourceShares); err != nil {
			return Result{}, err
		}
		for _, recipientName := range recipients {
			recipient, err := resolveTenant(ctx, tenants, recipientName)
			if err != nil {
				return Result{}, err
			}
			localShares, err := store.GetTenantShares(ctx, recipient.IncusName)
			if err != nil {
				return Result{}, err
			}
			if err := store.SetTenantShares(ctx, recipient.IncusName, RemoveShare(localShares, source.Tenant, project, name)); err != nil {
				return Result{}, err
			}
		}
	}
	return Result{
		Share:              found,
		DryRun:             request.DryRun,
		AffectedRecipients: recipients,
	}, nil
}

func CleanupTenantDeletion(ctx context.Context, tenants tenantpkg.IncusTenantStore, store Store, request TenantCleanupRequest) (TenantCleanupResult, error) {
	deleting, err := resolveTenant(ctx, tenants, request.Tenant)
	if err != nil {
		return TenantCleanupResult{}, err
	}
	summaries, err := tenantpkg.List(ctx, tenants)
	if err != nil {
		return TenantCleanupResult{}, err
	}
	result := TenantCleanupResult{
		Tenant:             deleting.Tenant,
		DryRun:             request.DryRun,
		RecipientSummaries: map[string]string{},
		SourceSummaries:    map[string]string{},
	}
	deletingShares, err := store.GetTenantShares(ctx, deleting.IncusName)
	if err != nil {
		return TenantCleanupResult{}, err
	}
	for _, storageShare := range deletingShares {
		if storageShare.SourceTenant != deleting.Tenant {
			continue
		}
		for _, recipient := range storageShare.Recipients {
			recipientSummary, ok := findTenant(summaries, recipient.Tenant)
			if !ok || recipientSummary.Tenant == deleting.Tenant {
				continue
			}
			localShares, err := store.GetTenantShares(ctx, recipientSummary.IncusName)
			if err != nil {
				return TenantCleanupResult{}, err
			}
			updatedLocal := RemoveShare(localShares, deleting.Tenant, storageShare.SourceProject, storageShare.Name)
			if !request.DryRun {
				if err := store.SetTenantShares(ctx, recipientSummary.IncusName, updatedLocal); err != nil {
					return TenantCleanupResult{}, err
				}
			}
			result.AffectedRecipients = appendUnique(result.AffectedRecipients, recipientSummary.Tenant)
			result.RecipientSummaries[recipientSummary.Tenant] = "removed inbound copy of " + storageShare.SourceProject + "/" + storageShare.Name
		}
	}
	for _, source := range summaries {
		if source.Tenant == deleting.Tenant {
			continue
		}
		sourceShares, err := store.GetTenantShares(ctx, source.IncusName)
		if err != nil {
			return TenantCleanupResult{}, err
		}
		changed := false
		updatedSourceShares := make([]meta.TenantStorageShare, 0, len(sourceShares))
		for _, storageShare := range sourceShares {
			updatedShare := storageShare
			updatedShare.Recipients = removeRecipient(updatedShare.Recipients, deleting.Tenant)
			removed := len(updatedShare.Recipients) != len(storageShare.Recipients)
			if removed {
				changed = true
			}
			if len(updatedShare.Recipients) == 0 && removed {
				continue
			}
			updatedSourceShares = append(updatedSourceShares, updatedShare)
		}
		if !changed {
			continue
		}
		sortShares(updatedSourceShares)
		if !request.DryRun {
			if err := store.SetTenantShares(ctx, source.IncusName, updatedSourceShares); err != nil {
				return TenantCleanupResult{}, err
			}
		}
		result.AffectedSources = appendUnique(result.AffectedSources, source.Tenant)
		result.SourceSummaries[source.Tenant] = "removed recipient " + deleting.Tenant
	}
	sort.Strings(result.AffectedRecipients)
	sort.Strings(result.AffectedSources)
	return result, nil
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func GetOutbound(ctx context.Context, tenants tenantpkg.IncusTenantStore, store Store, request StatusRequest) (Result, error) {
	summary, err := resolveTenant(ctx, tenants, request.Tenant)
	if err != nil {
		return Result{}, err
	}
	project := strings.TrimSpace(request.Project)
	if err := naming.ValidateProjectName(project); err != nil {
		return Result{}, err
	}
	name := strings.TrimSpace(request.Name)
	if err := ValidateShareName(name); err != nil {
		return Result{}, err
	}
	shares, err := store.GetTenantShares(ctx, summary.IncusName)
	if err != nil {
		return Result{}, err
	}
	shares, err = withAvailability(ctx, store, summary, shares)
	if err != nil {
		return Result{}, err
	}
	for _, candidate := range shares {
		if candidate.SourceProject == project && candidate.Name == name {
			return Result{Share: candidate}, nil
		}
	}
	return Result{}, fmt.Errorf("Tenant Storage Share %s/%s not found in tenant %s", project, name, summary.Tenant)
}

func RemoveShare(shares []meta.TenantStorageShare, sourceTenant string, sourceProject string, name string) []meta.TenantStorageShare {
	id := shareID(sourceTenant, sourceProject, name)
	output := make([]meta.TenantStorageShare, 0, len(shares))
	for _, candidate := range shares {
		if shareID(candidate.SourceTenant, candidate.SourceProject, candidate.Name) == id {
			continue
		}
		output = append(output, candidate)
	}
	sortShares(output)
	return output
}

func ValidateShareName(name string) error {
	if err := naming.ValidateProjectName(strings.TrimSpace(name)); err != nil {
		return fmt.Errorf("invalid share name %q", name)
	}
	if strings.Contains(name, ".") || strings.Contains(name, "/") {
		return fmt.Errorf("invalid share name %q", name)
	}
	return nil
}

func DeviceName(storageShare meta.TenantStorageShare) string {
	sum := sha1.Sum([]byte(storageShare.SourceTenant + "/" + storageShare.SourceProject + "/" + storageShare.Name))
	return "share-" + hex.EncodeToString(sum[:])[:12]
}

func MountPath(storageShare meta.TenantStorageShare) string {
	return "/shared/" + storageShare.SourceTenant + "/" + storageShare.SourceProject + "/" + storageShare.Name
}

// HostSourcePath is the on-disk directory of a share's source, bind-mounted
// read-only into recipient machines. Incus stores a project's custom volume at
// <pool source>/custom/<incusProject>_<volume>, and each v2 project has its own
// workspace volume, so the source directory sits directly at SourceDir inside it
// — there is no per-project subdirectory (that was the v1 single-volume layout).
//
// storagePool is a real Incus storage pool name (e.g. "default"), NOT the Incus
// project: passing the project here pointed the bind mount at a path that does
// not exist, so accepted shares never appeared on recipient machines.
func HostSourcePath(storageShare meta.TenantStorageShare, sourceIncusProject string, storagePool string, workspaceVolumeName string) string {
	return path.Join(
		"/var/lib/incus/storage-pools",
		storagePool,
		"custom",
		sourceIncusProject+"_"+workspaceVolumeName,
		storageShare.SourceDir,
	)
}

func DesiredDevice(storageShare meta.TenantStorageShare, sourceIncusProject string, storagePool string, workspaceVolumeName string) map[string]string {
	return map[string]string{
		"type":     "disk",
		"source":   HostSourcePath(storageShare, sourceIncusProject, storagePool, workspaceVolumeName),
		"path":     MountPath(storageShare),
		"readonly": "true",
	}
}

func IsAcceptedAvailable(storageShare meta.TenantStorageShare, recipientTenant string) bool {
	if storageShare.Availability != "" && storageShare.Availability != AvailabilityAvailable {
		return false
	}
	for _, recipient := range storageShare.Recipients {
		if recipient.Tenant == recipientTenant && recipient.State == RecipientStateAccepted {
			return true
		}
	}
	return false
}

func MarkAvailability(storageShare meta.TenantStorageShare, status SourceStatus) meta.TenantStorageShare {
	if status.Exists && status.Safe {
		storageShare.Availability = AvailabilityAvailable
		return storageShare
	}
	storageShare.Availability = AvailabilityUnavailable
	return storageShare
}

func sourceDirectoryStatus(ctx context.Context, store Store, incusProjectName string, workspaceRelativeDir string) (SourceStatus, error) {
	if typed, ok := store.(SourceStatusStore); ok {
		status, err := typed.SourceDirectoryStatus(ctx, incusProjectName, workspaceRelativeDir)
		if err != nil {
			return SourceStatus{}, err
		}
		if status.Exists && status.Safe == false && status.Reason == "" {
			status.Reason = "source boundary is unsafe"
		}
		return status, nil
	}
	exists, err := store.SourceDirectoryExists(ctx, incusProjectName, workspaceRelativeDir)
	if err != nil {
		return SourceStatus{}, err
	}
	return SourceStatus{Exists: exists, Safe: exists}, nil
}

func withAvailability(ctx context.Context, store Store, source tenantpkg.Summary, shares []meta.TenantStorageShare) ([]meta.TenantStorageShare, error) {
	output := append([]meta.TenantStorageShare{}, shares...)
	for i := range output {
		if output[i].SourceTenant != source.Tenant {
			continue
		}
		status, err := sourceDirectoryStatus(ctx, store, source.V2IncusProjectName(output[i].SourceProject), output[i].SourceDir)
		if err != nil {
			return nil, err
		}
		output[i] = MarkAvailability(output[i], status)
	}
	return output, nil
}

func ParseStatusRef(value string) (string, string, error) {
	project, name, ok := strings.Cut(strings.TrimSpace(value), "/")
	if !ok {
		return "", "", fmt.Errorf("share reference must be project/share-name")
	}
	if err := naming.ValidateProjectName(project); err != nil {
		return "", "", err
	}
	if err := ValidateShareName(name); err != nil {
		return "", "", err
	}
	return project, name, nil
}

func parseSource(value string) (string, string, error) {
	project, rawDir, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok {
		return "", "", fmt.Errorf("share source must be project:/workspace/dir or project:dir")
	}
	if err := naming.ValidateProjectName(project); err != nil {
		return "", "", err
	}
	rawDir = strings.TrimSpace(rawDir)
	rawDir = strings.TrimPrefix(rawDir, "/workspace/")
	if rawDir == "" || rawDir == "/workspace" {
		return "", "", fmt.Errorf("share source must be below /workspace")
	}
	if strings.Contains(rawDir, "\\") || path.IsAbs(rawDir) {
		return "", "", fmt.Errorf("share source directory must be relative to /workspace")
	}
	for _, segment := range strings.Split(rawDir, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", "", fmt.Errorf("share source directory %q must not contain empty, . or .. segments", rawDir)
		}
	}
	cleaned := path.Clean(rawDir)
	if cleaned == "." {
		return "", "", fmt.Errorf("share source must be below /workspace")
	}
	return project, cleaned, nil
}

func normalizeRecipients(input []string, sourceTenant string, summaries []tenantpkg.Summary) ([]string, error) {
	seen := map[string]bool{}
	output := make([]string, 0, len(input))
	for _, raw := range input {
		recipient := strings.TrimSpace(raw)
		if err := naming.ValidateTenantName(recipient); err != nil {
			return nil, err
		}
		if recipient == sourceTenant {
			return nil, fmt.Errorf("source tenant cannot offer a share to itself")
		}
		if _, ok := findTenant(summaries, recipient); !ok {
			return nil, fmt.Errorf("recipient tenant %s not found", recipient)
		}
		if seen[recipient] {
			continue
		}
		seen[recipient] = true
		output = append(output, recipient)
	}
	if len(output) == 0 {
		return nil, fmt.Errorf("at least one recipient tenant is required")
	}
	sort.Strings(output)
	return output, nil
}

func resolveTenant(ctx context.Context, tenants tenantpkg.IncusTenantStore, tenantName string) (tenantpkg.Summary, error) {
	summaries, err := tenantpkg.List(ctx, tenants)
	if err != nil {
		return tenantpkg.Summary{}, err
	}
	tenantName = strings.TrimSpace(tenantName)
	if err := naming.ValidateTenantName(tenantName); err != nil {
		return tenantpkg.Summary{}, err
	}
	if summary, ok := findTenant(summaries, tenantName); ok {
		return summary, nil
	}
	return tenantpkg.Summary{}, fmt.Errorf("Sandcastle tenant %s not found", tenantName)
}

func findTenant(summaries []tenantpkg.Summary, tenantName string) (tenantpkg.Summary, bool) {
	for _, summary := range summaries {
		if summary.Tenant == tenantName {
			return summary, true
		}
	}
	return tenantpkg.Summary{}, false
}

func tenantHasProject(summary tenantpkg.Summary, project string) bool {
	for _, candidate := range summary.Projects {
		if candidate.Name == project {
			return true
		}
	}
	return false
}

func sortShares(shares []meta.TenantStorageShare) {
	sort.Slice(shares, func(i, j int) bool {
		if shares[i].SourceProject != shares[j].SourceProject {
			return shares[i].SourceProject < shares[j].SourceProject
		}
		return shares[i].Name < shares[j].Name
	})
}

func findShareIndex(shares []meta.TenantStorageShare, sourceTenant string, sourceProject string, name string) (meta.TenantStorageShare, int) {
	id := shareID(sourceTenant, sourceProject, name)
	for i, candidate := range shares {
		if shareID(candidate.SourceTenant, candidate.SourceProject, candidate.Name) == id {
			return candidate, i
		}
	}
	return meta.TenantStorageShare{}, -1
}

func shareRecipients(storageShare meta.TenantStorageShare) []string {
	recipients := make([]string, 0, len(storageShare.Recipients))
	for _, recipient := range storageShare.Recipients {
		if strings.TrimSpace(recipient.Tenant) == "" {
			continue
		}
		recipients = append(recipients, recipient.Tenant)
	}
	sort.Strings(recipients)
	return recipients
}

func removeRecipient(recipients []meta.TenantStorageShareRecipient, tenant string) []meta.TenantStorageShareRecipient {
	output := make([]meta.TenantStorageShareRecipient, 0, len(recipients))
	for _, recipient := range recipients {
		if recipient.Tenant == tenant {
			continue
		}
		output = append(output, recipient)
	}
	return output
}

func shareID(sourceTenant string, sourceProject string, name string) string {
	return sourceTenant + "/" + sourceProject + "/" + name
}

func shareOfferedTo(share meta.TenantStorageShare, tenant string) bool {
	for _, recipient := range share.Recipients {
		if recipient.Tenant == tenant {
			return true
		}
	}
	return false
}

func recipientState(share meta.TenantStorageShare, tenant string, fallback string) string {
	for _, recipient := range share.Recipients {
		if recipient.Tenant == tenant && recipient.State != "" {
			return recipient.State
		}
	}
	return fallback
}

func upsertRecipientShare(shares []meta.TenantStorageShare, offered meta.TenantStorageShare, tenant string, state string, actor string, at string) []meta.TenantStorageShare {
	id := shareID(offered.SourceTenant, offered.SourceProject, offered.Name)
	entry := recipientEntry(tenant, state, actor, at)
	output := append([]meta.TenantStorageShare{}, shares...)
	for i := range output {
		if shareID(output[i].SourceTenant, output[i].SourceProject, output[i].Name) == id {
			output[i].SourceDir = offered.SourceDir
			output[i].Availability = offered.Availability
			output[i].Recipients = []meta.TenantStorageShareRecipient{entry}
			return output
		}
	}
	copy := offered
	copy.Recipients = []meta.TenantStorageShareRecipient{entry}
	output = append(output, copy)
	return output
}

func recipientEntry(tenant string, state string, actor string, at string) meta.TenantStorageShareRecipient {
	entry := meta.TenantStorageShareRecipient{Tenant: tenant, State: state}
	switch state {
	case RecipientStateAccepted:
		entry.AcceptedBy = strings.TrimSpace(actor)
		entry.AcceptedAt = at
	case RecipientStateDeclined:
		entry.DeclinedBy = strings.TrimSpace(actor)
		entry.DeclinedAt = at
	}
	return entry
}
