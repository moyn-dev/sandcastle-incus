package share

import (
	"context"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenantpkg "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func TestPlanCreateCreatesPendingOutboundOffer(t *testing.T) {
	store := &fakeStore{exists: true}
	result, err := PlanCreate(context.Background(), tenantStore(), store, CreateRequest{
		SourceTenant: "acme",
		Source:       "default:/workspace/docs",
		Recipients:   []string{"skorfman"},
		Actor:        "thieso2",
		Now:          "2026-05-27T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Share.SourceTenant != "acme" || result.Share.SourceProject != "default" || result.Share.SourceDir != "docs" || result.Share.Name != "docs" {
		t.Fatalf("share = %#v", result.Share)
	}
	if len(result.Share.Recipients) != 1 || result.Share.Recipients[0].Tenant != "skorfman" || result.Share.Recipients[0].State != RecipientStatePending {
		t.Fatalf("recipients = %#v", result.Share.Recipients)
	}
	if len(store.saved) != 1 {
		t.Fatalf("saved = %#v", store.saved)
	}
}

// The source directory of a share lives in the SOURCE project's own workspace
// volume (<prefix>-<tenant>-<project>), and the in-volume path is the directory
// alone. The v1 code checked the tenant's default project at <project>/<dir>,
// which under v2 does not exist — so `sc share create` failed on a directory
// that was really there.
func TestPlanCreateChecksTheSourceProjectsOwnVolume(t *testing.T) {
	for _, tc := range []struct {
		source      string
		wantProject string
		wantDir     string
	}{
		{"default:/workspace/docs", "sc2-acme-default", "docs"},
		{"backend:/workspace/data/sets", "sc2-acme-backend", "data/sets"},
	} {
		store := &fakeStatusStore{
			fakeStore: &fakeStore{exists: true},
			status:    SourceStatus{Exists: true, Safe: true},
		}
		if _, err := PlanCreate(context.Background(), tenantStoreWithProjects(), store, CreateRequest{
			SourceTenant: "acme",
			Source:       tc.source,
			Recipients:   []string{"skorfman"},
			Now:          "2026-05-27T12:00:00Z",
		}); err != nil {
			t.Fatalf("%s: %v", tc.source, err)
		}
		if len(store.sourceLookups) != 1 {
			t.Fatalf("%s: lookups = %#v", tc.source, store.sourceLookups)
		}
		got := store.sourceLookups[0]
		if got.incusProject != tc.wantProject || got.dir != tc.wantDir {
			t.Fatalf("%s: looked up %s:%q, want %s:%q", tc.source, got.incusProject, got.dir, tc.wantProject, tc.wantDir)
		}
	}
}

func TestPlanCreateRejectsSelfShare(t *testing.T) {
	_, err := PlanCreate(context.Background(), tenantStore(), &fakeStore{exists: true}, CreateRequest{
		SourceTenant: "acme",
		Source:       "default:docs",
		Recipients:   []string{"acme"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPlanCreateRequiresNameWhenBasenameIsNotPathSafe(t *testing.T) {
	_, err := PlanCreate(context.Background(), tenantStore(), &fakeStore{exists: true}, CreateRequest{
		SourceTenant: "acme",
		Source:       "default:Docs",
		Recipients:   []string{"skorfman"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPlanCreateDryRunDoesNotSave(t *testing.T) {
	store := &fakeStore{exists: true}
	result, err := PlanCreate(context.Background(), tenantStore(), store, CreateRequest{
		SourceTenant: "acme",
		Source:       "default:docs",
		Recipients:   []string{"skorfman"},
		DryRun:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.DryRun {
		t.Fatal("DryRun = false")
	}
	if len(store.saved) != 0 {
		t.Fatalf("saved = %#v", store.saved)
	}
}

func TestPlanCreateRejectsUnsafeSource(t *testing.T) {
	_, err := PlanCreate(context.Background(), tenantStore(), &fakeStatusStore{
		fakeStore: &fakeStore{exists: true},
		status:    SourceStatus{Exists: true, Safe: false, Reason: "symlink escapes source directory"},
	}, CreateRequest{
		SourceTenant: "acme",
		Source:       "default:docs",
		Recipients:   []string{"skorfman"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestListInboundShowsPendingOffers(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-acme-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStatePending,
			}},
		}},
	}}
	result, err := ListInbound(context.Background(), tenantStore(), store, ListRequest{Tenant: "skorfman", Offers: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Shares) != 1 || result.Shares[0].Recipients[0].State != RecipientStatePending {
		t.Fatalf("shares = %#v", result.Shares)
	}
}

func TestListInboundExcludesPendingOffersWithoutOffersFilter(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-acme-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStatePending,
			}},
		}},
	}}
	result, err := ListInbound(context.Background(), tenantStore(), store, ListRequest{Tenant: "skorfman", Inbound: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Shares) != 0 {
		t.Fatalf("shares = %#v", result.Shares)
	}
}

func TestListOutboundMarksMissingSourceUnavailable(t *testing.T) {
	store := &fakeStatusStore{
		fakeStore: &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
			"sc2-acme-default": {{
				SourceTenant:  "acme",
				SourceProject: "default",
				SourceDir:     "docs",
				Name:          "docs",
				Availability:  AvailabilityAvailable,
				Recipients: []meta.TenantStorageShareRecipient{{
					Tenant: "skorfman",
					State:  RecipientStatePending,
				}},
			}},
		}},
		status: SourceStatus{Exists: false, Safe: false, Reason: "source directory is missing"},
	}
	result, err := ListOutbound(context.Background(), tenantStore(), store, ListRequest{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Shares) != 1 || result.Shares[0].Availability != AvailabilityUnavailable {
		t.Fatalf("shares = %#v", result.Shares)
	}
}

func TestListOutboundRestoresAvailableSource(t *testing.T) {
	store := &fakeStatusStore{
		fakeStore: &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
			"sc2-acme-default": {{
				SourceTenant:  "acme",
				SourceProject: "default",
				SourceDir:     "docs",
				Name:          "docs",
				Availability:  AvailabilityUnavailable,
				Recipients: []meta.TenantStorageShareRecipient{{
					Tenant: "skorfman",
					State:  RecipientStatePending,
				}},
			}},
		}},
		status: SourceStatus{Exists: true, Safe: true},
	}
	result, err := ListOutbound(context.Background(), tenantStore(), store, ListRequest{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Shares) != 1 || result.Shares[0].Availability != AvailabilityAvailable {
		t.Fatalf("shares = %#v", result.Shares)
	}
}

func TestSetRecipientStateAcceptsOffer(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-acme-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStatePending,
			}},
		}},
	}}
	result, err := SetRecipientState(context.Background(), tenantStore(), store, RecipientRequest{
		Tenant:        "skorfman",
		SourceTenant:  "acme",
		SourceProject: "default",
		Name:          "docs",
		State:         RecipientStateAccepted,
		Actor:         "skorfman",
		Now:           "2026-05-27T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Share.Recipients[0].State != RecipientStateAccepted {
		t.Fatalf("share = %#v", result.Share)
	}
	saved := store.sharesByProject["sc2-skorfman-default"]
	if len(saved) != 1 || saved[0].Recipients[0].AcceptedBy != "skorfman" {
		t.Fatalf("saved = %#v", saved)
	}
}

func TestRevokeRecipientRemovesSourceAndRecipientState(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-acme-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{
				{Tenant: "skorfman", State: RecipientStateAccepted},
				{Tenant: "other", State: RecipientStatePending},
			},
		}},
		"sc2-skorfman-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStateAccepted,
			}},
		}},
	}}
	result, err := RevokeRecipient(context.Background(), tenantStore(), store, RevokeRequest{
		SourceTenant:    "acme",
		SourceProject:   "default",
		Name:            "docs",
		RecipientTenant: "skorfman",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Share.Recipients) != 1 || result.Share.Recipients[0].Tenant != "other" {
		t.Fatalf("share = %#v", result.Share)
	}
	if len(store.sharesByProject["sc2-skorfman-default"]) != 0 {
		t.Fatalf("recipient shares = %#v", store.sharesByProject["sc2-skorfman-default"])
	}
}

func TestRevokeRecipientRejectsLastRecipient(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-acme-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStateAccepted,
			}},
		}},
	}}
	_, err := RevokeRecipient(context.Background(), tenantStore(), store, RevokeRequest{
		SourceTenant:    "acme",
		SourceProject:   "default",
		Name:            "docs",
		RecipientTenant: "skorfman",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDeleteOutboundRemovesSourceAndRecipientCopies(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-acme-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStateAccepted,
			}},
		}},
		"sc2-skorfman-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStateAccepted,
			}},
		}},
	}}
	result, err := DeleteOutbound(context.Background(), tenantStore(), store, DeleteRequest{
		SourceTenant:  "acme",
		SourceProject: "default",
		Name:          "docs",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AffectedRecipients) != 1 || result.AffectedRecipients[0] != "skorfman" {
		t.Fatalf("affected = %#v", result.AffectedRecipients)
	}
	if len(store.sharesByProject["sc2-acme-default"]) != 0 || len(store.sharesByProject["sc2-skorfman-default"]) != 0 {
		t.Fatalf("shares = %#v", store.sharesByProject)
	}
}

func TestDeleteOutboundRejectsInboundCopy(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-skorfman-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStateAccepted,
			}},
		}},
	}}
	_, err := DeleteOutbound(context.Background(), tenantStore(), store, DeleteRequest{
		SourceTenant:  "skorfman",
		SourceProject: "default",
		Name:          "docs",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCleanupTenantDeletionAsSourceRemovesRecipientCopies(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-acme-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStateAccepted,
			}},
		}},
		"sc2-skorfman-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{{
				Tenant: "skorfman",
				State:  RecipientStateAccepted,
			}},
		}},
	}}
	result, err := CleanupTenantDeletion(context.Background(), tenantStore(), store, TenantCleanupRequest{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AffectedRecipients) != 1 || result.AffectedRecipients[0] != "skorfman" {
		t.Fatalf("affected = %#v", result.AffectedRecipients)
	}
	if len(store.sharesByProject["sc2-skorfman-default"]) != 0 {
		t.Fatalf("recipient shares = %#v", store.sharesByProject["sc2-skorfman-default"])
	}
}

func TestCleanupTenantDeletionAsRecipientRemovesSourceRecipientOnly(t *testing.T) {
	store := &fakeStore{sharesByProject: map[string][]meta.TenantStorageShare{
		"sc2-acme-default": {{
			SourceTenant:  "acme",
			SourceProject: "default",
			SourceDir:     "docs",
			Name:          "docs",
			Recipients: []meta.TenantStorageShareRecipient{
				{Tenant: "skorfman", State: RecipientStateAccepted},
				{Tenant: "other", State: RecipientStatePending},
			},
		}},
	}}
	result, err := CleanupTenantDeletion(context.Background(), tenantStore(), store, TenantCleanupRequest{Tenant: "skorfman"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.AffectedSources) != 1 || result.AffectedSources[0] != "acme" {
		t.Fatalf("affected = %#v", result.AffectedSources)
	}
	sourceShares := store.sharesByProject["sc2-acme-default"]
	if len(sourceShares) != 1 || len(sourceShares[0].Recipients) != 1 || sourceShares[0].Recipients[0].Tenant != "other" {
		t.Fatalf("source shares = %#v", sourceShares)
	}
}

type fakeStore struct {
	shares          []meta.TenantStorageShare
	sharesByProject map[string][]meta.TenantStorageShare
	saved           []meta.TenantStorageShare
	exists          bool
	// sourceLookups records every (incusProject, dir) the source-directory check
	// was asked about, so tests can assert the source is resolved to the source
	// project's OWN Incus project rather than the tenant default or infra project.
	sourceLookups []sourceLookup
}

type sourceLookup struct {
	incusProject string
	dir          string
}

type fakeStatusStore struct {
	*fakeStore
	status SourceStatus
}

func (s fakeStatusStore) SourceDirectoryStatus(ctx context.Context, incusProjectName string, workspaceRelativeDir string) (SourceStatus, error) {
	s.sourceLookups = append(s.sourceLookups, sourceLookup{incusProjectName, workspaceRelativeDir})
	return s.status, nil
}

func (s *fakeStore) GetTenantShares(ctx context.Context, incusProjectName string) ([]meta.TenantStorageShare, error) {
	if s.sharesByProject != nil {
		return append([]meta.TenantStorageShare{}, s.sharesByProject[incusProjectName]...), nil
	}
	return append([]meta.TenantStorageShare{}, s.shares...), nil
}

func (s *fakeStore) SetTenantShares(ctx context.Context, incusProjectName string, shares []meta.TenantStorageShare) error {
	if s.sharesByProject != nil {
		s.sharesByProject[incusProjectName] = append([]meta.TenantStorageShare{}, shares...)
	}
	s.saved = append([]meta.TenantStorageShare{}, shares...)
	return nil
}

func (s *fakeStore) SourceDirectoryExists(ctx context.Context, incusProjectName string, workspaceRelativeDir string) (bool, error) {
	s.sourceLookups = append(s.sourceLookups, sourceLookup{incusProjectName, workspaceRelativeDir})
	return s.exists, nil
}

func tenantStore() tenantpkg.MemoryStore {
	// v2 fixture: each tenant is a kind=infra project (carrying its /24) plus a
	// kind=project app project. v1 (kind=tenant) projects are no longer listed.
	projects := []tenantpkg.IncusProject{}
	for _, t := range []struct{ name, cidr string }{
		{"acme", "10.248.0.0/24"},
		{"skorfman", "10.248.1.0/24"},
		{"other", "10.248.2.0/24"},
	} {
		projects = append(projects,
			tenantpkg.IncusProject{Name: "sc2-" + t.name, Config: map[string]string{
				meta.KeyKind: meta.KindInfra, meta.KeyTenant: t.name, meta.KeyVersion: "2", meta.KeyV2CIDR: t.cidr,
			}},
			tenantpkg.IncusProject{Name: "sc2-" + t.name + "-default", Config: map[string]string{
				meta.KeyKind: meta.KindV2Project, meta.KeyTenant: t.name, meta.KeyVersion: "2",
			}},
		)
	}
	return tenantpkg.MemoryStore{Projects: projects}
}

// tenantStoreWithProjects is tenantStore() plus a non-default `backend` project
// for acme, so tests can share from a project other than default.
func tenantStoreWithProjects() tenantpkg.MemoryStore {
	store := tenantStore()
	store.Projects = append(store.Projects, tenantpkg.IncusProject{
		Name: "sc2-acme-backend",
		Config: map[string]string{
			meta.KeyKind: meta.KindV2Project, meta.KeyTenant: "acme", meta.KeyVersion: "2",
		},
	})
	return store
}
