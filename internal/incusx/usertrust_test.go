package incusx

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

type fakeTrustServer struct {
	certificates []api.Certificate
	updated      *api.CertificatePut
	// updatedFingerprints records every UpdateCertificate target in order (the
	// `updated` pointer only keeps the last write).
	updatedFingerprints []string
	deleted             []string
	tokenOp             incus.Operation
}

func (s *fakeTrustServer) GetCertificates() ([]api.Certificate, error) { return s.certificates, nil }
func (s *fakeTrustServer) UpdateCertificate(fingerprint string, certificate api.CertificatePut, etag string) error {
	s.updated = &certificate
	s.updatedFingerprints = append(s.updatedFingerprints, fingerprint)
	return nil
}
func (s *fakeTrustServer) DeleteCertificate(fingerprint string) error {
	s.deleted = append(s.deleted, fingerprint)
	return nil
}
func (s *fakeTrustServer) CreateCertificateToken(certificate api.CertificatesPost) (incus.Operation, error) {
	return s.tokenOp, nil
}

func TestTrustManagerGrant(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{{
		Fingerprint: "abc",
		CertificatePut: api.CertificatePut{
			Name:       "sandcastle-alice",
			Type:       api.CertificateTypeClient,
			Restricted: true,
			Projects:   []string{"sc-alice-existing"},
		},
	}}}
	manager := TrustManager{Server: server}
	err := manager.Grant(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Restricted:      true,
		Projects:        []string{"sc-alice-existing", "sc-alice-new"},
		Description:     "Sandcastle restricted user alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.updated == nil {
		t.Fatal("expected certificate update")
	}
	if !server.updated.Restricted {
		t.Fatal("Restricted = false, want true")
	}
	if len(server.updated.Projects) != 2 {
		t.Fatalf("Projects = %#v", server.updated.Projects)
	}
}

func TestTrustManagerGrantRejectsUnrestrictedCertificate(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{{
		Fingerprint: "abc",
		CertificatePut: api.CertificatePut{
			Name:       "sandcastle-alice",
			Type:       api.CertificateTypeClient,
			Restricted: false,
		},
	}}}
	manager := TrustManager{Server: server}
	err := manager.Grant(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Restricted:      true,
		Projects:        []string{"sc-alice-new"},
		Description:     "Sandcastle restricted user alice",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if server.updated != nil {
		t.Fatal("certificate should not be updated")
	}
}

func TestTrustManagerGrantRejectsServerCertificate(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{{
		Fingerprint: "abc",
		CertificatePut: api.CertificatePut{
			Name:       "sandcastle-alice",
			Type:       api.CertificateTypeServer,
			Restricted: true,
		},
	}}}
	manager := TrustManager{Server: server}
	err := manager.Grant(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Restricted:      true,
		Projects:        []string{"sc-alice-new"},
		Description:     "Sandcastle restricted user alice",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if server.updated != nil {
		t.Fatal("certificate should not be updated")
	}
}

func TestTrustManagerRevoke(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{{
		Fingerprint: "abc",
		CertificatePut: api.CertificatePut{
			Name:       "sandcastle-alice",
			Type:       api.CertificateTypeClient,
			Restricted: true,
			Projects:   []string{"sc-acme", "sc-other"},
		},
	}}}
	manager := TrustManager{Server: server}
	err := manager.Revoke(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Restricted:      true,
		Projects:        []string{"sc-acme"},
		Description:     "Sandcastle restricted user alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.updated == nil {
		t.Fatal("expected certificate update")
	}
	if len(server.updated.Projects) != 1 || server.updated.Projects[0] != "sc-other" {
		t.Fatalf("Projects = %#v", server.updated.Projects)
	}
}

func TestTrustManagerDelete(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{{
		Fingerprint: "abc123456789",
		CertificatePut: api.CertificatePut{
			Name:       "sandcastle-alice",
			Type:       api.CertificateTypeClient,
			Restricted: true,
			Projects:   []string{"sc-acme"},
		},
	}}}
	manager := TrustManager{Server: server}
	err := manager.Delete(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Restricted:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(server.deleted) != 1 || server.deleted[0] != "abc123456789" {
		t.Fatalf("deleted = %#v", server.deleted)
	}
}

func TestTrustManagerDeleteRejectsUnrestrictedCertificate(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{{
		Fingerprint: "abc123456789",
		CertificatePut: api.CertificatePut{
			Name:       "sandcastle-alice",
			Type:       api.CertificateTypeClient,
			Restricted: false,
		},
	}}}
	manager := TrustManager{Server: server}
	err := manager.Delete(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Restricted:      true,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if len(server.deleted) != 0 {
		t.Fatalf("deleted = %#v", server.deleted)
	}
}

func TestTrustManagerListsTenantUsers(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{
		{CertificatePut: api.CertificatePut{Name: "sandcastle-bob", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc-acme"}}},
		{CertificatePut: api.CertificatePut{Name: "sandcastle-alice", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc-acme"}}},
		{CertificatePut: api.CertificatePut{Name: "sandcastle-carol", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc-other"}}},
		{CertificatePut: api.CertificatePut{Name: "sandcastle-root", Type: api.CertificateTypeClient, Restricted: false, Projects: []string{"sc-acme"}}},
	}}
	manager := TrustManager{Server: server}
	result, err := manager.ListTenantUsers(context.Background(), usertrust.TenantUsersPlan{Tenant: "acme", IncusProject: "sc-acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Users) != 2 || result.Users[0] != "alice" || result.Users[1] != "bob" {
		t.Fatalf("Users = %#v", result.Users)
	}
}

func TestTrustManagerCreateToken(t *testing.T) {
	server := &fakeTrustServer{tokenOp: tokenOperation()}
	manager := TrustManager{Server: server}
	result, err := manager.CreateToken(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Restricted:      true,
		Projects:        []string{"sc-alice-myproject"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Token == "" {
		t.Fatal("expected token")
	}
}

func tokenOperation() incus.Operation {
	return staticOperation{op: api.Operation{Metadata: map[string]any{
		"request":     map[string]any{"name": "sandcastle-alice"},
		"secret":      "secret",
		"fingerprint": "fingerprint",
		"addresses":   []any{"127.0.0.1:8443"},
	}}}
}

type staticOperation struct {
	op api.Operation
}

func (o staticOperation) AddHandler(func(api.Operation)) (*incus.EventTarget, error) { return nil, nil }
func (o staticOperation) Cancel() error                                              { return nil }
func (o staticOperation) Get() api.Operation                                         { return o.op }
func (o staticOperation) GetWebsocket(string) (*websocket.Conn, error)               { return nil, nil }
func (o staticOperation) RemoveHandler(*incus.EventTarget) error                     { return nil }
func (o staticOperation) Refresh() error                                             { return nil }
func (o staticOperation) Wait() error                                                { return nil }
func (o staticOperation) WaitContext(context.Context) error                          { return nil }

// #115 (admin plane): a restricted client entry with ZERO projects is a dead
// keypair — post-#113 every live device holds at least one project, and empty
// entries are exactly what a name-bucket grant used to silently re-arm. Grant
// must skip them and extend only the live same-named entries.
func TestTrustManagerGrantSkipsDeadEntries(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{
		{Fingerprint: "dead", CertificatePut: api.CertificatePut{Name: "sandcastle-alice", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{}}},
		{Fingerprint: "live", CertificatePut: api.CertificatePut{Name: "sandcastle-alice", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sc2-alice-default"}}},
	}}
	manager := TrustManager{Server: server}
	err := manager.Grant(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Restricted:      true,
		Projects:        []string{"sc2-acme", "sc2-acme-default"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(server.updatedFingerprints) != 1 || server.updatedFingerprints[0] != "live" {
		t.Fatalf("updated = %v, want [live] only", server.updatedFingerprints)
	}
}

// When EVERY same-named entry is dead, the grant must fail loudly with the
// reason — a silent no-op would report success while granting nothing.
func TestTrustManagerGrantAllDeadEntriesErrors(t *testing.T) {
	server := &fakeTrustServer{certificates: []api.Certificate{
		{Fingerprint: "dead1", CertificatePut: api.CertificatePut{Name: "sandcastle-alice", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{}}},
		{Fingerprint: "dead2", CertificatePut: api.CertificatePut{Name: "sandcastle-alice", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{}}},
	}}
	manager := TrustManager{Server: server}
	err := manager.Grant(context.Background(), usertrust.UserPlan{
		User:            "alice",
		CertificateName: "sandcastle-alice",
		Projects:        []string{"sc2-acme-default"},
	})
	if err == nil || !strings.Contains(err.Error(), "no projects") {
		t.Fatalf("expected an all-dead-entries error, got %v", err)
	}
	if len(server.updatedFingerprints) != 0 {
		t.Fatalf("updated = %v, want none", server.updatedFingerprints)
	}
}

func TestGrantTenantMemberFallsBackToTheMembersPersonalTenantHolder(t *testing.T) {
	// Shared client identity: skorfmann's login on a client thieso2 enrolled
	// first left ONE entry, named after thieso2, holding both personal tenants.
	server := &fakeTrustServer{certificates: []api.Certificate{
		{Fingerprint: "dead", CertificatePut: api.CertificatePut{Name: "sandcastle-sh-skorfmann", Type: api.CertificateTypeClient, Restricted: true}},
		{Fingerprint: "live", CertificatePut: api.CertificatePut{Name: "sandcastle-sh-thieso2", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sh-thieso2", "sh-thieso2-default", "sh-skorfmann", "sh-skorfmann-default"}}},
		{Fingerprint: "other", CertificatePut: api.CertificatePut{Name: "sandcastle-sh-mallory", Type: api.CertificateTypeClient, Restricted: true, Projects: []string{"sh-mallory"}}},
	}}
	manager := TrustManager{Server: server}
	plan := usertrust.UserPlan{User: "skorfmann", CertificateName: "sandcastle-sh-skorfmann", Projects: []string{"sh-moyn-dev", "sh-moyn-dev-default"}}
	if err := manager.GrantTenantMember(context.Background(), plan, "sh-skorfmann"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(server.updatedFingerprints, []string{"live"}) {
		t.Fatalf("updated = %v, want only the live holder (never the dead same-named entry, never another user's)", server.updatedFingerprints)
	}
	if !slices.Contains(server.updated.Projects, "sh-moyn-dev-default") || !slices.Contains(server.updated.Projects, "sh-skorfmann") {
		t.Fatalf("projects = %v", server.updated.Projects)
	}
	server.updatedFingerprints = nil
	if err := manager.RevokeTenantMember(context.Background(), plan, "sh-skorfmann"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(server.updatedFingerprints, []string{"live"}) || slices.Contains(server.updated.Projects, "sh-moyn-dev") {
		t.Fatalf("revoke updated = %v projects = %v", server.updatedFingerprints, server.updated.Projects)
	}
	// No live entry at all: a clear refusal naming the prerequisite.
	if err := manager.GrantTenantMember(context.Background(), usertrust.UserPlan{User: "nobody", CertificateName: "sandcastle-sh-nobody", Projects: plan.Projects}, "sh-nobody"); err == nil || !strings.Contains(err.Error(), "sc login") {
		t.Fatalf("err = %v", err)
	}
}
