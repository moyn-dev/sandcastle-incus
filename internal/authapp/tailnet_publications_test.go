package authapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

type fakeTailnetPublisher struct {
	ip  string
	got TailnetPublication
}

func (f *fakeTailnetPublisher) Publish(_ context.Context, p TailnetPublication) (string, error) {
	f.got = p
	return f.ip, nil
}

func (f *fakeTailnetPublisher) Unpublish(_ context.Context, p TailnetPublication) (string, error) {
	f.got = p
	return f.ip, nil
}

func TestTailnetPublicationIssuesCertificateAndPublishesDNSOnlyA(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	// The fake zone validator/token setup is shared with the Public DNS Zone tests.
	if err := AddPublicDNSZone(context.Background(), db, "tc42.uk", CloudflareZone{ID: "zone-id", Name: "tc42.uk"}, "token", "admin"); err != nil {
		t.Fatal(err)
	}
	publisher := &fakeTailnetPublisher{ip: "100.64.0.9"}
	issuer := &fakeCertIssuer{}
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"success":true,"result":[]}`))
			return
		}
		if r.Method == http.MethodPost {
			w.Write([]byte(`{"success":true,"result":{}}`))
			return
		}
		t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
	}))
	defer cfServer.Close()
	h := NewHandler(db, HandlerOptions{TailnetPublisher: publisher, TailnetIssuer: issuer, CloudflareBaseURL: cfServer.URL})
	if err := UpsertUser(context.Background(), db, User{UserKey: "alice", GitHubUsername: "alice", GitHubUsernameNormalized: "alice", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	token, err := CreateCLIToken(context.Background(), db, "alice", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/tailnet-publications", strings.NewReader(`{"tenant":"alice","project":"wordpress","machine":"dev","hostname":"app.tc42.uk"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if publisher.got.TargetPort != 443 || publisher.got.Hostname != "app.tc42.uk" {
		t.Fatalf("publisher got %#v", publisher.got)
	}
	if len(issuer.calls) != 1 || issuer.calls[0].Zone != "tc42.uk" {
		t.Fatalf("issuer calls %#v", issuer.calls)
	}
}
