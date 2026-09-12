package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

type stubMachineCertificateClient struct {
	view     authapp.MachineCertificateView
	err      error
	requests []authapp.MachineCertificateRequest
}

func (s *stubMachineCertificateClient) RequestMachineCertificate(_ context.Context, request authapp.MachineCertificateRequest) (authapp.MachineCertificateView, error) {
	s.requests = append(s.requests, request)
	return s.view, s.err
}

func TestZoneModePublicHostname(t *testing.T) {
	summary := tenant.Summary{Tenant: "acme", Projects: []meta.Project{
		{Name: "default"},
		{Name: "baum", Domain: "Baum.hase.de."},
	}}
	if got := zoneModePublicHostname(summary, "baum", "Web"); got != "web.baum.hase.de" {
		t.Fatalf("zone project = %q", got)
	}
	if got := zoneModePublicHostname(summary, "default", "web"); got != "" {
		t.Fatalf("private project = %q, want empty", got)
	}
	if got := zoneModePublicHostname(summary, "nosuch", "web"); got != "" {
		t.Fatalf("unknown project = %q, want empty", got)
	}
}

func TestRequestMachineCertificateOutcomes(t *testing.T) {
	stub := &stubMachineCertificateClient{view: authapp.MachineCertificateView{Hostname: "web.baum.hase.de", State: "pending"}}
	config := commandConfig{authMachineCertificates: stub}
	outcome := requestMachineCertificate(context.Background(), config, "acme", "baum", "web")
	if outcome.State != "pending" || outcome.Reason != "" {
		t.Fatalf("outcome = %+v", outcome)
	}
	if len(stub.requests) != 1 || stub.requests[0] != (authapp.MachineCertificateRequest{Tenant: "acme", Project: "baum", Machine: "web"}) {
		t.Fatalf("requests = %+v", stub.requests)
	}

	stub.view = authapp.MachineCertificateView{State: "pending", Reason: "rate-limited", Error: "rate-limited — zone hase.de has used its 50 certificates"}
	outcome = requestMachineCertificate(context.Background(), config, "acme", "baum", "web")
	if outcome.Reason != "rate-limited" || outcome.Message == "" {
		t.Fatalf("rate-limited outcome = %+v", outcome)
	}

	stub.err = errors.New("dial tcp: connection refused")
	outcome = requestMachineCertificate(context.Background(), config, "acme", "baum", "web")
	if outcome.Reason != "auth-app-unreachable" {
		t.Fatalf("unreachable outcome = %+v", outcome)
	}

	// No client, no login: unreachable, never an error.
	outcome = requestMachineCertificate(context.Background(), commandConfig{}, "acme", "baum", "web")
	if outcome.Reason != "auth-app-unreachable" {
		t.Fatalf("no-login outcome = %+v", outcome)
	}
}

func TestFormatPublicNameLine(t *testing.T) {
	cases := []struct {
		name     string
		devImage bool
		outcome  machineCertificateOutcome
		want     string
	}{
		{"pending", false, machineCertificateOutcome{State: "pending"},
			"Public name: web.baum.hase.de (A record pending, certificate pending — see: sc project status baum)"},
		{"unreachable", false, machineCertificateOutcome{Reason: "auth-app-unreachable", Message: "timed out"},
			"Public name: web.baum.hase.de (A record pending, certificate pending: Auth App unreachable — retried by the reconciler)"},
		{"rate-limited", false, machineCertificateOutcome{State: "pending", Reason: "rate-limited", Message: "too many certificates (50) already issued"},
			"Public name: web.baum.hase.de (A record pending, certificate pending: rate-limited — too many certificates (50) already issued)"},
		{"retained", false, machineCertificateOutcome{State: "issued"},
			"Public name: web.baum.hase.de (A record pending, certificate retained, installing — see: sc project status baum)"},
		{"dev image", true, machineCertificateOutcome{},
			"Public name: web.baum.hase.de (A record pending; no Caddy — no certificate)"},
	}
	for _, tc := range cases {
		if got := formatPublicNameLine("web.baum.hase.de", "baum", tc.devImage, tc.outcome); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}
