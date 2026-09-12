package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// Public DNS Zones (ADR-0027, spec §2.3 / §3.4): after a zone-mode machine
// exists, `sc create` asks the Auth App to order its Machine Certificate. The
// call never blocks the create for long and never fails it — every outcome
// becomes a parenthesised detail on the "Public name:" line, and the
// reconciler retries whatever the Auth App could not take right now.

// authMachineCertificateClient is the seam `sc create` uses to reach
// POST /api/machine-certificates; authapp.DeviceClient satisfies it.
type authMachineCertificateClient interface {
	RequestMachineCertificate(context.Context, authapp.MachineCertificateRequest) (authapp.MachineCertificateView, error)
}

var _ authMachineCertificateClient = authapp.DeviceClient{}

// machineCertificateRequestTimeout bounds the create-time call; the
// reconciler owns everything slower than this.
const machineCertificateRequestTimeout = 5 * time.Second

// machineCertificateOutcome is what the create-time request produced.
type machineCertificateOutcome struct {
	// State is the Machine Certificate state the Auth App reported
	// ("pending", or "issued" when a retained certificate is reused).
	State string
	// Reason is the fixed-vocabulary failure reason when the Auth App
	// accepted the row but cannot order now ("rate-limited"), or
	// "auth-app-unreachable" when the call itself failed.
	Reason string
	// Message is the Auth App's human-readable explanation for Reason.
	Message string
}

// zoneModePublicHostname returns the Machine Public Hostname `sc create` is
// about to give a machine — <machine>.<Project Domain> — or "" for a
// private-mode project (no Project Domain in tenant.Summary).
func zoneModePublicHostname(summary tenant.Summary, project, machine string) string {
	for _, entry := range summary.Projects {
		if entry.Name != project {
			continue
		}
		if domain := strings.Trim(strings.TrimSpace(entry.Domain), "."); domain != "" {
			return strings.ToLower(machine + "." + domain)
		}
	}
	return ""
}

// requestMachineCertificate asks the Auth App to record the Machine
// Certificate order for publicHostname (spec §3.4). Call it only for a
// zone-mode machine that exists and is not a Dev Image machine. Errors are
// folded into the outcome, never returned: the machine is created either way.
func requestMachineCertificate(ctx context.Context, config commandConfig, tenantName, project, machine string) machineCertificateOutcome {
	client := config.authMachineCertificates
	if client == nil {
		baseURL := commandAuthHostname(config, "")
		token := strings.TrimSpace(config.adminConfig.AuthToken)
		if baseURL == "" || token == "" {
			return machineCertificateOutcome{Reason: "auth-app-unreachable", Message: "not logged in to an Auth App (run sc login)"}
		}
		client = authapp.DeviceClient{BaseURL: baseURL, AuthToken: token}
	}
	ctx, cancel := context.WithTimeout(ctx, machineCertificateRequestTimeout)
	defer cancel()
	view, err := client.RequestMachineCertificate(ctx, authapp.MachineCertificateRequest{Tenant: tenantName, Project: project, Machine: machine})
	if err != nil {
		message := err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			message = "timed out"
		}
		return machineCertificateOutcome{Reason: "auth-app-unreachable", Message: message}
	}
	return machineCertificateOutcome{State: view.State, Reason: view.Reason, Message: view.Error}
}

// formatPublicNameLine renders spec §2.3's "Public name:" line for a
// zone-mode machine from the create-time outcome.
func formatPublicNameLine(publicHostname, project string, devImage bool, outcome machineCertificateOutcome) string {
	if devImage {
		return fmt.Sprintf("Public name: %s (A record pending; no Caddy — no certificate)", publicHostname)
	}
	detail := fmt.Sprintf("certificate pending — see: sc project status %s", project)
	switch {
	case outcome.Reason == "auth-app-unreachable":
		detail = "certificate pending: Auth App unreachable — retried by the reconciler"
	case outcome.Reason != "":
		detail = "certificate pending: " + outcome.Reason
		if message := strings.TrimSpace(outcome.Message); message != "" {
			detail += " — " + message
		}
	case outcome.State == "issued":
		detail = fmt.Sprintf("certificate retained, installing — see: sc project status %s", project)
	}
	return fmt.Sprintf("Public name: %s (A record pending, %s)", publicHostname, detail)
}
