package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/moyn-dev/sandcastle-incus/internal/authapp"
	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
)

func idempotentLoginAdminConfig() scconfig.Admin {
	return scconfig.Admin{
		Remote:       "sandcastle-octocat",
		Tenant:       "octocat",
		AuthHostname: "https://auth.example.com",
		AuthToken:    "cli-token",
	}
}

func TestLoginReusesExistingSession(t *testing.T) {
	useLoginHomeForTest(t)
	tenants := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "octocat", Personal: true}}}
	device := &fakeAuthDeviceClient{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:             "sandcastle",
		adminConfig:      idempotentLoginAdminConfig(),
		authTenants:      tenants,
		authDevice:       device,
		loginRemoteProbe: func(context.Context, string) error { return nil },
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`Already logged in at https://auth.example.com (tenant "octocat"); remote "sandcastle-octocat" responds.`,
		"Re-run with --force to re-authenticate.",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if tenants.listRequests != 1 {
		t.Fatalf("ListTenants calls = %d", tenants.listRequests)
	}
	if device.startCalls != 0 {
		t.Fatalf("device flow started %d times, want 0", device.startCalls)
	}
	if strings.Contains(stdout, "Open: ") {
		t.Fatalf("device flow output present:\n%s", stdout)
	}
}

func TestLoginForceBypassesExistingSession(t *testing.T) {
	useLoginHomeForTest(t)
	installer := &fakeLoginRemoteInstaller{}
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			UserKey:           "octocat",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		adminConfig: idempotentLoginAdminConfig(),
		authTenants: &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "octocat"}}},
		authDevice:  device,
		loginRemote: installer,
		loginRemoteProbe: func(context.Context, string) error {
			t.Fatal("probe must not run with --force")
			return nil
		},
	}, "login", "https://auth.example.com", "--force")
	if err != nil {
		t.Fatal(err)
	}
	if device.startCalls != 1 {
		t.Fatalf("device flow started %d times, want 1", device.startCalls)
	}
	if !strings.Contains(stdout, "Approved as octocat.") {
		t.Fatalf("stdout missing approval:\n%s", stdout)
	}
}

func TestLoginFallsBackWhenSavedTokenRejected(t *testing.T) {
	useLoginHomeForTest(t)
	installer := &fakeLoginRemoteInstaller{}
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			UserKey:           "octocat",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		adminConfig: idempotentLoginAdminConfig(),
		authTenants: &fakeAuthTenantClient{err: errors.New("403 token expired")},
		authDevice:  device,
		loginRemote: installer,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if device.startCalls != 1 {
		t.Fatalf("device flow started %d times, want 1", device.startCalls)
	}
	if strings.Contains(stdout, "Already logged in") {
		t.Fatalf("unexpected shortcut output:\n%s", stdout)
	}
}

func TestLoginRefusesWhenNotTailnetNode(t *testing.T) {
	useLoginHomeForTest(t)
	device := &fakeAuthDeviceClient{}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  device,
		loginRemote: &fakeLoginRemoteInstaller{}, // skip the host `incus` preflight
		loginTailnetPrecheck: func(context.Context) error {
			return errors.New("this machine is not a tailnet node")
		},
	}, "login", "https://auth.example.com")
	if err == nil || !strings.Contains(err.Error(), "not a tailnet node") {
		t.Fatalf("err = %v", err)
	}
	if device.startCalls != 0 {
		t.Fatalf("device flow started %d times, want 0 (refused before browser)", device.startCalls)
	}
}

func TestLoginSkipSetupBypassesTailnetPrecheck(t *testing.T) {
	useLoginHomeForTest(t)
	installer := &fakeLoginRemoteInstaller{}
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			UserKey:           "octocat",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  device,
		loginRemote: installer,
		loginTailnetPrecheck: func(context.Context) error {
			t.Fatal("precheck must not run with --skip-setup")
			return nil
		},
	}, "login", "https://auth.example.com", "--skip-setup")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Approved as octocat.") {
		t.Fatalf("stdout missing approval:\n%s", stdout)
	}
}

func TestLoginDifferentHostSkipsShortcut(t *testing.T) {
	useLoginHomeForTest(t)
	tenants := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "octocat"}}}
	installer := &fakeLoginRemoteInstaller{}
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://other.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			UserKey:           "octocat",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
		}},
	}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		adminConfig: idempotentLoginAdminConfig(),
		authTenants: tenants,
		authDevice:  device,
		loginRemote: installer,
	}, "login", "https://other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if tenants.listRequests != 0 {
		t.Fatalf("ListTenants calls = %d, want 0 (different host)", tenants.listRequests)
	}
	if device.startCalls != 1 {
		t.Fatalf("device flow started %d times, want 1", device.startCalls)
	}
}

func TestLoginWaitsForSidecarTailnetJoin(t *testing.T) {
	useLoginHomeForTest(t)
	installer := &fakeLoginRemoteInstaller{}
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{
			{
				Status:            authapp.DeviceStatusApproved,
				UserKey:           "octocat",
				Token:             "token",
				RemoteName:        "sandcastle-octocat",
				TenantPrivateCIDR: "10.250.0.0/24",
				TailscaleLoginURL: "https://login.tailscale.com/a/abc123",
				AccessibleTenants: []string{"octocat"},
			},
			{
				Status:             authapp.DeviceStatusApproved,
				UserKey:            "octocat",
				Token:              "token2",
				RemoteName:         "sandcastle-octocat",
				TenantPrivateCIDR:  "10.250.0.0/24",
				IncusRemoteAddress: "100.90.124.119",
				AccessibleTenants:  []string{"octocat"},
			},
		},
	}
	setup := &fakeLoginSetupRunner{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  device,
		loginRemote: installer,
		loginSetup:  setup,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://login.tailscale.com/a/abc123",
		"Waiting for the sidecar to join the tailnet...",
		`Remote "sandcastle-octocat" enrolled.`,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Count(stdout, "Approved as octocat.") != 1 {
		t.Fatalf("approval should print once:\n%s", stdout)
	}
	if len(device.pollRequests) < 2 || !device.pollRequests[1].AwaitingTailnet {
		t.Fatalf("second poll should set AwaitingTailnet: %#v", device.pollRequests)
	}
	if len(installer.requests) != 1 || installer.requests[0].IncusAddress != "100.90.124.119" {
		t.Fatalf("installer requests = %#v", installer.requests)
	}
}

// The interactive tailnet-join URL may only surface on a later awaiting poll
// (the first approved poll can return before the sidecar's `tailscale up` has
// printed one). The login must still show it to the user when it arrives.
func TestLoginPrintsLateTailnetJoinURL(t *testing.T) {
	useLoginHomeForTest(t)
	installer := &fakeLoginRemoteInstaller{}
	approved := authapp.DevicePollResult{
		Status:            authapp.DeviceStatusApproved,
		UserKey:           "octocat",
		Token:             "token",
		RemoteName:        "sandcastle-octocat",
		TenantPrivateCIDR: "10.250.0.0/24",
		AccessibleTenants: []string{"octocat"},
	}
	withURL := approved
	withURL.TailscaleLoginURL = "https://login.tailscale.com/a/late456"
	done := approved
	done.IncusRemoteAddress = "100.90.124.119"
	device := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{approved, withURL, done},
	}
	setup := &fakeLoginSetupRunner{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  device,
		loginRemote: installer,
		loginSetup:  setup,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "https://login.tailscale.com/a/late456") {
		t.Fatalf("stdout missing late join URL:\n%s", stdout)
	}
	if strings.Count(stdout, "Waiting for the sidecar to join the tailnet...") != 1 {
		t.Fatalf("waiting line should print once:\n%s", stdout)
	}
}
