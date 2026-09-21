package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/dns"
	"github.com/thieso2/sandcastle-incus/internal/domain"
	"github.com/thieso2/sandcastle-incus/internal/images"
	"github.com/thieso2/sandcastle-incus/internal/localdns"
	"github.com/thieso2/sandcastle-incus/internal/localtrust"
	machine "github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/share"
	"github.com/thieso2/sandcastle-incus/internal/tailscale"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

func executeForTest(t *testing.T, name string, args ...string) (string, error) {
	return executeForTestWithConfig(t, commandConfig{name: name}, args...)
}

func envContains(env []string, value string) bool {
	for _, entry := range env {
		if entry == value {
			return true
		}
	}
	return false
}

func executeForTestWithConfig(t *testing.T, config commandConfig, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeForTestWithConfigAndStderr(t, config, args...)
	if rest := stripLoginProgressLines(stderr); rest != "" {
		t.Fatalf("unexpected stderr: %s", rest)
	}
	return stdout, err
}

// stripLoginProgressLines drops the always-on login step/heartbeat progress
// lines so the helpers still catch genuinely unexpected stderr.
func stripLoginProgressLines(stderr string) string {
	var kept []string
	for _, line := range strings.Split(stderr, "\n") {
		if line == "" ||
			strings.HasPrefix(line, "login: ") ||
			strings.HasPrefix(line, "login setup: ") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func executeForTestWithConfigAndStderr(t *testing.T, config commandConfig, args ...string) (string, string, error) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	config.stdout = &stdout
	config.stderr = &stderr
	if config.adminConfig.Remote == "" {
		config.adminConfig = testAdminConfig()
	}
	if config.loginTailnetPrecheck == nil {
		// The real precheck shells out to tailscale, which test environments
		// don't have; tests exercising the refusal inject their own.
		config.loginTailnetPrecheck = func(context.Context) error { return nil }
	}
	if config.loginRoutingCheck == nil {
		config.loginRoutingCheck = func(context.Context, io.Writer, string) error { return nil }
	}
	cmd := NewRootCommand(config)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func executeAdminForTest(t *testing.T, name string, args ...string) (string, error) {
	return executeAdminForTestWithConfig(t, commandConfig{name: name}, args...)
}

func executeAdminForTestWithConfig(t *testing.T, config commandConfig, args ...string) (string, error) {
	t.Helper()
	stdout, stderr, err := executeAdminForTestWithConfigAndStderr(t, config, args...)
	if stderr != "" {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
	return stdout, err
}

func executeAdminForTestWithConfigAndStderr(t *testing.T, config commandConfig, args ...string) (string, string, error) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	config.stdout = &stdout
	config.stderr = &stderr
	if config.adminConfig.Remote == "" {
		config.adminConfig = testAdminConfig()
	}
	cmd := NewAdminRootCommand(config)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func testAdminConfig() scconfig.Admin {
	admin := scconfig.LoadAdminFromEnv()
	if admin.Tenant == "" {
		admin.Tenant = "acme"
	}
	return admin
}

type fakeAuthDeviceClient struct {
	start            authapp.DeviceStartResult
	startCalls       int
	polls            []authapp.DevicePollResult
	polledDeviceCode string
	pollRequests     []authapp.DevicePollRequest
}

type fakeAuthWorkloadClient struct {
	start          authapp.DeviceStartResult
	starts         int
	polls          []authapp.DevicePollResult
	enableRequests []authapp.WorkloadEnableRequest
	enableResult   authapp.WorkloadEnableResult
}

type fakeAuthCloudIdentityClient struct {
	upsertRequests []authapp.CloudIdentityUpsertRequest
	upsertResult   authapp.CloudIdentityConfig
	getRequests    []struct {
		tenant string
		name   string
	}
	getResult authapp.CloudIdentityConfig
	getErr    error
}

type fakeAuthTenantClient struct {
	listRequests int
	tenants      []authapp.TenantAccessSummary
	err          error
}

type fakeAuthShareClient struct {
	createRequests    []authapp.ShareCreateRequest
	createResult      share.Result
	shares            []meta.TenantStorageShare
	inboundShares     []meta.TenantStorageShare
	offers            []meta.TenantStorageShare
	statusRequests    []authapp.ShareStatusRequest
	acceptRequests    []authapp.ShareRecipientRequest
	declineRequests   []authapp.ShareRecipientRequest
	revokeRequests    []authapp.ShareRevokeRequest
	deleteRequests    []authapp.ShareDeleteRequest
	reconcileRequests []authapp.ShareReconcileRequest
	reconcileResult   share.ReconcileResult
}

type fakeLoginRemoteInstaller struct {
	requests []loginRemoteInstallRequest
}

type fakeLoginTailnetVerifier struct {
	requests []string
	status   loginTailnetStatus
	err      error
}

type fakeLoginSetupRunner struct {
	requests []loginSetupRequest
	result   loginSetupResult
}

type fakeGCloudRunner struct {
	calls         [][]string
	projectNumber string
	existing      map[string]bool
}

func (r *fakeGCloudRunner) run(_ context.Context, args []string, _ io.Writer) (string, error) {
	copied := append([]string{}, args...)
	r.calls = append(r.calls, copied)
	if r.projectNumber == "" {
		r.projectNumber = "123456789012"
	}
	if len(args) == 3 && args[0] == "config" && args[1] == "get-value" && args[2] == "project" {
		return "example-gcp", nil
	}
	if len(args) == 4 && args[0] == "projects" && args[1] == "describe" && args[3] == "--format=value(projectNumber)" {
		return r.projectNumber, nil
	}
	if containsArg(args, "describe") {
		if r.existing != nil && r.existing[strings.Join(args, "\x00")] {
			return "", nil
		}
		return "", fmt.Errorf("not found")
	}
	return "", nil
}

func (r *fakeGCloudRunner) hasCall(want ...string) bool {
	for _, call := range r.calls {
		if len(call) != len(want) {
			continue
		}
		matches := true
		for i := range call {
			if call[i] != want[i] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func (r *fakeGCloudRunner) hasCallContaining(fragment string) bool {
	for _, call := range r.calls {
		if strings.Contains(strings.Join(call, " "), fragment) {
			return true
		}
	}
	return false
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func (i *fakeLoginRemoteInstaller) InstallLoginRemote(ctx context.Context, request loginRemoteInstallRequest) (loginRemoteInstallResult, error) {
	i.requests = append(i.requests, request)
	return loginRemoteInstallResult{RemoteName: request.RemoteName, Tenant: request.Tenant, IncusConfig: "/tmp/incus"}, nil
}

func (v *fakeLoginTailnetVerifier) VerifyTenantTailnet(ctx context.Context, tailnet string) (loginTailnetStatus, error) {
	v.requests = append(v.requests, tailnet)
	if v.err != nil {
		return loginTailnetStatus{}, v.err
	}
	return v.status, nil
}

func (r *fakeLoginSetupRunner) RunPostLoginSetup(ctx context.Context, request loginSetupRequest) (loginSetupResult, error) {
	r.requests = append(r.requests, request)
	if r.result.DNS.Reference == "" {
		r.result.DNS = dnsSetupResult{
			Reference: request.Tenant,
			Apply:     dns.ApplyResult{RecordCount: 2},
			Install:   localdns.Result{StatePath: "/tmp/dns.yaml", ResolverPath: "/tmp/resolver"},
		}
	}
	if r.result.Trust.Reference == "" {
		r.result.Trust = localtrust.Result{
			Reference: request.Tenant,
			Action:    "install",
			Target:    "/tmp/trust",
		}
	}
	if r.result.Tailscale.Reference == "" {
		r.result.Tailscale = tailscale.UpPlan{
			Reference:       request.Tenant,
			InstanceName:    "sc-" + request.Tenant,
			AdvertiseRoutes: []string{"10.248.0.0/24"},
			HasAuthKey:      request.TailscaleAuthKey != "",
		}
	}
	return r.result, nil
}

func (c *fakeAuthDeviceClient) Start(ctx context.Context) (authapp.DeviceStartResult, error) {
	c.startCalls++
	return c.start, nil
}

func (c *fakeAuthDeviceClient) Poll(ctx context.Context, deviceCode string, request authapp.DevicePollRequest) (authapp.DevicePollResult, error) {
	c.polledDeviceCode = deviceCode
	c.pollRequests = append(c.pollRequests, request)
	if len(c.polls) == 0 {
		return authapp.DevicePollResult{Status: authapp.DeviceStatusExpired}, nil
	}
	next := c.polls[0]
	c.polls = c.polls[1:]
	return next, nil
}

func (c *fakeAuthDeviceClient) DebugApprove(ctx context.Context, userCode string) error {
	return nil
}

func (c *fakeAuthDeviceClient) SimulateApprove(ctx context.Context, userCode, username, token string) error {
	return nil
}

func (c *fakeAuthWorkloadClient) Start(ctx context.Context) (authapp.DeviceStartResult, error) {
	c.starts++
	if c.start.DeviceCode == "" {
		c.start = authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1}
	}
	return c.start, nil
}

func (c *fakeAuthWorkloadClient) Poll(ctx context.Context, deviceCode string, request authapp.DevicePollRequest) (authapp.DevicePollResult, error) {
	if len(c.polls) == 0 {
		return authapp.DevicePollResult{Status: authapp.DeviceStatusApproved, UserKey: "acme"}, nil
	}
	result := c.polls[0]
	c.polls = c.polls[1:]
	return result, nil
}

func (c *fakeAuthWorkloadClient) DebugApprove(ctx context.Context, userCode string) error {
	return nil
}

func (c *fakeAuthWorkloadClient) EnableWorkload(ctx context.Context, request authapp.WorkloadEnableRequest) (authapp.WorkloadEnableResult, error) {
	c.enableRequests = append(c.enableRequests, request)
	if c.enableResult.RuntimeSecret == "" {
		c.enableResult = authapp.WorkloadEnableResult{
			Tenant:                            request.Tenant,
			Project:                           request.Project,
			Machine:                           request.Machine,
			RuntimeSecret:                     "runtime-secret",
			TokenEndpoint:                     "https://auth.example.com/internal/workload/token",
			Issuer:                            "https://auth.example.com/t/" + request.Tenant,
			CloudIdentityConfig:               request.CloudIdentityConfig,
			GCPAudience:                       "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/sandcastle-" + request.Tenant + "/providers/sandcastle",
			GCPServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@example.iam.gserviceaccount.com:generateAccessToken",
		}
	}
	return c.enableResult, nil
}

func (c *fakeAuthCloudIdentityClient) UpsertCloudIdentity(ctx context.Context, request authapp.CloudIdentityUpsertRequest) (authapp.CloudIdentityConfig, error) {
	c.upsertRequests = append(c.upsertRequests, request)
	if c.upsertResult.Name == "" {
		c.upsertResult = authapp.CloudIdentityConfig{
			Tenant:                            request.Tenant,
			Name:                              request.Name,
			Provider:                          request.Provider,
			GCPAudience:                       request.GCPAudience,
			GCPSubjectTokenType:               request.GCPSubjectTokenType,
			GCPServiceAccountImpersonationURL: request.GCPServiceAccountImpersonationURL,
		}
	}
	return c.upsertResult, nil
}

func (c *fakeAuthCloudIdentityClient) GetCloudIdentity(ctx context.Context, tenant string, name string) (authapp.CloudIdentityConfig, error) {
	c.getRequests = append(c.getRequests, struct {
		tenant string
		name   string
	}{tenant: tenant, name: name})
	if c.getErr != nil {
		return authapp.CloudIdentityConfig{}, c.getErr
	}
	if c.getResult.Name == "" {
		c.getResult = authapp.CloudIdentityConfig{
			Tenant:   tenant,
			Name:     name,
			Provider: "gcp",
		}
	}
	return c.getResult, nil
}

func (c *fakeAuthTenantClient) ListTenants(ctx context.Context) ([]authapp.TenantAccessSummary, error) {
	c.listRequests++
	if c.err != nil {
		return nil, c.err
	}
	return append([]authapp.TenantAccessSummary{}, c.tenants...), nil
}

func (c *fakeAuthShareClient) CreateShare(ctx context.Context, request authapp.ShareCreateRequest) (share.Result, error) {
	c.createRequests = append(c.createRequests, request)
	if c.createResult.Share.Name == "" {
		c.createResult = share.Result{
			Share:  meta.TenantStorageShare{SourceTenant: request.SourceTenant, SourceProject: "default", SourceDir: "docs", Name: "docs", Availability: "available"},
			DryRun: request.DryRun,
		}
	}
	return c.createResult, nil
}

func (c *fakeAuthShareClient) ListShares(ctx context.Context, tenant string) ([]meta.TenantStorageShare, error) {
	return append([]meta.TenantStorageShare{}, c.shares...), nil
}

func (c *fakeAuthShareClient) ListInboundShares(ctx context.Context, tenant string) ([]meta.TenantStorageShare, error) {
	return append([]meta.TenantStorageShare{}, c.inboundShares...), nil
}

func (c *fakeAuthShareClient) ListShareOffers(ctx context.Context, tenant string) ([]meta.TenantStorageShare, error) {
	return append([]meta.TenantStorageShare{}, c.offers...), nil
}

func (c *fakeAuthShareClient) GetShare(ctx context.Context, request authapp.ShareStatusRequest) (share.Result, error) {
	c.statusRequests = append(c.statusRequests, request)
	for _, storageShare := range c.shares {
		if !request.Inbound && storageShare.SourceProject == request.Project && storageShare.Name == request.Name {
			return c.shareStatusResult(request, storageShare), nil
		}
	}
	for _, storageShare := range c.inboundShares {
		if request.Inbound && storageShare.SourceTenant == request.SourceTenant && storageShare.SourceProject == request.Project && storageShare.Name == request.Name {
			return c.shareStatusResult(request, storageShare), nil
		}
	}
	return share.Result{}, fmt.Errorf("not found")
}

func (c *fakeAuthShareClient) shareStatusResult(request authapp.ShareStatusRequest, storageShare meta.TenantStorageShare) share.Result {
	result := share.Result{Share: storageShare}
	if len(c.reconcileResult.Machines) > 0 {
		result.Reconcile = &c.reconcileResult
	}
	return result
}

func (c *fakeAuthShareClient) AcceptShare(ctx context.Context, request authapp.ShareRecipientRequest) (share.Result, error) {
	c.acceptRequests = append(c.acceptRequests, request)
	return share.Result{Share: meta.TenantStorageShare{
		SourceTenant:  request.SourceTenant,
		SourceProject: request.SourceProject,
		SourceDir:     "docs",
		Name:          request.Name,
		Availability:  "available",
		Recipients: []meta.TenantStorageShareRecipient{{
			Tenant: request.Tenant,
			State:  "accepted",
		}},
	}}, nil
}

func (c *fakeAuthShareClient) DeclineShare(ctx context.Context, request authapp.ShareRecipientRequest) (share.Result, error) {
	c.declineRequests = append(c.declineRequests, request)
	return share.Result{Share: meta.TenantStorageShare{
		SourceTenant:  request.SourceTenant,
		SourceProject: request.SourceProject,
		SourceDir:     "docs",
		Name:          request.Name,
		Availability:  "available",
		Recipients: []meta.TenantStorageShareRecipient{{
			Tenant: request.Tenant,
			State:  "declined",
		}},
	}}, nil
}

func (c *fakeAuthShareClient) RevokeShare(ctx context.Context, request authapp.ShareRevokeRequest) (share.Result, error) {
	c.revokeRequests = append(c.revokeRequests, request)
	return share.Result{Share: meta.TenantStorageShare{
		SourceTenant:  request.Tenant,
		SourceProject: request.Project,
		SourceDir:     "docs",
		Name:          request.Name,
		Availability:  "available",
		Recipients: []meta.TenantStorageShareRecipient{{
			Tenant: "other",
			State:  "pending",
		}},
	}, Reconciles: []share.ReconcileResult{c.reconcileResult}}, nil
}

func (c *fakeAuthShareClient) DeleteShare(ctx context.Context, request authapp.ShareDeleteRequest) (share.Result, error) {
	c.deleteRequests = append(c.deleteRequests, request)
	return share.Result{Share: meta.TenantStorageShare{
		SourceTenant:  request.Tenant,
		SourceProject: request.Project,
		SourceDir:     "docs",
		Name:          request.Name,
		Availability:  "available",
	}, Reconciles: []share.ReconcileResult{c.reconcileResult}}, nil
}

func (c *fakeAuthShareClient) ReconcileShares(ctx context.Context, request authapp.ShareReconcileRequest) (share.ReconcileResult, error) {
	c.reconcileRequests = append(c.reconcileRequests, request)
	return c.reconcileResult, nil
}

func TestVersionText(t *testing.T) {
	stdout, err := executeForTest(t, "sandcastle", "version")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout); got != version {
		t.Fatalf("version output = %q, want %q", got, version)
	}
}

func TestVersionJSONUsesBinaryName(t *testing.T) {
	stdout, err := executeForTest(t, "sc", "--output", "json", "version")
	if err != nil {
		t.Fatal(err)
	}
	var payload versionPayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Name != "sc" {
		t.Fatalf("payload.Name = %q, want sc", payload.Name)
	}
	if payload.Version != version {
		t.Fatalf("payload.Version = %q, want %q", payload.Version, version)
	}
}

func TestJSONFlagUsesJSONOutput(t *testing.T) {
	stdout, err := executeForTest(t, "sandcastle", "--json", "version")
	if err != nil {
		t.Fatal(err)
	}
	var payload versionPayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Name != "sandcastle" {
		t.Fatalf("payload.Name = %q, want sandcastle", payload.Name)
	}
}

func TestJSONFlagRejectsExplicitTextOutput(t *testing.T) {
	_, err := executeForTest(t, "sandcastle", "--json", "--output", "text", "version")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--json") {
		t.Fatalf("error = %q", err)
	}
}

func TestLoginStartsDeviceFlowAndReportsApproval(t *testing.T) {
	useLoginHomeForTest(t)
	t.Setenv("USER", "loginuser")
	installer := &fakeLoginRemoteInstaller{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{
			DeviceCode:      "device",
			UserCode:        "ABCD-1234",
			VerificationURI: "https://auth.example.com/device?user_code=ABCD-1234",
			Interval:        1,
			Message:         "Waiting for browser approval.",
		},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			Message:           "Personal tenant octocat is ready.",
			UserKey:           "octocat",
			CLIAuthToken:      "cli-token",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  client,
		loginRemote: installer,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SSH key: SHA256:",
		"Open: https://auth.example.com/device?user_code=ABCD-1234",
		"Code: ABCD-1234",
		"Approved as octocat.",
		"Remote \"sandcastle-octocat\" enrolled.",
		"Default tenant set to \"octocat\".",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if client.polledDeviceCode != "device" {
		t.Fatalf("polled device code = %q", client.polledDeviceCode)
	}
	if len(client.pollRequests) != 1 || !strings.HasPrefix(client.pollRequests[0].SSHPublicKey, "ssh-ed25519 ") || client.pollRequests[0].LocalUnixUser != "loginuser" {
		t.Fatalf("poll requests = %#v", client.pollRequests)
	}
	if len(installer.requests) != 1 || installer.requests[0].Token != "token" || installer.requests[0].Tenant != "octocat" {
		t.Fatalf("installer requests = %#v", installer.requests)
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthHostname != "https://auth.example.com" {
		t.Fatalf("AuthHostname = %q", cfg.AuthHostname)
	}
	if cfg.AuthToken != "cli-token" {
		t.Fatalf("AuthToken = %q", cfg.AuthToken)
	}
}

func TestLoginDoesNotRepeatUnchangedDeviceMessage(t *testing.T) {
	useLoginHomeForTest(t)
	installer := &fakeLoginRemoteInstaller{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{
			DeviceCode:      "device",
			UserCode:        "ABCD-1234",
			VerificationURI: "https://auth.example.com/device?user_code=ABCD-1234",
			Interval:        1,
			Message:         "Waiting for browser approval.",
		},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			Message:           "Waiting for browser approval.",
			UserKey:           "octocat",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  client,
		loginRemote: installer,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(stdout, "Waiting for browser approval.") != 1 {
		t.Fatalf("stdout repeated device message:\n%s", stdout)
	}
}

func TestLoginVerboseReportsPollResult(t *testing.T) {
	useLoginHomeForTest(t)
	t.Setenv("VERBOSE", "1")
	installer := &fakeLoginRemoteInstaller{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{
			DeviceCode:      "device",
			UserCode:        "ABCD-1234",
			VerificationURI: "https://auth.example.com/device?user_code=ABCD-1234",
			Interval:        1,
			ExpiresIn:       600,
		},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			Message:           "Personal tenant octocat is ready.",
			UserKey:           "octocat",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
			ExpiresIn:         590,
		}},
	}
	_, stderr, err := executeForTestWithConfigAndStderr(t, commandConfig{
		name:        "sandcastle",
		authDevice:  client,
		loginRemote: installer,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[verbose] login: auth host=https://auth.example.com",
		"[verbose] login: device start: interval=1s expires_in=600s",
		"[verbose] login: poll result: status=approved expires_in=590s user=octocat remote=sandcastle-octocat tenants=octocat",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "poll attempt=") {
		t.Fatalf("stderr should not contain poll attempt lines:\n%s", stderr)
	}
	if strings.Contains(stderr, "token") {
		t.Fatalf("stderr leaked token:\n%s", stderr)
	}
}

func TestLoginRunsPostSetupForSingleTenant(t *testing.T) {
	installer := &fakeLoginRemoteInstaller{}
	setup := &fakeLoginSetupRunner{}
	client := &fakeAuthDeviceClient{
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
		authDevice:  client,
		loginRemote: installer,
		loginSetup:  setup,
	}, "login", "https://auth.example.com", "--tailscale-auth-key", "tskey-secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(setup.requests) != 1 {
		t.Fatalf("setup requests = %#v", setup.requests)
	}
	request := setup.requests[0]
	if request.RemoteName != "sandcastle-octocat" || request.IncusConfig != "/tmp/incus" || request.Tenant != "octocat" || request.TailscaleAuthKey != "tskey-secret" {
		t.Fatalf("setup request = %#v", request)
	}
	for _, want := range []string{
		"Setting up DNS, trust, and Tailscale for \"octocat\".",
		"DNS setup: octocat",
		"install tenant CA trust: octocat",
		"Tailscale: octocat",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "tskey-secret") {
		t.Fatalf("stdout leaked auth key: %s", stdout)
	}
}

func TestLoginUsesE2ETailscaleAuthKeyFallback(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E_TAILSCALE_AUTHKEY", "tskey-e2e")
	installer := &fakeLoginRemoteInstaller{}
	setup := &fakeLoginSetupRunner{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
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
		authDevice:  client,
		loginRemote: installer,
		loginSetup:  setup,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(setup.requests) != 1 || setup.requests[0].TailscaleAuthKey != "tskey-e2e" {
		t.Fatalf("setup requests = %#v", setup.requests)
	}
}

func TestLoginUsesAuthAppTailscaleAuthKeyBeforeEnvFallback(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E_TAILSCALE_AUTHKEY", "tskey-e2e")
	installer := &fakeLoginRemoteInstaller{}
	setup := &fakeLoginSetupRunner{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			UserKey:           "octocat",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
			TailscaleAuthKey:  "tskey-server",
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  client,
		loginRemote: installer,
		loginSetup:  setup,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(setup.requests) != 1 || setup.requests[0].TailscaleAuthKey != "tskey-server" {
		t.Fatalf("setup requests = %#v", setup.requests)
	}
	if strings.Contains(stdout, "tskey-server") {
		t.Fatalf("stdout leaked auth key: %s", stdout)
	}
}

func TestLoginSetupIncusConfigPaths(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "incus")
	file := filepath.Join(dir, "config.yml")
	if got := loginSetupIncusDir(dir); got != dir {
		t.Fatalf("loginSetupIncusDir(dir) = %q, want %q", got, dir)
	}
	if got := loginSetupIncusConfigFile(dir); got != file {
		t.Fatalf("loginSetupIncusConfigFile(dir) = %q, want %q", got, file)
	}
	if got := loginSetupIncusDir(file); got != dir {
		t.Fatalf("loginSetupIncusDir(file) = %q, want %q", got, dir)
	}
	if got := loginSetupIncusConfigFile(file); got != file {
		t.Fatalf("loginSetupIncusConfigFile(file) = %q, want %q", got, file)
	}
}

func TestLoginSkipSetupDoesNotRunPostSetup(t *testing.T) {
	installer := &fakeLoginRemoteInstaller{}
	setup := &fakeLoginSetupRunner{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
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
		authDevice:  client,
		loginRemote: installer,
		loginSetup:  setup,
	}, "login", "https://auth.example.com", "--skip-setup")
	if err != nil {
		t.Fatal(err)
	}
	if len(setup.requests) != 0 {
		t.Fatalf("setup requests = %#v", setup.requests)
	}
}

func TestLoginDoesNotSetTenantWhenNoAccessibleTenants(t *testing.T) {
	useLoginHomeForTest(t)
	installer := &fakeLoginRemoteInstaller{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:     authapp.DeviceStatusApproved,
			UserKey:    "octocat",
			Token:      "token",
			RemoteName: "sandcastle-octocat",
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  client,
		loginRemote: installer,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(installer.requests) != 1 || installer.requests[0].Tenant != "" {
		t.Fatalf("installer requests = %#v", installer.requests)
	}
	if !strings.Contains(stdout, "No default tenant set; no accessible tenants were returned.") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestLoginVerifiesTenantTailnetFromLoginResult(t *testing.T) {
	useLoginHomeForTest(t)
	installer := &fakeLoginRemoteInstaller{}
	verifier := &fakeLoginTailnetVerifier{status: loginTailnetStatus{Tailnet: "tailnet.example", IPs: []string{"100.64.0.10"}}}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			UserKey:           "octocat",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
			LoginResult: &authapp.CLILoginResult{
				TenantTailnetStatus: authapp.TenantTailnetStatus{Tailnet: "tailnet.example"},
			},
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		authDevice:   client,
		loginRemote:  installer,
		loginTailnet: verifier,
	}, "login", "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier.requests) != 1 || verifier.requests[0] != "tailnet.example" {
		t.Fatalf("verifier requests = %#v", verifier.requests)
	}
	for _, want := range []string{
		"Join Tenant Tailnet \"tailnet.example\"",
		"Tenant Tailnet \"tailnet.example\" connected with IP 100.64.0.10.",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestLoginReportsDeniedDeviceFlow(t *testing.T) {
	useLoginHomeForTest(t)
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status: authapp.DeviceStatusDenied,
		}},
	}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:       "sandcastle",
		authDevice: client,
	}, "login", "https://auth.example.com")
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoginAcceptsExplicitSSHPublicKeyPath(t *testing.T) {
	useLoginHomeForTest(t)
	keyPath := filepath.Join(t.TempDir(), "login.pub")
	if err := os.WriteFile(keyPath, []byte(validAuthorizedKeyForTest(t)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status: authapp.DeviceStatusApproved,
		}},
	}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:       "sandcastle",
		authDevice: client,
	}, "login", "--ssh-public-key", keyPath, "https://auth.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "SSH key: SHA256:") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestLoginRejectsInvalidExplicitSSHPublicKeyPath(t *testing.T) {
	useLoginHomeForTest(t)
	keyPath := filepath.Join(t.TempDir(), "login.pub")
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 not-base64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
	}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:       "sandcastle",
		authDevice: client,
	}, "login", "--ssh-public-key", keyPath, "https://auth.example.com")
	if err == nil || !strings.Contains(err.Error(), "parse SSH public key") {
		t.Fatalf("error = %v", err)
	}
	if client.polledDeviceCode != "" {
		t.Fatalf("device flow started after invalid SSH key: %q", client.polledDeviceCode)
	}
}

func TestConfigUnsetClearsStoredValue(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant:      "acme",
		Project:     "website",
		Remote:      "sc-acme",
		AdminRemote: "big",
	}); err != nil {
		t.Fatal(err)
	}

	stdout, err := executeForTest(t, "sandcastle", "config", "unset", "project")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Unset project") {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Project != "" {
		t.Fatalf("Project = %q, want empty", cfg.Project)
	}
	if cfg.Tenant != "acme" || cfg.Remote != "sc-acme" || cfg.AdminRemote != "big" {
		t.Fatalf("config = %#v, want other keys preserved", cfg)
	}
}

func TestConfigSetAuthHostname(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	configPath := scconfig.DefaultConfigPath()
	stdout, err := executeForTest(t, "sandcastle", "config", "set", "auth.hostname", "big.example.dev")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Set auth.hostname") {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthHostname != "big.example.dev" {
		t.Fatalf("AuthHostname = %q", cfg.AuthHostname)
	}
}

func TestTenantListShowsAccessibleTenantsAndCurrent(t *testing.T) {
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{
		{Tenant: "acme", Personal: true},
		{Tenant: "skorfman"},
	}}
	admin := testAdminConfig()
	admin.Tenant = "acme"
	admin.AuthHostname = "auth.example.com"
	admin.AuthToken = "stored-token"
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: admin,
		authTenants: client,
	}, "tenant", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  Tenant\tRole\tPersonal",
		"* acme\towner\tyes",
		"  skorfman\towner\tno",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Users") || strings.Contains(stdout, "Projects") || strings.Contains(stdout, "Shares") {
		t.Fatalf("stdout includes non-list diagnostics:\n%s", stdout)
	}
	if client.listRequests != 1 {
		t.Fatalf("listRequests = %d", client.listRequests)
	}
}

func TestTenantSwitchValidatesAccessAndPreservesProject(t *testing.T) {
	useLoginHomeForTest(t)
	t.Chdir(t.TempDir())
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant:       "acme",
		Project:      "website",
		Remote:       "sandcastle-acme",
		AuthHostname: "auth.example.com",
		AuthToken:    "stored-token",
	}); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "acme"}, {Tenant: "skorfman"}}}
	admin := testAdminConfig()
	admin.Tenant = "acme"
	admin.Project = "website"
	admin.AuthHostname = "auth.example.com"
	admin.AuthToken = "stored-token"
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: admin,
		authTenants: client,
	}, "tenant", "switch", "skorfman")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Current Tenant set to \"skorfman\"") || strings.Contains(stdout, "sc dns setup") || strings.Contains(stdout, "sc trust install") {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenant != "skorfman" || cfg.Project != "website" {
		t.Fatalf("config = %#v", cfg)
	}
	if client.listRequests != 1 {
		t.Fatalf("listRequests = %d", client.listRequests)
	}
}

func TestTenantSwitchListsOnlyMissingLocalSetupActions(t *testing.T) {
	useLoginHomeForTest(t)
	t.Chdir(t.TempDir())
	resolverDir := t.TempDir()
	trustDir := t.TempDir()
	t.Setenv("SANDCASTLE_RESOLVER_DIR", resolverDir)
	t.Setenv("SANDCASTLE_TRUST_DIR", trustDir)
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant:       "acme",
		Remote:       "sandcastle-acme",
		AuthHostname: "auth.example.com",
		AuthToken:    "stored-token",
	}); err != nil {
		t.Fatal(err)
	}
	store := tenantSwitchStoreForTest(t, "acme", "skorfman")
	if err := os.WriteFile(filepath.Join(resolverDir, "skorfman"), []byte("nameserver 10.248.7.3\nport 53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	trustPlan, err := localtrust.PlanInstall(context.Background(), testAdminConfig(), store, localtrust.Request{Reference: "skorfman"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trustDir, localtrust.CertFilename(trustPlan)), []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "acme"}, {Tenant: "skorfman"}}}
	admin := testAdminConfig()
	admin.Tenant = "acme"
	admin.AuthHostname = "auth.example.com"
	admin.AuthToken = "stored-token"
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: admin,
		authTenants: client,
		tenantStore: store,
		tailscale: &fakeTailscaleRunner{status: tailscale.StatusResult{
			Tailscale: meta.Tailscale{State: "running-logged-out"},
		}},
	}, "tenant", "switch", "skorfman")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "sc tailscale up skorfman") {
		t.Fatalf("stdout = %q, want tailscale action", stdout)
	}
	for _, unexpected := range []string{"sc dns setup skorfman", "sc trust install skorfman"} {
		if strings.Contains(stdout, unexpected) {
			t.Fatalf("stdout = %q, did not want %q", stdout, unexpected)
		}
	}
}

func TestTenantSwitchRejectsInaccessibleTenant(t *testing.T) {
	useLoginHomeForTest(t)
	t.Chdir(t.TempDir())
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{Tenant: "acme", Project: "website"}); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{tenants: []authapp.TenantAccessSummary{{Tenant: "acme"}}}
	admin := testAdminConfig()
	admin.Tenant = "acme"
	admin.AuthHostname = "auth.example.com"
	admin.AuthToken = "stored-token"
	_, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: admin,
		authTenants: client,
	}, "tenant", "switch", "skorfamn")
	if err == nil || !strings.Contains(err.Error(), "--local-only") {
		t.Fatalf("err = %v", err)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenant != "acme" || cfg.Project != "website" {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestTenantSwitchLocalOnlySkipsValidation(t *testing.T) {
	useLoginHomeForTest(t)
	t.Chdir(t.TempDir())
	configPath := scconfig.DefaultConfigPath()
	if err := scconfig.SaveSandcastleConfig(configPath, scconfig.SandcastleConfig{
		Tenant:       "acme",
		Project:      "website",
		AuthHostname: "auth.example.com",
		AuthToken:    "stored-token",
	}); err != nil {
		t.Fatal(err)
	}
	client := &fakeAuthTenantClient{err: fmt.Errorf("should not be called")}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		adminConfig: testAdminConfig(),
		authTenants: client,
	}, "tenant", "switch", "offline", "--local-only")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Skipped Auth App Tenant Access validation") {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenant != "offline" || cfg.Project != "website" {
		t.Fatalf("config = %#v", cfg)
	}
	if client.listRequests != 0 {
		t.Fatalf("listRequests = %d", client.listRequests)
	}
}

// v2TenantProjects builds the pair (or more) of Incus projects that make up a
// v2 tenant: one kind=infra project (<sc2>-<tenant>) carrying the private /24,
// plus one kind=project app project per name (<sc2>-<tenant>-<project>). This
// is the fixture shape tenant.ListForPrefix consumes now that v1 (kind=tenant)
// projects are gone.
func v2TenantProjects(tenantName, cidr string, projectNames ...string) []tenant.IncusProject {
	if len(projectNames) == 0 {
		projectNames = []string{"default"}
	}
	infra := "sc2-" + tenantName
	projects := []tenant.IncusProject{{
		Name: infra,
		Config: map[string]string{
			meta.KeyKind:    meta.KindInfra,
			meta.KeyTenant:  tenantName,
			meta.KeyVersion: "2",
			meta.KeyV2CIDR:  cidr,
		},
	}}
	for _, name := range projectNames {
		projects = append(projects, tenant.IncusProject{
			Name: infra + "-" + name,
			Config: map[string]string{
				meta.KeyKind:    meta.KindV2Project,
				meta.KeyTenant:  tenantName,
				meta.KeyVersion: "2",
			},
		})
	}
	return projects
}

// v2TenantProjectsWithPrefix builds the same fixture for a non-default install
// prefix, so tests can model two installs sharing one Incus daemon.
func v2TenantProjectsWithPrefix(prefix, tenantName, cidr string, projectNames ...string) []tenant.IncusProject {
	if len(projectNames) == 0 {
		projectNames = []string{"default"}
	}
	infra := prefix + "-" + tenantName
	projects := []tenant.IncusProject{{
		Name: infra,
		Config: map[string]string{
			meta.KeyKind:     meta.KindInfra,
			meta.KeyTenant:   tenantName,
			meta.KeyVersion:  "2",
			meta.KeyV2CIDR:   cidr,
			meta.KeyV2Prefix: prefix,
		},
	}}
	for _, name := range projectNames {
		projects = append(projects, tenant.IncusProject{
			Name: infra + "-" + name,
			Config: map[string]string{
				meta.KeyKind:     meta.KindV2Project,
				meta.KeyTenant:   tenantName,
				meta.KeyVersion:  "2",
				meta.KeyV2Prefix: prefix,
			},
		})
	}
	return projects
}

func tenantSwitchStoreForTest(t *testing.T, tenants ...string) tenant.MemoryStore {
	t.Helper()
	projects := make([]tenant.IncusProject, 0, len(tenants)*2)
	for _, name := range tenants {
		privateCIDR := "10.248.0.0/24"
		if name == "skorfman" {
			privateCIDR = "10.248.7.0/24"
		}
		projects = append(projects, v2TenantProjects(name, privateCIDR, "default")...)
	}
	return tenant.MemoryStore{Projects: projects}
}

func TestConfigUnsetRejectsUnknownKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := executeForTest(t, "sandcastle", "config", "unset", "bad")
	if err == nil || !strings.Contains(err.Error(), "supported keys: tenant, project, remote, auth.hostname, admin_remote") {
		t.Fatalf("err = %v", err)
	}
}

func TestCommandAuthHostnameInfersFromRemoteConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	incusDir := scconfig.RemoteIncusDir("sandcastle-acme")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes:\n  sandcastle-acme:\n    addr: https://big.thieso2.dev:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	admin := testAdminConfig()
	admin.Remote = "sandcastle-acme"
	admin.AuthHostname = ""
	if got := commandAuthHostname(commandConfig{adminConfig: admin}, ""); got != "big.thieso2.dev" {
		t.Fatalf("auth hostname = %q", got)
	}
}

func TestCommandAuthHostnamePrefersCurrentRemoteOverSavedConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	incusDir := scconfig.RemoteIncusDir("sandcastle-thieso2")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes:\n  sandcastle-thieso2:\n    addr: https://big.thieso2.dev:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	admin := testAdminConfig()
	admin.Remote = "sandcastle-thieso2"
	admin.AuthHostname = "https://auth.example.com"
	if got := commandAuthHostname(commandConfig{adminConfig: admin}, ""); got != "big.thieso2.dev" {
		t.Fatalf("auth hostname = %q", got)
	}
}

func TestCommandAuthHostnameExplicitOverridesRemoteInference(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SANDCASTLE_AUTH_HOSTNAME", "env.example.dev")
	incusDir := scconfig.RemoteIncusDir("sandcastle-thieso2")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes:\n  sandcastle-thieso2:\n    addr: https://big.thieso2.dev:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	admin := testAdminConfig()
	admin.Remote = "sandcastle-thieso2"
	admin.AuthHostname = "https://auth.example.com"
	config := commandConfig{adminConfig: admin}
	if got := commandAuthHostname(config, "flag.example.dev"); got != "flag.example.dev" {
		t.Fatalf("flag auth hostname = %q", got)
	}
	if got := commandAuthHostname(config, ""); got != "env.example.dev" {
		t.Fatalf("env auth hostname = %q", got)
	}
}

func TestCloudIdentityGCPSetupConfiguresTenantFederation(t *testing.T) {
	runner := &fakeGCloudRunner{}
	admin := testAdminConfig()
	admin.Tenant = "thieso2"
	admin.AuthHostname = "big.thieso2.dev"
	stdout, stderr, err := executeForTestWithConfigAndStderr(t, commandConfig{
		name:         "sandcastle",
		adminConfig:  admin,
		gcloudRunner: runner.run,
	}, "cloud-identity", "gcp", "setup", "--project", "example-gcp", "--role", "roles/storage.objectAdmin")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Configured Sandcastle GCP Workload Identity Federation.",
		"Issuer URI:               https://big.thieso2.dev/t/thieso2",
		"Cloud Identity Audience:  //iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/sandcastle-thieso2/providers/sandcastle",
		"Impersonation URL:        https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sandcastle-thieso2@example-gcp.iam.gserviceaccount.com:generateAccessToken",
		"Web UI:                   https://big.thieso2.dev/cloud-identities",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	for _, want := range []string{
		"+ gcloud services enable iam.googleapis.com",
		"+ gcloud iam workload-identity-pools create sandcastle-thieso2",
		"+ gcloud iam workload-identity-pools providers create-oidc sandcastle",
		"+ gcloud iam service-accounts create sandcastle-thieso2",
		"+ gcloud projects add-iam-policy-binding example-gcp",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if !runner.hasCall("iam", "service-accounts", "add-iam-policy-binding", "sandcastle-thieso2@example-gcp.iam.gserviceaccount.com", "--project=example-gcp", "--role=roles/iam.workloadIdentityUser", "--member=principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/sandcastle-thieso2/attribute.tenant/thieso2") {
		t.Fatalf("missing tenant-scoped workloadIdentityUser binding: %#v", runner.calls)
	}
	if !runner.hasCallContaining("--attribute-condition=assertion.tenant=='thieso2'") {
		t.Fatalf("missing tenant attribute condition: %#v", runner.calls)
	}
}

func TestCloudIdentityGCPSetupSavesConfigInAuthApp(t *testing.T) {
	runner := &fakeGCloudRunner{}
	authClient := &fakeAuthCloudIdentityClient{}
	admin := testAdminConfig()
	admin.Tenant = "thieso2"
	admin.AuthHostname = "big.thieso2.dev"
	admin.AuthToken = "stored-token"
	stdout, _, err := executeForTestWithConfigAndStderr(t, commandConfig{
		name:              "sandcastle",
		adminConfig:       admin,
		gcloudRunner:      runner.run,
		authCloudIdentity: authClient,
	}, "cloud-identity", "gcp", "setup", "--project", "example-gcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(authClient.upsertRequests) != 1 {
		t.Fatalf("upsert requests = %#v", authClient.upsertRequests)
	}
	request := authClient.upsertRequests[0]
	if request.Tenant != "thieso2" || request.Name != "gcp" || request.Provider != "gcp" {
		t.Fatalf("upsert request = %#v", request)
	}
	if request.GCPAudience != "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/sandcastle-thieso2/providers/sandcastle" {
		t.Fatalf("audience = %q", request.GCPAudience)
	}
	if request.GCPServiceAccountImpersonationURL != "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sandcastle-thieso2@example-gcp.iam.gserviceaccount.com:generateAccessToken" {
		t.Fatalf("impersonation URL = %q", request.GCPServiceAccountImpersonationURL)
	}
	if !strings.Contains(stdout, "Saved in Auth App:        yes") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestCloudIdentityGCPSetupUsesCurrentRemoteHostWhenSavedAuthHostnameIsStale(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	incusDir := scconfig.RemoteIncusDir("sandcastle-thieso2")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes:\n  sandcastle-thieso2:\n    addr: https://big.thieso2.dev:8443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeGCloudRunner{}
	admin := testAdminConfig()
	admin.Tenant = "thieso2"
	admin.Remote = "sandcastle-thieso2"
	admin.AuthHostname = "https://auth.example.com"
	stdout, _, err := executeForTestWithConfigAndStderr(t, commandConfig{
		name:         "sandcastle",
		adminConfig:  admin,
		gcloudRunner: runner.run,
	}, "cloud-identity", "gcp", "setup", "--project", "example-gcp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Issuer URI:               https://big.thieso2.dev/t/thieso2") {
		t.Fatalf("stdout = %q", stdout)
	}
	if strings.Contains(stdout, "https://auth.example.com/t/thieso2") {
		t.Fatalf("stale auth hostname used:\n%s", stdout)
	}
}

func TestCloudIdentityGCPSetupCanRestrictImpersonationToMachine(t *testing.T) {
	runner := &fakeGCloudRunner{}
	admin := testAdminConfig()
	admin.Tenant = "acme"
	admin.AuthHostname = "auth.example.com"
	_, _, err := executeForTestWithConfigAndStderr(t, commandConfig{
		name:         "sandcastle",
		adminConfig:  admin,
		gcloudRunner: runner.run,
	}, "cloud", "gcp", "setup", "--project", "example-gcp", "--machine-project", "website", "--machine", "codex")
	if err != nil {
		t.Fatal(err)
	}
	if !runner.hasCall("iam", "service-accounts", "add-iam-policy-binding", "sandcastle-acme@example-gcp.iam.gserviceaccount.com", "--project=example-gcp", "--role=roles/iam.workloadIdentityUser", "--member=principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/sandcastle-acme/subject/machine:acme/website/codex") {
		t.Fatalf("missing machine-scoped workloadIdentityUser binding: %#v", runner.calls)
	}
}

func TestListJSONStartsEmpty(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		tenantStore:  tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{},
	}, "--output", "json", "list")
	if err != nil {
		t.Fatal(err)
	}
	var payload listPayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Machines) != 0 {
		t.Fatalf("len(payload.Machines) = %d, want 0", len(payload.Machines))
	}
}

func TestListTextShowsManagedMachines(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{{
			Tenant:    "acme",
			Project:   "default",
			Name:      "codex",
			PrivateIP: "10.248.0.20",
			AppPort:   3000,
			Running:   true,
		}}},
	}, "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "default") || !strings.Contains(stdout, "codex") {
		t.Fatalf("stdout = %q, want machine project and name", stdout)
	}
	if strings.Contains(stdout, "Unmanaged:") {
		t.Fatalf("stdout = %q, want no unmanaged footer", stdout)
	}
}

func TestListUsesProjectFromEnv(t *testing.T) {
	t.Setenv("SANDCASTLE_PROJECT", "website")
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{{
			Tenant: "acme", Project: "default", Name: "builder", PrivateIP: "10.248.0.20", AppPort: 3000,
		}, {
			Tenant: "acme", Project: "website", Name: "codex", PrivateIP: "10.248.0.21", AppPort: 3000,
		}}},
	}, "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "website") || !strings.Contains(stdout, "codex") {
		t.Fatalf("stdout = %q, want website/codex", stdout)
	}
	if strings.Contains(stdout, "builder") {
		t.Fatalf("stdout = %q, want env project filter to hide default/builder", stdout)
	}
}

func TestListAliasShowsUnmanagedTenantWide(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{unmanaged: []machine.UnmanagedMachine{{
			Tenant: "acme", Name: "manual", InstanceName: "manual", Status: "Running", Running: true,
		}}},
	}, "ls")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "Unmanaged:") {
		t.Fatalf("stdout = %q, want no unmanaged footer", stdout)
	}
	if !strings.Contains(stdout, "manual") || !strings.Contains(stdout, "unmanaged:Running") {
		t.Fatalf("stdout = %q, want unmanaged row", stdout)
	}
}

func TestListRejectsRemovedUnmanagedFlag(t *testing.T) {
	_, err := executeForTest(t, "sandcastle", "list", "-u")
	if err == nil {
		t.Fatal("expected removed -u flag to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown shorthand flag") {
		t.Fatalf("error = %q", err)
	}
}

func TestListProjectScopeAlsoShowsUnmanagedRows(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{unmanaged: []machine.UnmanagedMachine{{
			Tenant: "acme", Name: "manual", InstanceName: "manual", Status: "Running", Running: true,
		}}},
	}, "list", "default")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "Unmanaged:") {
		t.Fatalf("stdout = %q, want no unmanaged footer", stdout)
	}
	if !strings.Contains(stdout, "manual") || !strings.Contains(stdout, "unmanaged:Running") {
		t.Fatalf("stdout = %q, want unmanaged row", stdout)
	}
}

func TestProjectListShowsCurrentTenantProjects(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "project", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "default") || !strings.Contains(stdout, "website") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestProjectStatusShowsMachineCount(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{
			{Tenant: "acme", Project: "website", Name: "codex"},
			{Tenant: "acme", Project: "default", Name: "shell"},
		}},
	}, "project", "status", "website")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Project: website") || !strings.Contains(stdout, "Machines: 1") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestProjectStatusJSON(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{
			{Tenant: "acme", Project: "website", Name: "codex"},
		}},
	}, "--output", "json", "project", "status", "website")
	if err != nil {
		t.Fatal(err)
	}
	var payload projectStatusPayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Tenant.Tenant != "acme" || payload.Project.Name != "website" || payload.MachineCount != 1 {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestProjectSetCloudIdentityUpdatesDefaultProject(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	updater := &fakeProjectUpdater{}
	authClient := &fakeAuthCloudIdentityClient{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:              "sandcastle",
		authCloudIdentity: authClient,
		projectSettings:   updater,
		tenantStore:       tenant.MemoryStore{Projects: projects},
	}, "project", "set-cloud-identity", "default", "gcp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "set cloud identity on project default") {
		t.Fatalf("stdout = %q", stdout)
	}
	// It must land on the project's OWN Incus project, which is what
	// tenant.v2Summaries reads the setting back from.
	if !updater.called || updater.incusProject != "sc2-acme-default" || updater.cloudIdentity != "gcp" {
		t.Fatalf("updater = %#v", updater)
	}
	if len(authClient.getRequests) != 1 || authClient.getRequests[0].tenant != "acme" || authClient.getRequests[0].name != "gcp" {
		t.Fatalf("get requests = %#v", authClient.getRequests)
	}
}

func TestProjectSetCloudIdentityRejectsMissingTenantConfig(t *testing.T) {
	projects := v2TenantProjects("some", "10.248.0.0/24", "io")
	admin := testAdminConfig()
	admin.Tenant = "some"
	authClient := &fakeAuthCloudIdentityClient{getErr: fmt.Errorf("cloud identity config not found")}
	updater := &fakeProjectUpdater{}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:              "sandcastle",
		adminConfig:       admin,
		authCloudIdentity: authClient,
		projectSettings:   updater,
		tenantStore:       tenant.MemoryStore{Projects: projects},
	}, "project", "set-cloud-identity", "io", "gcp")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `cloud identity config "gcp" is not configured for tenant "some"`) {
		t.Fatalf("error = %q", err)
	}
	if updater.called {
		t.Fatal("expected project metadata update to be skipped")
	}
}

func TestProjectSetDockerAutostartUpdatesDefaultProject(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	updater := &fakeProjectUpdater{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:            "sandcastle",
		projectSettings: updater,
		tenantStore:     tenant.MemoryStore{Projects: projects},
	}, "project", "set-docker-autostart", "default", "on")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "enable Docker autostart for project default") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !updater.called || updater.incusProject != "sc2-acme-default" || !updater.dockerAutostart {
		t.Fatalf("updater = %#v", updater)
	}
}

func TestProjectSetAndUnsetImage(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "work")
	updater := &fakeProjectUpdater{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name: "sandcastle", projectSettings: updater, tenantStore: tenant.MemoryStore{Projects: projects},
	}, "project", "set-image", "work", "images:ubuntu/26.04/cloud")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "set default image images:ubuntu/26.04/cloud on project work") || updater.incusProject != "sc2-acme-work" || updater.image != "images:ubuntu/26.04/cloud" {
		t.Fatalf("stdout = %q updater = %#v", stdout, updater)
	}
	updater = &fakeProjectUpdater{}
	if _, err := executeForTestWithConfig(t, commandConfig{
		name: "sandcastle", projectSettings: updater, tenantStore: tenant.MemoryStore{Projects: projects},
	}, "project", "unset-image", "work"); err != nil {
		t.Fatal(err)
	}
	if !updater.called || updater.image != "" {
		t.Fatalf("unset updater = %#v", updater)
	}
	if _, err := executeForTestWithConfig(t, commandConfig{
		name: "sandcastle", projectSettings: &fakeProjectUpdater{}, tenantStore: tenant.MemoryStore{Projects: projects},
	}, "project", "set-image", "work", "bad ref"); err == nil {
		t.Fatal("image ref with whitespace accepted")
	}
}

func TestProjectSetImageUsesTheAuthAppWhenLoggedIn(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "work")
	stub := &stubAuthProjects{tenant: "acme"}
	updater := &fakeProjectUpdater{}
	admin := testAdminConfig()
	admin.AuthHostname, admin.AuthToken = "https://auth.example.com", "stored-token"
	if _, err := executeForTestWithConfig(t, commandConfig{
		name: "sandcastle", adminConfig: admin, authProjects: stub, projectSettings: updater, tenantStore: tenant.MemoryStore{Projects: projects},
	}, "project", "set-image", "work", "images:ubuntu/26.04/cloud"); err != nil {
		t.Fatal(err)
	}
	if updater.called || len(stub.calls) != 1 || stub.calls[0] != "image:work=images:ubuntu/26.04/cloud" {
		t.Fatalf("direct updater called=%v auth calls=%v", updater.called, stub.calls)
	}
}

func TestProjectDeleteRejectsNonEmptyProject(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	_, err := executeForTestWithConfig(t, commandConfig{
		name:         "sandcastle",
		tenantStore:  tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{{Tenant: "acme", Project: "website", Name: "codex"}}},
	}, "project", "delete", "website", "--yes")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "still contains machine") {
		t.Fatalf("error = %q", err)
	}
}

// `sc project delete` used to only rewrite a `.sandcastle/projects` metadata file
// that nothing read: the Incus project, its volumes and its machines survived a
// "successful" delete. Deleting the Incus project IS the deletion.
func TestProjectDeleteDeletesTheIncusProject(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	settings := &fakeProjectUpdater{}
	deleter := &fakeProjectDeleter{}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:            "sandcastle",
		projectSettings: settings,
		projectDeleter:  deleter,
		tenantStore:     tenant.MemoryStore{Projects: projects},
		machineStore:    fakeMachineStatusStore{},
	}, "project", "delete", "website", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if deleter.incusProject != "sc2-acme-website" {
		t.Fatalf("deleted project = %q, want sc2-acme-website", deleter.incusProject)
	}
	if settings.called {
		t.Fatalf("project delete wrote project settings: %#v", settings)
	}
}

// --dry-run must plan and delete nothing.
func TestProjectDeleteDryRunDeletesNothing(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	deleter := &fakeProjectDeleter{}
	if _, err := executeForTestWithConfig(t, commandConfig{
		name:           "sandcastle",
		projectDeleter: deleter,
		tenantStore:    tenant.MemoryStore{Projects: projects},
		machineStore:   fakeMachineStatusStore{},
	}, "project", "delete", "website", "--yes", "--dry-run"); err != nil {
		t.Fatal(err)
	}
	if deleter.incusProject != "" {
		t.Fatalf("dry-run deleted %q", deleter.incusProject)
	}
}

type fakeProjectDeleter struct {
	incusProject string
	storagePool  string
}

func (f *fakeProjectDeleter) DeleteProjectV2(_ context.Context, incusProject string, storagePool string) error {
	f.incusProject = incusProject
	f.storagePool = storagePool
	return nil
}

func TestStatusJSON(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "status", "acme")
	if err != nil {
		t.Fatal(err)
	}
	var payload tenant.Status
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Summary.IncusName != "sc2-acme-default" {
		t.Fatalf("IncusName = %q", payload.Summary.IncusName)
	}
}

func TestStatusJSONUsesTenantRef(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "status", "acme")
	if err != nil {
		t.Fatal(err)
	}
	var payload tenant.Status
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Summary.Tenant != "acme" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestMachineDeleteRequiresConfirmation(t *testing.T) {
	_, err := executeForTest(t, "sandcastle", "delete", "codex")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error = %q, want --yes hint", err.Error())
	}
}

func TestPortSetRejectsInvalidPort(t *testing.T) {
	_, err := executeForTest(t, "sandcastle", "port", "set", "codex", "bad")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFormatLocalDNSPlanShowsResolverCommands(t *testing.T) {
	output := formatLocalDNSPlan("Install", localdns.Plan{
		Reference:        "acme",
		DNSEndpoint:      "10.248.0.3:53",
		ResolverStrategy: localdns.StrategySystemdResolve,
		ResolverCommands: []localdns.Command{
			{Args: []string{"resolvectl", "dns", "lo", "10.248.0.3:53"}},
			{Args: []string{"resolvectl", "domain", "lo", "~acme"}},
		},
	})
	for _, want := range []string{
		"Resolver: systemd-resolved",
		"Resolver commands:",
		"resolvectl dns lo 10.248.0.3:53",
		"resolvectl domain lo ~acme",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestDNSTeardownUsesCurrentTenantAndRunsSteps(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	localManager := &fakeLocalDNSManager{}
	admin := testAdminConfig()
	admin.Tenant = "acme"
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		adminConfig: admin,
		tenantStore: tenant.MemoryStore{Projects: projects},
		localDNS:    localManager,
	}, "dns", "teardown")
	if err != nil {
		t.Fatal(err)
	}
	if !localManager.uninstalled {
		t.Fatal("expected local DNS uninstall")
	}
	if localManager.uninstallPlan.Reference != "acme" {
		t.Fatalf("uninstall plan = %#v, want acme", localManager.uninstallPlan)
	}
	for _, want := range []string{"DNS teardown: acme", "Resolver:"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout = %q, want %q", stdout, want)
		}
	}
}

func TestIncusCommandUsesActiveRemoteConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	incusDir := scconfig.RemoteIncusDir("sandcastle-alice")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var gotArgs []string
	var gotEnv []string
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		adminConfig: scconfig.Admin{Remote: "sandcastle-alice", Tenant: "acme", IncusProjectPrefix: "sc"},
		tenantStore: tenant.MemoryStore{Projects: v2TenantProjects("acme", "10.248.0.0/24", "default")},
		incusRunner: func(ctx context.Context, args []string, env []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
			gotArgs = append([]string{}, args...)
			gotEnv = append([]string{}, env...)
			_, _ = stdout.Write([]byte("incus ok"))
			return nil
		},
	}, "incus", "project", "list")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "incus ok" {
		t.Fatalf("stdout = %q", stdout)
	}
	if strings.Join(gotArgs, " ") != "project list" {
		t.Fatalf("args = %#v", gotArgs)
	}
	if !envContains(gotEnv, "INCUS_CONF="+incusDir) {
		t.Fatalf("env missing INCUS_CONF=%s", incusDir)
	}
	if !envContains(gotEnv, "INCUS_REMOTE=sandcastle-alice") {
		t.Fatalf("env missing selected INCUS_REMOTE: %#v", gotEnv)
	}
	if !envContains(gotEnv, "INCUS_PROJECT=sc2-acme-default") {
		t.Fatalf("env missing INCUS_PROJECT=sc2-acme-default: %#v", gotEnv)
	}
}

func TestIncusCommandVerboseShowsEnvAndCommand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VERBOSE", "1")
	incusDir := scconfig.RemoteIncusDir("sandcastle-alice")
	if err := os.MkdirAll(incusDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(incusDir, "config.yml"), []byte("remotes: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, err := executeForTestWithConfigAndStderr(t, commandConfig{
		name:        "sandcastle",
		adminConfig: scconfig.Admin{Remote: "sandcastle-alice", Tenant: "acme", IncusProjectPrefix: "sc"},
		tenantStore: tenant.MemoryStore{Projects: v2TenantProjects("acme", "10.248.0.0/24", "default")},
		incusRunner: func(ctx context.Context, args []string, env []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
			return nil
		},
	}, "incus", "ls")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[verbose] sc incus env: INCUS_CONF=" + incusDir + " INCUS_PROJECT=sc2-acme-default",
		"[verbose] sc incus command: incus ls",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want %q", stderr, want)
		}
	}
}

func TestIncusCommandRequiresManagedRemoteConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		adminConfig: scconfig.Admin{Remote: "sandcastle-alice"},
	}, "incus", "ls")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "sc remote add") {
		t.Fatalf("error = %q", err)
	}
}

func TestTailscaleUpDryRunRedactsAuthKey(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "tailscale", "up", "acme", "--auth-key", "tskey-secret", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "tskey-secret") {
		t.Fatalf("stdout leaked auth key: %s", stdout)
	}
	var payload tailscale.UpPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.InstanceName != "sc2-acme-default" {
		t.Fatalf("InstanceName = %q", payload.InstanceName)
	}
	if !payload.HasAuthKey {
		t.Fatal("expected HasAuthKey")
	}
}

func TestTailscaleUpDryRunUsesDefaultAdvertiseTag(t *testing.T) {
	t.Setenv("SANDCASTLE_E2E_TAILSCALE_TAG", "")
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "tailscale", "up", "acme", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload tailscale.UpPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.AdvertiseTags) != 1 || payload.AdvertiseTags[0] != tailscale.DefaultAdvertiseTag {
		t.Fatalf("AdvertiseTags = %#v", payload.AdvertiseTags)
	}
	if !strings.Contains(strings.Join(payload.Command, " "), "--advertise-tags="+tailscale.DefaultAdvertiseTag) {
		t.Fatalf("Command = %#v", payload.Command)
	}
}

func TestTailscaleUpUsesCurrentTenant(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "tailscale", "up", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload tailscale.UpPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Reference != "acme" || payload.InstanceName != "sc2-acme-default" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestTailscaleUpDryRunRejectsInvalidAdvertiseTag(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	_, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "tailscale", "up", "acme", "--advertise-tag", "sandcastle", "--dry-run")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "Tailscale advertise tag") {
		t.Fatalf("error = %q", err)
	}
}

func TestTailscaleUpRunsExecutor(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	runner := &fakeTailscaleRunner{}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		tailscale:   runner,
	}, "tailscale", "up", "acme", "--auth-key", "tskey-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !runner.called {
		t.Fatal("expected tailscale runner call")
	}
	if runner.plan.InstanceName != "sc2-acme-default" {
		t.Fatalf("InstanceName = %q", runner.plan.InstanceName)
	}
	if runner.plan.AuthKey != "tskey-secret" {
		t.Fatalf("AuthKey = %q", runner.plan.AuthKey)
	}
}

func TestTailscaleStatusRunsExecutor(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	runner := &fakeTailscaleRunner{status: tailscale.StatusResult{
		Reference: "acme",
		Tailscale: meta.Tailscale{State: "Running", TailscaleIPs: []string{"100.80.12.34"}},
	}}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		tailscale:   runner,
	}, "--output", "json", "tailscale", "status", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !runner.statusCalled {
		t.Fatal("expected tailscale status runner call")
	}
	var payload tailscale.StatusResult
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Tailscale.State != "Running" {
		t.Fatalf("State = %q", payload.Tailscale.State)
	}
}

func TestTailscaleStatusUsesCurrentTenant(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	runner := &fakeTailscaleRunner{status: tailscale.StatusResult{
		Reference: "acme",
		Tailscale: meta.Tailscale{State: "Running"},
	}}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		tailscale:   runner,
	}, "tailscale", "status")
	if err != nil {
		t.Fatal(err)
	}
	if !runner.statusCalled || runner.statusPlan.Reference != "acme" {
		t.Fatalf("runner = %#v", runner)
	}
}

func TestTailscaleDownDryRunJSON(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "tailscale", "down", "acme", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload tailscale.DownPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if strings.Join(payload.Command, " ") != "tailscale down" {
		t.Fatalf("Command = %#v", payload.Command)
	}
}

func TestTailscaleDownUsesCurrentTenant(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "tailscale", "down", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload tailscale.DownPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Reference != "acme" || payload.InstanceName != "sc2-acme-default" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestTrustInstallDryRunJSON(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "trust", "install", "acme", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload localtrust.Plan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CAVolume != tenant.CAVolumeName {
		t.Fatalf("CAVolume = %q", payload.CAVolume)
	}
	if !strings.Contains(payload.Warning, "mint certificates") {
		t.Fatalf("Warning = %q", payload.Warning)
	}
}

func TestTrustInstallUsesCurrentTenantWithoutProject(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	admin := testAdminConfig()
	admin.Tenant = "acme"
	admin.Project = ""
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		adminConfig: admin,
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "trust", "install", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload localtrust.Plan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Reference != "acme" {
		t.Fatalf("Reference = %q", payload.Reference)
	}
	if payload.IncusProject != "sc2-acme-default" {
		t.Fatalf("IncusProject = %q", payload.IncusProject)
	}
}

func TestTrustInstallRunsExecutor(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	manager := &fakeLocalTrustManager{}
	stdout, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		localTrust:  manager,
	}, "trust", "install", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.installed {
		t.Fatal("expected local trust install call")
	}
	if !strings.Contains(stdout, "Warning: Trusting this tenant CA") {
		t.Fatalf("stdout missing pre-install trust warning: %q", stdout)
	}
	if !strings.Contains(stdout, "install tenant CA trust: acme") {
		t.Fatalf("stdout missing trust result: %q", stdout)
	}
	if manager.plan.IncusProject != "sc2-acme-default" {
		t.Fatalf("IncusProject = %q", manager.plan.IncusProject)
	}
}

func TestTrustUninstallRunsExecutor(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	manager := &fakeLocalTrustManager{}
	_, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		tenantStore: tenant.MemoryStore{Projects: projects},
		localTrust:  manager,
	}, "trust", "uninstall", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.deleted {
		t.Fatal("expected local trust uninstall call")
	}
}

func routeAdminConfigForTest() scconfig.Admin {
	admin := scconfig.LoadAdminFromEnv()
	admin.Tenant = "acme"
	admin.InfrastructureHost = "203.0.113.10"
	return admin
}

func TestAdminVersion(t *testing.T) {
	stdout, err := executeAdminForTest(t, "sandcastle-admin", "version")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(stdout); got != version {
		t.Fatalf("admin version output = %q, want %q", got, version)
	}
}

func TestAdminVersionHelpUsesAdminWording(t *testing.T) {
	stdout, err := executeAdminForTest(t, "sandcastle-admin", "version", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Print the Sandcastle admin command version") {
		t.Fatalf("admin version help = %q", stdout)
	}
}

func TestAdminTenantListJSON(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default")
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:        "sandcastle-admin",
		tenantStore: tenant.MemoryStore{Projects: projects},
	}, "--output", "json", "tenant", "list")
	if err != nil {
		t.Fatal(err)
	}
	var payload tenantListPayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Tenants) != 1 {
		t.Fatalf("len(payload.Tenants) = %d, want 1", len(payload.Tenants))
	}
	if payload.Tenants[0].IncusName != "sc2-acme-default" {
		t.Fatalf("IncusName = %q", payload.Tenants[0].IncusName)
	}
}

func TestAdminMachineListJSON(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:        "sandcastle-admin",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{{
			Tenant: "acme", Project: "default", Name: "codex", PrivateIP: "10.248.0.20", AppPort: 3000,
		}, {
			Tenant: "acme", Project: "website", Name: "codex", PrivateIP: "10.248.0.21", AppPort: 3000,
		}}},
	}, "--output", "json", "list", "acme")
	if err != nil {
		t.Fatal(err)
	}
	var payload listPayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Tenant.Tenant != "acme" || !payload.AllProjects || len(payload.Machines) != 2 {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestAdminMachineListProjectFilters(t *testing.T) {
	projects := v2TenantProjects("acme", "10.248.0.0/24", "default", "website")
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:        "sandcastle-admin",
		tenantStore: tenant.MemoryStore{Projects: projects},
		machineStore: fakeMachineStatusStore{machines: []meta.Machine{{
			Tenant: "acme", Project: "default", Name: "builder", PrivateIP: "10.248.0.20", AppPort: 3000,
		}, {
			Tenant: "acme", Project: "website", Name: "codex", PrivateIP: "10.248.0.21", AppPort: 3000,
		}}},
	}, "list", "acme/website")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "website") || !strings.Contains(stdout, "codex") {
		t.Fatalf("stdout = %q, want website/codex", stdout)
	}
	if strings.Contains(stdout, "builder") {
		t.Fatalf("stdout = %q, want project filter to hide default/builder", stdout)
	}
}

func TestAdminTLDRefreshWritesSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tlds":
			_, _ = w.Write([]byte("# Version 2026050700\nCOM\nORG\n"))
		case "/special-use":
			_, _ = w.Write([]byte("Name,Reference\nLOCAL.,[RFC6762]\nTEST.,[RFC6761]\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	output := filepath.Join(dir, "tld_snapshot_generated.go")
	specialUseOutput := filepath.Join(dir, "special_use_snapshot_generated.go")
	stdout, err := executeAdminForTest(t, "sandcastle-admin", "tld", "refresh", "--source-url", server.URL+"/tlds", "--output-file", output, "--special-use-source-url", server.URL+"/special-use", "--special-use-output-file", specialUseOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Refreshed 2 public TLDs") {
		t.Fatalf("stdout = %q", stdout)
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"com": true`) {
		t.Fatalf("content = %s", string(content))
	}
	specialUseContent, err := os.ReadFile(specialUseOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(specialUseContent), `"local": true`) {
		t.Fatalf("special use content = %s", string(specialUseContent))
	}
}

func TestAdminTLDRefreshDryRunJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tlds":
			_, _ = w.Write([]byte("COM\nORG\n"))
		case "/special-use":
			_, _ = w.Write([]byte("Name,Reference\nLOCAL.,[RFC6762]\nTEST.,[RFC6761]\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	output := filepath.Join(dir, "tld_snapshot_generated.go")
	specialUseOutput := filepath.Join(dir, "special_use_snapshot_generated.go")
	stdout, err := executeAdminForTest(t, "sandcastle-admin", "--output", "json", "tld", "refresh", "--source-url", server.URL+"/tlds", "--output-file", output, "--special-use-source-url", server.URL+"/special-use", "--special-use-output-file", specialUseOutput, "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload domain.DenyListRefreshResult
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.TLD.Count != 2 || payload.TLD.Written || payload.SpecialUse.Count != 2 || payload.SpecialUse.Written {
		t.Fatalf("payload = %#v", payload)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("expected dry run not to write output, stat err = %v", err)
	}
	if _, err := os.Stat(specialUseOutput); !os.IsNotExist(err) {
		t.Fatalf("expected dry run not to write special-use output, stat err = %v", err)
	}
}

func TestAdminTenantDeleteRequiresConfirmation(t *testing.T) {
	_, err := executeAdminForTest(t, "sandcastle-admin", "tenant", "delete", "acme")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error = %q, want --yes hint", err.Error())
	}
}

func imageSyncAdminConfig() scconfig.Admin {
	cfg := scconfig.LoadAdminFromEnv()
	cfg.Images = scconfig.Images{Base: "sandcastle/base:latest", AI: "sandcastle/ai:latest", Dev: "sandcastle/dev:latest"}
	return cfg
}

func TestAdminImageSyncDryRunJSON(t *testing.T) {
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:        "sandcastle-admin",
		adminConfig: imageSyncAdminConfig(),
	}, "--output", "json", "image", "sync", "sandcastle/base:debian-13", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload images.SyncPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Template != "base" {
		t.Fatalf("Template = %q", payload.Template)
	}
	if payload.Alias != "sandcastle/base:latest" {
		t.Fatalf("Alias = %q", payload.Alias)
	}
}

func TestAdminImageBuildDryRunJSON(t *testing.T) {
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:        "sandcastle-admin",
		adminConfig: scconfig.LoadAdminFromEnv(),
	}, "--output", "json", "image", "build", "base", "--tag", "sandcastle/base:debian-13", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload images.BuildPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Template != "base" || payload.Tag != "sandcastle/base:debian-13" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestAdminImageBuildRequiresPinnedAIVersions(t *testing.T) {
	_, err := executeAdminForTest(t, "sandcastle-admin", "image", "build", "ai", "--dry-run")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "codex-version") {
		t.Fatalf("error = %q", err)
	}
}

func TestAdminImageBuildCallsExecutor(t *testing.T) {
	builder := &fakeImageBuilder{}
	_, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		adminConfig:  scconfig.LoadAdminFromEnv(),
		imageBuilder: builder,
	}, "image", "build", "base", "--tag", "sandcastle/base:debian-13")
	if err != nil {
		t.Fatal(err)
	}
	if !builder.called {
		t.Fatal("expected image builder to be called")
	}
	if builder.plan.Tag != "sandcastle/base:debian-13" {
		t.Fatalf("Tag = %q", builder.plan.Tag)
	}
}

func TestAdminImageImportDryRunJSON(t *testing.T) {
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:        "sandcastle-admin",
		adminConfig: scconfig.LoadAdminFromEnv(),
	}, "--output", "json", "image", "import", "base", "oci:sandcastle/base:debian-13", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload images.ImportPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Alias != scconfig.DefaultBaseImageAlias {
		t.Fatalf("Alias = %q", payload.Alias)
	}
	if !strings.Contains(strings.Join(payload.Command, " "), "image copy oci:sandcastle/base:debian-13") {
		t.Fatalf("Command = %#v", payload.Command)
	}
}

func TestAdminImageImportCallsExecutor(t *testing.T) {
	importer := &fakeImageImporter{}
	_, err := executeAdminForTestWithConfig(t, commandConfig{
		name:          "sandcastle-admin",
		adminConfig:   scconfig.LoadAdminFromEnv(),
		imageImporter: importer,
	}, "image", "import", "ai", "oci:sandcastle/ai:debian-13")
	if err != nil {
		t.Fatal(err)
	}
	if !importer.called {
		t.Fatal("expected image importer to be called")
	}
	if importer.plan.Alias != scconfig.DefaultAIImageAlias {
		t.Fatalf("Alias = %q", importer.plan.Alias)
	}
}

func TestAdminImageSyncCallsExecutor(t *testing.T) {
	manager := &fakeImageManager{result: images.SyncResult{Fingerprint: "abc123", Action: "created"}}
	_, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		adminConfig:  imageSyncAdminConfig(),
		imageManager: manager,
	}, "image", "sync", "sandcastle/ai:debian-13")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.called {
		t.Fatal("expected image manager to be called")
	}
	if manager.plan.Alias != "sandcastle/ai:latest" {
		t.Fatalf("Alias = %q", manager.plan.Alias)
	}
}

func TestAdminTenantGrantDryRunJSON(t *testing.T) {
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:        "sandcastle-admin",
		adminConfig: scconfig.LoadAdminFromEnv(),
	}, "--output", "json", "tenant", "grant", "acme", "alice", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	var payload usertrust.UserPlan
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CertificateName != "sandcastle-alice" {
		t.Fatalf("CertificateName = %q", payload.CertificateName)
	}
	if !slices.Equal(payload.Projects, []string{"sc-acme", "sc-acme-default"}) {
		t.Fatalf("Projects = %#v", payload.Projects)
	}
}

func TestAdminTenantGrantCallsTrustManager(t *testing.T) {
	manager := &fakeTrustManager{}
	_, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		adminConfig:  scconfig.LoadAdminFromEnv(),
		trustManager: manager,
	}, "tenant", "grant", "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.grantCalled || manager.plan.User != "alice" || !slices.Equal(manager.plan.Projects, []string{"sc-acme", "sc-acme-default"}) {
		t.Fatalf("manager = %#v", manager)
	}
}

func TestAdminTenantRevokeCallsTrustManager(t *testing.T) {
	manager := &fakeTrustManager{}
	_, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		adminConfig:  scconfig.LoadAdminFromEnv(),
		trustManager: manager,
	}, "tenant", "revoke", "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.revokeCalled || manager.plan.User != "alice" || !slices.Equal(manager.plan.Projects, []string{"sc-acme", "sc-acme-default"}) {
		t.Fatalf("manager = %#v", manager)
	}
}

func TestAdminTenantUsersListsTrustUsers(t *testing.T) {
	manager := &fakeTrustManager{tenantUsers: usertrust.TenantUsersResult{
		Tenant:       "acme",
		IncusProject: "sc-acme",
		Users:        []string{"alice", "bob"},
	}}
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		adminConfig:  scconfig.LoadAdminFromEnv(),
		trustManager: manager,
	}, "tenant", "users", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.usersCalled {
		t.Fatal("expected tenant users manager call")
	}
	if !strings.Contains(stdout, "Users: alice, bob") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestAdminUserCreateDryRunShowsRemoteName(t *testing.T) {
	stdout, err := executeAdminForTest(t, "sandcastle-admin", "user", "create", "alice", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Remote: sandcastle-alice") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestAdminTenantGrantRejectsInvalidTenantRef(t *testing.T) {
	_, err := executeAdminForTestWithConfig(t, commandConfig{
		name:        "sandcastle-admin",
		adminConfig: scconfig.LoadAdminFromEnv(),
	}, "tenant", "grant", "bob/default", "alice", "--dry-run")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid tenant") {
		t.Fatalf("error = %q", err)
	}
}

func TestAdminUserTokenShowsBootstrapCommands(t *testing.T) {
	manager := &fakeTrustManager{token: "certificate-add-token"}
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		trustManager: manager,
	}, "user", "token", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.tokenCalled {
		t.Fatal("expected token manager to be called")
	}
	for _, want := range []string{
		"Remote: sandcastle-alice",
		"sc remote add sandcastle-alice certificate-add-token",
		"sc config set tenant <tenant>",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestAdminUserTokenSupportsPreGrantedTenant(t *testing.T) {
	manager := &fakeTrustManager{token: "certificate-add-token"}
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		trustManager: manager,
	}, "user", "token", "alice", "--tenant", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.tokenCalled {
		t.Fatal("expected token manager to be called")
	}
	if !slices.Equal(manager.plan.Projects, []string{"sc-acme", "sc-acme-default"}) {
		t.Fatalf("Projects = %#v", manager.plan.Projects)
	}
	if !strings.Contains(stdout, "sc remote add sandcastle-alice certificate-add-token --tenant acme") {
		t.Fatalf("stdout = %q", stdout)
	}
	if strings.Contains(stdout, "sc config set tenant") {
		t.Fatalf("stdout = %q, want no post-grant tenant hint", stdout)
	}
}

func TestAdminUserTokenJSONIncludesRemoteName(t *testing.T) {
	manager := &fakeTrustManager{token: "certificate-add-token"}
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		trustManager: manager,
	}, "--output", "json", "user", "token", "alice")
	if err != nil {
		t.Fatal(err)
	}
	var payload usertrust.TokenResult
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.RemoteName != "sandcastle-alice" {
		t.Fatalf("RemoteName = %q", payload.RemoteName)
	}
}

func TestAdminUserDeleteCallsTrustManager(t *testing.T) {
	manager := &fakeTrustManager{}
	stdout, err := executeAdminForTestWithConfig(t, commandConfig{
		name:         "sandcastle-admin",
		trustManager: manager,
	}, "user", "delete", "alice", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.deleteCalled {
		t.Fatal("expected delete manager to be called")
	}
	if manager.plan.CertificateName != "sandcastle-alice" {
		t.Fatalf("plan = %#v", manager.plan)
	}
	if !strings.Contains(stdout, "Deleted restricted user certificate: sandcastle-alice") {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestRejectsUnknownOutputFormat(t *testing.T) {
	_, err := executeForTest(t, "sandcastle", "--output", "yaml", "version")
	if err == nil {
		t.Fatal("expected error")
	}
}

type fakeProjectUpdater struct {
	called          bool
	incusProject    string
	cloudIdentity   string
	dockerAutostart bool
	image           string
}

func (f *fakeProjectUpdater) SetProjectCloudIdentity(_ context.Context, incusProject string, cloudIdentity string) error {
	f.called = true
	f.incusProject = incusProject
	f.cloudIdentity = cloudIdentity
	return nil
}

func (f *fakeProjectUpdater) SetProjectImage(_ context.Context, incusProject string, image string) error {
	f.called = true
	f.incusProject = incusProject
	f.image = image
	return nil
}

func (f *fakeProjectUpdater) SetProjectDockerAutostart(_ context.Context, incusProject string, enabled bool) error {
	f.called = true
	f.incusProject = incusProject
	f.dockerAutostart = enabled
	return nil
}

type fakeSSHKeyUpdater struct {
	called       bool
	incusProject string
	key          string
}

func (f *fakeSSHKeyUpdater) SetTenantSSHKey(ctx context.Context, incusProjectName string, sshKey string) error {
	f.called = true
	f.incusProject = incusProjectName
	f.key = sshKey
	return nil
}

type fakeImageManager struct {
	called bool
	plan   images.SyncPlan
	result images.SyncResult
}

func (f *fakeImageManager) SyncImage(ctx context.Context, plan images.SyncPlan) (images.SyncResult, error) {
	f.called = true
	f.plan = plan
	f.result.SyncPlan = plan
	return f.result, nil
}

type fakeImageBuilder struct {
	called bool
	plan   images.BuildPlan
	plans  []images.BuildPlan
}

func (f *fakeImageBuilder) BuildImage(ctx context.Context, plan images.BuildPlan) (images.BuildResult, error) {
	f.called = true
	f.plan = plan
	f.plans = append(f.plans, plan)
	return images.BuildResult{BuildPlan: plan, Built: true}, nil
}

type fakeImageImporter struct {
	called bool
	plan   images.ImportPlan
}

func (f *fakeImageImporter) ImportImage(ctx context.Context, plan images.ImportPlan) (images.ImportResult, error) {
	f.called = true
	f.plan = plan
	return images.ImportResult{ImportPlan: plan, Imported: true}, nil
}

type fakeImageUploader struct {
	called bool
	plan   images.UploadPlan
	plans  []images.UploadPlan
}

func (f *fakeImageUploader) UploadImage(ctx context.Context, plan images.UploadPlan) (images.UploadResult, error) {
	f.called = true
	f.plan = plan
	f.plans = append(f.plans, plan)
	return images.UploadResult{UploadPlan: plan, Uploaded: true}, nil
}

type fakeTailscaleRunner struct {
	called       bool
	statusCalled bool
	downCalled   bool
	plan         tailscale.UpPlan
	statusPlan   tailscale.StatusPlan
	downPlan     tailscale.DownPlan
	status       tailscale.StatusResult
}

type fakeLocalDNSManager struct {
	installed     bool
	refreshed     bool
	uninstalled   bool
	plan          localdns.Plan
	installPlan   localdns.Plan
	refreshPlan   localdns.Plan
	uninstallPlan localdns.Plan
}

func (f *fakeLocalDNSManager) Install(ctx context.Context, plan localdns.Plan) (localdns.Result, error) {
	f.installed = true
	f.plan = plan
	f.installPlan = plan
	return localdns.Result{Reference: plan.Reference, Action: "install", StatePath: plan.StatePath, ResolverPath: plan.ResolverPath}, nil
}

func (f *fakeLocalDNSManager) Refresh(ctx context.Context, plan localdns.Plan) (localdns.Result, error) {
	f.refreshed = true
	f.plan = plan
	f.refreshPlan = plan
	return localdns.Result{Reference: plan.Reference, Action: "refresh", StatePath: plan.StatePath, ResolverPath: plan.ResolverPath}, nil
}

func (f *fakeLocalDNSManager) Uninstall(ctx context.Context, plan localdns.Plan) (localdns.Result, error) {
	f.uninstalled = true
	f.plan = plan
	f.uninstallPlan = plan
	return localdns.Result{Reference: plan.Reference, Action: "uninstall", StatePath: plan.StatePath, ResolverPath: plan.ResolverPath}, nil
}

func (f *fakeTailscaleRunner) RunUp(ctx context.Context, plan tailscale.UpPlan, session tailscale.RunSession) error {
	f.called = true
	f.plan = plan
	return nil
}

func (f *fakeTailscaleRunner) RunStatus(ctx context.Context, plan tailscale.StatusPlan, session tailscale.RunSession) (tailscale.StatusResult, error) {
	f.statusCalled = true
	f.statusPlan = plan
	return f.status, nil
}

func (f *fakeTailscaleRunner) RunDown(ctx context.Context, plan tailscale.DownPlan, session tailscale.RunSession) error {
	f.downCalled = true
	f.downPlan = plan
	return nil
}

type fakeHostMachineStore struct{}

func (f fakeHostMachineStore) FindMachine(ctx context.Context, summary tenant.Summary, projectName string, name string) (meta.Machine, error) {
	return meta.Machine{
		Tenant:    summary.Tenant,
		Project:   projectName,
		Name:      name,
		AppPort:   3000,
		PrivateIP: "10.248.0.20",
		ExtraSANs: []string{"example.com"},
	}, nil
}

func (f fakeHostMachineStore) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	machine, err := f.FindMachine(ctx, summary, "default", "codex")
	if err != nil {
		return nil, err
	}
	return []meta.Machine{machine}, nil
}

type fakeMachineStatusStore struct {
	machines  []meta.Machine
	unmanaged []machine.UnmanagedMachine
}

func (f fakeMachineStatusStore) ListMachines(ctx context.Context, summary tenant.Summary) ([]meta.Machine, error) {
	return f.machines, nil
}

func (f fakeMachineStatusStore) ListUnmanagedMachines(ctx context.Context, summary tenant.Summary) ([]machine.UnmanagedMachine, error) {
	return f.unmanaged, nil
}

type fakeRouteMachineStore struct{}

func (f fakeRouteMachineStore) FindMachine(ctx context.Context, summary tenant.Summary, projectName string, name string) (meta.Machine, error) {
	return meta.Machine{
		Tenant:    summary.Tenant,
		Project:   projectName,
		Name:      name,
		AppPort:   5173,
		PrivateIP: "10.248.0.20",
	}, nil
}

type fakeTrustManager struct {
	tokenCalled  bool
	grantCalled  bool
	revokeCalled bool
	deleteCalled bool
	usersCalled  bool
	plan         usertrust.UserPlan
	usersPlan    usertrust.TenantUsersPlan
	tenantUsers  usertrust.TenantUsersResult
	token        string
}

func (f *fakeTrustManager) Grant(ctx context.Context, plan usertrust.UserPlan) error {
	f.grantCalled = true
	f.plan = plan
	return nil
}

func (f *fakeTrustManager) Revoke(ctx context.Context, plan usertrust.UserPlan) error {
	f.revokeCalled = true
	f.plan = plan
	return nil
}

func (f *fakeTrustManager) Delete(ctx context.Context, plan usertrust.UserPlan) error {
	f.deleteCalled = true
	f.plan = plan
	return nil
}

func (f *fakeTrustManager) ListTenantUsers(ctx context.Context, plan usertrust.TenantUsersPlan) (usertrust.TenantUsersResult, error) {
	f.usersCalled = true
	f.usersPlan = plan
	if f.tenantUsers.Tenant == "" {
		return usertrust.TenantUsersResult{Tenant: plan.Tenant, IncusProject: plan.IncusProject}, nil
	}
	return f.tenantUsers, nil
}

func (f *fakeTrustManager) CreateToken(ctx context.Context, plan usertrust.UserPlan) (usertrust.TokenResult, error) {
	f.tokenCalled = true
	f.plan = plan
	return usertrust.TokenResult{
		User:            plan.User,
		CertificateName: plan.CertificateName,
		RemoteName:      plan.RemoteName,
		Restricted:      plan.Restricted,
		Projects:        plan.Projects,
		Token:           f.token,
	}, nil
}

type fakeLocalTrustManager struct {
	installed  bool
	deleted    bool
	plan       localtrust.Plan
	installErr error
}

func (f *fakeLocalTrustManager) Install(ctx context.Context, plan localtrust.Plan) (localtrust.Result, error) {
	f.installed = true
	f.plan = plan
	if f.installErr != nil {
		return localtrust.Result{}, f.installErr
	}
	return localtrust.Result{Reference: plan.Reference, TrustName: plan.TrustName, Action: "install", Platform: "fake"}, nil
}

func (f *fakeLocalTrustManager) Uninstall(ctx context.Context, plan localtrust.Plan) (localtrust.Result, error) {
	f.deleted = true
	f.plan = plan
	return localtrust.Result{Reference: plan.Reference, TrustName: plan.TrustName, Action: "uninstall", Platform: "fake"}, nil
}

// Regression: the --dns-suffix flag must actually reach the device poll
// request (it was once accepted but silently dropped).
// Regression: sc login must send the shared-identity client certificate on
// the device poll so the server can union this install's projects into the
// existing trust entry (multi-install shared identity). This has silently
// vanished twice under adjacent edits.
func TestLoginSendsClientCertificate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USER", "loginuser")
	// Seed the shared incus dir with a client cert (as a prior install's login
	// would). AdoptNativeIncusDirIfChosen drops the ownership marker so the dir
	// resolves stably to the native dir even after a client cert lives in it.
	scconfig.AdoptNativeIncusDirIfChosen()
	shared := scconfig.SharedIncusDir()
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shared, "client.crt"), []byte("PEM-SENTINEL"), 0o600); err != nil {
		t.Fatal(err)
	}
	installer := &fakeLoginRemoteInstaller{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			UserKey:           "octocat",
			CLIAuthToken:      "cli-token",
			Token:             "token",
			RemoteName:        "sc-octocat",
			AccessibleTenants: []string{"octocat"},
		}},
	}
	if _, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  client,
		loginRemote: installer,
	}, "login", "https://auth.example.com", "--skip-setup"); err != nil {
		t.Fatal(err)
	}
	if len(client.pollRequests) == 0 || client.pollRequests[0].ClientCertificatePEM != "PEM-SENTINEL" {
		t.Fatalf("client certificate not sent on poll: %#v", client.pollRequests)
	}
}

func TestLoginSendsDNSSuffix(t *testing.T) {
	useLoginHomeForTest(t)
	t.Setenv("USER", "loginuser")
	installer := &fakeLoginRemoteInstaller{}
	client := &fakeAuthDeviceClient{
		start: authapp.DeviceStartResult{DeviceCode: "device", UserCode: "ABCD-1234", VerificationURI: "https://auth.example.com/device", Interval: 1},
		polls: []authapp.DevicePollResult{{
			Status:            authapp.DeviceStatusApproved,
			UserKey:           "octocat",
			CLIAuthToken:      "cli-token",
			Token:             "token",
			RemoteName:        "sandcastle-octocat",
			AccessibleTenants: []string{"octocat"},
		}},
	}
	if _, err := executeForTestWithConfig(t, commandConfig{
		name:        "sandcastle",
		authDevice:  client,
		loginRemote: installer,
	}, "login", "https://auth.example.com", "--dns-suffix", "castle"); err != nil {
		t.Fatal(err)
	}
	if len(client.pollRequests) == 0 || client.pollRequests[0].DNSSuffix != "castle" {
		t.Fatalf("poll requests missing dns suffix: %#v", client.pollRequests)
	}
}

// Regression for #60: the Broker addresses the tenant gateway on ONE install's
// CIDR pool. Switching remotes re-pointed auth.hostname but left the previous
// install's broker in place, so broker-derived commands (`sc trust install`)
// silently talked to the other install and fetched the wrong tenant CA.
func TestConfigSetRemoteRepointsTheBrokerForThatInstall(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VERBOSE", "1") // re-point detail lines are verbose-only
	configPath := scconfig.DefaultConfigPath()
	seed := scconfig.SandcastleConfig{
		Remote:       "sc-b",
		AuthHostname: "https://b.example.dev",
		Broker:       "https://10.62.0.1:9443", // install B
		Installs: map[string]string{
			"sc-a": "https://a.example.dev",
			"sc-b": "https://b.example.dev",
		},
		Brokers: map[string]string{
			"https://a.example.dev": "https://10.61.0.1:9443",
			"https://b.example.dev": "https://10.62.0.1:9443",
		},
	}
	if err := scconfig.SaveSandcastleConfig(configPath, seed); err != nil {
		t.Fatal(err)
	}
	stdout, err := executeForTest(t, "sandcastle", "config", "set", "remote", "sc-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, `Broker re-pointed to "https://10.61.0.1:9443"`) {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Broker != "https://10.61.0.1:9443" {
		t.Fatalf("Broker = %q, want install A's gateway", cfg.Broker)
	}
	if cfg.AuthHostname != "https://a.example.dev" {
		t.Fatalf("AuthHostname = %q", cfg.AuthHostname)
	}
}

// A login predating the brokers map records no broker for the target install.
// Clearing is right: a stale broker points at the WRONG install, which is worse
// than none (`sc project create` would create the project over there).
func TestConfigSetRemoteClearsAnUnknownInstallsBroker(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VERBOSE", "1") // re-point detail lines are verbose-only
	configPath := scconfig.DefaultConfigPath()
	seed := scconfig.SandcastleConfig{
		Remote:       "sc-b",
		AuthHostname: "https://b.example.dev",
		Broker:       "https://10.62.0.1:9443",
		Installs:     map[string]string{"sc-a": "https://a.example.dev", "sc-b": "https://b.example.dev"},
		// no Brokers map at all
	}
	if err := scconfig.SaveSandcastleConfig(configPath, seed); err != nil {
		t.Fatal(err)
	}
	stdout, err := executeForTest(t, "sandcastle", "config", "set", "remote", "sc-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Broker cleared") {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Broker != "" {
		t.Fatalf("Broker = %q, want cleared rather than pointing at install B", cfg.Broker)
	}
}

// A CLI auth token is minted by ONE install's Auth App. Leaving the previous
// install's token in place after a remote switch presents a credential across a
// trust boundary, and the target rejects it: `sc status` showed
// "shares:reconcile: error (auth app share reconcile: user not found)" while
// the token still authenticated fine against the OTHER install.
func TestConfigSetRemoteSwapsTheAuthTokenForThatInstall(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VERBOSE", "1") // re-point detail lines are verbose-only
	configPath := scconfig.DefaultConfigPath()
	seed := scconfig.SandcastleConfig{
		Remote:       "sc-b",
		AuthHostname: "https://b.example.dev",
		AuthToken:    "token-for-b",
		Installs:     map[string]string{"sc-a": "https://a.example.dev", "sc-b": "https://b.example.dev"},
		AuthTokens: map[string]string{
			"https://a.example.dev": "token-for-a",
			"https://b.example.dev": "token-for-b",
		},
	}
	if err := scconfig.SaveSandcastleConfig(configPath, seed); err != nil {
		t.Fatal(err)
	}
	stdout, err := executeForTest(t, "sandcastle", "config", "set", "remote", "sc-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Auth token switched") {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthToken != "token-for-a" {
		t.Fatalf("AuthToken = %q, want install A's token", cfg.AuthToken)
	}
}

// With no token recorded for the target install, clear it: a call that fails
// loudly ("sign in") beats one that quietly ships another install's credential.
func TestConfigSetRemoteClearsAnUnknownInstallsAuthToken(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VERBOSE", "1") // re-point detail lines are verbose-only
	configPath := scconfig.DefaultConfigPath()
	seed := scconfig.SandcastleConfig{
		Remote:       "sc-b",
		AuthHostname: "https://b.example.dev",
		AuthToken:    "token-for-b",
		Installs:     map[string]string{"sc-a": "https://a.example.dev", "sc-b": "https://b.example.dev"},
	}
	if err := scconfig.SaveSandcastleConfig(configPath, seed); err != nil {
		t.Fatal(err)
	}
	stdout, err := executeForTest(t, "sandcastle", "config", "set", "remote", "sc-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "Auth token cleared") {
		t.Fatalf("stdout = %q", stdout)
	}
	cfg, err := scconfig.LoadSandcastleConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthToken != "" {
		t.Fatalf("AuthToken = %q, want cleared rather than install B's token", cfg.AuthToken)
	}
}
