package authapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/projectbroker"
	"github.com/thieso2/sandcastle-incus/internal/share"
	"github.com/thieso2/sandcastle-incus/internal/update"
)

// defaultDeviceClientTimeout bounds each device poll. The poll that observes
// approval blocks while the server provisions the tenant, and first-login
// provisioning from a stock base image (download + install CoreDNS and
// Tailscale) can take a couple of minutes — a 2-minute budget lost that race by
// seconds. Keep it comfortably above the server's provisioning time so a single
// poll can await a first-login bring-up instead of erroring with a client
// timeout while the (detached) server work keeps running.
const defaultDeviceClientTimeout = 5 * time.Minute

type DeviceClient struct {
	BaseURL    string
	AuthToken  string
	HTTPClient *http.Client
	Verbose    bool
}

type DeviceStartResult struct {
	DeviceCode      string
	UserCode        string
	VerificationURI string
	ExpiresIn       int
	Interval        int
	Status          string
	Message         string
}

type DevicePollResult struct {
	Status             string
	Message            string
	UserKey            string
	CLIAuthToken       string
	Token              string
	RemoteName         string
	DNSSuffix          string
	IncusRemoteAddress string
	IncusProject       string
	TailscaleLoginURL  string
	TenantPrivateCIDR  string
	AccessibleTenants  []string
	Projects           []string
	CurrentTenant      string
	CurrentProject     string
	SSHKeyFingerprint  string
	TenantTailnetState string
	TailscaleAuthKey   string
	NextCommand        string
	LoginResult        *CLILoginResult
	ExpiresIn          int
	Warning            string
}

type DevicePollRequest struct {
	SSHPublicKey  string
	LocalUnixUser string
	// TailscaleAuthKey is the tenant's own tailnet key (BYO tailnet) used to
	// join the sidecar during provisioning; empty means interactive join.
	TailscaleAuthKey string
	// AwaitingTailnet re-runs the idempotent provisioning so an interactive
	// tailnet join is noticed (the client polls with this while waiting).
	AwaitingTailnet bool
	// DNSSuffix is the tenant-chosen Tenant DNS Suffix for first-login
	// provisioning (ADR-0018); empty means the tenant name.
	DNSSuffix string
	// InitialProject is the tenant-chosen initial-project short name for
	// first-login provisioning (issue #93); empty means "default".
	InitialProject string
	// ClientCertificatePEM is the client's existing shared-identity Incus
	// certificate, when one exists — the server unions this install's projects
	// into its trust entry (multi-install shared identity).
	ClientCertificatePEM string
}

func (c DeviceClient) Start(ctx context.Context) (DeviceStartResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/device/start"), nil)
	if err != nil {
		return DeviceStartResult{}, err
	}
	response, err := c.client().Do(request)
	if err != nil {
		return DeviceStartResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return DeviceStartResult{}, fmt.Errorf("auth app device start: %s", response.Status)
	}
	var payload deviceStartResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return DeviceStartResult{}, err
	}
	return DeviceStartResult{
		DeviceCode:      payload.DeviceCode,
		UserCode:        payload.UserCode,
		VerificationURI: payload.VerificationURI,
		ExpiresIn:       payload.ExpiresIn,
		Interval:        payload.Interval,
		Status:          payload.Status,
		Message:         payload.Message,
	}, nil
}

func (c DeviceClient) Poll(ctx context.Context, deviceCode string, poll DevicePollRequest) (DevicePollResult, error) {
	body, _ := json.Marshal(map[string]any{
		"device_code":        deviceCode,
		"ssh_public_key":     poll.SSHPublicKey,
		"local_unix_user":    poll.LocalUnixUser,
		"tailscale_auth_key": poll.TailscaleAuthKey,
		"awaiting_tailnet":   poll.AwaitingTailnet,
		"dns_suffix":         poll.DNSSuffix,
		"initial_project":    poll.InitialProject,
		"client_certificate": poll.ClientCertificatePEM,
	})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/device/poll"), bytes.NewReader(body))
	if err != nil {
		return DevicePollResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client().Do(request)
	if err != nil {
		return DevicePollResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return DevicePollResult{}, fmt.Errorf("auth app device poll: %s", msg)
	}
	var payload devicePollResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return DevicePollResult{}, err
	}
	return DevicePollResult{
		Status:             payload.Status,
		Message:            payload.Message,
		UserKey:            payload.UserKey,
		CLIAuthToken:       payload.CLIAuthToken,
		Token:              payload.Token,
		DNSSuffix:          payload.DNSSuffix,
		RemoteName:         payload.RemoteName,
		IncusRemoteAddress: payload.IncusRemoteAddress,
		IncusProject:       payload.IncusProject,
		TailscaleLoginURL:  payload.TailscaleLoginURL,
		TenantPrivateCIDR:  payload.TenantPrivateCIDR,
		AccessibleTenants:  append([]string{}, payload.AccessibleTenants...),
		Projects:           append([]string{}, payload.Projects...),
		CurrentTenant:      payload.CurrentTenant,
		CurrentProject:     payload.CurrentProject,
		SSHKeyFingerprint:  payload.SSHKeyFingerprint,
		TenantTailnetState: payload.TenantTailnetState,
		TailscaleAuthKey:   payload.TailscaleAuthKey,
		NextCommand:        payload.NextCommand,
		LoginResult:        payload.LoginResult,
		ExpiresIn:          payload.ExpiresIn,
		Warning:            payload.Warning,
	}, nil
}

// DebugApprove calls the server-side /debug/device/approve endpoint, which
// auto-approves the pending device login without browser or GitHub interaction.
// The server must be running with --debug-device-user set to an allowlisted user.
func (c DeviceClient) DebugApprove(ctx context.Context, userCode string) error {
	body := strings.NewReader("user_code=" + userCode)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/debug/device/approve"), body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.client().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = response.Status
		}
		return fmt.Errorf("debug approve: %s", msg)
	}
	return nil
}

// CreateProject drives the token-gated POST /api/projects — the
// tunnel-friendly tenant plane for project creation (no broker port). A
// Project Domain refusal's `{error}` body (ADR-0027) is returned verbatim.
func (c DeviceClient) CreateProject(ctx context.Context, request ProjectCreateRequest) (projectbroker.ProjectResult, error) {
	body, _ := json.Marshal(request)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/projects"), bytes.NewReader(body))
	if err != nil {
		return projectbroker.ProjectResult{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return projectbroker.ProjectResult{}, err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(payload, &refusal) == nil && strings.TrimSpace(refusal.Error) != "" {
			return projectbroker.ProjectResult{}, errors.New(refusal.Error)
		}
		return projectbroker.ProjectResult{}, fmt.Errorf("create project: %s: %s", response.Status, strings.TrimSpace(string(payload)))
	}
	var result projectbroker.ProjectResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return projectbroker.ProjectResult{}, err
	}
	return result, nil
}

// RequestMachineCertificate drives POST /api/machine-certificates (ADR-0027):
// it asks the Auth App to record the Machine Certificate order for a
// zone-mode machine `sc create` just made. A 202 and a 409 rate-limited answer
// both return the view (the latter with Reason set — the row exists either
// way); any other status is an error.
func (c DeviceClient) RequestMachineCertificate(ctx context.Context, request MachineCertificateRequest) (MachineCertificateView, error) {
	body, _ := json.Marshal(request)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/machine-certificates"), bytes.NewReader(body))
	if err != nil {
		return MachineCertificateView{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return MachineCertificateView{}, err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	var view MachineCertificateView
	switch response.StatusCode {
	case http.StatusAccepted:
		if err := json.Unmarshal(payload, &view); err != nil {
			return MachineCertificateView{}, err
		}
		return view, nil
	case http.StatusConflict:
		if err := json.Unmarshal(payload, &view); err == nil && view.Reason != "" {
			return view, nil
		}
	}
	return MachineCertificateView{}, fmt.Errorf("request machine certificate: %s: %s", response.Status, strings.TrimSpace(string(payload)))
}

// ListMachineHostnames reads GET /api/machines/{project}/{machine}/hostnames
// (ADR-0028). tenant "" means the caller's own.
func (c DeviceClient) ListMachineHostnames(ctx context.Context, tenant, project, machine string) (MachineHostnamesResult, error) {
	var result MachineHostnamesResult
	err := c.publicDNSZoneCall(ctx, http.MethodGet, machineHostnamesPath(project, machine, "")+tenantQuery(tenant, false), nil, &result)
	return result, err
}

// AddMachineHostname drives POST /api/machines/{project}/{machine}/hostnames
// (`sc hostname add`, `sc create --hostname`).
func (c DeviceClient) AddMachineHostname(ctx context.Context, request MachineHostnameRequest, project, machine string) (MachineHostnamesResult, error) {
	var result MachineHostnamesResult
	err := c.publicDNSZoneCall(ctx, http.MethodPost, machineHostnamesPath(project, machine, ""), request, &result)
	return result, err
}

// RemoveMachineHostname drives DELETE /api/machines/{project}/{machine}/hostnames/{hostname}
// (`sc hostname remove`, and `sc create`'s release on a failed create).
func (c DeviceClient) RemoveMachineHostname(ctx context.Context, tenant, project, machine, hostname string, dryRun bool) (MachineHostnamesResult, error) {
	var result MachineHostnamesResult
	err := c.publicDNSZoneCall(ctx, http.MethodDelete, machineHostnamesPath(project, machine, hostname)+tenantQuery(tenant, dryRun), nil, &result)
	return result, err
}

func machineHostnamesPath(project, machine, hostname string) string {
	path := "/api/machines/" + url.PathEscape(strings.TrimSpace(project)) + "/" + url.PathEscape(strings.TrimSpace(machine)) + "/hostnames"
	if hostname = strings.TrimSpace(hostname); hostname != "" {
		path += "/" + url.PathEscape(hostname)
	}
	return path
}

// tenantQuery renders the optional ?tenant= and dryRun=1 query of the
// hostname endpoints.
func tenantQuery(tenant string, dryRun bool) string {
	values := url.Values{}
	if tenant = strings.TrimSpace(tenant); tenant != "" {
		values.Set("tenant", tenant)
	}
	if dryRun {
		values.Set("dryRun", "1")
	}
	if len(values) == 0 {
		return ""
	}
	return "?" + values.Encode()
}

// GetProjectDomain reads GET /api/projects/{name}/domain (ADR-0027).
func (c DeviceClient) GetProjectDomain(ctx context.Context, project string) (ProjectDomainResult, error) {
	var result ProjectDomainResult
	err := c.publicDNSZoneCall(ctx, http.MethodGet, "/api/projects/"+url.PathEscape(strings.TrimSpace(project))+"/domain", nil, &result)
	return result, err
}

// SetProjectDomain drives PUT /api/projects/{name}/domain (`sc project
// set-domain`); the refusal text comes back verbatim.
func (c DeviceClient) SetProjectDomain(ctx context.Context, project, domain string, dryRun bool) (ProjectDomainResult, error) {
	var result ProjectDomainResult
	err := c.publicDNSZoneCall(ctx, http.MethodPut, "/api/projects/"+url.PathEscape(strings.TrimSpace(project))+"/domain", ProjectDomainRequest{Domain: domain, DryRun: dryRun}, &result)
	return result, err
}

// UnsetProjectDomain drives DELETE /api/projects/{name}/domain (`sc project
// unset-domain`).
func (c DeviceClient) UnsetProjectDomain(ctx context.Context, project string, dryRun bool) (ProjectDomainResult, error) {
	var result ProjectDomainResult
	err := c.publicDNSZoneCall(ctx, http.MethodDelete, "/api/projects/"+url.PathEscape(strings.TrimSpace(project))+"/domain"+dryRunQuery(dryRun), nil, &result)
	return result, err
}

// DeleteProject drives DELETE /api/projects/{name} (`sc project delete` on an
// Auth App install): releases the Project Domain claim, then deletes the
// Incus project.
func (c DeviceClient) DeleteProject(ctx context.Context, project string, dryRun bool) (ProjectDomainResult, error) {
	var result ProjectDomainResult
	err := c.publicDNSZoneCall(ctx, http.MethodDelete, "/api/projects/"+url.PathEscape(strings.TrimSpace(project))+dryRunQuery(dryRun), nil, &result)
	return result, err
}

func dryRunQuery(dryRun bool) string {
	if dryRun {
		return "?dryRun=1"
	}
	return ""
}

// UpdateSidecar asks the deployment to update the caller's own tenant
// sidecar to the deployment's running binary (#124 §5) via the
// token-authenticated POST /api/sidecar/update.
func (c DeviceClient) UpdateSidecar(ctx context.Context) (projectbroker.SidecarUpdateResult, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/sidecar/update"), nil)
	if err != nil {
		return projectbroker.SidecarUpdateResult{}, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	response, err := c.client().Do(request)
	if err != nil {
		return projectbroker.SidecarUpdateResult{}, err
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return projectbroker.SidecarUpdateResult{}, fmt.Errorf("sidecar update: %s: %s", response.Status, strings.TrimSpace(string(payload)))
	}
	var result projectbroker.SidecarUpdateResult
	if err := json.Unmarshal(payload, &result); err != nil {
		return projectbroker.SidecarUpdateResult{}, err
	}
	return result, nil
}

// SimulateApprove drives the token-gated /oauth/github/simulate endpoint to
// approve the pending device login as `username`, with no browser and no GitHub.
// The server must be running with --simulate-github-token equal to `token`. This
// is the offline counterpart to a real GitHub device login (DEV ONLY).
func (c DeviceClient) SimulateApprove(ctx context.Context, userCode, username, token string) error {
	form := url.Values{}
	form.Set("token", token)
	form.Set("username", username)
	form.Set("user_code", userCode)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/oauth/github/simulate"), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.client().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = response.Status
		}
		return fmt.Errorf("simulate approve: %s", msg)
	}
	return nil
}

func (c DeviceClient) EnableWorkload(ctx context.Context, request WorkloadEnableRequest) (WorkloadEnableResult, error) {
	body, _ := json.Marshal(request)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/workload/enable"), bytes.NewReader(body))
	if err != nil {
		return WorkloadEnableResult{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return WorkloadEnableResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return WorkloadEnableResult{}, fmt.Errorf("auth app workload enable: %s", msg)
	}
	var payload WorkloadEnableResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return WorkloadEnableResult{}, err
	}
	return payload, nil
}

func (c DeviceClient) UpsertCloudIdentity(ctx context.Context, request CloudIdentityUpsertRequest) (CloudIdentityConfig, error) {
	body, _ := json.Marshal(request)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/cloud-identities"), bytes.NewReader(body))
	if err != nil {
		return CloudIdentityConfig{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return CloudIdentityConfig{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return CloudIdentityConfig{}, fmt.Errorf("auth app cloud identity upsert: %s", msg)
	}
	var payload struct {
		ID                                string `json:"id"`
		UserKey                           string `json:"user_key"`
		Tenant                            string `json:"tenant"`
		Name                              string `json:"name"`
		Provider                          string `json:"provider"`
		GCPAudience                       string `json:"gcp_audience"`
		GCPSubjectTokenType               string `json:"gcp_subject_token_type"`
		GCPServiceAccountImpersonationURL string `json:"gcp_service_account_impersonation_url"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return CloudIdentityConfig{}, err
	}
	return CloudIdentityConfig{
		ID:                                payload.ID,
		UserKey:                           payload.UserKey,
		Tenant:                            payload.Tenant,
		Name:                              payload.Name,
		Provider:                          payload.Provider,
		GCPAudience:                       payload.GCPAudience,
		GCPSubjectTokenType:               payload.GCPSubjectTokenType,
		GCPServiceAccountImpersonationURL: payload.GCPServiceAccountImpersonationURL,
	}, nil
}

func (c DeviceClient) GetCloudIdentity(ctx context.Context, tenant string, name string) (CloudIdentityConfig, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/api/cloud-identities"), nil)
	if err != nil {
		return CloudIdentityConfig{}, err
	}
	query := httpRequest.URL.Query()
	query.Set("tenant", strings.TrimSpace(tenant))
	query.Set("name", strings.TrimSpace(name))
	httpRequest.URL.RawQuery = query.Encode()
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return CloudIdentityConfig{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return CloudIdentityConfig{}, fmt.Errorf("auth app cloud identity get: %s", msg)
	}
	var payload struct {
		ID                                string `json:"id"`
		UserKey                           string `json:"user_key"`
		Tenant                            string `json:"tenant"`
		Name                              string `json:"name"`
		Provider                          string `json:"provider"`
		GCPAudience                       string `json:"gcp_audience"`
		GCPSubjectTokenType               string `json:"gcp_subject_token_type"`
		GCPServiceAccountImpersonationURL string `json:"gcp_service_account_impersonation_url"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return CloudIdentityConfig{}, err
	}
	return CloudIdentityConfig{
		ID:                                payload.ID,
		UserKey:                           payload.UserKey,
		Tenant:                            payload.Tenant,
		Name:                              payload.Name,
		Provider:                          payload.Provider,
		GCPAudience:                       payload.GCPAudience,
		GCPSubjectTokenType:               payload.GCPSubjectTokenType,
		GCPServiceAccountImpersonationURL: payload.GCPServiceAccountImpersonationURL,
	}, nil
}

func (c DeviceClient) ListTenants(ctx context.Context) ([]TenantAccessSummary, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/api/tenants"), nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return nil, fmt.Errorf("auth app tenant list: %s", msg)
	}
	var payload TenantAccessListResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Tenants, nil
}

// ResourceListRequest is the query for GET /api/resources — the cache-backed
// counterpart of listMachinesRequest (internal/cli/list.go). Tenant is
// optional (see selectAccessibleTenant in resource_cache_api.go); Project and
// Machine carry the same literal-or-glob values `sc ls` already accepts.
type ResourceListRequest struct {
	Tenant  string
	Project string
	Machine string
	// Include names the resource kinds the caller will actually render (the
	// resourceKind* constants in resource_cache_api.go). Empty means "send
	// everything", which is what an appliance predating the param does anyway;
	// `sc ls` always fills it, because shipping the four resource types it is
	// not going to print is what pushed a real install's response to 79 KB and
	// its round trip past the cache budget.
	Include []string
}

// ListResources calls the t2 cache-backed GET /api/resources endpoint. `sc
// ls` (t3, internal/cli/list.go) treats ANY error return — network failure,
// timeout, or non-200 status (including the 503 the endpoint answers when the
// toggle is off or the cache is not ready) — as a signal to fall back to the
// live per-project Incus path; it never inspects the error string.
func (c DeviceClient) ListResources(ctx context.Context, request ResourceListRequest) (ResourceListResult, error) {
	query := url.Values{}
	if v := strings.TrimSpace(request.Tenant); v != "" {
		query.Set("tenant", v)
	}
	if v := strings.TrimSpace(request.Project); v != "" {
		query.Set("project", v)
	}
	if v := strings.TrimSpace(request.Machine); v != "" {
		query.Set("machine", v)
	}
	kinds := make([]string, 0, len(request.Include))
	for _, kind := range request.Include {
		if kind = strings.TrimSpace(kind); kind != "" {
			kinds = append(kinds, kind)
		}
	}
	if len(kinds) > 0 {
		query.Set("include", strings.Join(kinds, ","))
	}
	path := "/api/resources"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return ResourceListResult{}, err
	}
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return ResourceListResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return ResourceListResult{}, fmt.Errorf("auth app resource list: %s", msg)
	}
	var payload ResourceListResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return ResourceListResult{}, err
	}
	return payload, nil
}

func (c DeviceClient) CreateShare(ctx context.Context, request ShareCreateRequest) (share.Result, error) {
	body, _ := json.Marshal(request)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/shares"), bytes.NewReader(body))
	if err != nil {
		return share.Result{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return share.Result{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return share.Result{}, fmt.Errorf("auth app share create: %s", msg)
	}
	var payload share.Result
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return share.Result{}, err
	}
	return payload, nil
}

func (c DeviceClient) ListShares(ctx context.Context, tenant string) ([]meta.TenantStorageShare, error) {
	return c.listShares(ctx, tenant, "")
}

func (c DeviceClient) ListInboundShares(ctx context.Context, tenant string) ([]meta.TenantStorageShare, error) {
	return c.listShares(ctx, tenant, "inbound")
}

func (c DeviceClient) ListShareOffers(ctx context.Context, tenant string) ([]meta.TenantStorageShare, error) {
	return c.listShares(ctx, tenant, "offers")
}

func (c DeviceClient) listShares(ctx context.Context, tenant string, direction string) ([]meta.TenantStorageShare, error) {
	query := "?tenant=" + url.QueryEscape(strings.TrimSpace(tenant))
	if strings.TrimSpace(direction) != "" {
		query += "&direction=" + url.QueryEscape(strings.TrimSpace(direction))
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/api/shares")+query, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return nil, fmt.Errorf("auth app share list: %s", msg)
	}
	var payload ShareListResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Shares, nil
}

func (c DeviceClient) GetShare(ctx context.Context, request ShareStatusRequest) (share.Result, error) {
	query := "?tenant=" + url.QueryEscape(strings.TrimSpace(request.Tenant)) + "&project=" + url.QueryEscape(strings.TrimSpace(request.Project)) + "&name=" + url.QueryEscape(strings.TrimSpace(request.Name))
	if strings.TrimSpace(request.SourceTenant) != "" {
		query += "&source_tenant=" + url.QueryEscape(strings.TrimSpace(request.SourceTenant))
	}
	if request.Inbound {
		query += "&direction=inbound"
	}
	if request.Verbose {
		query += "&verbose=1"
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/api/shares/status")+query, nil)
	if err != nil {
		return share.Result{}, err
	}
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return share.Result{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return share.Result{}, fmt.Errorf("auth app share status: %s", msg)
	}
	var payload share.Result
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return share.Result{}, err
	}
	return payload, nil
}

func (c DeviceClient) AcceptShare(ctx context.Context, request ShareRecipientRequest) (share.Result, error) {
	return c.shareRecipientMutation(ctx, "/api/shares/accept", request, "accept")
}

func (c DeviceClient) DeclineShare(ctx context.Context, request ShareRecipientRequest) (share.Result, error) {
	return c.shareRecipientMutation(ctx, "/api/shares/decline", request, "decline")
}

func (c DeviceClient) RevokeShare(ctx context.Context, request ShareRevokeRequest) (share.Result, error) {
	body, _ := json.Marshal(request)
	return c.postShareResult(ctx, "/api/shares/revoke", body, "revoke")
}

func (c DeviceClient) DeleteShare(ctx context.Context, request ShareDeleteRequest) (share.Result, error) {
	body, _ := json.Marshal(request)
	return c.postShareResult(ctx, "/api/shares/delete", body, "delete")
}

func (c DeviceClient) shareRecipientMutation(ctx context.Context, path string, request ShareRecipientRequest, label string) (share.Result, error) {
	body, _ := json.Marshal(request)
	return c.postShareResult(ctx, path, body, label)
}

func (c DeviceClient) postShareResult(ctx context.Context, path string, body []byte, label string) (share.Result, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(path), bytes.NewReader(body))
	if err != nil {
		return share.Result{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return share.Result{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return share.Result{}, fmt.Errorf("auth app share %s: %s", label, msg)
	}
	var payload share.Result
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return share.Result{}, err
	}
	return payload, nil
}

func (c DeviceClient) ReconcileShares(ctx context.Context, request ShareReconcileRequest) (share.ReconcileResult, error) {
	body, _ := json.Marshal(request)
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/api/shares/reconcile"), bytes.NewReader(body))
	if err != nil {
		return share.ReconcileResult{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.AuthToken) != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
	}
	response, err := c.client().Do(httpRequest)
	if err != nil {
		return share.ReconcileResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = response.Status
		}
		return share.ReconcileResult{}, fmt.Errorf("auth app share reconcile: %s", msg)
	}
	var payload share.ReconcileResult
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return share.ReconcileResult{}, err
	}
	return payload, nil
}

func (c DeviceClient) url(path string) string {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}
	return base + path
}

func (c DeviceClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	// The default client performs the version exchange (#124 §6): it sends the
	// CLI version and records the appliance version/minimum from responses so
	// the CLI can print a skew warning after its normal output.
	return &http.Client{
		Timeout:   defaultDeviceClientTimeout,
		Transport: update.DefaultExchange.WrapTransport(nil),
	}
}
