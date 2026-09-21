package authapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/tenant"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
)

type WorkloadEnableRequest struct {
	DeviceCode          string `json:"device_code"`
	Tenant              string `json:"tenant"`
	Project             string `json:"project"`
	Machine             string `json:"machine"`
	CloudIdentityConfig string `json:"cloud_identity_config,omitempty"`
}

type WorkloadEnableResult struct {
	Tenant                            string `json:"tenant"`
	Project                           string `json:"project"`
	Machine                           string `json:"machine"`
	RuntimeSecret                     string `json:"runtime_secret"`
	TokenEndpoint                     string `json:"token_endpoint"`
	Issuer                            string `json:"issuer"`
	ExpiresInSeconds                  int    `json:"expires_in_seconds"`
	CloudIdentityConfig               string `json:"cloud_identity_config,omitempty"`
	GCPAudience                       string `json:"gcp_audience,omitempty"`
	GCPSubjectTokenType               string `json:"gcp_subject_token_type,omitempty"`
	GCPServiceAccountImpersonationURL string `json:"gcp_service_account_impersonation_url,omitempty"`
}

func (h handler) workloadEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request WorkloadEnableRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userKey, err := h.workloadEnableUser(r, request.DeviceCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	result, err := h.enableWorkloadForUser(r.Context(), userKey, request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h handler) workloadEnableUser(r *http.Request, deviceCode string) (string, error) {
	if token := bearerToken(r.Header.Get("Authorization")); token != "" {
		user, err := UserForCLIToken(r.Context(), h.db, token, timeNow())
		if err != nil {
			return "", err
		}
		return user.UserKey, nil
	}
	deviceCode = strings.TrimSpace(deviceCode)
	if deviceCode == "" {
		return "", fmt.Errorf("device_code or bearer token is required")
	}
	login, err := PollDeviceLogin(r.Context(), h.db, deviceCode, timeNow())
	if err != nil {
		return "", err
	}
	if login.Status != DeviceStatusApproved {
		return "", fmt.Errorf("device login is %s", login.Status)
	}
	if !timeNow().Before(login.ExpiresAt) {
		return "", fmt.Errorf("device login expired")
	}
	return login.UserKey, nil
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if len(header) < len("Bearer ") || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(header[len("Bearer "):])
}

func (h handler) enableWorkloadForUser(ctx context.Context, userKey string, request WorkloadEnableRequest) (WorkloadEnableResult, error) {
	request.DeviceCode = strings.TrimSpace(request.DeviceCode)
	request.Tenant = strings.TrimSpace(request.Tenant)
	request.Project = strings.TrimSpace(request.Project)
	request.Machine = strings.TrimSpace(request.Machine)
	request.CloudIdentityConfig = strings.TrimSpace(request.CloudIdentityConfig)
	if err := h.authorizeWorkloadTenant(ctx, userKey, request.Tenant); err != nil {
		return WorkloadEnableResult{}, err
	}
	if h.tenants == nil || h.machines == nil {
		return WorkloadEnableResult{}, fmt.Errorf("machine verification stores are not configured")
	}
	if _, _, err := h.findEnabledMachine(ctx, request.Tenant, request.Project, request.Machine); err != nil {
		return WorkloadEnableResult{}, err
	}
	var cloudConfig CloudIdentityConfig
	if request.CloudIdentityConfig != "" {
		var err error
		cloudConfig, err = FindCloudIdentityConfig(ctx, h.db, userKey, request.Tenant, request.CloudIdentityConfig)
		if err != nil {
			return WorkloadEnableResult{}, err
		}
	}
	enabled, err := EnableMachineWorkloadIdentity(ctx, h.db, h.authHostname, MachineRuntimeSecretRequest{
		Tenant:         request.Tenant,
		Project:        request.Project,
		Machine:        request.Machine,
		UserKey:        userKey,
		GitHubUsername: userKey,
	})
	if err != nil {
		return WorkloadEnableResult{}, err
	}
	result := WorkloadEnableResult{
		Tenant:           enabled.Tenant,
		Project:          enabled.Project,
		Machine:          enabled.Machine,
		RuntimeSecret:    enabled.RuntimeSecret,
		TokenEndpoint:    enabled.TokenEndpoint,
		Issuer:           enabled.Issuer,
		ExpiresInSeconds: enabled.ExpiresInSecond,
	}
	if request.CloudIdentityConfig != "" {
		result.CloudIdentityConfig = cloudConfig.Name
		result.GCPAudience = cloudConfig.GCPAudience
		result.GCPSubjectTokenType = cloudConfig.GCPSubjectTokenType
		result.GCPServiceAccountImpersonationURL = cloudConfig.GCPServiceAccountImpersonationURL
	}
	return result, nil
}

func (h handler) authorizeWorkloadTenant(ctx context.Context, userKey string, tenantName string) error {
	userKey = NormalizeGitHubUsername(userKey)
	tenantName = strings.TrimSpace(tenantName)
	if userKey == "" {
		return fmt.Errorf("device login user is required")
	}
	if tenantName == "" {
		return fmt.Errorf("tenant is required")
	}
	if userKey == tenantName {
		return nil
	}
	if h.tenants == nil || h.tenantAccess == nil {
		return fmt.Errorf("user %s is not authorized for tenant %s", userKey, tenantName)
	}
	summaries, err := tenant.ListForPrefix(ctx, h.tenants, h.admin.IncusProjectPrefix)
	if err != nil {
		return err
	}
	for _, summary := range summaries {
		if summary.Tenant != tenantName {
			continue
		}
		// Shared Tenant: membership recorded in Tenant Metadata wins outright.
		if summary.Accessible(userKey) {
			return nil
		}
		plan, err := usertrust.PlanTenantUsersForRequest(h.admin, usertrust.TenantAccessRequest{Tenant: summary.Tenant, Personal: summary.Personal})
		if err != nil {
			return err
		}
		result, err := h.tenantAccess.ListTenantUsers(ctx, plan)
		if err != nil {
			return err
		}
		for _, user := range result.Users {
			if NormalizeGitHubUsername(user) == userKey {
				return nil
			}
		}
		return fmt.Errorf("user %s is not authorized for tenant %s", userKey, tenantName)
	}
	return fmt.Errorf("tenant %s not found", tenantName)
}
