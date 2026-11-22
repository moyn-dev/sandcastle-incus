package authapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	"github.com/moyn-dev/sandcastle-incus/internal/svclog"
	"github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

const workloadTokenTTL = 15 * time.Minute

type MachineRuntimeSecretRequest struct {
	Tenant         string
	Project        string
	Machine        string
	UserKey        string
	GitHubUsername string
}

type MachineRuntimeSecretResult struct {
	Tenant          string `json:"tenant"`
	Project         string `json:"project"`
	Machine         string `json:"machine"`
	RuntimeSecret   string `json:"runtimeSecret"`
	TokenEndpoint   string `json:"tokenEndpoint"`
	Issuer          string `json:"issuer"`
	ExpiresInSecond int    `json:"expiresInSeconds"`
}

func EnableMachineWorkloadIdentity(ctx context.Context, db *sql.DB, authHostname string, request MachineRuntimeSecretRequest) (MachineRuntimeSecretResult, error) {
	if err := validateMachineRuntimeSecretRequest(request); err != nil {
		return MachineRuntimeSecretResult{}, err
	}
	if _, err := EnsureOIDCSigningKey(ctx, db, request.Tenant); err != nil {
		return MachineRuntimeSecretResult{}, err
	}
	secret, err := randomToken(32)
	if err != nil {
		return MachineRuntimeSecretResult{}, err
	}
	verifier := runtimeSecretVerifier(secret)
	_, err = db.ExecContext(ctx, `
INSERT INTO machine_runtime_secrets (tenant, project, machine, user_key, github_username, secret_verifier, enabled, rotated_at)
VALUES (?, ?, ?, ?, ?, ?, 1, ?)
ON CONFLICT(tenant, project, machine) DO UPDATE SET
    user_key = excluded.user_key,
    github_username = excluded.github_username,
    secret_verifier = excluded.secret_verifier,
    enabled = 1,
    rotated_at = excluded.rotated_at
`, request.Tenant, request.Project, request.Machine, request.UserKey, request.GitHubUsername, verifier, timeNow().UTC().Format(time.RFC3339))
	if err != nil {
		return MachineRuntimeSecretResult{}, fmt.Errorf("store machine runtime secret verifier: %w", err)
	}
	issuer, err := oidcIssuer(authHostname)
	if err != nil {
		return MachineRuntimeSecretResult{}, err
	}
	tenantIssuer, err := tenantOIDCIssuer(authHostname, request.Tenant)
	if err != nil {
		return MachineRuntimeSecretResult{}, err
	}
	return MachineRuntimeSecretResult{
		Tenant:          request.Tenant,
		Project:         request.Project,
		Machine:         request.Machine,
		RuntimeSecret:   secret,
		TokenEndpoint:   issuer + "/internal/workload/token",
		Issuer:          tenantIssuer,
		ExpiresInSecond: int(workloadTokenTTL.Seconds()),
	}, nil
}

func (h handler) workloadToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Tenant        string `json:"tenant"`
		Project       string `json:"project"`
		Machine       string `json:"machine"`
		RuntimeSecret string `json:"runtime_secret"`
		Audience      string `json:"audience"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.Audience) == "" {
		http.Error(w, "audience is required", http.StatusBadRequest)
		return
	}
	token, err := h.mintWorkloadToken(r.Context(), request.Tenant, request.Project, request.Machine, request.RuntimeSecret, request.Audience)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token_type":   "Bearer",
		"access_token": token,
		"expires_in":   int(workloadTokenTTL.Seconds()),
	})
}

func (h handler) mintWorkloadToken(ctx context.Context, tenantName string, projectName string, machineName string, secret string, audience string) (string, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return "", fmt.Errorf("audience is required")
	}
	if h.tenants == nil || h.machines == nil {
		return "", fmt.Errorf("machine verification stores are not configured")
	}
	enabled, err := findMachineRuntimeSecret(ctx, h.db, tenantName, projectName, machineName)
	if err != nil {
		return "", err
	}
	if !enabled.Enabled {
		return "", fmt.Errorf("workload identity is disabled for machine")
	}
	if runtimeSecretVerifier(secret) != enabled.SecretVerifier {
		return "", fmt.Errorf("invalid machine runtime secret")
	}
	// Attribute this issuance to the machine's owner so it appears in that
	// user's activity log (the caller is the machine, not a web session).
	svclog.SetUser(ctx, enabled.UserKey)
	svclog.Logf(ctx, "issue workload token for %s/%s/%s audience=%s", tenantName, projectName, machineName, audience)
	summary, machineState, err := h.findEnabledMachine(ctx, tenantName, projectName, machineName)
	if err != nil {
		return "", err
	}
	issuer, err := tenantOIDCIssuer(h.authHostname, summary.Tenant)
	if err != nil {
		return "", err
	}
	now := timeNow().UTC()
	issuedAt := now.Add(-30 * time.Second)
	claims := map[string]any{
		"iss":                 issuer,
		"sub":                 "machine:" + summary.Tenant + "/" + machineState.Project + "/" + machineState.Name,
		"iat":                 issuedAt.Unix(),
		"nbf":                 issuedAt.Unix(),
		"exp":                 now.Add(workloadTokenTTL).Unix(),
		"tenant":              summary.Tenant,
		"project":             machineState.Project,
		"machine":             machineState.Name,
		"sandcastle_user_key": enabled.UserKey,
		"github_username":     enabled.GitHubUsername,
	}
	claims["aud"] = audience
	key, privateKey, err := activeOIDCPrivateKey(ctx, h.db, summary.Tenant)
	if err != nil {
		return "", err
	}
	return signJWT(key.KID, privateKey, claims)
}

type machineRuntimeSecret struct {
	Tenant         string
	Project        string
	Machine        string
	UserKey        string
	GitHubUsername string
	SecretVerifier string
	Enabled        bool
}

func findMachineRuntimeSecret(ctx context.Context, db *sql.DB, tenantName string, projectName string, machineName string) (machineRuntimeSecret, error) {
	row := db.QueryRowContext(ctx, `
SELECT tenant, project, machine, user_key, github_username, secret_verifier, enabled
FROM machine_runtime_secrets
WHERE tenant = ? AND project = ? AND machine = ?
`, strings.TrimSpace(tenantName), strings.TrimSpace(projectName), strings.TrimSpace(machineName))
	var value machineRuntimeSecret
	var enabled int
	if err := row.Scan(&value.Tenant, &value.Project, &value.Machine, &value.UserKey, &value.GitHubUsername, &value.SecretVerifier, &enabled); err != nil {
		if err == sql.ErrNoRows {
			return machineRuntimeSecret{}, fmt.Errorf("workload identity is not enabled for machine")
		}
		return machineRuntimeSecret{}, err
	}
	value.Enabled = enabled == 1
	return value, nil
}

func (h handler) findEnabledMachine(ctx context.Context, tenantName string, projectName string, machineName string) (tenant.Summary, meta.Machine, error) {
	summaries, err := tenant.ListForPrefix(ctx, h.tenants, h.admin.IncusProjectPrefix)
	if err != nil {
		return tenant.Summary{}, meta.Machine{}, err
	}
	for _, summary := range summaries {
		if summary.Tenant != tenantName {
			continue
		}
		machines, err := h.machines.ListMachines(ctx, summary)
		if err != nil {
			return tenant.Summary{}, meta.Machine{}, err
		}
		for _, machineState := range machines {
			if machineState.Project == projectName && machineState.Name == machineName {
				return summary, machineState, nil
			}
		}
		return tenant.Summary{}, meta.Machine{}, fmt.Errorf("machine %s/%s/%s not found", tenantName, projectName, machineName)
	}
	return tenant.Summary{}, meta.Machine{}, fmt.Errorf("tenant %s not found", tenantName)
}

func validateMachineRuntimeSecretRequest(request MachineRuntimeSecretRequest) error {
	for label, value := range map[string]string{
		"tenant":  request.Tenant,
		"project": request.Project,
		"machine": request.Machine,
		"user":    request.UserKey,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	return nil
}

func runtimeSecretVerifier(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func signJWT(kid string, privateKey *rsa.PrivateKey, claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": oidcSigningAlg, "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
