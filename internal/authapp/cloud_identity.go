package authapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	machinepkg "github.com/moyn-dev/sandcastle-incus/internal/machine"
	"github.com/moyn-dev/sandcastle-incus/internal/svclog"
)

type CloudIdentityConfig struct {
	ID                                string
	UserKey                           string
	Tenant                            string
	Name                              string
	Provider                          string
	GCPAudience                       string
	GCPSubjectTokenType               string
	GCPServiceAccountImpersonationURL string
}

type CloudIdentityUpsertRequest struct {
	Tenant                            string `json:"tenant"`
	Name                              string `json:"name"`
	Provider                          string `json:"provider,omitempty"`
	GCPAudience                       string `json:"gcp_audience"`
	GCPSubjectTokenType               string `json:"gcp_subject_token_type,omitempty"`
	GCPServiceAccountImpersonationURL string `json:"gcp_service_account_impersonation_url,omitempty"`
}

func UpsertCloudIdentityConfig(ctx context.Context, db *sql.DB, config CloudIdentityConfig) (CloudIdentityConfig, error) {
	config.UserKey = NormalizeGitHubUsername(config.UserKey)
	config.Tenant = strings.TrimSpace(config.Tenant)
	config.Name = strings.TrimSpace(config.Name)
	config.Provider = strings.TrimSpace(config.Provider)
	if config.UserKey == "" || config.Tenant == "" || config.Name == "" {
		return CloudIdentityConfig{}, fmt.Errorf("user, tenant, and config name are required")
	}
	if config.Provider == "" {
		config.Provider = "gcp"
	}
	if config.Provider != "gcp" {
		return CloudIdentityConfig{}, fmt.Errorf("unsupported cloud identity provider %q", config.Provider)
	}
	if strings.TrimSpace(config.GCPAudience) == "" {
		return CloudIdentityConfig{}, fmt.Errorf("GCP audience is required")
	}
	id := config.ID
	if id == "" {
		var err error
		id, err = randomToken(16)
		if err != nil {
			return CloudIdentityConfig{}, err
		}
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO cloud_identity_configs (
    id, user_key, tenant, name, provider, gcp_audience, gcp_subject_token_type,
    gcp_service_account_impersonation_url, deleted, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'))
ON CONFLICT(user_key, tenant, name) DO UPDATE SET
    provider = excluded.provider,
    gcp_audience = excluded.gcp_audience,
    gcp_subject_token_type = excluded.gcp_subject_token_type,
    gcp_service_account_impersonation_url = excluded.gcp_service_account_impersonation_url,
    deleted = 0,
    updated_at = datetime('now')
`, id, config.UserKey, config.Tenant, config.Name, config.Provider, strings.TrimSpace(config.GCPAudience), strings.TrimSpace(config.GCPSubjectTokenType), strings.TrimSpace(config.GCPServiceAccountImpersonationURL))
	if err != nil {
		return CloudIdentityConfig{}, err
	}
	return FindCloudIdentityConfig(ctx, db, config.UserKey, config.Tenant, config.Name)
}

func ListCloudIdentityConfigs(ctx context.Context, db *sql.DB, userKey string) ([]CloudIdentityConfig, error) {
	rows, err := db.QueryContext(ctx, `
SELECT id, user_key, tenant, name, provider, gcp_audience, gcp_subject_token_type, gcp_service_account_impersonation_url
FROM cloud_identity_configs
WHERE user_key = ? AND deleted = 0
ORDER BY tenant, name
`, NormalizeGitHubUsername(userKey))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var configs []CloudIdentityConfig
	for rows.Next() {
		config, err := scanCloudIdentityConfig(rows)
		if err != nil {
			return nil, err
		}
		configs = append(configs, config)
	}
	return configs, rows.Err()
}

func FindCloudIdentityConfig(ctx context.Context, db *sql.DB, userKey string, tenant string, name string) (CloudIdentityConfig, error) {
	row := db.QueryRowContext(ctx, `
SELECT id, user_key, tenant, name, provider, gcp_audience, gcp_subject_token_type, gcp_service_account_impersonation_url
FROM cloud_identity_configs
WHERE user_key = ? AND tenant = ? AND name = ? AND deleted = 0
`, NormalizeGitHubUsername(userKey), strings.TrimSpace(tenant), strings.TrimSpace(name))
	return scanCloudIdentityConfig(row)
}

func DeleteCloudIdentityConfig(ctx context.Context, db *sql.DB, userKey string, tenant string, name string) error {
	result, err := db.ExecContext(ctx, `
UPDATE cloud_identity_configs
SET deleted = 1, updated_at = datetime('now')
WHERE user_key = ? AND tenant = ? AND name = ?
`, NormalizeGitHubUsername(userKey), strings.TrimSpace(tenant), strings.TrimSpace(name))
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err == nil && rows == 0 {
		return fmt.Errorf("cloud identity config not found")
	}
	return nil
}

func MachineWorkloadIdentityForCloudConfig(ctx context.Context, db *sql.DB, userKey string, tenant string, name string, tokenEndpoint string, runtimeSecret string) (*machinepkg.WorkloadIdentityRequest, error) {
	config, err := FindCloudIdentityConfig(ctx, db, userKey, tenant, name)
	if err != nil {
		return nil, err
	}
	return &machinepkg.WorkloadIdentityRequest{
		TokenEndpoint: tokenEndpoint,
		RuntimeSecret: runtimeSecret,
		GCP: &machinepkg.GCPWorkloadIdentityConfig{
			Audience:                       config.GCPAudience,
			SubjectTokenType:               config.GCPSubjectTokenType,
			ServiceAccountImpersonationURL: config.GCPServiceAccountImpersonationURL,
		},
	}, nil
}

type cloudIdentityScanner interface {
	Scan(dest ...any) error
}

func scanCloudIdentityConfig(scanner cloudIdentityScanner) (CloudIdentityConfig, error) {
	var config CloudIdentityConfig
	if err := scanner.Scan(&config.ID, &config.UserKey, &config.Tenant, &config.Name, &config.Provider, &config.GCPAudience, &config.GCPSubjectTokenType, &config.GCPServiceAccountImpersonationURL); err != nil {
		if err == sql.ErrNoRows {
			return CloudIdentityConfig{}, fmt.Errorf("cloud identity config not found")
		}
		return CloudIdentityConfig{}, err
	}
	return config, nil
}

func (h handler) cloudIdentities(w http.ResponseWriter, r *http.Request) {
	user, err := h.requireAllowlistedSession(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		configs, err := ListCloudIdentityConfigs(r.Context(), h.db, user.UserKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = cloudIdentityTemplate.Execute(w, configs)
	case http.MethodPost:
		_, err := UpsertCloudIdentityConfig(r.Context(), h.db, CloudIdentityConfig{
			UserKey:                           user.UserKey,
			Tenant:                            r.FormValue("tenant"),
			Name:                              r.FormValue("name"),
			Provider:                          "gcp",
			GCPAudience:                       r.FormValue("gcp_audience"),
			GCPSubjectTokenType:               r.FormValue("gcp_subject_token_type"),
			GCPServiceAccountImpersonationURL: r.FormValue("gcp_service_account_impersonation_url"),
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/cloud-identities", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h handler) cloudIdentityDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, err := h.requireAllowlistedSession(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := DeleteCloudIdentityConfig(r.Context(), h.db, user.UserKey, r.FormValue("tenant"), r.FormValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/cloud-identities", http.StatusSeeOther)
}

func (h handler) cloudIdentitiesAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	user, err := h.requireBearerUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet {
		tenant := r.URL.Query().Get("tenant")
		name := r.URL.Query().Get("name")
		if strings.TrimSpace(tenant) == "" || strings.TrimSpace(name) == "" {
			http.Error(w, "tenant and name are required", http.StatusBadRequest)
			return
		}
		config, err := FindCloudIdentityConfig(r.Context(), h.db, user.UserKey, tenant, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, cloudIdentityAPIResponse(config))
		return
	}
	var request CloudIdentityUpsertRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	saved, err := UpsertCloudIdentityConfig(r.Context(), h.db, CloudIdentityConfig{
		UserKey:                           user.UserKey,
		Tenant:                            request.Tenant,
		Name:                              request.Name,
		Provider:                          request.Provider,
		GCPAudience:                       request.GCPAudience,
		GCPSubjectTokenType:               request.GCPSubjectTokenType,
		GCPServiceAccountImpersonationURL: request.GCPServiceAccountImpersonationURL,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, cloudIdentityAPIResponse(saved))
}

func (h handler) requireBearerUser(r *http.Request) (User, error) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		return User{}, fmt.Errorf("bearer token is required")
	}
	user, err := UserForCLIToken(r.Context(), h.db, token, timeNow())
	if err != nil {
		return User{}, err
	}
	svclog.SetUser(r.Context(), user.UserKey)
	return user, nil
}

func cloudIdentityAPIResponse(config CloudIdentityConfig) map[string]any {
	return map[string]any{
		"id":                                    config.ID,
		"user_key":                              config.UserKey,
		"tenant":                                config.Tenant,
		"name":                                  config.Name,
		"provider":                              config.Provider,
		"gcp_audience":                          config.GCPAudience,
		"gcp_subject_token_type":                config.GCPSubjectTokenType,
		"gcp_service_account_impersonation_url": config.GCPServiceAccountImpersonationURL,
	}
}

var cloudIdentityTemplate = template.Must(template.New("cloud-identities").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><link rel="stylesheet" href="/style.css"><title>Cloud Identity Configs</title></head>
<body>
  <main>
    <h1>Cloud Identity Configs</h1>
    <form method="post" action="/cloud-identities">
      <label>Tenant <input name="tenant"></label>
      <label>Name <input name="name"></label>
      <label>GCP Audience <input name="gcp_audience"></label>
      <label>GCP Subject Token Type <input name="gcp_subject_token_type"></label>
      <label>GCP Service Account Impersonation URL <input name="gcp_service_account_impersonation_url"></label>
      <button type="submit">Save</button>
    </form>
    <table>
      <thead><tr><th>Tenant</th><th>Name</th><th>Provider</th><th>Audience</th></tr></thead>
      <tbody>{{range .}}<tr><td>{{.Tenant}}</td><td>{{.Name}}</td><td>{{.Provider}}</td><td>{{.GCPAudience}}</td></tr>{{end}}</tbody>
    </table>
  </main>
</body>
</html>
`))
