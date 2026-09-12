package authapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/naming"
)

const (
	oidcSigningAlg       = "RS256"
	oidcEncryptionKeyKey = "oidc_encryption_key"
	oidcCacheControl     = "public, max-age=300"
)

type oidcSigningKey struct {
	Tenant              string
	KID                 string
	Alg                 string
	EncryptedPrivateKey string
	PublicJWK           string
}

type publicJWK struct {
	KTY string `json:"kty"`
	Use string `json:"use,omitempty"`
	KID string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (h handler) oidcDiscovery(w http.ResponseWriter, r *http.Request) {
	h.oidcDiscoveryForTenant(w, r, "")
}

func (h handler) oidcDiscoveryForTenant(w http.ResponseWriter, r *http.Request, tenantName string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	issuer, err := tenantOIDCIssuer(h.authHostname, tenantName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := EnsureOIDCSigningKey(r.Context(), h.db, tenantName); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", oidcCacheControl)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": []string{oidcSigningAlg},
		"response_types_supported":              []string{"id_token"},
		"subject_types_supported":               []string{"public"},
	})
}

func (h handler) oidcJWKS(w http.ResponseWriter, r *http.Request) {
	h.oidcJWKSForTenant(w, r, "")
}

func (h handler) oidcJWKSForTenant(w http.ResponseWriter, r *http.Request, tenantName string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	keys, err := ListPublicOIDCSigningKeys(r.Context(), h.db, tenantName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", oidcCacheControl)
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func (h handler) tenantOIDC(w http.ResponseWriter, r *http.Request) {
	tenantName, endpoint, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/t/"), "/")
	if !ok || strings.TrimSpace(tenantName) == "" {
		http.NotFound(w, r)
		return
	}
	if err := validateOIDCTenant(tenantName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch endpoint {
	case ".well-known/openid-configuration":
		h.oidcDiscoveryForTenant(w, r, tenantName)
	case ".well-known/jwks.json":
		h.oidcJWKSForTenant(w, r, tenantName)
	default:
		http.NotFound(w, r)
	}
}

func EnsureOIDCSigningKey(ctx context.Context, db *sql.DB, tenantName string) (oidcSigningKey, error) {
	tenantName = strings.TrimSpace(tenantName)
	if tenantName != "" {
		if err := validateOIDCTenant(tenantName); err != nil {
			return oidcSigningKey{}, err
		}
	}
	key, err := activeOIDCSigningKey(ctx, db, tenantName)
	if err == nil {
		return key, nil
	}
	if err != sql.ErrNoRows {
		return oidcSigningKey{}, err
	}
	encryptionKey, err := oidcEncryptionKey(ctx, db)
	if err != nil {
		return oidcSigningKey{}, err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return oidcSigningKey{}, fmt.Errorf("generate OIDC signing key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return oidcSigningKey{}, err
	}
	encrypted, err := encryptOIDCPrivateKey(encryptionKey, privateDER)
	if err != nil {
		return oidcSigningKey{}, err
	}
	jwk := publicJWKForKey(privateKey)
	publicJSON, err := json.Marshal(jwk)
	if err != nil {
		return oidcSigningKey{}, err
	}
	now := timeNow().UTC().Format(time.RFC3339)
	_, err = db.ExecContext(ctx, `
INSERT INTO oidc_signing_keys (tenant, kid, alg, encrypted_private_key, public_jwk, active, created_at, not_before)
VALUES (?, ?, ?, ?, ?, 1, ?, ?)
`, tenantName, jwk.KID, oidcSigningAlg, encrypted, string(publicJSON), now, now)
	if err != nil {
		return oidcSigningKey{}, fmt.Errorf("store OIDC signing key: %w", err)
	}
	return activeOIDCSigningKey(ctx, db, tenantName)
}

func ListPublicOIDCSigningKeys(ctx context.Context, db *sql.DB, tenantName string) ([]json.RawMessage, error) {
	tenantName = strings.TrimSpace(tenantName)
	if tenantName != "" {
		if err := validateOIDCTenant(tenantName); err != nil {
			return nil, err
		}
	}
	if _, err := EnsureOIDCSigningKey(ctx, db, tenantName); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
SELECT public_jwk
FROM oidc_signing_keys
WHERE tenant = ? AND active = 1 AND retired_at = ''
ORDER BY created_at
`, tenantName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []json.RawMessage
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		keys = append(keys, json.RawMessage(raw))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func activeOIDCSigningKey(ctx context.Context, db *sql.DB, tenantName string) (oidcSigningKey, error) {
	tenantName = strings.TrimSpace(tenantName)
	if tenantName != "" {
		if err := validateOIDCTenant(tenantName); err != nil {
			return oidcSigningKey{}, err
		}
	}
	row := db.QueryRowContext(ctx, `
SELECT tenant, kid, alg, encrypted_private_key, public_jwk
FROM oidc_signing_keys
WHERE tenant = ? AND active = 1 AND retired_at = ''
ORDER BY created_at DESC
LIMIT 1
`, tenantName)
	var key oidcSigningKey
	if err := row.Scan(&key.Tenant, &key.KID, &key.Alg, &key.EncryptedPrivateKey, &key.PublicJWK); err != nil {
		return oidcSigningKey{}, err
	}
	return key, nil
}

// oidcEncryptionKey is the OIDC-signing-key purpose of secretEncryptionKey
// (secrets.go); the wrappers below keep the historical names.
func oidcEncryptionKey(ctx context.Context, db *sql.DB) ([]byte, error) {
	return secretEncryptionKey(ctx, db, oidcEncryptionKeyKey)
}

func encryptOIDCPrivateKey(key []byte, plaintext []byte) (string, error) {
	return encryptSecret(key, plaintext)
}

func decryptOIDCPrivateKey(key []byte, encoded string) ([]byte, error) {
	return decryptSecret(key, encoded)
}

func activeOIDCPrivateKey(ctx context.Context, db *sql.DB, tenantName string) (oidcSigningKey, *rsa.PrivateKey, error) {
	key, err := EnsureOIDCSigningKey(ctx, db, tenantName)
	if err != nil {
		return oidcSigningKey{}, nil, err
	}
	encryptionKey, err := oidcEncryptionKey(ctx, db)
	if err != nil {
		return oidcSigningKey{}, nil, err
	}
	der, err := decryptOIDCPrivateKey(encryptionKey, key.EncryptedPrivateKey)
	if err != nil {
		return oidcSigningKey{}, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return oidcSigningKey{}, nil, err
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return oidcSigningKey{}, nil, fmt.Errorf("OIDC private key is %T, want RSA", parsed)
	}
	return key, privateKey, nil
}

func publicJWKForKey(privateKey *rsa.PrivateKey) publicJWK {
	publicKey := privateKey.PublicKey
	kidMaterial := append(publicKey.N.Bytes(), big.NewInt(int64(publicKey.E)).Bytes()...)
	sum := sha256.Sum256(kidMaterial)
	return publicJWK{
		KTY: "RSA",
		Use: "sig",
		KID: base64.RawURLEncoding.EncodeToString(sum[:16]),
		Alg: oidcSigningAlg,
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
}

func oidcIssuer(authHostname string) (string, error) {
	return tenantOIDCIssuer(authHostname, "")
}

func tenantOIDCIssuer(authHostname string, tenantName string) (string, error) {
	host := strings.TrimRight(strings.TrimSpace(authHostname), "/")
	if host == "" {
		return "", fmt.Errorf("auth hostname is required for OIDC issuer")
	}
	base := ""
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		base = host
	} else {
		base = "https://" + strings.Trim(host, ".")
	}
	tenantName = strings.TrimSpace(tenantName)
	if tenantName == "" {
		return base, nil
	}
	if err := validateOIDCTenant(tenantName); err != nil {
		return "", err
	}
	return base + "/t/" + tenantName, nil
}

func validateOIDCTenant(tenantName string) error {
	tenantName = strings.TrimSpace(tenantName)
	if tenantName == "" {
		return fmt.Errorf("tenant is required for OIDC issuer")
	}
	if err := naming.ValidateTenantName(tenantName); err == nil {
		return nil
	}
	if err := naming.ValidateGitHubUsernameTenantName(tenantName); err == nil {
		return nil
	}
	return fmt.Errorf("invalid tenant %q", tenantName)
}
