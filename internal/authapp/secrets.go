package authapp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
)

// Secrets at rest (spec public-dns-zones §1.4). Every secret the Auth Database
// holds — OIDC signing keys, Public DNS Zone tokens, Machine Certificate private
// keys — is AES-256-GCM sealed under a purpose-labelled 32-byte key that lives
// in auth_app_meta and is generated on first use. One key per purpose, so a
// future rotation of one class of secret never touches the others.
const (
	publicDNSZoneEncryptionKeyKey = "public_dns_zone_key"
	machineCertEncryptionKeyKey   = "machine_cert_key"
)

// secretEncryptionKey returns the 32-byte key stored under metaKey in
// auth_app_meta, generating and persisting one when absent. The INSERT is
// ON CONFLICT DO NOTHING, so two racing first users converge on one key.
func secretEncryptionKey(ctx context.Context, db *sql.DB, metaKey string) ([]byte, error) {
	row := db.QueryRowContext(ctx, "SELECT value FROM auth_app_meta WHERE key = ?", metaKey)
	var encoded string
	if err := row.Scan(&encoded); err == nil {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", metaKey, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("%s has invalid length", metaKey)
		}
		return key, nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO auth_app_meta (key, value, updated_at)
VALUES (?, ?, datetime('now'))
ON CONFLICT(key) DO NOTHING
`, metaKey, base64.StdEncoding.EncodeToString(key))
	if err != nil {
		return nil, err
	}
	return secretEncryptionKey(ctx, db, metaKey)
}

// encryptSecret seals plaintext under key (AES-256-GCM, random nonce) and
// returns base64(nonce || ciphertext).
func encryptSecret(key []byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	payload := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(payload), nil
}

// decryptSecret is the inverse of encryptSecret.
func decryptSecret(key []byte, encoded string) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(payload) < gcm.NonceSize() {
		return nil, fmt.Errorf("encrypted secret is truncated")
	}
	nonce := payload[:gcm.NonceSize()]
	ciphertext := payload[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
