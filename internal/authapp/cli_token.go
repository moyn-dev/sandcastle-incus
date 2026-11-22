package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const cliTokenTTL = 90 * 24 * time.Hour

func CreateCLIToken(ctx context.Context, db *sql.DB, userKey string, now time.Time) (string, error) {
	userKey = NormalizeGitHubUsername(userKey)
	if userKey == "" {
		return "", fmt.Errorf("user is required")
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	id, err := randomToken(16)
	if err != nil {
		return "", err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO cli_tokens (id, user_key, token_verifier, created_at, expires_at)
VALUES (?, ?, ?, ?, ?)
`, id, userKey, runtimeSecretVerifier(token), now.UTC().Format(time.RFC3339), now.Add(cliTokenTTL).UTC().Format(time.RFC3339))
	if err != nil {
		return "", fmt.Errorf("create CLI token: %w", err)
	}
	return token, nil
}

func UserForCLIToken(ctx context.Context, db *sql.DB, token string, now time.Time) (User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return User{}, fmt.Errorf("CLI token is required")
	}
	row := db.QueryRowContext(ctx, `
SELECT users.user_key, users.github_username, users.github_username_normalized, users.github_account_id, users.github_email, users.allowlisted, users.sandcastle_admin
FROM cli_tokens
JOIN users ON users.user_key = cli_tokens.user_key
WHERE cli_tokens.token_verifier = ? AND cli_tokens.expires_at > ?
`, runtimeSecretVerifier(token), now.UTC().Format(time.RFC3339))
	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, errUserNotFound) {
			return User{}, fmt.Errorf("invalid or expired CLI token")
		}
		return User{}, err
	}
	_, _ = db.ExecContext(ctx, "UPDATE cli_tokens SET last_used_at = ? WHERE token_verifier = ?", now.UTC().Format(time.RFC3339), runtimeSecretVerifier(token))
	return user, nil
}
