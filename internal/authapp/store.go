package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/naming"
	"golang.org/x/crypto/ssh"
)

type User struct {
	UserKey                  string
	GitHubUsername           string
	GitHubUsernameNormalized string
	GitHubAccountID          string
	GitHubEmail              string
	Allowlisted              bool
	SandcastleAdmin          bool
	LocalUnixUser            string
	// SSHPublicKey is populated transiently during device-login provisioning so
	// the v2 tenant profile can bake it in at create time.
	SSHPublicKey string
}

func NormalizeGitHubUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func ValidateGitHubUsername(username string) error {
	normalized := NormalizeGitHubUsername(username)
	if err := naming.ValidateGitHubUsernameTenantName(normalized); err != nil {
		return fmt.Errorf("invalid GitHub username %q", username)
	}
	return nil
}

func NormalizeGitHubUsernames(usernames []string) []string {
	seen := map[string]bool{}
	output := make([]string, 0, len(usernames))
	for _, username := range usernames {
		normalized := NormalizeGitHubUsername(username)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		output = append(output, normalized)
	}
	return output
}

func BootstrapAdmins(ctx context.Context, db *sql.DB, usernames []string) error {
	for _, username := range NormalizeGitHubUsernames(usernames) {
		if err := UpsertUser(ctx, db, User{
			UserKey:                  username,
			GitHubUsername:           username,
			GitHubUsernameNormalized: username,
			Allowlisted:              true,
			SandcastleAdmin:          true,
		}); err != nil {
			return err
		}
		if err := enableGitHubLogin(ctx, db, username); err != nil {
			return err
		}
	}
	return nil
}

// enableGitHubLogin is the explicit admin act that lets a GitHub account with
// the user key's login sign in. UpsertUser never touches github_login, so an
// OIDC-only user cannot gain GitHub login as a side effect.
func enableGitHubLogin(ctx context.Context, db *sql.DB, userKey string) error {
	if _, err := db.ExecContext(ctx, "UPDATE users SET github_login = 1 WHERE user_key = ?", NormalizeGitHubUsername(userKey)); err != nil {
		return fmt.Errorf("enable GitHub login for %s: %w", userKey, err)
	}
	return nil
}

func UpsertUser(ctx context.Context, db *sql.DB, user User) error {
	normalized := NormalizeGitHubUsername(user.GitHubUsernameNormalized)
	if normalized == "" {
		normalized = NormalizeGitHubUsername(user.GitHubUsername)
	}
	if normalized == "" {
		return fmt.Errorf("GitHub username is required")
	}
	userKey := NormalizeGitHubUsername(user.UserKey)
	if userKey == "" {
		userKey = normalized
	}
	githubUsername := strings.TrimSpace(user.GitHubUsername)
	if githubUsername == "" {
		githubUsername = normalized
	}
	_, err := db.ExecContext(ctx, `
INSERT INTO users (
    user_key, github_username, github_username_normalized, github_account_id,
    github_email, allowlisted, sandcastle_admin, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
ON CONFLICT(user_key) DO UPDATE SET
    github_username = excluded.github_username,
    github_username_normalized = excluded.github_username_normalized,
    github_account_id = CASE WHEN excluded.github_account_id = '' THEN users.github_account_id ELSE excluded.github_account_id END,
    github_email = CASE WHEN excluded.github_email = '' THEN users.github_email ELSE excluded.github_email END,
    allowlisted = MAX(users.allowlisted, excluded.allowlisted),
    sandcastle_admin = MAX(users.sandcastle_admin, excluded.sandcastle_admin),
    updated_at = datetime('now')
`, userKey, githubUsername, normalized, strings.TrimSpace(user.GitHubAccountID), strings.TrimSpace(user.GitHubEmail), boolInt(user.Allowlisted), boolInt(user.SandcastleAdmin))
	if err != nil {
		return fmt.Errorf("upsert user %s: %w", normalized, err)
	}
	return nil
}

func FindLoginUser(ctx context.Context, db *sql.DB, normalizedUsername string) (User, error) {
	normalized := NormalizeGitHubUsername(normalizedUsername)
	row := db.QueryRowContext(ctx, `
SELECT user_key, github_username, github_username_normalized, github_account_id, github_email, allowlisted, sandcastle_admin
FROM users
WHERE github_username_normalized = ? AND allowlisted = 1 AND github_login = 1
`, normalized)
	var user User
	var allowlisted int
	var admin int
	if err := row.Scan(&user.UserKey, &user.GitHubUsername, &user.GitHubUsernameNormalized, &user.GitHubAccountID, &user.GitHubEmail, &allowlisted, &admin); err != nil {
		if err == sql.ErrNoRows {
			return User{}, fmt.Errorf("GitHub user %s is not allowlisted", normalized)
		}
		return User{}, err
	}
	user.Allowlisted = allowlisted == 1
	user.SandcastleAdmin = admin == 1
	return user, nil
}

func RecordGitHubLogin(ctx context.Context, db *sql.DB, user User, profile GitHubProfile) error {
	user.GitHubUsername = profile.Login
	user.GitHubUsernameNormalized = NormalizeGitHubUsername(profile.Login)
	user.GitHubAccountID = profile.ID
	user.GitHubEmail = profile.Email
	user.Allowlisted = true
	return UpsertUser(ctx, db, user)
}

func AllowlistGitHubUser(ctx context.Context, db *sql.DB, profile GitHubProfile) (User, error) {
	normalized := NormalizeGitHubUsername(profile.Login)
	if err := ValidateGitHubUsername(normalized); err != nil {
		return User{}, err
	}
	user := User{
		UserKey:                  normalized,
		GitHubUsername:           profile.Login,
		GitHubUsernameNormalized: normalized,
		GitHubAccountID:          profile.ID,
		GitHubEmail:              profile.Email,
		Allowlisted:              true,
	}
	if err := UpsertUser(ctx, db, user); err != nil {
		return User{}, err
	}
	if err := enableGitHubLogin(ctx, db, normalized); err != nil {
		return User{}, err
	}
	return FindUser(ctx, db, normalized)
}

func RemoveAllowlistedUser(ctx context.Context, db *sql.DB, normalizedUsername string) (User, error) {
	user, err := FindUser(ctx, db, normalizedUsername)
	if err != nil {
		return User{}, err
	}
	_, err = db.ExecContext(ctx, `
UPDATE users
SET allowlisted = 0, updated_at = datetime('now')
WHERE github_username_normalized = ?
`, user.GitHubUsernameNormalized)
	if err != nil {
		return User{}, fmt.Errorf("remove allowlisted user %s: %w", user.GitHubUsernameNormalized, err)
	}
	user.Allowlisted = false
	return user, nil
}

func FindUser(ctx context.Context, db *sql.DB, normalizedUsername string) (User, error) {
	normalized := NormalizeGitHubUsername(normalizedUsername)
	row := db.QueryRowContext(ctx, `
SELECT user_key, github_username, github_username_normalized, github_account_id, github_email, allowlisted, sandcastle_admin
FROM users
WHERE github_username_normalized = ?
`, normalized)
	return scanUser(row)
}

func ListUsers(ctx context.Context, db *sql.DB) ([]User, error) {
	rows, err := db.QueryContext(ctx, `
SELECT user_key, github_username, github_username_normalized, github_account_id, github_email, allowlisted, sandcastle_admin
FROM users
ORDER BY github_username_normalized
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

type UserSSHKey struct {
	PublicKey   string
	Fingerprint string
}

func SetUserSSHKey(ctx context.Context, db *sql.DB, userKey string, publicKey string) (UserSSHKey, bool, error) {
	key, err := normalizeUserSSHPublicKey(publicKey)
	if err != nil {
		return UserSSHKey{}, false, err
	}
	normalizedUser := NormalizeGitHubUsername(userKey)
	if normalizedUser == "" {
		return UserSSHKey{}, false, fmt.Errorf("user key is required")
	}
	existing, err := GetUserSSHKey(ctx, db, normalizedUser)
	if err != nil {
		return UserSSHKey{}, false, err
	}
	if existing.PublicKey == key.PublicKey {
		return existing, false, nil
	}
	result, err := db.ExecContext(ctx, `
UPDATE users
SET ssh_public_key = ?, ssh_key_fingerprint = ?, updated_at = datetime('now')
WHERE user_key = ?
`, key.PublicKey, key.Fingerprint, normalizedUser)
	if err != nil {
		return UserSSHKey{}, false, fmt.Errorf("store User SSH Public Key for %s: %w", normalizedUser, err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return UserSSHKey{}, false, fmt.Errorf("user %s not found", normalizedUser)
	}
	return key, true, nil
}

func GetUserSSHKey(ctx context.Context, db *sql.DB, userKey string) (UserSSHKey, error) {
	normalizedUser := NormalizeGitHubUsername(userKey)
	row := db.QueryRowContext(ctx, `
SELECT ssh_public_key, ssh_key_fingerprint
FROM users
WHERE user_key = ?
`, normalizedUser)
	var key UserSSHKey
	if err := row.Scan(&key.PublicKey, &key.Fingerprint); err != nil {
		if err == sql.ErrNoRows {
			return UserSSHKey{}, fmt.Errorf("user %s not found", normalizedUser)
		}
		return UserSSHKey{}, err
	}
	return key, nil
}

// SetUserClientCertificate records the client's shared-identity Incus
// certificate (PEM) on the user. Written at device login; read by the tenant
// plane to extend the caller's trust entry by fingerprint when the entry is
// named after another tenant's enrollment (shared client identity).
func SetUserClientCertificate(ctx context.Context, db *sql.DB, userKey string, certificatePEM string) error {
	normalizedUser := NormalizeGitHubUsername(userKey)
	if normalizedUser == "" {
		return fmt.Errorf("user key is required")
	}
	pem := strings.TrimSpace(certificatePEM)
	if pem == "" {
		return fmt.Errorf("client certificate is required")
	}
	result, err := db.ExecContext(ctx, `
UPDATE users
SET client_certificate_pem = ?, updated_at = datetime('now')
WHERE user_key = ? AND client_certificate_pem != ?
`, pem, normalizedUser, pem)
	if err != nil {
		return fmt.Errorf("store client certificate for %s: %w", normalizedUser, err)
	}
	_ = result
	return nil
}

// GetUserClientCertificate returns the user's recorded shared-identity Incus
// certificate PEM ("" when none was recorded).
func GetUserClientCertificate(ctx context.Context, db *sql.DB, userKey string) (string, error) {
	normalizedUser := NormalizeGitHubUsername(userKey)
	row := db.QueryRowContext(ctx, `
SELECT client_certificate_pem
FROM users
WHERE user_key = ?
`, normalizedUser)
	var pem string
	if err := row.Scan(&pem); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(pem), nil
}

func normalizeUserSSHPublicKey(value string) (UserSSHKey, error) {
	key := strings.TrimSpace(value)
	if key == "" {
		return UserSSHKey{}, fmt.Errorf("User SSH Public Key is required")
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return UserSSHKey{}, fmt.Errorf("parse User SSH Public Key: %w", err)
	}
	return UserSSHKey{PublicKey: key, Fingerprint: ssh.FingerprintSHA256(parsed)}, nil
}

func CreateSession(ctx context.Context, db *sql.DB, userKey string, now time.Time) (string, error) {
	id, err := randomToken(32)
	if err != nil {
		return "", err
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO web_sessions (id, user_key, created_at, expires_at)
VALUES (?, ?, ?, ?)
`, id, userKey, now.UTC().Format(time.RFC3339), now.Add(24*time.Hour).UTC().Format(time.RFC3339))
	if err != nil {
		return "", fmt.Errorf("create web session: %w", err)
	}
	return id, nil
}

func UserForSession(ctx context.Context, db *sql.DB, sessionID string, now time.Time) (User, error) {
	row := db.QueryRowContext(ctx, `
SELECT users.user_key, users.github_username, users.github_username_normalized, users.github_account_id, users.github_email, users.allowlisted, users.sandcastle_admin
FROM web_sessions
JOIN users ON users.user_key = web_sessions.user_key
WHERE web_sessions.id = ? AND web_sessions.expires_at > ?
`, strings.TrimSpace(sessionID), now.UTC().Format(time.RFC3339))
	return scanUser(row)
}

type userScanner interface {
	Scan(dest ...any) error
}

var errUserNotFound = errors.New("user not found")

func scanUser(scanner userScanner) (User, error) {
	var user User
	var allowlisted int
	var admin int
	if err := scanner.Scan(&user.UserKey, &user.GitHubUsername, &user.GitHubUsernameNormalized, &user.GitHubAccountID, &user.GitHubEmail, &allowlisted, &admin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, errUserNotFound
		}
		return User{}, err
	}
	user.Allowlisted = allowlisted == 1
	user.SandcastleAdmin = admin == 1
	return user, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
