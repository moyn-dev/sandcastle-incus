package authapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
)

// ---------------------------------------------------------------------------
// Public DNS Zones — ACME (ADR-0027, spec §1.3 / §3.5, slice 5)
//
// acme_storage is certmagic's Storage key/value: it holds the ACME account
// (one per install per directory URL; certmagic keys it by CA + contact) and
// the solver's transient state. Machine certificates themselves live in
// machine_certificates (machine_certificates.go), never here — the Auth App
// uses certmagic as an issuer library (ACMEIssuer.Issue), not through
// ManageSync/ManageAsync, so certmagic never writes certificates.
// ---------------------------------------------------------------------------

const acmeStorageSchema = `
CREATE TABLE IF NOT EXISTS acme_storage (
    key         TEXT PRIMARY KEY,
    value       BLOB NOT NULL,
    modified_at TEXT NOT NULL
);
`

// sqliteStorage implements certmagic.Storage over the auth database's
// acme_storage table. Keys are "/"-separated paths exactly as certmagic hands
// them out (e.g. acme/<ca-host>/users/<email>/<email>.key); a key is a
// "directory" when it is a strict prefix of other keys.
//
// Locks are an in-process mutex map, not rows: there is exactly one Auth App
// per install (ADR-0021), so the only contention certmagic can see is between
// goroutines of this process. Lock honours context cancellation; a lock is
// never stale because the process holding it is the only process there is.
type sqliteStorage struct {
	db *sql.DB

	mu    sync.Mutex
	locks map[string]chan struct{}
}

var _ certmagic.Storage = (*sqliteStorage)(nil)

func newSQLiteStorage(db *sql.DB) *sqliteStorage {
	return &sqliteStorage{db: db, locks: map[string]chan struct{}{}}
}

// Lock acquires the named lock, blocking until it is free or ctx is done.
func (s *sqliteStorage) Lock(ctx context.Context, name string) error {
	for {
		s.mu.Lock()
		released, held := s.locks[name]
		if !held {
			s.locks[name] = make(chan struct{})
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-released:
		}
	}
}

// Unlock releases the named lock. Calling it for a lock that is not held is
// an error, as certmagic's contract requires.
func (s *sqliteStorage) Unlock(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	released, held := s.locks[name]
	if !held {
		return fmt.Errorf("acme storage: lock %q is not held", name)
	}
	delete(s.locks, name)
	close(released)
	return nil
}

func (s *sqliteStorage) Store(ctx context.Context, key string, value []byte) error {
	key = cleanStorageKey(key)
	if key == "" {
		return fmt.Errorf("acme storage: empty key")
	}
	if value == nil {
		value = []byte{}
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO acme_storage (key, value, modified_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, modified_at = excluded.modified_at
`, key, value, timeNow().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *sqliteStorage) Load(ctx context.Context, key string) ([]byte, error) {
	key = cleanStorageKey(key)
	var value []byte
	err := s.db.QueryRowContext(ctx, "SELECT value FROM acme_storage WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("acme storage: %s: %w", key, fs.ErrNotExist)
	}
	if err != nil {
		return nil, err
	}
	if value == nil {
		value = []byte{}
	}
	return value, nil
}

// Delete removes the key and, when it is a directory, everything under it.
// Deleting an absent key is not an error (nothing is left behind).
func (s *sqliteStorage) Delete(ctx context.Context, key string) error {
	key = cleanStorageKey(key)
	if key == "" {
		return fmt.Errorf("acme storage: empty key")
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM acme_storage WHERE key = ? OR key LIKE ? ESCAPE '\\'",
		key, likePrefix(key+"/"))
	return err
}

func (s *sqliteStorage) Exists(ctx context.Context, key string) bool {
	key = cleanStorageKey(key)
	if key == "" {
		return false
	}
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM acme_storage WHERE key = ? OR key LIKE ? ESCAPE '\\'",
		key, likePrefix(key+"/")).Scan(&n)
	return err == nil && n > 0
}

// List returns the keys under prefix: every terminal key and intermediate
// directory below it when recursive, otherwise only the immediate children.
// A prefix that is neither a key nor a directory yields fs.ErrNotExist, as
// certmagic's FileStorage does for a missing directory.
func (s *sqliteStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	prefix = cleanStorageKey(prefix)
	pattern := "%"
	if prefix != "" {
		pattern = likePrefix(prefix + "/")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT key FROM acme_storage WHERE key LIKE ? ESCAPE '\\' ORDER BY key", pattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var keys []string
	add := func(key string) {
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		rest := key
		if prefix != "" {
			rest = strings.TrimPrefix(key, prefix+"/")
		}
		segments := strings.Split(rest, "/")
		if !recursive {
			add(joinStorageKey(prefix, segments[0]))
			continue
		}
		for i := range segments {
			add(joinStorageKey(prefix, strings.Join(segments[:i+1], "/")))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(keys) == 0 && prefix != "" && !s.Exists(ctx, prefix) {
		return nil, fmt.Errorf("acme storage: %s: %w", prefix, fs.ErrNotExist)
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *sqliteStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	key = cleanStorageKey(key)
	var modified string
	var size int64
	err := s.db.QueryRowContext(ctx, "SELECT modified_at, length(value) FROM acme_storage WHERE key = ?", key).Scan(&modified, &size)
	if err == nil {
		return certmagic.KeyInfo{Key: key, Modified: parseStorageTime(modified), Size: size, IsTerminal: true}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return certmagic.KeyInfo{}, err
	}
	// A directory: report the newest child as its modification time.
	var newest sql.NullString
	err = s.db.QueryRowContext(ctx, "SELECT max(modified_at) FROM acme_storage WHERE key LIKE ? ESCAPE '\\'", likePrefix(key+"/")).Scan(&newest)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	if !newest.Valid {
		return certmagic.KeyInfo{}, fmt.Errorf("acme storage: %s: %w", key, fs.ErrNotExist)
	}
	return certmagic.KeyInfo{Key: key, Modified: parseStorageTime(newest.String), IsTerminal: false}, nil
}

func cleanStorageKey(key string) string {
	return strings.Trim(strings.TrimSpace(key), "/")
}

func joinStorageKey(prefix, rest string) string {
	if prefix == "" {
		return rest
	}
	return prefix + "/" + rest
}

// likePrefix escapes a literal prefix for a LIKE ... ESCAPE '\' pattern.
func likePrefix(prefix string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(prefix) + "%"
}

func parseStorageTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
