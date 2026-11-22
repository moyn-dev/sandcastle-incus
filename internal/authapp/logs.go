package authapp

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/svclog"
)

// LogEntry is a persisted log row read back for the /logs browse page.
type LogEntry struct {
	Time       time.Time
	Level      string
	Kind       string
	Service    string
	Event      string
	RequestID  string
	UserKey    string
	Method     string
	Path       string
	Status     int
	DurationMS int64
	Detail     string
}

// DefaultLogListLimit bounds how many rows the browse page renders by default.
const DefaultLogListLimit = 500

// maxLogListLimit is the hard cap on a caller-supplied ?limit.
const maxLogListLimit = 5000

// InsertLog persists a single svclog.Entry into the logs table.
func InsertLog(ctx context.Context, db *sql.DB, e svclog.Entry) error {
	id, err := randomToken(16)
	if err != nil {
		return err
	}
	ts := e.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err = db.ExecContext(ctx, `
INSERT INTO logs (id, ts, level, kind, service, event, request_id, user_key, method, path, status, duration_ms, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, id, ts.UTC().Format(time.RFC3339Nano), e.Level, e.Kind, e.Service, e.Event, e.RequestID, e.UserKey, e.Method, e.Path, e.Status, e.DurationMS, e.Detail)
	if err != nil {
		return fmt.Errorf("insert log: %w", err)
	}
	return nil
}

// ListLogsForUser returns the most recent log rows attributed to userKey,
// optionally filtered by a case-insensitive substring across event/path/detail.
func ListLogsForUser(ctx context.Context, db *sql.DB, userKey string, search string, limit int) ([]LogEntry, error) {
	where := `WHERE user_key = ?`
	args := []any{userKey}
	where, args = appendSearch(where, args, search)
	return queryLogs(ctx, db, where, args, limit)
}

// ListAllLogs returns the most recent log rows across all users (admin view),
// optionally filtered by a case-insensitive substring across event/path/detail.
func ListAllLogs(ctx context.Context, db *sql.DB, search string, limit int) ([]LogEntry, error) {
	where, args := appendSearch(``, nil, search)
	return queryLogs(ctx, db, where, args, limit)
}

// appendSearch adds a LIKE filter across event/path/detail/user_key when search
// is non-empty, extending the WHERE clause and args in place.
func appendSearch(where string, args []any, search string) (string, []any) {
	search = strings.TrimSpace(search)
	if search == "" {
		return where, args
	}
	clause := `(event LIKE ? OR path LIKE ? OR detail LIKE ? OR user_key LIKE ?)`
	if where == "" {
		where = `WHERE ` + clause
	} else {
		where += ` AND ` + clause
	}
	like := "%" + search + "%"
	return where, append(args, like, like, like, like)
}

func queryLogs(ctx context.Context, db *sql.DB, where string, args []any, limit int) ([]LogEntry, error) {
	if limit <= 0 {
		limit = DefaultLogListLimit
	}
	if limit > maxLogListLimit {
		limit = maxLogListLimit
	}
	query := `
SELECT ts, level, kind, service, event, request_id, user_key, method, path, status, duration_ms, detail
FROM logs
` + where + `
ORDER BY ts DESC
LIMIT ?`
	rows, err := db.QueryContext(ctx, query, append(append([]any{}, args...), limit)...)
	if err != nil {
		return nil, fmt.Errorf("list logs: %w", err)
	}
	defer rows.Close()
	var out []LogEntry
	for rows.Next() {
		var (
			e     LogEntry
			tsStr string
		)
		if err := rows.Scan(&tsStr, &e.Level, &e.Kind, &e.Service, &e.Event, &e.RequestID, &e.UserKey, &e.Method, &e.Path, &e.Status, &e.DurationMS, &e.Detail); err != nil {
			return nil, fmt.Errorf("scan log: %w", err)
		}
		e.Time = parseLogTime(tsStr)
		out = append(out, e)
	}
	return out, rows.Err()
}

func parseLogTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

// dbSink implements svclog.Sink by persisting entries to the Auth Database. To
// keep the SQLite single-writer off the request path, writes are handed to a
// background goroutine over a buffered channel; when the buffer is full entries
// are dropped (best effort — the verbose stderr line is never dropped).
type dbSink struct {
	db      *sql.DB
	ch      chan svclog.Entry
	done    chan struct{}
	dropped uint64
}

func newDBSink(db *sql.DB, buffer int) *dbSink {
	if buffer <= 0 {
		buffer = 1024
	}
	s := &dbSink{
		db:   db,
		ch:   make(chan svclog.Entry, buffer),
		done: make(chan struct{}),
	}
	go s.run()
	return s
}

// Save enqueues an entry for persistence, dropping it if the buffer is full.
func (s *dbSink) Save(_ context.Context, e svclog.Entry) {
	select {
	case s.ch <- e:
	default:
		s.dropped++
	}
}

func (s *dbSink) run() {
	defer close(s.done)
	for e := range s.ch {
		// Detached context: the request that produced the entry may already
		// have returned. Bound each write so a stuck DB cannot wedge the drain.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = InsertLog(ctx, s.db, e)
		cancel()
	}
}

// Close stops accepting entries and waits for the drain goroutine to finish
// flushing what is already buffered.
func (s *dbSink) Close() {
	close(s.ch)
	<-s.done
}
