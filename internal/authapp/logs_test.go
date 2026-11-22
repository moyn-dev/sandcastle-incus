package authapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/svclog"
)

func TestLogScopingAdminSeesAllUserSeesOwn(t *testing.T) {
	db := authDBForTest(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

	// Three rows: two users plus one system row (empty user key).
	rows := []svclog.Entry{
		{Time: base.Add(1 * time.Second), Level: "INFO", Kind: svclog.KindRequest, Service: "auth-app", Event: "", UserKey: "alice", Method: "GET", Path: "/machines", Status: 200, DurationMS: 10},
		{Time: base.Add(2 * time.Second), Level: "INFO", Kind: svclog.KindSpan, Service: "auth-app", Event: "provision.personal_tenant", UserKey: "bob", DurationMS: 1200},
		{Time: base.Add(3 * time.Second), Level: "ERROR", Kind: svclog.KindMessage, Service: "auth-app", Detail: "reconcile failed"},
	}
	for _, e := range rows {
		if err := InsertLog(ctx, db, e); err != nil {
			t.Fatalf("InsertLog: %v", err)
		}
	}

	// Regular user alice: only her own row.
	aliceRows, err := ListLogsForUser(ctx, db, "alice", "", 100)
	if err != nil {
		t.Fatalf("ListLogsForUser: %v", err)
	}
	if len(aliceRows) != 1 || aliceRows[0].UserKey != "alice" {
		t.Fatalf("alice should see exactly her 1 row, got %+v", aliceRows)
	}

	// Regular user bob must NOT see alice's or the system row.
	bobRows, err := ListLogsForUser(ctx, db, "bob", "", 100)
	if err != nil {
		t.Fatalf("ListLogsForUser bob: %v", err)
	}
	if len(bobRows) != 1 || bobRows[0].Event != "provision.personal_tenant" {
		t.Fatalf("bob should see exactly his 1 row, got %+v", bobRows)
	}

	// Admin sees everything, including the system (empty-user) row.
	all, err := ListAllLogs(ctx, db, "", 100)
	if err != nil {
		t.Fatalf("ListAllLogs: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("admin should see all 3 rows, got %d", len(all))
	}
	// Newest first.
	if all[0].Detail != "reconcile failed" {
		t.Errorf("expected newest (system) row first, got %+v", all[0])
	}

	// Search filters within scope.
	filtered, err := ListAllLogs(ctx, db, "provision", 100)
	if err != nil {
		t.Fatalf("ListAllLogs search: %v", err)
	}
	if len(filtered) != 1 || filtered[0].UserKey != "bob" {
		t.Fatalf("search 'provision' should match bob's span only, got %+v", filtered)
	}

	// A user's search cannot escape her scope.
	aliceSearch, err := ListLogsForUser(ctx, db, "alice", "provision", 100)
	if err != nil {
		t.Fatalf("ListLogsForUser alice search: %v", err)
	}
	if len(aliceSearch) != 0 {
		t.Fatalf("alice searching 'provision' must not see bob's row, got %+v", aliceSearch)
	}
}

// TestDBSinkPersistsRequestAndSpan wires the svclog HTTP middleware to the real
// async dbSink and confirms a request + its span land in the logs table
// attributed to the user set inside the handler.
func TestDBSinkPersistsRequestAndSpan(t *testing.T) {
	db := authDBForTest(t)
	ctx := context.Background()

	sink := newDBSink(db, 0)
	logger := svclog.New("auth-app", nil, sink)

	h := logger.HTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svclog.SetUser(r.Context(), "alice")
		_ = svclog.Span(r.Context(), "incus.create", func() error { return nil })
		w.WriteHeader(http.StatusCreated)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/machines", nil))

	sink.Close() // flush the async buffer

	rows, err := ListLogsForUser(ctx, db, "alice", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 persisted rows (request+span), got %d: %+v", len(rows), rows)
	}
	var haveRequest, haveSpan bool
	for _, row := range rows {
		switch row.Kind {
		case svclog.KindRequest:
			haveRequest = true
			if row.Status != http.StatusCreated || row.Path != "/api/machines" {
				t.Errorf("request row = %+v", row)
			}
		case svclog.KindSpan:
			haveSpan = true
			if row.Event != "incus.create" {
				t.Errorf("span row = %+v", row)
			}
		}
	}
	if !haveRequest || !haveSpan {
		t.Errorf("missing request or span row: %+v", rows)
	}
}

// TestLogsWebPageScopesByViewer drives the /logs HTTP handler end-to-end: a
// regular user sees only her own rows in the rendered page, while an admin sees
// every user's rows plus system rows.
func TestLogsWebPageScopesByViewer(t *testing.T) {
	db := authDBForTest(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

	if _, err := AllowlistGitHubUser(ctx, db, GitHubProfile{Login: "alice", ID: "1"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range []svclog.Entry{
		{Time: base.Add(1 * time.Second), Level: "INFO", Kind: svclog.KindRequest, Service: "auth-app", UserKey: "alice", Method: "GET", Path: "/machines", Status: 200, DurationMS: 12},
		{Time: base.Add(2 * time.Second), Level: "INFO", Kind: svclog.KindSpan, Service: "auth-app", Event: "provision.personal_tenant", UserKey: "bob", DurationMS: 3400},
		{Time: base.Add(3 * time.Second), Level: "ERROR", Kind: svclog.KindMessage, Service: "auth-app", Detail: "reconcile failed"},
	} {
		if err := InsertLog(ctx, db, e); err != nil {
			t.Fatal(err)
		}
	}

	handler := NewHandler(db, HandlerOptions{})

	// Regular user alice.
	aliceSession, err := CreateSession(ctx, db, "alice", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	aliceReq := httptest.NewRequest(http.MethodGet, "/logs", nil)
	aliceReq.AddCookie(&http.Cookie{Name: "sandcastle_session", Value: aliceSession})
	aliceResp := httptest.NewRecorder()
	handler.ServeHTTP(aliceResp, aliceReq)
	if aliceResp.Code != http.StatusOK {
		t.Fatalf("alice /logs = %d %q", aliceResp.Code, aliceResp.Body.String())
	}
	aliceBody := aliceResp.Body.String()
	if !strings.Contains(aliceBody, "/machines") {
		t.Errorf("alice should see her own request row")
	}
	if strings.Contains(aliceBody, "provision.personal_tenant") || strings.Contains(aliceBody, "reconcile failed") {
		t.Errorf("alice must NOT see bob's or system rows:\n%s", aliceBody)
	}
	if !strings.Contains(aliceBody, "Showing only your activity") {
		t.Errorf("alice page should say it is scoped to her")
	}

	// Admin.
	adminReq := httptest.NewRequest(http.MethodGet, "/logs", nil)
	adminReq.AddCookie(adminSessionCookieForTest(t, db))
	adminResp := httptest.NewRecorder()
	handler.ServeHTTP(adminResp, adminReq)
	if adminResp.Code != http.StatusOK {
		t.Fatalf("admin /logs = %d %q", adminResp.Code, adminResp.Body.String())
	}
	adminBody := adminResp.Body.String()
	for _, want := range []string{"/machines", "provision.personal_tenant", "reconcile failed", "Showing all users' activity"} {
		if !strings.Contains(adminBody, want) {
			t.Errorf("admin page missing %q", want)
		}
	}
}
