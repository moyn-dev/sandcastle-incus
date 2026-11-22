package authapp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestUserForCLITokenNamesAnUnknownOrExpiredToken(t *testing.T) {
	ctx := context.Background()
	db := authDBForTest(t)
	if err := UpsertUser(ctx, db, User{UserKey: "alice", GitHubUsername: "alice", Allowlisted: true}); err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token, err := CreateCLIToken(ctx, db, "alice", issued)
	if err != nil {
		t.Fatal(err)
	}
	if user, err := UserForCLIToken(ctx, db, token, issued.Add(time.Hour)); err != nil || user.UserKey != "alice" {
		t.Fatalf("valid token = %+v, %v", user, err)
	}

	const want = "invalid or expired CLI token"
	if _, err := UserForCLIToken(ctx, db, "never-issued", issued); err == nil || err.Error() != want {
		t.Fatalf("unknown token error = %v, want %q", err, want)
	}
	if _, err := UserForCLIToken(ctx, db, token, issued.Add(cliTokenTTL+time.Second)); err == nil || err.Error() != want {
		t.Fatalf("expired token error = %v, want %q", err, want)
	}
}

func TestFindUserStillReportsUserNotFound(t *testing.T) {
	if _, err := FindUser(context.Background(), authDBForTest(t), "nobody"); err == nil || err.Error() != "user not found" {
		t.Fatalf("FindUser error = %v, want \"user not found\"", err)
	}
}

func TestResourcesAPI_UnknownTokenAnswers401NamingTheToken(t *testing.T) {
	h, _ := resourceAPITestHandler(t, readyResourceCacheForTest())
	req := httptest.NewRequest(http.MethodGet, "/api/resources?tenant=alice", nil)
	req.Header.Set("Authorization", "Bearer never-issued")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), "invalid or expired CLI token") {
		t.Fatalf("unknown token = %d %q, want 401 naming the token", res.Code, res.Body.String())
	}
}

func TestListResourcesSurfacesTheHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "invalid or expired CLI token", http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err := DeviceClient{BaseURL: server.URL, AuthToken: "stale"}.ListResources(context.Background(), ResourceListRequest{Tenant: "alice"})
	var listErr *ResourceListError
	if !errors.As(err, &listErr) || listErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error = %#v, want a ResourceListError carrying 401", err)
	}
	if err.Error() != "auth app resource list: invalid or expired CLI token" {
		t.Fatalf("message = %q", err.Error())
	}
}
