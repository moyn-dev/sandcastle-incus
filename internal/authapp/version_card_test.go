package authapp

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moyn-dev/sandcastle-incus/internal/update"
)

func TestReleaseCacheCardOutdated(t *testing.T) {
	c := &releaseCache{
		checkedAt: time.Now(),
		latest: update.Release{
			TagName: "v0.2.0",
			HTMLURL: "https://github.com/moyn-dev/sandcastle-incus/releases/tag/v0.2.0",
		},
	}
	card := c.card("0.1.0")
	if !card.Outdated || card.Latest != "v0.2.0" || card.Version != "v0.1.0" {
		t.Fatalf("card = %+v", card)
	}
	current := c.card("0.2.0")
	if current.Outdated {
		t.Fatalf("current version flagged outdated: %+v", current)
	}
}

func TestReleaseCacheDevBuildSkipsGitHub(t *testing.T) {
	called := false
	c := &releaseCache{resolve: func(ctx context.Context) (update.Release, error) {
		called = true
		return update.Release{}, nil
	}}
	card := c.card("0.0.0-dev")
	if card.Version != "0.0.0-dev (dev)" || card.Latest != "" {
		t.Fatalf("card = %+v", card)
	}
	// The background refresh must not even be scheduled for dev builds.
	time.Sleep(20 * time.Millisecond)
	if called {
		t.Fatal("dev build triggered a GitHub check")
	}
}

func TestStatusPageShowsVersionCard(t *testing.T) {
	db, err := OpenDatabase(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(db, HandlerOptions{
		AuthHostname: "auth.example.com",
		Version:      "0.1.0",
		// Stubbed so no unit test ever calls the real GitHub API.
		ReleaseResolver: func(ctx context.Context) (update.Release, error) {
			return update.Release{TagName: "v0.2.0"}, nil
		},
	})
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "v0.1.0") {
		t.Fatalf("status page missing version card, body:\n%s", body)
	}
	if got := rec.Header().Get(update.HeaderVersion); got != "v0.1.0" {
		t.Fatalf("version header = %q", got)
	}
}
