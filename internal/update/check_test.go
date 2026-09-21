package update

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

const releaseJSON = `{
	"tag_name": "v0.2.0",
	"html_url": "https://github.com/thieso2/sandcastle-incus/releases/tag/v0.2.0",
	"published_at": "2026-07-10T09:00:00Z",
	"assets": [
		{"name": "sandcastle-linux-amd64.tar.gz", "browser_download_url": "https://github.com/thieso2/sandcastle-incus/releases/download/v0.2.0/sandcastle-linux-amd64.tar.gz"},
		{"name": "checksums.txt", "browser_download_url": "https://github.com/thieso2/sandcastle-incus/releases/download/v0.2.0/checksums.txt"}
	]
}`

// deadWeb is a github.com stand-in that answers nothing useful, so a test
// exercises the API fallback instead of the (preferred) release-page path.
func deadWeb(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	t.Cleanup(server.Close)
	return server.URL
}

func TestCheckFetchesAndCachesLatestRelease(t *testing.T) {
	var gotPath, gotIfNoneMatch string
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotPath = r.URL.Path
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		if gotIfNoneMatch == `W/"etag-1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `W/"etag-1"`)
		w.Write([]byte(releaseJSON))
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "update-state.json")
	checker := &Checker{APIBaseURL: server.URL, WebBaseURL: deadWeb(t), StatePath: statePath}

	st, err := checker.Check(t.Context(), now)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if gotPath != "/repos/thieso2/sandcastle-incus/releases/latest" {
		t.Fatalf("unexpected path %q", gotPath)
	}
	if st.LatestTag != "v0.2.0" || st.ETag != `W/"etag-1"` {
		t.Fatalf("unexpected state %+v", st)
	}
	if want := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC); !st.PublishedAt.Equal(want) {
		t.Fatalf("published_at = %v, want %v", st.PublishedAt, want)
	}
	if !st.CheckedAt.Equal(now) {
		t.Fatalf("checked_at = %v, want %v", st.CheckedAt, now)
	}

	// Persisted: a reload sees the same tag.
	onDisk, err := LoadState(statePath)
	if err != nil || onDisk.LatestTag != "v0.2.0" {
		t.Fatalf("state not persisted: %+v err=%v", onDisk, err)
	}

	// Second check replays the ETag; a 304 keeps the cached tag and bumps CheckedAt.
	later := now.Add(25 * time.Hour)
	st2, err := checker.Check(t.Context(), later)
	if err != nil {
		t.Fatalf("second Check: %v", err)
	}
	if gotIfNoneMatch != `W/"etag-1"` {
		t.Fatalf("second request If-None-Match = %q", gotIfNoneMatch)
	}
	if st2.LatestTag != "v0.2.0" || !st2.CheckedAt.Equal(later) {
		t.Fatalf("304 handling wrong: %+v", st2)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
}

func TestCheckServerErrorKeepsPriorState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // rate-limited
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "update-state.json")
	prior := State{CheckedAt: twoDays, LatestTag: "v0.1.5"}
	if err := SaveState(statePath, prior); err != nil {
		t.Fatal(err)
	}
	checker := &Checker{APIBaseURL: server.URL, WebBaseURL: deadWeb(t), StatePath: statePath}
	if _, err := checker.Check(t.Context(), now); err == nil {
		t.Fatal("expected error on 403")
	}
	onDisk, _ := LoadState(statePath)
	if onDisk.LatestTag != "v0.1.5" {
		t.Fatalf("prior state clobbered: %+v", onDisk)
	}
}

func TestResolveReleaseByTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/thieso2/sandcastle-incus/releases/tags/v0.2.0" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(releaseJSON))
	}))
	defer server.Close()

	checker := &Checker{APIBaseURL: server.URL, WebBaseURL: deadWeb(t)}
	rel, err := checker.ResolveRelease(t.Context(), "v0.2.0")
	if err != nil {
		t.Fatalf("ResolveRelease: %v", err)
	}
	if rel.TagName != "v0.2.0" || len(rel.Assets) != 2 {
		t.Fatalf("unexpected release %+v", rel)
	}
	url, ok := rel.AssetURL("sandcastle-linux-amd64.tar.gz")
	if !ok || url != "https://github.com/thieso2/sandcastle-incus/releases/download/v0.2.0/sandcastle-linux-amd64.tar.gz" {
		t.Fatalf("AssetURL = %q, %v", url, ok)
	}
	if _, ok := rel.AssetURL("sandcastle-plan9-386.tar.gz"); ok {
		t.Fatal("unexpected asset match")
	}
}

func TestResolveReleaseUsesTheReleasePageBeforeTheAPI(t *testing.T) {
	apiCalls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"API rate limit exceeded for 1.2.3.4."}`))
	}))
	defer api.Close()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && r.URL.Path == "/thieso2/sandcastle-incus/releases/latest":
			w.Header().Set("Location", "https://github.com/thieso2/sandcastle-incus/releases/tag/v0.18.2")
			w.WriteHeader(http.StatusFound)
		case r.Method == http.MethodHead && (r.URL.Path == "/thieso2/sandcastle-incus/releases/tag/v0.18.2" || r.URL.Path == "/thieso2/sandcastle-incus/releases/tag/v0.17.3"):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer web.Close()

	checker := &Checker{APIBaseURL: api.URL, WebBaseURL: web.URL}
	rel, err := checker.ResolveRelease(t.Context(), "")
	if err != nil {
		t.Fatalf("ResolveRelease: %v", err)
	}
	if rel.TagName != "v0.18.2" {
		t.Fatalf("tag = %q", rel.TagName)
	}
	url, ok := rel.AssetURL("sandcastle-linux-amd64.tar.gz")
	if !ok || url != web.URL+"/thieso2/sandcastle-incus/releases/download/v0.18.2/sandcastle-linux-amd64.tar.gz" {
		t.Fatalf("AssetURL = %q, %v", url, ok)
	}
	if _, ok := rel.AssetURL("checksums.txt"); !ok {
		t.Fatal("checksums asset missing from the web-resolved release")
	}
	// A pinned tag needs no redirect at all.
	pinned, err := checker.ResolveRelease(t.Context(), "v0.17.3")
	if err != nil || pinned.TagName != "v0.17.3" {
		t.Fatalf("pinned = %+v, %v", pinned, err)
	}
	// Check() learns the tag the same way and persists it.
	checker.StatePath = filepath.Join(t.TempDir(), "state.json")
	st, err := checker.Check(t.Context(), now)
	if err != nil || st.LatestTag != "v0.18.2" {
		t.Fatalf("Check = %+v, %v", st, err)
	}
	if apiCalls != 0 {
		t.Fatalf("the API was called %d times; the release page path needs no API and no token", apiCalls)
	}
	// A typo'd pinned tag is refused by the tag page, then by the API.
	if _, err := checker.ResolveRelease(t.Context(), "v9.9.9"); err == nil {
		t.Fatal("unknown tag resolved")
	}
	if apiCalls != 1 {
		t.Fatalf("API fallback calls = %d", apiCalls)
	}
}

func TestResolveReleaseSendsOptionalToken(t *testing.T) {
	var auth string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Write([]byte(releaseJSON))
	}))
	defer api.Close()
	if _, err := (&Checker{APIBaseURL: api.URL, WebBaseURL: deadWeb(t), Token: "tok"}).ResolveRelease(t.Context(), "v0.2.0"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer tok" {
		t.Fatalf("Authorization = %q", auth)
	}
	if _, err := (&Checker{APIBaseURL: api.URL, WebBaseURL: deadWeb(t)}).ResolveRelease(t.Context(), "v0.2.0"); err != nil || auth != "" {
		t.Fatalf("anonymous request carried %q (%v)", auth, err)
	}
}
