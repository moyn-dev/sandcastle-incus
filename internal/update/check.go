package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Repo is the GitHub repository releases are cut from.
const Repo = "thieso2/sandcastle-incus"

const defaultAPIBaseURL = "https://api.github.com"

// defaultWebBaseURL is github.com itself: the release page and the download
// URLs live there and are NOT subject to the API rate limit, which is what
// the web fallback below relies on.
const defaultWebBaseURL = "https://github.com"

// knownAssets are GoReleaser's fixed asset names, so a release resolved
// without the API (no asset list) can still be downloaded from the
// predictable `/releases/download/<tag>/<asset>` URLs.
var knownAssets = []string{
	checksumsAsset,
	AssetName("linux", "amd64"), AssetName("linux", "arm64"),
	AssetName("darwin", "amd64"), AssetName("darwin", "arm64"),
}

// Release is the subset of the GitHub release object the updater needs.
type Release struct {
	TagName     string    `json:"tag_name"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Asset is one downloadable file attached to a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// AssetURL returns the download URL for the named asset.
func (r Release) AssetURL(name string) (string, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a.BrowserDownloadURL, true
		}
	}
	return "", false
}

// Checker performs release lookups against the GitHub API and maintains the
// cached check State on disk.
type Checker struct {
	// APIBaseURL overrides the GitHub API base (tests); empty means api.github.com.
	APIBaseURL string
	// WebBaseURL overrides github.com (tests) for the no-API fallback.
	WebBaseURL string
	// Token, when set, authenticates API requests (a higher rate limit). The
	// CLI fills it from GITHUB_TOKEN / GH_TOKEN; empty stays anonymous.
	Token string
	// StatePath is where the cached check state lives; empty means Check
	// does not persist (ResolveRelease never persists).
	StatePath string
	// HTTPClient overrides the default 30s-timeout client.
	HTTPClient *http.Client
	// RetryDelay overrides the pause between download retries (tests).
	RetryDelay time.Duration
}

// Check fetches the latest release, honouring the stored ETag, and persists
// the refreshed State. A 304 keeps the cached result and only bumps
// CheckedAt. Errors leave the prior state untouched.
func (c *Checker) Check(ctx context.Context, now time.Time) (State, error) {
	st, err := LoadState(c.StatePath)
	if err != nil {
		return State{}, err
	}
	// No-API path first (see resolveReleaseViaWeb): one HEAD on the release
	// page, no rate limit, no token. The API is the fallback and the only
	// source of the publish date, which merely gates the notice's grace.
	if rel, werr := c.resolveReleaseViaWeb(ctx, ""); werr == nil {
		if rel.TagName == st.LatestTag {
			st.CheckedAt = now
		} else {
			st = State{CheckedAt: now, LatestTag: rel.TagName, LatestURL: rel.HTMLURL, NoticedAt: st.NoticedAt}
		}
		if c.StatePath != "" {
			if err := SaveState(c.StatePath, st); err != nil {
				return State{}, err
			}
		}
		return st, nil
	}
	req, err := c.newRequest(ctx, "/repos/"+Repo+"/releases/latest")
	if err != nil {
		return State{}, err
	}
	if st.ETag != "" {
		req.Header.Set("If-None-Match", st.ETag)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return State{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		st.CheckedAt = now
	case http.StatusOK:
		var rel Release
		if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
			return State{}, fmt.Errorf("decode release: %w", err)
		}
		st = State{
			CheckedAt:   now,
			ETag:        resp.Header.Get("ETag"),
			LatestTag:   rel.TagName,
			LatestURL:   rel.HTMLURL,
			PublishedAt: rel.PublishedAt,
			NoticedAt:   st.NoticedAt,
		}
	default:
		return State{}, fmt.Errorf("release check: unexpected status %s", resp.Status)
	}
	if c.StatePath != "" {
		if err := SaveState(c.StatePath, st); err != nil {
			return State{}, err
		}
	}
	return st, nil
}

// ResolveRelease fetches release metadata for a pinned tag, or the latest
// release when tag is empty. It never touches the cached state.
func (c *Checker) ResolveRelease(ctx context.Context, tag string) (Release, error) {
	// No-API path first: anonymous API calls share one small rate limit per
	// source address ("API rate limit exceeded" behind a NAT is routine),
	// while the release page redirect and the download URLs are not rate
	// limited and need no token. The API remains the fallback (a pinned tag
	// that does not exist is only detected there — or at download time).
	webRel, webErr := c.resolveReleaseViaWeb(ctx, tag)
	if webErr == nil {
		return webRel, nil
	}
	path := "/repos/" + Repo + "/releases/latest"
	if tag != "" {
		path = "/repos/" + Repo + "/releases/tags/" + tag
	}
	req, err := c.newRequest(ctx, path)
	if err != nil {
		return Release{}, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("%w (release page: %v)", err, webErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Release{}, fmt.Errorf("resolve release %s: %s: %s (release page: %v)", path, resp.Status, body, webErr)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return Release{}, fmt.Errorf("decode release: %w", err)
	}
	return rel, nil
}

// resolveReleaseViaWeb resolves a release WITHOUT the GitHub API:
// `<web>/<repo>/releases/latest` redirects to `/releases/tag/<tag>` (a pinned
// tag is used as is), and the assets are the fixed GoReleaser names under
// `/releases/download/<tag>/`. checksums.txt still verifies every download,
// so nothing is trusted that the API would have vouched for.
func (c *Checker) resolveReleaseViaWeb(ctx context.Context, tag string) (Release, error) {
	base := c.WebBaseURL
	if base == "" {
		base = defaultWebBaseURL
	}
	if tag == "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, base+"/"+Repo+"/releases/latest", nil)
		if err != nil {
			return Release{}, err
		}
		client := c.client()
		noRedirect := *client
		noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := noRedirect.Do(req)
		if err != nil {
			return Release{}, err
		}
		resp.Body.Close()
		location := resp.Header.Get("Location")
		idx := strings.LastIndex(location, "/releases/tag/")
		if resp.StatusCode/100 != 3 || idx < 0 {
			return Release{}, fmt.Errorf("resolve latest release via %s: status %s, location %q", base, resp.Status, location)
		}
		tag = strings.TrimSpace(location[idx+len("/releases/tag/"):])
		if tag == "" {
			return Release{}, fmt.Errorf("resolve latest release via %s: empty tag in %q", base, location)
		}
	}
	if strings.TrimSpace(tag) == "" {
		return Release{}, fmt.Errorf("release tag is required")
	}
	// A pinned tag is checked against its page so a typo fails here, not at
	// download time with a bare 404.
	if req, err := http.NewRequestWithContext(ctx, http.MethodHead, base+"/"+Repo+"/releases/tag/"+tag, nil); err == nil {
		if resp, err := c.client().Do(req); err != nil {
			return Release{}, err
		} else {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return Release{}, fmt.Errorf("release %s: %s", tag, resp.Status)
			}
		}
	}
	rel := Release{TagName: tag, HTMLURL: base + "/" + Repo + "/releases/tag/" + tag}
	for _, name := range knownAssets {
		rel.Assets = append(rel.Assets, Asset{Name: name, BrowserDownloadURL: base + "/" + Repo + "/releases/download/" + tag + "/" + name})
	}
	return rel, nil
}

func (c *Checker) newRequest(ctx context.Context, path string) (*http.Request, error) {
	base := c.APIBaseURL
	if base == "" {
		base = defaultAPIBaseURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token := strings.TrimSpace(c.Token); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

// TokenFromEnv returns the GitHub token the CLI should authenticate release
// lookups with: GITHUB_TOKEN, then GH_TOKEN (what `gh` uses); "" when unset.
func TokenFromEnv() string {
	for _, name := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return ""
}

func (c *Checker) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}
