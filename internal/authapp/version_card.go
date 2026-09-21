package authapp

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/update"
)

// versionCard is the always-visible version card on the auth-app pages
// (#124 §8): the appliance's own running version plus the latest release
// from its own daily-cached GitHub check. Green when current; amber with
// the update command and release-notes link when behind.
type versionCard struct {
	Version    string // own running version, display form
	Latest     string // latest release tag ("" when unknown)
	ReleaseURL string
	Outdated   bool
}

// releaseCache is the appliance-side daily-cached release check. It is
// failure-tolerant and never blocks a page render: a due check refreshes in
// the background while the stale (or empty) result is served.
type releaseCache struct {
	mu        sync.Mutex
	checkedAt time.Time
	latest    update.Release
	fetching  bool
	// resolve is injectable for tests; nil uses the GitHub API.
	resolve func(ctx context.Context) (update.Release, error)
}

func (c *releaseCache) resolveFunc() func(ctx context.Context) (update.Release, error) {
	if c.resolve != nil {
		return c.resolve
	}
	checker := &update.Checker{Token: update.TokenFromEnv()}
	return func(ctx context.Context) (update.Release, error) {
		return checker.ResolveRelease(ctx, "")
	}
}

// card renders the version card for the given running version, kicking off
// a background refresh when the daily cache is stale. Dev builds never call
// GitHub (mirrors the CLI's dev-build exemption).
func (c *releaseCache) card(version string) versionCard {
	card := versionCard{Version: displayVersion(version)}
	if update.IsDevBuild(version) {
		return card
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.checkedAt) >= 24*time.Hour && !c.fetching {
		c.fetching = true
		go c.refresh()
	}
	card.Latest = c.latest.TagName
	card.ReleaseURL = c.latest.HTMLURL
	card.Outdated = update.IsNewer(c.latest.TagName, version)
	return card
}

func (c *releaseCache) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release, err := c.resolveFunc()(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fetching = false
	if err != nil {
		// Failure-tolerant: keep the stale result, retry not before the next
		// daily window elapses from now (avoids hammering GitHub on errors).
		c.checkedAt = time.Now().Add(-23 * time.Hour)
		return
	}
	c.latest = release
	c.checkedAt = time.Now()
}

func displayVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return "dev"
	}
	if update.IsDevBuild(version) {
		return version + " (dev)"
	}
	return "v" + strings.TrimPrefix(version, "v")
}
