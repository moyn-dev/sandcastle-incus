package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/update"
)

// updateStatePath is the daily release-check cache in the sandcastle config
// dir (#124 §1).
func updateStatePath() string {
	return filepath.Join(scconfig.DefaultConfigDir(), "update-state.json")
}

func stderrIsTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// startBackgroundUpdateCheck kicks off the daily-cached GitHub release check
// in the background of a normal command run (#124 §1). Returns nil when no
// check is due (checked within 24h, dev build, opt-out env, or non-TTY).
// The check is failure-tolerant: an error just means no refreshed state.
func startBackgroundUpdateCheck() <-chan update.State {
	if !stderrIsTerminal() {
		return nil
	}
	path := updateStatePath()
	st, err := update.LoadState(path)
	if err != nil || !update.CheckDue(st, version, time.Now()) {
		return nil
	}
	ch := make(chan update.State, 1)
	go func() {
		defer close(ch)
		checker := &update.Checker{StatePath: path, Token: update.TokenFromEnv()}
		if fresh, err := checker.Check(context.Background(), time.Now()); err == nil {
			ch <- fresh
		}
	}()
	return ch
}

// maybePrintUpdateNotices prints, on stderr after the command's normal
// output: the two-line release notice and the sidecar-behind notice (each
// ≤ once per 24h, #124 §2), plus the unthrottled one-line version-skew
// warning when an appliance on a different version was contacted (§6).
func maybePrintUpdateNotices(stderr io.Writer, refreshed <-chan update.State) {
	if !stderrIsTerminal() {
		return
	}
	path := updateStatePath()
	st, err := update.LoadState(path)
	if err != nil {
		return
	}
	if refreshed != nil {
		// Give an in-flight first check a moment to land so a fresh install can
		// notice on its first run; otherwise the cached state serves next time.
		select {
		case fresh, ok := <-refreshed:
			if ok {
				st = fresh
			}
		case <-time.After(2 * time.Second):
		}
	}

	now := time.Now()
	changed := false
	if update.NoticeDue(st, version, now) {
		fmt.Fprintf(stderr, "\nA new sandcastle release is available: v%s → %s\nRun `sc update` to see and apply updates.\n",
			strings.TrimPrefix(version, "v"), st.LatestTag)
		st.NoticedAt = now
		changed = true
	}

	deployment, _ := update.DefaultExchange.Observed()
	sidecar := update.DefaultExchange.SidecarVersion()
	if update.SidecarNoticeDue(st, sidecar, deployment, now) {
		fmt.Fprintf(stderr, "Your sidecar (%s) is behind the deployment (%s) — run `sc update`.\n", sidecar, deployment)
		st.SidecarNoticedAt = now
		changed = true
	}
	if changed {
		_ = update.SaveState(path, st)
	}

	if msg, ok := update.SkewWarning(version, deployment); ok {
		fmt.Fprintln(stderr, msg)
	}
}
