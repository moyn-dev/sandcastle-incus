package cli

import (
	"fmt"
	"strings"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
)

// Remote fan-out: the leading part of "[[remote:]project:]machine" may be a
// glob, in which case the command runs once per matching enrolled install.
//
// A remote pattern is matched against ENROLLED SANDCASTLE REMOTE NAMES (what
// `sc remote list` shows) — not against every incus remote, so `*` never
// wanders into `images:` or `local:`, and not against install DNS suffixes,
// which cannot be enumerated without connecting to each install first.
//
// Scopes are entered SEQUENTIALLY. Binding a config to an install re-points the
// process-wide INCUS_CONF for the duration (that is how the incus client
// finds the right restricted certificate), so two installs cannot be in scope
// at once. Within one install the per-project and per-machine work still fans
// out concurrently, which is where the round trips actually are.

// remoteBinder rebuilds a command config bound to another enrolled install and
// returns the func that unbinds it. Injected so the fan-out is testable
// without enrolled installs on the host.
type remoteBinder func(base commandConfig, remote string) (commandConfig, func(), error)

// remoteFanout is the host-dependent half of a fan-out: which installs exist,
// and how to bind to one.
type remoteFanout struct {
	names func() ([]string, error)
	bind  remoteBinder
}

func defaultRemoteFanout() remoteFanout {
	return remoteFanout{names: enrolledRemoteNames, bind: bindConfigToRemote}
}

// enrolledRemoteNames returns the enrolled Sandcastle installs, sorted. It is
// `sc remote list`'s set: incus remotes that are project-pinned or carry an
// Auth Hostname, which excludes the system remotes.
func enrolledRemoteNames() ([]string, error) {
	incusDir, _ := scconfig.SharedIncusDirExplained()
	remotes, err := readLocalRemotes(incusDir)
	if err != nil {
		return nil, fmt.Errorf("read incus remotes from %s: %w", incusDir, err)
	}
	// A missing sandcastle config is not fatal: project-pinned remotes are
	// still recognisable without it.
	cfg, _ := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	return sandcastleRemoteNames(remotes, cfg), nil
}

// matchingRemotes expands a remote pattern to the installs it names.
func (f remoteFanout) matchingRemotes(pattern string) ([]string, error) {
	names, err := f.names()
	if err != nil {
		return nil, err
	}
	matched := make([]string, 0, len(names))
	for _, name := range names {
		if naming.MatchName(pattern, name) {
			matched = append(matched, name)
		}
	}
	if len(matched) == 0 {
		hint := "run `sc remote list` to see enrolled installs"
		if len(names) > 0 {
			hint = "enrolled remotes: " + strings.Join(names, ", ")
		}
		return nil, fmt.Errorf("no enrolled Sandcastle remote matches %q; %s", pattern, hint)
	}
	return matched, nil
}

// forEachRemoteScope runs fn once per install the pattern selects, in name
// order. An empty pattern means "the current remote" and does no binding at
// all, so the overwhelmingly common single-install case pays nothing.
//
// fn runs with config bound to that install; the binding is undone before the
// next one. Errors are collected rather than aborting the sweep — a `sc stop
// '*:*:dev'` across four installs should not be silently truncated because the
// second one is unreachable — and returned joined at the end.
func (f remoteFanout) forEachRemoteScope(config commandConfig, pattern string, fn func(remote string, config commandConfig) error) error {
	current := strings.TrimSpace(config.adminConfig.Remote)
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return fn(current, config)
	}
	names, err := f.matchingRemotes(pattern)
	if err != nil {
		return err
	}
	failures := []string{}
	for _, name := range names {
		if err := f.runInScope(config, name, current, fn); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", strings.Join(failures, "\n"))
	}
	return nil
}

// runInScope binds, runs, and unbinds — as one unit, so a failing fn cannot
// leave INCUS_CONF pointing at the wrong install.
func (f remoteFanout) runInScope(config commandConfig, remote string, current string, fn func(string, commandConfig) error) error {
	if remote == current {
		return fn(remote, config)
	}
	scoped, restore, err := f.bind(config, remote)
	if err != nil {
		return err
	}
	defer restore()
	return fn(remote, scoped)
}

// qualifyReference renders a "remote:project:machine" reference, dropping the
// remote when it is the one the command is already on.
func qualifyReference(remote string, current string, project string, machine string) string {
	if remote == "" || remote == current {
		return project + ":" + machine
	}
	return remote + ":" + project + ":" + machine
}
