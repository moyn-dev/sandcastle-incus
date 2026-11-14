package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/usertrust"
	"gopkg.in/yaml.v2"
)

// localRemote is one incus remote as read from the client config: its name, the
// endpoint it points at, and the incus project it is pinned to.
type localRemote struct {
	Name     string
	Endpoint string
	Project  string
}

// remoteRename is one legacy remote to rename to the ADR-0021 scheme.
type remoteRename struct {
	From string
	To   string
}

// remoteMigration is the set of changes that bring a tenant's incus remotes onto
// the ADR-0021 single-remote-per-install scheme: rename one primary to `<suffix>`
// and remove the same-install extras (the per-project remotes being collapsed).
type remoteMigration struct {
	Renames []remoteRename
	Removes []string
}

// planRemoteMigration computes the changes that collapse a tenant's incus remotes
// for one install onto the ADR-0021 `<suffix>` scheme (one remote per install). A
// remote belongs to this install iff its endpoint matches AND its pinned incus
// project is `sc2-<tenant>-<proj>` (never by parsing the name — ADR-0020 dec. 2).
// One primary (an already-`<suffix>`-named remote, else the default-project one,
// else the lexicographically first) becomes `<suffix>`; the rest are removed.
// Fully-migrated inputs (only `<suffix>` present) yield an empty plan (idempotent).
//
// The installEndpoint scope is MANDATORY, not best-effort: a same-named tenant on
// a different install has the same pinned-project pattern, so without this
// install's endpoint we cannot tell them apart — and touching the wrong install's
// remotes is worse than not migrating. An empty endpoint therefore yields no plan.
func planRemoteMigration(remotes []localRemote, tenant, suffix, installEndpoint string) remoteMigration {
	suffix = strings.TrimSpace(suffix)
	tenant = strings.TrimSpace(tenant)
	installEndpoint = strings.TrimSpace(installEndpoint)
	target := usertrust.RemoteNameForSuffix(suffix)
	if target == "" || tenant == "" || installEndpoint == "" {
		return remoteMigration{} // fail safe: never migrate unscoped
	}
	var candidates []localRemote
	for _, r := range remotes {
		if strings.TrimSpace(r.Endpoint) != installEndpoint {
			continue // a different install's remote — never touch across installs
		}
		if shortProjectName(r.Project, tenant) == "" {
			continue // infra project, or not this tenant's per-project remote
		}
		candidates = append(candidates, r)
	}
	if len(candidates) == 0 {
		return remoteMigration{}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })

	// Pick the primary: an already-`<suffix>`-named remote, else the one pinned to
	// the default project, else the first.
	primary := -1
	for i, r := range candidates {
		if r.Name == target {
			primary = i
			break
		}
	}
	if primary == -1 {
		for i, r := range candidates {
			if shortProjectName(r.Project, tenant) == naming.DefaultProjectName {
				primary = i
				break
			}
		}
	}
	if primary == -1 {
		primary = 0
	}

	var m remoteMigration
	for i, r := range candidates {
		if i == primary {
			if r.Name != target {
				m.Renames = append(m.Renames, remoteRename{From: r.Name, To: target})
			}
			continue
		}
		m.Removes = append(m.Removes, r.Name)
	}
	return m
}

// readLocalRemotes reads the incus config.yml in incusDir into localRemotes.
func readLocalRemotes(incusDir string) ([]localRemote, error) {
	data, err := os.ReadFile(filepath.Join(incusDir, "config.yml"))
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Remotes map[string]struct {
			Addr    string `yaml:"addr"`
			Project string `yaml:"project"`
		} `yaml:"remotes"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	remotes := make([]localRemote, 0, len(parsed.Remotes))
	for name, r := range parsed.Remotes {
		remotes = append(remotes, localRemote{Name: name, Endpoint: r.Addr, Project: r.Project})
	}
	return remotes, nil
}

// migrateLegacyRemotes lazily collapses a tenant's incus remotes onto the
// ADR-0021 single-`<suffix>` scheme at login. Best-effort: failures are logged
// and skipped, and the caller's login is never failed by a migration hiccup.
// installEndpoint must be this install's endpoint; an empty one migrates nothing
// (see planRemoteMigration). It never removes the current default-remote (that
// would break the incus current-remote pointer) — it leaves it with a note.
func migrateLegacyRemotes(ctx context.Context, incusDir, tenant, suffix, installEndpoint string, stderr io.Writer) {
	remotes, err := readLocalRemotes(incusDir)
	if err != nil {
		return
	}
	byName := make(map[string]localRemote, len(remotes))
	for _, r := range remotes {
		byName[r.Name] = r
	}
	current := readLocalDefaultRemote(incusDir)
	m := planRemoteMigration(remotes, tenant, suffix, installEndpoint)
	for _, rename := range m.Renames {
		// The target may already exist (e.g. this login just enrolled `<suffix>`).
		// Same install (endpoint) → the source is now a redundant duplicate; drop
		// it. A target pointing at a DIFFERENT install is a cross-install name
		// clash: never clobber — leave both and surface it.
		if target, exists := byName[rename.To]; exists {
			from := byName[rename.From]
			if target.Endpoint == from.Endpoint {
				removeUnlessCurrent(ctx, incusDir, current, rename.From, stderr)
			} else if stderr != nil {
				fmt.Fprintf(stderr, "Note: remote %q left as-is — %q already exists for a different install\n", rename.From, rename.To)
			}
			continue
		}
		runIncusRemote(ctx, incusDir, stderr, rename.From, rename.To, "rename", rename.From, rename.To)
	}
	for _, name := range m.Removes {
		removeUnlessCurrent(ctx, incusDir, current, name, stderr)
	}
	if len(m.Renames)+len(m.Removes) > 0 {
		syncNativeIncusMirror(stderr)
	}
}

// removeUnlessCurrent removes an incus remote unless it is the current
// default-remote (removing that would orphan the incus current-remote pointer).
func removeUnlessCurrent(ctx context.Context, incusDir, current, name string, stderr io.Writer) {
	if strings.TrimSpace(name) == strings.TrimSpace(current) {
		if stderr != nil {
			fmt.Fprintf(stderr, "Note: remote %q left as-is — it is your current remote; switch away then remove it to finish collapsing to one remote per install\n", name)
		}
		return
	}
	runIncusRemote(ctx, incusDir, stderr, name, "", "remove", name)
}

// readLocalDefaultRemote returns the incus config dir's current default-remote.
func readLocalDefaultRemote(incusDir string) string {
	data, err := os.ReadFile(filepath.Join(incusDir, "config.yml"))
	if err != nil {
		return ""
	}
	var parsed struct {
		DefaultRemote string `yaml:"default-remote"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.DefaultRemote)
}

// runIncusRemote runs `incus remote <args...>` in incusDir, logging a best-effort
// migration note (naming from→to) on failure without failing the caller.
func runIncusRemote(ctx context.Context, incusDir string, stderr io.Writer, from, to string, args ...string) {
	cmd := exec.CommandContext(ctx, "incus", append([]string{"remote"}, args...)...)
	cmd.Env = os.Environ()
	if strings.TrimSpace(incusDir) != "" {
		cmd.Env = append(cmd.Env, "INCUS_CONF="+incusDir)
	}
	if out, err := cmd.CombinedOutput(); err != nil && stderr != nil {
		fmt.Fprintf(stderr, "Note: could not migrate remote %q → %q: %s\n", from, to, strings.TrimSpace(string(out)))
	}
}
