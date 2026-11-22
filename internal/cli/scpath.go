package cli

import (
	"fmt"
	"strings"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
)

// Sandcastle Path: the slash form of a reference, /install/tenant/project/machine
// (ADR-0032; the install segment is the Install Name, see installIndex).
//
// It is a second grammar beside the colon one ([tenant@][[remote:]project:]
// machine, ADR-0020) and is selected purely by shape: an argument that starts
// with "/", "./", "../" or "~", or is exactly ".", "..", "~" or "-", is a
// path; everything else is the colon grammar, untouched. A path resolves
// against the Current Position (the nearest .sandcastle) like a shell path
// resolves against the working directory, and every segment may be a shell
// glob. Machine commands then see the resolved path as the colon reference
// remote:project:machine, the remote being the one enrolled for the path's
// install and tenant, so nothing below the parser changes.

// Tree levels, by depth (the number of segments of an absolute path).
const (
	levelRoot    = 0
	levelInstall = 1
	levelTenant  = 2
	levelProject = 3
	levelMachine = 4
)

// levelName names a depth for messages.
func levelName(depth int) string {
	switch depth {
	case levelRoot:
		return "root"
	case levelInstall:
		return "install"
	case levelTenant:
		return "tenant"
	case levelProject:
		return "project"
	default:
		return "machine"
	}
}

// levelKeyword is the .sandcastle level value for a depth.
func levelKeyword(depth int) string {
	switch depth {
	case levelRoot:
		return scconfig.PositionRoot
	case levelInstall:
		return scconfig.PositionInstall
	case levelTenant:
		return scconfig.PositionTenant
	default:
		return scconfig.PositionProject
	}
}

// isPathReference reports whether an argument is written in the path grammar.
func isPathReference(arg string) bool {
	arg = strings.TrimSpace(arg)
	switch arg {
	case ".", "..", "~", "-":
		return true
	}
	return strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") || strings.HasPrefix(arg, "~/")
}

// formatPath renders segments as an absolute Sandcastle Path; the root is "/".
func formatPath(segments []string) string {
	return "/" + strings.Join(segments, "/")
}

// currentPosition is the Current Position as path segments: install, tenant
// and project, cut at the selection's level; the install is the selected
// remote's. The project falls back to
// "default" only at project level, matching what every command assumes when
// the selection names no project.
func currentPosition(config commandConfig) []string {
	admin := config.adminConfig
	segments := []string{loadInstallIndex().installNameOf(admin.Remote), strings.TrimSpace(admin.Tenant), strings.TrimSpace(admin.Project)}
	depth := scconfig.PositionDepth(admin.PositionLevel)
	if admin.PositionLevel == "" {
		depth = levelProject
	}
	if depth == levelProject && segments[2] == "" {
		segments[2] = naming.DefaultProjectName
	}
	return segments[:depth]
}

// homePosition is what `cd` with no argument and "~" mean: the global
// config's remote (as its install), tenant and project — the layer beneath
// every .sandcastle.
func homePosition() ([]string, error) {
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	remote := strings.TrimSpace(cfg.Remote)
	if remote == "" {
		return nil, fmt.Errorf("no home position: the global config names no remote (run sc login)")
	}
	tenant := strings.TrimSpace(cfg.Tenant)
	if t := cfg.TenantForRemote(remote); t != "" {
		tenant = t
	}
	project := strings.TrimSpace(cfg.Project)
	if project == "" {
		project = naming.DefaultProjectName
	}
	return []string{buildInstallIndex(cfg).installNameOf(remote), tenant, project}, nil
}

// previousPosition is the position recorded by the last `sc cd`, for "-".
func previousPosition() ([]string, error) {
	local, path, err := scconfig.LoadDirectoryConfig("")
	if err != nil {
		return nil, err
	}
	if path == "" || strings.TrimSpace(local.Previous) == "" {
		return nil, fmt.Errorf("no previous position: `sc cd -` needs an earlier `sc cd` in this directory")
	}
	return splitPath(strings.TrimSpace(local.Previous)), nil
}

// splitPath splits an absolute path into its non-empty segments.
func splitPath(path string) []string {
	segments := []string{}
	for _, part := range strings.Split(path, "/") {
		if part = strings.TrimSpace(part); part != "" {
			segments = append(segments, part)
		}
	}
	return segments
}

// globstar is the segment that matches across levels: zero or more
// directories in a listing, and as many "*" as reach a machine in a machine
// reference (`/**/dev` is `*:*:dev`). A "**" inside a longer segment
// ("web**") is an ordinary "*".
const globstar = "**"

// resolvePath turns a path argument into absolute segments against the
// Current Position. "." and ".." are folded ("" above the root stays at the
// root, like a shell), "~" is the home position and "-" the previous one.
// A path deeper than a machine is an error; "**" counts for nothing there,
// since it may match no level at all.
func resolvePath(config commandConfig, arg string) ([]string, error) {
	arg = strings.TrimSpace(arg)
	var base []string
	rest := arg
	switch {
	case arg == "-":
		previous, err := previousPosition()
		if err != nil {
			return nil, err
		}
		base, rest = previous, ""
	case arg == "~" || strings.HasPrefix(arg, "~/"):
		home, err := homePosition()
		if err != nil {
			return nil, err
		}
		base, rest = home, strings.TrimPrefix(arg, "~")
	case strings.HasPrefix(arg, "/"):
		base = []string{}
	default:
		base = currentPosition(config)
	}
	segments := append([]string{}, base...)
	for _, part := range strings.Split(rest, "/") {
		switch part {
		case "", ".":
		case "..":
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		default:
			segments = append(segments, part)
		}
	}
	segments, err := canonicalSegments(config, segments)
	if err != nil {
		return nil, err
	}
	if fixedSegments(segments) > levelMachine {
		return nil, fmt.Errorf("path %q is deeper than a machine: expected /install/tenant/project/machine", arg)
	}
	for depth, segment := range segments {
		if segment == globstar {
			continue
		}
		if err := validatePathSegment(depth+1, segment); err != nil {
			return nil, err
		}
	}
	return segments, nil
}

// fixedSegments counts the segments that are not "**".
func fixedSegments(segments []string) int {
	count := 0
	for _, segment := range segments {
		if segment != globstar {
			count++
		}
	}
	return count
}

// expandGlobstarToMachine rewrites "**" segments into the "*" segments that
// bring the path to machine depth: the first "**" absorbs them all, further
// ones vanish. A path with no "**" is returned as is.
func expandGlobstarToMachine(segments []string) []string {
	fixed := fixedSegments(segments)
	if fixed == len(segments) {
		return segments
	}
	stars := levelMachine - fixed
	out := make([]string, 0, levelMachine)
	absorbed := false
	for _, segment := range segments {
		if segment != globstar {
			out = append(out, segment)
			continue
		}
		if !absorbed {
			for i := 0; i < stars; i++ {
				out = append(out, "*")
			}
			absorbed = true
		}
	}
	return out
}

// validatePathSegment validates one segment as a literal or a glob for its
// level (1 for the install), with the same rules the colon grammar applies
// to its parts.
func validatePathSegment(depth int, value string) error {
	if naming.IsPattern(value) {
		return naming.ValidateNamePattern(levelName(depth), value)
	}
	switch depth {
	case levelInstall:
		return naming.ValidateInstallSuffix(value)
	case levelTenant:
		if value == "" {
			return fmt.Errorf("tenant segment is required")
		}
		return nil
	case levelProject:
		return naming.ValidateProjectName(value)
	default:
		return naming.ValidateMachineName(value)
	}
}

// canonicalSegments rewrites a remote-form path (ADR-0030,
// /remote/tenant/…) into the install form and says so once on stderr. Only a
// first segment that is no Install Name but an enrolled remote is rewritten:
// when a name is both, the install reading wins (ADR-0032 decision 5).
func canonicalSegments(config commandConfig, segments []string) ([]string, error) {
	if len(segments) == 0 || segments[0] == globstar || naming.IsPattern(segments[0]) {
		return segments, nil
	}
	ix := loadInstallIndex()
	if _, ok := ix.install(segments[0]); ok {
		return segments, nil
	}
	place, ok := ix.remotes[segments[0]]
	if !ok || place.Install == "" || place.Tenant == "" {
		return segments, nil
	}
	rewritten := []string{place.Install, place.Tenant}
	switch {
	case len(segments) == 1:
	case segments[1] == globstar:
		rewritten = append(rewritten, segments[1:]...)
	case naming.MatchName(segments[1], place.Tenant):
		rewritten = append(rewritten, segments[2:]...)
	default:
		return nil, fmt.Errorf("remote %q serves tenant %q, not %q: use %s", segments[0], place.Tenant, segments[1], formatPath(append([]string{place.Install}, segments[1:]...)))
	}
	if config.stderr != nil {
		fmt.Fprintf(config.stderr, "note: %s is %s (paths start at the install)\n", formatPath(segments), formatPath(rewritten))
	}
	return rewritten, nil
}

// pathToMachineReference converts a machine-level path into the colon
// reference remote:project:machine that every machine command parses. The
// install and tenant segments pick the remote. A glob there must narrow to
// one remote, or span every one ("*"): the colon grammar's remote part
// cannot name a set. A shorter path names a directory, which no machine
// command accepts.
func pathToMachineReference(config commandConfig, arg string) (string, error) {
	segments, err := resolvePath(config, arg)
	if err != nil {
		return "", err
	}
	segments = expandGlobstarToMachine(segments)
	if len(segments) != levelMachine {
		return "", fmt.Errorf("path %s names a %s, not a machine: expected /install/tenant/project/machine", formatPath(segments), levelName(len(segments)))
	}
	install, tenantName, project, machine := segments[0], segments[1], segments[2], segments[3]
	remote, err := pathRemote(config, install, tenantName)
	if err != nil {
		return "", err
	}
	return remote + ":" + project + ":" + machine, nil
}

// pathRemote is the colon reference's remote part for a path's install and
// tenant segments.
func pathRemote(config commandConfig, install, tenantName string) (string, error) {
	if install == "*" && tenantName == "*" {
		return "*", nil
	}
	ix := loadInstallIndex()
	if !naming.IsPattern(install) && !naming.IsPattern(tenantName) {
		return ix.positionRemote(config, install, tenantName)
	}
	remotes := ix.matchingRemotes(install, tenantName)
	switch {
	case len(remotes) == 0:
		return "", fmt.Errorf("no enrolled tenant matches /%s/%s; installs: %s", install, tenantName, strings.Join(ix.names(), ", "))
	case len(remotes) == 1:
		return remotes[0], nil
	case len(remotes) == len(ix.matchingRemotes("*", "*")):
		return "*", nil
	}
	return "", fmt.Errorf("/%s/%s spans %d tenants (remotes %s); machine commands take one tenant or all of them (/*/*/…)", install, tenantName, len(remotes), strings.Join(remotes, ", "))
}

// normalizeReference is the one hook every reference-taking command goes
// through: a path argument becomes its colon reference, anything else is
// returned untouched.
func normalizeReference(config commandConfig, reference string) (string, error) {
	if !isPathReference(reference) {
		return reference, nil
	}
	return pathToMachineReference(config, reference)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
