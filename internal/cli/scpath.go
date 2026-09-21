package cli

import (
	"fmt"
	"strings"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// Sandcastle Path: the slash form of a reference, /remote/tenant/project/machine.
//
// It is a second grammar beside the colon one ([tenant@][[remote:]project:]
// machine, ADR-0020) and is selected purely by shape: an argument that starts
// with "/", "./", "../" or "~", or is exactly ".", "..", "~" or "-", is a
// path; everything else is the colon grammar, untouched. A path resolves
// against the Current Position (the nearest .sandcastle) like a shell path
// resolves against the working directory, and every segment may be a shell
// glob. Machine commands then see the resolved path as the colon reference
// remote:project:machine, so nothing below the parser changes.

// Tree levels, by depth (the number of segments of an absolute path).
const (
	levelRoot    = 0
	levelRemote  = 1
	levelTenant  = 2
	levelProject = 3
	levelMachine = 4
)

// levelName names a depth for messages.
func levelName(depth int) string {
	switch depth {
	case levelRoot:
		return "root"
	case levelRemote:
		return "remote"
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
	case levelRemote:
		return scconfig.PositionRemote
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

// currentPosition is the Current Position as path segments: remote, tenant
// and project, cut at the selection's level. The project falls back to
// "default" only at project level, matching what every command assumes when
// the selection names no project.
func currentPosition(config commandConfig) []string {
	admin := config.adminConfig
	segments := []string{strings.TrimSpace(admin.Remote), strings.TrimSpace(admin.Tenant), strings.TrimSpace(admin.Project)}
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
// config's remote, tenant and project — the layer beneath every .sandcastle.
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
	return []string{remote, tenant, project}, nil
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
		return previousPosition()
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
	if fixedSegments(segments) > levelMachine {
		return nil, fmt.Errorf("path %q is deeper than a machine: expected /remote/tenant/project/machine", arg)
	}
	for depth, segment := range segments {
		if segment == globstar {
			continue
		}
		if err := validatePathSegment(depth, segment); err != nil {
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
// level, with the same rules the colon grammar applies to its parts.
func validatePathSegment(depth int, value string) error {
	if naming.IsPattern(value) {
		return naming.ValidateNamePattern(levelName(depth), value)
	}
	switch depth {
	case levelRemote:
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

// tenantOfRemote is the tenant a remote is enrolled for: the Current Tenant
// on the current remote, else the recorded enrollment. Empty when unknown.
func tenantOfRemote(config commandConfig, remote string) string {
	if remote == strings.TrimSpace(config.adminConfig.Remote) {
		if tenant := strings.TrimSpace(config.adminConfig.Tenant); tenant != "" {
			return tenant
		}
	}
	cfg, err := scconfig.LoadSandcastleConfig(scconfig.DefaultConfigPath())
	if err != nil {
		return ""
	}
	return cfg.TenantForRemote(remote)
}

// pathToMachineReference converts a machine-level path into the colon
// reference remote:project:machine that every machine command parses. The
// tenant segment must be the tenant the remote serves — a remote is enrolled
// for exactly one tenant (ADR-0021), so another tenant's machines are reached
// by `sc cd` into that tenant, which enrolls its remote. A shorter path names
// a directory, which no machine command accepts.
func pathToMachineReference(config commandConfig, arg string) (string, error) {
	segments, err := resolvePath(config, arg)
	if err != nil {
		return "", err
	}
	segments = expandGlobstarToMachine(segments)
	if len(segments) != levelMachine {
		return "", fmt.Errorf("path %s names a %s, not a machine: expected /remote/tenant/project/machine", formatPath(segments), levelName(len(segments)))
	}
	remote, tenant, project, machine := segments[0], segments[1], segments[2], segments[3]
	if !naming.IsPattern(remote) {
		names, err := enrolledRemoteNames()
		if err != nil {
			return "", err
		}
		if !containsString(names, remote) {
			hint := "run `sc remote list` to see enrolled installs, or `sc login <auth-hostname>` to enroll"
			if len(names) > 0 {
				hint = "enrolled remotes: " + strings.Join(names, ", ")
			}
			return "", fmt.Errorf("no enrolled Sandcastle remote %q in path %s; %s", remote, formatPath(segments), hint)
		}
		if served := tenantOfRemote(config, remote); served != "" && !naming.MatchName(tenant, served) {
			return "", fmt.Errorf("remote %q serves tenant %q, not %q: `sc cd /%s/%s` first", remote, served, tenant, remote, tenant)
		}
	}
	return remote + ":" + project + ":" + machine, nil
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
