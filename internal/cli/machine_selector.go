package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	machine "github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// machineSelector is the glob-capable form of a machine reference. It has the
// same "[[dns-suffix:]project:]machine" shape as parseV2MachineReference, but
// either name part may be a shell-style pattern ("gbrain:*", "g*:d*"), so it
// designates a SET of machines rather than one. Literal parts still designate
// exactly one thing — MatchName on a literal is an equality check — which is
// what lets every reference go through the selector without changing how
// unqualified references behave.
type machineSelector struct {
	// Remote is the leading part of a three-part reference. Empty means "the
	// install the command is already on". A glob here expands to every
	// matching ENROLLED remote (see remote_scope.go); a literal that is not an
	// enrolled remote is an install DNS suffix and stays the cross-install
	// addressing path's business (ADR-0020).
	Remote  string
	Project string
	Machine string
	// Reference is the text the user typed, for error messages.
	Reference string
}

// HasPattern reports whether the reference globs. Commands branch on this and
// not on the match count: a pattern that matched one machine is still a
// pattern, and a literal that matched nothing is still an error.
func (s machineSelector) HasPattern() bool {
	return s.HasRemotePattern() || naming.IsPattern(s.Project) || naming.IsPattern(s.Machine)
}

// HasRemotePattern reports whether the reference spans installs.
func (s machineSelector) HasRemotePattern() bool {
	return naming.IsPattern(s.Remote)
}

// String renders the selector for messages, naming the remote only when the
// reference actually addressed one.
func (s machineSelector) String() string {
	if s.Remote != "" {
		return s.Remote + ":" + s.Project + ":" + s.Machine
	}
	return s.Project + ":" + s.Machine
}

// parseMachineSelector splits "[[remote:]project:]machine" into parts that may
// be globs. It mirrors parseV2MachineReference — same colon grammar, same
// project defaulting — but validates each part as a pattern.
//
// Only the THREE-part form carries a remote. A two-part "a:b" stays
// project:machine unless "a" exactly names an enrolled remote, which is what
// rebindForReference already resolves before this is reached. Making a
// two-part glob able to mean remote:machine would put the reading of
// "g*:d*" at the mercy of whether some install happens to be named gizmo —
// so globbing installs is spelled out in full: "sc ls '*:*:dev'".
func parseMachineSelector(reference string, currentProject string) (machineSelector, error) {
	remote, project, machineName, err := splitMachineReference(reference, currentProject)
	if err != nil {
		return machineSelector{}, err
	}
	if remote != "" {
		if err := validateNamePart("remote", remote); err != nil {
			return machineSelector{}, err
		}
	}
	if err := validateNamePart("project", project); err != nil {
		return machineSelector{}, err
	}
	if err := validateNamePart("machine", machineName); err != nil {
		return machineSelector{}, err
	}
	return machineSelector{
		Remote:    remote,
		Project:   project,
		Machine:   machineName,
		Reference: strings.TrimSpace(reference),
	}, nil
}

// validateNamePart validates one reference part as either a glob or a literal
// name, so a literal keeps its exact, kind-specific error message.
func validateNamePart(kind string, value string) error {
	if naming.IsPattern(value) {
		return naming.ValidateNamePattern(kind, value)
	}
	switch kind {
	case "project":
		return naming.ValidateProjectName(value)
	case "remote":
		// A literal leading part is an incus remote name or an install DNS
		// suffix — the same single-label shape either way (ADR-0020).
		return naming.ValidateInstallSuffix(value)
	}
	return naming.ValidateMachineName(value)
}

// selectMachines returns the tenant's machines the selector matches, sorted by
// project then name so output and prompts are stable.
//
// When the project part is literal the listing is scoped to that one Incus
// project (see incusx.ListMachinesInProject) instead of querying every project
// of the tenant — which is what makes "gbrain:*" cost one round trip rather
// than one per project.
func selectMachines(ctx context.Context, config commandConfig, summary tenant.Summary, selector machineSelector) ([]meta.Machine, error) {
	if config.machineStore == nil {
		return nil, fmt.Errorf("machine metadata store is not configured")
	}
	if !naming.IsPattern(selector.Project) {
		// A literal project must exist — otherwise a typo comes back as an
		// empty listing that reads like "no machines" rather than "no such
		// project". A project GLOB matching nothing is not an error: it is an
		// empty set, the same as a machine glob matching nothing.
		if _, ok := findProject(summary, selector.Project); !ok {
			return nil, unknownProject{err: unknownProjectError(summary, selector.Project, selector.Machine)}
		}
	}
	// The project part — glob or not — is pushed into the store, which resolves
	// it against the tenant summary's project list before issuing any Incus
	// call. So "w*" against an install whose only project is "home" costs zero
	// round trips rather than one per project.
	machines, err := listMachinesScoped(ctx, config.machineStore, summary, selector.Project)
	if err != nil {
		return nil, err
	}
	matched := make([]meta.Machine, 0, len(machines))
	for _, candidate := range machines {
		if !naming.MatchName(selector.Project, candidate.Project) {
			continue
		}
		if !naming.MatchName(selector.Machine, candidate.Name) {
			continue
		}
		matched = append(matched, candidate)
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].Project != matched[j].Project {
			return matched[i].Project < matched[j].Project
		}
		return matched[i].Name < matched[j].Name
	})
	return matched, nil
}

// listMachinesScoped reads the tenant's machines, pushing the project filter
// (a name or a glob) down into the store so only the matching Incus projects
// are queried. Stores that cannot scope fall back to the whole tenant; the
// caller filters either way.
func listMachinesScoped(ctx context.Context, store machine.Store, summary tenant.Summary, projectFilter string) ([]meta.Machine, error) {
	if projectFilter != "" {
		if scoped, ok := store.(machine.ProjectScopedStore); ok {
			return scoped.ListMachinesInProject(ctx, summary, projectFilter)
		}
	}
	return store.ListMachines(ctx, summary)
}

// resolveSingleMachineReference narrows a possibly-globbing reference to the
// one existing machine it names and returns it as a literal "project:machine".
// It is the front door for commands that act on exactly one machine (connect,
// fix, route, image): a wildcard is a convenient way to SELECT that machine,
// but the command still needs one.
//
// A literal reference passes through untouched, unresolved — `sc connect` may
// legitimately name a machine that does not exist yet and create it, and only
// the caller knows whether that is allowed. A wildcard never creates anything:
// it can only pick from what is already there.
func resolveSingleMachineReference(ctx context.Context, config commandConfig, summary tenant.Summary, reference string) (string, error) {
	selector, err := parseMachineSelector(reference, config.adminConfig.Project)
	if err != nil {
		// Not ours to report — the caller's strict parser raises this with its
		// own wording, and the reference is unchanged either way.
		return reference, nil
	}
	if !selector.HasPattern() {
		return reference, nil
	}
	if selector.HasRemotePattern() {
		// The caller is already bound to one install, so a cross-install
		// narrowing has to happen before it binds — see narrowRemoteGlob.
		return "", fmt.Errorf("%q globs the install part; this command acts on one machine on one install — name the install",
			selector.Reference)
	}
	matched, err := selectMachines(ctx, config, summary, selector)
	if err != nil {
		return "", err
	}
	targets := machineTargets(matched)
	switch len(matched) {
	case 0:
		return "", fmt.Errorf("no machines match %q in tenant %s", selector.Reference, summary.Tenant)
	case 1:
		return targets[0], nil
	}
	if !isTerminalInput(config) {
		return "", fmt.Errorf("%q matches %d machines (%s); this command acts on one — name it, or narrow the pattern",
			selector.Reference, len(matched), strings.Join(targets, ", "))
	}
	choice, err := promptChoice(config, fmt.Sprintf("%q matches %d machines:", selector.Reference, len(matched)), targets)
	if err != nil {
		return "", err
	}
	return targets[choice], nil
}

// narrowRemoteGlob resolves a reference whose INSTALL part globs down to one
// concrete "remote:project:machine", by sweeping the matching installs for the
// machines it names. It runs BEFORE the caller binds to an install — that is
// the whole point: rebindForReference needs a literal remote name, and this is
// what turns a glob into one.
//
// References that do not glob the install part pass through untouched, so
// single-install addressing is not routed through the sweep.
func narrowRemoteGlob(ctx context.Context, config commandConfig, fanout remoteFanout, reference string) (string, error) {
	reference, err := normalizeReference(config, reference)
	if err != nil {
		return "", err
	}
	selector, err := parseMachineSelector(reference, config.adminConfig.Project)
	if err != nil || !selector.HasRemotePattern() {
		return reference, nil
	}
	matches, err := selectMachinesAcrossRemotes(ctx, config, fanout, selector)
	if err != nil {
		return "", err
	}
	targets := matchTargets(matches)
	qualified := make([]string, 0, len(matches))
	for _, match := range matches {
		qualified = append(qualified, match.Remote+":"+match.Machine.Project+":"+match.Machine.Name)
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no machines match %q on any enrolled install", selector.Reference)
	case 1:
		return qualified[0], nil
	}
	if !isTerminalInput(config) {
		return "", fmt.Errorf("%q matches %d machines (%s); this command acts on one — name it, or narrow the pattern",
			selector.Reference, len(matches), strings.Join(targets, ", "))
	}
	choice, err := promptChoice(config, fmt.Sprintf("%q matches %d machines:", selector.Reference, len(matches)), targets)
	if err != nil {
		return "", err
	}
	return qualified[choice], nil
}

// machineTargets renders matches as "project:machine" for prompts and errors.
func machineTargets(machines []meta.Machine) []string {
	targets := make([]string, 0, len(machines))
	for _, candidate := range machines {
		targets = append(targets, candidate.Project+":"+candidate.Name)
	}
	return targets
}

// machineMatch is one selected machine together with the install it lives on —
// which a remote-globbing selector needs, because each install has its own
// tenant summary (DNS suffix, project list, Incus project naming).
type machineMatch struct {
	Remote  string
	Summary tenant.Summary
	Machine meta.Machine
}

// remotePattern returns the part of the selector that drives a remote fan-out.
// A LITERAL remote is not one: by the time a selector is parsed, an enrolled
// remote prefix has already been stripped and bound by rebindForReference, and
// anything else literal is an install DNS suffix that the cross-install path
// owns (ADR-0020).
func (s machineSelector) remotePattern() string {
	if s.HasRemotePattern() {
		return s.Remote
	}
	return ""
}

// selectMachinesAcrossRemotes expands the whole selector, sweeping every
// enrolled install the remote part matches. With no remote pattern it is
// selectMachines against the current install and costs nothing extra.
//
// Failures are not swallowed: an install that cannot be reached, or has no
// tenant, comes back in the error. Callers acting destructively should treat
// that as fatal (acting on a partial sweep is not what the user asked for);
// `sc ls` reports it and shows what it did find.
func selectMachinesAcrossRemotes(ctx context.Context, config commandConfig, fanout remoteFanout, selector machineSelector) ([]machineMatch, error) {
	matches := []machineMatch{}
	spansInstalls := selector.HasRemotePattern()
	// Across installs a literal project that is absent HERE is not an error —
	// installs have different project sets, and `sc stop '*:web:api'` must not
	// fail whole because one install has no "web". It is only an error when no
	// swept install had it at all, which is what a typo looks like.
	var projectMissing error
	sawProject := false
	err := fanout.forEachRemoteScope(config, selector.remotePattern(), func(remote string, scoped commandConfig) error {
		summary, err := requireV2Tenant(ctx, scoped)
		if err != nil {
			return err
		}
		found, err := selectMachines(ctx, scoped, summary, selector)
		if err != nil {
			var missing unknownProject
			if spansInstalls && errors.As(err, &missing) {
				projectMissing = err
				return nil
			}
			return err
		}
		sawProject = true
		for _, candidate := range found {
			// Remote is recorded only for a cross-install sweep. It is what
			// makes output name the install, and a same-install selection must
			// not start printing one.
			match := machineMatch{Summary: summary, Machine: candidate}
			if spansInstalls {
				match.Remote = remote
			}
			matches = append(matches, match)
		}
		return nil
	})
	if err != nil {
		return matches, err
	}
	if !sawProject && projectMissing != nil {
		return nil, projectMissing
	}
	return matches, nil
}

// matchTargets renders matches for prompts and errors. A match carries its
// install only when it came from a cross-install sweep, and then the install
// is always named — "work:api" would be actively misleading when the machine
// is on a DIFFERENT install from the one the command is sitting on.
func matchTargets(matches []machineMatch) []string {
	targets := make([]string, 0, len(matches))
	for _, match := range matches {
		if match.Remote != "" {
			targets = append(targets, match.Remote+":"+match.Machine.Project+":"+match.Machine.Name)
			continue
		}
		targets = append(targets, match.Machine.Project+":"+match.Machine.Name)
	}
	return targets
}

// unknownProject marks "this tenant has no such project" so a cross-install
// sweep can tell it apart from a real failure. On ONE install it is an error
// (a typo must not read as "no machines"); across several it is expected —
// installs have different project sets — and only means there is nothing to
// match here.
type unknownProject struct{ err error }

func (e unknownProject) Error() string { return e.err.Error() }
func (e unknownProject) Unwrap() error { return e.err }

// unknownProjectError is the shared "that project does not exist" error, kept
// identical to the one resolveV2MachineReference raises so a mistyped project
// reads the same whichever path resolved the reference.
func unknownProjectError(summary tenant.Summary, project string, machineName string) error {
	names := make([]string, 0, len(summary.Projects))
	for _, candidate := range summary.Projects {
		names = append(names, candidate.Name)
	}
	hint := ""
	if _, swapped := findProject(summary, machineName); swapped {
		hint = fmt.Sprintf("\nThe reference is [[dns-suffix:]project:]machine — did you mean %q?", machineName+":"+project)
	}
	if hint == "" && localRemoteExists(project) {
		hint = fmt.Sprintf("\n%q is an incus remote, not a project — reach another install with dns-suffix:project:machine.", project)
	}
	return fmt.Errorf("project %q not found in tenant %s (projects: %s).%s\nCreate it with: sc project create %s",
		project, summary.Tenant, strings.Join(names, ", "), hint, project)
}
