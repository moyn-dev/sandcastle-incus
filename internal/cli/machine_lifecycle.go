package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	machine "github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// machineActionResult is one machine's outcome in a lifecycle run. Remote is
// set only when the run spanned installs.
type machineActionResult struct {
	// Path is the machine's Sandcastle Path, the name text output uses.
	Path    string `json:"path,omitempty"`
	Remote  string `json:"remote,omitempty"`
	Project string `json:"project"`
	Machine string `json:"machine"`
	Error   string `json:"error,omitempty"`
}

// target renders the result for text output: its Sandcastle Path when the
// run knew the install and tenant, else the colon reference.
func (r machineActionResult) target() string {
	if r.Path != "" {
		return r.Path
	}
	if r.Remote != "" {
		return r.Remote + ":" + r.Project + ":" + r.Machine
	}
	return r.Project + ":" + r.Machine
}

// machineActionPayload is the JSON of a wildcard lifecycle run. A reference
// that names one machine keeps the historical scalar payload instead — see
// runMachineLifecycle — so existing scripts parsing `sc stop web --json` do
// not have to change.
type machineActionPayload struct {
	Action   string                `json:"action"`
	Tenant   string                `json:"tenant"`
	Selector string                `json:"selector"`
	Results  []machineActionResult `json:"results"`
}

// machineLifecycleAliases are the short forms of the lifecycle verbs
// (`sc del web`, `sc up web`), beside `c` for connect and `ls` for list.
var machineLifecycleAliases = map[string][]string{
	"delete":  {"del", "rm"},
	"start":   {"up"},
	"stop":    {"down"},
	"restart": {"reboot"},
}

func newMachineLifecycleCommand(config commandConfig, opts *rootOptions, use string, action machine.Action, requireYes bool) *cobra.Command {
	var yes, force, dryRun, recursive bool
	command := &cobra.Command{
		Use:     use + " [[remote:]project:]machine",
		Aliases: machineLifecycleAliases[use],
		Short:   machineLifecycleShort(action),
		Long: machineLifecycleShort(action) + `.

Every part of the reference accepts shell-style wildcards, so one invocation
can act on a set: "` + use + ` 'gbrain:*'" for every machine in project gbrain,
"` + use + ` '*:web-*'" for the web-* machines of every project, and
"` + use + ` '*:*:dev'" for the dev machine of every ENROLLED INSTALL. Globbing
installs needs all three parts spelled out. Quote the pattern so the shell does
not expand it first. A wildcard that matches nothing is an error, and ` + use + `
reports every machine it acted on.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: pathCompletion(config, levelMachine),
		RunE: func(cmd *cobra.Command, args []string) error {
			yes = yes || force
			if action == machine.ActionDelete && isPathReference(args[0]) {
				// `sc rm /remote/tenant/project` removes a project; a machine
				// path falls through to the machine grammar below.
				handled, err := removeProjectPath(cmd.Context(), config, opts, args[0], recursive, yes, dryRun)
				if handled || err != nil {
					return err
				}
			}
			config, reference, restore, err := rebindForReference(config, args[0])
			if err != nil {
				return err
			}
			defer restore()
			if dryRun {
				return planMachineLifecycle(cmd.Context(), config, opts, reference, action)
			}
			return runMachineLifecycle(cmd.Context(), config, opts, defaultRemoteFanout(), reference, action, requireYes, yes)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "show targets and certificate decision without changing machines")
	if requireYes {
		command.Flags().BoolVar(&yes, "yes", false, "confirm machine deletion")
		command.Flags().BoolVarP(&force, "force", "f", false, "delete without asking (same as --yes)")
		command.Flags().BoolVarP(&recursive, "recursive", "r", false, "with a project path: delete the project's machines first, then the project")
	}
	return command
}

// removeProjectPath is `sc rm` on a Sandcastle Path that names a project:
// the project is deleted (its machines first with -r; an empty project is
// required otherwise, as `sc project delete` requires). A path naming a
// machine is not handled here (false, nil), a remote or tenant is an error.
func removeProjectPath(ctx context.Context, config commandConfig, opts *rootOptions, arg string, recursive bool, yes bool, dryRun bool) (bool, error) {
	segments, err := resolvePath(config, arg)
	if err != nil {
		return true, err
	}
	switch len(segments) {
	case levelMachine:
		return false, nil
	case levelProject:
	default:
		return true, fmt.Errorf("%s is a %s: rm removes projects and machines; remotes and tenants are managed by sc remote, sc login and sc-adm", formatPath(segments), levelName(len(segments)))
	}
	remote, tenantName, project := segments[0], segments[1], segments[2]
	if naming.IsPattern(remote) || naming.IsPattern(tenantName) || naming.IsPattern(project) {
		return true, fmt.Errorf("rm needs one project, not the pattern %s", formatPath(segments))
	}
	bound, restore, err := configForPosition(config, remote, tenantName)
	if err != nil {
		return true, err
	}
	defer restore()
	if recursive {
		summary, err := requireV2Tenant(ctx, bound)
		if err != nil {
			return true, err
		}
		if _, ok := findProject(summary, project); !ok {
			return true, unknownProjectError(summary, project, "")
		}
		selector, err := parseMachineSelector(project+":*", project)
		if err != nil {
			return true, err
		}
		machines, err := selectMachines(ctx, bound, summary, selector)
		if err != nil {
			return true, err
		}
		if len(machines) > 0 {
			// ONE confirmation for the whole removal — the project and its
			// machines are a single decision, not a prompt per step.
			if !yes && !dryRun {
				names := make([]string, 0, len(machines))
				for _, m := range machines {
					names = append(names, m.Name)
				}
				noun := "machine"
				if len(names) > 1 {
					noun = "machines"
				}
				prompt := fmt.Sprintf("Delete project %s and its %d %s (%s)?", formatPath(segments), len(names), noun, strings.Join(names, ", "))
				confirmed, err := confirmMissingYes(bound, prompt, "refusing to delete project without --yes")
				if err != nil {
					return true, err
				}
				if !confirmed {
					return true, fmt.Errorf("delete canceled")
				}
				yes = true
			}
			if err := runMachineLifecycle(ctx, bound, opts, defaultRemoteFanout(), project+":*", machine.ActionDelete, true, yes); err != nil {
				return true, err
			}
		}
	}
	return true, runProjectDelete(ctx, bound, opts, project, yes, dryRun)
}

func runMachineLifecycle(ctx context.Context, config commandConfig, opts *rootOptions, fanout remoteFanout, reference string, action machine.Action, requireYes bool, yes bool) error {
	selector, err := parseMachineSelector(reference, config.adminConfig.Project)
	if err != nil {
		return err
	}
	// Fail before doing any lookup work when the run cannot possibly be
	// confirmed — the pre-existing guard, kept ahead of the resolution so a
	// non-interactive `sc delete` still errors the way it always did.
	if requireYes && !yes && !isTerminalInput(config) {
		return fmt.Errorf("refusing to delete machine without --yes")
	}
	targets, err := lifecycleTargets(ctx, config, fanout, selector)
	if err != nil {
		return err
	}
	if requireYes && !yes {
		prompt := "Delete machine " + matchTargets(config, targets)[0] + "?"
		if len(targets) > 1 {
			prompt = fmt.Sprintf("Delete %d machines (%s)?", len(targets), strings.Join(matchTargets(config, targets), ", "))
		}
		confirmed, err := confirmMissingYes(config, prompt, "refusing to delete machine without --yes")
		if err != nil {
			return err
		}
		if !confirmed {
			return fmt.Errorf("delete canceled")
		}
	}
	results, err := runMachineAction(ctx, config, fanout, selector, targets, action)
	if err != nil {
		return err
	}

	// One machine named literally keeps the original scalar payload and
	// one-line text; a wildcard reports the whole set.
	if !selector.HasPattern() {
		result := results[0]
		if result.Error != "" {
			return fmt.Errorf("%s", result.Error)
		}
		path := machinePath(config.adminConfig.Remote, targets[0].Summary.Tenant, result.Project, result.Machine)
		payload := struct {
			Action  string `json:"action"`
			Path    string `json:"path"`
			Tenant  string `json:"tenant"`
			Project string `json:"project"`
			Machine string `json:"machine"`
		}{string(action), path, targets[0].Summary.Tenant, result.Project, result.Machine}
		return writeOutput(config.stdout, opts.output, fmt.Sprintf("%s %s", action, path), payload)
	}
	payload := machineActionPayload{
		Action:   string(action),
		Tenant:   targets[0].Summary.Tenant,
		Selector: selector.String(),
		Results:  results,
	}
	if err := writeOutput(config.stdout, opts.output, formatMachineActionResults(action, results), payload); err != nil {
		return err
	}
	return machineActionError(action, results)
}

// lifecycleTargets resolves the selector to the machines to act on. A literal
// reference keeps the established single-machine resolution — including the
// bare-name search across projects and the "which one did you mean?" prompt —
// so wildcards are strictly additive.
func lifecycleTargets(ctx context.Context, config commandConfig, fanout remoteFanout, selector machineSelector) ([]machineMatch, error) {
	if !selector.HasPattern() {
		summary, err := requireV2Tenant(ctx, config)
		if err != nil {
			return nil, err
		}
		project, machineName, err := resolveV2MachineTarget(ctx, config, summary, selector.Reference)
		if err != nil {
			return nil, err
		}
		return []machineMatch{{
			Summary: summary,
			Machine: meta.Machine{Tenant: summary.Tenant, Project: project, Name: machineName},
		}}, nil
	}
	matched, err := selectMachinesAcrossRemotes(ctx, config, fanout, selector)
	if err != nil {
		// A partial sweep is not what was asked for. Refuse rather than act on
		// the installs that happened to answer — especially for delete.
		return nil, err
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("no machines match %q", selector.Reference)
	}
	return matched, nil
}

// runMachineAction applies the action to every target. Targets are grouped by
// install and each install is entered in turn (only one can be bound at a
// time — see remote_scope.go); within an install the machines go concurrently.
func runMachineAction(ctx context.Context, config commandConfig, fanout remoteFanout, selector machineSelector, targets []machineMatch, action machine.Action) ([]machineActionResult, error) {
	spansRemotes := selector.HasRemotePattern()
	byRemote := map[string][]machineMatch{}
	for _, target := range targets {
		byRemote[target.Remote] = append(byRemote[target.Remote], target)
	}
	results := []machineActionResult{}
	err := fanout.forEachRemoteScope(config, selector.remotePattern(), func(remote string, scoped commandConfig) error {
		// Targets record their install only for a cross-install selection; a
		// same-install one is keyed under "" (see selectMachinesAcrossRemotes).
		key := remote
		if !spansRemotes {
			key = ""
		}
		group := byRemote[key]
		if len(group) == 0 {
			return nil
		}
		machines := make([]meta.Machine, 0, len(group))
		for _, target := range group {
			machines = append(machines, target.Machine)
		}
		summary := group[0].Summary
		applied := applyMachineAction(ctx, machines, func(ctx context.Context, target meta.Machine) error {
			return scoped.tenantCreator.MachineLifecycleV2(ctx, summary.V2IncusProjectName(target.Project), target.Name, string(action))
		})
		for index := range applied {
			if spansRemotes {
				applied[index].Remote = remote
			}
			applied[index].Path = machinePath(remote, summary.Tenant, applied[index].Project, applied[index].Machine)
		}
		results = append(results, applied...)
		return nil
	})
	return results, err
}

// applyMachineAction runs run against every target. The calls go out
// concurrently — each is an independent Incus operation and a stop or delete
// can take seconds, so a ten-machine wildcard should not cost ten times one —
// and the results stay in target order regardless of completion order. One
// machine's failure does not cancel the others: the report says which ones
// worked.
func applyMachineAction(ctx context.Context, targets []meta.Machine, run func(context.Context, meta.Machine) error) []machineActionResult {
	results := make([]machineActionResult, len(targets))
	var group sync.WaitGroup
	for index, target := range targets {
		results[index] = machineActionResult{Project: target.Project, Machine: target.Name}
		group.Add(1)
		go func() {
			defer group.Done()
			if err := run(ctx, target); err != nil {
				results[index].Error = err.Error()
			}
		}()
	}
	group.Wait()
	return results
}

func formatMachineActionResults(action machine.Action, results []machineActionResult) string {
	lines := make([]string, 0, len(results))
	for _, result := range results {
		if result.Error != "" {
			lines = append(lines, fmt.Sprintf("%s %s failed: %s", action, result.target(), result.Error))
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s", action, result.target()))
	}
	return strings.Join(lines, "\n")
}

// machineActionError summarises a partial failure. The per-machine failures are
// already in the output, so this only has to make the exit status non-zero and
// say how many machines are affected.
func machineActionError(action machine.Action, results []machineActionResult) error {
	failed := 0
	for _, result := range results {
		if result.Error != "" {
			failed++
		}
	}
	if failed == 0 {
		return nil
	}
	return fmt.Errorf("%s failed on %d of %d machines", action, failed, len(results))
}

func machineLifecycleShort(action machine.Action) string {
	switch action {
	case machine.ActionStart:
		return "Start a Sandcastle machine"
	case machine.ActionStop:
		return "Stop a Sandcastle machine"
	case machine.ActionRestart:
		return "Restart a Sandcastle machine"
	case machine.ActionDelete:
		return "Delete a Sandcastle machine"
	default:
		return string(action) + " a Sandcastle machine"
	}
}

func planMachineLifecycle(ctx context.Context, config commandConfig, opts *rootOptions, reference string, action machine.Action) error {
	selector, err := parseMachineSelector(reference, config.adminConfig.Project)
	if err != nil {
		return err
	}
	targets, err := lifecycleTargets(ctx, config, defaultRemoteFanout(), selector)
	if err != nil {
		return err
	}
	type entry struct {
		Path                string `json:"path"`
		Project             string `json:"project"`
		Machine             string `json:"machine"`
		CertificateDecision string `json:"certificateDecision"`
	}
	var entries []entry
	var out strings.Builder
	for _, target := range targets {
		decision := "per-name certificates retained; no new order"
		if p, ok := findProject(target.Summary, target.Machine.Project); ok && p.Domain != "" {
			decision = "project certificate retained; no machine certificate order"
		}
		if action == machine.ActionDelete {
			decision += "; remove machine A records"
		}
		remote := target.Remote
		if remote == "" {
			remote = strings.TrimSpace(config.adminConfig.Remote)
		}
		path := machinePath(remote, target.Summary.Tenant, target.Machine.Project, target.Machine.Name)
		entries = append(entries, entry{path, target.Machine.Project, target.Machine.Name, decision})
		fmt.Fprintf(&out, "[dry-run] %s %s — %s\n", action, path, decision)
	}
	return writeOutput(config.stdout, opts.output, strings.TrimSpace(out.String()), struct {
		DryRun   bool           `json:"dryRun"`
		Action   machine.Action `json:"action"`
		Machines []entry        `json:"machines"`
	}{true, action, entries})
}
