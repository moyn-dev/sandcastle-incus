package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// positionOutput is what `sc cd` and `sc pwd` report: the Current Position
// as a Sandcastle Path plus its parts.
type positionOutput struct {
	Path       string `json:"path"`
	Level      string `json:"level"`
	Remote     string `json:"remote,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	Project    string `json:"project,omitempty"`
	Previous   string `json:"previous,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
}

func positionFromSegments(segments []string) positionOutput {
	out := positionOutput{Path: formatPath(segments), Level: levelName(len(segments))}
	if len(segments) > levelRoot {
		out.Remote = segments[0]
	}
	if len(segments) > levelRemote {
		out.Tenant = segments[1]
	}
	if len(segments) > levelTenant {
		out.Project = segments[2]
	}
	return out
}

// newPwdCommand prints the Current Position.
func newPwdCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "pwd",
		Short: "Print the Current Position as a Sandcastle Path (/remote/tenant/project)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := positionFromSegments(currentPosition(config))
			out.ConfigPath = config.adminConfig.DirectoryConfigPath
			if local, _, err := scconfig.LoadDirectoryConfig(""); err == nil {
				out.Previous = strings.TrimSpace(local.Previous)
			}
			return writeOutput(config.stdout, opts.output, out.Path, out)
		},
	}
}

// newCdCommand moves the Current Position: `sc cd /remote/tenant/project`,
// `sc cd ..`, `sc cd -`, `sc cd` (home). It is the path-shaped front of the
// three switch commands and writes the same .sandcastle they do.
func newCdCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var localOnly bool
	command := &cobra.Command{
		Use:   "cd [path]",
		Short: "Change the Current Position (remote, tenant, project) by Sandcastle Path",
		Long: `Change the Current Position, the remote/tenant/project every unqualified
command acts in, by Sandcastle Path:

  sc cd /obelix/acme/web     absolute: remote obelix, tenant acme, project web
  sc cd backend              from a project: the sibling project backend
  sc cd ../backend           the same, spelled out
  sc cd ..                   up to the tenant level (sc ls then lists projects)
  sc cd -                    back to the previous position
  sc cd                      home: the global config's remote, tenant and project
  sc cd ~/web                project web under the home remote and tenant

Like a shell cd, the target must exist: the remote must be enrolled, the tenant
accessible (a Shared Tenant is entered through the Auth App, as sc tenant
switch does) and the project present in the tenant. --local-only records the
position without those lookups. A machine is a leaf: use sc connect to enter
one. The position is saved in the nearest .sandcastle, the file the switch
commands write, so it is per directory tree, not per terminal.`,
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: pathCompletion(config, levelProject),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg := "~"
			if len(args) == 1 {
				arg = args[0]
			}
			out, err := runCd(cmd.Context(), config, arg, localOnly)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, out.Path, out)
		},
	}
	command.Flags().BoolVar(&localOnly, "local-only", false, "record the position without checking the remote, tenant or project exist")
	return command
}

// runCd resolves the target and applies the switches it implies, in tree
// order: remote, then tenant, then project. Each switch writes .sandcastle
// and the global config exactly as its command does; the config is reloaded
// between them so the next step sees the new state. The level and the
// previous position are recorded last.
func runCd(ctx context.Context, config commandConfig, arg string, localOnly bool) (positionOutput, error) {
	if !isPathReference(arg) {
		// A bare name is relative: `sc cd web` from a tenant is the project
		// web. From a project, whose children are machines (leaves a cd can
		// never enter), it is the sibling project web — the only reading
		// that can succeed, and the one a user switching projects means.
		if !strings.Contains(arg, "/") && len(currentPosition(config)) == levelProject {
			arg = "../" + arg
		} else {
			arg = "./" + arg
		}
	}
	target, err := resolvePath(config, arg)
	if err != nil {
		return positionOutput{}, err
	}
	for depth, segment := range target {
		if naming.IsPattern(segment) {
			return positionOutput{}, fmt.Errorf("cd needs one %s, not the pattern %q", levelName(depth+1), segment)
		}
	}
	if len(target) == levelMachine {
		return positionOutput{}, fmt.Errorf("%s is a machine: a machine is a leaf, use `sc connect %s`", formatPath(target), formatPath(target))
	}
	before := currentPosition(config)
	previous := formatPath(before)
	notes := config.stderr
	if notes == nil {
		notes = io.Discard
	}

	current := config
	if len(target) > levelRoot && target[0] != strings.TrimSpace(current.adminConfig.Remote) {
		if _, _, _, err := switchRemoteSelection(current, target[0]); err != nil {
			return positionOutput{}, err
		}
		if current, err = reloadCommandConfig(current); err != nil {
			return positionOutput{}, err
		}
	}
	if len(target) > levelRemote && target[1] != strings.TrimSpace(current.adminConfig.Tenant) {
		if _, err := runTenantSwitch(ctx, current, target[1], localOnly, notes); err != nil {
			return positionOutput{}, err
		}
		if current, err = reloadCommandConfig(current); err != nil {
			return positionOutput{}, err
		}
	}
	if len(target) > levelTenant && target[2] != strings.TrimSpace(current.adminConfig.Project) {
		if _, err := switchProjectSelection(ctx, current, target[2], localOnly); err != nil {
			return positionOutput{}, err
		}
	}

	// The level and the previous position live beside the selection the
	// switches wrote; above the project level the project field keeps the
	// remembered project so a later `cd` back down (or an old binary) still
	// finds one.
	local, err := directorySelection(current)
	if err != nil {
		return positionOutput{}, err
	}
	if len(target) > levelRoot {
		local.Remote = target[0]
	}
	if len(target) > levelRemote {
		local.Tenant = target[1]
	}
	if len(target) > levelTenant {
		local.Project = target[2]
		local.RemoteProjects[local.Remote] = local.Project
	} else if remembered := local.RemoteProjects[local.Remote]; remembered != "" {
		local.Project = remembered
	}
	if local.Project == "" {
		local.Project = naming.DefaultProjectName
	}
	local.Level = ""
	if len(target) < levelProject {
		local.Level = levelKeyword(len(target))
	}
	local.Previous = previous
	path, err := scconfig.SaveDirectoryConfig(local)
	if err != nil {
		return positionOutput{}, fmt.Errorf("save selection: %w", err)
	}
	out := positionFromSegments(target)
	out.Previous = previous
	out.ConfigPath = path
	return out, nil
}

// reloadCommandConfig rebuilds the command config from the files a switch
// just wrote, the way the next `sc` invocation would see them.
func reloadCommandConfig(config commandConfig) (commandConfig, error) {
	admin, err := scconfig.LoadUserWithError()
	if err != nil {
		return config, err
	}
	rebuilt := newUserCommandConfig(config.name, config.stdin, config.stdout, config.stderr, admin)
	// Injected clients (tests, or a caller that already holds one) carry over.
	if config.authTenants != nil {
		rebuilt.authTenants = config.authTenants
	}
	if config.authResources != nil {
		rebuilt.authResources = config.authResources
	}
	return rebuilt, nil
}
