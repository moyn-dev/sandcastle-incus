package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	scconfig "github.com/moyn-dev/sandcastle-incus/internal/config"
	"github.com/moyn-dev/sandcastle-incus/internal/naming"
)

// positionOutput is what `sc cd` and `sc pwd` report: the Current Position
// as a Sandcastle Path plus its parts. Remote is the Incus remote the
// position resolves to, not a path segment.
type positionOutput struct {
	Path       string `json:"path"`
	Level      string `json:"level"`
	Install    string `json:"install,omitempty"`
	Remote     string `json:"remote,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	Project    string `json:"project,omitempty"`
	Previous   string `json:"previous,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
}

func positionFromSegments(segments []string, remote string) positionOutput {
	out := positionOutput{Path: formatPath(segments), Level: levelName(len(segments))}
	if len(segments) > levelRoot {
		out.Install = segments[0]
		out.Remote = strings.TrimSpace(remote)
	}
	if len(segments) > levelInstall {
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
		Short: "Print the Current Position as a Sandcastle Path (/install/tenant/project)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := positionFromSegments(currentPosition(config), config.adminConfig.Remote)
			out.ConfigPath = config.adminConfig.DirectoryConfigPath
			if local, _, err := scconfig.LoadDirectoryConfig(""); err == nil {
				out.Previous = strings.TrimSpace(local.Previous)
			}
			return writeOutput(config.stdout, opts.output, out.Path, out)
		},
	}
}

// newCdCommand moves the Current Position: `sc cd /install/tenant/project`,
// `sc cd ..`, `sc cd -`, `sc cd` (home). It is the path-shaped front of the
// three switch commands and writes the same .sandcastle.yml they do.
func newCdCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var localOnly bool
	command := &cobra.Command{
		Use:   "cd [path]",
		Short: "Change the Current Position (install, tenant, project) by Sandcastle Path",
		Long: `Change the Current Position, the install/tenant/project every unqualified
command acts in, by Sandcastle Path:

  sc cd /obelix/acme/web     absolute: install obelix, tenant acme, project web
  sc cd backend              from a project: the sibling project backend
  sc cd ../backend           the same, spelled out
  sc cd ..                   up to the tenant level (sc ls then lists projects)
  sc cd -                    back to the previous position
  sc cd                      home: the global config's install, tenant and project
  sc cd ~/web                project web under the home install and tenant

The install is the first label of its Auth Hostname (obelix for
https://obelix.example.com). Like a shell cd, the target must exist: the
install must be enrolled, the tenant listed by its Auth App and the project
present in the tenant. A tenant with no Incus remote on this client yet is
enrolled the way sc tenant switch enrols it. --local-only records the position
without those lookups. A machine is a leaf: use sc connect to enter one. The
position is saved in the nearest .sandcastle.yml, the file the switch commands
write, so it is per directory tree, not per terminal. A path that starts with
a remote name instead of an install (/moyn-dev-miraculix/moyn-dev) still works
and prints its install form.`,
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
	command.Flags().BoolVar(&localOnly, "local-only", false, "record the position without checking the install, tenant or project exist")
	return command
}

// runCd resolves the target and applies the switches it implies, in tree
// order: the remote serving the install and tenant (enrolling one when the
// tenant has none yet), then the tenant, then the project. Each switch
// writes .sandcastle.yml and the global config exactly as its command does; the
// config is reloaded between them so the next step sees the new state. The
// level and the previous position are recorded last.
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
	previous := formatPath(currentPosition(config))
	notes := config.stderr
	if notes == nil {
		notes = io.Discard
	}

	current := config
	if len(target) > levelRoot {
		ix := loadInstallIndex()
		remote, enrol := ix.anchorRemote(config, target[0]), false
		if len(target) > levelInstall {
			resolved, err := ix.positionRemote(config, target[0], target[1])
			var missing errTenantNotEnrolled
			switch {
			case errors.As(err, &missing):
				enrol = true
			case err != nil:
				return positionOutput{}, err
			default:
				remote = resolved
			}
		} else if _, known := ix.install(target[0]); !known && remote == "" {
			if remote, err = ix.positionRemote(config, target[0], ""); err != nil {
				return positionOutput{}, err
			}
		}
		if enrol && !localOnly {
			if err := requireInstallListsTenant(ctx, config, ix, target[0], target[1]); err != nil {
				return positionOutput{}, err
			}
		}
		if remote == "" {
			return positionOutput{}, fmt.Errorf("install %s has no enrolled remote on this client: run sc login %s", target[0], firstNonEmptyString(installHost(ix, target[0]), "<auth-hostname>"))
		}
		if remote != strings.TrimSpace(current.adminConfig.Remote) {
			if _, _, _, err := switchRemoteSelection(current, remote); err != nil {
				return positionOutput{}, err
			}
			if current, err = reloadCommandConfig(current); err != nil {
				return positionOutput{}, err
			}
		}
		switch {
		case enrol:
			if _, err := runTenantSwitch(ctx, current, target[1], localOnly, notes); err != nil {
				return positionOutput{}, err
			}
			if current, err = reloadCommandConfig(current); err != nil {
				return positionOutput{}, err
			}
		case len(target) > levelInstall && target[1] != strings.TrimSpace(current.adminConfig.Tenant):
			local, err := directorySelection(current)
			if err != nil {
				return positionOutput{}, err
			}
			local.Tenant = target[1]
			if _, err := scconfig.SaveDirectoryConfig(local); err != nil {
				return positionOutput{}, fmt.Errorf("save selection: %w", err)
			}
			if current, err = reloadCommandConfig(current); err != nil {
				return positionOutput{}, err
			}
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
	if len(target) > levelInstall {
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
	out := positionFromSegments(target, local.Remote)
	out.Previous = previous
	out.ConfigPath = path
	return out, nil
}

// requireInstallListsTenant refuses to enrol a tenant the install's Auth App
// does not list, naming the install, before any remote is switched.
func requireInstallListsTenant(ctx context.Context, config commandConfig, ix installIndex, install, tenantName string) error {
	tenants, err := installTenants(ctx, config, ix, install)
	if err != nil {
		return fmt.Errorf("install %s: list tenants: %w", install, err)
	}
	names := make([]string, 0, len(tenants))
	for _, candidate := range tenants {
		if candidate.Tenant == tenantName {
			return nil
		}
		names = append(names, candidate.Tenant)
	}
	sort.Strings(names)
	return fmt.Errorf("install %s does not list tenant %q (tenants: %s)", install, tenantName, strings.Join(names, ", "))
}

func installHost(ix installIndex, install string) string {
	record, _ := ix.install(install)
	return record.AuthHost
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
	if config.tenantRemote != nil {
		rebuilt.tenantRemote = config.tenantRemote
	}
	return rebuilt, nil
}
