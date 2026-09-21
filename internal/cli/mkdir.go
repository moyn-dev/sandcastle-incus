package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// newMkdirCommand creates a project or a machine by Sandcastle Path.
func newMkdirCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var parents, vm bool
	var image string
	command := &cobra.Command{
		Use:   "mkdir [-p] path",
		Short: "Create a project (/remote/tenant/project) or a machine (…/project/machine) by Sandcastle Path",
		Long: `Create by Sandcastle Path: a three-segment path (or a relative path that
resolves to one) creates a project, as sc project create does; a
four-segment path creates a machine, as sc create does.

  sc mkdir web            from a tenant: project web; from a project: machine web
  sc mkdir ../api         sibling project api
  sc mkdir -p ../api/dev  project api, then machine dev in it

Remotes and tenants are not created here: enroll installs with sc login and
sc enroll, and tenants with sc-adm create tenant.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: pathCompletion(config, levelMachine),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMkdir(cmd.Context(), config, opts, args[0], mkdirOptions{Parents: parents, Image: image, VM: vm})
		},
	}
	command.Flags().BoolVarP(&parents, "parents", "p", false, "create the project first when a machine's project does not exist")
	command.Flags().StringVar(&image, "image", "", "image to launch a machine from (default "+v2DefaultMachineImage+")")
	command.Flags().BoolVar(&vm, "vm", false, "launch a virtual machine instead of a container")
	return command
}

type mkdirOptions struct {
	Parents bool
	Image   string
	VM      bool
}

func runMkdir(ctx context.Context, config commandConfig, opts *rootOptions, arg string, options mkdirOptions) error {
	if !isPathReference(arg) {
		arg = "./" + arg
	}
	segments, err := resolvePath(config, arg)
	if err != nil {
		return err
	}
	for depth, segment := range segments {
		if naming.IsPattern(segment) {
			return fmt.Errorf("mkdir needs one %s, not the pattern %q", levelName(depth+1), segment)
		}
	}
	if len(segments) < levelProject {
		return fmt.Errorf("%s is a %s: mkdir creates projects and machines; enroll remotes with sc login or sc enroll, create tenants with sc-adm create tenant", formatPath(segments), levelName(len(segments)))
	}
	remote, tenantName, project := segments[0], segments[1], segments[2]
	bound, restore, err := configForPosition(config, remote, tenantName)
	if err != nil {
		return err
	}
	defer restore()
	if served := tenantOfRemote(config, remote); served != "" && served != tenantName {
		return fmt.Errorf("remote %q serves tenant %q, not %q: `sc cd /%s/%s` first", remote, served, tenantName, remote, tenantName)
	}
	if len(segments) == levelProject {
		return createProjectViaPath(ctx, bound, opts, project)
	}
	summary, err := requireV2Tenant(ctx, bound)
	if err != nil {
		return err
	}
	if _, ok := findProject(summary, project); !ok {
		if !options.Parents {
			return fmt.Errorf("project %s does not exist in tenant %s: create it with `sc mkdir %s` or pass -p", project, summary.Tenant, formatPath(segments[:levelProject]))
		}
		if err := createProjectViaPath(ctx, bound, opts, project); err != nil {
			return err
		}
		// The project list is served from the Auth App cache, which learns
		// about the new project from its own event; read the summary again
		// so the create below finds the project.
		if summary, err = requireV2Tenant(ctx, bound); err != nil {
			return err
		}
	}
	return runCreateMachineV2(ctx, bound, opts, summary, project+":"+segments[3], createV2Options{Image: options.Image, VM: options.VM})
}

// createProjectViaPath creates a project through the Auth App's tenant
// plane, the path every logged-in CLI has; the broker and client-certificate
// paths stay with `sc project create`, which keeps their flags.
func createProjectViaPath(ctx context.Context, config commandConfig, opts *rootOptions, project string) error {
	if err := naming.ValidateNewProjectName(project); err != nil {
		return err
	}
	if !projectAuthAppAvailable(config, "") {
		return fmt.Errorf("creating a project by path needs an Auth App login on remote %q (run sc login), or use `sc project create %s` with --broker", strings.TrimSpace(config.adminConfig.Remote), project)
	}
	return runProjectCreateViaAuthApp(ctx, config, opts, authapp.ProjectCreateRequest{Project: project}, false, "", "", "")
}

// requireProjectPosition refuses a creating command that would fall back to
// the default project because the Current Position stands above a project:
// silence would create somewhere the user is not looking. A reference that
// names its project is fine anywhere.
func requireProjectPosition(config commandConfig, reference string, verb string) error {
	if v2ReferenceHasProject(reference) {
		return nil
	}
	if scconfig.PositionDepth(config.adminConfig.PositionLevel) >= levelProject || config.adminConfig.PositionLevel == "" {
		return nil
	}
	return fmt.Errorf("not in a project (position %s): `sc cd` into one, or name it as project:%s", formatPath(currentPosition(config)), reference)
}
