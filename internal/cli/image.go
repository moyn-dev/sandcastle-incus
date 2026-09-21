package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// newImageCommand builds `sc image` — save a running machine as a reusable base
// image, list saved bases, and remove them. v2 (freeform) tenants only; the
// saved alias is consumed by `sc create <name> --image <base>`.
func newImageCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:     "image",
		Aliases: []string{"img"},
		Short:   "Save and manage reusable base images from your machines",
	}
	command.AddCommand(newImageSaveCommand(config, opts))
	command.AddCommand(newImageListCommand(config, opts))
	command.AddCommand(newImageRemoveCommand(config, opts))
	return command
}

func newImageSaveCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "save [[remote:]project:]machine name",
		Short: "Snapshot a running machine into a reusable base image",
		Long: "Snapshot a running machine and publish it as a reusable local base image.\n" +
			"The machine keeps running; the shared /home and /workspace volumes are not\n" +
			"included (only the installed-software rootfs). Launch from it with:\n" +
			"  sc create <new-machine> --image <name>",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := narrowRemoteGlob(cmd.Context(), config, defaultRemoteFanout(), args[0])
			if err != nil {
				return err
			}
			config, reference, restore, err := rebindForReference(config, ref)
			if err != nil {
				return err
			}
			defer restore()
			summary, err := requireV2Tenant(cmd.Context(), config)
			if err != nil {
				return err
			}
			reference, err = resolveSingleMachineReference(cmd.Context(), config, summary, reference)
			if err != nil {
				return err
			}
			project, machine, err := resolveV2MachineReference(summary, reference, config.adminConfig.Project)
			if err != nil {
				return err
			}
			name := strings.TrimSpace(args[1])
			if err := validateImageName(name); err != nil {
				return err
			}
			saved, err := config.tenantCreator.SaveMachineImageV2(cmd.Context(), summary.V2IncusProjectName(project), machine, name)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatSavedImage(saved), saved)
		},
	}
	return command
}

func newImageListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var project string
	command := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List saved base images",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			summary, err := requireV2Tenant(cmd.Context(), config)
			if err != nil {
				return err
			}
			incusProject, err := resolveV2ProjectFlag(summary, config, project)
			if err != nil {
				return err
			}
			images, err := config.tenantCreator.ListImagesV2(incusProject)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatSavedImageList(images), images)
		},
	}
	command.Flags().StringVar(&project, "project", "", "project to list images from (default "+naming.DefaultProjectName+")")
	return command
}

func newImageRemoveCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var project string
	command := &cobra.Command{
		Use:     "rm name",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove a saved base image",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			summary, err := requireV2Tenant(cmd.Context(), config)
			if err != nil {
				return err
			}
			incusProject, err := resolveV2ProjectFlag(summary, config, project)
			if err != nil {
				return err
			}
			name := strings.TrimSpace(args[0])
			if err := config.tenantCreator.DeleteImageV2(incusProject, name); err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, "Removed image "+name, map[string]string{"removed": name})
		},
	}
	command.Flags().StringVar(&project, "project", "", "project to remove the image from (default "+naming.DefaultProjectName+")")
	return command
}

// resolveV2ProjectFlag turns a --project flag (or the config default) into the
// tenant's Incus app-project name, validating it exists in the tenant.
func resolveV2ProjectFlag(summary tenant.Summary, config commandConfig, projectFlag string) (string, error) {
	project := strings.TrimSpace(projectFlag)
	if project == "" {
		project = strings.TrimSpace(config.adminConfig.Project)
	}
	if project == "" {
		project = naming.DefaultProjectName
	}
	if _, ok := findProject(summary, project); !ok {
		return "", fmt.Errorf("project %q not found in tenant %s", project, summary.Tenant)
	}
	return summary.V2IncusProjectName(project), nil
}

// validateImageName keeps saved base names simple and Incus-alias-safe.
func validateImageName(name string) error {
	if name == "" {
		return fmt.Errorf("image name is required")
	}
	if strings.ContainsAny(name, " /:\t") {
		return fmt.Errorf("image name %q may not contain spaces, '/' or ':'", name)
	}
	return nil
}

func formatSavedImage(image incusx.SavedImage) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Saved image: %s\n", image.Name)
	if image.Source != "" {
		fmt.Fprintf(&b, "From machine: %s\n", image.Source)
	}
	if image.Fingerprint != "" {
		fmt.Fprintf(&b, "Fingerprint: %s\n", shortFingerprint(image.Fingerprint))
	}
	if image.Size > 0 {
		fmt.Fprintf(&b, "Size: %s\n", humanBytes(image.Size))
	}
	fmt.Fprintf(&b, "Launch a machine from it with: sc create <machine> --image %s", image.Name)
	return b.String()
}

func formatSavedImageList(images []incusx.SavedImage) string {
	if len(images) == 0 {
		return "No saved images. Create one with: sc image save <machine> <name>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-20s %-14s %-10s %-12s %s\n", "NAME", "FINGERPRINT", "SIZE", "SOURCE", "CREATED")
	for _, image := range images {
		created := ""
		if !image.CreatedAt.IsZero() {
			created = image.CreatedAt.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(&b, "%-20s %-14s %-10s %-12s %s\n",
			image.Name, shortFingerprint(image.Fingerprint), humanBytes(image.Size), image.Source, created)
	}
	return strings.TrimRight(b.String(), "\n")
}

func shortFingerprint(fingerprint string) string {
	if len(fingerprint) > 12 {
		return fingerprint[:12]
	}
	return fingerprint
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "-"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}
