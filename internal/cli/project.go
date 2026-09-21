package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thieso2/sandcastle-incus/internal/authapp"
	scconfig "github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

func newProjectCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "project",
		Short: "Manage lightweight projects in the current tenant",
	}
	command.AddCommand(newProjectListCommand(config, opts))
	command.AddCommand(newProjectSwitchCommand(config, opts))
	command.AddCommand(newProjectCreateV2Command(config, opts))
	command.AddCommand(newProjectStatusCommand(config, opts))
	command.AddCommand(newProjectSetDomainCommand(config, opts))
	command.AddCommand(newProjectUnsetDomainCommand(config, opts))
	command.AddCommand(newProjectSetCloudIdentityCommand(config, opts))
	command.AddCommand(newProjectUnsetCloudIdentityCommand(config, opts))
	command.AddCommand(newProjectSetDockerAutostartCommand(config, opts))
	command.AddCommand(newProjectDeleteCommand(config, opts))
	return command
}

func newProjectListCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List projects in the current tenant",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tenantSummary, err := currentTenantSummary(cmd.Context(), config)
			if err != nil {
				return err
			}
			payload := struct {
				tenant.Summary
				ConfigPath string `json:"config_path"`
			}{tenantSummary, config.adminConfig.DirectoryConfigPath}
			return writeOutput(config.stdout, opts.output, selectionSource(config)+"\n"+formatProjectNamespaceList(tenantSummary, currentProjectName(config, tenantSummary)), payload)
		},
	}
}

type projectSwitchOutput struct {
	Project    string `json:"project"`
	LocalOnly  bool   `json:"local_only,omitempty"`
	ConfigPath string `json:"config_path"`
}

// newProjectSwitchCommand validates and saves the nearest directory selection.
func newProjectSwitchCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var localOnly bool
	command := &cobra.Command{
		Use:   "switch name",
		Short: "Select the local current project in the current tenant",
		Long:  "Select the project in the nearest .sandcastle (create in the current directory if absent). By default this checks the project exists in the current tenant; use --local-only to skip the lookup. Global Sandcastle and Incus defaults are unchanged.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if name == "" {
				return fmt.Errorf("project is required")
			}
			if err := naming.ValidateProjectName(name); err != nil {
				return err
			}
			if !localOnly {
				summary, err := currentTenantSummary(cmd.Context(), config)
				if err != nil {
					return err
				}
				if _, ok := findProject(summary, name); !ok {
					names := make([]string, 0, len(summary.Projects))
					for _, p := range summary.Projects {
						names = append(names, p.Name)
					}
					return fmt.Errorf("project %s not found in tenant %s (projects: %s); use --local-only to set it anyway", name, summary.Tenant, strings.Join(names, ", "))
				}
			}
			local, err := directorySelection(config)
			if err != nil {
				return err
			}
			local.Project = name
			local.RemoteProjects[local.Remote] = name
			cfgPath, err := scconfig.SaveDirectoryConfig(local)
			if err != nil {
				return fmt.Errorf("save selection: %w", err)
			}

			result := projectSwitchOutput{
				Project:    name,
				LocalOnly:  localOnly,
				ConfigPath: cfgPath,
			}
			return writeOutput(config.stdout, opts.output, formatProjectSwitch(result), result)
		},
	}
	command.Flags().BoolVar(&localOnly, "local-only", false, "update the local current project without checking it exists in the tenant")
	return command
}

func formatProjectSwitch(out projectSwitchOutput) string {
	msg := fmt.Sprintf("Switched to project %q (saved in %s).", out.Project, out.ConfigPath)
	return msg
}

// infraFromPinnedProject recovers the `<prefix>-<tenant>` stem from a pinned
// incus project `<prefix>-<tenant>[-<project>]`, or "" when it doesn't match.
func infraFromPinnedProject(pin, tenant string) string {
	pin = strings.TrimSpace(pin)
	tenant = strings.TrimSpace(tenant)
	if pin == "" || tenant == "" {
		return ""
	}
	marker := "-" + tenant
	if idx := strings.Index(pin, marker+"-"); idx >= 0 {
		return pin[:idx+len(marker)]
	}
	if strings.HasSuffix(pin, marker) {
		return pin
	}
	return ""
}

// currentProjectName resolves the project to mark as current in listings: the
// configured project, else the tenant's default project.
func currentProjectName(config commandConfig, summary tenant.Summary) string {
	if current := strings.TrimSpace(config.adminConfig.Project); current != "" {
		return current
	}
	return strings.TrimSpace(summary.DefaultProject)
}

type projectStatusPayload struct {
	CertState    string         `json:"certState,omitempty"`
	CertNotAfter string         `json:"certNotAfter,omitempty"`
	SANs         []string       `json:"sans,omitempty"`
	Tenant       tenant.Summary `json:"tenant"`
	Project      meta.Project   `json:"project"`
	MachineCount int            `json:"machineCount"`
	// Domain and Zone are the project's Project Domain and the Public DNS
	// Zone it is claimed under (ADR-0027); Zone is read from the Auth App and
	// stays empty when the CLI has no login.
	Domain string `json:"domain,omitempty"`
	Zone   string `json:"zone,omitempty"`
	// Machines is the public-name table: one row per (machine, Machine
	// Public Hostname) — shown when the project has a Project Domain or any
	// of its machines carries an explicit hostname (ADR-0028).
	Machines []projectMachineStatus `json:"machines,omitempty"`
}

// projectMachineStatus is one row of `sc project status`'s table: one
// Machine Public Hostname of one machine with the state mirrored for it. A
// machine without a public name has one row with an empty PublicHostname.
type projectMachineStatus struct {
	Machine        string `json:"machine"`
	PublicHostname string `json:"publicHostname,omitempty"`
	CertState      string `json:"certState,omitempty"`
	// CertNotAfter is the machine's EARLIEST installed expiry (the mirror
	// carries one value per machine), shown on its installed/renewing rows.
	CertNotAfter string `json:"certNotAfter,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

func newProjectStatusCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "status [name]",
		Short: "Show project status in the current tenant",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				project := strings.TrimSpace(config.adminConfig.Project)
				if project == "" {
					summary, err := currentTenantSummary(cmd.Context(), config)
					if err != nil {
						return err
					}
					project = summary.DefaultProject
				}
				args = append([]string{project}, args...)
			}
			if err := naming.ValidateProjectName(args[0]); err != nil {
				return err
			}
			tenantSummary, machines, err := currentTenantMachines(cmd, config)
			if err != nil {
				return err
			}
			project, ok := findProject(tenantSummary, args[0])
			if !ok {
				return fmt.Errorf("Sandcastle project %s not found in tenant %s", args[0], tenantSummary.Tenant)
			}
			payload := projectStatusPayload{
				Tenant:  tenantSummary,
				Project: project,
				Domain:  project.Domain,
			}
			showTable := project.Domain != ""
			var projectMachines []meta.Machine
			for _, machine := range machines {
				if machine.Project != project.Name {
					continue
				}
				payload.MachineCount++
				projectMachines = append(projectMachines, machine)
				if machine.HasPublicHostname() {
					showTable = true
				}
			}
			if showTable {
				for _, machine := range projectMachines {
					payload.Machines = append(payload.Machines, projectMachineStatusOf(machine)...)
				}
			}
			if project.Domain != "" && projectAuthAppAvailable(config, "") {
				// The zone lives on the claim row, not on Incus: best-effort,
				// the status still renders without it.
				if claim, err := projectAuthClient(config).GetProjectDomain(cmd.Context(), project.Name); err == nil {
					payload.Zone = claim.Zone
					payload.CertState, payload.CertNotAfter, payload.SANs = claim.CertState, claim.CertNotAfter, claim.SANs
				}
			}
			return writeOutput(config.stdout, opts.output, formatProjectNamespaceStatus(payload), payload)
		},
	}
}

// projectMachineStatusOf renders one machine for the status table: one row
// per Machine Public Hostname with the state mirrored for that name (a
// failed certificate carries its reason); a machine without a public name
// is one row reading "private name only".
func projectMachineStatusOf(machine meta.Machine) []projectMachineStatus {
	names := machine.PublicNames()
	if len(names) == 0 {
		return []projectMachineStatus{{Machine: machine.Name, Detail: "private name only"}}
	}
	rows := make([]projectMachineStatus, 0, len(names))
	for _, name := range names {
		row := projectMachineStatus{Machine: machine.Name, PublicHostname: name, CertState: machine.CertStateOf(name)}
		switch {
		case strings.HasPrefix(row.CertState, meta.CertStateFailedPrefix):
			row.Detail = strings.TrimPrefix(row.CertState, meta.CertStateFailedPrefix)
			row.CertState = "failed"
		case row.CertState == meta.CertStateInstalled || row.CertState == meta.CertStateRenewing:
			row.CertNotAfter = machine.CertNotAfter
		}
		rows = append(rows, row)
	}
	return rows
}

// projectDomainVerbsUnavailable is the broker-only refusal of set-domain and
// unset-domain — the same sentence as the create flag's, since the cause is
// the same: no Auth App login to claim through.
const projectDomainVerbsUnavailable = "--domain is not available on this install"

func newProjectSetDomainCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "set-domain [name] domain",
		Short: "Claim (or replace) the Project Domain of a project",
		Long: `Claim (or replace) the Project Domain of an existing project (ADR-0027/0028).
Every machine of the project gets the public name <machine>.<domain> beside its
Machine Private Hostname: existing machines are re-derived by the zone reconciler
(records, a new certificate, the hostnames file), a replaced domain's names and
certificates are released. Explicit hostnames are unaffected.`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				project := strings.TrimSpace(config.adminConfig.Project)
				if project == "" {
					summary, err := currentTenantSummary(cmd.Context(), config)
					if err != nil {
						return err
					}
					project = summary.DefaultProject
				}
				args = append([]string{project}, args...)
			}
			project := strings.TrimSpace(args[0])
			if err := naming.ValidateProjectName(project); err != nil {
				return err
			}
			domainValue, err := authapp.NormalizeProjectDomain(args[1])
			if err != nil {
				return err
			}
			if !projectAuthAppAvailable(config, "") {
				return fmt.Errorf("%s", projectDomainVerbsUnavailable)
			}
			result, err := projectAuthClient(config).SetProjectDomain(cmd.Context(), project, domainValue, dryRun)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatProjectDomainResult("set-domain", result), result)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "validate the claim (zone, conflicts) without changing anything")
	return command
}

func newProjectUnsetDomainCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "unset-domain [name]",
		Short: "Release the Project Domain of a project",
		Long: `Release a project's Project Domain (ADR-0027/0028). Every machine loses its
derived <machine>.<domain> name (records and certificates are released; the zone
reconciler pushes the shrunken hostnames file); explicit hostnames and the Machine
Private Hostname stay.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				project := strings.TrimSpace(config.adminConfig.Project)
				if project == "" {
					summary, err := currentTenantSummary(cmd.Context(), config)
					if err != nil {
						return err
					}
					project = summary.DefaultProject
				}
				args = append([]string{project}, args...)
			}
			project := strings.TrimSpace(args[0])
			if err := naming.ValidateProjectName(project); err != nil {
				return err
			}
			if !projectAuthAppAvailable(config, "") {
				return fmt.Errorf("%s", projectDomainVerbsUnavailable)
			}
			result, err := projectAuthClient(config).UnsetProjectDomain(cmd.Context(), project, dryRun)
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatProjectDomainResult("unset-domain", result), result)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "check the release (machines) without changing anything")
	return command
}

// formatProjectDomainResult renders the domain verbs' outcome. The
// same-project identical re-claim is a no-op with its own §2.2 text.
func formatProjectDomainResult(verb string, result authapp.ProjectDomainResult) string {
	var what string
	switch verb {
	case "set-domain":
		if result.AlreadyClaimed {
			return fmt.Sprintf("project domain %q already claimed by this project", result.Domain)
		}
		what = fmt.Sprintf("claimed project domain %s (zone %s) for project %s", result.Domain, result.Zone, result.Project)
	case "unset-domain":
		if result.Released == "" {
			what = fmt.Sprintf("project %s has no project domain to release", result.Project)
		} else {
			what = fmt.Sprintf("released project domain %s from project %s", result.Released, result.Project)
		}
	default:
		if result.Released != "" {
			what = fmt.Sprintf("deleted project %s and released project domain %s", result.Project, result.Released)
		} else {
			what = fmt.Sprintf("deleted project %s", result.Project)
		}
	}
	if verb == "set-domain" {
		what += " — one project certificate for " + result.Domain + ", *." + result.Domain
	}
	if verb == "unset-domain" && result.Released != "" {
		what += " — drop project certificate"
	}
	if result.DryRun {
		return "[dry-run] would have: " + what
	}
	return what
}

func newProjectDeleteCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var yes bool
	var dryRun bool
	command := &cobra.Command{
		Use:   "delete name",
		Short: "Delete an empty project namespace from the current tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes && !dryRun {
				confirmed, err := confirmMissingYes(config, "Delete project "+args[0]+"?", "refusing to delete project without --yes")
				if err != nil {
					return err
				}
				if !confirmed {
					return nil
				}
			}
			tenantSummary, machines, err := currentTenantMachines(cmd, config)
			if err != nil {
				return err
			}
			plan, err := tenant.PlanDeleteProject(cmd.Context(), config.adminConfig, config.tenantStore, tenant.ProjectMutationRequest{
				Name:     args[0],
				Machines: machines,
			})
			if err != nil {
				return err
			}
			plan.Tenant = tenantSummary
			if projectAuthAppAvailable(config, "") {
				// The tenant plane (ADR-0027 §3.2): DELETE /api/projects/<name>
				// releases the Project Domain claim, then deletes the Incus
				// project with admin credentials — a restricted tenant
				// certificate cannot. Falls through to the direct path only
				// when the deployment has no delete endpoint.
				result, err := projectAuthClient(config).DeleteProject(cmd.Context(), args[0], dryRun)
				if err == nil {
					return writeOutput(config.stdout, opts.output, formatProjectDomainResult("delete", result), result)
				}
				if !strings.Contains(err.Error(), "not available on this deployment") {
					return err
				}
			}
			if !dryRun {
				// Deleting the Incus project IS the deletion: a tenant's project
				// list is derived from its Incus projects. This used to only
				// rewrite a metadata file nothing read, so the project, its
				// volumes and its machines all survived a "successful" delete.
				if config.projectDeleter == nil {
					return fmt.Errorf("project deleter is not configured")
				}
				if err := config.projectDeleter.DeleteProjectV2(cmd.Context(), tenantSummary.V2IncusProjectName(args[0]), config.adminConfig.StoragePool); err != nil {
					// A tenant's restricted certificate may not delete an Incus
					// project; without an Auth App login the tenant plane's
					// delete endpoint is out of reach. Say so, rather than
					// surfacing a bare "Certificate is restricted".
					if strings.Contains(err.Error(), "restricted") || strings.Contains(err.Error(), "not authorized") {
						return fmt.Errorf("deleting a project needs admin rights: your tenant certificate is restricted (run sc login so `sc project delete` can use the Auth App).\nOr ask an admin to run: sc-adm project delete %s %s --yes", tenantSummary.Tenant, args[0])
					}
					return err
				}
			}
			return writeOutput(config.stdout, opts.output, formatProjectMutationPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&yes, "yes", false, "confirm project deletion")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the project metadata update without mutating resources")
	return command
}

func newProjectSetCloudIdentityCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "set-cloud-identity name cloud-identity",
		Short: "Set a default Cloud Identity Config for a project",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := tenant.PlanSetProjectCloudIdentity(cmd.Context(), config.adminConfig, config.tenantStore, tenant.ProjectMutationRequest{
				Name:          args[0],
				CloudIdentity: strings.TrimSpace(args[1]),
			})
			if err != nil {
				return err
			}
			if err := validateProjectCloudIdentity(cmd.Context(), config, plan.Tenant.Tenant, strings.TrimSpace(args[1])); err != nil {
				return err
			}
			if !dryRun {
				// Persist on the project's own Incus project — that is where
				// tenant.v2Summaries reads it back from.
				if config.projectSettings == nil {
					return fmt.Errorf("project settings updater is not configured")
				}
				if err := config.projectSettings.SetProjectCloudIdentity(cmd.Context(), plan.Tenant.V2IncusProjectName(args[0]), strings.TrimSpace(args[1])); err != nil {
					return err
				}
			}
			return writeOutput(config.stdout, opts.output, formatProjectMutationPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the project metadata update without mutating resources")
	return command
}

func validateProjectCloudIdentity(ctx context.Context, config commandConfig, tenantName string, cloudIdentity string) error {
	tenantName = strings.TrimSpace(tenantName)
	cloudIdentity = strings.TrimSpace(cloudIdentity)
	if tenantName == "" || cloudIdentity == "" {
		return fmt.Errorf("tenant and cloud identity config are required")
	}
	client := config.authCloudIdentity
	if client == nil {
		baseURL := commandAuthHostname(config, "")
		if baseURL == "" {
			return fmt.Errorf("cannot validate cloud identity %q for tenant %q: --auth-hostname is required (or run sc login again)", cloudIdentity, tenantName)
		}
		if strings.TrimSpace(config.adminConfig.AuthToken) == "" {
			return fmt.Errorf("cannot validate cloud identity %q for tenant %q: run sc login first", cloudIdentity, tenantName)
		}
		client = authapp.DeviceClient{BaseURL: baseURL, AuthToken: config.adminConfig.AuthToken, Tenant: strings.TrimSpace(config.adminConfig.Tenant)}
	}
	configured, err := client.GetCloudIdentity(ctx, tenantName, cloudIdentity)
	if err != nil {
		return fmt.Errorf("cloud identity config %q is not configured for tenant %q: %w", cloudIdentity, tenantName, err)
	}
	if strings.TrimSpace(configured.Tenant) != tenantName {
		return fmt.Errorf("cloud identity config %q belongs to tenant %q, not tenant %q", cloudIdentity, configured.Tenant, tenantName)
	}
	return nil
}

func newProjectUnsetCloudIdentityCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "unset-cloud-identity name",
		Short: "Clear the default Cloud Identity Config for a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := tenant.PlanSetProjectCloudIdentity(cmd.Context(), config.adminConfig, config.tenantStore, tenant.ProjectMutationRequest{Name: args[0]})
			if err != nil {
				return err
			}
			return writeOutput(config.stdout, opts.output, formatProjectMutationPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the project metadata update without mutating resources")
	return command
}

func newProjectSetDockerAutostartCommand(config commandConfig, opts *rootOptions) *cobra.Command {
	var dryRun bool
	command := &cobra.Command{
		Use:   "set-docker-autostart name on|off",
		Short: "Set whether Docker starts automatically for new machines in a project",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			enabled, err := parseOnOff(args[1])
			if err != nil {
				return err
			}
			plan, err := tenant.PlanSetProjectDockerAutostart(cmd.Context(), config.adminConfig, config.tenantStore, tenant.ProjectMutationRequest{
				Name:            args[0],
				DockerAutostart: enabled,
			})
			if err != nil {
				return err
			}
			if !dryRun {
				if config.projectSettings == nil {
					return fmt.Errorf("project settings updater is not configured")
				}
				if err := config.projectSettings.SetProjectDockerAutostart(cmd.Context(), plan.Tenant.V2IncusProjectName(args[0]), enabled); err != nil {
					return err
				}
			}
			return writeOutput(config.stdout, opts.output, formatProjectMutationPlan(plan), plan)
		},
	}
	command.Flags().BoolVar(&dryRun, "dry-run", false, "render the project metadata update without mutating resources")
	return command
}

func parseOnOff(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "true", "yes", "1", "enabled", "enable":
		return true, nil
	case "off", "false", "no", "0", "disabled", "disable":
		return false, nil
	default:
		return false, fmt.Errorf("value must be on or off")
	}
}

func currentTenantMachines(cmd *cobra.Command, config commandConfig) (tenant.Summary, []meta.Machine, error) {
	result, err := listMachines(cmd.Context(), config, listMachinesRequest{AllProjects: true})
	if err != nil {
		return tenant.Summary{}, nil, err
	}
	return result.Tenant, result.Machines, nil
}

func currentTenantSummary(ctx context.Context, config commandConfig) (tenant.Summary, error) {
	ref, err := naming.ParseTenantRef(config.adminConfig.Tenant)
	if err != nil {
		return tenant.Summary{}, fmt.Errorf("tenant is required; set SANDCASTLE_TENANT or local tenant config")
	}
	tenants, err := scopedListTenants(ctx, config, ref.Tenant)
	if err != nil {
		return tenant.Summary{}, err
	}
	for _, tenant := range tenants {
		if tenant.Tenant == ref.Tenant {
			return tenant, nil
		}
	}
	return tenant.Summary{}, fmt.Errorf("Sandcastle tenant %s not found", ref.Tenant)
}

func formatProjectNamespaceList(tenant tenant.Summary, current string) string {
	if len(tenant.Projects) == 0 {
		return "No Sandcastle projects found."
	}
	current = strings.TrimSpace(current)
	var builder strings.Builder
	for _, namespace := range tenant.Projects {
		marker := "  "
		if namespace.Name == current {
			marker = "* "
		}
		fmt.Fprintf(&builder, "%s%s\n", marker, namespace.Name)
	}
	return strings.TrimRight(builder.String(), "\n")
}

func formatProjectNamespaceStatus(status projectStatusPayload) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Project: %s\n", status.Project.Name)
	fmt.Fprintf(&builder, "Tenant: %s\n", status.Tenant.Tenant)
	if status.Project.CloudIdentity != "" {
		fmt.Fprintf(&builder, "Cloud identity: %s\n", status.Project.CloudIdentity)
	}
	if status.Project.DockerAutostart {
		fmt.Fprintln(&builder, "Docker autostart: on")
	}
	fmt.Fprintf(&builder, "Machines: %d\n", status.MachineCount)
	if status.Domain == "" {
		fmt.Fprint(&builder, "Domain: (none)")
	} else {
		fmt.Fprintf(&builder, "Domain: %s", status.Domain)
		if status.Zone != "" {
			fmt.Fprintf(&builder, "   (zone %s)", status.Zone)
		}
	}
	if status.CertState != "" {
		fmt.Fprintf(&builder, "\nCertificate: %s  expires %s\nSANs: %s", status.CertState, orDash(status.CertNotAfter), strings.Join(status.SANs, ", "))
	}
	if len(status.Machines) == 0 {
		return builder.String()
	}
	fmt.Fprintln(&builder)
	table := [][]string{{"MACHINE", "PUBLIC NAME", "CERT", "NOT AFTER", "DETAIL"}}
	for _, m := range status.Machines {
		table = append(table, []string{m.Machine, orDash(m.PublicHostname), orDash(m.CertState), orDash(m.CertNotAfter), m.Detail})
	}
	fmt.Fprint(&builder, formatAlignedTable(table))
	return builder.String()
}

// formatAlignedTable renders rows as space-aligned columns (two spaces between
// columns, no trailing spaces).
func formatAlignedTable(rows [][]string) string {
	widths := map[int]int{}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	var builder strings.Builder
	for r, row := range rows {
		line := ""
		for i, cell := range row {
			if i == len(row)-1 {
				line += cell
			} else {
				line += fmt.Sprintf("%-*s  ", widths[i], cell)
			}
		}
		builder.WriteString(strings.TrimRight(line, " "))
		if r < len(rows)-1 {
			builder.WriteString("\n")
		}
	}
	return builder.String()
}

func formatProjectMutationPlan(plan tenant.ProjectMutationPlan) string {
	return fmt.Sprintf("%s project %s in tenant %s", plan.Action, plan.Project.Name, plan.Tenant.Tenant)
}

func findProject(summary tenant.Summary, name string) (meta.Project, bool) {
	for _, project := range summary.Projects {
		if project.Name == name {
			return project, true
		}
	}
	return meta.Project{}, false
}
