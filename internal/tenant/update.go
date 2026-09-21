package tenant

import (
	"context"
	"fmt"
	"strings"

	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

type ResolvedRef struct {
	IncusProject string
}

type ProjectMutationRequest struct {
	Name            string
	Machines        []meta.Machine
	CloudIdentity   string
	DockerAutostart bool
	Image           string
}

type ProjectMutationPlan struct {
	Action       string         `json:"action"`
	Tenant       Summary        `json:"tenant"`
	Project      meta.Project   `json:"project"`
	Projects     []meta.Project `json:"projects"`
	IncusProject string         `json:"incusProject"`
}

func ParseRef(admin config.Admin, reference string) (ResolvedRef, error) {
	ref, err := naming.ParseTenantRef(reference)
	if err != nil {
		return ResolvedRef{}, err
	}
	incusName, err := naming.TenantIncusProjectNameWithPrefix(admin.IncusProjectPrefix, ref)
	if err != nil {
		return ResolvedRef{}, err
	}
	return ResolvedRef{IncusProject: incusName}, nil
}

func PlanCreateProject(ctx context.Context, admin config.Admin, store IncusTenantStore, request ProjectMutationRequest) (ProjectMutationPlan, error) {
	if err := admin.Validate(); err != nil {
		return ProjectMutationPlan{}, err
	}
	if err := naming.ValidateNewProjectName(request.Name); err != nil {
		return ProjectMutationPlan{}, err
	}
	summary, err := findCurrentTenant(ctx, admin, store)
	if err != nil {
		return ProjectMutationPlan{}, err
	}
	if summaryHasProject(summary, request.Name) {
		return ProjectMutationPlan{}, fmt.Errorf("Sandcastle project %s already exists in tenant %s", request.Name, summary.Tenant)
	}
	created := meta.Project{Name: request.Name}
	projects := append([]meta.Project{}, summary.Projects...)
	projects = append(projects, created)
	return ProjectMutationPlan{
		Action:       "create",
		Tenant:       summary,
		Project:      created,
		Projects:     projects,
		IncusProject: summary.IncusName,
	}, nil
}

func PlanDeleteProject(ctx context.Context, admin config.Admin, store IncusTenantStore, request ProjectMutationRequest) (ProjectMutationPlan, error) {
	if err := admin.Validate(); err != nil {
		return ProjectMutationPlan{}, err
	}
	if err := naming.ValidateProjectName(request.Name); err != nil {
		return ProjectMutationPlan{}, err
	}
	if request.Name == naming.DefaultProjectName {
		return ProjectMutationPlan{}, fmt.Errorf("default project cannot be deleted")
	}
	summary, err := findCurrentTenant(ctx, admin, store)
	if err != nil {
		return ProjectMutationPlan{}, err
	}
	if !summaryHasProject(summary, request.Name) {
		return ProjectMutationPlan{}, fmt.Errorf("Sandcastle project %s not found in tenant %s", request.Name, summary.Tenant)
	}
	for _, machine := range request.Machines {
		if machine.Project == request.Name {
			return ProjectMutationPlan{}, fmt.Errorf("Sandcastle project %s still contains machine %s", request.Name, machine.Name)
		}
	}
	for _, storageShare := range summary.StorageShares {
		if storageShare.SourceTenant == summary.Tenant && storageShare.SourceProject == request.Name {
			return ProjectMutationPlan{}, fmt.Errorf("Sandcastle project %s still has active Tenant Storage Share %s", request.Name, storageShare.Name)
		}
	}
	projects := make([]meta.Project, 0, len(summary.Projects)-1)
	var deleted meta.Project
	for _, candidate := range summary.Projects {
		if candidate.Name == request.Name {
			deleted = candidate
			continue
		}
		projects = append(projects, candidate)
	}
	return ProjectMutationPlan{
		Action:       "delete",
		Tenant:       summary,
		Project:      deleted,
		Projects:     projects,
		IncusProject: summary.IncusName,
	}, nil
}

func PlanSetProjectCloudIdentity(ctx context.Context, admin config.Admin, store IncusTenantStore, request ProjectMutationRequest) (ProjectMutationPlan, error) {
	if err := admin.Validate(); err != nil {
		return ProjectMutationPlan{}, err
	}
	if err := naming.ValidateProjectName(request.Name); err != nil {
		return ProjectMutationPlan{}, err
	}
	summary, err := findCurrentTenant(ctx, admin, store)
	if err != nil {
		return ProjectMutationPlan{}, err
	}
	projects := append([]meta.Project{}, summary.Projects...)
	var updated meta.Project
	found := false
	for i := range projects {
		if projects[i].Name == request.Name {
			projects[i].CloudIdentity = request.CloudIdentity
			updated = projects[i]
			found = true
			break
		}
	}
	if !found {
		return ProjectMutationPlan{}, fmt.Errorf("Sandcastle project %s not found in tenant %s", request.Name, summary.Tenant)
	}
	return ProjectMutationPlan{
		Action:       "set cloud identity on",
		Tenant:       summary,
		Project:      updated,
		Projects:     projects,
		IncusProject: summary.IncusName,
	}, nil
}

func PlanSetProjectDockerAutostart(ctx context.Context, admin config.Admin, store IncusTenantStore, request ProjectMutationRequest) (ProjectMutationPlan, error) {
	if err := admin.Validate(); err != nil {
		return ProjectMutationPlan{}, err
	}
	if err := naming.ValidateProjectName(request.Name); err != nil {
		return ProjectMutationPlan{}, err
	}
	summary, err := findCurrentTenant(ctx, admin, store)
	if err != nil {
		return ProjectMutationPlan{}, err
	}
	projects := append([]meta.Project{}, summary.Projects...)
	var updated meta.Project
	found := false
	for i := range projects {
		if projects[i].Name == request.Name {
			projects[i].DockerAutostart = request.DockerAutostart
			updated = projects[i]
			found = true
			break
		}
	}
	if !found {
		return ProjectMutationPlan{}, fmt.Errorf("Sandcastle project %s not found in tenant %s", request.Name, summary.Tenant)
	}
	action := "disable Docker autostart for"
	if request.DockerAutostart {
		action = "enable Docker autostart for"
	}
	return ProjectMutationPlan{
		Action:       action,
		Tenant:       summary,
		Project:      updated,
		Projects:     projects,
		IncusProject: summary.IncusName,
	}, nil
}

func findCurrentTenant(ctx context.Context, admin config.Admin, store IncusTenantStore) (Summary, error) {
	ref, err := naming.ParseTenantRef(admin.Tenant)
	if err != nil {
		return Summary{}, err
	}
	tenants, err := List(ctx, store)
	if err != nil {
		return Summary{}, err
	}
	for _, summary := range tenants {
		if summary.Tenant == ref.Tenant {
			return summary, nil
		}
	}
	return Summary{}, fmt.Errorf("Sandcastle tenant %s not found", ref.Tenant)
}

func summaryHasProject(summary Summary, name string) bool {
	for _, project := range summary.Projects {
		if project.Name == name {
			return true
		}
	}
	return false
}

// PlanSetProjectImage records a project's default machine image ("" clears
// it back to the CLI's stock default). The image ref is not validated against
// the remote here: aliases and images: refs resolve at `sc create` time.
func PlanSetProjectImage(ctx context.Context, admin config.Admin, store IncusTenantStore, request ProjectMutationRequest) (ProjectMutationPlan, error) {
	if err := admin.Validate(); err != nil {
		return ProjectMutationPlan{}, err
	}
	if err := naming.ValidateProjectName(request.Name); err != nil {
		return ProjectMutationPlan{}, err
	}
	image := strings.TrimSpace(request.Image)
	if strings.ContainsAny(image, " \t\n") {
		return ProjectMutationPlan{}, fmt.Errorf("invalid image reference %q", request.Image)
	}
	summary, err := findCurrentTenant(ctx, admin, store)
	if err != nil {
		return ProjectMutationPlan{}, err
	}
	projects := append([]meta.Project{}, summary.Projects...)
	var updated meta.Project
	found := false
	for i := range projects {
		if projects[i].Name == request.Name {
			projects[i].Image = image
			updated = projects[i]
			found = true
			break
		}
	}
	if !found {
		return ProjectMutationPlan{}, fmt.Errorf("Sandcastle project %s not found in tenant %s", request.Name, summary.Tenant)
	}
	action := "set default image " + image + " on"
	if image == "" {
		action = "clear the default image of"
	}
	return ProjectMutationPlan{
		Action:       action,
		Tenant:       summary,
		Project:      updated,
		Projects:     projects,
		IncusProject: summary.IncusName,
	}, nil
}
