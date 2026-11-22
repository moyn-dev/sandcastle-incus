package cli

import (
	"strings"

	"github.com/moyn-dev/sandcastle-incus/internal/meta"
	tenant "github.com/moyn-dev/sandcastle-incus/internal/tenant"
)

func effectiveProjectCloudIdentity(config commandConfig, summary tenant.Summary, projectName string, explicit string) string {
	if value := strings.TrimSpace(explicit); value != "" {
		return value
	}
	for _, project := range summary.Projects {
		if project.Name == projectName && strings.TrimSpace(project.CloudIdentity) != "" {
			value := strings.TrimSpace(project.CloudIdentity)
			verboseCLI(config, "workload identity: using project %s default cloud identity %q", projectName, value)
			return value
		}
	}
	return ""
}

func projectHasCloudIdentity(projects []meta.Project, name string, cloudIdentity string) bool {
	for _, project := range projects {
		if project.Name == name && project.CloudIdentity == cloudIdentity {
			return true
		}
	}
	return false
}

func projectHasDockerAutostart(projects []meta.Project, name string) bool {
	for _, project := range projects {
		if project.Name == name && project.DockerAutostart {
			return true
		}
	}
	return false
}
