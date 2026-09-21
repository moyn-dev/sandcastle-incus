package incusx

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
)

// SetProjectCloudIdentity and SetProjectDockerAutostart persist a v2 project's
// settings on the project's own Incus project config, which is where
// tenant.v2Summaries reads them back from.
//
// They used to be written into a `.sandcastle/projects` file on the tenant's
// workspace volume. Nothing read that file, so both commands were no-ops that
// printed a plan — and on a v2 tenant the write itself failed, because the file
// was addressed on the infra project, which has no workspace volume.
func (c TenantCreator) SetProjectCloudIdentity(_ context.Context, incusProject string, cloudIdentity string) error {
	return c.updateProjectConfig(incusProject, meta.KeyV2CloudIdentity, strings.TrimSpace(cloudIdentity))
}

// SetProjectImage stores (or clears, with "") a project's default machine image.
func (c TenantCreator) SetProjectImage(_ context.Context, incusProject string, image string) error {
	return c.updateProjectConfig(incusProject, meta.KeyV2Image, strings.TrimSpace(image))
}

func (c TenantCreator) SetProjectDockerAutostart(_ context.Context, incusProject string, enabled bool) error {
	return c.updateProjectConfig(incusProject, meta.KeyV2DockerAutostart, strconv.FormatBool(enabled))
}

// updateProjectConfig sets one key on an Incus project, deleting it when the
// value is empty so the config does not accumulate blanks.
func (c TenantCreator) updateProjectConfig(incusProject string, key string, value string) error {
	incusProject = strings.TrimSpace(incusProject)
	if incusProject == "" {
		return fmt.Errorf("incus project is required")
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	project, etag, err := server.GetProject(incusProject)
	if err != nil {
		return fmt.Errorf("project %s not found: %w", incusProject, err)
	}
	config := map[string]string{}
	for existingKey, existingValue := range project.Config {
		config[existingKey] = existingValue
	}
	if value == "" {
		delete(config, key)
	} else {
		config[key] = value
	}
	c.log("set " + key + " on " + incusProject)
	if err := server.UpdateProject(incusProject, api.ProjectPut{Config: config, Description: project.Description}, etag); err != nil {
		return fmt.Errorf("update %s on %s: %w", key, incusProject, err)
	}
	return nil
}
