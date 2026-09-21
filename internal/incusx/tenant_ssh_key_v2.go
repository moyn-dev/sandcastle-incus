package incusx

import (
	"context"
	"fmt"

	"github.com/lxc/incus/v6/shared/api"

	"github.com/thieso2/sandcastle-incus/internal/meta"
)

// SetTenantSSHKeyV2 replaces the SSH public key list baked into a v2 tenant's
// machines (one key per line; see meta.KeyV2SSHKey).
//
// The authoritative store is the infra project's `user.sandcastle.v2.sshkey`
// config — that is what `ensureV2AppProfile` renders into each app project's
// default profile cloud-init, and therefore what a newly created machine
// authorizes. Writing the key into the tenant's `workspace` metadata file (what
// the old code did) reached nothing: no code reads that file back.
//
// Existing machines keep the key they were created with; cloud-init only runs
// once. Rotating for a running machine is `MachineSSHKeyReconciler`'s job.
func (c TenantCreator) SetTenantSSHKeyV2(_ context.Context, installPrefix string, tenantName string, sshKey string, projects []string) error {
	sshKey = meta.FormatSSHKeys(meta.ParseSSHKeys(sshKey))
	if sshKey == "" {
		return fmt.Errorf("ssh key is required")
	}
	server, err := c.resolveV2Server()
	if err != nil {
		return err
	}
	infraProject, infra, etag, err := tenantV2Infra(server, installPrefix, tenantName)
	if err != nil {
		return err
	}
	config := map[string]string{}
	for key, value := range infra.Config {
		config[key] = value
	}
	config[keyV2SSHKey] = sshKey
	c.log("update " + keyV2SSHKey + " on " + infraProject)
	if err := server.UpdateProject(infraProject, api.ProjectPut{Config: config, Description: infra.Description}, etag); err != nil {
		return fmt.Errorf("store ssh key on %s: %w", infraProject, err)
	}
	// Re-render every app project's default profile so machines created from now
	// on authorize the new key set (own keys + every Tenant Member's). Without
	// this the command changed nothing a machine could observe.
	return c.renderTenantProfilesV2(server, tenantName, infraProject, config, projects)
}
