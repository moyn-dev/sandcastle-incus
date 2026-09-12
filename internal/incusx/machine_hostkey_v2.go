package incusx

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/meta"
)

// hostKeyFiles are the sshd public host keys we try, in descending order of
// preference. sshd cannot start without at least one of these, so on any
// machine whose port 22 is open, one of them exists.
var hostKeyFiles = []string{
	"/etc/ssh/ssh_host_ed25519_key.pub",
	"/etc/ssh/ssh_host_ecdsa_key.pub",
	"/etc/ssh/ssh_host_rsa_key.pub",
}

// HostKey is a machine's SSH host public key, as read from the machine itself.
type HostKey struct {
	Type string // e.g. "ssh-ed25519"
	Key  string // base64 blob, no comment
}

// MachineHostKeysV2 reads every SSH host public key a v2 machine has, over the
// Incus API.
//
// This is the authoritative source: the keys are read out of the instance's own
// filesystem across the mTLS Incus connection, so they never cross the network
// the SSH session is about to traverse. That is what lets connect run with
// StrictHostKeyChecking=yes instead of trusting whatever answers on port 22.
//
// All key types are returned, not just the preferred one. OpenSSH's
// UpdateHostKeys learns a server's other host keys after authenticating and
// appends them to known_hosts; recording only one would leave ssh forever
// re-adding the rest as untagged lines that the next connect would reclaim.
//
// Containers expose their filesystem directly. Virtual machines route file
// access through incus-agent inside the guest, so this fails on a VM whose
// agent is not running — callers fall back to ssh-keyscan and mark the keys as
// trust-on-first-use.
func (c TenantCreator) MachineHostKeysV2(ctx context.Context, incusProject string, name string) ([]HostKey, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	project := server.UseProject(incusProject)
	var keys []HostKey
	var lastErr error
	for _, path := range hostKeyFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.log("read host key " + incusProject + "/" + name + ":" + path)
		content, _, err := project.GetInstanceFile(name, path)
		if err != nil {
			lastErr = err
			continue
		}
		raw, err := io.ReadAll(content)
		_ = content.Close()
		if err != nil {
			lastErr = err
			continue
		}
		key, err := parseHostKey(raw)
		if err != nil {
			lastErr = err
			continue
		}
		keys = append(keys, key)
	}
	if len(keys) > 0 {
		return keys, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no SSH host key found")
	}
	return nil, fmt.Errorf("read host keys for machine %s: %w", name, lastErr)
}

// parseHostKey pulls the type and key blob out of an authorized-key line,
// discarding the trailing comment (usually root@<hostname>).
func parseHostKey(raw []byte) (HostKey, error) {
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return HostKey{}, fmt.Errorf("malformed host key %q", strings.TrimSpace(string(raw)))
	}
	return HostKey{Type: fields[0], Key: fields[1]}, nil
}

// MachineSubnetV2 reports the subnet a running machine's interface sits on, in
// CIDR form, or "" when the machine has no lease. The tenant bridge's own
// config is invisible to a restricted certificate, so this — read from the
// machine's interface — is how the tenant learns its own private CIDR.
func (c TenantCreator) MachineSubnetV2(ctx context.Context, incusProject string, name string) (string, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return "", err
	}
	_, cidr := waitForV2InstanceIPv4(ctx, server.UseProject(incusProject), name, 0)
	return cidr, nil
}

// V2MachineRef names one live v2 machine by its short project and machine name.
type V2MachineRef struct {
	Project string // short project name, e.g. "default"
	Name    string
	// PublicHostname is the machine's Naming Mode record (ADR-0027) read off
	// its own instance config: the Machine Public Hostname, or "" for a
	// private-mode (or unstamped) machine.
	PublicHostname string
}

// ListMachinesV2 returns every live machine across all of a tenant's app
// projects. infraProject is the tenant's Incus project prefix, so its app
// projects are exactly those named "<infraProject>-<short>".
func (c TenantCreator) ListMachinesV2(ctx context.Context, infraProject string) ([]V2MachineRef, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return nil, err
	}
	names, err := server.GetProjectNames()
	if err != nil {
		return nil, fmt.Errorf("list Incus projects: %w", err)
	}
	prefix := strings.TrimSpace(infraProject) + "-"
	var machines []V2MachineRef
	for _, incusProject := range names {
		short := strings.TrimPrefix(incusProject, prefix)
		if short == incusProject || short == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		instances, err := server.UseProject(incusProject).GetInstances(api.InstanceTypeAny)
		if err != nil {
			return nil, fmt.Errorf("list machines in project %s: %w", incusProject, err)
		}
		for _, instance := range instances {
			machines = append(machines, V2MachineRef{
				Project:        short,
				Name:           instance.Name,
				PublicHostname: meta.PublicHostnameFromConfig(instance.Config),
			})
		}
	}
	return machines, nil
}
