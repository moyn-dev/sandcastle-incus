package incusx

import (
	"context"
	"fmt"
)

// Cloud-init marker paths, read over the Incus API the same way host keys are.
//
// boot-finished is written once every cloud-init module has run for this boot.
// It matters to `sc connect` because the `ssh` module DELETES and regenerates
// every SSH host key on a machine's first boot — sshd is already listening on
// port 22 with the keys the image (or the ssh package's first-boot hook) left
// behind, so "port 22 answers" is not "the host keys are final".
const (
	cloudInitBootFinished = "/var/lib/cloud/instance/boot-finished"
	cloudInitDir          = "/var/lib/cloud"
	// A path every Linux image has, used only to tell "this machine has no
	// cloud-init" apart from "this machine cannot be read at all".
	machineProbePath = "/etc/hostname"
)

// MachineCloudInitDoneV2 reports whether a machine has finished its cloud-init
// run for this boot, i.e. whether its SSH host keys have stopped moving.
//
// An image that does not ship cloud-init counts as done — there is nothing to
// wait for. An error means the question could not be answered (a VM whose
// incus-agent has not started, most often); callers proceed rather than block.
func (c TenantCreator) MachineCloudInitDoneV2(ctx context.Context, incusProject string, name string) (bool, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return false, err
	}
	project := server.UseProject(incusProject)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c.log("read cloud-init state " + incusProject + "/" + name)
	// A directory comes back with a nil body, so every read is closed defensively.
	readable := func(path string) bool {
		content, _, err := project.GetInstanceFile(name, path)
		if content != nil {
			_ = content.Close()
		}
		return err == nil
	}
	if readable(cloudInitBootFinished) {
		return true, nil
	}
	if readable(cloudInitDir) {
		return false, nil // cloud-init is present and has not finished yet
	}
	if readable(machineProbePath) {
		return true, nil // readable machine, no cloud-init: nothing regenerates keys
	}
	return false, fmt.Errorf("read cloud-init state for machine %s: file access unavailable", name)
}

// MachineHasCloudInitV2 reports whether the machine's image ships cloud-init
// at all (a non-cloud `images:` variant does not — it then never gets a
// login user, keys or sshd). An unreadable machine is an error.
func (c TenantCreator) MachineHasCloudInitV2(ctx context.Context, incusProject string, name string) (bool, error) {
	server, err := c.resolveV2Server()
	if err != nil {
		return false, err
	}
	project := server.UseProject(incusProject)
	readable := func(path string) bool {
		content, _, err := project.GetInstanceFile(name, path)
		if content != nil {
			_ = content.Close()
		}
		return err == nil
	}
	if readable(cloudInitBootFinished) || readable(cloudInitDir) {
		return true, nil
	}
	if readable(machineProbePath) {
		return false, nil
	}
	return false, fmt.Errorf("read cloud-init presence for machine %s: file access unavailable", name)
}
