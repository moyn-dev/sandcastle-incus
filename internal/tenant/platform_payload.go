package tenant

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// The per-tenant /.sc shared-scripts volume (spec #127) presents two layers to
// every machine: a platform-managed base and a tenant-owned overlay. Machines
// carry only stable shims at the fixed OS paths; the shims source the payload
// from these mount points, platform first, local second.
const (
	SCPlatformPath = "/.sc/platform"
	SCLocalPath    = "/.sc/local"
)

// PlatformPayloadFile is one file of the /.sc/platform payload. Path is
// relative to SCPlatformPath.
type PlatformPayloadFile struct {
	Path    string `json:"path"`
	Mode    int    `json:"mode"`
	Content string `json:"content"`
}

// PlatformPayloadVersionFile is the payload's version marker: a file inside
// /.sc/platform whose content is the payload version, so any machine (and the
// central updater) can tell which payload a tenant is running.
const PlatformPayloadVersionFile = "VERSION"

// Payload script paths (relative to SCPlatformPath). These are the exact paths
// the baked shims source — the shim↔payload contract test keeps the two sides
// in agreement, so a shim can never point at a script the payload doesn't ship.
const (
	SCPayloadSSHRCPath      = "ssh/sshrc"
	SCPayloadShellRCPath    = "shell/rc.sh"
	SCPayloadGeneralizePath = "sbin/machine-generalize"
	SCPayloadCaddySetupPath = "sbin/caddy-setup"
	// SCPayloadCloudflaredPath is the Machine Tunnel connector launcher.  Its
	// stable path lets systemd units follow centrally-synced platform behavior
	// rather than carrying a private /usr/local binary per Machine.
	SCPayloadCloudflaredPath = "sbin/cloudflared"
)

// PlatformPayload returns the versioned /.sc/platform payload: every platform
// script as a file set plus the payload version. The content comes from the
// same shared constants the agent-forwarding work established (one source of
// truth), so the payload, the profile-era scripts, and the `sc fix` backfill
// can never drift apart.
//
// The version is derived from the file contents, so it is stable for a given
// payload and changes exactly when the payload does. The VERSION marker file
// is part of the returned set.
func PlatformPayload() ([]PlatformPayloadFile, string) {
	files := []PlatformPayloadFile{
		{Path: SCPayloadSSHRCPath, Mode: 0o755, Content: sshAgentRepublishScript},
		{Path: SCPayloadShellRCPath, Mode: 0o644, Content: sshAgentConsumeSnippet},
		{Path: SCPayloadGeneralizePath, Mode: 0o755, Content: machineGeneralizeScript},
		{Path: SCPayloadCaddySetupPath, Mode: 0o755, Content: caddyIngressSetupScript},
		{Path: SCPayloadCloudflaredPath, Mode: 0o755, Content: cloudflaredPlatformLauncher},
	}
	version := platformPayloadVersion(files)
	files = append(files, PlatformPayloadFile{Path: PlatformPayloadVersionFile, Mode: 0o644, Content: version + "\n"})
	return files, version
}

// platformPayloadVersion hashes the payload's (path, mode, content) tuples in
// order. Content-derived: two binaries shipping identical scripts agree on the
// version; any script change (or an older binary re-run for rollback) yields
// its own version, making drift detectable and rollback a plain re-sync.
func platformPayloadVersion(files []PlatformPayloadFile) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00%o\x00%s\x00", f.Path, f.Mode, f.Content)
	}
	return "sc-payload-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// PlatformPayloadVersion returns the version of the payload built into this
// binary — what a central sync would write.
func PlatformPayloadVersion() string {
	_, version := PlatformPayload()
	return version
}

// SCShimMarker is the grep sentinel identifying an installed /.sc shim — the
// profile, the `sc fix` backfill/check scripts, and the fleet script share it,
// so idempotent installs can detect an already-shimmed rc file.
const SCShimMarker = "Sandcastle /.sc shim"

// scShimSourceLines renders the load-bearing shim body for one payload script:
// source the platform layer first, then the tenant's local overlay, each
// guarded with `[ -r … ] &&` so an unmounted /.sc or missing payload is a
// clean no-op — the feature is simply absent, never a shell/SSH lockout.
func scShimSourceLines(relPath string) string {
	platform := SCPlatformPath + "/" + relPath
	local := SCLocalPath + "/" + relPath
	return "[ -r " + platform + " ] && . " + platform + "\n" +
		"[ -r " + local + " ] && . " + local + "\n" +
		"true\n"
}

// SCSSHRCShim is the stable /etc/ssh/sshrc baked into every machine. sshd runs
// it at session start; the agent-forwarding republish logic it used to carry
// inline now lives in the platform payload on /.sc, so a payload update
// reaches every machine without touching cloud-init or the machine itself.
// Content-stable: payload changes never require re-baking this file.
var SCSSHRCShim = "#!/bin/sh\n" +
	"# " + SCShimMarker + " (stable) — the logic lives on the /.sc volume (ADR-0022).\n" +
	scShimSourceLines(SCPayloadSSHRCPath)

// SCShellRCShim is the stable block appended to /etc/zsh/zshrc and
// /etc/bash.bashrc (both interactive-startup files, so a herdr/tmux pane picks
// it up whichever shell it runs).
var SCShellRCShim = "# " + SCShimMarker + " (stable) — shell setup lives on the /.sc volume (ADR-0022).\n" +
	scShimSourceLines(SCPayloadShellRCPath)

// scBootShim renders the stable shim for a boot-time payload consumer (a
// cloud-init runcmd target under /usr/local/sbin). Unlike the shell-rc shims,
// boot consumers can race the volume mount — a VM's virtiofs share comes up
// via the incus agent and may lag early cloud-init — so the shim waits briefly
// for the payload before the usual fail-safe no-op. Only the platform layer is
// sourced: boot scripts are platform-managed; tenant customization belongs in
// the shell/rc overlay, not machine bring-up.
func scBootShim(relPath string) string {
	platform := SCPlatformPath + "/" + relPath
	return "#!/bin/sh\n" +
		"# " + SCShimMarker + " (stable) — the logic lives on the /.sc volume (ADR-0022).\n" +
		"# Boot-time consumer: wait briefly for the volume mount, then fail safe.\n" +
		"i=0\n" +
		"while [ ! -r " + platform + " ] && [ \"$i\" -lt 30 ]; do i=$((i+1)); sleep 1; done\n" +
		"[ -r " + platform + " ] && . " + platform + "\n" +
		"true\n"
}

// SCGeneralizeShim / SCCaddySetupShim are the stable bodies baked at
// /usr/local/sbin/sandcastle-generalize and /usr/local/sbin/sandcastle-caddy-setup
// (the cloud-init runcmd targets). The scripts they used to carry inline now
// ship as platform-payload entries, so fixing machine bring-up no longer means
// re-baking cloud-init.
var (
	SCGeneralizeShim = scBootShim(SCPayloadGeneralizePath)
	SCCaddySetupShim = scBootShim(SCPayloadCaddySetupPath)
)

// SCVolume describes one layer of the /.sc shared-scripts volume as plan data:
// the custom volume, the default-profile disk device attaching it, its
// in-machine mount path, and whether machines mount it read-only (the platform
// layer) or read-write (the tenant-owned local layer).
type SCVolume struct {
	Volume     string `json:"volume"`
	DeviceName string `json:"deviceName"`
	Path       string `json:"path"`
	ReadOnly   bool   `json:"readOnly"`
}

// V2SCVolumes is the /.sc volume set every v2 app project carries. The
// external contract is the two paths and their writability (spec #127):
// /.sc/platform read-only to the tenant's machines, /.sc/local read-write —
// for containers and virtual machines alike. RO/RW is enforced where machines
// mount the layer (the disk device), matching how /workspace is shared.
func V2SCVolumes() []SCVolume {
	return []SCVolume{
		{Volume: V2SCPlatformVolumeName, DeviceName: "sc-platform", Path: SCPlatformPath, ReadOnly: true},
		{Volume: V2SCLocalVolumeName, DeviceName: "sc-local", Path: SCLocalPath, ReadOnly: false},
	}
}

// Device renders the layer's Incus disk-device descriptor for a storage pool —
// the one shape both the profile renderer and the legacy onboarding attach.
func (v SCVolume) Device(pool string) map[string]string {
	device := map[string]string{"type": "disk", "pool": pool, "source": v.Volume, "path": v.Path}
	if v.ReadOnly {
		device["readonly"] = "true"
	}
	return device
}
