package cli

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/hostkeys"
	"github.com/thieso2/sandcastle-incus/internal/incusx"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	"github.com/thieso2/sandcastle-incus/internal/tenant"
)

// v2MachineNames lists every name a v2 machine answers at (ADR-0028): its
// Machine Private Hostname first (plus the short alias the default project
// also serves, ADR-0018), then every Machine Public Hostname — derived or
// explicit. The first name is what HostKeyAlias pins, so it stays the
// private name whenever the tenant has a DNS suffix; slice 2 of #172
// finalizes SSH naming. Without a suffix only the public names remain.
func v2MachineNames(summary tenant.Summary, project string, machine string, publicHostnames []string) []string {
	var names []string
	if suffix := strings.TrimSpace(summary.DNSSuffix); suffix != "" {
		names = append(names, machine+"."+project+"."+suffix)
		if project == naming.DefaultProjectName {
			names = append(names, machine+"."+suffix)
		}
	}
	for _, name := range publicHostnames {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// hostKeysConfig binds the hostkeys package to this tenant. privateCIDR is the
// subnet read from a live machine's own interface: a restricted tenant
// certificate cannot see the tenant bridge's config, so summary.PrivateCIDR is
// empty for v2 and only the machine can tell us. An empty CIDR disables the
// recycled-IP purge rather than guessing at a subnet.
func hostKeysConfig(config commandConfig, summary tenant.Summary, privateCIDR string) hostkeys.Config {
	if strings.TrimSpace(privateCIDR) == "" {
		privateCIDR = summary.PrivateCIDR
	}
	cidr, err := netip.ParsePrefix(strings.TrimSpace(privateCIDR))
	if err != nil {
		cidr = netip.Prefix{}
	}
	return hostkeys.Config{
		Path:   hostkeys.DefaultPath(),
		Remote: config.adminConfig.Remote,
		Tenant: summary.Tenant,
		CIDR:   cidr,
		Stderr: config.stderr,
	}
}

// machineHostKeys reads the machine's host keys authoritatively over the Incus
// API, falling back to ssh-keyscan when that channel is unavailable — a VM
// whose incus-agent has not started, most often. The bool reports whether the
// keys were merely trusted on first use.
func machineHostKeys(ctx context.Context, config commandConfig, incusProject string, machineName string, privateIP string) ([]hostkeys.Key, bool, error) {
	found, err := config.tenantCreator.MachineHostKeysV2(ctx, incusProject, machineName)
	if err == nil {
		return toHostKeys(found), false, nil
	}
	verboseCLI(config, "host key: authoritative read failed: %v", err)
	scanned, scanErr := hostkeys.Keyscan(ctx, privateIP)
	if scanErr != nil {
		return nil, false, fmt.Errorf("%w (ssh-keyscan also failed: %v)", err, scanErr)
	}
	if config.stderr != nil {
		fmt.Fprintf(config.stderr, "warning: could not read %s's host keys over the Incus API (%v)\n", machineName, err)
		fmt.Fprintf(config.stderr, "         falling back to ssh-keyscan; the keys are trusted on first use\n")
	}
	return scanned, true, nil
}

// hostKeySettleWait bounds how long connect waits for a machine to stop moving
// its host keys. It only ever elapses on a machine that is genuinely churning;
// a settled machine costs one ssh-keyscan.
const hostKeySettleWait = 60 * time.Second

// settledHostKeys reads the machine's host keys and accepts them only once sshd
// is presenting them.
//
// The Incus API read is authoritative about what is ON DISK, and on a first
// boot that is not yet what sshd is serving: cloud-init's ssh module deletes
// and regenerates every host key and restarts sshd, and sshd is listening on
// port 22 before that happens. Pinning the pre-regeneration keys with
// StrictHostKeyChecking=yes is what produced "REMOTE HOST IDENTIFICATION HAS
// CHANGED" on a machine `sc` had itself just created — and reading mid-delete
// can even yield a partial set (ed25519 + ecdsa, no rsa).
//
// So the read is cross-checked against what port 22 actually offers before it
// is trusted. The scan is never used as a key source here — it decides only
// whether the authoritative read has stopped changing.
func settledHostKeys(ctx context.Context, config commandConfig, incusProject string, machineName string, privateIP string) ([]hostkeys.Key, bool, error) {
	deadline := time.Now().Add(hostKeySettleWait)
	announced := false
	for {
		keys, tofu, err := machineHostKeys(ctx, config, incusProject, machineName, privateIP)
		// The keyscan fallback already reports what the wire serves, so there is
		// nothing left to cross-check.
		if err != nil || tofu {
			return keys, tofu, err
		}
		scanned, scanErr := hostkeys.Keyscan(ctx, privateIP)
		if scanErr != nil {
			verboseCLI(config, "host key: could not confirm %s over port 22 (%v); trusting the Incus API read", privateIP, scanErr)
			return keys, false, nil
		}
		disagreement := hostKeyDisagreement(keys, scanned)
		if disagreement == "" {
			return keys, false, nil
		}
		if !time.Now().Before(deadline) {
			if config.stderr != nil {
				fmt.Fprintf(config.stderr, "warning: %s still disagrees with its own SSH host keys after %s (%s)\n",
					machineName, hostKeySettleWait, disagreement)
			}
			return keys, false, nil
		}
		if !announced {
			announced = true
			if config.stderr != nil {
				fmt.Fprintf(config.stderr, "waiting for %s to settle its SSH host keys (cloud-init regenerates them on first boot)\n", machineName)
			}
		}
		verboseCLI(config, "host key: %s not settled yet (%s)", machineName, disagreement)
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// hostKeyDisagreement compares what sshd offers against what was read from the
// machine's filesystem and describes the first mismatch, or "" when they agree.
// A key type the scan reports but the read missed counts as a mismatch: that is
// exactly what a half-regenerated /etc/ssh looks like.
func hostKeyDisagreement(authoritative []hostkeys.Key, scanned []hostkeys.Key) string {
	onDisk := make(map[string]string, len(authoritative))
	for _, key := range authoritative {
		onDisk[key.Type] = key.Key
	}
	for _, key := range scanned {
		recorded, ok := onDisk[key.Type]
		if !ok {
			return "sshd offers a " + key.Type + " key that /etc/ssh did not yield"
		}
		if recorded != key.Key {
			return "the " + key.Type + " key on port 22 is not the one in /etc/ssh"
		}
	}
	return ""
}

// waitForCloudInitV2 blocks until cloud-init has finished its run for this boot,
// because until it has, the machine's SSH host keys are not final. A machine
// whose state cannot be read (a VM without incus-agent) or whose image ships no
// cloud-init returns immediately.
func waitForCloudInitV2(ctx context.Context, config commandConfig, incusProject string, machineName string, deadline time.Time) {
	announced := false
	for {
		done, err := config.tenantCreator.MachineCloudInitDoneV2(ctx, incusProject, machineName)
		if err != nil {
			verboseCLI(config, "cloud-init: cannot read %s's state (%v); not waiting", machineName, err)
			return
		}
		if done {
			return
		}
		if !time.Now().Before(deadline) {
			if config.stderr != nil {
				fmt.Fprintf(config.stderr, "warning: cloud-init is still running on %s; its SSH host keys may change under this session\n", machineName)
			}
			return
		}
		if !announced {
			announced = true
			fmt.Fprintf(config.stdout, "Waiting for cloud-init to finish on %s...\n", machineName)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func toHostKeys(found []incusx.HostKey) []hostkeys.Key {
	keys := make([]hostkeys.Key, 0, len(found))
	for _, key := range found {
		keys = append(keys, hostkeys.Key{Type: key.Type, Key: key.Key})
	}
	return keys
}

// ensureV2HostKey makes ~/.ssh/known_hosts tell the truth about this machine,
// so the SSH session that follows can demand StrictHostKeyChecking=yes. It
// reclaims the machine's names from stale untagged entries and purges recycled
// private-IP debris. Returns false when no key could be obtained at all, in
// which case the caller must fall back to accept-new.
func ensureV2HostKey(ctx context.Context, config commandConfig, summary tenant.Summary, project string, machineName string, publicHostnames []string, privateIP string, privateCIDR string) bool {
	names := v2MachineNames(summary, project, machineName, publicHostnames)
	keysConfig := hostKeysConfig(config, summary, privateCIDR)
	if len(names) == 0 || keysConfig.Path == "" {
		verboseCLI(config, "host key: no hostname or known_hosts path; leaving host key handling to ssh")
		return false
	}
	if !keysConfig.CIDR.IsValid() {
		verboseCLI(config, "host key: no private CIDR for %s; skipping recycled-IP purge", summary.Tenant)
	}
	keys, tofu, err := settledHostKeys(ctx, config, summary.V2IncusProjectName(project), machineName, privateIP)
	if err != nil {
		if config.stderr != nil {
			fmt.Fprintf(config.stderr, "warning: could not determine %s's host keys: %v\n", machineName, err)
		}
		return false
	}
	plan, err := keysConfig.Ensure(hostkeys.Machine{Names: names, Keys: keys, TOFU: tofu})
	if err != nil {
		if config.stderr != nil {
			fmt.Fprintf(config.stderr, "warning: could not update %s: %v\n", keysConfig.Path, err)
		}
		return false
	}
	reportHostKeyPlan(config, plan)
	if err := plan.Apply(); err != nil {
		if config.stderr != nil {
			fmt.Fprintf(config.stderr, "warning: could not write %s: %v\n", keysConfig.Path, err)
		}
		return false
	}
	return true
}

// reportHostKeyPlan prints every line sc is about to remove or rewrite. The
// file belongs to the user; deletions from it are never silent.
func reportHostKeyPlan(config commandConfig, plan hostkeys.Plan) {
	if config.stderr == nil {
		return
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(config.stderr, "warning: %s\n", warning)
	}
	if plan.PurgeSkipped != "" {
		fmt.Fprintf(config.stderr, "note: %s\n", plan.PurgeSkipped)
	}
	for _, change := range plan.Changes {
		if change.Action == hostkeys.ActionAdd {
			verboseCLI(config, "known_hosts: %s", change)
			continue
		}
		fmt.Fprintf(config.stderr, "known_hosts: %s\n", change)
	}
}
