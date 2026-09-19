package incusx

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

// MachineSudoStatus is what ReconcileMachineSudo found or did.
type MachineSudoStatus struct {
	// State is "current" (rule present, sudo works), "updated" (rule and/or
	// group membership restored), or "needs-fix" (checkOnly and something is
	// missing or `sudo -n true` fails).
	State string
	// Detail is the script's explanation when State is not "current".
	Detail string
}

// machineSudoScript restores the login user's passwordless sudo — the rule
// cloud-init writes to /etc/sudoers.d/90-cloud-init-users at first boot and
// the `sudo` group membership it grants. Every other `sc fix` fixup runs
// `sudo sh -s` over SSH, so a machine that lost this rule (a sudo-rs machine
// answers `I'm sorry <user>. I'm afraid I can't do that`) cannot be repaired
// over SSH at all; this runs as root over the Incus API instead. It is
// additive: an existing sudoers file is appended to, never rewritten, and a
// candidate file is `visudo -c`hecked before it is moved into place. The
// final `sudo -n true` as the login user proves the result rather than
// trusting the file.
const machineSudoScript = `set -eu
user="${SANDCASTLE_USER:?}"
check="${SANDCASTLE_CHECK_ONLY:-0}"
rule="$user ALL=(ALL) NOPASSWD:ALL"
file=/etc/sudoers.d/90-cloud-init-users
if ! getent passwd "$user" >/dev/null 2>&1; then
  echo "login user $user does not exist on this machine"
  exit 3
fi
state=current
detail=""
if getent group sudo >/dev/null 2>&1 && ! id -nG "$user" | tr ' ' '\n' | grep -qx sudo; then
  if [ "$check" = 1 ]; then state=needs-fix; detail="$user is not in group sudo"
  else usermod -aG sudo "$user"; state=updated; detail="added $user to group sudo"; fi
fi
if ! grep -qsxF "$rule" "$file"; then
  if [ "$check" = 1 ]; then state=needs-fix; detail="${detail:+$detail; }$file lacks '$rule'"
  else
    mkdir -p /etc/sudoers.d
    tmp="$file.sc-tmp"
    { cat "$file" 2>/dev/null || true; printf '%s\n' "$rule"; } > "$tmp"
    chmod 0440 "$tmp"
    if command -v visudo >/dev/null 2>&1; then visudo -cf "$tmp" >/dev/null; fi
    mv "$tmp" "$file"
    state=updated; detail="${detail:+$detail; }wrote '$rule' to $file"
  fi
fi
if [ "$state" != needs-fix ]; then
  if ! su -s /bin/sh "$user" -c 'sudo -n true' >/dev/null 2>&1; then
    if [ "$check" = 1 ]; then state=needs-fix; detail="${detail:+$detail; }sudo -n true still fails for $user"
    else echo "sudo -n true still fails for $user after restoring $file"; exit 4; fi
  fi
fi
echo "$state"
echo "$detail"
`

// ReconcileMachineSudo restores (or, with checkOnly, only checks) the login
// user's NOPASSWD sudo rule on one Machine over the Incus API.
func (r MachineSSHKeyReconciler) ReconcileMachineSudo(ctx context.Context, summary tenant.Summary, project, machine, userKey string, checkOnly bool) (MachineSudoStatus, error) {
	store := r.Store
	if store == nil {
		return MachineSudoStatus{}, fmt.Errorf("machine store is not configured")
	}
	machines, err := store.ListMachines(ctx, summary)
	if err != nil {
		return MachineSudoStatus{}, err
	}
	project = strings.TrimSpace(project)
	machine = strings.TrimSpace(machine)
	for _, managed := range machines {
		name := strings.TrimSpace(managed.Project)
		if name == "" {
			name = naming.DefaultProjectName
		}
		if name != project || managed.Name != machine {
			continue
		}
		if managed.Bare {
			return MachineSudoStatus{State: "current", Detail: "bare machine has no login user"}, nil
		}
		if !managed.Running {
			return MachineSudoStatus{}, fmt.Errorf("machine %s is not running", machine)
		}
		server, err := r.server()
		if err != nil {
			return MachineSudoStatus{}, err
		}
		resource := server.UseProject(summary.V2IncusProjectName(project))
		env := map[string]string{"SANDCASTLE_USER": v2LoginUser(summary, managed, userKey)}
		if checkOnly {
			env["SANDCASTLE_CHECK_ONLY"] = "1"
		}
		var stdout, stderr bytes.Buffer
		dataDone := make(chan bool)
		op, err := resource.ExecInstance(machine, api.InstanceExecPost{
			Command:     []string{"/bin/sh", "-c", machineSudoScript},
			Environment: env,
			WaitForWS:   true,
		}, &incus.InstanceExecArgs{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr, DataDone: dataDone})
		if err != nil {
			return MachineSudoStatus{}, fmt.Errorf("restore sudo on machine %s: %w", machine, err)
		}
		if err := op.Wait(); err != nil {
			return MachineSudoStatus{}, fmt.Errorf("wait for sudo restore on machine %s: %w", machine, err)
		}
		<-dataDone
		if code := execReturnCode(op); code != 0 {
			detail := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
			return MachineSudoStatus{}, fmt.Errorf("restore sudo on machine %s: script exited %d: %s", machine, code, detail)
		}
		lines := strings.SplitN(strings.TrimRight(stdout.String(), "\n"), "\n", 2)
		status := MachineSudoStatus{State: strings.TrimSpace(lines[0])}
		if len(lines) > 1 {
			status.Detail = strings.TrimSpace(lines[1])
		}
		if status.State == "" {
			status.State = "current"
		}
		return status, nil
	}
	return MachineSudoStatus{}, fmt.Errorf("machine %s not found in project %s", machine, project)
}
