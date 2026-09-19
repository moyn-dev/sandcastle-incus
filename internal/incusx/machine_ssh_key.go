package incusx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
	"github.com/thieso2/sandcastle-incus/internal/machine"
	"github.com/thieso2/sandcastle-incus/internal/meta"
	"github.com/thieso2/sandcastle-incus/internal/naming"
	tenant "github.com/thieso2/sandcastle-incus/internal/tenant"
)

type MachineSSHKeyReconciler struct {
	Remote     string
	ConfigPath string
	Store      machine.Store
	Server     MachineSSHKeyServer
}

type MachineSSHKeyServer interface {
	UseProject(name string) MachineSSHKeyResourceServer
}

type MachineSSHKeyResourceServer interface {
	ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error)
}

func NewMachineSSHKeyReconciler(remote string, store machine.Store) MachineSSHKeyReconciler {
	return MachineSSHKeyReconciler{Remote: remote, Store: store}
}

func NewMachineSSHKeyReconcilerForServer(server incus.InstanceServer, store machine.Store) MachineSSHKeyReconciler {
	return MachineSSHKeyReconciler{Server: sdkMachineSSHKeyServer{inner: server}, Store: store}
}

func (r MachineSSHKeyReconciler) ReconcileUserSSHKey(ctx context.Context, summary tenant.Summary, userKey string, publicKey string) error {
	if strings.TrimSpace(publicKey) == "" {
		return fmt.Errorf("User SSH Public Key is required")
	}
	store := r.Store
	if store == nil {
		return fmt.Errorf("machine store is not configured")
	}
	machines, err := store.ListMachines(ctx, summary)
	if err != nil {
		return err
	}
	if len(machines) == 0 {
		return nil
	}
	server, err := r.server()
	if err != nil {
		return err
	}
	_, err = r.reconcileV2(ctx, server, summary, userKey, publicKey, machines)
	return err
}

// ReconcileMachineUserSSHKey enrols the current User SSH Public Key on one
// Machine and returns the keys authorized_keys then holds (one `ssh-keygen -l`
// line per key). It is the narrow repair used before a CLI connection: a stale
// project profile must never lock the user out of the Machine it just created.
// It is strictly additive — no key already in the file is removed or replaced.
func (r MachineSSHKeyReconciler) ReconcileMachineUserSSHKey(ctx context.Context, summary tenant.Summary, project, machine, userKey, publicKey string) ([]string, error) {
	if strings.TrimSpace(publicKey) == "" {
		return nil, fmt.Errorf("User SSH Public Key is required")
	}
	store := r.Store
	if store == nil {
		return nil, fmt.Errorf("machine store is not configured")
	}
	machines, err := store.ListMachines(ctx, summary)
	if err != nil {
		return nil, err
	}
	project = strings.TrimSpace(project)
	filtered := machines[:0]
	for _, managed := range machines {
		name := strings.TrimSpace(managed.Project)
		if name == "" {
			name = naming.DefaultProjectName
		}
		if name == project && managed.Name == strings.TrimSpace(machine) {
			filtered = append(filtered, managed)
		}
	}
	if len(filtered) == 0 {
		return nil, nil
	}
	server, err := r.server()
	if err != nil {
		return nil, err
	}
	return r.reconcileV2(ctx, server, summary, userKey, publicKey, filtered)
}

// reconcileV2 adds the key to each v2 project's shared /home and returns the
// enrolled-key listing of every project it reached. It uses one available
// Machine per project; broad login reconciliation is best-effort, while
// targeted repairs use ReconcileMachineUserSSHKey above.
func (r MachineSSHKeyReconciler) reconcileV2(ctx context.Context, server MachineSSHKeyServer, summary tenant.Summary, userKey string, publicKey string, machines []meta.Machine) ([]string, error) {
	byProject := map[string][]meta.Machine{}
	order := []string{}
	for _, managed := range machines {
		project := strings.TrimSpace(managed.Project)
		if project == "" {
			project = naming.DefaultProjectName
		}
		if _, seen := byProject[project]; !seen {
			order = append(order, project)
		}
		byProject[project] = append(byProject[project], managed)
	}
	var failures []error
	var enrolled []string
	for _, project := range order {
		projectServer := server.UseProject(summary.V2IncusProjectName(project))
		var lastErr error
		reconciled := false
		for _, managed := range byProject[project] {
			if !managed.Running {
				continue
			}
			listing, err := r.reconcileMachine(ctx, projectServer, managed.Name, managed, v2LoginUser(summary, managed, userKey), publicKey)
			if err != nil {
				lastErr = err
				continue
			}
			enrolled = append(enrolled, listing...)
			reconciled = true
			break
		}
		if !reconciled && lastErr != nil {
			failures = append(failures, lastErr)
		}
	}
	return enrolled, errors.Join(failures...)
}

// v2LoginUser resolves the Unix account whose authorized_keys must carry the
// key. v2 machine listings do not populate LinuxUser, and the GitHub user key is
// NOT a Unix account on the machine — falling back to it silently wrote to
// /home/<github-user>, which does not exist.
func v2LoginUser(summary tenant.Summary, managed meta.Machine, userKey string) string {
	if user := strings.TrimSpace(managed.LinuxUser); user != "" {
		return user
	}
	if user := strings.TrimSpace(summary.UnixUser); user != "" {
		return user
	}
	return userKey
}

// reconcileMachine enrols the key on one machine and returns the resulting
// authorized_keys listing. The script is ADDITIVE: it never strips a line —
// not a hand-added key, not an older Sandcastle key. A key already present
// anywhere in the file is left where it is; a missing one is inserted inside
// the marker block (before its end marker, or as a new block at the end) so
// RevokeUserSSHKey can still drop every Sandcastle-managed key at once. The
// listing is `ssh-keygen -l` over the whole file (raw key lines when
// ssh-keygen is missing), so the operator sees every enrolled key, not only
// the one just written.
func (r MachineSSHKeyReconciler) reconcileMachine(ctx context.Context, server MachineSSHKeyResourceServer, instanceName string, managed meta.Machine, userKey string, publicKey string) ([]string, error) {
	linuxUser := managed.LinuxUser
	if strings.TrimSpace(linuxUser) == "" {
		linuxUser = userKey
	}
	script := strings.Join([]string{
		"set -eu",
		`user="${SANDCASTLE_USER:?}"`,
		`key="${SANDCASTLE_SSH_PUBLIC_KEY:?}"`,
		`home="$(getent passwd "$user" | cut -d: -f6)"`,
		`if [ -z "$home" ]; then home="/home/$user"; fi`,
		`ssh_dir="$home/.ssh"`,
		`auth="$ssh_dir/authorized_keys"`,
		`tmp="$auth.tmp"`,
		`install -d -m 0700 -o "$user" -g "$user" "$ssh_dir"`,
		`if [ ! -f "$auth" ]; then install -m 0600 -o "$user" -g "$user" /dev/null "$auth"; fi`,
		`if ! grep -qxF "$key" "$auth"; then`,
		`  if grep -qxF '# sandcastle user ssh key end' "$auth"; then`,
		`    awk -v key="$key" '$0 == "# sandcastle user ssh key end" { print key } { print }' "$auth" > "$tmp"`,
		`  else`,
		`    cat "$auth" > "$tmp"`,
		`    printf '%s\n%s\n%s\n' '# sandcastle user ssh key begin' "$key" '# sandcastle user ssh key end' >> "$tmp"`,
		`  fi`,
		`  install -m 0600 -o "$user" -g "$user" "$tmp" "$auth"`,
		`  rm -f "$tmp"`,
		`fi`,
		`if command -v ssh-keygen >/dev/null 2>&1; then ssh-keygen -lf "$auth"; else grep -v '^#' "$auth" | grep -v '^$'; fi`,
	}, "\n")
	var stdout, stderr bytes.Buffer
	dataDone := make(chan bool)
	op, err := server.ExecInstance(instanceName, api.InstanceExecPost{
		Command: []string{"/bin/sh", "-c", script},
		Environment: map[string]string{
			"SANDCASTLE_USER":           linuxUser,
			"SANDCASTLE_SSH_PUBLIC_KEY": strings.TrimSpace(publicKey),
		},
		WaitForWS: true,
	}, &incus.InstanceExecArgs{
		Stdin:    strings.NewReader(""),
		Stdout:   &stdout,
		Stderr:   &stderr,
		DataDone: dataDone,
	})
	if err != nil {
		return nil, fmt.Errorf("reconcile User SSH Public Key on machine %s: %w", instanceName, err)
	}
	if err := op.Wait(); err != nil {
		return nil, fmt.Errorf("wait for User SSH Public Key reconciliation on machine %s: %w", instanceName, err)
	}
	<-dataDone
	// op.Wait() only reports whether the exec could RUN; a non-zero script exit
	// is reported in the operation metadata. Without this check a failed write
	// (e.g. the target Unix user does not exist) looked like success.
	if code := execReturnCode(op); code != 0 {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return nil, fmt.Errorf("reconcile User SSH Public Key on machine %s: script exited %d: %s", instanceName, code, detail)
		}
		return nil, fmt.Errorf("reconcile User SSH Public Key on machine %s: script exited %d", instanceName, code)
	}
	var listing []string
	for _, line := range strings.Split(stdout.String(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			listing = append(listing, line)
		}
	}
	return listing, nil
}

// execReturnCode reads the exit status an Incus exec operation records in its
// metadata ("return"). A missing value means the operation carried no exit
// status; treat that as success rather than inventing a failure.
func execReturnCode(op incus.Operation) int {
	if op == nil {
		return 0
	}
	metadata := op.Get().Metadata
	if metadata == nil {
		return 0
	}
	value, ok := metadata["return"]
	if !ok {
		return 0
	}
	switch code := value.(type) {
	case float64:
		return int(code)
	case int:
		return code
	case int64:
		return int(code)
	}
	return 0
}

func (r MachineSSHKeyReconciler) server() (MachineSSHKeyServer, error) {
	if r.Server != nil {
		return r.Server, nil
	}
	loaded, err := LoadCLIConfig(r.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load Incus config: %w", err)
	}
	remote := r.Remote
	if remote == "" {
		remote = loaded.DefaultRemote
	}
	server, err := connectInstanceServer(loaded, remote)
	if err != nil {
		return nil, fmt.Errorf("connect to Incus remote %q: %w", remote, err)
	}
	return sdkMachineSSHKeyServer{inner: server}, nil
}

type sdkMachineSSHKeyServer struct {
	inner incus.InstanceServer
}

func (s sdkMachineSSHKeyServer) UseProject(name string) MachineSSHKeyResourceServer {
	return sdkMachineSSHKeyResourceServer{inner: s.inner.UseProject(name)}
}

type sdkMachineSSHKeyResourceServer struct {
	inner incus.InstanceServer
}

func (s sdkMachineSSHKeyResourceServer) ExecInstance(instanceName string, exec api.InstanceExecPost, args *incus.InstanceExecArgs) (incus.Operation, error) {
	return s.inner.ExecInstance(instanceName, exec, args)
}

// RevokeUserSSHKey removes the marker-delimited Sandcastle key block from every
// machine in the tenant. Called when a user is de-allowlisted or loses tenant
// access. Like the reconcile path it writes once per project (a v2 project's
// machines share one /home volume) and skips machines that are not running.
func (r MachineSSHKeyReconciler) RevokeUserSSHKey(ctx context.Context, summary tenant.Summary, userKey string) error {
	store := r.Store
	if store == nil {
		return fmt.Errorf("machine store is not configured")
	}
	machines, err := store.ListMachines(ctx, summary)
	if err != nil {
		return err
	}
	if len(machines) == 0 {
		return nil
	}
	server, err := r.server()
	if err != nil {
		return err
	}
	byProject := map[string][]meta.Machine{}
	order := []string{}
	for _, managed := range machines {
		project := strings.TrimSpace(managed.Project)
		if project == "" {
			project = naming.DefaultProjectName
		}
		if _, seen := byProject[project]; !seen {
			order = append(order, project)
		}
		byProject[project] = append(byProject[project], managed)
	}
	var failures []error
	for _, project := range order {
		projectServer := server.UseProject(summary.V2IncusProjectName(project))
		var lastErr error
		revoked := false
		for _, managed := range byProject[project] {
			if !managed.Running {
				continue
			}
			if err := r.revokeMachine(ctx, projectServer, managed.Name, v2LoginUser(summary, managed, userKey)); err != nil {
				lastErr = err
				continue
			}
			revoked = true
			break
		}
		if !revoked && lastErr != nil {
			// Keep going, same as reconcileV2: an unrevokable project must not
			// leave the key standing in every project after it.
			failures = append(failures, lastErr)
		}
	}
	return errors.Join(failures...)
}

func (r MachineSSHKeyReconciler) revokeMachine(ctx context.Context, server MachineSSHKeyResourceServer, instanceName string, linuxUser string) error {
	script := strings.Join([]string{
		"set -eu",
		`user="${SANDCASTLE_USER:?}"`,
		`home="$(getent passwd "$user" | cut -d: -f6)"`,
		`if [ -z "$home" ]; then home="/home/$user"; fi`,
		`auth="$home/.ssh/authorized_keys"`,
		`[ -e "$auth" ] || exit 0`,
		`tmp="$auth.tmp"`,
		`awk '/^# sandcastle user ssh key begin$/ {skip=1; next} /^# sandcastle user ssh key end$/ {skip=0; next} !skip {print}' "$auth" > "$tmp"`,
		`install -m 0600 -o "$user" -g "$user" "$tmp" "$auth"`,
		`rm -f "$tmp"`,
	}, "\n")
	dataDone := make(chan bool)
	op, err := server.ExecInstance(instanceName, api.InstanceExecPost{
		Command:     []string{"/bin/sh", "-c", script},
		Environment: map[string]string{"SANDCASTLE_USER": linuxUser},
		WaitForWS:   true,
	}, &incus.InstanceExecArgs{Stdin: strings.NewReader(""), DataDone: dataDone})
	if err != nil {
		return fmt.Errorf("revoke User SSH Public Key on machine %s: %w", instanceName, err)
	}
	if err := op.Wait(); err != nil {
		return fmt.Errorf("wait for User SSH Public Key revocation on machine %s: %w", instanceName, err)
	}
	<-dataDone
	if code := execReturnCode(op); code != 0 {
		return fmt.Errorf("revoke User SSH Public Key on machine %s: script exited %d", instanceName, code)
	}
	return nil
}
