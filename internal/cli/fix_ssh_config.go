package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The ssh-key fixup also teaches the LOCAL ssh client about the machine: a
// marker-delimited Host block in ~/.ssh/config that pins the CLI key, the
// login user and the host-key alias, so a bare `ssh <machine-fqdn>` or
// `ssh <private-ip>` behaves exactly like `sc connect` instead of offering
// ~/.ssh/id_* (which the machine never enrolled) and falling back to a
// password prompt. One block per machine, replaced in place on every run and
// never touching anything outside its own markers.

const sshConfigMarkerPrefix = "# sandcastle machine "

func sshConfigBlockTag(remote, project, machine string) string {
	return strings.TrimSpace(remote) + ":" + strings.TrimSpace(project) + ":" + strings.TrimSpace(machine)
}

func sshConfigBeginMarker(tag string) string { return sshConfigMarkerPrefix + tag + " begin" }
func sshConfigEndMarker(tag string) string   { return sshConfigMarkerPrefix + tag + " end" }

// renderSSHConfigBlock builds the managed Host block. names[0] is the Machine
// Private Hostname and doubles as HostKeyAlias, matching the argv `sc connect`
// builds, so the known_hosts line connect already pinned is what a bare ssh
// verifies against — no "authenticity can't be established" prompt for the
// recycled private IP either.
func renderSSHConfigBlock(tag string, names []string, privateIP, loginUser, identityFile string) string {
	patterns := append([]string{}, names...)
	if ip := strings.TrimSpace(privateIP); ip != "" {
		patterns = append(patterns, ip)
	}
	var b strings.Builder
	b.WriteString(sshConfigBeginMarker(tag) + "\n")
	b.WriteString("# managed by `sc fix --only ssh-key`; edits inside the markers are overwritten\n")
	b.WriteString("Host " + strings.Join(patterns, " ") + "\n")
	if user := strings.TrimSpace(loginUser); user != "" {
		b.WriteString("    User " + user + "\n")
	}
	b.WriteString("    IdentityFile " + identityFile + "\n")
	b.WriteString("    IdentitiesOnly yes\n")
	if len(names) > 0 {
		b.WriteString("    HostKeyAlias " + names[0] + "\n")
		b.WriteString("    CheckHostIP no\n")
	}
	b.WriteString(sshConfigEndMarker(tag) + "\n")
	return b.String()
}

// upsertSSHConfigBlock replaces the block tagged `tag` (wherever it sits) and
// puts the fresh one at the TOP of the file: ssh takes the first value it
// obtains for an option, so a managed block must precede any `Host *` the
// user keeps below it. Everything outside the markers is preserved verbatim.
func upsertSSHConfigBlock(existing, tag, block string) (string, bool) {
	begin, end := sshConfigBeginMarker(tag), sshConfigEndMarker(tag)
	lines := strings.Split(existing, "\n")
	kept := make([]string, 0, len(lines))
	skipping := false
	for _, line := range lines {
		switch {
		case !skipping && strings.TrimSpace(line) == begin:
			skipping = true
		case skipping && strings.TrimSpace(line) == end:
			skipping = false
		case !skipping:
			kept = append(kept, line)
		}
	}
	rest := strings.TrimLeft(strings.Join(kept, "\n"), "\n")
	updated := block
	if strings.TrimSpace(rest) != "" {
		updated += "\n" + rest
	}
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	return updated, updated != existing
}

func defaultSSHConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "config")
}

// syncLocalSSHConfig writes the block into path (created 0600 if missing).
// It returns "current", "updated", or — under checkOnly — "NEEDS FIX".
func syncLocalSSHConfig(path, tag, block string, checkOnly bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("cannot resolve ~/.ssh/config")
	}
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	updated, changed := upsertSSHConfigBlock(string(existing), tag, block)
	if !changed {
		return "current", nil
	}
	if checkOnly {
		return "NEEDS FIX", nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".sc-tmp"
	if err := os.WriteFile(tmp, []byte(updated), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("replace %s: %w", path, err)
	}
	return "updated", nil
}

// tildePath renders a path under $HOME as ~/…, which is what ssh_config
// expects and what a human recognises.
func tildePath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
		return "~/" + filepath.ToSlash(rel)
	}
	return path
}
