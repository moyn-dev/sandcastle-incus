package tenant

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/thieso2/sandcastle-incus/internal/certs"
	"github.com/thieso2/sandcastle-incus/internal/cidr"
	"github.com/thieso2/sandcastle-incus/internal/config"
	"github.com/thieso2/sandcastle-incus/internal/dns"
	domainrules "github.com/thieso2/sandcastle-incus/internal/domain"
	"github.com/thieso2/sandcastle-incus/internal/naming"
)

// V2DefaultProfileUserData renders the cloud-init user-data baked into a v2
// project's default profile. Freeform `incus launch` of a cloud-init image
// applies it at first boot, creating the login user (UID 2000, sudo) with the
// tenant's SSH key and an enabled sshd — so machines are reachable over the
// tenant's tailnet with no Sandcastle-in-the-loop configure step.
//
// When project and suffix are known the user-data is a jinja template that
// stamps each machine with its canonical Machine Private Hostname
// <machine>.<project>.<suffix> (ADR-0018) — identity only; resolution comes
// from the sidecar CoreDNS zone.
func V2DefaultProfileUserData(user string, sshKey string, project string, suffix string, signerURL string) string {
	return V2ProfileUserData(user, sshKey, project, suffix, "", signerURL)
}

// V2ProfileUserData is V2DefaultProfileUserData with the project's Project
// Domain (ADR-0028). The machine's identity is ALWAYS its Machine Private
// Hostname <machine>.<project>.<suffix> — a Project Domain changes nothing
// about who the machine is; it only seeds the machine's public-name set:
// machine.env's PUBLIC_HOSTNAMES line lists the derived
// <machine>.<projectDomain> (when the project has a domain) and whatever the
// instance's KeyV2PublicHostnames record says, read through cloud-init's
// datasource at first boot (see PublicHostnamesEnvLine). caddy-setup serves
// the private name from the sidecar leaf and one site block per public name
// once the Auth App has pushed its certificate.
func V2ProfileUserData(user string, sshKey string, project string, suffix string, projectDomain string, signerURL string) string {
	header := "#cloud-config\n"
	identity := ""
	project = strings.TrimSpace(project)
	suffix = strings.TrimSpace(suffix)
	projectDomain = strings.TrimSpace(projectDomain)
	signerURL = strings.TrimRight(strings.TrimSpace(signerURL), "/")
	jinja := project != "" && suffix != ""
	if jinja {
		header = "## template: jinja\n#cloud-config\n"
		identity = fmt.Sprintf("fqdn: {{ v1.local_hostname }}.%s.%s\nprefer_fqdn_over_hostname: true\n", project, suffix)
	}
	body := fmt.Sprintf(`users:
  - name: %s
    uid: 2000
    groups: [sudo]
    shell: /bin/zsh
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - %s
packages:
  - openssh-server
  - zsh
`, user, sshKey)

	// Machines carry only stable /.sc shims (ADR-0022): scShimWriteFiles bakes
	// thin, guarded sourcing stubs at the fixed OS paths; the actual platform
	// scripts (agent-forwarding first) live on the shared /.sc volume and are
	// updated centrally. Ships in both branches so the shims work with or
	// without ingress.

	// Caddy HTTPS ingress (ADR-0011): only when we know the machine's identity
	// (jinja) and where to fetch its leaf (the sidecar signer). What gets baked
	// is only the stable boot SHIMS (base64 to sidestep YAML/indentation
	// pitfalls) — the caddy-setup and generalize bodies ship in the /.sc
	// platform payload (ADR-0022) and update centrally. machine.env stays
	// per-machine: it carries this machine's FQDN (jinja), its public-name
	// seed, and the signer URL.
	if jinja && signerURL != "" {
		script := base64.StdEncoding.EncodeToString([]byte(SCCaddySetupShim))
		generalize := base64.StdEncoding.EncodeToString([]byte(SCGeneralizeShim))
		body += "write_files:\n" + scShimWriteFiles + fmt.Sprintf(`  - path: /etc/sandcastle/machine.env
    permissions: '0644'
    content: |
      FQDN={{ v1.local_hostname }}.%s.%s
      %s
      SIGNER=%s
      HOME=/home/%s
  - path: /usr/local/sbin/sandcastle-generalize
    permissions: '0755'
    encoding: b64
    content: %s
  - path: /usr/local/sbin/sandcastle-caddy-setup
    permissions: '0755'
    encoding: b64
    content: %s
runcmd:
  - [/usr/local/sbin/sandcastle-generalize]
  - [systemctl, enable, --now, ssh]
  - [/usr/local/sbin/sandcastle-caddy-setup]
`, project, suffix, PublicHostnamesEnvLine(projectDomain), signerURL, user, generalize, script)
		return header + identity + body
	}

	return header + identity + body + "write_files:\n" + scShimWriteFiles + `runcmd:
  - [systemctl, enable, --now, ssh]
`
}

// PublicHostnamesEnvKey is the machine.env variable caddy-setup seeds
// /etc/sandcastle/hostnames from at first boot: a comma-separated list of
// the machine's Machine Public Hostnames.
const PublicHostnamesEnvKey = "PUBLIC_HOSTNAMES"

// publicHostnamesInstanceKeyExpr is the jinja expression that reads the
// instance's KeyV2PublicHostnames record (the sorted, comma-separated set
// `sc create` stamps and the Auth App rewrites) through cloud-init's LXD/Incus
// datasource, which exposes every `user.*` instance key under ds.config. It
// degrades to "" on a datasource without ds.config or an unstamped instance
// (a Freeform Machine): the reconciler pushes the hostnames file afterwards
// either way. The key name is spelled out rather than imported from meta —
// tenant must not depend on meta.
const publicHostnamesInstanceKeyExpr = "{{ ds.config['user.sandcastle.v2.public-hostnames'] | default('') if ds is defined and ds.config is defined else '' }}"

// publicHostnamesInstanceKeyTailExpr is the same record rendered as ",<record>"
// — or nothing when the record is absent or empty — for joining behind the
// derived name without leaving a trailing comma (the live run saw
// `PUBLIC_HOSTNAMES=m1.dbg…,` on an unstamped instance; harmless after
// normalization, but the seed should read cleanly).
const publicHostnamesInstanceKeyTailExpr = "{{ ',' ~ ds.config['user.sandcastle.v2.public-hostnames'] if ds is defined and ds.config is defined and ds.config['user.sandcastle.v2.public-hostnames'] | default('') else '' }}"

// PublicHostnamesEnvLine renders machine.env's PUBLIC_HOSTNAMES= line for a
// project: the derived <machine>.<projectDomain> (jinja, when the project has
// a domain) joined with the instance record. caddy-setup normalizes and
// deduplicates the list, so the derived name appearing in both is harmless —
// naming it explicitly here keeps a project with a domain correct even where
// the datasource lookup yields nothing.
func PublicHostnamesEnvLine(projectDomain string) string {
	projectDomain = strings.Trim(strings.TrimSpace(projectDomain), ".")
	if projectDomain == "" {
		return PublicHostnamesEnvKey + "=" + publicHostnamesInstanceKeyExpr
	}
	return PublicHostnamesEnvKey + "={{ v1.local_hostname }}." + projectDomain + publicHostnamesInstanceKeyTailExpr
}

// publicHostnamesEnvLinePattern reads a rendered profile's PUBLIC_HOSTNAMES=
// line back verbatim (incusx hands it to the bare document, so a bare
// machine's seed is exactly its siblings').
var publicHostnamesEnvLinePattern = regexp.MustCompile(`(?m)^\s*(` + PublicHostnamesEnvKey + `=.*?)\s*$`)

// PublicHostnamesEnvLineOf returns the PUBLIC_HOSTNAMES= line of a rendered
// cloud-init document, or the private-project default when the document
// predates the line (a profile rendered by an older binary).
func PublicHostnamesEnvLineOf(userData string) string {
	if match := publicHostnamesEnvLinePattern.FindStringSubmatch(userData); match != nil {
		return match[1]
	}
	return PublicHostnamesEnvLine("")
}

// BareMachineHome is the $HOME a bare machine hands to the caddy-setup script.
// The Caddyfile serves $HOME at /_h, and a bare machine has no login user whose
// home could go there. /srv exists on every Debian-family image and is empty, so
// the handler answers 404 rather than the Caddyfile failing to load.
const BareMachineHome = "/srv"

// V2BareUserData renders the cloud-init user-data of a BARE machine
// (`sc create --bare`): one that boots with its canonical Machine Private
// Hostname and serves HTTPS with a tenant-CA leaf (plus its public names once
// their certificates land), and nothing else — no login user, no SSH key, no
// sshd, no shell shims.
//
// It is deliberately V2DefaultProfileUserData minus the interactive half, and
// reuses the very same boot shims, so a bare machine tracks /.sc platform
// payload updates like every other machine (ADR-0022). It is applied as
// INSTANCE config, overriding the project default profile's user-data, which is
// why it must re-state the identity: domain is "<project>.<suffix>" and
// signerURL the sidecar leaf signer, both read back off that same profile so a
// bare machine can never disagree with its project about who it is.
func V2BareUserData(domain string, signerURL string) string {
	return V2BareUserDataWithPublicHostnames(domain, signerURL, "")
}

// V2BareUserDataWithPublicHostnames is V2BareUserData with the project's
// public-name seed (ADR-0028): publicHostnamesEnvLine is the PUBLIC_HOSTNAMES=
// line read verbatim off the project's default profile (PublicHostnamesEnvLineOf),
// so a bare machine's machine.env is exactly what the profile would have
// given a non-bare sibling — same private FQDN, same seed. "" renders the
// private-project default line. domain is always the private
// "<project>.<suffix>", read back off that same profile.
func V2BareUserDataWithPublicHostnames(domain string, signerURL string, publicHostnamesEnvLine string) string {
	generalize := base64.StdEncoding.EncodeToString([]byte(SCGeneralizeShim))
	caddy := base64.StdEncoding.EncodeToString([]byte(SCCaddySetupShim))
	if strings.TrimSpace(publicHostnamesEnvLine) == "" {
		publicHostnamesEnvLine = PublicHostnamesEnvLine("")
	}
	return fmt.Sprintf(`## template: jinja
#cloud-config
fqdn: {{ v1.local_hostname }}.%s
prefer_fqdn_over_hostname: true
# An ABSENT users: key makes cloud-init create the distro default user; an empty
# list creates none. That distinction is the whole of --bare's "no user".
users: []
# caddy-setup apt-installs Caddy, so the package cache must be warm before it runs.
package_update: true
write_files:
  - path: /etc/sandcastle/machine.env
    permissions: '0644'
    content: |
      FQDN={{ v1.local_hostname }}.%s
      %s
      SIGNER=%s
      HOME=%s
  - path: /usr/local/sbin/sandcastle-generalize
    permissions: '0755'
    encoding: b64
    content: %s
  - path: /usr/local/sbin/sandcastle-caddy-setup
    permissions: '0755'
    encoding: b64
    content: %s
runcmd:
  - [/usr/local/sbin/sandcastle-generalize]
  # Belt and braces: nothing here installs sshd, but an image that ships one
  # enabled would quietly make "no ssh" untrue.
  - [sh, -c, "systemctl disable --now ssh 2>/dev/null || true"]
  - [/usr/local/sbin/sandcastle-caddy-setup]
`, domain, domain, publicHostnamesEnvLine, signerURL, BareMachineHome, generalize, caddy)
}

// V2DevUserData renders the cloud-init user-data of a Dev Image machine: one
// launched from admin.Images.Dev, the full interactive dev environment image
// (Ubuntu 26.04, zsh/mise/starship/Claude Code — see images/dev/Dockerfile).
//
// Unlike V2BareUserData, a Dev Image machine keeps everything that makes it
// reachable and usable over SSH: the login user, its SSH key, and an enabled
// sshd. What it drops is the Caddy branch V2DefaultProfileUserData applies to
// every other image (lines 64-87 there) — Dev Image machines have no public
// HTTPS ingress, so there is nothing for Caddy to serve and no leaf to fetch;
// the generalize step exists only to prep a machine for that leaf fetch, so it
// drops with it.
//
// It is applied as INSTANCE config, overriding the project default profile's
// user-data — same lever as V2BareUserData, and for the same reason: identity
// is read back off that same profile (domain, the already-joined
// "<project>.<suffix>") so a Dev Image machine can never disagree with its
// project about who it is.
func V2DevUserData(user string, sshKey string, domain string) string {
	body := fmt.Sprintf(`## template: jinja
#cloud-config
fqdn: {{ v1.local_hostname }}.%s
prefer_fqdn_over_hostname: true
users:
  - name: %s
    uid: 2000
    groups: [sudo]
    shell: /bin/zsh
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - %s
packages:
  - openssh-server
  - zsh
write_files:
`, domain, user, sshKey)
	return body + scShimWriteFiles + `runcmd:
  - [systemctl, enable, --now, ssh]
`
}

// The forwarded-agent indirection. Two guards must be exactly this way — the
// obvious alternatives silently break multiplexer panes:
//
//  1. /etc/ssh/sshrc re-points the stable link on EVERY session (not only when
//     it is dead): a link left pointing at a session that has since closed is
//     healed by the next login, so a persistent herdr/tmux server always ends
//     up on a live agent.
//  2. The consume snippet guards on -h (symlink present), NOT -S (live socket):
//     a pane opened while the link dangles must still export the LINK path so it
//     follows the link once a new session heals it in place — the whole point of
//     the indirection. Guarding on -S would pin such a pane to a dead socket.
//
// The consume snippet reaches both zsh (the default login shell) and bash via
// the /.sc shell shim appended to /etc/zsh/zshrc and /etc/bash.bashrc, so a
// herdr pane picks up the agent whichever shell it runs.
//
// sshAgentRepublishScript and sshAgentConsumeSnippet are the single source of
// truth, shipped as the first entries of the /.sc platform payload (ADR-0022):
// machines bake only the stable shims and source these from /.sc, so a payload
// update reaches every machine in a tenant centrally.
const sshAgentRepublishScript = `#!/bin/sh
# Sandcastle: republish this session's forwarded SSH agent at a stable path
# so multiplexer panes (herdr/tmux) that outlive the session keep a live
# agent. Re-point on every session so a new login heals a dangling link.
if [ -n "$SSH_AUTH_SOCK" ] && [ "$SSH_AUTH_SOCK" != "$HOME/.ssh/ssh_auth_sock" ]; then
  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
  ln -sf "$SSH_AUTH_SOCK" "$HOME/.ssh/ssh_auth_sock"
fi
`

const sshAgentConsumeSnippet = `# Sandcastle: follow the forwarded agent republished by /etc/ssh/sshrc.
# Guard on -h (symlink present), NOT -S (live socket): a pane opened while
# the link dangles must still point AT the link so the next session heals it.
if [ -h "$HOME/.ssh/ssh_auth_sock" ]; then
  export SSH_AUTH_SOCK="$HOME/.ssh/ssh_auth_sock"
fi
`

// scShimWriteFiles is a cloud-init write_files fragment (entries only, under a
// caller-supplied `write_files:` key) baking the stable /.sc shims (ADR-0022)
// at the fixed OS paths. The script bodies live in the platform payload on the
// shared volume — never inline here — so they update centrally.
var scShimWriteFiles = "  - path: /etc/ssh/sshrc\n" +
	"    permissions: '0755'\n    content: |\n" + indentBlock(SCSSHRCShim, 6) +
	"  - path: /etc/zsh/zshrc\n    append: true\n    content: |\n" + indentBlock(SCShellRCShim, 6) +
	"  - path: /etc/bash.bashrc\n    append: true\n    content: |\n" + indentBlock(SCShellRCShim, 6)

// indentBlock left-pads every non-empty line of s by n spaces (for embedding a
// script under a YAML `content: |` block scalar).
func indentBlock(s string, n int) string {
	pad := strings.Repeat(" ", n)
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line == "" {
			b.WriteByte('\n')
			continue
		}
		b.WriteString(pad)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// SSHAgentForwardBackfillScript is an idempotent /bin/sh script — run as root —
// that bootstraps a machine into the /.sc model (`sc fix <machine>`, ADR-0022):
// it installs the exact stable shims cloud-init bakes on fresh machines (it no
// longer pushes script bodies — those live in the platform payload on /.sc and
// update centrally), and reports (never rewrites) a broken hand-rolled ~/.zshrc.
func SSHAgentForwardBackfillScript() string {
	versionPath := SCPlatformPath + "/" + PlatformPayloadVersionFile
	return `set -eu
if grep -q '` + SCShimMarker + `' /etc/ssh/sshrc 2>/dev/null; then
  echo "  = /etc/ssh/sshrc is already the /.sc shim"
else
  cat > /etc/ssh/sshrc <<'SANDCASTLE_SSHRC_EOF'
` + SCSSHRCShim + `SANDCASTLE_SSHRC_EOF
  chmod 0755 /etc/ssh/sshrc
  echo "  + installed the /etc/ssh/sshrc /.sc shim"
fi
SNIPPET='` + strings.TrimRight(SCShellRCShim, "\n") + `'
for RC in /etc/zsh/zshrc /etc/bash.bashrc; do
  # A missing rc means the shell isn't installed (legacy machines predate the
  # zsh-default profile) — creating it would collide with the package's
  # conffile later, so skip; a re-run after installing the shell adds the shim.
  [ -e "$RC" ] || { echo "  - $RC absent (shell not installed), skipped"; continue; }
  if grep -q '` + SCShimMarker + `' "$RC" 2>/dev/null; then
    echo "  = $RC already has the /.sc shim"
  else
    printf '\n%s\n' "$SNIPPET" >> "$RC"
    echo "  + appended the /.sc shim to $RC"
  fi
done
for home in /root /home/*; do
  [ -d "$home" ] || continue
  z="$home/.zshrc"
  if [ -f "$z" ] && grep -q 'ssh_auth_sock_known' "$z" 2>/dev/null; then
    echo "  ! WARNING: $z has a broken hand-rolled agent block (ssh_auth_sock_known);"
    echo "    replace it with the read-only consume snippet by hand — it self-links and breaks the agent."
  fi
  rm -f "$home/.ssh/ssh_auth_sock_known" 2>/dev/null || true
done
if [ -r ` + versionPath + ` ]; then
  echo "  ok  /.sc/platform payload $(cat ` + versionPath + `)"
else
  echo "  ! /.sc/platform payload not visible (volume not attached or never synced);"
  echo "    the shims no-op until it appears"
fi
echo "agent-forwarding: installed"
`
}

// SSHAgentForwardCheckScript is a read-only /bin/sh script — run as root — that
// reports whether the /.sc shims are installed and the platform payload this
// binary ships is present and current, changing nothing. It prints a trailing
// "agent-forwarding: OK" or "agent-forwarding: NEEDS FIX".
func SSHAgentForwardCheckScript() string {
	versionPath := SCPlatformPath + "/" + PlatformPayloadVersionFile
	expected := PlatformPayloadVersion()
	return `set -u
need=0
if [ -f /etc/ssh/sshrc ] && grep -q '` + SCShimMarker + `' /etc/ssh/sshrc 2>/dev/null; then
  echo "  ok  /etc/ssh/sshrc is the /.sc shim"
else
  echo "  MISSING  /.sc shim at /etc/ssh/sshrc"; need=1
fi
for RC in /etc/zsh/zshrc /etc/bash.bashrc; do
  if [ ! -e "$RC" ]; then
    echo "  --  $RC absent (shell not installed), skipped"
  elif grep -q '` + SCShimMarker + `' "$RC" 2>/dev/null; then
    echo "  ok  $RC sources the /.sc shell payload"
  else
    echo "  MISSING  /.sc shim in $RC"; need=1
  fi
done
v="$(cat ` + versionPath + ` 2>/dev/null || true)"
if [ "$v" = "` + expected + `" ]; then
  echo "  ok  /.sc/platform payload is current ($v)"
elif [ -n "$v" ]; then
  echo "  STALE  /.sc/platform payload $v (this binary ships ` + expected + `)"; need=1
else
  echo "  MISSING  /.sc/platform payload (volume not attached or never synced)"; need=1
fi
for home in /root /home/*; do
  z="$home/.zshrc"
  if [ -f "$z" ] && grep -q 'ssh_auth_sock_known' "$z" 2>/dev/null; then
    echo "  BROKEN  $z has a hand-rolled ssh_auth_sock_known block"; need=1
  fi
done
if [ "$need" = 0 ]; then echo "agent-forwarding: OK"; else echo "agent-forwarding: NEEDS FIX"; fi
`
}

// machineGeneralizeScript freshens per-instance identity so a machine launched
// from an `sc image save` base image does NOT inherit the source machine's SSH
// host keys, machine-id, or stale TLS leaf. It runs once per instance (cloud-init
// per-instance runcmd, via the /usr/local/sbin/sandcastle-generalize boot shim
// — the body ships as the platform-payload entry SCPayloadGeneralizePath, so it
// updates centrally) before sshd is (re)started. On a fresh stock machine the
// identity is already unique, so every step is a harmless no-op — correctness
// lives here in one place rather than at save time.
const machineGeneralizeScript = `#!/bin/sh
# POSIX sh: the boot shim sources this with /bin/sh (dash on Debian).
set -u
# Drop the source machine's host identity + stale leaf (re-fetched by caddy-setup),
# its public-name certificates and hostnames file (this machine's set is seeded
# fresh from machine.env and pushed by the Auth App — never inherited).
rm -f /etc/ssh/ssh_host_* /etc/sandcastle/tls/cert.pem /etc/sandcastle/tls/key.pem /etc/sandcastle/hostnames
find /etc/sandcastle/tls -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
ssh-keygen -A >/dev/null 2>&1 || true
# Remove (not truncate) machine-id so systemd-machine-id-setup mints a fresh one;
# a leftover empty read-only file is not reliably regenerated in a container.
rm -f /etc/machine-id /var/lib/dbus/machine-id
systemd-machine-id-setup >/dev/null 2>&1 || true
# A cloned image had sshd enabled, so it is already serving the now-deleted keys;
# restart it (if running) to pick up the freshly generated host keys.
systemctl try-restart ssh >/dev/null 2>&1 || true
`

// caddyIngressSetupScript installs Caddy, trusts the Tenant CA, fetches this
// machine's private leaf, renders the Caddyfile and enables Caddy as root. It
// sources /etc/sandcastle/machine.env for FQDN (the Machine Private
// Hostname), PUBLIC_HOSTNAMES (the first-boot seed of the public-name set),
// SIGNER and HOME (ADR-0028, spec machine-hostnames §6).
//
// Every machine serves its private name: the leaf is fetched from the
// sidecar signer before Caddy starts, exactly as before public names
// existed, so Caddy is always enabled and started — there is no conditional
// start and no MODE. On top of that the script renders one site block per
// Machine Public Hostname listed in /etc/sandcastle/hostnames (one per line;
// seeded from PUBLIC_HOSTNAMES when the file is absent, pushed whole by the
// Auth App afterwards), each against /etc/sandcastle/tls/<host>/{cert,key}.pem
// — rendered only once both files exist, so a name whose certificate has not
// landed yet is simply not served rather than breaking the Caddyfile. All
// blocks carry the same handlers; only the name and the certificate differ.
//
// `--refresh` is the entry point the reconciler execs after pushing a
// hostnames file or a certificate: it skips the install/trust/leaf steps,
// re-reads the hostnames file and the per-host directories, re-renders,
// validates, and reloads Caddy (starts it when inactive). Idempotent — safe
// to run any number of times; a failed validation leaves the running
// Caddyfile and the old marker untouched.
//
// The Caddy Setup Marker (CaddySetupMarkerPath) is written LAST, after the
// validated Caddyfile is in place: PRIVATE=<fqdn>, one PUBLIC=<host> per
// public block actually rendered, RENDERED=<unix ts>. Its presence tells the
// reconciler the machine runs this contract.
//
// Runs via the /usr/local/sbin/sandcastle-caddy-setup boot shim — the body
// ships as the platform-payload entry SCPayloadCaddySetupPath (ADR-0022) and
// serves `sc create`, `--bare`, Freeform Machines, containers and VMs alike.
// The shim is `#!/bin/sh` and sources the body, so the body executes under
// dash on Debian: it must stay strictly POSIX sh (no process substitution,
// `[[`, arrays, `pipefail`, …) — TestPayloadScriptsArePOSIXSh and the sh-run
// goldens in caddy_setup_test.go enforce that.
const caddyIngressSetupScript = `#!/bin/sh
# Sandcastle caddy-setup (ADR-0028): first boot, or --refresh after the Auth
# App pushed /etc/sandcastle/hostnames or a per-hostname certificate.
# POSIX sh only: the /usr/local/sbin/sandcastle-caddy-setup boot shim sources
# this body with /bin/sh (dash on Debian) — no bash syntax anywhere in here.
set -eu
. /etc/sandcastle/machine.env
REFRESH=0
if [ "${1:-}" = --refresh ]; then REFRESH=1; fi
export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /etc/sandcastle/tls /usr/local/share/ca-certificates /etc/caddy /etc/systemd/system/caddy.service.d

# hostnames_normalized prints the machine's public names, one per line:
# lower case, trimmed, no trailing dot, only DNS characters, never the
# private name, sorted and deduplicated. Stdin is the raw list.
hostnames_normalized() {
  tr 'A-Z,' 'a-z\n' | tr -d ' \t\r' | sed 's/\.$//' | grep -E '^[a-z0-9][a-z0-9.-]*$' | grep -vxF "$FQDN" | LC_ALL=C sort -u || true
}

if [ "$REFRESH" = 0 ]; then
  # Install Caddy from its official repo (not in stock Debian apt).
  if ! command -v caddy >/dev/null 2>&1; then
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl gnupg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy
  fi

  # Trust the tenant CA on this machine (machine-to-machine HTTPS).
  curl -fsS "$SIGNER/tls/ca" -o /usr/local/share/ca-certificates/sandcastle-tenant.crt && update-ca-certificates || true

  # Fetch this machine's private leaf (key+cert) from the sidecar signer
  # BEFORE Caddy serves. Public names get their certificates pushed by the
  # Auth App into /etc/sandcastle/tls/<host>/.
  curl -fsS "$SIGNER/tls/leaf?fqdn=$FQDN" | python3 -c 'import json,sys;d=json.load(sys.stdin);open("/etc/sandcastle/tls/cert.pem","w").write(d["cert"]);open("/etc/sandcastle/tls/key.pem","w").write(d["key"])'
  chmod 600 /etc/sandcastle/tls/key.pem
fi

# Seed the hostnames file once from machine.env; from then on the Auth App
# owns it (pushed whole whenever the set changes).
if [ ! -e /etc/sandcastle/hostnames ]; then
  printf '%s\n' "${PUBLIC_HOSTNAMES:-}" | hostnames_normalized > /etc/sandcastle/hostnames
fi

# site_block NAME CERT KEY: one Caddy site — HTTPS with the given
# certificate (auto HTTP->HTTPS redirect), /_h browses the login user's
# $HOME, /_w browses /workspace, everything else proxies to :3000 with Host
# preserved. redir handles the bare /_h and /_w (no trailing slash). The
# handlers are identical for every name.
site_block() {
  cat <<EOF
$1, *.$1 {
    tls $2 $3
    redir /_h /_h/
    redir /_w /_w/
    handle_path /_h/* {
        root * $HOME
        file_server browse
    }
    handle_path /_w/* {
        root * /workspace
        file_server browse
    }
    handle {
        reverse_proxy localhost:3000
    }
}
EOF
}

# Render: the private block always, then one block per public name whose
# certificate directory is complete. Validate before installing so a bad
# render never replaces a working Caddyfile. The normalized names hold no
# whitespace (DNS characters only), so a plain word-split loop over them is
# exact — and unlike a pipe into "while read", it keeps RENDERED in this shell.
HOSTS="$(hostnames_normalized < /etc/sandcastle/hostnames)"
RENDERED=""
{
  site_block "$FQDN" /etc/sandcastle/tls/cert.pem /etc/sandcastle/tls/key.pem
  for host in $HOSTS; do
    if [ -s "/etc/sandcastle/tls/$host/cert.pem" ] && [ -s "/etc/sandcastle/tls/$host/key.pem" ]; then
      printf '\n'
      site_block "$host" "/etc/sandcastle/tls/$host/cert.pem" "/etc/sandcastle/tls/$host/key.pem"
      RENDERED="$RENDERED $host"
    fi
  done
} > /etc/caddy/Caddyfile.new
caddy validate --config /etc/caddy/Caddyfile.new --adapter caddyfile >/dev/null
mv -f /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile

if [ "$REFRESH" = 0 ]; then
  # Caddy runs as root so it can read $HOME/... regardless of owner and bind :443.
  printf '%s\n' '[Service]' 'User=root' 'Group=root' 'AmbientCapabilities=' > /etc/systemd/system/caddy.service.d/override.conf
  systemctl daemon-reload
  systemctl enable caddy
fi
# Marker LAST: it asserts the Caddyfile above is in place for these names.
{
  printf 'PRIVATE=%s\n' "$FQDN"
  for host in $RENDERED; do printf 'PUBLIC=%s\n' "$host"; done
  printf 'RENDERED=%s\n' "$(date +%s)"
} > /etc/sandcastle/caddy.ready
if [ "$REFRESH" = 0 ]; then
  systemctl restart caddy
elif systemctl is-active --quiet caddy; then
  systemctl reload caddy || systemctl restart caddy
else
  systemctl start caddy
fi
`

// DefaultV2UnixUser is the login user baked into a v2 project's default
// profile when the create request does not specify one. It matches the UID-2000
// convention (ADR-0014) applied when the profile is materialized.
const DefaultV2UnixUser = "dev"

// CreatePlanV2 describes the v2 MVP tenant bring-up (ADR-0016): one per-tenant
// infra project holding a single sidecar (CoreDNS + Tailscale + Caddy), one
// shared per-tenant bridge, and a seeded default app project. Machines are
// created later by the tenant with native incus into app projects on the shared
// bridge; DNS is flat (<machine>.<suffix>).
type CreatePlanV2 struct {
	Tenant         string `json:"tenant"`
	Prefix         string `json:"prefix"`
	InfraProject   string `json:"infraProject"`
	DefaultProject string `json:"defaultProject"`
	// DefaultProjectShort is the short name of the tenant's one project (issue
	// #93). The user chooses it at first login; it defaults to "default". The
	// full Incus project name is DefaultProject (<prefix>-<tenant>-<short>).
	DefaultProjectShort string `json:"defaultProjectShort"`
	Bridge              string `json:"bridge"`
	DNSSuffix           string `json:"dnsSuffix"`
	PrivateCIDR         string `json:"privateCIDR"`
	GatewayAddress      string `json:"gatewayAddress"`
	TailscaleAddress    string `json:"tailscaleAddress"`
	DNSAddress          string `json:"dnsAddress"`
	StoragePool         string `json:"storagePool"`
	HomeVolume          string `json:"homeVolume"`
	WorkspaceVolume     string `json:"workspaceVolume"`
	CAVolume            string `json:"caVolume"`
	// SCVolumes is the per-tenant /.sc shared-scripts volume set (spec #127):
	// the platform layer machines mount read-only and the tenant-writable local
	// layer, as pure-testable plan data.
	SCVolumes          []SCVolume `json:"scVolumes"`
	SidecarInstance    string     `json:"sidecarInstance"`
	SidecarImage       string     `json:"sidecarImage"`
	DefaultProfileUser string     `json:"defaultProfileUser"`
	SSHPublicKey       string     `json:"sshPublicKey"`
	// ProjectDomain is the app project's Project Domain (ADR-0027) when the
	// plan renders one project's profile; empty for private projects and for
	// tenant creation (a fresh tenant's initial project has no domain).
	ProjectDomain      string     `json:"projectDomain,omitempty"`
	ImageAliases       []string   `json:"imageAliases"`
	DNSFiles           []dns.File `json:"dnsFiles"`
	TenantCA           TenantCA   `json:"tenantCA"`
	RestrictedProjects []string   `json:"restrictedProjects"`
}

// PlanCreateV2 builds a CreatePlanV2 from admin config and a create request.
// It is pure (aside from CA key generation and the current time) so it can be
// unit tested without touching Incus.
func PlanCreateV2(admin config.Admin, request CreateRequest) (CreatePlanV2, error) {
	if err := admin.Validate(); err != nil {
		return CreatePlanV2{}, err
	}
	ref, err := naming.ParseTenantRef(request.Reference)
	if err != nil {
		return CreatePlanV2{}, err
	}
	prefix := naming.NormalizeV2Prefix(admin.IncusProjectPrefix)
	infraProject, err := naming.V2TenantInfraProjectName(prefix, ref.Tenant)
	if err != nil {
		return CreatePlanV2{}, err
	}
	// The tenant's one project (issue #93): the user names it at first login;
	// on re-login the stored short name is reused; blank on both ⇒ "default".
	// Not immutable — unlike the DNS suffix — so a differing request just wins.
	defaultProjectShort := strings.TrimSpace(request.InitialProject)
	if defaultProjectShort == "" {
		defaultProjectShort = strings.TrimSpace(request.ExistingDefaultProject)
	}
	if defaultProjectShort == "" {
		defaultProjectShort = naming.DefaultProjectName
	}
	if err := naming.ValidateProjectName(defaultProjectShort); err != nil {
		// Bad user input — no retry can fix a rejected project name.
		return CreatePlanV2{}, TerminalProvisionError{Err: err}
	}
	defaultProject, err := naming.V2ProjectName(prefix, ref.Tenant, defaultProjectShort)
	if err != nil {
		return CreatePlanV2{}, err
	}
	bridge, err := naming.V2BridgeName(prefix, ref.Tenant)
	if err != nil {
		return CreatePlanV2{}, err
	}
	// Reuse fallbacks (#134): a blank request means "keep what the tenant has",
	// never "reset to defaults" — the stored user/key drive every app project's
	// default profile, and clobbering them to dev/empty breaks SSH tenant-wide.
	unixUser := strings.TrimSpace(request.UnixUser)
	if unixUser == "" {
		unixUser = strings.TrimSpace(request.ExistingUnixUser)
	}
	if unixUser == "" {
		unixUser = DefaultV2UnixUser
	}
	if err := naming.ValidateUnixUsername(unixUser); err != nil {
		return CreatePlanV2{}, err
	}
	sshPublicKey := strings.TrimSpace(request.SSHPublicKey)
	if sshPublicKey == "" {
		sshPublicKey = strings.TrimSpace(request.ExistingSSHKey)
	}
	requestedSuffix := strings.TrimSpace(request.DNSSuffix)
	existingSuffix := strings.TrimSpace(request.ExistingDNSSuffix)
	if requestedSuffix != "" && existingSuffix != "" && requestedSuffix != existingSuffix {
		return CreatePlanV2{}, TerminalProvisionError{Err: fmt.Errorf("the Tenant DNS Suffix is immutable: tenant %s already uses %q (requested %q)", ref.Tenant, existingSuffix, requestedSuffix)}
	}
	effectiveSuffix := requestedSuffix
	if effectiveSuffix == "" {
		effectiveSuffix = existingSuffix
	}
	if effectiveSuffix == "" {
		effectiveSuffix = ref.Tenant
	}
	suffix, err := domainrules.ValidateTenantDNSSuffix(effectiveSuffix, domainrules.Policy{
		AllowedSuffixes: admin.AllowedDomainSuffixes,
		DeniedSuffixes:  admin.DeniedDomainSuffixes,
	})
	if err != nil {
		// Bad user input — no retry can fix a rejected suffix.
		return CreatePlanV2{}, TerminalProvisionError{Err: err}
	}
	var tenantCIDR netip.Prefix
	if pref := strings.TrimSpace(request.PreferredCIDR); pref != "" {
		// Reuse the tenant's existing /24 (idempotent re-provision).
		tenantCIDR, err = netip.ParsePrefix(pref)
		if err != nil {
			return CreatePlanV2{}, fmt.Errorf("parse preferred CIDR %q: %w", pref, err)
		}
		tenantCIDR = tenantCIDR.Masked()
		// A reused CIDR must still come from this install's pool: anything
		// else means the reuse scan picked up a foreign install's tenant (or
		// the pool changed), and provisioning it would stand up a bridge on
		// address space this install doesn't own.
		if pool, perr := netip.ParsePrefix(strings.TrimSpace(admin.CIDRPool)); perr == nil {
			if !pool.Contains(tenantCIDR.Addr()) || tenantCIDR.Bits() < pool.Bits() {
				return CreatePlanV2{}, fmt.Errorf("preferred CIDR %s is outside the tenant CIDR pool %s", tenantCIDR, pool)
			}
		}
	} else if tenantCIDR, err = cidr.Allocate(admin.CIDRPool, cidr.DefaultTenantPrefixBits, request.OccupiedCIDRs); err != nil {
		return CreatePlanV2{}, err
	}
	gatewayAddress, err := roleAddress(tenantCIDR, cidr.GatewayHostOctet)
	if err != nil {
		return CreatePlanV2{}, err
	}
	tailscaleAddress, err := roleAddress(tenantCIDR, cidr.TailscaleHostOctet)
	if err != nil {
		return CreatePlanV2{}, err
	}
	dnsAddress, err := roleAddress(tenantCIDR, cidr.DNSHostOctet)
	if err != nil {
		return CreatePlanV2{}, err
	}
	dnsFiles, err := dns.RenderInitial(suffix, dnsAddress.String())
	if err != nil {
		return CreatePlanV2{}, err
	}
	ca, err := certs.GenerateCA("Sandcastle "+ref.String()+" tenant CA", time.Now().UTC())
	if err != nil {
		return CreatePlanV2{}, err
	}

	return CreatePlanV2{
		Tenant:              ref.Tenant,
		Prefix:              prefix,
		InfraProject:        infraProject,
		DefaultProject:      defaultProject,
		DefaultProjectShort: defaultProjectShort,
		Bridge:              bridge,
		DNSSuffix:           suffix,
		PrivateCIDR:         tenantCIDR.String(),
		GatewayAddress:      gatewayAddress.String(),
		TailscaleAddress:    tailscaleAddress.String(),
		DNSAddress:          dnsAddress.String(),
		StoragePool:         admin.StoragePool,
		HomeVolume:          HomeVolumeName,
		WorkspaceVolume:     WorkspaceVolumeName,
		CAVolume:            CAVolumeName,
		SCVolumes:           V2SCVolumes(),
		SidecarInstance:     naming.V2SidecarInstanceName,
		SidecarImage:        admin.Images.Base,
		DefaultProfileUser:  unixUser,
		SSHPublicKey:        sshPublicKey,
		ImageAliases:        uniqueImageAliases(admin.Images.Base, admin.Images.AI, admin.Images.Dev),
		DNSFiles:            dnsFiles,
		TenantCA: TenantCA{
			CertificatePath: TenantCACertPath,
			PrivateKeyPath:  TenantCAKeyPath,
			CertificatePEM:  ca.CertificatePEM,
			PrivateKeyPEM:   ca.PrivateKeyPEM,
		},
		RestrictedProjects: restrictedProjects(defaultProject, request.ExistingProjects),
	}, nil
}

// restrictedProjects is the project scope a tenant's enrollment token grants:
// the default project first, then every other existing app project (sorted,
// deduplicated). Existing projects must be included — a re-login mints a fresh
// restricted certificate (or extends the shared one), and scoping it to the
// default project alone locked new clients out of every project created since
// first login.
func restrictedProjects(defaultProject string, existing []string) []string {
	out := []string{defaultProject}
	seen := map[string]bool{defaultProject: true}
	sorted := append([]string(nil), existing...)
	sort.Strings(sorted)
	for _, name := range sorted {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// DNSAddressForCIDR returns the sidecar's address inside a tenant's private /24
// — the host that serves CoreDNS and the TLS leaf signer.
//
// Callers that re-render an app project's default profile must supply it: the
// profile's cloud-init embeds `http://<dns address>:<signer port>` as the machine
// Caddy's signer URL, and an empty address yields `http://:9443`, so the machine
// can never fetch its leaf and serves no HTTPS at all.
func DNSAddressForCIDR(privateCIDR string) (string, error) {
	privateCIDR = strings.TrimSpace(privateCIDR)
	if privateCIDR == "" {
		return "", fmt.Errorf("tenant private CIDR is empty")
	}
	prefix, err := netip.ParsePrefix(privateCIDR)
	if err != nil {
		return "", fmt.Errorf("parse tenant private CIDR %q: %w", privateCIDR, err)
	}
	address, err := roleAddress(prefix, cidr.DNSHostOctet)
	if err != nil {
		return "", err
	}
	return address.String(), nil
}
