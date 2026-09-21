# Sandcastle operations

Per-area semantics and recipes for the tenant CLI. `sc <cmd> --help` lists the
flags; this file carries what the flags do not say.

## Machines

`sc create [[remote:]project:]machine`:

- `--vm` launches a virtual machine instead of a container.
- `--image <ref>` launches from a saved base image (`sc image list`) or any Incus
  image ref. Default is a stock cloud image (`images:debian/13/cloud`).
- `--home-share` adds the project's `homeshare` profile so the machine shares
  `/home` with the project's other `--home-share` machines. Without it the
  machine gets a private `/home` from its image. **Profiles apply at create time
  only** — an existing machine keeps what it was created with.
- `--bare` creates a machine with no login user, no SSH key, and no sshd: just a
  hostname and a Caddy serving its tenant-CA leaf. `sc connect` reaches a bare
  machine over `incus exec` as root instead of SSH.
- `--dry-run` renders the plan without creating anything.
- `--background` / `--detach` are deprecated no-ops; creation never attaches.

`/workspace` is shared across every machine in the project and is writable by the
login user. It survives machine deletion. `/home` is machine-local unless
`--home-share`.

`sc connect` resolves cache-first: when the machine is cached as running with an
address and `known_hosts` already pins its host key, it is one auth-app request
plus one keyscan. Anything short of certainty falls back to the full live dial —
first connect, stopped or absent machine, bare machine, globbed reference, or a
host key that disagrees with `known_hosts`. `SANDCASTLE_CONNECT_CACHE=0` forces
the live path.

`sc fix` applies idempotent maintenance fixups over SSH to a running machine —
changes that shipped in cloud-init after the machine was built and so never
reached it. `--check` reports without changing; `--only <fixup>` narrows. It
always resolves live; it exists to repair, not to be fast.

## Projects

A project is a real Incus project with its own machines, profiles, and shared
volumes. Tenants create them self-service through the broker; no flags are
needed after `sc login`, which records the broker URL and uses the enrolled
remote's client certificate.

```bash
sc project create backend     # broker scaffolds it and extends your certificate
sc project list
sc project switch backend     # also re-pins the active incus remote to the project
sc project status backend
sc project delete backend --yes
```

`sc project delete` requires the project to be empty. Per-project settings:
`set-cloud-identity` / `unset-cloud-identity` (default Cloud Identity Config for
new machines) and `set-docker-autostart <name> on|off`.

`--write-remote` on `sc project create` adds a separate directly-addressable
incus remote for the project. It is off by default — the install's single remote
plus `sc project switch` already covers projects.

## Public routes

`sc route` publishes a machine's local port to the public Internet through the
auth-app appliance's Caddy. Bare `sc route` prints this install's route
configuration: the auto-hostname pattern, the CNAME target for custom hostnames,
and whether routes are enabled at all.

```bash
sc route                                     # what this install supports
sc route publish web --port 3000             # → https://<name>.<tenant>.<base-domain>
sc route publish web --port 3000 --hostname app.example.com
sc route publish web --port 3000 --hostname '*.apps.example.com'
sc route list                                # HOSTNAME  MACHINE  PORT  STATUS
sc route status <hostname>
sc route delete <hostname> --yes
```

- The MACHINE column is the Machine Private Hostname
  (`<machine>.<project>.<suffix>`), the FQDN `sc ls` prints — not the bare name.
- Auto-subdomains ride a wildcard DNS record the operator set up. A custom
  `--hostname` needs its own CNAME onto the target `sc route` reports; until that
  record exists the route sits at `awaiting-dns`.
- Certificates issue on the **first HTTPS request**, so that request is slow.
- On a Cloudflare zone a custom route hostname must be DNS-only (grey cloud); a
  proxied record intercepts `:443` and no certificate ever issues.
- A wildcard route issues one certificate per real subdomain on demand. An exact
  route for the same name beats a covering wildcard.
- **Deleting a machine prunes its routes** within seconds. A delete-and-recreate
  rebuild therefore needs a re-publish; only an IP change on a live machine is
  refreshed in place.
- An install without route ingress errors with the admin fix rather than a bare
  failure. That is an operator decision (`--route-ingress`), not something the
  tenant can turn on.

## Base images

Turn a hand-customized machine into a reusable base. The snapshot captures the
instance rootfs only — the shared `/home` and `/workspace` volumes are attached
devices and are excluded.

```bash
sc image save dev mybase      # machine keeps running; re-save replaces idempotently
sc image list                 # NAME FINGERPRINT SIZE SOURCE CREATED
sc create probe --image mybase
sc image rm mybase
```

**Base images are per-project.** `sc image save` publishes into the project the
machine reference resolved to, and `sc image list` / `rm` read the *active*
project (falling back to `default`), so an image saved in one project is invisible
from another. Pass `--project <name>` to `list` / `rm`, and save into the project
you will create from.

Children are generalized on first boot: fresh SSH host keys and machine-id, the
stale TLS leaf dropped, then a new leaf fetched for the new FQDN. That is what
keeps a child from carrying the source machine's identity.

## DNS, trust, tailnet

The tenant's sidecar runs CoreDNS for the tenant zone at the tenant CIDR's `.3`
address, reachable over the tailnet subnet route.

```bash
sc tailscale status          # sidecar attachment
sc tailscale up --auth-key … # attach (or interactively via the printed URL)
sc tailscale down
sc trust install             # install the tenant CA into local trust
sc trust uninstall
sc dns teardown / sc dns uninstall   # remove local resolver state for a tenant
```

Verify resolution directly against the sidecar rather than trusting the local
resolver:

```bash
dig +short dev.default.<suffix> @<tenant-cidr>.3
dig +short dev.<suffix>         @<tenant-cidr>.3   # short alias: default project only
```

## SSH host keys

`sc c` reads each machine's host keys over the Incus API and writes them to
`~/.ssh/known_hosts`, tagged `# sandcastle:<remote>/<tenant>`, connecting with
`StrictHostKeyChecking=yes`. Bare `ssh <machine>.<project>.<suffix>` then works
with no prompt.

```bash
sc ssh-key purge --dry-run    # report only; never writes
sc ssh-key purge --yes        # drop tagged orphans and recycled-IP debris
sc ssh-key purge --all        # every tenant this install knows
```

Purge removes only entries Sandcastle wrote, plus untagged literal IPs inside the
tenant's own CIDR (recycled DHCP leases). Other hosts, `@cert-authority`,
`@revoked`, and comments are untouched. The first destructive write of the day
leaves a `~/.ssh/known_hosts.sc-backup-<date>`.

## The `/.sc` platform payload

Every machine mounts a shared `/.sc` volume: `/.sc/platform` (read-only,
centrally updated platform scripts) and `/.sc/local` (tenant-writable). Stable
shims baked into the machine (`/etc/ssh/sshrc`, blocks in `/etc/zsh/zshrc` and
`/etc/bash.bashrc`) source the payload, each guarded so a missing payload fails
safe.

```bash
sc payload-sync --check   # report each project's payload version vs this binary's
sc payload-sync           # converge every app project of the tenant
```

Written once per project, never per machine. Running machines pick the change up
through the mount — no re-create, no sweep. Rolling back means running
`payload-sync` from the previous binary.

## Updates

```bash
sc update --check              # sc CLI vs latest release; sidecar vs deployment
sc update --yes                # apply both
sc update --version vX.Y.Z --yes   # pin, or roll back to an older tag
```

The sidecar update restarts only the leaf signer — CoreDNS and tailscaled keep
running, so DNS and SSH survive it. Homebrew installs print `brew upgrade
sandcastle` instead of self-replacing. Direct installs replace atomically and
keep a `.bak`; a root-owned install directory needs the update run as root.

## Login and enrollment

```bash
sc login https://<auth-host>                      # device login in the browser
sc login https://<auth-host> --force              # re-authenticate
sc login https://<auth-host> --dns-suffix castle --default-project work
sc login https://<auth-host> --tailscale-auth-key … --ssh-public-key ~/.ssh/id_ed25519.pub
sc enroll <tenant> --token <enrollment-token>     # enroll from an admin-minted token
sc remote add <name> <join-token> --tenant <tenant>
```

- Login is **idempotent**: with a saved token the auth-app still accepts and a
  responding remote, it prints `Already logged in at …` and exits. `--force`
  re-authenticates.
- Login **refuses to start** unless the client is already a tailnet node, and
  verifies afterwards that traffic actually egresses over the tailnet, printing
  one ✓/✗ line per layer. `--skip-setup` skips the client-side DNS/trust/
  tailscale setup and that precheck.
- The **Tenant DNS Suffix is immutable** once the tenant exists. A later
  `--dns-suffix` on the same tenant is refused.
- Login shells out to the `incus` client, which must be installed
  (`incus-client` on Debian/Ubuntu).

## Cloud identity

`sc cloud-identity gcp setup` configures tenant-scoped GCP Workload Identity
Federation — pool, provider, service account, and IAM role bindings — against the
active gcloud project. `--machine` with `--machine-project` restricts
impersonation to one machine. Machines then mint short-lived Workload Identity
Tokens from the Sandcastle OIDC provider.

## Storage shares

`sc share` manages Tenant Storage Shares (offer a `/workspace` directory to
another tenant, accept, reconcile onto machines). **Not yet supported on the
current topology** — the subcommands exist but the feature is not live.

## Raw incus

```bash
sc incus <any incus command>        # scoped to the tenant's active app project
sc incus-infra <any incus command>  # scoped to the tenant's infra project (sidecar)
```

Both wrap the vanilla `incus` client with the active install's restricted
certificate and the right project pinned, so `sc incus exec`, `sc incus file
push`, `sc incus config show`, and `sc incus profile show` all target the right
place. `sc incus` requires a live tenant for the current remote: it reads the app
project name off the tenant summary rather than guessing it.

Use it for anything the `sc` surface does not cover — attaching devices,
inspecting profiles, copying files, snapshots.
