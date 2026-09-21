# Sandcastle operations

Per-area semantics and recipes for the tenant CLI. `sc <cmd> --help` lists the
flags; this file carries what the flags do not say.

## Machines

Short aliases: `c` connect, `ls` list, `new` create, `del`/`rm` delete, `up`
start, `down` stop, `reboot` restart, `st` status, `upd` update; groups `t`
tenant, `p`/`proj` project, `rem` remote, `img` image, `host` hostname; `sw`
for `tenant switch` / `project switch`.

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

The `ssh-key` fixup runs first and over the Incus API, not SSH, so it works
when SSH is locked out. It is additive: it never removes or replaces a line of
`authorized_keys`, only appends the current CLI key when missing, then lists
every enrolled key (`ssh-keygen -l` lines, current key marked). It also writes
a marker-delimited `Host` block for the machine at the top of `~/.ssh/config`
(fqdn, public hostnames, private IP → `User`, `IdentityFile` = CLI key,
`IdentitiesOnly yes`, `HostKeyAlias` = fqdn), so a bare `ssh <fqdn>` or
`ssh <ip>` logs in like `sc connect` does. Without that block plain ssh offers
only `~/.ssh/id_*`, never `~/.ssh/sandcastle_ed25519`, and prompts for a
password while `sc connect` works — `VERBOSE=1 sc c <m>` prints the exact
ssh line to compare against. The other fixups run `sudo sh -s` over SSH and
need the login user's NOPASSWD rule (`/etc/sudoers.d/90-cloud-init-users`,
written by cloud-init at first boot); on Ubuntu 25.10+ the machine's `sudo` is
sudo-rs, whose refusal reads `I'm sorry <user>. I'm afraid I can't do that`
— that is "no sudoers rule matches", not a wrong password. The `sudo` fixup
(central, over the Incus API, runs before the SSH ones) restores group
membership and the rule and proves it with `sudo -n true`:
`sc fix <m> --only sudo` (`--check` reports `sudo: OK` / `NEEDS FIX (…)`).

## Projects

A project is a real Incus project with its own machines, profiles, and shared
volumes. Tenants create them self-service through the broker; no flags are
needed after `sc login`, which records the broker URL and uses the enrolled
remote's client certificate.

```bash
sc project create backend     # broker scaffolds it and extends your certificate
sc project list
sc project switch backend     # writes the nearest .sandcastle; leaves global Incus defaults alone
sc project status backend
sc project delete backend --yes
```

`sc project delete` requires the project to be empty. After `sc login` it goes
through the Auth App (`DELETE /api/projects/<name>`), which releases the
project's Project Domain claim and deletes the Incus project with admin rights;
without a login it deletes directly, which a restricted tenant certificate
cannot. Per-project settings: `set-cloud-identity` / `unset-cloud-identity`
(default Cloud Identity Config for new machines),
`set-docker-autostart <name> on|off`, and `set-image <name> <image>` /
`unset-image <name>` (default image for `sc create` without `--image`: an
`images:` ref — cloud variant only — or an alias from `sc image save`), and
`rerender [name]` (re-render the project's profiles from the current release
and tenant settings; cloud-init runs once per machine, so only machines
created afterwards see it).

### Project Domains and certificates

```bash
sc project set-domain zp baum.hase.de [--dry-run]
sc project status zp --json
sc project unset-domain zp [--dry-run]
sc create zp:web --alias admin-web --alias console-web [--dry-run]
sc hostname add zp:web admin-web.baum.hase.de [--dry-run]
sc hostname list zp:web
sc hostname remove zp:web admin-web.baum.hase.de [--dry-run]
sc hostname add zp:web '*.web.baum.hase.de' [--dry-run]
sc create zp:other --hostname web12.tc42.uk --fqdn shop.tc42.uk [--dry-run]
sc delete zp:web --dry-run
```

- Each Project Domain owns one DNS-01 certificate for the domain and its
  one-label wildcard, renewed with ARI independently of the machine fleet.
  Status reports `certState`, `certNotAfter`, and `sans`; omitting the project
  on status/set-domain/unset-domain selects the current project.
- Derived names and one-label aliases use that certificate. Create reports
  `served by project certificate`; instance metadata is `cert-state=project`
  with no expiry. `sc ls` resolves shared state and expiry from the Auth App.
- Aliases are explicit reservations in the machine's own domain; `--alias`
  accepts one label and is repeatable. The derived name cannot be removed.
  Deeper names, outside names and zone apex names retain per-name orders
  (subject to reservation conflicts). Explicit wildcards order only that SAN.
  Cross-project overlaps remain forbidden. `--hostname`/`--fqdn` still claim
  before creation, and a failed create releases its claims.
- The reconciler creates A records, pushes the hostname list, and distributes
  `/etc/sandcastle/tls/<domain>/{cert,key}.pem` on start and renewal to each
  machine with a Caddy setup marker. `/etc/sandcastle/project-domain` selects
  the shared directory; `caddy-setup --refresh` serves exact one-label names
  using it. Per-name directories remain for other names. Tenant-CA private
  names and `/etc/sandcastle/tls/{cert,key}.pem` are unchanged.
- `incus copy` needs no metadata overrides: the reconciler re-derives the
  destination name, removes copied source aliases and certificate metadata,
  and converges DNS. Delete removes records and has no derived-name/alias
  certificate row to retain. Old derived-name certificates expire without
  renewal or revocation; outside-domain per-name retention is unchanged.
- Unsetting/replacing a domain drops its project certificate and clears the
  machine's shared-directory selector. Upgrade the Auth App and shared
  platform payload together with the CLI; a CLI-only upgrade cannot change
  issuance or Caddy rendering. All affected mutations have `--dry-run`.
- `sc connect` still dials the bridge IP; private names remain the SSH
  `HostKeyAlias`, and `known_hosts` includes public names.

## Machine Tunnels and Tailnet HTTPS

```bash
sc tunnel publish <project>:<machine> --port 3000 --hostname app.example.com
sc tunnel unpublish <project>:<machine> [--hostname 'app-*.example.com']
sc tailnet publish <project>:<machine> --hostname internal.example.com
sc tailnet unpublish <project>:<machine> [--hostname 'internal-*.example.com']
```

A Machine Tunnel is public Cloudflare ingress: it creates one dedicated tunnel
and connector per hostname. Its systemd unit starts
`/.sc/platform/sbin/cloudflared`; the launcher is shared and versioned with the
project payload, while the run token and service unit are Machine-local. A
Tailnet publication is different: it creates DNS-only A records to the
Machine's private bridge address, gets a Let's Encrypt DNS-01 certificate, and
the Auth App pushes that certificate/key into
`/etc/sandcastle/tls/<hostname>/` before running Caddy refresh. Neither
Machine receives the Cloudflare API token. Omit `--hostname` on unpublish to
remove every recorded publication of that kind from that Machine.

For a pre-platform connector or Caddy unit, run `sc payload-sync`, then
`sc fix <machine> --only cloudflared` or `--only caddy-publications`.

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
- Exact-route certificates issue on the **first HTTPS request**, so that request
  is slow. Wildcard routes do too unless the operator configured route DNS-01.
- On a Cloudflare zone a custom route hostname must be DNS-only (grey cloud); a
  proxied record intercepts `:443` and no certificate ever issues.
- By default a wildcard route issues one certificate per real subdomain on
  demand. With operator-configured Cloudflare route DNS-01 it uses one wildcard
  certificate. An exact route for the same name still beats a covering wildcard.
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

**Deprecated parts first.** Private-suffix names (`<machine>.<project>.<suffix>`
served by the sidecar CoreDNS) and the tenant CA are the private-DNS era. The
supported way to reach a machine by name over HTTPS is a Public DNS Zone plus a
Project Domain (see "Project Domains and certificates"): real A records and
Let's Encrypt certificates. `sc dns setup` and `sc trust install` remain for
old private-only setups; do not recommend them, and `sc tenant switch` no
longer hints them. `--dns-suffix` is deprecated too: the suffix defaults to the
tenant name.

Tailnet membership is the default state, not an opt-in: every sandcastle is on
its Tenant Tailnet — tenant creation attaches the sidecar, and all access (CLI,
SSH, DNS, the Incus remote itself) rides it. `sc tailscale up` re-attaches or
repairs a detached sidecar; it does not enable an optional feature.

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

- The shell rc puts `/.sc/platform/bin`, `~/.local/bin` and the user's mise
  shims on PATH (and activates mise in interactive shells), and sets the
  prompt to `user@<fqdn>:` (just `<fqdn>:` when the user is the tenant).
- `install-agentic.sh` (on PATH via `/.sc/platform/bin`) installs mise for
  the calling user, then `herdr`, `claude` and `codex` through it; re-run to
  upgrade. `SC_AGENTIC_TOOLS="claude"` narrows the set. Not as root.

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

## Cache first

`sc` commands read the tenant's projects, machines and payload versions from
the Auth App's event-fed resource cache (one request) and fall back to live
Incus on any non-answer. `VERBOSE=1` prints `tenant store: cache unavailable
…` / `connect cache: falling back …` when that happens; a persistent
fallback means the appliance is older than the CLI or its cache is off
(`SANDCASTLE_RESOURCE_CACHE`). `SANDCASTLE_CONNECT_CACHE=0` forces live.

## Login and enrollment

```bash
sc login https://<auth-host>                      # device login in the browser
sc login https://<auth-host> --force              # re-authenticate
sc login https://<auth-host> --default-project work   # (--dns-suffix is deprecated: the suffix is the tenant name)
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
- The **Tenant DNS Suffix is immutable** once the tenant exists and defaults to
  the tenant name; `--dns-suffix` is deprecated and a differing later value is
  refused.
- Login shells out to the `incus` client, which must be installed
  (`incus-client` on Debian/Ubuntu).

## Shared tenants

```bash
sc tenant list                                    # "*" marks the active tenant; Role: owner | member
sc tenant switch moyn-dev                         # member: enrols remote "moyn-dev" (the tenant's suffix, i.e. its
                                                  # name) at the tenant sidecar's tailnet IP, pins its default project
sc tenant switch thieso2                          # back to the personal tenant (re-activates its remote)
sc-adm tenant create moyn-dev --member thieso2 --member skorfmann \
    [--tailscale-authkey …]                       # admin: Shared Tenant with two members (pool derived; without a
                                                  # key it prints the tailnet login URL — re-run once after joining)
sc-adm tenant grant moyn-dev alice                # admin: add a member later (cert scope over every
                                                  # project, membership metadata, profiles, running machines)
sc-adm tenant revoke moyn-dev alice
sc-adm tenant users moyn-dev
sc-adm tenant add-ssh-key moyn-dev "ssh-ed25519 …"     # extra keys; set-ssh-key replaces the list,
sc-adm tenant remove-ssh-key moyn-dev "ssh-ed25519 …"  # remove-ssh-key refuses to drop the last key
```

- Machines log in as the tenant's unix user, which defaults to the tenant
  name (`ssh moyn-dev@<ip>` for `moyn-dev`); `sc-adm tenant create
  --unix-user` overrides it. Messages name machines by their Sandcastle
  Path (`/obelix/thieso2/work/dev`), which every command accepts, so a
  printed path pastes back.
- **Prerequisite**: every member has already run `sc login` on the install
  (their Personal Tenant carries the login SSH key the shared machines
  authorize) and is on the tenant's tailnet. `create --member` and
  `tenant grant` refuse a user without a Personal Tenant.
- Membership lives on the tenant's infra project (`user.sandcastle.v2.members`);
  the tenant's own keys are one per line in `user.sandcastle.v2.sshkey`.
- `sc tenant switch` records remote, project and tenant in the nearest
  `.sandcastle` selection file (created in the working directory when
  missing, like `sc remote switch`), so the tenant is per directory.
- After `sc tenant switch <shared>`, every `sc` command (machines, projects,
  hostnames, certificates, shares) acts on that tenant: the CLI sends the
  Current Tenant as `X-Sandcastle-Tenant` to the auth-app.
- A member's key rotation at login re-renders the shared tenants' profiles
  and enrols the new key on their running machines; a new machine created
  while the profile is stale can be repaired with `sc fix --only ssh-key`.
- Login itself is unchanged: it provisions the caller's Personal Tenant and
  never switches to a shared one.

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
