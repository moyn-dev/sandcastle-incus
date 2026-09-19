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
— that is "no sudoers rule matches", not a wrong password. Restore the rule as
root over `incus exec` (admin) and rerun.

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
(default Cloud Identity Config for new machines) and
`set-docker-autostart <name> on|off`.

### Project Domains (ADR-0027)

```bash
sc project create zp --domain baum.hase.de   # claim + create; the admin must have registered hase.de
sc project set-domain zp baum.hase.de        # claim for an existing project, or replace its domain
sc project unset-domain zp                   # release it; new machines are private again
sc project status zp                         # Domain: baum.hase.de   (zone hase.de) + MACHINE/PUBLIC NAME/CERT table
```

- Every machine created in the project **after** the claim gets the derived
  Machine Public Hostname `<machine>.<domain>` beside its private name;
  machines created before keep only their private name until the follow-on
  slices of #172 re-derive names. See "Explicit machine hostnames" below for
  the rest of a machine's public-name set.
- Claims are install-wide and first-come. Refusals are verbatim: a cross-tenant
  overlap never names the owner (`… overlaps a domain already claimed on this
  install; choose another`); a same-tenant overlap does (`… overlaps "<d>"
  claimed by project "<p>" in this tenant`); a Public Route hostname or the
  install's own names give `… is reserved by this install`; no zone gives
  `no Public DNS Zone covers <domain> — ask your admin`; the apex gives `… is a
  zone apex; claim at least one label below <zone>`.
- `set-domain`/`unset-domain` are allowed with machines in the project (ADR-0028
  slice 3): the zone reconciler re-derives every machine's `<m>.<domain>` —
  list key, A records, a fresh certificate, the hostnames file — within a
  minute; the replaced/released domain's records and certificate rows go with
  the claim; explicit hostnames are untouched. Re-claiming the same domain is a
  no-op.
- The verbs need `sc login`; on a broker-only install they print `--domain is
  not available on this install`. All take `--dry-run`.
- `sc create` in a project with a domain stamps the set
  `user.sandcastle.v2.public-hostnames` (derived `<machine>.<domain>` + any
  `--hostname`) on the instance in the create call and prints the usual `DNS:`
  line followed by one `Public name: <h> (A record pending, certificate pending
  — see: sc project status <p>)` line per name; `--bare` adds `HTTPS:
  https://<m>.<p>.<suffix>   (Caddy with the tenant-CA leaf, …)` and `HTTPS
  (public): https://<h>   (Let's Encrypt; served once the certificate lands)`;
  a Dev Image machine prints `(A record pending; no Caddy — no certificate)`.
  Read the set back with `sc ls` (FQDN + CERT columns), `sc hostname list`, or
  `sc incus config get <m> user.sandcastle.v2.public-hostnames` — never guess
  it from the project's current domain.
- On the machine (ADR-0028, one contract for every machine): `caddy-setup`
  (payload) fetches the **private** leaf from the sidecar into
  `/etc/sandcastle/tls/{cert,key}.pem`, seeds `/etc/sandcastle/hostnames` from
  `PUBLIC_HOSTNAMES=` in `/etc/sandcastle/machine.env` (once; the Auth App owns
  the file afterwards), renders the private site block plus one block per
  listed name whose `/etc/sandcastle/tls/<name>/{cert,key}.pem` both exist,
  validates, enables + starts Caddy, and writes the Caddy Setup Marker
  `/etc/sandcastle/caddy.ready` last (`PRIVATE=<m>.<p>.<suffix>`, one
  `PUBLIC=<name>` per rendered block, `RENDERED=<unix ts>`). Caddy is always
  running; a public name is served as soon as its certificate lands and
  `sandcastle-caddy-setup --refresh` (execed by the reconciler after every
  push; safe to run by hand) re-renders. Validation, systemd start, and reload
  execute through `/.sc/platform/sbin/caddy`; the rendered Caddyfile and the
  certificate/key files remain Machine-local.
- The Auth App's zone reconciler (30 s + instance events + a kick from every
  `sc hostname add|remove` / `set-domain` / `unset-domain`) does the rest with
  no operator step, **per (machine, public name)** — the derived `<m>.<d>` plus
  every explicit hostname: public `A` records for `<name>` and `*.<name>`
  (DNS-only, tenant-bridge IP; stopped machines keep them, deleted ones lose
  the records of all their names), one Let's Encrypt order per name via DNS-01
  (max 4 at once, backoff 1m → 6h on failure, ARI-timed renewal with a fresh
  key; adding a name never reissues the others), the cert + key push into
  `/etc/sandcastle/tls/<name>/` once a per-name marker exists
  (`instance-started` re-pushes a stopped machine within seconds), a push of
  `/etc/sandcastle/hostnames` whole whenever the machine's file does not list
  exactly its set (add, remove, re-derived domain, empty first-boot seed), a
  per-pass fingerprint drift check per name, and the mirror into
  `user.sandcastle.v2.cert-state` (per name: `host=state,…`) /
  `cert-not-after` (earliest) that `sc ls` (worst state) and `sc project
  status` (one row per name) read. Freeform `incus launch` machines get their
  list key stamped on first sight and are treated the same; a Dev Image
  machine gets A records but no certificate (no Caddy, no marker). Deleting a
  machine or removing a hostname retains its certificate row until expiry, so
  the same name reuses the certificate without a new order. Diagnosis:
  `reference/troubleshooting.md`.
- `sc connect` dials the bridge IP; `known_hosts` records the private names
  and every public name, and `HostKeyAlias` stays the Machine Private Hostname
  (ADR-0028; slice 2 of #172 finalizes SSH naming).

### Explicit machine hostnames (ADR-0028)

```bash
sc create zp:web --hostname web12.tc42.uk --fqdn shop.tc42.uk   # claimed BEFORE the instance exists; a refusal creates nothing
sc hostname add zp:web api.tc42.uk [--dry-run]                  # claim + certificate row + instance key rewritten
sc hostname list zp:web                                         # PUBLIC NAME / KIND (derived|explicit) / ZONE
sc hostname remove zp:web api.tc42.uk [--dry-run]               # release (alias rm); the derived name is not removable per machine
sc ls                                                           # FQDN = first public name + "(+N)"; --json carries publicHostnames
sc incus config get web user.sandcastle.v2.public-hostnames     # the sorted list the Auth App maintains
```

- A machine's public names are a **set**: the derived `<m>.<domain>` (when
  the project has a domain) plus explicit names under any registered Public
  DNS Zone — apex-level names (`web12.tc42.uk`) included, in a project with or
  without a domain. Each is an install-wide, first-come reservation of itself
  plus its wildcard subtree, with its own certificate (`name` + `*.name`).
- Refusals are verbatim and mirror Project Domains: cross-tenant `machine
  hostname "<h>" overlaps a name already claimed on this install; choose
  another`; same tenant `… overlaps "<x>" held by machine "<p>:<m>" in this
  tenant` / `… overlaps project domain "<d>" claimed by project "<p>" in this
  tenant`; routes and install names `… is reserved by this install`; the zone
  apex `… is a zone apex; use at least one label below <zone>`; no zone `no
  Public DNS Zone covers <h> — ask your admin`. The reverse checks refuse a
  Project Domain or a custom Public Route that overlaps a hostname.
- Needs `sc login`: `--hostname is not available on this install (log in to
  an Auth App with sc login)` otherwise. `sc project delete` releases the
  project's hostnames; a machine deleted out-of-band is pruned by the 5-minute
  loop; `sc-adm public-dns-zone remove` is refused while hostnames are held.
- Every name — derived or explicit — gets its own A records, certificate and
  Caddy site block from the zone reconciler (above); `sc hostname add` shows
  up on the machine within seconds (hostnames file), records within a minute,
  the certificate within about five. `sc hostname remove` deletes the name's
  records at once and keeps its certificate row for a re-add.

`--write-remote` on `sc project create` adds a separate directly-addressable
incus remote for the project. It is off by default — the install's single remote
plus `sc project switch` already covers projects.

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
