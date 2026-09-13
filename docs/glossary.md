# Sandcastle Glossary

The canonical domain vocabulary. Architecture overview in [`topology.md`](topology.md).

## Core nouns

- **Tenant** — The top-level ownership, identity, and infrastructure boundary.
  Its handle is the normalized GitHub username for login-provisioned tenants, or
  an admin-minted handle. Access, DNS, tailnet, storage, and the OIDC issuer are
  all scoped to it. Names key on the handle *and* the installation prefix
  (`sc-adm install --prefix`; the default `sc` normalizes to `sc2`): infra
  project `<prefix>-<tenant>`, app project `<prefix>-<tenant>-<project>`, bridge
  `<prefix>-<tenant>`. Examples elsewhere show the default `sc2-`; read the real
  names from `sc remote list` rather than deriving them from the handle alone.
- **Project** — A real Incus project owned by a tenant (`sc2-<tenant>-<project>`),
  holding that project's machines, profiles, and storage. Created/deleted as an
  actual Incus project through the broker, not a metadata label. The seeded
  first project is `default`.
- **Machine** — A freeform container or VM inside a project — a vanilla `incus`
  instance with a native name (no `<project>-<machine>` mangling; `dev` can exist
  in two projects). Sits on the shared per-tenant bridge with a private IP and is
  **not** a Tailscale node. Created from a stock cloud image; the project's
  default profile supplies its login user, SSH key, and shared volumes.
- **Sidecar** — The one instance in `sc2-<tenant>` running CoreDNS (the tenant's
  DNS zone) and the Tailscale subnet-router, plus the Incus Reach proxy. One
  sidecar serves all of the tenant's projects.
- **Shared per-tenant bridge** — One bridge, `sc2-<tenant>`, created in the
  `default` Incus project; every `sc2-<tenant>-*` project references it via
  `features.networks=false`. Projects are not network-isolated from each other.
- **Per-tenant tailnet** — The Tailscale network the tenant's sidecar joins,
  using the **tenant's own** Tailscale key (supplied at `sc login`, or joined
  interactively via the printed login URL). The sidecar is its subnet-router,
  advertising the tenant's `/24`.
- **Tailnet egress** — The opt-in reverse direction of the subnet route
  (ADR-0026): machines reach tailnet peers (the CGNAT range `100.64.0.0/10`)
  through the sidecar. A DHCP classless static route on the tenant bridge
  steers the traffic at the sidecar, which masquerades it onto `tailscale0`,
  so peers see the sidecar's tailnet IP and need no `--accept-routes`. Toggled
  per tenant with `sc tailscale egress on|off` and applied by the idempotent
  tenant converge; the tailnet ACL still decides what the sidecar's tag may
  reach. Off by default — all of a tenant's machines share the sidecar's ACL
  identity.
- **Incus Reach** — The sidecar's `tailscale serve` proxy that forwards the
  sidecar's tailnet `:8443` to the host's Incus API. The tenant's enrolled remote
  points at the sidecar's tailnet IP, so the host's TLS certificate is pinned
  end-to-end and no host port is exposed.
- **Machine Private Hostname** — The canonical name of a machine,
  `<machine>.<project>.<Tenant DNS Suffix>`, for every project including
  `default`, plus a wildcard `*.<machine>.<project>.<suffix>` (ADR-0018).
  One CoreDNS zone per tenant, the only DNS authority; the Auth App reconciler
  auto-registers every running machine. Resolves to the machine's bridge IP,
  reachable over the tenant tailnet's subnet route.
- **Default Project Short Hostname** — The one short form: `<machine>.<suffix>`
  (+ wildcard), aliasing the *default* project's machine of that name. Machines
  in other projects have no short name — never first-wins, never dependent on
  uniqueness across projects.
- **Tenant DNS Suffix** — The tenant-chosen, single-label final part of every
  machine hostname. Set at tenant creation (`--dns-suffix`), immutable
  thereafter, and defaulting to the tenant handle — but not required to equal
  it, so never assume the two are the same.
- **Project profile** — Each project's Incus `default` profile bundles the shared
  `/workspace` volume, the shared-bridge NIC, and cloud-init login
  (user + SSH key + sshd). This is how a machine "in a project" gets its shared,
  persistent workspace and is reachable over SSH for free. On hosts with
  idmapped-mount support the shared volumes are `security.shifted` so a CT and a
  VM see consistent ownership.
- **`homeshare` profile** — The project's second profile, holding the shared
  `/home` volume and nothing else. It is applied only to machines created with
  `sc create --home-share` (or `sc connect --home-share`), so a shared home
  directory across a project's machines is opt-in; every other machine keeps a
  private `/home` from its image. Profiles apply at create time — an existing
  machine keeps the profiles it was created with.
- **Per-tenant CA** — The certificate authority for private machine TLS
  hostnames, scoped to the tenant. (Leaf issuance for the private HTTPS path is
  future work; the public ingress path needs no CA install.)
- **`/.sc` volume** — The per-tenant shared-scripts volume (ADR-0022, spec
  #127): two layers mounted on every machine — `/.sc/platform` (read-only in
  machines; centrally updated platform scripts) and `/.sc/local`
  (tenant-writable from any machine, like `/workspace`). Realized as the
  per-app-project custom volumes `sc-platform`/`sc-local`.
- **Platform Payload** — The versioned file set on `/.sc/platform`
  (`tenant.PlatformPayload()`): the platform scripts plus a content-derived
  `VERSION` marker. Written once per project (tenant/project provisioning,
  `sc-adm tenant payload-sync`, `sc fix`) — never per machine; rollback is the
  previous binary's sync.
- **`/.sc` Shim** — A stable, baked stub at a fixed OS path (`/etc/ssh/sshrc`,
  appended blocks in `/etc/zsh/zshrc` + `/etc/bash.bashrc`) that sources
  `/.sc/platform/<x>` then `/.sc/local/<x>`, each `[ -r … ] &&`-guarded so a
  missing payload fails safe. The shim never changes; the payload does.

## Infrastructure

- **Auth App** — The web service at the Auth Hostname: GitHub OAuth login, CLI
  device login, tenant provisioning, the Sandcastle OIDC provider for machine
  workload identity, and the DNS auto-registration reconciler. Terminates its own
  public hostname (embedded caddy + optional cloudflared).
- **Sandcastle Broker** — The appliance that authorizes and performs privileged
  tenant + project lifecycle over the host Incus socket, authenticating callers by
  their restricted client certificate.
- **Public Route** — A public HTTP(S) hostname → a machine, served by the edge
  (a caddy vhost, or a tunnel host). The host routes between `incusbr0` and the
  tenant bridge, so the edge reaches the machine's private IP directly.
- **Workload Identity / OIDC** — Short-lived Workload Identity Tokens the Auth
  App issues to machines; the OIDC issuer is per tenant.
- **Infrastructure Seed File** — The operator bootstrap bundle carrying Auth
  Hostname, Incus remote, CIDR pool, TLS material, and image references.
- **CIDR** — One `/24` per tenant, allocated from the installation's shared pool
  (auth-app + broker share it; the allocator de-conflicts across tenants). Role
  addresses: gateway `.1`, Tailscale `.2`, DNS `.3`.

## Auth

- **User Key** — The normalized GitHub username identifying a login user; for a
  personal tenant it is also the tenant handle.
- **CLI Device Login** — Browser-assisted device authorization that approves a
  login and provisions the caller's tenant; `sc login` drives it.
- **Restricted certificate** — The tenant's project-scoped Incus TLS client
  certificate, extended (never re-minted) when a new project is created.

## TLS / Machine Ingress

- **Tenant CA** — Per-tenant certificate authority generated at provisioning; its
  private key resides only on the tenant's sidecar. Trust root for all HTTPS on
  the tenant's machines.
- **Leaf cert** — A per-machine TLS certificate signed by the Tenant CA for the
  machine's own DNS names (e.g. `ct1.default.idefix`, `*.ct1.default.idefix`).
- **Machine name zone** — The DNS names the sidecar will sign for a tenant:
  everything under `*.default.<suffix>`. The sidecar signs any name in its own
  zone; it does not scope per machine.
- **caddy profile** — An Incus profile that installs Caddy on a machine to
  terminate HTTPS, force HTTP→HTTPS, reverse-proxy the app, and serve the
  built-in `/_h` (browse `$HOME`) and `/_w` (browse `/workspace`) file routes.
- **Base image** — A reusable local Incus image published from a running machine
  with `sc image save <machine> <name>`. It captures only the instance rootfs
  (installed software), not the shared `/home` / `/workspace` volumes. Launch new
  machines from it with `sc create <machine> --image <name>`; manage with
  `sc image list` / `sc image rm`. See ADR-0019.
- **Generalize (machine)** — The first-boot step (`sandcastle-generalize`) that
  freshens a cloned machine's identity — regenerates SSH host keys + machine-id
  and drops the stale TLS leaf — so children of a base image don't share the
  source machine's identity.

## Public DNS Zones (ADR-0027)

- **Public DNS Zone** — A Cloudflare-hosted public domain (e.g. `hase.de`) an
  admin registers with the install (`sc-adm public-dns-zone add`, also
  `sc admin public-dns-zone`) together with an API token (`Zone > DNS > Edit`
  + `Zone > Zone > Read`, that zone only) the Auth App uses to manage records
  in it. Zones may not nest; the token is stored encrypted and shown only as
  a fingerprint.
- **Project Domain** — The public name a project claims under a Public DNS Zone
  (`sc project create zp --domain baum.hase.de`, `set-domain`,
  `unset-domain`; shown by `sc project status`). At least one label below the
  zone; reserved install-wide, first come, including everything below it. A
  project without one is a private-mode project.
- **Machine Public Hostname** — `<machine>.<Project Domain>`: the public DNS
  name of a machine created in a project that has a Project Domain. Its A
  records (base + `*.` wildcard, DNS-only) point at the machine's tenant-bridge
  address, so it is reachable only over the tenant tailnet; distinct from a
  Public Route, which goes through the edge.
- **Naming Mode** — The per-machine choice, fixed at creation and recorded in
  `user.sandcastle.v2.public-hostname`, between `private` (Machine Private
  Hostname, Tenant CA leaf) and `zone` (Machine Public Hostname, Let's Encrypt
  certificate). Set by the project's Project Domain at create time; a later
  `set-domain`/`unset-domain` never changes an existing machine, which is why
  both are refused while zone-mode machines exist.
- **Machine Certificate** — The publicly trusted certificate the Auth App orders
  (Let's Encrypt, DNS-01 with the zone's token, one per machine for
  `<m>.<d>` + `*.<m>.<d>`), holds, pushes into `/etc/sandcastle/tls/` and
  renews on the CA's ARI schedule. Its state — `pending`, `issued`,
  `installed`, `renewing`, `failed:<reason>` — is mirrored into
  `user.sandcastle.v2.cert-state` (+ `cert-not-after`) and read by `sc ls`
  (CERT column: `pending` / `ok` / `failed` / `-`) and `sc project status`.
- **Caddy Setup Marker** — `/etc/sandcastle/caddy.ready` (`MODE=` / `FQDN=`),
  written last by the payload's `caddy-setup`. The Auth App pushes a
  certificate only when the marker names the expected Machine Public Hostname;
  Dev Image machines never write one and never get a certificate.
- **Zone reconciler** — The zone stage of the Auth App's DNS reconciler (30 s
  ticker + instance events): stamps Freeform Machines' Naming Mode, writes and
  prunes the public A records, orders/renews/pushes Machine Certificates, checks
  for drift, and mirrors the state. Logs as
  `auth-app zone reconcile: <hostname>: …`.
- **ACME directory** (`--acme-directory`) — The Let's Encrypt endpoint the
  install orders Machine Certificates from: production by default,
  `https://acme-staging-v02.api.letsencrypt.org/directory` for e2e and first
  runs. Staging and production never mix; switching re-orders every certificate.
