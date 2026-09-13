# Sandcastle Topology — Architecture Overview

The domain vocabulary is in [`glossary.md`](glossary.md); the runnable end-to-end
proof is [`e2e-sc2.md`](e2e-sc2.md). This document ties the pieces together and
maps them onto the code.

Two principles run through everything:

- **No prebuilt images.** Every container and VM is created from stock upstream
  images (`images:debian/13`), pulled on demand. There is no `sandcastle/base`
  to build or pre-cache.
- **No inbound ports required.** The public Auth Hostname is fronted by an
  outbound Cloudflare tunnel by default (ACME on host `:80/:443` is opt-in); the
  tenant's Incus API and machines are reached over the tenant's tailnet. A host
  behind NAT can run a complete Sandcastle.

## The model

Every Incus-level name derives from the installation **prefix**, chosen at
`sc-adm install --prefix` so several sandcastles can share one Incus host. The
built-in default `sc` normalizes to the Incus project prefix `sc2`
(`naming.NormalizeV2Prefix`), which is what the examples below show; an install
made with `--prefix id` uses `id-` throughout instead. Never derive a project
name from the tenant handle alone — read the real one from `sc remote list` or
`sc ls -a`.

```
Tenant  (the ownership/identity/infra boundary; handle = GitHub username for
 │       login-provisioned tenants, or an admin-minted handle)
 │
 ├── sc2-<tenant>            Incus project = per-tenant infra
 │     └── one sidecar (instance `sidecar`): CoreDNS + Tailscale subnet-router
 │                                           (+ Incus Reach proxy)
 │
 ├── sc2-<tenant>            bridge (in the `default` Incus project)  ← one shared
 │                           network for all the tenant's projects (10.x.y.0/24)
 │
 ├── sc2-<tenant>-default    Incus project (features.networks=false → shared bridge)
 │     ├── default profile   = shared /workspace volume + cloud-init login
 │     ├── homeshare profile = shared /home volume (opt-in: sc create --home-share)
 │     └── machines: dev, web, …   → dev.default.<suffix>  (+ short  dev.<suffix>)
 │
 └── sc2-<tenant>-<project>  Incus project   (a second project; same shape)
       └── machines: dev1, …          → dev1.<project>.<suffix>   (no short form)
```

- **Boundary = Tenant.** Access (a restricted, project-scoped Incus TLS cert),
  DNS, tailnet, storage, and the OIDC issuer are all scoped to the tenant.
- **Project = its own Incus project** (`sc2-<tenant>-<project>`). Machines are
  freeform `incus` instances with native names — `dev` in two projects coexist.
  Each project carries its own shared `/home` + `/workspace` volumes and the
  tenant's login profile — `/workspace` on every machine, `/home` only on
  machines created with `--home-share` (the `homeshare` profile).
- **One shared network per tenant** (`sc2-<tenant>` bridge in `default`);
  projects are not network-isolated from each other (single owner).
- **Per-tenant tailnet, subnet-router sidecar.** Machines are **not** tailnet
  nodes; they sit on the bridge (`10.x`) and are reached over the tenant's
  tailnet via the sidecar's advertised `/24` subnet route. The tenant brings
  their own Tailscale key (or joins the sidecar interactively at login).
- **DNS: `<machine>.<project>.<Tenant DNS Suffix>`** for every machine in every
  project, `default` included (ADR-0018). Exactly one short form exists — the
  Default Project Short Hostname `<machine>.<suffix>`, aliasing the *default*
  project's machine of that name; machines in other projects have none. Each
  record carries a wildcard (`*.<machine>.<project>.<suffix>`). One CoreDNS zone
  per tenant, the only DNS authority; a background reconciler in the Auth App
  registers every running machine automatically. The Tenant DNS Suffix is
  tenant-chosen, single-label, and immutable — it defaults to the tenant name but
  is not required to equal it.
- **A second DNS authority for public names (ADR-0027).** A project may claim a
  Project Domain under a Cloudflare-hosted Public DNS Zone the admin registered;
  machines created in it afterwards carry the Machine Public Hostname
  `<machine>.<domain>` instead of a private one. The same Auth App reconciler
  runs a zone stage for those machines: it writes the public `A` records (base +
  wildcard, DNS-only, pointing at the tenant-bridge address — reachable over the
  tailnet only), orders one Let's Encrypt certificate per machine centrally via
  DNS-01 with the zone's token, pushes cert + key into the machine's Caddy, renews
  on the CA's ARI schedule, and mirrors the certificate state into instance
  config. The sidecar CoreDNS and the Tenant CA are not involved for such
  machines; private-mode machines are unchanged.

## Native `incus`, brokered lifecycle

The tenant's primary interface is the vanilla `incus` client over their
restricted cert — enrolled by `sc login` (or `sc enroll` from a token), pointed
at the sidecar's tailnet IP (the **Incus Reach**: the sidecar proxies the host's
Incus API onto the tenant tailnet, so the host cert is pinned end-to-end). The
`sc` CLI wraps this: `sc c <machine>`, `sc list`, `sc create --vm`, and the
lifecycle commands operate on freeform instances.

Project **lifecycle** (create/delete) is privileged, so it goes through the
**Sandcastle Broker** appliance: `sc project create <name> --broker …` is
authorized by the tenant's restricted cert, and the broker does the scaffolding
(new Incus project + bridge wiring + profile + volumes) and extends the tenant's
certificate to cover it.

## The appliances

All three are stock-image system containers with the one fat binary copied in,
deployed in one command by `sc-adm install`:

| Appliance | Role |
|---|---|
| **Auth App** (`sc2-auth-app`) | GitHub OAuth login + device login; provisions tenants; the OIDC provider for workload identity; the DNS auto-registration reconciler and, for projects with a Project Domain, the zone reconciler (public A records, Let's Encrypt Machine Certificates via DNS-01, cert push into machines — ADR-0027). Terminates its own public hostname (embedded caddy; optional cloudflared for tunnel mode) — no separate edge appliance. |
| **Broker** (`sc2-broker`) | Authorizes and performs tenant + project lifecycle over the host Incus socket. |
| **Sidecar** (instance `sidecar`, in project `sc2-<tenant>`) | Per tenant: CoreDNS (the tenant zone) + Tailscale subnet-router + the Incus Reach proxy. |

## Public ingress

The Auth App appliance terminates its own public hostname (`--ingress`):

- **cloudflare** — `cloudflared` dials out to a Cloudflare tunnel; no inbound
  ports. The installer can create the tunnel + DNS itself (`--cloudflare-api-token`)
  or use a dashboard-made tunnel token.
- **acme** — caddy binds the host's `:80/:443` and gets a real Let's Encrypt
  certificate (needs a public IP + an A record).
- **none** — bring your own edge.

Tenant apps get public HTTPS the same way (a vhost on the same caddy, or a
tunnel host), reaching the machine's bridge IP directly since the host routes
between `incusbr0` and the tenant bridge.

## Open / deferred

- **Multi-host clusters:** the shared edge reaching tenant bridges relies on
  single-host routing. Revisit for clustering.
- **Split-DNS over tailscale:** serving the tenant zone to tailnet clients on the
  sidecar's tailnet IP (so `ssh dev.<tenant>` resolves client-side) is future work.
- **Per-tenant CA / private HTTPS:** the tenant-CA leaf path (for `sc trust
  install`) is not yet issued; the public ingress path needs no CA install.
