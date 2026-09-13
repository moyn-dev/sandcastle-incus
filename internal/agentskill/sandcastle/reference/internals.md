# Sandcastle internals

What the names mean, where state lives, and what the JSON looks like.

## Naming

An install has a **prefix**, chosen at `sc-adm install --prefix` (default `sc`,
which normalizes to the Incus project prefix `sc2`). Every name derives from it:

| Thing | Name |
|---|---|
| Tenant infra Incus project | `<prefix>-<tenant>` |
| App Incus project (one per project) | `<prefix>-<tenant>-<project>` |
| Shared per-tenant bridge (in Incus project `default`) | `<prefix>-<tenant>` |
| Per-install appliance bridge | `<prefix>-net` |
| Sidecar instance (inside the infra project) | `sidecar` |
| Auth App / Broker appliance | `<prefix>-auth-app` / `<prefix>-broker` |
| Machine instance | the bare Sandcastle machine name — no mangling |
| Enrolled incus remote | the install's Tenant DNS Suffix (older installs: `sc-<tenant>`, or `sc-<prefix>-<tenant>`) |

A long tenant handle whose bridge name would exceed the 15-character interface
limit falls back to a stable hashed name.

**Read the real names rather than deriving them.** `sc remote list` shows each
install's pinned project; `sc ls -a` shows every FQDN. A tenant's restricted
certificate cannot see its own infra project, so `sc status` reports CIDR and
topology as `unknown` — that is expected, not a fault.

## DNS

- Canonical: `<machine>.<project>.<suffix>`
- Default-project alias: `<machine>.<suffix>` — only for the tenant's default
  project; other projects have no short form.
- Wildcard: `*.<machine>.<project>.<suffix>` resolves to the same machine.
- One CoreDNS zone per tenant, served by the sidecar. The Auth App reconciler
  registers every running machine within seconds of creation (30s loop as
  backstop).

Per-tenant CIDR is one `/24` from the install's pool. Role addresses: gateway
`.1`, Tailscale `.2`, DNS `.3`.

## Topology

```
Tenant
 ├── <prefix>-<tenant>              infra Incus project
 │     └── sidecar                  CoreDNS + Tailscale subnet router + Incus Reach proxy
 ├── <prefix>-<tenant>              bridge, in Incus project `default` (10.x.y.0/24)
 └── <prefix>-<tenant>-<project>    app Incus project (features.networks=false)
       ├── default profile          shared /workspace volume, bridge NIC, cloud-init login
       ├── homeshare profile        shared /home volume (opt-in, --home-share)
       └── machines
```

- **Incus Reach** — the sidecar's `tailscale serve` proxy forwards its tailnet
  `:8443` to the host's Incus API, so the tenant's enrolled remote points at the
  sidecar's tailnet IP and the host certificate is pinned end to end. No host
  port is exposed.
- Machines are **not** tailnet nodes. They are reached over the sidecar's
  advertised `/24` subnet route, which must be approved on the tailnet (a
  `tag:sandcastle` autoApprover rule is the zero-touch way) and accepted by the
  client (`tailscale up --accept-routes`).
- Projects share one bridge and are not network-isolated from each other. The
  bridge carries `dns.mode=none`, so the same machine name in two projects is
  fine.
- Appliances are stock-image system containers with the one fat binary copied
  in. No prebuilt Sandcastle images are required anywhere.

## Files on disk (client)

| Path | Contents |
|---|---|
| `~/.config/sandcastle/config.yml` | tenant, project, remote, admin_remote, auth_hostname, and the per-install / per-remote token, broker, and tenant maps |
| `~/.config/sandcastle/incus/` | the shared Incus config dir: one client keypair, every enrolled install as a remote |
| `~/.config/sandcastle/<remote>/incus/` | per-remote restricted certificates (older layout) |
| `~/.config/incus/` | the **admin** Incus config — what `sc-adm` uses |
| `~/.ssh/known_hosts` | Sandcastle host keys, tagged `# sandcastle:<remote>/<tenant>` |
| `~/.config/sandcastle/update-state.json` | update-notifier throttle state |

`config.yml` keys worth knowing: `remote_auth_tokens`, `remote_brokers`, and
`remote_tenants` map an enrolled remote to its bearer token, broker URL, and
tenant, so switching remotes swaps identity coherently. `auth_tokens` and
`brokers` are the older per-Auth-Hostname maps, which cannot tell two tenants of
one install apart.

The config file holds **bearer tokens in cleartext**. Redact it before pasting
anywhere.

## Environment variables

| Variable | Effect |
|---|---|
| `SANDCASTLE_REMOTE` | override the active install for one invocation |
| `SANDCASTLE_TENANT` / `SANDCASTLE_PROJECT` | override tenant / project |
| `SANDCASTLE_AUTH_HOSTNAME` / `SANDCASTLE_AUTH_TOKEN` / `SANDCASTLE_BROKER` | override the auth plane |
| `SANDCASTLE_ADMIN_REMOTE` | Incus remote for admin commands |
| `VERBOSE=1` | print `[verbose]` diagnostics on stderr, including which resolution path was used |
| `SANDCASTLE_CONNECT_CACHE=0` | force `sc connect` onto the live path |
| `SANDCASTLE_LS_CACHE_TIMEOUT` | budget for the `sc ls` cache request (default 5s) |
| `SANDCASTLE_NO_UPDATE_NOTIFIER=1` | silence release and skew notices |
| `INCUS_CONF` | the Incus config dir; `sc` points it at the install's restricted certs, `sc-adm` leaves it at the admin dir |

`SANDCASTLE_INCUS_PROJECT_PREFIX`, `SANDCASTLE_CIDR_POOL`, `SANDCASTLE_STORAGE_POOL`,
`SANDCASTLE_BASE_IMAGE` / `_AI_IMAGE` / `_DEV_IMAGE`, and the `SANDCASTLE_AUTH_*`
family configure the operator side; `SANDCASTLE_E2E_*` gate the test harnesses.

Config resolution order: CLI flags → `SANDCASTLE_*` env → seed file → built-in
defaults.

## JSON shapes

`--json` (or `--output json`) on any command. The shapes scripts depend on:

- `sc info` → `{tenant, project, remote, authHostname, projects[]}`
- `sc ls` → `{tenant, remote, project, machine, allProjects, machines[], unmanaged[], unmanagedCount}`;
  with `--networks` / `--profiles` / `--images` / `--storage-pools` /
  `--storage-volumes` those arrays are populated too — **but only on the
  cache-backed path**; on the live fallback the flags are silent no-ops.
- A `sc ls` whose install part globs returns `{remotePattern, remotes[], warnings[]}`
  instead — one `listPayload` per install swept.
- A machine in `machines[]` → `{tenant, project, name, type, privateIP, linuxUser,
  running, bare, createdAt, createdBy, …}`.
- Lifecycle commands: a **literal** reference returns `{action, tenant, project,
  machine}`; a **glob** returns `{action, tenant, selector, results[]}`, each
  result naming its remote on a cross-install sweep.
- `sc status` / tenant listings return `tenant.Summary`:
  `{incusName, infraProject, tenant, dnsSuffix, defaultProject, privateCIDR,
  dnsAddress, unixUser, projects[], status, tailscale, publicRoutes[]}`.

## Vocabulary

Inside a `sandcastle-incus` checkout, the canonical term list is
`docs/glossary.md`, the architecture overview is `docs/topology.md`, resolved
design decisions are the ADRs under `docs/adr/`, and `docs/e2e-sc2.md` is the
executable behavioural source of truth — a change not reflected there is not
done. Outside a checkout, this skill is the reference.

Tenant topology **version 1 is gone**. Every tenant is v2; surviving `v1`
mentions in Go are historical comments. Never add a version gate or a v1
fallback.
