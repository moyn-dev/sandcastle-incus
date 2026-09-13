# Spec: Machine Public Hostnames — explicit names, one certificate each (addendum to Public DNS Zones)

> Decision record: ADR-0028 (`docs/adr/0028-explicit-machine-public-hostnames.md`), amending
> ADR-0027. Map: issue #172 (slices #173 slice 1 — this document's data model, API and CLI;
> slice 2 — the machine contract; slice 3 — the per-hostname reconciler; slice 4 — e2e Phase 12g).
> Everything not restated here is `docs/spec/public-dns-zones.md`'s and still applies.

Glossary terms are `CONTEXT.md`'s: **Machine Public Hostname** (now one of a Machine's *set* of
public names), **Project Domain**, **Public DNS Zone**, **Machine Certificate**, **Caddy Setup
Marker**, **Machine Private Hostname**, **Public Route**, **Auth Hostname**. **Naming Mode** is
superseded.

## Goal

A tenant gives a Machine public names beyond `<machine>.<Project Domain>` — at creation
(`sc create zp:web --hostname web12.tc42.uk --hostname shop.tc42.uk`) or later (`sc hostname add
zp:web api.tc42.uk`) — in a Project with or without a Project Domain. Each name is reserved
install-wide like a Project Domain, gets its own Let's Encrypt certificate (name + `*.name`) and,
with slices 2–3, its own A records and Caddy site block. The Machine keeps its Machine Private
Hostname throughout.

## 1. Data model

### 1.1 Auth Database

```sql
CREATE TABLE IF NOT EXISTS machine_hostnames (
    hostname   TEXT PRIMARY KEY,                  -- normalized explicit Machine Public Hostname
    tenant     TEXT NOT NULL,
    project    TEXT NOT NULL,                     -- short project name
    machine    TEXT NOT NULL,
    zone       TEXT NOT NULL REFERENCES public_dns_zones(zone),
    user_key   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS machine_hostnames_machine ON machine_hostnames(tenant, project, machine);
```

A row is the reservation of exactly that name plus its wildcard subtree. **The derived name
`<machine>.<Project Domain>` is not a row**: it is implied by the project's `project_domain_claims`
row, which already reserves the whole subtree. `machine_certificates` (public-dns-zones §1.3) is
unchanged: one row per hostname, whatever kind; `POST …/hostnames` creates the pending row through
the same `requestMachineCertificate` path `sc create` uses for the derived name.

### 1.2 Normalization and validation (`internal/authapp/machine_hostnames.go`)

Normalization is the Project Domain one (lowercase, trim, one trailing dot, ASCII labels, no
`_`/`*` labels; `domain.NormalizeMachineHostname`, wording `invalid machine hostname …`). Then:

1. Zone lookup: unique longest-suffix match against `public_dns_zones`; none → `no Public DNS Zone
   covers <h> — ask your admin` (admin view: `…; registered zones: …`).
2. `h != zone`: the apex itself is refused (`machine hostname "<h>" is a zone apex; use at least
   one label below <zone>`). **Apex-level** names (`web12.tc42.uk` under `tc42.uk`) are allowed
   (ADR-0028 decision 2) — unlike Project Domains, no "at least one label" rule beyond that.
3. `len("*.") + len(h) <= 253` (the certificate covers the one-level wildcard).

### 1.3 Conflict classes — unified with Project Domains and Public Routes, both directions

Candidate hostname `h`; every class blocks regardless of tenant, the class only shapes the text.

| Class | Test | Text |
|---|---|---|
| install | `h` equals, is above, or is below the Auth Hostname or the route base domain | `machine hostname "<h>" is reserved by this install` |
| route | a `routes.hostname` `r` (leading `*.` stripped): `r == h` or `r` inside `h` | same install text |
| domain | a `project_domain_claims.domain` `d`: `d == h`, `h` inside `d`, or `d` inside `h` | same tenant: `machine hostname "<h>" overlaps project domain "<d>" claimed by project "<p>" in this tenant`; else flat |
| exact / ancestor / descendant | another `machine_hostnames.hostname` `x`: `x == h`, `x` inside `h`, `h` inside `x` | same tenant: `machine hostname "<h>" overlaps "<x>" held by machine "<p>:<m>" in this tenant`; else flat |

Flat (cross-tenant) text: `machine hostname "<h>" overlaps a name already claimed on this install;
choose another`. A same-machine identical re-claim is a no-op (`machine hostname "<h>" already held
by this machine`, exit 0). Note that a hostname inside the caller's **own** Project Domain is refused
too (`api.baum.hase.de` for a machine of the project holding `baum.hase.de`): the derived names of
that domain are the project's, and a hostname there would collide with a future machine `api`.

**Reverse checks** (the same scan, from the other side):

- `ClaimProjectDomain` gains class `hostname` (`DomainClaimConflictHostname`): a candidate domain that
  equals, covers or sits inside any `machine_hostnames` row is refused — same tenant:
  `project domain "<d>" overlaps hostname "<x>" held by machine "<p>:<m>" in this tenant`; cross-tenant
  the flat Project Domain text.
- `UpsertRoute`: a custom route hostname (leading `*.` stripped) that equals or sits inside a hostname
  is refused with `route hostname "<r>" is inside machine hostname "<x>" claimed on this install`. A
  route *above* a hostname is not blocked (a route reserves one level; same as with Project
  Domains).

**Transaction.** Both registries share one `BEGIN IMMEDIATE` scan (`withReservationLock` +
`loadInstallReservations` read claims, hostnames and route hostnames on the locked connection);
INSERT and COMMIT follow the scan. The `hostname` PRIMARY KEY is the last line of defence. A
concurrency test (8 claimers, one name) pins "exactly one wins".

### 1.4 Instance key — `user.sandcastle.v2.public-hostnames` (`meta.KeyV2PublicHostnames`)

Comma-separated, **sorted**, lowercase list of every Machine Public Hostname of the instance: the
derived name when the project holds a Project Domain, plus every explicit hostname. It supersedes the
single `user.sandcastle.v2.public-hostname` (ADR-0027) — which is now legacy:

- **Readers accept both** during the transition: `meta.PublicHostnamesFromConfig` takes the list when
  present, else the single key (unless it is the literal `private`), else nothing. `meta.Machine`
  gains `PublicHostnames []string`; `PublicHostname` is kept one release as the **first element** of
  the sorted list. `meta.Machine.PublicNames()` tolerates a payload that carries only the single
  field (an older Auth App's resource cache).
- **Writers write only the list**: `sc create` stamps it in the create call (never the single key,
  never empty — an empty set stamps nothing); the Auth App rewrites it on every add/remove
  (`SetMachinePublicHostnames`, an empty set deletes the key). The zone reconciler still stamps the
  legacy key on a machine that carries neither (Freeform Machine) and reads the derived name off the
  list when present; slice 3 retires the legacy stamp.
- `user.sandcastle.v2.cert-state` / `cert-not-after` stay one value per machine in slice 1 (the
  derived name's); slice 3 folds per-hostname states.

## 2. Auth App endpoints (tenant plane, CLI Auth Token)

```
GET    /api/machines/{project}/{machine}/hostnames            ?tenant=
POST   /api/machines/{project}/{machine}/hostnames            {hostname, tenant?, dryRun?, beforeCreate?}
DELETE /api/machines/{project}/{machine}/hostnames/{hostname} ?tenant=&dryRun=1
```

Authorization is the machine-certificates one: the caller's own tenant, or one it is granted
(`authorizeWorkloadTenant`); 403 otherwise. Mutations answer 501 without the Incus seam
(`machine hostnames are not available on this deployment`). Result body, every success:

```json
{"tenant":"acme","project":"zp","machine":"web","hostname":"web12.tc42.uk","zone":"tc42.uk",
 "hostnames":[{"hostname":"web.baum.hase.de","derived":true,"zone":"hase.de"},
              {"hostname":"web12.tc42.uk","zone":"tc42.uk","createdAt":"…"}],
 "released":"…","alreadyHeld":false,"dryRun":false,
 "certificate":{"hostname":"web12.tc42.uk","state":"pending"}}
```

- **POST**: claim (§1.3; 409 conflict / 400 validation, `{error}` verbatim) → pending
  `machine_certificates` row (reusing `requestMachineCertificate`; a retained certificate reports
  `state: issued`) → rewrite the instance key from the registries (derived + explicit) unless
  `beforeCreate`. `beforeCreate` is `sc create --hostname`'s: the instance does not exist yet and the
  create call stamps the key itself. A failed Incus write (machine missing → 404, project missing →
  404, other → 500) releases the reservation again (compensation), exactly like a failed
  `CreateTenantProjectWithDomain`. `dryRun` validates and scans in a rolled-back transaction and
  returns the would-be set.
- **DELETE**: release (404 `machine hostname "<h>" is not held by machine "<p>:<m>"` — a foreign
  holder is never revealed; the derived name is not removable per machine) → `onMachineHostnameReleased`
  hook → rewrite the key. The hook is a named no-op in slice 1; slice 3 fills in "delete the A
  records" (the certificate row keeps its own retention). A failed key rewrite after the release is
  logged, never rolled back.
- **GET**: the full set, derived flagged.
- **`DELETE /api/projects/{name}`** releases every hostname of the project's machines (after the
  domain claim, before Incus), through the same hook.
- **Zone removal** (`DELETE /api/public-dns-zones/{zone}`) is also refused while hostnames are held
  under the zone: `public DNS zone <z> still has machine hostnames: <h> (<tenant>/<p>:<m>), …; remove
  them first` (Project Domains are reported first when both block).

### 2.1 GC (slow loop, 5 min, with the Project Domain GC)

`ReconcileMachineHostnames`: a row whose `<tenant>/<project>` is not a live project, or whose machine
is absent from the machine listing, is dropped through the release hook. **Nothing is retained** —
retention is `machine_certificates`' own rule. An empty live set is never trusted; without a machine
listing (no store, or a listing error) only rows of vanished projects go. Explicit hostnames are
"live" for the zone reconciler's certificate-row GC, so their pending rows survive until slice 3
orders them.

## 3. CLI

```
sc create <p>:<m> --hostname <fqdn> [--hostname <fqdn> …]     # --fqdn is an alias; both feed one list
sc hostname add    <p>:<m> <fqdn>   [--dry-run]
sc hostname remove <p>:<m> <fqdn>   [--dry-run]                 # alias rm
sc hostname list   <p>:<m>                                      # alias ls
```

All take the global `--json`/`--output json`. Every verb needs `sc login`; without an Auth App:
`--hostname is not available on this install (log in to an Auth App with sc login)`. The CLI
normalizes and refuses the obviously malformed locally; server refusals print verbatim.

- `sc create`: names are claimed **before** `CreateInstance` (`beforeCreate`); the first refusal
  releases what was already claimed and creates nothing; a failed create releases every claim (a
  release failure is appended to the error; the GC covers the rest). The create call stamps the full
  set. Output: one `Public name: <name> (…)` line per name — the derived line unchanged from ADR-0027,
  explicit lines with the certificate detail the claim reported (`certificate pending`, `certificate
  retained, installing`, `certificate pending: rate-limited — …`). A project **without** a domain keeps
  its `DNS:` line above the `Public name:` lines; a project with one prints only the public lines
  (slice 2 restores the private line there). `--dry-run` validates the names server-side (rolled
  back) and prints the same lines with the default pending text. `--json` carries `publicHostnames`
  (and `publicHostname`, the first).
- `sc hostname add` prints `Public name: <h> (<certificate detail>)` and the machine's full set as a
  `PUBLIC NAME / KIND / ZONE` table (`derived` / `explicit`); `remove` prints `Released <h> from
  machine <p>:<m>.` + the table; `list` the table (`Machine <p>:<m> has no public name.` when empty).
- `sc ls`: the FQDN column shows the first public name and `(+N)` when there are more; `--json`
  carries the list. `sc project status` keeps showing the first name per machine.
- `sc connect` / `sc ssh-key purge`: `v2MachineNames` returns the private name(s) **then** every
  public name; `HostKeyAlias` stays the Machine Private Hostname (slice 2 finalizes SSH naming).

## 4. What slices 2–3 owe

- **Slice 2 — machine contract.** `machine.env` carries the set (`FQDNS=…` beside the existing
  `FQDN`), `caddy-setup` renders one site block per name against a per-hostname certificate directory
  (`/etc/sandcastle/tls/<hostname>/{cert,key}.pem`), the Caddy Setup Marker lists every name it
  configured, `--bare` and Dev Image variants follow, `sc create` prints the private `DNS:` line for
  every machine again, and `HostKeyAlias`/`known_hosts` are finalized. Existing machines converge on
  the next `sc fix` / payload sync.
- **Slice 3 — reconciler.** Per-hostname A records and orders (the derived name and every explicit
  name, each its own `machine_certificates` row), per-hostname push to its directory with a
  per-hostname marker gate, the derived name re-derived when a Project's domain changes (retiring the
  `set-domain`/`unset-domain` refusal and the legacy `public-hostname` stamp), `cert-state` folded
  across names, `onMachineHostnameReleased` deleting the name's records, and the explicit-hostname
  rows no longer exempt from the row GC by fiat.
- **Slice 4 — e2e Phase 12g** automates the outline below.

## 5. e2e Phase 12g (outline; placeholder in `docs/e2e-sc2.md`)

Gate as Phase 12. `ZONE` is the test zone; `zp` holds `e2e-$RUN.$ZONE`; `pp` is a project without a
domain.

1. `sc create zp:web --hostname web12-$RUN.$ZONE --fqdn shop-$RUN.$ZONE` — two `Public name:` lines
   beside the derived one; the instance key lists all three sorted; `sc ls` shows the first `(+2)`;
   (DB) two `machine_hostnames` rows (the derived name is not a row) and three
   `machine_certificates` rows.
2. `sc create zp:dup --hostname web12-$RUN.$ZONE` — refused with the same-tenant text, **no
   instance created**, no row leaked.
3. `sc create pp:solo --hostname solo-$RUN.$ZONE` — `DNS:` line kept, one `Public name:` line;
   `sc project set-domain pp …` still allowed (explicit names never block).
4. `sc hostname add zp:web api-$RUN.$ZONE` / `list` / `remove` — key rewritten each time; `remove`
   of the derived name is refused; a second tenant's `add` of `x.web12-$RUN.$ZONE` is refused flat;
   `sc project create x --domain web12-$RUN.$ZONE` and `sc route publish … --hostname
   www.web12-$RUN.$ZONE` are refused (reverse checks).
5. `sc-adm public-dns-zone remove $ZONE` refused while hostnames are held; `sc delete zp:web`
   (out-of-band `incus delete` variant) — within 5 min the GC prunes the rows; `sc project delete pp
   --yes` releases `solo-$RUN.$ZONE`.
6. Slices 2–3 add: A records and certificates per name, Caddy serving every name, `openssl
   s_client -servername` per name, `known_hosts` lines for every name.
