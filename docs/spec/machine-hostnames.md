> Project certificate update: [project-certificates.md](project-certificates.md)
> supersedes the per-derived-name certificate rules, the prohibition on aliases
> under a machine's own Project Domain, and the zone-apex/wildcard restrictions
> below. Other reservation, authentication and compensation rules still apply.

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
  (`SetMachinePublicHostnames`, an empty set deletes the key); the zone reconciler **converges** it
  to derived + explicit on every pass (§6.1) — a Freeform Machine is stamped on first sight, a
  changed Project Domain re-derives the name — and deletes the legacy single key on the way. The
  legacy key is never stamped any more.
- `user.sandcastle.v2.cert-state` is **per hostname** since slice 3: `host=state[,host=state…]`,
  sorted by host (`meta.FormatCertStates`/`ParseCertStates`); `cert-not-after` is the **earliest**
  expiry among the machine's installed certificates. `meta.Machine` decodes both — `CertStates
  map[string]string` and `CertState` = the worst state (failed > pending > issued > renewing >
  installed; a name without an entry counts as pending) — so `sc ls` folds the worst into its CERT
  column and `sc project status` lists one row per name (§6.3). A bare pre-slice-3 value is read as
  the first name's state.

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
  hook (deletes the name's base + wildcard A records and its `_acme-challenge` TXT; the certificate
  row keeps its own retention, §6.4) → rewrite the key → kick the zone reconciler (the shrunken
  hostnames file is pushed within seconds, not at the next tick). A failed key rewrite after the
  release is logged, never rolled back — the reconciler converges the key. POST kicks the reconciler
  too, so records, the order and the hostnames-file push start at once.
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
listing (no store, or a listing error) only rows of vanished projects go. A reservation that still
exists keeps its certificate row "live" for the zone reconciler's row GC (§6.5): the reservation
says the tenant still wants the name, and this GC is what ends it.

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

- **Slice 2 — machine contract.** Delivered (§5 below): `machine.env` carries the seed
  (`PUBLIC_HOSTNAMES=…` beside the private `FQDN`), `caddy-setup` renders one site block per name
  against a per-hostname certificate directory (`/etc/sandcastle/tls/<hostname>/{cert,key}.pem`), the
  Caddy Setup Marker lists every name it configured, `--bare` and Dev Image variants follow, `sc
  create` prints the private `DNS:` line for every machine again, and `HostKeyAlias`/`known_hosts`
  are finalized. Existing machines converge on the next payload sync + recreate.
- **Slice 3 — reconciler.** Delivered (§6 below): per-hostname A records and orders (the derived
  name and every explicit name, each its own `machine_certificates` row), per-hostname push to its
  directory with a per-hostname marker gate, the derived name re-derived when a Project's domain
  changes (the `set-domain`/`unset-domain` refusal and the legacy `public-hostname` stamp are
  retired), `cert-state` per name, `onMachineHostnameReleased` deleting the name's records, and the
  hostnames file pushed whenever the machine's set changes.
- **Slice 4 — e2e Phase 12g** automates the outline below.

## 5. Machine contract (slice 2, final) — supersedes public-dns-zones §5

Every machine runs the same contract, whatever its public-name set; there is no mode. The
platform payload's `sbin/caddy-setup` (ADR-0022; `tenant.caddyIngressSetupScript`) is the one
script for `sc create`, `--bare`, Freeform Machines, containers and VMs. Dev Image machines run
no `caddy-setup` (no Caddy, no marker, no certificate — they carry public names as records only).

**Payload scripts are POSIX sh.** The boot shims (`/usr/local/sbin/sandcastle-caddy-setup`,
`sandcastle-generalize`) are `#!/bin/sh` and *source* the payload body, so `caddy-setup` and
`generalize` execute under whatever `/bin/sh` is on the image — dash on Debian. They may use nothing
beyond POSIX sh: no process substitution (`<(…)`), `[[ ]]`, arrays, `local -n`, `+=`, `${x//…}`,
`pipefail`, `read -a`, `$'…'`. The goldens in `internal/tenant/caddy_setup_test.go` run the script
with `sh` (dash) exactly as the shim does, and `TestPayloadScriptsArePOSIXSh` rejects the listed
bashisms statically — the live run of 2026-09-13 found a `done < <(…)` that dash refused
("Syntax error: redirection unexpected"): no Caddyfile, no marker, no certificate push.

### 5.1 `machine.env` (cloud-init, per machine)

```
FQDN={{ v1.local_hostname }}.<project>.<suffix>           # the Machine Private Hostname — always
PUBLIC_HOSTNAMES=<seed>                                    # comma list, see below
SIGNER=http://<sidecar>:9443
HOME=/home/<user>                                          # /srv for --bare
```

The cloud-init `fqdn:` is the private name for every project. `PUBLIC_HOSTNAMES` is rendered by the
project's default profile (`tenant.PublicHostnamesEnvLine`) as the derived `{{ v1.local_hostname
}}.<Project Domain>` (only when the project has one) joined with a jinja read of the instance's
`user.sandcastle.v2.public-hostnames` record through cloud-init's datasource
(`ds.config[...]`, guarded so a datasource without it renders `''`). `set-domain`/`unset-domain`
re-render the profile; `--bare` copies the profile's line verbatim (`PublicHostnamesEnvLineOf` →
`V2BareUserDataWithPublicHostnames`); a profile rendered by an older binary has no line, which the
script treats as an empty seed. The line is a **seed**, read once (§5.2); the record of truth is the
instance key and, on the machine, `/etc/sandcastle/hostnames`.

### 5.2 `/etc/sandcastle/hostnames`

One Machine Public Hostname per line. Created by `caddy-setup` from `PUBLIC_HOSTNAMES` only when the
file does not exist (normalized: lower case, no trailing dot, DNS characters only, never the private
name, sorted, deduplicated — `tenant.FormatMachineHostnamesFile` is the Go twin). Afterwards the file
belongs to the Auth App: the reconciler pushes it whole whenever the set changes
(`ZoneMachineServer.PushMachineHostnames`, wired in slice 3) and a certificate push appends the name
if it is missing. An existing empty file means "no public name"; the script never rewrites it.

### 5.3 Certificates

- Private: `/etc/sandcastle/tls/cert.pem` + `key.pem`, the Tenant CA leaf fetched from the sidecar
  signer at first boot, exactly as before public names existed (`tenant.MachineTLSCertPath`).
- Per public name: `/etc/sandcastle/tls/<hostname>/cert.pem` + `key.pem`
  (`tenant.MachineTLSHostCertPath/KeyPath`, directory `MachineTLSHostDir`), pushed by the Auth App
  (`PushMachineCertificate(ctx, project, machine, hostname, cert, key)`: directory created, `.new`
  files 0644/0600 root, one exec `mv && mv && <list name> && sandcastle-caddy-setup --refresh`).
  The private leaf is never overwritten by a push; drift is checked per name against the name's
  `cert.pem`.

### 5.4 `caddy-setup` (first boot) and `caddy-setup --refresh`

```
first boot:  install caddy · trust Tenant CA · fetch private leaf · seed hostnames (if absent)
             · render → validate → install Caddyfile · override.conf · daemon-reload · enable
             · marker · systemctl restart caddy
--refresh:   seed hostnames (if absent) · render → validate → install Caddyfile · marker
             · reload (restart on reload failure) — or start when Caddy is inactive
```

The render is the private block always, then one block per name in the hostnames file whose
directory holds a non-empty `cert.pem` **and** `key.pem`, in file order (sorted). Every block is the
same `site_block NAME CERT KEY` heredoc: `NAME, *.NAME { tls CERT KEY; redir /_h /_h/; redir /_w
/_w/; handle_path /_h/* { root * $HOME; file_server browse }; handle_path /_w/* { root * /workspace;
file_server browse }; handle { reverse_proxy localhost:3000 } }`. It is written to
`/etc/caddy/Caddyfile.new`, `caddy validate`d and moved into place — a failing render leaves the
running Caddyfile and the previous marker untouched and exits nonzero. Caddy is always enabled and
started (the private block always has a certificate): no `ConditionPathExists` drop-in, no
"enabled-inactive" state. `--refresh` is idempotent — the reconciler execs it after every push, and
an operator may run it by hand at any time.

### 5.5 Caddy Setup Marker

`/etc/sandcastle/caddy.ready`, 0644, `KEY=value` lines, written last by both entry points:

```
PRIVATE=web.zp.acme
PUBLIC=shop.tc42.uk           # one line per public block actually rendered (sorted)
PUBLIC=web.baum.hase.de
RENDERED=1757760000           # unix time of this render
```

`tenant.ParseCaddySetupMarker` → `CaddySetupMarker{Private, Public, Rendered, LegacyMode,
LegacyFQDN}`. `ReadyFor(host)` — the reconciler's push gate — is true for **any** non-empty host when
the marker is a per-name marker (`PRIVATE=` present): the name need not be rendered yet, since its
block cannot appear before its push, and the push's `--refresh` renders it. `Serves(host)` answers
"is this name rendered right now" (private name or a `PUBLIC=` line) for diagnostics and the slice-3
per-name verification. An ADR-0027 marker (`MODE=`/`FQDN=`) parses as legacy and never clears the
gate — that machine has no per-name directories and no `--refresh`; it converges after a payload
sync + recreate. Parse failure, a marker with neither `PRIVATE=` nor `MODE=`, or an absent file are
"no marker".

### 5.6 Generalize, SSH naming, output

- `machine-generalize` (image clones) also removes `/etc/sandcastle/hostnames` and every
  `/etc/sandcastle/tls/<name>/` directory, so a machine launched from an `sc image save` image never
  inherits the source's public names or certificates.
- `known_hosts`: one line per machine carrying the private name(s) — `<m>.<p>.<suffix>` and, in the
  default project, `<m>.<suffix>` — then every public name in stamped order; `HostKeyAlias` is the
  Machine Private Hostname (`v2MachineNames`).
- `sc create` prints the `DNS:` line for every machine, then one `Public name: <h> (A record pending,
  <certificate detail>)` line per name (Dev Image: `(A record pending; no Caddy — no certificate)`);
  `--bare` adds `HTTPS: https://<private>   (Caddy with the tenant-CA leaf, …)` and, with public
  names, `HTTPS (public): https://<h>[, https://<h>…]   (Let's Encrypt; served once the certificate
  lands)`.

## 6. Reconciler (slice 3, final) — supersedes public-dns-zones §4.1, §4.2, §4.6 (records), §4.7

The zone stage of the ADR-0018 DNS pass (`internal/authapp/zone_reconcile.go`, 5-minute ticker +
instance lifecycle events + a kick from the hostname/domain endpoints and from every finished
order). Everything public-dns-zones §4 says about ordering (§4.3: ARI, backoff, TXT sweep,
concurrency cap, orders regardless of running state), the push protocol (§4.4 as amended by §5.3),
drift (§4.5) and certificate-row retention (§4.6) still holds — **per (machine, hostname) pair**.

### 6.1 Targets and the list key

For every live Machine of the install the target set is the **union** of its derived name
(`<machine>.<Project Domain>` when its project holds a claim that agrees with the Incus domain key)
and its `machine_hostnames` rows. A Machine with no public name is not a target (the private stage
serves it as before). The list key `user.sandcastle.v2.public-hostnames` is converged to exactly
that set on every pass where it differs — the Freeform Machine's first-sight stamp, the re-derived
name after `set-domain`/`unset-domain`, a stale list after a failed API write — and the legacy
`public-hostname` key is deleted in the same write (its readers would otherwise fall back to it).
Nothing is written when they agree. A project whose Incus key and claim disagree, or that carries
the key without a claim (public-dns-zones §4.6), gets no derived name and its machines' keys,
mirrors and hostnames files are left alone (logged once) — their explicit names are still served.

`set-domain` and `unset-domain` are therefore **allowed with machines in the project** (the §2.2
refusal is retired): a replaced or released domain goes through `onProjectDomainReleased` (its
records and certificate rows), and the next pass re-derives every machine (new list key, records,
a fresh row once the marker is there, hostnames file). Explicit names are unaffected by either.

### 6.2 Per hostname

- **A records** (§4.2 per pair): base + wildcard, relative to the Cloudflare zone containing the
  Public DNS Zone; one `GetRecords` per zone per pass. A zone is reconciled when it holds at least
  one claim **or** one explicit hostname (with an empty target list when nothing under it is live).
  *Managed* records — those the pass may delete as stale — are the A records under a claimed
  Project Domain and exactly the base/wildcard of a reserved explicit hostname; anything else in
  the zone is never touched. A stopped Machine keeps its records; a deleted Machine (also out-of-band)
  loses the records of **all** its names on the next pass, while its explicit reservations wait
  for the 5-minute hostname GC (§2.1), whose release hook finds nothing left to delete.
- **Certificate**: one `machine_certificates` row per hostname (rows come from `sc create`, `sc
  hostname add`, or are created by the reconciler for a name without one when the Machine carries a
  per-name marker — a Dev Image Machine never orders); order, ARI, backoff, sweep and cap as in §4.3
  with the row's own zone; push into `/etc/sandcastle/tls/<host>/` with the one-exec swap +
  `--refresh` (§5.3); the marker gate is `ReadyFor(host)` (a per-name marker exists; read once per
  Machine per pass); drift is checked per name against the name's `cert.pem`.
- **Hostnames file**: for every running Machine with a per-name marker whose set is non-empty, or
  that had names in an earlier pass of this Auth App process, the pass reads
  `/etc/sandcastle/hostnames`; when it does not list exactly the set (a name added or removed, a
  re-derived name, a first-boot seed the datasource read left empty), `PushMachineHostnames` writes
  it whole and runs `--refresh` (§5.2). A Machine that never had a name in this process and has none
  now is not read (the file is only ever wrong on a Machine that had names; the one gap — the last
  name removed and the Auth App restarted before the next pass — is closed by `--refresh` by hand or
  the next add/remove).

### 6.3 Mirroring

After every Machine one write, only when changed: `user.sandcastle.v2.cert-state` =
`host=state[,host=state…]` (sorted by host; states as public-dns-zones §1.5) and
`user.sandcastle.v2.cert-not-after` = the earliest `not_after` among the names whose issued
certificate is the pushed one (a renewed-but-unpushed name contributes the Machine's previous
value). A Machine that loses its last name has both keys deleted. `sc ls` CERT shows the worst
state (`meta.Machine.CertState`); `sc project status` prints one row per (machine, name) with the
name's state — for a project with a Project Domain, or a project without one as soon as a machine
carries an explicit hostname — where NOT AFTER is the Machine's earliest installed expiry (shown on
its `installed`/`renewing` rows) and a machine without a public name reads `private name only`.

### 6.4 Removal

`onMachineHostnameReleased` (DELETE `…/hostnames/{h}`, `DELETE /api/projects/{name}`, the GC)
deletes the name's base + wildcard A records and its `_acme-challenge` TXT and **retains the row**
(public-dns-zones §4.6: a re-added name reuses the certificate without a new order until it
expires). The DELETE endpoint then rewrites the key and kicks the reconciler, whose next pass pushes
the shrunken hostnames file + `--refresh` and drops the name from the mirror. Machine deletion:
records of all its names on the next pass, rows retained. Project domain release/replace: derived
names only (records + rows under the domain, as before); explicit names stay. Zone removal is
refused while hostnames are claimed (§2).

### 6.5 Row GC

Unchanged rule (§4.6) with one clarification: a row is *live* while its hostname is a target
**or** still reserved in `machine_hostnames` — so a `sc create --hostname` claim made before the
instance exists (`beforeCreate`) is never dropped between the claim and the first pass that sees
the Machine, and a vanished Machine's explicit rows follow its reservations out (hostname GC, then
the row on the next pass, once the certificate holds nothing worth retaining).

## 7. e2e Phase 12g (outline; placeholder in `docs/e2e-sc2.md`)

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
6. Slice 2 (machine side, checkable now): `machine.env` carries `PUBLIC_HOSTNAMES=` with the names,
   `/etc/sandcastle/hostnames` lists them, `caddy.ready` reads `PRIVATE=<m>.<p>.<suffix>` (+ `PUBLIC=`
   per rendered name), the private name serves the Tenant CA leaf from the first boot, and
   `sandcastle-caddy-setup --refresh` is idempotent.
7. Slice 3 (reconciler): A records for every name (`dig` per name, base + wildcard), one certificate
   per name pushed into `/etc/sandcastle/tls/<name>/`, Caddy serving every name (`openssl s_client
   -servername` per name; one `PUBLIC=` line per name in the marker), `cert-state` per name
   (`host=state,…`) with `sc ls` CERT `ok` and `sc project status` one row per name; `sc hostname
   add|remove` pushes the hostnames file whole within seconds (records of a removed name gone, row
   retained); `sc project set-domain`/`unset-domain` with machines re-derive their names.
