# Spec: Public DNS Zones — Machine Public Hostnames with Let's Encrypt certificates

> Decision record: ADR-0027 (`docs/adr/0027-public-dns-zones-machine-certificates-via-dns01.md`).
> Map: issue #155. Resolved tickets this spec transcribes: #156 (ACME client), #157 (certificate
> lifecycle), #158 (Project Domain claims), #159 (machine-side contract), #160 (CLI surface).
> Research: `docs/research/acme-client-for-auth-app-2026-09-12.md`.

Glossary terms are `CONTEXT.md`'s: **Public DNS Zone**, **Project Domain**, **Machine Public
Hostname**, **Naming Mode**, **Caddy Setup Marker**, **Freeform Machine**, **Machine Certificate**,
plus the existing **Machine Private Hostname**, **Tenant DNS Suffix**, **Tenant CA**, **Public Route**,
**Auth App**, **Auth Database**, **Auth Hostname**, **Tenant Tailnet**.

## Goal

An admin registers a Public DNS Zone (`sc-adm public-dns-zone add hase.de --token …`) — a Cloudflare
zone, or any name inside one (`e2e.sc.tc42.uk` inside `tc42.uk`; records are written into the
containing Cloudflare zone under their full names); a tenant
claims a Project Domain under it (`sc project create baum --domain baum.hase.de`); every Machine
created afterwards in that project is `web.baum.hase.de` with a public A record pointing at its
tenant-bridge address and a Let's Encrypt certificate for `web.baum.hase.de` + `*.web.baum.hase.de`,
issued by the Auth App over DNS-01 and pushed into the Machine's Caddy. A stock browser on the
Tenant Tailnet gets a trusted `https://web.baum.hase.de` with no trust or resolver setup.

## Non-goals

- No change to private-mode Machines, the Tenant CA, `sc trust`, the sidecar CoreDNS, the sidecar
  `tls-sign` signer, or the client resolver. They are legacy from now on, not removed.
- No migration of existing Machines. A Machine is `private` or `zone` for life.
- No tenant-supplied zones, no non-Cloudflare providers, no Internet-facing Machine ingress
  (ADR-0013 stands), no Public Route targeting a Machine Public Hostname.
- No revocation, ever, except manually on key compromise.
- No sidecar change.

## 1. Data model

### 1.1 Incus config keys (`internal/meta/meta.go`)

All keys are under the existing `user.sandcastle.v2.` prefix and must be mirrored as `keyV2…`
constants in `incusx` where that package already duplicates them.

| Constant | Key | On | Value | Written by | Rewritten? |
|---|---|---|---|---|---|
| `KeyV2Domain` | `user.sandcastle.v2.domain` | app project | Project Domain, normalized | Auth App (`POST /api/projects`, `PUT …/domain`); removed by `DELETE …/domain` | on `set-domain`/`unset-domain` only |
| `KeyV2PublicHostname` | `user.sandcastle.v2.public-hostname` | instance | `<m>.<pd>` or the literal `private` | `sc create` at creation; reconciler on first sight of a Freeform Machine | **never** — this key *is* the Naming Mode record |
| `KeyV2CertState` | `user.sandcastle.v2.cert-state` | instance | `pending` \| `issued` \| `installed` \| `renewing` \| `failed:<reason>` | reconciler, every pass where it changed | yes |
| `KeyV2CertNotAfter` | `user.sandcastle.v2.cert-not-after` | instance | RFC 3339 UTC of the *installed* certificate, empty until installed | reconciler | yes |

Naming Mode is derived from `KeyV2PublicHostname`: absent or `private` → `private`; anything else →
`zone` with that Machine Public Hostname. "Absent" covers every Machine created before this feature,
so the fleet is private by default. The reconciler stamps `private` on an unstamped Machine in a
project **without** a domain too, so a later `set-domain` cannot retroactively flip it (this is the
only case where the reconciler stamps a non-zone value).

`KeyV2CertState`/`KeyV2CertNotAfter` are written only for zone-mode Machines. They exist so the
ADR-0023 cache path and the live Incus path render identically — no CLI code ever queries the Auth
Database for certificate state.

### 1.2 `meta.Machine`

```go
// zone mode (ADR-0027); empty for private-mode machines
PublicHostname string `json:"publicHostname,omitempty"` // user.sandcastle.v2.public-hostname unless "private"
CertState      string `json:"certState,omitempty"`      // user.sandcastle.v2.cert-state
CertNotAfter   string `json:"certNotAfter,omitempty"`   // user.sandcastle.v2.cert-not-after
```

`DecodeMachine` (and the resource-cache instance → `meta.Machine` conversion) fill them from the
instance config. `meta.Project` gains `Domain string` from `KeyV2Domain`; `tenant.Summary`'s project
entries carry it so `sc project status` and `sc create` can read it without a second call.

### 1.3 Auth Database tables (`internal/authapp/app.go` migration block)

```sql
CREATE TABLE IF NOT EXISTS public_dns_zones (
    zone               TEXT PRIMARY KEY,          -- normalized (lowercase, no trailing dot)
    cloudflare_zone    TEXT NOT NULL DEFAULT '',  -- the Cloudflare zone containing it, resolved at add time ('' = zone itself, pre-column rows)
    cloudflare_zone_id TEXT NOT NULL,             -- resolved at add time
    encrypted_token    TEXT NOT NULL,             -- AES-GCM under the auth_app_meta deployment key (see 1.4)
    created_by         TEXT NOT NULL DEFAULT '',  -- admin user key
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_domain_claims (
    domain     TEXT PRIMARY KEY,                  -- normalized Project Domain
    tenant     TEXT NOT NULL,
    project    TEXT NOT NULL,                     -- short project name
    zone       TEXT NOT NULL REFERENCES public_dns_zones(zone),
    user_key   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (tenant, project)                      -- one domain per project
);

CREATE TABLE IF NOT EXISTS acme_storage (          -- certmagic.Storage key/value: account key + solver state
    key         TEXT PRIMARY KEY,
    value       BLOB NOT NULL,
    modified_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS machine_certificates (
    hostname        TEXT PRIMARY KEY,             -- Machine Public Hostname; retained across machine delete
    tenant          TEXT NOT NULL,
    project         TEXT NOT NULL,
    machine         TEXT NOT NULL,
    zone            TEXT NOT NULL,
    directory_url   TEXT NOT NULL,                -- which CA issued it (staging vs production never mix)
    cert_pem        TEXT NOT NULL DEFAULT '',     -- full chain; empty = never issued
    key_pem         TEXT NOT NULL DEFAULT '',     -- ECDSA P-256, encrypted like encrypted_token
    serial          TEXT NOT NULL DEFAULT '',
    fingerprint     TEXT NOT NULL DEFAULT '',     -- sha256 of the leaf DER, for the drift check
    not_before      TEXT NOT NULL DEFAULT '',
    not_after       TEXT NOT NULL DEFAULT '',
    renew_after     TEXT NOT NULL DEFAULT '',     -- ARI window start; fallback 2/3 of lifetime elapsed
    ari_check_after TEXT NOT NULL DEFAULT '',     -- ARI Retry-After; default now+6h
    pushed_serial   TEXT NOT NULL DEFAULT '',     -- serial last confirmed on the machine
    last_error      TEXT NOT NULL DEFAULT '',
    attempts        INTEGER NOT NULL DEFAULT 0,   -- consecutive failures, drives backoff
    next_attempt_at TEXT NOT NULL DEFAULT '',
    requested_at    TEXT NOT NULL,                -- when sc create / reconciler asked for it
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS machine_certificates_tenant_project ON machine_certificates(tenant, project);
```

certmagic's `Storage` interface also has `Lock`/`Unlock`; because there is exactly one Auth App per
install (ADR-0021) these are an in-process mutex map keyed by name, not rows.

### 1.4 Secrets at rest

Zone tokens and machine private keys are encrypted with the same mechanism as
`oidc_signing_keys.encrypted_private_key` (`encryptOIDCPrivateKey`/`decryptOIDCPrivateKey`, key held
in `auth_app_meta`). Generalize those two functions to `encryptSecret`/`decryptSecret` with a
purpose-labelled key (`public_dns_zone_key`, `machine_cert_key`) derived on first use the way
`oidcEncryptionKey` is. Tokens are never logged, never returned by any endpoint (`list` shows the
zone, the containing Cloudflare zone and its id, a token fingerprint `sha256[:8]`, created-by, created-at).

A Public DNS Zone may be the Cloudflare zone itself or any name inside one. Cloudflare tokens are
zone-scoped, so the zone the token can see that equals the Public DNS Zone or is its parent on a
label boundary (the longest such match) is the **Cloudflare zone** of the row; every libdns call
(`GetRecords`/`SetRecords`/`DeleteRecords`, the challenge sweep, the release) is addressed to it,
and record names are `libdns.RelativeName(<fqdn>, <cloudflare zone>)` — `web.baum.e2e.sc` in
`tc42.uk` for `web.baum.e2e.sc.tc42.uk`. certmagic's DNS-01 solver finds the zone by SOA on its
own. `cloudflare_zone` is added by a guarded `ALTER TABLE` so older databases migrate in place;
their rows were registered by exact name and read as their own Cloudflare zone.

### 1.5 Machine Certificate state (derived, never stored)

| State | Condition |
|---|---|
| `pending` | `cert_pem = ''` and `last_error = ''` |
| `failed:<reason>` | `cert_pem = ''` and `last_error != ''` (in backoff); or `not_after < now` |
| `issued` | `cert_pem != ''` and `pushed_serial != serial` |
| `installed` | `pushed_serial = serial` and `now < renew_after` |
| `renewing` | `pushed_serial = serial` and `now >= renew_after` (a `last_error` here is carried as detail in `sc project status`, not as `failed`, because the installed certificate is still valid) |

`<reason>` is a short, fixed-vocabulary token, not the raw ACME error: `rate-limited`, `dns-propagation`,
`cloudflare-rejected`, `validation`, `auth-app-unreachable`, `expired`, `other`. The raw error is in
`last_error` and in `sc project status`.

`sc ls` `CERT` column mapping: private → `-`; `pending`, `issued` → `pending`; `installed`, `renewing`
→ `ok`; `failed:*` → `failed`.

## 2. CLI

Every mutating verb below takes `--dry-run` (prints what would be done, touches nothing).

### 2.1 Zone registry (admin) — on **both** roots: `sc admin public-dns-zone …` and `sc-adm public-dns-zone …`

All four verbs are thin clients of `/api/public-dns-zones` (§3.1) using the admin bearer token
(`requireAdmin`), so they work through a tunnel and need no appliance restart or redeploy.

```
public-dns-zone add <zone> (--token <t> | --token-file <path> | token on stdin)
public-dns-zone list [-o json]
public-dns-zone remove <zone>
public-dns-zone set-token <zone> (--token <t> | --token-file <path> | token on stdin)
```

- `add`: normalizes the zone (lowercase, trim, strip trailing dot; labels via `validateDomainLabels`),
  calls the Auth App, which validates the token against Cloudflare: it lists the zones the token can
  read (`GET /zones?per_page=50`, following `result_info` paging) and picks the one whose name equals
  the Public DNS Zone or is its parent on a label boundary — the longest such match (the token may see
  both `tc42.uk` and `sc.tc42.uk`); then `GET /zones/<id>/dns_records?per_page=1` against it proves
  `DNS` read. The Cloudflare zone's name and id are stored. No containing zone →
  `Cloudflare rejected the token for zone <zone>: the token cannot see a zone containing <zone> (check Zone > Zone > Read and the zone the token is scoped to)`.
  Existing zone → `public DNS zone <zone> is already registered (use set-token to rotate its token)`.
  Nesting (`add hase.de` when `sc.hase.de` exists, or vice versa) →
  `public DNS zone <zone> overlaps registered zone <other>; zones may not nest`.
  Rejected token → `Cloudflare rejected the token for zone <zone>: <api message>` and nothing is stored.
- `list`: table `ZONE  CLOUDFLARE-ZONE  CLOUDFLARE-ID  TOKEN  CLAIMS  CREATED-BY  CREATED` (CLOUDFLARE-ZONE = the
  containing Cloudflare zone resolved at add time, TOKEN = fingerprint, CLAIMS = count of Project Domains under it).
- `remove`: refused while any Project Domain is claimed under it —
  `public DNS zone <zone> still has claimed project domains: <d1> (<tenant>/<project>), …; unset them first`.
  No `--force`.
- `set-token`: same Cloudflare validation as `add`, rotates in place (re-resolving the Cloudflare zone —
  the new token may be scoped to a closer one), same rejection text.
- Required token scope, printed in the `add` help text and docs: `Zone > DNS > Edit` + `Zone > Zone > Read`
  on the Cloudflare zone containing the Public DNS Zone (Read is used only at `add`/`set-token`; runtime
  needs `DNS > Edit`). Cloudflare tokens cannot be scoped below zone level — registering a name inside
  the zone keeps Sandcastle's records apart, not the token's reach.

### 2.2 Project Domain (tenant)

```
sc project create <name> [--domain <domain>]      # existing command gains the flag
sc project set-domain <name> <domain>
sc project unset-domain <name>
sc project status <name>                          # gains Domain: + cert summary
```

- `--domain` / `set-domain` go through the Auth App (§3.2). Validation is server-side; the CLI only
  normalizes and rejects the obviously malformed (`*`/`_` labels, empty) with the same texts.
- Error texts, verbatim (server-produced, CLI prints as-is):
  - cross-tenant, every conflict class: `project domain "<d>" overlaps a domain already claimed on this install; choose another`
  - same tenant: `project domain "<d>" overlaps "<existing>" claimed by project "<p>" in this tenant`
  - install-reserved (Auth Hostname, route base domain, or an existing Public Route hostname): `project domain "<d>" is reserved by this install`
  - no zone: tenant sees `no Public DNS Zone covers <domain> — ask your admin`; the admin roots (`sc-adm project …`, if a domain flag is ever added there) see `no Public DNS Zone covers <domain>; registered zones: <z1>, <z2>`
  - apex: `project domain "<d>" is a zone apex; claim at least one label below <zone>`
  - too long: `project domain "<d>" is too long: "*.<63-char machine>.<d>" must fit in 253 characters`
  - zone-mode Machines exist (`set-domain`/`unset-domain`): `project <p> has machines with a public name: <m1>, <m2>; delete them before changing the project domain`
- Same-project identical re-claim is a no-op (exit 0, `project domain "<d>" already claimed by this project`).
- `sc project status <name>` output gains, after the existing lines:

  ```
  Domain: baum.hase.de   (zone hase.de)
  MACHINE   PUBLIC NAME            CERT        NOT AFTER              DETAIL
  web       web.baum.hase.de       installed   2026-12-11T09:14:00Z
  api       api.baum.hase.de       pending
  old       -                      -                                  private mode
  bad       bad.baum.hase.de       failed      -                      rate-limited: too many certificates (5) already issued for this exact set of identifiers …
  ```

  Projects without a domain print `Domain: (none)` and omit the table. JSON output (`-o json`) carries
  `domain`, `zone`, and per-machine `publicHostname`, `certState`, `certNotAfter`.
- `sc project delete <name>` now calls `DELETE /api/projects/<name>` (§3.2) when the tenant is logged
  in to an Auth App; the fallback to direct Incus deletion stays for admin paths, and the reconciler GC
  (§4.6) covers it.

### 2.3 `sc create` output (zone-mode project)

`sc create` determines the Naming Mode from the project's `Domain` in `tenant.Summary`: non-empty →
zone, and it stamps `KeyV2PublicHostname=<m>.<pd>` in the same instance-create call (never a second
write). For a private project it stamps `private`. Then, for zone mode and unless `--image` selected the
dev image, it calls `POST /api/machine-certificates` (§3.4) *after* the instance exists, with a short
timeout, and never fails the create on that call.

Replace the `DNS:` line (both the immediate-IP and still-booting forms, and `--dry-run`) with:

```
Public name: <m>.<pd> (A record pending, certificate pending — see: sc project status <project>)
```

`--bare` `HTTPS:` line becomes:

```
HTTPS: https://<m>.<pd>   (Let's Encrypt, certificate pending)
```

Dev-image Machines print:

```
Public name: <m>.<pd> (A record pending; no Caddy — no certificate)
```

When `POST /api/machine-certificates` fails (unreachable, 5xx, timeout) the pending line's parenthesis
becomes `(A record pending, certificate pending: Auth App unreachable — retried by the reconciler)`.
When it answers 429-class (LE budget) the reason is spliced in the same slot, e.g.
`certificate pending: rate-limited — <api message>`. The machine is created in every case.

The private-mode text (`DNS: … (auto-registers …)`, `HTTPS: … (Caddy with the tenant-CA leaf …)`) is
unchanged byte-for-byte.

### 2.4 `sc ls`

- `FQDN` column shows the Machine Public Hostname for zone-mode Machines (`machineFQDN` reads
  `PublicHostname` first).
- New `CERT` column after `FQDN`, values per §1.5 (`-`, `pending`, `ok`, `failed`). Present in every
  table variant (`sc ls`, `sc ls -a`, the admin list). Golden-output tests updated.

### 2.5 `sc connect` / host keys

`v2MachineNames` returns `[<m>.<pd>]` for a zone-mode Machine — no private name, no short alias. SSH
still dials the tenant-bridge IP; `HostKeyAlias=<m>.<pd>`; the known_hosts entry is keyed by the public
name with the same `# sandcastle:<remote>/<tenant>` marker (ADR-0020). Both the cache path
(`connect_cache.go`) and the live path get the mode from `meta.Machine.PublicHostname`.

### 2.6 Admin `auth-app deploy` / `install`

New install-level flag on both: `--acme-directory <url>` (default
`https://acme-v02.api.letsencrypt.org/directory`; e2e passes the staging URL). Stored on the appliance
like `--acme-email`, which doubles as the ACME account contact. Not per zone.

## 3. Auth App

### 3.1 `/api/public-dns-zones` (admin-only, `requireAdmin`)

| Method | Path | Body | Result |
|---|---|---|---|
| `GET` | `/api/public-dns-zones` | — | `{zones:[{zone, cloudflareZone, cloudflareZoneID, tokenFingerprint, claims, createdBy, createdAt}]}` |
| `POST` | `/api/public-dns-zones` | `{zone, token, dryRun}` | 201 `{zone, cloudflareZone, cloudflareZoneID}`; 409 exists/nesting; 422 Cloudflare rejected |
| `PUT` | `/api/public-dns-zones/{zone}/token` | `{token, dryRun}` | 200; 404; 422 |
| `DELETE` | `/api/public-dns-zones/{zone}` | `?dryRun=1` | 204; 409 with the claim list |

Error bodies are `{error: "<verbatim text from §2.1>"}`; the CLI prints `error` unchanged.

### 3.2 Project endpoints (tenant plane, bearer token)

- `POST /api/projects` gains `domain` (optional). The handler claims the domain (§3.3) **before**
  `CreateTenantProject`; on Incus failure it deletes the claim row (compensation). The project's
  `KeyV2Domain` is set in the same project-create request to Incus.
- `PUT /api/projects/{name}/domain` `{domain, dryRun}`: refuses if any instance in the project has
  `KeyV2PublicHostname` other than `private`/absent (§2.2 text), claims, then sets `KeyV2Domain` and
  re-renders the project default profile (§5.1).
- `DELETE /api/projects/{name}/domain`: same refusal, deletes the claim row, unsets `KeyV2Domain`,
  re-renders the profile. Cloudflare records and certificate rows for that domain are dropped by the
  GC (§4.6) — none can exist if no zone-mode Machine exists.
- `DELETE /api/projects/{name}` (**new**, closes the "no project-delete endpoint" gap): releases the
  claim, deletes every A record under the Project Domain, drops `machine_certificates` rows for the
  project, then deletes the Incus project (existing `sc project delete` semantics, `--yes`
  enforced client-side). Order: DB claim → Cloudflare → cert rows → Incus; a failure after the claim
  is released is repaired by the GC, never rolled back.

### 3.3 Claims: validation, conflict classes, transaction (`internal/authapp/project_domain_claims.go`)

Normalization: lowercase, `TrimSpace`, strip one trailing `.`. Validation, in order:

1. `validateDomainLabels` (ASCII, 1–63 chars, alnum + internal hyphens); labels starting with `_` or
   `*` rejected; no IDN.
2. Zone lookup: **unique longest-suffix match** against `public_dns_zones`; none → the "no Public DNS
   Zone covers" error.
3. `domain != zone` (apex) and at least one label below it.
4. `len("*.") + 63 + 1 + len(domain) <= 253`.

Conflict classes, all blocking regardless of tenant (`d` = candidate, `c` = existing):

| Class | Test |
|---|---|
| exact | `d == c` (unless same tenant+project → no-op) |
| ancestor | `c` ends with `"." + d` (`d` would cover an existing claim) |
| descendant | `d` ends with `"." + c` |
| Public Route | for every `routes.hostname` `h` (with a leading `*.` stripped): `h == d` or `h` ends with `"." + d` |
| install-reserved | `d` equals or is an ancestor of the Auth Hostname or the route base domain |

Message selection: install-reserved → "is reserved by this install"; any other class where the
existing claim's tenant equals the caller's tenant → the same-tenant text naming `existing` and
`project`; otherwise the flat no-owner text. `DomainClaimError{Domain, Existing, Project, Class,
SameTenant bool}` mirrors `SuffixClaimError` and is what handlers map to 409.

Transaction: `BEGIN IMMEDIATE` (SQLite write lock) → run the conflict scan inside the transaction →
`INSERT` → `COMMIT`. The write lock makes the scan + insert atomic against concurrent claims; the
`domain` PK is the last line of defence. Only after commit does the handler touch Incus.

**Reverse check in `UpsertRoute`** (`internal/authapp/routes.go`): before the insert, a custom
hostname `h` (leading `*.` stripped) that equals or is under any `project_domain_claims.domain` is
rejected with `route hostname "<h>" is inside project domain "<d>" claimed on this install` (proposed
text; #158 fixed the check, not the wording). The auto-subdomain path (`<name>.<route base>`) cannot
collide because the route base domain is install-reserved.

### 3.4 `POST /api/machine-certificates` (tenant plane)

`{project, machine}` → upserts a `machine_certificates` row (`requested_at = now`) for
`<machine>.<domain of project>` if the caller's tenant owns the project and the project has a domain.
Returns 202 `{hostname, state}`; if a retained row for the hostname already holds a valid certificate,
returns 202 with `state: issued` and no order happens. Returns 409 with reason `rate-limited` if the
zone's rolling 7-day count of successful issuances (`SELECT count(*) … WHERE zone=? AND not_before > now-7d`)
is at 50, so `sc create` can print the reason up front (the row is still created; the reconciler will
try when the window frees — see Open §9 for whether creation should refuse instead).

### 3.5 ACME issuer (`internal/authapp/acme.go`)

- One `certmagic.Config{Storage: sqliteStorage}` and one `certmagic.ACMEIssuer{CA: directoryURL,
  Email: acmeEmail, Agreed: true, DisableHTTPChallenge: true, DisableTLSALPNChallenge: true,
  DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider:
  &cloudflare.Provider{APIToken: zoneToken}, TTL: 60 * time.Second}}}` **per zone** (the provider is
  token-bound), created lazily and cached; the ACME account (one per install per directory URL) lives in
  `acme_storage` and is shared across zones.
- Per order: generate ECDSA P-256 key, CSR with `DNSNames: [<m>.<pd>, *.<m>.<pd>]`, call
  `ACMEIssuer.Issue(ctx, csr)`; renewals set the ARI `Replaces` context value from the current cert.
  Never `ManageSync`/`ManageAsync`.
- Behind an interface `certIssuer{ Issue(ctx, zone, hostnames) (certPEM, keyPEM, notBefore, notAfter, err);
  RenewalInfo(ctx, certPEM) (renewAfter, retryAfter, err) }` so unit tests use a fake; the certmagic
  implementation is the only production one.
- Staging and production certificates never mix: the row's `directory_url` must equal the running
  setting or the row is treated as absent (re-ordered) — this is how an install switched from staging
  to production heals.

## 4. Reconciler (`internal/incusx/dns_v2.go` + new `internal/authapp/zone_reconcile.go`)

The existing ADR-0018 pass (30s ticker + lifecycle events) gains a zone stage. The private stage
skips zone-mode Machines (no private name for them) and is otherwise unchanged. Every per-Machine
error is collected with `errors.Join` and logged; a pass never fails as a whole.

### 4.1 Inputs per pass

Live: every app project of the install (prefix-scoped) with `KeyV2Domain`, its instances with config
+ state + bridge IPv4. DB: `project_domain_claims`, `machine_certificates`, `public_dns_zones`.
Per instance: Naming Mode (§1.1). Unstamped instance in a domain project → stamp
`KeyV2PublicHostname=<m>.<pd>` (Freeform Machine, first sight); unstamped in a non-domain project →
stamp `private`.

### 4.2 A records

For each zone-mode Machine with a bridge IPv4: ensure Cloudflare `A <m>.<pd> → <ip>` and
`A *.<m>.<pd> → <ip>`, `proxied: false`, TTL 60 (the wildcard record is what makes the wildcard SAN
useful, mirroring ADR-0018's per-machine wildcard in CoreDNS). Stopped Machine → records stay (the
address is stable across restarts); deleted Machine → both records deleted. Records are managed via
`libdns/cloudflare` `SetRecords`/`DeleteRecords` (same client as the solver). The reconciler compares
desired vs. `GetRecords` once per pass per domain, so an unchanged fleet makes exactly one Cloudflare
read per Project Domain per pass.

### 4.3 Order scheduling

A Machine needs an order when its row is `pending`/`failed` with `next_attempt_at <= now`, or
`installed`/`renewing` with `renew_after <= now`. Rows come from `sc create` (§3.4) or are created
by the reconciler when a zone-mode Machine carries a Caddy Setup Marker and has no row (Freeform
Machine, `--bare`). A dev-image Machine never writes the marker and never gets a row.

- **ARI**: when `ari_check_after <= now` and a cert exists, call `RenewalInfo`; store `renew_after`
  (window start) and `ari_check_after` (Retry-After, default now+6h). Fallback when ARI errors:
  `renew_after = not_before + 2/3·(not_after − not_before)`. No ACME call happens unless one of these
  timestamps has passed.
- **Backoff** on any order error: `attempts++`, `next_attempt_at = now + {1m, 5m, 30m, 2h, 6h}[min(attempts−1, 4)]`,
  `last_error = err`. Success resets `attempts`/`last_error`. Rate-limit responses (`urn:ietf:params:acme:error:rateLimited`)
  jump straight to the 6h step and set reason `rate-limited`.
- **TXT sweep**: before each order, list and delete every `_acme-challenge.<m>.<pd>` TXT record in the
  zone (leftovers from a crashed pass would fail validation).
- **Concurrency**: at most 4 orders in flight per pass, never two for one hostname, oldest
  `next_attempt_at` first. Orders run in goroutines that outlive the pass but hold a per-hostname lock;
  a next pass skips locked hostnames.
- Orders do not require the Machine to be running (DNS-01 needs no Machine); a stopped Machine renews
  on time and the `instance-started` event pushes.
- A Machine whose delete/recreate hits the 5-per-identifier-set limit is served from the retained row
  (§4.6) before any order is considered.

### 4.4 Push protocol

Trigger: row `issued` (pushed_serial ≠ serial) and the Machine is running and the marker gate passes.

1. `GetInstanceFile("/etc/sandcastle/caddy.ready")` → must parse as `MODE=zone` and
   `FQDN=<m>.<pd>` matching the row's hostname. Absent or mismatched → A record only; log once per
   instance (in-memory dedupe keyed by instance + marker content) and set nothing on the row.
2. `CreateInstanceFile("/etc/sandcastle/tls/cert.pem.new", 0644)` and
   `CreateInstanceFile("/etc/sandcastle/tls/key.pem.new", 0600)`, both root-owned.
3. One exec, checked with `execExitError`:
   ```
   sh -c 'mv -f /etc/sandcastle/tls/cert.pem.new /etc/sandcastle/tls/cert.pem && mv -f /etc/sandcastle/tls/key.pem.new /etc/sandcastle/tls/key.pem && (systemctl reload caddy || systemctl restart caddy)'
   ```
   On the first push Caddy is enabled but inactive, so `reload` fails and `restart` starts it (the
   `ConditionPathExists` is now satisfied).
4. On success: `pushed_serial = serial`, stamp `KeyV2CertState=installed`, `KeyV2CertNotAfter`.
   On failure: leave `pushed_serial`, log, retry next pass (no backoff — pushes are cheap and local).

`.new` + `mv` keeps each file swap atomic; the two files are swapped back-to-back before the reload so
Caddy never loads a cert/key pair from different generations.

### 4.5 Fingerprint drift

Every pass, for each running zone-mode Machine whose row is `installed`/`renewing`:
`GetInstanceFile("/etc/sandcastle/tls/cert.pem")`, sha256 of the leaf, compare with `fingerprint`.
Mismatch (rebuilt Machine, manual edit, restored snapshot) → treat as `issued` and re-push. Stopped or
unreachable → skip, next pass. `instance-started` → re-push unconditionally if the row is `issued`,
else drift-check. Reading files emits `instance-file-retrieved`, which ADR-0018 already excludes from
the trigger set, so this cannot feed back into the loop.

### 4.6 Garbage collection (slow loop, `suffixClaimReconcileInterval` cadence — 5 min)

- **Claims**: `project_domain_claims` row whose `<tenant>/<project>` is not a live app project →
  delete the row, delete all A records under the domain, drop its certificate rows (they are retained
  by *hostname*, but a released domain can be re-claimed by another tenant, so its certificates must
  not survive the claim). Empty live set is never trusted (same guard as `pruneOrphanSuffixClaims`).
- **Incus key without row** (`KeyV2Domain` set, no claim): logged once, ignored; never auto-claimed.
  Machines in such a project are treated as private for DNS and get no certificate.
- **Records**: A records under a claimed domain with no matching zone-mode Machine → deleted (covers
  out-of-band `incus delete`).
- **Certificate rows**: a row whose Machine is gone stays until `not_after` (retained for reuse), then is
  dropped. Rows whose `directory_url` ≠ the running setting are dropped.
- **Machine reappears** (same hostname, row retained, `not_after − now > 0`): the row is reused as-is
  (`pushed_serial` cleared so it counts as `issued` and is pushed once the marker appears).

### 4.7 Instance-config mirroring

After each pass the reconciler writes `KeyV2CertState`/`KeyV2CertNotAfter` on every zone-mode instance
where the derived value changed (compare first; an unchanged fleet makes no `UpdateInstance` calls —
each write emits `instance-updated`, which the resource cache consumes). `KeyV2PublicHostname` is
written only when absent (§1.1), never updated.

## 5. Machine contract

### 5.1 Profile and `machine.env`

The project default profile's cloud-init (`V2DefaultProfileUserData`, `create_plan_v2.go`) is rendered
per project from the project's domain. For a domain project:

```
FQDN={{ v1.local_hostname }}.<pd>
MODE=zone
SIGNER=<sidecar url>        # kept: CA-trust step only
HOME=/home/<user>
```

and the cloud-init `fqdn:` becomes `{{ v1.local_hostname }}.<pd>`. Private projects add `MODE=private`
(explicit, but every consumer defaults an absent `MODE` to `private` so pre-feature Machines keep
working). `set-domain`/`unset-domain` re-render the profile; existing Machines never re-run cloud-init,
so they keep their `machine.env` — consistent with Naming Mode being fixed at creation. The `--bare`
user-data template is rendered the same way.

### 5.2 Mode-aware `caddy-setup` (platform payload `sbin/caddy-setup`, ADR-0022)

```bash
#!/bin/bash
set -eu
. /etc/sandcastle/machine.env
MODE="${MODE:-private}"
export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /etc/sandcastle/tls /usr/local/share/ca-certificates /etc/caddy /etc/systemd/system/caddy.service.d
# … Caddy apt install, unchanged …
# Tenant CA trust stays in both modes (private-mode siblings are still HTTPS peers).
curl -fsS "$SIGNER/tls/ca" -o /usr/local/share/ca-certificates/sandcastle-tenant.crt && update-ca-certificates || true
if [ "$MODE" = private ]; then
  # unchanged: fetch the leaf from the sidecar signer before Caddy serves
  curl -fsS "$SIGNER/tls/leaf?fqdn=$FQDN" | python3 -c '…'
  chmod 600 /etc/sandcastle/tls/key.pem
fi
cat > /etc/caddy/Caddyfile <<EOF
$FQDN, *.$FQDN {
    tls /etc/sandcastle/tls/cert.pem /etc/sandcastle/tls/key.pem
    … handlers byte-identical to today (redir /_h, /_w; handle_path /_h/* root $HOME; /_w/* root /workspace; reverse_proxy localhost:3000) …
}
EOF
printf '%s\n' '[Service]' 'User=root' 'Group=root' 'AmbientCapabilities=' > /etc/systemd/system/caddy.service.d/override.conf
if [ "$MODE" = zone ]; then
  printf '%s\n' '[Unit]' 'ConditionPathExists=/etc/sandcastle/tls/cert.pem' 'ConditionPathExists=/etc/sandcastle/tls/key.pem' > /etc/systemd/system/caddy.service.d/sandcastle-zone.conf
fi
systemctl daemon-reload
systemctl enable caddy
# Marker LAST: it asserts the Caddyfile above is in place for this FQDN.
printf 'MODE=%s\nFQDN=%s\n' "$MODE" "$FQDN" > /etc/sandcastle/caddy.ready
if [ "$MODE" = zone ]; then
  systemctl start caddy || true   # condition unmet until the first push: a no-op, not a failure
else
  systemctl restart caddy
fi
```

The Caddyfile is the same template in both modes — only the site names and where the cert came from
differ. The same script serves `sc create`, `--bare`, Freeform Machines, containers and VMs.

### 5.3 Caddy Setup Marker

Path `/etc/sandcastle/caddy.ready`, mode 0644, shell-sourceable `KEY=value` lines:

```
MODE=zone
FQDN=web.baum.hase.de
```

Written once by `caddy-setup` after the Caddyfile and unit drop-ins exist. The reconciler treats any
parse failure, a missing `MODE`, `MODE=private`, or an `FQDN` that differs from the expected Machine
Public Hostname as "no marker".

### 5.4 systemd drop-in

`/etc/systemd/system/caddy.service.d/sandcastle-zone.conf` with `ConditionPathExists=` for both
`cert.pem` and `key.pem`. With the condition unmet, `systemctl start` exits 0 and logs a skipped
start; a reboot before the first push therefore does not crash-loop. The first push's
`reload || restart` starts Caddy.

### 5.5 Sidecar

No change. The `tls-sign` signer answers 403 for names outside the tenant zone, which is correct for a
public name. `SIGNER` stays in `machine.env` for the CA-trust step.

## 6. Cloudflare and Let's Encrypt facts the implementation relies on

- Token: `Zone > DNS > Edit` (runtime) + `Zone > Zone > Read` (only at `add`/`set-token`). Not scopable
  below zone level.
- Base + wildcard in one order = two authorizations at the same `_acme-challenge.<m>.<pd>` name;
  two TXT values coexist. certmagic's solver appends/deletes by value.
- Propagation: wait for authoritative visibility (certmagic `DNSManager.Wait`, 2 min default), never a
  fixed sleep. Multi-perspective validation.
- Limits: 50/registered domain/week (one per Machine), 5/identifier set/week (no override), 300
  orders/account/3h, 5 failed validations/identifier/hour. ARI-timed renewals are exempt.
- Staging directory: `https://acme-staging-v02.api.letsencrypt.org/directory`. OCSP is gone; no stapling.
- A records to RFC 1918 addresses must be DNS-only (`proxied: false`) — Cloudflare's proxy cannot reach them.
- **Rebind protection**: resolvers with `stop-dns-rebind` (dnsmasq), Unbound `private-address`, and many
  home routers refuse a public name that answers with a private address. Users behind one must
  allowlist the zone (`rebind-domain-ok=/hase.de/`) or use a different resolver. Document in usage.html
  and the skill.

## 7. e2e phases to add to `docs/e2e-sc2.md`

New `## Phase 12 — Public DNS Zones: Machine Public Hostnames + Let's Encrypt staging (ADR-0027)`,
placed after Phase 11. Gate: `SANDCASTLE_E2E_CLOUDFLARE_TOKEN` and `SANDCASTLE_E2E_PUBLIC_DNS_ZONE`
(a real test zone the token can edit); absent → the phase is **skipped, not failed**. The Auth App is
deployed with `--acme-directory https://acme-staging-v02.api.letsencrypt.org/directory`.

```
# 12a — zone registry (admin)
sc-adm public-dns-zone add $ZONE --token-file <(printf %s "$SANDCASTLE_E2E_CLOUDFLARE_TOKEN")
sc-adm public-dns-zone list
# PASS: the zone lists with a Cloudflare id and a token fingerprint; a second `add` fails with
#       "already registered"; `add` with a garbage token fails with "Cloudflare rejected the token"
#       and `list` is unchanged; `add sub.$ZONE` fails with "zones may not nest".

# 12b — Project Domain claims (tenant)
sc project create zp --domain e2e-$RUN.$ZONE
sc project status zp
# PASS: `Domain: e2e-$RUN.$ZONE (zone $ZONE)`; the Incus project carries
#       user.sandcastle.v2.domain; a second tenant's `sc project create x --domain e2e-$RUN.$ZONE`
#       and `--domain a.e2e-$RUN.$ZONE` both fail with the flat "overlaps a domain already claimed on
#       this install" text (no owner named); `--domain $ZONE` fails with the apex text;
#       `--domain e2e-$RUN.nosuch.example` fails with "no Public DNS Zone covers … — ask your admin".

# 12c — zone-mode machine: A record + certificate
sc create web --project zp
# PASS: output has "Public name: web.e2e-$RUN.$ZONE (A record pending, certificate pending — see: sc project status zp)"
#       and returns without waiting.
# PASS (≤ 60s): `dig +short web.e2e-$RUN.$ZONE @1.1.1.1` and `dig +short x.web.e2e-$RUN.$ZONE @1.1.1.1`
#       both answer the machine's tenant-bridge IPv4 (the IP column of `sc ls`).
# PASS (≤ 5 min): `sc ls` CERT column reads `ok`; `sc project status zp` shows `installed` with a
#       NOT AFTER; `sc incus config get web user.sandcastle.v2.cert-state` = installed.
# PASS: from the client (on the tenant tailnet):
#   openssl s_client -connect <bridge-ip>:443 -servername web.e2e-$RUN.$ZONE </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName -issuer
#   shows both SANs `DNS:web.e2e-$RUN.$ZONE, DNS:*.web.e2e-$RUN.$ZONE` and an issuer from the
#   Let's Encrypt STAGING hierarchy ("(STAGING)" in the issuer CN). Browser trust is NOT asserted.
# PASS: `curl --resolve x.web.e2e-$RUN.$ZONE:443:<bridge-ip> -k https://x.web.e2e-$RUN.$ZONE/_w/` serves
#       the /workspace listing (wildcard vhost reaches the same Caddy).
# PASS (negative): `dig web.zp.<suffix> @<sidecar-tailscale-ip>` is NXDOMAIN — a zone-mode machine has
#       no Machine Private Hostname; `sc c web` connects and its known_hosts line is keyed
#       `web.e2e-$RUN.$ZONE` with the `# sandcastle:` marker.

# 12d — marker gating + freeform + dev image
incus launch <ct-image> ff --project <prefix>-<tenant>-zp     # Freeform Machine, profile = default
sc create devbox --project zp --image <dev-alias>
# PASS: ff gets an A record and, once its cloud-init caddy-setup has written /etc/sandcastle/caddy.ready,
#       a certificate (CERT ok); devbox prints "(A record pending; no Caddy — no certificate)", gets
#       an A record, and CERT stays `pending` with no order in the auth-app log ("no caddy setup marker").
# PASS: `sc create --bare b1 --project zp` prints "HTTPS: https://b1.e2e-$RUN.$ZONE   (Let's Encrypt, certificate pending)"
#       and reaches CERT ok.

# 12e — stopped through a push, reboot before cert, drift
sc stop web; sc-adm … (force a re-issue by clearing pushed_serial in the Auth DB, or wait for renew_after in a
#   test build with a short fallback); sc start web
# PASS: within seconds of instance-started the new serial is on the machine (fingerprint matches the DB).
sc create late --project zp; sc restart late      # restart BEFORE the cert lands
# PASS: caddy is enabled, inactive, `systemctl status caddy` reports the ConditionPathExists skip,
#       no crash loop; once pushed, caddy is active and serves the cert.
sc incus exec web -- sh -c 'echo x >> /etc/sandcastle/tls/cert.pem'
# PASS (≤ 60s): the reconciler re-pushes (fingerprint drift) and Caddy serves the correct chain again.

# 12f — set-domain / unset-domain / remove guards, delete + GC
sc project unset-domain zp
# PASS: refused, lists web, ff, b1, late (devbox too — it has a public name).
sc-adm public-dns-zone remove $ZONE
# PASS: refused, lists e2e-$RUN.$ZONE (<tenant>/zp).
sc delete web
# PASS (≤ 60s): both A records gone; the machine_certificates row for web.e2e-$RUN.$ZONE is RETAINED.
sc create web --project zp
# PASS: CERT reaches ok with NO new ACME order in the auth-app log (retained certificate reused —
#       the 5-per-identifier-set limit is not spent).
sc project delete zp --yes
# PASS: claim row gone, no A records under the domain remain, the zone is removable, and
#       `sc-adm public-dns-zone remove $ZONE` now succeeds.
# PASS (private-mode regression): Phases 7c, 8, 8c run unchanged in a project without a domain on the
#       same install — DNS:/HTTPS: lines byte-identical, CERT column `-`.
```

Also amend the existing Phase 1 (deploy) with the `--acme-directory` flag and Phase 8c's PASS notes
with a pointer that zone-mode Machines are covered in Phase 12.

## 8. Docs to update in the same commits

- `docs/usage.html`: `public-dns-zone add|list|remove|set-token` on both roots; `sc project create
  --domain`, `set-domain`, `unset-domain`; `sc project status` domain + cert table; `sc create`
  zone-mode output; `sc ls` CERT column; `--acme-directory`; the rebind-protection caveat; the LE budget
  numbers; token scope and "dedicate a zone".
- `docs/admin-developer-quickstart.html`: a "Public DNS Zones" step after ingress: create the
  Cloudflare token, `public-dns-zone add`, hand the domain to a tenant, what "certificate pending" means.
- `docs/agents/skills/sandcastle/` (`SKILL.md` + reference): the two-root command tree, how to read
  CERT/`sc project status`, the diagnosis path for `pending`/`failed` (marker present? A record? auth-app
  log line), and the rule that Naming Mode never changes.
- `docs/e2e-sc2.md`: Phase 12 above.
- `docs/topology.md`: one paragraph on the second DNS authority (Cloudflare, public names) beside CoreDNS.
- `CONTEXT.md`: already carries the seven terms (this branch).
- `implementation-notes.md`: only for deviations discovered while implementing.

## 9. Implementation plan (PR-sized slices, in order)

1. **Keys + model.** `meta.KeyV2Domain/PublicHostname/CertState/CertNotAfter`, `meta.Machine` and
   `meta.Project` fields, `DecodeMachine`, resource-cache conversion, `tenant.Summary` project domain,
   `v2MachineNames` zone branch, `machineFQDN`, `sc ls` CERT column. Pure, golden-tested, no behaviour
   change for unstamped Machines.
2. **Zone registry.** `public_dns_zones` table, `encryptSecret`, Cloudflare validation client (or
   `libdns/cloudflare` + one `GET /zones` call), `/api/public-dns-zones`, `public-dns-zone` command
   on both roots, `--dry-run`, docs for §2.1.
3. **Project Domain claims.** `project_domain_claims`, validation + conflict classes + transaction,
   `DomainClaimError`, `POST /api/projects` `domain`, `PUT/DELETE …/domain`, `DELETE /api/projects/{name}`,
   `UpsertRoute` reverse check, claim GC in the slow loop, `sc project create --domain` /
   `set-domain` / `unset-domain` / `status` output, profile re-render with `MODE`/`FQDN` (§5.1).
4. **Machine contract.** Mode-aware `caddy-setup` payload + marker + drop-in (§5.2–5.4), `sc create`
   Naming Mode stamp and output strings, `--bare` and dev-image variants, `sc connect` HostKeyAlias.
   Ships before any certificate exists: a zone-mode Machine now boots with Caddy enabled-inactive.
5. **ACME.** `go.mod` deps, `acme_storage` + `sqliteStorage`, `machine_certificates`, `certIssuer`
   interface + certmagic implementation + fake, `--acme-directory`, `POST /api/machine-certificates`,
   `sc create` calling it. No reconciler yet — rows are created but nothing orders.
6. **Reconciler.** A records, order scheduling (ARI, backoff, TXT sweep, concurrency), push protocol,
   marker gating, drift, mirroring, record + certificate GC, retention/reuse. Unit tests with the fake
   issuer and a fake libdns provider; first live run against staging.
7. **e2e + docs.** Phase 12, usage/quickstart/skill/topology updates, `make e2e-safe` gate wiring
   for the new env vars.

Slices 1–4 are safe to merge without 5–6 (no certificate is ever expected until the reconciler exists);
slice 4 must not ship to a production install *before* slice 6 if any project already has a domain,
since its Machines would sit `pending` indefinitely.

## 10. Open

Left open by the tickets; not decided here. Items the implementation slices
*did* settle are marked **resolved** with a pointer to the dated entry in
`implementation-notes.md` (2026-09-12); the list itself is kept as written.
Settled outside this list: ARI-timed renewals run **without** the ACME
`replaces` field (§3.5 asked for it; certmagic keeps the key unexported — see
"slice 6: the zone reconciler"), and private-mode profiles carry no
`MODE=private` line (§5.1 — see "slice 3: Project Domain claims").

- **Budget exhaustion up front.** The reconciler's backoff absorbs LE rate-limit errors as
  `failed:rate-limited` (#157), and §3.4 lets `sc create` print the reason. Whether `sc create` should
  *refuse* when the zone's weekly budget is spent, and how exhaustion is surfaced to the admin
  (`public-dns-zone list` column? auth-app admin page?) is open (#155).
- **Tenant-supplied (BYO) zones** with a tenant-held token.
- **Deprecating private mode** (Tenant CA, `sc trust`, CoreDNS, client resolver) and migrating
  existing Machines and clients.
- **Public Routes targeting a Machine Public Hostname** instead of a machine port.
- **Folding the ADR-0025 route-DNS token into Public DNS Zones**; they coexist for now.
- **Certificate profile** (`classic` vs `tlsserver`) — default `classic`; ARI handles either.
  (Unchanged by the slices: no profile is requested, so the CA's default applies.)
- **`UpsertRoute` reverse-check wording** (§3.3) and the **`project status` table layout** (§2.2) are
  proposed here, not fixed by a ticket; implementers may adjust the wording, not the check.
  **Resolved** (slice 3, `implementation-notes.md` "Project Domain claims"): every route
  conflict — own tenant or foreign — reads as install-reserved, and the `project status` table is
  `MACHINE / PUBLIC NAME / CERT / NOT AFTER / DETAIL` with `DETAIL` carrying the `failed:` reason
  token only (the raw `last_error` stays on the row).
