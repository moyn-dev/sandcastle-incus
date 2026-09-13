# Explicit Machine Public Hostnames: a Machine carries a set of public names, one certificate each

> Status: **accepted** (2026-09-13). Decided on issue #172 (grilling, all four recommendations accepted); implemented in four slices (#173 and its three siblings) on branch `feat/machine-hostnames` from v0.10.0. Spec addendum: `docs/spec/machine-hostnames.md`. **Amends** ADR-0027 (Public DNS Zones): decisions 3 and 4 there — "a zone-mode Machine has no Machine Private Hostname" and "Naming Mode is per Machine, fixed at creation" — are reversed here; everything else in ADR-0027 (zones, Project Domain claims, central ACME, the push protocol, retention) stands and is what this builds on.

## Context

ADR-0027 gave a Machine in a Project with a Project Domain exactly one public name, `<machine>.<Project Domain>`, and made "private or zone" a per-Machine **Naming Mode** fixed at creation: a zone-mode Machine lost its Machine Private Hostname, the sidecar CoreDNS and the Tenant CA became legacy for it, and `set-domain`/`unset-domain` were refused while such Machines existed.

Two things did not fit that model as soon as Public DNS Zones were live:

- A tenant wants a Machine reachable at a name that is **not** `<machine>.<Project Domain>` — a product name directly under a registered zone (`web12.tc42.uk`), a second name for the same Machine, or a public name for a Machine in a Project that has no domain at all. ADR-0027 had no verb for any of these.
- "Private *or* zone, never both" forced a choice a tenant does not actually want to make. The private name costs nothing (CoreDNS and the Tenant CA already exist for every other Machine of the tenant) and keeps every private-mode client path working; the public names are an addition, not a replacement.

The reservation machinery (`project_domain_claims`, the `BEGIN IMMEDIATE` conflict scan against Project Domains, Public Routes and the install's own names) and the certificate machinery (one `machine_certificates` row per hostname, central DNS-01, push-on-marker, retention across delete) were built per hostname from the start; nothing in them assumed one name per Machine except the Naming Mode record.

## Decision

The four decisions of #172, verbatim in intent:

1. **Verb.** `sc create <project>:<machine> --hostname <fqdn>` (repeatable; `--fqdn` is an alias) and `sc hostname add|remove|list <project>:<machine> [<fqdn>]`. *Not* `sc route`: a Public Route is Internet ingress through the auth-app edge to a Machine port; a Machine Public Hostname is a name that resolves to the Machine's tenant-private address and is reachable only over the Tenant Tailnet. They are different things and get different verbs.

2. **Apex-level names are allowed for explicit hostnames.** `web12.tc42.uk` directly under the registered zone `tc42.uk` is a valid hostname. A hostname reserves **exactly itself plus its wildcard subtree**, install-wide, first come, with the same overlap classes as Project Domains — against Project Domains, other hostnames and Public Routes, in both directions. Project Domains still cannot claim a zone apex, and a hostname cannot *be* the apex either (it would reserve the whole zone).

3. **Naming Mode is retired.** Every Machine always has its Machine Private Hostname (`<machine>.<project>.<Tenant DNS Suffix>`, Tenant CA leaf, CoreDNS) and additionally a **set** of Machine Public Hostnames: the derived `<machine>.<Project Domain>` when the Project has a domain, plus any explicit hostnames. Caddy serves one site block per name. A Machine in a Project without a domain can carry explicit hostnames. The instance records the set in `user.sandcastle.v2.public-hostnames` (comma-separated, sorted); the single `public-hostname` key of ADR-0027 is legacy — readers accept both during the transition, writers write only the list.

4. **One Machine Certificate per hostname** (`<name>` + `*.<name>`), pushed to a per-hostname directory on the Machine. Adding or removing a hostname never reissues the others; the derived name's certificate is the one ADR-0027 already orders.

## What this reverses in ADR-0027

- **Decision 3**, "such a Machine has no Machine Private Hostname; the sidecar CoreDNS and the Tenant CA become legacy for it": reversed. Every Machine keeps its private name; CoreDNS and the Tenant CA are not legacy.
- **Decision 4**, "Naming Mode is per Machine, fixed at creation, never rewritten": reversed. There is no mode. The public-name set is rewritten by the Auth App whenever a hostname is added or removed, and the reconciler re-derives the derived name when a Project's domain changes (slice 3). The `set-domain`/`unset-domain` refusal survives only as a transitional guard until the reconciler re-derives names.
- `CONTEXT.md`'s **Naming Mode** entry is superseded; **Machine Public Hostname** is redefined as *one of* a Machine's public names.

## Consequences

- **Certificate budget is per hostname, not per Machine.** Let's Encrypt's 50 new certificates per registered domain per week now bounds *hostnames* per zone per week, and the 5-per-identifier-set limit applies per hostname. A Machine with three names is three orders. Retention across delete (ADR-0027 decision 9) still keys by hostname, so recreating a Machine with the same names spends nothing.
- **Apex-level names compete with Project Domains** for the same slots first come: `web12.tc42.uk` can be a hostname *or* a Project Domain, never both, and neither can appear inside the other. Cross-tenant refusals name no owner.
- **Two public-name keys exist for one release.** `sc ls`, `sc project status`, `sc connect`, the resource cache and the zone reconciler read the list first and fall back to the single key; `sc create` and the Auth App write only the list. The reconciler still stamps the legacy key on first sight of a Machine that carries neither (a Freeform Machine) until slice 3 retires that path.
- **The machine contract grows per name** (slice 2): `machine.env` carries the set, `caddy-setup` renders one site block per name, each with its own certificate directory, and the Caddy Setup Marker lists every name it configured. The reconciler pushes per hostname (slice 3), and a Machine's `CERT` column folds the states of all its certificates.
- **SSH naming**: `known_hosts` records the private names *and* every public name; `HostKeyAlias` stays the Machine Private Hostname (slice 2 finalizes).
- Every `machine_hostnames` row is a reservation with no Cloudflare or certificate side effect of its own until slice 3; the release hook is named now so the three release paths (verb, project delete, GC) do not change again.

## Rejected alternatives

- **`sc route` as the verb.** Public Routes are Internet ingress via the auth-app edge with a machine port as target; overloading the verb would conflate two things with different trust and data paths (ADR-0013). A separate `hostname` verb keeps the vocabulary honest.
- **One multi-SAN certificate per Machine** (all names in one order). Fewer orders, but adding a name reissues every other name's certificate (a reload of every site block, a fresh key for names that did not change), a single failed validation blocks all names, and the 5-per-identifier-set budget is spent on every combination. One certificate per hostname keeps the blast radius per name and is what the existing per-hostname row already models.
- **Keeping Naming Mode with a mode flip** (`private` → `zone` when the first explicit hostname is added, back when the last is removed). Keeps ADR-0027's "one name" plumbing but reintroduces the thing the tenant does not want — losing the private name — and makes a hostname *add* a Machine-wide state change that `set-domain` refusals, `HostKeyAlias` and the Caddyfile all have to react to. A set with no mode has none of that.
- **Storing the derived name as a `machine_hostnames` row.** It would let one table answer every question, but the derived name is already reserved by the Project Domain claim (whole subtree), and two rows reserving the same name would need a special case in every scan. The derived name stays implied by the claim and is rendered into the list, never stored twice.
- **Allowing the zone apex itself as a hostname.** Decision 2 allows apex-*level* names; the apex would reserve the entire zone and its wildcard subtree for one Machine, which is what a Public DNS Zone registered by the admin is for. Refused with the same shape of message as the Project Domain apex rule.
