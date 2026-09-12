# Public DNS Zones: Machine Public Hostnames with Let's Encrypt Certificates via Central DNS-01

> Status: **proposed** (2026-09-12). Map: issue #155 (tickets #156–#161). Spec: `docs/spec/public-dns-zones.md`. Builds on ADR-0018 (Machine Private Hostnames, Auth App DNS reconciler), ADR-0021 (one Incus remote, one Auth App per install), ADR-0022 (`/.sc` platform payload), ADR-0023 (resource cache). **Amends** ADR-0025 (the Auth App now holds a DNS-edit token) and ADR-0011 decision 6 (cert delivery is inverted for zone mode). Leaves ADR-0013 untouched.

## Context

Every Machine today has a Machine Private Hostname (`<machine>.<project>.<Tenant DNS Suffix>`) served by the tenant sidecar's CoreDNS and a leaf certificate signed by the Tenant CA (ADR-0011). That works, but browser trust needs a client-side step: `sc login` / `sc trust` must install the Tenant CA into every client's trust store, and every client must be pointed at the sidecar resolver (`localdns`). Anything that cannot take a custom CA — a phone, a colleague's laptop, a hosted webhook tester, a CI runner — cannot talk HTTPS to a Machine at all.

We want a Machine to carry a certificate a stock browser trusts, without giving up the tenant-private data path (ADR-0013: Machines are never Internet-facing; Public Routes remain the ingress). The ingredients already exist in the install: the Auth App runs a 30s DNS reconciler that watches Machine lifecycle across all projects (ADR-0018), ADR-0025 already proved Cloudflare DNS-01 in the appliance's Caddy, and Let's Encrypt issues wildcard certificates for DNS-01 validated names.

## Decision

Add **Public DNS Zones** as an additive, opt-in feature. Nothing changes for a Project that does not claim a Project Domain.

1. **Zones are admin-owned, Cloudflare-hosted, any number per install.** An admin registers a Public DNS Zone with `sc-adm public-dns-zone add <zone> --token …` (also `sc admin public-dns-zone …`). The Auth Database stores the zone name, the Cloudflare zone id (resolved at `add` time) and the API token, encrypted at rest. Zones may not nest.

2. **A Project claims a Project Domain under a zone**, at creation (`sc project create <name> --domain <domain>`) or later (`set-domain` / `unset-domain`). A Project Domain is at least one label below a zone (never the apex), reserved install-wide, first come, whole subtree. Cross-tenant conflicts name no owner.

3. **Machines created afterwards in that Project get a Machine Public Hostname** `<machine>.<Project Domain>` and one Machine Certificate covering `<m>.<pd>` and `*.<m>.<pd>` — one two-SAN order per Machine, at creation. Such a Machine has no Machine Private Hostname; the sidecar CoreDNS and the Tenant CA become legacy for it.

4. **Naming Mode is per Machine, fixed at creation, never rewritten.** `sc create` (or the reconciler, on first sight of a Freeform Machine) stamps the Machine's Naming Mode into instance config once. Changing a Project's domain affects only the profile and future Machines; `set-domain`/`unset-domain` are refused while zone-mode Machines exist.

5. **The Auth App runs ACME centrally and is the only holder of the DNS token.** It embeds certmagic (+ acmez, libdns/cloudflare) as an *issuer library* — `ACMEIssuer.Issue` with one two-SAN CSR — not through `ManageSync`, which would order one certificate per name. One ACME account per install; the ACME directory (production / staging) is an install-level setting of `sc-adm auth-app deploy`. Certificates, keys and ACME state live in the Auth Database; renewal is ARI-timed from the existing 30s reconciler, with persisted exponential backoff and a pre-order TXT sweep.

6. **The Auth App pushes cert + key into the Machine** (`CreateInstanceFile` as `.new`, one exec to `mv` and `systemctl reload caddy || systemctl restart caddy`), on issue and on renewal, and only when the Machine's Caddy Setup Marker names the expected Machine Public Hostname. The Machine keeps writing its own Caddyfile from `machine.env` (`MODE=zone`, `FQDN=<m>.<pd>`); Caddy carries `ConditionPathExists` on the certificate so a Machine that reboots before the first push does not crash-loop. **This inverts ADR-0011 decision 6** ("fetch-at-first-boot, never generated-then-pushed") for zone mode: a public certificate cannot be minted by the sidecar, so ordering is guaranteed by the marker + condition instead of by fetch-before-start.

7. **Public A records carry the Machine's tenant-bridge address**, written by the reconciler (Cloudflare DNS-only, never proxied). The name is public; the address is reachable only over the Tenant Tailnet. A Freeform Machine in a zone Project gets its A record like any other; a certificate is pushed only if it carries the marker.

8. **`sc create` never blocks on issuance.** It returns with `Public name: … (certificate pending)`; the reconciler mirrors public-hostname, cert-state and cert-not-after into instance config so `sc ls` / `sc project status` render the same from the ADR-0023 cache and the live path.

9. **Deletion retains the certificate row** (keyed by hostname, for the certificate's remaining lifetime) and drops the A record; no revocation. A Machine reappearing with the same Machine Public Hostname gets the retained certificate without a new order.

## Consequences

- A stock browser on any device on the Tenant Tailnet gets a trusted `https://<m>.<pd>` with no `sc trust`, no resolver configuration. Wildcard subdomains under each Machine are covered by the same certificate.
- **Let's Encrypt budgets bound zone-mode Machine creation:** 50 new certificates per registered domain per week (override obtainable), 5 per exact identifier set per week (no override), 5 failed validations per identifier per hour. One certificate per Machine keeps the zone budget at 50 Machines/week; a delete/recreate loop of one Machine name is absorbed by certificate retention. ARI-timed renewals are exempt. Rate-limit errors surface as a `failed` Machine Certificate and are retried with backoff; whether `sc create` should refuse up front is left open (#155).
- **Rebind protection can break resolution.** A public name resolving to an RFC 1918 address is exactly what DNS-rebind filters (dnsmasq `stop-dns-rebind`, some routers, Unbound `private-address`) drop. Clients behind such a resolver must allowlist the zone or use a resolver without the filter; the docs must say so.
- **The Auth App now holds a DNS-edit secret by design.** ADR-0025 stored the route-DNS token in a Caddy-only env file so that "the Auth App does not receive the DNS token". That rationale is **amended**: the Auth App is the ACME client for Machine Certificates and needs `Zone > DNS > Edit` on every Public DNS Zone. Cloudflare tokens cannot be scoped below zone level, so an admin should dedicate a zone to Sandcastle. The ADR-0025 route-DNS token (Caddy env file) and Public DNS Zone tokens (Auth Database) coexist as separate secrets; the same Cloudflare token may be pasted into both. Folding them is a later ticket.
- Each certificate is logged in Certificate Transparency: Machine names in zone Projects are public knowledge. Private-mode Machines are not affected.
- Two consumers of Cloudflare exist in the binary (Caddy's `caddy-dns/cloudflare` in the appliance, `libdns/cloudflare` in the Auth App); the hand-rolled tunnel client stays as is.
- `go.mod` gains certmagic, acmez, libdns and `go.uber.org/zap` (certmagic's logging dependency).
- The Tenant CA, `sc trust`, CoreDNS and the client resolver are unchanged and remain required for private-mode Machines. They are now **legacy**; deprecating them and migrating existing Machines is a separate effort, not this one.

## Rejected alternatives

- **Sidecar as the ACME client.** The sidecar already signs leaves (ADR-0011) and sits next to every Machine, but it would need the Cloudflare token (one copy per tenant, on a tenant-reachable host) and its own ACME storage; the Auth App already watches every Machine, holds the Auth Database and is the one component per install (ADR-0021). No sidecar change at all.
- **Retire the Tenant CA / migrate existing Machines now.** Would turn an additive feature into a fleet migration with a hard cut-over for every client. Deferred; private mode is legacy, not removed.
- **One wildcard certificate per Project** (`*.<pd>`) pushed to every Machine. One order per Project instead of per Machine, but the same key on every Machine of the Project, second-level names (`x.<m>.<pd>`) uncovered (wildcards match one label), and every Machine's Caddy reload on every renewal. One certificate per Machine keeps the blast radius per Machine.
- **HTTP-01.** Machines are not Internet-reachable (ADR-0013) and wildcards require DNS-01 anyway.
- **Tenant-held tokens (BYO zones).** Parked until admin zones ship; tenant zones stay fog on the map.
- **Split DNS** (public name answered only by the sidecar CoreDNS). Keeps rebind filters happy and the address private, but reintroduces the resolver step on every client, which is the thing this feature removes. Public A records with private addresses were chosen knowingly.
- **lego v5 / raw `x/crypto/acme` / certmagic `ManageSync`.** lego: 109 direct dependencies, no storage or renewal scaffolding, fresh v4→v5 API break. `x/crypto/acme`: no solver, propagation check, storage or ARI; `autocert` cannot do DNS-01. `ManageSync`: one certificate per name, doubling budget use. See `docs/research/acme-client-for-auth-app-2026-09-12.md`.
- **Self-signed placeholder certificate until the first push.** Would let Caddy start immediately but serve a browser error for a name that promised trust; `ConditionPathExists` plus a `pending` state is honest and cheaper.
- **Pebble + fake DNS provider for hermetic e2e.** A second solver path that never runs in production; the e2e stage uses Let's Encrypt staging against a real Cloudflare test zone instead, gated by `SANDCASTLE_E2E_CLOUDFLARE_TOKEN`.
