# ADR-0033: Tailnet egress covers subnet routes and is on for new tenants

Date: 2026-11-18. Status: accepted (2026-11-18). Amends ADR-0026 (what egress
steers, the masquerade scope, the sidecar's accept-routes setting, and the
off-by-default rule for new tenants).

## Context

ADR-0026 steers only the tailnet CGNAT range `100.64.0.0/10` at the sidecar.
That reaches tailnet *nodes*, not the subnets other tailnet routers advertise.
Every Sandcastle sidecar is such a router: it advertises its tenant `/24`. A
machine on one install therefore cannot reach a machine on another install,
even when both tenants share a tailnet.

Observed live on 2026-11-18. A machine of tenant `thies` on install
`miraculix` (`10.125.0.0/24`, sidecar `10.125.0.3`) had to reach
`cliproxy.moyn.dev` = `10.123.1.140`, a machine on install `obelix`, whose
sidecar advertises `10.123.1.0/24`. Three manual changes made it work. The
sidecar got `tailscale set --accept-routes` and a masquerade for any
destination on `tailscale0`. The machine got routes for `10.120.0.0/13` and
`100.64.0.0/10` via the sidecar. With these, `curl https://cliproxy.moyn.dev/`
returned 200 and internet traffic still went via the host gateway.

Tenant CIDR pools are operator-chosen `/16`s inside `10.0.0.0/8` (default
`10.249.0.0/16`; live installs use `10.123/16`, `10.124/16`, `10.125/16`).

## Decision

1. **Steer subnet routes too.** With egress on, option 121 steers an ordered
   prefix list (`tenant.EgressSteeredPrefixes`) at the sidecar:
   `100.64.0.0/10`, then `10.0.0.0/8`, then the default route via the gateway
   (RFC 3442, as in ADR-0026). The tenant's own `/24` is on-link and more
   specific, so gateway, broker and DNS traffic is unchanged. A `10.x`
   destination that no accepted tailnet route covers falls through the
   sidecar's main table back to the host, un-NATed. That is one extra hop
   for traffic that was never tailnet-bound.
2. **Masquerade everything that leaves on `tailscale0`.** The
   `sandcastle-egress` rule becomes `oifname "tailscale0" ip saddr <cidr>
   masquerade`. Tailscaled decides what goes out on `tailscale0` (node
   addresses and accepted routes), so a destination filter would only
   duplicate its routing table and fall out of sync with it.
3. **The sidecar accepts routes exactly while egress is on.** The converge
   passes `--accept-routes=<egress>` in every sidecar `tailscale up` and
   re-asserts it with `tailscale set` once the sidecar has joined. Egress off
   restores `--accept-routes=false`. The setting lives in the converge, not
   the boot oneshot. The oneshot can run before tailscaled is up, tailscaled
   already persists the setting, and the off path removes the oneshot.
4. **New tenants default on.** The converge that *creates* a tenant's infra
   project writes `user.sandcastle.v2.tailnet-egress=true`. For existing
   tenants an absent key still reads as off (CLAUDE.md Compatibility, and
   ADR-0026's fail-closed rule). `sc tailscale egress <tenant> off` deletes
   the key and disables egress as before.

None of this touches cloud-init or the machine image. The steer is a bridge
DHCP option and the rest happens on the sidecar, so existing machines get it
on DHCP renewal, whatever their image.

## Consequences

- The `tag:sandcastle` ACL now also governs reach into other installs' tenant
  subnets (any route the tailnet's routers advertise), not only tailnet
  nodes. On a default-open ACL, every machine of every new tenant reaches
  every advertised subnet on the tailnet. ADR-0026's shared-identity
  trade-off now applies by default for new tenants, so new tenants should
  get an ACL that grants only what they need.
- Accepted-route overlap. If any tailnet router advertises a prefix that
  covers a tenant `/24`, for example two installs that both use the default
  pool, or a router advertising `10.0.0.0/8`, the sidecar installs that route
  in tailscale's table 52. Table 52 is consulted before the main table, so
  the sidecar's replies to its own tenant can go to the tailnet. Choose
  distinct tenant pools per install, and switch egress off for a tenant
  whose tailnet carries such a route.
- Machines pick up the new option 121 on their next DHCP renewal (or a NIC
  bounce). Tenants that already have egress on get the subnet-route steer on
  their next converge. Static-IP machines still don't consume option 121.
- Existing tenants opt in with `sc tailscale egress <tenant> on`, then a
  converge (`sc-adm tenant create <tenant>` or the tenant's next `sc login`).
- A sidecar where someone enabled `--accept-routes` by hand, on a tenant
  with egress off, has it reset to false on its next converge.
- `sc tailscale up` (the standalone command) does not pass the converge's
  flags (`--hostname`, `--accept-dns=false`, now `--accept-routes`), so on a
  converged sidecar tailscale may refuse it with "mention all non-default
  flags". This is unchanged by this ADR. The converge is the supported path.
