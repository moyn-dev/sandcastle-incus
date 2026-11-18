# Tailnet egress: machines reach tailnet peers through the sidecar

Status: accepted. Amended by ADR-0033 (subnet routes are steered too, the sidecar accepts routes, and new tenants default on).

## Context

Machines are deliberately **not** tailnet nodes (ADR-0006, ADR-0017): the
sidecar is the tenant's single tailnet touchpoint, advertising the tenant `/24`
as a subnet route. That gives *inbound* reachability only. A machine sending
*to* a tailnet address (the CGNAT range `100.64.0.0/10`) follows its default
route to the host bridge gateway (`.1`), which forwards it to the public
uplink, where CGNAT is unroutable and silently dropped.

Diagnosed live (tenant `thieso2` on `obelix`, target a Reachy Mini robot at
`100.87.148.82`): ping/HTTP/SSH all time out; TTL-stepped pings show hop 1 =
the host gateway, hop 2+ = the provider's public routers. The sidecar sits on
the same bridge with a working `tailscale0` path and never sees the traffic.

The considered alternative — making machines tailnet nodes (per-machine
tailscaled) — was rejected as the default: device sprawl (tagged ephemeral auth
keys, cleanup of deleted machines), `/dev/net/tun` in every instance, dual
reachability muddying DNS and ingress, and it dilutes the sidecar-as-single-
touchpoint model. It may return later as an explicit opt-in for machines that
need node features (Tailscale SSH, serve/funnel, per-machine ACL identity).

## Decision

Egress is **per-tenant, opt-in, off by default**, entirely router-side —
machines stay clean. Three pieces:

1. **Steer (bridge):** the tenant bridge's `raw.dnsmasq` gains a DHCP
   classless static route (option 121): `100.64.0.0/10` via the sidecar's
   bridge address. RFC 3442 makes clients that receive option 121 ignore the
   router option, so the **default route rides along in the same option**.
   Machines — current and future — pick it up on lease renewal, zero
   per-machine setup.
2. **NAT (sidecar):** an `nftables` table (`sandcastle-egress`, own table so
   it composes with whatever tailscaled manages) masquerades tenant-sourced,
   CGNAT-destined traffic onto `tailscale0`. Peers see a normal connection
   from the sidecar's tailnet IP and need neither `--accept-routes` nor
   knowledge of the tenant CIDR. Applied by a oneshot unit
   (`sandcastle-sidecar-egress.service`) alongside the existing
   `sandcastle-sidecar-network` oneshot. This NAT is independent of the
   bridge's `ipv4.nat=true` (host-masqueraded machine→internet); do not
   "simplify" one into the other.
3. **Permit (tailnet ACL, out of platform scope):** the sidecar is tagged
   (`tag:sandcastle`); tagged nodes are strictly ACL-governed, so packets are
   dropped until the tenant's policy grants the tag access to the intended
   peers. The docs must say this out loud, and also the flip side: on a
   default-open ACL, enabling egress lets **every** machine of the tenant
   reach **every** tailnet node, with the sidecar's tag as the shared
   identity. That shared identity is the accepted trade-off.

**State & converge:** the toggle is `user.sandcastle.v2.tailnet-egress` on the
kind=infra project — written only by `sc tailscale egress on|off`, read by the
`CreateTenantV2` converge, which is the *only* code path applying/removing the
mechanics (bridge option and sidecar unit both), on `sc-adm tenant create` and
every tenant `sc login`. One code path, nothing to drift. Unknown/absent reads
as off: egress fails closed.

**Role addresses:** the option-121 next-hop is the sidecar's real bridge
address — `plan.DNSAddress` (`.3`). The `.2` "Tailscale" role address
(`internal/cidr/roles.go`, `TailscaleAddress` in the plan) is dead code that
nothing ever assigns; re-IPing sidecars onto `.2` would break the DHCP
reservation, the `dhcp-option=6` resolver, and the `:9443` TLS-signer URL
baked into app-profile cloud-init, for no benefit.

## Consequences

- Enabling: `sc tailscale egress <tenant> on`, then converge (`sc-adm tenant
  create <tenant>` or the tenant's next `sc login`), then wait for DHCP
  renewal (≤ half the lease, ~20–40 min) or bounce the machine's NIC; add the
  ACL grant. Verify with `ip route get <peer-ip>` (next hop = sidecar) and a
  `curl` to the peer.
- Disabling converges the bridge back to the resolver-only dnsmasq value and
  tears the sidecar unit/table down; machines lose the route on renewal.
- Static-IP machines don't consume DHCP options and won't pick up the route.
- Follow-up (separate): MagicDNS for machines — the sidecar CoreDNS could
  forward the tailnet zone so peers resolve by name; egress only moves packets.
