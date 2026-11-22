# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sc-edge` (formerly `caddy-sni-proxy`) is a **self-contained, portable edge
appliance**. It is a generic recipe, **not wired into any host** — it is copied to
whatever host should serve app traffic. It lives inside the `sandcastle-incus` repo
but is independent of the Go project the parent `CLAUDE.md` documents; nothing here
builds or imports Go. See `CONTEXT.md` for the glossary and
`docs/adr/0001-sc-edge-three-mode-flexible-edge.md` for the design rationale.

**One appliance, two cooperating processes:** Caddy (the routing brain — owns all
ingress modes; the `Caddyfile` is the single source of truth) and `cloudflared` (a
dumb outbound pipe, present only when a tunnel token is given).

Files: `Caddyfile` (the shared, portable config), `launch.sh` + `caddy.service` +
`cloudflared.service` (the recommended **Incus system container** path), and
`Dockerfile` + `compose.yaml` (Docker fallback for non-Incus hosts).

**Primary deployment = Incus CT.** `launch.sh` provisions an Incus system container
running Caddy natively under `systemd` (matching how the parent project runs its
`sc-caddy` infra container — see ADR-0016's native-Incus direction), rather than as
a Docker/OCI application container. It fetches the layer4-enabled binary from Caddy's
official download API (`caddyserver.com/api/download?...&p=github.com/mholt/caddy-l4`),
and (when a token is set) the `cloudflared` binary from Cloudflare's GitHub releases,
so the CT needs no Go/xcaddy toolchain. The same `Caddyfile` drives both the CT and
Docker paths.

It supports **three co-equal ingress modes** (a hostname uses exactly one):
1. **SNI passthrough** — forwards the raw, still-encrypted TLS stream to a backend
   that owns its own cert. Caddy never decrypts. Needs public `:443`.
2. **ACME termination + reverse-proxy** — terminates TLS with a Let's Encrypt cert
   and reverse-proxies to a plain-HTTP backend. Needs public `:80`/`:443`.
3. **Cloudflare tunnel** — `cloudflared` dials **outbound** to Cloudflare (no public
   IP / no public sockets needed); Cloudflare terminates TLS at its edge and forwards
   cleartext down the tunnel to Caddy on `127.0.0.1:8080`, which reverse-proxies to a
   plain-HTTP backend. This is the "no public IP" mode; the trade is that Cloudflare
   sees plaintext (so it is mutually exclusive with passthrough per host).

Plus, for the public-IP modes: `http://` → `https://` redirect for every host (308).

Modes are **additive** (hybrid): one container may own public `:80`/`:443` *and* run
the tunnel at once. On an IP-less host, run with `PUBLIC_PORTS=0` and only mode 3 is
active.

## Commands

Incus CT (primary):
- Provision (public-IP modes): `ACME_EMAIL=you@example.com ./launch.sh [name]` (defaults: name `sc-edge`, `IMAGE=images:debian/13`). Add `DATA_HOST_PATH=…` to back `/var/lib/caddy` with a host disk that survives CT deletion.
- Provision with tunnel: also set `CLOUDFLARE_TUNNEL_TOKEN=…`. On an IP-less tunnel-only host add `PUBLIC_PORTS=0`.
- Apply Caddyfile edits (no downtime): `incus file push Caddyfile <name>/etc/caddy/Caddyfile && incus exec <name> -- systemctl reload caddy`
- Validate: `incus exec <name> -- caddy validate --config /etc/caddy/Caddyfile`

Docker (fallback):
- Build + run: `CLOUDFLARE_TUNNEL_TOKEN=… docker compose up -d --build` (omit the token to skip the tunnel; also drop the caddy `ports:` block on an IP-less host).
- Hot reload: `docker exec <caddy-container> caddy reload --config /etc/caddy/Caddyfile`

Set the ACME contact via the `ACME_EMAIL` env var, and the tunnel via
`CLOUDFLARE_TUNNEL_TOKEN`, in either case.

## Architecture — the load-bearing constraint

Both the passthrough and terminate paths share the **single public `:443` socket**.
That split is only possible with the [`caddy-l4`](https://github.com/mholt/caddy-l4)
(`layer4`) plugin, which is why the `Dockerfile` does a **custom `xcaddy` build**
(`--with github.com/mholt/caddy-l4`) rather than using the stock `caddy:2` image. Any
change that touches SNI routing depends on this plugin being present.

The `layer4 { :443 }` block owns the public socket and routes by SNI:
- **passthrough SNIs** → `proxy` raw TLS to the external backend (which presents its own cert).
- **terminate SNIs** → `proxy` raw TLS to `127.0.0.1:8443`, where ordinary Caddy
  `https://…:8443` vhosts (each `bind 127.0.0.1`) decrypt and `reverse_proxy` to an
  internal HTTP backend.

`auto_https disable_redirects` is essential: it keeps ACME automation ON while
stopping Caddy from opening its own `:443` (which would fight `layer4`) or its own
auto-`:80` redirect (we do the redirect in the explicit `:80` block). The terminating
vhosts `bind 127.0.0.1` so they never contend for the public `:443`.

ACME still works despite the terminators being on localhost: HTTP-01 arrives on `:80`
(served by the redirect block automatically); TLS-ALPN-01 arrives on `:443` and
`layer4` routes it to `127.0.0.1:8443`.

### The Cloudflare tunnel path (mode 3)

`cloudflared` is a **dumb outbound pipe** — it holds no per-host routing. It runs a
**remotely-managed** tunnel (just a `CLOUDFLARE_TUNNEL_TOKEN`; the tunnel object and
its ingress live in the Cloudflare dashboard) whose single wildcard route
`*.your-domain → http://127.0.0.1:8080` delivers **all** tunneled traffic to one
plain-HTTP Caddy listener. Caddy then routes by `Host`. So Caddy remains the sole
routing brain across all three modes; `cloudflared` never decides where a request
goes. The `:8080` vhosts `bind 127.0.0.1` (Cloudflare already terminated TLS; the
localhost hop is cleartext HTTP). This path touches **no** public socket, so it works
on a host with no public IP. In Docker the `cloudflared` service uses
`network_mode: "service:caddy"` so it shares Caddy's loopback.

## Editing the Caddyfile

**Adding a terminate host requires TWO edits** — this is the easiest thing to get
wrong: (1) add the name to the `@terminate` `sni` list inside the `layer4` block, AND
(2) add a matching `https://<name>:8443 { bind 127.0.0.1; reverse_proxy http://backend }`
vhost. Missing either one breaks that host silently.

**Adding a tunnel host is ONE edit** (the payoff of the wildcard route): add a single
`http://<name>:8080 { bind 127.0.0.1; reverse_proxy http://backend }` vhost. No
`cloudflared` change and no dashboard change — the wildcard already covers the name.
A `:8080` catch-all returns `404` for undeclared names.

Adding a passthrough host is one edit: add the name to the `@passthrough` `sni` list
and point its `route`'s `proxy { to … }` at a backend that speaks TLS.

Unmatched SNIs fall through and the connection closes; add a catch-all `route` in the
`layer4` block if you want a default backend.

## Gotchas

- **Persist `/data`** — it holds issued certs. Losing it re-triggers ACME issuance and
  can hit Let's Encrypt rate limits.
- Every terminate/passthrough hostname must resolve to this host's public IP, and
  `:80` + `:443` must be internet-reachable for ACME.
- Passthrough backends must present a valid cert themselves — Caddy cannot issue for them.
- The terminate path in this scaffold assumes **HTTP backends**; to re-encrypt to an
  HTTPS backend use `reverse_proxy https://backend` with `transport http { tls }`.
- **Tunnel mode:** the tunnel is remotely-managed — you must create it and a wildcard
  `*.domain → http://127.0.0.1:8080` public-hostname route once in the Cloudflare
  dashboard, then pass its token. The token is a secret (`/etc/default/cloudflared`,
  mode `600`); don't commit it. Cloudflare terminates TLS, so tunneled hosts are
  **mutually exclusive with SNI passthrough** and do not use ACME at all.

## Agent skills

`sc-edge` lives inside the `sandcastle-incus` repo and shares its issue tracker and
triage vocabulary. Only the domain docs are local.

### Issue tracker

Issues and PRDs are tracked in GitHub Issues (`moyn-dev/sandcastle-incus`) — the same
tracker as the parent project; there is no separate `sc-edge` tracker. External pull
requests are also a triage surface. See [`../docs/agents/issue-tracker.md`](../docs/agents/issue-tracker.md).

### Triage labels

The standard five-label triage vocabulary. See [`../docs/agents/triage-labels.md`](../docs/agents/triage-labels.md).

### Domain docs

`sc-edge` is a **child context** in a multi-context repo. Read both:

- [`CONTEXT.md`](CONTEXT.md) — edge-appliance glossary (this context)
- [`../CONTEXT.md`](../CONTEXT.md) → [`../docs/glossary.md`](../docs/glossary.md) — Sandcastle-wide vocabulary the child defers to

ADRs likewise: [`docs/adr/`](docs/adr/) for edge decisions, [`../docs/adr/`](../docs/adr/)
for system-wide ones. The root [`../CONTEXT-MAP.md`](../CONTEXT-MAP.md) indexes both.
Consumer rules are in [`../docs/agents/domain.md`](../docs/agents/domain.md).
