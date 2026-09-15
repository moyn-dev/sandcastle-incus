# Installing Sandcastle on a fresh host

This guide stands up the complete Sandcastle stack on one fresh Debian machine:
Incus itself, the **auth-app** appliance (GitHub login + OIDC + tenant
provisioning, with the public edge built in). (An **acme**/**none**-ingress
install also deploys a **broker** appliance for the tenant plane; the Cloudflare
path in this guide does not — see §4.) Tenants then run as native Incus projects; their
machines are plain Incus containers/VMs.

It is the distilled, install-only path — two commands on the server plus a
Cloudflare tunnel you create in the dashboard. For the full end-to-end
**validation** runbook (with PASS criteria for every phase) see
[`docs/e2e-sc2.md`](docs/e2e-sc2.md); for design background see
`docs/adr/0016-*` and `CONTEXT.md`.

The flow below was last proven end-to-end on 2026-07-06 (hosts `obelix`/`asterix`).

---

## 1. Prerequisites

- **A fresh Debian-based host** (Debian 12/13 or Ubuntu) you can SSH into with
  sudo. It does **not** need a public IP (the Cloudflare-tunnel ingress dials
  out), and it does **not** need Incus yet — §2 installs it.
- **An Auth Hostname** on a DNS zone you control, e.g. `obelix.example.dev`.
  For the Cloudflare-tunnel ingress the zone must be on Cloudflare, and the
  hostname must be **first-level** (`obelix.example.dev`, not
  `a.b.example.dev` — free Universal SSL only covers one level).
- **A GitHub OAuth App** (for login). Set its **Authorization callback URL** to
  `https://<auth-hostname>/oauth/github/callback`. Note the **client id** +
  **secret**.
  - **Testing shortcut — no OAuth app needed.** Pass
    `--simulate-github-token <secret>` instead of the `--github-*` flags:
    the appliance fabricates logins offline (any username), gated by that
    shared secret. Log in with
    `sc login <auth-host> --simulate-token <secret> --as <username>`.
    **Dev/e2e only — never in production.**
- **No Tailscale on the server.** The host, the admin, and the appliances are
  on no tailnet. Each tenant brings their own Tailscale key at `sc login`
  (or approves an interactive join URL); the tenant's sidecar joins the
  *tenant's* tailnet. There is nothing tailnet-related to prepare server-side.
- **The fat binary, built for Linux.** One binary provides `sc` / `sc-adm`:
  ```bash
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 BIN_DIR=bin/linux-amd64 make build
  # produces bin/linux-amd64/{sandcastle,sc,sc-adm,sandcastle-admin}
  ```

---

## 2. Install the binary + Incus on the host

Copy the fat binary onto the host and create the busybox-style names —
**all four names must point at the one binary** (the invocation name selects
the role):

```bash
scp bin/linux-amd64/sandcastle <host>:/tmp/
ssh <host>
sudo install -m 0755 /tmp/sandcastle /usr/local/bin/sandcastle
sudo ln -sf sandcastle /usr/local/bin/sc
sudo ln -sf sandcastle /usr/local/bin/sc-adm
sudo ln -sf sandcastle /usr/local/bin/sandcastle-admin

sudo sc-adm install-incus
```

`install-incus` is idempotent and does four things: adds the **Zabbly stable**
apt repository (Debian's own archive ships an old LTS; sandcastle wants the
current release for shared CT+VM volumes and `security.shifted`), installs or
upgrades the `incus` package, runs `incus admin init --minimal` when the daemon
is uninitialized (creates the `default` dir storage pool and the `incusbr0`
bridge), and adds the invoking user to the `incus-admin` group.

Then, still on the host:

```bash
# log out and back in first — the incus-admin group membership is per-session
incus config set core.https_address=:8443
```

Without the network listener, tenant provisioning later fails at token issuance
with `Can't issue token when server isn't listening on network`.

Verify:

```bash
incus storage list                    # pool "default" (dir), state CREATED
incus network list                    # bridge "incusbr0", managed, 10.x.y.1/24
incus config get core.https_address   # :8443
```

---

## 3. Create the public ingress — Cloudflare tunnel (by hand)

The recommended ingress for a host without a public IP: Cloudflare terminates
TLS at its edge and forwards down an **outbound** tunnel to the auth-app —
nothing inbound reaches the host. You create the tunnel once in the dashboard
and hand its connector token to the installer; the appliance runs `cloudflared`
itself.

In the Cloudflare dashboard (free plan is fine):

1. **Zero Trust** (one.dash.cloudflare.com) → **Networks → Tunnels** →
   **Create a tunnel** → connector **Cloudflared** → name it (e.g. `obelix`)
   → **Save tunnel**.
2. On "Install and run a connector": **don't install anything.** Copy the
   **token** — the long `eyJ…` string in the shown
   `cloudflared service install eyJ…` command (keep only the `eyJ…` part).
   Click **Next**.
3. On the **Public Hostname** step:
   - **Subdomain:** `obelix` — **Domain:** `example.dev` — **Path:** empty
   - **Service:** Type **HTTP**, URL **`localhost:8080`**
     (the port the appliance's edge listens on inside)
   - **Save.** This normally auto-creates the proxied DNS record.
4. The tunnel shows **Down/Inactive** — expected; nothing runs the connector
   until §4.

> **Verify the DNS record actually exists** — record creation can silently
> fail (e.g. a conflicting record). Check the zone's **DNS → Records** for
> `<auth-hostname>`; if missing, add it yourself: **CNAME**, name `obelix`,
> target `<tunnel-id>.cfargotunnel.com`, **Proxied** (orange cloud). The
> tunnel id is in the tunnel's dashboard page (also the `t` field inside the
> base64 token). Symptom of a missing record: NXDOMAIN, `curl` exit 6.

**Alternatives** (all via `sc-adm install --ingress …`):
- `--ingress cloudflare --cloudflare-api-token <token>` — same topology, but
  the installer creates the tunnel, ingress rule, and DNS record itself
  (token needs Tunnel:Edit + DNS:Edit + Zone:Read).
- `--ingress acme` — host has a public IP: binds host `:80`/`:443` and issues
  a Let's Encrypt cert directly (`--acme-email`). The Auth Hostname must
  resolve to the host's public IP.
- `--ingress none` — bring your own edge (e.g. a standalone
  [`sc-edge`](sc-edge/) appliance) and front `:9444` yourself.
- `--route-ingress acme|acme-proxied --route-dns-cloudflare-wildcard '*.jot.example.com' --route-dns-cloudflare-api-token <token>`
  — optional route TLS optimization for services that mint open-ended
  hostnames: exactly allowlisted leading-wildcard Public Routes use one
  Cloudflare DNS-01 certificate instead of issuing a certificate on every
  first request. Scope the token to `Zone:Read` + `DNS:Edit` for the route zone.

---

## 4. Install Sandcastle — one command

On the host:

```bash
sc-adm install \
  --auth-hostname obelix.example.dev \
  --github-client-id     "$GH_CLIENT_ID" \
  --github-client-secret "$GH_CLIENT_SECRET" \
  --admin-github-users   yourgithubname \
  --ingress cloudflare \
  --cloudflare-tunnel-token "$CLOUDFLARE_TUNNEL_TOKEN" \
  --cidr-pool 10.253.0.0/16
```

This deploys the **auth-app appliance** from stock `images:debian/13` (pulled on
demand), copying the **running binary** (`os.Executable()`) into it:

- `sc2-auth-app` (project `infrastructure`) — auth-app on `:9444` internally,
  fronted by caddy + cloudflared *inside the same container* (no host ports)

> **The install owns its own appliance bridge.** By default `sc-adm install`
> creates a NATed bridge `<prefix>-net` (e.g. `sc2-net`; long prefixes use a
> stable `sc-<8-hex>-net` name to fit Linux's 15-character limit) with an auto-picked
> subnet and puts the appliances on it — so an install shares **no** network
> object with v1 or with other installs (the only thing shared is the Incus
> daemon). Appliances need only outbound (image pulls, cloudflared, tailscale);
> provisioning rides the mounted host socket, not L3. Pass `--bridge incusbr0`
> (or any existing bridge) to opt out and put the appliances on the host bridge
> instead. Per-**tenant** bridges are unaffected — each tenant still owns its
> own `/24`.

> **No broker with Cloudflare ingress.** The broker appliance is only deployed
> for `--ingress acme`/`none`, where it needs a reachable host `:9443` for the
> tenant plane. With a Cloudflare tunnel there is no inbound host port and no
> route to the broker, and tenant self-service (`sc project create`) rides the
> auth-app's `POST /api/projects` instead — so the broker is skipped entirely
> and **nothing binds `:9443` on the host**.

Both share the one `--cidr-pool` for tenant allocation — see §6 before
picking it. `sc-adm install` refuses to run when an installation under the
same `--prefix` (default `sc`) already exists, and warns when the pool
overlaps a host address.

No Tailscale flags: tenants bring their own keys at login
(`--tailscale-auth-key` sets a server-side default key — only sensible when
the operator owns the tenants' tailnet, e.g. single-user or CI installs).
Subnet-route approval is the tenant's job on the tenant's tailnet: approve in
the Tailscale admin console, or add a `tag:sandcastle` `autoApprovers` ACL
rule for zero-touch approval.

---

## 5. Verify the install

On the host:

```bash
incus exec sc2-auth-app --project sc2-infra -- \
  systemctl is-active sandcastle-auth-app caddy cloudflared   # active ×3
# (acme/none ingress only — Cloudflare installs deploy no broker)
# incus exec sc2-broker --project sc2-broker -- systemctl is-active sandcastle-broker
```

The tunnel in the Cloudflare dashboard flips to **Healthy**. (In the
cloudflared journal, `QUIC connection failed` + `proceed using 'http2'` is a
harmless fallback when outbound UDP/7844 is blocked.)

Then the public path:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://obelix.example.dev/healthz   # 200
# real OAuth:  https://…/login/github → 302 to github.com…client_id=…
# simulated:   https://…/oauth/github/simulate?token=…&username=… → 200
```

---

## 6. First login — provisions the tenant

From a **client machine that is itself a tailnet node** (not the server — and
not a box that other infrastructure already routes to by subnet; see the
two-VM note in `docs/e2e-sc2.md`):

```bash
sc login https://obelix.example.dev
```

What happens, in order:

1. Prints the SSH key it will register and a device-login URL
   (`…/device?user_code=XXXX-XXXX`) — open it, sign in with GitHub, approve.
2. First login **provisions your tenant** (1–2 minutes): projects
   `sc2-<user>` (sidecar infra) + `sc2-<user>-default` (your machines), on a
   per-tenant bridge cut from the CIDR pool.
3. **Sidecar joins YOUR tailnet.** Either pass
   `--tailscale-auth-key tskey-…` for unattended join, or login prints an
   interactive `https://login.tailscale.com/a/…` URL — open it, log in, and
   **approve the sidecar's advertised subnet route** in the Tailscale admin
   console (Machines → the sidecar → Edit route settings). Login waits and
   continues automatically.
4. **Tenant routing is verified layer by layer** — login turns on
   `tailscale set --accept-routes=true` for you, then requires: tailscale up
   → accept-routes on → route served by a primary peer → a probe to the
   tenant gateway that **egressed via the tailnet** (a LAN answer doesn't
   count). Any broken layer halts login with specific advice.
5. Local enrollment is written to `~/.config/sandcastle/<tenant>/incus`
   (restricted per-tenant Incus certs + remotes).

Then use it:

```bash
sc status                        # tenant overview
sc create mybox                  # create a machine (container)
sc connect mybox                 # SSH in (alias: sc c)
sc incus -- list                 # raw incus against your tenant remote
sc project create test2          # self-service project via the broker
                                 # (broker URL + client cert come from the login)
```

**Admin path (no browser):** admins can create tenants directly on the host —
`sc-adm tenant create <name> --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" --cidr-pool …`
(remote `--broker https://<host>:9443` works only for acme/none installs that
have a broker). It prints an enrollment
token; the user runs `sc enroll <token>` on their client.

---

## 7. CIDR pools — the one config you must get right

Each tenant gets a `/24` cut from the `--cidr-pool` `/16`, and its gateway
becomes a real bridge (`dnsmasq`) on the host. The allocator only skips CIDRs
it can see as existing tenants — it is blind to any other bridge on the host.
So a pool that overlaps another bridge fails provisioning with:

```
dnsmasq: failed to create listening socket for <gw>: Address already in use
```

Rules:
- The pool must not overlap the host's own addresses, `incusbr0`, or any
  pre-existing bridge on the host.
- Keep pools **distinct across installations that share a tailnet** — tenant
  subnet routes from two sandcastles must not collide on the clients that
  accept them.
- Check what's taken before choosing:
  ```bash
  ip -br a                                              # host side
  incus network list --project default -c n4 --format csv | grep bridge
  ```

---

## 8. Gotchas

- **`sc-adm: unknown command` after updating the binary.** All four names
  must resolve to the **same** file — check `ls -la /usr/local/bin/`; a stale
  separate `sandcastle-admin` binary shadows the new one via the `sc-adm`
  symlink.
- **Systemd image only.** Appliances must launch from a **container-type**
  systemd image (`images:debian/13`). An OCI/app image has no systemd PID 1
  and `systemctl` fails.
- **`text file busy` pushing a binary** into a running appliance:
  `systemctl stop <svc>` → `incus file push …` → `systemctl start <svc>`.
- **`Image not provided for instance creation`.** The stock base image isn't
  in the `default` project's store — re-cache:
  `incus image copy images:debian/13 local: --project default`.
- **Auth Hostname resolves but TLS fails / NXDOMAIN.** See the DNS-record
  verification note in §3 — the tunnel's Public Hostname step can fail to
  create the record.
- **Client resolves the Auth Hostname to a private IP.** A local search
  domain or wildcard resolver (e.g. another sandcastle's DNS) can shadow the
  public record — test with `getent hosts <auth-hostname>.` (trailing dot)
  or from a clean machine.
- **SSH into a tenant machine** offering many agent keys? Use
  `ssh -o IdentitiesOnly=yes -i <key> dev@<ip>`.

---

## What you end up with

```
Incus host
├── project sc2-infra
│   └── sc2-auth-app   auth-app :9444 + caddy :8080 + cloudflared (outbound tunnel)
├── project sc2-broker            (acme/none ingress only — omitted with Cloudflare)
│   └── sc2-broker     broker :9443  (admin provisioning plane)
└── project sc2-<tenant> / sc2-<tenant>-default
    ├── sc2-<tenant>   per-tenant sidecar (CoreDNS + Tailscale on the TENANT's tailnet)
    └── <machines>     native Incus CTs/VMs the tenant launches

Public surface: ONE hostname through the Cloudflare tunnel (the auth-app).
No inbound ports. No server-side tailnet.
```
