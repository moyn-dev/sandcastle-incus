# Making a tenant sidecar user-owned (so machines can reach shared machines)

Written 2026-09-03, after doing it to tenant `thieso2` on `obelix`.

## Why you would

Every sidecar joins the tailnet tagged `tag:sandcastle` (ADR-0017), and a tag
replaces the human owner. Tailscale's **machine sharing** hands a machine to a
*user*: it appears only in the peer lists of that user's devices, and
"a machine cannot be … accessed by tagged machines on another tailnet, as only
users can accept machine shares". So a tagged sidecar never holds a shared
machine in its netmap, and no ACL, route or NAT rule changes that — with
tailnet egress on (ADR-0026) the steer and the masquerade work perfectly and
the packets still die at the sidecar with "no matching peer".

Re-authenticate the sidecar as a **user** and the share appears. Tenant
machines then reach it through the egress path they already have, with no
per-machine Tailscale client.

## What you keep, what you lose

- **Keep route auto-approval.** The tag's real job. `autoApprovers` accepts a
  user's login email as well as a tag, so add the user next to it:

  ```jsonc
  "autoApprovers": { "routes": { "10.0.0.0/8": ["tag:sandcastle", "someone@example.com"] } }
  ```

  This must be saved **before** the sidecar re-registers: auto-approvers are
  evaluated when a route advertisement is first received, and do not
  retroactively approve a pending route. Get the order wrong and the tenant's
  `/24` needs one manual approval, during which the tenant is unreachable over
  the tailnet.
- **Lose expiry immunity.** Tagged nodes never expire; user-owned ones do.
  **Disable key expiry on the sidecar in the admin console.** An expired
  sidecar takes the whole tenant off the tailnet.
- **Shared identity becomes a person's.** Every machine of the tenant now acts
  on the tailnet as that user, for everything egress allows. Reasonable for a
  personal tenant; do not do it to a tenant whose machines belong to several
  people, or to one that runs autonomous agents.

## Where to run it — not over the tailnet

The sequence logs the sidecar out, so **every path that depends on the
sidecar's tailnet address dies mid-procedure**: `ssh` to tenant machines,
`sc c`, and `sc incus` / `sc incus-infra` when the enrolled remote is the
sidecar's `100.x` address (check `~/.config/sandcastle/incus/config.yml`:
a remote at `https://100.x:8443` is such a case, one at
`https://10.x.y.1:8443` is not).

Run it from somewhere that reaches the Incus API another way:

- the operator's admin remote (`incus … big:` over the host's public name), or
- a machine on the tenant bridge, whose remote is the bridge gateway.

And issue logout and `tailscale up` as **one detached command**, so the
sidecar finishes the sequence and sits waiting for authentication even if your
control connection drops at the wrong moment.

## Procedure

Substitute: `PROJ` the tenant's **infra** Incus project (`<install>-<tenant>`),
`CIDR` the tenant's `/24`, `HOST` the sidecar's current tailnet hostname.

```sh
PROJ=obelix-thieso2 CIDR=10.123.0.0/24 HOST=sc-obelix-thieso2-dev-thieso2

# 0. record what it has now (routes, hostname, DNS/route prefs) and its IP
incus exec big:sidecar --project $PROJ -- tailscale debug prefs > prefs.before.json
incus exec big:sidecar --project $PROJ -- tailscale ip -4

# 1. tailnet policy: add the user's email to autoApprovers, SAVE IT NOW

# 2. re-authenticate, detached; the URL lands in /tmp/tsup.log
incus exec big:sidecar --project $PROJ -- sh -c "
  tailscale debug prefs > /tmp/prefs.before.json
  tailscale logout
  rm -f /tmp/tsup.log
  setsid sh -c 'tailscale up --advertise-routes=$CIDR --hostname=$HOST --accept-dns=false >/tmp/tsup.log 2>&1' &
  sleep 10; cat /tmp/tsup.log"
```

Open the printed `https://login.tailscale.com/a/…` URL and sign in **as the
user who owns the shares**. Then, in the admin console:

- check the node's IPv4; if it changed, set it back to the old address, or
  every enrolled `sc` client of that tenant must be re-enrolled;
- **disable key expiry**;
- delete the old, logged-out sidecar device row so the MagicDNS name is not
  suffixed;
- approve the `/24` route if step 1 was late.

No `--advertise-tags` is the whole trick. Note `sc tailscale up --advertise-tag=""`
composes the same arguments but does **not** log out first, and prefs alone
cannot change a registered node's identity — the logout (or `--force-reauth`)
is the operative step.

## Verify

```sh
incus exec big:sidecar --project $PROJ -- tailscale status --json | \
  python3 -c 'import json,sys; n=json.load(sys.stdin); s=n["Self"]; u=(n.get("User") or {}).get(str(s["UserID"]),{});
print("tags:", s.get("Tags"), "owner:", u.get("LoginName"), "ip:", s.get("TailscaleIPs"));
print("shared peer present:", any("<shared-host>" in (p.get("DNSName") or "") for p in (n.get("Peer") or {}).values()))'

# route approved = the CIDR is in the node's own AllowedIPs
incus exec big:sidecar --project $PROJ -- tailscale debug netmap | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["SelfNode"]["AllowedIPs"])'

# and from any tenant machine, with egress on and no Tailscale client:
curl -sI https://<name-of-the-shared-service>/ | head -1
```

Observed on thieso2: `Tags: None`, owner the tenant's user, IP unchanged,
peers 17 → 18 with the shared node present, and a tenant machine reaching it
by name over the option-121 steer plus the `sandcastle-egress` masquerade.
The recipient-side 1:1 NAT for a shared node applies to traffic the sidecar
**forwards**, not only to what it originates.

## Rollback

Same procedure with the tag restored:

```sh
incus exec big:sidecar --project $PROJ -- sh -c "
  tailscale logout
  setsid sh -c 'tailscale up --advertise-routes=$CIDR --hostname=$HOST --accept-dns=false \
    --advertise-tags=tag:sandcastle --auth-key=<key> >/tmp/tsup.log 2>&1' &
  sleep 10; cat /tmp/tsup.log"
```

A tagged re-join can use an auth key and needs no browser. The
`tag:sandcastle` autoApprover takes the route back automatically.

## Does a converge undo it?

No, as long as the sidecar stays registered: the interactive path in
`v2TailscaleUp` exits early when `tailscale ip -4` already answers, so
`sc login` and `sc-adm tenant create` leave a logged-in sidecar alone. A
converge run **with** `--tailscale-authkey` does re-run `tailscale up` with
`--advertise-tags=tag:sandcastle` and would re-tag it.

## See also

- ADR-0017 (sidecar as the tenant's single tailnet touchpoint), ADR-0026
  (tailnet egress).
- `docs/research/shared-tailscale-node-egress-2026-09-03.md` — the evidence,
  the options considered, and the measurements.

## Applied a second time: skorfmann on obelix, 2026-09-04

Same procedure, run from the operator's admin remote (`incus … big:`), with
egress switched on first — that tenant never had it:

```sh
incus project set big:obelix-skorfmann user.sandcastle.v2.tailnet-egress=true
# bridge + sidecar artifacts applied by hand from internal/tenant/egress.go
# rather than running a full `sc-adm tenant create` converge against a tenant
# holding live prod machines (the converge also touches suffix, profiles,
# payload and the sidecar's tailnet hostname).
```

Observed: the sidecar kept its tailnet IPv4 (100.84.214.28) and its hostname,
so no duplicate device row appeared and no `sc` client needed re-enrolling;
the `/24` came back approved without a manual click; peers 17 → 18 with the
shared node present. During the ~1 minute the node is logged out the admin
console shows the route as no longer advertised — that is the window, not a
failure; check `tailscale debug netmap | SelfNode.AllowedIPs` afterwards.

Still owed on every switch: **disable key expiry** in the console (the fresh
node came back with a 180-day expiry).
