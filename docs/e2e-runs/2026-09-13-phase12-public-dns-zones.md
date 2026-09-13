# Test protocol — e2e Phase 12, Public DNS Zones (ADR-0027)

| | |
|---|---|
| Date | 2026-09-13 (UTC) |
| Branch / binary | `feat/public-dns-zones` @ `d536ba3`, `make build` → `0.0.0-dev` |
| Operator | thies (driven by Claude Code from devbox `dev.devbox.obelix`) |
| Admin remote | `big` (`big.thieso2.dev:8443`) |
| Install under test | **fresh**, prefix `tc`, Auth Hostname `https://sc.tc42.uk`, CIDR pool `10.250.0.0/16`, `--ingress none` fronted by the host's `sc-edge`, ACME directory **Let's Encrypt staging** |
| Public DNS Zone | `e2e.sc.tc42.uk` (inside Cloudflare zone `tc42.uk`) |
| Client | container `e2e-pdz-client` (project `default` on `big`), Debian trixie, tailnet node via `TAILSCALE_AUTH_KEY` |
| Protocol source | `docs/e2e-sc2.md` Phase 12; automation `scripts/e2e-pdz.sh` |
| Logs | `/tmp/pdz-e2e/logs/*.log` on the devbox (copied into §Appendix) |

Why a fresh install and a separate client: the devbox that drives the run is a
Sandcastle machine on the `obelix` install and is not a tailnet node, and
`sc login` refuses such a client; the two existing installs on `big` (`obelix`,
prod; `sc`, the older e2e install at `big.thieso2.dev`) were left untouched.

## 0. Preflight

| Check | Result |
|---|---|
| Cloudflare token sees zone `tc42.uk` (`GET /zones`) | PASS — `tc42.uk` id `708029ec…`, also `thieso2.dev` |
| `dig`, `openssl`, `curl`, `jq` on the driver | PASS (`bind9-dnsutils` installed on devbox) |
| Host `:80/:443` owner | `sc-edge` (project `infrastructure`) — so `--ingress none` + edge vhost |
| Free CIDR pool | `10.250.0.0/16` (in use: 10.123, 10.124, 10.196, 10.239, 10.248, 10.200, 10.73, 10.10) |
| A record `sc.tc42.uk → 65.21.132.31` | created via Cloudflare API, DNS-only, TTL 120 |

## 1. Install (server side)

```
$ SANDCASTLE_REMOTE=big sc-adm install --prefix tc --auth-hostname sc.tc42.uk \
    --ingress none --cidr-pool 10.250.0.0/16 --simulate-github-token *** \
    --admin-github-users thieso2 --tailscale-auth-key *** --acme-email thies@moyn.dev \
    --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory
```

Result (08:17:18 → 08:17:30 UTC): **PASS.**

```
[0/2] creating appliance bridge tc-net (own, NATed)...
[1/2] deploying auth-app appliance tc-auth-app...
[2/2] deploying broker appliance tc-broker...
sandcastle installed (prefix "tc"):
  auth-app: tc-auth-app (project tc-infra), serving :9444 internally
  broker:   tc-broker (project tc-broker), :9443
  tenant CIDR pool: 10.250.0.0/16
```

PASS criteria from `docs/e2e-sc2.md` (Phase 1, `--acme-directory`):

| Criterion | Observed |
|---|---|
| `systemctl is-active sandcastle-auth-app` in `tc-auth-app` | `active` |
| `/etc/sandcastle/auth-app/env` carries the staging directory | `SANDCASTLE_AUTH_ACME_DIRECTORY='https://acme-staging-v02.api.letsencrypt.org/directory'` |
| journal logs the directory at startup | `machine certificates: acme directory https://acme-staging-v02.api.letsencrypt.org/directory` |
| `http://127.0.0.1:9444/healthz` inside the appliance | `200` |

Note: `sandcastle-admin version` inside the appliance printed a warning that it could not tell which Incus remote hosts install "local" — cosmetic for this run (the appliance uses the mounted socket), noted for follow-up.

## 2. Public edge (sc-edge vhost)

`tc-auth-app` sits at `10.202.145.97` on `tc-net`. Appended to `/etc/caddy/Caddyfile` in `sc-edge` (backup `Caddyfile.bak.pre-tc42`), then `caddy validate` + `systemctl reload caddy`:

```
http://sc.tc42.uk  { reverse_proxy http://10.202.145.97:9444 }
https://sc.tc42.uk { reverse_proxy http://10.202.145.97:9444 }
```

| Criterion | Observed |
|---|---|
| `sc.tc42.uk` resolves publicly | `65.21.132.31` at 1.1.1.1 and 8.8.8.8 |
| `curl http://sc.tc42.uk/healthz` | `200` |
| `curl https://sc.tc42.uk/healthz` (real Let's Encrypt cert on the edge) | `200`, `ssl_verify_result=0` |

**PASS** (08:18:34 UTC).

## 3. Client (tailnet node)

`incus launch big:50661fc47920 e2e-pdz-client --project default` (Debian trixie base image on the host); `apt-get install curl ca-certificates jq bind9-dnsutils openssl gnupg incus-client`; Tailscale via `install.sh` (1.102.4); `/dev/net/tun` present without extra devices; fat binary pushed to `/usr/local/bin/sandcastle` with `sc`/`sc-adm`/`sandcastle-admin` links; `scripts/e2e-pdz.sh` and a minimal `/root/.env.e2e` pushed.

```
$ tailscale up --auth-key "$TAILSCALE_AUTH_KEY" --accept-routes --hostname e2e-pdz-client --timeout 90s
backend error: invalid key: API key does not exist
Logged out.
```

**BLOCKED** (08:19:19 UTC): the coordination server rejects the auth key (`tskey-auth-…`, 61 chars, not the sample placeholder). "API key does not exist" is Tailscale's wording for an auth key that is expired, already consumed (single-use), or revoked. Nothing downstream can run without a tailnet client: `sc login` refuses a non-tailnet client, and 12c dials the machine's tenant-bridge IP over the subnet route.

Resume point: put a fresh **reusable, pre-authorized** auth key into `.env.e2e` (the sidecar joins with `--advertise-tags=tag:sandcastle`, so the key must be allowed to carry that tag — or the tailnet policy must have `tagOwners`/`autoApprovers` for it as in `docs/e2e-sc2.md` prerequisites), re-push `/root/.env.e2e` to the client, and continue from §3.

Left in place for the resume: install `tc` (`tc-infra`, `tc-broker`, bridge `tc-net`), the `sc-edge` vhost, the A record `sc.tc42.uk`, and the client container `e2e-pdz-client`.

Retry with a fresh key (08:52:08 UTC):

```
state=Running self=e2e-pdz-client.tail61f416.ts.net. ip=100.115.171.18
```

**PASS** — client is a tailnet node with `--accept-routes`.

## 4. Login (tenant provisioning on the `tc` install)

```
$ sc login https://sc.tc42.uk --simulate-token *** --as thieso2 --tailscale-auth-key *** --dns-suffix tcpdz
```
(`--as thieso2` because `thieso2` is the install's Sandcastle Admin: the `public-dns-zone` verbs in 12a need it.)

Result (08:52:21 → 09:08:42 UTC): **BLOCKED** — device login auto-approved (simulated GitHub), the server created `tc-thieso2` + `tc-thieso2-default` and the sidecar, but the sidecar's `tailscale up` failed on every provisioning retry and the login polling timed out:

```
Personal Tenant provisioning failed: tailscale up: command exited with status 1
  (stderr: backend error: invalid key: API key k2LrARpYD721CNTRL not valid … tailscale did not connect)
device login polling timed out
```

Diagnosis: the key id in the error is the key from `.env.e2e` (passed via `--tailscale-auth-key` at login; the login key wins over the install default, `provision.go` → `V2Create(plan, tailscaleAuthKey)`). The same key had joined `e2e-pdz-client` successfully 30 s earlier, so it is a **single-use** key that the client consumed. The sidecar needs a **reusable** key (and it advertises `tag:sandcastle`).

Resume point: reusable + pre-authorized key allowed to carry `tag:sandcastle` → `.env.e2e` → re-push `/root/.env.e2e` → `sc login … --force` (provisioning resumes on the existing tenant projects).

Second key (09:22 UTC) is on a **different tailnet** (`moyn.dev`, `tail07b93e`). Client re-joined: `tailscale logout` → `tailscale up --force-reauth …`:

```
state=Running self=e2e-pdz-client.tail07b93e.ts.net. ip=100.103.96.69 tailnet=moyn.dev
```

Login retried with `--force` and the new key (09:22:10 UTC).

Result (09:22:11 → 09:22:49 UTC): **PASS.**

```
Approved. Provisioning will continue in the CLI.
v2 tenant thieso2 is ready.
Remote "tcpdz" enrolled.
  ✓ tailscale is up (this machine is 100.103.96.69, …)
  ✓ accept-routes is enabled
  ✓ route 10.250.0.0/24 is served by peer "sc-sc-tc42-uk-thieso2" (100.74.0.4, online)
  ✓ probe to 10.250.0.1:8443 connected via this machine's tailnet address
  ✓ local resolver: *.tcpdz → tenant CoreDNS at 10.250.0.3:53
Tenant CA "Sandcastle tcpdz tenant CA" trusted
```

PASS criteria (docs/e2e-sc2.md, login): all four routing checks ✓; the sidecar's `/24` was **auto-approved** on the `moyn.dev` tailnet (no manual console step); the private-mode trust/resolver setup still runs unchanged (additive feature — Tenant CA and CoreDNS untouched).

## 5. Phase 12 — `scripts/e2e-pdz.sh` (09:23 UTC)

```
$ SANDCASTLE_E2E=1 bash /root/e2e-pdz.sh     # in e2e-pdz-client, env from /root/.env.e2e
```

### Run 1 (09:23:00 UTC) — **FAIL at 12a**, defect found

```
== 12a zone registry
Cloudflare rejected the token for zone e2e.sc.tc42.uk: the token cannot see a zone named e2e.sc.tc42.uk
  (check Zone > Zone > Read and the zone the token is scoped to)
FAIL: public-dns-zone add e2e.sc.tc42.uk
```

Finding **F1 — zone registry requires the Public DNS Zone to be a Cloudflare zone by exact name.**
`public_dns_zones.go` resolved the zone id with `GET /zones?name=<zone>`. The design (map #155, CLI surface #160, `.env.e2e.sample`) allows a Public DNS Zone to be any name *inside* a Cloudflare zone, with records written into the containing zone. The token here sees `tc42.uk` (verified in preflight). Fix: resolve the longest Cloudflare zone that equals or contains the requested name, persist its name (`cloudflare_zone`), and address libdns records relative to it. Fixed on the branch before run 2 (commit noted below).

Fix: commit `587928b` on `feat/public-dns-zones` — containing-zone resolution (longest match over the zones the token can read, `result_info` paging), `cloudflare_zone` column + guarded migration, libdns names relative to the Cloudflare zone in the reconciler/sweep/release paths; unit tests for equal/subdomain/none/longest-match/paging/migration/reconcile-relative-names.

Rollout (09:32:21 UTC): binary pushed into `tc-auth-app` as `sandcastle-admin`, service restarted — journal: `auth database migrated in 6ms`, staging directory logged again; `healthz` 200 locally and via `https://sc.tc42.uk`. Same binary + script pushed into the client.

### Run 2 (09:32 UTC, run id `e2e-p12b`)

```
== 12a zone registry
Registered public DNS zone e2e.sc.tc42.uk (Cloudflare zone id 708029ec1cd45a969a519d5308431564)
PASS: e2e.sc.tc42.uk listed with a Cloudflare id and a token fingerprint
PASS: refused: already registered
FAIL: expected … "Cloudflare rejected the token", got: public DNS zone garbage-p12b.e2e.sc.tc42.uk overlaps registered zone e2e.sc.tc42.uk; zones may not nest
```

F1 is fixed (zone registered against Cloudflare zone `tc42.uk`, id `708029ec…`). The remaining failure is a **harness defect, F2**: the bad-token probe used a name *under* the just-registered zone, so the nesting refusal (which runs before any Cloudflare call) fired first. Corrected in `scripts/e2e-pdz.sh` and `docs/e2e-sc2.md`: the probe now uses a sibling name (`bad-<id>.${ZONE#*.}`). No product change. Zone `e2e.sc.tc42.uk` stays registered for run 3 (the script tolerates a pre-registered zone).

### Run 3 (09:35 UTC, run id `e2e-p12c`)

| Step | Result |
|---|---|
| 12a zone registry: add (inside `tc42.uk`), list with id + fingerprint, duplicate refused, bad token refused (sibling name), nesting refused, registry unchanged | **PASS** ×5 |
| 12b project domain: create `zp-p12c --domain e2e-p12c.e2e.sc.tc42.uk`, status shows Domain + zone, zone list counts the claim, apex refused, uncovered zone refused, overlap refused (same tenant, names the project), same-domain `set-domain` no-op | **PASS** ×7 |
| 12c `sc create zp-p12c:web`: `Public name: web.e2e-p12c.e2e.sc.tc42.uk (A record pending, certificate pending — see: sc project status zp-p12c)`, no `DNS:` line; bridge IP `10.250.0.112` | **PASS** ×2 |
| 12c both A records (`web…`, `x.web…`) answer `10.250.0.112` at 1.1.1.1 | **PASS** (within ~40 s of create) |
| 12c `cert-state` → `installed`; `sc ls` CERT = `ok`; `sc project status` shows installed with NOT AFTER `2026-12-12T08:35:23Z` | **PASS** ×3 |
| 12c `openssl s_client` (SNI `web…`, bridge IP:443): SANs `*.web.e2e-p12c.e2e.sc.tc42.uk`, `web.e2e-p12c.e2e.sc.tc42.uk`; issuer `C=US, O=Let's Encrypt, CN=(STAGING) Baloney Bulgur YE2` | **PASS** |
| 12c wildcard vhost `x.web…` serves `/_w/` over the same Caddy | **PASS** |
| 12f `unset-domain` refused ("has machines with a public name: web"); zone `remove` refused ("still has claimed project domains") | **PASS** ×2 |
| cleanup `sc delete zp-p12c:web` → wait for both A records to vanish (180 s, TTL 60) | **FAIL** — records still answered by Cloudflare's authoritative servers at timeout; removed only when the script's failure cleanup ran `sc project delete` (09:37:08, project-delete hook deleted them) |

Timeline from the appliance journal: 09:33:20 `POST /api/machine-certificates` 202 → 09:33:23 `set 2 A record(s)` → 09:33:59 staging certificate `2cae0a99…` issued → 09:34:01 installed on `tc-thieso2-zp-p12c/web` (**41 s create → installed**) → 09:34:02 unset/remove refusals (409) → machine deleted ~09:34:05 → **no reconcile activity for the zone until** 09:37:08 project delete.

Finding **F3 — stale A records survive the deletion of the last zone-mode machine.** `zoneReconciler.Reconcile` returns early on an empty fleet ("never trusted") and derives the zones to reconcile from live machines only; a zone whose claims have no live machine is never revisited, so its records are GC'd only by the project-delete hook. Fix on the branch before run 4 (commit noted below). Leftover state after run 3: project deleted, zone removed, no records under `e2e.sc.tc42.uk` at Cloudflare (verified via API), retained certificate row for `web.e2e-p12c…` in the Auth Database (by design, §4.6).

Fix: commit `e5cb0da` on `feat/public-dns-zones` — the per-pass zone set is now the union of zones with live machines and zones with claims (records reconciled with an empty target list, so stale A records under a claimed domain are deleted); the empty-fleet early return is gone (a listing failure is an error, an empty slice is a real state; records self-heal, certificate rows are retained), kept only for the never-issued-row GC where a wrong empty listing would destroy backoff/ARI state. Tests: last machine in a zone deleted (other zone untouched), whole fleet empty (records deleted, retained row kept), zone without claims never read. Also carries the F2 harness fix.

Rollout (09:41:53 UTC): binary into `tc-auth-app` + restart (`active`, healthz 200); binary + script into the client.

### Run 4 (09:41:56 UTC, run id `e2e-p12d`)

**ALL PASS** (09:41:56 → 09:43:27 UTC, 91 s wall clock).

| Step | Result |
|---|---|
| 12a zone registry (5 checks) | PASS |
| 12b project domain (7 checks) | PASS |
| 12c `sc create` output, bridge IP, both A records public, `cert-state` installed, `sc ls` CERT ok, `sc project status` NOT AFTER `2026-12-12T08:44:09Z`, `openssl` SANs `*.web…` + `web…` from `(STAGING) Baloney Bulgur YE2`, wildcard vhost | PASS |
| 12f guards (unset-domain / zone remove refused) | PASS |
| cleanup: `sc delete` → **both A records gone** (reconciler `deleted 2 stale A record(s)` 11 s after the refusals) → project delete releases the claim → zone removable | PASS |

Appliance timeline: 09:42:06 cert requested (202) → 09:42:09 `set 2 A record(s)` → 09:42:47 staging certificate issued → 09:42:50 **installed on the machine (44 s from `sc create`)** → 09:43:04 stale records GC'd after the delete → 09:43:26 project deleted (claim released) → 09:43:27 zone removed.

End state (verified 09:44 UTC): 0 records under `e2e.sc.tc42.uk` at Cloudflare; no zone registered; projects left on `big`: `tc-infra`, `tc-broker`, `tc-thieso2`, `tc-thieso2-default` (the install + the enrolled tenant, no machines); retained `machine_certificates` rows for the four run hostnames (by design, dropped at expiry).

## 6. Findings

| # | Kind | Summary | Fix |
|---|---|---|---|
| F1 | product | Zone registry resolved the Cloudflare zone by exact name; a Public DNS Zone *inside* a Cloudflare zone (`e2e.sc.tc42.uk` in `tc42.uk`) was rejected. | `587928b` — containing-zone resolution (longest match, paged), `cloudflare_zone` column + migration, libdns names relative to the Cloudflare zone. |
| F2 | harness | Bad-token probe used a name under the just-registered zone; the nesting check refused it before Cloudflare was asked. | `e5cb0da` — probe uses a sibling name (`bad-<id>.${ZONE#*.}`); doc PASS text updated. |
| F3 | product | After the last zone-mode machine in a zone was deleted, its A records were never GC'd (empty-fleet early return + zones derived from live machines). | `e5cb0da` — reconcile every zone with a claim, drop the empty-fleet guard except for never-issued-row GC. |
| F4 | cosmetic | `sandcastle-admin version` inside the appliance warns it cannot tell which Incus remote hosts install "local". | open — follow-up. |
| F5 | protocol | The client needs a **reusable** Tailscale auth key: a single-use key is consumed by the client and the sidecar's join then fails with "API key … not valid". | documented in `.env.e2e.sample` + `docs/e2e-sc2.md` prerequisites (see below). |

## 7. Teardown (not performed — left for re-runs)

```
# client
incus delete big:e2e-pdz-client --project default --force
# install "tc" (auth-app, broker, tenant thieso2, bridge)
SANDCASTLE_REMOTE=big sc-adm tenant delete thieso2 --prefix tc          # or delete projects tc-thieso2*, tc-broker, tc-infra + network tc-net
# edge + DNS
incus exec big:sc-edge --project infrastructure -- sh -c 'cp /etc/caddy/Caddyfile.bak.pre-tc42 /etc/caddy/Caddyfile && systemctl reload caddy'
# Cloudflare: delete A sc.tc42.uk (tc42.uk zone)
```

## Appendix — logs

On the devbox: `/tmp/pdz-e2e/logs/01-install.log`, `02-client-build.log`, `03-edge-vhost.log`, `04-client-tailnet.log`, `07-rollout-587928b.log`, `08-rollout-e5cb0da.log`. In the client container: `/root/05-login.log`, `/root/05-login-2.log`, `/root/06-phase12*.log` (runs 1–4).

---

# Part 2 — explicit Machine Public Hostnames (ADR-0028), same day

| | |
|---|---|
| Branch / binary | `feat/machine-hostnames` @ `ce03163` (slices 1–4 of #172), `make build` → `0.0.0-dev` |
| Install | the same `tc` install; appliance binary replaced (`c484ffe` build) + `sandcastle-auth-app` restarted (`auth database migrated in 5ms`); client binary replaced; `sc payload-sync` reported the default project `current` at the new payload hash |
| Script | `scripts/e2e-pdz.sh` with 12g (explicit hostnames) between 12c and 12f |

## Run mph1 (12:5x UTC, run id `e2e-mph1`)

**FAIL at 12c (12:58:59 UTC)** — `sc create` printed no `DNS:` line. Cause: **operator error, not product** — the client still ran the previous binary (sha `240203c8…` vs build `3158f543…`); the in-place `incus file push` over the running binary had not taken. Re-pushed via `sandcastle.new` + `mv`, hash verified equal, `sc create --help` shows `--hostname`. Cleanup trap left nothing behind (no `zp-mph1`, no zone).

## Run mph2 (13:0x UTC, run id `e2e-mph2`)

12a, 12b PASS; 12c: `DNS: web.zp-mph2.tcpdz` **and** `Public name: web.e2e-mph2.e2e.sc.tc42.uk` printed (PASS), bridge IP, both A records public (PASS) — then **FAIL: timed out after 600 s waiting for CERT installed**. Appliance journal: certificate issued 13:00:31, never `installed`, no error, no gate log line.

Reproduction (`dbg` project, machine `m1`, 13:17 UTC), inspected inside the machine after 75 s: `sc ls` → `certState: issued`; `/etc/sandcastle/hostnames` seeded correctly; private leaf at `/etc/sandcastle/tls/`; Caddy active (private block only); **no `/etc/sandcastle/caddy.ready`**; `/var/log/cloud-init-output.log`:

```
/usr/local/sbin/sandcastle-caddy-setup: 83: /.sc/platform/sbin/caddy-setup: Syntax error: redirection unexpected
```

Finding **F6 — the payload's caddy-setup is executed by the boot shim with `sh` (dash), and slice 2 introduced bash-only syntax** (`done < <(…)`). The script aborts after the leaf fetch: no public site blocks, no marker → the reconciler's push gate (`markerReady`) sees no marker and returns false **silently** (**F7**), so the issued certificate is never installed. The bash-executed golden tests could not catch it. Also seen at the failed run's cleanup: **F8** — the zone pass errored with `delete 2 stale A record(s): HTTP 404 Record does not exist` when records had already been removed by the project-delete hook. Side note: profile renders `PUBLIC_HOSTNAMES=<name>,` with a trailing comma (harmless, normalized away).

Fixes on the branch before run mph3 (commit noted below): POSIX-sh payload scripts + goldens executed with `sh`, marker-missing log line, 404-tolerant stale-record delete. Reproduction torn down (`dbg` deleted, zone removed).

Fix: commit `b9e903f` — POSIX-sh payload scripts (goldens now run under `sh`/dash + a static bashism check), marker-missing log line, 404-tolerant stale-record delete. Rollout 13:24:35 UTC (hashes verified on appliance + client; `sc payload-sync`: `synced sc-payload-4f4a44c8… -> sc-payload-0c546be7…`).

## Run mph3 (13:24:39 UTC, run id `e2e-mph3`)

12a, 12b PASS. **12c PASS in full under the new contract**: `DNS:` + `Public name:` lines, A records, `cert-state installed`, `sc ls` CERT ok, NOT AFTER `2026-12-12T12:26:52Z`, `openssl` SANs `*.web…` + `web…` from `(STAGING) Artificial Amaranth YE1`, wildcard vhost — i.e. F6/F7 are fixed (the marker now gates the push correctly and the certificate landed within ~2 min of create).

**FAIL at 12g**: `sc create zp-mph3:api --hostname api-mph3.e2e.sc.tc42.uk` → `machine hostname "api-mph3.e2e.sc.tc42.uk" is reserved by this install` (API 409).

Finding **F9 — inconsistent install-reservation rule.** `scanMachineHostnameConflicts` refuses a hostname that is *inside* the Auth Hostname / route base subtree (`HasSuffix(h, "."+reserved)`), whereas `scanProjectDomainConflicts` refuses only the reserved name itself or an ancestor of it. The test zone `e2e.sc.tc42.uk` lives under the Auth Hostname `sc.tc42.uk`, so 12b's domain claim passed and 12g's hostname claim failed on the same shape. Rule aligned to the project-domain one (exact / ancestor only): a name below the Auth Hostname is only a problem if it collides with an actual Public Route, which the route reservation checks already cover. Cleanup trap left nothing behind.

Fix: `d15a4f0` (+ test follow-up `83f04a6`) — hostnames below the Auth Hostname / route base are claimable; equal/ancestor still refused. Rolled out with hash checks (13:3x UTC).

## Run mph4 (run id `e2e-mph4`)

**ALL PASS** (13:28:15 → 13:31:42 UTC, 3 min 27 s wall clock; 4 staging certificates).

| Step | Result |
|---|---|
| 12a zone registry, 12b project domain | PASS |
| 12c machine `web` (derived name): `DNS:` + `Public name:`, A records, cert installed, `sc ls` CERT ok, both SANs from the staging issuer, wildcard vhost | PASS |
| 12g `sc create zp-mph4:api --hostname api-mph4.e2e.sc.tc42.uk` (apex-level): `DNS:` line + one `Public name:` per name (explicit + derived); `sc ls` `api-mph4… (+1)`; `sc hostname list` shows explicit + derived | PASS |
| 12g A records for both names; `cert-state installed` for both; `openssl` SNI `api-mph4…` → its SANs from staging; SNI `api.zp-mph4.tcpdz` → **tenant-CA leaf still served** | PASS |
| 12g `sc hostname add zp-mph4:api alt-mph4…` on the running machine: three names listed; A records; cert installed; SNI `alt-…` → **its own** staging cert; SNI `api-mph4…` → **unchanged serial** (one certificate per hostname) | PASS |
| 12g refusals (inside a Project Domain; hostname held by a machine, both directions; project domain over a hostname; zone apex; removing the derived name) and "dry-runs changed nothing" | PASS ×6 |
| 12g `sc hostname remove … alt-…`: list/ls/status drop it, A records gone, SNI no longer served, `api-mph4…` serial unchanged; taken-name `sc create --hostname --dry-run` refused | PASS |
| 12f: `unset-domain --dry-run` allowed with machines (ADR-0028), zone remove refused while claimed | PASS |
| cleanup: `api` records gone (4 stale deleted), `web` records gone (2), claim released, zone removed | PASS |

Timeline: web cert 13:28:26 requested → 13:29:06 installed (**40 s**); api derived 13:29:14 → 13:29:46 installed; api explicit 13:29:54 issued → 13:30:03 installed; alt (added at 13:30:08 on a running machine) → 13:30:48 installed (**40 s from `sc hostname add` to served**); remove 13:30:51 → records GC'd 13:31:11/13:31:27.

One journal ERROR at 13:28:24, transient and self-healed on the next pass (**F10**, minor): `"auth-app zone reconcile: mirror certificate state on tc-thieso2-zp-mph4/web: wait for instance web config update: Failed to create instance update operation: Instance is busy running a 'start' operation"`

End state (13:33 UTC): 0 records under `e2e.sc.tc42.uk`, no zone registered, projects `tc-infra tc-broker tc-thieso2 tc-thieso2-default`.

## Findings, Part 2

| # | Kind | Summary | Fix |
|---|---|---|---|
| F6 | product (blocker) | Payload `caddy-setup` is run by dash; slice 2 used a bash-only construct → no public site blocks, no marker, certificate never installed. | `b9e903f` — POSIX-sh payload scripts; goldens run under `sh`; static bashism check + `dash -n`. |
| F7 | product | Missing marker skipped the push silently. | `b9e903f` — logged once per machine/hostname. |
| F8 | product | Zone pass failed on a 404 deleting records another path had already removed. | `b9e903f` — 404/"does not exist" tolerated. |
| F9 | product | Hostnames refused any name *below* the Auth Hostname / route base; Project Domains did not. | `d15a4f0` — same equal/ancestor rule for both. |
| F10 | product (minor) | Transient "wait for instance config update" error mirroring cert-state right after create; self-heals next pass. | open — consider treating as retryable without logging at ERROR. |
| — | operator | A stale client binary produced the mph1 false start; verify hashes after every push (`.new` + `mv`). | protocol practice. |
