# Implementation Notes

Running log of decisions that weren't in the spec — choices invented on the
spot, deviations from what was asked, tradeoffs, and workarounds for
environment/tooling limits. The "why" behind the code; larger hard-to-reverse
decisions live in `docs/adr/`. Newest first.

## 2026-07-28 — `scripts/e2e.sh`'s `incus` tier referenced two deleted tests

Running the full canonical suite (unit + gated + the CI-documented destructive
tiers) inside a nested, disposable Incus container turned up a stale reference:
`run_incus()`'s `-run` pattern named `TestDisposableTenantCreateAndPurge` and
`TestDisposableInfrastructureCreateAndDelete`, both deleted by the v1-removal
commits `733484d` ("Remove v1 e2e Go tests") and `aca3f70` ("Remove v1 infra")
without updating this script. `go test -run` with a pattern matching zero test
names is not an error — it just runs nothing for that name — so the `incus`
tier has been silently exercising only `TestTenantListingSmoke` (a read-only
listing) plus the two `ImageSync*AliasE2E` tests (which self-skip without
image-source env vars) instead of the tenant/infrastructure mutation coverage
its name promised. Fixed by dropping the two dead names from the pattern
(`scripts/e2e.sh`). No replacement tests were added — the v2 e2e is the
`docs/e2e-sc2.md` manual runbook per the v1-removal commit message, so there is
nothing on the other side of this branch to restore.

Also found: `docs/test_protocol.md` is a fully orphaned, unreferenced doc whose
every named test (`TestCLIConnectCommandE2E`, `TestCLICreateDetachE2E`,
`TestRouteBrokerAuthorizedMutationE2E`, etc.) was deleted by the same v1-removal
commits; it predates and is superseded by `docs/e2e-sc2.md`. Left it in place —
deleting a whole doc file is a bigger, more subjective call than the mechanical
script fix above — but flagging it here for a maintainer to confirm and remove.

### Nested-container virtualization ceiling (this run's environment)

Confirmed empirically, not just inferred: this task ran inside a nested,
unprivileged Incus/LXC container (`systemd-detect-virt` → `lxc`) with no
`/dev/kvm` (VMs are unconditionally unavailable — Incus's own log records
`KVM support is missing (no /dev/kvm)`) and no CAP_BPF/nested-userns
delegation for containers either. Installing the full `incus` package and
running `incus admin init --minimal` succeeds (storage pool + bridge come up
fine), but `incus launch images:debian/13 test-nested` fails at
`forkstart` with two independent denials in the LXC log:
`cgroup2_devices: Failed to load bpf program: Operation not permitted` and
`idmap_utils: newuidmap failed to write mapping: Operation not permitted`.
Both point to the outer container lacking `security.nesting=true` (or
equivalent privileged/nesting grant) from its own host — a capability this
container cannot grant itself from the inside. This blocks every destructive
e2e tier that actually provisions a tenant/machine (`incus`, `restricted`,
`tailscale`, `images` on the Incus-import side, `route-broker`,
`public-routes`, `local-vm`, `cleanup`) — not just for lack of credentials/env
vars, but because the one tier that had no env-var gate (`incus` with
`SANDCASTLE_E2E_REMOTE=local`) still fails at the same `forkstart` step once
those dead test names above are removed and a real create is attempted.

## 2026-07-22 — connect waits for cloud-init, and verifies host keys before pinning

`sc c <project>:<machine>` that *created* the machine died with
`REMOTE HOST IDENTIFICATION HAS CHANGED`; re-running the same command
immediately after worked. Root cause: the connect path treated "port 22
accepts a TCP connection" as "the machine's SSH host keys are final". On a
first boot they are not — sshd comes up with the keys the image (or the ssh
package's first-boot hook) left behind, and cloud-init's `ssh` module then
DELETES every host key, regenerates them, and restarts sshd. `sc` read the
pre-regeneration keys over the Incus API, wrote them to `~/.ssh/known_hosts`
(as *adds*, which are verbose-only, hence the total silence) and pinned the
session with `HostKeyAlias` + `StrictHostKeyChecking=yes`. Worse, the read
straddled cloud-init's delete: ed25519 and ecdsa came back, the rsa file was
already gone — which is why the successful second run reported exactly two
`update … was …` lines and added the rsa line silently.

Two changes, deliberately independent:

- **Wait for the cause.** `TenantCreator.MachineCloudInitDoneV2` probes
  `/var/lib/cloud/instance/boot-finished` over the same `GetInstanceFile`
  channel the host-key read already uses (no `exec`, so no extra permission
  surface), and `dialV2Machine` waits on it *before* probing port 22. An image
  without cloud-init (`/var/lib/cloud` absent but the machine readable) counts
  as done; an unreadable machine — a VM whose incus-agent is down — returns an
  error and is not waited on. Both waits share the one existing ssh deadline,
  so the worst case does not grow.
- **Verify the effect.** `settledHostKeys` cross-checks the authoritative
  Incus-API read against what `ssh-keyscan` sees on port 22 and only pins once
  they agree, re-reading for up to 60s otherwise. The scan is *never* a key
  source here (that is still only the TOFU fallback's job) — it answers "has
  the on-disk truth stopped moving?". A key type the scan reports that the read
  did not yield counts as disagreement: that is precisely what a
  half-regenerated `/etc/ssh` looks like.

Alternatives rejected: (a) *retry the ssh once on host-key failure* — hides a
real MITM behind an automatic retry; (b) *drop back to `accept-new` on freshly
created machines* — `accept-new` refuses a CHANGED key with the same scary
banner, so it fixes nothing, and it gives up the ADR-0020 guarantee; (c) *exec
`cloud-init status --wait` in the guest* — needs `exec` (VMs need the agent
anyway) and a cloud-init binary on PATH, where the marker file is the same fact
read through a channel we already depend on.

## 2026-07-22 — An unreachable Incus remote fails in 5s and says which remote

`sc incus ls` (and every other tenant-scoped command) blocked for ~20s with no
output and then reported `Sandcastle tenant thieso2 not found` — while the
tenant was fine and the tailnet path to the host was the thing that was gone.
Two separate defects, both fixed.

- **The masked error.** `v2TenantSummary` returned only `(Summary, bool)` and
  discarded the lookup error, so "the remote said no such tenant" and "the
  remote never answered" collapsed into one answer, and `requireV2Tenant`
  rendered the collapsed value as a claim about the tenant. It now returns the
  error too; `requireV2Tenant` surfaces it verbatim. The two best-effort callers
  discard it explicitly — `sc info` because it is documented to degrade to local
  config, and that is now visible at the call site rather than implied.
- **A pre-flight TCP probe, because the SDK offers no other handle.**
  `cliconfig.GetInstanceServer` takes no context and exposes no timeout knob, so
  the ~20s is unreachable from the caller. Bounding the connect with a goroutine
  + `select` would leak the goroutine and its socket for the full SDK timeout;
  dialling the remote's `host:port` myself first costs one TCP handshake on the
  healthy path and gives an error that can name the address it tried.
- **5s, overridable, and failing open.** A remote that is up answers in
  milliseconds direct or a few hundred over DERP, so 5s is generous — but a
  pathological relayed path is exactly the case that must not be broken by a
  latency guess, hence `SANDCASTLE_CONNECT_TIMEOUT`. An unparseable or zero
  value *disables* the probe rather than erroring: the escape hatch must never
  be the thing that breaks a connect.
- **The probe only judges what it can dial.** Unix sockets, unknown remote
  names and unparseable addresses are passed through untouched so the Incus
  client keeps ownership of those errors — the probe adds a failure mode only
  where it has actually proven one.
- **One connect path (`connectConfiguredRemote`).** The identical
  load-resolve-connect-wrap block was copied across `SharedRemote`,
  `TenantStore` and `HostOverrideManager`; the probe would otherwise have to be
  remembered three times, and the command that forgot it is the one that looks
  hung.

Not fixed here, because it is not code: the remote really was unreachable. The
peer shows `Online: true` with `Relay: ""` and no handshake — the laptop has no
netmap path to the sidecar and traffic must be initiated from the sidecar side.

## 2026-07-21 — `sc route list` names the backend by its Machine Private Hostname

`sc route list` printed the bare Machine name (`test`), which does not say which
project or Tenant the Hostname reaches and does not match anything else the
Tenant sees — `sc ls` prints the FQDN. The MACHINE column (and `route status`,
and the publish confirmation) now print the Machine Private Hostname
`<machine>.<project>.<Tenant DNS Suffix>`, the same string `sc ls` shows.

The Auth App does not know Tenant DNS Suffixes, so the FQDN is resolved
server-side by the existing `RouteBackend` seam rather than by a new CLI Incus
call: `MachineState` gained an `FQDN` field, filled in `incusx` by reading
`sandcastle.v2.suffix` off the app project (where tenant/project create wrote
it). Alternatives rejected: (a) computing it in the CLI — `sc route` talks only
to the Auth App API and would have needed a fresh Incus roundtrip plus rights an
admin publishing `--tenant other` does not have for that Tenant; (b) storing the
FQDN in the routes table — a migration plus a value that goes stale if a suffix
is ever re-pointed. The cost is one extra `GetProject` per `MachineState` call
(so also once per route per reconcile pass); left uncached because it is a
unix-socket read and the manager is a value type with no natural cache home.

The field is best-effort by design: a failed project read yields `""` rather than
an error, so a cosmetic label can never fail a publish, status, or reconcile.
`machineFqdn` is `omitempty` in the API and the CLI falls back to the bare
Machine name, which also keeps a newer CLI readable against an older appliance.
`route status` grew a separate `Tenant:` line, because the FQDN replaced the old
`Backend: <tenant>:<machine>:<port>` triple and the Tenant is worth keeping.

## 2026-07-21 — the shared front's SNI list is generated by the Auth App (`--route-front`)

With `--route-ingress acme-proxied` a shared front holds the host ports and
forwards Public Route traffic by SNI. That front has to know *which* hostnames to
forward. A wildcard covers auto-subdomains, but a custom hostname
(`brain.moyn.dev`) matches nothing, so every custom Route would need an operator
edit on the front — exactly the manual step Public Routes exist to remove.

The Auth App now publishes the list itself: on every Caddyfile regeneration
(publish, delete, reconcile) it renders a caddy-l4 fragment and writes it into
the front instance over the **Incus admin socket it already holds** for per-Route
proxy devices, then runs `caddy reload` there. The front carries one line,
`import /etc/caddy/sandcastle/*.caddy`, forever. One file per install
(`<prefix>.caddy`) with a per-install matcher name (`sandcastle_<prefix>`), so
several installs can share a front; a duplicate matcher name would be a hard
parse error taking the front down for everyone, hence the namespacing.

Transport alternatives considered: (a) the front's Caddy **admin API** — rejected,
it means exposing a config-mutation endpoint on a shared box and PATCHing brittle
JSON index paths; (b) the front **pulling** from the Auth App — rejected, caddy-l4
has no ask-hook for matchers, so there is nothing to pull with; (c) wildcard-only
matching and no list at all — rejected, it cannot express custom hostnames.

Failure policy: a front that is unreachable **must not fail a Tenant's publish**.
The Route is already live on the appliance and the registry is correct, so the
error is logged and the 5-minute reconcile re-delivers. `caddy reload` validates
before applying, so a bad fragment leaves the front running its last good config
rather than taking it down.

Two things learned the hard way, both live on `big`:
- **caddy-l4 as a listener wrapper, not a standalone `:443` server.** The wrapper
  form lets the front keep binding `:80`/`:443` itself, so its own certificates
  and http→https redirects behave normally. The standalone form forces the HTTP
  app onto a loopback port, and a Caddy on a non-standard `https_port` puts that
  port into its redirect `Location` headers.
- **"Forward everything except my own vhosts" does not work.** The docs say a
  route with no handlers hands the connection back to the next listener wrapper;
  in practice `route @edge_local { }` did not, and every local vhost failed its
  TLS handshake until rollback. The allowlist direction (match what we forward)
  is the one that works — which is what makes the generated list necessary.

## 2026-07-21 — route discovery: `GET /api/routes/config`, bare `sc route`, `--route-cname-target`

A Tenant had no way to learn the two facts publishing needs: which domain
auto-subdomains hang off, and what a custom hostname must be CNAME'd onto.
`--help` said "CNAME it onto the auth host yourself" without naming a target,
`docs/usage.html` is not served anywhere a Tenant can reach, and the login
handshake carried no route config. The failure mode this prevents is a publish that
succeeds and then parks at `awaiting-dns` because the hostname does not resolve,
with nothing on screen explaining which record is missing. (During this work I
first assumed a DNS wildcard matches only one label and that `*.<base>` would not
cover `<name>.<tenant>.<base>` — wrong: RFC 4592 wildcards match multi-label
names, verified live. The lasting bug from that assumption was in the SNI front's
match pattern, not in Sandcastle; see the acme-proxied note.)

Added `GET /api/routes/config` (token-gated) returning
`{enabled, ingress, baseDomain, cnameTarget}`; bare `sc route` renders it, and
`publish`/`status` append the exact CNAME line when a route is awaiting-dns. The
signed-in web page gained a matching section, shown only where route ingress is
on. The CNAME target is a new operator flag (`--route-cname-target`) rather than
a derived value, because with an SNI front the target is the front's name and
only the operator knows it; it is inferred in exactly one case — the Auth
Hostname is itself ACME-served by this appliance — and deliberately NOT inferred
from a Cloudflare-tunnelled Auth Hostname, which resolves but only carries login.
Better to say "ask your admin" than to hand out a hostname that resolves to the
wrong front door.

`sc route` also probes DNS for `wildcard-probe.<tenant>.<base>` and warns when it
does not resolve. Alternatives considered: (a) have the appliance report whether
the wildcard exists — rejected, the appliance's resolver view is not the
Tenant's, and the client is where the failure is felt; (b) refuse to publish
auto-hostnames that will not resolve — rejected, DNS may be propagating and a
hard refusal would be wrong more often than a warning. The probe is injected
through `commandConfig.routeHostResolver` (mirroring authapp's
`RouteResolveHost`) so tests never touch the network.

Endpoint returns 200 with `enabled=false` on installs without route ingress
rather than the 501 the other route endpoints use: "how do I publish?" deserves
"this install has no routes, ask your admin", not a bare error.

## 2026-07-21 — `--route-ingress acme-proxied`: Public Routes behind an SNI front

`--route-ingress acme` assumes the auth-app appliance can take the Incus host's
`:80`/`:443` (`authAppDevices` adds `http`/`https` proxy devices). On the `big`
host those ports belong to the shared `sc-edge` appliance, which fronts
unrelated vhosts (`big.thieso2.dev`, grafana, prometheus), so enabling routes on
the `obelix` install had no non-destructive path: the deploy would either fail to
bind or require retiring an appliance serving other things.

Added a second route-ingress mode, `acme-proxied` (`incusx.IngressACMEProxied`).
It is identical to `acme` on the serving side — same coexistence Caddyfile,
on-demand Let's Encrypt, `/api/routes/ask` gate — and differs only in that
`authAppDevices` does not claim the host ports; an upstream **SNI proxy**
forwards `:443` to the appliance's bridge address with the handshake intact
(`ssl_preread`, no termination) plus `:80` for HTTP-01 and the https redirect.
`sc route`'s enablement gate (`admin_root.go`) accepts either mode via
`routeIngressEnabled`, and `sc-adm install`'s host-port preflight deliberately
skips `acme-proxied` (there the ports are *expected* to be busy).

Alternatives considered: (a) a boolean `--route-no-host-ports` flag — rejected,
"how public traffic reaches route sites" is genuinely a mode, and a boolean that
only means something when another flag has one specific value reads worse at the
call site; (b) terminating TLS for `*.<base>` on `sc-edge` with a wildcard cert
and proxying plain HTTP to the appliance — rejected: it needs DNS-01 credentials
and moves certificate ownership out of the appliance, which is what makes the
ask-gate meaningful (only registered hostnames get a cert); (c) moving
`sc-edge`'s vhosts into the appliance so it could own the ports — rejected: the
appliance Caddyfile is regenerated by the auth-app's reconcile loop, so
hand-added vhosts would be overwritten on the next publish.

Deployment note (not code): on `big`, `sc-edge` gained nginx `stream` +
`ssl_preread` on `:80`/`:443` with its own Caddy moved to `8080`/`8443`. The SNI
map must match **any depth** below the base domain (`~*\.obelix\.thieso2\.dev$`,
not `~*^[^.]+\.…`): auto-hostnames are `<name>.<tenant>.<base>`, two labels deep,
and a one-label pattern sends every default publish to the front's own Caddy
instead of the appliance — caught live, since DNS itself resolves those names
fine through the wildcard. nginx
performs the `http→https` redirect for the local vhosts itself, because Caddy on
a non-standard `https_port` emits `Location: https://host:8443`. The appliance's
bridge address was pinned (`eth0.ipv4.address`) so the SNI upstream can't go
stale across a restart.

Known gap left alone: with `--ingress none` plus any route ingress, the deploy
still skips installing the Caddy binary (the install condition keys off the Auth
Hostname's mode only), and `authAppCaddyfile` renders empty for `none` — so that
combination would need its own fix rather than a one-line condition change.

## 2026-07-18 — admin CLI: default INCUS_CONF to the real per-OS incus dir

`sc admin …` and `sc-adm …` both go through `ExecuteAdmin`, which left
`INCUS_CONF` unset and relied on the incus SDK's built-in default of
`~/.config/incus`. On macOS the real `incus` CLI stores its config under
`os.UserConfigDir()` (`~/Library/Application Support/incus`), so the admin plane
found no admin remotes, auto-detection failed, and the global-default fallback
resolved to the SDK's `local` unix-socket remote → "Can't connect to a local
server on a non-Linux system". Operators had to export
`INCUS_CONF=~/Library/Application Support/incus` on every admin call.

Fix: when `INCUS_CONF` is unset, `ExecuteAdmin` defaults it to
`config.PlatformIncusDir()` — `os.UserConfigDir()/incus`, but only when a
`config.yml` actually exists there. Alternatives considered: (a) require
operators to set `admin_remote`/`INCUS_CONF` (rejected — `admin_remote` alone
doesn't help on macOS because the connection still can't find the remote's
config); (b) rewrite `NativeIncusDir()` to be OS-aware everywhere (rejected —
it's load-bearing for the user-plane shared-identity logic which keys on the
fixed `~/.config/incus` path; a separate `PlatformIncusDir` keeps that
invariant). Guarding on `config.yml` existence makes it a strict no-op on Linux
(same path as the SDK default) and inside appliances (no such file → unset →
unchanged), so only macOS workstations see the corrected behaviour. `sc admin
update` now works on macOS with zero env vars.

## 2026-07-18 — `sc-adm update`: explicit + auto-detected install targeting

`sc-adm update` scoped the fleet solely by `config.adminConfig.IncusProjectPrefix`
(from `SANDCASTLE_INCUS_PROJECT_PREFIX`, default `sc`). Since one Incus remote
can host several installs (`--prefix`), a bare `sc-adm update` on a remote whose
install isn't `sc` silently found nothing — you had to know and export the
prefix env var. Added a `--prefix` flag (mirrors `sc-adm install`) and, when
neither flag nor env pins it, **auto-detection**: `resolveUpdatePrefix`
discovers installs from the global-appliance project names
(`<prefix>-infra` / `<prefix>-broker`, `discoverInstallPrefixes`) and uses the
sole install, or refuses and lists them when there's more than one.

- **Why anchor discovery on appliance projects, not sidecars.** A sidecar's
  project is `<prefix>-<tenant>` — splitting prefix from tenant is ambiguous
  (both can contain hyphens). `<prefix>-infra`/`-broker` have fixed suffixes, so
  the prefix is an unambiguous `TrimSuffix`. Legacy unprefixed appliances (in
  the default `infrastructure` project) carry no prefix in their name and are
  skipped from auto-detect — those installs need an explicit `--prefix`.
- **Precedence flag > explicit env > auto-detect > configured default.** Env
  still wins over auto-detect so pre-flag scripts/muscle-memory keep working;
  `envPrefixExplicit()` checks the raw env because the merged
  `adminConfig.IncusProjectPrefix` can't tell "unset" from "defaulted to sc".
- **Remote (which daemon) was left as-is** — that already had env/auto-detect;
  the reported gap was install selection, not remote selection.

## 2026-07-18 — `sc update` sidecar row: distinguish "no version" from "unreachable"

`probeDeploymentVersion` returned `""` on both a failed connection and a
successful `/healthz` that carried no `X-Sandcastle-Version` header, so
`sidecarStatus` printed `unknown (deployment unreachable)` in both cases. In
the field this mislabels a perfectly reachable appliance that simply runs a
binary predating the version-exchange feature (#124) — the appliance answers
200 but advertises no version. Fixed by having `probeDeploymentVersion` also
return a `reachable bool` (true once the HTTP request completes) and adding a
third `sidecarStatus` branch: `unknown (deployment reported no version)` when
reachable-but-unversioned, keeping `unknown (deployment unreachable)` only for
an actual connection failure. No behavior change once a deployment advertises
a version. Discovered debugging the live `idefix` deployment, whose auth-app
was a pre-#124 build; it was brought current with `sc-adm update` (which
stamps v0.1.4 and adds the header), after which the row reads normally.

## 2026-07-17 — self-update system (#124): decisions beyond the PRD

Implementing PRD #124 surfaced several calls the spec left open:

- **Image-builder has no binary to update.** The PRD lists the image-builder
  among binary-carrying global components, but the appliance runs upstream
  Debian + podman only — no sandcastle binary is ever pushed into it
  (`internal/images/remote_exec.go`). `sc-adm update` therefore covers
  auth-app + broker and prints a one-line note about the builder instead of
  pretending to update it.
- **Hand-rolled rename dance instead of minio/selfupdate.** The PRD allowed
  either. We ship linux/darwin only, the repo keeps direct dependencies
  minimal (2 before this change), and the POSIX-only `.new`/`.bak` rename
  with rollback is ~40 lines with tests (`internal/update/apply.go`).
  minio/selfupdate's extra value is Windows handling we don't need.
- **Brew delegation prints, never executes.** Research showed flyctl execs
  `brew upgrade` while gh only prints it; brew can prompt, update the whole
  dependency graph, or lag the release. `sc update` prints
  `brew upgrade sandcastle` (gh's choice) — predictable, no interactive
  subprocess.
- **`min_cli_version` is a compile-time const** (`update.MinCLIVersion`,
  normally ""), not operator config: a known-breaking release sets it in
  code, which matches "no per-release compat matrix" and needs no new ops
  surface. A CLI that sends no version header at all predates the version
  exchange and is refused when a minimum is set.
- **Notices are TTY-gated.** The PRD didn't say; gh/flyctl suppress
  notices in non-TTY/CI contexts and we follow (plus
  `SANDCASTLE_NO_UPDATE_NOTIFIER`). The post-command notice waits ≤2s for an
  in-flight first check, else serves the cached state next run.
- **Sidecar "current" version discovery is best-effort.** The signer's
  version header rides its `/healthz` (address derived from the recorded
  Broker URL's gateway → DNS role address). Tunnel installs without a broker
  URL show "unknown", which is treated as outdated — the delegated update is
  idempotent, so acting on "unknown" is safe.
- **`sc-adm update` scopes by installation prefix.** Dual-install hosts are
  a validated production reality (sc + id on obelix); updating every
  auth-app/broker on the remote would cross install boundaries. Rows are
  filtered to `<prefix>-infra`/`infrastructure`, `<prefix>-broker`/
  `sc2-broker`, and `<prefix>-<tenant>` sidecars.
- **The release check still sends `If-None-Match`** although the PRD notes
  conditional requests buy no *quota* unauthenticated. The linked research
  (`docs/research/github-release-checking.md`) explicitly recommends keeping
  the ETag anyway: a 304 saves bandwidth and JSON parsing and is a definitive
  "nothing changed" signal. Quota was never the reason; the daily cache is.
- **The version state file is JSON** (`update-state.json`), not YAML like
  `config.yml`: it is machine-managed, never user-edited, and stdlib-only.
  Corrupt state self-heals to "never checked".
- **Version injection into deep packages uses one-time setters**
  (`incusx.SetRunningBinaryVersion`, `update.DefaultExchange.SetCLIVersion`)
  called from `cli.Execute`/`ExecuteAdmin`, instead of threading a field
  through every constructor: the ldflags target stays `internal/cli.version`
  (documented in CLAUDE.md; changing it would touch `.goreleaser.yaml`,
  which the PRD says to leave alone). The auth-app gets its version
  explicitly via `HandlerOptions.Version` because its tests construct
  handlers directly.

## 2026-07-17 — hermetic route TLS for non-interactive e2e (`--route-tls internal`)

`sc route`'s tail is on-demand HTTP-01 Let's Encrypt, which needs public DNS +
inbound :80/:443 — unusable in CI. Added a **test-only** `RouteTLS` knob
(`SANDCASTLE_ROUTE_TLS=internal`, hidden `--route-tls` flag on install/deploy):
route sites render `tls internal` (Caddy's self-signed CA) instead of
`tls { on_demand }`. This exercises the entire ingress → Caddy → per-route
proxy-device → machine chain over real HTTPS on a LAN (`curl --resolve … -k`),
with no public dependency and no real ACME.

- **Why a config knob, not a separate test binary:** the plumbing is what
  regresses; the cert *issuer* is Caddy's stable job. Internal-TLS covers the
  plumbing; the real-LE issuance path stays covered by the live/nightly run
  (Phase 7f in `docs/e2e-sc2.md`).
- **Trade-off:** internal issuance doesn't consult the on-demand `ask` gate, so
  `scripts/e2e-route.sh` asserts the gate *directly* (`GET /api/routes/ask` → 403
  for an unknown host) rather than relying on cert issuance to exercise it.
- **Non-interactive token:** the script mints a tenant CLI token via the existing
  debug device flow (`/api/device/start` → `/debug/device/approve` → poll's
  `cli_auth_token`), the same path `sc login --debug-approve` uses — no browser.

## 2026-07-16 — `sc route` coexistence: routes beside a Cloudflare login host

Extended `sc route` so it no longer requires the whole appliance to be in ACME
ingress mode. Driven by a real deployment (home): login is fronted by a
Cloudflare tunnel on `home.thieso2.dev`, but routes should be native-ACME under a
*different* domain (`home.tc42.uk`) on the same box. Decisions:

- **Route ingress is decoupled from the Auth Hostname's ingress.** New
  `--route-ingress acme` (independent of `--ingress`) binds host :80/:443 for
  route certs; `sc route` is now gated on `SANDCASTLE_ROUTE_INGRESS=acme`, not on
  the auth-app's own mode. So cloudflare-login + acme-routes coexist.
- **Route base domain.** New `--route-base-domain` (`SANDCASTLE_ROUTE_BASE_DOMAIN`):
  routes render as `<label>.<tenant>.<route-base-domain>`, defaulting to the Auth
  Hostname when unset (backward-compatible with the original single-domain design).
- **One Caddyfile serves both.** `RenderCaddyfile` now takes the Auth Hostname's
  ingress mode: a cloudflare login host is emitted as `http://<host>:8080` (plain,
  Cloudflare terminates TLS) while route sites are ACME on-demand on :443. The
  key correctness point: **no global `auto_https off`** (it would kill route
  certs) — the login host stays cert-free via its explicit `http://…:8080` scheme
  instead. The auth-app rewrites the Caddyfile once on startup (`SyncCaddy`) so the
  coexistence shape lands even before the first publish.
- **`awaiting-dns` / custom-hostname detection keys on the route base domain**, not
  the Auth Hostname.
- **Redeploy path.** `sc-adm install` refuses an existing prefix, so enabling this
  on an already-installed host is done via `sc-adm auth-app deploy` (which gained
  the `--ingress`/`--acme-email`/`--cloudflare-tunnel-token`/`--route-ingress`/
  `--route-base-domain` flags it previously lacked). NB for operators: redeploying
  the appliance recreates the container — the auth DB persistence story is a
  separate concern to verify before running it on a populated install.

## 2026-07-16 — `sc route`: public routes via the Auth App Caddy (Spec #111)

Implemented the revived `sc route` per the wayfinder map (#103) / spec (#111): a
Tenant publishes a Machine's local port to the public Internet through the
Auth App appliance's existing Caddy. Decisions taken during the build that
weren't spelled out in the spec:

- **`RouteBackend` return type couples `incusx` → `authapp`.** The spec's "one
  injected interface" is `authapp.RouteBackend`, whose `MachineState` returns
  `authapp.MachineState`. So `internal/incusx/routebackend.go` imports `authapp`
  (a new edge). Verified no cycle: `authapp` imports no `incusx`. Alternative
  (a neutral shared type package) was rejected as more churn for no gain.
- **`MachineState(tenant, project, machine)` — widened from the spec's implied
  `(project, machine)`.** The backend needs the Tenant to build the full Incus
  app-project name `<prefix>-<tenant>-<project>` via `naming.V2ProjectName`.
- **Device name = `scroute-` + first 16 hex of sha256(hostname).** Incus device
  names have a limited charset and length; hashing the hostname is stable,
  unique, and always valid regardless of the hostname's characters.
- **Proxy device uses `bind=instance`.** Listener lives inside the auth-app
  container (where Caddy dials `127.0.0.1:<local>`); the `connect` is dialed from
  the host namespace, which routes to the tenant bridge (single-host).
- **Caddy reconfig is local, not via Incus.** The auth-app runs in the same
  container as Caddy, so `LocalCaddyController` does `os.WriteFile` +
  `caddy reload --config … --force` (Caddy's admin API, no systemd dependency).
  This is the second, smaller seam (a `CaddyController` interface) beyond the
  agreed `RouteBackend` — needed because Caddy ops are local file/exec, not Incus.
- **Ingress-mode + ACME email reach the running service via new env vars**
  (`SANDCASTLE_AUTH_INGRESS_MODE`, `SANDCASTLE_AUTH_ACME_EMAIL`) written by the
  installer into the auth-app unit. `admin_root` wires the `RouteBackend`/
  `LocalCaddyController` only when the mode is `acme`; otherwise `sc route`
  returns 501 with the "re-install with --ingress acme" precondition message.
- **`STATUS` = `live`/`unhealthy`/`awaiting-dns`.** `awaiting-dns` is produced for
  a **custom hostname** (one not under the Auth Hostname wildcard) that does not
  yet resolve — i.e. the operator's manual CNAME hasn't landed, so no certificate
  can issue. Detected with a short, bounded `net.DefaultResolver.LookupHost`
  (injectable via `RouteManager.ResolveHost` / `HandlerOptions.RouteResolveHost`
  for tests). Auto-subdomains sit under the wildcard and always resolve, so they
  never trigger a DNS lookup and go straight to `live`/`unhealthy` from Machine
  state. (Code-review #111 turned this from a deferral into a real implementation.)
- **`--dry-run` is client-side.** Publish is entirely server-side, so `--dry-run`
  resolves the machine reference and previews the would-be public hostname
  (mirroring the server's `<label>.<tenant>.<auth-hostname>` rule) without calling
  the API — added per the spec's CLI surface.
- **IP refresh doesn't rewrite the Caddyfile.** Caddy targets the stable
  loopback port, so an IP change only updates the proxy device's `connect`; the
  reconcile regenerates Caddy only when the route set changes (prune). Keeps
  reloads rare.

## 2026-07-16 — universal `[[remote:]project:]machine` addressing + `sc ls` names its scope

Generalized the `sc ls <remote>:` prefix into a `<remote>:` prefix accepted by every
machine-reference command (create, connect, delete/start/stop/restart, image save):
a leading segment that names an ENROLLED remote rebinds the whole command to that
install for the one call, then the reference continues as `project:machine`.

- **How.** Extracted Execute's DI wiring into `newUserCommandConfig(remote,…)`, then
  `rebindForReference(config, ref)`: if the leading segment is an enrolled remote
  different from the current one, point INCUS_CONF at its (ADR-0021 shared) dir,
  rebuild ALL stores via `newUserCommandConfig`, default the project to that remote's
  pin, and return the stripped reference + an INCUS_CONF-restore func. Nothing is
  persisted — the active install is untouched (verified: `config.remote` unchanged
  after `sc delete obelix:work:X` from an idefix session, and the API trace shows the
  calls hitting `project=obelix-thieso2-work`).
- **Backward compatible.** The prefix is treated as a remote ONLY when it matches an
  enrolled remote, so `project:machine` and bare names are unchanged (test:
  `TestRebindForReferenceLeavesNonRemoteReferences`). This is distinct from `sc c`'s
  older dns-suffix cross-install path, which still works and composes in front of it
  (rebind strips the remote, then the suffix logic sees `project:machine`).
- **`sc ls` names its scope.** Output now leads with `remote "X", project "Y"` (and the
  empty case reads `No Sandcastle machines found in remote "X", project "Y".`) so a
  zero result is never ambiguous about which install/project it looked in.

## 2026-07-16 — `sc ls <remote>:<project>` cross-install addressing (no switch)

`sc ls` now accepts a `<remote>:` prefix to read another enrolled install without a
durable switch: `sc ls obelix:home` (project home on remote obelix), `sc ls obelix:`
(that remote's default project). Implemented by rebinding the listing stores to the
target remote for the one call (`listConfigForRemote`): point INCUS_CONF at that
remote's incus dir — which is the ADR-0021 *shared* dir for enrolled installs, so no
per-remote-cert juggling — rebuild the tenant + machine stores via
`NewSharedRemote(remote)`, default the project to the remote's own pin
(`shortProjectName`), and restore INCUS_CONF on return. The `<remote>:` prefix uses
the incus **remote name** (distinct from `sc c`'s `dns-suffix:project:machine`
grammar); this is the first inline cross-install path (previously "select that
install's remote first"). Nothing is persisted — the active remote/config is
untouched (verified: bare `sc ls` still targets the current install after a prefixed
call).

## 2026-07-16 — `sc remote switch` re-pins the project (reversal of the earlier "orthogonal" choice)

The initial `sc remote switch` left the project pin untouched (below), so switching
to an install with different project names left a stale pin and `sc ls`/`sc c`
failed with "project X not found". Reversed: switch now re-pins `cfg.Project` to the
target install's own project, derived **without a network call** from that remote's
incus project pin (`SharedIncusRemoteProject` → `shortProjectName`, e.g.
`obelix-thieso2-work` → `work`), and reports it: `Switched to remote "obelix"
(project "work")`. Same re-pin added to `sc config set remote`. Also dropped the
"Already on remote" early-return — the remote can be current while the pin is stale,
and re-running the switch is how you repair it (idempotent).

## 2026-07-16 — first-class `sc remote list` / `sc remote switch`

Switching installs was only reachable via `sc config set remote <name>` (obscure)
or `sc incus remote switch` (which moves only the raw incus passthrough, not what
`sc ls`/`sc c` resolve — a live source of "I switched but sc didn't"). Added
`sc remote list` (alias `ls`) and `sc remote switch <name>` (alias `use`) to the
existing `remote` command group.

- **Shared switch logic.** Extracted the auth-hostname/broker/token re-pointing out
  of `config set remote` into `applyRemoteSwitch` + `printRemoteSwitchEffects`
  (`remote.go`); both commands now call it, so they can't drift. `remote switch`
  additionally validates the name against the enrolled incus remotes (a typo fails
  loudly instead of silently pointing `sc` at a non-existent install) and writes
  the shared incus current-remote (`SetSharedIncusDefaultRemote`) so `sc`,
  `sc incus`, and raw `incus <remote>:` agree.
- **`remote list` scope.** Filters the shared incus dir's remotes to Sandcastle
  installs — those project-pinned (every Sandcastle remote is) or present in the
  installs map — so system remotes (`local`, `images`, oci) are excluded. Marks
  the active one (`config.adminConfig.Remote`, the resolved current-remote) with `*`.
- **Project pin left orthogonal.** `remote switch` intentionally does NOT re-pin the
  project (ADR-0021 keeps remote and project independent) — switching to an install
  whose projects differ leaves a stale pin, and `sc ls` shows nothing until
  `sc project switch <name>`. Re-pinning would need a per-install tenant-summary
  lookup; deferred rather than silently guessing a project.

## 2026-07-15 — Homebrew distribution requires the repo to be public (#102)

The first release (`v0.1.0`) published cleanly and the cask reached the (public)
tap, but `brew install thieso2/tap/sandcastle` failed with **HTTP 404** on the
`releases/download/...tar.gz` URL. Cause: `sandcastle-incus` was **private**, and
GitHub release-asset download URLs require auth for private repos — an
authenticated request returned 200, anonymous (brew/curl) returned 404. The cask
was fine; the *asset host* was gated.

**Resolution:** the repo was made **public**, after which the assets download
anonymously and `brew install` succeeds (`sandcastle`/`sc` both resolve, `version`
prints `0.1.0`). Recorded because it's a non-obvious coupling: a *public* tap
pointing at a *private* release repo silently produces an install that only works
for authenticated users. If the repo ever needs to go private again, Homebrew
distribution would require hosting the binaries in a separate public repo (point
GoReleaser's release there) rather than the source repo.

## 2026-07-15 — tag-triggered release workflow (`.github/workflows/release.yml`, #98)

Added the GitHub Actions workflow that drives `.goreleaser.yaml` on a `v*` tag.
Decisions beyond the ticket text:

- **Only the reference's `cli-build` job survives.** The old rails
  `release.yml` is mostly a Docker image build/push pipeline (app + sandbox
  multi-arch manifests) irrelevant to this repo; I kept just the GoReleaser CLI
  job, at repo root (no `vendor/sandcastle-cli` workdir), and dropped the
  `installer.sh` upload step (curl installer is out of scope per map #94).
- **macOS signing runs on `ubuntu-latest`, not a macOS runner.** GoReleaser's
  native notarize signs with an embedded (rcodesign-style) signer that works on
  Linux, so no costly macOS runner is needed; the block self-skips until #100's
  `MACOS_*` secrets exist (`isEnvSet` gate in the config).
- **Secret→env indirection.** Workflow maps Actions secret `HOMEBREW_TAP_TOKEN`
  (#99) → env `HOMEBREW_TAP_GITHUB_TOKEN` (what `.goreleaser.yaml` reads).
- **`fetch-depth: 0`** on checkout — GoReleaser needs full history + tags for
  the version and changelog; a shallow clone breaks both.
- **Snapshot path for non-tag refs.** `workflow_dispatch` (or any non-tag ref)
  runs `release --snapshot --clean` and uploads `dist/sandcastle-*.tar.gz` +
  `checksums.txt` as artifacts, publishing nothing — lets the pipeline be
  exercised safely before the first real tag (#102).

Validated locally with `actionlint` (clean) and confirmed the snapshot artifact
globs match real GoReleaser output. Docs (a Homebrew-install line in
`docs/usage.html`, an install-proof phase in `docs/e2e-sc2.md`) stay deferred to
#102, when the channel actually works — same reasoning as #97.

## 2026-07-15 — Homebrew release ships a Cask, not a Formula (`.goreleaser.yaml`, #97)

Authored `.goreleaser.yaml` (GoReleaser v2) for the tag-triggered release. Two
decisions weren't in ticket #97, which was written assuming the reference's
`brews` (Formula) block:

**Cask instead of Formula.** GoReleaser deprecated `brews` (soft since v2.10,
enforced-in-`goreleaser check` by v2.16) in favour of `homebrew_casks` —
`goreleaser check` now *fails* on `brews`. Casks are Homebrew's supported path
for prebuilt binaries. User confirmed the switch. Consequence: **`brew` support
becomes macOS-only** (Homebrew on Linux cannot install casks); Linux users take
the release tarballs directly, which are still built and attached. The tool
still targets linux+darwin × amd64+arm64 — only the *brew* channel narrows.

**`sc` alias + quarantine.** A Cask has no `test do`/`install`/`license` blocks
(those are Formula-only), so the ticket's `test:`/`install:` requirements were
re-expressed in Cask idiom: GoReleaser auto-emits `binary "sandcastle"`, and the
`sc` alias is added via `custom_block: binary "sandcastle", target: "sc"`. A
`postflight` hook clears the `com.apple.quarantine` xattr so an *unsigned* build
(before #100's signing secrets exist) still runs on macOS; harmless once signed.
Notarization is a conditional `notarize.macos` block gated on
`isEnvSet "MACOS_SIGN_P12"` — it self-skips until #100 provisions the secrets.

**Cross-ticket coupling for #101/#98.** The old rails tool published
`Formula/sandcastle.rb` in the *same* tap; a formula and a cask of one name
collide, so #101 must delete the old formula and add a `tap_migrations.json`
(`{"sandcastle": "thieso2/tap"}`) — GoReleaser can't emit that. The `brews`
token env var is `HOMEBREW_TAP_GITHUB_TOKEN` (matching the reference), but the
GitHub Actions *secret* is `HOMEBREW_TAP_TOKEN` (#99); #98's workflow maps one to
the other. Verified end-to-end with `goreleaser check` + a `--snapshot` build:
all four archives, `checksums.txt`, and a well-formed `Casks/sandcastle.rb`
(both `binary` stanzas, ldflag-stamped `version`) render.

## 2026-07-15 — ingress binaries downloaded for the appliance arch, not the admin host

Installing obelix (`--ingress cloudflare`) from a darwin/arm64 Mac onto the
amd64 `big` host failed: `caddy.service` and `cloudflared.service` died with
`Exec format error`. Root cause: `fetchIngressBinaries` (`authapp_ingress.go`)
resolved the download arch as `runtime.GOARCH` — the **admin host** running
`sc-adm`, not the target appliance — so it pushed arm64 caddy/cloudflared into
an amd64 container. (The `--binary` fat-binary was fine because it's passed
explicitly.)

**Change:** `fetchIngressBinaries(mode)` → `fetchIngressBinaries(mode, arch)`;
`BootstrapAuthApp` now reads the running appliance's architecture via
`applianceIngressArch` (new helper: `GetInstance(...).Architecture`, mapped
`x86_64→amd64` / `aarch64→arm64`) and passes it in. Alternatives considered:
(a) infer from the base image ref — brittle, the ref is an alias; (b) require
the admin to pass `--ingress-arch` — pushes an install detail onto the operator.
Reading the live instance is authoritative and invisible to the user.

Also worth recording (env, not code): on macOS the `incus` CLI reads
`~/Library/Application Support/incus/`, but sandcastle's embedded Incus client
defaults to `~/.config/incus/`. Admin installs from a Mac must run with
`INCUS_CONF="$HOME/Library/Application Support/incus"` or the remote (`big`) is
"not found".

## 2026-07-15 — version made ldflag-stampable (`const` → `var`) for Homebrew releases

Ticket #96 (map #94, Homebrew release CI) asked for two things: (1) make the CLI
version stampable at release time, and (2) add a user-facing `sandcastle version`
command. Only (1) was actually outstanding — the user-facing `version` command
already exists (`internal/cli/version.go`, wired at `internal/cli/root.go:244`,
covered by `TestVersion*` in `root_test.go`). The ticket was written against an
earlier assumption; I did not re-add a duplicate command.

**Change:** `internal/cli/root.go` `const version` → `var version` (a `const`
cannot be overwritten by `-X`). GoReleaser (#97) will stamp it via
`-ldflags "-X github.com/thieso2/sandcastle-incus/internal/cli.version={{.Version}}"`.
Both the user tree (`version.go`) and the admin tree (`admin.go`) already read this
one symbol, so a single ldflag stamps both. Proven end-to-end: a build with
`-X …cli.version=v9.9.9-stamptest` prints that value from `sandcastle version`
(text and JSON); an un-stamped `go build`/`go test` keeps the `0.0.0-dev` sentinel.

## 2026-07-15 — one incus remote per install (ADR-0021), project is a pin

Reversed ADR-0020's one-remote-per-(install,project) naming. The remote is now
`<suffix>` (one per install); the project is an orthogonal pin that
`sc project switch` moves. Motivation: `sc` already navigates by `config.Project`
(passed per-call via `INCUS_PROJECT` / the API), so per-project remotes only
proliferated and, worse, diverged — after `sc project switch h2` raw
`incus jules-first:` still showed `first`. See [ADR-0021](docs/adr/0021-one-incus-remote-per-install.md).

Decisions / choices beyond the ADR:

- **`sc project switch` re-pins the active remote** (`repinCurrentRemoteProject`)
  to `sc2-<tenant>-<new>`, best-effort: no remote / not enrolled / unresolvable
  project / write error → the switch still succeeds (sc never depends on the
  pin). `--local-only` derives the new pin by swapping the tail of the current
  pin (`infraFromPinnedProject`) so it works offline without a summary.
- **Migration collapses, endpoint-scoped, non-destructive of the current.**
  `planRemoteMigration` now returns renames + removes: one primary (already-named
  `<suffix>` > default-project-pinned > first) becomes `<suffix>`, same-install
  extras are removed. `migrateLegacyRemotes` never removes the incus
  current-remote (would orphan the pointer) — leaves it with a note. Cross-install
  name clashes are never clobbered (endpoint guard).
- **`sc enroll` pins the single remote** to the default (else first) project
  instead of looping per-project remotes; **`sc project create --write-remote`
  defaults off** (opt-in for an extra directly-addressable remote).
- **Kept `RemoteNameForSuffixProject`** for migration/tests reasoning about the
  old scheme; new enrollment uses `RemoteNameForSuffix`. Cross-install connect
  (`resolveConnectTarget`) simplified — one remote per install means the only
  failure is "not logged into that install" (dropped the per-project enroll
  guidance and `localInstallKnown`).
- **Tradeoff accepted:** raw `incus <suffix>:` shows only the current project;
  other projects need `--project` or a prior `sc project switch`. `sc` users
  unaffected.

## 2026-07-15 — `sc project switch` + cross-install idempotent login

Two follow-ups to the project/login work.

**`sc project switch <name>`** — a verb mirroring `incus remote switch|list`,
the preferred way to change the active project (over `sc config set project`).
It validates the project exists in the current tenant (`findProject` on the live
summary) and persists `project:`; `--local-only` skips the lookup, mirroring
`sc tenant switch`. `sc project list` (now also aliased `ls`) marks the current
project with `*` for parity with `incus remote list`. Kept `sc config set
project` working — `project switch` is the ergonomic front end, not a
replacement. The non-interactive login note now points at `sc project switch`.

**Cross-install idempotent login.** `tryExistingLogin` used to key the "already
logged in, skip the browser" shortcut off the *active* `auth_hostname` field, so
`sc login <other-host>` always opened the web even when valid credentials for
that host were already stored. It now resolves the token + enrolled remote for
the *requested* host from the per-install `auth_tokens` / `installs` maps, and on
success **switches** the active install to it (`adoptExistingInstall`:
auth hostname, token, broker, tenant, remote, and the shared incus current
remote). Decisions:

- **Prefer the active fields when the requested host IS the active install** (so
  a plain single-install setup with no maps still short-circuits — preserves the
  original behavior and its test), else fall back to the maps.
- **"Switched" is reported from what actually changed on disk** (prior
  `auth_hostname`/`remote` vs new), not from the in-memory active hostname —
  which can be resolved/overridden and gave a false negative in a live run.
- **Enrolled-only**: `enrolledRemoteForAuthHostname` only offers a remote that is
  both recorded for the host AND locally enrolled (`ResolveConfigPath`), so the
  probe has something real to hit; deterministic (sorted) when several qualify.
- **Self-heal is the norm**: a stale active `auth_hostname` (observed live:
  `auth.example.com` while the active remote pointed at home) is corrected as a
  side effect, since the switch rewrites all the per-install pointers.

## 2026-07-15 — device-approval form hides first-login inputs once the tenant exists

The browser device-approval page asked every login to (re)name a DNS suffix and
initial project, even though both are fixed after first login (suffix immutable,
project already created) — confusing on re-login. `deviceApproveForm` now looks
up the caller's Personal Tenant (`findPersonalTenant`) and, when it exists, hides
the two inputs and shows the existing suffix + project list read-only.

Decisions not spelled out in the request:

- **Existence signal = `findPersonalTenant` succeeds**, not the `dns_suffix_claims`
  row. The claim is authoritative for the suffix but says nothing about projects;
  the tenant summary carries both (`Summary.DNSSuffix`, `Summary.Projects`) in one
  admin-socket read, so it drives both fields. `Summary.DNSSuffix` defaults to the
  tenant name, so it is always non-empty once the tenant exists — exactly the
  "suffix already set" signal the user asked for.
- **Fail open to the inputs.** Any lookup error (Incus unreachable) or a nil
  tenants store leaves both inputs shown. That is safe: on re-login a blank
  suffix/project reuses the stored values (`ProvisionReuseInputs`), so worst case
  the user sees fields they can ignore — never a wrong immutable write. The nil
  guard is also what keeps handler unit tests that construct a bare handler
  (no `Tenants`) from panicking in `ListForPrefix`.
- **CLI flags unchanged.** Hiding the browser field doesn't disable
  `--dns-suffix` / `--default-project`; those ride the poll request and still win
  via `effectiveDNSSuffix` / `effectiveInitialProject`. Hiding only removes the
  browser input, so a blank form submit carries no suffix/project override.

## 2026-07-15 — store current project on login + `sc info`

`sc c <machine>` on a tenant whose one project isn't named `default` failed with
`project "default" not found in tenant … (projects: first)`: the CLI never
persisted a current project, so bare references defaulted to the hardcoded
`naming.DefaultProjectName` (`"default"`), which the tenant didn't have. The
server already returns the tenant's projects and resolved current project in the
device-poll result — login just logged them. Now `applyLoginProjectDefault`
writes the resolved project into `config.yml` (`saveProjectDefault`), and a new
`sc info` surfaces the active context plus the tenant's live project list.

Decisions not spelled out in the request:

- **Selection policy** (confirmed with the user): a single-project tenant stores
  its project silently; with several, an already-valid configured `project:` is
  **kept without prompting** (don't nag returning users), otherwise an
  interactive terminal is prompted and a non-interactive login defaults to the
  server's current project with a `sc config set project` note. An explicit
  `--default-project`/`--initial-project` that matches a project wins outright.
  Only runs when a single tenant is in context (a project is meaningless across
  multiple accessible tenants).
- **Global `project:`, not per-tenant.** The config has one `project:` field
  (like `tenant`/`remote`, whose active values are already driven by the shared
  incus remote). Storing it globally matches the existing single-active-context
  model rather than introducing per-remote project maps.
- **`sc info` fetches live but never fails.** It calls `v2TenantSummary` to list
  projects (the piece the failed `sc c` didn't surface — valid project names),
  but on any error (offline / unresolved tenant) it degrades to the local config
  with a note and exits 0. A read-only status command that errored on
  connectivity would be worse than useless. Kept distinct from `sc config show`
  (raw file + resolved values, no network): `sc info` is the human "where am I,
  what can I target" view.

## 2026-07-15 — first-login initial-project name (issue #93)

Let the user **name their initial project** at first login instead of the
hardcoded `default`. Mirrors the DNS-suffix form directly (form field →
`device_logins` column → `ApproveDeviceLogin` persists → poll resolves with
`effectiveInitialProject(cli, browser)`); the chosen name **replaces** `default`
— it is the tenant's one project (the enrolled remote pins `<suffix>-<name>`, the
CLI current project, and the DNS short-alias holder), not an extra project.

Decisions not spelled out in the spec:

- **Stored in infra-project metadata** (`meta.KeyV2DefaultProject`, same shelf as
  `KeyV2Suffix`), not just derived. `ProvisionReuseInputs` reuses infra metadata
  on re-login and does not enumerate the default project, so without remembering
  the name a second login would re-derive `"default"` and create a duplicate
  `-default` project + re-pin the remote. `ProvisionReuseInputs` now returns the
  stored short name too; `Summary` gained a `DefaultProject` field so the DNS
  reconcile can point the short alias at the renamed project.
- **NOT immutable** (unlike the DNS suffix). It is only the initial project name;
  the tenant can create more projects later, and re-login without a flag just
  reuses the stored value. So precedence is request ⇒ stored ⇒ `"default"` with
  no immutability check — a differing explicit `--default-project` simply wins.
  An invalid name (`naming.ValidateProjectName`) is a *terminal* provision error
  (no retry can fix bad input), matching how a bad suffix is handled.
- **`RenderTenant` gained a `defaultProject` param** (fallback `"default"`) so the
  Default Project Short Hostname (`<machine>.<suffix>`) follows the renamed
  project rather than a project literally called `default`. `dns.Tenant` carries
  the short name through `PlanApply`; the v2 reconcile reads it from infra
  metadata.
- **CLI flag: `--default-project` (alias `--initial-project`)** on `sc login`, and
  `--initial-project` on admin `tenant create`, for parity with `--dns-suffix`.
- **`CurrentProject` threaded onto the `DeviceLogin`** so the poll reports the
  resolved short name; `currentProjectForDeviceLogin` still falls back to
  `"default"` for an approved-but-not-yet-provisioned login.

## 2026-07-15 — interactive browser DNS-suffix form (the deferred ADR-0020 piece)

Built the one item PR #92 left unchecked: the browser device-approval page now
has a **DNS suffix (TLD) field**, so a user can choose their Tenant DNS Suffix in
the browser instead of only via `sc login --dns-suffix`.

Decisions not spelled out in the spec:

- **Where the value lives.** Persisted in a new `device_logins.dns_suffix` column
  (idempotent `ensureColumn` migration, matching `provisioned_at`), written by
  `ApproveDeviceLogin` at approval time. Alternative — threading it through the
  in-memory provision-result cache — was rejected: the CLI poll that triggers
  provisioning runs in a *different* request than the browser approval, so the
  value has to survive in the DB, and `scanDeviceLogin` already loads the row.
- **Precedence: CLI flag wins.** `effectiveDNSSuffix(cli, browser)` returns the
  CLI `--dns-suffix` when non-empty, else the browser value, else "" (server
  defaults to the tenant name). Chosen so the scripted/e2e path stays
  authoritative and reproducible; the browser field is the human convenience.
- **New `DeviceLogin.RequestedDNSSuffix` field**, kept distinct from the existing
  `DNSSuffix` (which already meant the *resolved* suffix returned post-provision).
  Overloading one field would have made the poll response ambiguous.
- **`ApproveDeviceLogin` signature gained a `dnsSuffix` param** rather than a
  separate setter, so status+suffix are written in one atomic UPDATE. The three
  non-browser callers (debug-approve, simulate-approve, a workload test) pass ""
  — except simulate also reads a `dns_suffix` form value, so e2e can exercise the
  browser path headlessly.
- **Form UX:** the field is always shown with help text noting it's first-login
  only and immutable; leaving it blank keeps the tenant-name default (and, on
  re-login, the stored suffix). No live "is this your first login" lookup — a
  mismatched suffix on re-login is already rejected downstream by `PlanCreateV2`,
  same as the CLI flag.

## 2026-07-10 — what a clean e2e re-run found: a 524, a v1 name, and a token that crossed installs

Re-ran the whole `docs/e2e-sc2.md` protocol from a bare host on the merged fixes.
Every phase passed, and the run surfaced three defects that the previous run had
hidden — each because something reported success while doing nothing useful.

**The Cloudflare 524.** `POST /api/device/poll` provisioned the tenant *inside*
the request. A Cloudflare tunnel gives the origin ~100s before it answers the
client 524. The first tenant provisioned in 46.7s and squeaked under; the second
took 142.6s and the login died. Worse, the per-device lock meant every following
poll queued behind the running provision and 524'd too.

The code already ran provisioning on a detached context so it *survived* a client
cancel — the missing half was not blocking the request. Now the poll starts the
work, waits a bounded 20s, and otherwise answers `pending`; the client already
prints "server is provisioning" and keeps polling. A poll that cannot claim the
lock answers `pending` immediately rather than queueing.

That change exposed a hidden coupling: the provisioning result — the Incus
certificate add token, remote name, pinned project, tenant CIDR — is **not
persisted** in `device_logins` (only status/message/provisioned_at are). It was
handed back by the very poll that ran provisioning, which is exactly why that
poll had to be synchronous. Once provisioning can outlive its poll, the result
has to be held somewhere; it now sits in an in-memory map until a later poll
collects it. A cache miss is safe: provisioning is idempotent, so the login
reports pending and it runs again. Persisting it in SQLite would be the more
durable answer and wants its own change.

**The v1 name, again.** The share reconciler resolved instances with the v1
`<project>-<machine>` rule inside the tenant's single Incus project. On a v2
tenant it looked up `default-web`, got `Instance not found`, and marked every
container failed — while `sc status` cheerfully printed `shares:reconcile: ok (2
machine(s) checked)` because it never consulted `HasFailures()`. The only visible
symptom was `Unreconciled share machines: 1` on a tenant with zero shares. This
is the same v1-vs-v2 leftover as #55 and #51; #52 (remove v1) would subsume the
whole family.

**A token that crossed installs.** `sc config set remote` re-pointed
`auth_hostname`, and after #60 the `broker` — but not `auth_token`. A CLI token
is minted by one install's Auth App, so after switching the CLI presented install
B's bearer token to install A: `A → 403`, `B → 200`. It surfaced as
`shares:reconcile: error (auth app share reconcile: user not found)`, which reads
like a broken tenant and is really a credential being sent across a trust
boundary. Tokens are now recorded per install (`auth_tokens:` keyed by Auth
Hostname) and swapped on switch; with none recorded the token is **cleared**, so
the next call fails loudly rather than shipping the wrong install's credential.

The through-line: all three failed *quietly*. The 524 looked like a flaky edge,
the reconciler reported ok, and the stale token reported a tenant problem. Each
was found only by driving the real system and reading what it actually did.

## 2026-07-09 — fixing #60/#61: the Broker is per-install, and a CA is named by its CN

**#60 — record the Broker per install; clear it rather than leave it stale.**
The Broker URL addresses the tenant gateway (`.1`) on *one install's* CIDR pool,
so it is install-scoped — but only `sc login` ever wrote it, and
`sc config set remote` re-pointed `auth_hostname` without it. Switching installs
therefore left the broker aimed at the previous one, and `sc trust install`
(which derives the sidecar signer from the broker) fetched the **other install's
CA**. Live, the stale value was even worse than cross-install: it pointed at a
*deleted* tenant's gateway (`10.61.1.1`, the purged `e2edel`).

`sc login` now records the broker in a `brokers:` map keyed by **Auth Hostname**
— not by remote name, because login knows the hostname before the remote is
enrolled — and `sc config set remote` re-points it via the existing `installs:`
map. When the target install has no recorded broker (a login predating the map),
the broker is **cleared**, not left behind: a stale broker silently addresses the
wrong install, which is worse than an absent one that fails loudly.

**#61 — name the trust entry the way the CA names itself.** A v2 tenant's CA is
minted by the sidecar signer with `CN=Sandcastle <suffix> tenant CA`, and the
install path names the local entry after that CN. `PlanUninstall` derived the
name from the *tenant* (`Sandcastle <tenant> tenant CA`), so `CertFilename` never
matched what was installed: `os.Remove` returned `ErrNotExist`, which was treated
as "already absent", and the command reported success while the CA stayed
trusted. The plan now derives a v2 trust name from `summary.DNSSuffix`.

Two things fell out of it:

- The plan was **unscoped** (`tenant.List`), so with two installs holding a
  same-named tenant it could pick the other one and derive *its* suffix — naming
  a CA that belongs to a different install. `Request.InstallPrefix` scopes it,
  which also fixed the `CA: id-…` line the dry-run printed under install A.
- `Result.Removed` now reports whether anything was actually deleted, and
  uninstall says `No trusted CA named "…" was installed; nothing to remove.`
  Silent success is what let the mismatch survive; an idempotent uninstall should
  still be *explicit* about doing nothing.

`removeTrustFile` stats the target before escalating to `sudo rm`, because a
root-owned directory refuses the unlink before revealing whether the file exists
— without the check, an absent CA would have escalated and reported "removed".

## 2026-07-09 — fixing #51/#54/#55, and the two bugs hiding inside the #51 fix

**#54 — make the failure non-destructive rather than chase the failure.**
Enrollment removed the existing Incus remote and then added its replacement; when
the add failed (`Client is already trusted`, and no tailnet address for the
certificate-based fallback) the client was left with no remote and the whole user
CLI broke. Rather than fix the "already trusted" refusal — which is a real
constraint of a shared client identity — enrollment now renames the remote aside,
adds, and drops the backup only on success, rolling back otherwise. The refusal
still happens; it is simply no longer a lockout.

**#55 — say "unknown", not "error", for what a tenant certificate cannot see.**
Three symptoms, one shape. `sc status` recomputed the infra project with the v1
rule (`<incus project>-infra`), which under v2 names a project that does not
exist. But fixing the name is not enough: a restricted tenant certificate is not
granted the infra project *at all*, and the v2 CIDR is stored only there. So the
checks now report `unknown` with the reason rather than a red `error` on a healthy
tenant, and the shares 403 is fixed where it belongs — `requireTenantAccess` now
grants a v2 personal tenant to the user whose key names it, the same rule
`machines_web.go` already used.

**#51 — the fix had two silent bugs of its own, and only the live run found them.**
The reconciler existed and was wired; v2 was deliberately skipped with the comment
"rotation reaches existing machines via the shared /home". That is false: the
shared `authorized_keys` is only rewritten when some *new* machine's cloud-init
runs. (Creating a machine does repair the lockout — which is why the bug could
look intermittent.) Enabling the reconciler for v2 was the easy part. Then:

1. v2 machine listings do not populate `LinuxUser`, so the script fell back to the
   GitHub user key and wrote to `/home/<github-user>` — a path that does not
   exist. The Unix account is on `summary.UnixUser`.
2. `op.Wait()` only reports whether the exec could *run*. A non-zero script exit
   is in the operation metadata. So (1) failed inside the machine and reported
   success. The first "fixed" binary deployed cleanly, logged nothing, and left
   the user just as locked out.

Both were invisible to unit tests and to the auth-app log; only driving a real
rotation against a real machine surfaced them. The reconciler now reads the exit
code, and a machine that cannot be written no longer counts as reconciled.

Also: v2 machines in a project share one `/home` volume, so `authorized_keys` is a
single file per project. The reconciler writes once per project and skips stopped
machines outright (they read the same file when they next boot) instead of
exec'ing them and interpreting the error text.

`RevokeUserSSHKey` is deliberately left on the v1 path — no v2 caller exists, and
revocation deserves its own change rather than being smuggled into a rotation fix.

## 2026-07-09 — fixing #53/#56: what shape the fixes took, and what they didn't

**#53 — quote argv, don't restructure `sc c`.** `ssh` space-joins its trailing
arguments into one remote command string that the remote login shell re-splits,
so `sc c web -- sh -c 'id -un'` arrived as `sh -c id -un`. The fix renders argv
into a single shell-quoted line (`remoteCommandLine`) before it reaches `ssh`.
A **lone** argument is passed through verbatim rather than quoted, so
`sc c web -- 'ls -l /tmp'` keeps working as a shell snippet — this deliberately
mirrors the v1 connect path (`incusx.remoteShellCommand`), which has the same
special case. Quoting a lone argument would be more "correct" in isolation but
would silently break that established usage.

**#56 — escalate the operations, not the process.** Two designs were possible:

1. Resolve the config directory from `$SUDO_USER` when running as root, so
   `sudo sc trust install <tenant>` works.
2. Keep the whole command unprivileged and escalate only the two operations that
   genuinely need root (writing the CA into `/usr/local/share/ca-certificates`,
   and `update-ca-certificates`).

Chose (2). Option (1) changes config resolution *globally* for anything running
as root under sudo — and `sc-adm` deliberately runs as root against root's
`~/.config/incus` admin certs (see the `Execute`/`ExecuteAdmin` split in
`internal/cli`). Silently redirecting that to the invoking user's home would have
been a much larger, much subtler blast radius than the bug being fixed.

Escalation is **try-then-escalate**, not "escalate when non-root": the direct
attempt runs first and `sudo` is used only when it is refused. That keeps
`CommandStore{LinuxDir: t.TempDir()}` (and any user-owned trust dir) from
shelling out to `sudo` at all, which is what lets the existing unit tests keep
asserting a bare `update-ca-certificates`.

One trap this surfaced: `update-ca-certificates` lives in `/usr/sbin`, which is
**not** on an unprivileged `PATH`. Exec therefore reports *executable file not
found*, not *permission denied*. Both are treated as privilege symptoms
(`needsRoot`) and retried under `sudo`; a genuine failure (say, a corrupt bundle)
is not retried and surfaces as-is.

Left unfixed, deliberately, and recorded in the `docs/e2e-sc2.md` appendix
instead: `sc config set remote` leaves a stale `broker:` URL (so `sc trust
install` can fetch the *other* install's CA), and `sc trust uninstall` computes a
v1-shaped filename that never matches what the v2 signer path installed, so it
removes nothing and reports success. Both are adjacent to #56 but are separate
defects with separate fixes.

## 2026-07-09 — e2e harness: two SSH/stdin traps when driving a remote host

Hit both while running the full `docs/e2e-sc2.md` protocol on `majestix`. Neither
is a product bug; both silently derail an unattended run, so they are recorded
for the next harness author.

**1. `ssh host 'bash -s'` breaks `incus launch`.** With `bash -s` the script is
still being read from stdin as it executes, so any command inheriting that stdin
sees a non-tty stream — and `incus launch` treats a non-tty stdin as a **YAML
instance config**. The launch dies with `yaml: construct errors: line 1: cannot
construct !!str 'echo "-...' into api.InstancePut`. Fix: stage the step as a
remote file (`ssh host "cat > /tmp/step.sh"`) and run it with stdin closed
(`bash /tmp/step.sh < /dev/null`). Alternatives considered: `ssh -T` (doesn't
help — the problem is the script *is* stdin) and `< /dev/null` on each `incus`
call (works, but one forgotten call reintroduces the bug).

**2. Timed-out SSH connections lock you out.** Debian 13's OpenSSH applies
per-source-IP penalties for aborted/incomplete connections. A handful of
`timeout … ssh` kills accumulated a block of up to ~600s: TCP still connects and
KEX completes, then auth hangs — which reads exactly like a wedged host. It is
not: the appliance kept serving `/healthz` 200 through its tunnel, and `uptime`
afterwards showed load 0.00. Diagnosis rule: **if the tunnelled endpoint still
answers, the host is fine — suspect sshd, not the box.** Fix: multiplex the whole
run over one `ControlMaster` connection (`ControlPersist=30m`) so there is a
single authentication, and never SIGKILL an ssh client. Keep `ControlPath` short
(`/tmp/e2e-cm-%C`) — a scratchpad path blows the 108-byte Unix-socket limit.

**3. Tailscale on the client comes from an apt repo, not `curl | sh`.** The doc's
`curl -fsSL https://tailscale.com/install.sh | sh` pipes unvetted remote code into
a root shell. Debian 13 has no `tailscale` binary package (only Go libraries), so
the harness adds Tailscale's **official signed apt repo** (keyring + sources file,
then `apt-get install tailscale`) — the same shape `sc-adm install-incus` already
uses for Zabbly. The resulting node is identical for the protocol's purposes.

**4. Bugs found mid-run were recorded, not hot-patched.** The 2026-07-09 run
surfaced four product defects (see the `docs/e2e-sc2.md` appendix). None was fixed
while the run was in flight: the doc's own gotcha is that a mid-run binary swap
does not retro-apply to an already-provisioned tenant (the suffix is immutable),
so patching would have invalidated the tenant under test and made the remaining
phases meaningless. They are documented with reproductions and left for a
follow-up change that can be verified by a fresh run.
## 2026-07-09 — a bare machine name searches every project instead of assuming the Current Project

`sc delete dev` resolved `dev` against the Current Project and asked "Delete
machine dev?" — a prompt that names neither the project it picked nor the fact
that another project holds a `dev` too. Duplicate machine names across a
tenant's projects are ordinary in v2 (each project is its own Incus project), so
the prompt was hiding the one thing the user needed to decide.

`resolveV2MachineTarget` (`internal/cli/create_v2.go`) now backs the lifecycle
commands (`start`/`stop`/`restart`/`delete`): an explicit `project:machine` is
taken at its word, but a bare name is looked up across every project via
`machineStore.ListMachines`. One hit resolves silently — including when the
machine lives outside the Current Project, which is a deliberate change from the
old "Current Project or bust" rule and the reason `sc delete dev` now finds
`io:dev` from anywhere. Several hits prompt with a numbered `project:machine`
list; without a terminal they are an error naming the candidates, never a guess.
Both confirm prompts (v1 and v2) now render `project:machine`.

Alternatives considered. (a) Keep the Current-Project rule and only qualify the
prompt text — rejected: it still silently deletes the wrong `dev` when the
Current Project happens to hold one. (b) Prompt only when the Current Project
has *no* match — rejected for `delete`, where the whole point is that the user
did not say which one; being asked once is cheaper than an unrecoverable delete.
(c) Extend the search to `sc connect`/`sc image` — deliberately not done:
`connect` *creates* a missing machine, so a cross-project search would change
where new machines land. Those still use `resolveV2MachineReference`.

Scope note: the search only makes duplicate names *manageable*. It does not make
them *workable* — Incus scopes instance DNS names to the bridge (`nic_bridged.go`
`checkAddressConflict` → `nicCheckDNSNameConflict`, which compares instance names,
not `dns.hostname`), and all of a tenant's projects share one bridge, so a second
`dev` can be created but never started. Worse, the check enumerates instances from
the database irrespective of state, so a stopped duplicate also blocks the
surviving `dev` from starting. Setting `dns.mode: none` on the tenant bridge
disables the check outright and costs nothing — per ADR-0018 the bridge dnsmasq
is not the DNS authority (guests get `dhcp-option=6` pointing at the sidecar
CoreDNS, which forwards to 1.1.1.1), and `UsesDNSMasq()` still returns true for
IPv4 DHCP so leases keep working. Not applied here; tracked separately.

## 2026-07-08 — `sc project create` dialed the placeholder Auth Hostname

`sc project create` (the v2 auth-app path in `internal/cli/project_v2.go`) read
the Auth Hostname straight from `config.adminConfig.AuthHostname` — the raw
top-level `auth_hostname` in `config.yml` — both for the gate that decides
whether to use the auth-app path and for the `DeviceClient.BaseURL`. On installs
where `sc login` recorded the real hostname only in the per-remote `installs`
map (leaving the top-level field at its `https://auth.example.com` default), the
command POSTed to `auth.example.com` and failed DNS. Every other command uses
`commandAuthHostname(config, "")` (flag → env → `installs[<current-remote>]` →
inferred → top-level fallback), so the stale top-level value was masked
everywhere except here. Fix: route both call sites through
`commandAuthHostname`. No CLI surface change; correct-by-construction since the
resolver's result equals `sc config show`'s `auth.hostname.effective`.

## 2026-07-08 — majestix e2e run: three live-caught fixes

All three surfaced running the full `docs/e2e-sc2.md` protocol from scratch on
a fresh VM (`majestix`, two installs `sc`+`id` on one Incus 7.2 daemon, nested
client VM). Each was fixed, regression-tested, redeployed, and re-verified live
in the same run.

- **Auth DB `SQLITE_BUSY` on first login.** The new svclog sink writes a row
  per request into the same SQLite DB the device poll writes users to;
  `OpenDatabase` set pragmas via a one-off `Exec` (one pooled connection) and
  left the default rollback journal with no busy timeout, so the very first
  `sc login` died with `database is locked (5)`. Fix: pragmas in the DSN
  (`busy_timeout(10000)`, `journal_mode(WAL)`, `foreign_keys(1)`,
  `synchronous(NORMAL)`) so every pooled connection gets them. Alternative
  considered: `SetMaxOpenConns(1)` — rejected, it serializes reads too.
- **`sc dns-proxy`: the resolved link scope now points at an on-link forwarder,
  not at the tenant CoreDNS.** systemd-resolved binds a link scope's UDP
  sockets to the scope's interface; our scope lives on a dummy link, so UDP to
  the off-link CoreDNS was transmitted into the dummy and dropped (tcpdump:
  zero packets on any real interface). resolved silently degraded the server
  to TCP and then re-probed UDP after each ~5-min idle grace period — failing
  exactly one `getent` per idle period, forever. Alternatives considered:
  (a) a primer query in the unit — shipped first, but only fixes the first
  cycle, not the idle re-probe; (b) a keepalive timer — shrinks but keeps the
  window, masks the defect; (c) attaching the scope to `tailscale0` —
  tailscaled owns that link's resolved settings and clobbers them; (d) socat —
  new client dependency. Chosen: a ~100-line UDP+TCP forwarder inside the fat
  binary (`sc dns-proxy`, hidden), run by the per-suffix unit as a daemon
  (`Type=exec`, `Restart=on-failure`, `PartOf=systemd-resolved.service`): it
  owns the dummy link, listens on the link's own 169.254 address (bound-to-link
  delivery of an on-link address is local), pins the scope there, forwards to
  the CoreDNS over normal routing. UDP+EDNS0 works natively; the degradation
  ladder is gone; the resolver-install step dropped from ~21s (probe cost) to
  ~0.4s. The unit embeds `os.Executable()` at render time — moving the binary
  needs a re-login (documented tradeoff).
- **Install scoping for URL-named remotes.** The naming-url-install-identity
  merge renamed enrolled remotes to `sc-<install-label>` (from the Auth
  Hostname), but `installPrefixFromRemoteName` still only inverted the legacy
  `sc-<prefix>-<tenant>` shape — every lookup under a URL-named remote ran
  unscoped and the cross-install shadowing returned (`sc list` under install A
  showed install B's machines). Fix: derive the prefix from the remote's
  pinned project in the shared incus config (`remotes[<remote>].project` =
  `<prefix>-<tenant>[-<app>]`), which login writes for every enrollment; the
  legacy name-shape inversion stays as fallback. Considered extending the
  `installs:` map in `config.yml` to carry the prefix — rejected: the pin
  already exists for every enrollment (old and new) and needs no schema change.

## 2026-07-08 — majestix e2e round 2: exec exit codes were silently swallowed everywhere

The single most consequential find of the run: the incus SDK's `op.Wait()` on
an exec operation succeeds as long as the *operation* ran — a command that
exited nonzero is only visible in `Metadata["return"]`, which none of the
sidecar exec helpers checked. Consequences caught live: `sc-adm tenant create`
returned success in ~5s on a cached-image host while the whole package install
had failed against a still-booting container (no CoreDNS, no Tailscale); the
DNS reconciler's post-write CoreDNS reload failed invisibly and the live-file
compare then skipped it forever (zone file right, served zone stale ~1min).
Fixes: `execExitError` applied to `execSidecar`/`execSidecarCapture`, the v1
`restartCoreDNS`, and the reconciler's reload (now with stderr capture);
`waitV2SidecarBoot` (systemd settled + tenant IPv4 on eth0) between sidecar
launch and provisioning execs. Deliberately NOT swept every other exec site in
one go (machine connect/lifecycle/ssh-key paths) — those have their own
error-observation semantics and deserve a separate pass; noted here so the
sweep isn't forgotten. Also repaired `scripts/e2e-v2.sh` (pipefail early-exit,
nss-myhostname false positives via `getent ahostsv4`, cleanup that now purges
via the product path incl. shared volumes). `e2e-v2.sh` runs GREEN on majestix.

## 2026-07-08 — verbose service logging + per-user log browser

- Added a shared `internal/svclog` package (the repo had no logging layer at
  all — only two `log.Printf` calls in the auth-app). It emits one verbose,
  timestamped line per HTTP request plus named work spans, each with a duration,
  to stderr (journald under systemd), and optionally to a `Sink`.
- **Identity attribution via request-scoped context, not middleware guessing.**
  The HTTP middleware knows method/path/status/duration but not *who* — that is
  resolved inside handlers (session cookie, CLI bearer token, cert fingerprint).
  Rather than re-resolve identity in middleware (an extra DB hit, and impossible
  for the machine-called workload-token path), the middleware installs a mutable
  record in the context and handlers enrich it with `svclog.SetUser`. I
  instrumented the existing identity choke points **once** each
  (`requireAllowlistedSession`, `requireAdmin`, `requireBearerUser`,
  `requireTenantAccess`, plus the broker principal resolvers) so every route is
  attributed for free. Workload-token issuance is attributed to the machine's
  owning `user_key` from the runtime-secret row, so it shows in that user's log.
- **Async DB sink.** SQLite is a single writer; writing a log row synchronously
  on every request would serialize request handling. The auth-app's `dbSink`
  hands entries to a background goroutine over a buffered channel and **drops on
  overflow** (best effort) — the verbose stderr line is never dropped, only the
  persisted copy. `Close()` flushes the buffer at shutdown. Each drained write
  uses a detached 5s-bounded context so a wedged DB can't block the drain.
- **Scope decision (asked the user):** the browse UI covers auth-app activity
  only. The brokers get the same verbose stderr logger but no DB sink — they are
  a separate `sandcastle-broker` process on a separate appliance and don't share
  the auth DB. Shipping broker logs into the UI was deferred; it would need an
  authenticated internal endpoint.
- **Retention: keep forever (user's choice).** No pruning job. The `logs` table
  grows unbounded; flagged for the future. Indexes on `(user_key, ts)` and `ts`
  keep the browse queries fast regardless.
- `/logs` page: reuses the session guard `requireAllowlistedSession`, branches on
  `user.SandcastleAdmin` (admin → `ListAllLogs`, else `ListLogsForUser`). System
  rows (empty `user_key`, e.g. the DNS-reconcile error) are visible to admins
  only. Styling copied from `machinesTemplate` (mobile-first inline CSS).
- Verified with `go test ./internal/svclog ./internal/authapp` — unit tests for
  middleware status/duration + span timing, the security-critical scoping
  (`ListLogsForUser` vs `ListAllLogs`, and search can't escape a user's scope),
  the `/logs` page rendered per viewer, and the full middleware→dbSink→DB→query
  pipeline.

## 2026-07-07 — `sc connect --vm`: auto-create as a virtual machine

- `sc c <name>` (v2) already auto-creates a missing machine, but always as a
  container. Added `--vm` to connect so `sc c --vm tubu` creates the machine as
  a VM when it doesn't exist (pass-through to `EnsureMachineV2`; no effect on
  an existing machine). VMs get a 240s SSH-wait window instead of 120s —
  firmware + kernel boot precede cloud-init. Validated live: created a VM in
  `tc3-thieso2-default`, SSH'd in, hostname `tubu.default.tc4` (login-chosen
  DNS suffix intact).

## 2026-07-07 — incus current remote is the single source of truth for `sc`'s remote

- Two knobs selected the active install and could disagree: the shared incus
  dir's `default-remote` (moved by `incus remote switch`, set by login's
  enrollment) and `remote:` in `~/.config/sandcastle/config.yml` (written by
  login, read by `sc`). A manual `sc incus remote switch` moved only the first,
  so `sc` kept operating on the previous install — exactly the confusion the
  operator hit with tc2/tc3 on one daemon.
- Now `LoadUser` prefers the shared incus dir's `default-remote` whenever it
  names a Sandcastle enrollment (`sc-…` and listed in that config); precedence
  is `SANDCASTLE_REMOTE` env → incus current remote → config.yml `remote` →
  default. Non-sandcastle current remotes (`local`, `images`, …) are ignored so
  raw-incus work doesn't hijack `sc`. `sc config set remote X` writes through
  to the incus `default-remote` (refusing names that aren't enrolled), so the
  two knobs can no longer diverge; config.yml's `remote` stays as a fallback
  and for back-compat. Admin commands (`LoadAdmin`) are unchanged — their
  remote points at an Incus host, not an enrollment.

## 2026-07-07 — tenant lookup scoped to the current remote's install (same-daemon multi-install)

- With two installs on one Incus daemon (tc2 + tc3) and one user logged into
  both, `sc incus ls` connected over the tc3 remote but pinned
  `INCUS_PROJECT=tc2-thieso2-default` — every sidecar's Incus Reach lands on
  the same host API and the shared client cert sees BOTH installs' projects, so
  `v2TenantSummary`'s first-match-by-tenant-name picked whichever install
  sorted first. All summary consumers (`sc incus`, `create`, `connect`,
  machine lifecycle) inherited the wrong project.
- Fix: `v2TenantSummary` now scopes `tenant.ListForPrefix` by the install
  prefix recovered from the configured remote's name
  (`installPrefixFromRemoteName`: `sc-<prefix>-<tenant>` → prefix,
  `sc-<tenant>` → default). Chose the remote name as the source of truth
  because it is the one client-side datum that is per-install by construction
  (server-generated via `usertrust.RemoteInstallName`); unparseable remote
  names fall back to the old unscoped behavior. Note `sc incus remote switch`
  moves only the raw incus CLI's current remote — `sc`'s own install selection
  is `sc config set remote …`.

## 2026-07-07 — first-login "write /etc/resolv.conf to sidecar: Not Found" root-caused (dangling symlink, not a boot race)

- Every fresh v2 tenant provisioning failed once with `write /etc/resolv.conf
  to sidecar: Not Found` and only succeeded on the re-ensure pass. The earlier
  `waitInstanceRunning` guard assumed a boot race, but the real cause is that
  `/etc/resolv.conf` on the stock Debian sidecar image is a **symlink** to
  systemd-resolved's stub under `/run`; the Incus file API follows symlinks, and
  pushing through a dangling one returns "Not Found". It never hit the other DNS
  files (real paths), and the retry only worked because the package-install
  bootstrap had meanwhile written through the symlink, creating the target.
  The machine-create path already guarded this with `rm -f /etc/resolv.conf`
  before writing; the sidecar path didn't.
- Fix: `writeInstanceDir` (the prep step before every sidecar/appliance file
  push) now also clears a symlink at the target path (`[ ! -L p ] || rm -f p`),
  so pushes always land on a regular file. Chose the generic prep-step fix over
  a resolv.conf special case since any pushed path could be a symlink on a
  future base image.

## 2026-07-07 — interactive tailnet-join URL made durable (primary path; auth key is CI-only)

- **Context.** `sc login` without a Tailscale auth key looked like an infinite
  loop: after approval it polled "waiting to join your tailnet" for hours with
  ~70s per poll. Root causes were all in the interactive branch of
  `v2TailscaleUp` (re-run by the server on every awaiting-tailnet poll):
  (1) each pass truncated `/var/lib/sandcastle-tsup.log` and then failed
  silently to restart the already-running `sandcastle-tsup` unit, so the login
  URL was destroyed and could never be re-obtained — a Ctrl-C + re-login printed
  no URL at all; (2) `tailscale status` exits non-zero while logged out, so the
  daemon-wait loop burned its full 30s on every pass, plus another 30s grepping
  the now-empty log. Design decision confirmed with the operator: the
  **interactive URL is the primary join path**; `--tailscale-auth-key` at login
  is for unattended/CI only — so the fix makes the URL durable rather than
  pushing users toward keys.
- **Fix (sidecar script).** The pending `tailscale up` unit is now left alone
  while healthy: the script (re)starts it only when the unit is not running *or*
  its log no longer contains a `login.tailscale.com` URL (which also self-heals
  sidecars stuck by the old truncation bug). The log is truncated only when a
  fresh unit is started. Daemon readiness uses `tailscale status --json`, which
  answers as soon as tailscaled is up even when logged out. The URL grep takes
  the *newest* match (`tail -n 1`) since each `up` mints a fresh URL. Awaiting
  polls now answer in seconds.
- **Fix (client).** `sc login` printed the join instructions only on the first
  approved poll — if that poll carried no URL (or the URL changed later), the
  user never saw it. It now prints the instruction block whenever the reported
  URL is new, and prints "Waiting for the sidecar…" once. The tip line now
  frames `--tailscale-auth-key` as unattended/CI, matching the intended design.
- **Not changed (deliberate).** The server still never uses its deployment-wide
  `--tailscale-auth-key` for sidecar provisioning (it only echoes it to clients)
  and approved device logins still don't expire while awaiting the tailnet join
  — acceptable now that polls are cheap and the client's `--max-polls` bounds
  the wait (~25 min at the 5s cadence).

## 2026-07-07 — per-install infra project `<prefix>-infra` + install resource inventory

- **The auth-app appliance now lives in `<prefix>-infra`, not the generic
  `infrastructure`.** Every install put its auth-app in one shared, unprefixed
  `infrastructure` project, so on a host with several sandcastles (or an older
  `sc-infra` install) you couldn't tell which appliance belonged to which install,
  and the project name didn't group with its own `<prefix>-<tenant>` / `<prefix>-net`
  resources. The install now derives `infraProject := installV2Prefix(prefix) +
  "-infra"` (e.g. default `sc` → `sc2-infra`, `--prefix id` → `id-infra`), matching
  the appliance-bridge (`<prefix>-net`) and tenant (`<prefix>-<tenant>`) naming.
  Safe rename: the appliance project name is decoupled from runtime — provisioning
  and the DNS reconciler scope tenants by `SANDCASTLE_INCUS_PROJECT_PREFIX`, not by
  the appliance project name — so only the install wiring + the existing-install
  guard referenced the literal. `AuthAppDefaultProject` stays `"infrastructure"` as
  the fallback for the lower-level standalone `authapp deploy`.
- **Install now prints a resource inventory.** The summary ends with a
  "resources created by this install" list (infra project, auth-app instance,
  bridge, broker project/instance, cloudflare tunnel) plus a one-line teardown
  hint. Makes coexistence auditable and teardown obvious (delete the listed
  project(s) + bridge).

## 2026-07-07 — enrollment reaches the sidecar over the tailnet, not the private CIDR

Found during the first real-OAuth login from a Mac that was on the tenant tailnet
but had NOT accepted the tenant subnet route.

- **`incus remote add` now auto-answers with the sidecar's tailnet endpoint.** The
  Incus join token embeds the sidecar Incus's own https address, which lives on the
  tenant's PRIVATE CIDR (e.g. 10.253.x.x). A client that already accepted the tenant
  subnet route (like the e2e VM) can reach it; a plain tailnet client cannot, so
  `incus remote add <token>` fell through to an interactive "provide alternate
  server addresses" prompt and, non-interactively, failed with "All server
  addresses are unavailable." The auth-app already returns the sidecar's TAILNET IP
  as `IncusRemoteAddress` (used for the later `set-url`), so we now feed that
  `<ip>:8443` to the prompt on stdin — enrollment connects over the tailnet with no
  subnet route required. Falls back to the caller's stdin when no tailnet address is
  known. Without this, every first login from a Mac/laptop that isn't a subnet-route
  client would stall at the prompt.
- **TODO (not yet fixed): auth-app SQLite `SQLITE_BUSY` under concurrent device
  poll.** The first real login hit `auth app device poll: database is locked (5)
  (SQLITE_BUSY)`; a retry cleared it. The device-poll path races provisioning
  writes on the same SQLite file. Needs a busy_timeout / WAL / serialized writer.

## 2026-07-07 — client-side split-DNS for v2 + reconciler self-heal

Surfaced while chasing "why doesn't `<machine>.<project>.<suffix>` resolve on the
client" during the coexistence e2e. Four linked fixes:

- **systemd-resolved: drop-in, not `resolvectl … lo`.** The old strategy ran
  `resolvectl dns lo <ip>` / `domain lo ~<suffix>`; modern systemd-resolved (257
  on Debian 13) rejects it outright — "Link lo is loopback device." Pinning to a
  real link (`tailscale0`) works but *replaces* Tailscale's MagicDNS servers on
  that link. Chosen fix: a global `resolved.conf.d` drop-in
  (`DNS=<endpoint>` + `Domains=~<suffix>`) so the kernel routes the query to the
  tenant CoreDNS over the tailnet and every link is left alone. macOS keeps its
  `/etc/resolver/<domain>` file. Alternatives rejected: dummy interface (query
  binds to the link's egress, which can't route to the tenant subnet); per-link
  tailscale0 (clobbers MagicDNS).
- **`10-` filename prefix is load-bearing.** systemd merges `resolved.conf.d`
  into ONE flat global server list in lexical order and does NOT fall through on
  an authoritative NXDOMAIN. So the tenant CoreDNS must sort before the public
  upstream (`50-public-upstream.conf`): CoreDNS answers its own zone and REFUSEs
  everything else (fall-through covers public + other tenants), whereas a public
  server would NXDOMAIN a tenant name first and win. Verified live: with the
  tenant server last, resolution failed; first, it worked.
- **v2 login installs the resolver automatically.** The v2 login path previously
  only verified tenant routing and left client name resolution to a *manual*
  Tailscale Split DNS console entry — exactly the kind of shortcut the e2e is
  meant to avoid. It now also installs the local split-DNS drop-in, using the
  CIDR the device response already carries (a restricted client can't read its
  infra project's CIDR via the store — see `internal/tenant/list.go` — so
  `localdns.PlanForV2` takes it directly) and the suffix visible on the app
  projects. Best-effort: a failure warns and points at the Tailscale Split DNS
  fallback rather than failing the login.
- **Elevation executes the exact plan.** `runLocalDNSWithSudoFallback` used to
  re-run `sc dns <action> <tenant>` under sudo, which rebuilt the plan from the
  store (empty CIDR → `ParsePrefix("")`). It now serializes the resolved plan and
  a hidden `dns apply-elevated` runs it verbatim across the privilege boundary.
- **DNS reconciler self-heals an externally-reset sidecar.** The auth-app
  reconciler skipped writing when the rendered zone matched an in-memory
  `lastZone` cache. But a sidecar can restart and lose its zone (back to SOA+ns)
  while the auth-app keeps running — the cache then masks the loss forever
  (observed live: a machine's A-record vanished and only an auth-app restart,
  which clears the cache, brought it back). Fixed by comparing against the
  sidecar's ACTUAL zone file (serial-normalized) instead of the cache.

## 2026-07-07 — enrollment hang on a second install (trusted-client project pin)

- **Cert-based remote-add fallback now pins `--project`.** Found live during a
  full-suite e2e: enrolling a *second* install on a client that already trusts
  the shared keypair failed. The token path is refused (`Client is already
  trusted`), so we fall back to `incus remote add … --auth-type=tls
  --accept-certificate`; but the shared cert can see *both* installs' projects,
  so `incus remote add` prompted interactively (`Name of the project to use for
  this remote:`) and died on EOF in the non-interactive login — the login hung
  and never enrolled `sc-id-<tenant>`. Fix: pass `--project <install-default>`
  to that fallback so it never prompts. Extracted `trustedClientRemoteAddArgs`
  for a pure unit-test (the shell-out itself resists mocking because
  `setRemoteProject` expects the remote already in `config.yml`). Validated live:
  second install now enrolls cleanly, project pins correct, no cross-leak.

## 2026-07-07 — multi-install coexistence, shared identity, appliance bridge

- **Each install owns its appliance bridge `<prefix>-net`** (was: appliances on
  shared `incusbr0`). Subnet is `ipv4.address=auto` — let Incus pick a free /24,
  provably non-overlapping, vs. a `--appliance-cidr` flag or deriving from the
  tenant pool. `--bridge` default flipped from `incusbr0` to empty (empty ⇒ own
  bridge; set ⇒ use that existing bridge) — a deliberate behaviour change.
  No unit test (no `TenantCreateServer` fake; logic mirrors the live-tested
  `ensureV2Bridge`) — validated on the live install.
- **Skip the broker entirely for Cloudflare ingress** (was: broker deployed with
  a container-internal `:9443`). It was unreachable dead weight — no host port,
  no tunnel route; tenant self-service rides the auth-app `/api/projects`.
  Removed the `NoHostPort` half-measure. Existing-install guard keys on the
  auth-app instance, so detection still works with no broker project.
- **Shared incus dir auto-detects `~/.config/incus`.** Prefer the native dir so
  plain `incus` works with no wrapper, but only when it has no foreign identity.
  A `.sandcastle-owned` marker (dropped *before* the client cert is written)
  pins the choice so the dir doesn't flip to the dedicated dir once its own
  `client.crt` appears. Driven by the hard constraint: one keypair per Incus
  config dir, so an admin cert and a restricted tenant cert can't coexist —
  which keeps hosts/admin workstations on the dedicated dir automatically.
- **Provision on a detached context** (`context.Background()`, 8-min budget, per
  device-code lock) instead of the poll request context. Workaround for a real
  limit: over a flaky Cloudflare tunnel the client poll times out (~30s) and
  cancels the request, which aborted provisioning mid-flight so bring-up never
  finished. This was *the* unlock for the from-scratch dual-install e2e. A full
  async-job design is possible; this was the minimal correct fix.
- **Provisioning idempotency/boot-race fixes** exposed by a cached-base-image
  host (creates return instantly): tolerate spurious "already running" on
  `Start:true`; wait for RUNNING before configuring an appliance/sidecar; start
  an existing STOPPED sidecar on re-provision.
- **Trust union + per-remote project pin** (shared-identity core): Incus keys
  trust by cert fingerprint, so multiple installs sharing one client cert means
  each install must *union* its projects into the one trust entry, and each
  remote must be *pinned* to its install's default project (the shared cert's
  server-side default is otherwise ambiguous and lists the wrong install's
  machines).
- **Environment note (not a code decision):** the test VMs' frp link drops
  constantly and aggressive manual cleanup (`rm -rf /var/lib/incus`, `ip link
  delete` on bridges) corrupts the Incus seccomp/device runtime → fresh sidecars
  flake to STOPPED; a daemon/VM reboot clears it. Tear down tenant bridges with
  `incus network delete` (clear the app project's default-profile `eth0` first),
  never raw `ip link`, or dnsmasq orphans hold the gateway `:53`.

## 2026-07-07 — foreign v1 tenant CIDR adopted as own on a second install

- **Bug (live on big):** first login to the `tc2` install by GitHub user
  `thieso2` failed with `dnsmasq: failed to create listening socket for
  10.248.1.1: Address already in use`. `ProvisionReuseInputs` scoped v2
  (`kind=infra`) own-tenant matching by `meta.KeyV2Prefix`, but the v1
  (`kind=tenant`) branch matched by tenant name alone — so the old `sc`
  install's v1 project `sc-thieso2` (10.248.1.0/24) was adopted as the new
  install's own CIDR (`PreferredCIDR`) instead of counting as occupied, and
  tc2 tried to build its tenant bridge on the live `sc-thieso2` gateway.
- **Fix:** v1 (`kind=tenant`) projects are **never** own in the v2
  provisioning path — same-named or not, whatever the prefix, their `/24` is
  always occupied. Alternative considered: recognize a v1 tenant as own when
  the project name equals `<installPrefix>-<tenant>` (v1 carries no prefix
  metadata), so a same-install v1→v2 re-provision keeps its /24 — rejected
  because the v1 bridge (dnsmasq bound to the gateway IP) may still be live,
  so reusing the /24 collides at bridge creation even within the same
  install, and the v2 path never creates `kind=tenant` projects anyway.
  Regression test: `TestProvisionReuseInputsNeverOwnsV1CIDR`. One fix covers
  all three provisioning paths (device login, `sc-adm tenant create`, project
  broker) — they all call `ProvisionReuseInputs`.

## 2026-07-07 — `sc list` (and project/dns/status) matched same-named tenants unscoped

- **Bug (witnessed live):** with two installs sharing one Incus daemon and the
  same tenant name in both (the standard coexistence shape — one GitHub user,
  two installs), `sc create dev` succeeded but `sc list` came back without the
  machine. The earlier cross-install scoping fix covered `sc create`,
  `sc connect`, lifecycle, and `sc incus*` (via `v2TenantSummary` →
  `tenant.ListForPrefix`), but `sc list`, `sc project *`, the dns/trust
  commands, and `sc status` still resolved the tenant by NAME only over the
  unscoped `tenant.List` — and the other install's same-named tenant sorts
  first (`id-…` < `sc2-…` in the project scan), so those commands silently
  operated on the other install.
- **Fix:** one shared `scopedListTenants` helper (prefix from
  `installPrefixFromRemoteName`, i.e. the current remote is the single source
  of truth), used by `listMachines`, `currentTenantSummary` (project.go), and
  `findTenantSummary` (dns.go); `tenant.GetStatusWithTopologyForPrefix` for
  `sc status`. Unscoped fallback (empty prefix) is preserved for admin remotes
  and v1 shapes. Alternative considered: filter inside `tenant.List` by a
  store-carried prefix — rejected as it would push CLI remote-name semantics
  into the tenant package's store abstraction.
- Regression test: `TestListMachinesScopedToCurrentInstall` (two installs,
  same tenant name, each remote must see its own machine set).

## 2026-07-07 — Incus 7.x broke idmapped-mounts detection → shared /home silently gone

- **Bug (caught by the shared-home e2e battery on obelix):** on a fresh Incus
  7.2 host the `home` volume was created but attached to NO profile, and both
  shared volumes were created unshifted — CT↔VM `/home` sharing silently
  gone. `SupportsIdmappedMounts` keyed on
  `kernel_features["idmapped_mounts"] == "true"`, and Incus 7.x stopped
  populating `environment.kernel_features` (always `{}`), so every 7.x host
  read as idmapped-less.
- **Fix:** absent entry → supported (Incus 7.x's kernel floor 5.15 already
  includes idmapped mounts, which landed in 5.12); explicit `"false"` (older
  daemons that still report) → unsupported. Alternative considered: probing
  by attaching a shifted volume — rejected, the failure only surfaces at
  instance start. Known tradeoff: a container-hosted incus (nested CT) also
  reports `{}` and would now try shifted volumes and fail at machine start —
  that topology can't host the tenant VMs anyway and is not a supported
  server shape. Regression test: `TestKernelFeaturesSupportIdmappedMounts`.

## 2026-07-07 — terminal provisioning errors kept the device login polling to timeout

- **Bug (immutability e2e check):** `sc login --force --dns-suffix other`
  printed the immutable-suffix error immediately but then polled for ~10
  minutes to "device login polling timed out", with the server re-attempting
  provisioning on every poll. Provisioning failures always left the device
  login `pending` — right for transient bring-up errors (the retry loop is
  deliberate), wrong for deterministic user-input errors.
- **Fix:** a `tenant.TerminalProvisionError` wrapper marks no-retry-can-fix
  errors (immutable-suffix conflict, rejected suffix); the poll handler
  DENIES the device login on one, and the client surfaces
  `device login denied: <message>` (exit 1) on its next poll. Transient
  errors keep the pending/retry behavior. Regression test:
  `TestDevicePollDeniesLoginOnTerminalProvisioningError`.
- **Deploy gotcha (harness):** `incus file push` over an existing same-named
  file through the nested (big → obelix VM) path silently left the OLD file
  in place once — always `rm -f` the target first and verify `sha256sum`
  after pushing a binary.

## 2026-07-07 — multi-suffix client DNS: global resolved drop-ins replaced by per-suffix link scopes

- **Bug (coexistence e2e, two installs on one Linux client):** only one Tenant
  DNS Suffix ever resolved via `getent` even though `dig @<sidecar>` answered
  for both. Two layered causes:
  1. The sidecar Corefile's catch-all `.:53` FORWARDED foreign names upstream,
     so a tailnet client asking the wrong tenant's server got an authoritative
     NXDOMAIN instead of the REFUSED the client-resolver design depended on.
  2. Even with REFUSED, systemd-resolved's GLOBAL scope (where the
     resolved.conf.d drop-ins landed every tenant server) asks only its
     rotating "current server" — the REFUSED answers rotate it onto the
     public upstream and then BOTH tenant zones die with public NXDOMAINs.
     Per-domain routing in resolved only works ACROSS link scopes; the `10-`
     filename-ordering trick was never sufficient.
- **Fix, server side:** the Corefile catch-all now REFUSES tailnet sources
  (`acl { block net 100.64.0.0/10 }`) — machines on the tenant bridge keep
  full recursion (that server is their only DNS), clients get the terminal
  REFUSED.
- **Fix, client side (the real one):** each suffix gets its own resolved link
  scope: `sandcastle-dns-<suffix>.service` creates a dummy link
  (`scdns-<fnv32-hash>`, name ≤ IFNAMSIZ) with a deterministic 169.254/16
  link-local address — resolved does NOT activate a link's DNS scope until
  the link carries an address (found empirically; a bare `up` dummy stays
  "Current Scopes: none") — and pins `DNS=<CoreDNS>` `Domains=~<suffix>` via
  resolvectl. `PartOf=systemd-resolved.service` re-applies the runtime scope
  whenever resolved restarts (validated live: restart → scopes re-form,
  both zones + public resolve). Install removes any legacy drop-in (plus one
  resolved restart to flush its global servers). Alternatives considered:
  systemd-networkd .network files (only work where networkd manages links)
  and putting tenant servers on the tailscale0 link (same flat-list problem,
  plus clobbers MagicDNS).
- macOS is untouched: `/etc/resolver/<suffix>` is natively per-domain.

## 2026-07-07 — `sc-adm tenant delete` on a v2 tenant was a silent no-op success

- **Bug (audit, validated live):** `tenant delete e2ea --yes` on a v2 tenant
  printed "Deleted runtime resources for e2ea; durable state was preserved."
  and deleted NOTHING — `PlanDelete` computes v1 `sc-<tenant>` resource names
  that don't exist for v2, and each per-resource delete is ignore-not-found.
  An operator would believe the tenant was gone.
- **Fix:** the delete command first runs `tenant.PlanDeleteV2` (scoped to the
  install prefix — a same-named tenant of another install must not be
  touched); a v2 match routes to `TenantDeleter.DeleteTenantV2`, which tears
  down each app project (instances, images, shared home/workspace volumes —
  detached from the default profile first — and profiles), the infra project
  (sidecar), and the tenant bridge. Without `--purge` a v2 tenant is refused:
  the shared volumes live inside the app projects, so there is no meaningful
  "runtime only" subset (unlike v1, whose volumes live in the tenant project
  and survive a non-purge delete). First live run caught a second bug: the
  plan reused the v1 volume names (`sc-home`/`sc-workspace`) — the deletes
  404'd silently and project deletion failed with "Only empty projects can be
  removed"; v2 names are plain `home`/`workspace` (now shared constants
  `tenant.V2HomeVolumeName`/`V2WorkspaceVolumeName` used by create and
  delete). The sidecar's tailnet device is deliberately not removed (BYO
  tailnet, no server-side API key — ADR-0017); documented instead.

## 2026-07-09 — agent-skill config: repo is multi-context, not single-context

- **Trigger:** re-ran the `setup-matt-pocock-skills` scaffolding. `docs/agents/`
  already existed from a prior run, so this was a correction pass, not a
  greenfield write.
- **Finding (the reason this entry exists):** `docs/agents/domain.md` declared a
  single-context layout, but the repo has two — the root Sandcastle context and
  `sc-edge/`, which carries its own `CONTEXT.md`, its own `docs/adr/`
  (ADR-0001), and its own `CLAUDE.md`. `sc-edge/CONTEXT.md` explicitly defers to
  the parent for Sandcastle-wide vocabulary, so it is a *child* context, not a
  peer. Under the old declaration, any skill editing the edge appliance would
  have read the root glossary and silently never seen the edge vocabulary or its
  ADR.
- **Decision:** declared multi-context and added `CONTEXT-MAP.md` at the root as
  the index. Considered leaving the layout undeclared and describing both
  locations inline in `domain.md` (one fewer root file), but the skills already
  key off the *presence* of `CONTEXT-MAP.md` to decide whether to look for
  per-context glossaries — describing it in prose only would not have changed
  their behaviour. Also considered demoting `sc-edge` to "not a real context",
  which would have been a lie about the tree.
- **Second finding:** the root `CONTEXT.md` is a pointer, not a term list — the
  canonical vocabulary is in `docs/glossary.md`. Skills are told to "read
  `CONTEXT.md`", so they land one hop short. Documented the hop explicitly in
  `domain.md` and `CONTEXT-MAP.md` rather than inlining the glossary, which would
  have duplicated a file that already has a single owner. Inlining remains the
  cleaner long-term fix.
- **Also corrected:** `CLAUDE.md` named the issue repo `thieso2/incus-sandcastle`
  while the git remote and `docs/agents/issue-tracker.md` both say
  `thieso2/sandcastle-incus` — the repo's own instructions disagreed with
  themselves. (Fixed concurrently by another writer mid-session; left that
  wording in place.)
- **Enabled external PRs as a triage surface** (`/triage` reads this flag from
  `issue-tracker.md`) and created the three missing GitHub labels —
  `needs-triage`, `needs-info`, `ready-for-human`. `wontfix` and
  `ready-for-agent` already existed. All five now use the canonical strings, so
  `triage-labels.md` needs no remapping.
- **Tooling workaround:** the skill's seed template documents the external-PR
  filter as `gh pr list --json ...,authorAssociation`. That field does not exist
  on `gh` 2.46.0 (Debian) — neither `pr list` nor `pr view` accepts it; both fail
  with `Unknown JSON field`. Rewrote the filter against the REST API
  (`gh api repos/<owner>/<repo>/pulls`), whose `author_association` is populated.
  Cost: labels and comments are absent from that payload and need a follow-up
  `gh pr view <n> --json labels,comments` per PR. Considered pinning a newer `gh`
  instead, but the REST call works on every version and adds no install step.
- **Landed via cherry-pick, not merge.** A second agent was committing to this
  repo concurrently; it rebased its e2e-protocol branch onto `main` and deleted
  the branch, orphaning the base this work was branched from. Merging would have
  replayed its five commits as duplicates. Cherry-picked the single docs commit
  onto `main` instead — no overlap, since its commits touch only
  `.github/workflows/ci.yml` and `mise.toml`. It also fixed the `CLAUDE.md`
  issue-repo typo independently, in `docs: point the issue-tracker note at this
  repo's actual remote`; that version won.

## Running Notes

- Started implementation from the committed domain docs (`CONTEXT.md`,
  `docs/sandcastle-v1-spec.md`, ADR-0001). The existing Go code is still built
  around the superseded owner/project/sandbox model.
- First implementation slice is the foundational naming and metadata vocabulary,
  because CLI parsing, Incus resource names, DNS, routes, and tests all depend
  on those types.
- `internal/naming` now owns the new reference grammar:
  `tenant/project`, `tenant/machine`, `tenant/project/machine`, user
  `machine`, and user `project/machine`. Incus tenant project names are
  `sc-{tenant}` and machine instance names are `{project}-{machine}`.
- Local/admin config moved from `Owner`/`SANDCASTLE_OWNER` to
  `Tenant`/`SANDCASTLE_TENANT`. Local config also has a `Project` field for the
  current-project behavior.
- `internal/meta` now serializes `tenant`, `machine`, and route target tenant
  fields. I moved the previous per-project SSH public key to tenant metadata
  because the new spec has tenant-scoped infrastructure/storage and projects
  have no settings.
- Renamed the old Incus-project lifecycle package from `internal/project` to
  `internal/tenant`. Its focused tests now cover tenant creation/deletion/list
  and status. `PlanCreate` takes only a tenant name, derives `sc-{tenant}`,
  initializes the `default` project in tenant metadata, and renders DNS for the
  tenant suffix.
- Renamed the runtime package from `internal/sandbox` to `internal/machine`.
  Machine planning now uses current tenant/current project resolution, Incus
  instance names of `{project}-{machine}`, private hostnames of
  `{machine}.{project}.{tenant}`, and tenant storage defaults of
  `{project}/{machine}`.
- Local DNS, local trust, Tailscale, and restricted-user grants now resolve
  tenant references rather than owner/project references. Local DNS writes a new
  `tenants:` state schema with `dnsSuffix` entries; there is intentionally no
  migration or compatibility alias for the old `projects:` local state.
- Restricted-user grants still produce Incus restricted certificate `Projects`
  because that is the Incus API surface, but command input is now tenant refs
  and maps to `sc-{tenant}`.
- Public route planning and host overrides now target machines, not sandboxes.
  Canonical references are `tenant/project/machine`; user-side calls may resolve
  `machine` or `project/machine` through `SANDCASTLE_TENANT` and
  `SANDCASTLE_PROJECT`. Route metadata writes `targetTenant`,
  `targetProject`, and `targetMachine`.
- `sandcastle route status <hostname>` is implemented as a filtered read over
  the existing route listing API rather than a new broker endpoint. That keeps
  the current mTLS broker protocol smaller while still exposing the v1 command
  shape; it can become a dedicated metadata lookup later if route lists become
  too large.
- Route broker authorization is now tenant-grant based. The mTLS principal has
  a human user string for audit (`CreatedBy`), but route create/delete
  authorization checks whether the certificate grants the target Incus tenant
  project (`sc-{tenant}`), not whether the user name matches the tenant.
- The Incus adapter layer moved from project/sandbox method semantics to
  tenant/machine semantics. The remaining old public-surface names are Incus API
  terms such as project, or historical notes explicitly describing the
  superseded model.
- User CLI command names now expose the new no-alias surface for the main
  machine lifecycle: `list`, `create`, `connect`, and `delete`. I removed the
  old `ls`, `add`, `enter`, and `rm` registrations from the root command rather
  than keeping compatibility aliases. `status <machine>` now uses the machine
  status planner/result directly; the old `inspect` command is no longer
  registered.
- `sandcastle list` now lists machines in the current tenant instead of listing
  tenant summaries. It scopes to `SANDCASTLE_PROJECT` unless `--all-projects/-a`
  is supplied or no current project is configured. The `--include-unmanaged/-u`
  flag shows non-Sandcastle Incus instances for tenant-wide lists, while the
  unmanaged count is always printed even when unmanaged rows are hidden.
- The admin tenant lifecycle group is now `sandcastle-admin tenant ...` instead
  of `project ...`. The admin machine lifecycle is now top-level:
  `sandcastle-admin list tenant[/project]`,
  `sandcastle-admin create/connect/status/delete tenant[/project]/machine`.
  These commands translate admin refs into the same tenant-scoped machine
  planners used by the user CLI so the admin and user paths do not diverge.
- Admin tenant access is now exposed in tenant-first command shape:
  `sandcastle-admin tenant grant <tenant> <user>`,
  `sandcastle-admin tenant revoke <tenant> <user>`, and
  `sandcastle-admin tenant users <tenant>`. These commands still mutate Incus
  restricted certificate project grants internally, because Incus calls the
  access boundary a project. The duplicate user-first
  `sandcastle-admin user grant <user> <tenant>` surface has been removed so
  tenant access has one canonical admin shape.
- Bare machine resolution for existing-machine operations now searches across
  the current tenant only when no current project is configured. If exactly one
  project contains the machine name, `connect`/`status`/`delete` use it; if
  multiple projects match, the CLI returns an ambiguity error and requires an
  explicit `project/machine`. When `SANDCASTLE_PROJECT` is set, bare names stay
  scoped to that project.
- User project management now lives under `sandcastle project
  list/create/status/delete`. Projects remain lightweight tenant metadata only.
  Project status intentionally reports tenant, project, and machine count rather
  than infrastructure checks, because v1 projects do not own Incus networks,
  DNS, storage, or CA state. Delete requires `--yes`, rejects `default`, and
  checks the tenant's machine metadata to ensure the project is empty. There is
  no `createdBy` value yet for user-created projects because the current local
  config identifies the tenant but not the human principal.
- I cleaned up several command help strings and e2e fixture references that
  still said owner/project/sandbox. The e2e tests that create machines now use
  the v1 instance and DNS shape (`default-{machine}` or `{project}-{machine}`,
  `{machine}.default.{tenant}` / `{machine}.{project}.{tenant}`).
- Updated the user-facing usage docs, quickstart snippets, README overview, and
  `.env.default` examples away from `SANDCASTLE_OWNER`, `add`/`enter`/`rm`/
  `inspect`/`ls`, and sandbox wording toward tenant/project/machine command
  shape. Later docs passes replaced the deeper implementation and e2e planning
  docs with the current tenant/project/machine shape.
- Disposable VM e2e with Debian 13's Incus 6.0.4 exposed that tenant storage
  pool creation cannot pass a derived `source` path for `dir` pools: Incus does
  not create that nested path before volume file upload. The creator now omits
  `source` for `dir` pools and lets Incus manage the pool path; non-dir pools
  still derive a per-tenant source from the admin pool.
- E2E fixtures and diagnostics now use tenant references and tenant local-DNS
  state. Safe e2e tiers pass after the latest CLI-shape work:
  `go test ./...`, `scripts/e2e.sh unit`, `scripts/e2e.sh gated`, and
  `scripts/e2e.sh local`. Full destructive tiers still need more environment
  setup than the host currently provides: image-dependent tests require
  `SANDCASTLE_E2E_BASE_IMAGE_SOURCE` and `SANDCASTLE_E2E_AI_IMAGE_SOURCE`, the
  restricted tier requires a non-local HTTPS Incus remote, and Tailscale/public
  route tiers require external credentials or DNS inputs.
- Disposable VM e2e on Debian 13/Incus 6.0.4 also exposed that SDK image copy
  from the default project into a tenant project fails over a local Unix socket
  with `The source server isn't listening on the network`. Tenant image
  propagation now uses Incus relay mode for project image copies. This is less
  efficient than pull mode for remote-to-remote copies, but it works for the
  local-admin path and keeps behavior deterministic across Unix-socket and HTTPS
  remotes.
- The same Incus 6.0.4 VM does not support the storage volume file API used by
  newer Incus clients for custom volumes (`CreateStorageVolumeFile`/
  `GetStorageVolumeFile` return `not found`). For local dir-backed storage
  volumes, the Incus adapter now falls back to reading/writing the project
  volume path under `/var/lib/incus/storage-pools/<pool>/custom/<project>_<vol>`
  after the SDK returns 404. HTTPS remotes and newer servers still use the SDK
  path first.
- Tenant private bridge names can no longer be simple 15-character truncations
  of long Incus project names. Linux bridge names have a 15-character limit, but
  truncation made e2e tenants like `sc-tenant-e2e-local...` collide on
  `sc-tenant-e2e-l`, causing sidecar IP/subnet validation failures. Long names
  now use a stable `sc-` plus 12-hex hash bridge name.
- I created disposable Incus VMs twice and seeded nested Incus images to keep
  exercising `scripts/e2e.sh local-vm`. Docker-based image building filled the
  host's 9.6 GB root filesystem, so I switched to a lean Incus-native image seed
  by copying `images:debian/13`, installing only sidecar runtime packages, and
  publishing `sandcastle/base:latest`/`sandcastle/ai:latest`. Even with that,
  nested tenant creation and image copies filled the host root filesystem and
  forced the VM into Incus `ERROR`; both disposable VMs were deleted to restore
  space. Current verified host gates after these fixes: `go test ./...`,
  `scripts/e2e.sh unit`, `scripts/e2e.sh gated`, and `scripts/e2e.sh local`.
- Host Incus e2e needed the same image shape as the Debian base Dockerfile.
  Using a quick Ubuntu cloud image seed let Caddy/CoreDNS install, but it already
  had UID/GID 1000 allocated and caused tenant user bootstrap to silently miss
  the expected Linux user in one detached create path. I replaced the host seed
  with an Incus-native Debian 13 container image customized with the base runtime
  packages and `sandcastle-bootstrap`, then pointed
  `sandcastle/base:latest`/`sandcastle/ai:latest` at that Debian image.
- Some base images expose `/etc/resolv.conf` as a symlink whose target does not
  exist when Incus' file API tries to overwrite it. Machine creation now falls
  back to an in-instance shell write for machine resolver configuration when
  `CreateInstanceFile("/etc/resolv.conf")` returns 404.
- With the Debian host seed, the destructive `incus` tier passed the CLI
  create/detach, default create/connect, connect, host override, image sync,
  local trust, tenant purge, tenant listing, and machine lifecycle cases.
  Remaining host `incus` failures from run `e2e-incus-20260521-1051`:
  infrastructure route broker mTLS probe got connection refused, and tenant DNS
  lookup from one machine timed out.
- Tenant DNS timeout was caused by Debian Incus images running
  `systemd-resolved`, which binds port 53 on loopback and prevents CoreDNS from
  binding `:53`. DNS sidecar CoreDNS restart now stops and masks
  `systemd-resolved` before launching CoreDNS. Verified with
  `TestTenantDNSE2E` on host Incus run `e2e-dns-fix-20260521-1100`.
- Infrastructure now uploads and runs `sandcastle-admin` for the route broker
  service (`sandcastle-admin route-broker serve`). `SANDCASTLE_ADMIN_BIN` is the
  preferred binary source, with `SANDCASTLE_BIN` as a local fallback for older
  setups. The e2e infrastructure tests build `./cmd/sandcastle-admin` for the
  target architecture before creating the sidecars.
- The route broker sidecar uses the mounted Incus Unix socket directly when it
  is serving inside infrastructure. Socket-mounted broker instances are marked
  privileged because an unprivileged container root cannot open the host
  `/var/lib/incus/unix.socket`; Caddy remains unprivileged and does not receive
  that mount.
- Tenant listing skips managed projects whose Sandcastle metadata kind is not
  `tenant`, so infrastructure projects (`kind=infrastructure`) no longer make
  `tenant list`/e2e diagnostics fail while parsing tenant summaries.
- Route broker mutation e2e now uses canonical `tenant/default/machine` target
  references. The host route-broker tier passed as
  `e2e-route-broker-20260521-1212`, including unowned-target 403, DNS-proof 400,
  add/list/remove 201/200, and route cleanup checks.
- The broader host `incus` tier passed again as `e2e-incus-20260521-1220` after
  the route broker service and route ingress fixes. The broker mutation path now
  uses the default host Incus socket mount, and the dedicated `route-broker` tier
  covers that socket-mounted path.
- Added `scripts/e2e-local-vm.sh` as a reusable host-side harness for the
  VM-only local mutation tier. It launches a disposable local Incus VM, installs
  Go, mise, and nested Incus, copies the checkout, seeds nested image aliases
  from host `sandcastle/base:latest` and `sandcastle/ai:latest`, starts root's
  systemd user service manager for the local DNS service test, and runs
  `scripts/e2e.sh local-vm` inside the VM. This replaces prior ad hoc VM setup
  attempts and gives the remaining disk-constrained verification a repeatable
  entry point.
- Debian 13/Incus 6.0.4 also returned success for custom-volume file uploads on
  local dir-backed tenant pools while leaving the CA files empty. When running
  against local dir-backed volumes as root, the adapter now writes directly to
  `/var/lib/incus/storage-pools/<pool>/custom/<project>_<vol>` instead of using
  the broken upload path. The host-side VM harness passed end-to-end as
  `e2e-local-vm-20260521-122306`, covering host overrides, local DNS service
  install/reload/uninstall, local trust, and platform trust.
- The same custom-volume subdirectory fix initially regressed host e2e runs
  executed as a non-root Incus admin user: the SDK returned 404 for volume-file
  directory creation, but the process could not write `/var/lib/incus` directly.
  Machine creation now falls back to a short-lived storage helper container in
  the tenant project. The helper mounts the top-level `sc-home` and
  `sc-workspace` custom volumes, creates the requested subdirectories with UID
  and GID 1000, then is deleted before the real machine is created. This keeps
  non-root local Incus, root VM, and newer remote Incus paths working. Verified
  host tiers: `incus` passed as `e2e-20260521-123440-18835`; `route-broker`
  passed as `e2e-20260521-123909-31423`; the host-side VM harness passed again
  as `e2e-local-vm-20260521-124224`.
- Removed stale user-as-tenant bootstrap output from `sandcastle-admin user
  create/token`. The human output now tells developers to run `sc remote add
  ...` and set the default tenant explicitly after access is granted, while
  `sc remote add --tenant` remains the one-step handoff path when the tenant is
  already known.
- Replaced the old implementation and e2e planning docs with the current
  tenant/project/machine shape. The docs now describe tenant-scoped DNS,
  Tailscale, local trust, route broker authorization by restricted certificate
  grants, the disposable VM harness, and the current command names instead of
  owner/project/sandbox milestones.
- Renamed the route broker mTLS principal identity from `Owner` to `User`.
  Authorization was already grant-based; this removes the misleading implication
  that the user name must own or match the target tenant. Route metadata keeps
  `CreatedBy` as the audit field.
- Renamed the remaining private Go `sandbox` vocabulary to `machine` across the
  CLI, Incus adapter, cert, Caddy, route, and e2e helpers. The behavioral API
  was already machine-oriented; this pass removes stale type/function/file names
  such as `SandboxCreator`, `RenderSandbox`, and `sandbox_lifecycle.go`.
- Cleaned up more private e2e/test vocabulary after the public docs pass:
  restricted-user, Tailscale, route-broker, local DNS, and cleanup fixtures now
  distinguish human users from tenants instead of using `owner` as a generic
  variable name. This was behavior-preserving, but it makes the grant-based
  route broker model harder to misread.
- Renamed the private machine connection path from `enter`/`add` vocabulary to
  `connect`/`create`: `PlanConnect`, `ConnectPlan`, `MachineConnector`, and the
  e2e runner's CLI test names now match the public command surface. The executor
  still delegates to Incus `ExecInstance`; only Sandcastle's internal naming
  changed.
- Renamed the tenant lifecycle Incus adapters from project-facing store,
  creator, deleter, and SSH-key updater names to tenant-facing names. Literal
  Incus API methods and struct fields still use project terminology where Incus
  itself exposes projects, but Sandcastle-facing dependencies now read as
  tenant stores, creators, and resources.
- Verified the tenant adapter rename against full host Incus, dedicated route
  broker, and disposable local VM tiers on 2026-05-21:
  `e2e-20260521-134205-85388`, `e2e-20260521-134629-98093`, and
  `e2e-local-vm-20260521-134918`.
- Renamed private imports of `internal/tenant` from the old `project` alias to
  `tenant`, and renamed the tenant lifecycle/DNS/listing e2e tests plus the
  `scripts/e2e.sh incus` regex to match. Incus SDK method names still say
  `Project` where they call Incus projects directly.
- Verified the tenant import/test rename against safe and destructive tiers on
  2026-05-21: `scripts/e2e.sh local` run `e2e-20260521-135906-105611`, host
  `incus` run `e2e-20260521-135924-105773`, route-broker run
  `e2e-20260521-140348-118342`, and disposable VM run
  `e2e-local-vm-20260521-140634`.
- Local trust help, output, and adapter errors now say tenant CA instead of
  project CA. The command was already tenant-scoped; this only fixes stale
  wording and docs examples that omitted the tenant argument during cleanup.
- Refreshed the docs front doors after the tenant/machine rename pass. README
  now links the usage guide and admin/developer quickstart; the usage guide's
  tenant sections no longer call tenant delete/grant operations "project"
  operations; the quickstart uses the current private DNS shape
  `machine.project.tenant` and includes the tenant argument for Tailscale
  cleanup; the e2e plan examples now match the Debian 13 image aliases used by
  the runner examples.
- Renamed the route creation internals from `Add` vocabulary to `Create`
  vocabulary across the route planner, route broker client/server, Incus route
  manager, CLI wiring, and tests. The HTTP broker endpoint remains `POST
  /routes`; only Sandcastle's internal architecture now matches the public
  `sandcastle route create` command. I left host override internals as `Add`
  because that package is modeling local hosts-file entry addition rather than
  a public command verb.
- Verified that route create rename with `go test ./...`, `scripts/e2e.sh
  gated`, `scripts/e2e.sh local` run `e2e-20260521-142111-127490`, and the
  dedicated route broker mutation tier run `e2e-20260521-142123-127636`.
- Removed the obsolete `SANDCASTLE_E2E_DOMAIN_SUFFIX` harness/workflow setting.
  Tenant DNS suffixes are now always derived from tenant names, so keeping a
  separate e2e domain suffix suggested the superseded project-domain model.
- Verified the e2e harness cleanup with `go test ./...`, `scripts/e2e.sh
  gated`, `scripts/e2e.sh local` run `e2e-20260521-142654-132797`, and
  `scripts/e2e-local-vm.sh` run `e2e-local-vm-20260521-142730`.
- Removed the remaining public `ValidateProjectDomain` helper and moved domain
  validation directly into `ValidateTenantDNSSuffix`. Tenant DNS suffixes are
  intentionally single-label tenant-derived names, not configurable project
  domains. I also refreshed the low-level Caddy, certificate, and local DNS
  fixtures away from `project-tld` examples so test vocabulary matches the
  tenant DNS model.
- Verified the tenant DNS validator cleanup with focused domain/local DNS/cert
  tests, `go test ./...`, `scripts/e2e.sh gated`, `scripts/e2e.sh local` run
  `e2e-20260521-143922-137741`, host `incus` run
  `e2e-20260521-143930-137902`, route-broker run
  `e2e-20260521-144404-150446`, and disposable VM run
  `e2e-local-vm-20260521-144651`.
- Changed `sandcastle host override list` from the misleading required
  `project` argument to `list [tenant]`. Host overrides are tenant-level
  machine metadata, so the command now defaults to the current tenant while
  still allowing an explicit tenant for admin-style inspection.
- Verified the host override list shape with `go test ./internal/cli
  ./internal/hostoverride`, `go test ./...`, `scripts/e2e.sh gated`,
  `scripts/e2e.sh local` run `e2e-20260521-145351-156029`, and targeted local
  Incus `TestHostOverrideE2E`.
- Renamed the remaining internal machine inspect planner/formatter/test
  vocabulary to status vocabulary. This is behavior-preserving, but it removes
  the last old command-shape name from the machine status path.
- Verified the machine status rename with `go test ./internal/machine
  ./internal/cli ./internal/e2e`, `go test ./...`, `scripts/e2e.sh gated`,
  `scripts/e2e.sh local` run `e2e-20260521-145647-159278`, and targeted local
  Incus `TestCLICreateDetachE2E` run `e2e-20260521-145657-000000000`.
- Changed `sandcastle tailscale up|status|down` to take an optional tenant
  argument. The Tailscale planners already defaulted an empty reference to the
  current tenant; the CLI now matches the spec's current-tenant user flow while
  still allowing explicit tenant references.
- Verified the Tailscale current-tenant CLI shape with `go test ./...`,
  `scripts/e2e.sh gated`, and `scripts/e2e.sh local` run
  `e2e-20260521-150242-162965`. The destructive Tailscale tier still requires
  a `SANDCASTLE_E2E_TAILSCALE_AUTHKEY` and route approval policy, which this
  environment does not provide.
- Removed the stale `.env.default` `SANDCASTLE_E2E_DOMAIN_SUFFIX` example that
  survived the earlier harness cleanup. The e2e harness already derives tenant
  DNS suffixes from tenant names, so leaving the old project-domain knob in the
  template would send operators toward a setting the code no longer reads.
- Renamed the admin/runtime "project prefix" config field to "Incus project
  prefix" and changed the documented env template to
  `SANDCASTLE_INCUS_PROJECT_PREFIX`. This prefix controls Incus project names
  like `sc-<tenant>`, not Sandcastle project namespaces. The loader still
  accepts the old `SANDCASTLE_PROJECT_PREFIX` as a fallback so existing local
  environments do not silently fall back to `sc`; the new env var wins when
  both are set.
- While updating the prefix docs, fixed older admin examples that still used
  `SANDCASTLE_PRIVATE_CIDR_POOL` and `SANDCASTLE_INFRASTRUCTURE_PROJECT`; the
  code reads `SANDCASTLE_CIDR_POOL` and `SANDCASTLE_INFRA_PROJECT`.
- Verified the Incus project prefix/env cleanup with `go test ./...`,
  `scripts/e2e.sh gated`, `scripts/e2e.sh local` run
  `e2e-20260521-150755-165557`, host `incus` run
  `e2e-20260521-150808-165654`, route-broker run
  `e2e-20260521-151232-178254`, and disposable VM run
  `e2e-local-vm-20260521-151522`.
- Renamed the private admin CLI command constructors and e2e test names from
  `AdminProject` to `AdminTenant`. The public command was already
  `sandcastle-admin tenant`; this removes stale internal vocabulary without
  changing command behavior.
- Verified the admin tenant private rename with `go test ./internal/cli
  ./internal/e2e`, `go test ./...`, `scripts/e2e.sh gated`, and
  `scripts/e2e.sh local` run `e2e-20260521-152337-183929`.
- Renamed a few remaining private tenant-summary helpers and local variables
  that still used project wording (`tailscale.projectSummary`, tenant status
  list results, route-broker e2e delete plans). Incus API variables that hold
  actual Incus projects remain project-named.
- Verified the tenant-summary helper rename with `go test ./internal/tailscale
  ./internal/tenant ./internal/e2e ./internal/incusx`, `go test ./...`,
  `scripts/e2e.sh gated`, and `scripts/e2e.sh local` run
  `e2e-20260521-152606-185485`.
- Renamed the machine lifecycle delete action from the private/internal
  `remove` value to `delete`. The public command has been
  `sandcastle delete`; keeping `remove` in JSON plans and executor messages
  was unnecessary command-shape drift.
- Verified the machine delete action rename with `go test ./internal/machine
  ./internal/incusx ./internal/cli ./internal/e2e`, `go test ./...`,
  `scripts/e2e.sh gated`, `scripts/e2e.sh local` run
  `e2e-20260521-153150-187628`, and targeted local Incus
  `TestMachineLifecycleE2E` run `e2e-20260521-153200-000000000`.
- Renamed public route and local host override delete internals from remove to
  delete vocabulary: `DeleteRequest`, `DeletePlan`, `PlanDelete`, manager
  `Delete`, broker `AuthorizeDelete`, CLI formatters, and e2e probe labels.
  I left low-level helpers named `RemoveHostsEntry`, `removeMachineExtraSAN`,
  `removeRouteIngressAttachment`, and `removeRouteBacklink` because those
  describe removing individual entries/devices from local files or Incus
  metadata, not the public command action.
- Tightened user-facing help/docs for the same slice: `sandcastle route delete`
  and `sandcastle host override delete` now say delete, `dns service
  uninstall` says uninstall instead of stop/remove, and the usage/e2e docs use
  delete wording for route and host override workflows.
- Verified the route/host override delete vocabulary slice with `go test
  ./internal/route ./internal/hostoverride ./internal/routebroker
  ./internal/incusx ./internal/cli ./internal/e2e`, `go test ./...`,
  `scripts/e2e.sh gated`, `scripts/e2e.sh local` run
  `e2e-20260521-153741-192726`, host `incus` run
  `e2e-20260521-154044-195768`, route-broker runs
  `e2e-20260521-154507-208246` and `e2e-20260521-155343-213621`, and
  disposable VM run `e2e-local-vm-20260521-154755`.
- Adjusted `sandcastle route create` and `sandcastle host override create`
  help text from "Plan..." to "Create..." because both commands mutate by
  default and only render plans when `--dry-run` is supplied. The dry-run flag
  text still uses plan vocabulary intentionally.
- Verified the create-help wording cleanup with `go test ./internal/cli
  ./internal/route ./internal/hostoverride`, `go test ./...`,
  `scripts/e2e.sh gated`, and `scripts/e2e.sh local` run
  `e2e-20260521-160128-222392`.
- Adjusted `sandcastle-admin user token` help text from "Plan..." to
  "Create..." because it creates a restricted certificate add token by default
  and only renders the token plan with `--dry-run`.
- Verified the user-token help cleanup with `go test ./internal/cli
  ./internal/usertrust`, `go test ./...`, `scripts/e2e.sh gated`, and
  `scripts/e2e.sh local` run `e2e-20260521-160343-223640`.
- Implemented the documented `sandcastle config unset <key>` command for the
  same local config keys supported by `config set`: `tenant`, `project`,
  `remote`, and `admin_remote`. The v1 spec already showed `config unset
  project`; the command was missing from the CLI. Unsetting clears only the
  selected key and preserves the rest of `~/.config/sandcastle/config.yml`.
- Updated the usage guide, admin/developer quickstart, and implementation plan
  for `config unset`.
- Verified `config unset` with `go test ./internal/cli ./internal/config`,
  `go test ./...`, `scripts/e2e.sh gated`, and `scripts/e2e.sh local` run
  `e2e-20260521-160626-224980`.
- Corrected stale docs that still described removed or unimplemented admin
  command shapes: `CONTEXT.md` now lists the implemented restricted-user
  surface (`user create`, `user token`, and tenant access commands), and the v1
  spec now states that admin `status` requires an explicit machine reference.
- Verified the docs audit cleanup with `go test ./...`, `scripts/e2e.sh
  gated`, and `scripts/e2e.sh local` run `e2e-20260521-160859-226933`.
- Wired `sandcastle-admin version` to the existing admin-specific version
  command helper instead of the generic user CLI version helper. The output
  payload remains unchanged; only admin help now says "Print the Sandcastle
  admin command version".
- Verified the admin version help cleanup with `go test ./internal/cli`, `go
  test ./...`, `scripts/e2e.sh gated`, and `scripts/e2e.sh local` run
  `e2e-20260521-161041-228322`.

## 2026-07-10 — #52: closing the last v1 name shapes (`<project>-infra`, `<project>-native`)

Deleting `naming.MachineIncusInstanceName` proved no code could build a v1
*instance* name. Three call sites could still build a v1 *project* name, so the
`<project>-infra` shape behind #51/#55 stayed constructable. All three are now
gone, and `naming.TenantInfraIncusProjectName` / `TenantNativeIncusProjectName`
are deleted — the build passing is the proof, and the CI guard keeps it that way.

**`sc incus` no longer derives its project from the tenant name.** It had a
fallback: use the live v2 summary if one exists, else derive `sc-<tenant>` and
append `-infra`/`-native`. That fallback is precisely the bug pattern — a name
computed from a string rather than read from live state. It now calls
`requireV2Tenant` and reads `summary.V2IncusProjectName` / `summary.InfraProject`.
No tenant means a clear error, not a request against a project that never existed.

**`sc incus-native` is deleted.** It scoped `incus` to the tenant's freeform
project, which only existed beside the v1 main project. Under v2 freeform *is*
the model, so the command had become a verbatim alias for `sc incus`. Alternative
considered: keep it as an alias. Rejected — it documents a project split that no
longer exists. `sc incus` and `sc incus-infra` remain.

**`sc-adm tenant grant` never granted access to the tenant's machines.**
`usertrust.tenantAccessProjects` restricted a tenant user's cert to
`<prefix>-<tenant>`, `…-infra` and `…-native`. Under v2 only the first exists —
and it is the *infra* project, holding the sidecar. The machines live in the app
project `<prefix>-<tenant>-<project>`, which was never on the list. So a granted
user received access to the sidecar project plus two projects that do not exist,
and none to their own machines.

I first assumed Incus would reject a restriction naming a nonexistent project,
and wrote that into the commit message. Verified on majestix: it does **not** —
`incus config trust add v52probe-tok --restricted --projects sc2-e2edns-infra`
exits 0. The grant therefore failed quietly, in the house style (cf.
`docs/e2e-sc2.md`, "Problems encountered"): the command succeeded and produced a
certificate that could not see the tenant's machines. Claim corrected.

It now grants the infra project plus `-default`, matching the `RestrictedProjects`
that `tenant.CreatePlanV2` already grants at provisioning time. Verified live:
against tenant `e2edns` on majestix, `main` planned
`[sc2-e2edns, sc2-e2edns-infra, sc2-e2edns-native]` while the branch plans
`[sc2-e2edns, sc2-e2edns-default]`; only the latter two projects exist, and
`sc2-e2edns-default` is where `web` and `vm1` actually live.

**A latent limit, recorded rather than fixed:** `ValidateTenantName` accepts a
53-character tenant, sized for v1's 7-char `-native` suffix. v2 appends
`-default` (8), so `V2ProjectName` rejects the resulting 64-char project name.
It fails closed — the tenant name is rejected at plan time with a clear message,
not truncated — so this is a usability wart, not a correctness bug.
`TestV2ProjectNameLengthLimit` pins the fail-closed property.

## 2026-07-10 — e2e regression: `sc-adm tenant delete --yes` stopped parsing

Found by Phase 0 of the `docs/e2e-sc2.md` run, immediately: the teardown command
exits 1 with `unknown flag: --yes`.

Commit `842d3e5` (v1 package deletion, #52) dropped
`command.Flags().BoolVar(&yes, "yes", …)` from `newAdminTenantDeleteCommand`
while leaving `var yes bool` and the `confirmMissingYes(…, "refusing to delete
without --yes")` call that reads it. The result was the worst of both: the flag
the error message tells you to pass did not exist, so the command could not be
run non-interactively at all. Nothing caught it — the unit tests exercise the
delete *plan*, not the flag set, and `--yes` is invisible to a plan test.

Fix: re-register the flag. Guard: `TestDestructiveCommandsRegisterYes` walks both
command trees and asserts that every `delete`/`destroy`/`purge` command registers
`--yes`, and `TestYesFlagIsParsable` parses `--yes --purge` on the real command.
Verified the guard fails when the registration is removed again.

`dns uninstall` / `trust uninstall` are deliberately excluded from the walk: they
revert local host configuration (resolver entries, trust store) rather than
destroying server-side state, and have never taken `--yes`.

## 2026-07-10 — e2e Phase 4: three defects in `sc enroll`, all silent

Phase 4 (client enrollment) reported `connected tenant "e2edns" — config at … (0
project remote(s))` and exited **0**. Three independent bugs, each of which alone
makes enrollment produce a client that cannot see its own machines.

1. **`--incus-endpoint` defaulted to a hardcoded developer host**
   (`https://big.thieso2.dev:8443`). On any other install every per-project remote
   was added against the wrong Incus daemon, or failed with the opaque
   `Error: EOF`. The endpoint is now read off the base remote that the enrollment
   token just created (the token carries the daemon's addresses), and the flag has
   no default.

2. **`shortProjectName` hardcoded the `sc2-` install prefix.** An install created
   with `sc-adm install --prefix id` has projects `id-<tenant>-<project>`, so every
   project was filtered out and no project remote was ever added. It now anchors on
   the `-<tenant>-` segment, which is the part that is actually known. This means
   the multi-install coexistence the docs advertise never worked through `sc
   enroll` — only through `sc login`.

3. **No shared-identity fallback.** When the daemon already trusts this client's
   keypair (because another install on the same host enrolled it), it refuses to
   redeem a second token with `Failed to create certificate: Client is already
   trusted`. `addIncusRemoteWithToken` (the `sc login` path) has handled this for a
   while by adding the remote certificate-based; `sc enroll` called `incus remote
   add` directly and had no fallback. `sc enroll` now decodes the token's
   `addresses` and retries certificate-based against each in turn.

And the reason none of this was noticed: **enroll treated "added zero project
remotes" as success.** Each failure printed `Note: could not add remote …` to
stderr and continued. It now returns an error when the certificate can see
projects but not one remote could be added.

`incusTokenAddresses` decodes the base64-JSON Incus certificate add token. A token
it cannot parse yields no addresses rather than an error — every caller has a
fallback path.

## 2026-07-10 — e2e Phase 7c: two more defects

**`sc-adm tenant set-ssh-key` never worked against a real Incus daemon.**
`TenantSSHKeyManager.writeTenantMetadataFile` calls
`CreateStorageVolumeFile(pool, volumeType, volumeName, …)` — and passed the
**Incus project name** in the `pool` position. Real Incus answers
`Storage pool not found`; so does the share source validation at
`SourceDirectoryStatus`. The unit tests never noticed because the fake
`CreateStorageVolumeFile` accepted any string for `pool`.

Fix: `TenantSSHKeyManager` gains a `StoragePool` field (empty ⇒
`config.DefaultStoragePool`), wired from `adminConfig.StoragePool` at every
construction site. The test fake now **rejects** a pool name that looks like an
Incus project, reproducing the daemon's error; verified it fails when the old
argument is put back. A fake that accepts anything tests nothing.

**`sc c` broke after any delete + recreate.** Tenant machines are ephemeral and
their IPs recycle inside the tenant's `/24`, so the host key for a given IP
changes. `sc c` passed `StrictHostKeyChecking=accept-new` against the user's own
`~/.ssh/known_hosts`, so the second connect to a recycled IP died with
`Host key verification failed` and the user had to hand-edit the file.

v1's connect pruned the entry first (`localKnownHostsManager.RefreshMachine`),
but that manager was only ever wired to `machine.CreatePlan` — the v1 path. The
v2 connect in `create_v2.go` never called it, so this was a **pre-existing v2
gap**, not a #52 regression; deleting `known_hosts.go` removed code that was
already dead for v2.

Fix: keep Sandcastle host keys in `~/.config/sandcastle/known_hosts` and drop the
entry for the target IP before connecting. Same posture as v1, and the user's own
`known_hosts` is neither polluted nor invalidated.

## 2026-07-10 — `sc-adm tenant set-ssh-key` rewritten for v2

Chasing the storage-pool bug revealed the command was wrong end to end for v2. It
wrote the key into a `workspace` metadata file (`.sandcastle/ssh_public_key`) on
the **infra** project — where the volume does not exist — and nothing ever read
that file back: `readTenantSSHKey` had no callers left.

The authoritative store is the infra project's `user.sandcastle.v2.sshkey`
config. `ensureV2AppProfile` renders it into each app project's default-profile
cloud-init, and that is what a newly created machine authorizes.

`TenantCreator.SetTenantSSHKeyV2` now updates that config and re-renders the
default profile of every app project of the tenant. The CLI resolves the tenant's
real project list from its summary instead of deriving one Incus project name.
The command prints what it changed and states plainly that existing machines keep
the key they were created with (cloud-init runs once) — rotating a *running*
machine is `MachineSSHKeyReconciler`'s job, via the Auth App.

Deleted as dead: `TenantSSHKeyManager.SetTenantSSHKey`, `readTenantSSHKey`,
`tenantSSHPublicKeyFile`, and the corresponding interface methods in
`tenant.TenantUpdater` and `authapp`.

Verified live on majestix: `sc-adm tenant set-ssh-key e2edns <client key>` puts
the key in `sc2-e2edns-default`'s default profile, after which `sc c lc2` creates
a machine and lands a shell as `dev`.

## 2026-07-10 — e2e Phase 9: `sc login` could not enroll, and admin commands ignored the install prefix

**`sc login` died with `incus remote add: exit status 1`.** Same root cause as the
`sc enroll` bug: the daemon already trusted this client's keypair, so it refused
to redeem the join token. `addIncusRemoteWithToken` did have a certificate-based
fallback, but it was gated on `incusAddress != ""` — the sidecar's tailnet
address, which is unknown until the sidecar has joined the tailnet. On a first
login (sidecar still joining) the fallback was skipped and login failed.

`trustedClientRemoteURLs` now tries the tailnet address first (ADR-0017) and then
each address the token itself advertises.

**`sc-adm tenant status <t>` reported another install's tenant.** Two installs
share one Incus daemon (`sc2-` and `id-`), so a same-named tenant exists once per
install. The user CLI scopes by install prefix; the admin path did not. Live:
`SANDCASTLE_INCUS_PROJECT_PREFIX=sc2 sc-adm tenant status e2edns` printed
`Incus project: id-e2edns-default` and install B's CIDR. `sc-adm tenant list <t>`
and the new `set-ssh-key` resolved the same way.

All three now use `tenant.ListForPrefix` / `GetStatusWithTopologyForPrefix` with
`adminConfig.IncusProjectPrefix`. `sc-adm tenant list` with no argument still
lists every install's tenants — that is useful; resolving *one* tenant by name is
not. The regression test models both installs with the *other* one first, because
an unscoped lookup takes the first match: with the fixture the other way round the
test passes even against the bug.

**Not a bug:** `sc status` prints an empty `Private CIDR` for a tenant user. The
CIDR lives on the infra project, which a restricted tenant certificate cannot
read, and the check says so explicitly:
`cidr: unknown (stored on the infra project …, which a tenant certificate cannot read)`.

## 2026-07-10 — e2e Phase 8c: the whole tenant-metadata-file mechanism was write-only

Phase 8c (machine HTTPS) failed because machines in a project created *after* the
tenant had `SIGNER=http://:9443` in `/etc/sandcastle/machine.env`: an empty
sidecar address. `CreateProjectV2` built the profile plan without `DNSAddress`, so
the cloud-init that installs the machine's Caddy pointed it at nothing and no leaf
was ever fetched. **My own `SetTenantSSHKeyV2` copied the same omission.**

`tenant.DNSAddressForCIDR` now derives it from the infra project's CIDR, both call
sites use it, and `ensureV2AppProfile` refuses to render a profile with an empty
address rather than emitting `http://:9443`.

Pulling that thread exposed that the tenant-metadata files on the workspace volume
are **write-only**, across the board:

- `readTenantSSHKey`, `readTenantProjects`, `readTenantUnixUser`: zero callers.
- `readTenantStorageShares` (the one live reader) passed the Incus project name in
  the `pool` argument. Incus answers 404, and `isMissingTenantMetadata` maps 404 to
  "no metadata" — so **every tenant read as having zero shares**.
- `Summary.Projects` is built from Incus projects and never carried the settings,
  so `sc project set-cloud-identity` / `set-docker-autostart` wrote a file nobody
  read: no-ops that printed a plan.
- `sc project delete` only rewrote that same file. The Incus project, its volumes
  and its machines survived a "successful" delete.

So: project settings now live on the project's own Incus project config
(`user.sandcastle.v2.cloud-identity`, `…docker-autostart`), which `v2Summaries`
reads back; the shares reader takes a real pool; `sc project delete` deletes the
Incus project (`TenantDeleter.DeleteProjectV2`); and the dead readers/writers are
gone, along with `ensureTenantUnixUserForMachineCreate`, which had no callers.

A tenant's restricted certificate may not delete an Incus project, and the tenant
plane exposes `POST /api/projects` with no delete. `sc project delete` now says
that in words instead of surfacing `Certificate is restricted`, and
**`sc-adm project delete <tenant> <project>`** is the working path — symmetric
with `sc-adm project create`, refusing the default project. Adding a destructive
DELETE endpoint to the Auth App is a product decision, not one to make mid-e2e.

### The trap that hid all of it for an hour

`incus file push` onto a **running** executable fails with `text file busy`, and I
was discarding its stderr. The auth-app appliance ran the original pre-fix binary
for the whole middle of this run, so several "the fix didn't work" conclusions were
about code that was never deployed. `scratchpad/e2e/deploy.sh` now stops the unit,
pushes beside the target and renames over it (rename leaves the running process on
the old inode), and **verifies every binary by sha256**, failing loudly on a stale
one.

## 2026-07-10 — #68: Tenant Storage Shares made to work under v2

Five bugs, four of them the v1 single-volume layout, one a missing registry read.
All found and fixed against the running majestix stack.

1. **Source Incus project.** The reconciler derived `<prefix>-<sourceTenant>` (the
   infra project, no workspace volume). Now `<prefix>-<sourceTenant>-<sourceProject>`.
   The prefix is taken from the recipient summary's `InfraProject`, not
   `r.Admin.IncusProjectPrefix`: the user-facing default "sc" maps to the real v2
   prefix "sc2", so the admin value would miss the real projects.
2. **Volume name.** Every share store access used `tenant.WorkspaceVolumeName`
   (`"sc-workspace"`, v1). v2 volumes are `workspace` (`V2WorkspaceVolumeName`), so
   reads 404'd → "source directory does not exist" and "zero shares".
3. **In-volume path.** The source check looked at `<project>/<dir>`; each v2
   project has its own volume mounted at `/workspace`, so it is `<dir>` alone.
   Dropped the redundant `project` parameter from the SourceStatus/Exists interface
   so the v1 shape cannot be passed again.
4. **Host bind-mount path.** `HostSourcePath` used the Incus project as the
   storage-pool path segment and appended a per-project subdirectory. Corrected to
   `/var/lib/incus/storage-pools/<pool>/custom/<sourceIncusProject>_workspace/<dir>`,
   verified against the on-disk layout on majestix.
5. **Registry never read into the summary.** `tenant.ListForPrefix` leaves
   `Summary.StorageShares` empty, and the auth-app's `findTenantSummary` returned it
   as-is. The reconciler mounts exactly what is in `StorageShares`, so a real accept
   mounted nothing (only the dry-run branches patched it in). `findTenantSummary`
   now reads the registry via the share store.

`sc status` share counts were computed client-side from the empty summaries, and
the inbound counts need every other tenant's registry — which only the server can
read. `sc status` now fills the counts from the Auth App's list endpoints
(`ListShares`/`ListInboundShares`/`ListShareOffers`).

The test fakes were the reason none of this failed in CI: they accepted any
`incusProject`/`dir`/`pool`. The share-package fake now records every source
lookup so a test can assert the resolved project and path, and a reconcile test
pins the full on-disk source path.

Verified live: thieso2 shares `/workspace/shared68` to octocat; octocat accepts;
reconcile adds a read-only disk device with source
`/var/lib/incus/storage-pools/default/custom/sc2-thieso2-default_workspace/shared68`;
the recipient reads the payload and cannot write it; `sc status` shows outbound 1
for thieso2 and inbound-accepted 1 for octocat.

Not addressed (separate from the layout): the share registry lives in a
user-writable `/workspace/.sandcastle/storage_shares` file, so a tenant can forge
its own registry. Moving it to non-mounted storage or project config is a
follow-up.

## 2026-07-10 — `sc share` gated off on v2 (#70), plumbing kept

After #68 made the share flow functional, the registry-location problem (#70 — a
tenant can rewrite its own `/workspace/.sandcastle/storage_shares`) means shares
are not safe to present as a supported v2 feature. Per the maintainer, `sc share`
is gated off rather than shipped:

- The `sc share` command tree gets a `PersistentPreRunE` returning
  "Tenant Storage Shares are not yet supported on v2 (tracked in #70). …". `--help`
  still works, so the subcommands stay discoverable.
- The Auth App's seven `/api/shares*` routes are pointed at a single handler that
  returns 501. Since every reconcile flows through these endpoints (there is no
  background/auto reconcile), this also neutralises the forged-registry → mount
  path via the sanctioned code.
- `sc status` / `sc-adm tenant status` no longer report share health or counts;
  the four share lines and the `shares:reconcile` check are removed.

Everything from #68/#69 stays in the tree, dormant behind the gate — the share
package, the reconciler, the Auth App handlers, and their unit tests. Ungating is
flipping the two gates back once the registry moves (#70). The CLI/endpoint
behaviour tests were replaced with two gate tests (`TestShareCommandsAreGatedOnV2`,
`TestShareEndpointsAreGatedOnV2`); the dormant plumbing keeps its own unit
coverage in `internal/share` and `internal/incusx`.
## 2026-07-15 — ADR-0020 stage 1: reference grammar parser (client only, additive)

Implementing the ADR-0020 machine-addressing model (spec:
`docs/design/machine-addressing-and-remote-naming.md`, wayfinder map #82). The
full spec is a coordinated change across client parser, remote-naming, the
first-login suffix-selection browser flow, an auth-DB claim table + provision, a
client-side lazy migration, and cross-install remote switching. Those pieces are
**interdependent** and cannot ship as safe isolated increments — e.g. making the
parser's bare-machine case error when no current project is set (per the spec)
would regress `sc create dev` *before* the reserved `default` project is removed
server-side. So this commit lands only the self-contained, unit-testable
foundation and defers the rest.

**What this commit does:**
- `parseV2MachineReference` now returns `(dnsSuffix, project, machine, err)` and
  parses the ADR-0020 grammar `[[dns-suffix:]project:]machine` (colon count 0/1/2
  selects scope). `naming.ValidateInstallSuffix` validates the install component.
- `resolveV2MachineReference` treats an install suffix equal to the current
  install's `summary.DNSSuffix` as a no-op, and returns a clear error for a
  *different* install (inline cross-install switching is not wired yet).
- Command help (`Use:`) for connect/create/machine-lifecycle/image-save updated to
  the new grammar.

**Deliberate deviations from the spec, deferred to later stages:**
1. **`tenant/` prefix kept.** ADR-0020 drops it, but removal is coupled to the
   coordinated change and would break existing callers/tests in isolation. Kept
   working (and dropped from `--help`); remove when the coordinated change lands.
2. **Bare-machine still defaults to `default` project.** ADR-0020 wants
   error-with-hint when no current project is set, but that depends on removing the
   reserved `default` project server-side (#85). Left as-is to avoid regressing
   `sc create dev`.
3. **Cross-install execution errors instead of switching remotes.** Remote
   switching (per-remote `INCUS_CONF`, fetching the target install's summary) is a
   separate infra change. Same-install suffixes resolve; cross-install is a clear
   error, matching the ADR-0020 "no magic, guide the user" ethos.
4. **`naming.ParseUserMachineRef` not yet retired** — done alongside the coordinated
   change so nothing else regresses.

**Not in this commit (remaining stages):** remote-naming scheme
(`dns-suffix-projectname`), first-login suffix+project browser form, auth-DB claim
table + provision changes, client-side lazy migration, cross-install remote
switching, and the `docs/e2e-sc2.md` / `docs/usage.html` updates. Each is a
follow-on. e2e (`SANDCASTLE_INCUS_E2E`) needs the live deployment and was not run.

**Code-review follow-ups (same stage, noted so they aren't lost):**
- The spec §6 *diagnostic* error ("`obelix-sc` is a remote, not a project — did you
  mean `obelix:sc:dev`?") is **not** implemented — it needs the not-yet-deployed
  remote-naming scheme to know remote names / known suffixes. Deferred with the
  remote-naming stage; the existing backwards-reference swap hint still fires.
- Same-install suffix resolution currently works **only while `summary.DNSSuffix`
  equals the value the user types**. Today `DNSSuffix` defaults to the *tenant name*
  (`tenant/list.go`), so `sc c <tenant>:proj:machine` resolves but `sc c obelix:…`
  does not until the first-login suffix-selection + claim-table stage sets an
  install-distinguishing suffix. The cross-install branch is otherwise correct.

## 2026-07-15 — ADR-0020 stage 3: remote naming from the DNS suffix (server core)

- `usertrust.RemoteNameForSuffixProject(suffix, project)` -> `<suffix>-<project>`
  (no omission, no `sc-` prefix). Added alongside the legacy
  `RemoteNameForAuthHostname`/`RemoteInstallName`, which stay as fallbacks so
  suffix-less/older installs still get a name and existing unit tests hold.
- `ensurePersonalTenantV2` now names the login remote `<suffix>-default`
  (prefers the suffix; falls back to the auth-hostname label, then the tenant
  name). `PersonalTenantResult.DNSSuffix` (stage 2) supplies the value; the client
  already prefers `result.RemoteName`.

**Deferred to the client-side stages (5-6):** the *per-project* client remotes
from `sc project create` (`<tenant>-<project>`) and `sc enroll`
(`<baseRemote>-<shortProject>`). Renaming these to `<suffix>-<project>` needs the
suffix threaded to the client (a new field on the project-create result +
client use), which is done holistically with cross-install switching (stage 5)
and lazy migration (stage 6). Until then those remotes keep their legacy names
and still work; only the login remote uses the new scheme.

## 2026-07-15 — ADR-0020 stage 4: DESCOPED (remove reserved `default` project)

**Decision: do not rip out the hardcoded `default` project.** Investigation showed
`naming.DefaultProjectName` is not a parser convenience — it is the actual name of
every tenant's first project, hardcoded across ~10 provisioning sites
(`create_plan_v2.go` default-project plan, `tenant_create_v2.go` profile/DNS,
`dns/render.go`, `machine_store.go`, token scoping, `usertrust/plan.go`). Making the
initial project user-named would thread a chosen name through all of provisioning —
a large, high-regression-risk change on the exact code path my notes warn "reports
success while doing nothing".

Its value to the addressing goal is nil: `sc c <suffix>:default:<machine>` resolves
identically whether the first project is named `default` or something else, and
ADR-0020 decision #85 already says existing `default` projects stay valid ordinary
names (no forced rename). The parser already satisfies the practical intent — bare
`machine` uses the config's **current project**, with `default` (a real, existing
project) as the fallback when it is unset; that fallback is safe and desirable, not
"magic" in the harmful sense.

**Kept as-is; not implemented:** user-named initial project at login and the
error-when-no-current-project behavior. If wanted later, it is its own focused
refactor + provisioning change, tracked separately from this coordinated branch.

## 2026-07-15 — ADR-0020 stages 1-3 validated LIVE on majestix (install A)

Deployed the stage-1..3 binary into `sc2-auth-app` (install A only; B untouched),
restarted, validated, then deleted the throwaway tenant and rolled the binary back.

- **Stage 1 (migration):** the deployed binary's `Migrate` created `dns_suffix_claims`
  in the live `auth.db` with the exact schema. (Caught the WAL trap — the main .db
  file lagged; had to pull `-wal`/`-shm` too. Recorded to memory.)
- **Stage 2 (claim):** logging in a fresh tenant `sctest --dns-suffix=sctest` inserted
  the claim row `('sctest','sctest','sctest')` during provisioning.
- **Stage 2 (uniqueness):** a second tenant `sctest2` claiming the same suffix was
  **rejected server-side in 15ms, before provisioning**, with the exact
  `SuffixClaimError` text: *"DNS suffix 'sctest' is already claimed on this install"*.
  This is the registry's core value, confirmed live.
- **Stage 3 (naming):** suffix flow confirmed live; the remote name is
  `<suffix>-default` by the unit-tested `RemoteNameForSuffixProject`. Not rendered on
  the client because the keyless throwaway sidecar never joined the tailnet, so
  `incus remote add` (which prints the name) couldn't run. Logic deployed + unit-tested
  + input verified; literal wire-string not captured (would need a tenant tailnet key).

**Gap surfaced:** `sc-adm tenant delete` does NOT call `ReleaseDNSSuffixClaim`, so the
deleted `sctest` left an orphan claim row (harmless post-rollback; `ReconcileDNSSuffixClaims`
would prune it once the reconcile is wired to a loop). Release-on-delete + a periodic
reconcile invocation are still to be wired (stage-1 built the functions; nothing calls
them yet). Left the orphan row rather than hand-edit the live WAL db.

## 2026-07-15 — ADR-0020: wired the DNS-suffix-claim reconcile (the gap found live)

The release-on-delete gap from the live-validation run is now closed via the
**reconcile path**, which is the architecturally-correct mechanism:

- `sc-adm tenant delete` runs client-side against Incus and has **no access to the
  auth database** (there is no auth-app tenant-delete endpoint — verified). So a
  *synchronous* `ReleaseDNSSuffixClaim` on delete is not feasible without adding an
  endpoint + an sc-adm round-trip. Out of scope; `ReleaseDNSSuffixClaim` stays for any
  future auth-app-mediated delete.
- Instead, `Serve` now starts `runSuffixClaimReconcileLoop` (every 5 min + one pass at
  startup) which lists the install's live tenants (`tenant.ListForPrefix`) and prunes
  claims whose tenant is gone. This matches the spec ("Incus is the source of truth for
  tenant existence; a reconcile prunes orphans"). Cleanup latency is ≤ one interval.
- **Safety:** `pruneOrphanSuffixClaims` never prunes on an **empty** live set, and
  `reconcileSuffixClaimsOnce` aborts (no prune) on a listing **error** — so a transient
  Incus hiccup can never wipe the registry. Both guards are unit-tested.

The orphan `sctest` claim left on majestix during validation would be pruned by this
loop on the next deploy of the new binary.

## 2026-07-15 — ADR-0020 stage 5: cross-install connect switching

`sc connect <suffix>:<project>:<machine>` now switches to the target install
instead of erroring:

- `resolveConnectTarget` (pure, unit-tested) decides: same-install (no switch) vs
  cross-install → target remote `<suffix>-<project>`, or a guidance error (ADR-0020
  §7: "connect never auto-provisions — log in/enroll first") when that remote isn't
  enrolled locally.
- `switchConfigToRemote` shallow-copies the commandConfig, points `INCUS_CONF` at the
  target remote's cert dir (`ResolveConfigPath`), and rebuilds the only two
  remote-scoped stores `runConnectV2` uses (`tenantStore` for the summary,
  `tenantCreator` for machine-ensure). SSH is a direct shell-out to the machine's
  private tailnet IP, so nothing else needs rebinding.
- The connect command detects the suffix, switches, re-fetches the target summary,
  and connects with the suffix stripped (`project:machine`).

**Not unit-testable (infra-bound):** the actual switch+connect needs two real
enrolled remotes with certs; only `resolveConnectTarget` is unit-tested. Needs live
validation against a two-install stack.

**Depends on new-scheme remote names.** Switching resolves the target as
`<suffix>-<project>`, so it works for remotes named the new way (login's
`<suffix>-default`, or post-migration). Legacy per-project remotes
(`<tenant>-<project>` from `sc project create`; `<baseRemote>-<short>` from
`sc enroll`) won't be found until they're renamed — that client-side rename + the
deferred stage-3 per-project naming both land in stage 6 (migration). Cross-install
switching for other reference-taking commands (create/lifecycle/image) is not wired
here — connect is the primary; they still hit the resolveV2MachineReference
cross-install error.

## 2026-07-15 — ADR-0020 stage 6: lazy remote migration at login

Renames a tenant's legacy incus remotes to `<suffix>-<project>` at next login (#88):

- `planRemoteMigration` (pure, unit-tested): a remote is this tenant's iff pinned to
  `sc2-<tenant>-<proj>`; new name `<suffix>-<proj>`; scoped by install endpoint so a
  same-named tenant on another install is never touched; idempotent (skips
  already-migrated + infra-pinned remotes).
- `migrateLegacyRemotes` (infra glue): reads the incus config, runs `incus remote
  rename` per plan; best-effort — a rename failure (e.g. target name already taken =
  the cross-install collision guard) is logged, never fails login.
- Threaded `DNSSuffix` through the device-poll wire (DeviceLogin → devicePollResponse
  → DevicePollResult) so a **re-login** (no `--dns-suffix`) still gets the tenant's
  stored suffix — which is exactly the migration case (existing tenants).
- Hooked into `sc login` after remote enrollment; runs only when the server returns a
  suffix. This also retro-fixes the stage-3 deferral: once a tenant's remotes are
  migrated, they carry `<suffix>-<project>` names, which is what stage-5 cross-install
  switching resolves against.

**Not unit-testable (infra-bound):** the `incus remote rename` execution + login hook;
only `planRemoteMigration` is unit-tested. Needs live validation against a client with
legacy remotes.

## 2026-07-15 — ADR-0020 stage 7: drop tenant/ prefix; retire ParseUserMachineRef

- Removed the legacy `tenant/` handling from `parseV2MachineReference`: `/` is no
  longer special (a slash now fails name validation). Grammar is purely
  `[[dns-suffix:]project:]machine`. `currentTenant` stays in the signature (callers
  pass it) but is unused. Parser tests updated (the two `tenant/` cases now expect
  errors).
- Deleted the unused `naming.ParseUserMachineRef` (no production caller — connect/
  create/lifecycle/image all go through `parseV2MachineReference`) and its 5 tests.
  `ProjectRef`/`ParseProjectRef` are kept — still used by `sc admin` machine commands.

One canonical machine-reference parser remains, as ADR-0020 §6 specified.

## 2026-07-15 — ADR-0020 code-review fixes (3 findings)

- **Migration scoping is now fail-safe** (spec §8): `planRemoteMigration` requires a
  non-empty `installEndpoint` and returns no plan without one — an unknown endpoint
  migrates NOTHING rather than widening scope to another install's same-named remotes.
  Endpoint match is mandatory, not `if != ""`.
- **Dropped the dead current-remote plumbing**: `migrateLegacyRemotes` no longer
  returns `updatedCurrent` and `remoteRename` loses `IsCurrent` (the login caller
  discarded it; config is never re-pointed at this hook, since the current remote is
  already the freshly-enrolled one). Simpler, honest.
- **Split the missing-remote guidance** (spec §7): `resolveConnectTarget` now takes an
  `installKnown` predicate — "install known, project not enrolled" → `sc enroll` /
  `sc project create`; "install never touched" → `sc login <host>`.
- **Added the §6 diagnostic**: `resolveV2MachineReference` now hints when the failed
  project token is actually an incus remote ("`obelix-sc` is a remote, not a project —
  reach another install with dns-suffix:project:machine"), without decoding the name.
- Collapsed a duplicated remote-name comment in `provision.go` (merge artifact).

## 2026-07-15 — ADR-0020 stages 5 & 6 live validation on majestix (part 1: stage 6)

Deployed the fixed client to `e2eclient` + new binary to install A's auth-app.

**Stage 6 (lazy migration) — VALIDATED live**, and it surfaced + fixed a real gap:
- First run: re-login `octocat` enrolled `octocat-default` (stage-3 naming works on the
  real client+server ✓), the migration hook ran best-effort (didn't fail login ✓), and
  endpoint-scoping held (`thieso2-web` at another endpoint untouched ✓). BUT the legacy
  base remote `sc-majestix-4502b206-thieso2-dev` **lingered**: `sc login` enrolls the
  canonical `<suffix>-default` *first*, so migration's rename collided
  (`Remote octocat-default already exists`) and left a redundant duplicate.
- **Fix:** `migrateLegacyRemotes` now, when the target already exists AND the legacy
  remote is a duplicate (same endpoint + pinned project), **removes** the legacy remote
  instead of leaving both; a target that exists for a *different* install is left and
  surfaced (never clobbered).
- Second run (fixed client): re-login `octocat` → `octocat-default` current, and the
  legacy `sc-majestix-...` remote is **removed**. Clean.

Stage 5 (cross-install) validation pending install-B auth-app deploy (separate authorization).

## 2026-07-15 — ADR-0020 stage 5 live validation on majestix (part 2)

Validated the cross-install switch on install A using two different-suffix tenants
(octocat current → thieso2 target; same daemon, different suffix/remote/sidecar —
identical switch code path). **Found + fixed a real bug:**

- **Error paths validated:** `sc c newbox:default:dev` → "unknown install … sc login".
- **Switch bug found:** `sc c thieso2:web:x` first errored "project web not found in
  tenant **octocat**" — `switchConfigToRemote` rebound the stores + remote but left
  `adminConfig.Tenant` unchanged, and `v2TenantSummary` keys off the tenant NAME, so it
  kept resolving the current tenant on the new remote.
- **Fix:** `switchConfigToRemote` now re-points `adminConfig.Tenant` to the target
  tenant, recovered from the target remote's pinned incus project
  (`<prefix>-<tenant>-<project>`) via `tenantFromPinnedProject` (pure, unit-tested;
  handles dashed tenants/projects + non-default install prefix).
- **Re-validated:** the same command now errors "project web not found in tenant
  **thieso2** (projects: default)" — the switch correctly lands on thieso2's summary.
  The machine-connect after the switch is unchanged runConnectV2 logic (not run to
  completion: no cross-install-reachable project here had a machine).

e2edns@B login was blocked by a PRE-EXISTING, unrelated failure ("reconcile User SSH
Public Key on machine api: script exited 1"), so the switch was validated via the A/A
different-suffix path instead of A→B.

## 2026-07-15 — shared tenant bridge must set `dns.mode=none` (same machine name across projects)

**Bug (reported live):** `sc c h2:t1` failed to start with
`Failed start validation for device "eth0": Instance DNS name "t1" already used on
network` when a machine named `t1` already existed in a sibling project `h1` of the
same tenant. All of a tenant's projects share one Incus bridge (`sc2-<tenant>`), and
Incus's managed bridge DNS enforces **per-network** uniqueness of the instance name
(`nic_bridged.go`, gated on `dns.mode != "none"`). Two `t1`s on one bridge collide even
though their sandcastle FQDNs (`t1.h1.<suffix>` / `t1.h2.<suffix>`) are distinct.

**Fix:** `ensureV2Bridge` now sets `dns.mode=none` on the tenant bridge, both at
creation and by converging pre-existing bridges on the next idempotent re-provision
(same pattern already used for the `raw.dnsmasq` CoreDNS resolver option). The bridge's
built-in DNS was already dead weight — ADR-0018 makes the sidecar CoreDNS the sole
authority and guests are pointed at it via `dhcp-option=6`, so disabling the bridge's
managed DNS loses nothing and DHCP is unaffected.

**Alternatives considered:** (a) set a project-qualified NIC `hostname`/DNS name per
instance (e.g. `t1-h1`) — rejected: more moving parts, and the bridge DNS is never
consulted anyway; (b) one bridge per project — rejected: a larger topology change that
would break the shared-CIDR/sidecar model. `dns.mode=none` is the minimal, correct fix.

**Live remediation for existing deployments:** the converge path only runs on tenant
re-provision, so an already-created bridge can be fixed immediately with
`incus network set sc2-<tenant> dns.mode=none` (admin remote), or by re-running tenant
provisioning.

## 2026-07-09 — Authoritative SSH host keys (`internal/hostkeys`)

Context: `ssh tubu.default.obelix` failed with `REMOTE HOST IDENTIFICATION HAS
CHANGED`. Root cause was not a bug in one place but a design gap; see
`docs/adr/0020-authoritative-ssh-host-keys.md` for the decisions. Notes on the
choices that were *not* in the original ask:

- **The reported failure did not come from `sc`.** `sc c` (v2) sshed to the raw
  private IP with `accept-new`, so it only ever wrote IP-keyed lines. The
  name-keyed line that went stale was written by a bare `ssh` long before. Fixing
  only `sc` would not have fixed the reported symptom; hence `~/.ssh/known_hosts`
  became the single source of truth rather than the per-tenant file.

- **`GetInstanceFile` works under a restricted tenant certificate.** This was
  verified against a live tenant before committing to the design — `localtrust`
  only exercised it with admin certs, and the whole approach collapses to
  trust-on-first-use if restricted certs are denied. They are not.

- **The tenant CIDR is unavailable to the tenant.** `tenant.Summary.PrivateCIDR`
  is empty for v2 (`internal/tenant/list.go` says so in a comment: the `kind=infra`
  project is not visible to a restricted cert), and Incus redacts network config,
  so `ipv4.address` on the bridge is unreadable too. The first implementation
  therefore silently never purged anything. `GetInstanceState` reports the
  machine's own address *and netmask*, which is authoritative and needs no infra
  visibility — `waitForV2InstanceIPv4` now returns both, and
  `MachineSubnetV2` exposes it to `purge`. Discovered only by running the thing.

- **All host key types must be recorded, not just ed25519.** OpenSSH's
  `UpdateHostKeys` (on by default) appends the server's *other* host keys after a
  successful auth. With one key recorded, a bare `ssh` re-added untagged rsa and
  ecdsa lines, the next `sc c` reclaimed and deleted them, and ssh added them
  back — a permanent ping-pong that showed up as `sc c` never being idempotent.
  Also discovered only by running it; the unit tests were green throughout.

- **`sc c --fix` was designed away.** The original ask was for a repair mode on
  `sc c`. Once connect reconciles unconditionally, the flag had nothing left to
  do; the work that genuinely needs a live-machine list (tagged orphans) moved to
  `sc ssh-key purge`.

- **Name reclamation is not optional.** OpenSSH uses the *first* matching line, so
  appending a correct entry beneath a stale one changes nothing. `sc` must remove
  untagged lines claiming names it owns. That is a deletion from the user's file,
  which is why every line `sc` writes carries a `# sandcastle:<remote>/<tenant>`
  marker and why removals are backed up and printed.

- **`confirmMissingYes` grew a `…Named` variant** so `purge` does not report
  "delete canceled" when a user declines. Existing callers are unchanged.

- Verified against the live `obelix` tenant: stale entry reclaimed, 23 recycled
  `10.123.0.x` entries purged, another install's 100 `10.248.x` entries and all
  foreign/`@cert-authority` lines untouched, `ssh tubu.default.obelix` and
  `ssh tubu.obelix` both working, `sc c` silent and idempotent on re-run,
  `sc ssh-key purge --dry-run` non-mutating, tagged orphans removed by
  `sc ssh-key purge --yes`. A VM without `incus-agent` (`macos-vm`) is correctly
  treated as live-but-unreadable and left alone.

## 2026-07-17 — Tenant-plane cert extension falls back to a fingerprint union (shared client identity)

Caught live in the full majestix e2e run: the SECOND tenant logging in from one
client (`--as octocat` after `--as e2edns`, one shared keypair) could create
machines but not projects — `sc project create` 500'd with `restricted
certificate "sandcastle-octocat" not found`. The daemon's one trust entry for
the keypair is named after the FIRST tenant's enrollment; login provisioning
grants the second tenant's projects into it by *fingerprint*
(`EnsureClientCertificate`), while the tenant plane's `Grant` looked up by
*name* only.

Decision: record the client's certificate on the user at device login
(`users.client_certificate_pem`, best-effort) and thread it into
`CreateTenantProject`; the grant now falls back to the same fingerprint union
the login path uses (`extendTenantCertificate` in `internal/incusx`). The
broker plane passes its mTLS peer certificate for the same reason.
Alternatives considered: (a) matching certs by "already holds this tenant's
projects" — rejected because it would silently widen *granted* users'
(`sc-adm tenant grant`) access on every project create; (b) making the name
lookup fingerprint-first — rejected because the bearer-token tenant plane has
no TLS peer, so a recorded certificate is needed anyway. Also noticed during
teardown: `tenant delete --purge` leaves the tenant's trust entries behind
(orphaned `sandcastle-<tenant>` certs with empty project lists) — not fixed
here, worth a follow-up issue.

## 2026-07-17 — Route-phase fixes from the majestix full e2e run

- **`sc route delete --yes` honored.** The flag was registered but never read;
  non-interactive deletes always refused. Gated the confirm on `!yes` (the
  pattern every other delete command uses) + regression tests.
- **Appliance redeploy no longer overwrites running executables.**
  `writeApplianceFile`/`writeBrokerFile` now push to a `.sandcastle-push` temp
  path and `mv -f` over the target. A direct overwrite of the running
  auth-app/caddy binary aborted the push stream with ETXTBSY ("broken pipe"),
  killing every redeploy of a live appliance. Alternative considered: stop all
  units before pushing — rejected, it turns every redeploy into a login outage;
  rename keeps services running on the old inode until restart.
- **`scripts/e2e-route.sh` made robust** (pipefail-safe IP poll, container-image
  pick instead of `head -1` grabbing the VM image, client-side name match since
  name-filtered `incus list <remote>:<name>` returns an empty set on Incus 7.2).
- **Routes-unavailable message corrected** to point at `--route-ingress acme`
  (redeploy), not `--ingress acme` (which would change the login front).
- Noted but not changed: with two tenants of one install enrolled from one
  client, the per-install `auth_tokens` map means the LAST login's token wins —
  `sc remote switch` between two same-install suffix remotes does not switch
  the bearer identity, so the other tenant's `sc route`/API calls 403 until a
  re-login. Security-correct but surprising; candidate for a per-(install,user)
  token map keyed off the remote.

## 2026-07-17 — Fixes for #112 / #113 / #114

- **#112 (bearer identity follows the remote).** New per-REMOTE config maps
  (`remote_auth_tokens`, `remote_brokers`, `remote_tenants`) recorded at login;
  `applyRemoteSwitch` prefers them over the hostname-keyed maps and re-points
  cfg.Tenant too — the live 403 turned out to be the *tenant* selection, not
  just the token, and the project re-pin also needed the right tenant to parse
  the pinned project. Hostname-keyed maps stay as fallback for logins predating
  the new maps (last-login-wins, the old behavior). Alternative considered:
  re-keying the existing maps with a migration — rejected, additive maps keep
  old configs working with zero migration code.
- **#113 (purge sweeps trust entries).** `DeletePlanV2.TrustEntry` carries the
  install-scoped certificate name; `DeleteTenantV2` deletes restricted client
  entries under that name whose project list is empty once the tenant's own
  projects are discounted — a shared-identity entry still granting another
  tenant survives. `TenantDeleteServer` gained `GetCertificates`/
  `DeleteCertificate` (certs are global, not project-scoped). Validated live
  on majestix 2026-07-17: a fresh keypair's first enrollment (throwaway tenant
  `trashcan`) created `sandcastle-trashcan`; the purge removed projects,
  bridge, AND the trust entry, with the shared-identity `sandcastle-e2edns`
  entry (still granting e2edns+octocat) untouched.
- **#114 (route refresh coverage).** `scripts/e2e-route.sh` step 5b pins a new
  static lease (`incus config device override … ipv4.address=…`), reboots the
  machine, and asserts the `scroute-…` device's `connect` follows and the route
  serves again — validated live on majestix (ALL PASS). The prune-vs-refresh
  race is now documented in Phase 7f as intended behavior (delete prunes within
  seconds; only a live machine's IP change refreshes in place) rather than
  changed with a prune grace period.

## 2026-07-17 — #115: fingerprint-first tenant-plane cert extension

`extendTenantCertificate` now extends the CALLER's certificate by fingerprint
first and never runs the name-bucket `Grant` when a recorded certificate
exists — the name bucket extended every same-named entry, re-arming dead
keypairs when tenant/project names recurred (observed live on majestix). The
tenant's other live devices are synced by the new `GrantTenantFleet` (same
name AND already holding a project in the tenant's namespace) because the
login-path union only grants the default project, so fingerprint-only would
have left a user's second device without new projects until who-knows-when.
Alternatives considered: (a) filtering inside `Grant` itself — rejected,
`sc-adm tenant grant` legitimately targets entries that hold none of the
tenant's projects yet (first grant), and multi-device users legitimately share
an entry name; (b) fingerprint-only without fleet sync — rejected per above.
Legacy name-based Grant remains only when no certificate was ever recorded
(pre-cacd832 logins) or the record is stale. Validated live with a
manufactured dead+fleet+caller matrix on majestix.

## 2026-07-17 — #115 addendum: admin-plane Grant hardened too

`TrustManager.Grant` now skips restricted client entries with ZERO projects
and errors (with remediation) when every same-named entry is dead. Rationale:
post-#113 a live device always holds ≥1 project (enrollment grants one; the
sweep removes entries a teardown emptied), so an empty entry is a dead keypair
by definition — extending it is the #115 re-arm, and `sc-adm tenant grant` /
the web grant were still doing it. Multi-device users and first-grants are
unaffected (their entries are non-empty). A silent all-skipped "success" was
rejected in favor of a loud error naming the cleanup command. Validated live
on majestix (synthetic dead+live pair under one name).

## 2026-07-17 — Regression test for fingerprint-first cert extension across install-prefix name drift

**Decision:** Added `internal/incusx/usertrust_ensure_test.go` exercising the *real*
`TrustManager.EnsureClientCertificate` (previously only ever faked in
`projectbroker_adapter_test.go`).

**Why:** Live incident on the `obelix` install — `sc project create scraper`
returned `500 … extend tenant certificate … restricted certificate
"sandcastle-obelix-thieso2" not found`. Root cause: the tenant's restricted
cert is trusted under name `sandcastle-tc2-thieso2` (enrolled when the install
used prefix `tc2`) while the broker now runs prefix `obelix` and plans for
`sandcastle-obelix-thieso2`. The name-based `Grant` can never find that name;
`EnsureClientCertificate` is supposed to reach the entry BY FINGERPRINT and
union the new project regardless of name. That path already exists (#115,
`cacd832`/`6d6f064`, shipped v0.1.1) — the failing broker on obelix was an old
`0.0.0-dev` binary built 2026-07-15, two days before the fix. The Incus project
itself (`obelix-thieso2-scraper`) was already created; only the cert-grant step
failed, so the live unblock was a one-line `incus config trust edit` adding the
project to fingerprint `d9f65d7ef320`.

**Alternatives considered:** (a) leave coverage at the adapter level (fake
return) — rejected, it never pinned that a name-mismatched entry is matched by
fingerprint, the exact property the incident depended on; (b) add a code fix —
none needed, the behaviour is already correct in-tree. The test locks it so a
future refactor of the fingerprint match can't silently regress to name-only.

## 2026-07-17 — v2 profile: zsh default shell + forwarded-agent indirection (herdr panes)

**Symptom:** `herdr --remote dev.scraper.obelix` panes had no working SSH agent
even though `ssh -A` to the machine worked. A terminal multiplexer's server
outlives the ssh session that seeded its `SSH_AUTH_SOCK`, so panes inherit a
`/tmp/ssh-*/agent.*` socket sshd has already deleted.

**Root cause (two layers):**
1. `V2DefaultProfileUserData` shipped **no** agent indirection at all — contrary
   to a stale memory that claimed it existed. It was never committed to
   `internal/`; the only copy lived in the legacy v1 `images/base/sandcastle-bootstrap`
   (not run on v2 machines), and even there with the wrong guards.
2. The live machine's personal `~/.zshrc` had a hand-rolled block that conflated
   *republish* and *consume* on one path: `export SSH_AUTH_SOCK=~/.ssh/ssh_auth_sock_known`
   plus `ln -sf "$SSH_AUTH_SOCK" ~/.ssh/ssh_auth_sock_known` guarded only by
   `[ -n "$SSH_AUTH_SOCK" ]`. A pane inheriting the (dangling) `_known` path
   re-linked it to itself → a **self-referential symlink** that broke the agent
   for every pane.

**Fix (code):** the profile now sets `shell: /bin/zsh`, installs `zsh` (per
"use zsh by default"), and writes three files via cloud-init `write_files`:
`/etc/ssh/sshrc` (republish each session's forwarded agent at the stable path
`~/.ssh/ssh_auth_sock`) and an append to both `/etc/zsh/zshrc` and
`/etc/bash.bashrc` (consume it). Guards: republish on **every** session (heals a
dangling link); consume via `-h` not `-S` (a pane opened while the link dangles
still follows it and heals in place). The shell only ever *reads* the link;
sshrc is the sole writer, from the real forwarded socket — eliminating the
self-link race the `~/.zshrc` version had.

**Alternatives considered:** (a) `/etc/profile.d/*.sh` for the consume snippet —
rejected, sourced only by login shells, and herdr panes are non-login; Debian's
`/etc/bash.bashrc` (and `/etc/zsh/zshrc`) cover both. (b) keep the shell-side
republish (as `~/.zshrc` did) — rejected, it is the source of the self-link bug;
splitting republish (root, sshrc, from the real socket) from consume (shell,
read-only) is what makes it robust. (c) b64-embed the scripts like the caddy
setup — unnecessary here, the snippets are short and a YAML-validity unit test
guards the indentation.

**Backfill:** the profile is rendered at project-create, so existing projects
keep the old (bash, no-indirection) user-data; `sc admin tenant ssh-key <tenant>
<key>` re-renders every project's profile for future machines. Already-running
machines need the files installed directly (done live on `dev.scraper.obelix`,
and its broken `~/.zshrc` block replaced with the read-only consume snippet).

## 2026-07-17 — `sc fix`: backfill machine fixups (agent-forwarding) + shared script source

**Context:** the zsh/agent-forwarding profile change (above) only reaches
machines built after it ships, because cloud-init runs once at first boot.
Existing machines need the files pushed in. After weighing a flag on `sc c`, a
`sc fix` verb, and a `sc machine check|fix|upgrade` subtree, the user chose a
dedicated `sc fix` verb.

**What shipped:**
- `sc fix [[remote:]project:]machine` (`internal/cli/fix.go`) — runs idempotent
  fixups from a small registry (`machineFixups`) over the connect SSH path, as
  the login user via `sudo sh -s` (script on stdin — nothing to shell-quote).
  `--check` runs the read-only variant; `--only <name>` filters. One fixup today:
  `agent-forwarding`.
- Extracted `withResolvedV2Machine` (reference rebind + cross-install switch) and
  `dialV2Machine` (ensure + ssh-wait + host-key argv) out of connect so `sc fix`
  and `sc connect` resolve/dial identically.
- Single source of truth: `sshAgentRepublishScript` + `sshAgentConsumeSnippet`
  consts in `create_plan_v2.go` now build BOTH the cloud-init `write_files` and
  the `SSHAgentForwardBackfillScript()`/`SSHAgentForwardCheckScript()` used by
  `sc fix`, so a repaired machine is byte-identical to a fresh one. A unit test
  pins that they share content.
- `scripts/fix-agent-forwarding.sh` stays as the admin fleet tool (whole project
  over `incus exec`, no SSH/agent needed); `sc fix` is the per-machine user path.

**Design choices worth noting:**
- `sc fix` reuses `dialV2Machine`, which *ensures* (creates/starts) the machine
  like `connect` — so `--check` may start a stopped machine. Accepted: you can't
  inspect a machine you can't reach, and the alternative (a separate
  existence-only lookup) added surface for little value. Documented in `--help`.
- Backfill/check **detect but never rewrite** a user's hand-rolled `~/.zshrc`
  agent block — rewriting a personal dotfile blind is worse than a loud warning.
- Fixup registry is a slice of `{name, summary, apply, check}` so adding the next
  backfill is one entry; `--only` and the help text derive from it.

## 2026-07-17 — `/.sc` shared-scripts volume (spec #127, tickets #128–#132)

**What shipped:** the per-tenant `/.sc` two-layer shared-scripts volume
(ADR-0022): per-app-project custom volumes `sc-platform` (→ `/.sc/platform`,
machine-RO) + `sc-local` (→ `/.sc/local`, tenant-RW), stable guarded shims in
cloud-init, a pure versioned payload builder (`tenant.PlatformPayload`),
payload population at tenant/project provisioning, `sc-adm tenant
payload-sync` for central updates, and `sc fix` retargeted to
shim-bootstrap + API-side payload converge.

**Decisions not in the spec (the spec left them open or said "implementation
choice"):**
- **Two volumes, not one volume with an ownership-enforced subtree.** RO/RW is
  enforced with `readonly=true` on the platform disk device — works
  identically for CT (RO bind) and VM (RO virtiofs), needs no idmap tricks,
  and mirrors how storage shares already do RO. One-volume/subtree would have
  hinged on `security.shifted` ownership semantics differing across CT/VM.
- **Per-project volumes realize the per-tenant contract** (exactly the
  home/workspace machinery ticket #129 pointed at). Multi-project tenants stay
  converged on the *platform* layer because every central write loops all app
  projects of the tenant; the *local* layer is per-project for now — accepted,
  single-project tenants are the primary target (spec's own scope note).
- **"Sidecar owns the payload" is realized as "the admin binary owns it".**
  The sidecar has (by design, ADR-0017) no Incus API credentials, and app-project
  volumes are only reachable via the API — so the canonical payload lives in
  the binary (`tenant.PlatformPayload`) and the sync runs wherever
  sandcastle-admin runs (tenant create, project create, `payload-sync`,
  `sc fix`). Same binary ships on the sidecar, so a future sidecar-resident
  sync is a wiring change, not a redesign.
- **Content-derived version (`sc-payload-<sha256/16>`)** instead of a manual
  counter: two binaries with identical scripts agree, any change (or an older
  binary = rollback) yields its own version, and "stable for a given payload"
  holds by construction. VERSION is written **last** so a partial write never
  advertises the new version.
- **The tenant's own restricted cert may write the platform volume** (that is
  how `sc fix` converges the payload without admin help). Platform "read-only
  to the tenant" is a *machine-mount* guarantee (accident prevention — the
  spec's user story 7), not an API ACL; the tenant already has root on their
  machines, so this adds no authority (trust analysis in ADR-0022/spec).
- **Legacy machines need one re-provision for the mounts**: `sc fix` installs
  shims + payload but cannot invent the profile's volume devices; the
  idempotent re-provision at login (or `sc-adm project create` path) re-renders
  the profile. Containers pick the new disks up live; VMs on next restart.
  Documented in Phase 6 of `docs/e2e-sc2.md`.
- Old inline consume snippets on legacy machines are left in place beside the
  new shims (identical logic, harmless duplication) — deleting user-visible rc
  content risked more than it bought.

## 2026-07-17 — boot scripts migrated onto /.sc (follow-up to #127)

`sandcastle-generalize` and `sandcastle-caddy-setup` no longer ship inline in
cloud-init: the profile bakes stable **boot shims** at the same
`/usr/local/sbin` paths and the bodies are platform-payload entries
(`sbin/machine-generalize`, `sbin/caddy-setup`). Decisions:

- **Boot shims wait up to 30s for the mount** before the fail-safe no-op — a
  VM's virtiofs share is mounted by the incus agent and can lag early
  cloud-init runcmd; the shell-rc shims don't need this (a login always comes
  later than boot).
- Boot shims source **only the platform layer** — machine bring-up is
  platform-managed; tenant customization stays in the shell-rc overlay. Sourcing
  tenant-writable code into a root boot path would also weaken the blast-radius
  story for no benefit.
- The runcmd paths are unchanged, so `sc image save` children and any tooling
  referencing `/usr/local/sbin/sandcastle-*` keep working; legacy machines keep
  their baked full scripts (still functional — no fixup added).
- Token/workload helpers were NOT migrated: no such baked script exists yet
  (workload identity isn't wired into provisioning), so there is nothing to move.

## 2026-07-17 — Phase 10 (self-update) validated live with v0.1.3; skew-note opt-out fix

10a–10f all validated on the majestix dual-install stack against the real
v0.1.3 release (details in docs/e2e-sc2.md Phase 10 status). Two findings:

- **Fixed here:** `SANDCASTLE_NO_UPDATE_NOTIFIER=1` silenced the release and
  sidecar notices but NOT the CLI↔deployment skew note (the gate lived in
  `NoticeDue`/`SidecarNoticeDue`, and `SkewWarning` had none). The gate now
  lives inside `update.SkewWarning` itself so every print site inherits it.
  Ships in v0.1.4.
- **Filed as #134 (not fixed here):** admin `tenant create` re-run without
  `--unix-user`/`--ssh-key` clobbers the tenant's stored user/key (additive
  metadata converge + defaulting request); needs the Existing*-reuse pattern
  the DNS suffix already has. The live e2edns tenant was repaired via the
  product path (unattended `sc login` re-provision on the new auth-app).

## 2026-07-20 — Machine IP selection keys off Incus NIC devices, not map order

`sc ls` reported `172.17.0.1` (docker0) for a Docker-running machine and the
correct tenant-bridge address for one without Docker. Cause: the three
selectors that read a machine's address from live state all iterated
`InstanceState.Network` — a Go map, so iteration order is randomized. Any
in-guest bridge was as likely to win as the real NIC; a 12-run loop returned
docker0 10 times. `firstGlobalIPv4` (routebackend) was the consequential one:
it feeds a Route's proxy device target, so a published route could point at a
container-local address that routes nowhere.

Now a single helper (`internal/incusx/instance_ipv4.go`) considers only NIC
devices from `ExpandedDevices`, in sorted device order.

- **Structural exclusion over a blocklist.** `docker0`/`br-*`/`veth*` are
  in-guest and never appear in `ExpandedDevices`. Enumerating bad interface
  names instead would need an edit per new container runtime.
- **MAC match before name match.** Resolving a NIC device to its guest
  interface by name alone works for containers (Incus names the veth) but
  breaks every VM, where the guest renames to `enp5s0`/`ens3` and the device key
  `eth0` is absent from the state map — it would have reported *no* address for
  VMs. Matching `hwaddr` / `volatile.<device>.hwaddr` first (case-insensitive)
  covers both; name is the fallback when no MAC is recorded.
- **Rejected: filtering by the tenant CIDR**, which is what `instanceTenantIPv4`
  (`dns_v2.go`) does and was the obvious reuse. That CIDR lives on the infra
  project and is unreadable from a tenant certificate — `Summary.PrivateCIDR` is
  empty for `sc ls` callers — so it would have blanked the IP column rather than
  fixed it. A comment in the new file records this so it isn't "improved" back.
- **No fallback to the old scan.** When an instance has no NIC device, the
  helper returns "" rather than any global address it can find: reporting
  nothing beats reporting whichever bridge sorted first. All three call sites
  have devices available, so this only affects genuinely NIC-less instances.
- `waitForV2InstanceIPv4` re-reads devices each poll pass — the instance may not
  exist on the first iteration, and a NIC can be hot-plugged mid-wait.

## 2026-07-21 — `sc payload-sync`: tenant self-service /.sc payload convergence

ADR-0022's payload sync existed only as `sc-adm tenant payload-sync <tenant>`,
which needs an admin remote and the install prefix — so a tenant could not
converge their own `/.sc/platform` after a CLI upgrade, even though the volume
lives inside projects they own. `sc payload-sync` (`internal/cli/payload_sync.go`)
adds the tenant-facing half; `TenantCreator.SyncVisiblePlatformPayload` is its
backend.

- **Certificate visibility as the target set, not a name prefix.** The admin
  path enumerates projects by `<prefix>-<tenant>-…` naming; the tenant path
  can't, because the tenant doesn't know (or have) the install prefix. A
  restricted Incus certificate only ever *lists* the projects it was granted,
  so `GetProjectNames()` is already scoped — the filter reduces to the metadata
  predicate (`kind=project` + `tenant=<name>`), factored out as
  `isV2AppProjectOfTenant` and now shared by both paths. Consequence: on a
  shared daemon the tenant converges exactly the projects they can reach,
  which is the correct blast radius.
- **`403` on an individual project is skipped, not fatal.** A listing entry the
  cert may name but not read is normal on a shared host; failing the whole sync
  on it would make the command unusable there. Every other `GetProject` error
  still aborts.
- **Empty result is an error, not a silent success.** Zero matching projects
  means a mistyped/misconfigured tenant far more often than "nothing to do", and
  a silent no-op would read as "payload converged".
- **No `--prefix` / `--remote` flags, deliberately.** Tenant and remote come
  from the login config; adding the admin knobs here would invite tenants to
  aim the command at projects their cert can't write anyway.
- `ensureProjectPlatformPayload` was extracted from
  `EnsureProjectPlatformPayload` so the admin sync, `sc fix`, and this share one
  per-project convergence body.

## 2026-07-21 — #134: tenant create re-run no longer clobbers stored user/key

`ProvisionReuseInputs` now returns a `ProvisionReuse` struct (the 5-tuple was
already a data clump) carrying the infra project's stored login unix user and
SSH public key beside CIDR/suffix/default-project; all three provisioning
sites (admin CLI, broker adapter, auth-app login) thread them into
`CreateRequest.ExistingUnixUser`/`ExistingSSHKey`, and `PlanCreateV2` prefers
request → stored → default (`dev`). Deliberately the *reuse-fallback* pattern
of the default project — NOT the immutability pattern of the DNS suffix: an
explicit `--unix-user`/`--ssh-key` still replaces the stored values (that is a
legitimate admin operation); only the blank re-run stops degrading them.
`meta.KeyV2SSHKey` added so the tenant package can read the key the incusx
writer already stores (incusx now references the shared constant).

## 2026-07-21 — Admin links on the auth-app home page

Adding a GitHub user to the Login Allowlist has only ever been a web action
(`/admin/allowlist`); there is no CLI equivalent. But nothing on the signed-in
home page pointed there — the two admin pages only cross-linked to each other,
so you had to already know the URL to find them.

- **A conditional section on the onboarding page, not a global nav.** The page
  already receives the full `User` record, so `{{if .User.SandcastleAdmin}}`
  gates the section with no handler or struct change. A shared nav bar across
  every page would have been the bigger refactor and would leak the existence
  of admin routes to non-admins.
- **Links only, no inline allowlist form.** Adding a user hits the GitHub API to
  verify the username and has real revocation semantics on removal; that belongs
  on its own page with the existing user list beside it, not as a stray field on
  the landing page.
- Access control is unchanged — `/admin/*` still enforces `requireAdmin` on
  every request. The section is discoverability, not authorization.
