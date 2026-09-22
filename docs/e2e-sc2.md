# sc2 End-to-End Test Protocol

A re-executable runbook that validates the full sc2 (v2) feature set: appliance
deploy → tenant provisioning (stock Debian sidecar) → client enrollment → machine
+ DNS → per-tenant HTTPS. Every step lists the command and the **PASS** criterion.

Run it top-to-bottom. **Phase 0 (teardown)** makes it idempotent — re-running
starts from a clean slate.

## Status legend
- ✅ **validated** live on `big` (2026-07-02)
- ⚠️ **partial** — works but has a known rough edge (noted inline)
- 🚧 **to build** — feature not implemented yet; step documents the target

## Prerequisites
- Run from a host with the **admin** Incus remote: `export INCUS_CONF=~/.config/incus-admin` (remote `big`).
- The one **fat binary** built static for linux: `bin/linux-amd64/sandcastle` (`make build` with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 BIN_DIR=bin/linux-amd64`). It is copied into every appliance.
- **Stock images, no `sandcastle/base`.** Everything (auth-app, broker, tenant sidecars) runs on the stock upstream image `images:debian/13`, **pulled on demand from the public `images:` remote** — no custom image build and no manual `incus image copy` pre-caching required. (The appliance/sidecar launch code resolves `images:…`/`ubuntu:…` refs to a simplestreams pull; a bare alias or fingerprint still means a local image.) The Incus **server** just needs outbound access to `images.linuxcontainers.org`.
- **Host network listener — now automatic.** Provisioning turns the daemon's network listener on itself: `CreateToken` calls `ensureServerListening`, which sets `core.https_address=:8443` if unset (a fresh `incus admin init --minimal` host only has the unix socket). No manual `incus config set core.https_address :8443` is needed anymore; before this fix, provisioning failed at token issuance with `Can't issue token when server isn't listening on network`.
- **Client needs the `incus` CLI.** `sc login` shells out to `incus remote add` to enrol the tenant remote, so the client machine must have the Incus client installed (`apt-get install -y incus-client` on Debian/Ubuntu; `incus-client` is the lightweight client-only package). Without it, login provisions the tenant but fails at enrollment with `incus remote add: exec: "incus": executable file not found in $PATH`.
- **GitHub auth — two modes:**
  - **Simulated (no OAuth app, recommended for e2e):** deploy the auth-app with `--simulate-github-token <secret>`; log in with `sc login <auth-host> --simulate-token <secret> --as <username>`. No `GH_CLIENT_ID`/`GH_CLIENT_SECRET`, no browser, no network to GitHub. **Dev/e2e only.**
  - **Real OAuth app:** `.env.sc2` with `GH_CLIENT_ID`, `GH_CLIENT_SECRET`; the OAuth **callback URL is `https://<auth-host>/oauth/github/callback`** (note `/oauth/…`, not `/login/…`).
- `.env.sc2` at repo root (start from the tracked `.env.e2e.sample`) with: `PUBIC_URL=sc2.thieso2.dev`, `TAILSCALE_AUTH_KEY` (**reusable** — the client and every sidecar join with it; a single-use key fails at the sidecar with "API key … not valid"), and (real-OAuth only) `GH_CLIENT_ID`/`GH_CLIENT_SECRET`. (An optional `TAILSCALE_API_KEY` is useful only for the harness's own tenant-side route-approval scripting — the product has no API-key flag.) For **Phase 12** add `SANDCASTLE_E2E_CLOUDFLARE_TOKEN` and `SANDCASTLE_E2E_PUBLIC_DNS_ZONE` (a dedicated Cloudflare test zone the token can edit); without them Phase 12 is skipped, not failed.
- **Tenant machine reachability (per-tenant tailnet, ADR-0017).** Every sandcastle is part of a tailnet by default — the tailnet is the main operation mode, and every access path (CLI, SSH, DNS, the Incus remote) rides it. The sidecar advertises the tenant `/24` as a subnet route; a client reaches tenant machines only once that route is **approved** and the client **accepts routes**. Every sidecar joins the tailnet tagged **`tag:sandcastle`** (`tailscale up --advertise-tags=tag:sandcastle`), so the **recommended zero-touch approval** is a Tailscale ACL `autoApprovers` rule that auto-approves any route advertised by that tag — no API key, no manual step. Add to the tailnet policy:
  ```jsonc
  "tagOwners":     { "tag:sandcastle": ["autogroup:admin"] },
  "autoApprovers": { "routes": { "10.0.0.0/8": ["tag:sandcastle"] } }
  ```
  (Scope the route prefix to your CIDR pool.) On the client side, `sc login` enables `--accept-routes` and **verifies the route actually egresses over the tailnet, halting with guidance if not** (a raw connect to the gateway is not trusted — it can leak via the client's own LAN). Alternative to the tag rule: approve each route manually in the Tailscale admin console.
- **CIDR pools must not overlap the host's own network.** Pick `/16`s clear of the host IP and of `incusbr0`/other bridges (e.g. broker `10.249.0.0/16`, auth-app `10.250.0.0/16`). The allocator only sees existing v2 tenants, not the host subnet — an overlap fails with `dnsmasq: Address already in use`.
- Public DNS: `sc2.thieso2.dev` → the host's public IP (`65.21.132.31`). *(On an IP-less host, front the auth-host via a Cloudflare tunnel + `sc-edge` instead — see `docs/handoff-sandcastle-e2e-tunnel.md`.)*
- `TENANT=e2etest` throughout.

```bash
cd /workspace/sandcastle-incus
export INCUS_CONF=~/.config/incus-admin
set -a; . ./.env.sc2; set +a
TENANT=e2etest
SSHKEY=$(cat ~/.ssh/sandcastle_ed25519.pub)
IMAGE=images:debian/13          # stock upstream image, pulled on demand
SIMULATE_TOKEN=e2e-simulate-$(head -c6 /dev/urandom | base64 | tr -dc a-z0-9)   # simulated-auth mode
```

---

## The two-VM protocol ✅ — bare server VM + bare client VM

**The canonical e2e shape** (validated live 2026-07-06, `e2eserver`/`e2eclient`
on `obelix`): the operator hands over **two bare Debian 13 VMs**. VM 1 becomes
the **sc server** (Incus + auth-app + broker + public ingress); VM 2 becomes the
**client**, where **all client functionality** is installed and tested. Nothing
is mocked and nothing is pre-installed — both machines start from a stock
`images:debian/13/cloud` (or any bare Debian 13 with SSH + sudo).

Operator-supplied inputs: a first-level public hostname on a Cloudflare zone +
either a Cloudflare **API token** (installer creates tunnel + DNS itself) or a
dashboard-created **tunnel token**; a **Tailscale auth key** (the tenant's own
tailnet); optionally a Tailscale **API key** for tenant-side route approval; a
random `SIMULATE_TOKEN` (simulated GitHub — no OAuth app).

**Credentials come from the operator's gitignored `.env*` file** (repo-root
`.env.default`, or a run-specific `.env.sc2` sourced in the prologue) so the
whole e2e runs unattended — the harness sources it (`set -a; . ./.env.default;
set +a`) and never prompts. The Tailscale side is already there
(`SANDCASTLE_E2E_TAILSCALE_AUTHKEY`, `SANDCASTLE_E2E_TAILSCALE_TAG`,
`SANDCASTLE_E2E_TAILSCALE_ROUTES_APPROVED`, plus `SANDCASTLE_TAILSCALE_AUTHKEY`
/ `SANDCASTLE_AUTH_TAILSCALE_AUTHKEY` for install-time keys); keep the
Cloudflare API token for `--cloudflare-api-token` next to them
(`SANDCASTLE_E2E_CLOUDFLARE_API_TOKEN`). Never commit these files.

**Test-lab access (unattended SSH, verified live 2026-07-07).** The lab VMs on
`big` are reachable through host port-forwards, passwordless with the
operator's standard key:

```bash
ssh -p 7001 sc@big.thieso2.dev   # → obelix
ssh -p 7002 sc@big.thieso2.dev   # → asterix
```

Additional passwordless per-VM keys are named `<host>_ed25519` and may live in
`~/.config/sandcastle/` (e.g. `obelix_ed25519`, `asterix_ed25519`,
`e2e-test_ed25519`) or in `~/` — pass one with `ssh -i` when the default key
isn't authorized.

**Unattended by default.** The e2e must run with no human in the loop, so the
server install **always** includes `--simulate-github-token "$SIMULATE_TOKEN"`
— even when real OAuth credentials are also configured: the two modes coexist
(the token-gated `/oauth/github/simulate` endpoint registers *in addition to*
the real OAuth handlers), so humans can still log in with GitHub while the
harness short-circuits OAuth with `sc login --simulate-token … --as <user>`.
The secret gates everything — treat it like a password, generate it fresh per
run, and never enable it on a production install you don't intend to test
against. An attended real-OAuth login is an optional extra verification, not
part of the default protocol.

### Multi-install coexistence + shared identity (validated from scratch 2026-07-07)

Several sandcastles share one Incus host via `--prefix` (e.g. `sc` +
`--prefix id`), each with its own hostname/tunnel, CIDR pool, and Tenant DNS
Suffix. Validated **from scratch** (purged host → `install-incus` → two
`sc-adm install` runs) side by side on one server + one client:

- **Server:** distinct appliances (`sc2-*` vs `id-*`); tunnel installs bind
  **no broker host port** (tenant plane = auth-app token-gated
  `POST /api/projects`), so with a Cloudflare tunnel the broker appliance is
  **not deployed at all** and **nothing binds `:9443` on the host**. Own-tenant
  lookup,
  `tenant.List`, and the DNS reconciler are all prefix-scoped (`meta.KeyV2Prefix`
  on the infra project), so same-named tenants of different installs are
  distinct and each auth-app only sweeps its own sidecars. This scoping covers
  **v1 tenants too**, more strictly: a `kind=tenant` project is **always** a
  legacy install's tenant — same-named or not, whatever the prefix — so its
  `/24` is **occupied**, never adopted as `PreferredCIDR` (the v1 bridge, with
  its dnsmasq on the gateway IP, may still be live; the v2 path never creates
  `kind=tenant` projects). Before this, a first login by a user who owned a v1
  tenant reused the v1 tenant's `/24` and the new install's bridge died with
  `dnsmasq: failed to create listening socket for <gw>: Address already in
  use`. Regression test: `TestProvisionReuseInputsNeverOwnsV1CIDR`. **e2e
  check:** on a host with a v1 `sc-<user>` tenant, first login by the same
  user to any v2 install provisions on a fresh `/24`.
- **Own appliance bridge:** each install creates and owns a NATed bridge
  `<prefix>-net` (`sc2-net`, `id-net`) when that fits Linux's 15-character
  interface-name limit; longer prefixes use a stable hashed `sc-<hash>-net`
  name. It has an Incus auto-picked subnet and puts
  its auth-app/broker on it — so the appliances share **no** network object with
  v1 or with another install (only the Incus daemon is shared). `--bridge`
  overrides to an existing bridge (e.g. `incusbr0`). Per-tenant bridges are
  unchanged — each tenant still owns its own `/24`. **e2e check:** after two
  installs, `incus network list` shows `sc2-net` and `id-net` as distinct
  managed bridges, and nothing binds `:9443` on the host.
- **Client — shared identity:** all enrollments live in ONE incus config dir
  (`~/.config/sandcastle/incus`) sharing ONE client keypair; each install is a
  plain remote — `sc-<tenant>` (default install), `sc-<prefix>-<tenant>`
  otherwise — so `incus remote switch sc-id-<tenant>` moves between sandcastles
  natively. Each remote is pinned to its install's default project (the shared
  cert's server-side default is ambiguous). Because Incus keys trust by
  fingerprint, `sc login` sends the client's existing cert and each install
  **unions** its projects into that one trust entry. Enrolling the *second*
  install can't redeem the join token (the daemon already trusts the keypair —
  `Client is already trusted`), so `sc login` falls back to a certificate-based
  `incus remote add … --auth-type=tls --accept-certificate --project
  <install-default>`. The explicit `--project` is load-bearing: without it
  `incus remote add` sees both installs' projects through the shared cert and
  **prompts interactively**, which EOFs and hangs the login. Regression test:
  `TestTrustedClientRemoteAddArgsPinsProject`.
- **Proven green:** native `incus launch sc-e2e:web` and `sc-id-e2e:api` both
  RUNNING from the one client; per-install DNS zones with **zero cross-zone
  bleed** (`web.default.e2e` resolves in the sc zone and is NXDOMAIN in the id
  zone, and vice-versa for `api.default.idefix`).

**One client, several sandcastles on the SAME Incus daemon (validated live
2026-07-07, prefixes `tc2` + `tc3`).** Every sidecar's Incus Reach proxies to
the *same* host Incus API, and the shared client cert's trust entry unions the
projects of every install the user enrolled in — so from the daemon's point of
view all of one user's remotes are interchangeable, and only the
`INCUS_PROJECT` pin separates the installs. The CLI therefore scopes every
tenant lookup to the install the **configured remote** belongs to: the remote
name encodes the install (`sc-<prefix>-<tenant>`, `sc-<tenant>` for the
default prefix; inverted by `installPrefixFromRemoteName`, regression test
`TestInstallPrefixFromRemoteName`). Without that scoping, `sc incus`,
`sc create`, and `sc connect` matched the first same-named tenant on the daemon
and silently operated on the *other* install's project.
- **Protocol:** install two sandcastles on one Incus host with distinct
  `--prefix`, distinct `--auth-hostname`, distinct `--cidr-pool`, and log the
  same GitHub user into BOTH from one client machine, choosing a different
  Tenant DNS Suffix per login (e.g. `sc login https://<host-a> --dns-suffix=tcA`,
  `sc login https://<host-b> --dns-suffix=tcB`). Switch installs with
  `sc remote switch <suffix>`. **PASS:** the nearest `.sandcastle` selects the
  remote and project; the CLI's tenant and bearer identity follow that selection
  in memory. Global Sandcastle and Incus defaults are unchanged. Without a local
  file, existing global defaults are fallback; environment overrides still win.
  **Bearer identity follows the remote (#112):** login also records the CLI
  token and Broker URL per REMOTE (`remote_auth_tokens`/`remote_brokers`), so
  switching between two tenants of ONE install (same Auth Hostname — the
  hostname-keyed maps can't tell them apart) swaps the token/broker to the
  target tenant's. **e2e check:** log two users into the same install from one
  client, `sc remote switch` between their suffix remotes, and a token-backed
  command (`sc route list`, `sc project create`) must act as the CURRENT
  remote's tenant — no 403 `user <other> is not authorized`, no re-login.
  (Logins predating the per-remote maps fall back to last-login-wins.)
- **PASS:** with a machine created in only one install,
  `VERBOSE=1 sc incus ls` under each remote prints
  `INCUS_PROJECT=<that-install's-prefix>-<tenant>-default` and lists only that
  install's machines (the other install's view is empty — no cross-install
  bleed). `sc create`/`sc connect`/`sc delete` land in the install the current
  remote belongs to, and **`sc list` / `sc project list` / `sc status` show that
  same install** — a machine visible to `sc incus ls` but missing from `sc list`
  under the same remote is the name-only-match regression (see appendix). Each login installed its own resolver zone
  (`/etc/resolver/tcA`, `/etc/resolver/tcB` on darwin) pointing at its own
  tenant's CoreDNS, and each tenant got a /24 from its own install's pool.

**Tenant DNS Suffix e2e scenarios (`sc login --dns-suffix=…`).** The suffix is
chosen at first login, is **immutable** per tenant per install
(`TestPlanCreateV2DNSSuffix`), and the existing-suffix lookup is
prefix-scoped so the same user on two installs can (and should) use two
different suffixes (`ProvisionReuseInputs` tests). It can be supplied two ways
(ADR-0020): the **DNS suffix field on the browser device-approval page**, or the
`--dns-suffix` CLI flag; when both are present the **CLI flag wins**
(`effectiveDNSSuffix`, `TestEffectiveDNSSuffixPrecedence`). Run all three:

0. **Browser-chosen suffix.** On a fresh tenant, run `sc login https://<host-a>`
   with NO `--dns-suffix`, type a suffix (e.g. `tcweb`) into the DNS-suffix field
   on the device-approval page, approve, then `sc create dev`. **PASS:** the
   tenant is provisioned with suffix `tcweb` (remote `tcweb-default`,
   `/etc/resolver/tcweb`), exactly as if `--dns-suffix=tcweb` had been passed.

1. **Fresh suffix.** `sc login https://<host-a> --dns-suffix=tcA` on a fresh
   tenant, then `sc create dev`. **PASS:** the login installs
   `/etc/resolver/tcA` (darwin; `resolvectl` domain on linux) pointing at the
   tenant's CoreDNS; `dev.default.tcA` resolves to the machine's tenant IP from
   the client (`dscacheutil -q host -a name dev.default.tcA` / `getent hosts`),
   and `sc connect dev` works by name.
2. **Persistence + immutability.** Re-run `sc login https://<host-a>` with NO
   `--dns-suffix`. **PASS:** the suffix stays `tcA` (summary + resolver
   unchanged). Then `sc login https://<host-a> --dns-suffix=other` must fail
   fast with `the Tenant DNS Suffix is immutable: … already uses "tcA"` — no
   half-provisioned state, and the tcA zone keeps resolving.
3. **Two installs, one client, two suffixes.** With install A (`tcA`) and
   install B on the same Incus daemon: `sc login https://<host-b>
   --dns-suffix=tcB`. Suffixes MUST be distinct across installs — the client
   resolver path is per-suffix (`/etc/resolver/<suffix>`), so a shared suffix
   would clobber the other install's resolver. **PASS:** both resolver files
   coexist, each pointing at its own tenant's CoreDNS address (from its own
   install's CIDR pool); names in BOTH zones resolve simultaneously without
   switching remotes (DNS is per-suffix, not per-current-remote); cross-zone
   lookups fail both ways (`dev.default.tcA` absent from tcB's zone and vice
   versa). Asking a sidecar's CoreDNS for a name in the *other* install's suffix
   answers **REFUSED**, not NXDOMAIN (it is not authoritative for that zone) —
   verified on `majestix` 2026-07-09. NXDOMAIN is what you get for an absent
   name *within* a zone the server does own (e.g. `api.castle`, a short alias
   outside the default project).

**Suffix-as-remote-name + cross-install addressing (ADR-0020).** The Tenant DNS
Suffix is now also the **stem of the incus remote name** and a per-install
**uniqueness key**:

4. **Suffix uniqueness is enforced per install.** After a tenant claims a suffix
   on install A, a *second* tenant logging into the same install with the same
   `--dns-suffix` must be **rejected before provisioning** with
   `DNS suffix "<x>" is already claimed on this install` (the claim is reserved in
   the auth DB's `dns_suffix_claims` table before `V2Create`). **PASS:** the second
   tenant is not provisioned; the first tenant's claim row is intact. *(Validated
   live on `majestix` 2026-07-15: `sctest` claimed `sctest`; `sctest2` rejected in
   15 ms.)*
5. **Remote is named `<suffix>-<project>`.** After `sc login … --dns-suffix=tcA`,
   the enrolled remote is `tcA-default` (not `sc-<authhost>`); a per-project remote
   for project `web` is `tcA-web`. **PASS:** `incus remote list` shows the
   suffix-stemmed names.
6. **Cross-install connect.** `sc connect tcB:default:dev` from a client whose
   current install is A switches to install B's `tcB-default` remote and connects;
   naming an install/project with no local remote errors with enroll guidance
   (connect never auto-provisions). *(Built; validate against a two-install client
   — `majestix` has installs A+B.)*
7. **Lazy migration.** An existing tenant's next `sc login` renames its legacy
   remotes (`<tenant>-<project>`, `sc-<authhost>`) to `<suffix>-<project>`, scoped
   to that install's endpoint. **PASS:** old names are gone, new names present, and
   a same-named tenant on another install is untouched. *(Built; validate against a
   client holding legacy remotes.)*

**First-login initial project name (`sc login --default-project=…`, issue #93).**
At first login the user may name their one project instead of the hardcoded
`default`; the chosen name **replaces** `default` — it is the tenant's project,
not an extra one. It is supplied two ways: the **Initial project field on the
browser device-approval page** or the `--default-project` (alias
`--initial-project`) CLI flag; CLI wins (`effectiveInitialProject`,
`TestEffectiveInitialProjectPrecedence`). Unlike the suffix it is **not
immutable** — blank ⇒ `default`, re-login reuses the stored name. Needs **live
e2e on `home`** (DNS short-alias + tenant networking can't be fully unit-tested):

8. **Named initial project.** On a fresh tenant, `sc login https://<host-a>
   --dns-suffix=tcA --default-project=web`, then `sc create dev`. **PASS:** the
   enrolled remote is `tcA-web` (not `tcA-default`); the Incus project is
   `sc2-<tenant>-web`; `sc list` shows the project as `web`; the canonical name
   `dev.web.tcA` resolves to the machine's tenant IP AND the short alias
   `dev.tcA` resolves to the same IP (the short alias follows the renamed
   project, `TestRenderTenantShortNameFollowsRenamedDefaultProject`); `sc connect
   dev` works.
9. **Persistence, no duplicate.** Re-run `sc login https://<host-a>` with NO
   `--default-project`. **PASS:** the project stays `web` (summary + remote
   unchanged); crucially NO second `sc2-<tenant>-default` project is created and
   the remote is not re-pointed (`ProvisionReuseInputs` returns the stored `web`,
   `TestProvisionReuseInputsReturnsStoredDefaultProject`). A blank browser field
   on the same tenant likewise keeps `web`.

**Device-approval page adapts to the tenant.** The browser device-approval page
(`GET /device`) shows the DNS-suffix and initial-project **inputs only on first
login**; once the tenant exists it renders the immutable suffix and existing
projects **read-only** (`deviceApproveForm` looks the tenant up via
`findPersonalTenant`; `TestDeviceFormShowsInputsForFirstLogin`,
`TestDeviceFormHidesInputsForExistingTenant`). Live check on `home`:

13. **Fresh tenant shows inputs; re-login shows state.** On a fresh tenant, open
    the device-approval URL — **PASS:** the page has editable *DNS suffix* and
    *Initial project* fields. Approve, provision, then start a second
    `sc login` and open the approval page again — **PASS:** the fields are gone;
    the page instead shows the tenant's suffix (e.g. `castle`) and its projects
    (e.g. `default`, `web`) as read-only text, and approving still works with a
    single click (blank submit reuses the stored suffix/project, no duplicate).

**Current project stored on login + `sc info`.** Login writes the tenant's
project into `~/.config/sandcastle/config.yml` (`project:`) so bare machine
references resolve without `--project` — the fix for `project "default" not
found in tenant … (projects: <name>)` on a tenant whose one project isn't named
`default` (`applyLoginProjectDefault`, `saveProjectDefault`;
`TestLoginStoresSingleProject`, `TestLoginMultipleProjectsNonInteractiveDefaults`,
`TestLoginMultipleProjectsInteractivePrompt`, `TestLoginKeepsExistingValidProject`).
Unit-tested, but the connect resolution deserves a live pass on `home`:

10. **Bare connect resolves after login.** On the `--default-project=web` tenant
    from scenario 8, immediately after login run `sc config show`. **PASS:**
    `file.project: "web"` (login stored it; no manual `sc config set project`).
    Then `sc create dev` and `sc c dev` (no `project:` prefix, no `--project`)
    **PASS:** connects — no `project "default" not found` error.
11. **`sc info` shows context + projects.** Run `sc info`. **PASS:** prints
    `Tenant`, `Project` (`web`), `Remote`, and `Auth`, then `Projects in <tenant>:`
    listing the tenant's projects with the current one marked `*`. With the
    tenant unreachable it still prints the local config plus a
    `showing local config only` note and exits 0. `sc info --json` emits the same
    fields as JSON.
11b. **An unreachable remote says so, fast.** With the remote's Incus endpoint
    unreachable (drop the tailnet path to it, or point the remote at a blackholed
    address), run any tenant-scoped command — `sc incus ls`, `sc ls`, `sc c dev`.
    **PASS:** each fails within ~5s with
    `connect to Incus remote "<name>": <host>:8443 is not reachable within 5s …`,
    naming the remote and the address it dialled. **FAIL:** a ~20s silent block,
    or the old misreport `Sandcastle tenant <name> not found` — which is a claim
    about the tenant that the CLI never actually got an answer to. The probe
    budget is `SANDCASTLE_CONNECT_TIMEOUT` (default `5s`, `0` disables it).
12. **Multi-project selection.** Add a second project (`sc project create api`),
    then re-login. **PASS:** because the configured `project:` (`web`) is still
    valid, login keeps it and prints `Current project: "web".` (no prompt). Clear
    it (`sc config unset project`) and re-login on a TTY: login **prompts** for
    the default; a non-interactive login instead defaults to the tenant's current
    project and prints a `Change with: sc project switch <name>` note.
12b. **Re-login grants every existing project — new client.** With a multi-
    project tenant (≥2 projects), log in from a machine that has never enrolled
    (fresh client certificate). **PASS:** `sc project ls` on the new machine
    lists ALL the tenant's projects, same as an established client — the
    enrollment token (and the shared-certificate union for an existing cert) is
    scoped to every existing app project, default first
    (`PlanCreateV2.RestrictedProjects`, `ProvisionReuse.Projects`;
    `TestPlanCreateV2RestrictedProjectsUnionExisting`,
    `TestProvisionReuseInputsReturnsExistingProjects`). **FAIL:** the new
    client sees only the default project (the pre-fix behaviour: the token was
    scoped to the default project alone, and only certificates that lived
    through each `sc project create` had been extended project-by-project).
13. **`sc project switch`.** With ≥2 projects, `sc project switch api` **PASS:**
    prints `Switched to project "api"` and the absolute `.sandcastle` path,
    `sc config show` shows resolved `project: "api"`, and `sc project list`
    reports the same file and marks `* api`. `sc project switch ghost`
    **PASS:** errors `project ghost not found in tenant … (projects: …)` unless
    `--local-only` is passed (`newProjectSwitchCommand`;
    `TestProjectSwitchSetsCurrentProject`, `TestProjectSwitchRejectsUnknownProject`,
    `TestProjectListMarksCurrent`).

**Idempotent login skips the browser — cross-install.** Before opening the web,
`sc login <host>` reuses a still-valid saved login: token accepted + enrolled
remote responds + tailnet routing healthy. It resolves the token/remote for the
*requested* host from the `installs`/`auth_tokens` maps (not just the active
install), so it works even when another install is active — and switches to it
(`tryExistingLogin`, `enrolledRemoteForAuthHostname`, `adoptExistingInstall`;
`TestLoginSwitchesToExistingInstallWithoutBrowser`). Live check on this Mac (has
both `big` and `home` enrolled):

14. **Skip web + switch.** With `big` active, `sc login https://home.thieso2.dev`
    **PASS:** no browser opens; prints `Already logged in at https://home.thieso2.dev`
    (+ `Switched active install to …` when the prior install differed), the
    routing check passes, and `sc config show` now shows the home auth hostname,
    remote, and broker (self-healed). `--force` still runs a full device flow.

**One incus remote per install (ADR-0021).** The enrolled remote is named
`<suffix>` (not `<suffix>-<project>`); the project is an orthogonal pin.
`sc project switch` now selects the project locally; it leaves the raw Incus
pin unchanged (directory selection supersedes ADR-0021's switch write-through).
Login still collapses per-project remotes for the same install.

15. **Directory selection and isolated checkouts.** In checkout A, run
    `sc project switch h2`. **PASS:** it creates `.sandcastle` with remote and
    project, prints its absolute path, and `sc incus ls` lists `h2`. Record the
    global Sandcastle and Incus config bytes before switching; **PASS:** unchanged
    afterward. Raw `incus` retains its existing project pin.
    In A's nested `src` directory, switch project again; **PASS:** updates A's
    file, creates no child file, and both list commands report A's path.
    Switch to another remote, select a project there, then switch back and forth;
    **PASS:** each remote's local project choice is restored and token-backed
    commands use that remote's tenant credentials. No credentials appear locally.
    In independent checkout B, **PASS:** A's selection has no effect; without a
    file B uses global fallback and says so. Its first switch creates B's file.
    Put an independent `.sandcastle` in A/src; **PASS:** only that file is read.
    Export `SANDCASTLE_REMOTE`/`SANDCASTLE_PROJECT`; **PASS:** overrides win without
    changing files. Invalid YAML or missing required fields in the nearest file
    must fail with its path instead of using a parent/global fallback.
    `sc project list --json` **PASS:** valid JSON with `config_path`.
    Regression coverage: `TestDirectorySwitchesAreIsolatedAndRememberProjects`,
    `TestDirectorySelectionWalkAndWrite`, `TestDirectorySelectionInvalidFileStopsLookup`.

Keep CIDR pools distinct across installs sharing a tailnet. Robustness fixes the
from-scratch run surfaced (all in `internal/incusx` + the auth-app): tolerate
the spurious "already running" on a cached-image create; wait for RUNNING
before configuring an appliance/sidecar; start an existing STOPPED sidecar on
re-provision; and — the big one for flaky edges — **provision on a detached
context** so a Cloudflare-tunnel poll timeout can't cancel tenant bring-up
mid-flight.

### Run logging — `logs/<machine-name>.log` (required)

Every install/test run keeps a **verbatim transcript per machine**: each command
that runs on a VM, followed by that command's full output, appended to
`logs/<machine-name>.log` (e.g. `logs/e2eserver.log`, `logs/e2eclient.log`) in
the run's working directory. Drive every remote command through this wrapper —
no untracked side-channel commands:

```bash
mkdir -p logs
# run <machine-name> <ssh-target> <command…> — echoes the command, appends
# command + combined output to logs/<machine-name>.log, and prints it live.
run() {
  local m="$1" t="$2"; shift 2
  { printf '\n$ %s\n' "$*"; ssh "$t" "$@" 2>&1; } | tee -a "logs/$m.log"
}
run e2eserver server sudo sc-adm install-incus            # example
```

**PASS:** after the run, `logs/` contains one log per machine, and every
command from the protocol below appears in the right log with its output —
the logs alone must be enough to replay or debug the run.

### VM 1 — the server

```bash
# from the workstation: the fat binary, then the four names
scp bin/linux-amd64/sandcastle server:/tmp/
ssh server 'sudo install -m0755 /tmp/sandcastle /usr/local/bin/sandcastle &&
  for n in sc sc-adm sandcastle-admin; do sudo ln -sf sandcastle /usr/local/bin/$n; done'

ssh server
sudo sc-adm install-incus                       # Zabbly repo + incus + minimal init
incus config set core.https_address=:8443
sc-adm install \
  --auth-hostname  "$E2E_HOSTNAME" \
  --simulate-github-token "$SIMULATE_TOKEN" \   # ALWAYS — unattended runs; coexists with real --github-* creds
  --admin-github-users thieso2 \
  --ingress cloudflare --cloudflare-api-token "$CLOUDFLARE_API_TOKEN" \
  --cidr-pool 10.254.0.0/16                     # clear of every other deployment on the tailnet
```

**PASS:** `systemctl is-active` reports `active` for `sandcastle-auth-app`,
`caddy`, `cloudflared` (in `sc2-auth-app`) and `sandcastle-broker` (in
`sc2-broker`); tunnel **Healthy**; `curl https://$E2E_HOSTNAME/healthz` → 200.

### VM 2 — the client (all client functionality)

```bash
# install: binary (as above) + the two client prerequisites
apt-get install -y incus-client                                  # sc login shells out to incus
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --auth-key "$TAILSCALE_AUTH_KEY" --accept-routes    # client must be a tailnet node

# 1. login — provisions the tenant, exercises --dns-suffix
sc login "https://$E2E_HOSTNAME" --simulate-token "$SIMULATE_TOKEN" --as e2edns \
  --tailscale-auth-key "$TAILSCALE_AUTH_KEY" --dns-suffix castle
#    approve the sidecar's advertised /24 (Tailscale admin console, API, or a
#    tag:sandcastle autoApprover)
# PASS: all four routing checks ✓; the tenant's stored suffix is the chosen one
#       (server: incus project get sc2-<tenant> user.sandcastle.v2.suffix)

# 2. projects + machines (flagless broker path, project-scoped refs)
sc create web --detach                       # default project
sc project create backend                    # NO flags: broker URL + cert from the login
sc create backend:api --detach
sc create backend:web --detach               # SAME machine name as default:web
sc list                                      # FQDN column shows canonical names
# PASS: EVERY machine created above appears in `sc list` immediately (list is
#       scoped to the current remote's install — a same-named tenant of another
#       install on the same daemon must never shadow this one)
# PASS: the IP column shows each machine's TENANT BRIDGE address (inside the
#       tenant CIDR) and is STABLE across repeated runs. On a machine running
#       Docker, `172.17.0.1` (docker0) must never appear: the address is picked
#       from the instance's Incus NIC devices, not from whichever interface Go's
#       map iteration surfaced first. Run `sc list` ~10x and diff the IP column.
# PASS: `backend:web` starts cleanly even though `default:web` already exists —
#       both projects share the tenant bridge, and the bridge carries
#       dns.mode=none so Incus does NOT reject the second `web` with
#       "Instance DNS name \"web\" already used on network". Their FQDNs stay
#       distinct: web.default.castle vs web.backend.castle.

# 2b. shared /workspace across the project (CT ↔ VM), and opt-in shared $HOME
sc create vm1 --vm --detach                  # a VM next to the CTs in default
#    wait for both to be RUNNING (sc list), then:
# NB: `sc incus exec` runs as ROOT inside the machine, so $USER expands to "root"
# and /home/root does not exist. Use the login user's home explicitly (default: sc).
# NB: `sc c <machine> -- sh -c '<script>'` works (fixed in #53 — `remoteCommandLine`
# shell-quotes argv before it reaches ssh). A LONE argument still passes through raw
# as a shell snippet, so `sc c web -- 'ls -l /tmp'` is also correct. The steps below
# use `sc incus exec` because they need ROOT, not because `sc c` cannot run them.
sc incus exec web -- sh -c 'echo from-ct > /workspace/marker'
sc incus exec vm1 -- sh -c 'cat /workspace/marker'   # → from-ct
sc incus exec vm1 -- sh -c 'echo from-vm >> /workspace/marker'
sc incus exec web -- cat /workspace/marker   # → from-ct then from-vm
# PASS: the VM reads what the CT wrote on /workspace and vice-versa (one shared
#       workspace volume per project, security.shifted); the login user can
#       write /workspace. /home is NOT shared here: web and vm1 were created
#       without --home-share, so each has its own machine-local /home.

# 2c. --home-share: the opt-in shared /home (homeshare profile)
sc create hs1 --home-share --detach
sc create hs2 --home-share --vm --detach
#    wait for both, then:
sc incus exec hs1 -- sh -c 'echo home-ct > /home/sc/hmarker'
sc incus exec hs2 -- sh -c 'cat /home/sc/hmarker'          # → home-ct
sc incus exec web  -- sh -c 'cat /home/sc/hmarker'          # PASS: No such file
sc incus profile show homeshare                             # only a `home` disk device
# PASS: hs1/hs2 list profiles `default,homeshare` (`sc incus config show hs1`)
#       and share one /home across CT + VM; `web` (default only) does not see it.
#       `sc c <new-machine> --home-share` does the same when connect creates it.

# 2d. cache-backed `sc ls` (event-bus resource cache, admin-server config toggle)
# The admin server's Incus resource cache is on by default (opt-out toggle —
# see the auth-app admin docs for the env var). Right after `auth-app serve`
# starts, the cache has not finished its initial sync yet.
sc ls -a                                     # PASS: identical machine list/columns
#       to a pre-cache `sc ls -a`, whether or not the cache is ready — the
#       fallback (still-syncing cache, dropped event-bus connection, or the
#       toggle explicitly disabled) is silent, with no error and no visible
#       difference in output. Run with VERBOSE=1 to see which path was used:
VERBOSE=1 sc ls -a 2>&1 | grep -i 'cache-backed\|incus api'
# PASS (cache not ready / toggle off): a "[verbose] incus api: sc ls
#       cache-backed endpoint unavailable (…), falling back to live
#       per-project query" line, followed by the same "[verbose] incus api:
#       GetInstancesFull project=… " trace as before this wish, one call per
#       project.
# PASS (cache ready): no live per-project GetInstancesFull calls at all —
#       `sc ls -a` returns near-instantly instead of the multi-second
#       sequential pattern a many-project tenant showed before this wish.
sc ls -a --networks --storage-pools --storage-volumes --profiles --images
# PASS (cache ready): additional NETWORKS / STORAGE POOLS / STORAGE VOLUMES /
#       PROFILES / IMAGES sections appear, scoped to the same tenant/project
#       filters as the machine table.
# PASS (cache not ready, or toggle off): the same flags are silent no-ops —
#       output is machines-only, exactly like plain `sc ls -a` before this
#       wish; the extra resource types only ever come from the cache path.
# NOTE: `sc-adm list` / `sc admin list` are explicitly out of scope for this
#       cache — they keep querying Incus live, unaffected by the toggle.

# 2d-ii. cache-first `sc connect` (same resource cache, plus a keyscan)
# On the happy path — the machine is cached as running with an address, and
# ~/.ssh/known_hosts already pins the host key its sshd presents — `sc c`
# resolves everything from ONE auth-app request plus ONE ssh-keyscan against
# the machine, instead of the ~10 sequential live Incus API calls of the full
# dial (project probe, profile read, instance/state reads, cloud-init gate,
# three host-key fetches).
VERBOSE=1 sc c <project>:<machine> -- true 2>&1 | grep 'connect cache'
# PASS (hit): a "[verbose] connect cache: hit — <project>/<machine> at <ip>
#       (skipping live Incus resolution)" line, NO "[verbose] incus api:" trace
#       lines, ssh opens with StrictHostKeyChecking=yes, and the session is
#       noticeably faster than the live path.
# PASS (miss): a "[verbose] connect cache: falling back to live resolution
#       (<reason>)" line and the familiar live trace — behavior identical to
#       pre-cache connect. Misses are anything short of certainty: first
#       connect to a machine (no pinned host key yet), machine stopped or
#       absent (connect must create/start it), bare machines, globbed/dotted/
#       remote-prefixed references, cache unreachable, or the host key on
#       port 22 disagreeing with known_hosts (a REBUILT machine must take the
#       live path so its key gets re-read authoritatively and repaired —
#       the cache path must never pin around a changed identity).
# Client-side kill switch: SANDCASTLE_CONNECT_CACHE=0 forces the live path.
# `sc fix` always resolves live — it exists to repair, not to be fast.

# The request must ask only for what it will print — a plain `sc ls` that
# ships four unrendered resource types is what pushed a real install's
# response to 79 KB and lost the cache to a timeout. Read the endpoint
# directly (token from ~/.config/sandcastle/config.yml auth_tokens):
curl -s -o /dev/null -w '%{size_download}\n' -H "Authorization: Bearer $TOKEN" \
  "https://<auth-hostname>/api/resources?tenant=<tenant>&include=machines"
curl -s -o /dev/null -w '%{size_download}\n' -H "Authorization: Bearer $TOKEN" \
  "https://<auth-hostname>/api/resources?tenant=<tenant>"
# PASS: include=machines returns a body with a "machines" array and no
#       networks/storagePools/storageVolumes/profiles/images keys, and is
#       substantially smaller than the no-include= request (which still
#       returns every kind — that back-compat is what keeps an older `sc ls`
#       working against a current appliance).
# PASS: an unknown kind is ignored, not rejected —
#       include=machines,quantum-widgets still answers 200 with machines.
# PASS: `sc ls --storage-pools` shows STORAGE POOL/DRIVER/STATUS and
#       `sc ls --profiles` shows PROJECT/PROFILE/USED BY — the trims that
#       drop pool used_by and profile config/devices from the wire must not
#       cost a rendered column.
SANDCASTLE_LS_CACHE_TIMEOUT=10s VERBOSE=1 sc ls -a
# PASS: the cache budget is overridable — useful on a tunnelled Auth
#       Hostname where a cold TLS handshake alone can cost seconds. A junk
#       or non-positive value is ignored and the 5s default applies.

# 2e. a fresh machine's IP must appear immediately (cache miss on a blank
# address). Nothing on the Incus event bus fires when a guest picks up its
# DHCP lease, so the cache keeps the empty address it read at
# instance-started until some unrelated event touches the same project. A
# cache-backed `sc ls` must never report that blank as fact.
sc create dev                                # in a fresh project
# Capture ONE listing and assert everything from it. Running `sc ls` twice is
# not a valid check here: any lifecycle event landing in between re-reads that
# project, so a second run can be a cache hit that hides what the first did.
VERBOSE=1 sc ls > /tmp/first-ls.txt 2>&1     # IMMEDIATELY, no sleep
cat /tmp/first-ls.txt
sc-adm incus list <remote>: --project <prefix>-<tenant>-<project> -c ns4
# PASS: the IP column in /tmp/first-ls.txt shows the machine's tenant address
#       on the FIRST `sc ls` after create — never blank-then-populated-later —
#       and it matches the live `sc-adm incus list` output above.
grep -i 'cache-backed' /tmp/first-ls.txt
# PASS (cache still holds the pre-lease snapshot): that SAME captured run
#       carries a "[verbose] incus api: sc ls cache-backed endpoint
#       unavailable (cached machine <project>/<name> is running with no
#       address), falling back to live per-project query" line — the listing
#       was served live and correct, one per-project GetInstancesFull slower.
#       This is the intended trade: ADR-0023 decision 3 accepts a silently
#       stale cache, and `sc ls` refuses to pass that staleness on when it is
#       detectable in the answer itself.
# PASS: no such line is ALSO fine — it means the cache happened to be current
#       for that project. What must never appear is a blank IP column,
#       whichever path served the listing.
# NOTE: `sc create` polls for the lease itself, bounded by v2MachineIPTimeout
#       (45s container / 90s VM, internal/incusx/machine_create_v2.go), and can
#       still return with an empty PrivateIP on timeout. That is a different
#       failure — a machine that really has no address — and it shows up as a
#       blank IP in the LIVE `sc-adm incus list` output too, which is what
#       distinguishes the two.
# PASS: a STOPPED machine with no address does NOT trigger the fallback —
#       blank there is the truth, and treating it as a miss would bypass the
#       cache for every listing that includes a stopped machine.

# 3. the ADR-0018 DNS battery (sidecar CoreDNS = tenant CIDR .3)
DNS=10.254.0.3
dig +short web.default.castle      @$DNS     # canonical            → machine IP
dig +short web.castle              @$DNS     # default short alias  → same IP
dig +short app1.web.default.castle @$DNS     # wildcard             → same IP
dig +short api.backend.castle      @$DNS     # canonical, 2nd proj  → machine IP
dig +short api.castle              @$DNS     # PASS = NXDOMAIN (no short outside default)
# guest identity + guest resolver (via the server admin socket):
#   incus exec web --project sc2-<tenant>-default -- hostname -f   → web.default.castle
#   incus exec api --project sc2-<tenant>-backend -- getent hosts web.default.castle

# 4. lifecycle + error UX
sc c web -- hostname                         # ensure/start/ssh
sc delete backend:api --yes
sc create nosuch:box        # PASS: "project \"nosuch\" not found in tenant … (projects: …)"
sc delete api:backend --yes # PASS: swapped-reference hint: did you mean "backend:api"?

# 4a. duplicate machine names across projects
# The tenant bridge carries dns.mode=none (see step 2 above), so a second "web"
# in another project starts CLEANLY with its own IP — the old "Instance DNS name
# already used on network" refusal is gone (validated on majestix 2026-07-17;
# both webs RUNNING, distinct FQDNs web.default.castle / web.backend.castle).
# What remains is the REFERENCE ambiguity when a bare name matches two projects:
sc create backend:web       # PASS: created AND running, own IP, FQDN web.backend.castle
sc ls -a                    # PASS: both webs listed, both running
sc start web                # PASS (no tty): "machine \"web\" exists in 2 projects (backend:web, default:web); name the one you mean as project:machine"
                            # PASS (tty): numbered prompt "Which one? [1-2]"
sc delete backend:web --yes # PASS: qualified reference deletes without asking
sc delete web               # PASS (tty): confirm names it "default:web", not "web"

# 5. suffix immutability
sc login "https://$E2E_HOSTNAME" --simulate-token "$SIMULATE_TOKEN" --as e2edns \
  --force --dns-suffix other
# PASS: "the Tenant DNS Suffix is immutable: tenant … already uses \"castle\""

# 6. verbose service logging + Activity Log (per-user scoping)
#    a) server VM: every request + work span carries a timestamp and duration.
#       journalctl -u sandcastle-auth-app -n 50 --no-pager
#       journalctl -u sandcastle-broker  -n 50 --no-pager
#       PASS: lines like "… auth-app request POST /api/device/poll status=200 dur=…"
#             and spans "… span provision.personal_tenant dur=… user=<tenant>".
#    b) auth-app /logs UI, signed in as a regular (non-admin) user:
#       PASS: the page shows THIS user's requests/spans with timestamps + durations,
#             and shows NO other user's rows and NO system rows.
#    c) auth-app /logs UI, signed in as a Sandcastle Admin:
#       PASS: the page shows ALL users' rows plus system rows (empty user);
#             the ?q= filter narrows in place; a non-admin cannot reach another
#             user's rows even with ?q=.
```

Registration is event-driven: records appear **within seconds** of
`incus launch`/`sc create` (5-minute reconcile loop as backstop). The admin-plane
counterpart of this protocol is automated in `scripts/e2e-v2.sh` (run it on the
server VM once the stack is up — it refuses to run without the auth-app).

**Teardown:** delete both VMs; remove the tenant sidecar + client devices from
the tailnet; delete the run's Cloudflare tunnel + DNS record.

> Gotcha from the validated run: mid-run binary swaps on the server do NOT
> retro-apply to an already-provisioned tenant — the suffix is immutable, so a
> tenant provisioned before a fix keeps its original suffix. Use a fresh
> `--as <user>` per attempt.

---

## Hermetic harness — a fresh sc2 per run, torn down after 🚧
The real e2e provisions a **throwaway sc2 host** as a VM on `big`, with its **own
nested Incus** and its own sc2 stack (edge + broker + auth-app), and routes a fresh
public hostname to it through the **outer** `sc-edge`. Each run is fully isolated and
leaves nothing behind — no shared appliances, no leftover tenants.

Why it works: **`*.scdev.thieso2.dev` is a public wildcard CNAME to the outer
`sc-edge`.** So a run can claim `<run>.scdev.thieso2.dev`, point the outer sc-edge at
the run's VM, and the whole flow (LE cert, GitHub OAuth, login, machines) happens
against a hostname that resolves publicly and terminates at a **fresh, disposable**
sc2 — a genuine end-to-end path, not a mock.

```bash
RUN=e2e-$(date +%s)                 # unique id per run
HOST=$RUN.scdev.thieso2.dev         # resolves (publicly) to the outer sc-edge

# 1) fresh VM on big with nested virtualization → it becomes its own Incus host
incus launch images:debian/13/cloud big:sc2-$RUN --vm \
  -c security.secureboot=false -c limits.cpu=4 -c limits.memory=8GiB \
  -c security.nesting=true
# wait for cloud-init + agent, capture the VM's bridge IP
for i in $(seq 1 60); do VMIP=$(incus ls big:sc2-$RUN -c4 --format csv 2>/dev/null | grep -oE '10\.[0-9.]+' | head -1); [ -n "$VMIP" ] && break; sleep 3; done

# 2) inside the VM: install Incus + push this fat binary + stand up the sc2 stack.
#    The run's sc2 uses $HOST as its Auth Hostname (so LE + OAuth callback match).
incus exec big:sc2-$RUN -- bash -c 'apt-get update -qq && apt-get install -y -qq incus'
incus file push bin/linux-amd64/sandcastle big:sc2-$RUN/usr/local/bin/sandcastle --mode 0755
#    … init incus, deploy sc-edge/broker/auth-app inside the VM (Phases 1–3 run *in* the VM),
#    with the inner auth app fronted by the inner sc-edge for $HOST.

# 3) route <RUN>.scdev.thieso2.dev → the run's VM via the OUTER sc-edge.
#    SNI passthrough so the VM's inner edge owns the TLS (does its own LE for $HOST):
incus exec big:sc-edge --project infrastructure -- bash -c "
  # add a layer4 SNI-passthrough for $HOST → $VMIP:443, then reload
  systemctl reload caddy"
```

**Teardown (always, even on failure):**
```bash
incus delete -f big:sc2-$RUN                       # removes the whole disposable sc2
incus exec big:sc-edge --project infrastructure -- \
  sed -i "/$HOST/d" /etc/caddy/Caddyfile           # drop the run's route
incus exec big:sc-edge --project infrastructure -- systemctl reload caddy
```

🚧 **To build:** the nested-Incus VM image + an automated inner-stack deploy
(`Phases 1–3` executed *inside* the VM against `$HOST`), and the outer sc-edge
SNI-passthrough entry. Until then, the phases below run against the **persistent**
sc2 on `big` (edge/broker/auth-app + a throwaway `e2etest` tenant) — same flow, but
sharing the long-lived appliances. The hermetic harness makes every run disposable.

> ✅ **Full from-scratch validation incl. routes (2026-07-17, `majestix`, run id
> `74764b9d`):** Phase 0 teardown of a live dual-install stack → two `sc-adm
> install`s (cloudflare tunnels, prefixes `sc2`+`id`, pools 10.61/10.62) → the
> whole client battery (suffix scenarios 1-6/8-11/14-15, machines, DNS incl.
> tailnet-IP + reverse-REFUSED, shared volumes, 7c/7d/7e, 8b incl. the distrust
> window, 8c, 8d), `scripts/e2e-v2.sh` GREEN, multi-install coexistence + the
> new addressing features (`sc remote list/switch`, `castle:`-refs,
> cross-install connect), and **Phase 7f routes**: redeploy-coexistence onto the
> tunnelled login host, `scripts/e2e-route.sh` ALL PASS (hermetic
> `--route-tls internal`), the `sc route` CLI end-to-end, auto-prune self-heal
> (~10 s), and the 501 no-route-ingress precondition. Four defects caught live
> and fixed in the same run (shared-client-keypair `sc project create` 500,
> `sc route delete --yes` ignored, appliance redeploy ETXTBSY, e2e-route.sh
> robustness) — see the appendix rows dated 2026-07-17.

> ✅ **Second full validation (2026-07-04 evening, `testzone-vm1`):** the whole
> protocol re-ran from scratch on another fresh isolated VM — including the new
> **Phase 7c** (`sc c` create/start/SSH lifecycle from the client), the **login
> tailnet precheck** (verified refusing on the tailscale-less host), the
> **layered routing diagnosis** (all ✓ on the client node), and **idempotent
> re-login** (`Already logged in …`). The run caught and fixed three real bugs
> (shared-volume idmap shift breaking VM sshd, enroll not saving local
> defaults, `/api/tenants` blind to v2 tenants) — see the appendix. Deliberate
> deviation: distinct CIDR pools (broker `10.251/16`, auth-app `10.252/16`) so
> the run's tailnet routes can't contend with the live `igel` deployment.

> ✅ **Pattern validated by hand (2026-07-04, `sc2iso-vm2`):** the full protocol was
> executed on a fresh, fully isolated Debian 13 VM — own Incus 7.2 (Zabbly), own
> sc-edge (**Cloudflare-tunnel mode**, `PUBLIC_PORTS=0`, API-created tunnel +
> first-level hostname `sc2iso2-<rand>.thieso2.dev`), own auth-app + broker, a
> nested client CT driving everything. All phases green except 8b (unchanged ⚠️).
> In tunnel mode Cloudflare's edge serves a real LE cert, so the Phase 2/7b issuer
> checks pass verbatim; the inner Caddyfile is plain `http://<host>:8080` vhosts.
> What remains 🚧 is only the *automation* of this setup.

> ⚠️ **The real e2e needs TWO VMs, and BOTH must be genuine tailscale nodes**
> — the runnable protocol is [The two-VM protocol](#the-two-vm-protocol---bare-server-vm--bare-client-vm) above.
> `sc login` now refuses to start the device flow on a machine that is not itself
> a tailnet node (see Phase 9 notes), because in a tailnet **subnet-to-subnet does
> not route**: a machine that is merely *resident* in a subnet some other router
> advertises (e.g. a VM on `big` reached via big's subnet routes) can never reach
> the tenant `/24` behind the sidecar's route — and making such a machine a node
> breaks its old inbound path (asymmetric routing: replies leave via its own
> tailscale0 and get dropped by the caller). So the harness topology is:
> **VM 1 = the sc2 host** (Incus + edge + auth-app + broker; the *sidecar* is its
> tailnet presence) and **VM 2 = the client**, a clean machine whose ONLY sandcastle
> path is its own `tailscale up --accept-routes` membership — not a machine that
> other infrastructure already routes to by subnet.

---

## Phase 0 — Teardown (idempotent reset) ✅
Remove any prior test-tenant server state + local client config so the run starts clean.

> ✅ **v2 tenants now have a product teardown path:**
> `sc-adm tenant delete <tenant> --yes --purge` (scope a prefixed install with
> `SANDCASTLE_INCUS_PROJECT_PREFIX=<prefix>`) deletes the app projects
> (machines, images, shared home/workspace volumes, profiles), the infra
> project (sidecar), and the tenant bridge — the manual loop below remains for
> partial states. Without `--purge` a v2 tenant is refused
> (all-or-nothing). The sidecar's tailnet device is NOT removed (BYO tailnet —
> no server-side API key by design): delete it in the Tailscale admin console
> or use ephemeral keys. **PASS:** after the purge, `incus project list | grep
> <prefix>-<tenant>` and `incus network list | grep <prefix>-<tenant>` are both
> empty, and a same-named tenant of ANOTHER install on the daemon is untouched.
> The purge also sweeps the tenant's **trust entries** (#113): `incus config
> trust list` shows no restricted client cert named
> `sandcastle-[<prefix>-]<tenant>` left with an empty project list — while a
> shared-identity cert under that name that still grants ANOTHER tenant's
> projects survives (one keypair can serve several tenants). *(Validated live
> on `majestix` 2026-07-17: fresh-keypair tenant `trashcan` enrolled, purged —
> entry gone, shared `sandcastle-e2edns` entry untouched.)*

```bash
# server: delete the test tenant's instances + images + custom profiles + projects + bridge.
# NB: v2 projects have their own image store (features.images=true) and a custom
# `sidecar` profile; a project won't delete until BOTH are cleared, so purge them too.
for p in sc2-$TENANT-default sc2-$TENANT; do
  incus list big: --project $p -c n --format csv 2>/dev/null | while read -r n; do
    [ -n "$n" ] && incus delete -f big:$n --project $p 2>/dev/null; done
  incus image list big: --project $p --format csv -c f 2>/dev/null | while read -r fp; do
    [ -n "$fp" ] && incus image delete big:$fp --project $p 2>/dev/null; done
  # shared home/workspace volumes: detach from the profiles FIRST, then delete.
  # `workspace` hangs off `default`, `home` off the opt-in `homeshare` profile.
  incus profile device remove big:default workspace --project $p 2>/dev/null
  incus profile device remove big:homeshare home --project $p 2>/dev/null
  for v in home workspace; do
    incus storage volume delete big:default $v --project $p 2>/dev/null
  done
  incus profile list big: --project $p --format csv -c n 2>/dev/null | while read -r pr; do
    [ -n "$pr" ] && [ "$pr" != "default" ] && incus profile delete big:$pr --project $p 2>/dev/null; done
  incus project delete big:$p 2>/dev/null || true
done
incus network delete big:sc2-$TENANT 2>/dev/null || true
# client: wipe the generated local incus config
rm -rf ~/.config/sandcastle/$TENANT
```
**PASS:** no `sc2-e2etest*` projects remain (`incus project list big: | grep e2etest` is empty).

> ⚠️ Purging a v2 project's image store deletes its **only local copy** of the stock
> base image if that image lives solely inside the tenant project. If a later run
> reports `Image not provided for instance creation`, re-cache it into the shared
> store: `incus image copy images:debian/13 big: --project default` (restores
> fingerprint `d31c34fadc08`, which infra projects share via `features.images=false`).

---

## Phase 1 — Deploy the Auth App appliance ✅
The sc2 web API. No host port (fronted by `sc-edge`). Copies the fat binary in.
Stock image is the default (`--base-image images:debian/13`, pulled on demand — no `--base-image` needed).

> ✅ **Host prep is one command too (2026-07-05):** `sudo sc-adm install-incus`
> installs the latest Incus from the Zabbly stable repo on any Debian-based
> host (repo + apt + `incus admin init --minimal` + incus-admin group),
> idempotently — replaces the hand-rolled Zabbly setup script.

> ✅ **One-command install (2026-07-05).** `sc-adm install` now deploys the
> auth-app AND the broker in one shot with a shared `--cidr-pool` (optional,
> default `10.248.0.0/16` — keep pools distinct across installations sharing a
> tailnet) and a `--prefix` (default `sc`) that scopes the whole installation.
> It **refuses to run when an installation under the same prefix already
> exists** (listing what it found) and warns when the pool overlaps a host
> address. Phases 1+3-broker collapse to:
> ```bash
> sc-adm install --auth-hostname "$PUBIC_URL" \
>   --simulate-github-token "$SIMULATE_TOKEN" --admin-github-users thieso2 \
>   --cidr-pool 10.252.0.0/16
> ```
> `--ingress cloudflare|acme|none` builds the public edge INTO the auth-app
> appliance (caddy + cloudflared inside the same container, proxying
> localhost:9444): `--cloudflare-api-token` creates the tunnel + DNS fully
> automatically (validated live 2026-07-05 — healthz 200 over an
> installer-created tunnel); `--cloudflare-tunnel-token` uses a
> dashboard-created tunnel; `acme` binds host :80/:443 with Let's Encrypt.
> The standalone sc-edge recipe is no longer needed for the auth hostname.
> First-login provisioning must succeed on its **first pass** — a
> `Personal Tenant provisioning failed: write /etc/resolv.conf to sidecar: Not
> Found` message is a regression (the sidecar's `/etc/resolv.conf` is a symlink
> on the stock image; file pushes must clear it first).
> The **interactive `login.tailscale.com` URL is the primary join path**: the
> tenant logs in with no key, `sc login` prints the sidecar's URL and **waits**
> for the join, then finishes enrollment automatically.
> (`--tailscale-auth-key tskey-…` at login is for unattended/CI runs only.)
> The URL is durable: the sidecar keeps its pending `tailscale up` (and the URL)
> across awaiting-tailnet polls and across `sc login` re-runs, re-mints a fresh
> URL if the recorded one is lost or stale, and login re-prints whenever the URL
> changes. **PASS:** with no auth key, `sc login` prints a
> `https://login.tailscale.com/…` URL; Ctrl-C + `sc login --force` prints a URL
> again (same one while the pending join is healthy); awaiting polls cycle in
> seconds, not minutes; opening the URL and approving the route lets the waiting
> login complete enrollment on its next poll. The old separate
> `auth-app deploy` + `bootstrap` commands still exist for piecewise installs.

**Simulated GitHub (recommended for e2e — no OAuth app):**
```bash
sc-adm auth-app deploy \
  --auth-hostname "$PUBIC_URL" \
  --simulate-github-token "$SIMULATE_TOKEN" \
  --admin-github-users thieso2 \
  --tailscale-auth-key "$TAILSCALE_AUTH_KEY" \
  --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory
```
> `--acme-directory` (ADR-0027, also on `sc-adm install`) is the ACME directory
> the Auth App orders Machine Certificates from for Public DNS Zone projects
> (Phase 12). e2e ALWAYS deploys with the Let's Encrypt
> **staging** URL so no production budget is spent; the default is production.
> PASS: the appliance's `/etc/sandcastle/auth-app/env` carries
> `SANDCASTLE_AUTH_ACME_DIRECTORY='https://acme-staging-v02.api.letsencrypt.org/directory'`
> and the auth-app journal logs `machine certificates: acme directory
> https://acme-staging-v02.api.letsencrypt.org/directory` at startup. An
> invalid value (not an absolute http(s) URL) is refused by deploy before any
> appliance work.

**Real OAuth app (alternative):**
```bash
sc-adm auth-app deploy \
  --auth-hostname "$PUBIC_URL" \
  --github-client-id "$GH_CLIENT_ID" \
  --github-client-secret "$GH_CLIENT_SECRET" \
  --admin-github-users thieso2
```
> Note (⚠️): running the wrapper against a multi-address remote can mangle the
> address list. Deployed here by hand into `d31c34fadc08` in project
> `infrastructure` as `sc2-auth-app` (systemd unit `sandcastle-auth-app`,
> listening `:9444`). Both paths yield the same appliance.

**PASS:** `incus exec big:sc2-auth-app --project sc2-infra -- systemctl is-active sandcastle-auth-app` → `active`, listening `:9444`.

---

### Phase 1b — Auth App idle load on the Incus host (HANDOFF-incusd-polling) 🚧 not yet run

Read-only check on a running install with tenants and machines. PASS: while
no machine is created or started, `incus monitor <remote>: --type=logging
--format=json` over 90 s shows **fewer than 10** `Handling API request`
entries for `/1.0/instances?…recursion=2` from the auth-app and no periodic
burst of `instance-file-retrieved` events; `incusd` sits below 0.2 cores.
After `sc create`, the machine's record and certificate still converge
within seconds (event-driven), and the 5-minute pass lists the fleet
**once** (one all-projects request, or none when the resource cache is
ready).

## Phase 2 — Front it on `sc-edge` (public HTTPS, LE cert, no client certs) ✅
Add a terminate vhost so `https://sc2.thieso2.dev` reverse-proxies to the auth app.

```bash
AUTH_IP=$(incus exec big:sc2-auth-app --project sc2-infra -- \
  ip -4 -o addr show eth0 | grep -oE '10\.196\.38\.[0-9]+' | head -1)
incus exec big:sc-edge --project infrastructure -- bash -c "
  grep -q '$PUBIC_URL' /etc/caddy/Caddyfile || printf '\n%s {\n    reverse_proxy http://%s:9444\n}\n' '$PUBIC_URL' '$AUTH_IP' >> /etc/caddy/Caddyfile
  caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy"
```
**PASS (all ✅ validated):**
```bash
curl -s --resolve $PUBIC_URL:443:65.21.132.31 https://$PUBIC_URL/healthz -o /dev/null -w '%{http_code}\n'   # 200
# simulated mode: a valid token mints a session (200); a wrong token → 403; unset → 404 (route unregistered)
curl -s --resolve $PUBIC_URL:443:65.21.132.31 -o /dev/null -w '%{http_code}\n' \
  "https://$PUBIC_URL/oauth/github/simulate?token=$SIMULATE_TOKEN&username=thieso2"   # 200
# real-OAuth mode instead: /login/github → 302 to github.com; callback lands at /oauth/github/callback
echo | openssl s_client -servername $PUBIC_URL -connect 65.21.132.31:443 2>/dev/null | openssl x509 -noout -issuer   # issuer=… Let's Encrypt
```

---

## Phase 3 — Provision the tenant (v2, stock Debian sidecar) ✅
Runs inside the broker appliance (has the host socket). Installs CoreDNS (binary) +
Tailscale (apt) on a **stock** Debian sidecar — no `sandcastle/base`. `TAILSCALE_AUTH_KEY`
answers the tailnet question; `--ssh-key` bakes the key into the default-project profile.

```bash
# ensure the broker runs the current fat binary
incus exec big:sc2-broker --project sc2-broker -- systemctl stop sandcastle-broker
incus file push bin/linux-amd64/sandcastle big:sc2-broker/usr/local/bin/sandcastle-admin --project sc2-broker --mode 0755
incus exec big:sc2-broker --project sc2-broker -- systemctl start sandcastle-broker

# create the tenant; capture the enrollment token
OUT=$(incus exec big:sc2-broker --project sc2-broker -- \
  /usr/local/bin/sandcastle-admin tenant create $TENANT \
  --sidecar-image $IMAGE --ssh-key "$SSHKEY" --tailscale-authkey "$TAILSCALE_AUTH_KEY")
TOKEN=$(echo "$OUT" | grep -oE 'token=[A-Za-z0-9+/=]+' | head -1 | cut -d= -f2-)
echo "token len: ${#TOKEN}"
```
**PASS:**
- Projects `sc2-e2etest` (infra) + `sc2-e2etest-default` created; bridge `sc2-e2etest` = `10.249.0.0/24`; sidecar `sc2-e2etest` at `10.249.0.3`. ✅
- CoreDNS: `incus exec big:sc2-e2etest --project sc2-e2etest -- /usr/local/bin/coredns -version` → `CoreDNS-1.14.3`, service `active`. ✅
- `$TOKEN` non-empty (~640 chars). ✅
- ⚠️ **Tailscale readiness race:** the automated `tailscale up` during create can land before `tailscaled` is ready → sidecar shows `Logged out`. Manual `tailscale up --auth-key=$TAILSCALE_AUTH_KEY --advertise-routes=10.249.0.0/24` **succeeds** (joins as `sc2-e2etest`). **Fix pending:** add a `tailscaled` readiness wait/retry in `v2TailscaleUp`.

---

## Phase 4 — Client enrollment: local incus config from scratch ✅
Wipe the local config and regenerate it from the token.

```bash
rm -rf ~/.config/sandcastle/$TENANT
./bin/sc enroll $TENANT --token "$TOKEN"       # NB: add --incus-endpoint https://<host>:8443 when the Incus host is not big
DIR=~/.config/sandcastle/$TENANT/incus
ls "$DIR"                                   # client.crt client.key config.yml servercerts/
INCUS_CONF="$DIR" incus remote list | grep $TENANT
```
**PASS (✅ validated):** `$DIR` recreated with `client.crt`/`client.key`/`config.yml`; two cert-pinned remotes — `e2etest` (base) and `e2etest-default` (project).

**PASS (restricted-cert scope):** the tenant's restricted user certificate reaches
**exactly** the infra project (`sc2-$TENANT`) plus `sc2-$TENANT-default` and no
other project — `sc-adm tenant grant $TENANT <user>` grants precisely that pair
(verify with `sc-adm tenant users $TENANT`). Any other Incus project on the daemon
(another install's, or a second app project the user was never granted) is denied
over this cert.

---

## Phase 5 — `incus remote switch <project>` works ✅
```bash
export INCUS_CONF=~/.config/sandcastle/$TENANT/incus
incus remote switch $TENANT-default
incus list                                  # empty table (no machines yet), no auth error
export INCUS_CONF=~/.config/incus-admin
```
**PASS (✅ validated):** switch succeeds; `incus list` returns cleanly over the cert-pinned remote.

---

## Phase 6 — Default-project profile: SSH key + user + cloud-init ✅
```bash
incus profile show big:default --project sc2-$TENANT-default
```
**PASS (✅ validated):** `cloud-init.user-data` contains the login user with
`shell: /bin/bash` and `ssh_authorized_keys: [ <your keys> ]`, installs
`openssh-server` only, and `runcmd: [systemctl, enable, --now, ssh]`;
devices include the shared **`workspace`** (→ `/workspace`), **`sc-platform`**
(→ `/.sc/platform`, `readonly: "true"`) and **`sc-local`** (→ `/.sc/local`)
volumes — and **no `home` device**: the shared `/home` moved to the separate
opt-in profile. `incus profile show big:homeshare --project sc2-$TENANT-default`
carries exactly one device, `home` (→ `/home`), attached only to machines
created with `--home-share`.

> **`/.sc` shared-scripts volume (ADR-0022, spec #127).** Machines carry only
> *stable shims*: the profile writes `/etc/ssh/sshrc` and appends a block to
> `/etc/zsh/zshrc` + `/etc/bash.bashrc`, each sourcing
> `/.sc/platform/<x>` then `/.sc/local/<x>` behind `[ -r … ] &&` guards (a
> missing payload fails safe — never a lockout). The script *bodies* — the
> forwarded-agent republish (`ssh/sshrc`) and consume (`shell/rc.sh`) logic,
> plus the boot-time `sbin/machine-generalize` and `sbin/caddy-setup` (run via
> stable shims at `/usr/local/sbin/sandcastle-{generalize,caddy-setup}`) —
> live in the **platform payload** on the shared `sc-platform` volume, written
> at tenant/project provisioning and updatable centrally with
> `sc-adm tenant payload-sync <tenant>` — or, tenant self-service, with
> `sc payload-sync` (no tenant argument, no install prefix: the restricted
> certificate lists only the caller's own projects and may write the volume
> inside them). Either way it is once per project, never per machine; running
> machines pick it up on next shell/SSH use. `/.sc/platform/VERSION`
> carries the content-derived payload version. **PASS:**
> - `incus exec <m> -- cat /.sc/platform/VERSION` prints `sc-payload-…` and
>   matches on every machine of the tenant;
> - `/.sc/platform` is **read-only in machines**: `incus exec <m> -- sh -c
>   'touch /.sc/platform/x'` fails (`Read-only file system`); as the login user
>   a write to `/.sc/local/` **succeeds** and the file is visible from every
>   other machine in the project;
> - a broken `/.sc/local/shell/rc.sh` (e.g. `exit`-free garbage) leaves login
>   shells and SSH working (guarded shims fail safe);
> - **central update reaches a running machine without re-create:** append a
>   marker line to `/.sc/platform/shell/rc.sh` via
>   `incus storage volume` (or run `payload-sync` from a binary with a changed
>   payload) and observe the change on an already-running machine's next
>   login; `sc-adm tenant payload-sync <t> --check` then reports the drifted
>   version, and a re-run restores (rollback = older binary's sync);
> - **the tenant can do it themselves:** logged in as a normal tenant user
>   (restricted cert, no admin remote, no prefix env), `sc payload-sync
>   --check` lists every app project of the current tenant with its payload
>   version, and `sc payload-sync` converges them — same result as the admin
>   command scoped to that tenant. With no tenant configured it fails asking
>   for `SANDCASTLE_TENANT`; a tenant whose projects the certificate cannot
>   see fails with "no app projects visible to this certificate".
>
> **Forwarded SSH agent survives multiplexers** — served from the payload:
> `/.sc/platform/ssh/sshrc` republishes each session's forwarded agent at the
> stable path `~/.ssh/ssh_auth_sock`; `/.sc/platform/shell/rc.sh` exports it.
> This keeps `ssh -A` working inside a `herdr`/`tmux` pane whose server
> outlives the ssh session that seeded `SSH_AUTH_SOCK`. Verify on a machine
> with `herdr pane split` → `ssh-add -l` → `herdr pane close`. Two guards are
> load-bearing: sshrc re-points on **every** session (heals a link left
> dangling by a closed one), and the shell consumes via `-h` (symlink
> present), **not** `-S` (live socket), so a pane opened while the link
> dangles still follows it and heals in place. This mechanism is
> image-agnostic (the shim lands via the profile/payload, not the image) and
> so also covers the Dev Image (Phase 8e) — same PASS criterion, no separate
> mechanism.
>
> **Onboarding older machines.** cloud-init runs only at first boot, so a
> machine built before /.sc shipped still has the old inline scripts (or
> nothing). `sc fix <machine>` bootstraps it: converges the project's shared
> payload over the Incus API and installs the stable shims over SSH
> (idempotent; `--check` reports shim + payload-version status without
> changing anything); `scripts/fix-agent-forwarding.sh --remote <r>:
> --project <p>` installs the shims across a whole project over `incus exec`.
> **PASS:** on an older machine, `sc fix <m> --check` prints
> `agent-forwarding: NEEDS FIX`, then `sc fix <m>` followed by
> `sc fix <m> --check` prints `agent-forwarding: OK` (payload line shows
> `current`). Projects that predate /.sc are onboarded by the sync itself:
> `sc-adm tenant payload-sync` (and `sc fix`) create the missing volumes and
> additively merge the profile's `sc-platform`/`sc-local` devices — running
> containers **and** VMs pick the new mounts up live (validated on Incus 7.2);
> a machine without zsh gets the shim only in `/etc/bash.bashrc` (`/etc/zsh/`
> is skipped, not pre-created).

> **Login user + key provenance.** `sc login` prepares the SSH key itself —
> it uses `~/.ssh/id_ed25519.pub` when present, otherwise generates
> `~/.ssh/sandcastle_ed25519` — and uploads it during the device poll; the
> auth-app stores it on the user and bakes it into this profile on every
> (re-)login, so rotating the key is just `sc login --force`. The profile's
> login **username** is the client's Unix user from device login (`$USER`),
> falling back to the deployment's `--default-unix-user`, then `dev`
> (`root` and invalid names are skipped, not errors). Broker-created tenants
> (`tenant create`) take `--ssh-key` explicitly and default to `dev`.
>
> **`sc fix <m> --only ssh-key` is additive and lists what is enrolled.** It
> runs over the Incus API (works when SSH is locked out) and never removes or
> replaces a line of the login user's `authorized_keys`: a hand-added key and an
> older CLI key both survive; the current CLI key is appended only when missing,
> inside the `# sandcastle user ssh key begin/end` block so an allowlist revoke
> can still strip every Sandcastle-managed key. **PASS:** add a foreign line
> `ssh-ed25519 AAAA… foreign` to `authorized_keys` on a machine, run
> `sc fix <m> --only ssh-key` twice: the foreign line and every pre-existing key
> are still there, the current key appears exactly once, the output prints
> `authorized_keys on <m>:` with one `ssh-keygen -l` line per key and
> `<- current CLI key` on the CLI key, and the file is byte-identical between the
> two runs. The same run puts a `# sandcastle machine <remote>:<p>:<m> begin/end`
> block at the top of the local `~/.ssh/config` (`Host <fqdn> <public names>
> <ip>` with `User`, `IdentityFile` = the CLI key, `IdentitiesOnly yes`,
> `HostKeyAlias <fqdn>`): a bare `ssh <fqdn> true` and `ssh <ip> true` succeed
> with no password prompt, the user's own lines (e.g. a `Host *` with
> `IdentityAgent`) are untouched, the second run reports `~/.ssh/config:
> current` and `--check` reports `NEEDS FIX` only before the first apply.
> `VERBOSE=1 sc c <m> -- true` prints `[verbose] ssh command: ssh -o
> IdentitiesOnly=yes -i … -o HostKeyAlias=<fqdn> … <user>@<ip> true` on stderr. The remaining fixups need the login user's NOPASSWD sudo rule; a
> sudo-rs machine (Ubuntu 25.10+) without it prints
> `sudo: I'm sorry <user>. I'm afraid I can't do that` and the fixup is reported
> failed — `ssh-key` still succeeds because it never goes through SSH. The
> `sudo` fixup repairs exactly that, over the Incus API. **PASS:** on a
> machine, as root, `rm /etc/sudoers.d/90-cloud-init-users; gpasswd -d <user>
> sudo`; `sc fix <m> --check` prints `sudo: NEEDS FIX (<user> is not in group
> sudo; /etc/sudoers.d/90-cloud-init-users lacks '<user> ALL=(ALL)
> NOPASSWD:ALL')`; `sc fix <m>` prints `sudo: installed (added <user> to group
> sudo; wrote … )` and then every SSH fixup runs (no `I'm sorry` line);
> `sc fix <m> --check` prints `sudo: OK`; the file is mode 0440, contains the
> rule exactly once after a second run, and `sudo -n true` succeeds as the user
> over `sc c <m> -- sudo -n true`.
>
> **Key reconcile is best-effort.** Writing the (re-)login key into EXISTING
> machines can fail on a machine that lacks the tenant's Unix user (e.g. one
> launched from a stock `images:` image without the Sandcastle profile). That
> must NOT abort the device login: the poll still answers `approved` with the
> enrollment token, and the CLI prints
> `Warning: SSH key was saved but not written to every existing machine: …`
> on stderr. **PASS:** with such a machine running in some project, `sc login
> --force` completes enrollment and prints the warning; stopping the machine
> (or creating the user in it) makes the warning disappear on the next login.
>
> **And best-effort is per-project, not first-failure-aborts.** A project whose
> running machines all lack the login user must not block key distribution to
> the projects reconciled after it: with a broken project AND a healthy
> multi-machine tenant, `sc login --force` **PASS:** the warning names only the
> broken project's machine(s), and `ssh <user>@<machine>` works against every
> healthy project — including ones ordered after the broken one
> (`reconcileV2` collects per-project failures with `errors.Join` instead of
> returning early; `TestMachineSSHKeyReconcilerV2ContinuesPastBrokenProject`).
> **FAIL:** machines in projects after the broken one still hold only the old
> key (the pre-fix early return, observed live on obelix 2026-08-22).

---

## Phase 7 — Launch a CT **and** a VM via `incus launch`, verify DNS + SSH ✅
The tenant launches machines into their default project. **Use the `/cloud` image
variant** — cloud-init applies the default-project profile (user `dev` + SSH key +
`openssh-server` + `systemctl enable --now ssh`). The plain image has **no cloud-init**,
so there'd be no `dev` user and SSH would be refused.

```bash
Pd="--project sc2-$TENANT-default"
incus launch images:debian/13/cloud big:ct1 $Pd          # container
incus launch images:debian/13/cloud big:vm1 $Pd --vm     # virtual machine
# wait for cloud-init (dev user + sshd) and capture IPs
declare -A IP
for m in ct1 vm1; do
  for i in $(seq 1 45); do
    a=$(incus exec big:$m $Pd -- sh -c 'ip -4 -o addr show | grep -oE "10\.249\.0\.[0-9]+" | head -1' 2>/dev/null)
    r=$(incus exec big:$m $Pd -- sh -c 'id dev >/dev/null 2>&1 && ss -ltn | grep -q ":22 " && echo ready' 2>/dev/null)
    [ "$r" = ready ] && { IP[$m]=$a; break; }; sleep 6
  done
  echo "$m = ${IP[$m]}"
done
# register A-records in the sidecar CoreDNS (now auto-registered by the auth-app reconciler within seconds of the lifecycle event (5-minute backstop); manual step optional)
incus exec big:sc2-$TENANT --project sc2-$TENANT -- bash -c "
  Z=/etc/coredns/zones/db.$TENANT
  grep -q '^ct1 ' \$Z || echo 'ct1 IN A ${IP[ct1]}' >> \$Z
  grep -q '^vm1 ' \$Z || echo 'vm1 IN A ${IP[vm1]}' >> \$Z
  sed -i 's/hostmaster.$TENANT. [0-9]*/hostmaster.$TENANT. 3/' \$Z; systemctl restart coredns"
```
**PASS (✅ validated):**
```bash
# DNS via CoreDNS resolves both
incus exec big:sc2-$TENANT --project sc2-$TENANT -- sh -c 'for n in ct1.'$TENANT' vm1.'$TENANT'; do echo "$n -> $(dig @127.0.0.1 $n +short)"; done'
#   ct1.e2etest -> 10.249.0.89   vm1.e2etest -> 10.249.0.195
# SSH into BOTH as dev with the profile-baked key (sc-dev reaches the tenant bridge via host routing)
ssh -i ~/.ssh/sandcastle_ed25519 dev@${IP[ct1]} 'echo OK $(whoami)@$(hostname) $(uname -r)'   # OK dev@ct1 7.0.x  (container)
ssh -i ~/.ssh/sandcastle_ed25519 dev@${IP[vm1]} 'echo OK $(whoami)@$(hostname) $(uname -r)'   # OK dev@vm1 6.12.x (VM kernel)
```

**Shared `/workspace` across the project (CT ↔ VM) ✅** — machines in the same
project share `/workspace` **by default** (a per-project storage volume), so a
file written on the CT is visible on the VM and vice-versa. `$HOME` is **not**
shared unless the machine was created with `--home-share`:
```bash
# write on the CT, read on the VM (and the reverse) — same project, shared volume
incus exec big:ct1 $Pd -- sh -c 'echo from-ct > /workspace/marker'
incus exec big:vm1 $Pd -- sh -c 'cat /workspace/marker'                          # → from-ct
ssh -i ~/.ssh/sandcastle_ed25519 dev@${IP[vm1]} 'echo from-vm >> /workspace/marker'
incus exec big:ct1 $Pd -- cat /workspace/marker                                   # → from-ct then from-vm
```
**PASS (✅ validated on Incus 7.2):** the VM reads `from-ct` written by the CT, and the
CT sees the VM's append — `/workspace` is one shared volume per project.
✅ **Built:** `CreateTenantV2` (and `CreateProjectV2` for later app projects) creates
per-project custom **filesystem** volumes — `workspace` (→ `/workspace`), `home`
(→ `/home`), plus the `/.sc` script layers `sc-platform` (→ `/.sc/platform`,
read-only in machines) and `sc-local` (→ `/.sc/local`) — and attaches them as
`disk` devices: everything except `home` on the `default` profile, `home` alone
on the opt-in **`homeshare`** profile. The
same fs volume attaches to a CT **and** a VM simultaneously (incus shares it via
virtiofs to the VM), so files written on any machine in the project are visible on the
others. With `--home-share` that extends to the login user's whole home directory
(cloud-init creates it with the authorized key on the first such machine; every later
one sees the same `$HOME`); without it each machine keeps a private `/home` from its
own image, which is the default because one shared home means one dotfile/state tree
for the whole project.
Validated 2026-07-04 on `igel` (tenant `hometest`, when `/home` was still on the
default profile): a CT-written `/home/dev/marker` read+appended on a VM and back,
`authorized_keys` living on the shared volume, `ssh` active on both — the same check
now applies to a pair created with `--home-share`.

> ✅ **Auto-registration is now automatic.** A background reconciler in the auth-app
> registers every running machine (incl. freeform `incus launch`) into the sidecar
> CoreDNS zone as `<name>.<suffix>` (within seconds; 5-minute backstop). Manual A-record steps below are no longer
> required — query CoreDNS by IP to verify (`dig @<sidecar-ip> <name>.<suffix>`).
> The reconciler compares against the sidecar's **live** zone (not just an in-memory
> cache), so if a sidecar restarts and loses its zone the next pass re-writes it.
> The plain image has no cloud-init → no `dev` user / sshd; always use `images:debian/13/cloud` for tenant machines.
>
> ✅ **Client name resolution is automatic (no Tailscale Split DNS needed).** `sc login`
> gives each Tenant DNS Suffix its **own systemd-resolved link scope** on Linux: a
> persistent unit (`/etc/systemd/system/sandcastle-dns-<suffix>.service`) runs the
> **`sc dns-proxy` daemon**, which creates a dummy link `scdns-<hash>` with a 169.254/16
> link-local address (resolved only activates a link's DNS scope once it carries an
> address), listens on that address (UDP+TCP :53), pins `DNS=<that address>`
> `Domains=~<suffix>` to the link, and forwards every query to the tenant CoreDNS.
> The scope's server must be **on the dummy link itself**: resolved binds a link
> scope's UDP sockets to the link, so pointing the scope straight at the (off-link)
> tenant CoreDNS blackholed UDP — resolved silently degraded that server to TCP and
> then failed ONE lookup after every ~5-min idle period when it re-probed UDP (caught
> live on majestix 2026-07-08; see appendix). macOS uses `/etc/resolver/<suffix>`
> (natively per-domain, no daemon).
> Per-domain DNS routing in systemd-resolved only works ACROSS link scopes — the earlier
> global resolved.conf.d drop-in merged every tenant's server into one flat list where
> only the rotating "current server" is asked, so with two installs one zone always died
> (see appendix). The unit is `PartOf=systemd-resolved.service`, so a resolved restart
> re-applies the scope automatically. **PASS:** after `sc login`,
> `getent hosts <machine>.<project>.<suffix>` returns the machine's private IP with no
> manual config — **for every enrolled suffix simultaneously** — public names still
> resolve, `getent hosts <machine>.<project>.<other-suffix>` is NXDOMAIN (per-install
> isolation), and the FIRST lookup still succeeds both right after
> `systemctl restart systemd-resolved` (wait for the unit to be active again) and after
> a 10-minute DNS-idle period (the resolved re-probe window that used to fail).
> A **Tailscale Split DNS** entry (route `<suffix>` → the sidecar's tailnet IP) remains a
> valid fallback (e.g. if the client can't run privileged resolver setup).

> ✅ **The `sc` CLI now speaks the v2 topology (2026-07-04, validated on `igel`).**
> From an enrolled client, `sc list` shows every instance across the tenant's v2
> projects (flat FQDN `<machine>.<suffix>`, live DHCP IP; freeform `incus launch`
> machines included), `sc create dev` launches `images:debian/13/cloud` into the
> tenant's app project via the default profile (`--vm` for a VM, `--image` to
> override; prints IP + SSH hint, no auto-connect), lifecycle commands
> (`sc delete/start/stop/restart`) act on the freeform instances, and
> `sc incus` scopes to the v2 app project (`sc incus-infra` → the
> infra project).

### Phase 7c — `sc` CLI v2 machine lifecycle (from the enrolled client) ✅
Run the whole machine lifecycle through the `sc` CLI — this is the regression net
for the tenant-topology support (each step below failed at least once before being
fixed; see the appendix).

```bash
sc c lc1 -- hostname                           # connect CREATES a missing machine: asks first, waits for sshd, SSHes
                                               #   answer `n` once → "create canceled", nothing created, then re-run and answer `y`
                                               #   (unattended: `sc c --yes lc1 -- hostname`)
sc list                                        # lc1 with flat FQDN lc1.<suffix> + live IP
sc incus exec lc1 -- sh -c '
  su - $LOGIN_USER -c "touch /workspace/ok"    # /workspace writable by the login user
  ls /home/$LOGIN_USER/.ssh/authorized_keys'   # $HOME (machine-local unless --home-share) with the key
sc stop lc1
sc c lc1 -- hostname                           # connect STARTS a stopped machine, then SSHes
sc delete lc1 --yes
sc list                                        # lc1 gone
```
**PASS (✅ validated on `igel` 2026-07-04):**
- `sc list` resolves the v2 tenant (no `Sandcastle tenant … not found`) and shows
  machines with `<name>.<suffix>` FQDNs and live IPs.
- The profile's login user (your client Unix username) exists in the machine, can
  **write `/workspace`**, and has `~/.ssh/authorized_keys` (on the machine's own
  `/home`; on the shared `/home` volume when created with `--home-share`).
- `sc c <machine>` creates a missing machine, starts a stopped one, waits for
  sshd, and lands an SSH session as the profile login user. Creating one is
  **confirmed first**: `Machine <tenant>@<remote>:default:lc1 does not exist. Create
  it? [y/N]`, and anything but `y`/`yes` cancels with `create canceled` and
  creates nothing. `--yes` skips the prompt; with no terminal the missing
  `--yes` is an error (`… pass --yes to create it`), not a silent create.
  Starting a stopped machine is **not** prompted — nothing is provisioned.
- `sc delete <machine> --yes` deletes the freeform instance (force-stops first);
  start/stop/restart work; `sc incus` targets the right project.
- `sc incus` **requires a live v2 tenant**: it reads the app project name off the
  tenant summary (it no longer derives it from the tenant name), so with no v2
  tenant for the current remote it fails with a clear error instead of targeting a
  guessed project.

#### Phase 7c-glob — wildcard machine references

The project and machine parts of a reference are globs, on both the listing and
the lifecycle commands. Quote the patterns so the shell does not expand them.

```bash
sc c --yes lc1 -- true && sc c --yes lc2 -- true && sc c --yes web-a -- true   # three machines in the current project

sc ls ':lc*'                    # machine glob within the current project
sc ls -a '*:lc*'                # …across every project: first line is the Current Position path, then project/machine names
sc ls -l -a '*:lc*'             # the table; RENDERED column = the release whose profile each machine booted with (the running release for machines created now; '-' for machines predating the stamp or Freeform Machines)
sc ls -a 'zz*:*'                # project glob matching nothing → empty listing, exit 0
sc ls 'zzznope:*'               # literal project that does not exist → error, exit 1

sc stop 'lc*'                   # acts on lc1 AND lc2, one report line each
sc ls -a '*:lc*'                # both stopped
sc start 'lc?'                  # ? matches exactly one character
sc restart '[lw]*'              # character class: lc1, lc2, web-a

sc delete 'lc*' --yes           # deletes both; without --yes the prompt NAMES both
sc delete 'zz*'                 # no match → error, exit 1
sc delete web-a --yes
```

**PASS:**
- `sc ls` filters on both parts: `-a 'g*:d*'` lists the `d*` machines of every
  project matching `g*`, and the header echoes the filter
  (`projects matching "g*", machines matching "d*"`).
- A leading part is read as a **remote** only when it names an enrolled one, so
  `sc ls 'g*:d*'` filters projects/machines and `sc ls obelix:home` still
  addresses the other install. `sc ls obelix:` still means that install's
  default project.
- A **project glob** matching nothing lists nothing and exits 0; a **literal**
  project that does not exist is an error naming the tenant's projects.
- The project filter is resolved against the tenant summary **before** any Incus
  call, so only the matching projects are queried. Check with `VERBOSE=1`:
  `sc ls -a 'g*:d*'` on a 7-project tenant must emit **one**
  `GetInstancesFull`, and a glob matching no project must emit **none**.
- Lifecycle commands act on **every** match, concurrently, reporting one line
  per machine (`stop gbrain:dev`). A failure on one machine does not stop the
  others; the command exits non-zero with `… failed on N of M machines`, and the
  successful machines are still reported as done.
- A wildcard that matches nothing is an **error** (`no machines match "lc*" …`),
  never a silent no-op. A wildcard never creates a machine — only `sc c <name>`
  with a literal name does, and only after confirming (or `--yes`).
- `sc delete '<pattern>'` interactively prompts once, naming every machine
  (`Delete 2 machines (default:lc1, default:lc2)?`); non-interactively it still
  refuses without `--yes`.
- `--json` keeps the historical `{action, tenant, project, machine}` object for a
  literal reference and returns `{action, tenant, selector, results[]}` for a
  wildcard.
- Single-target commands (`sc c`, `sc fix`, `sc route add`, `sc image save`)
  accept a glob that narrows to exactly one machine; an ambiguous glob asks
  which one (tty) or errors listing the candidates.
- A malformed pattern is rejected up front (`sc ls 'gbrain:[abc'` →
  `invalid machine pattern "[abc": syntax error in pattern`) rather than
  silently matching nothing.
#### Phase 7c-glob-installs — wildcards across enrolled installs

Requires **two enrolled installs** (see *Multi-install coexistence*). The
install part of `[[remote:]project:]machine` globs too, and then the command
sweeps every enrolled install whose name matches.

```bash
sc remote list                  # both installs enrolled; note their names

sc ls -a '*:*:*'                # every machine on every install
sc ls -a '*:*:dev'              # the dev machine of every project of every install
sc ls -a 'i*:*:*'               # only the installs matching i*
sc ls -a 'zz*:*:*'              # no install matches → error naming the enrolled ones

sc stop '*:*:dev'               # …acts on all of them, one report line each
sc c '*:*:dev'                  # ambiguous across installs → asks / errors with candidates

# Installs legitimately have different project sets:
sc ls -a '*:<project-only-on-one-install>:*'   # lists it, no error for the other install
sc stop '*:nosuchproject:api'                  # no install has it → project-not-found error
```

**PASS:**
- `sc ls -a '*:*:*'` sweeps **both** installs, gains a `REMOTE` column, and
  each row's FQDN carries **its own install's DNS suffix**
  (`wildschwein.home.idefix` vs `wildschwein.work.obelix`) — a shared summary
  would mislabel them.
- Globbing installs requires **all three parts**. `sc ls 'g*:d*'` still filters
  projects and machines, and `sc ls obelix:home` still addresses the install.
- An install pattern matches only the names `sc remote list` shows, so `*`
  never reaches system incus remotes (`images`, `local`).
- A pattern matching no install errors with
  `no enrolled Sandcastle remote matches "zz*"; enrolled remotes: …`.
- **Different project sets are normal.** `'*:<project>:<machine>'` skips an
  install that has no such project instead of failing the run; a project that
  NO install has is still a project-not-found error.
- **Unreachable install:** a lifecycle verb refuses the whole run naming the
  install (`idefix: connection refused`) rather than acting on a partial sweep
  — for `delete` that is unrecoverable. `sc ls` does the opposite: it prints
  `warning: idefix: …` and still shows the installs that answered.
- Installs are swept **sequentially** (INCUS_CONF picks the restricted
  certificate and is process-wide); the per-project and per-machine work inside
  each install is still concurrent.
- Cross-install results name their install everywhere: `stop obelix:work:dev`,
  the delete confirmation, the ambiguity candidates, and a `remote` field on
  each JSON result.
- A same-install reference never grows a remote prefix in its output, and the
  `--json` scalar payload for a literal reference is unchanged.

To verify no scope leaks: after any cross-install command, `sc ls` with no
argument must still list the **original** current install (the INCUS_CONF
binding is undone per scope).

### Phase 7e — SSH host keys are authoritative, marked, and self-healing (ADR-0020) ✅
`sc c` reads each machine's host keys **over the Incus API** (`GetInstanceFile`),
records them in `~/.ssh/known_hosts` keyed by the Machine Private Hostname (via
`-o HostKeyAlias`), and connects with `StrictHostKeyChecking=yes`. Every line it
writes is tagged `# sandcastle:<remote>/<tenant>`. There is **no** per-tenant
known_hosts file for v2, and **no** IP-keyed entry is ever written.

```bash
M=hk1
sc c --yes $M -- true                          # creates hk1; records ALL host key types, tagged
grep "^$M\." ~/.ssh/known_hosts                # one tagged line per key type

# the reported bug: rebuild the machine, its host key changes
sc delete $M --yes && sc c --yes $M -- true    # must NOT warn; must reclaim the stale name

# first boot: cloud-init deletes and regenerates every host key AFTER sshd is up
sc delete $M --yes
sc c --yes $M -- true                          # create+connect in one shot; must NOT warn
ssh -o BatchMode=yes $M.default.$SUFFIX true   # bare ssh works, by name
ssh -o BatchMode=yes $M.$SUFFIX true           # short alias too (default project, ADR-0018)

# convergence: bare ssh's UpdateHostKeys must find nothing to add
sc c $M -- true                                # silent — no known_hosts output at all

# maintenance
sc ssh-key purge --dry-run                     # reports, never writes
sc ssh-key purge --yes                         # drops tagged orphans + recycled-IP debris
```
**PASS (✅ validated on `obelix` 2026-07-09):**
- The connect prints `known_hosts: update <fqdn> … was <type> SHA256:…` exactly once
  after a rebuild, then connects. No `REMOTE HOST IDENTIFICATION HAS CHANGED`.
- `~/.ssh/known_hosts` holds **one tagged line per host key type**
  (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`), each listing both names:
  `<m>.<project>.<suffix>,<m>.<suffix> … # sandcastle:<remote>/<tenant>`.
- Bare `ssh <m>.<project>.<suffix>` and `ssh <m>.<suffix>` both succeed with no prompt.
- A **second** `sc c` after a bare `ssh` prints nothing about known_hosts — the file
  has converged and OpenSSH's `UpdateHostKeys` has nothing to append. **If this
  regresses, only one key type is being recorded.**
- Untagged IP literals inside the tenant's private CIDR are removed (the CIDR is read
  from the machine's own interface netmask; a restricted cert cannot see the bridge).
  Entries for **other** tenants/installs, `@cert-authority`, `@revoked`, comments, and
  foreign hostnames are untouched.
- The first destructive write of the day leaves `~/.ssh/known_hosts.sc-backup-<date>`.
- **A `sc c` that creates the machine connects on the first try.** On a first boot
  cloud-init deletes and regenerates every host key and restarts sshd — *after* port 22
  is already answering — so `sc c` waits for cloud-init (`/var/lib/cloud/instance/boot-finished`,
  printing `Waiting for cloud-init to finish on <m>...` if it has to) and then confirms
  the keys it read match what port 22 serves before pinning them. No
  `REMOTE HOST IDENTIFICATION HAS CHANGED`, and no second run needed. If the check has to
  wait it says `waiting for <m> to settle its SSH host keys`; a machine that never agrees
  warns instead of silently pinning a key the server does not have.
- A VM whose `incus-agent` is not running is *live but unreadable*: `sc c` falls back to
  `ssh-keyscan` and tags the line ` tofu`; `sc ssh-key purge` leaves its entries alone
  rather than treating them as orphans. A later connect that can read it drops the marker.
- `sc ssh-key purge --dry-run` does not modify the file (compare `shasum` before/after);
  without a TTY and without `--yes` it refuses.

### Phase 7d — second project via broker self-service

> Since 2026-09-22 a project created through the Auth App gets a default
> image at creation: `--image` if given, else the tenant's default project's
> image, else the install default (`images:ubuntu/26.04/cloud`). PASS: after
> `sc project create api`, `sc project list -l` shows that image in the
> IMAGE column and `sc create api:dev --dry-run` names it; the broker path
> (no Auth App) leaves the column `-`.
A tenant creates additional projects THEMSELVES through the broker's tenant
plane, authenticated by their enrolled client certificate. The broker scaffolds
the project (bridge wiring, default profile with the tenant's user + key, its
own shared `home`/`workspace` volumes) **and extends the tenant's restricted
certificate** to cover it — the admin shortcut (`sc-adm project create`)
scaffolds only.

```bash
# No flags needed after `sc login`: it records the broker URL
# (https://<tenant-gateway>:9443 — the host's :9443 reached over the subnet
# route) and the enrolled remote's client cert is used automatically.
sc project create web
# equivalent explicit form (pre-login enrollments, or overriding):
#   DIR=~/.config/sandcastle/sandcastle-$TENANT/incus
#   sc project create web --broker https://<gateway>:9443 \
#     --cert "$DIR/client.crt" --key "$DIR/client.key"

sc list                        # summary now lists project "web"
sc c --yes web:dev1 -- hostname # machine lifecycle scoped by project prefix (--yes: dev1 is new)
sc delete web:dev1 --yes
```
**PASS:**
- `sc project create web` works **with no flags** (broker URL from the saved
  login, cert/key from the enrolled remote) and returns the new project +
  writes the per-project remote (`<tenant>-web`) into the enrolled remote's
  incus config.
- `sc list`/`sc c web:dev1` work over the SAME certificate (extension applied,
  no re-login) — machines in `web` use that project's own shared volumes.

---

## Phase 7b — Expose a machine on `sc-edge` (public HTTPS) ✅
Create a machine with a name of your choice, run an app on `:3000`,
find its internal IP with the **admin** incus, and add an `sc-edge` vhost. `sc-edge`
lives in project **`infrastructure`** and reverse-proxies to the machine's internal IP
— the host routes between `incusbr0` and the tenant bridge, so `sc-edge` reaches
`10.249.0.x` directly. `*.scdev.thieso2.dev` is a CNAME to the sc-edge ingress, so any
`<name>.scdev.thieso2.dev` gets a **real Let's Encrypt** cert.

```bash
NAME=e2eweb
HOST=$NAME.scdev.thieso2.dev
# copy a VM image into the tenant project (own image store) + launch a VM
incus image copy big:73ad3e1133c5 big: --project default --target-project sc2-$TENANT-default --alias deb-vm-e2e 2>/dev/null || true
incus launch big:deb-vm-e2e big:$NAME --project sc2-$TENANT-default --vm
# find the internal IP via the ADMIN incus (this is where you read the forward target)
for i in $(seq 1 40); do VM_IP=$(INCUS_CONF=~/.config/incus-admin incus ls big: --project sc2-$TENANT-default \
  -c n4 --format csv 2>/dev/null | awk -F, "/^$NAME,/{print \$2}" | grep -oE '10\.249\.0\.[0-9]+' | head -1); [ -n "$VM_IP" ] && break; sleep 3; done
echo "$NAME -> $VM_IP"
# app on :3000
incus exec big:$NAME --project sc2-$TENANT-default -- bash -c '
  command -v python3 >/dev/null || { apt-get update -qq; apt-get install -y -qq python3; }
  echo hello-from-'$NAME'-VM-3000 > /root/index.html
  systemd-run --unit=app --collect python3 -m http.server 3000 --directory /root'
# wire sc-edge (project infrastructure) → VM:3000
incus exec big:sc-edge --project infrastructure -- bash -c "
  grep -q '$HOST' /etc/caddy/Caddyfile || printf '\n%s {\n    reverse_proxy http://%s:3000\n}\n' '$HOST' '$VM_IP' >> /etc/caddy/Caddyfile
  caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy"
```
**PASS (✅ validated):**
```bash
sleep 8
curl -s --resolve $HOST:443:65.21.132.31 https://$HOST/ -w '  [%{http_code} verify=%{ssl_verify_result}]\n'
# → hello-from-e2eweb-VM-3000  [200 verify=0]
echo | openssl s_client -servername $HOST -connect 65.21.132.31:443 2>/dev/null | openssl x509 -noout -issuer
# → issuer=… Let's Encrypt
```

---

## Phase 7f — Publish a public route with `sc route` (Spec #111) ✅
Phase 7b's manual `sc-edge` vhost is exactly what `sc route` productizes, but
against the **auth-app appliance's own Caddy**, not a separate `sc-edge`.
Requires **route ingress** — deploy with `--route-ingress acme` (on `sc-adm
install` or `sc-adm auth-app deploy`), **independent of the Auth Hostname's own
ingress**, so routes run beside a Cloudflare-tunnelled login host. Where the host
ports are already taken, `--route-ingress acme-proxied` does the same behind an
SNI proxy (variant below). `--route-base-domain`
puts routes under a separate domain from login; empty defaults to the Auth Hostname.
Auto-subdomains need a wildcard `*.<route-base-domain>` → the host's public IP (a
wildcard CNAME to a dynamic-DNS name works, tracking a changing residential IP);
a **custom FQDN** (`--hostname`) instead needs its own CNAME → the public IP. The
auth-app owns the route end to end: it records the route in its SQLite `routes`
table, adds a per-route Incus `proxy` device onto its own instance
(`listen 127.0.0.1:<local>` → `connect <machine-ip>:<port>`), regenerates
`/etc/caddy/Caddyfile` (a global `on_demand_tls { ask … }` block plus one site per
route), reloads Caddy, and gates certificate issuance through the
`/api/routes/ask` endpoint so only registered hostnames get a cert.

```bash
# As the tenant (restricted cert), with a machine "web" running an app on :3000.

# Auto-subdomain under the route base domain (rides the wildcard):
sc route publish web --port 3000
# → https://web.<tenant>.<route-base-domain>

# Custom FQDN (you CNAME it to your public IP yourself):
sc route publish web --port 3000 --hostname app.example.com

# MACHINE is the Machine Private Hostname (the FQDN `sc ls` prints), not the
# bare instance name:
sc route list          # HOSTNAME · MACHINE · PORT · STATUS
                       # → web.<tenant>.<base>  web.default.<suffix>  3000  live
sc route status <hostname>
sc route delete <hostname> --yes
```
**PASS (✅ validated live on `home`/`idefix` 2026-07-17 — login on Cloudflare
`idefix.thieso2.dev`, routes native-ACME under `home.tc42.uk`):**
- Redeploying an existing **cloudflare-login** appliance with `--route-ingress acme`
  binds host `:80/:443`, writes the **coexistence** Caddyfile (login stays
  `http://<auth-hostname>:8080`, **no** global `auto_https off`), and leaves login
  serving throughout (`<auth-hostname>/healthz` → 200 across the change).
- `sc route publish web --port 3000` → `https://web.<tenant>.<route-base-domain>`,
  `status: live`; the Caddyfile gains a `<host> { tls { on_demand } reverse_proxy
  127.0.0.1:<local> }` site and a per-route `scroute-…` proxy device appears in
  `incus config device show`.
- **Public HTTPS** `curl https://web.<tenant>.<route-base-domain>/` (no `-k`) returns
  the app body with a **real Let's Encrypt** cert (issuer `Let's Encrypt`), issued
  on the first request via HTTP-01.
- **Custom FQDN** `--hostname gurke.thieso2.dev` (own CNAME → public IP) works
  identically: `curl https://gurke.thieso2.dev/` returns the app body with a real
  Let's Encrypt cert (`subject=gurke.thieso2.dev`).
- The `/api/routes/ask` gate returns **403** for an unregistered hostname — no
  cert-issuance abuse under the wildcard.
- `sc route list` / `status` name the backend by its **Machine Private Hostname**
  (`<machine>.<project>.<Tenant DNS Suffix>` — the FQDN `sc ls` prints), so the
  row says which Machine on which project a Hostname reaches. An appliance that
  cannot resolve the suffix (or one older than this change) omits `machineFqdn`
  and the CLI falls back to the bare Machine name.
- `sc route delete <hostname> --yes` removes the site block, the proxy device, and
  the registry row; login stays up.
- **Self-heal:** machine deleted → route auto-pruned (validated live on
  `majestix` 2026-07-17: gone from `sc route list` ~10 s after the delete —
  reconcile is event-triggered on instance lifecycle, with a 5-min ticker as
  backstop); machine's IP changed while it stays alive → the reconcile
  refreshes the proxy device `connect` (asserted by `scripts/e2e-route.sh`
  step 5b, which pins a new static lease and reboots the machine, #114).
  **Prune-vs-refresh race, by design:** a DELETED machine loses its route
  within seconds — a delete+recreate "rebuild" therefore needs a re-publish;
  only an IP change on a live machine is refreshed in place. Don't read a
  pruned route after a slow rebuild as a reconcile bug.
- **Precondition:** on an install **without** route ingress, every `sc route`
  command errors with "no route ingress … redeploy with `--route-ingress acme`"
  (validated live on `majestix` install B 2026-07-17).
- **Cloudflare-zone gotcha:** a custom route FQDN on a Cloudflare zone must be
  **DNS-only (grey cloud)** — a proxied (orange) record makes Cloudflare intercept
  `:443`, so HTTP-01 never reaches the host and no cert issues.

> Validated via the auth-app's `POST/DELETE /api/routes` with the tenant token
> (the tenant `sc` restricted cert wasn't set up on the test client); the `sc route`
> CLI drives the same endpoints after a normal `sc login`.

### Variant — wildcard route (`--hostname '*.<domain>'`, #141)
A single Route can cover an open-ended set of subdomains — e.g. a push-to-deploy
platform minting a fresh `<slug>.jot.moyn.dev` per deployment — instead of
publishing one Route per name. There is no real wildcard certificate: Caddy's
`on_demand_tls` issues one leaf cert per real SNI the first time it is hit, gated
by the same `/api/routes/ask` endpoint extended to recognize a domain covered by
a registered wildcard Route (exact-match Routes are checked first and win over a
covering wildcard for the same name).

```bash
sc route publish web --port 3000 --hostname '*.jot.moyn.dev'
# → operator points a wildcard DNS record *.jot.moyn.dev at the auth host

sc route status '*.jot.moyn.dev'   # live once ANY real subdomain resolves —
                                    # the literal "*.jot.moyn.dev" is never queried
```

**PASS:**
- `sc route publish … --hostname '*.jot.moyn.dev'` succeeds and `sc route status
  '*.jot.moyn.dev'` reports `live` once the operator's wildcard DNS record is in
  place — the liveness probe resolves a random subdomain (e.g.
  `a1b2c3.jot.moyn.dev`), never the literal `*.jot.moyn.dev` string.
- Hit **at least two distinct random subdomains** under the wildcard, e.g.
  `curl https://foo1.jot.moyn.dev/` and `curl https://foo2.jot.moyn.dev/` (no
  prior publish for either name): each returns the app body from `web` over a
  **live proxied response**, with its **own** on-demand-issued certificate
  (distinct leaf certs, not one shared wildcard cert — confirm via
  `openssl s_client -connect <host>:443 -servername <subdomain>` showing
  `subject=CN=<that exact subdomain>` for each).
- `curl https://jot.moyn.dev/` (the bare zone, not covered — wildcard matches
  exactly one extra label) and a name under an **unregistered** zone both fail
  the `/api/routes/ask` gate with no cert issued.
- Publishing an exact hostname under the same zone (e.g. `sc route publish web2
  --port 3001 --hostname pinned.jot.moyn.dev`) alongside the wildcard Route
  serves `pinned.jot.moyn.dev` from `web2`, not `web` — exact beats wildcard.
- `sc route delete '*.jot.moyn.dev' --yes` removes the wildcard site block; the
  previously-hit subdomains stop resolving through this Route (their leaf certs
  simply go unused, nothing to clean up per-subdomain).

### Variant — one DNS-01 certificate for a wildcard route

Redeploy the appliance with route ingress plus a zone-scoped Cloudflare token:

```bash
sc-adm auth-app deploy … \
  --route-ingress acme-proxied \
  --route-dns-cloudflare-wildcard '*.jot.moyn.dev' \
  --route-dns-cloudflare-api-token "$ROUTE_DNS_TOKEN"
```

The token needs only `Zone:Read` and `DNS:Edit` for the wildcard route's zone.
Publish `*.jot.moyn.dev` as above.

**PASS:**
- The generated wildcard site contains `dns cloudflare
  {env.SANDCASTLE_ROUTE_DNS_CLOUDFLARE_API_TOKEN}` and no `on_demand` directive;
  an exact route in the same Caddyfile still contains `on_demand`.
- `/usr/bin/caddy list-modules` in the appliance includes the Cloudflare DNS
  provider, while a redeploy without the flag returns to the stock build.
- Two previously unseen subdomains both complete their first TLS handshake
  without creating per-host certificates. `openssl s_client` shows the same
  certificate with a `*.jot.moyn.dev` SAN for each.
- The Auth App environment contains the normalized `*.jot.moyn.dev` allowlist;
  an unlisted wildcard Route retains `on_demand` TLS.
- `/etc/sandcastle/auth-app/route-dns.env` is mode `0600`, contains only the
  route DNS token, and is empty after redeploying without the option.

### Route discovery — `sc route` and `GET /api/routes/config`
A Tenant cannot derive the route base domain or the CNAME target from anything
they can see, so the install reports both: `GET /api/routes/config` (token-gated)
returns `{enabled, ingress, baseDomain, cnameTarget}`, and bare `sc route` renders
it. The operator declares the front door with `--route-cname-target`; it is
inferred only when the Auth Hostname is itself ACME-served by the appliance (a
Cloudflare-tunnelled Auth Hostname is never used as a route target — the tunnel
carries login only).

**PASS:**
- `sc route` on an install **with** routes prints the tenant's auto-hostname
  pattern (`<name>.<tenant>.<base>`) and, when a target is known, the literal
  record `CNAME app.example.com -> <front-door>`; with no target declared it says
  to ask the admin rather than naming a wrong host.
- `sc route` warns `*.<tenant>.<base> does not resolve` when the wildcard is
  missing — the case where a publish otherwise succeeds and then sits at
  `awaiting-dns` with no explanation.
- `sc route` on an install **without** route ingress prints "not available on
  this install" plus the admin fix (`--route-ingress acme` / `acme-proxied`),
  instead of a bare 501.
- `sc route publish`/`status` append the exact CNAME line whenever the resulting
  route is `awaiting-dns`.
- The signed-in web page at the Auth Hostname shows the same facts under
  *Publish a public route*, and omits the section entirely where routes are off.

### Variant — routes behind an existing edge (`--route-ingress acme-proxied`)
When the Incus host's `:80/:443` are already held by another appliance (a shared
`sc-edge` fronting unrelated vhosts), `--route-ingress acme` cannot bind them.
`--route-ingress acme-proxied` enables Public Routes **without** adding the
`http`/`https` proxy devices: route TLS is still terminated by the appliance's
Caddy (on-demand Let's Encrypt, `/api/routes/ask` gate), and an **SNI proxy** on
the port-owning box forwards the handshake untouched to the appliance's bridge
address. The front must not terminate TLS for route hostnames — the certificate
lives in the appliance.

**PASS (✅ validated live on `big`/`obelix` 2026-07-21 — login on Cloudflare
`obelix.thieso2.dev`, routes under the same domain via `sc-edge`):**
- Redeploying the cloudflare-login appliance with `--route-ingress acme-proxied`
  leaves `incus config device list` at `root/eth0/incus-socket` (**no** `http`/
  `https` devices), writes the coexistence Caddyfile with the global
  `on_demand_tls { ask … }` block, and keeps login serving (`/` → 200 throughout).
- `sc route` stops returning the 501 no-route-ingress error and lists routes.
- With a caddy-l4 **listener wrapper** on `sc-edge` importing the Auth App's
  generated fragment (`import /etc/caddy/sandcastle/*.caddy` inside `layer4`,
  the front still binding `:80`/`:443` itself), and `:80` catch-all proxied to
  the appliance:
  `sc route publish work:test --port 8099 --hostname something.obelix.thieso2.dev`
  → `curl https://something.obelix.thieso2.dev/` returns the app body with a real
  **Let's Encrypt** cert (`CN=something.obelix.thieso2.dev`), `http://…` → **308**
  to https, and `sc route list` reports `live`.
- **Auto-hostnames work through the same wildcard**: `sc route publish work:test2
  --port 8099` (no `--hostname`) → `https://test2.thieso2.obelix.thieso2.dev`,
  live, real Let's Encrypt cert. A DNS wildcard matches multi-label names
  (RFC 4592), so `*.<base>` covers `<name>.<tenant>.<base>` — but the SNI front's
  pattern must match **any depth** below the base domain, or default publishes
  fall through to the front's own Caddy.
- The ask-gate still holds through the SNI front: an unregistered host under the
  same wildcard (`https://nope.obelix.thieso2.dev/`) fails the handshake with a
  TLS internal error — no certificate is issued.
- The front's own vhosts are unaffected (`big.thieso2.dev` 200, `grafana.` 302,
  `prometheus.` 401 basicauth) — nginx does the `http→https` redirect for them
  itself, since a Caddy on a non-standard `https_port` would put `:8443` in the
  `Location` header.
- **Pin the appliance IP** (`incus config device set <instance> eth0 ipv4.address
  <ip>`) before pointing the front at it; the bridge lease is otherwise free to
  move on restart and the SNI upstream would go stale.

### The front's SNI list is generated, not maintained (`--route-front`)
A shared front must know which hostnames to forward, and only the Auth App knows
— it is where Routes are published. Deploy with `--route-front <project>/<instance>`
and every Caddyfile regeneration also renders `/etc/caddy/sandcastle/<prefix>.caddy`
into that instance over the Incus admin socket the appliance already holds, then
runs `caddy reload` there. The front imports the directory once; one file per
install, named by install prefix, with a per-install matcher name
(`sandcastle_<prefix>`) so several sandcastles can share one front.

**PASS (✅ validated live on `big`/`obelix` 2026-07-21):**
- `sc route publish work:test2 --port 8099 --name frontloop` → within seconds the
  fragment on `sc-edge` gains `frontloop.thieso2.obelix.thieso2.dev`, and
  `curl https://frontloop.thieso2.obelix.thieso2.dev/` returns the app body —
  **no edit on the front**.
- `sc route delete … --yes` → the hostname disappears from the fragment.
- A **custom** hostname works the same way with no wildcard involved: a route on
  `brain.moyn.dev` (tenant `skorfmann`) is forwarded by SNI and served with a
  real Let's Encrypt cert issued inside the appliance.
- The front's own vhosts are untouched throughout (`big.thieso2.dev` 200,
  grafana 302, prometheus 401).
- A front that is down must not fail a publish: the Route still serves from the
  appliance, the failure is logged, and the 5-minute reconcile re-delivers.
- **Don't** try to invert this into "forward everything except the front's own
  vhosts": an empty caddy-l4 route (`route @edge_local { }`) does **not** hand
  the connection back to the HTTP app — every local vhost broke with a TLS
  handshake failure until the config was rolled back (caught live 2026-07-21).

### Non-interactive / hermetic variant (`scripts/e2e-route.sh`)
The live check above needs public DNS + inbound `:80/:443` + real Let's Encrypt.
For CI, deploy the appliance in **hermetic route-TLS mode** so the *entire chain*
runs on a LAN with no public dependencies:

```bash
sc-adm auth-app deploy … \
  --route-ingress acme --route-base-domain routes.test \
  --route-tls internal \        # route sites use Caddy's self-signed CA (no ACME/DNS)
  --debug-device-user <tenant>  # headless token via /debug/device/approve

SANDCASTLE_REMOTE=<remote> SC_AUTH_HOST=https://<auth-host> \
SC_ROUTE_BASE_DOMAIN=routes.test SC_HOST_IP=<host-ip> \
  scripts/e2e-route.sh
```
The script mints a tenant token via the debug device flow (no browser), launches a
machine running an app on `:3000`, publishes a route, and reaches it with
`curl --resolve <host>:443:<host-ip> -k` — asserting: the route serves the app
body, the Caddyfile gained the site, a `scroute-…` proxy device exists, **the
reconcile follows an IP change** (step 5b: new static lease + reboot → the
device's `connect` re-points and the route serves again, #114), the
`/api/routes/ask` gate returns **403** for an unknown host, and delete removes
everything. **PASS:** `ALL PASS — sc route non-interactive e2e`.

`--route-tls internal` is **test-only** (hidden flag / `SANDCASTLE_ROUTE_TLS=internal`);
production uses on-demand Let's Encrypt except for wildcard routes on an install
with operator-configured route DNS-01. The internal-TLS mode swaps the cert
issuer but exercises the same ingress → Caddy → proxy-device → machine plumbing; the
real-LE issuance path is covered by the live run above.

---

## Phase 8 — Tenant DNS via CoreDNS (queried at the sidecar tailscale IP) ✅
The tenant sidecar's CoreDNS serves the `<suffix>` zone (`/etc/coredns/zones/db.e2etest`).
Machine A-records live there; query CoreDNS at the **sidecar's tailscale IP** — that's the
address the split-DNS will be served on to tailnet clients later.

```bash
TSIP=$(incus exec big:sc2-$TENANT --project sc2-$TENANT -- tailscale ip -4 | head -1)
# register machine A-records + bump SOA serial + reload (now auto-registered by the auth-app reconciler within seconds of the lifecycle event (5-minute backstop); manual step optional)
incus exec big:sc2-$TENANT --project sc2-$TENANT -- bash -c '
  Z=/etc/coredns/zones/db.e2etest
  grep -q "^'$NAME' " $Z || echo "'$NAME' IN A '$VM_IP'" >> $Z
  sed -i "s/ SOA ns.e2etest. hostmaster.e2etest. [0-9]*/ SOA ns.e2etest. hostmaster.e2etest. 2/" $Z
  systemctl restart coredns; command -v dig >/dev/null || apt-get install -y -qq dnsutils'
# verify resolution AT THE TAILSCALE IP
incus exec big:sc2-$TENANT --project sc2-$TENANT -- dig @$TSIP $NAME.e2etest +short
```
**PASS (✅ validated):** `ns.e2etest → 10.249.0.3`, `web.e2etest → 10.249.0.211`,
`e2eweb.e2etest → 10.249.0.196` — correct IPs resolve at the CoreDNS tailscale IP.
> Note: the split-DNS binding over tailscale is future work; the e2e checks CoreDNS
> resolves the right IPs at its tailnet address.
> ⚠️ Machine A-records are **added manually** above — auto-registration on machine
> create is not built yet.

---

## Phase 8b — Install the tenant CA into local trust (Linux vs macOS) ⚠️
For the **private** HTTPS path (a tenant-CA-signed cert, as opposed to the public
Let's Encrypt cert from `sc-edge` in Phase 7), the client must trust the tenant CA.
The sandcastle utility installs it with **`sc trust install <tenant>`**
(`internal/localtrust`), and the mechanism **differs by OS**:

- **Linux:** writes the CA PEM into the distro's anchors directory and refreshes the
  bundle, detected by which anchors directory exists:
  - Arch: `/etc/ca-certificates/trust-source/anchors/<name>.crt` + `update-ca-trust`
  - Fedora/RHEL: `/etc/pki/ca-trust/source/anchors/<name>.crt` + `update-ca-trust`
  - openSUSE: `/etc/pki/trust/anchors/<name>.crt` + `update-ca-certificates`
  - Debian/Ubuntu (default): `/usr/local/share/ca-certificates/<name>.crt` + `update-ca-certificates`

  **PASS (Arch):** `trust list | grep -i sandcastle` shows the CA after install.
- **macOS:** `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db <ca.pem>`
  (system-wide uses `/Library/Keychains/System.keychain`). Uninstall:
  `security delete-certificate -c <trust-name>`.

```bash
sc trust install $TENANT            # installs the tenant CA into the OS trust store
sc trust install $TENANT --dry-run  # preview the per-OS plan without changing trust
```
**PASS (target):** after install, `curl https://<machine>.<suffix>/` over the private
tenant path validates **without `-k`**.

**v2 (ADR-0011):** the tenant CA is now issued by the **sidecar leaf signer**
(`sandcastle-admin sidecar tls-sign`), and `sc login` **auto-installs** it — the
v2 login branch fetches `http://<tenant .3>:9443/tls/ca` over the tenant subnet
route and installs it into the local trust store, naming the entry after the
CA's CN (`Sandcastle <suffix> tenant CA`) so same-named tenants of different
installs don't collide. The public `sc-edge` path in Phase 7 needs **no** CA
install (Let's Encrypt is already trusted).

> ✅ **Runs unprivileged** (fixed 2026-07-09, [#56](https://github.com/thieso2/sandcastle-incus/issues/56); validated on `majestix`).
> The system trust directory is root-owned but `sc` is a user command, so
> `internal/localtrust` escalates **only the two privileged operations** — writing
> the CA into the anchors directory and running the refresh command
> (`update-ca-certificates` / `update-ca-trust`) — via `sudo`, and only after the direct attempt is
> refused. Everything else keeps running as the invoking user, so `$HOME` (and the
> Sandcastle login config in it) stays reachable. `sudo` may prompt for a password.
>
> Note `update-ca-certificates` lives in `/usr/sbin`, absent from an unprivileged
> `PATH`, so exec reports *not found* rather than *permission denied*; both are
> treated as privilege symptoms and retried under `sudo`.
>
> Before the fix an ordinary `sc login` printed
> `Note: tenant CA trust install failed: … permission denied` and carried on, and
> the follow-up it suggested could not work either — `sc trust install` hit the
> same permission error, while plain `sudo sc trust install` failed with
> `… (log in first)` because sudo resets `$HOME`. Only `sudo -E` worked. Now:
>
> ```bash
> sc trust install e2edns          # rc=0, escalates internally
> curl -so /dev/null -w '%{http_code} verify=%{ssl_verify_result}\n' https://web.default.castle/
> # → 200 verify=0
> ```

> ✅ **`sc trust uninstall` removes what install wrote** (fixed 2026-07-09, [#61](https://github.com/thieso2/sandcastle-incus/issues/61)).
> A v2 trust entry is named after the tenant's DNS **suffix**
> (`Sandcastle <suffix> tenant CA`) — the signer's CN — on both the install and
> the uninstall path, so the filenames match. Previously uninstall derived the
> name from the tenant, targeted a file that never existed, removed nothing and
> reported success. An uninstall that finds nothing now says so:
> `No trusted CA named "…" was installed; nothing to remove.`
>
> The trust plan is **install-scoped** ([#60](https://github.com/thieso2/sandcastle-incus/issues/60)):
> two installs can hold a same-named tenant with different suffixes, so an
> unscoped lookup could name the other install's CA.

---

## Phase 8c — Machine HTTPS ingress: Caddy + per-machine tenant leaf (ADR-0011) ✅

Every v2 machine terminates HTTPS locally with Caddy, using a per-machine leaf
signed by the tenant CA. The **sidecar** runs `sandcastle-admin sidecar tls-sign`
on `<tenant .3>:9443` — it self-generates the tenant CA on first start (key stays
on the sidecar) and signs leaves for names in its zone. The **default-profile
cloud-init** installs Caddy, fetches this machine's leaf (`GET
/tls/leaf?fqdn=<fqdn>` → `{cert,key}`) *before* starting Caddy, and serves:
HTTP→HTTPS redirect, `/_h`→browse the login user's `$HOME`, `/_w`→browse
`/workspace`, everything else reverse-proxied to `localhost:3000` (Host preserved,
so `*.<machine>` vhosts). Caddy runs as root.

```bash
# On a fresh machine, from any tailnet-connected client (CA already trusted by sc login):
curl -sS https://<machine>.<project>.<suffix>/            # 502 until an app listens on :3000;
                                                         # 200 once it does. No -k either way —
                                                         # TLS always chains to the tenant CA.
curl -sI  http://<machine>.<project>.<suffix>/ | head -1  # 308 → https (redirect)
curl -so /dev/null -w '%{http_code}\n' https://<machine>.<project>.<suffix>/_h/  # 200 ($HOME)
curl -so /dev/null -w '%{http_code}\n' https://<machine>.<project>.<suffix>/_w/  # 200 (/workspace)
curl -sS https://foo.<machine>.<project>.<suffix>/         # wildcard vhost → :3000
```

Server-side sanity (no client trust needed):

```bash
# signer up + CA CN is suffix-scoped
incus exec sidecar --project <infra> -- systemctl is-active sandcastle-tls-sign
incus exec sidecar --project <infra> -- openssl x509 -in /etc/sandcastle/ca/ca.crt -noout -subject
#   → CN=Sandcastle <suffix> tenant CA
# leaf SANs cover the machine + wildcard
incus exec <machine> --project <default> -- openssl x509 -in /etc/sandcastle/tls/cert.pem -noout -ext subjectAltName
#   → DNS:<machine>.<project>.<suffix>, DNS:*.<machine>.<project>.<suffix>
```

**PASS (validated 2026-07-08 on idefix `ct2`):** signer self-generated
`Sandcastle idefix tenant CA`; `ct2` fetched a leaf with SANs
`[ct2.default.idefix, *.ct2.default.idefix]`; Caddy served valid HTTPS chained to
the CA (no `-k`), 308-redirected HTTP→HTTPS, proxied to `:3000`, vhosted
`*.ct2.default.idefix`, and (at the time) `/_r` browsed `/` while `/_w` browsed
`/workspace`. The file routes were later scoped to `/_h`→`$HOME` (+ `/_w`), which
also dropped the `/`-root bind-mount workaround.

> This phase is the **Machine Private Hostname** contract (Tenant CA leaf
> fetched from the sidecar) — every machine runs it. A machine with public
> names (a Project Domain, or `--hostname`) runs the same Caddy with one extra
> site block per name against a Let's Encrypt certificate the Auth App pushes —
> that is **Phase 12** (ADR-0027/0028), which also re-runs this phase as its
> private-name regression check.

### Phase 8c-bare — `sc create --bare`: HTTPS and hostname, nothing else ✅

`sc create --bare <machine>` creates a machine that boots with its canonical
Machine Private Hostname and a Caddy serving its tenant-CA leaf, and with **no
login user, no SSH key and no sshd**, and joining **none of the project's shared
storage**. Mechanically it keeps the project's `default` profile (bridge NIC,
root disk, the `/.sc` layers) and overrides two things at the **instance** level:
`cloud-init.user-data`, and the `home`/`workspace` disks, masked with Incus's
device-inhibit type (`type: none`) so they are not mounted whatever the profiles
say. `/.sc/platform` is deliberately NOT masked — the boot shims source
caddy-setup from it. The masks also make the homeshare migration a no-op on bare
machines: an appended `homeshare` profile loses to the instance-level mask. The FQDN domain
and signer URL are read back off that same default profile, so a bare machine can
never disagree with its project about the tenant's zone. It bakes the same
`sandcastle-generalize` / `sandcastle-caddy-setup` boot shims as every other
machine, so `/.sc` platform-payload updates reach it too (ADR-0022).

```bash
sc create --bare web
# → Machine <tenant>@<remote>:default:web created (container, image images:debian/13/cloud).
#   HTTPS: https://web.default.<suffix>   (Caddy with the tenant-CA leaf, …)
#   Bare: no login user, no sshd — `sc connect` will not work; …

# HTTPS works exactly as in Phase 8c (no -k: chains to the tenant CA)
curl -so /dev/null -w '%{http_code}\n' https://web.default.<suffix>/     # 502 until :3000 listens
incus exec web --project <default> -- openssl x509 -in /etc/sandcastle/tls/cert.pem -noout -ext subjectAltName
#   → DNS:web.default.<suffix>, DNS:*.web.default.<suffix>

# sc connect works — it detects the bare machine and execs a shell as root
sc c web -- 'hostname -f; id -un'
#   → Connecting: incus exec web as root (bare machine — no user, no sshd)
#     web.default.<suffix>
#     root
sc ls                                       # → TYPE column reads "CT (bare)"
sc fix web                                  # → refuses: nothing interactive to fix

# …and nothing else is there
sc incus exec web -- sh -c 'getent passwd | grep -c :2000:; systemctl is-active ssh'
#   → 0 UID-2000 users; ssh inactive (or no such unit)
sc incus exec web -- hostname -f            # → web.default.<suffix>

# no shared storage: the only volume mount left is the read-only /.sc/platform
sc incus exec web -- df --output=target | grep -E '^/(home|workspace)$'   # → no match
sc incus config device show web
#   → home: {type: none}, workspace: {type: none}   (masks, not mounts)
```

**PASS criteria:** the machine leases an IP and registers DNS like any other
machine (the reconciler reads Incus state, not machine contents); `hostname -f` is
the canonical FQDN; Caddy serves a leaf with the machine + wildcard SANs; `df`
shows neither `/home` nor `/workspace` (but still `/.sc/platform`); there is
no UID-2000 user, no `~/.ssh`, and nothing listening on `:22`; `sc connect web`
opens an Incus exec session as root (never an SSH attempt, never a timeout) and
still forwards a trailing `-- command`; `sc fix web` refuses with a reason; and
`sc list` marks the row `CT (bare)` with `"bare": true` in the JSON. A project whose default profile carries no FQDN/signer must
**refuse** the create (naming `sc project create <name>` as the fix), not launch a
machine with no certificate and no way in.

**PASS (validated 2026-08-07 on obelix `builder:tubu6`):** `home` and `workspace`
came up as `type: none` and `df` showed neither, with `/.sc/platform` and
`/.sc/local` still mounted; Caddy served a leaf with SANs
`[tubu6.builder.obelix, *.tubu6.builder.obelix]` — 502 over HTTPS with no `-k`
(nothing on `:3000` yet) and 308 on HTTP; `getent passwd` had no UID-2000 user
and `ssh` was inactive; `hostname -f` was `tubu6.builder.obelix`; and
`sc c tubu6 -- '…'` opened an Incus exec session as root, printing
`Connecting: incus exec tubu6 (bare machine — no sshd)`. Detection also caught
`tubu`, created before the marker key existed, via its userless cloud-init.

---

## Phase 9 — Unattended login without GitHub ✅
Two short-circuits bypass the GitHub browser step for CI. **Prefer the simulated-auth
path** (Phase 9a): it needs no real OAuth app at all, is token-gated, and works for any
username. The older `--debug-device-user` hack (Phase 9b) is single-user and untoken.

> **`sc login` behavior (2026-07-04, validated live on the `igel` real deployment):**
> - **Idempotent.** With a saved CLI Auth Token for the same auth host that the
>   auth-app still accepts (`GET /api/tenants`) and an enrolled remote that
>   responds, `sc login` prints `Already logged in at …` and exits — no browser,
>   no new device code. `--force` re-authenticates.
> - **Tailnet precheck.** Unless `--skip-setup` is given, login REFUSES to start
>   the device flow when the machine is not a tailnet node (tailscale missing,
>   logged out, or stopped) — e2e clients must `tailscale up --accept-routes`
>   **before** `sc login`, or pass `--skip-setup`.
> - **Layered routing diagnosis.** The post-login verification prints one ✓/✗
>   line per layer (tailscale up → accept-routes → route offered/primary → probe
>   egresses via the client's own tailnet address) and halts with advice specific
>   to the first broken layer — including the "answered via local address …, NOT
>   the tailnet" case that catches overlapping local networks.

### Phase 9a — Simulated GitHub (recommended) ✅
If the auth-app was deployed with `--simulate-github-token` (Phase 1), one command does
the whole device login offline — no browser, no GitHub, no OAuth app:

```bash
rm -rf ~/.config/sandcastle/$TENANT
./bin/sc login https://$PUBIC_URL --simulate-token "$SIMULATE_TOKEN" --as thieso2 --skip-setup
```
`--simulate-token` drives `/oauth/github/simulate` (token-gated, constant-time compare),
which auto-allowlists `--as <user>`, approves the pending device code, and mints the
session. The auth-app then **provisions the v2 tenant directly** over its mounted host
socket (`EnsurePersonalTenant` → `ensurePersonalTenantV2` → `CreateTenantV2`).

**PASS (✅ validated on vm-thieso, 2026-07-03):** login output ends with `v2 tenant
thieso2 is ready.`, `Approved as thieso2.`, and `Remote "sandcastle-thieso2" enrolled.`
The tenant sidecar (CoreDNS + Tailscale) comes up on **stock `images:debian/13` pulled
from the remote** — no cached image, no `sandcastle/base`. `--skip-setup` skips the
client-side `RunPostLoginSetup` (DNS/trust/`tailscale up`).

### Phase 9b — Legacy `--debug-device-user` short-circuit ✅
The older hidden URL `/debug/device/approve`, enabled when the auth app runs with
`--debug-device-user <gh-user>`; `sc login --debug-approve` uses it. Single fixed user,
not token-gated — kept for back-compat.

```bash
# TEMPORARILY enable on the auth app (revert after!):
incus exec big:sc2-auth-app --project sc2-infra -- bash -c \
  "sed -i \"s/^SANDCASTLE_AUTH_DEBUG_DEVICE_USER=.*/SANDCASTLE_AUTH_DEBUG_DEVICE_USER='thieso2'/\" /etc/sandcastle/auth-app/env && systemctl restart sandcastle-auth-app"

rm -rf ~/.config/sandcastle/$TENANT
./bin/sc login https://$PUBIC_URL --debug-approve --skip-setup

# ALWAYS revert (security):
incus exec big:sc2-auth-app --project sc2-infra -- bash -c \
  "sed -i \"s/^SANDCASTLE_AUTH_DEBUG_DEVICE_USER=.*/SANDCASTLE_AUTH_DEBUG_DEVICE_USER=''/\" /etc/sandcastle/auth-app/env && systemctl restart sandcastle-auth-app"
```
**PASS (✅ validated):** `--debug-approve` auto-approves (no browser); same provisioning
path and end state as Phase 9a.

> ✅ **CIDR allocation (fixed).** Provisioning now derives occupancy with
> `tenant.CIDRAllocationInputs`, which scans **all** managed projects and reads the
> CIDR from both v1 (`kind=tenant`) and v2 (`kind=infra`, `user.sandcastle.v2.cidr`)
> tenants — so a new tenant never reuses another tenant's `/24`, and re-provisioning
> an existing tenant **reuses its own** `/24` (idempotent; via `PreferredCIDR`).
> Earlier this path allocated the pool's first `/24` every time and collided
> (`dnsmasq: failed to create listening socket for <gw>: Address already in use`).
> Still keep the broker and auth-app pools from overlapping **v1** or each other
> (broker `10.249.0.0/16`, auth-app a distinct clean range like `10.250.0.0/16`):
> the allocator sees tenant-owned bridges, not arbitrary foreign/orphaned ones.

---

## Phase 8d — Base images from a running machine (`sc image`) ✅

Turn a hand-customized machine into a reusable base, no image build recipe
(ADR-0019). Save snapshots the rootfs only — the shared `/home` and `/workspace`
volumes are attached devices and are excluded by `incus publish`.

```bash
# customize a machine however you like, then:
sc image save <machine> <name>          # snapshot rootfs → local base alias (machine keeps running)
sc image list                           # NAME / FINGERPRINT / SIZE / SOURCE / CREATED
sc create <new> --image <name>          # launch a fresh machine from the base (fast: packages baked)
sc image rm <name>                      # delete the base
```

Children are generalized on first boot (`sandcastle-generalize`, before sshd):
fresh SSH host keys + machine-id, stale TLS leaf dropped; the caddy-setup then
re-fetches a leaf and rewrites `machine.env`/Caddyfile for the new FQDN.
Both `/usr/local/sbin/sandcastle-generalize` and `…/sandcastle-caddy-setup` are
stable `/.sc` **boot shims** (ADR-0022): the script bodies live in the platform
payload (`/.sc/platform/sbin/machine-generalize`, `…/sbin/caddy-setup`) and
update centrally; the shim waits briefly for the volume mount (VM virtiofs can
lag early cloud-init) then fails safe. **PASS:** on a fresh machine both sbin
files contain the `Sandcastle /.sc shim` marker (not the script bodies), and
`systemctl is-active caddy` still comes up serving the machine's HTTPS.

**PASS (validated 2026-07-08 on obelix):** planted a rootfs marker on `test`,
`sc image save test mybase` → 309.7 MB image (re-save replaced it idempotently),
`sc create probe --image mybase` launched in ~11 s. `probe` carried the marker,
got a fresh SSH host key + its own `probe.default.obelix` FQDN and `probe.*` TLS
leaf; the corrected machine-id reset was validated live (old→new random id).

---

## Phase 8e — Dev Image: `sc create --image <dev-alias>` provisioning ⚠️

Validates the third Machine Template (`images/dev/Dockerfile`, `FROM
ubuntu:26.04` — a distinct OS lineage from `base`/`ai`'s Debian) end to end: a
batteries-included interactive shell, no public HTTPS ingress. `<dev-alias>`
is whatever alias the operator built/uploaded to (by convention
`sandcastle/dev:latest`, `SANDCASTLE_DEV_IMAGE`) — `--image dev` only works
verbatim if an operator happens to publish under the literal alias `dev`.
`DefaultDevImageAlias` (`images:ubuntu/26.04`) is the zero-build fallback, the
same pattern `base`/`ai` use — **verified 2026-08-12** to exist on the public
`images:` remote (`incus image list images: ubuntu` lists `ubuntu/26.04` and
`ubuntu/26.04/cloud`, x86_64 and aarch64; a Sandcastle machine needs the
`/cloud` variant, which carries cloud-init).

```bash
sc create devbox --image <dev-alias>
sc c devbox
```

### 8e.0 — Building the image (two paths, two image *types*)

**PASS — the in-project build (`mise run image:dev:build-in-project`,
`scripts/build-image-in-project.sh`):** builds in a throwaway machine in a
Sandcastle project on the host — native host architecture, no docker on the
operator's machine, no GHCR — and publishes with `sc image save`, which yields
a **system-container** image (systemd as PID 1). Verify:
- `sc create` for the build machine prints `Dev Image: no Caddy/TLS ingress —
  SSH only.` (the script sets `SANDCASTLE_DEV_IMAGE` to the base image for that
  call so Caddy is never installed into, and so never baked into, the template).
- After the run, `sc image list` in the build project shows the alias, and the
  build machine is gone (unless `--keep`).
- On a machine created from the published image: `ps -p 1 -o comm=` → `systemd`,
  and the login user exists with a home populated from `/etc/skel` (proving
  `provision.sh clean` removed the build machine's own account rather than
  shipping it, which would make cloud-init skip user creation on the child).

**Known trap — `build-remote` produces the wrong image type.** `mise run
image:dev:build-remote` publishes to GHCR and imports with `incus image copy
ghcr:… --alias …`, which yields an **OCI** image. Incus runs OCI images as
application containers: PID 1 is the image's entrypoint, **systemd never boots**,
so sshd/caddy/anything unit-driven is dead on arrival, and launching one makes
Incus re-pull layers from ghcr.io. `build-remote` is for registry distribution,
not for producing machine images. **PASS:** `incus image info <alias>` reports
`Type: container` (not `oci`) for any alias machines are created from.

**PASS — shell/toolchain (spec B2/B4/B5):**
- `echo $SHELL` / `getent passwd $(whoami)` → `/bin/zsh` (also the image's own
  root/system default, belt-and-braces alongside the profile's independent
  `shell: /bin/zsh`).
- Prompt is one line: `user@fqdn:` left-aligned, `>` green on success / red
  after a failing command; directory + git branch right-aligned, branch
  colored by dirty/clean state (the wish's verbatim `starship.toml`).
- `fd`, `rg`, `gh`, `make`, `git` all resolve on `$PATH`.
- `mise ls` shows `go`/`node`/`herdr`/`starship` already installed (pre-resolved
  at build time — no first-boot network fetch).
- `ping -c2 <gateway>` **as the login user** succeeds. Regression guard: Ubuntu
  ships no `cap_net_raw` on `/usr/bin/ping`, and systemd's default
  `-net.ipv4.ping_group_range = 0 2147483647` silently fails in an unprivileged
  container (gid unmapped → `EINVAL`, swallowed by the `-`), leaving
  `65534 65534` and "missing cap_net_raw+p capability or setuid?".
  **PASS:** `sysctl -n net.ipv4.ping_group_range` → `0 65534`, from the image's
  `/etc/sysctl.d/99-sandcastle-ping.conf`.

**PASS — AI CLI tooling (spec B6):**
- `claude --version` and `codex --version` resolve; `~/.claude/skills`
  is populated from `mattpocock/skills`.
- `gemini` does **not** resolve — confirms the intentional non-parity with
  `ai` (the dev image installs Claude Code + Codex only).

**PASS — both status-line artifacts render/exist (spec B7/B8):**
- Claude Code: the wish's synthetic-payload command against
  `~/.claude/statusline-command.sh` produces the documented one-line output
  (model name, 10-segment context bar colored green/yellow/red, `~`-relative
  cwd, git branch, both rate-limit segments with the reset clock in local
  `HH:MM`). Requires a Nerd Font in the terminal for the folder (U+F07C) and
  branch (U+E0A0) glyphs — without one they render as placeholder boxes, not
  an error.
  ```sh
  echo '{
    "model": {"display_name": "Opus 5"},
    "context_window": {"used_percentage": 42.3},
    "workspace": {"current_dir": "'"$HOME"'"},
    "rate_limits": {
      "five_hour": {"used_percentage": 18, "resets_at": 1786000000},
      "seven_day": {"used_percentage": 73}
    }
  }' | ~/.claude/statusline-command.sh
  ```
- Codex: `~/.codex/config.toml` exists and its `[tui] status_line` stanza
  lists `model-with-reasoning`, `context-used`, `current-dir`, `git-branch`,
  `five-hour-limit`, `weekly-limit` — Codex has no command-hook status line
  (no config key runs an external script), so this is a static config
  selection, not a script to invoke. **Capability gaps, verified from
  Codex source, not faked:** `context-used` is percentage-only (no bar, no
  color ramp); `five-hour-limit`/`weekly-limit` are documented as
  **remaining**, not used; neither has a reset-time field.

**PASS — git identity self-populates (spec B9):**
- Fresh machine, before any `gh auth login`: `git config --global
  user.email` is empty; `git config --global --get-regexp 'alias\.'` already
  lists the baseline (`co`, `br`, `st`, `last`, `unstage`, `amend`).
- `gh auth login` (interactive; credential goes to `gh`'s own storage — OS
  keyring where available, 0600 file fallback — never a plaintext token file,
  never co-located with `~/.ssh/`), then a new shell: `git config --global
  user.name`/`user.email` populated from `gh api user`.
- Change `user.email` by hand, run `gh auth login` again: unchanged
  (idempotent — the hook only fires when *both* values are unset).

**PASS — no ingress, no tailnet, no SMB surface (spec B8/§Ground truth,
acceptance scenarios 6-7):**
- No Caddy process on the machine, no TLS leaf fetched, no answer on `:443`
  for its private hostname — `sc create`'s own output says so
  (`CreateMachineV2Result.DevImage` messaging: "Dev Image: no Caddy/TLS
  ingress — SSH only."). The machine keeps its login user, SSH key, and sshd
  (unlike `--bare`); its private hostname still resolves in DNS and `sc c`/
  `incus exec` still reach it.
- Not visible in `tailscale status` from another tenant machine; `smbclient
  -L` against its IP fails to connect (dev never installs Tailscale/Samba —
  satisfied by omission from the Dockerfile, no dedicated check needed beyond
  confirming the packages are absent).

**PASS — agent forwarding (spec B1) is the same PASS criterion as Phase 6's
"Forwarded SSH agent survives multiplexers"** (no new mechanism — the shim
ships via the profile/payload, image-agnostic): `ssh -A` in, `herdr pane
split`, `ssh-add -l` in the new pane, `herdr pane close`, close the original
SSH connection, reconnect fresh, `herdr attach`, confirm `ssh-add -l` (and an
agent-dependent op, e.g. `git fetch` over SSH) still works in the reattached
pane.

**Not validated live in this repo's sandbox** (no Docker daemon, no live
Incus, no authenticated Codex/gh session available where this doc was
written): an actual image build, the herdr/agent-forwarding reattach
protocol on a real Dev Image machine, and live rendering of both status
lines. Verified instead, at the source level: `go build ./...`/`go vet
./...`/`go test ./...` (including `images/dev/statusline_test.go` and
`images/dev/install_ai_cli_tools_test.go`) pass; the Codex `status_line`
identifiers and remaining-vs-used rate-limit semantics were confirmed
against `openai/codex@main`'s own source
(`codex-rs/core/config.schema.json`,
`codex-rs/tui/src/bottom_pane/status_line_setup.rs`), not a live Codex
session — see `implementation-notes.md`.

---

## Phase 10 — Self-update system (#124) ✅

Validates the update surfaces end to end: check → global update → tenant
sidecar update → skew warning. Needs at least one published GitHub release
(the release check and downloads hit `github.com/thieso2/sandcastle-incus`);
run with release-stamped binaries (goreleaser artifacts), not `make build`
dev builds — dev builds intentionally skip the release check.

```bash
# 10a — fleet check (admin): stamp-based table, one Incus listing
sc-adm update --check
# expect: auth-app + broker rows (VERSION = stamped tag, or "unknown" on
# pre-#124 deploys, noted outdated), every sidecar row marked tenant-managed;
# latest release printed; image-builder noted as carrying no binary.

# 10a-bis — the admin tree targets the install `sc ls` is on (not the ambient
# incus default remote). With no SANDCASTLE_REMOTE / admin_remote set:
sc remote list                          # note the active (*) install
sc admin update --check
# expect: 'targeting install "<active>" (the one `sc ls` is on)', and the
# fleet rows are that install's projects (<active>-infra/...), even when the
# global `incus` default remote points at a DIFFERENT host hosting a
# different sandcastle. PASS requires the install named here to equal the one
# marked * above.
# expect: no "could not tell which Incus remote hosts …" warning. If it
# appears, the fallback to the global incus default remote is in play and the
# target may be the wrong deployment — treat as FAIL unless the client is
# genuinely enrolled nowhere.
SANDCASTLE_REMOTE=<other-remote> sc admin update --check
# expect: the explicit remote wins over the active install (no warning).

# 10b — global update (admin)
sc-adm update --yes                     # or --version v<X.Y.Z> to pin/rollback
# PASS: the plan under "Updating to v<X.Y.Z>:" prints every row as
#       "<kind> <project>/<instance>  <running> -> v<X.Y.Z>" — the running version is
#       always shown next to the target ("unknown" for an unstamped appliance).
# 10b-all — the one-shot variant: components + every sidecar + every tenant's
# profiles re-rendered + this CLI. expect: the 10b lines, then one
# "ok   profiles <tenant> re-rendered" per tenant, then "ok   CLI → v<X.Y.Z>"
# (or "skip CLI" for a dev build / Homebrew install); afterwards a NEW machine
# shows v<X.Y.Z> under RENDERED in `sc ls -l`, existing machines still "-".
sc-adm update --all --yes
# expect: per-component "ok" lines; services back active
#   (systemctl is-active sandcastle-auth-app / sandcastle-broker inside the
#   appliances); user.sandcastle.binary-version stamped on both instances;
#   re-run is idempotent ("ok" again, no errors).

# 10c — tenant-facing status + sidecar update (from the enrolled client)
sc update --check
# expect: table with "sc CLI" row (vs GitHub latest) and "sidecar" row
#   (current from the signer's version header, wanted = deployment version).
sc update --yes
# expect: sidecar updated via the deployment (auth-app token plane on tunnel
#   installs, broker mTLS otherwise); ONLY sandcastle-tls-sign.service
#   restarts (verify: coredns/tailscaled uptime unchanged, tenant DNS + SSH
#   still work mid-update); the update reconciles Incus Reach, so
#   `tailscale serve status --json` in the sidecar contains raw TCP :8443 →
#   the tenant bridge gateway :8443 even when Serve state was empty before;
#   sidecar stamp = deployment version afterwards.

# 10c-i — install script (curl | bash), the install `sc update` can self-replace
curl -fsSL https://raw.githubusercontent.com/thieso2/sandcastle-incus/main/install.sh \
  | bash -s -- --dir /tmp/sc-install --version v<older>
/tmp/sc-install/sc version            # <older>; `sandcastle` is the real file, `sc` a symlink
/tmp/sc-install/sc-adm version        # only with --admin (default links `sc` alone)
# expect: SHA-256 verified against the release checksums.txt before anything is
#   written (corrupt the tarball → "checksum mismatch", nothing installed); a
#   404 release tag fails loudly; the script writes ONLY inside --dir and never
#   edits a shell profile; re-running upgrades in place.

# 10d — CLI self-update (direct install)
/tmp/sc-install/sc update --yes       # the install.sh layout self-replaces (not brew-managed)
sc update --version v<older> --yes      # roll the CLI back…
sc version                              # …binary now reports <older>, .bak kept
sc update --yes                         # …and forward to latest again
# Homebrew installs instead print `brew upgrade sandcastle` and change nothing.

# 10e — passive notice + skew warning
#   with the CLI one release behind: any sc command on a TTY prints (stderr,
#   once per 24h) the two-line "new release available / run `sc update`"
#   notice; after touching the auth-app it prints the one-line CLI↔deployment
#   skew note. SANDCASTLE_NO_UPDATE_NOTIFIER=1 silences both. Releases
#   younger than 24h are not announced (Homebrew tap grace).

# 10f — admin page version card
#   open https://<auth-hostname>/ — the version card shows the auth-app's own
#   version; green "Up to date" when current, amber "run sc-adm update" +
#   release-notes link when behind (appliance-side daily-cached GitHub check).
```

**PASS:** 10a table complete and truthful (unknown ⇒ outdated); 10b idempotent
with stamps written; 10c restarts only the leaf signer, restores missing Incus
Reach without restarting Tailscale, keeps connectivity intact, and leaves the
sidecar never ahead of the deployment; 10c-i installs a
checksum-verified binary into the requested directory as `sandcastle` + `sc`
symlink, and `sc update` then reports that install as self-updatable (not
Homebrew-managed); 10d atomic replace with `.bak` rollback artifact through the
symlink (brew installs never self-replace); 10e notices
throttled ≤1/24h per target and env-suppressible; 10f card states match the
stamps.

**Status (2026-07-17, v0.1.1 cut):** 10d validated live against the real
v0.1.1 release — dev binary pinned to v0.1.1: asset + `checksums.txt`
downloaded, SHA-256 verified, atomic replace through the `sc` symlink
(symlink preserved, `.bak` kept), new binary reports 0.1.1 and its own
`sc update --check` says current; the sidecar row correctly reads "unknown"
with no reachable deployment; the tap bumped to 0.1.1 in the same release
run. 10a/10b/10c/10e/10f still need a live deployment (majestix/obelix)
running release-stamped appliances.

**Status (2026-07-17 late, v0.1.3 cut): 10a–10f ALL validated live on the
majestix dual-install stack.** 10a: fleet tables truthful on both installs
(unknown ⇒ outdated; tunnel installs have no broker appliance, so an
auth-app-only table is correct; image-builder note printed). 10b: both
auth-apps → v0.1.3, stamped, services active, tunnels serving 200, re-run
idempotent. 10c: sidecar updated via the auth-app token plane; ONLY
`sandcastle-tls-sign` restarted (coredns/tailscaled uptimes unchanged),
sidecar stamp v0.1.3, DNS + `sc c` SSH fine afterwards. 10d re-validated on
the client VM: v0.1.3 → v0.1.2 → v0.1.3, `.bak` kept, symlinks preserved;
NOTE a root-owned `/usr/local/bin` needs the update run as root ("permission
denied" is the truthful per-user error). 10e: with the CLI at v0.1.2 the
release notice correctly did NOT fire (v0.1.3 was inside the 24h tap-grace
window — asserting the grace, not the notice); the skew note printed after
touching the deployment; **run-caught bug:** `SANDCASTLE_NO_UPDATE_NOTIFIER=1`
did not silence the skew note — fixed (gate moved into `update.SkewWarning`,
ships in v0.1.4) and suppression re-validated against the v0.1.4 release
binary. 10f: version card green "Up to date" at v0.1.3. Side finding
(pre-existing, NOT an update bug): the live e2edns profile had been rendered
by an old binary with default user `dev` + empty key (admin `tenant create`
re-run without `--unix-user`/`--ssh-key` clobbers the stored values — filed
as an issue); repaired via the product path (unattended `sc login` against
the v0.1.3 auth-app re-rendered user/key/shims and `sc c` works again).

---

## Summary
**Green today (validated live 2026-07-02):** Phases 0–9 — teardown, auth-app deploy, sc-edge
front, v2 tenant provision (stock Debian sidecar: CoreDNS + Tailscale), client enrollment,
remote switch, profile (SSH+cloud-init), CT **and** VM launched via `incus launch` with DNS +
SSH, a machine **exposed on sc-edge over public HTTPS with a real LE cert** (7b),
**tenant DNS resolving at the CoreDNS tailscale IP**, and **unattended login provisioning the
v2 tenant** (v2-only `EnsurePersonalTenant`). Tailscale-readiness race is **fixed**; the v1
Personal-Tenant login path is **removed**. The one non-green step is **Phase 8b** (private
tenant-CA trust), which stays ⚠️ pending the unbuilt per-tenant tenant-CA cert path.

**Remaining work to make every phase green:**
1. **Machine DNS auto-registration** (Phases 7/8) — write the A-record into `db.e2etest` on machine create (done manually in the e2e today).
2. **Per-tenant tenant-CA cert path** (Phase 8b) — issue a tenant CA + leaf so the *private* HTTPS path exists; then `sc trust install` (Linux/macOS) makes it trusted. (The *public* sc-edge LE path in Phase 7 already works with no CA install.)
3. **Split-DNS over tailscale** (Phase 8) — serve the tenant zone to tailnet clients on the sidecar tailscale IP.
4. ~~**Shared `$HOME` + `/workspace`** (Phase 7)~~ — ✅ done: both per-project volumes are created and attached in the default profile (tenant + later app projects).
5. **Deploy-command polish** — local-image default; fix the multi-address remote mangling so Phases 1/3 run via the CLI, not by-hand. (CIDR allocation across v1+v2 tenants and idempotent re-provision are now fixed — see the appendix.)

Phases 0–9 are validated green today; the items above are refinements, not blockers.

---

## Phase 11 — Tailnet egress (ADR-0026, opt-in) ⚠️ not yet run

Machines reaching tailnet peers *outbound* through the sidecar. Off by default;
all of a tenant's machines share the sidecar's `tag:sandcastle` ACL identity —
on a default-open ACL, enabling egress opens the whole tailnet to every machine.

```bash
# 1. Baseline: from a machine, a tailnet peer is UNREACHABLE (default route → host → public uplink drops CGNAT)
sc c dev -- sh -c 'curl -sS -m5 http://<peer-tailnet-ip>:<port>/ && echo UNEXPECTED || echo unreachable-as-expected'

# 2. Enable + converge (admin plane; the toggle alone changes nothing)
sc tailscale egress <tenant> on
sc-adm tenant create <tenant> ...      # idempotent converge applies bridge option 121 + sidecar NAT unit

# 3. Bridge carries both options now (project default)
incus network get <prefix>-<tenant> raw.dnsmasq   # dhcp-option=6,<dns> + dhcp-option=121,100.64.0.0/10,<dns>,0.0.0.0/0,<gw>

# 4. Sidecar unit + table live
incus exec sidecar --project <prefix>-<tenant> -- systemctl is-active sandcastle-sidecar-egress.service
incus exec sidecar --project <prefix>-<tenant> -- nft list table ip sandcastle-egress

# 5. ACL: grant tag:sandcastle → <peer>:<port> in the tenant's tailnet policy (packets are DROPPED until then)

# 6. Machine picks up the route on DHCP renewal (≤ lease/2) — force it, then verify
sc c dev -- sh -c 'ip route get <peer-tailnet-ip>'      # next hop must be the sidecar (.3), not .1
sc c dev -- sh -c 'curl -sS -m8 http://<peer-tailnet-ip>:<port>/'   # PASS: peer answers

# 7. Disable converges everything back
sc tailscale egress <tenant> off && sc-adm tenant create <tenant> ...   # bridge back to resolver-only, unit+table gone
```

PASS: step 1 fails closed, step 6 reaches the peer, step 7 restores the baseline.

---

## Appendix — Problems encountered & fixes (keep updating)
Log every problem hit while running this e2e and how it was resolved, so the runbook
stays truthful and self-healing.

| Problem | Root cause | Fix |
|---|---|---|
| **(2026-07-10 run)** `sc-adm tenant delete --yes` → `unknown flag: --yes` | #52 dropped the flag registration while the code still read `yes` and the error still told you to pass `--yes` | Flag restored. `TestDestructiveCommandsRegisterYes` walks both command trees and requires `--yes` on every `delete`/`destroy`/`purge` |
| **(2026-07-10 run)** `sc enroll` reported success with `0 project remote(s)` — the client could not see its own machines | Three bugs: `--incus-endpoint` defaulted to a hardcoded host; `shortProjectName` hardcoded the `sc2-` install prefix; no fallback when the daemon already trusts the client keypair. All were hidden because "added zero remotes" counted as success | Endpoint derived from the base remote/token; prefix-agnostic project matching; certificate-based fallback; enroll now fails when it can add no project remote |
| **(2026-07-10 run)** `sc login` → `incus remote add: exit status 1` | The already-trusted fallback required the sidecar's tailnet address, unknown during a first login | Fall back to the addresses the enrollment token advertises |
| **(2026-07-10 run)** `sc-adm tenant set-ssh-key` → `Storage pool not found`, then changed nothing | `CreateStorageVolumeFile`'s first argument is a **pool**; the code passed the Incus project. And the key was written to a metadata file no code reads — machines take the key from the app project's default-profile cloud-init | `SetTenantSSHKeyV2` updates `user.sandcastle.v2.sshkey` on the infra project and re-renders every app project's default profile. The test fake now rejects a project-shaped pool |
| **(2026-07-10 run)** `sc c <machine>` → `Host key verification failed` after a delete + recreate | Tenant machine IPs recycle inside the tenant `/24`, so host keys change. v1 pruned the stale entry; the v2 connect path never did | Sandcastle host keys live in `~/.config/sandcastle/known_hosts`; the entry for the target IP is dropped before connecting |
| **(2026-07-10 run)** `sc-adm tenant status <t>` printed **another install's** tenant | Two installs share one Incus daemon; the admin path did not scope by install prefix | `tenant status` / `tenant list <t>` / `set-ssh-key` scope by `IncusProjectPrefix`; `tenant list` with no argument still spans installs |
| **(2026-07-10 run)** A machine in a project created after its tenant served **no HTTPS** (`SIGNER=http://:9443`) | `CreateProjectV2` rendered the default profile without `DNSAddress`, so the machine Caddy's signer URL was empty | `tenant.DNSAddressForCIDR` derives it; `ensureV2AppProfile` now refuses to render a profile with an empty address |
| **(2026-07-10 run)** `sc project set-cloud-identity` / `set-docker-autostart` were no-ops; `sc project delete` deleted nothing | All wrote a `.sandcastle/*` file on the workspace volume that **nothing reads**. `Summary.Projects` is built from Incus projects | Settings persist on the project's own Incus project config and are read back by `v2Summaries`; `sc project delete` deletes the Incus project. A tenant certificate may not delete a project and the tenant plane has no delete endpoint — use **`sc-adm project delete <tenant> <project>`** |
| **(#68 → #70, 2026-07-10)** Tenant Storage Shares under v2 | The v1 layout (#68) was fixed and the flow verified live (create → accept → read-only mount). But the share **registry** lives in a user-writable `/workspace/.sandcastle/storage_shares` file a tenant can forge (#70), so the feature is not safe to present as supported | **Gated off.** `sc share *` exits with "not yet supported on v2 (#70)" and the Auth App share endpoints return 501; `sc status` no longer reports share health/counts. The #68 layout fixes and the plumbing stay in place, dormant behind the gate, ready for when the registry moves off the user-writable volume. Do not test shares in this runbook until #70 lands |
| **(2026-07-10 run, harness)** "the fix didn't work" for a whole hour | `incus file push` onto a **running** executable fails with `text file busy`; the error was being discarded, so the auth-app appliance kept running the pre-fix binary | Deploy stops the unit, pushes beside the target and renames over it, and **verifies every binary by sha256** |
| Appliance services won't start (`systemctl` "not booted with systemd") | Launched from an **OCI** image (app container, no systemd PID1) | Use a **CONTAINER-type systemd** image (`d31c34fadc08` / `images:debian/13`) |
| Caddy re-issues certs / ignores copied ones | Under systemd Caddy has no `$HOME` → wrong storage dir | Pin `storage file_system /root/.local/share/caddy` in the Caddyfile |
| `sc`/`sc-adm` against a multi-address remote → `lookup <addr>,https: no such host` with a concatenated address | **Solved (2026-07-04):** newer incus CLIs store a multi-address token enrollment as a comma-joined `addr` plus `last_working_address`; the vendored incus SDK's `cliconfig` predates that format and treats the joined string as one URL — the `incus` binary works while every SDK-based `sc` call fails | **Fixed:** `incusx.LoadCLIConfig` (used by every SDK connection) normalizes multi-address remotes to `last_working_address` (else the first address) |
| `incus file push` → `text file busy` | Overwriting the binary the appliance is running | `systemctl stop` the service, push, `start` |
| `incus launch big:<fp>` in the tenant project → "Image not found" | Tenant `default` project has its own image store (`features.images=true`) | `incus image copy … --target-project sc2-<tenant>-default` first |
| Sidecar has no CoreDNS/Tailscale | Neither is in Debian apt | CoreDNS **binary** download; Tailscale **official apt repo** (`installV2SidecarPackages`) |
| Sidecar Tailscale shows `Logged out` after create | `tailscale up` ran before `tailscaled` was ready | Readiness wait + retry + `tailscale ip -4` gate in `v2TailscaleUp` |
| `:3000` server won't start / `setsid` hangs `incus exec` | Minimal image lacks `python3`; detached process blocks the exec stream | `apt-get install python3`; start via `systemd-run --unit=app --collect` |
| Machine name doesn't resolve in CoreDNS | No A-record auto-registration on machine create yet | Add the record to `db.e2etest` + bump SOA + `systemctl restart coredns` (auto-reg TODO) |
| Tenant machine SSH refused / no `dev` user | Plain image has no cloud-init → profile user-data never applied | Launch tenant machines from `images:debian/13/cloud` (has cloud-init) |
| `create` / appliance deploy → `Image not provided for instance creation` | Historic: the launch code only resolved *local* aliases/fingerprints, so a stock `images:debian/13` ref wasn't pulled | **Fixed:** `imageInstanceSource` now turns an `images:…`/`ubuntu:…` ref into a simplestreams **pull** — stock images work with no pre-caching. (Bare alias/fingerprint still means a local image; the Incus server needs outbound access to `images.linuxcontainers.org`.) |
| Second v2 tenant → `dnsmasq: failed to create listening socket for <gw>: Address already in use` | Occupancy was `tenant.List`+`OccupiedCIDRs`, which only surfaces v1 `kind=tenant` projects; v2 tenants (`kind=infra`) were invisible, so the allocator re-picked the pool's first `/24` | **Fixed:** `tenant.CIDRAllocationInputs` scans v1+v2 projects for occupancy; also point pools clear of v1 (`10.248.x`) as defense-in-depth |
| Re-provision/login of an existing tenant → `Device IP address … not within network … subnet` | The v2-aware occupancy fix counted the tenant's OWN `/24` as occupied and allocated a fresh one that didn't match the existing bridge | **Fixed:** `CreateRequest.PreferredCIDR` reuses the tenant's existing `/24` (idempotent) |
| Auth-app tailnet key ignored / sidecar `Logged out` | `SANDCASTLE_AUTH_TAILSCALE_AUTHKEY` line in `/etc/sandcastle/auth-app/env` was mangled by repeated `sed` edits (concatenated key + var name) | Rewrite the line cleanly from `.env.sc2`: `sed -i "8s\|.*\|SANDCASTLE_AUTH_TAILSCALE_AUTHKEY='<key>'\|" env`, then restart |
| `sc login`/`ssh` needs the running fat binary on appliances | Appliances still ran a pre-v1-removal binary | `systemctl stop`, `incus file push bin/linux-amd64/sandcastle …/usr/local/bin/sandcastle-admin`, `systemctl start` on `sc2-broker` **and** `sc2-auth-app` |
| SSH `Too many authentication failures` reaching a tenant machine | The local ssh-agent offered many keys before the right one; server cut off at 6 | Add `-o IdentitiesOnly=yes -i ~/.ssh/sandcastle_ed25519` |
| `enroll` enrolls the base remote but project remote fails with `Error: EOF` | `--incus-endpoint` **defaults to `https://big.thieso2.dev:8443`** — wrong/unreachable on any other Incus host | Re-run `sc enroll <tenant> --incus-endpoint https://<host>:8443` (idempotent, no token needed on re-run) |
| `incus config device add <ct> tun unix-char …` on a RUNNING client CT → `Failed to add mount for device inside container` | tun unix-char hot-plug into a live CT fails (Incus 7.2) | `incus stop <ct>` → `device add` → `start` (cold-add works) |
| `dig @127.0.0.1 …` in the sidecar silently empty | stock Debian sidecar has no `dig` (dnsutils not installed by provisioning) | `apt-get install -y dnsutils` in the sidecar before DNS PASS checks (Phase 8 already does; Phase 7 checks need it too) |
| Two LIVE sidecars (different hosts/runs) both hold `enabledRoutes` for the SAME `/24` (e.g. both auth-app stacks allocate `10.250.0.0/24` first) | Every deployment uses the same default CIDR pools, and prune-on-approve only removes *same-hostname* stragglers — a sibling environment's online router survives | Verify your sidecar owns `Self.PrimaryRoutes` after provisioning; for parallel test envs use distinct pools per host, ephemeral tailnet keys, or tear down the sibling before the run |
| Client's ping to the tenant gateway succeeds (sub-ms!) yet login's routing check fails | ANOTHER deployment's bridge on the client's LAN path uses the same `/24` — the "reply" came from the local network, not the tenant (the check rejects non-tailnet egress by design) | Delete/renumber the colliding stale bridges (`incus network delete <sc2-…>` on the old host); the diagnosis now prints the answering local address |
| **(2026-07-17 Phase 10 run)** `sc c` dialed `dev@` against machines whose login user is `sc` — SSH refused | An admin `tenant create` re-run without `--unix-user`/`--ssh-key` clobbered the tenant's stored user/key back to `dev`/empty (defaulting request + additive metadata converge) and re-rendered every default profile with them (#134) | `ProvisionReuseInputs` now returns the stored user + SSH key and `PlanCreateV2` reuses them when the request is blank (the Existing\*-fallback pattern the default project already had); explicit flags still replace. A hit tenant self-heals on the next `sc login` |
| **(2026-07-22)** `sc c <project>:<m>` that CREATES the machine → `REMOTE HOST IDENTIFICATION HAS CHANGED`, and the identical command right after works | "Port 22 answers" was taken as "the host keys are final". On a first boot sshd starts with the keys the image left behind, then cloud-init's `ssh` module deletes and regenerates all of them and restarts sshd. `sc` pinned the pre-regeneration keys with `StrictHostKeyChecking=yes` (silently — adds are verbose-only), and the read even straddled the delete: it got ed25519 + ecdsa and no rsa | `sc c` waits for `/var/lib/cloud/instance/boot-finished` before reading, and cross-checks the Incus-API read against what port 22 serves (`hostKeyDisagreement`) before pinning; a mismatch re-reads until it settles |
| Making a subnet-resident machine a tailnet node breaks its OLD inbound reachability | Asymmetric routing: callers still reach it via the other router's subnet route, but its replies now leave via its own `tailscale0` and the caller's tailscaled drops them (source not in that node's allowed IPs) | Don't dual-home test clients: a client VM is EITHER reached via someone's subnet route OR is a tailnet node. For the e2e use a dedicated client VM that is a node (see the two-VM note) |
| `sc list`/`sc create`/`sc incus` on a v2 tenant → `Sandcastle tenant … not found` / `permission for project "sc-<tenant>"` | The v1 command family resolved tenants via `kind=tenant` projects and `sc-<tenant>` naming; v2 tenants have neither | **Fixed:** `tenant.List` surfaces v2 tenants from their `kind=project, version=2` Incus projects; `sc create` launches stock cloud images for v2 (`--image`/`--vm`); `sc incus*` scope to the v2 project names |
| `sc login --force` on a v2 tenant WITH machines → `reconcile User SSH Public Key … Instance not found: default-dev3` | Making v2 tenants visible to `tenant.List` armed the auth-app's v1 per-machine key reconciler, which uses v1 `<project>-<machine>` instance naming | **Fixed:** v2 tenants skip the v1 reconcile/stamp (the key lives in the profile; rotation reaches machines via the shared /home) |
| `sc delete <machine>` on a v2 tenant → `Sandcastle tenant … not found` even though `sc list` works | `filterTenantProjects` (tenant-filtered store used by lifecycle/plan paths) dropped every non-`kind=tenant` project, so v2 tenants vanished before the v2 branch could run | **Fixed:** the filter keeps `kind=project`/`kind=infra` projects whose `user.sandcastle.tenant` matches; `sc delete/start/stop/restart` now act on v2 freeform instances (Phase 7c) |
| Login user cannot write `/workspace` (`drwx--x--x root root`) | The shared volume was created with default root ownership; nothing chowned it | **Fixed:** volumes are created with `initial.uid/gid=2000, initial.mode=0775`; pre-existing tenants: one-time `chown 2000:2000 /workspace && chmod 0775 /workspace` from any machine (shared volume → fixes all) |
| On a host WITHOUT idmapped mounts (e.g. a `dir` storage pool), a **VM** cannot SSH when a CT wrote the shared `/home` first — the VM sees it owned by the CT idmap (`1002000`) and sshd StrictModes rejects it | idmapped mounts (needed for `security.shifted`) are absent, so a shared `/home` cannot show consistent ownership to both a CT and a VM | **Fixed:** the shared `/home` is opt-in — machines get a local `/home` unless created with `--home-share` (the `homeshare` profile), so SSH always works; `/workspace` stays shared. On a host without idmapped mounts, `--home-share` still hits this: provisioning logs a WARNING and the volume is unshifted. Enable idmapped mounts (a zfs/btrfs pool) for a shared `/home` across CT + VM. |
| SSH into a **VM** fails `Permission denied (publickey)` while the CT works; VM sees `/home/dev` owned by `1002000` | CT writes to the shared volume through its idmap; without `security.shifted` a VM (virtiofs, no shift) sees raw shifted owners → sshd StrictModes rejects the foreign-owned `~` | **Fixed:** shared volumes are created with `security.shifted=true`; pre-existing tenants: stop machines, `incus storage volume set default home security.shifted=true` (and `workspace`), start, then `chown -R 2000:2000 /home/<user>` once from a VM (raw view) |
| `sc list`/`sc c` on a enroll-enrolled client → `tenant is required` | `enroll` never persisted `tenant`/`remote` into `~/.config/sandcastle/config.yml` (only the login path did) | **Fixed:** `enroll` saves the tenant + base remote as local defaults |
| Second `sc login` re-runs the whole device flow instead of `Already logged in` | `/api/tenants` filtered accessibility through the v1 `ListTenantUsers` metadata, which v2 tenants don't have — the saved-token check concluded the tenant was "no longer accessible" | **Fixed:** a v2 personal tenant is accessible to the user whose key names it; also fixes `sc tenant list` for v2 |
| Tenant CIDR ignores `bootstrap --cidr-pool` when created via `incus exec … tenant create` | The flag lands in the broker **service** env (`/etc/sandcastle/broker/env`), but a direct `incus exec` CLI call doesn't inherit an EnvironmentFile | Source it in the exec: `incus exec sc2-broker … -- sh -c '. /etc/sandcastle/broker/env && export SANDCASTLE_CIDR_POOL && sandcastle-admin tenant create …'` |
| **(fixed 2026-07-09, [#53](https://github.com/thieso2/sandcastle-incus/issues/53))** `sc c <machine> -- sh -c '<script>'` silently misbehaves: `sh -c 'echo hi'` prints an empty line, `sh -c 'id -un'` prints the full `id` output, `touch X && …` reports "missing file operand" | `internal/cli/create_v2.go:266` does `sshArgs = append(sshArgs, command...)` and execs `ssh` — `ssh` joins its trailing args with **spaces** into one remote command string that the remote shell re-splits, so `sh -c` receives `echo` and `hi` as separate words. `sc incus exec` is unaffected (argv goes over the Incus API) | **Fixed:** `remoteCommandLine` renders argv as ONE shell-quoted command line before it reaches `ssh` (a lone argument still passes through raw, so `sc c web -- 'ls -l /tmp'` stays a shell snippet — matching the v1 path `incusx.remoteShellCommand`) |
| **(fixed 2026-07-09, [#54](https://github.com/thieso2/sandcastle-incus/issues/54))** A second user's `sc login` to an install **destroys the first user's enrollment on that client**: afterwards `sc list`/`sc status`/`sc c` all fail with `The remote "sc-<install>" doesn't exist` | The enrolled Incus remote is named per **install** (`sc-<auth-hostname>`), not per (install, user). A second user's login removes that remote and re-adds it; the re-add fails with `Failed to create certificate: Client is already trusted` (the client cert is already trusted from the first enrollment), leaving **no** remote behind | **Fixed:** enrollment renames the existing remote aside, adds the replacement, and only then drops the backup — a failed re-enrollment rolls back and prints "Enrollment failed; kept the existing remote". The underlying `Client is already trusted` refusal remains (the certificate-based fallback needs a tailnet address), but it is no longer destructive |
| **(fixed 2026-07-09, [#51](https://github.com/thieso2/sandcastle-incus/issues/51))** Rotating the login SSH key (regenerating `~/.ssh/sandcastle_ed25519`, then `sc login --force`) locked the user out of every EXISTING machine — `sc c web` → `Permission denied (publickey)` | The key is baked in once by cloud-init at create. Provisioning re-stamps the default-project profile, which only reaches machines created afterwards. The auth-app's per-machine reconciler was **skipped entirely for v2**, on the belief that "rotation reaches existing machines via the shared /home" — it does not, until some *new* machine's cloud-init happens to rewrite `authorized_keys` (creating one does repair it, which is why this looked intermittent). Two further traps: v2 machine listings carry no `LinuxUser`, so the reconcile script wrote to `/home/<github-user>`, and `op.Wait()` does not fail on a non-zero script exit, so that wrote nothing and reported success | **Fixed:** the reconciler is v2-aware (bare instance names, per-project Incus projects, the tenant's `UnixUser`), runs on every login, writes once per project (machines share one `/home` volume), skips stopped machines, and now surfaces a non-zero script exit |
| **(fixed 2026-07-09, [#55](https://github.com/thieso2/sandcastle-incus/issues/55))** `sc status` reported three errors on a perfectly healthy v2 tenant: `cidr: missing`, `topology: error (… permission for project "sc2-<tenant>-default-infra")`, `shares:reconcile: error (user not found / not granted access to tenant …)`; the auth-app logs a matching `POST /api/shares/reconcile status=403` | The topology check derives the infra project with the **v1** rule `naming.go:197` → `mainProjectName + "-infra"`, i.e. `sc2-<tenant>-default-infra`. Under v2 the infra project is `sc2-<tenant>` (no suffix). `Private CIDR` and the shares reconcile are broken in the same v1-vs-v2 way | **Fixed:** topology now uses `summary.InfraProject` (the v2 infra project `sc2-<tenant>`). A restricted tenant certificate is not granted the infra project at all, so `cidr` and `topology` report **unknown** with the reason instead of a red error, and `requireTenantAccess` grants a v2 personal tenant to the user whose key names it (the shares 403). Live: `cidr: unknown (stored on the infra project sc2-e2edns …)`, `topology: unknown (… run from an admin remote)`, `shares:reconcile: ok` |
| **(fixed 2026-07-09, [#56](https://github.com/thieso2/sandcastle-incus/issues/56))** `sc login` prints `Note: tenant CA trust install failed: … permission denied`, and its suggested follow-up `sc trust install <tenant>` also fails | `internal/localtrust/store.go` writes `/usr/local/share/ca-certificates/<name>.crt` and runs `update-ca-certificates` with **no privilege escalation**. Plain `sudo` fails differently — it resets `$HOME`, so the login config is unreachable (`… (log in first)`) | **Fixed:** `localtrust` escalates only the privileged operations (write the CA, `update-ca-certificates`) via `sudo`, and only after the direct attempt is refused — so the rest of the command keeps the caller's `$HOME` and the login config stays reachable. `update-ca-certificates` sits in `/usr/sbin` (off an unprivileged `PATH`), so exec's *not found* is treated as a privilege symptom too. Plain `sc trust install <tenant>` and `sc login` now both work unprivileged. See Phase 8b |
| **(fixed 2026-07-10)** Behind a Cloudflare tunnel, a first login whose tenant takes >100s to provision dies with `auth app device poll: error code: 524`; every retry 524s too | `POST /api/device/poll` ran provisioning INSIDE the request. A Cloudflare tunnel gives the origin ~100s before answering the client 524. A first tenant on a quiet host took 46.7s and squeaked under; a **second** tenant took 142.6s. The per-device lock then made every following poll queue behind the running one, so they 524'd as well | **Fixed:** provisioning runs in the background on a detached context; the poll waits a bounded `devicePollProvisionWait` (20s) and otherwise answers `pending`, so the client keeps polling (it already prints "server is provisioning"). A poll that cannot claim the lock answers `pending` immediately instead of queueing. The provisioning result (Incus add token, remote name, project, CIDR) is NOT persisted in `device_logins`, so it is held in memory until a later poll collects it. Live: a 53.3s provision, polls returning in 0ms, login succeeded |
| **(fixed 2026-07-10)** `sc status` on a v2 tenant with NO shares reports `Unreconciled share machines: 1` while `shares:reconcile` says `ok` | The share reconciler used the v1 `<project>-<machine>` instance name inside the tenant's single Incus project, so on v2 it looked up `default-web` in `sc2-<tenant>-default` and every container came back `Instance not found` → `status: failed`. `sc status` then reported `ok (N machine(s) checked)` anyway, because it never consulted `ReconcileResult.HasFailures()` | **Fixed:** the reconciler resolves v2 instance names (bare) and per-project Incus projects, and `sc status` reports `error` naming the failing machines when any machine failed |
| **(fixed 2026-07-10)** After `sc config set remote <other-install>`, `sc status` shows `shares:reconcile: error (auth app share reconcile: user not found)` — while the same token authenticates fine against the OTHER install | The CLI auth token is minted by one install's Auth App. `sc config set remote` re-pointed `auth_hostname` and (since #60) `broker`, but left `auth_token` — so the CLI presented install B's bearer token to install A (`A → 403`, `B → 200`), carrying a credential across a trust boundary | **Fixed:** `sc login` records the token per install (`auth_tokens:` map keyed by Auth Hostname) and `sc config set remote` swaps it, printing `Auth token switched to this install's token.` With none recorded for the target install it is **cleared**, so the next call fails loudly instead of shipping another install's credential |
| **(fixed 2026-07-09, [#60](https://github.com/thieso2/sandcastle-incus/issues/60))** `sc config set remote <other-install>` leaves `broker:` pointing at the PREVIOUS install's tenant gateway, so `sc trust install` fetches the wrong install's CA (`Sandcastle idefix tenant CA` while the remote is the `castle` install) and HTTPS then fails `verify=20` | `sc config set remote` re-points `remote` and `auth_hostname` but never `broker`; only `sc login` rewrites it. `sc trust install` derives the sidecar leaf signer (`.3`) from the saved broker URL | **Fixed:** `sc login` records the Broker URL per install (`brokers:` map, keyed by Auth Hostname) and `sc config set remote` re-points it — printing `Broker re-pointed to "…" for this install.` A login predating the map leaves nothing recorded, so the broker is **cleared** rather than left aimed at the previous install. The trust plan is now install-scoped too |
| **(fixed 2026-07-09, [#61](https://github.com/thieso2/sandcastle-incus/issues/61))** `sc trust uninstall <tenant>` reports success but removes nothing on a v2 tenant | The install path names the file after the CA's CN fetched from the sidecar signer (`sandcastle-<suffix>-tenant-ca.crt`); `localtrust.PlanUninstall` derives the trust name the v1 way, so the computed filename never matches and `os.Remove` hits `ErrNotExist` (treated as "already absent") | **Fixed:** the plan names a v2 trust entry after the tenant's DNS **suffix** (`Sandcastle <suffix> tenant CA`), which is the signer's CN — so uninstall targets exactly what install wrote. An uninstall that finds nothing now says `No trusted CA named "…" was installed; nothing to remove.` instead of reporting success |
| **(obsolete — #52 removed the `sc route` command family)** Public routes were unusable under Cloudflare-tunnel ingress | `--ingress cloudflare` deliberately deploys **no broker appliance**, and public-route DNS proof needed a public-IP infrastructure host | Public routes and the whole `sc route` command family were **removed** with tenant v1 (see the #52 row below); there is no longer any command to run here |
| `sc create dev` succeeds but the machine does NOT show in `sc list` (two installs, same tenant name on one daemon) | `sc list` (also `sc project`, `sc dns/trust`, `sc status`) resolved the tenant by NAME only over the unscoped `tenant.List` — the other install's same-named tenant sorts first and shadows this one; only create/connect/lifecycle/incus were install-scoped | **Fixed:** those commands resolve via `scopedListTenants` (`tenant.ListForPrefix` keyed on the current remote's install prefix); regression test `TestListMachinesScopedToCurrentInstall` |
| Shared `/home` silently NOT shared (VM can't see the CT's `/home` writes); `home` volume exists but is attached to no profile | `SupportsIdmappedMounts` keyed on `kernel_features["idmapped_mounts"] == "true"`, and **Incus 7.x stopped populating `kernel_features`** (always `{}`) — so every 7.x host looked idmapped-less and provisioning omitted the shared `/home` (and created both volumes unshifted) | **Fixed:** an ABSENT `idmapped_mounts` entry now means supported (the Incus 7.x kernel floor ≥ 5.15 includes it); only an explicit `"false"` disables the shared `/home`. Regression test `TestKernelFeaturesSupportIdmappedMounts`. **e2e check:** after provisioning, `incus profile show default --project <prefix>-<tenant>-default` lists the `workspace` device and `incus profile show homeshare …` the `home` device (they were on one profile until the 2026-08-06 split), and both volumes have `security.shifted=true` |
| `sc login --force --dns-suffix other` prints the immutable-suffix error, then hangs polling for ~10 min ("device login polling timed out") while the server re-attempts provisioning every poll | A provisioning failure always left the device login `pending` (correct for transient bring-up errors, wrong for deterministic user-input errors) | **Fixed:** terminal errors (`tenant.TerminalProvisionError`: immutable-suffix conflict, rejected suffix) DENY the device login; the client fails fast with `device login denied: <message>` and exit 1. Regression test `TestDevicePollDeniesLoginOnTerminalProvisioningError` |
| Two installs on one client (Linux): only ONE suffix ever resolves via `getent` — direct `dig @<sidecar>` works for both, and which zone dies varies | Per-domain DNS routing in systemd-resolved only works ACROSS link scopes; the global resolved.conf.d drop-ins merged both tenant servers + public upstreams into ONE flat list where only the rotating "current server" is asked — an authoritative NXDOMAIN from the wrong server ends the lookup (and the tenant servers' REFUSED responses rotate the current server onto the public upstream, killing both zones) | **Fixed:** per-suffix link scopes — `sandcastle-dns-<suffix>.service` creates a dummy link (`scdns-<hash>`, 169.254/16 addr — no address = no active scope) pinned to `DNS=<CoreDNS> Domains=~<suffix>`, `PartOf=systemd-resolved.service` so a resolved restart re-applies it; login removes any legacy drop-in. The sidecar CoreDNS also now REFUSES tailnet (100.64/10) sources outside its zone instead of forwarding them upstream (`acl` block) — machines on the bridge keep recursion. Tests: `TestSystemdResolvedUnitCreatesPerSuffixLinkScope`, `TestRenderInitial` |
| `sc-adm tenant delete <v2-tenant> --yes` prints "Deleted runtime resources … durable state preserved" but deletes NOTHING (all v2 projects, machines, sidecar, bridge survive) | `PlanDelete` is v1-shaped: it computes `sc-<tenant>` resource names that don't exist for a v2 tenant, and every per-resource delete is ignore-not-found — a silent no-op reported as success | **Fixed:** `tenant delete` detects a v2 tenant (install-prefix-scoped, `PlanDeleteV2`) and tears down app projects (machines, images, shared volumes, profiles), infra project (sidecar), and bridge via `DeleteTenantV2`; without `--purge` it REFUSES (v2 deletion is all-or-nothing — the shared volumes live in the app projects). Validated live on the `id` install with the `sc2` install's same-named tenant untouched. Tests: `TestPlanDeleteV2` |
| First `sc login` fails at the device poll with `store User SSH Public Key … database is locked (5) (SQLITE_BUSY)` | The new svclog sink writes a request/span row per request into the SAME SQLite DB as the device poll; `OpenDatabase` configured pragmas via a one-off `Exec` (one pooled connection only) and left the default rollback journal with no busy timeout | **Fixed:** pragmas moved into the DSN so every pooled connection gets them — `busy_timeout(10000)`, `journal_mode(WAL)`, `foreign_keys(1)`, `synchronous(NORMAL)`. Test: `TestOpenDatabaseConfiguresWALAndBusyTimeoutOnEveryConnection` |
| Client `getent hosts <machine>.<project>.<suffix>` fails ONE lookup after every resolved restart AND after every ~5-min DNS-idle period, while direct `dig @<CoreDNS>` always works; journal shows `Using degraded feature set UDP…`/`…TCP…` for the tenant server | systemd-resolved binds a link scope's UDP sockets to the scope's interface; the Sandcastle scope lives on a **dummy** link, so resolved's UDP queries to the off-link tenant CoreDNS were transmitted into the dummy and dropped (tcpdump: zero packets on any real interface). resolved only worked after silently degrading the server to TCP — and it re-probes UDP after each idle grace period, failing the caller's lookup each time | **Fixed:** the per-suffix unit now runs the long-lived **`sc dns-proxy`** daemon: it owns the dummy link, listens on the link's OWN 169.254 address (bound-to-link delivery of an on-link address works), pins the resolved scope to that address, and forwards UDP+TCP to the tenant CoreDNS over normal routing — UDP+EDNS0 works natively, no degradation ladder at all. Tests: `TestSystemdResolvedUnitCreatesPerSuffixLinkScope`, `TestServeDNSProxyForwardsUDPAndTCP` |
| Two installs, one client, URL-named remotes (`sc-<install-label>`): `sc list`/`sc incus`/`sc status` under install A's remote show install B's machines/project (`INCUS_PROJECT=<other-install>-…`) | `installPrefixFromRemoteName` only inverts the LEGACY remote shape `sc-<prefix>-<tenant>`; the URL-based names carry no prefix, so it returned "" and every tenant lookup ran **unscoped** — the other install's same-named tenant won, resurrecting the cross-install shadowing | **Fixed:** the install prefix is now derived from the remote's **pinned project** in the shared incus config (`remotes[<remote>].project` = `<prefix>-<tenant>[-<app>]`), with the legacy name-shape inversion as fallback. Test: `TestInstallPrefixFromRemotePinnedProject` |
| `sc-adm tenant create` on a host with the base image already cached returns success in ~5s — but the sidecar has NO CoreDNS/Tailscale (unit `failed`, `/usr/local/bin` empty); every freeform-tenant DNS/SSH check then fails. Re-running create "fixes" it | TWO stacked defects. (1) The SDK's `op.Wait()` on an exec operation only fails when the OPERATION fails — a script that ran and exited nonzero still "succeeds" (the exit code is in `Metadata["return"]`), so every `execSidecar` failure was silently swallowed. (2) With a cached image the container reaches RUNNING in ~1s, and the package-install exec raced the boot: apt had no network yet and failed — invisibly, per (1). A slow first-time image pull (the login-path timing) let the container boot first, masking the race | **Fixed:** `execExitError` surfaces nonzero command exits from every sidecar exec (install, configure, tailscale, CoreDNS restart), and `ensureV2Sidecar` now ends with `waitV2SidecarBoot` — an in-container wait for `systemctl is-system-running` ∈ {running, degraded} and a tenant IPv4 on eth0 — before any provisioning exec. Test: `TestExecExitErrorSurfacesNonzeroCommandExit` |
| Machine record present in the sidecar zone FILE and `coredns` active, yet the name doesn't resolve for up to ~1 min (which check flakes varies run to run) | The DNS reconciler's post-write CoreDNS reload exec ran with no stderr capture and no exit-code check — a failed reload (sidecar mid-provisioning, unit not yet installed) was invisible, and the next pass's live-file compare then SKIPPED the reload forever; CoreDNS's file-plugin ~1-minute reload timer was what eventually served the zone | **Fixed:** the reload exec captures stderr and propagates the command exit code (`execExitError`); a failed reload now surfaces in the auth-app log and leaves `lastZone` unset so the pass retries |
| `scripts/e2e-v2.sh`: RED exit before the summary, spurious canonical-name PASS (an `fe80::` from the machine itself), and its cleanup leaving app projects + the tenant bridge behind (poisoning the next run's CIDR allocation with `dnsmasq: Address already in use`) | Three script defects: `set -o pipefail` killed the script on the first non-resolving `getent` in a pipeline; `getent hosts` prefers AAAA and nss-myhostname answers the machine's OWN canonical name; the manual cleanup predated the v2 shared home/workspace volumes (a project won't delete while they exist) and its stack check predated `sc-adm install`'s `sc2-infra` project | **Fixed:** resolver checks use `getent ahostsv4` with `|| true` guards and 60s patience; cleanup calls `sc-adm tenant delete --yes --purge` first and its manual sweep detaches+deletes the shared volumes; the stack check accepts the auth-app in `sc2-infra` or legacy `infrastructure` |
| **(2026-07-17 run, majestix)** SECOND tenant on a shared client keypair: `sc project create <p>` → 500 `extend tenant certificate … restricted certificate "sandcastle-<tenant>" not found` — while `sc create`/machines work fine for that tenant | Incus keys trust by fingerprint: the keypair's ONE trust entry is named after whichever tenant enrolled it FIRST (`sandcastle-<first-tenant>`). Login provisioning unions the second tenant's projects into that entry **by fingerprint** (`EnsureClientCertificate`), but the tenant plane's cert extension looked the entry up **by name** and missed | Device login now records the client certificate on the user (`users.client_certificate_pem`); `POST /api/projects` passes it through and the grant falls back to the same fingerprint union when the name lookup misses (`extendTenantCertificate`); the broker plane passes its mTLS peer certificate. Tests: `TestExtendTenantCertificateFallsBackToFingerprintUnion`, `TestGrantNotFoundErrorIsSentinel` |
| **(2026-07-17 run, majestix)** `sc route delete <host> --yes` refuses with "refusing to delete route without --yes" — the flag it just got | `newRouteDeleteCommand` registered `--yes` but never read it; every call fell into the interactive confirm, which errors without a TTY | The command gates the confirm on `!yes` like every other delete. Tests: `TestRouteDeleteHonorsYesWithoutTTY`, `TestRouteDeleteWithoutYesRefusesNonInteractive` |
| **(2026-07-17 run, majestix)** `sc-adm auth-app deploy` onto a RUNNING appliance dies mid-push with `write unix @->/var/lib/incus/unix.socket: write: broken pipe` (first on the auth-app binary, then on caddy) | The deploy pushed binaries **over the running executables** — ETXTBSY aborts the Incus file-push stream. Manually stopping `sandcastle-auth-app` only moved the failure to caddy | `writeApplianceFile`/`writeBrokerFile` push to `<path>.sandcastle-push` and `mv -f` over the target — rename swaps the directory entry while the running program keeps its old inode. Redeploy now works with every service running |
| **(2026-07-17 run, majestix)** `scripts/e2e-route.sh` died silently after its first PASS; after one fix it failed `machine e2eroute never got an IP` twice | Three script defects: (1) under `set -e -o pipefail` the first empty IP poll's `grep` exit-1 killed the script; (2) `head -1` on the project image list picked the **VM** image and launched it without `--vm` (boots nothing); (3) a name-filtered `incus list <remote>:<name>` returns an **empty set** on Incus 7.2, so the poll never saw the IP | Poll guards with `\|\| true`, image pick filters `type==CONTAINER`, and the poll lists unfiltered + matches the name client-side (`awk`), like Phase 7b does |
| **(#115, fixed 2026-07-17)** Two DEAD keypairs' trust entries (previous installs, empty projects) silently regained `sc2-e2edns-backend` after this run's `sc project create backend` | `TrustManager.Grant` looks entries up by NAME and extends **every** match — any stale same-named entry is re-armed the moment a same-named tenant creates a project. The #113 sweep prevents new orphans but cannot retro-clean pre-fix ones | The tenant plane extends **fingerprint-first**: the caller's recorded certificate exactly (`EnsureClientCertificate`), then `GrantTenantFleet` syncs only same-named entries ALREADY holding one of the tenant's projects — dead/foreign entries are never touched. Name-based Grant remains only for logins predating the recorded certificate — and is itself hardened: `Grant` (the admin plane too: `sc-adm tenant grant`, the web grant) **skips entries with zero projects** (dead keypairs by definition post-#113) and errors loudly when every same-named entry is dead. Validated live (dead entry stayed empty in BOTH the tenant-plane and admin-grant paths; fleet/live entries extended; all-dead grant refused with remediation). Tests: `TestExtendTenantCertificateFingerprintFirst`, `TestGrantTenantFleetSkipsDeadAndForeignEntries`, `TestTrustManagerGrantSkipsDeadEntries`, `TestTrustManagerGrantAllDeadEntriesErrors` |
| **(#52, tenant v1 removed 2026-07-10)** Steps/PASS criteria that ran `sc route` (+ subcommands), `sc host`, `sc port`, `sc password`, `sc ssh-key`, `sc workload`, `sc dns refresh`, `sc incus-native`, `sc status <machine>`, admin `route-broker serve`, or `sc-adm … apply tenant` no longer have a command to run | Issue #52 removed the entire **tenant v1** topology (`kind=tenant` `sc-<tenant>` projects, `<project>-<machine>` instance names, and the `<project>-infra`/`<project>-native` companion projects). v2 (infra project `<prefix>-<tenant>` + one app project `<prefix>-<tenant>-<project>` + a CoreDNS sidecar) is now the only topology | **Fixed:** those user/admin commands and the `route`, `routebroker`, `hostoverride`, and `caddy/render.go` packages were deleted; public routes as a user feature are gone with `sc route`, and `sc-edge` vhosts are wired by hand (Phases 2/7b). This runbook is v2-only: `sc status` takes only a **tenant** name; `sc incus` requires a live v2 tenant (reads the app project off the tenant summary); `sc-adm tenant grant` restricts a user cert to the infra project plus `<prefix>-<tenant>-default`. The v1-only naming/metadata Go symbols were deleted too, and CI greps for them so the v1 shapes can't reappear |

---

## Appendix — Nested full-stack e2e (client CT drives the tenant via `sc login`)

A self-contained run where **one VM hosts the whole stack** (Incus + sc-edge +
auth-app + broker + the tenant sidecar + tenant machines) and **one nested
container is the tenant's client**, connecting with `sc login` and then exercising
the full tenant workflow. Validated on `sc2nest-vm1` (Debian 13, 4 vCPU / 16 GiB,
nested KVM) fronted by a Cloudflare tunnel.

### Host: latest Incus (Zabbly), not Debian's LTS
Debian 13 apt ships Incus `6.0.4` (LTS). For the newest feature release use the
Zabbly repo — this run used **Incus 7.2**:
```bash
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc
sudo tee /etc/apt/sources.list.d/zabbly-incus-stable.sources >/dev/null <<SRC
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: trixie
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/zabbly.asc
SRC
sudo apt-get update && sudo apt-get install -y incus
sudo usermod -aG incus-admin "$USER" && sudo incus admin init --minimal
```
Then deploy sc-edge (tunnel-only), auth-app, and broker as in Phases 1–2. The VM's
own `/dev/kvm` lets the tenant create **nested VMs** (`incus launch … --vm`).

### Client CT: prerequisites
The nested client container needs three things:
- **`incus-client`** — `sc login` shells out to `incus remote add` (`apt-get install -y incus-client`).
- **`tailscale`** with a **`/dev/net/tun`** device — the enrolled Incus remote is the
  sidecar's *tailnet* IP (ADR-0017), so the client must be on the tenant's tailnet:
  ```bash
  incus config device add <client> tun unix-char path=/dev/net/tun
  incus config set <client> security.nesting=true && incus restart <client>
  # inside the CT:
  curl -fsSL https://tailscale.com/install.sh | sh
  tailscale up --auth-key=$TAILSCALE_AUTH_KEY --accept-routes --hostname=<client>
  ```
- the **`sc`** binary (`incus file push bin/linux-amd64/sandcastle <client>/usr/local/bin/sc`).

### The run (from inside the client CT)
```bash
sc login https://$PUBIC_URL --simulate-token "$SIMULATE_TOKEN" --as thieso2 --skip-setup
export INCUS_CONF=~/.config/sandcastle/sandcastle-thieso2/incus
incus list --project sc2-thieso2-default                     # empty — reaches the sidecar over tailnet
incus launch images:debian/13/cloud deva --project sc2-thieso2-default        # CT
incus launch images:debian/13/cloud devb --project sc2-thieso2-default --vm   # nested VM
# … dig @<sidecar-bridge-ip> deva.thieso2 ; ssh dev@<ip> ; curl http://<ip>:3000 ; /workspace shared …
incus delete -f deva devb --project sc2-thieso2-default
```

**PASS (✅ validated):**
- `sc login` provisions the tenant + sidecar and enrols the remote at
  `https://<sidecar-tailnet-ip>:8443`; `incus list/launch/delete` of both a **CT and a
  nested VM** work over that remote.
- **DNS** auto-registration: `deva.thieso2`/`devb.thieso2` resolve at the sidecar CoreDNS.
- **SSH** as `dev` and an **HTTP app on :3000** respond on each machine.
- **Shared `/workspace`** — a file written on the CT is read on the VM and vice-versa.

### ⚠️ The one gating requirement: approve the tenant subnet route
The client reaches tenant machines (`10.x.x.N`: SSH, HTTP, and CoreDNS at `.3`) **only
once the sidecar's advertised `/24` subnet route is approved** on the tailnet. Every
sidecar is tagged **`tag:sandcastle`**, so the clean fix is the `autoApprovers` ACL
(see Prerequisites) — then the route approves the moment the sidecar advertises it, and
the client (with `--accept-routes`) reaches every machine. Without approval the sidecar's
own IP (`.3`) is reachable but machines behind it are not (`No route to host`), and
`sc login` (without `--skip-setup`) correctly **halts** at the routing check. Alternative:
approve manually in the Tailscale admin console. (There is deliberately no server-side
API-key path — approval is a tenant action on the tenant's tailnet.)

> **Stale sidecar devices blackhole an approved route.** Each teardown+rebuild (or a
> re-register) leaves the previous sidecar as a **dead tailnet device with the same
> hostname**, still advertising the tenant's `/24`. With several duplicates, Tailscale's
> subnet-router primary election can pick an **offline** one — so the route reads as
> approved yet the client still gets `No route to host`. When approving by hand,
> delete the old `sc2-<tenant>` devices in the admin console (or use an **ephemeral**
> auth key so they self-remove when offline). Symptom to recognise: the device's
> `enabledRoutes` shows the `/24` but the node's `Self.PrimaryRoutes` is `null`.

> **Co-located caveat:** in this all-in-one-VM topology the machines are also directly
> reachable from the **VM host** (host routing to the tenant bridge), which is handy for
> validation; but a *real* remote client depends on the approved subnet route, so that is
> what this appendix tests.


## Phase 12 — Public DNS Zones: Machine Public Hostnames + Let's Encrypt staging (ADR-0027/0028) ⚠️ 12a–12f ALL PASS 2026-09-13 (`docs/e2e-runs/`), 12g not yet run

A project claims a **Project Domain** under a Cloudflare zone the admin
registered; every machine created in it afterwards gets the derived **Machine
Public Hostname** `<machine>.<domain>`, and any machine can carry explicit
ones (`sc create --hostname`, `sc hostname add`, ADR-0028) — every machine
keeps its Machine Private Hostname (Tenant CA leaf, CoreDNS) and additionally
has a *set* of public names. Per public name: public `A` records (pointing at
the tenant-bridge address, reachable over the tailnet only) and one Let's
Encrypt certificate, ordered centrally over DNS-01 and pushed into the
machine's Caddy as its own site block. Spec: `docs/spec/public-dns-zones.md` +
`docs/spec/machine-hostnames.md`; user reference:
`docs/usage.html#public-dns-zones`, `#machine-hostnames`.

**Gate: `SANDCASTLE_E2E_CLOUDFLARE_TOKEN` + `SANDCASTLE_E2E_PUBLIC_DNS_ZONE`**
(a real, *dedicated* test zone the token can edit — `Zone > DNS > Edit` +
`Zone > Zone > Read` on that zone only). Put both in `.env.sc2`. **Absent →
the phase is skipped, not failed** — `make e2e-safe` prints
`SKIP: e2e Phase 12 …` and stays green; the Go test
(`TestPublicDNSZonePhase12E2E`) `t.Skip`s with the same reason.

The install is deployed with the Let's Encrypt **staging** directory (Phase 1:
`--acme-directory https://acme-staging-v02.api.letsencrypt.org/directory`), so
no production budget is spent and **browser trust is never asserted** — the
`openssl s_client` check reads the issuer and the SANs. The reconciler logs
every step as `auth-app zone reconcile: <hostname>: …`; read it with
`sc-adm incus exec <remote>:<prefix>-auth-app --project <infra-project> -- journalctl -u sandcastle-auth-app --no-pager`.
Every step below reads `sc`/`sc-adm` output; the few that look into the Auth
Database are marked **(DB)** and need `sqlite3` inside the appliance
(`apt-get install -y sqlite3` there — the stock image does not carry it).

Variables: `ZONE=$SANDCASTLE_E2E_PUBLIC_DNS_ZONE`, `RUN` a per-run id, the
project `zp`, its domain `e2e-$RUN.$ZONE`, the machine `web`. Machine
references are `<project>:<machine>` (`sc create zp:web`).

### Non-interactive variant (`scripts/e2e-pdz.sh`) — the one CI runs

```bash
# from an enrolled client: `sc login` done as a Sandcastle Admin, tenant tailnet route approved,
# dig/openssl/curl/jq on PATH, .env.sc2 carrying the two gate variables
SANDCASTLE_E2E=1 scripts/e2e.sh pdz            # sources .env.sc2, runs TestPublicDNSZonePhase12E2E → scripts/e2e-pdz.sh
SANDCASTLE_E2E=1 make e2e-safe                 # same, after the unit + gated tiers
```
The script drives 12a → 12b → 12c/12d (create: `DNS:` + `Public name:` lines,
A records at `1.1.1.1`, CERT `ok`, `sc project status`, `openssl s_client`,
wildcard vhost) → 12g (`sc create --hostname` with an apex-level name, the
derived name beside it, the private name still served, `sc hostname
add|list|remove`, per-name certificates with unchanged serials, the refusals,
`sc create --hostname` of a taken name) → 12f (`unset-domain --dry-run`
allowed with machines, zone remove refused, delete `api` then `web` → records
gone, project delete → claim released, zone removed) and prints **`ALL PASS —
Phase 12 Public DNS Zones + explicit hostnames e2e`**. It skips (exit 0)
without the variables, reuses a zone that is already registered (and then
leaves it), and tears everything down on failure (`api`, `web`, the project,
the zone) unless `SANDCASTLE_E2E_PDZ_KEEP=1`. 12e, the Freeform/Dev-Image
checks of 12d and the **(DB)**/other-tenant extras of 12g are manual.

### 12a — zone registry (admin)

```bash
sc-adm public-dns-zone add $ZONE --token-file <(printf %s "$SANDCASTLE_E2E_CLOUDFLARE_TOKEN")
# PASS: $ZONE may be the Cloudflare zone itself or a name inside it (e2e.sc.tc42.uk in tc42.uk);
#       add prints "(inside Cloudflare zone <cf-zone>, id …)" in the latter case.
sc-adm public-dns-zone list
# PASS: the zone lists with CLOUDFLARE-ZONE = the Cloudflare zone the token is scoped to, a
#       Cloudflare id, an 8-hex token fingerprint and CLAIMS 0.
# PASS: the call goes to the Auth Hostname of the install the user CLI is on (installs[<active
#       remote>], token from the same login) — never to the global file's top-level auth_hostname,
#       which may be a stale placeholder (auth.example.com) on a client with several logins; the
#       same holds with `admin_remote`/SANDCASTLE_REMOTE naming the Incus host (never a login remote).
sc-adm public-dns-zone add $ZONE --token-file <(printf %s "$SANDCASTLE_E2E_CLOUDFLARE_TOKEN")   # again
# PASS: "public DNS zone $ZONE is already registered (use set-token to rotate its token)".
sc-adm public-dns-zone add bad.${ZONE#*.} --token-file <(printf %s not-a-token)   # a SIBLING of $ZONE, not a name under it
# PASS: "Cloudflare rejected the token for zone …" and `list` is unchanged (nothing stored).
#       (a name under $ZONE would be refused by the nesting check first — that check runs before the token is tried)
sc-adm public-dns-zone add sub.$ZONE --token-file <(printf %s "$SANDCASTLE_E2E_CLOUDFLARE_TOKEN")
# PASS: "… overlaps registered zone $ZONE; zones may not nest".
# PASS: `sc admin public-dns-zone list` prints the same table (both roots, one tree);
#       `sc public-dns-zone` is "unknown command" — the verb is admin-only.
```

### 12b — Project Domain claims (tenant, after `sc login`)

```bash
sc project create zp --domain e2e-$RUN.$ZONE
sc project status zp
# PASS: `Domain: e2e-$RUN.$ZONE   (zone $ZONE)` and no machine table (the project is empty);
#       `sc incus project get <prefix>-<tenant>-zp user.sandcastle.v2.domain` = e2e-$RUN.$ZONE;
#       the project's default profile cloud-init keeps `fqdn: {{ v1.local_hostname }}.zp.<suffix>` (the private
#       identity, ADR-0028) and its machine.env gains `PUBLIC_HOSTNAMES={{ v1.local_hostname }}.e2e-$RUN.$ZONE,{{ ds.config[…] … }}`
#       — no MODE line anywhere; `sc-adm public-dns-zone list` shows CLAIMS 1.
# PASS (refusals — all `--dry-run` so nothing is created):
#   a second tenant's `sc project create x --domain e2e-$RUN.$ZONE` and `--domain a.e2e-$RUN.$ZONE`
#     → the flat "overlaps a domain already claimed on this install; choose another" (no owner named);
#   this tenant's  `sc project create y --domain a.e2e-$RUN.$ZONE`
#     → `overlaps "e2e-$RUN.$ZONE" claimed by project "zp" in this tenant`;
#   `--domain $ZONE`                     → "is a zone apex; claim at least one label below $ZONE";
#   `--domain e2e-$RUN.nosuch.example`   → "no Public DNS Zone covers … — ask your admin";
#   `--domain <auth-hostname>`           → "is reserved by this install".
sc project set-domain zp e2e-$RUN.$ZONE
# PASS: `project domain "e2e-$RUN.$ZONE" already claimed by this project`, exit 0.
sc project set-domain zp e2e-$RUN-2.$ZONE --dry-run
# PASS: `[dry-run] would have: …`; `sc project status zp` unchanged.
sc route publish <any-private-machine> --hostname x.e2e-$RUN.$ZONE
# PASS: `route hostname "x.e2e-$RUN.$ZONE" is inside project domain "e2e-$RUN.$ZONE" claimed on this install`.
sc create zp:old; sc project unset-domain zp
# PASS (ADR-0028 slice 3 — the former "has machines with a public name" refusal is retired): allowed with
#       machines; `sc project status zp` reads `Domain: (none)`; the Incus key is gone and the profile's
#       PUBLIC_HOSTNAMES line is back to the instance-record read alone (no derived name); within 60 s the
#       auth-app log shows "stamped <prefix>-<tenant>-zp/old user.sandcastle.v2.public-hostnames=(none)" and
#       "old: hostnames file pushed ((none))", `sc incus config get old user.sandcastle.v2.public-hostnames`
#       is empty, `/etc/sandcastle/hostnames` on old is empty, and old.e2e-$RUN.$ZONE's A records are gone.
sc project set-domain zp e2e-$RUN.$ZONE            # re-claim for the rest of the phase
# PASS: the reconciler re-derives old: the key reads old.e2e-$RUN.$ZONE again, the A records return, the hostnames
#       file is pushed with the name, and old reaches CERT ok (a fresh row, since the released domain dropped the
#       old one). `sc delete zp:old --yes` afterwards.
```

### 12c — machine with a derived public name: the machine contract (ADR-0028, slice 2 of #172)

```bash
sc create zp:web
# PASS: output has "DNS: web.zp.<suffix> (auto-registers within seconds)" and, under it,
#       "Public name: web.e2e-$RUN.$ZONE (A record pending, certificate pending — see: sc project status zp)"
#       (the IP: line stands alone above both) and returns without waiting;
#       `sc create zp:web2 --dry-run` prints the same DNS: + Public name lines and makes no Auth App request;
#       with the Auth App stopped the parenthesis reads
#       "certificate pending: Auth App unreachable — retried by the reconciler" and the machine is still created.
# PASS (stamp): `sc incus config get web user.sandcastle.v2.public-hostnames` = web.e2e-$RUN.$ZONE, set by the
#       create call itself (no user.sandcastle.v2.public-hostname key); a machine created in a private project
#       carries neither key; `sc ls zp:web` shows FQDN web.e2e-$RUN.$ZONE and CERT `pending`.
# PASS (machine side, once `sc incus exec web -- cloud-init status --wait` returns):
#   sc incus exec web -- hostname -f                               # → web.zp.<suffix> (the private identity)
#   sc incus exec web -- grep PUBLIC_HOSTNAMES /etc/sandcastle/machine.env
#       # → PUBLIC_HOSTNAMES=web.e2e-$RUN.$ZONE,web.e2e-$RUN.$ZONE   (derived name from the profile + the
#       #   instance record read through cloud-init's datasource; a datasource without ds.config yields a
#       #   trailing comma instead — record which one this image gives)
#   sc incus exec web -- cat /etc/sandcastle/hostnames             # → web.e2e-$RUN.$ZONE (one line, deduplicated)
#   sc incus exec web -- cat /etc/sandcastle/caddy.ready           # → PRIVATE=web.zp.<suffix> / RENDERED=<unix ts> (0644);
#       #   no PUBLIC= line yet (no certificate pushed), no MODE= line
#   sc incus exec web -- test -e /etc/systemd/system/caddy.service.d/sandcastle-zone.conf   # → absent (no drop-in)
#   sc incus exec web -- systemctl is-enabled caddy                # → enabled
#   sc incus exec web -- systemctl is-active caddy                 # → active (the private block has its leaf)
#   sc incus exec web -- ls /etc/sandcastle/tls                    # → cert.pem key.pem (the private leaf; no <name>/ dir yet)
#   sc incus exec web -- test -s /usr/local/share/ca-certificates/sandcastle-tenant.crt   # → tenant CA trusted
#   sc incus exec web -- head -1 /etc/caddy/Caddyfile              # → "web.zp.<suffix>, *.web.zp.<suffix> {"
#   sc incus exec web -- grep -c 'tls /etc/sandcastle/tls/' /etc/caddy/Caddyfile   # → 1 (private block only)
#   sc incus exec web -- /usr/local/sbin/sandcastle-caddy-setup --refresh; sc incus exec web -- systemctl is-active caddy
#       # → exit 0, Caddyfile byte-identical, marker rewritten with a newer RENDERED=, caddy active (idempotent)
#   sc restart zp:web; sc incus exec web -- systemctl is-active caddy   # → active again (no conditional start)
#   openssl s_client -connect <bridge-ip>:443 -servername web.zp.<suffix> </dev/null 2>/dev/null | openssl x509 -noout -issuer
#       # → the tenant CA issuer: the private name serves from the first boot
# PASS (connect): `sc c zp:web -- hostname -f` prints web.zp.<suffix>, the ssh line is
#       `Connecting to /<remote>/<tenant>/zp/web: ssh dev@<bridge-ip>` with HostKeyAlias=web.zp.<suffix>, and ~/.ssh/known_hosts gains ONE line
#       keyed `web.zp.<suffix>,web.e2e-$RUN.$ZONE` (private name first, then the public name) with the
#       `# sandcastle:<remote>/<tenant>` marker; `sc ssh-key purge --dry-run` reports nothing to do for it.
# PASS (private DNS): `dig web.zp.<suffix> @<sidecar-tailscale-ip>` answers the bridge IP — every machine keeps its
#       Machine Private Hostname.
```

### 12d — A records and the certificate (Let's Encrypt staging)

```bash
dig +short web.e2e-$RUN.$ZONE @1.1.1.1; dig +short x.web.e2e-$RUN.$ZONE @1.1.1.1
# PASS (≤ 60s): both answer the machine's tenant-bridge IPv4 (the IP column of `sc ls`); the Cloudflare
#       dashboard shows both records DNS-only (grey cloud), TTL 60; the auth-app log has
#       "zone reconcile: zone $ZONE: set 2 A record(s)" exactly once — later passes make no writes.
sc ls zp:web; sc project status zp
# PASS (≤ 5 min): the auth-app log shows, in order, "web.e2e-$RUN.$ZONE: certificate <serial> issued" and
#       "certificate <serial> installed on <prefix>-<tenant>-zp/web"; `sc ls` CERT reads `ok`;
#       `sc project status zp` shows `installed` with a NOT AFTER ~90 days out;
#       `sc incus config get web user.sandcastle.v2.cert-state` = `web.e2e-$RUN.$ZONE=installed` (per name since
#       ADR-0028 slice 3) and `… user.sandcastle.v2.cert-not-after` equals that NOT AFTER (RFC 3339 UTC).
# PASS (machine side after the push): /etc/sandcastle/tls/web.e2e-$RUN.$ZONE/ holds cert.pem (0644) and key.pem
#       (0600), no *.new leftovers; the private leaf /etc/sandcastle/tls/{cert,key}.pem is untouched;
#       /etc/sandcastle/caddy.ready now has `PUBLIC=web.e2e-$RUN.$ZONE` and a newer RENDERED=; the Caddyfile has
#       a second block "web.e2e-$RUN.$ZONE, *.web.e2e-$RUN.$ZONE {" with `tls /etc/sandcastle/tls/web.e2e-$RUN.$ZONE/…`;
#       `systemctl is-active caddy` → active; `journalctl -u caddy` shows one start and one reload
#       (the push's `sandcastle-caddy-setup --refresh`), no failure loop.
openssl s_client -connect <bridge-ip>:443 -servername web.e2e-$RUN.$ZONE </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName -issuer
# PASS: both SANs `DNS:web.e2e-$RUN.$ZONE, DNS:*.web.e2e-$RUN.$ZONE` and an issuer from the Let's Encrypt
#       STAGING hierarchy ("(STAGING)" in the issuer CN). Browser trust is NOT asserted.
curl --resolve x.web.e2e-$RUN.$ZONE:443:<bridge-ip> -k https://x.web.e2e-$RUN.$ZONE/_w/
# PASS: the /workspace listing (wildcard vhost reaches the same Caddy).
dig +short TXT _acme-challenge.web.e2e-$RUN.$ZONE @1.1.1.1
# PASS: empty once installed (certmagic cleans up; the reconciler sweeps before every order).
sc create --bare zp:b1
# PASS: prints the DNS: line, the Public name line, "HTTPS: https://b1.zp.<suffix>   (Caddy with the tenant-CA leaf,
#       proxying to localhost:3000)" and "HTTPS (public): https://b1.e2e-$RUN.$ZONE   (Let's Encrypt; served once the
#       certificate lands)"; its cloud-init machine.env carries the same PUBLIC_HOSTNAMES line as the profile and no
#       MODE; the 12c marker/no-drop-in/caddy-active checks hold for b1 too; it reaches CERT ok like web.
sc create zp:devbox --image <dev-alias>
# PASS: prints "Public name: devbox.e2e-$RUN.$ZONE (A record pending; no Caddy — no certificate)" plus the usual
#       "Dev Image: no Caddy/TLS ingress — SSH only." line; the instance is stamped with the public name, gets an
#       A record, but has no /etc/sandcastle/caddy.ready, no /etc/sandcastle/hostnames and no caddy unit; CERT stays
#       `pending` and the auth-app log has exactly one "devbox: no caddy setup marker" line and no order for
#       devbox.e2e-$RUN.$ZONE. Its output reads "DNS: devbox.zp.<suffix> …" then
#       "Public name: devbox.e2e-$RUN.$ZONE (A record pending; no Caddy — no certificate)".
incus launch <ct-image> ff --project <prefix>-<tenant>-zp     # Freeform Machine, profile = default
# PASS (≤ 60s): the auth-app log shows "stamped <prefix>-<tenant>-zp/ff user.sandcastle.v2.public-hostnames=ff.e2e-$RUN.$ZONE"
#       (once; the LIST key — no user.sandcastle.v2.public-hostname key is ever written);
#       `dig +short ff.e2e-$RUN.$ZONE @1.1.1.1` answers its bridge IP; while cloud-init runs the log has
#       ONE "ff: no caddy setup marker; A record only" line; once /etc/sandcastle/caddy.ready exists the log shows
#       "certificate row created", then issued, then installed — CERT ok with no `sc create` involved.
```

### 12e — marker gate, stopped machines, reboot before the cert, drift

```bash
# marker gate refuses a legacy (ADR-0027) marker
sc incus exec ff -- sh -c 'cp /etc/sandcastle/caddy.ready /tmp/marker; printf "MODE=zone\nFQDN=ff.e2e-$RUN.$ZONE\n" > /etc/sandcastle/caddy.ready'
sc-adm incus exec <remote>:<prefix>-auth-app --project <infra-project> -- \
  sqlite3 /var/lib/sandcastle/auth/auth.db "UPDATE machine_certificates SET pushed_serial='' WHERE hostname='ff.e2e-$RUN.$ZONE'"   # (DB)
# PASS: the log shows "caddy setup marker does not clear the push gate for ff.e2e-$RUN.$ZONE (MODE=zone FQDN=… (legacy))"
#       once, CERT reads `pending` (state issued), nothing is pushed; restore the marker
#       (`sc incus exec ff -- /usr/local/sbin/sandcastle-caddy-setup --refresh` rewrites it) → pushed within 60s.
# stopped through a push
sc stop zp:web
sc-adm incus exec <remote>:<prefix>-auth-app --project <infra-project> -- \
  sqlite3 /var/lib/sandcastle/auth/auth.db "UPDATE machine_certificates SET pushed_serial='' WHERE hostname='web.e2e-$RUN.$ZONE'"   # (DB)
# PASS: the next passes log nothing for web (stopped: no push, no drift check); `sc ls` CERT `pending`
#       (state issued), `sc project status zp` DETAIL empty.
sc start zp:web
# PASS (≤ 15s of instance-started): "certificate <serial> installed on …/web" with the SAME serial (a re-push,
#       no new order); CERT ok again.
# reboot before the certificate lands
sc create zp:late; sc restart zp:late          # within ~60s of create
# PASS: caddy is enabled and active after the reboot (the private block serves), the marker has no PUBLIC= line
#       yet; once pushed, `openssl s_client -servername late.e2e-$RUN.$ZONE` serves the Let's Encrypt certificate
#       and `-servername late.zp.<suffix>` still serves the tenant leaf.
# drift
sc incus exec web -- sh -c 'echo x >> /etc/sandcastle/tls/web.e2e-$RUN.$ZONE/cert.pem'
# PASS (≤ 60s): the log shows "certificate on …/web differs from the issued one; re-pushing" and a new
#       "installed" line with the SAME serial; that cert.pem is byte-identical to the Auth App's copy again and
#       Caddy serves the correct chain. No new order in the log. The private leaf is not part of the drift check:
#       `echo x >> /etc/sandcastle/tls/cert.pem` triggers nothing (repair with `sc restart` — generalize does not
#       run again — or by re-fetching the leaf by hand).
# refresh with a removed name
sc incus exec web -- sh -c ': > /etc/sandcastle/hostnames; /usr/local/sbin/sandcastle-caddy-setup --refresh'
# PASS: the Caddyfile has the private block only, the marker has no PUBLIC= line, caddy active; restore with
#       `echo web.e2e-$RUN.$ZONE > /etc/sandcastle/hostnames; sandcastle-caddy-setup --refresh` → the public block
#       is back without any push (the certificate directory was kept).
# PASS (renewal timing is not spent) (DB): `SELECT renew_after, ari_check_after FROM machine_certificates` — renew_after
#       is ~60 days out (2/3 of the 90-day lifetime) or the ARI window start once ari_check_after (6h) has passed;
#       the log shows no order for web after the first one.
```

### 12f — refusals, then cleanup (delete → records gone → claim released → zone removed)

```bash
sc project unset-domain zp --dry-run
# PASS: `[dry-run] would have: …` — allowed with machines present (ADR-0028 slice 3 retired the "has machines
#       with a public name" refusal; a real unset re-derives web, ff, b1, late and devbox, see 12b).
sc-adm public-dns-zone remove $ZONE
# PASS: refused — "public DNS zone $ZONE still has claimed project domains: e2e-$RUN.$ZONE (<tenant>/zp); unset them first".
sc delete zp:web --yes
# PASS (≤ 60s): both A records gone (`dig` empty; log "deleted 2 stale A record(s)"); (DB) the
#       machine_certificates row for web.e2e-$RUN.$ZONE is RETAINED (`SELECT hostname, serial FROM machine_certificates`).
sc create zp:web
# PASS: the usual Public name line; CERT reaches ok with NO new "issued" line in the auth-app log — the retained
#       certificate (same serial) is pushed once the marker appears (the 5-per-identifier-set budget is not spent).
sc delete 'zp:*' --yes; sc project delete zp --yes
# PASS: the Incus project is gone; `sc-adm public-dns-zone list` shows CLAIMS 0; no A records under
#       e2e-$RUN.$ZONE remain (including *.<m> and any _acme-challenge TXT); (DB)
#       `SELECT count(*) FROM machine_certificates WHERE hostname LIKE '%.e2e-$RUN.$ZONE'` = 0.
sc-adm public-dns-zone remove $ZONE
# PASS: succeeds now; `list` no longer shows it.
# PASS (GC, out-of-band): register the zone again, re-create zp --domain and a machine, wait for CERT ok, then
#       `sc-adm project delete <tenant> zp --yes` (Incus only); within 5 minutes the auth-app log shows
#       "pruned orphaned project domain claim e2e-$RUN.$ZONE (<tenant>/zp)", the A records are gone and the
#       certificate row is dropped with the claim; CLAIMS 0 and the zone is removable.
# PASS (staging → production switch heals): redeploy the auth-app with the production directory on a throwaway
#       install — every certificate row logs "certificate issued by <staging>, running <production>; re-ordering"
#       once and is re-issued (spends production budget: only on a dedicated test zone).
# PASS (private-only regression): Phases 7c, 8, 8c run unchanged in a project without a domain on the same
#       install — DNS:/HTTPS: lines byte-identical, CERT column `-`, no public-hostname(s) key on the machine,
#       /etc/sandcastle/caddy.ready reads PRIVATE=<m>.<p>.<suffix> / RENDERED=<ts> (no PUBLIC=, no MODE=),
#       /etc/sandcastle/hostnames exists and is empty, no sandcastle-zone.conf drop-in, Caddy active with the
#       tenant-CA leaf, and the zone stage never touches such a machine (no A record, no cert-state key, no log
#       line for it).
```

### 12g — explicit Machine Public Hostnames (ADR-0028) — automated by `scripts/e2e-pdz.sh` (slice 4 of #172)

Runs after 12c on the same project `zp` (it holds `e2e-$RUN.$ZONE`, so every
machine also carries the derived `<m>.e2e-$RUN.$ZONE`). The script's names:
machine `api`, explicit hostnames `api-$RUN.$ZONE` (given at create,
**apex-level** — directly under the registered zone) and `alt-$RUN.$ZONE`
(added on the running machine). `<suffix>` is the Tenant DNS Suffix
(`sc ls --json` → `.tenant.dnsSuffix`); `<api-ip>` the machine's tenant-bridge
IP (`sc ls zp:api --json` → `.privateIP`). Every check reads `sc` output or
dials the machine over the tailnet; the **(DB)** and other-tenant extras at the
end are manual.

```bash
sc create zp:api --hostname api-$RUN.$ZONE
# PASS: output has "DNS: api.zp.<suffix> (auto-registers within seconds)" (every machine keeps its Machine
#       Private Hostname) and one Public name line PER name:
#       "Public name: api-$RUN.$ZONE (A record pending, certificate pending — see: sc project status zp)" and
#       "Public name: api.e2e-$RUN.$ZONE (A record pending, certificate pending — …)"; returns at once.
sc ls zp:api; sc ls zp:api --json | jq .machines[0].publicHostnames
# PASS: FQDN column reads "api-$RUN.$ZONE (+1)" (first name + count); --json carries exactly
#       ["api-$RUN.$ZONE","api.e2e-$RUN.$ZONE"] (sorted). `sc incus config get api user.sandcastle.v2.public-hostnames`
#       is the same list comma-separated; there is NO user.sandcastle.v2.public-hostname key.
sc hostname list zp:api
# PASS: PUBLIC NAME / KIND / ZONE table with `api-$RUN.$ZONE  explicit  $ZONE` and `api.e2e-$RUN.$ZONE  derived  $ZONE`.
dig +short api-$RUN.$ZONE @1.1.1.1; dig +short x.api-$RUN.$ZONE @1.1.1.1      # and the same for api.e2e-$RUN.$ZONE
# PASS (≤ 180 s): all four answer <api-ip>; in the Cloudflare zone the apex-level records are `api-$RUN` and
#       `*.api-$RUN` (relative to the containing Cloudflare zone), DNS-only, TTL 60.
sc ls zp:api
# PASS (≤ 10 min): CERT `ok` — the column folds the WORST state across the machine's names, so it reads
#       `pending` until BOTH certificates are installed; `sc ls --json` .certStates = {"api-…":"installed",
#       "api.e2e-…":"installed"}; `sc incus config get api user.sandcastle.v2.cert-state` =
#       `api-$RUN.$ZONE=installed,api.e2e-$RUN.$ZONE=installed`; `sc project status zp` has one row per name for api.
openssl s_client -connect <api-ip>:443 -servername api-$RUN.$ZONE </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName -issuer -serial
# PASS: SANs `DNS:api-$RUN.$ZONE, DNS:*.api-$RUN.$ZONE`, issuer from the Let's Encrypt STAGING hierarchy;
#       note the serial — it must not change below.
openssl s_client -connect <api-ip>:443 -servername api.zp.<suffix> </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName -issuer
# PASS: SAN `DNS:api.zp.<suffix>` and an issuer containing "Sandcastle" (the tenant CA), NOT staging — the
#       Machine Private Hostname keeps serving the tenant-CA leaf beside the public names.

sc hostname add zp:api alt-$RUN.$ZONE
# PASS: "Public name: alt-$RUN.$ZONE (certificate pending)" followed by the table with all three names
#       (alt-… explicit, api-… explicit, api.e2e-… derived); `sc ls zp:api --json` .publicHostnames lists the
#       three (sorted) within seconds — the endpoint kicks the reconciler, which pushes /etc/sandcastle/hostnames
#       whole ("api: hostnames file pushed (…)" in the auth-app log).
dig +short alt-$RUN.$ZONE @1.1.1.1; dig +short x.alt-$RUN.$ZONE @1.1.1.1
# PASS (≤ 180 s): both answer <api-ip>.
sc ls zp:api
# PASS (≤ 10 min): CERT `pending` while alt-… is ordered, then `ok`; .certStates gains "alt-…":"installed";
#       the marker /etc/sandcastle/caddy.ready on api has three PUBLIC= lines; /etc/sandcastle/tls/alt-$RUN.$ZONE/
#       holds cert.pem + key.pem.
openssl s_client -connect <api-ip>:443 -servername alt-$RUN.$ZONE </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName -issuer
# PASS: its OWN certificate — SANs `DNS:alt-$RUN.$ZONE, DNS:*.alt-$RUN.$ZONE`, staging issuer.
openssl s_client -connect <api-ip>:443 -servername api-$RUN.$ZONE </dev/null 2>/dev/null | openssl x509 -noout -serial
# PASS: the SAME serial as before the add — one certificate per hostname, adding a name never reissues the
#       others (the auth-app log has one "issued" + one "installed" line for alt-… and none for api-…).

# refusals — every one --dry-run, and `sc ls zp:api --json` .publicHostnames is unchanged afterwards
sc hostname add zp:api sub.e2e-$RUN.$ZONE --dry-run
# PASS: `machine hostname "sub.e2e-$RUN.$ZONE" overlaps project domain "e2e-$RUN.$ZONE" claimed by project "zp"
#       in this tenant` (a name inside a Project Domain — even the project's own — is the domain's).
sc hostname add zp:web api-$RUN.$ZONE --dry-run
# PASS: `machine hostname "api-$RUN.$ZONE" overlaps "api-$RUN.$ZONE" held by machine "zp:api" in this tenant`.
sc project create x-$RUN --domain api-$RUN.$ZONE --dry-run
# PASS: `project domain "api-$RUN.$ZONE" overlaps hostname "api-$RUN.$ZONE" held by machine "zp:api" in this tenant`
#       (reverse check: a domain may not sit on, above or below a hostname).
sc hostname add zp:api $ZONE --dry-run
# PASS: `machine hostname "$ZONE" is a zone apex; use at least one label below $ZONE`.
sc hostname remove zp:api api.e2e-$RUN.$ZONE --dry-run
# PASS: `machine hostname "api.e2e-$RUN.$ZONE" is not held by machine "zp:api"` — the derived name goes with the
#       project's domain, never per machine.

sc hostname remove zp:api alt-$RUN.$ZONE
# PASS: "Released alt-$RUN.$ZONE from machine zp:api." + the table without alt-…; `sc hostname list zp:api` no
#       longer shows it; within 60 s `sc ls zp:api --json` .publicHostnames is back to two names and .certStates
#       has no alt-… entry (`sc incus config get api user.sandcastle.v2.cert-state` lists two names);
#       `sc project status zp` lists api with api-… and api.e2e-… only.
dig +short alt-$RUN.$ZONE @1.1.1.1; dig +short x.alt-$RUN.$ZONE @1.1.1.1
# PASS (≤ 180 s, TTL 60): both empty — the release hook deleted them; they never come back.
openssl s_client -connect <api-ip>:443 -servername alt-$RUN.$ZONE </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName
# PASS (≤ 120 s): no certificate carrying DNS:alt-$RUN.$ZONE any more — the handshake fails or Caddy answers with
#       another block's certificate (the shrunken hostnames file was pushed and --refresh dropped the block);
#       `-servername api-$RUN.$ZONE` still serves its certificate with the SAME serial as at the start.
# NOTE: the retained machine_certificates row for alt-… is not visible through `sc` (`sc project status` reads
#       the instance mirror) — the script prints a note; check it by hand (DB, below).
sc create zp:api2 --hostname api-$RUN.$ZONE --dry-run
# PASS: refused — `machine hostname "api-$RUN.$ZONE" overlaps "api-$RUN.$ZONE" held by machine "zp:api" in this
#       tenant`; `sc ls zp:api2` lists nothing (a refused claim creates no instance).
# cleanup (the script does this before the 12f teardown of web):
sc delete zp:api --yes
# PASS (≤ 180 s): the A records of api-$RUN.$ZONE and api.e2e-$RUN.$ZONE (base + wildcard) are gone; the
#       reservation api-$RUN.$ZONE is released by `sc delete` → the name is claimable again at once.
```

Manual extras (not in the script — run when a second tenant, a private project
or the appliance's `sqlite3` is at hand):

```bash
# (DB) after `sc hostname remove zp:api alt-$RUN.$ZONE`
sqlite3 /var/lib/sandcastle/auth/auth.db "SELECT hostname, state, serial FROM machine_certificates WHERE hostname='alt-$RUN.$ZONE'"
# PASS: the row is RETAINED (state issued/installed, serial kept); `sc hostname add zp:api alt-$RUN.$ZONE` again
#       reaches `installed` with NO new "issued" line in the auth-app log (the retained certificate is re-pushed).
# (DB) `SELECT hostname FROM machine_hostnames` — one row per EXPLICIT name (api-…; alt-… while held); the derived
#       api.e2e-$RUN.$ZONE is never a row (it is implied by the project_domain_claims row).
sc create pp:solo --hostname solo-$RUN.$ZONE            # pp: a project WITHOUT a domain
# PASS: the DNS: line and ONE Public name line; /etc/sandcastle/hostnames on solo reads solo-$RUN.$ZONE (seeded from
#       the instance record, or pushed by the reconciler within 60 s when the datasource read is empty — record which);
#       `sc project status pp` shows `Domain: (none)` AND the table row solo / solo-$RUN.$ZONE / installed;
#       `sc project set-domain pp x-$RUN.$ZONE --dry-run` is allowed (explicit names never block a domain change).
sc hostname add <other-tenant-project>:m x.api-$RUN.$ZONE   # from a second tenant
# PASS: the flat `machine hostname "x.api-$RUN.$ZONE" overlaps a name already claimed on this install; choose another`.
sc route publish <machine> --hostname www.api-$RUN.$ZONE
# PASS: `route hostname "www.api-$RUN.$ZONE" is inside machine hostname "api-$RUN.$ZONE" claimed on this install`.
sc-adm public-dns-zone remove $ZONE                     # while zp is deleted but pp:solo still holds solo-…
# PASS: refused — "public DNS zone $ZONE still has machine hostnames: solo-$RUN.$ZONE (<tenant>/pp:solo); remove them first".
sc-adm incus delete <remote>:solo --project <prefix>-<tenant>-pp     # out-of-band
# PASS (≤ 60 s): solo-…'s A records are gone ("deleted 2 stale A record(s)"); (≤ 5 min) the auth-app log shows
#       "pruned orphaned machine hostname solo-$RUN.$ZONE (<tenant>/pp:solo)" and the zone is removable.
# PASS (machine side, per name): /etc/sandcastle/tls/<name>/{cert,key}.pem (0644/0600) per public name, the private
#       leaf /etc/sandcastle/tls/{cert,key}.pem untouched; caddy.ready = PRIVATE=api.zp.<suffix> + one PUBLIC=<name>
#       per rendered block; `sandcastle-caddy-setup --refresh` by hand is idempotent; `sc c zp:api -- true` writes ONE
#       known_hosts line keyed `api.zp.<suffix>,api-$RUN.$ZONE,api.e2e-$RUN.$ZONE` (private name first).
```

**PASS (phase):** `scripts/e2e-pdz.sh` ends with `ALL PASS`, and the manual
12d/12e extras above hold. Tenants provisioned before this feature keep working
unchanged; their `/.sc` payload (the per-name `caddy-setup`, a new payload
version with slice 2 of #172) converges on the next `sc payload-sync` /
`sc-adm tenant payload-sync <tenant>` — needed before *their* machines get a
public name; machines that already ran an older `caddy-setup` are recreated,
not migrated in place.

## Machine publication lifecycle: fresh nested-Incus E2E

Run this phase only in a new VM with a new **supported** Incus installation:
bootstrap it with `sc-adm install-incus`, not Debian's older Incus package.
The shared `/.sc/platform` payload uses the storage-volume file API available
in the supported Zabbly release. Install the Auth App with `--ingress
cloudflare` and `--simulate-github-token`; GitHub OAuth, browser approval, and
GitHub client credentials are prohibited. The nested VM
uses Tailscale for control-plane access only and keeps `tailscale set
--accept-routes=false`; a separate enrolled Tailnet client accepts the Tenant
subnet route.

The Public DNS Zone token needs `Zone:Read`, `DNS:Edit`, and account-level
`Cloudflare Tunnel:Edit`. Use a disposable subzone and Let's Encrypt staging.
The automated phase creates a disposable project and Machine, starts an HTTP
response on `:3000`, then runs both publication lifecycles:

```bash
SANDCASTLE_E2E=1 \
  SANDCASTLE_E2E_MACHINE_PUBLICATIONS=1 \
  SANDCASTLE_E2E_SIMULATED_GITHUB=1 \
  scripts/e2e.sh publications
```

**Machine Tunnel PASS:** `sc tunnel publish` creates a dedicated Machine
`cloudflared` connector and Sandcastle-owned Cloudflare Tunnel CNAME; public
HTTPS returns the Machine response. An identical publish preserves that CNAME,
`sc ls` renders it in `TUNNEL`, an occupied hostname is refused without
mutation, and repeated `sc tunnel unpublish` is safe while removing the
connector and CNAME. The gate exercises wildcard and omitted-hostname
unpublish; both inspect only that Machine's recorded publication, not zone DNS.
Publish two tunnels and verify a selective wildcard removes only its match;
omitting the hostname must then remove the remaining tunnel. Exercise the same
sequence for two Tailnet names. Both tunnel-over-Tailnet and Tailnet-over-tunnel
claims must fail before altering the existing publication or DNS.
Check the proxied CNAME's ID and target through the Cloudflare API: public DNS
returns Cloudflare edge A/AAAA records rather than the proxied CNAME itself.
Resolve transport probes through `SANDCASTLE_E2E_PDZ_RESOLVER` (default
`1.1.1.1`), then connect to the returned edge with the original HTTPS hostname.
Also check ordinary client resolution; if it differs, inspect the client's
upstream resolver before attributing NXDOMAIN to record creation. The isolated
driver's Incus gateway has been observed returning NXDOMAIN for records that
already resolve at the public resolver. Configure a working upstream on that
test client and verify ordinary curl as well. DNS removal must be checked at
the API and after recursive-cache expiry; absence of a public CNAME alone is
insufficient. Certificate readiness checks retry while issuance is pending.
Assert that the generated systemd unit starts `/.sc/platform/sbin/cloudflared`
(rather than a Machine-private `/usr/local` binary). No Machine receives the Cloudflare API token and the VM has no
inbound public service port.

**Direct-Machine Tailnet PASS:** `sc tailnet publish` creates the existing
Machine Public Hostname lifecycle: DNS-only direct A record(s) to the Machine's
tenant-bridge IPv4, DNS-01 certificate, and Machine-Caddy site block. The
record is never proxied and never targets the Tenant Sidecar's `100.x` address.
From the Tailnet client HTTPS reaches the Machine and serves its certificate;
assert the Machine's Caddy service override executes
`/.sc/platform/sbin/caddy` for start and reload;
the Machine holds the certificate/key but neither it nor the Sidecar holds the
Cloudflare API token. Repeating publish is idempotent; `sc ls` renders the
requested view in `TAILNET`; repeated `sc tailnet unpublish` safely removes DNS
and the Machine-Caddy site according to Machine Public Hostname cleanup. The
gate also verifies a shell-quoted hostname wildcard and an omitted hostname
select only Tailnet publications recorded on that Machine.

Run `VERBOSE=1` for both paths. It must show immediate progress before a long
wait and Cloudflare method/path/status/duration traces, with credentials
redacted. Direct-Machine Tailnet output must name Machine/subnet-route
resolution and must not invent a Sidecar-IP API step.

Legacy Sidecar-backed publications are transition-only: after upgrading the
nested install, verify they keep their existing target and work until explicit
unpublish, DNS-propagation wait, and a new direct-Machine publish. No command
may retarget a live hostname automatically. This legacy migration is a separate
opt-in E2E run using the prior release artifact; it is not part of the fresh
installation gate above.


## Project certificate acceptance (supersedes per-derived-name orders)

Use the disposable `skorfmann/tod0s` project on its confirmed install. Deploy
updated Auth App and platform payload before testing; record the ACME directory,
project certificate serial, order-log baseline and test start time. Do not
switch networks automatically.

1. `sc project set-domain tod0s tod0s.tc42.uk --dry-run` must plan one project
   certificate; the real command followed by `sc project status tod0s --json`
   must show SANs `tod0s.tc42.uk` and `*.tod0s.tc42.uk`, state and expiry.
2. `sc create tod0s:x1 --alias console-x1` must print `served by project
   certificate`. Serve a test backend on port 3000 and verify HTTPS for
   `x1.tod0s.tc42.uk` and `console-x1.tod0s.tc42.uk` after first boot. Compare
   the peer leaf serial/SANs to the project certificate. No derived/alias
   row or order may appear in the Auth Database or Auth App journal.
3. Add `admin-x1.tod0s.tc42.uk` with `sc hostname add`; verify the same leaf
   and no new order. List/remove the alias; removing the derived name must fail.
4. Use `incus copy x1 x2 --project <actual-incus-project>` with no `-c`
   overrides, then start x2. Verify destination public names contain only
   `x2.tod0s.tc42.uk`, raw cert-state is `project`, raw cert-not-after is empty,
   and `sc ls --json` resolves shared state/expiry. HTTPS uses the same leaf.
5. `sc delete tod0s:x2 --dry-run` must not mutate. Delete for real and verify
   its A/wildcard records disappear and no x2 certificate row remains.
6. Add `'*.x1.tod0s.tc42.uk'` explicitly and verify one per-name wildcard order.
   Create a separate machine with `--hostname web12.tc42.uk`; verify its
   per-name order remains. A two-label alias also gets a per-name order.
7. Verify renewal on a staging deployment: all running machines receive the
   new project serial; a stopped machine receives it on start without an order.
   Unset-domain drops the project row and clears the Caddy selector. Private
   tenant-CA certificate files must remain unchanged throughout.

PASS requires positive journal/DB evidence of the exact order set. A crt.sh
query can corroborate production issuance, but absence there alone is not
proof because certificate transparency indexing may lag. Record live timing
and any unavailable acceptance checks separately from unit tests.


## Phase 13 — Shared Tenants (ADR-0029, `docs/spec/shared-tenants.md`) ✅ 13a–13h PASS 2026-09-22 (13a–13g 2026-09-21)

One tenant, several users. Membership is Tenant Metadata (`v2.members` on
the infra project), every member's login key is authorized on the tenant's
machines, and every member's certificate covers every project. Automation:
`scripts/e2e-shared-tenant.sh`, run on the enrolled Tailnet **client** of a
fresh `--simulate-github-token` install.

**Prerequisites (the feature's own):**
- Two users have completed `sc login` on the install from the client:
  `$OWNER` (thieso2, the client's default key) and `$MEMBER` (skorfmann,
  `--ssh-public-key ~/.ssh/skorfmann_ed25519.pub`, a second key so the
  machine can be shown to authorize both). Each login leaves a remote named
  after its DNS suffix (`thieso2sh`, `skorfmannsh`); the script switches
  users with `sc remote switch <suffix>`.
- The client and the tenant's sidecar share one tailnet, with a
  `tag:sandcastle` autoApprover (Prerequisites above).
- The admin side runs where the admin Incus socket is
  (`SANDCASTLE_E2E_ADMIN_EXEC="incus exec big:<vm> --"` when the install
  lives in a VM), with `SANDCASTLE_INCUS_PROJECT_PREFIX=<prefix>`.
- **Cloudflare ingress hostname depth.** The install's `--auth-hostname`
  must sit directly under the Cloudflare zone (`sh-shared.tc42.uk`):
  Cloudflare's universal certificate covers one label, so a deeper name
  (`x.e2e.sc.tc42.uk`) answers TLS handshake failures from the edge.

```bash
set -a; . ./.env.sc2; set +a
SANDCASTLE_E2E_ADMIN_EXEC="incus exec big:sc-shared-e2e --" SANDCASTLE_E2E_PREFIX=sh \
  scripts/e2e-shared-tenant.sh
```

| Step | PASS criteria |
|---|---|
| **13a** prerequisite | both users list their Personal Tenant; `sc-adm tenant create … --member never-logged-in` is **refused** with ``must run `sc login` `` and creates nothing |
| **13b** create | `sc-adm tenant create moyn-dev --member $OWNER --member $MEMBER --tailscale-authkey … --dns-suffix moyn` prints `Member <u> granted [<prefix>-moyn-dev <prefix>-moyn-dev-default]` for both; `sc-adm tenant users moyn-dev` lists both; `v2.members` on `<prefix>-moyn-dev` = `skorfmann,thieso2`; the default profile's `ssh_authorized_keys` carries **both** members' keys |
| **13c** switch | as `$MEMBER`: `sc tenant list` shows `moyn-dev … member`; `sc tenant switch moyn-dev` enrols the Incus remote `moyn` (certificate-based, `https://<sidecar tailnet ip>:8443`, pinned to `<prefix>-moyn-dev-default`), records `remote_tenants/remote_auth_tokens/remote_brokers/installs[moyn]`, sets `remote: moyn`, `tenant: moyn-dev`, `project: default`; a second switch is a no-op |
| **13d** machine | `sc create web` in the shared tenant; `ssh dev@<ip>` succeeds with **both** the owner's default key and `-i ~/.ssh/skorfmann_ed25519` |
| **13e** project | `$MEMBER`: `sc project create api` (through the auth-app tenant plane, `X-Sandcastle-Tenant: moyn-dev`); `$OWNER` after `sc tenant switch moyn-dev` sees `web` and creates `api:svc` — the other member's certificate was extended with `<prefix>-moyn-dev-api` |
| **13f** scoping | `sc tenant switch $OWNER` back: `sc ls` no longer shows the shared machines (personal remote re-activated) |
| **13h** new device | as `$MEMBER` with a fresh `HOME` (a new device): `sc login <auth> --simulate-token … --as $MEMBER --ssh-public-key …` mints a certificate that already carries every project of `moyn-dev` (infra, `default`, `api`); `sc tenant switch moyn-dev` then `sc incus list` on the shared default project and on `api` both succeed (before the fix: `User does not have permission for project`). Requires `SANDCASTLE_E2E_AUTH_HOST` and `SANDCASTLE_E2E_SIMULATE_TOKEN` |
| **13g** revoke | `sc-adm tenant revoke moyn-dev $MEMBER` prints `members: $OWNER`; `$MEMBER`'s `sc tenant list` no longer lists it and `sc tenant switch moyn-dev` is refused with `not accessible`; the profile no longer carries the member's key |

Live run 2026-09-21 (`big:sc-shared-e2e`, Incus 7.4, install prefix `sh`,
Auth Hostname `https://sh-shared.tc42.uk`, client `big:e2e-pdz-client`):
see `docs/e2e-runs/2026-09-21-phase13-shared-tenants.md`; 13h added and the whole
phase re-run 2026-09-22, see `docs/e2e-runs/2026-09-22-phase13-shared-tenants-13h.md`.

## Phase 14 — Path navigation: `sc cd` / `pwd` / `ls <path>` / `mkdir` / `rm` (ADR-0030) ✅ 14a–14i PASS 2026-09-21

The four levels as a tree walked with a slash grammar, additive to the colon
grammar. Run on the enrolled Tailnet **client** of a `--simulate-github-token`
install with at least two projects (`default`, `web`) and one machine
(`web:dev`); a second enrolled install (any) makes 14g meaningful. Unit
coverage: `go test ./internal/cli -run 'TestCdPwdLs|TestPathToMachine|TestResolvePath'`.

| Step | PASS criteria |
|---|---|
| **14a** pwd | inside a project directory `sc pwd` prints `/<remote>/<tenant>/<project>`; `sc pwd --json` carries `remote`, `tenant`, `project`, `level: project` |
| **14b** cd | `sc cd web` (from `default`) prints `/<remote>/<tenant>/web`; `.sandcastle` has `project: web`, no `level`; `sc project list` marks `web`; `sc cd nope` fails with `project nope not found`; `sc cd ./dev` fails with `is a machine` |
| **14c** up | `sc cd ..` prints `/<remote>/<tenant>`; `.sandcastle` has `level: tenant`, `previous: /<remote>/<tenant>/web`, `project: web` kept; `sc ls` lists the project names; `sc create x` is refused with `not in a project`; `sc connect dev -- hostname` resolves `web:dev` through the tenant-wide lookup and `sc connect nope` is refused with `no machine "nope" in any project`; `sc cd -` returns to `/<remote>/<tenant>/web` |
| **14d** globs | from `web`: `sc ls '../*'` prints every project under a `path:` header; `sc ls -d '../*'` the paths only; `sc ls -l ..` a `PROJECT DOMAIN IMAGE` table; `sc ls -R ..` the machines of every project; `sc ls ../web/d*` prints `/<remote>/<tenant>/web/dev`; `sc ls -d '../**'` lists every project and machine of the tenant; `sc ls '/**/web/*'` the machines of project web; `sc stop /<remote>/<tenant>/web/dev`, `sc start ./dev` and `sc restart '/**/dev'` act on `web:dev` |
| **14e** mkdir/rm | `sc mkdir ../api` creates project api (visible in `sc project list`); `sc mkdir -p ../api2/dev` creates project api2 and machine `api2:dev`; `sc rm ../api --yes` deletes the empty project; `sc rm -r ../api2 --yes` deletes `api2:dev` then api2 (interactively, `sc rm -r ../api2` asks ONCE — "Delete project … and its 1 machine (dev)?" — never a second "Delete project" prompt; `-f` asks nothing); `sc mkdir /` and `sc rm ..` are refused with the remote/tenant guidance |
| **14f** home/root | `sc cd /` prints `/`; `sc ls` lists the enrolled remotes and `sc ls -l /` shows `REMOTE TENANT PROJECT AUTH`; `sc ls /<remote>` lists the accessible tenants; `sc cd` (no argument) returns to the global config's `/<remote>/<tenant>/<project>` |
| **14g** cross-remote | with a second enrolled install: `sc cd /<other>/<its tenant>/<its project>` switches remote (as `sc remote switch` does) and `sc ls` lists that install's machines; `sc cd /<other>/<wrong-tenant>` fails through Tenant Access validation; `sc c /<other>/<tenant>/<project>/<machine> -- true` from the first install runs without a durable switch (`sc pwd` unchanged); `sc ls <other>:<project>` reports `<its tenant>@<other>:<project>`, not the current tenant |
| **14h** completion | `sc completion zsh` emits a script; `sc __complete cd ../` lists the sibling projects with a trailing `/`; `sc __complete connect ./` lists the project's machines; `sc __complete cd /` lists the remotes |
| **14i** compatibility | with `.sandcastle` at project level, `sc ls`, `sc ls -a`, `sc ls 'gbrain:*'` keep their filters (output is now the position line plus names; `-l` restores the table), and `sc c web:dev`, `sc remote switch`, `sc project switch`, `sc tenant switch` behave exactly as in Phases 7c/13 |

Live run 2026-09-21 (`big:sc-shared-e2e`, client `big:e2e-pdz-client`, branch
`feat/path-navigation`): see `docs/e2e-runs/2026-09-21-phase14-path-navigation.md`.
