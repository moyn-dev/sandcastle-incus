# Implementation Notes

Running log of decisions that weren't in the spec — choices invented on the
spot, deviations from what was asked, tradeoffs, and workarounds for
environment/tooling limits. The "why" behind the code; larger hard-to-reverse
decisions live in `docs/adr/`. Newest first.

## 2026-09-15 — Fresh publication E2E requires supported Incus and bounded bridge names

Validation: isolated run `e2e-pubfix4` completed with `ALL PASS: Machine
publication lifecycle` on a fresh Debian container inside the dedicated nested
Incus VM, accessed from a separate Tailnet client with simulated GitHub login.
Both public tunnels served the port-3000 response. Direct Tailnet HTTPS served
the response with the issued Let's Encrypt staging hostname/wildcard
certificate. Both conflict directions, repeated publish/unpublish, selective
wildcards, omitted-hostname removal, listing, platform launchers, provider DNS
identity/removal, and credential-free verbose Cloudflare traces passed. A
separate admin inspection confirmed no legacy Sidecar publication artifacts.
Production ACME issuance and legacy migration are separate gates, not claimed
by this fresh staging run.

The cross-kind E2E found a missing reverse ownership check: Tailnet publish
accepted a hostname already held by a Machine Tunnel, then the reconciler
attempted an A record over its CNAME. Machine Public Hostname claims now check
active tunnel reservations under their existing SQLite write lock, including
tunnels in the candidate's reserved subtree. A regression reproduces the
conflict through the actual claim function and verifies no hostname is stored.
The fresh suite now covers two publications per Machine, selective wildcard
removal, omitted-hostname removal, and conflicts in both directions.

The publication harness now checks the proxied CNAME through Cloudflare's API
and public edge addresses through DNS. Public DNS flattens the proxied record,
so requiring a visible CNAME was an invalid assertion. The isolated driver's
Incus gateway returned NXDOMAIN while `1.1.1.1` returned working edge addresses;
changing that driver's upstream restored ordinary curl. Transport probes use
the configured public resolver and preserve HTTPS hostname validation. API
record identity is compared across repeated publish and checked after removal.
Certificate checks return a retryable failure during asynchronous issuance.

Disposable project suffixes are bounded because the install and tenant names
are added to the Incus project name. Launcher assertions resolve the Incus
project explicitly: `sc incus` forwards native Incus syntax, so a Sandcastle
`project:machine` reference otherwise means an Incus remote. These changes fix
the test harness rather than changing established command semantics.

The first isolated Machine-publication run found two host-bootstrap boundaries
that unit tests could not expose. Debian 13's stock Incus 6.0.4 lacks the
storage-volume file API used to seed the shared `/.sc/platform` payload, so a
fresh E2E VM must run `sc-adm install-incus` (Zabbly stable) before it creates
the Auth App or a tenant. `scripts/e2e-local-vm.sh` now follows that production
bootstrap rather than installing Debian's `incus` package directly.

The same run used a timestamped install prefix; its default `<prefix>-net`
bridge exceeded Linux's 15-character network-interface limit. New installs
keep the established readable name when it fits; longer prefixes receive a
stable SHA-256-derived `sc-<8-hex>-net` bridge name. This only affects new,
long-prefix installs and avoids an error after Cloudflare ingress has already
been provisioned.

## 2026-09-14 — Machine Tunnel publish is idempotent for its own CNAME

Cloudflare rejects a second POST for an existing CNAME. Publishing the same
Machine Tunnel again must converge rather than fail, so the Auth App first
looks up the hostname's record: it reuses an identical `*.cfargotunnel.com`
CNAME and refuses any other existing record. This retains the additive
ownership boundary: a tunnel never silently repoints a Machine Public
Hostname or hand-managed DNS record.

## 2026-09-14 — Fresh E2E uses simulated GitHub approval

Fresh E2E deployments use `--simulate-github-token`, not a real GitHub OAuth
application. This keeps the test isolated and repeatable: Cloudflare and
Tailscale credentials exercise their real integrations while authentication is
explicitly test-only.

## 2026-09-13 — Machine Tunnels are additive, dedicated Cloudflare connectors

Machine Tunnels are an opt-in public-ingress feature: one Cloudflare Tunnel and
one connector belong to each Machine, rather than extending either a Machine
Public Hostname (which remains tailnet-only) or the install's shared Public
Route ingress. The alternative of routing every Machine Tunnel through the
Auth App would reuse existing infrastructure, but contradicts the requested
per-Machine isolation and leaves one tunnel's availability and credentials as
a shared blast radius. Existing public hostnames and public routes are
unchanged; a hostname must be released before a tunnel can claim it.

## 2026-09-13 — `sc skill` reminder: a once-a-day interactive hint

The spec: after a successful interactive `sc` run, print one stderr line when
the skill is missing/outdated for an agent present on the box, throttled to
24h, with config + env opt-outs. Decisions it left open:

- **Own state file, own loader — not a field in `update-state.json`.** The
  update notice's `update.State` is rewritten by the background release check
  (`Checker.Check` saves the whole struct); folding `noticed_at` for the skill
  into it would race that goroutine's write within one run. A sibling
  `skill-reminder-state.json` in the same dir keeps the "next to the update
  notice" convention with zero coupling. The spec's "skip if it would take a
  lock the update notice already holds" turned out moot: the update path
  takes no file lock (only an in-process mutex in `update.Exchange`), so
  there is nothing to contend with.
- **"Agent present" = the target's `ConfigDir` exists**, the same test
  `sc skill install` uses to skip absent agents, so the hint and the install
  it recommends agree on which agents count. Unmanaged copies stay silent —
  the hint recommends `sc skill install`, which would refuse them.
- **Gates read back from cobra, not threaded through `rootOptions`.**
  `Execute` switches to `ExecuteContextC` to learn the executed leaf
  (`CommandPath()` → skip the `sc skill` subtree) and reads `--output`/`--json`
  from the root's persistent flags after the run, so the reminder needs no
  hook inside `NewRootCommand`. The admin tree is excluded twice: `ExecuteAdmin`
  never calls it, and `skillReminderLine` also refuses `sc-adm`/`… admin`
  root names so the unit test can prove it without a process boundary.
- **Both stdout and stderr must be terminals** (the update notice checks
  only stderr). A `sc ls | grep` with a terminal stderr is a script in
  spirit; a hint there is noise.
- **`sc skill install` deletes the state file** rather than stamping a new
  time: the throttle only exists to avoid nagging, and a fresh install is
  the strongest possible "user acted" signal. `--dry-run` leaves it alone.
- **Env accepts `0`/`false`/`off`/`no`**, not only the `0` the spec named,
  matching how people write boolean env vars; the config key accepts
  `on`/`off` only and rejects anything else so a typo cannot silently mean
  "on".

## 2026-09-13 — `sc skill`: the agent skill ships in the binary

The spec asked for `sc skill install|status|uninstall|show` for Claude Code and
Codex. Decisions it left open:

- **Embedded copy + drift test, not a build step.** `go:embed` cannot reach
  `docs/agents/skills/sandcastle/` from `internal/agentskill/`, so the package
  carries a byte-exact copy and `TestEmbeddedSkillMatchesTrackedSource` fails
  on any file-set or content difference; `make skill-sync` refreshes it.
  Alternatives: a `go generate` step (invisible until someone runs it) or
  moving the tracked source under `internal/` (breaks the "docs are the
  source" rule and the plain-copy install path). The test makes a forgotten
  sync a red `go test ./...`, which is the cheapest enforcement we have.
- **Codex project scope is `<repo>/.agents/skills/`, user scope
  `$CODEX_HOME/skills/`.** Source: https://developers.openai.com/codex/skills
  (redirects to https://learn.chatgpt.com/docs/build-skills; table "Skill
  Scope / Location": REPO `$REPO_ROOT/.agents/skills`, USER
  `$HOME/.agents/skills`, ADMIN `/etc/codex/skills`) cross-checked against
  `codex-rs/ext/skills/src/host_roots.rs` on `openai/codex` main, which still
  loads `$CODEX_HOME/skills` with the comment "Deprecated user skills location
  (`$CODEX_HOME/skills`), kept for backward compatibility" beside
  `$HOME/.agents/skills` and the project `.codex/skills` layer. User scope
  keeps `$CODEX_HOME/skills` (`~/.codex/skills`) because that is where this
  box's existing Codex skills live and its config dir doubles as the "is
  Codex installed" probe; `~/.agents/skills` has no such marker. If Codex
  drops the deprecated root, switch `Resolve` to `~/.agents/skills`.
- **Marker file `.sc-skill-version`** (`version=<12-hex content hash>`,
  `cli=<CLI version>`) inside the skill directory decides managed vs
  unmanaged. A directory without it is never overwritten (`--force`) or
  removed — a hand-edited copy is the user's. The content hash (SHA-256 over
  sorted path+data) rather than the CLI version keys "outdated", so a CLI
  release that did not touch the skill leaves every copy "up to date".
- **Atomic install = stage + two renames.** Files are written into a temp
  sibling `.sandcastle.tmp-*`, the old tree is renamed to `.sandcastle.old-*`,
  the staged tree renamed in, the old one removed. `rename(2)` cannot replace
  a non-empty directory, hence the move-aside; an agent reading the skill
  mid-install sees either the old or the new tree, and files the skill no
  longer ships vanish with the old tree (a copy-over-in-place would leave
  them).
- **`sc update` treats skills as a third, non-fatal target.** Managed
  user-scope copies show as `skill (<agent>, user)` rows and are refreshed
  from the skill embedded in the *running* binary after the CLI/sidecar
  steps; a refresh failure is a stderr note, not an exit code. After a CLI
  self-replace the running process still embeds the old skill, so the freshly
  installed binary's newer skill lands on the next `sc update` — accepted
  over re-exec'ing the new binary, which the update path does not do either.
- **Absent agent = skipped, unless named.** Default `--agent all` skips an
  agent whose config dir does not exist ("codex: not installed (no ~/.codex),
  skipped") so a Claude-only machine does not grow a `~/.codex`; `--agent
  codex` creates it, since the user asked.

## 2026-08-28 — wildcard Public Routes may use one DNS-01 certificate

Production measurements on `*.jot.moyn.dev` isolated a 5–7 second first-click
delay to ACME inside the TLS handshake. A second connection to the same hostname
completed in about 140 ms, and newly issued certificate timestamps aligned with
the first request. JotD had not received HTTP yet, so application caching could
not fix it.

PR #148 deliberately chose broker-authorized, leaf-per-SNI on-demand TLS. That
remains the zero-credential default. This follow-up adds the operator flags
`--route-dns-cloudflare-api-token` and
`--route-dns-cloudflare-wildcard '*.jot.moyn.dev'`: when both are present, the
appliance downloads Caddy with `caddy-dns/cloudflare`, stores the token in a
Caddy-only `0600` environment file, and renders only exactly allowlisted
leading-wildcard Public Routes with DNS-01. Other wildcard routes and all exact
routes still use the ask-gated on-demand path.

The exact wildcard allowlist is an authorization boundary, not convenience
configuration. A Cloudflare token may cover a whole zone, while Public Route
hostnames are Tenant input; allowing every wildcard Route to use that token
would let Tenant publication silently exercise operator DNS authority.

The token is not added to the Auth App's environment. Pointing Caddy at the
existing Auth App environment file would also disclose the GitHub OAuth secret,
simulated-login token, and Tailscale key to Caddy; a separate file keeps the
process secret boundary narrow. An empty file is written when the option is
disabled so a redeploy removes stale DNS authority.

Alternatives rejected: prewarming every hostname (same issuance and rate-limit
cost, only shifts latency) and passing TLS through to the target Machine (reopens
ADR-0013's shared public-ingress decision and needs another L4 routing layer).

## 2026-08-12 — `sc ls` asks the cache only for what it prints, and gets 5s to do it

Reported from the field on `obelix`: `VERBOSE=1 sc ls -a` still logged
`cache-backed endpoint unavailable (context deadline exceeded), falling back
to live per-project query` — the same symptom as the 2026-08-10 storage-volume
entry below, on an install that already had that fix. Measured this time
rather than guessed:

- `GET /api/resources?tenant=thieso2` returned **79 KB** — machines **3.9 KB**,
  storage-pool `used_by` **16.8 KB** (13.7 KB of it one pool), profile
  `config`/`devices` **45 KB**. A plain `sc ls` renders *none* of the latter,
  and the pools section is server-scoped so it shipped even with a project
  filter applied.
- Server-side work was not the problem: warm-connection TTFB was 0.43–0.69s.
  The rest was transport — a cold TLS handshake through the Cloudflare tunnel
  cost 0.7–2.2s, a 3-byte `/healthz` over the same tunnel measured 0.25–4.2s,
  and the 79 KB body added ~2s of trickle after first byte.

So the 3s budget was being spent almost entirely on data nobody reads, plus
tunnel latency that exists whatever the payload.

**Decision, two parts.**

1. **`include=` on the endpoint** — the follow-up the 2026-08-10 entry
   explicitly deferred, now that the numbers justify it. `sc ls` sends the
   kinds it will render (`machines`, plus one per `--networks`/
   `--storage-pools`/`--storage-volumes`/`--profiles`/`--images`), and the
   handler builds only those sections. A **missing** `include` still means
   "everything", so an older `sc ls` against a current appliance is
   unaffected; an **unknown** kind is **ignored, not 400'd**, so a newer
   `sc ls` against an older appliance is too — the CLI and the appliance
   version independently, and a 400 would silently push that client onto the
   live path, which is the exact failure this endpoint exists to prevent.
   Default payload: 79 KB → ~4.4 KB.
2. **Budget 3s → 5s, overridable with `SANDCASTLE_LS_CACHE_TIMEOUT`.** The
   2026-08-10 entry rejected raising it, on the grounds that waiting longer
   for a payload that is 95% unread data inverts the feature's purpose. That
   reasoning is retired by part 1, not contradicted: with the payload minimal,
   what remains in the budget is connection setup the CLI cannot avoid. The
   decisive number is the other side of the trade — on the same install a
   *fallback* run took **49 seconds**, so treating the cache as cheap to
   abandon was wrong by an order of magnitude. An endpoint that is genuinely
   down fails on connect long before 5s; only a live-but-slow one waits.

Also trimmed on the wire, same rule as `trimStorageVolume` (drop what no
`sc ls` section renders, keep what it does): storage-pool `UsedBy`
(`formatStoragePoolsSection` prints name/driver/status) and profile
`Config`/`Devices` (`formatProfilesSection` prints project/name and the
*count* of `UsedBy`, so `UsedBy` stays). The cache keeps the full objects; only
the response is trimmed, and a test asserts that.

Alternatives considered:

- **Trim harder and leave the budget at 3s.** Rejected: after `include=` the
  body is already near-minimal, and the measurements show the remaining cost
  is tunnel latency. 3s would still fail intermittently on a link where
  `/healthz` alone can take 4s.
- **Reuse a connection across `sc` invocations** (the "would buy far more
  headroom" note left by the 2026-08-10 entry). Still true, still the bigger
  win, still out of scope — it needs a local agent or a persistent session,
  which is a different feature, not a fix.
- **Make `include=` reject unknown kinds.** Rejected for the version-skew
  reason above; forward compatibility matters more here than catching a
  typo in a hand-written `curl`.

Verified against `obelix` after the client change alone (the appliance is
still on the old build, so it ignores `include=` and still returns 79 KB):
4 of 5 `sc ls -a` runs answered from the cache in ~1s, versus 0 of 1 before.
The remaining fallback is what the server-side `include=` handling removes
once the appliance is updated.

## 2026-08-12 — `starship.toml`: literal string for the stashed symbol

`git_status.stashed = "\$"` made starship refuse the whole config on every
shell start (`TOML parse error … missing escaped value`). `\$` is not a valid
escape in a TOML *basic* string; the `$` still has to be escaped for starship,
which parses these values as format strings. Fixed with a TOML **literal**
string, `stashed = '\$'`, rather than the double-escaped `"\\$"` starship's own
docs use — the literal form keeps the file readable and can't drift again if
another `$` symbol is added. Applied to the running `mydev` machine's
`~/.config/starship.toml` and `/etc/skel/.config/starship.toml` too, since the
image predates the fix.

## 2026-08-12 — Building the dev image in a Sandcastle project, not on the Mac

Added `scripts/build-image-in-project.sh` + `mise run image:dev:build-in-project`:
build the dev image inside a throwaway machine in one of the operator's own
Sandcastle projects, and publish it from there with `sc image save`.

- **Why not the existing paths.** The ask was "build the container on the host
  with the right arch, build the image there, publish from there". Two paths
  already existed and neither does it: `image:dev:build-upload` builds with
  docker **on the Mac** under `DOCKER_DEFAULT_PLATFORM=linux/amd64` emulation,
  and `image:dev:build-remote` does build on the host (in the `sc-build`
  appliance, ADR-0010) but publishes through GHCR — needing a token, a public
  registry round trip, and, decisively, **producing an OCI image**. Incus runs
  OCI images as application containers: PID 1 is the entrypoint, systemd never
  boots, so a Sandcastle machine built from one has no sshd, no caddy, nothing.
  Only the `import-docker-image-to-incus.sh` path produced system-container
  images, and it runs on the Mac.
- **`sc image save` as the publish step.** ADR-0019 already publishes a running
  machine as a local image; that is a system-container image by construction and
  runs entirely server-side. So instead of building an OCI image and converting
  it, the build machine *is* the image: provision it, then snapshot it.
  Alternatives rejected: (a) `podman export` in the appliance + `incus image
  import` — the rootfs tarball has to reach a client that can talk to the target
  daemon, i.e. it round-trips through the laptop (~GBs over a relayed tailnet);
  (b) doing the import over SSH on the host, which `importOnHost` already does —
  but SSH to the host is not universally available (IncusOS hosts have no shell,
  and `big`'s sshd is LAN-only); (c) mounting the Incus socket into the builder
  so it could import server-side — a real privilege escalation for an
  internet-facing appliance that handles a registry token.
- **One recipe, two engines.** The Dockerfile's `RUN` bodies were extracted into
  `images/dev/provision.sh`, staged (`packages`/`ai`/`skills`/`shell`/`stamp`)
  so each stage is still exactly one Docker layer with its original cache mount,
  and the Dockerfile now calls it. Same split `install-ai-cli-tools.sh` already
  uses. Without this the native path would have been a second copy of the recipe
  and the two would drift on the first change. `provision.sh` finds its context
  dir from `$SANDCASTLE_DEV_CTX`, else its own directory, else
  `/usr/local/share/sandcastle-dev` (where the Dockerfile puts it) — so the same
  script works copied to `/usr/local/sbin` in a build and run from a pushed
  directory in a machine.
- **A `clean` stage the Dockerfile never calls.** `sc image save` publishes the
  whole rootfs, so the build machine's own boot state would ship inside the
  template. `clean` removes the login user (a child's cloud-init would otherwise
  find the account present, skip creation, and never populate a home from
  `/etc/skel` — the entire interactive environment silently missing), strips the
  `/.sc` shims that cloud-init re-appends per instance, and resets cloud-init
  state. It deliberately leaves SSH host keys and `/etc/machine-id` alone:
  `sandcastle-generalize` regenerates both on the child's first boot (ADR-0019),
  and that logic should live in exactly one place.
- **The build machine is created as a Dev Image machine.** `SANDCASTLE_DEV_IMAGE`
  is set to the base image for the `sc create` call, so the machine takes the
  ADR-0024 no-Caddy path. Not cosmetic: otherwise cloud-init apt-installs Caddy
  and fetches a TLS leaf, and both would be baked into the published template.
- **Detached provisioning, not a long `incus exec`.** The first live run died on
  `write tcp …: i/o timeout` during `incus file push -r` — the link to the host
  is a relayed tailnet path (one API call per file, any of which can time out).
  The context is now streamed as a single tar over `exec`'s stdin, and the
  provisioning itself runs as a transient systemd unit (`systemd-run`) that the
  script polls, so a dropped connection cannot kill a 15-minute build.
- **Found and fixed a live bug in the merged dev-image feature.**
  `internal/config/sandcastle.go`'s `adminFromConfigAndEnv` — the **user** CLI's
  config assembly, and the only reader of `Images.Dev` that matters, since
  `sc create` matches `--image` against it — set `Images.Base` and `Images.AI`
  from the environment but omitted `Dev`. `SANDCASTLE_DEV_IMAGE` was therefore
  ignored by `sc`, pinning `Images.Dev` to `DefaultDevImageAlias`
  (`images:ubuntu/26.04`), so ADR-0024's no-Caddy carve-out could never trigger
  for any operator-built dev image. Added the field plus
  `TestLoadUserFromFileAndEnvCarriesImageOverrides`.
- **Also verified what ADR-0024 flagged as unverified:** `images:ubuntu/26.04`
  does exist on the public `images:` remote, including the `/cloud` variant this
  script builds from (`incus image list images: ubuntu` → `ubuntu/26.04`,
  `ubuntu/26.04/cloud`, x86_64 + aarch64).
- **`ping` needed a sysctl drop-in, not a capability.** First real use of a Dev
  Image machine hit `ping: socket: Operation not permitted … missing
  cap_net_raw+p capability or setuid?`. Ubuntu ships `/usr/bin/ping` with no
  file capability and no setuid, relying on unprivileged ICMP datagram sockets
  gated by `net.ipv4.ping_group_range`. systemd's own
  `/usr/lib/sysctl.d/50-default.conf` tries to open that up with
  `-net.ipv4.ping_group_range = 0 2147483647` — but gid 2147483647 is not mapped
  into an unprivileged container's user namespace, so the kernel rejects the
  write with `EINVAL`, and the entry's leading `-` makes systemd-sysctl swallow
  the failure. The value silently stays at `65534 65534` (gid `nogroup` only).
  Fix: `provision.sh packages` writes `/etc/sysctl.d/99-sandcastle-ping.conf`
  with `0 65534` — inside the mapped gid range, and `99-` sorts after
  `50-default.conf`. Rejected `setcap cap_net_raw+ep /usr/bin/ping`: file
  capabilities in a userns are v3 xattrs carrying a rootid, which makes them
  fragile across the publish/relaunch uid remapping, whereas the sysctl is
  namespaced state the container owns outright. Verified live (`ping` as the
  login user, 0% loss). Scoped to the dev template only — `base`/`ai` plausibly
  share the trait, but widening this to the project profile's cloud-init would
  touch every machine's boot path and was out of scope for this change.
- **Known limitation:** `sc image save` publishes into the tenant project it
  runs in, so the result is a project-local image. `--copy-to` copies it into
  other projects (resolving each target's Incus project name off the live
  tenant, never deriving it), but there is no tenant-wide alias.

## 2026-08-11 — t2: `images/dev/Dockerfile` (the interactive dev image)

Built the whole Dockerfile plus its baked assets (`images/dev/{gitconfig,
starship.toml, mise-config.toml, zshrc, git-identity-hook.sh,
statusline-command.sh, claude-settings.json, codex-config.toml,
install-ai-cli-tools.sh}`), covering wish §§1-8 / spec B1(partial)-B9, and
refactored `images/ai/Dockerfile` per the plan's B6 step.

- **§B6 "shared script" could not be a single physically-shared file.**
  `internal/images/plan.go`'s already-committed `PlanBuild` sets
  `ContextDir: filepath.Join("images", template)` — i.e. `docker build`'s
  context for `ai`/`dev` is `images/ai`/`images/dev`, not the repo root, and
  `internal/images/remote.go`'s `PlanRemoteBuild` + `remote_exec.go`'s
  `shipContext`/`writeContextTar` mirror that (they tar exactly
  `ContextDir`'s contents with a leading dir named after the template, then
  the in-appliance build script re-derives `contextDir :=
  builderBuildRoot + "/" + plan.Template`). Docker's COPY forbids reaching
  outside the build context, so `images/scripts/install-ai-cli-tools.sh`
  (the plan's suggested location) is not COPY-reachable from either
  Dockerfile as committed. Widening `ContextDir` to the repo root (matching
  the ticket handoff's own standalone example, `docker build -f
  images/dev/Dockerfile .`) or to `images/` would fix `COPY`, but ripples
  into `remote.go`/`remote_exec.go`'s tar-shipping leading-dir logic in ways
  I have no live Incus Image Builder appliance to verify in this sandbox —
  too large and too risky a blast radius for this ticket. **Decision:** keep
  `install-ai-cli-tools.sh` as a deliberate byte-identical duplicate in both
  `images/ai/` and `images/dev/`, guarded by a drift test
  (`images/dev/install_ai_cli_tools_test.go`, asserts the two files are
  byte-equal) instead of a single shared path. `images/ai/Dockerfile`'s two
  install `RUN` steps now call the shared script instead of inlining
  `npm install -g`/`npx skills`, preserving the exact prior two-step
  `HOME`/cache-mount structure so the change is behavior-preserving (same
  packages, same versions, same `HOME=/etc/skel` scoping for the skills
  step only) — confirmed by rereading the diff, not by a live `docker
  build` (no Docker daemon in this sandbox).
- **`nodejs`/`npm`/`build-essential` added to `images/dev`'s apt list**,
  beyond wish §2's literal `git gh ripgrep fd-find make zsh`. Spec B6
  already resolved the wish's install-mechanism ambiguity (curl installer
  vs. npm) in favor of npm, to reuse `ai`'s mechanism and avoid version
  drift — that decision requires npm actually being on `$PATH` at build
  time, which `ai` gets for free from `sandcastle/base`'s Debian toolchain
  layer but `dev` (FROM `ubuntu:26.04` directly, no base image) does not.
- **Codex `status_line` identifiers and rate-limit semantics verified from
  source, not a live Codex session** (no Codex CLI/authenticated session
  available in this sandbox). Fetched
  `codex-rs/core/config.schema.json` (`openai/codex@main`): `[tui]
  status_line` is `array<string>`, default
  `["model-with-reasoning", "current-dir"]`. Fetched
  `codex-rs/tui/src/bottom_pane/status_line_setup.rs`: confirms the six
  kebab-case identifiers used in `images/dev/codex-config.toml`
  (`model-with-reasoning`, `context-used`, `current-dir`, `git-branch`,
  `five-hour-limit`, `weekly-limit`) via the `StatusLineItem` enum's
  `#[strum(serialize_all = "kebab_case")]`, and resolves spec B8's
  remaining-vs-used caveat: the doc comments on `FiveHourLimit`/
  `WeeklyLimit` read "Remaining usage on the primary/secondary rate limit"
  — **remaining**, not used, matching the spec's stated caveat exactly. No
  bar, color ramp, or reset-time field exists anywhere in that file for
  either item, so none are faked in `codex-config.toml`.
- **Found (not introduced) a real bug in the wish's own
  `statusline-command.sh`, shipped verbatim anyway per the explicit
  byte-for-byte instruction.** The four glyph escapes
  (`\xef\x81\xbc`/`\xee\x82\xa0`/`\xe2\x8f\xb3`/`\xf0\x9f\x93\x85`/
  `\xe2\x86\xbb`) sit in the *format string* of their `printf` calls, not
  in a `%b`-tagged argument. dash's `printf` builtin only expands `\xHH`
  escapes inside `%b` arguments, not the format string itself (bash's
  `printf` does both, which is presumably why this wasn't caught during
  drafting) — verified directly: `dash -c 'printf "\xef\x81\xbc\n"'`
  prints the literal 12-byte string `\xef\x81\xbc`, `bash -c` prints the
  3-byte glyph. The Dev Image's `/bin/sh` is dash (Ubuntu default), so on
  a real Dev Image machine all five glyphs will render as literal
  backslash-escape text, not icons — cosmetic only (every other segment:
  model, bar, percentages, colors, works correctly), but real. Not fixed
  here — the spec is explicit that this script ships byte-for-byte, no
  deviation — but flagged here for whoever reviews next; a fix would be
  either switching the shebang to `#!/bin/bash` or moving each `\xHH`
  sequence into its own `%b` argument. `images/dev/statusline_test.go`
  asserts the *actual* (literal-text) output, i.e. it tests the shipped
  artifact's real behavior, not the presumably-intended one.
- **`DefaultDevImageAlias` / mise `image:dev:*` tasks / `admin.Images.Dev`
  plumbing were already committed by t1** before this session started;
  nothing here touches `internal/config/admin.go`, `internal/images/*.go`,
  `internal/cli/admin.go`, or `mise.toml` beyond what t1 already landed.
  `herdr`'s mise-registry entry was independently re-verified (fetched
  `registry/herdr.toml` from `jdx/mise@main`: `backends =
  ["aqua:herdrdev/herdr", "github:herdrdev/herdr"]`), confirming t1's
  Ground-truth claim that it needs no special plugin handling.
- **Default shell**: `/etc/default/useradd`'s `SHELL=` line (not `DSHELL=`
  — that was a naming slip in the plan) is rewritten to `/usr/bin/zsh`,
  plus `chsh -s /usr/bin/zsh root` for the image's own root shell.
- **Git identity hook** (`images/dev/git-identity-hook.sh`, sourced from
  `/etc/skel/.zshrc`) guards on *both* `user.name` and `user.email` being
  unset before populating either from `gh api user` — matching the spec's
  literal "neither value is already configured" wording, so a tenant who
  hand-sets only one of the two is still left alone.
- **Not run in this sandbox** (no Docker daemon, no live Incus, no
  authenticated Codex/gh session available here): an actual `docker build
  -f images/dev/Dockerfile images/dev`, the §B1 herdr/agent-forwarding
  reattach protocol, and live verification of the Codex `status_line`
  rendering. Verified instead: `sh -n`/`go vet`/`go build ./...`/`go test
  ./images/...` all pass; `images/ai/Dockerfile` still builds the same
  packages at the same versions (read-diff verified, not built); the
  Codex findings above are sourced from `openai/codex@main`'s own code,
  not a live session.

## 2026-08-11 — tenant creation: Dev Image alias sync + ingress-skip mechanism

- **Where the "image resolves to admin.Images.Dev" detection actually
  lives: the CLI, not `incusx`.** Traced `V2BareUserData`'s one call site
  (`v2BareInstanceConfig` in `internal/incusx/machine_create_v2.go`,
  invoked from `CreateMachineV2` when `request.Bare`) back through
  `CreateMachineV2Request` to where it's built —
  `runCreateMachineV2` in `internal/cli/create_v2.go`, which already has
  `config.adminConfig` (the resolved `config.Admin`, including
  `Images.Dev`) in scope. `TenantCreator`/`CreateMachineV2Request` itself
  carries no admin config, so the comparison can't happen at the point
  instance user-data is assembled — it has to happen one layer up, at the
  point the `--image` value is resolved, and be threaded down as a plain
  bool. Added `CreateMachineV2Request.DevImage`, set in
  `runCreateMachineV2` as `image == strings.TrimSpace(config.adminConfig.Images.Dev)`
  (exact string match against the configured alias — the only signal
  available, as the ticket predicted). `--bare` wins if both would apply
  (`DevImage: request.DevImage && !request.Bare` in `CreateMachineV2`) —
  an explicit `--bare` on a Dev Image image still yields the bare
  document; not spec'd either way, but bare's "no way in" promise reads as
  the more explicit ask when both are in play.
- **`V2DevUserData(user, sshKey, domain string)` signature mirrors
  `V2BareUserData(domain, signerURL string)`, not
  `V2DefaultProfileUserData`'s.** It's applied as INSTANCE config the same
  way bare is, so identity has to be read back off the project's default
  profile rather than threaded fresh — same reasoning as the existing
  `v2BareInstanceConfig` doc comment (a restricted tenant certificate
  can't see the infra project). Added `v2ProfileSSHKeyPattern` (matches
  the line right after `ssh_authorized_keys:`) alongside the existing
  `v2ProfileFQDNPattern`; login user reuses the existing
  `v2ProfileUserPattern` extraction (with the same
  `tenant.DefaultV2UnixUser` fallback `v2ProfileLoginUser` uses) rather
  than a second profile fetch.
- **Confirmed "drop the Caddy branch" means dropping generalize too, not
  just caddy-setup.** The ticket's own phrasing ("it only drops the Caddy
  branch (lines 64-87 of `V2DefaultProfileUserData`)") and the test
  spec's explicit "Caddy/generalize write_files/runcmd entries are
  ABSENT" agree: those two lines are one unit in the source (generalize
  exists only to prep a machine for the leaf fetch caddy-setup then
  does), so `V2DevUserData`'s body is exactly
  `V2DefaultProfileUserData`'s `jinja && signerURL == ""` fallback shape
  (identity + users + shims + `enable --now ssh`, no generalize, no
  caddy-setup) but rendered from a single already-joined `domain` string
  like `V2BareUserData` rather than separate `project`/`suffix` args.
- **`uniqueImageAliases` change is one word.** `admin.Images.Dev` slots
  into the existing variadic call
  (`uniqueImageAliases(admin.Images.Base, admin.Images.AI, admin.Images.Dev)`)
  — the function was already generic over any number of aliases, so
  there was no design choice here beyond confirming that and adding the
  dedup test (`TestPlanCreateV2ImageAliasesDeduplicated`, aliasing
  `Images.Dev` to `Images.Base` and asserting the result collapses to
  two entries).
- **`CreateMachineV2Result.DevImage` + CLI messaging** ("Dev Image: no
  Caddy/TLS ingress — SSH only.") added for parity with the existing
  `Bare` result field/messaging — not required by the ticket's "Done
  when", but leaving a Dev Image machine's `sc create` output identical
  to a normal machine's would silently under-report the one thing this
  ticket exists to guarantee (no ingress), which seemed worse than the
  small addition.
- **Not run against a real Incus deployment** (none available in this
  sandbox): the "create a Dev-Image machine end-to-end, confirm no Caddy
  process / no TLS leaf / no answer on :443 / private hostname still
  resolves / `sc c`/`incus exec` still reach it" manual check the ticket
  asks for. Verified instead: `go build ./...`, `go vet ./...`, and
  `go test ./internal/tenant/... ./internal/incusx/...` (including the
  new `TestV2DevUserData*`/`TestV2ProfileSSHKeyPattern*`/
  `TestV2DevUserDataFollowsTheProfileIdentity` tests) all pass; the
  pre-existing `internal/cli` `TestLogin*` failures in this sandbox are
  unrelated (no `incus` binary on PATH here — reproduced on the
  pre-change tree via `git stash` to confirm).

## 2026-08-11 — t4: Documentation & ADR-0024 for the dev image

Last slice of `docs/plan/add-a-dev-base-image-ubuntu-26-04-fixed-b2qtk8g.md`.
Docs-only: `docs/usage.html`, `docs/admin-developer-quickstart.html`,
`docs/e2e-sc2.md` (new Phase 8e + one-line Phase 6 addition),
`docs/adr/0024-dev-image-third-machine-template.md`. No code changes.

- **The four facts this slice was asked to consolidate were already recorded
  by t1-t3** — nothing new to add for them, only to cite: the exact
  `DefaultDevImageAlias` string and its unverified-against-a-live-remote
  status (t1, above), the byte-identical-duplicate `install-ai-cli-tools.sh`
  factoring for §B6 and the Claude-vs-Codex install-mechanism/status-line
  note (t2, below), and the exact ingress-skip function
  (`V2DevUserData(user, sshKey, domain string)`, `internal/tenant/create_plan_v2.go`)
  plus its detection mechanism (`CreateMachineV2Request.DevImage`,
  `internal/cli/create_v2.go`'s `runCreateMachineV2`) (t3, below). ADR-0024
  cites all three by name/signature rather than re-deriving them.
- **ADR number: 0024**, the next free slot after 0023 (event-bus resource
  cache) — no collision to resolve.
- **`docs/e2e-sc2.md` Phase 8e placed between Phase 8d (base images from a
  running machine) and Phase 10 (self-update), not appended at the end.**
  The doc's phases are meant to run top-to-bottom and Phase 9 already covers
  unattended login (orthogonal); 8e sits with the other "images" phases
  (8c/8c-bare/8d) rather than after the self-update phase, which is
  unrelated to image templates. Marked ⚠️ (partial) in the doc's own status
  legend, not ✅, since none of it was run against a live Incus deployment
  from this session.
- **Acceptance scenarios 1-8 (spec section "Acceptance scenarios"):
  none were re-run live in this session** (no Docker daemon, no live Incus,
  no authenticated Codex/gh session in this sandbox, same constraint every
  prior slice hit). Scenario 8 (`base`/`ai` unaffected) is the one with real
  automated coverage: `internal/config/admin_test.go`'s validate-with-no-dev-env
  case (t1) and the `images/ai/Dockerfile` read-diff check (t2) stand in for
  it. The rest (2, 3, 6, 7 especially) are documented in `docs/e2e-sc2.md`
  Phase 8e as PASS criteria to run against a live deployment, each flagged
  unverified-in-this-environment rather than claimed — per this ticket's
  "Done when" clause.

## 2026-08-11 — t1: config/build plumbing for the `dev` image template

First slice of `docs/plan/add-a-dev-base-image-ubuntu-26-04-fixed-b2qtk8g.md`.
Added a third image template, `dev`, alongside `base`/`ai` throughout
`internal/config/admin.go`, `internal/images/plan.go`, `internal/images/remote.go`,
`internal/cli/admin.go`, and `mise.toml`. Pure plumbing — no Dockerfile, no
tenant-creation wiring (those are t2/t3).

- **`DefaultDevImageAlias = "images:ubuntu/26.04"` — not verified against a
  live Incus `images:` remote.** The repo's source can't answer whether Incus's
  public images: remote actually publishes an Ubuntu 26.04 entry under that
  exact path (vs. e.g. `images:ubuntu/26.04/cloud`, or a not-yet-published
  release given Ubuntu 26.04 is itself very new at the time of this wish). I
  picked the alias that follows the identical naming pattern
  `DefaultBaseImageAlias`/`DefaultAIImageAlias` already use
  (`images:debian/13`), which the spec explicitly sanctions as the fallback
  approach ("`DefaultDevImageAlias` should follow the identical pattern... but
  whether `images:ubuntu/26.04` needs to actually exist... did not send it
  out to check"). This alias is only a fallback default anyway —
  `SANDCASTLE_DEV_IMAGE` or `--tag`/`--dev-image` overrides it once an
  operator builds+uploads the real Dev Image (mirroring how `ai` already
  works today). If it turns out to be wrong, it's a one-line constant fix,
  not a design change.
- **`dev`'s version-arg validation requires `--codex-version` and
  `--claude-version` but not `--gemini-version`** (per spec §B6/§B8 — no
  Gemini CLI on the Dev Image), in both `PlanBuild` (`internal/images/plan.go`)
  and `PlanRemoteBuild` (`internal/images/remote.go`). This is a real
  asymmetry from `ai`'s three-arg requirement, not an oversight.
- **`dev` does not carry a `SANDCASTLE_BASE_IMAGE` build-arg or `BaseRef`.**
  Unlike `ai` (built FROM the Sandcastle base image), the Dev Image is
  `FROM ubuntu:26.04` directly per the spec — a structurally independent
  template, not a layer on top of `base`. `PlanBuild`/`PlanRemoteBuild` reflect
  that: no base-image plumbing in the `dev` arm at all.
- **Collateral fix, not in this ticket's file list:** `Admin.Validate()` now
  requires `Images.Dev` to be non-empty (matching Base/AI). Two existing test
  fixtures elsewhere in the repo (`internal/incusx/images_test.go`,
  `internal/tenant/create_plan_v2_test.go`) built `config.Images{...}` literals
  by hand without a `Dev` field and started failing `Validate()` as a result.
  Fixed both with a one-line addition of `Dev: "..."` to keep `go test ./...`
  green repo-wide; left the substantive t3 work (tenant-creation Dev Image
  alias wiring, the ingress-skip mechanism) untouched — that's a different
  ticket's slice. Did **not** touch the equivalent literals in
  `internal/e2e/image_build_test.go`/`image_sync_test.go`: those are gated
  behind `SANDCASTLE_INCUS_E2E`/`SANDCASTLE_E2E_IMAGE_BUILD`, don't run in
  plain `go test ./...`, and updating them would mean growing their helper
  function signatures (`imageBuildAdminConfig(e2eConfig, baseTag, aiTag)` etc.)
  — a real design decision about e2e Dev Image coverage that belongs with the
  e2e-doc/t4 slice (`docs/e2e-sc2.md` is explicitly listed as that slice's
  responsibility), not a plumbing ticket.
- **`internal/cli/admin_test.go` did not exist before this change** — created
  it fresh for `remoteBuildTemplates` coverage since no prior test file
  covered that helper.


## 2026-08-11 — one dead storage volume no longer disables the resource cache

Found while verifying the `obelix` install after updating its auth-app to
v0.6.2: `sc ls` still fell back, now with 503 instead of 404, and the
auth-app logged the same line every ~10 seconds forever:

```
[resource-cache] initial read failed: list storage volumes for pool default across projects:
  Failed to run: zfs get -H -p -o value used rpool/incus/containers/obelix-thieso2-klabauter_klabauter-postgres:
  exit status 1 (cannot open '…': dataset does not exist)
```

The install has one broken instance — `klabauter-postgres` exists in the
Incus database (STOPPED, with a `container/klabauter-postgres` volume record
whose `used_by` points at it) but its ZFS dataset is gone. Listing volumes
reaches into the storage driver per volume, so that one record fails
`GetStoragePoolVolumesFullAllProjects("default")` for **every** project, and
a fatal seed turned it into a permanent outage of the whole cache:
`RunResourceCache` re-seeded every 5s, failed identically, and every tenant's
`sc ls` silently used the live path.

**Decision:** storage volumes become best-effort. A pool whose listing fails
is logged and skipped in `seedResourceCache`, and the per-event refresh does
the same; if *every* pool fails during a refresh the previous entry is kept
rather than blanked, so a transient storage error cannot delete volumes that
were readable a moment ago. Every other resource type stays fatal — those are
plain database reads, and a listing without instances would be wrong rather
than merely incomplete. ADR-0023 amended; decision 2's single readiness flag
is unchanged.

Alternatives considered:

- **Leave it fatal and fix the host.** The environment is genuinely broken
  and should be repaired, but "one dangling volume anywhere disables a
  fleet-wide feature for every tenant, permanently, and says so only in the
  appliance log" is not a failure mode worth preserving.
- **Per-resource-type readiness flags** (partial cache answers). This is what
  ADR-0023 decision 2 deliberately rejected, and it is a much larger change:
  `sc ls` and the endpoint would have to reason about mixing cache-backed
  instances with live-queried volumes. Degrading the one type that can fail
  independently gets the same benefit without that.
- **Drop the offending volume from the listing instead of the pool.** The
  Incus API fails the whole call; there is no per-volume error to filter, so
  this is not available without listing volumes one at a time.

Note: the skip is per pool, so on a host with a single pool `sc ls
--storage-volumes` shows nothing at all while the breakage lasts. That is
why the log line names the pool and says what it means.

## 2026-08-11 — `sc admin` follows the install `sc ls` is on

Reported from the field: `sc admin update`, run with `sc remote list` showing
`*obelix`, offered to update **idefix** — a different deployment on a
different host — and said `targeting install "idefix" (the only one on this
remote)`, which reads like confirmation. Four things stacked up:

1. `detectAdminRemote` scanned a hardcoded `~/.config/incus/servercerts`,
   ignoring the `INCUS_CONF` that `ExecuteAdmin` had *just* set to the real
   per-OS dir for exactly this reason. On macOS `~/.config/incus` does not
   exist, so detection died on its first step.
2. That `ReadDir` failure returned `""` instead of falling back to
   `detectAdminRemoteByAddr`, unlike the function's two other failure paths.
3. Even repaired, neither strategy can resolve a v2 install. A user's Incus
   remote points at their own tenant **sidecar** on the tailnet (ADR-0017,
   `obelix` → `https://100.97.217.39:8443`), not at the Incus host
   (`big.thieso2.dev` → `65.21.132.31`). Certificate and address matching
   both assume the two planes share a server; since v2 they never do.
4. The final fallback — "use the global incus default remote" — was silent
   unless `VERBOSE=1`.

**Decision:** resolve the install the way `sc ls` does and make the admin
plane follow it. `ExecuteAdmin` now records `activeInstall` from
`scconfig.LoadUser()` (the same call `sc ls` makes, so the shared incus dir's
current remote wins over `config.yml`), and when cert/address matching comes
up empty, `incusx.FindRemoteHostingInstall` asks each enrolled admin remote
which installs it hosts and picks the one carrying `<install>-infra`.
`resolveUpdatePrefix` then prefers that install over "the only one on this
remote", so a remote hosting several is still updated on the right one.
Explicit `SANDCASTLE_REMOTE`/`admin_remote` short-circuits all of it.

Alternatives considered:

- **Record the mapping in `config.yml`** (`remote_admin_remotes: {obelix:
  big}`), written at enrollment. Cheaper at run time and fully explicit, but
  it needs a backfill for every already-enrolled remote and goes stale when a
  deployment moves — the failure mode being, again, "acts on the wrong
  sandcastle."
- **Fix the two bugs and refuse when detection fails.** Safest, but leaves
  this setup permanently manual: cert/address matching cannot succeed for a
  v2 install, so refusing would be the *normal* outcome, not the exception.
- **Match on the remote name alone** (remote `obelix` ⇒ prefix `obelix`).
  True here and under ADR-0020, but it is a coincidence of naming, not a
  guarantee; asking the remote what it actually hosts is barely more work and
  cannot be wrong.

Notes for later:

- The install scan dials remotes. It runs only on the fallback path, tries
  the default remote first, skips public/image servers, and inherits
  `remoteDialTimeout`, so an unreachable remote costs one bounded dial.
- The last-resort global-default fallback now prints an unconditional warning
  naming the install, because everything downstream reports what it found in
  a tone that reads like agreement.
- `resolveUpdatePrefix` must test the *raw* active-install string before
  normalizing: `naming.NormalizeV2Prefix("")` answers with the default
  prefix, which would have matched an install genuinely named that whenever
  no user install was active. The existing "multiple installs error" test
  caught this.

## 2026-08-10 — `GET /api/resources` omits storage-volume snapshots and backups

Found in the field on the `idefix` install, right after it was updated to
v0.6.0: `VERBOSE=1 sc ls -a` still logged `cache-backed endpoint unavailable
(context deadline exceeded), falling back to live per-project query` even
though the auth-app was current, the cache was ready, and the endpoint
answered 200 to a plain `curl`. The cause was payload size, not readiness —
`/api/resources` returned **167 KB for a one-machine tenant**, of which
~95% was storage-volume snapshots: Sandcastle's own hourly autosnaps
(`snapshots.expiry=3d` on the `sc-local` shared-scripts volume, ADR-0022)
serialize as ~72 snapshot objects per volume, each with its full config, at
~43 KB per volume across four volumes. Over a Cloudflare-tunnelled Auth
Hostname (~32 KB/s measured) the body transfer alone cost 1.1–1.6s on top of
a 1.0–1.4s TLS handshake, tipping the round trip past `sc ls`'s 3s
`resourceCacheRequestTimeout` — so a *working, ready* cache still fell back
to the live path every time, which is precisely the outcome the cache
exists to prevent, and the fallback is silent unless `VERBOSE=1`.

**Decision:** trim `Snapshots` and `Backups` off each `api.StorageVolumeFull`
in the response (`trimStorageVolume`, `internal/authapp/resource_cache_api.go`).
`formatStorageVolumesSection` renders only project/name/type/content-type, so
nothing user-visible is lost; the same tenant's payload drops from 167 KB to
~9 KB.

Alternatives considered:

- **Raise `resourceCacheRequestTimeout` past 3s.** Rejected: it treats the
  symptom and inverts the feature's purpose — waiting longer for a payload
  that is 95% unread data is worse than the live path it was meant to beat.
  The budget is not the thing that is wrong here.
- **Only send the resource kinds the caller asked to display** (an `include=`
  query param driven by `--storage-volumes`/`--images`/…). A real
  improvement and probably the eventual shape, but it changes the endpoint's
  request contract, and once snapshots are gone the whole payload is ~9 KB —
  the remaining per-kind savings are noise on this link. Left for a
  follow-up rather than bundled into a field fix.
- **Stop caching snapshots at all** (trim at ingest, in `ResourceCache`).
  Rejected: the cache should keep what Incus returned, so a future consumer
  that genuinely needs snapshots can expose them behind an explicit param
  instead of re-reading Incus. Only the wire response is trimmed; a test
  asserts the cache still holds the full objects.

Note for whoever tunes this next: even with a ~9 KB body, the measured
round trip to a tunnelled Auth Hostname is ~1.8s, most of it TLS handshake
and tunnel latency rather than Sandcastle. The 3s budget holds, but not by
much on a slow link — a persistent/reused connection would buy far more
headroom than trimming further.

## 2026-08-10 — t4: ADR + end-to-end verification for the `sc ls` cache wish

Final slice of `docs/plan/admin-server-config-toggled-event-bus-ca8marg.md`.
Added `docs/adr/0023-event-bus-fed-resource-cache-for-sc-ls.md` (the
larger, harder-to-reverse decisions from t1–t3: why the cache lives in Auth
App, the single all-resource-type readiness gate, event-bus-only with no
periodic resync, the opt-out-by-default toggle, `sc-adm list` staying out of
scope) and did a holistic verification pass across the four combinations in
the wish's acceptance criteria. No live Incus is available in this
environment, so verification is via the existing `internal/authapp` +
`internal/cli` unit/integration test layers, per the plan's own fallback
clause ("targeted `internal/authapp` + `internal/cli` tests if a live Incus
isn't available").

- **What t1–t3 already covered, confirmed by reading and re-running the
  suites, not just trusting their own notes:** `internal/authapp/resource_cache_test.go`
  exercises the readiness state machine directly (not-ready before seed,
  not-ready after seed until the stream connects, ready once connected,
  stays ready across a heartbeat within the staleness window, goes not-ready
  past it, recovers on a fresh heartbeat, goes not-ready immediately on
  disconnect, recovers on reconnect) — combinations 2 and 3 from the wish's
  acceptance criteria, at the cache-engine layer.
  `internal/authapp/resource_cache_api_test.go` confirms the endpoint itself
  answers 503 for both toggle-off (nil cache) and not-ready (seeded but
  stream never connected) — the same signal `sc ls` keys its fallback off —
  plus tenant-scoping and project/machine filtering when ready.
  `internal/cli/list_cache_test.go` confirms `listMachinesViaCache` answers
  from a ready cache with exactly one call to the endpoint and falls back
  (returning `ok=false`) on every trigger the plan lists (no stored
  `AuthToken`, unreachable, not-ready, toggle-off — the last two are
  indistinguishable to the client on purpose, see the t3 note below).
- **Gap found and fixed: no test exercised the actual `sc ls`/`RunE`
  dispatch proving the live Incus stores are never touched on a cache hit.**
  Every existing test called `listMachinesViaCache` or the HTTP handler
  directly — real coverage, but one layer short of "run `sc ls -a` the way an
  operator does and prove it didn't reach Incus," which is what acceptance
  criterion 1 actually asks for ("verify it's not hitting live Incus
  calls"). Added `TestListCommand_ToggleOnReadyAnswersFromCacheWithoutLiveIncusCall`
  in `internal/cli/list_cache_test.go`: it runs `sc ls -a` through
  `NewRootCommand`/`cmd.Execute()` (the same path `main()` takes) with
  `tenantStore`/`machineStore` wired to a `poisonTenantStore`/
  `poisonMachineStore` pair that call `t.Fatal` the instant either method is
  invoked. Only a ready cache answer can make the test pass, since any
  fallback would immediately touch the poisoned stores and fail it. Paired
  it with `TestListCommand_FallsBackToLiveWhenCacheUnavailable`, the mirror
  case at the same layer (real `tenant.MemoryStore`/`fakeMachineStatusStore`
  behind a client returning the endpoint's actual 503 message), to make sure
  the poison test's absence of failure is meaningful and not an artifact of
  the command never reaching the fallback branch at all.
- **Toggle-off byte-for-byte compatibility (combination 4) was already
  covered, just not labeled as such.** `TestListJSONStartsEmpty`,
  `TestListTextShowsManagedMachines`, `TestListUsesProjectFromEnv`, and
  siblings in `root_test.go` all run the full `sc ls`/`list` command with no
  `authResources` client and no `AuthToken` configured — which is exactly
  "toggle off" from the client's point of view (`listMachinesViaCache`
  cannot tell "server toggle is off" apart from "I have nothing to try
  with"; see the t3 note on this file). Those tests predate this wish and
  assert output that must still match today, so their continuing to pass
  after t1–t3 landed is itself the toggle-off regression check the plan
  asked for — no gap here, just cross-referencing it explicitly for whoever
  reads this file next.
- **Docs cross-checked against shipped code, not just against the plan.**
  Verified `docs/usage.html`'s cache-backed-listing section
  (`SANDCASTLE_RESOURCE_CACHE`, `--networks`/`--storage-pools`/
  `--storage-volumes`/`--profiles`/`--images`, the on-by-default framing) and
  `docs/e2e-sc2.md`'s §2d (the exact verbose fallback message text, the flag
  list, the `sc-adm list` out-of-scope note) against the actual strings in
  `internal/cli/admin_root.go`'s `resourceCacheEnabled`, `internal/cli/list.go`'s
  flag definitions and `logListCacheFallback`, and
  `internal/authapp/resource_cache_api.go`'s `resourceCacheUnavailableMessage`.
  All matched what t1–t3 actually shipped — no drift found, no doc edits
  needed beyond the new ADR.
- `go build ./...`, `go vet ./...`, and `go test ./...` all pass except four
  pre-existing `TestLogin*` failures in `internal/cli` caused by no `incus`
  binary being on `PATH` in this environment — confirmed pre-existing (same
  failures on the unmodified branch before this slice's changes) and
  unrelated to this wish.

## 2026-08-10 — `GET /api/resources`: the cache-backed listing endpoint (t2 of the `sc ls` cache wish)

Second slice of `docs/plan/admin-server-config-toggled-event-bus-ca8marg.md`:
a bearer-authenticated endpoint answering from the t1 `ResourceCache` instead
of a live per-project Incus sweep. t3 (CLI wiring, new flags/columns) is not
built here — this slice only adds the HTTP surface and the request/response
contract it exposes.

- **Response/error contract for the "non-answer" cases (this is the load-
  bearing decision t3 depends on).** `GET /api/resources` returns exactly one
  of: **200** with a fully-populated, correctly-filtered `ResourceListResult`
  (cache toggle on, ready, request valid, tenant authorized); **503** with a
  plain-text body when the cache is not a safe source of truth — toggle off
  (`ResourceCache` is nil, since `HTTPRunner.Serve` never constructs one when
  `ResourceCacheEnabled` is false) or not-ready (`Snapshot().Ready == false`:
  initial read incomplete, event stream disconnected, or stale). Both
  toggle-off and not-ready collapse to the same 503 — deliberately: t3 is
  specified to fall back identically for either ("any non-answer... falls
  through transparently"), so the CLI needs one signal, not two. **401** (no/
  invalid bearer token), **403** (tenant query param not in the caller's own
  `accessibleTenantSummaries` — cross-tenant attempt), **404** (a literal,
  non-glob project filter that does not name one of the tenant's own
  projects — mirrors `listMachines()`'s "a typo should say so, not read as
  empty" rule), and **400** (a project/machine filter that fails
  `naming.ValidateNamePattern`/`ValidateProjectName`/`ValidateMachineName`)
  are all genuine request errors, not cache-unavailability — t3 must **not**
  fall back to live on these (that would just reproduce the identical error
  from the live path, but silently, after the fallback round trip). Only 503
  means "try live instead." This distinction (503 = fall back; everything
  else = surface the error) is the one thing this note exists to pin down for
  whoever builds t3.
- **`tenant` is a required-ish query param, not implicit.** The server has no
  visibility into the CLI's local `~/.config/sandcastle/config.yml` pin, so
  it cannot resolve "the caller's tenant" the way `listMachines()` resolves
  it from `config.adminConfig.Tenant`. When the param is empty AND the
  caller's bearer token grants exactly one accessible tenant (the common
  case — a v2 personal tenant's `accessibleTenantSummaries` is always
  exactly `[self]`), that one tenant is used; otherwise the request is
  rejected with 403 rather than guessed. `project`/`machine` accept the same
  literal-or-glob values `sc ls` already does (`naming.MatchName`/
  `naming.IsPattern`, the identical package the CLI's own filtering uses —
  no duplicated matching logic), and an empty `project` means "all
  projects" (`AllProjects` in the response mirrors `listPayload.AllProjects`
  exactly: `project filter == ""`). There is no `-a`/`--all-projects` or
  `-u`/`--include-unmanaged` request field: `-a` is just "call with
  `project` unset" from the client side, and `-u` does not exist anywhere in
  the current CLI (`internal/cli/list.go` has no such flag) — v2 machines
  are freeform instances with no "unmanaged" bucket at all
  (`HostOverrideManager.ListMachinesAndUnmanaged` always returns `nil`
  unmanaged), so `ResourceListResult` has no Unmanaged field either; the
  plan doc's mention of it describes a flag that does not exist in this
  codebase.
- **Authorization is `accessibleTenantSummaries`, not
  `authorizeWorkloadTenant`.** The plan explicitly says "same scoping as
  tenantsAPI/projectsAPI," and `tenantsAPI` uses
  `accessibleTenantSummaries(user)` (tenant name == caller's own normalized
  username) rather than the broader grant-based
  `authorizeWorkloadTenant`/`authorizeRouteTenant` used by the route/
  workload APIs (which also honor `TenantAccessManager` collaborator
  grants). Picking the narrower one on purpose: a cache-backed answer must
  never show a caller *more* than tenantsAPI already would, and mixing in
  the broader grant check here — which nothing in the plan asked for — would
  have done exactly that.
- **Per-resource-type project scoping is enforced by intersecting the
  snapshot against the caller's OWN raw Incus project names, not by trusting
  the request.** `tenantProjectNames(summary)` inverts
  `tenant.Summary.V2IncusProjectName` to map every raw cached project key
  (e.g. `sc2-alice-docker`) back to its short name for exactly the
  authorized tenant; every resource type (instances, networks, volumes,
  profiles) is filtered through that map before anything else, so a cache
  that (correctly) holds every tenant's data server-wide can never leak
  another tenant's rows through this endpoint regardless of what the
  `project`/`machine` query params say. Storage pools are the one
  exception — Incus storage pools are server-scoped, not per-project, and
  no existing live `sc ls` path ever gated them per tenant either, so
  `ResourceListResult.StoragePools` is the full cache list, unfiltered.
- **`Machines` reuses `meta.Machine` (and, transitively,
  `incusx.MachineFromInstance`); the other four resource types are exposed
  in their raw `api.Network`/`api.StorageVolumeFull`/`api.Profile`/
  `api.Image` shapes.** `sc ls` has an existing, tested contract for what a
  machine listing looks like (sidecar filtering, NIC-address resolution,
  bare-machine detection) — reusing it outright, instead of re-deriving a
  parallel shape, is what keeps this endpoint from drifting from
  `listMachines()`. The other four have no such contract yet (t3 gets to
  invent `sc ls`'s columns/flags for them), so passing the Incus API shapes
  through as-is avoids designing a rendering contract twice.
- **The instance→`meta.Machine` conversion lives in `incusx`
  (`MachineFromInstance`, extracted from `machine_store.go`'s
  `listV2Machines` loop, which now calls it too) and is injected into
  `authapp` as a function-typed field
  (`HTTPRunner.ResourceCacheMachineRenderer` →
  `HandlerOptions.ResourceCacheMachineRenderer`), wired in `admin_root.go`
  as `incusx.MachineFromInstance` — mirroring the existing
  `RouteBackend`/`CaddyController`/`ResourceCacheServer` pattern (interface
  or function surface defined in `authapp`, implementation in `incusx`,
  because `incusx` already imports `authapp` for the ResourceCacheServer
  adapter and the reverse import would cycle).** The alternative —
  duplicating NIC-address resolution (MAC-vs-name interface matching,
  `docker0` exclusion) and bare-machine detection inside `authapp` — was
  rejected outright: that logic is exactly the kind of subtle, already-
  tested code CLAUDE.md says not to re-derive, and package-boundary
  necessity is not a reason to fork it.
- **`HTTPRunner.Serve` now constructs the `*ResourceCache` before building
  `HandlerOptions`** (previously it was a local variable used only by the
  `RunResourceCache` goroutine): the handler needs the same instance to
  answer `GET /api/resources`, and a nil `HandlerOptions.ResourceCache` is
  exactly the toggle-off/no-socket signal the endpoint keys its 503 off of —
  no separate `ResourceCacheEnabled` plumbing needed on the handler side.
- Not done in this slice, by design (t3): no `sc ls` wiring to this
  endpoint, no live-vs-cache fallback logic, no new `sc ls` flags/columns
  for networks/storage/profiles/images. `docs/usage.html` is not touched
  here — there is no new CLI-facing surface yet, only a server endpoint.

## 2026-08-10 — Auth App resource cache engine (event-bus fed, t1 of the `sc ls` cache wish)

First slice of `docs/plan/admin-server-config-toggled-event-bus-ca8marg.md`:
the in-memory `authapp.ResourceCache` that will eventually back a cache-first
`sc ls` (t2 adds the HTTP endpoint, t3 wires the CLI). This slice only builds
and wires up the engine — no HTTP surface yet.

- **Staleness/heartbeat detection: last-event-received timestamp vs. a fixed
  timeout, reset on (re)connect.** The Incus event bus has no built-in
  liveness ping, so `ResourceCache` tracks `lastEventAt` and treats the stream
  as gone stale if `now() - lastEventAt` exceeds `DefaultResourceCacheStaleAfter`
  (2 minutes). Two design choices worth flagging: (1) the heartbeat is reset by
  *any* event received on the listener, not just ones the cache acts on — a
  handler registered with `nil` types (matches every event type) exists solely
  to prove the socket is alive, separate from the lifecycle-only handler that
  actually mutates the cache; a chatty-but-cache-irrelevant event still counts
  as proof of life. (2) `markStreamConnected` resets the heartbeat clock too,
  so a fresh reconnect gets a full timeout window rather than immediately
  reading as stale from whatever `lastEventAt` was before the drop. Accepted
  tradeoff: a genuinely idle install with zero Incus activity for over 2
  minutes will report not-ready and `sc ls` (once t3 lands) will fall back to
  live — judged acceptable since the fallback is exactly today's behavior, not
  an error.
- **On any relevant lifecycle event, refresh the whole (kind, project) bucket
  — never try to patch a single named resource from the event payload.**
  `api.EventLifecycle.Name`/`.Project` (the `event_lifecycle_name_and_project`
  extension) are not documented well enough to know, for a `*-renamed` action,
  whether `Name` is the old or new name across Incus versions. Rather than
  guess, the event handler ignores the event's own name entirely and just
  re-reads that project's full list for that resource kind via the same
  `UseProject(...).GetXFull()` pattern `listMachines()` already uses per
  project today. This makes create/update/delete/rename all reduce to the same
  code path and makes the cache correct regardless of exactly what a given
  Incus version puts in the event payload, at the cost of one wider per-project
  read instead of a single-item patch — cheap relative to the multi-second
  per-project reads this wish exists to avoid, since it only fires on actual
  lifecycle events, not on every `sc ls` invocation.
- **Subscribed action set: DNS reconciler's set (`admin_dns_events.go`) plus
  `instance-updated`/`instance-migrated`, plus the equivalent create/update/
  delete/rename(/refresh) actions for networks, storage volumes, storage pools,
  profiles, and images — but still short of "every event".** The shape doc
  explicitly warns not to copy the DNS reconciler's trimmed set (it excludes
  `instance-updated`, which this cache needs for IP/state changes, precisely
  because the DNS reconciler has a periodic-ticker backstop this cache
  deliberately does not). But "broadly enough" isn't "everything": actions
  that touch a resource without changing any field `sc ls` could ever display —
  `instance-exec`, `instance-console*`, `instance-file-*`, `instance-log-*`,
  `instance-metadata-*`, `image-retrieved`, snapshot/backup events — are still
  excluded, same rationale the DNS reconciler used, just without the ticker as
  a fallback for anything misclassified. `image-alias-*` events ARE included
  despite not being an `image-*` action, because aliases live inside
  `api.Image.Aliases` with no separate `image-updated` firing alongside them.
- **Storage pools vs. storage volumes are two different cache buckets.** Incus
  storage pools are server-scoped (not per-project); storage volumes are
  per-project. The wish's "storage" resource type maps to volumes for the
  per-project index (`ResourceCache.StorageVolumes`, keyed like the other four
  types), with pools kept as a small separate global list
  (`ResourceCache.StoragePools`) used only to know which pools to ask about
  when refreshing a project's volumes — not exposed as its own `sc ls` filter
  dimension (that's t3's call to make, once it exists).
- **Toggle defaults to on; env var `SANDCASTLE_RESOURCE_CACHE`.** Per the shape
  doc's decision, the cache engine starts unless an operator explicitly opts
  out (`SANDCASTLE_RESOURCE_CACHE=off`/`disable`/`disabled`/`0`/`false`, case-
  insensitive) — read once at `auth-app serve` startup in `admin_root.go`,
  following the exact `os.Getenv` + trim pattern already used for
  `SANDCASTLE_ROUTE_INGRESS`/`SANDCASTLE_AUTH_INGRESS_MODE`. When off, or when
  there's no mounted host socket (not the serving appliance — same gate
  `DNSEvents`/`RouteEvents` already use), `HTTPRunner.Serve` never constructs
  or starts a `ResourceCache` at all: no wasted initial read, no event
  subscription.
- **Interface defined in `authapp`, live-Incus adapter in `incusx` — mirrors
  the existing `authapp.RouteBackend` / `incusx.RouteBackend` split.**
  `authapp.ResourceCacheServer`/`ResourceCacheProjectServer` are the narrow
  Incus surfaces the cache engine needs (an all-projects read per type, a
  per-project re-read via `UseProject`, `GetEventsAllProjects`); `incusx`
  already imports `authapp` for exactly this kind of interface (see
  `routebackend.go`), so `incusx.ResourceCacheServer` wraps a live
  `incus.InstanceServer` the same way. This keeps `internal/authapp` free of a
  direct Incus client SDK dependency for the parts of the cache that don't
  need one, while still letting `admin_root.go` wire a real server in with one
  constructor call, same as every other `NewXForServer(socketServer)` already
  there.
- Not done in this slice, by design (see the plan's t2/t3): no HTTP endpoint,
  no `sc ls` wiring, no new `sc ls` flags/columns for the newly-cached resource
  types. `ResourceCache.Snapshot()` exists as the one read seam those slices
  are expected to build on, but its exact shape is intentionally not yet
  contorted to match a not-yet-designed HTTP response contract.

## 2026-08-07 — Reaching a bare machine: `sc connect` execs, `sc ls` says so

`sc connect` to a bare machine could only ever spend two minutes waiting for an
sshd that is never coming. It now detects one and opens an Incus exec session
instead. Decisions that were not in the ask:

- **Two-tier detection, off the INSTANCE config.** `--bare` writes a
  `user.sandcastle.v2.bare=true` marker at create time; the fallback is the
  instance's own cloud-init matching `^users: []$`. The marker alone would miss
  every machine created by the first `--bare` release (there were already six on
  obelix by the time this was written); the heuristic alone would be guesswork.
  Read from `instance.Config`, never `ExpandedConfig` — a profile could carry the
  key for every machine in the project, which is the opposite of what it means.
  The heuristic's false positive is a hand-launched machine whose user-data
  creates no users, and for that machine exec is the right door anyway.

- **Shell out to `incus exec`, don't drive the websocket.** The Incus client
  exposes exec directly, but then the PTY, window resizing and signal forwarding
  are all ours to get right. `sc incus` already shells out to the CLI with
  INCUS_CONF/INCUS_PROJECT set; reusing that path costs one process and buys all
  of it. And no `-t`/`-T`: incus allocates a PTY exactly when stdin AND stdout
  are terminals, which is already right for both `sc c web` and `sc c web -- cmd`.

- **The shell is chosen inside the machine.** `if command -v bash; then exec
  bash -l; else exec sh -l; fi`, because a bare machine is whatever image the
  tenant pointed `--image` at, and hard-coding bash turns a working session into
  "no such file" on anything busybox-ish.

- **Marked in the TYPE column, not a new one.** `sc ls` renders `CT (bare)`.
  Bareness is a property of what the machine IS, and TYPE is where a reader
  looks to understand why one row is reached over exec and the others over SSH.
  A fourth column would have had to be added to three separate tables and would
  be empty for almost every row. JSON gets a `"bare": true` field.

- **`sc fix` refuses rather than exec'ing.** It shares `dialV2Machine` with
  connect, so it sees the same flag — but every fixup it installs (the /.sc
  shell shims, the forwarded agent, sshd) is part of the interactive half a bare
  machine deliberately does not have. Nothing to fix is not the same as broken.

## 2026-08-07 — `sc create --bare`: a machine with a hostname and a leaf, and nothing else

The ask: create a machine that boots, has the correct hostname, and runs Caddy
with the right certs — no ssh, no user. Decisions that were not in the ask:

- **Instance-level cloud-init override, not a second profile.** The obvious
  alternative was a `bare` profile beside `default`/`homeshare`. It loses:
  profiles compose by *union* per key, so a bare profile could not un-set the
  default profile's `cloud-init.user-data` — it would have to replace `default`
  wholesale and therefore restate the NIC, root disk, `/workspace` and both
  `/.sc` devices, which then drift every time the default profile's devices
  change. Instance config wins over profile config for the same key, so setting
  `cloud-init.user-data` on the instance replaces exactly the half we want and
  inherits the devices. Cost: the override is only applied at create time, which
  is fine — cloud-init has already run by the time anything could change it.

- **The bare machine's identity is read BACK off the project's default profile.**
  Rendering the bare document needs `<project>.<suffix>` and the sidecar signer
  URL. The tenant summary looks like the natural source, but `Summary.DNSAddress`
  is derived from the `kind=infra` project, which a *restricted tenant
  certificate cannot see* — i.e. it is empty for exactly the callers that run
  `sc create`. The default profile's user-data carries both (that is where the
  machine's own `machine.env` comes from) and is always readable, so
  `v2BareInstanceConfig` greps them out of it. Bonus: a bare machine and its
  siblings physically cannot disagree about the tenant's zone. The coupling is
  pinned by a round-trip test against the real renderer rather than a sample.

- **A profile with no identity is a hard error.** `V2DefaultProfileUserData` has
  a minimal branch (no jinja, no signer) for projects provisioned without a
  suffix. Launching `--bare` there would produce a machine with no certificate
  *and* no way to log in and fix it — strictly worse than not creating it. So it
  refuses, and names `sc project create <name>` as the repair.

- **Reuse the caddy-setup shim rather than inlining the setup.** The bare
  user-data bakes the same `sandcastle-generalize` + `sandcastle-caddy-setup`
  boot shims as the default profile, so the actual bodies stay in the `/.sc`
  platform payload and update centrally (ADR-0022). Duplicating the install +
  fetch logic into a second cloud-init document would have been the first thing
  to drift.

- **Shared storage is masked per instance, not avoided by a new profile.** A
  bare machine should join none of the project's shared filesystems, and the
  obvious route — a third profile without the `home`/`workspace` disks — would
  need every project *re-provisioned* to gain it, and would have to restate the
  NIC, root disk and both `/.sc` devices (drifting from `default` the moment
  those change). Incus has a device type for exactly this: `type: none` inhibits
  an inherited device. So `--bare` sets `home`/`workspace` to `type: none` on the
  instance, which is the same instance-beats-profile rule the cloud-init
  override already rides on. It works on projects provisioned by ANY past
  version (the live `obelix-thieso2-builder` has no `homeshare` profile at all),
  needs no server-side reconcile, and makes the homeshare migration a no-op on
  bare machines — an appended `homeshare` profile loses to the mask.
  `/.sc/platform` is pointedly NOT masked: the boot shims source caddy-setup
  from it, so masking it would cost the machine the one thing `--bare` promises.
  The cost of masking by name is that a device added to `default` later is
  inherited until it is named here; a test asserts each mask still corresponds
  to a real profile device, so a rename shows up as a failure rather than as
  silent dead config.

- **`HOME=/srv` on a bare machine.** caddy-setup's Caddyfile serves `$HOME` at
  `/_h`, and a bare machine has no login user. `/srv` exists on every
  Debian-family image and is empty, so the handler answers 404 instead of the
  Caddyfile failing to load. Pointing it at `/workspace` would have made `/_h`
  and `/_w` silently the same tree.

- **`users: []`, plus an explicit sshd disable.** An *absent* `users:` key makes
  cloud-init create the distro default user, so the empty list is what makes
  "no user" true — subtle enough that the test asserts on the parsed YAML rather
  than a string match. Nothing in the document installs sshd, but a
  `--image` that ships one enabled would quietly make "no ssh" untrue, so the
  runcmd disables it defensively.

- **The output tells the truth about being unreachable.** `sc create --bare`
  prints the HTTPS URL instead of the SSH hint, and says outright that
  `sc connect` will not work, pointing at `sc incus exec` instead. `--bare` was
  deliberately *not* wired into `sc connect`/`sc fix`'s create-if-missing path:
  those exist to open a shell, and creating a machine there is a means to that
  end.

## 2026-08-06 — Splitting `/home` out of the default profile into `homeshare`

The ask: keep `/workspace` shared on every new machine, stop sharing `/home`,
and add a second profile that can be requested at machine creation. Decisions
that were not in the ask:

- **Existing machines are migrated, not stranded.** Removing the `home` device
  from `default` reaches *running* machines the next time any reconcile
  re-renders that profile (tenant create, project create, `sc login --force`).
  Those machines' home directories — including the login user's
  `~/.ssh/authorized_keys`, written there by cloud-init — live on the shared
  volume, so a silent detach would swap `$HOME` for the image's empty one and
  break key auth fleet-wide. `migrateV2MachinesToHomeShare` therefore runs in
  between: when the *live* `default` profile still carries the device, every
  instance using `default` gets `homeshare` appended first. It is self-limiting
  (once the device is gone from `default` there is nothing to migrate) and
  per-instance failures are logged, not fatal — one machine that cannot hotplug
  the disk is not a reason to abort a tenant reconcile.
- **`ensureV2AppProfiles` is the single entry point.** The ordering above
  (homeshare → migrate → default) is load-bearing, so the three call sites
  (tenant create, project create, SSH-key re-render) call one function instead
  of composing it themselves. The SSH-key path doubles as the backfill for
  projects created before `homeshare` existed.
- **`--home-share` on `sc connect` too, not just `sc create`.** `connect`
  creates the machine when it is missing, and its `--vm` flag already has the
  same "only when it has to be created first" semantics. Both flags are
  create-time only — Incus applies profiles at instance create, and an existing
  machine keeps what it was created with; the flag help says so.
- **Teardown had to learn about the second profile.** `deleteV2AppProject`
  detached the shared volumes from `default` only; with `/home` on `homeshare`
  the volume delete would have failed ("in use") and taken the project delete
  with it. The sweep now runs over every profile in the project (the same fix
  applied to the manual teardown loop in `docs/e2e-sc2.md`).
- **The profile is created even on hosts without idmapped mounts.** There the
  shared volume cannot show consistent ownership to a CT and a VM (VM sshd
  StrictModes rejects the foreign-owned `~`), which is exactly why `/home` used
  to be dropped from `default` on such hosts. Now that sharing is opt-in, the
  provisioning WARNING is the right place to say it — refusing to create the
  profile would only turn an informed choice into a confusing "profile not
  found" at create time.

## 2026-08-02 — A project GLOB is pushed into the store too, not just a literal

Follow-up to the two entries below, from a `VERBOSE=1` trace of
`sc ls -a 'i*:w*:w*'`: it issued a `GetInstancesFull` against
`idefix-thieso2-home` even though the project glob `w*` could never match
`home`. I had reasoned that "a glob has to see every project to know which ones
match", and pushed only a *literal* project into the store. That was wrong —
the tenant summary already carries the project list, locally, with no Incus
call. Matching a glob against it needs nothing from the daemon.

`listV2Machines` now filters `summary.Projects` with `naming.MatchName`
(equality for a literal, so one branch serves both) and the CLI passes the
project part through whether or not it globs. On the 7-project obelix tenant
`sc ls -a 'g*:d*'` drops from 7 `GetInstancesFull` calls to 1, and a glob
matching no project — the case in the trace — costs zero.

## 2026-08-02 — Wildcards in the INSTALL part too (`*:*:dev`)

Extends the entry below to the leading part of `[[remote:]project:]machine`, so
a reference can sweep enrolled installs. Decisions that were not in the ask:

- **Only the THREE-part form carries an install glob.** `a:b` was already
  ambiguous (remote:project for `sc ls`, remote:machine elsewhere), resolved by
  "is `a` an enrolled remote". Extending that to patterns would make `g*:d*`
  mean project:machine today and remote:machine the day someone enrols an
  install called `gizmo` — a reference whose meaning depends on unrelated
  state. So globbing installs is spelled out: `sc ls '*:*:dev'`. Two-part
  behaviour is untouched.

- **Patterns match enrolled remote NAMES, not install DNS suffixes.** The
  names are `sc remote list`'s set — project-pinned or Auth-Hostname-carrying
  incus remotes — so `*` never wanders into `images:`/`local:`. DNS suffixes
  would have to be discovered by connecting to each install first, which is
  what the pattern is supposed to decide.

- **Installs are swept sequentially, on purpose.** Binding to an install
  re-points the process-wide `INCUS_CONF` (that is how the incus client finds
  the right restricted certificate), so two cannot be in scope at once.
  Parallelising would have meant threading an explicit `ConfigPath` through
  every store constructor — a large refactor for a set that is realistically
  2–5 installs, when the round trips that actually cost are the per-project and
  per-machine ones, which stay concurrent. `forEachRemoteScope` enforces the
  bind/run/unbind unit structurally so a failing sweep cannot leave INCUS_CONF
  pointing at the wrong install. The binder and the install list are injected
  (`remoteFanout`) so all of this is testable without enrolled installs.

- **Different project sets across installs are normal, not an error.** The
  "literal project must exist" rule from the entry below would have made
  `sc stop '*:web:api'` fail whole the moment one install has no `web`. A new
  `unknownProject` sentinel lets a cross-install sweep treat it as "nothing to
  match here", while a project that NO swept install has is still the typo it
  is. On a single install nothing changes.

- **A partial sweep is fatal for lifecycle verbs, a warning for `sc ls`.** If
  an install is unreachable, acting on "every dev machine" minus the ones we
  could not see is not what was asked — and for `delete` it is unrecoverable.
  A listing has the opposite duty: one broken install should not blind you to
  the rest, so it prints `warning: <install>: …` and shows what answered.

- **`machineMatch.Remote` is set only for a cross-install sweep**, and output
  names the install whenever it is set. The earlier "qualify only when the set
  spans installs" rule was wrong: a sweep that matched on exactly one install —
  which may not be the one you are sitting on — would have printed a bare
  `work:api`.

- **`sc ls` gets a separate multi-install payload** (`{remotePattern, remotes[],
  warnings[]}`, each entry a normal listing) rather than a flattened one. Each
  section keeps its OWN tenant summary, which the FQDN column needs — installs
  have different DNS suffixes, and one shared summary mislabels every row.

- **Single-target commands narrow before binding.** `narrowRemoteGlob` runs
  ahead of `rebindForReference` (which needs a literal remote name) and turns
  the glob into a concrete `remote:project:machine`. `sc route publish` is the
  exception: it never rebinds, so a globbed install there is refused with an
  explicit message rather than silently acting on the current install.

## 2026-08-02 — Wildcards in machine references

`sc ls -a 'g*:d*'` and `sc delete 'gbrain:*'` now work; globs are accepted
wherever a machine reference is. Decisions that were not in the ask:

- **`path.Match`, not a new matcher.** Sandcastle names are single labels with
  no separators, so shell globbing is exactly `path.Match` on one path element —
  `*` cannot escape a segment because there is nothing to escape into. The
  reference is split on `:` by us and each part matched on its own.
  `naming.MatchName` on a *literal* is an equality check, which is what lets
  every reference run through the selector without changing how unqualified
  references behave.

- **A pattern-aware validator, kept separate from the strict one.**
  `naming.ValidateNamePattern` drops the two-character floor of
  `ValidateProjectName`/`ValidateMachineName` (`*` is a legal pattern but not a
  legal name) and admits the metacharacters. `parseV2MachineReference` stays
  strict and is still what `sc create` uses — creating a machine called `*` is
  not a thing. The colon grammar was extracted into `splitMachineReference` so
  the strict and glob parsers cannot drift apart.

- **`sc ls`'s two-part argument was ambiguous and is now resolved by
  enrollment.** `sc ls a:b` was `remote:project`; the ask needs it to also be
  `project:machine`. Resolved the way `rebindForReference` already resolves the
  same ambiguity for every other command: the leading part is a remote only if
  it names an ENROLLED one. So `sc ls obelix:home` is unchanged and
  `sc ls 'g*:d*'` filters projects and machines. `splitListReference` takes the
  "is this enrolled" predicate as a parameter so it stays a pure function.
  Behaviour change: `sc ls foo:bar` where `foo` is *not* enrolled used to fail
  with "no enrolled Sandcastle remote"; it now reads as project `foo`,
  machine `bar`. Alternative considered: a distinct separator for the machine
  part (`/`), rejected — it would make `sc ls` the one command with its own
  reference syntax.

- **A glob that matches nothing means different things to different verbs.**
  For `sc ls` it is an empty listing (exit 0) — the question "which machines
  match?" has an answer, and it is none. For a lifecycle verb it is an error:
  the user asked for machines to be acted on and none were. Orthogonally, a
  *literal* project that does not exist is always an error, so a typo does not
  read as "no machines".

- **One-target commands take globs as a selector, not a fan-out.** `connect`,
  `fix`, `route add`, `image save` narrow through
  `resolveSingleMachineReference`: exactly one match proceeds, several prompt
  (tty) or error listing candidates, none errors. It passes literals through
  *unresolved* because `sc connect` legitimately names machines that do not
  exist yet and creates them — a glob can only ever pick from what is there.

- **The lifecycle JSON payload stays scalar for literal references.** A
  wildcard returns `{action, tenant, selector, results[]}`; a literal keeps the
  historical `{action, tenant, project, machine}`. Always emitting the array
  would have been tidier but breaks anything parsing `sc stop web --json`
  today, and the shape now keys off something the caller controls explicitly.

- **Fan-out is concurrent and does not stop at the first failure.** A ten-
  machine `sc stop` should not cost ten times one, and a partial failure should
  say which machines are fine. Results stay in target order regardless of
  completion order; the command exits non-zero with `… failed on N of M`.
  `applyMachineAction` takes the per-machine action as a function so it is
  testable without an Incus daemon (`tenantCreator` is a concrete struct, not
  an interface).

- **The install part was left literal at first**; it globs as of the entry
  above.

## 2026-08-02 — Machine listing fans out per project, and scopes down when the caller has one project

`listV2Machines` walked the tenant's app projects in a `for` loop, one blocking
`GetInstancesFull` per project. On obelix (7 projects, loaded host) a verbose
trace showed the individual calls taking 2–10s each and the command paying the
**sum** — ~33s of wall clock to answer a listing.

Two changes, both in `internal/incusx/machine_store.go`:

- **Fan out.** The per-project calls now run in goroutines and the results are
  reassembled in project order (so output ordering does not depend on which
  project answered first, and neither does which error surfaces on a
  multi-project failure). Wall clock drops to the slowest single project.
  `resolveServer()` already established the connection before the loop, so the
  goroutines share an already-connected HTTP client and nothing races on
  connect. Alternatives considered: `errgroup` (would add
  `golang.org/x/sync` as a direct dependency for a `WaitGroup` plus an error
  slice — not worth it) and a bounded worker pool (a tenant has a handful of
  projects; the daemon is not at risk from that many concurrent GETs).

- **Push the project scope into the store.** `sc list` already computed a
  `projectFilter` — including implicitly, from the pinned `config.project` —
  but applied it to the *results*, after querying every project. Added
  `ListMachinesInProject` / `ListMachinesAndUnmanagedInProject`, surfaced as the
  optional `machine.ProjectScopedStore` / `ProjectScopedCombinedStore`
  interfaces so the CLI can type-assert for them without every `machine.Store`
  implementation having to grow the method. The caller-side filter stays as a
  cheap safety net. `FindMachine` uses the scoped form too — it always knew its
  project. Deliberately left whole-tenant: `v2MachineProjects` (cross-project
  unique-search is the point), SSH-key and share reconciles, and the auth-app's
  machine listings.

Also made the verbose Incus API logger serialised (`verboseLogger` in
`api_log.go`): concurrent calls now write to that sink, and it is a
`bytes.Buffer` under test, so unserialised `fmt.Fprint` was a genuine data race.

Not touched: the auth-app's `reconcileOneV2TenantDNS` has the same serial
per-project loop, but it is a background reconciler on a different blast
radius — out of scope here.

## 2026-07-31 — DNS/route reconcile triggers on a lifecycle-action whitelist, not `instance-*`

The obelix auth-app burned a steady ~10.7% CPU (26 h over a 10-day uptime)
while serving almost no requests. Profiling showed the ADR-0018 event-driven
DNS reconcile loop running *continuously* instead of every 30s, for two
compounding reasons:

- `subscribeInstanceLifecycleEvents` triggered on **any** action prefixed
  `instance-` across all projects. A monitoring agent exec-polling `ps` in the
  container (~1/s, each emitting `instance-exec`) kept the trigger channel
  permanently full.
- The loop **fed itself**: every reconcile pass reads each tenant sidecar's
  CoreDNS zone file via the Incus file API, which emits
  `instance-file-retrieved` — itself an `instance-*` event — so each burst
  re-armed the next one even with no external activity.

Fix: trigger only on a whitelist of actions that can actually change what DNS
resolves to (created/deleted/renamed/restarted/restored/resumed/shutdown/
started/stopped). Alternatives considered: ignoring self-caused events
(requestor matching — fragile, the SDK doesn't expose our own identity),
debouncing (treats the symptom; the loop would still run far more than
needed), and scoping the subscription to the install's project prefix
(insufficient alone — the sidecar file reads happen *inside* our own
projects). Excluded actions that could in principle matter (e.g. a NIC swap
arrives as `instance-updated`) are covered by the periodic ticker, which is
the documented convergence guarantee. The original comment claimed a spurious
trigger "costs one render" — it actually costs a full Incus API sweep
(ListProjects + per-tenant GetInstancesFull + sidecar file reads), which is
what made the feedback loop expensive.

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

## 2026-08-10 — t3: `sc ls` cache-first with live fallback (event-bus cache wish)

Wired the `sc ls` path of `listMachines()` (`internal/cli/list.go`) to try the
t2 `GET /api/resources` endpoint first, via a new `authapp.DeviceClient.ListResources`
and a `config.authResources` injection seam (mirroring `authTenants`), falling
back to exactly the existing live per-project path on any failure. Only
`newListCommand`'s `RunE` was rewired — `sc-adm list`/`sc admin list`
(`admin_machine.go`) and the internal `currentTenantMachines` helper
(`project.go`) call `listMachines()` directly, unchanged, per the plan's
explicit scope boundary.

- **Any client-side error collapses to "fall back," no status-code branching.**
  `ListResources` returns a plain `error` for a dial failure, a timeout, or any
  non-200 (including the 503 the endpoint answers for both "toggle off" and
  "cache not ready" — see t2's `resourceCacheUnavailableMessage`). `sc ls`
  never distinguishes these; it just retries live. This matches the plan's "ANY
  non-answer" wording and means the CLI does not need to know the server's
  toggle state at all.
- **A short (3s), request-scoped timeout, not `DeviceClient`'s default.** The
  default client timeout (5 minutes, sized for the device-login poll) would
  make an unreachable admin server hang `sc ls` far longer than "falls back
  near-instantly" implies. `listMachinesViaCache` wraps the caller's context
  with its own `resourceCacheRequestTimeout` instead of changing
  `DeviceClient`'s shared default, so other callers (`sc tenant list`, `sc
  project create`, …) are unaffected.
- **`listMachines()` itself is untouched.** Rather than refactor its
  tenant/project resolution to share code with the new cache path, the cache
  wiring duplicates just the ~6 lines it needs
  (`splitListTenantAndProject`) as a separate function. `listMachines()`
  already has direct test coverage asserting its exact behavior (wildcard
  filters, typo-vs-glob project errors, cross-install scoping); the duplication
  cost is small and it removes any risk of the byte-for-byte toggle-off
  acceptance criterion regressing from a shared-code refactor.
- **New resource-type flags are opt-in and irrelevant to fallback.**
  `--networks`/`--storage-pools`/`--storage-volumes`/`--profiles`/`--images`
  only control which extra sections `formatMachineList` renders; the live path
  never populates those `listPayload` fields, so on any fallback the flags are
  silent no-ops rather than an error — matching "behaves exactly as it does
  today (instances only)" from the plan. Table columns are a first pass
  (Project/Name/Type/Managed for networks, etc.) — not exhaustive, since the
  plan calls flag/column naming an implementation detail.
- Multi-remote glob sweeps (`sc ls 'o*:gbrain:d*'`, `listMachinesAcrossRemotes`)
  were left on the plain live `listMachines()` call — the wish's motivating
  trace and acceptance criteria are single-install, and threading the cache
  path through the fanout would need its own request/response shape decision
  the plan doesn't make.

## 2026-08-13 — plan_ticket: confirm Caddyfile wildcard rendering + exact-vs-wildcard precedence

`RenderCaddyfile` (`internal/authapp/routes_caddy.go`) already writes each
Route's `Hostname` verbatim as the site address — no rendering code change was
needed. Added `TestRenderCaddyfile_WildcardRouteBlock` and
`TestRenderCaddyfile_ExactAndWildcardBothRendered`
(`internal/authapp/routes_caddy_test.go`) confirming a `*.jot.moyn.dev` Route
renders a valid `*.jot.moyn.dev {` block with on-demand TLS and the right
`reverse_proxy` target, standalone and alongside an exact-host Route for the
same zone. Both pass.

- **No executable confirmation of exact-over-wildcard precedence.** This repo
  has no `caddy` binary and no `caddyserver/caddy` module dependency anywhere
  (checked `go.mod`, `PATH`, and the filesystem) — Caddy config here is plain
  string templating, never adapted or run. So the "exact route wins" decision
  is not exercised by a test; it relies on Caddy's own documented behavior
  (site addresses are matched most-specific-first, and a literal hostname is
  more specific than the same zone's wildcard). If this precedence is ever
  load-bearing enough to need proof beyond the docs, that requires vendoring a
  `caddy adapt`/`caddy validate` step, which is out of scope for this slice.

## 2026-08-13 — plan_ticket: wildcard public routes (#141) — the two non-obvious calls

Recording both non-obvious choices made while building wildcard route support
(spanning the `routesAsk`/hostname-validation change, the `RenderCaddyfile`
confirmation, and the `Status` DNS-liveness probe), per the spec's
"Documentation to update alongside the code" note:

- **Leaf cert per real SNI, not one real wildcard certificate.** `routesAsk`
  (`internal/authapp/routes_api.go`) authorizes on-demand issuance for any
  concrete subdomain covered by a registered `*.<zone>` Route, but a literal
  `*.<zone>` domain is always denied (no TLS handshake ever presents a literal
  `*` SNI). Caddy's `on_demand_tls` therefore issues and caches one ACME leaf
  cert per distinct subdomain the first time it's hit — there is no DNS-01
  challenge and no xcaddy plugin anywhere in this change, matching the spec's
  non-goal. The tradeoff: first-hit latency and one Let's Encrypt issuance per
  new subdomain, in exchange for zero added infra (no DNS provider API
  credentials, no custom-built Caddy).
- **Exact-vs-wildcard precedence relies on Caddy's own address-specificity
  sort, not app-level matching logic** — confirmed by *reading* Caddyfile
  address-matching semantics, not by an executable test: this repo has no
  `caddy` binary or `caddyserver/caddy` module dependency, so `caddy
  adapt`/`validate` isn't available to exercise it directly. See the entry
  above ("confirm Caddyfile wildcard rendering + exact-vs-wildcard
  precedence") for what was actually tested (`RenderCaddyfile` emits both
  blocks correctly) versus what's asserted from docs (which block wins).

## 2026-08-21 — `sc ls` treats a running machine with a blank address as a cache miss

**What.** `listMachinesViaCache` (`internal/cli/list.go`) now scans a
cache-backed answer before returning it: if any machine is `Running` with an
empty `PrivateIP`, the answer is discarded and `sc ls` falls through to the live
per-project path, logging the reason under `VERBOSE=1` like every other
fallback. New helper `runningWithoutAddress`.

**Why (this was a real, reproducible bug, not a theoretical gap).** ADR-0023
decision 3 keeps the resource cache event-driven with no periodic resync, on the
premise that `sc ls`'s fields are covered by `instance-updated` ("IP/NIC/state
changes"). That premise does not hold for addresses. Upstream emits
`api.EventLifecycleInstanceUpdated` from exactly two sites — the tail of
`(*lxc).Update()` and `(*qemu).Update()` — i.e. an instance **config** change
made through the API. A guest picking up its DHCP lease is not an API operation
and emits nothing at all. So the sequence on every `sc create` is:
`instance-created` + `instance-started` → cache re-reads the project → eth0 has
no lease yet → an empty address is cached → the lease lands → **no event** → the
blank survives until some unrelated create/update/start/stop happens to touch
that same project. Observed live on obelix on 2026-08-21: `7ed-sdui/dev` was
reachable over ssh at `10.123.0.190` while `sc ls` printed an empty IP column,
and `wordpress/dev` did the same an hour earlier.

**Alternatives considered.**

- *Periodic resync ticker* (what ADR-0023 names as the follow-up, ADR-0018's
  pattern). Rejected for now: it pays a recurring full-fleet sweep — the exact
  cost the cache exists to remove — to fix a gap that is detectable for free at
  the point of use.
- *Delayed re-read after `instance-started`* (server side). Rejected as a guess
  at a timer: no delay is right for every image and network, and a wrong guess
  reintroduces the same blank with extra machinery.
- *Render blank as "pending"*. Rejected — it dresses up a stale read as a state
  the system does not actually have.

**Tradeoff, stated plainly.** A machine that genuinely runs without an address —
no NIC device, or a VM whose incus-agent never came up — makes the fallback
permanent for any listing that includes it. That is exactly pre-cache `sc ls`
behaviour: one live per-project read, slower but never wrong. Chosen
deliberately, because reporting an address the machine does not have (or
omitting one it does) is the worse failure. Stopped machines are excluded from
the check for the same reason in reverse: a blank there is the truth, and
treating it as a miss would bypass the cache for every listing containing a
stopped machine.

## 2026-08-21 — Device login no longer fails when the SSH-key reconcile hits a broken machine

**Decision.** `devicePoll` now treats a `reconcilePersonalTenantSSHKey` failure
as a warning, not a 500: the key is stored, the login approves with the
enrollment token, and the poll response carries a new `warning` field that the
CLI prints to stderr (`Warning: SSH key was saved but not written to every
existing machine: …`). Previously the error aborted the whole login before the
client received the token.

**Why.** Observed live on obelix (2026-08-21): a brand-new laptop could not
enroll at all because project `herdr` contained two running containers launched
from a stock Ubuntu image — no `thies` Unix user, so the in-machine
`install -d -o thies` exited 1, `reconcileV2` surfaced it (correctly: no machine
in that project took the key), and the poll 500'd. One machine the user is
locked out of either way must not block enrolling a new device; the handler
already treats the client-certificate recording just above as best-effort.

**Alternatives considered.** (a) Skip machines whose Unix user is missing inside
the reconcile script — rejected: it silently narrows "reconcile failed" to
success and hides real breakage; (b) keep the hard failure and document
"stop the offending machine" — rejected: turns a cosmetic inconsistency into a
login outage. The warning keeps the signal without the outage.

## 2026-08-22 — Re-login enrollment token grants every existing project

**Decision.** `PlanCreateV2` no longer scopes `RestrictedProjects` to the
default project alone: it unions in the tenant's existing app projects
(`CreateRequest.ExistingProjects`, gathered by `ProvisionReuseInputs` from live
kind=project Incus projects, prefix- and tenant-scoped), default first, rest
sorted. All three token-minting callers (auth-app login provisioning, project
broker tenant create, `sc-adm tenant create`) thread the reuse list through.

**Why.** Observed live on obelix (2026-08-22): a first login from a new machine
enrolled a fresh restricted certificate that could only see the default project
(`sc project ls` → just `work`), while an older client's certificate saw all 13
— it had been extended one project at a time by each `sc project create`. The
token (and the shared-certificate union on re-login, which uses the same
`tokenPlan.Projects`) must carry the full set for clients that weren't around
when the projects were created.

**Alternatives.** Fixing only in the auth-app provisioner (union at the
`tokenPlan` site) was rejected: the broker and admin-CLI paths mint tokens from
the same plan and had the same flaw; putting the union in the plan fixes all
three and keeps `RestrictedProjects` the single authority on token scope.

## 2026-08-22 — SSH-key reconcile continues past a broken project

**Decision.** `reconcileV2` and `RevokeUserSSHKey` no longer return on the
first project that cannot be written: per-project failures are collected and
returned joined (`errors.Join`) after every project has been attempted.

**Why.** Observed live on obelix (2026-08-22): the `herdr` project's running
machines are hand-made stock-image containers without the tenant's `thies`
user, so its reconcile failed (`script exited 1`) — and the early return then
skipped every project ordered after it. `wordpress` (and others) silently never
received the re-login key: SSH from the newly enrolled Arch client was denied
while the Mac (whose key was cloud-init-baked at machine create) kept working.
#150 had made the login itself survive the failure, but the reconcile still
aborted mid-fleet.

**Alternatives.** Skipping user-missing machines silently (treat like stopped)
was rejected: "your key is not on machine X" is information the user needs —
the warning stays, it just stops taking the rest of the tenant hostage.

## 2026-08-22 — Cache-first `sc connect`

**Decision.** `sc connect` gained a cache-first happy path
(`dialV2MachineViaCache`): when the referenced machine is cached by the
auth-app resource cache as running with an address, AND `~/.ssh/known_hosts`
already pins a host key that matches what the machine's sshd presents (checked
with one `ssh-keyscan` against the machine itself), the session opens from ONE
auth-app request + ONE keyscan — no live Incus API calls at all. Anything
short of that certainty falls back to the unchanged live path (which owns
creation, starting, bare machines, cross-install refs, and authoritative
host-key repair). Client kill switch: `SANDCASTLE_CONNECT_CACHE=0`.

**Why.** Observed live: a repeat `sc c wordpress:dev` spent ~2s on ~10
sequential Incus round trips (~150ms each over the tailnet) re-deriving facts
that had not changed since the last connect. Measured 3.3s → 1.3s end-to-end
for a `-- true` session.

**Key design point.** The keyscan is what keeps the fast path honest: it
doubles as the sshd-reachability probe (a machine the cache wrongly believes
is up fails it) and as the identity check (a REBUILT machine's key mismatches
the pinned one and takes the live path, which re-reads keys authoritatively
via `ensureV2HostKey` and repairs known_hosts). The alternative — trusting the
pinned key blindly and letting ssh hard-fail on mismatch — was rejected: it
would turn every machine rebuild into a scary MITM warning.

**Scope.** `sc fix` deliberately stays live-only (it exists to repair).
`hostkeys` gained an exported `Config.Recorded(host)` lookup for the pinned-
key check.

## 2026-08-25 — Agent skill for driving Sandcastle from the shell (`docs/agents/skills/sandcastle/`)

**Decision.** Added a model-invoked Claude Code skill: `SKILL.md` plus four
disclosed reference files (`operations.md`, `admin.md`, `internals.md`,
`troubleshooting.md`). The tracked copy lives under `docs/agents/skills/`,
beside the other agent-facing docs.

**Why not `.claude/skills/`** — the natural home, and where a working copy also
sits: `.claude/` is gitignored as local Claude Code settings, so a skill there
never versions with the CLI it documents. **Why not `.agents/skills/`** — that
tree is vendored from `mattpocock-skills` and governed by `skills-lock.json`, so
a hand-written repo skill there would fight the sync. `docs/agents/` was already
the home for agent consumer rules (`domain.md`, `issue-tracker.md`,
`triage-labels.md`), which makes `docs/agents/skills/` the one tracked location
that fits. Install it by copying to `~/.claude/skills/` (or the repo's
`.claude/skills/`); those copies are derived, this one is the source.

**What it deliberately does NOT contain.** No exhaustive flag dump. `sc <cmd>
--help` is one command away and is the single source of truth for flags; a copy
in the skill would be a cache that goes stale on every CLI change. The skill
carries only what `--help` cannot: the tenant/project/machine model, the
prefix→`sc2` naming derivation, the JSON payload shapes, and the behavioural
gotchas (connect creates on a missing name; `--yes` is required without a TTY;
`sc c` runs as the login user while `sc incus exec` runs as root; globs must be
quoted and matching nothing is an error; routes are pruned when a machine is
deleted). Alternative considered: generating a full command reference from the
cobra tree at build time — rejected as maintenance the repo does not currently
carry, and it would duplicate `docs/usage.html`.

**Facts verified against live state, not docs.** `docs/topology.md` says the
Incus projects are `sc2-<tenant>`; `naming.DefaultIncusProjectPrefix` is `sc` and
`NormalizeV2Prefix` maps it to `sc2`, and a real install on `obelix` uses prefix
`obelix` throughout (`obelix-thieso2-family`). The skill therefore states the
derivation rule and tells the agent to READ the real names (`sc remote list`,
`sc ls -a`) rather than assume any prefix. Likewise `docs/e2e-sc2.md:481` still
carries a stale NB that `sc c <m> -- sh -c '<script>'` does not work; that was
fixed in #53 (`remoteCommandLine` shell-quotes argv), and the skill documents the
current behaviour — multi-arg is quoted and joined, a lone arg passes through raw
as a shell snippet.

**Also newly written down:** base images are per-project (`sc image save`
publishes into the resolved machine's project; `sc image list`/`rm` read the
ACTIVE project, not literally `default` as the flag help implies), so an image
saved in one project is invisible from another. That is not stated in any doc.

## 2026-08-25 — Doc drift fixed: install prefix, and flat DNS superseded by ADR-0018

Writing the shell skill meant checking the docs against the live CLI and a real
install, which surfaced drift in three places. Fixed at the source rather than
worked around in the skill.

**1. Incus project prefix.** `docs/topology.md` and `docs/glossary.md` stated the
project/bridge names as `sc2-<tenant>` flat, as if `sc2` were fixed. The rule is
`<install-prefix>-<tenant>`, where the prefix comes from `sc-adm install
--prefix` and the built-in default `sc` normalizes to `sc2`
(`naming.NormalizeV2Prefix`). A live install on `obelix` uses prefix `obelix`
throughout (`obelix-thieso2-family`), so an agent deriving a project name from
the tenant handle targets nothing. Both docs now state the derivation, keep
`sc2-` as the *example* default, and say to read the real names from
`sc remote list` / `sc ls -a`.

**2. Flat DNS.** `docs/glossary.md` ("Machine hostname — Flat:
`<machine>.<suffix>`"), `docs/topology.md`, and `docs/usage.html` all still
described ADR-0016 decision 9, which **ADR-0018 superseded** in 2026-07. The
canonical name is `<machine>.<project>.<Tenant DNS Suffix>` for every project
including `default`; exactly one short form exists (the Default Project Short
Hostname), and machines outside the default project have none. The glossary's
entry was the worst of the three — it is the canonical term list the other docs
defer to, so leaving it would have re-seeded the error. It is now split into
three entries (Machine Private Hostname / Default Project Short Hostname /
Tenant DNS Suffix) matching `CONTEXT.md`'s wording, and records that the suffix
defaults to the tenant handle without being required to equal it.

**3. Stale `sc c` NB.** `docs/e2e-sc2.md` step 2b warned that
`sc c <m> -- sh -c '<script>'` does not work. Issue #53 fixed that in 2026-07
(`remoteCommandLine` shell-quotes argv before it reaches ssh) and the doc's own
appendix records the fix — only the inline NB was missed. It now states the
current behaviour (multi-arg quoted and joined; a lone arg passes through raw as
a shell snippet) and explains that the steps below it use `sc incus exec`
because they need root, not because `sc c` cannot run them.

## 2026-08-25 — `sc connect` confirms before it creates a machine

`sc c <name>` provisioned a machine whenever the name did not exist, so a typo
launched a container and waited for it to boot. The creation branch now asks
first: `Machine dev does not exist in project default. Create it? [y/N]`, with
`--yes` to skip the prompt. Starting a *stopped* machine still happens silently
— nothing is provisioned there.

**Where the hook lives.** The obvious implementation — an `InstanceExists` call
in `dialV2Machine` before `EnsureMachineV2` — costs a second round trip and
opens a window between "does not exist" and the create. Instead
`CreateMachineV2Request` grew an optional `ConfirmCreate func() error` that
`EnsureMachineV2` calls in its `StatusNotFound` branch, i.e. on the lookup it
already did, immediately before creating. A domain request struct carrying a
callback is unusual, but it keeps the decision atomic with the branch it guards.
`CreateMachineV2` ignores it — an explicit `sc create` is its own confirmation.

**Only `sc connect` sets it.** `dialV2Machine` is shared with `sc fix`, which
passes `launchV2Options{}` and therefore keeps creating silently: the prompt is
about `sc c` being the everyday command a typo lands in.

**No terminal ⇒ error, not a silent create.** Following the repo's existing
`confirmMissingYes` pattern (`sc delete`, `sc project delete`, …), a
non-interactive caller without `--yes` gets `machine dev does not exist in
project default; pass --yes to create it`. This is a deliberate behaviour break
for scripts that relied on connect-creates: the alternative — prompting on a TTY
but creating silently without one — makes the guarantee depend on where the
command runs, which is worse than one loud error. `docs/e2e-sc2.md` steps whose
connect creates the machine now pass `--yes`.

## 2026-08-25 — `curl | bash` installer (`install.sh`)

`brew install thieso2/tap/sandcastle` is macOS-only and Homebrew installs are
deliberately never self-replaced by `sc update` (the Caskroom desynchronizes and
the next `brew upgrade` silently downgrades). Linux had no install path but
"download the tarball and put it on PATH". `install.sh` at the repo root closes
both: `curl -fsSL …/main/install.sh | bash` installs the release binary into
`~/.local/bin`, and because that directory is the user's own, `sc update`
self-replaces in place on Linux *and* macOS.

**Layout.** The real file is installed as `sandcastle` with `sc` a symlink
beside it — the busybox layout `cmd/sandcastle/main.go` dispatches on. That is
also what makes self-update work unchanged: `update.Apply` resolves the symlink
and replaces the real file, so `sc` survives. `sc-adm`/`sandcastle-admin` are
`--admin`-only, matching the Homebrew cask, which deliberately exposes only the
user CLI.

**Latest release via the redirect, not the API.** `curl -fsSLI` on
`/releases/latest` yields the tag from the redirect target.
`api.github.com` unauthenticated is rate-limited **per IP**, which is exactly
the wrong failure mode for an installer that runs from shared CI addresses.

**Checksums are mandatory.** The script verifies the tarball against the
release's `checksums.txt` (`sha256sum` or `shasum -a 256`) and refuses to
install if neither tool exists, rather than offering a `--skip-checksum`
escape hatch nobody should take on a `curl | bash`.

**It writes nothing outside `--dir`.** No shell profile is edited; when the
directory is not on `PATH` the script prints the line to add, per shell. Staging
as `.sandcastle.new` + `mv` means a failed download never leaves a half-written
binary on `PATH`, and a running `sc` keeps its own inode.

**Help text is embedded, not read from `$0`.** Piped into bash, `$0` is `bash` —
the original `sed -n '3,22p' "$0"` usage would have failed in the one invocation
form the script exists for.

**CI lints it.** `ci.yml` runs `bash -n` + `shellcheck --severity=warning`:
the file is served straight from `main`, so a syntax error there breaks every
new install immediately, with no release to gate it.

## 2026-09-04 — sidecar updates reconcile Incus Reach

An `obelix` tenant sidecar remained healthy on Tailscale but had an empty
Tailscale Serve configuration, so its enrolled Incus remote received immediate
TCP refusals on `:8443`. Sidecar updates previously replaced the binary and
restarted only the TLS signer; they never checked the Incus Reach invariant
established during tenant creation.

**Decision:** every sidecar update now derives the tenant bridge gateway from
the infra project's authoritative `user.sandcastle.v2.cidr` metadata and
idempotently runs the same raw-TCP `tailscale serve` command as provisioning.
The update fails if the metadata is missing/invalid or Serve cannot be
configured, rather than claiming success while the tenant cannot reach Incus.
This repairs drift without restarting `tailscaled` or CoreDNS.

Alternatives considered:

- **Only repair the live sidecars.** This restores access once but leaves every
  tenant vulnerable to the same undetected drift.
- **Install a new systemd unit.** Useful eventual hardening across arbitrary
  Tailscale state loss, but broader than the reported update regression. The
  existing update convergence point provides immediate fleet repair with no
  additional long-running component.

## 2026-09-10 — `sc trust install` detects the Linux trust layout

`localtrust` hardcoded Debian's `/usr/local/share/ca-certificates` +
`update-ca-certificates`. On Arch that command does not exist and p11-kit never
reads that directory, so the install failed after leaving a stray cert there.

**Decision:** pick the layout by which anchors directory exists — Arch
`/etc/ca-certificates/trust-source/anchors` and Fedora/RHEL
`/etc/pki/ca-trust/source/anchors` (both `update-ca-trust`), openSUSE
`/etc/pki/trust/anchors` (`update-ca-certificates`), else Debian. The
`sc tenant` trust-status check uses the same detection.

Alternatives considered:

- **Probe the refresh command on PATH.** Unreliable: `update-ca-certificates`
  lives in `/usr/sbin`, off an unprivileged PATH, so absence proves nothing.
- **`trust anchor --store` (p11-kit CLI).** Arch/Fedora only, and its removal
  semantics differ; the plain file + refresh keeps one code path for all distros.
- **Read `/etc/os-release`.** Derivatives (Manjaro, EndeavourOS, Rocky) would
  need an ID/ID_LIKE table; the anchors directory is the thing that actually
  matters.

## 2026-09-12 — Public DNS Zones slice 1: `meta.DecodeMachine` and the CERT column

Spec `docs/spec/public-dns-zones.md` §1.2 says "`DecodeMachine` (and the
resource-cache instance → `meta.Machine` conversion) fill them from the
instance config". No `DecodeMachine` existed, and there is only ONE instance →
`meta.Machine` conversion: `incusx.MachineFromInstance`, which the live
per-project sweep calls and which is injected into the Auth App as the
ADR-0023 `ResourceCacheMachineRenderer`.

**Decision:** introduce `meta.DecodeMachine(config, machine) Machine` as the
pure step that reads `KeyV2PublicHostname` / `KeyV2CertState` /
`KeyV2CertNotAfter`, and have `MachineFromInstance` funnel through it. Both
paths agree by construction rather than by a second copy of the decode. It
ignores the two certificate keys unless the machine is in zone mode, so a
stray `cert-state` on an unstamped machine can never leak into the listing.

Two small choices the spec left open:

- A zone-mode machine with **no** `cert-state` yet (`sc create` has stamped
  the public hostname, the reconciler has not run) renders `CERT` as
  `pending` — that is what `sc create`'s "certificate pending" promises. An
  unrecognised state string is shown verbatim rather than mapped to a guess.
- `v2MachineNames` gained a fourth parameter, `publicHostname`, instead of
  taking a `meta.Machine`: two callers (`ssh_key_purge.go`, the live connect
  path in `create_v2.go`) only have a name/project pair today and pass `""`
  (private mode) until slice 4 wires the Naming Mode record through. The
  connect-cache path already passes `cached.PublicHostname`.

`incusx` does not yet mirror the new keys as `keyV2…` constants: nothing in
`incusx` writes them in this slice (the stamp is slice 4, the mirror slice 6);
the mirror is added with the first writer.

## 2026-09-12 — Public DNS Zones slice 2: the zone registry

Spec `docs/spec/public-dns-zones.md` §1.3/§1.4, §2.1, §3.1, §9 item 2
(issue #164). Things the spec left to the implementer:

- **Claims are a seam, not a table, in this slice.** `remove` must refuse
  while a Project Domain is claimed under the zone and `list` shows a CLAIMS
  count, but `project_domain_claims` is slice 3's. The registry consumes a
  `ProjectDomainClaimSource` interface (`ClaimsUnderZone(ctx, zone)`), wired
  through `HandlerOptions.ProjectDomainClaims`; the default is
  `noProjectDomainClaims{}`, which truthfully answers "none" because no claim
  can exist yet. **Slice 3 must replace that default** with the SQL-backed
  implementation over `project_domain_claims` (and can keep the option for
  tests). The refusal text and the 409 mapping are already in place and
  tested against a fake source.
- **`encryptSecret`/`decryptSecret` live in `internal/authapp/secrets.go`**
  with `secretEncryptionKey(ctx, db, metaKey)`; the OIDC functions became
  one-line wrappers so `oidc.go` barely changed. The `machine_cert_key`
  constant is declared there too so slice 5 only has to call
  `secretEncryptionKey(ctx, db, machineCertEncryptionKeyKey)`, not add a
  constant beside mine.
- **Admin gate is bearer-only.** The spec says "admin bearer token
  (`requireAdmin`)", but the existing `requireAdmin` is the web-session
  cookie gate for the HTML admin pages. `/api/public-dns-zones` uses a new
  `requireAdminBearer` (= `requireBearerUser` + `SandcastleAdmin`, 401 / 403)
  and does not accept the session cookie — the endpoint exists for the CLI.
- **Cloudflare validation is a small in-package client**, not
  `libdns/cloudflare`: the spec offered both, and pulling certmagic's
  dependency tree into `go.mod` is slice 5's job (parallel branch — avoiding
  a `go.mod` conflict). `CloudflareZoneClient{BaseURL}` does exactly the two
  calls the spec names; a fake server tests it. A success envelope with zero
  (or several) zones has no API message, so the "rejected" text carries a
  Sandcastle-written reason there ("the token cannot see a zone named …").
  A transport failure is **not** a rejection: 502 `cloudflare: …`, nothing
  stored — so an outage can never read as "your token is bad".
- **`sc admin` and `sc-adm` are one tree.** `cmd/sandcastle/main.go` already
  routes `sc admin …` to `ExecuteAdmin("sc admin", …)`, so mounting on
  `NewAdminRootCommand` serves both names; the command is also added to the
  legacy `newAdminCommand` subcommand tree in `admin.go` (unmounted today)
  for parity with `tenant`/`user`/`image`/`tld`. The CLI tests run each verb
  under both `config.name`s and assert it is *not* a top-level user command.
- **`list [-o json]`** in the spec is rendered as `--output json` / `--json`:
  neither root has an `-o` shorthand and adding one globally is out of scope.
- **Token fingerprint** = first 8 hex characters of `sha256(token)`
  (`sha256[:8]` read as characters of the hex digest).
- **Dry-run responses** are 200 with `{zone, cloudflareZoneID, dryRun:true}`
  for all three mutating verbs (the spec only fixes 201/200/204 for the real
  thing); the CLI prints `[dry-run] would have: …`. A dry-run `add`/`set-token`
  still calls Cloudflare — that is the point of it.
- **Zone shape**: `domain.NormalizePublicDNSZone` requires at least two
  labels (a bare TLD is never an admin's zone) on top of `validateDomainLabels`.
- **No `e2e-sc2.md` change**: the spec's §7 e2e phase (Phase 12) is slice 7's
  and nothing user-visible changes for tenants until slice 3.
## 2026-09-12 — Public DNS Zones slice 5: ACME issuer, `acme_storage`, `machine_certificates`

Spec `docs/spec/public-dns-zones.md` §1.3, §3.4, §3.5, §9 item 5 (issue #167).
Decisions the spec left open, and one thing it asks for that certmagic's
public API does not allow:

- **Dependency weight.** `github.com/caddyserver/certmagic v0.25.4` +
  `github.com/libdns/cloudflare v0.2.2` add 15 modules to the graph
  (`go list -m all`: 243 → 258): acmez/v3, libdns, zerossl, miekg/dns,
  zeebo/blake3, klauspost/cpuid, zap + zap/exp + multierr, and x/mod, x/net,
  x/sync, x/tools bumps. `go.uber.org/zap` is a *direct* require because the
  issuer builds certmagic's mandatory `*zap.Logger` (stderr, Info) itself.
  x/crypto moved v0.49 → v0.50 and x/term v0.41 → v0.42 as a side effect.
- **`sqliteStorage` semantics** follow certmagic's `FileStorage` where the
  interface doc is vague: keys are `/`-paths, a key that is a strict prefix
  of others is a directory; `List` non-recursive returns immediate children
  (files and directories), recursive returns every terminal key *and* every
  intermediate directory; `List`/`Stat`/`Load` on an absent key wrap
  `fs.ErrNotExist`; `Delete` of a directory removes the subtree and deleting
  an absent key is not an error. LIKE patterns are escaped so `%`/`_` in a
  key (certmagic keys contain the contact email) match literally.
  `Lock`/`Unlock` are an in-process channel map honouring `ctx` (ADR-0021:
  one Auth App per install, so no cross-process lock is needed); `Unlock` of
  a lock that is not held is an error, as certmagic's contract says.
- **`POST /api/machine-certificates` needs the Project Domain and its zone,
  which live in slice 3's `project_domain_claims`.** Rather than reach into a
  table that does not exist on this branch, the handler takes a
  `ProjectDomainResolver` (`ResolveProjectDomain(ctx, tenant, project) →
  (domain, zone)`) via `HandlerOptions.ProjectDomains` / `HTTPRunner.ProjectDomains`.
  Slice 3 supplies the claims-backed implementation; until then the field is
  nil and the endpoint answers 501, the same pattern as `Projects == nil`.
  A project without a domain answers **404** `{"error":"project \"<p>\" has no
  project domain"}` (the spec names no status).
- **Zone tokens** likewise belong to slice 2's `public_dns_zones`. The
  certmagic issuer takes a `zoneTokenSource func(ctx, zone) (token, error)`;
  the reconciler (slice 6) wires slice 2's decryptor in. `acmeIssuer` is
  therefore *not* instantiated in `Serve` yet — nothing orders in this slice.
- **Secret-at-rest helper.** Spec §1.4 asks to generalize
  `encryptOIDCPrivateKey`/`decryptOIDCPrivateKey` into `encryptSecret`/
  `decryptSecret` with purpose-labelled keys — slice 2 owns that refactor
  (same file, same functions). To merge cleanly this slice reuses the two
  OIDC AES-GCM functions unchanged and adds only the purpose key
  (`purposeEncryptionKey` → `auth_app_meta` key `machine_cert_key`).
  Fold `machineCertEncryptionKey` onto slice 2's helper at merge.
- **Retained row on re-request.** §3.4 says a retained valid certificate
  returns `state: issued` with no order; §4.6 says reuse clears
  `pushed_serial`. The upsert does exactly that (and updates
  tenant/project/machine + `requested_at`). A row that is *not* usable —
  never issued, expired, or issued under a different `directory_url` — is
  reset to a fresh pending row (cert/key/serial/backoff cleared), which is
  how a staging → production switch heals without a separate migration.
- **`TestCA` is pinned to the configured directory.** certmagic's
  `ACMEIssuer.Issue` retries against `TestCA` (defaulting to LE staging when
  `CA` is LE production) on attempt > 0. We never set the attempts context
  key, but pinning `TestCA = CA` makes "staging and production never mix" a
  property of the issuer rather than of the caller.
- **ARI `Replaces` cannot be set through certmagic's public API.** Spec §3.5
  says renewals "set the ARI `Replaces` context value"; the key
  (`ctxKeyARIReplaces`) is unexported and only certmagic's own renew path
  sets it. The `certIssuer.Issue` signature is the spec's; slice 6 either
  accepts ARI-timed renewals *without* `replaces` (still exempt from the
  new-orders and per-registered-domain limits, but counted against the
  5-per-identifier-set duplicate limit) or drops to `acmez.Client.
  ObtainCertificate` with `OrderParameters.Replaces` for renewals. Noted
  here so slice 6 does not rediscover it.
- **The `Public name:` line lives in `runCreateMachineV2`, not in
  `formatCreateMachineV2`.** Slice 4 owns the create output rewrite (it
  replaces the `DNS:` line). This slice adds the certificate request behind
  `zoneModePublicHostname(summary, project, machine)` — `""` for a project
  without a domain, so nothing changes for today's fleet — and prints the
  spec's `Public name: …` line *after* the existing output, text mode only,
  Dev Image machines excluded. Slice 4 should move `formatPublicNameLine`
  into the formatter and drop the `DNS:` line for zone mode.
- **Failure-reason vocabulary** (`acmeFailureReason`) is a substring
  classifier over `last_error` — good enough for the six fixed tokens; the
  raw error is kept verbatim on the row for `sc project status`.

## 2026-09-12 — merge of slice 5 onto slice 2: one purpose-keyed secret helper

Slices 2 and 5 were built in parallel and each added a "32-byte AES key per purpose in `auth_app_meta`" helper (`secretEncryptionKey` in `secrets.go`, `purposeEncryptionKey` in `machine_certificates.go`) under the same `machine_cert_key` meta key. Kept the slice-2 one, since Public DNS Zone tokens already use it, and made `machineCertEncryptionKey` delegate to it; the slice-5 copy and its private base64/rand helpers were deleted. No behavioural difference: same key derivation, same `ON CONFLICT DO NOTHING` first-use race handling.

## 2026-09-12 — Public DNS Zones slice 3: Project Domain claims

Spec `docs/spec/public-dns-zones.md` §1.3, §2.2, §3.2/§3.3, §4.6, §5.1, §9 item 3
(issue #165; decision record on #158). Things the spec left to the implementer:

- **`BEGIN IMMEDIATE` through a dedicated `*sql.Conn`.** `database/sql` cannot
  pick SQLite's transaction mode (`db.BeginTx` always issues a plain `BEGIN`,
  which is deferred), so `ClaimProjectDomain` takes `db.Conn(ctx)`, runs
  `BEGIN IMMEDIATE` / `COMMIT` / `ROLLBACK` by hand, and scans + inserts on
  that connection. Alternatives: a `_txlock=immediate` DSN parameter (would
  make *every* transaction on the pool take the write lock up front, including
  the log sink's) or trusting the PK alone (loses the classified error: a
  descendant/ancestor overlap has no unique constraint to fire). A concurrency
  test (8 goroutines, one domain) pins the "exactly one wins, the rest see a
  `DomainClaimError`" property.
- **Same project, different domain = replace.** The spec fixes the identical
  re-claim as a no-op and says `set-domain` refuses only while zone-mode
  Machines exist, but never says what a second `set-domain` with a *different*
  domain does. `UNIQUE (tenant, project)` forbids two rows, so the claim
  transaction deletes the project's own row and inserts the new one, skipping
  the project's own row in the conflict scan. The previous claim is returned
  so the handler can restore it (`restoreProjectDomainClaim`, best-effort) when
  the Incus write fails — otherwise a failed `set-domain` would leave the
  project domain-less in the DB while Incus still carried the old key.
- **Route conflicts read as install-reserved, whoever owns the route.** §2.2
  lists "an existing Public Route hostname" under the install-reserved text,
  while §3.3's message-selection rule would have sent a same-tenant route to
  the "claimed by project …" wording (which names a *project*, and a route has
  a machine). The install-reserved text wins for every route, own or foreign;
  `DomainClaimError.Class` still distinguishes `route` from `install` for
  callers.
- **`no-zone` before everything else, apex is a validation error.** Validation
  (zone lookup, apex, length) runs *before* the transaction — it only reads
  `public_dns_zones`, and refusing early keeps the write lock short. These are
  `*ProjectDomainError` (400), distinct from `*DomainClaimError` (409). The
  admin wording ("registered zones: …") is selected by `AdminView`, which the
  handler sets from `user.SandcastleAdmin` — the spec ties it to the admin
  *roots*, but no admin root claims domains today, so an admin logging in with
  the user CLI is the closest reading.
- **Malformed domains are 400 with the `domain` package's text.** `_`/`*`
  labels get an explicit "labels may not start with" reason (the spec names
  them; `validateDomainLabels` would have rejected them with the generic
  "invalid project domain"). The CLI runs the same `NormalizeProjectDomain`
  before calling, so the obviously malformed never leave the client.
- **`POST /api/projects` with a domain for an already-claimed project is a
  conflict, not a no-op.** The project cannot exist yet (create), so a row
  for it is an orphan the GC would drop; the "already claimed" no-op is
  `set-domain`'s.
- **`--dry-run` on `sc project create`.** The spec asks for `--dry-run` on
  every mutating verb; `create` never had one. It now validates the name and
  (with `--domain`) the claim server-side in a rolled-back transaction, and
  prints `[dry-run] would have: …`; on the broker path it prints the same
  without contacting the broker.
- **`set-domain`/`unset-domain` without a login print the create flag's
  text**, `--domain is not available on this install`, rather than a third
  sentence: the cause is identical (no Auth App to claim through) and the
  spec fixed only that wording.
- **`sc project status` reads the zone from the Auth App.** The zone is stored
  on the claim row, not on Incus (§1.1 has no key for it), so `status` calls a
  new `GET /api/projects/{name}/domain` best-effort when logged in and omits
  `(zone …)` otherwise — the status never fails on it. The per-machine table
  is rendered from the slice-1 `meta.Machine` fields; `DETAIL` carries the
  `failed:<reason>` token (the raw `last_error` lives in slice 5's table and
  is not surfaced yet).
- **Private profiles are byte-identical, no `MODE=private`.** §5.1 says
  private projects "add `MODE=private` (explicit …)", the issue says "private
  projects unchanged, golden-tested". The issue wins: `V2ProfileUserData` with
  an empty domain renders exactly what `V2DefaultProfileUserData` always did
  (a test diffs the two), and every consumer defaults an absent `MODE` to
  private — which §5.1 itself requires for pre-feature Machines anyway.
  `V2DefaultProfileUserData` is kept as a wrapper so no caller changed.
- **`--bare` and dev user-data untouched.** Both are rendered by `sc create`
  (slice 4's surface) from the profile's `fqdn:` line, which a zone project
  now renders as `{{ v1.local_hostname }}.<domain>` — so a bare machine in a
  zone project already boots with the right name; the `MODE=zone` line in its
  own `machine.env` comes with slice 4's create path.
- **The Incus seam is one interface, `TenantProjectDomainManager`**, next to
  the existing `TenantProjectCreator` rather than widening it: the broker
  (`projectbroker.Handler`) shares `CreateTenantProject`, and a four-method
  interface would have forced every broker fake to grow. `ProjectBrokerCreator`
  implements both; `ProjectDomains` on `HTTPRunner`/`HandlerOptions` is wired
  in `admin_root.go` with a `TenantDeleter` (new `NewTenantDeleterForServer`
  for the socket path). A missing app project wraps
  `projectbroker.ErrProjectNotFound` → 404.
- **`DELETE /api/projects/{name}` deletes unconditionally.** The "project must
  be empty" rule stays client-side (`tenant.PlanDeleteProject`), as it always
  was for the direct path; the endpoint mirrors `sc-adm project delete`
  (machines, volumes, profiles go). The `default` project is refused. Order:
  claim row → `onProjectDomainReleased` → Incus; a failure after the release
  is left to the GC, never rolled back.
- **`onProjectDomainReleased` is the slice-6 hook.** A no-op today, called on
  `DELETE …/domain`, `DELETE /api/projects/{name}` and from the GC with the
  released claim; slice 6 fills in "delete every A record under the domain,
  drop its `machine_certificates` rows".
- **GC rides the existing 5-minute suffix loop**, reusing its tenant listing
  (`tenant.ListForPrefix` summaries carry `Projects[].Domain` since slice 1);
  the empty-live-set guard is the same. "Incus key without row" is logged
  once per project+domain (in-loop `map`, reset on restart), never claimed.
  `unset-domain` on such a project clears the key even with no row, so a
  tenant can repair it without admin help.
- **`sc project delete` prefers the endpoint and falls back on 501 only.** Any
  other error from the Auth App (409 machines, network) is surfaced, not
  retried against Incus — a restricted certificate would only produce a worse
  error. The old "no project-delete endpoint yet" hint is gone.
- **`sqlProjectDomainClaims` replaces slice 2's stub as the default.**
  `HandlerOptions.ProjectDomainClaims` stays for tests; `noProjectDomainClaims`
  stays only as the nil-safe fallback inside `checkPublicDNSZoneRemovable`.
  The FK `zone REFERENCES public_dns_zones(zone)` is live (`foreign_keys(1)`
  is in the DSN), so a zone with claims cannot be deleted at the DB level
  either.
- **e2e:** Phase 12 is added with 12a/12b (this slice's user-visible surface)
  and a note that 12c–12f land with slices 4–7; the `unset-domain` step
  records that it is *allowed* until slice 4 stamps the Naming Mode.

## 2026-09-12 — merge of slice 3 onto slices 2+5: two seams called `ProjectDomains`

Slice 5 (built before slice 3 existed) added `HTTPRunner.ProjectDomains` typed `ProjectDomainResolver` (the "which domain does this project have" lookup for `POST /api/machine-certificates`, left nil → 501). Slice 3 added a same-named field typed `TenantProjectDomainManager` (the Incus seam that writes `KeyV2Domain` and re-renders the profile). Textually the merge was clean; semantically it was a redeclaration. Resolution: the resolver seam is renamed `ProjectDomainResolver` / `projectDomainResolver`, and it now defaults to `sqlProjectDomainClaims` (which gained `ResolveProjectDomain` over `GetProjectDomainClaim`) whenever the handler has a database — so the 501 "no claims yet" path is gone and the machine-certificates endpoint answers 404 for a project without a domain. The test fake was renamed `fakeProjectDomainResolver` to avoid clashing with slice 3's `fakeProjectDomains`.

## 2026-09-12 — Public DNS Zones slice 4: the machine contract

Spec `docs/spec/public-dns-zones.md` §2.3, §5, §9 item 4 (issue #166; decision
record on #159). Things the spec left to the implementer:

- **The Caddyfile heredoc is its own constant** (`caddyfileHeredoc`), spliced
  into `caddyIngressSetupScript`, so a test can pin it byte for byte against
  the pre-slice-4 text. The script itself necessarily changes (the payload
  version bumps once, as any payload edit does); what "private mode unchanged"
  means here is the *behaviour* — leaf fetch, Caddyfile, override.conf, marker
  aside, `systemctl restart` — and `TestCaddySetupPrivateMode` runs the real
  script under bash with stubbed tools against a throwaway root to prove it.
  The absolute paths are rebased textually for that run; the drop-in content
  is compared in rebased form for the same reason.
- **The private marker is written too.** §5.3 only needs the marker in zone
  mode, but §5.2's script writes it unconditionally and it costs nothing; a
  `MODE=private` marker is "no marker" for the push gate
  (`CaddySetupMarker.ReadyFor`) and is a useful diagnostic on the machine.
  `tenant.ParseCaddySetupMarker` / `ReadyFor` are provided for slice 6 so the
  gate semantics (§4.4 step 1: parse failure, missing MODE, MODE=private, FQDN
  mismatch → no marker) live next to the writer.
- **`--bare` takes its MODE from the profile, not from the request.** The
  bare document already reads the FQDN domain and signer back off the
  project's default profile so a bare machine can never disagree with its
  siblings; the `MODE=zone` line follows the same rule
  (`v2ProfileModePattern` → `V2BareUserDataForMode`). The Naming Mode *stamp*
  comes from the CLI's request (the tenant summary's `Domain`), as §2.3 says.
  Both derive from `KeyV2Domain` and are written by the same Auth App
  transaction, so they agree except across a stale profile — which
  `set-domain` re-rendering already rules out. Dev Image machines run no
  caddy-setup at all, so their cloud-init is untouched: public name stamp, no
  marker, no certificate.
- **The stamp is read back, not recomputed.** `CreateMachineV2Result` /
  `EnsureMachineV2Result` / `V2MachineRef` all carry `PublicHostname` from the
  instance (or from the request when the call created it), and the create
  output, the certificate request and `sc connect`'s `HostKeyAlias` use that.
  `zoneModePublicHostname` is now called exactly once per create (and once
  in `dialV2Machine`, only for the ensure-creates case). `meta.KeyV2PublicHostname`
  is used directly in `incusx`, like `meta.KeyV2Bare` — the `keyV2…` mirror
  block is for infra-project keys.
- **`ListMachinesV2` switched from `GetInstanceNames` to `GetInstances`** so
  the purge sees each machine's Naming Mode record in one call per project
  instead of one `GetInstance` per machine; `TenantResourceServer` gained
  `GetInstances` (the two fakes embed the interface, so nothing else moved).
- **Zone-mode `IP:` line stands alone.** Private mode prints
  `IP: <ip>   DNS: … (auto-registers within seconds)` on one line; the zone
  `Public name:` line is long and carries the certificate detail, so it gets
  its own line under `IP: <ip>`. The still-booting and `--dry-run` forms
  already had the name on its own line. A zone machine in the default project
  shows no `(also: <m>.<suffix>)` alias — it has exactly one name.
- **The certificate request runs in every output mode**, not text only as
  slice 5 had it: creating the `machine_certificates` row is part of the
  create, not of the rendering. `--json` carries `publicHostname`; the
  outcome text is text-mode only. `--dry-run` never calls the Auth App and
  prints the default pending text whatever a caller hands the formatter.
- **e2e:** Phase 12c is written for what slice 4 can show (stamp, output,
  marker, drop-in, enabled-inactive Caddy, connect keyed by the public name);
  the A-record / certificate timing criteria and 12d–12f stay for slices 6–7.

## 2026-09-12 — Public DNS Zones slice 6: the zone reconciler

Spec `docs/spec/public-dns-zones.md` §4 (+ §1.5, §3.5, §4.6), §9 item 6
(issue #168; decision records on #157 and #159). Things the spec left to the
implementer, and one thing it asks for that the library does not allow:

- **ARI renewals go through `certmagic.ACMEIssuer.Issue` without the ACME
  `replaces` field.** Slice 5 found the `Replaces` context key
  (`ctxKeyARIReplaces`) unexported; the alternative was dropping to
  `acmez.Client.ObtainCertificate` with `OrderParameters.Replaces` for
  renewals. Rejected: it would mean re-implementing certmagic's account
  lookup/registration over `acme_storage` (the account is certmagic's,
  loaded by an unexported path), the DNS-01 solver wiring and the
  propagation wait — a second issuance path that only runs at renewal time,
  i.e. the least-exercised code in the system. It would also not have worked
  as a certmagic feature anyway: certmagic only sends `replaces` when
  `!usingTestCA`, and slice 5 pins `TestCA = CA`, so even certmagic's own
  renew path suppresses it under our configuration. Cost of the decision:
  ARI-timed renewals are *not* exempt from Let's Encrypt's
  5-per-identifier-set/week duplicate limit (the exemption requires
  `replaces`); a Machine renews once per ~60 days, so the limit is
  unreachable through renewals — the budget consumer is delete/recreate,
  which the retained row (§4.6) already defuses. `RenewalInfo` is still used
  for *timing*, so the "renew when the CA asks" property holds. If certmagic
  exports the key (or gains a `Replaces` field on `Issue`), the change is one
  `context.WithValue` in `acmeIssuer.Issue` plus a "renewal of" parameter on
  `certIssuer.Issue`; noted in `docs/usage.html`.
- **Package split: logic in `authapp`, Incus in `incusx`.** `incusx` imports
  `authapp`, not the reverse, so `zone_reconcile.go` in `authapp` holds the
  whole pass behind a four-method `ZoneMachineServer` seam (`ListZoneMachines`,
  `StampInstanceConfig`, `ReadInstanceFile`, `PushMachineCertificate`) that
  `incusx.ZoneMachineServer` implements over the mounted socket; the DNS side
  is a `zoneDNSProvider` (three libdns interfaces) built by a package-level
  factory so tests never touch Cloudflare (`init()` in the test file replaces
  the factory for the whole package — the release hook runs in existing
  handler tests too). The `V2DNSReconciler` in `dns_v2.go` is untouched: the
  spec's "private stage skips zone-mode Machines" is already true because a
  zone Machine's private name is never rendered (slice 4), and threading the
  zone stage into that function would have coupled two reconcilers with
  different failure modes.
- **One loop, not two.** The zone stage runs inside `runDNSReconcileLoop`
  after `DNSReconcile`, sharing the 30 s ticker and the lifecycle-event
  trigger (that is what makes `instance-started` push within seconds). A
  finished order — success *or* failure — kicks the same trigger, so the
  push (or the `failed:` mirror) never waits for the ticker; the loop now
  also starts when only the zone stage is configured.
- **Provider per pass, not per zone lifetime.** `libdns/cloudflare` caches
  the zone id inside the `Provider`; building a fresh one per pass and zone
  (one `GetRecords` each) means a rotated token (`set-token`) is live on the
  next pass with no cache invalidation hook. The TXT sweep runs inside the
  order goroutine with its own zone read: orders outlive the pass, and a
  stale snapshot could miss a challenge record certmagic wrote meanwhile.
- **Records under a claimed domain are the reconciler's, nothing else is.**
  Stale-record deletion is scoped to A records whose relative name ends in
  `.<claimed domain>` and whose Machine label is not live; anything else in
  the zone (the admin's own `www`, other tenants' domains) is never read as
  "stale". A stopped Machine has no lease, so its records are *kept*, not
  re-set; a deleted Machine's two records go on the next pass.
- **Unclaimed `KeyV2Domain` → nothing stamped.** §1.1 says the reconciler
  stamps `private` on unstamped Machines in a project *without* a domain;
  §4.6 says a project with the key but no claim is "treated as private for
  DNS". Stamping is irreversible, and the tenant can still repair such a
  project with `set-domain`, so its unstamped Machines are left unstamped
  (logged once per project); a claim and key that disagree are handled the
  same way.
- **Drift = leaf fingerprint OR file content.** §4.5 compares the leaf
  sha256; e2e 12e appends junk to `cert.pem` and expects a re-push, which a
  leaf comparison alone would not notice (the first PEM block still parses).
  Both are compared; a missing file on a *running* Machine is drift too
  (`ErrInstanceFileNotFound`, the incusx seam maps Incus 404 onto it), which
  is how a Freeform Machine rebuilt under a retained row gets its
  certificate without an API call that clears `pushed_serial`. Any other
  read error is "unreachable": skipped, retried next pass.
- **`systemctl start caddy` only on the first push.** The push script is the
  spec's `mv && mv && (reload || restart)`; `restart` already starts an
  inactive unit, but the issue asks for an explicit `start` on the first
  push, so it is appended when the row had no `pushed_serial` *before* the
  pass (a drift re-push clears the serial and must not read as first).
- **Mirror `cert-not-after` for `issued` keeps the previous value.** A renewed
  but not yet pushed row is `issued` while the old certificate still serves;
  clearing the expiry would flicker `sc project status`. The key is written
  from the row only when `pushed_serial == serial`.
- **GC in the fast pass, not the 5-minute loop.** Row GC is one `SELECT` over
  a small table and needs the live fleet, which the pass already has; it runs
  every pass under the same "empty fleet is never trusted" guard. Rules:
  a row whose Machine is gone is dropped when it holds nothing worth
  retaining (never issued, expired, or issued under another directory);
  a valid retained row waits for its Machine. `onProjectDomainReleased`
  (slice 3's hook) now returns an error: it drops every row under the domain
  (`hostname LIKE '%.<domain>'`, escaped) *before* deleting the A and
  `_acme-challenge` records, so a Cloudflare outage cannot leave
  certificates behind a released claim; callers log the error.
- **Rate limit → last backoff step by setting `attempts = 5`**, so the
  ladder index lands on 6 h without a second field; the fixed-vocabulary
  classifier (`acmeFailureReason`) decides "rate-limited" from the raw error.
- **Not done here:** `sc project status` DETAIL still shows only the reason
  token (the raw `last_error` is on the row, surfaced via the skill's
  `sqlite3` recipe); the e2e phase's `sqlite3` steps assume the client is
  present on the appliance image. Slice 7 owns the e2e run and the
  `make e2e-safe` gate wiring for `SANDCASTLE_E2E_CLOUDFLARE_TOKEN`.

## 2026-09-12 — Public DNS Zones slice 7: e2e Phase 12 + docs sweep

Spec `docs/spec/public-dns-zones.md` §7, §8, §9 item 7 (issue #169). No product
code changed; the decisions are about how the phase is wired and run:

- **Phase 12 is a shell driver, and the Go e2e test runs it.** The other
  phases of `docs/e2e-sc2.md` are a manual runbook; the two hermetic variants
  that exist (`scripts/e2e-route.sh`, `scripts/e2e-local-vm.sh`) are bash
  over the CLIs. Phase 12 follows that shape: `scripts/e2e-pdz.sh` drives
  `sc`/`sc admin` (one fat binary — `sc admin …` *is* the `sc-adm` tree, so the
  script needs a single binary path) and asserts with `dig`, `openssl s_client`
  and `curl --resolve`. `TestPublicDNSZonePhase12E2E` in `internal/e2e` is the
  harness-side gate: it `t.Skip`s without `SANDCASTLE_E2E=1` or without the two
  zone variables, builds the binary, and execs the script. Alternative
  considered: reimplementing the phase in Go against the Auth App HTTP API and
  the Incus client — rejected, it would test the API rather than the CLI the
  operator runs, and it could not do the tailnet-side `openssl`/`curl` checks
  any better than bash.
- **Three-way gate, never a failure.** `scripts/e2e.sh pdz` sources
  `.env.sc2` (where the other e2e secrets already live), then skips (exit 0)
  when the token/zone are absent *and also* when they are present but
  `SANDCASTLE_E2E` is not `1`. The issue asked only for the first skip; the
  second keeps `make e2e-safe` from turning destructive (real Cloudflare
  records, a real staging order) the moment the operator drops the credentials
  into `.env.sc2`. The live run is therefore an explicit opt-in:
  `SANDCASTLE_E2E=1 scripts/e2e.sh pdz` (or `SANDCASTLE_E2E=1 make e2e-safe`).
- **The script covers the issue's core path; 12e stays manual.** Registry →
  claim → create → A records → CERT ok → `openssl` (both SANs, STAGING issuer)
  → wildcard vhost → unset/remove refusals → delete (records gone) → project
  delete (claim released) → zone removed. The marker-gate, stopped-through-a-
  push and drift checks of 12e need `sqlite3` inside the appliance (the stock
  image has none) and wall-clock waits on the reconciler; they are written up
  as manual steps marked **(DB)** rather than automated with an `apt-get`
  inside the auth-app. Refusal checks use `--dry-run` so a failed assertion
  never leaves a stray project behind; a zone that is already registered is
  reused and left in place (so a run against a shared test install does not
  unregister someone's zone).
- **Docs fixed on the way.** The earlier slices' examples used
  `sc create web --project zp`; `sc create` takes a machine reference
  (`zp:web`) and has no `--project` flag — corrected in `docs/e2e-sc2.md` and
  `docs/usage.html`. The skill's troubleshooting table claimed `DETAIL` shows
  the raw `last_error`; it shows the reason token only (`project.go`), so the
  raw error is documented as auth-app-log / `sqlite3` only. Phase 12 fragments
  12a–12f from slices 3, 4 and 6 were merged into one section with a single
  gate paragraph, the "until slice N" wording removed, and a pointer added to
  Phase 8c (private-mode contract) and to the Phase 1 `--acme-directory` note.
- **`docs/glossary.md` gained a Public DNS Zones section** (the seven
  `CONTEXT.md` terms plus "zone reconciler" and "ACME directory", phrased for
  the CLI reader); `CONTEXT.md` itself was already complete.
- **ADR-0027 flipped to accepted**; the spec's §10 list is kept verbatim with
  resolved markers pointing here (route-conflict wording, `project status`
  layout, ARI without `replaces`, no `MODE=private` line).
- **The installed skill copy** (`~/.claude/skills/sandcastle/`) was refreshed
  from the tracked `docs/agents/skills/sandcastle/`; the tracked directory
  remains the source.

## 2026-09-13 — Public DNS Zones: a zone may live inside its Cloudflare zone

The first live run of Phase 12 (`docs/e2e-runs/2026-09-13-phase12-public-dns-zones.md`,
finding F1) failed at 12a: `sc admin public-dns-zone add e2e.sc.tc42.uk --token …`
printed `Cloudflare rejected the token for zone e2e.sc.tc42.uk: the token cannot
see a zone named e2e.sc.tc42.uk`. The Cloudflare zone is `tc42.uk`;
`e2e.sc.tc42.uk` is a name inside it. The design (map #155, the #160 grilling,
the tracked `.env.e2e.sample`) always allowed that — Cloudflare tokens are
zone-scoped, records for `<m>.<pd>` are simply written into the containing
zone under full names — but slice 2 resolved the zone id with an exact
`GET /zones?name=<zone>`, and slice 6 handed the Public DNS Zone name itself to
libdns, which would have failed the same way one step later.

- **Resolution is "longest containing zone the token can see."**
  `CloudflareZoneClient` now lists the token's zones (`GET /zones?per_page=50`,
  following `result_info.total_pages`, capped at 100 pages) and picks the name
  equal to the Public DNS Zone or its parent on a label boundary, longest
  first, so a token that sees both `tc42.uk` and `sc.tc42.uk` lands on
  `sc.tc42.uk`. Alternative considered: walking the name label by label with
  `GET /zones?name=<candidate>` (one call per label, no paging) — rejected
  because it costs up to N calls for a deep name and the listing is what Zone
  Read grants anyway; a Sandcastle token sees a handful of zones. Two zones
  with the same longest name is still an ambiguity error, as before. The
  rejection text became `the token cannot see a zone containing <zone> (…)`.
- **The Cloudflare zone name is persisted next to its id** (`cloudflare_zone`,
  a guarded `ALTER TABLE … ADD COLUMN` via `ensureColumn`, so live and test
  databases migrate in place). Rows from before the column carry `''` and are
  read as "the zone itself" (`cloudflareZoneOrSelf`) — they were registered by
  exact name, so that is exactly right; no backfill needed. `set-token`
  re-resolves, since a rotated token may be scoped to a closer zone. The name
  is exposed as `cloudflareZone` in the API/JSON, as `CLOUDFLARE-ZONE` in
  `list`, and `add`/`set-token` print `(inside Cloudflare zone tc42.uk, id …)`
  when it differs from the zone. Alternative: storing only the id and asking
  Cloudflare for the name at reconcile time — rejected, the reconciler must
  not depend on a Zone Read call per pass, and the name is what libdns wants.
- **libdns is always addressed to the Cloudflare zone.** `PublicDNSZoneCredentials`
  returns (cloudflare zone, token); the reconciler's per-pass provider cache
  carries the libdns zone with the provider, and `reconcileZoneRecords`, the
  `_acme-challenge` sweep and `releaseProjectDomainRecords` all use it, with
  relative names via `libdns.RelativeName(<fqdn>, <cloudflare zone>)`
  (`web.baum.e2e.sc` in `tc42.uk.`). The claimed-domain suffix filter and
  `machineRelativeName` are therefore relative to the Cloudflare zone too.
  The certmagic issuer needed no change: it is keyed by the Public DNS Zone
  only to find the token, and its DNS-01 solver locates the zone by SOA.
- **Tests** cover zone == Cloudflare zone, two labels deep, no containing
  zone (sibling and non-label-boundary `otherhase.de`), longest match in both
  listing orders, paging across two pages, the migration of an old-schema DB,
  and a reconciler run with a subdomain zone (records, sweep, release all
  relative to `tc42.uk.`, nothing written under `e2e.sc.tc42.uk.`).

## 2026-09-13 — Public DNS Zones: GC records after the last Machine in a zone is deleted

The live e2e run showed `sc delete zp-p12c:web` (the tenant's only Machine)
leaving both A records in Cloudflare for 180 s; only the project-delete hook
removed them. Two causes in `zoneReconciler.Reconcile`, both fixed:

- **Zones are reconciled by claim, not by live target.** `byZone` was built
  from targets only, so a zone whose claims had no live Machine was never
  passed to `reconcileZoneRecords` and stale records under its claimed domains
  were never GC'd. Now the zone set is the union of zones-with-targets and
  zones-of-claims, with an empty target list where nothing is live. A
  registered zone with no claims is still skipped — nothing to converge, and
  no Cloudflare read for it. Alternative: reconciling every registered zone
  — rejected, it costs a read per idle zone per pass for nothing.
- **The empty-fleet early return is gone.** It was copied from the claim GC
  ("an empty live set is never trusted"), but `ListZoneMachines` returns an
  error on a listing failure, so an empty slice is a real state — and after
  the last Machine is deleted it is the *expected* state. Records are
  self-healing (a wrong deletion is re-created by the next pass within 30 s)
  and certificate rows are retained on Machine deletion by design, so the
  record and certificate passes run on an empty fleet. The one step that is
  destructive and not self-healing is `gcMachineCertificates` (dropping
  never-issued / expired / foreign-directory rows): a row dropped on a wrong
  empty listing takes its persisted backoff and ARI state with it, and a
  re-created row would order at once. That step alone keeps the guard
  (`len(machines) > 0`), with a comment. Alternatives: dropping the guard
  entirely (rejected for the backoff-loss reason) or keeping the whole early
  return and deleting records from the machine-delete path instead
  (rejected — the reconciler is the single owner of records per §4.6, and
  out-of-band `incus delete` would still leak).
- Tests: last Machine of one zone deleted while another zone's Machine
  remains (base + wildcard deleted, other zone untouched, deletion logged);
  fleet empty after the last Machine (records deleted, `retained` row kept);
  registered zone without claims (no provider, no read). The existing GC
  test's empty-fleet step now documents that only the row GC is skipped.
- The commit also carries the harness fix from the same run: the bad-token
  probe registers a *sibling* of the zone (`bad-<id>.<parent>`), because a
  name under the zone is refused by the nesting check before the token is
  ever tried.

## 2026-09-13 — Machine Public Hostnames slice 1 (#173): ADR-0028, reservations, API, `sc create --hostname` / `sc hostname`

Decisions of #172 are the ADR's; what the slice ticket left to the implementer:

- **The reservation transaction is shared, not duplicated.** `ClaimProjectDomain`'s
  hand-rolled `BEGIN IMMEDIATE` block became `withReservationLock` +
  `loadInstallReservations` (claims, hostnames, route hostnames read on the locked
  connection); `ClaimMachineHostname` and `ClaimProjectDomain` both run their scan +
  INSERT inside it. `scanProjectDomainConflicts` now takes the snapshot struct and
  gained the hostname half; the domain-vs-domain part is `scanProjectDomainClaimConflicts`.
  `DomainClaimError` grew `Machine` and the class `hostname`; the cross-tenant text is
  unchanged (flat), the same-tenant text names `"<p>:<m>"`.
- **The derived name is not a `machine_hostnames` row.** It is implied by the project's
  domain claim (whole subtree), so the table holds explicit names only; every reader
  that needs the full set (`PublicHostnamesOfMachine`, the GET view) renders derived +
  explicit. Alternative — a row per derived name, kept in sync by the reconciler — was
  rejected: two rows reserving one name would need a special case in every scan.
- **A hostname inside the caller's own Project Domain is refused.** The issue said
  "any Project Domain it is inside or that is inside it"; no own-project exemption was
  asked for and `api.baum.hase.de` is the future machine `api`'s derived name, so the
  scan treats the own domain like any other (same-tenant text names the project).
- **The zone apex itself is refused; apex-level is allowed.** Decision 2 allows
  `web12.tc42.uk`; `tc42.uk` would reserve the whole zone, which is what registering
  the zone is for. Text mirrors the Project Domain apex rule ("use at least one label
  below <zone>").
- **Routes: symmetric one-level semantics.** A hostname conflicts with a route equal
  to or inside it (wildcard stripped); a route is refused equal to or inside a
  hostname; a route *above* a hostname (`*.y` vs `deep.x.y`) is allowed in both
  directions, exactly as with Project Domains (slice 3 of ADR-0027 chose this; a
  one-level wildcard does not cover a deeper name).
- **`beforeCreate` on POST instead of swallowing 404.** `sc create --hostname` claims
  before the instance exists, so the Auth App cannot stamp the key; rather than
  ignoring "machine not found" (which would let a typo in `sc hostname add` hold a
  name), the create flow says so explicitly and the create call stamps the set. A
  `sc hostname add` on a missing machine is 404 and the reservation is released again
  (compensation like `CreateTenantProjectWithDomain`). `authapp.ErrMachineNotFound` is
  wrapped by the Incus seam for that.
- **The Incus seam is `TenantProjectDomainManager` widened by one method**
  (`SetMachinePublicHostnames`), not a new interface: it is the same wiring
  (`ProjectBrokerCreator`) and the one test fake grows one method. It writes via the
  existing `stampInstanceConfig` (an empty list deletes the key).
- **Writers write only the list; the reconciler is touched minimally.** `sc create`
  stamps `KeyV2PublicHostnames` and never the single key (an empty set stamps nothing —
  the `private` pin has no purpose without Naming Mode). The zone reconciler reads the
  list when present (derived target = the name under the claim; explicit names ignored
  until slice 3) and never stamps the legacy key on such a machine; the legacy
  first-sight stamp survives only for machines with neither key. Explicit hostnames are
  added to the reconciler's `liveHostnames` so their pending `machine_certificates` rows
  are not GC'd 30 s after `sc hostname add`.
- **`ListZoneModeMachines` now means "machines with a derived name under the current
  domain"** (reads both keys, filters by suffix; a project without a domain returns
  none). This keeps the transitional `set-domain`/`unset-domain` refusal honest while
  letting a private project with explicit hostnames claim a domain later — the issue
  says explicit names in a private project are allowed, and blocking `set-domain` on
  them would contradict that. The refusal itself goes with slice 3.
- **Output policy until slice 2.** A project with a domain prints only `Public name:`
  lines (as ADR-0027 did — its machine contract still serves only the derived name);
  a project without a domain keeps its `DNS:` line and adds the `Public name:` lines
  (its private name *is* served). `formatCreateMachineV2` takes a per-name outcome map;
  the golden test summary now carries `Projects[].Domain` because the formatter reads
  the derived name off the summary rather than off a single field.
- **`meta.Machine.PublicNames()`** tolerates a payload with only the legacy single
  field (an older Auth App's resource cache still serves `publicHostname`), so `sc ls`
  against a not-yet-updated appliance keeps rendering. `NamingMode()` stays one release
  as a shim over `HasPublicHostname()`.
- **`--hostname`/`--fqdn` are one `appendStringFlag`.** Two `StringArrayVar`s on one
  slice do not merge: pflag's array value replaces the slice on each flag's first `Set`,
  so `--hostname a --fqdn b` would have kept only `b`.
- **`sc hostname list` needs no seam and answers without the Incus seam**; mutations are
  501 without it (`machine hostnames are not available on this deployment`).
- **GC listing.** The slow loop's hostname GC uses `HTTPRunner.Machines` (the
  `machine.Store` the handler already has) for the live machine set; a listing error
  degrades to project-level pruning only, never to "no machines".
- **e2e 12g is a placeholder**, written for what slice 1 can show; slice 4 automates it.

## 2026-09-13 — Machine Public Hostnames slice 2 (#174): the per-name machine contract

Issue #174 (decisions on #172; ADR-0028; spec `docs/spec/machine-hostnames.md` §5). What the
ticket left to the implementer:

- **How the explicit names reach `machine.env` at first boot.** The profile is per project; an
  explicit `--hostname` is per instance, and cloud-init runs the *profile's* user-data. Three
  options: (a) an instance-level `cloud-init.user-data` override carrying the set (would make every
  `--hostname` machine diverge from its profile forever, like `--bare` does on purpose), (b) let
  `caddy-setup` query the guest socket (`/dev/incus/sock`, `GET /1.0/config/user.…`) at boot, (c) a
  jinja read of the instance key through cloud-init's datasource. Chose (c):
  `PUBLIC_HOSTNAMES={{ v1.local_hostname }}.<pd>,{{ ds.config['user.sandcastle.v2.public-hostnames']
  | default('') if ds is defined and ds.config is defined else '' }}` — the LXD/Incus datasource
  exposes every `user.*` instance key under `ds.config`, and the guard makes any other datasource
  render `''` instead of a `CI_MISSING_JINJA_VAR` token or a template error. The derived name is
  rendered **explicitly** from the Project Domain as well, so a project with a domain is correct even
  if the datasource read yields nothing; `caddy-setup` normalizes and deduplicates. The seed is read
  **once** (only when `/etc/sandcastle/hostnames` does not exist); the reconciler owns the file after
  that (slice 3 pushes it whole). `PUBLIC_HOSTNAMES` rather than the spec's `FQDNS` — the line
  carries public names only, never the private FQDN. The read is unverified on a live image in this
  slice; e2e 12c/12g record what the image gives.
- **The private identity is unconditional.** `fqdn:` and `FQDN=` are `<m>.<p>.<suffix>` for every
  project; `V2ProfileUserData`'s `projectDomain` now only shapes the seed line. The profile of a
  private project changes too (it gains the seed line, reading the instance record) because a
  machine in a private project can carry explicit hostnames — so "private profile byte-identical to
  pre-feature" (ADR-0027's promise) is gone on purpose; the *behaviour* of a private-only machine is
  pinned instead by `TestCaddySetupPrivateOnly` (leaf fetch, private block, enable + restart, same
  calls as before) and a `machine.env` without the line at all is tested to work.
- **One `site_block` function, not a heredoc constant.** The per-name render loops over a bash
  function; the golden test pins the rendered block text (handlers byte-identical to the ADR-0027
  Caddyfile) and asserts exactly one `cat <<EOF` in the script, so every name goes through the same
  block.
- **Render to `.new`, `caddy validate`, then `mv`.** Not in the ticket. A refresh execed by the
  reconciler must never replace a working Caddyfile with a broken one; a failed validate exits
  nonzero, keeps the old Caddyfile *and* the old marker (the marker asserts what is in place).
- **Both files must be non-empty (`-s`)**, not merely exist: a zero-byte `cert.pem` would fail
  validation and take every name down with it.
- **Marker gate = "per-name marker present".** `ReadyFor(host)` no longer compares names: a name
  cannot be in the marker before its certificate is pushed, and the push's `--refresh` renders it.
  What the gate now guards is "this machine runs the per-name contract" (`PRIVATE=` present), i.e.
  it has per-name directories and `--refresh`. `Serves(host)` is the per-name question for
  diagnostics and slice 3. **Legacy `MODE=` markers parse but never clear the gate** — the old push
  path (private-leaf paths + `systemctl reload`) is gone with the drop-in, and pushing into a
  machine running the old script would overwrite its only certificate. Those machines (ADR-0027
  zone mode, or a stale payload) are recreated after a payload sync, not migrated in place; the
  docs say so.
- **The push moved to the per-host directory in this slice**, though the ticket said slice 3
  rewires the reconciler. Leaving it would have had the interim reconciler overwrite the private
  leaf with the derived name's Let's Encrypt certificate and never render the public block. Minimal
  change: `PushMachineCertificate` gains `hostname` and loses `start` (the refresh starts Caddy when
  inactive), creates the directory with a directory-type file push (the Incus file API makes no
  parents), and its one exec appends the name to `/etc/sandcastle/hostnames` if missing before
  `--refresh` — a Freeform Machine (no seed) is served as soon as its certificate lands, without
  waiting for slice 3's hostnames push. `PushMachineHostnames` (file + refresh) is provided now as
  the seam slice 3 wires; drift is checked against the name's `cert.pem`.
- **`--refresh` does not re-seed a present file and never rewrites it**; an empty file means "no
  public names". `machine-generalize` removes the file and every `tls/<name>/` directory so an
  `sc image save` clone never inherits names or certificates.
- **`sc create --bare` output** prints the private `HTTPS:` line always and an `HTTPS (public):`
  line listing the public names (served once the certificate lands) — the old "Let's Encrypt,
  certificate pending" line named a URL that did not serve yet; now the served one is first.
- **HostKeyAlias** needed no code change (slice 1 already ordered private names first); the test
  now pins derived-only, explicit-only, mixed and default-project orders, and the no-suffix case.
- **Payload version bump.** Any change to `caddyIngressSetupScript`/`machineGeneralizeScript`
  changes the content-derived payload version; existing tenants converge with `sc payload-sync` /
  `sc-adm tenant payload-sync` (`--check` shows the drift) — only machines created *after* the sync
  run the per-name script, hence "recreate" above.
- **`sc project set-domain` help** no longer says "Naming Mode is fixed at creation"; the refusal
  is described as the transitional guard it is.

## 2026-09-13 — Machine Public Hostnames slice 3 (#175): the reconciler per (machine, hostname)

Issue #175 (decisions on #172; ADR-0028; spec `docs/spec/machine-hostnames.md` §6). What the
ticket left to the implementer:

- **The list key is converged, not stamped once.** The ticket asked for the Freeform first-sight
  stamp "now as a list"; the spec (§4) also owed the derived-name re-derivation on a domain change.
  One rule covers both: every pass computes the machine's set (derived + explicit) and rewrites
  `user.sandcastle.v2.public-hostnames` when it differs (deleting the key when the set is empty),
  and deletes the legacy `public-hostname` key in the same write — `PublicHostnamesFromConfig`
  falls back to the legacy key once the list is gone, so a stale `web.baum.hase.de` there would have
  resurrected a released derived name. Cost: one `UpdateInstance` per legacy-stamped machine on the
  first pass after the upgrade (every machine the v0.10.0 reconciler saw carries `private` or a
  derived name), never again. Alternative — stamp only when the key is absent, as before — rejected:
  it cannot express unset-domain, set-domain or a failed API write. The "Incus key without claim"
  and "key disagrees with claim" projects keep the old behaviour (nothing written, logged once),
  because the tenant may still repair them; their explicit names are served regardless.
- **`set-domain`/`unset-domain` refusal retired, and `ListZoneModeMachines` with it.** The seam
  method, its incusx implementation, the adapter, `ProjectDomainMachinesError` and the handler guard
  are gone rather than left as dead code. `projectDomainSet` now runs `onProjectDomainReleased` for
  a **replaced** domain (the previous claim) — before this slice the refusal made replacement with
  machines impossible, so the replaced domain's records and rows were never released; without it
  the old derived names' A records would leak (they are under no claimed domain any more, so the
  stale-record GC would not touch them). Both verbs kick the reconciler.
- **The API kicks the reconciler.** `HandlerOptions.ZoneReconcileKick` / `zoneReconciler.RequestPass`
  (mutex-guarded, nil-safe, set by the loop) so `sc hostname add|remove` and the domain verbs
  converge within seconds instead of at the next 30 s tick. The reconciler is built before the
  handler in `Serve` for that. Alternative — have the DELETE handler push the hostnames file itself
  — rejected: the handler has no `ZoneMachineServer` and no Incus project name, and one owner of
  the file (the reconciler) is the whole point of §5.2.
- **Hostnames-file convergence is bounded, not fleet-wide.** Reading `/etc/sandcastle/hostnames`
  on every running machine every 30 s would add a file read per private-only machine that never
  had a public name. The pass reads it for machines with ≥1 target and for machines this process
  remembers having had names (`namedBefore`), so the last-name removal converges to an empty file
  in the same process. The one gap — the last name removed and the Auth App restarted before the
  next pass — leaves a stale (harmless: the name's records are gone) file until `--refresh` by hand
  or the next add/remove; documented in the skill. Alternatives: reading every machine (rejected,
  cost on the private fleet), or persisting "had names" in the DB (rejected as a table for one
  edge). The marker is read once per machine per pass (`markerByMachine`) since several names share
  it.
- **The certificate-row GC keeps rows "live" while the hostname is reserved.** The ticket said
  explicit rows should stop being exempt "by fiat"; the reason they must stay is now concrete:
  `sc create --hostname` records the row *before* the instance exists (`beforeCreate`), so a pass
  between the claim and the create would drop a never-issued row of a "vanished" machine — and a
  Dev Image machine would never get it back. A reservation that exists says the tenant wants the
  name; the hostname GC (5 min) ends the reservation of a vanished machine and the row follows on
  the next pass. The old exemption had no such tie to the reservation's lifetime.
- **Mirror format and folding.** `cert-state` = `host=state,…` sorted by host (the parser also
  accepts a bare pre-slice-3 value as the first name's); `cert-not-after` = the earliest expiry
  among names whose pushed serial is the issued one (a renewed-but-unpushed name contributes the
  machine's previous value, as before). Worst-state order `failed > (unknown) > pending > issued >
  renewing > installed`, a name without an entry counting as pending — so `sc ls` reads `pending`
  until *every* name serves, which is what the operator wants to see. An unknown state ranks just
  below failed so the CERT column still shows it verbatim rather than hiding it behind a healthy
  sibling. `WorstCertState` returns "" when nothing is mirrored yet, keeping the pre-slice JSON
  (`certState` absent for a fresh machine) and the existing decode tests.
- **`sc project status` per name.** One row per (machine, name); NOT AFTER — one value per machine
  in the mirror — is printed on the machine's `installed`/`renewing` rows as its earliest expiry
  (conservative; documented) rather than only on the first row, where a `pending` first row would
  have carried an expiry that is not its own. A machine without a name reads `private name only`
  ("private mode" was Naming Mode vocabulary). The table now also appears for a project without a
  domain once a machine carries an explicit hostname — before, such a project ended at
  `Domain: (none)` and the hostname's state was invisible outside `sc ls`.
- **Managed records for explicit names are exactly base + wildcard**, not the subtree the
  reservation covers: the reconciler deletes only what it writes, so a record a tenant might add by
  hand below a reserved name is never read as stale. Zones are reconciled when they hold a claim or
  a hostname row (with an empty target list when nothing is live), so a zone holding only explicit
  names still GC's a deleted machine's records.
- **Removal hook deletes records only.** `onMachineHostnameReleased` → `releaseMachineHostnameRecords`
  (base + wildcard A, the name's `_acme-challenge` TXT) through the same provider factory as the
  domain release, so the package's tests stay off Cloudflare; the row is untouched (§4.6 retention —
  the tests pin that a re-added name reaches `installed` with no order).
- **Tests.** The reconciler tests were rewritten for the pair model (fake fleet gained
  `PushMachineHostnames` and list-key stamping; the harness routes the release hooks to its own fake
  DNS) and gained: add later, remove (records gone, row retained, file pushed, re-add reuses), the
  last name removed (empty file, keys deleted, machine not revisited), explicit name in a private
  project (empty seed pushed), derived + explicit mixed with per-name mirror and earliest expiry,
  machine deletion covering all names, set-domain / unset-domain re-derivation, list-key convergence
  + legacy-key deletion + a legacy-marker machine, and the API kick. `meta` tests cover the mirror
  format, parsing, worst-state folding and `CertStateOf`; the CLI golden covers per-name rows and
  the private-project table.

## 2026-09-13 — MPH slice 4 (#176): e2e Phase 12g automation + docs sweep

Decisions the ticket left open while extending `scripts/e2e-pdz.sh` and Phase 12 of `docs/e2e-sc2.md`:

- **12c/12f had to change, not only grow.** The script still asserted ADR-0027 behaviour that slices
  2–3 retired: "no `DNS:` line for a zone-mode machine" and the `unset-domain` "has machines with a
  public name" refusal. Keeping "every existing step intact" literally would have made the phase fail
  on the first run, so 12c now asserts the `DNS: <m>.<p>.<suffix>` line *and* the `Public name:` line
  (and pins `publicHostnames == [<derived>]`), and 12f replaces the refusal with
  `sc project unset-domain --dry-run` succeeding with machines present — a dry-run, because a real
  unset would release both machines' derived names and re-order certificates mid-run. The zone-remove
  refusal ("still has claimed project domains") is unchanged; the hostname variant of that refusal is
  reachable only once the domain is gone, so it stays a manual extra.
- **Private FQDN is derived, not read.** `sc ls --json` carries no private-name field (`meta.Machine`
  has none; the private name is `<name>.<project>.<tenant.dnsSuffix>` by construction), so the script
  reads `.tenant.dnsSuffix` once in 12c and builds `PRIVATE`/`PRIVATE2` from it rather than adding a
  JSON field for the harness. The tenant-CA check is `issuer contains "Sandcastle"` (the CA CN is
  `Sandcastle <suffix> tenant CA`) and `SAN = the private name`, plus "not STAGING".
- **Per-hostname certificates are proven by serial.** Rather than trusting the log, 12g captures the
  serial of `api-<id>.<zone>`'s certificate before `sc hostname add alt-…` and asserts it is unchanged
  after the add *and* after the remove — the observable form of "adding/removing a name never reissues
  the others".
- **"alt no longer served" is asserted loosely.** After the remove, Caddy either fails the handshake
  for SNI `alt-…` or answers with another block's certificate (Caddy's default-site fallback), so the
  check is "no certificate carrying `DNS:alt-…`", polled up to 120 s (hostnames-file push + `--refresh`
  come from the reconciler pass the endpoint kicks). The mirror check waits for `certStates` to drop
  the name the same way.
- **Retained certificate row: note, not assertion.** `sc project status` renders the instance mirror
  (one row per name in `public-hostnames`), so a removed hostname's retained `machine_certificates` row
  is invisible through `sc`; the script asserts the row is *gone from the status table* and prints a
  note pointing at the (DB) check in the doc instead of skipping silently.
- **Refusal texts are asserted verbatim** (the same-tenant classes: inside own Project Domain, held by
  another machine of the tenant, domain over a hostname, apex, derived name not removable) — the
  cross-tenant flat texts need a second tenant and stay manual. The taken-name `sc create --hostname`
  probe is `--dry-run` (server-side validation, rolled back) followed by `sc ls <project>:api2` empty.
- **Cleanup order.** `api` is deleted before `web` (its records — explicit *and* derived — must vanish
  on their own, not through the project-delete hook), then the existing web/project/zone teardown; the
  EXIT trap deletes `api` too. No new env vars: the two hostnames derive from `SANDCASTLE_E2E_RUN_ID`
  (`api-<id>.<zone>`, `alt-<id>.<zone>`), documented in `.env.e2e.sample`.

## 2026-09-13 — MPH live run defects: caddy-setup under dash, silent marker gate, 404 on stale delete

The first live e2e run of explicit Machine Public Hostnames (Debian trixie cloud image, real
Cloudflare + ACME) surfaced three defects that the pure tests could not see. Fixes on the same
branch; no spec change beyond a §5 note.

- **F6 — the payload body runs under dash, not bash.** `caddyIngressSetupScript` carried a
  `#!/bin/bash` shebang and, since slice 2, `done < <(hostnames_normalized < …)`. The shebang is
  irrelevant: the boot shim `/usr/local/sbin/sandcastle-caddy-setup` is `#!/bin/sh` and *sources*
  the body, so on Debian it executes under dash — which stopped at the process substitution
  (`Syntax error: redirection unexpected`) after the private leaf was fetched: no Caddyfile with
  public blocks, no `caddy.ready`, and the reconciler never pushed the issued certificate.
  *Fix:* the script is strictly POSIX sh. The normalized names are captured into `HOSTS="$(…)"`
  and iterated with `for host in $HOSTS` (they contain only DNS characters, so word-splitting is
  exact, and unlike a pipe into `while read` the loop keeps `RENDERED` in the calling shell — a
  temp file would have worked too but adds a file to clean up). `generalize` was already POSIX
  apart from its shebang; both shebangs are `#!/bin/sh` now for honesty.
  *Rule (new):* every script sourced by a `/bin/sh` shim is POSIX sh. The goldens now execute the
  script with `sh` (falling back to `dash`, then `bash --posix`), and `TestPayloadScriptsArePOSIXSh`
  statically rejects `<(`, `>(`, `[[`, `pipefail`, `declare`, `local -a/-n`, `+=(`, `read -a`,
  `function`, `&>`, `|&`, ANSI-C `$'…'` (word-start only — grep's `*$'` anchor is not quoting),
  any `${…}` beyond `${name}`/`${name:-…}`, and a non-`#!/bin/sh` shebang, and runs `dash -n`
  where dash exists — a `bash --posix` run alone would still have accepted the original bug.
  Also seen in the run: `PUBLIC_HOSTNAMES=m1.dbg…,` — the profile rendered `<derived>,<record>`
  with an empty record. Harmless after normalization, but the jinja tail is now
  `{{ ',' ~ record if … and record | default('') else '' }}`, so no trailing comma is emitted.
- **F7 — a missing marker held the certificate back silently.** `markerReady` returned false for
  `!ok` without a word (only `readMarker`'s generic "no caddy setup marker; A record only" existed,
  which reads as "private-only machine"). It now logs once per (instance, hostname):
  `caddy setup marker missing or unreadable (/etc/sandcastle/caddy.ready); certificate for <host>
  not pushed`, so a broken machine-side setup is visible in the journal instead of looking like a
  slow boot.
- **F8 — a zone pass failed on records another path had already deleted.** The project-delete
  hook and the pass GC race for the same stale A records; the loser got Cloudflare's
  `HTTP 404: [{Code:81044 Message:Record does not exist.}]` from libdns and failed the whole
  zone pass. `recordsAlreadyGone(err)` (matches `Record does not exist`, `81044`, `HTTP 404` in
  the error text — libdns/cloudflare exposes no typed error) turns that into an INFO
  "already gone" in `reconcileZoneRecords` and a nil result in the zone GC delete; any other
  delete failure still fails the pass. The fake provider grew a `deleteErr` for the test.


## 2026-09-13 — F9 (live run mph3): hostnames below the Auth Hostname are not install-reserved

`scanMachineHostnameConflicts` refused any hostname *inside* the Auth Hostname / route base subtree, while `scanProjectDomainConflicts` refused only the reserved name itself or an ancestor. With the e2e zone `e2e.sc.tc42.uk` registered under the Auth Hostname `sc.tc42.uk`, a Project Domain claim passed and an explicit hostname of the same shape was refused ("reserved by this install"). Aligned the hostname rule to the domain rule: equal/ancestor conflicts, descendants do not — a real collision with a Public Route (`<label>.<tenant>.<route base>`) is caught by the route reservation scan in both directions. Alternative rejected: making Project Domains refuse the subtree too, which would forbid registering any zone under the Auth Hostname, a layout an admin may well choose.
## 2026-09-14 — Tailnet publication terminates TLS on the Tenant Sidecar

`sc tailnet publish` always proxies to the selected Machine's established
private HTTPS endpoint on port 443. The Tenant Sidecar owns the generated
Caddy site and holds the issued certificate, while the Auth App alone uses the
registered Public DNS Zone token for DNS-01 and a DNS-only A record to the
sidecar's Tailscale address. Raw `tailscale serve` was rejected because it
cannot select several Machine upstreams by SNI on one shared port.

## 2026-09-14 — Direct-Machine Tailnet publication converges on Machine Public Hostnames

The Sidecar-Caddy implementation above is legacy transition infrastructure. New
`sc tailnet publish` work must create and manage the same **Machine Public
Hostname** resource used by `sc hostname add`: a DNS-only record targeting the
Machine's tenant-private address, plus the Auth App-issued certificate installed
in that Machine's Caddy. `sc tailnet unpublish` reverses that same resource
lifecycle. Existing Sidecar-backed publications are deliberately preserved until
an operator explicitly unpublishes and republishes them; changing their target
automatically is unsafe because DNS changes are not instantaneous.

## 2026-09-15 — Wildcard publication removal is Machine-scoped

`sc tunnel unpublish` and `sc tailnet unpublish` accept an optional hostname.
Without it they remove the publication records owned by the selected Machine;
a shell-quoted Go-style wildcard selects a subset of those records. They do not
list a DNS zone to discover removal targets. That deliberately keeps the
convenient bulk operation scoped to durable Machine ownership and prevents a
pattern from removing another Machine's hostname during DNS propagation.

## 2026-09-15 — `sc fix` repairs Machine-side publication contracts only

`caddy-publications` refreshes the local Caddy setup and writes the per-name
readiness marker needed by the Auth App's existing certificate delivery loop.
It intentionally does not claim DNS, order a certificate, or retarget a
hostname. `cloudflared` similarly restarts only a connector that already has
its Sandcastle token and service files; a missing connector requires the
explicit tunnel publication lifecycle. This makes `sc fix` safe for legacy
Machines without turning a repair command into a publication command.

## 2026-09-15 — SSH lockout repair is Machine-scoped through Incus

A project profile can retain an SSH key from an earlier login, while the CLI
offers its current local key. `sc fix --only ssh-key` therefore bypasses SSH
and writes the current managed authorized-key block through restricted Incus
exec on the selected Machine. It must not assume project-wide `/home`: that is
an opt-in mount, so a local-home sibling needs its own repair. New Machine
creation performs the same targeted reconciliation before its first SSH dial.

## 2026-09-15 — Machine Tunnel connectors are hostname-scoped

A Machine Tunnel is one Cloudflare Tunnel and one connector token per hostname,
not one mutable tunnel per Machine. Multiple hostnames can therefore use
different local ports without a token/configuration collision. The Machine
records a normalized hostname collection and creates a namespaced systemd unit
per member. The former singleton metadata and unit remain readable and are
removed only when that exact legacy hostname is unpublished; this keeps old
Machines operable without silently interrupting their connector.

## 2026-09-15 — Machine Tunnel reservation is recorded before connector setup

Cloudflare provisioning and guest connector installation are separate failure
domains. The Machine writes a `pending` publication entry immediately after a
Cloudflare run token is returned, then clears that state only after systemd has
started the connector. This prefers a visible, retryable reservation over a
best-effort rollback: the latter can fail independently and leaves a hostname
claimed with no CLI recovery path.

## 2026-09-15 — Tailnet publication diagnostics show the routed private IP

Tailnet publication remains a hostname claim; the Auth App owns the actual
DNS, certificate and Caddy reconciliation. In verbose mode the CLI reads the
selected Machine only to show the intended DNS-only A-record target and calls
out asynchronous convergence. Listing failure is deliberately non-fatal so a
diagnostic cannot block a legitimate publication.

## 2026-09-15 — Stop a Machine Tunnel connector before deleting its Cloudflare Tunnel

Cloudflare rejects deletion while a `cloudflared` replica is connected. Tunnel
unpublish therefore stops/removes the Machine-side connector first, retains the
publication record if provider cleanup fails, and retries the documented short
connection-drain window. This ordering makes a retry safe: publish can restore
the connector from the retained Cloudflare token, while unpublish can finish
the external cleanup without an orphaned ownership record.

## 2026-09-15 — `sc update` checks project payloads centrally

`sc update` includes a read-only row for each visible app project's shared
`/.sc` platform payload. Applying it writes once per stale project, so all of
that project's Machines observe the new platform payload without a per-Machine
SSH sweep or any change to publication state. A self-updated executable cannot
load its newly embedded payload until the next process, therefore an update
that replaces the CLI proposes the payload update but asks for one rerun rather
than writing the old payload under a new release label. `sc update` also skips
passive version notices after its own status table, avoiding a false skew
warning from the still-running pre-update process.

## 2026-09-15 — Machine Tunnel units start the platform cloudflared launcher

Machine Tunnel service units execute `/.sc/platform/sbin/cloudflared`, making
their startup policy part of the centrally versioned shared payload instead of
a per-Machine `/usr/local` binary. The provider executable remains a local
runtime cache because the platform volume is mounted read-only inside Machines;
the launcher populates that cache only on first use. This retains the existing
no-provider-token-on-Machine boundary while allowing a payload sync to update
the connector launcher for every Machine in a project. Old units are preserved
until the user explicitly runs `sc fix --only cloudflared` after payload sync.

## 2026-09-15 — Machine Caddy executes through the platform launcher

The Machine Caddy setup script now validates through and writes a systemd
override whose start/reload commands use `/.sc/platform/sbin/caddy`. Debian's
Caddy package remains responsible for the local executable, service account,
and package lifecycle; the platform launcher is the versioned control point.
This avoids replacing package-managed operating-system integration while making
the running command path centrally converged by the shared payload. Older
Machines retain their package unit until an explicit Caddy publications fix.

## 2026-09-15 — Publication E2E environment validation is tier-local

The publication runner's shared `require_env` helper did not bind its function
arguments, so Bash attempted an invalid indirect expansion before any test
resource was created. It now accepts the tier and variable name explicitly,
which makes the destructive publication tier fail with the missing credential's
actual name. This is intentionally a hard preflight error: a real Cloudflare
publication E2E must not fall back to a fake credential or a production OAuth
installation.

## 2026-09-17 — Directory selection and local project history

The user explicitly approved replacing switch-time global defaults with nearest-ancestor
`.sandcastle` selection, keeping globals only as fallback. The agreed behavior is in
`docs/spec/directory-selection.md`; the bounded decisions were settled directly, so no
multi-session wayfinder map was needed. This supersedes ADR-0021's project re-pinning.

Use a small YAML selection file (required remote/project, optional remote_projects),
not the secret-bearing global config type. Store per-remote project history locally:
reading only Incus pins would forget project switches now that those pins stay unchanged.
A remote without local history starts from its existing Incus pin, then default.
Invalid files stop lookup instead of silently targeting another install. Writes use
atomic replacement; explicit global config edits and login/enrollment remain compatible.
The global enrollment maps resolve tenant/auth/token/broker in memory on every local
selection, reusing the existing cross-tenant ambiguity rules.

Go was absent from PATH, so validation uses an isolated Go 1.25.6 toolchain under
`/tmp/sandcastle-go`, matching go.mod, without installing system packages.

`sc incus` now passes `INCUS_REMOTE` alongside `INCUS_PROJECT` to its child process,
so local selection works without changing the shared Incus config. The matching
Incus v6.23.0 client is built under `/tmp/sandcastle-go/bin` for validation only.

Validation: `go test ./...` and `go vet ./...` pass with the temporary Go/Incus
toolchain. No live gated Incus integration/E2E deployment was run.

## 2026-09-19 — `sc fix --only ssh-key` is additive and lists enrolled keys

The ssh-key fixup (and the same reconciler `sc connect` runs on a freshly created
machine) used to rewrite the `# sandcastle user ssh key begin/end` block of the login
user's `authorized_keys`, replacing whatever key was inside with the current CLI key.
Foreign lines outside the block were preserved, but an older CLI key was silently
dropped. The user's rule: a fix must never remove anything from `authorized_keys` —
only add, and show what is enrolled.

Decision: the script is now append-only. A key present anywhere in the file is left
where it is; a missing one is inserted before the block's end marker (or a new block is
appended when there is none). The marker block is kept so `RevokeUserSSHKey` (allowlist
removal in the Auth App) can still drop every Sandcastle-managed key in one pass — that
path is an explicit revoke, not a fix, and was left untouched. The script then prints
`ssh-keygen -lf authorized_keys` (raw key lines when ssh-keygen is missing); the
reconciler captures stdout and `ReconcileMachineUserSSHKey` returns the lines, which
`sc fix` prints with the current CLI key marked. Alternatives considered: dropping the
markers entirely (simplest, but breaks revoke) and listing only the managed block
(hides exactly the foreign keys an operator is usually looking for).

Also recorded while debugging: on Ubuntu 25.10+ machines `sudo` is sudo-rs, whose
"no sudoers rule matches" refusal reads `I'm sorry <user>. I'm afraid I can't do that`
— it is not a password failure. The SSH fixups rely on cloud-init's
`/etc/sudoers.d/90-cloud-init-users`; when that file is gone they fail while `ssh-key`
still works, because it goes over the Incus API.

## 2026-09-19 — ssh-key fixup manages a `~/.ssh/config` block; VERBOSE prints the ssh line

Why plain `ssh user@ip` prompted for a password while `sc connect` worked: connect
pins the CLI key with `-i … -o IdentitiesOnly=yes`, plain ssh offers `~/.ssh/id_*`
only. The user asked for two things: `VERBOSE=1` must print the full ssh command line,
and the ssh-key fixup should teach the local ssh client about the machine.

`logSSHCommand` prints `[verbose] ssh command: …` (shell-quoted via the existing
`shellCommandLine`) on stderr from both `runSSHSession` and each `sc fix` SSH fixup —
the same trace style `sc incus` already uses.

The fixup now upserts one marker-delimited `Host` block per machine in `~/.ssh/config`:
patterns = private fqdn + public hostnames + private IP; `User`, `IdentityFile` (tilde
path of the CLI key), `IdentitiesOnly yes`, `HostKeyAlias <fqdn>`, `CheckHostIP no` —
the exact argv connect builds, so the known_hosts line connect pinned is what plain ssh
verifies. Decisions: the block goes at the TOP of the file (ssh takes the first value
per option, so it must precede a user's `Host *`); only the block's own markers are
rewritten and everything else is preserved byte-for-byte; the private IP is included
although leases recycle — the block is refreshed on every fix and a reassigned IP fails
closed on the HostKeyAlias mismatch rather than silently connecting elsewhere. Written
atomically (tmp + rename, 0600), `--check` never writes. Alternatives: a separate
`Include ~/.ssh/sandcastle.d/*` file (cleaner, but needs an `Include` line at the top of
the user's config anyway, which is the same edit) and a global `Host 10.123.*` pattern
(wrong across tenants/remotes that reuse the CIDR).

## 2026-09-19 — `sc fix` gets a central `sudo` fixup

Every SSH fixup runs `sudo sh -s`, so a machine that lost cloud-init's
`/etc/sudoers.d/90-cloud-init-users` (seen on butler:thies, with the user also gone
from group `sudo`; root cause unknown) could not be repaired by `sc fix` at all. The
user asked for `sc fix` to fix sudo too.

Decision: a central fixup (Incus API exec as root, like `ssh-key`, ordered right after
it and before the SSH fixups) that restores group membership (`usermod -aG sudo`) and
the `<user> ALL=(ALL) NOPASSWD:ALL` rule. The file is appended to, not rewritten, and
`visudo -cf` validates the candidate before `mv` — a bad sudoers file locks root out of
sudo for everyone, so the check is not optional where visudo exists (sudo-rs ships it).
The script ends with `su -s /bin/sh <user> -c 'sudo -n true'`: the fixup reports what
sudo actually does, not what the file says. It lives on `MachineSSHKeyReconciler`
(reusing its store/server plumbing) rather than a new type; the name is now slightly
too narrow, renaming it was not worth the churn. Alternative considered: making the SSH
fixups tolerate a missing rule by falling back to Incus exec — rejected, the Incus path
needs no sudo at all and one narrow root-level repair is easier to reason about than
four fixups with two transports each.


## 2026-09-17 — Project-owned public certificates

Reuse the encrypted ACME row format, ARI scheduler, backoff and order queue
instead of duplicating a second certificate store. Project rows use reserved
machine owner `@project` (not a legal machine name) and a partial unique index
on tenant/project; their hostname is the Project Domain. Delivery checks each
machine's certificate independently rather than trusting a single pushed serial.

The machine selector `/etc/sandcastle/project-domain` is authoritative for
shared-directory rendering. Inferring coverage from parent directories alone
would keep serving a released project's stale certificate; unset clears the
selector. Certificate pushes no longer append storage names to hostnames:
otherwise the project apex would incorrectly become every machine's name.

Public DNS Zone apex hostnames were rejected in the existing implementation,
despite the task describing existing per-name orders for them. Accept them
through the per-name path while preserving all reservation conflict checks.
Explicit wildcard requests similarly needed normalization/rendering support;
they order only the wildcard SAN (never `*.*.<name>`). Same-machine wildcards
and deeper names can coexist; cross-machine overlaps remain rejected.

Add optional current-project forms for status/set-domain/unset-domain and
machine lifecycle dry-run plans, since the requested forms were absent.
The updated CLI resolves project state for listings through the Auth App;
raw instance metadata remains `project` without the shared expiry.

Validation uses the pre-existing scratch Go 1.25.6 and Incus client under
`/tmp/sandcastle-go`; no system package installation. The supplied follow-up
handoff concerns hello.thieso2.dev tunnel deployment, not project certificates.
The local login is thieso2 on obelix (also enrolled on idefix); the hosting
install/access for skorfmann/tod0s has not been identified, so local checks
must not be reported as live acceptance.

Validation completed: `go test ./...` and `go vet ./...` pass with the scratch
toolchain. Added coverage for empty projects, copies, aliases, shared renewal,
legacy leaf expiry, status/list resolution, Caddy directory selection, explicit
wildcards/zone apex DNS lifecycle and mutation dry-run plans. Live tod0s checks
remain unrun; no deployment or Let's Encrypt production order was performed.

## 2026-09-21 — Shared Tenants (spec docs/spec/shared-tenants.md, ADR-0029)

Membership is stored on the tenant's infra Incus project (`v2.members`)
rather than in the Auth Database, because `sc-adm tenant grant` runs against
Incus without an Auth App and both grant paths must converge on one record.
Members' SSH keys are not copied onto the shared tenant: profile rendering
reads each member's Personal Tenant key, so keys stay attributable and a
revoke cannot strip the wrong key. The cost is the hard prerequisite that a
member has logged in on the install, enforced at `create tenant --member`
and `tenant grant`.

The tenant's own key value (`v2.sshkey`) became a newline-separated list
instead of a new key, so every existing reader keeps working; the profile
key regexp now captures the whole `ssh_authorized_keys` block. A login-time
key rotation replaces only the FIRST line (the owner's key) and keeps keys
added with `add-ssh-key`.

Tenant scoping of the Auth App's tenant plane uses one request header
(`X-Sandcastle-Tenant`) stamped by the CLI's DeviceClient transport, instead
of threading a tenant field through every request struct; the endpoints that
already had an explicit tenant field keep it (explicit wins). No header keeps
the pre-existing "caller's own tenant" behaviour.

`sc login` deliberately still returns only the Personal Tenant as accessible:
returning memberships would make a member's first login skip the personal
setup (the CLI treats "several tenants" as "no default"). Memberships surface
through `sc tenant list`; `sc tenant switch` enrols the shared tenant's
remote (certificate-based, at the sidecar's tailnet IP that `/api/tenants`
now reports for memberships).

`PlanGrant` now names the certificate per install (`RestrictedInstallName`),
a latent bug on `--prefix` installs where the default-install name never
matched the entry a device login enrolled; the default install is unchanged.

E2E: the first fresh install used a hostname four labels deep under the
Cloudflare zone; Cloudflare's universal certificate covers one level only, so
the public hostname handshake failed and the install was redone as
`sh-shared.tc42.uk`. Recorded in Phase 13's prerequisites.

Live e2e (Phase 13, first run) caught a grant gap the unit tests could not:
two users logging in from ONE client share a keypair, so the daemon holds one
trust entry named after the first enrollment (`sandcastle-sh-thieso2`) and
the second member's name-based grant found nothing. The admin plane has no
recorded client certificate to go fingerprint-first, so `GrantTenantMember`
falls back to the entries that already hold the member's own Personal Tenant
projects — the member's live devices by construction — and never touches
dead same-named entries (#115 rule kept). The Auth App uses the same fallback
after its fingerprint-first attempt.

Live e2e also showed that `sc remote switch` (since 20cdc40) records the
active remote in a directory selection file (`.sandcastle`) which overrides
the global config; a member's `sc tenant switch` that only rewrote the global
remote left every command in that directory on the personal remote. The
switch now re-points the nearest selection file when one exists (never
creates one, keeping the global-config behaviour and its tests intact). The
e2e script itself had a `set -o pipefail` + `grep -q` trap that reported a
successful switch as a failure; its checks now capture output first.

Third live finding: with two logins on one client, `sc tenant switch` recorded
the GLOBAL config's auth token (the last login's) for the shared remote, so
the other member's later switch presented the wrong user's token and the
Auth App answered "not accessible". The switch now records the caller's
resolved credentials (active remote / directory selection), which is what
every other command uses.

## 2026-09-21 — `sc-adm tenant create` derives its CIDR pool from the install

The flag's built-in default (`10.249.0.0/16`) used to override the
configured pool, so an operator creating a tenant on a running install had
to look the pool up or silently get a foreign /16. The pool now resolves
flag > configured (env/seed; the admin default constant does not count) >
the /16 the install's existing tenants occupy > built-in default.

## 2026-09-21 — Auth App reconcilers stop polling incusd (HANDOFF-incusd-polling.md)

On `big` the obelix auth-app produced ~450 of ~460 Incus API requests per
90 s: the DNS and zone reconcilers each swept every project with
`recursion=2` on a 30 s ticker and re-read machine files every pass. Changes:

- **One fleet listing per pass, shared.** `runDNSReconcileLoop` assembles an
  `InstanceFleet` (project → instances) once and hands it to both stages
  (`V2DNSReconciler.ReconcileFleet`, `zoneReconciler.ReconcileFleet` →
  `ZoneMachineServer.ListZoneMachinesFrom`). Source order: the event-fed
  `ResourceCache` when ready (zero requests), else ONE
  `GetInstancesFullAllProjects` filtered to the install prefix
  (`incusx.FleetServer`). The per-project listing survives only as the
  fallback for installs without a mounted socket (nil fleet).
- **Events name their project.** `DNSProjectEvents` passes the event's
  project; the pass re-reads only dirty projects live (the DHCP lease lands
  after the event, so the cache's own refresh is too early) and feeds the
  result back into the cache. Settle passes (+3 s, +8 s) reuse the dirty set,
  then it is cleared.
- **File reads are cached** (`zoneReconciler.readFile`, 10 min TTL): marker,
  hostnames file, project-domain file, certificate and key. Our own pushes
  (`forgetMachineFiles`) and lifecycle events (`markProjectDirty`) drop a
  machine's entries; unreachable-instance errors are never cached. TTL 0 in
  tests keeps the existing drift tests exact; Serve sets the TTL.
- **Fallback ticker 30 s → 5 min.** Events already give convergence within
  seconds; the ticker only covers missed events and restarts.
- Not done: the ~5 s `instance-updated` on the auth-app's own instance. The
  route backend's `EnsureProxyDevice` already skips equal device maps and
  nothing else in this code writes that instance periodically; it needs a
  live look at the event's requestor before changing anything.

Verification target from the handoff (idle: incusd < 0.2 cores, < 10
listings/min) is recorded in docs/e2e-sc2.md's Phase 1 notes as a read-only
check (`incus monitor --type=logging`) — no live run was done here.

## 2026-09-21 — `sc update` resolves releases without the GitHub API

`sc update` printed `API rate limit exceeded for <ip>` from the laptop: the
anonymous GitHub API limit is per public address, shared by everyone behind
the NAT. Requiring a token was ruled out. The release page redirect
(`/releases/latest` → `/releases/tag/<tag>`) and the download URLs are not
rate limited, and GoReleaser's asset names are fixed, so the checker now
resolves the tag from the redirect and synthesizes the asset list; the
checksums file still verifies every download. The API is the fallback only
(and the only source of `published_at`, which merely gates the notice's
grace). A pinned tag is checked against its page so a typo fails early. A
`GITHUB_TOKEN` / `GH_TOKEN` in the environment is used when present, never
required.

## 2026-09-21 — Incus Reach after an interactive sidecar join

`sc-adm tenant create` without `--tailscale-authkey` prints the login URL and
returns; the sidecar joins later, but the Reach (`tailscale serve` of the
host's Incus :8443 onto the sidecar's tailnet address) only runs on a later
provisioning pass, which login re-polls for and the admin create does not.
A member's `sc tenant switch` then hit "connection refused" on the sidecar's
:8443 (live on obelix, moyn-dev). `SidecarTailnetIPV2` — what the Auth App
calls to report the address to a member — now completes the Reach
idempotently before answering, and the create's URL hint says to re-run the
command once after joining.

## 2026-09-21 — shared remote recorded against the resolved Auth Hostname

Live on obelix: `sc tenant switch moyn-dev` worked, `sc tenant switch
thieso2` then failed with `lookup auth.example.com`. The switch had recorded
`installs[moyn-dev]` from the top-level `auth_hostname` of the user config,
a placeholder an old login left behind, while the real hostname lives in
`installs[<remote>]`. It now records what `commandAuthHostname` resolves —
the same value every other command talks to.

## 2026-09-21 — tenant is part of the directory selection; `*` in tenant list

The Current Tenant now lives in `.sandcastle` next to remote and project:
`sc tenant switch` writes (or creates) the nearest selection with all three,
`sc remote switch` records the remote's enrolled tenant, and
`LoadUserWithError` applies the selection's tenant over the remote-derived
one. Without it a member's shared tenant was only in the global config while
the directory selection kept the remote — two sources that could disagree.
`sc tenant list` marks the active tenant with `*` (like project list) and
drops the yes/no Current column.

## 2026-09-21 — full machine paths in messages; unix user defaults to the tenant name

With directory selections and Shared Tenants a bare machine name no longer
says where the user is, so the connect prompt, the create/start lines and
the empty-list message now render `remote:tenant:project:machine`
(`machinePath` / `scopePath`); listings by pattern keep their labelled form.
A tenant's login user now defaults to the tenant name (valid Unix username
required; else `dev`), overridable with `--unix-user`; the login path keeps
sending the client's local user and stored users are never rewritten.

## 2026-09-21 — default machine profile no longer installs zsh

The stock-image profile installed `zsh` and set it as the login shell for
every machine; the operator wants the default lean. The profile now installs
`openssh-server` only and the login shell is `/bin/bash`. The `/.sc` shell
shim is still appended to both `/etc/bash.bashrc` and `/etc/zsh/zshrc`
(harmless without zsh; picked up if a user installs it). The Dev Image keeps
its own zsh/starship setup — that image is opinionated by design.

## 2026-09-21 — `sc tenant switch` re-points a drifted shared remote

Live on obelix the moyn-dev sidecar re-registered on the tailnet as
`obelix-moyn-dev-1` with a new address; the member's remote still pointed at
the old, offline node and every command timed out on :8443. The switch now
compares the remote's recorded address with the one the Auth App reports
and re-points it (`incus remote set-url`) when they differ. The stale
tailnet device has to be deleted in the admin console (see the e2e doc's
"stale sidecar devices" note).

## 2026-09-21 — tenant switch hints: tailnet only, and only when unreachable

`sc tenant switch` printed `sc dns setup` / `sc trust install` / `sc
tailscale up` after every switch. The first two are retired (Public DNS
Zones and real certificates replaced private DNS and the tenant CA), and the
third was printed even when the switch had just connected to the sidecar
over the tailnet: a member's restricted certificate cannot read the
sidecar's Tailscale status, so the status check always failed. The switch
now dials the sidecar's :8443 when it knows the address and hints only on
failure; owners without a known address keep the status check.

Also observed live: the moyn-dev sidecar was deleted and recreated at 12:56
UTC (not by this code — nothing here deletes a sidecar), which registered a
third tailnet node; the drift re-pointing from v0.18.9 handled it.

## 2026-09-21 — machine prompt `user@<fqdn>:` (just `<fqdn>:` for the tenant user)

Set in the platform payload's `shell/rc.sh` (sourced by the bash and zsh
shims on every machine, updated centrally by the payload sync) rather than
in cloud-init, so existing machines get it too. The rule "user equals
domain" is implemented as "the FQDN ends in `.<user>`": the tenant name is
both the default login user and the private DNS suffix. User rc files run
after the shim and override it.

## 2026-09-21 — `install-agentic.sh` in the platform payload; PATH via the shell rc

The installer lives in `/.sc/platform/bin` (a new payload dir) instead of
the image or cloud-init, so every machine — existing ones after a payload
sync — has it, and it updates centrally. It installs mise per user
(`https://mise.run` into `~/.local/bin`) and the three tools through mise's
registry (`herdr`, `claude`, `codex`), which keeps versions upgradeable with
`mise up`. The shared shell rc prepends `/.sc/platform/bin`, `~/.local/bin`
and the mise shims to PATH unconditionally (non-interactive SSH commands
need them) and activates mise only in interactive shells. Root is refused:
the tools are per user and the machines' login user is the tenant.

## 2026-09-21 — `/.sc/platform` volume root 0755

Live: `find /.sc` as the login user answered `/.sc/platform: Permission
denied`. Incus creates a custom volume's root as 0711, so the tree was
traversable (sourcing `shell/rc.sh` and running `bin/install-agentic.sh`
by path worked) but not listable. New platform volumes get
`initial.mode=0755`; existing ones keep 0711 (`initial.*` applies at
creation only; the file API cannot chmod an existing directory) — harmless,
just not browsable.

## 2026-09-21 — prompt applied from PROMPT_COMMAND

Live on dev2 the prompt stayed Debian's: the skel `~/.bashrc` sets PS1
after `/etc/bash.bashrc` (where our shim runs). The rc now installs a
one-shot `PROMPT_COMMAND` hook that replaces a stock prompt (one still
containing `\u@\h`) at the first prompt and leaves a custom one alone.
Interactive PATH/mise verified on dev2; non-interactive `ssh host cmd`
shells do not read the rc (Debian's `.bashrc` returns early), which is a
known limit — use `ssh host 'bash -ic cmd'` or a login shell for now.

## 2026-09-21 — `sc update` finishes in one run

After replacing its own binary the old process still carried the old
embedded skill and payload, so it asked for a second `sc update`. It now
re-runs the freshly installed binary as a child (`update --yes
--no-self-update`, hidden flag) with stdio passed through — a child rather
than exec(2) so it stays portable and the exit status propagates — and each
stage narrates what it changes.

## 2026-09-21 — machine paths as `tenant@remote:project:machine`

The colon-only form (`obelix:thieso2:work:dev`) read poorly and doubled up
for a shared tenant whose remote carries its name. Messages now print
`thieso2@obelix:work:dev`: the `tenant@` reads like the machine's shell
prompt, the rest is exactly the reference grammar, and the parser accepts
(and ignores) a leading `tenant@` so a printed path pastes back into any
command. A `remote/project` variant was considered and rejected because it
would have introduced a second grammar next to the colon one.

## 2026-09-21 — `sc project set-image` / `unset-image`

A per-project default machine image (`v2.image` on the app project), used
by `sc create` and the auto-create of `sc connect` when `--image` is not
given. Stored as a plain ref (an `images:` ref or an alias from `sc image
save`) and not validated against the remote at set time — aliases resolve at
create time, and a project may be configured before its image is published.
Mirrors the docker-autostart setting's plan/updater shape.

## 2026-09-21 — short aliases; `set-image` rides the Auth App

Aliases for the frequent verbs (`del`/`rm`, `up`, `down`, `reboot`, `new`,
`st`, `upd`, `t`, `p`/`proj`, `rem`, `img`, `host`, `sw`). Live: `sc project
set-image` failed with `Certificate is restricted` — a restricted tenant
certificate may not edit Incus project config. After a login the write now
goes through `PUT/DELETE /api/projects/{name}/image` on the Auth App (admin
rights, tenant-scoped via the Current Tenant header), direct Incus only
without a login. `set-cloud-identity` and `set-docker-autostart` still
write directly and will hit the same restriction for tenant users; they
should follow the same seam.

## 2026-09-21 — `images:` refs must be the cloud variant

Live: `sc p set-image newbuild2 images:ubuntu/26.04` produced a machine
that booted but never opened SSH — the plain image has no cloud-init, so
no user, keys or sshd ever appeared, and `sc c` only said "did not open SSH
within 2m". `tenant.ValidateMachineImageRef` now refuses a non-cloud
`images:` ref at `sc create --image`, `sc project set-image` and the Auth
App endpoint (aliases and fingerprints pass), and the SSH timeout path
probes for cloud-init and names the cause when it is absent.

## 2026-09-21 — bare names resolve in the current project; `project rerender`

`sc del dev` in project newbuild2 asked "which of 12 projects?" because a
bare name was looked up tenant-wide first. It now means the current
project's machine when one exists there; the tenant-wide lookup (one hit
resolves, several ask) only runs when the current project has no such
machine. Wildcards (`'*:dev'`) remain the way to act across projects.

A project's cloud-init profile is only re-rendered by events (grant, key,
domain), so profile changes shipped in a release (no zsh, bash shell)
never reached existing projects. `sc project rerender [name]` (Auth App,
admin rights) and `sc-adm tenant rerender <tenant> [project]` re-render on
demand; cloud-init runs once per machine, so only new machines see it.

## 2026-09-21 — bare-name lookup: current project first, then the cache

`sc del dev` still listed every project of the tenant (26 `recursion=2`
listings, ~8 s) to find where `dev` lives before honouring the current
project. The lookup now asks the Auth App resource cache (one request) or,
without it, lists only the current project; the tenant-wide sweep is the
last resort. Also on obelix: the `newbuild2` profile was re-rendered as
operator with `sc-adm tenant rerender thieso2 newbuild2` (the appliance is
on v0.18.18 and lacks the tenant-plane rerender endpoint until updated).

## 2026-09-21 — admin tenant commands detect the install prefix

`SANDCASTLE_REMOTE=big sc-adm tenant rerender thieso2` failed with "infra
project sc2-thieso2 not found": `big` hosts two installs and the CLI looked
under the default prefix. The tenant commands (grant, revoke, users,
set/add/remove-ssh-key, rerender) now scan the infra projects for the tenant
when the configured prefix is the default; one match selects its install
(with a note), several are refused, none falls through to the original
error. `tenant create` keeps needing the prefix (there is no tenant yet).

Verified live on `big`: `sc-adm tenant users moyn-dev` without a prefix
detects `obelix`; `thieso2` is refused as ambiguous because the Phase 12
`tc` install (13 Sep) is still on the host with stopped appliances — a
leftover to tear down, not a detection bug. Two more fixes from the same
check: v1-era `<project>-infra` projects (`version: "1"`) no longer count as
installs, and `tenant users` matches certificates holding ANY project of
the tenant namespace (a personal login certificate never held the infra
project, so personal tenants listed "none") and shows each user once,
without the install prefix.

## 2026-09-21 — `sc update`: download deadline; compact status table

Live: the CLI tarball download died with "context deadline exceeded" —
`download` reused the API client's 30 s overall timeout for a ~40 MB body.
Downloads now run under their own 15-minute context with the client's
timeout disabled. The status table prints detail only for outdated rows and
one summary line per kind for current ones (26 payload rows → one line).

## 2026-09-21 — cache first for every command

`sc update` (and every command) began with a live `GET /1.0/projects`
(>1 s on obelix) plus, for the payload check, a project read, a profile read
and a volume file read per project. The Auth App resource cache now also
holds the server's project list (seeded with `GetProjects`, refreshed on
project lifecycle events) and answers `include=projects` (the tenant's
namespace, infra config included) and `include=payloads` (each matched
project's /.sc VERSION, read over the appliance's local socket, pool taken
from the cached default profile). The user CLI's tenant store is wrapped
(`cachedTenantStore`): ListProjects from the cache, live on any non-answer;
`sc update`'s payload rows come from `include=payloads` the same way.
Verified on the E2E install: `sc ls` and `sc update --check` issue no live
Incus calls. Writes (payload sync, machine ops) stay live.

## 2026-09-21 — updater retries GitHub's download CDN

Right after v0.18.26 was published, `releases/download/...` answered 504
for minutes while the API listed the asset as uploaded and served it (the
laptop was updated from that path by hand). The downloader now retries 5xx
answers (six times, ten seconds apart, within the 15-minute deadline);
4xx stays final. install.sh already retried four times back to back, which
is too short for this lag — the Go path is the one `sc update` uses.
