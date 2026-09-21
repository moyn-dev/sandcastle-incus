# Handoff: auth-app reconcilers overload incusd on `big`

**Problem.** On `big` (obelix install, sandcastle-admin **0.17.0** in `obelix-infra/obelix-auth-app`),
incusd uses 1.3–1.8 cores constantly, more than all workloads combined. A pprof profile shows 45% of
that in SQLite (cowsql), serving `instancesGet` → `RenderFull` → `Snapshots()`.

**Measured 2026-09-21** (incusd debug request log, 90 s; strace, 60 s):
- The obelix auth-app sent 443 of 457 API requests: 222 file-API reads (`/etc/sandcastle/caddy.ready`,
  `hostnames`, `tls/<host>/cert.pem`), 193× `GET /1.0/instances?project=…&recursion=2` (one per
  obelix project, ~27 projects), and 28 project listings.
- Those 457 requests caused ~2,600 ZFS `GetInstanceUsage` lookups. The fleet has 191 instances and
  ~11k snapshots.
- The event bus showed 112× `instance-file-retrieved` in 60 s (the reconciler's own reads), plus
  11× `instance-updated` on `obelix-infra/obelix-auth-app` itself (about every 5 s). The cause of the
  updates isn't confirmed; probably the route manager refreshing its proxy devices.
- The feedback loop fixed in 33c6bec (lifecycle-action whitelist) is **not** active, because 0.17.0
  includes it.

**Cause (v0.17.0 code):**
- `internal/authapp/app.go:386` `runDNSReconcileLoop`: a 30 s ticker calls **two** reconcilers per
  tick. Both do a full per-project `GetInstancesFull` sweep:
  - `internal/incusx/dns_v2.go:117` (V2DNSReconciler)
  - `internal/incusx/zone_reconcile.go:62` (`ListZoneMachines`)
- `internal/authapp/zone_reconcile.go`: `readMarker`, `convergeHostnamesFile` and `driftCheck` read
  files through the Incus file API on every pass. The marker cache is reset each pass (`Reconcile`,
  ~line 290).
- Each lifecycle event adds 3 passes (0/+3/+8 s), and each finished ACME order calls
  `RequestPass()` (`runOrder`) for another.

**Suggested fixes (largest effect first):**
1. List machines once per tick and share the list between the DNS and zone reconcilers.
2. Stop using `recursion=2` for this. Use `recursion=1` plus state only for the IPs needed, or feed
   both reconcilers from the event-driven `ResourceCache` (`RunResourceCache`, already present).
3. Cache marker, hostnames and cert reads across passes (key on instance ETag or mtime), or publish
   them as instance `user.*` config keys instead of files.
4. Raise the fallback ticker from 30 s to about 5 min, since events already give fast convergence.
5. Find what updates `obelix-auth-app`'s own instance every ~5 s and make it a no-op when nothing
   changed.

**How to verify on big (read-only):**
- From a client trusted on big: `incus monitor big: --type=logging --format=json` (90 s), then
  count `Handling API request` entries by url.
- `incus monitor big: --type=lifecycle --all-projects --format=json` shows the event rate.
- incusd pprof is available on the host:
  `curl 127.0.0.1:8444/debug/pprof/profile?seconds=30`.
- Target: incusd under 0.2 cores and fewer than 10 listings per minute when idle.

Full analysis: https://claude.ai/artifact/4j9AkUvLwmUw7px5br5Ku3 (CPU & incusd tab).
