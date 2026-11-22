# User-Chosen DNS Suffix as the Incus Remote Name; Unified `[[dns-suffix:]project:]machine` Addressing

> Status: **decision 1 superseded by [ADR-0021](0021-one-incus-remote-per-install.md)** (2026-07-15) — the remote is now named `<dns-suffix>` (one per install), not `<dns-suffix>-<project>`; the project is an orthogonal pin that follows `sc project switch`. Decisions 2–6 below stand. Original status: proposed (2026-07-15). Amends ADR-0018 decision 3 (the Tenant DNS Suffix becomes mandatory-at-first-login, uniqueness-bearing, and the incus remote-name stem). Builds on ADR-0016 (native Incus access) and ADR-0018 (machine private hostnames). Full mechanics: [`../design/machine-addressing-and-remote-naming.md`](../design/machine-addressing-and-remote-naming.md). Produced by wayfinder map [#82](https://github.com/moyn-dev/sandcastle-incus/issues/82).

## Context

`sc connect` addresses `[tenant/][project:]machine` and has **no way to name an install**, so `sc c sc-obelix-thieso2-dev:sc:dev` fails (`invalid machine "sc:dev"` — the parser splits project on the first `:` and the rest lands in the machine slot). Meanwhile incus remotes are named by **three inconsistent schemes** — `sc-<authhost-label>` (base, from the Auth Hostname), `sc-<tenant>-<project>` (`sc enroll`), and `<tenant>-<project>` (`sc project create`) — so a user's `incus remote list` shows two unrelated families and cannot distinguish installs.

ADR-0018 already made the **Tenant DNS Suffix** tenant-chosen, single-label, and immutable, but optional (defaulting to the tenant name) and — because BYO tailnets isolate resolution — explicitly *allowed two tenants to pick the same word*. This ADR makes that suffix **load-bearing for client-side identity**: it becomes the incus remote name, which lives in the client's `~/.config/incus/` across many installs, so it now needs disambiguation the isolated-tailnet model never required.

## Decisions

1. **The incus remote name is `dns-suffix-projectname`** — always, one remote per (install, project). No `sc-` prefix, no omission, replacing all three current schemes. This unifies "how a remote is named" with "how a machine is addressed" (decision 4).

2. **Remote names are opaque display labels — never string-parsed** back into (install, project). The project is recovered from the remote's pinned incus project (`sc2-<tenant>-<project>`), the install from its endpoint; composition (`suffix + "-" + project`) is one-way. This dissolves the dash-ambiguity of decoding a dashed suffix next to a dashed project.

3. **The Tenant DNS Suffix is mandatory, user-chosen at first login, immutable thereafter**, and is the remote-name stem. Amends ADR-0018 decision 3: no longer optional / tenant-name-defaulted. Chosen in a browser form during device-login (re-login returns the stored value). Claim-and-reserve — **no DNS ownership proof** (it resolves internally over the tenant's Tailscale split-DNS + `/etc/resolver/`, so public ownership is functionally irrelevant).

4. **Uniqueness is enforced by two guards, with no central authority** (installs stay autonomous, per ADR-0016's independence): a **per-install server registry** (a new `UNIQUE` auth-DB table) rejects a suffix already claimed on that install (first-come-first-served), and a **client-side guard** refuses a suffix that already maps to a *different* install in the user's local config. A cross-install suffix collision makes `foo:project:machine` ambiguous, so the guard **refuses** — it never renames a local remote (that would break decision 2's deterministic composition). This narrows ADR-0018's "two tenants may pick the same word": still true across *isolated* installs a given client never mixes, but a single client cannot hold two installs with the same suffix.

5. **The reserved magic project `default` is removed.** The user names their initial project at first login (it seeds the config's current project). Existing projects literally named `default` remain valid ordinary names.

6. **One addressing grammar, `[[dns-suffix:]project:]machine`, shared by every reference-taking command** (`connect`, `create`, machine-lifecycle verbs, `image save`) through one canonical parser (extended `parseV2MachineReference`; `naming.ParseUserMachineRef` retired). Colon count selects scope: 0 = current install+project, 1 = current install + named project, 2 = named install + project. **One colon is always `project`** — there is no silent fallback to incus-native `remote:instance`; a full-remote-shaped token yields a diagnostic hint. The old `[tenant/]` prefix is dropped.

7. **No silent config mutation when naming a machine.** A missing remote errors with guidance (`sc enroll`, `sc project create`, or `sc login <host>` first) rather than auto-provisioning. Migration of the three legacy schemes is **lazy, at next login, non-breaking**: a suffix-less existing tenant's next login is treated as a first-login suffix choice, then the client renames its remotes in place (`incus remote rename`, detected by endpoint + pinned project, preserving certs). No standalone migrate command.

## Considered and rejected

- **A central cross-install suffix registry / global authority** — would give true global uniqueness but requires a new shared service and breaks the autonomous-per-install architecture (ADR-0016). Rejected in favor of the two local guards (decision 4).
- **DNS proof-of-ownership for the suffix** — the suffix resolves only inside the tenant's own split DNS, so ownership proves nothing functional; and the old `internal/route/dnsproof.go` was deleted with v1 and only ever proved "points-at-our-IP" anyway. Rejected (decision 3).
- **Omitting the project segment for a "default" remote** (`dns-suffix` alone) — prettier, but reintroduces a cross-install name collision (one install's bare-suffix remote vs another's `suffix-project`) and forces a reserved magic project. Rejected mid-design in favor of always-`dns-suffix-projectname` + naming the initial project (decisions 1, 5).
- **Silent incus-native `remote:instance` fallback, or auto-provisioning a missing remote** — both make a command's meaning depend on ambient state (which remotes exist). Rejected as magic; strict grammar + diagnostic errors instead (decisions 6, 7).
- **Auto-deriving existing tenants' suffixes** — the auth-hostname label is shared across all tenants on an install (→ collision), and the tenant-name derive recreates the `thieso2-*` names this effort escapes. Rejected in favor of choosing at next login (decision 7).
