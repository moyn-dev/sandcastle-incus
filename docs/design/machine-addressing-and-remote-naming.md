# Spec: Machine addressing & incus-remote naming

Status: **Proposed** — implementation-ready design produced by wayfinder map
[#82](https://github.com/moyn-dev/sandcastle-incus/issues/82). Every claim below is a
resolved decision; each section links the ticket that holds its full reasoning.

> **Everything is v2.** This spec adds no version gates and no v1 paths.

## 1. Motivation

`sc c sc-obelix-thieso2-dev:sc:dev` fails with `invalid machine "sc:dev"`: the connect
parser understands `[tenant/][project:]machine` but has no concept of naming an
*install*, and it splits the project on the first `:`, sliding the rest into the machine
slot. Separately, incus remotes are named by **three inconsistent schemes**
(`sc-<authhost-label>`, `sc-<tenant>-<project>`, `<tenant>-<project>`), so a user's
`incus remote list` shows two visually unrelated families and no way to tell installs
apart.

This spec unifies both into **one coherent model**: a user-chosen, globally-disambiguated
**DNS suffix** per install that *is* the remote name stem, and a single addressing grammar
`[[dns-suffix:]project:]machine` shared by every command that names a machine. After it,
the original command is spelled `sc c obelix:sc:dev` → incus remote `obelix-sc`,
instance `dev`.

## 2. Model & vocabulary

Domain terms are canonical in `CONTEXT.md`.

- **Install** — one Sandcastle deployment (one Incus daemon + auth app), reached at one
  endpoint. Identified to the user by its **DNS suffix**.
- **DNS suffix (dnsprefix)** — *is* the **Tenant DNS Suffix**. A property of the tenant,
  **chosen at first login**, immutable afterward. It is the stem of every incus remote
  name and the DNS suffix under which the tenant's machine hostnames resolve
  (`dev.<suffix>`), served **internally over Tailscale split-DNS + `/etc/resolver/`** —
  never public DNS. ([#84](https://github.com/moyn-dev/sandcastle-incus/issues/84))
- **Project** — a namespace within a tenant on an install. The reserved magic project
  `default` is **removed**; the user names their initial project at first login.
  ([#85](https://github.com/moyn-dev/sandcastle-incus/issues/85))
- **Remote** — an incus remote binding one (install, project) pair; named
  `dns-suffix-projectname`.

## 3. Remote naming scheme ([#85](https://github.com/moyn-dev/sandcastle-incus/issues/85))

A remote is **always** named `dns-suffix-projectname` — the project segment is never
omitted, there is no `sc-` prefix, and there is no reserved `default`. One remote per
(install, project).

- Example: suffix `obelix`, project `sc` → remote **`obelix-sc`**.
- This replaces all three current schemes and eliminates the `thieso2-io` / `thieso2-sc`
  family.

**Names are opaque display labels — never string-parsed back into (install, project).**
The two components are always available from authoritative sources:

- **project** ← the remote's pinned incus project in config (`project: sc2-<tenant>-<project>`),
  extracted with the existing `shortProjectName` `-<tenant>-` marker.
- **install** ← the remote's endpoint.
- Composing a name is one-way: `suffix + "-" + project`.

Because nothing decodes, the dash ambiguity (`a-b-c` = `a`+`b-c` or `a-b`+`c`) never
arises in code. Project names may keep dashes (`ValidateProjectName` stays
`[a-z][a-z0-9-]{1,62}`). The one residual *string* collision across two installs is
backstopped by the client-side guard (§5) — incus's own "remote already exists" is the
trigger.

## 4. The DNS suffix: identity, uniqueness, enforcement ([#84](https://github.com/moyn-dev/sandcastle-incus/issues/84))

- **Chosen once, at tenant creation (first login).** On every later login to an existing
  tenant the server **returns the stored suffix**; the user cannot re-choose. Effectively
  immutable.
- **Claim-and-reserve, no ownership proof.** Since the suffix resolves internally
  (Tailscale split-DNS + `/etc/resolver/`), publicly owning it buys nothing. (Note: the
  old `internal/route/dnsproof.go` is **deleted** and only ever proved "points-at-our-IP",
  not ownership — it is not reused. [#83](https://github.com/moyn-dev/sandcastle-incus/issues/83))
- **Uniqueness = two guards, no central authority** (installs stay autonomous):
  1. **Per-install, server-side (FCFS):** the auth app rejects a suffix already claimed by
     another tenant on that install.
  2. **Client-side guard:** `sc` refuses a suffix that already maps to a *different* install
     in the user's local config (the cross-install surface a per-install registry can't see).

  A cross-install suffix collision is not a naming nuisance — it makes `foo:project:machine`
  fundamentally ambiguous — so the guard **refuses**; it never renames a local remote
  (renaming would break the deterministic grammar composition).

## 5. Login flow ([#87](https://github.com/moyn-dev/sandcastle-incus/issues/87))

`sc login <host>` is browser-assisted device auth. The server detects new-vs-existing
tenant:

- **Re-login (existing tenant):** no form; server returns the stored suffix; CLI proceeds.
- **First login (new tenant):** the browser presents a **form** — choose DNS suffix + name
  the initial project.

**Selection, rejection, and both uniqueness guards live in that one form, pre-commit:**

- The CLI hands its list of **locally-used suffixes** to the auth app when it initiates
  device login.
- The form's **live server-side validation** red-fields (with a suggestion, inline retry)
  a suffix that is **taken on that install** *or* **already used by this client for a
  different install**. Nothing commits until the suffix passes both.

**Storage — a new per-install auth-DB (SQLite) table:**

- Suffix as a **`UNIQUE`** column → atomic first-come-first-served (`INSERT … ON CONFLICT`),
  referencing the tenant/`user_key`. Fits the existing DDL pattern in
  `internal/authapp/app.go` `Migrate` and CRUD style in `store.go`
  ([#83](https://github.com/moyn-dev/sandcastle-incus/issues/83)).
- Read on every login to return the stored suffix.
- **Lifecycle:** freed on tenant delete (`sc-adm project delete` / tenant-delete path); a
  reconcile prunes claims whose tenant no longer exists in live Incus. Incus stays the
  source of truth for tenant *existence*; the table is authoritative only for the suffix
  *value + uniqueness*.

The chosen initial project seeds the config's **current project** (`~/.config/sandcastle/config.yml`).

## 6. Reference grammar ([#86](https://github.com/moyn-dev/sandcastle-incus/issues/86), [#91](https://github.com/moyn-dev/sandcastle-incus/issues/91))

Grammar: **`[[dns-suffix:]project:]machine`**. Colon count selects scope:

| Input | Colons | Scope | Resolves to incus |
|---|---|---|---|
| `machine` | 0 | current install + **current project** (config) | `<cur-suffix>-<cur-proj>:machine` |
| `project:machine` | 1 | current install, named project | `<cur-suffix>-project:machine` |
| `dns-suffix:project:machine` | 2 | named install, named project | `dns-suffix-project:machine` |

- Composition is **one-way** (§3); the grammar never decodes a remote name.
- **1 colon is always `project:machine`.** There is **no** silent fallback to incus-native
  `remote:instance`. When a project lookup fails and the leftmost token matches an existing
  remote or splits as `<known-suffix>-<project>`, the error is **diagnostic**:
  *"`obelix-sc` is a remote, not a project — did you mean `obelix:sc:dev`?"*
- **Bare `machine` with no current project set** → error with a hint to pick/set a project.
  No auto-select.
- The old **`[tenant/]`** prefix is **removed** (you are always your own single tenant; the
  suffix identifies the install).

**Canonical parser.** Extend the in-use `parseV2MachineReference`
(`internal/cli/create_v2.go:127`) to accept the optional leading `dns-suffix:` install
component; **retire the unused `naming.ParseUserMachineRef`** so there is one parser.
Resolution stays in `resolveV2MachineReference`, extended to compose the remote name and
switch install context when a suffix is supplied.

**Reach — uniform across every reference-taking command** via that shared parser
([#91](https://github.com/moyn-dev/sandcastle-incus/issues/91)):
`connect` (`connect.go`), `create` (`create_v2.go`), the machine-lifecycle verbs
(`machine_lifecycle.go`), and `image save` (`image.go`). `share`
(`project:/dir --to tenant`) uses a different reference shape and is untouched.

## 7. Missing remote on connect ([#90](https://github.com/moyn-dev/sandcastle-incus/issues/90))

Connect (and every reference-taking command) **never silently creates a remote.** It
errors with guidance:

- **Install known, project remote missing** (you hold trust, but no `X-foo` remote):
  *"no remote for `X-foo` — run `sc enroll`"*. If the project does not exist in the tenant
  summary at all → *"project `foo` not found — create with `sc project create foo`"*.
- **Install never touched** (no endpoint/creds for suffix `X`): *"unknown install `X` — run
  `sc login <host>` first"* (forced — the client cannot discover the endpoint for an unseen
  suffix).

Consistent with the no-magic theme (§6) and with migration (§8): neither path mutates the
user's incus config as a side effect of naming a machine.

## 8. Migration ([#88](https://github.com/moyn-dev/sandcastle-incus/issues/88))

**Lazy, at next login, non-breaking.** Old-scheme remotes keep working until reconcile;
there is **no standalone migrate command**.

- **Suffix source:** an existing suffix-less tenant's **next login is treated as a
  first-login suffix choice** (the §5 form). No safe auto-derive exists — the auth-hostname
  label is shared across tenants on an install (→ collision), and deriving from the tenant
  name recreates the `thieso2-*` names this effort escapes. This is a deliberate one-time
  bend of "immutable" for pre-existing tenants.
- **Client-side reconcile at that login:**
  - **Detect by metadata** (not name-parsing): local remotes whose endpoint = this install
    and whose pinned incus project is `sc2-<tenant>-*`.
  - **`incus remote rename <old> → <suffix>-<project>`** — preserves the client cert and
    pinned project; no token re-fetch.
  - Old base remote (`sc-<authhost-label>`, no user project): → `suffix-default` if pinned
    to `default`, **removed** if pinned to the infra project (base/enroll role is gone).
  - Update the current-remote pointer if renamed; idempotent (skip `suffix-*` remotes); a
    target name taken locally by a different install defers to the §5 client guard.
- Existing projects literally named `default` keep their name (now an ordinary name); only
  the remote reshapes to `suffix-default`.
- Server side: just the normal claim-table insert; Incus projects (`sc2-<tenant>-<project>`)
  are untouched. Migration is almost entirely client-side remote renaming.

## 9. Affected code (survey [#83](https://github.com/moyn-dev/sandcastle-incus/issues/83))

- `internal/cli/create_v2.go` — extend `parseV2MachineReference` / `resolveV2MachineReference`
  (add `dns-suffix:` component; drop `tenant/`; bare-machine → current project).
- `internal/naming/naming.go` — retire `ParseUserMachineRef`.
- `internal/usertrust/plan.go` — replace `RemoteNameForAuthHostname` / `RemoteInstallName`
  scheme with `dns-suffix-projectname` composition.
- `internal/cli/login.go` + `internal/authapp/provision.go` — first-login suffix+project
  form, stored-suffix return on re-login, client sends locally-used suffixes.
- `internal/authapp/app.go` (`Migrate`) + `store.go` — new claim table + CRUD + reconcile;
  free-on-delete in the tenant/project delete path.
- `internal/cli/project_v2.go`, `connect_v2.go` — per-project remote naming → new scheme;
  the trusted-cert enroll path stays for `sc enroll`.
- Client reconcile (migration) — new logic invoked from the login path.

## 10. Documentation updates required (in the implementing PR)

Per the repo's docs discipline (`CLAUDE.md`), the implementation must update, in the same
commits:

- **`docs/e2e-sc2.md`** — the executable source of truth. Amend/add phases for: first-login
  suffix + initial-project selection and the rejection UX; re-login returning the stored
  suffix; the `dns-suffix-projectname` remote names in every PASS criterion; the
  `[[dns-suffix:]project:]machine` connect/lifecycle/create/image grammar; missing-remote
  error behavior; and the lazy at-login migration of existing remotes.
- **`docs/usage.html`** — CLI reference for the new grammar and login flags/flow.
- **`docs/admin-developer-quickstart.html`** — onboarding steps that mention remote names /
  login.
- **`implementation-notes.md`** — entries for any decisions invented during implementation.
- Correct the stale `internal/route/dnsproof.go` reference at `CLAUDE.md:67`.

## 11. Out of scope

- Implementation itself (this is the spec).
- A central cross-install suffix registry / global authority (explicitly rejected, §4).
- Ownership-proving the suffix via DNS (unnecessary, §4).
- `share`'s `project:/dir` grammar (untouched, §6).
