# One Incus Remote per Install (named by DNS suffix); Project Is an Orthogonal Pin

> **2026-09-17 amendment:** The project-switch write-through in decision 2 is
> superseded by [Directory Selection](../spec/directory-selection.md).
> Switches now persist the nearest `.sandcastle`, leaving global Incus pins
> unchanged. The one-remote-per-install and enrollment decisions still apply.

> Status: **proposed** (2026-07-15). **Supersedes ADR-0020 decision 1** (the remote name is `<dns-suffix>-<project>`, one remote per (install, project)). Keeps ADR-0020 decisions 2–6 (opaque labels, mandatory immutable suffix, uniqueness guards, unified `[[dns-suffix:]project:]machine` grammar). Builds on ADR-0016 (native Incus access).

## Context

ADR-0020 decision 1 minted **one incus remote per (install, project)**, named `<dns-suffix>-<project>` (e.g. `jules-first`, `jules-h2`), each cert-pinned to its `sc2-<tenant>-<project>` Incus project. In practice `sc` never navigates by these remotes: every first-class command (`sc create`, `sc connect`, `sc incus`) resolves the operating project from **`config.Project`** and passes it explicitly (API `project` param / `INCUS_PROJECT`), overriding whatever the active remote is pinned to. The remote pin is load-bearing only for **raw `incus <remote>:`** and for **install disambiguation** (`installPrefixForRemote`).

This produced two problems:

1. **Proliferation + stale names.** A tenant with N projects accrued N cert-pinned remotes in the user's `~/.config/incus/`, most never used directly.
2. **Divergence after `sc project switch`.** Switching the Sandcastle project rewrote only `config.Project`; it never re-pinned the remote. So `sc incus ls` (follows `config.Project`) and raw `incus <suffix>-<first>:` (follows the static pin) reported **different projects**, and the remote name `jules-first` became a lie once you switched to `h2`.

The remote identifies **an install**, not a project — the project is a mutable dimension `sc` already carries elsewhere. The name should reflect that.

## Decisions

1. **One incus remote per install, named `<dns-suffix>`** (e.g. `jules`, `obelix`, `home`) — no project segment. The DNS suffix is already unique per install (ADR-0020 decisions 3–4), so it is a stable, collision-free per-install handle. This supersedes ADR-0020 decision 1's `<suffix>-<project>` naming and its one-remote-per-project cardinality.

2. **The project is an orthogonal pin that follows `sc project switch`.** The remote is pinned (`remotes[<suffix>].project`) to `sc2-<tenant>-<project>` for the *current* project; `sc project switch <p>` re-pins it to `sc2-<tenant>-<p>`. This makes `sc`, `sc incus`, and raw `incus <suffix>:` agree — the divergence is gone. `config.Project` remains the source of truth; the pin is kept in sync as a convenience for raw `incus`.

3. **Enrollment and creation stop minting per-project remotes.** First login enrolls one `<suffix>` remote (pinned to the initial project). `sc project create` no longer writes a per-project remote by default (`--write-remote` defaults off; still available for users who want an extra directly-addressable remote). `sc enroll` regenerates a single `<suffix>` remote rather than one per visible project.

4. **Lazy migration collapses existing remotes.** On login, a tenant's existing per-project / legacy remotes for this install (identified by endpoint + `sc2-<tenant>-*` pin, per ADR-0020 decision 2 — never by parsing the name) are collapsed to a single `<suffix>` remote: the primary (the currently-current remote if it is this install's, else the one pinned to the default project) is renamed to `<suffix>`, and the other same-install duplicates are removed. Cross-install name clashes are never clobbered (ADR-0020 decision 4's client guard still holds).

## Consequences

- `sc incus remote ls` shows one row per install (`jules`, not `jules-first`). Fewer, stable remotes.
- **Tradeoff (accepted):** raw `incus <suffix>:` shows only the *currently-switched* project. Addressing another project via raw incus needs `incus <suffix>: --project sc2-<tenant>-<other>` or a prior `sc project switch`. Under ADR-0020 you could `incus <suffix>-<other>:` any project without flags. For `sc` users nothing changes — `sc` always carries the project itself.
- `sc project switch` is now the single source of truth for the active project across `sc`, `sc incus`, and raw `incus`.
- Live installs (home, obelix, big) migrate their remotes to the `<suffix>` name on the next `sc login`; the collapse is idempotent and endpoint-scoped so a same-named tenant on another install is untouched.
