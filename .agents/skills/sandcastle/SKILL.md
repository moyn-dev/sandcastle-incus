---
name: sandcastle
description: Drive Sandcastle from the shell with the `sc` and `sc-adm` CLIs. Use when creating, connecting to, listing, starting/stopping, or deleting Sandcastle machines; managing projects, public routes, base images, tenant DNS, trust, or SSH host keys; running `sc login` or enrolling a remote; operating an install with `sc-adm` (install, tenant/user provisioning, image aliases, fleet updates); or diagnosing a Sandcastle machine that will not connect, resolve, or serve a route.
---

# Sandcastle from the shell

Sandcastle provisions Incus containers and VMs, scoped by tenant and project,
reached over the tenant's own tailnet. `sc` is the tenant CLI; `sc-adm` is the
operator CLI. Both are the same binary, dispatching on `argv[0]`.

## Orient before you act

Every reference you type resolves against three ambient settings. Run this
first, every session, before any command that names a machine:

```bash
sc info          # tenant, project, remote (install), auth hostname, project list
sc remote list   # every enrolled install; * marks the active one
sc ls -a         # every machine in every project of the active install
```

`sc info --json` and `sc ls --json` give the same facts parseably. Read the
result rather than assuming: an install's project prefix, DNS suffix, and remote
name are all operator-chosen and differ per deployment.

Switch context with `sc remote switch <name>` (install), `sc tenant switch
<name>`, `sc project switch <name>`. The active **incus remote is the single
source of truth** for which install `sc` targets; `SANDCASTLE_REMOTE=<name>`
overrides it for one invocation.

## The model

```
Tenant                          the ownership / identity / DNS / tailnet boundary
 └── Project                    an Incus project; owns shared /home + /workspace volumes
      └── Machine               a container (CT) or VM; native Incus instance name
```

- A **machine reference** is `[[remote:]project:]machine`. Omitted parts fall
  back to the active install and project.
- A machine's DNS name is `<machine>.<project>.<suffix>`. Machines in the
  tenant's **default project only** also answer to `<machine>.<suffix>`.
- The same machine name may exist in several projects. A bare name that matches
  more than one is ambiguous — qualify it as `project:machine`.
- Machines are **not** tailnet nodes. They sit on the tenant's private bridge and
  are reached over the sidecar's advertised subnet route, so the client must be
  on the tenant's tailnet with `--accept-routes`.

## Everyday operations

```bash
sc ls                       # machines in the active project
sc ls -a                    # …across every project (PROJECT MACHINE TYPE FQDN IP CREATED STATE)
sc create dev               # create a container in the active project
sc create dev --vm          # …a VM instead
sc create web --image mybase --home-share
sc c dev                    # interactive shell as the login user
sc c dev -- uptime          # run one command, non-interactive
sc c backend:api -- uptime  # …in another project
sc start dev / sc stop dev / sc restart dev
sc delete dev --yes
sc fix dev                  # backfill maintenance fixups over SSH (idempotent)
```

`sc create` is idempotent about nothing — it fails if the machine exists.
Lifecycle verbs (`start`/`stop`/`restart`/`delete`) never create.

**Globs.** Every part of a reference accepts shell wildcards, so one invocation
acts on a set. Quote them so the shell does not expand them first:

```bash
sc ls 'gbrain:*'        # every machine in project gbrain
sc ls -a '*:web-*'      # web-* machines of every project
sc ls -a '*:*:dev'      # the dev machine of every project of every install
sc stop 'lc*'           # acts on each match, one report line per machine
```

Globbing the install part requires all three parts spelled out. A glob that
matches nothing is an **error**, never a silent no-op — except a project glob in
`sc ls`, which lists nothing and exits 0. A glob never creates a machine.

## Rules that bite

**`sc connect` creates the machine when it does not exist — after asking.**
`Machine dev does not exist in project default. Create it? [y/N]`; anything but
`y`/`yes` cancels. Non-interactively (which is how you run it) there is nobody
to ask, so the create is an **error** unless you pass `--yes` — `sc c --yes dev`
is the deliberate "create it" form. Confirm the name with `sc ls` first, or
reach for a lifecycle verb, which refuses an unknown name. `sc fix` still
creates silently.

**Destructive commands need `--yes` without a TTY.** `sc delete`, `sc project
delete`, `sc route delete`, `sc ssh-key purge` prompt interactively; with no
terminal the missing confirmation is an error, not a default-no. Pass `--yes`
deliberately.

**`sc c <m> -- …` quoting.** Several arguments are shell-quoted individually and
joined, so `sc c dev -- sh -c 'echo hi'` works. A *single* argument passes
through raw as a shell snippet, so `sc c dev -- 'ls -l /tmp'` is also correct.
Prefer the multi-argument form.

**`sc c` runs as the login user; `sc incus exec` runs as root.** Inside
`sc incus exec`, `$USER` is `root` and `$HOME` is `/root` — name the login user's
home explicitly. Use `sc incus exec` when you need root or when the machine has
no sshd.

**Never assume the Incus project prefix.** It is `<install-prefix>-<tenant>-<project>`
where the prefix is operator-chosen (the built-in default `sc` maps to `sc2`).
Read the real names from `sc remote list` (PROJECT column) or `sc ls -a`.

**`--json` everywhere, `VERBOSE=1` to see the path taken.** Every command takes
`--json` (or `--output json`). `VERBOSE=1` on stderr reveals whether `sc ls` /
`sc c` were served from the resource cache or fell back to a live Incus query.

**Most write commands take `--dry-run`.** Use it to render the plan before
mutating anything you are unsure of.

**A stale `sc` is announced, not enforced.** Update notices print once per 24h on
a TTY; `SANDCASTLE_NO_UPDATE_NOTIFIER=1` silences them.

## Command index

| Command | Purpose |
|---|---|
| `sc info` / `sc status` / `sc version` | active context / tenant health / CLI version |
| `sc ls`, `sc create`, `sc c`, `sc start\|stop\|restart\|delete`, `sc fix` | machine lifecycle |
| `sc project …` | create, delete, list, switch, per-project settings |
| `sc tenant …` / `sc remote …` | select tenant / manage and switch installs |
| `sc login` / `sc enroll` | device login and provisioning / enroll from a token |
| `sc route …` | publish a machine port to the public Internet |
| `sc image …` | save, list, remove reusable base images |
| `sc dns …` / `sc trust …` / `sc ssh-key purge` | local resolver / tenant CA / known_hosts |
| `sc tailscale …` | attach, detach, check the tenant sidecar |
| `sc incus …` / `sc incus-infra …` | raw incus, scoped to the tenant's app / infra project |
| `sc payload-sync` / `sc update` | converge the `/.sc` platform payload / update CLI + sidecar |
| `sc config set\|show\|unset` / `sc cloud-identity …` / `sc share …` | local config / GCP federation / storage shares |
| `sc-adm …` | operator plane — see `reference/admin.md` |

`--help` on any command is the authority for its flags. The reference files below
carry the semantics and gotchas `--help` does not.

## Reference

- **`reference/operations.md`** — per-area recipes and semantics: projects,
  public routes, base images, DNS and trust, the `/.sc` payload, SSH host keys,
  updates, cloud identity, and the raw-`incus` escape hatch.
- **`reference/admin.md`** — the `sc-adm` operator plane: installing a
  sandcastle, provisioning tenants and users, image aliases, appliances, and
  fleet updates.
- **`reference/internals.md`** — naming rules, Incus project and bridge layout,
  files on disk, environment variables, and JSON output shapes.
- **`reference/troubleshooting.md`** — symptom → diagnosis → fix for connect,
  DNS, tailnet, route, login, and listing failures.
