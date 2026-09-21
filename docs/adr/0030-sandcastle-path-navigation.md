# ADR-0030: Sandcastle Path navigation — cd, pwd, ls, mkdir, rm over /remote/tenant/project/machine

Date: 2026-09-21. Status: accepted. Wayfinder map: issue #190.

## Context

The user CLI addresses machines with the colon grammar of ADR-0020,
`[tenant@][[remote:]project:]machine`, and moves its ambient remote, tenant
and project with three switch commands that write the nearest `.sandcastle`.
The four levels — remote (install), tenant, project, machine — already form a
tree, but the CLI offered no way to stand in it, look around, or move with
the muscle memory every shell user has. `sc ls` could span installs with
globs, yet nothing listed tenants or projects as children of anything, and
no command registered shell completion.

Constraints: everything additive (CLAUDE.md); the colon grammar, the switch
commands, `sc ls`'s output and JSON, and the `.sandcastle` written by a
selection that never moved must stay as they are.

## Decision

1. **A second grammar, selected by shape.** A **Sandcastle Path** is
   `/remote/tenant/project/machine`. An argument is a path iff it starts with
   `/`, `./`, `../`, `~/` or is exactly `.`, `..`, `~`, `-`. Every other
   argument is the colon grammar, untouched. Relative paths resolve against
   the **Current Position**; `..` above the root stays at the root; `~` is
   the global config's remote/tenant/project (the layer below every
   `.sandcastle`); `-` is the previous position. Any segment may be a glob,
   and `**` matches across levels: zero or more directories in a listing,
   and as many `*` as reach a machine in a machine reference (`/**/dev` is
   `*:*:dev`; the first `**` absorbs them all).
2. **One conversion point.** A machine-level path becomes the colon reference
   `remote:project:machine` inside the two functions every machine command
   already calls (`rebindForReference`, `narrowRemoteGlob`), so `create`,
   `connect`, `start/stop/restart/delete`, `fix`, `image save`, `hostname`,
   `tunnel`, `tailnet` all accept paths without a second parser. The tenant
   segment must be the tenant the remote serves (ADR-0021); a remote that is
   not enrolled is an error with the enroll guidance, never auto-enrolled.
3. **The position lives in `.sandcastle`.** `sc cd` composes the three
   switches in tree order and reloads config between them; it then records
   `level` (`root|remote|tenant`, only when above a project) and `previous`.
   `remote` and `project` stay mandatory and filled, so an old `.sandcastle`
   is a valid position and a new one keeps the remembered project. There is
   no per-terminal position.
4. **Above a project.** Creating commands refuse a bare name (`not in a
   project`); reading and acting commands resolve it with the existing
   tenant-wide unique search; `sc ls` lists the children of the position
   and reads bare arguments as children. A machine is a leaf: `cd` into one
   errors and points at `sc connect`.
5. **`ls` is shell-faithful with one exception.** A matched directory lists
   its children; several matches, or any globbed argument, print each under
   a `path:` header (the exception: a shell prints one match bare, but a
   glob matching one empty project would then print nothing). `-d` names,
   `-l` a per-level table, `-R` recursion. Inside a project without path
   arguments or path flags, `sc ls` is the unchanged colon listing.
6. **`mkdir` and `rm` act on projects and machines only.** `mkdir` is
   `project create` (Auth App tenant plane) or `create`, `-p` both; `rm`
   extends `delete`: a project path deletes the project (empty, or `-r` for
   its machines first). Remotes and tenants keep their own commands.
7. **Completion is cobra's.** The default `completion` command is documented;
   path arguments complete level by level from the same sources `ls` reads,
   within a 3 s budget, no cache of its own.

## Consequences

- The tree has one vocabulary: **Sandcastle Path**, **Current Position**
  (CONTEXT.md). Messages print the Sandcastle Path (`/obelix/thieso2/work/dev`)
  wherever the remote and tenant are known — amended 2026-09-21; the first
  cut kept `tenant@remote:project:machine`, which is still accepted on input.
- A binary older than this ADR rejects a `.sandcastle` carrying `level` or
  `previous` (strict YAML); `sc update` resolves it, and a selection that
  never ran `cd` above a project is unchanged on disk.
- Out of scope, recorded on map #190: the admin CLI over all tenants,
  creating tenants or enrolling remotes via `mkdir`, machine facets as
  children (`cat dev/hostname`), `mv`/`cp`, a per-terminal session
  position, a REPL, a completion cache.

## Prior art

Issue #191 surveyed lftp/sftp (stateful `cd` with verification and
per-site `cd -` history), gsutil/gcloud storage (server-side prefix plus
client-side filter, `-d`, a 15 s completion cache), rclone/s3cmd/mc/aws/az
(no `cd`; root lists buckets), vault/nomad/consul (server-side prefix
lists, `complete -C` binary callbacks), pulumi/terraform/kubectl (position
persisted in a file under the config dir or the working tree). Sandcastle
takes lftp's stateful, validated `cd` and `cd -`, gsutil's `-d`/`-l`/`-R`
and header-per-directory listing, and kubectl's file-backed position.
