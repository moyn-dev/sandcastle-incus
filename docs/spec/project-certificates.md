# Project certificates

A Project Domain owns one DNS-01 certificate with SANs `<domain>` and
`*.<domain>`. Issuance and ARI renewal do not depend on any machine existing
or running. `sc project set-domain [project] domain` and project creation
with `--domain` kick reconciliation. Unsetting or replacing a domain drops
its project certificate; no revocation request is made.

`sc project status [project] --json` exposes `certState`, `certNotAfter`, and
`sans`. An omitted project uses the current project. Certificates use the
existing encrypted ACME storage, with reserved owner `@project` and a unique
index on `(tenant, project)` for that owner. Old machine certificate rows
for derived names are not renewed or revoked; they expire normally.

| Name | Certificate decision |
| --- | --- |
| `x1.tod0s.tc42.uk` (derived) | Project certificate |
| `admin-x1.tod0s.tc42.uk` (alias) | Project certificate |
| `admin.x1.tod0s.tc42.uk` | Per-name certificate |
| `web12.tc42.uk` | Per-name certificate |
| Public DNS Zone apex | Per-name certificate, subject to reservations |
| `*.x1.tod0s.tc42.uk` | Explicit wildcard certificate; no double wildcard SAN |

`sc create tod0s:x1 --alias admin-x1 --alias console-x1` claims aliases before
creating the machine, using the same compensation and dry-run path as
`--hostname` / `--fqdn`. Aliases must be one DNS label and need a Project
Domain. `sc hostname add|list|remove` treats aliases as explicit reservations;
the derived name cannot be removed or claimed as an explicit alias.
Names beneath another project's domain remain forbidden.

Machines carry the derived name and aliases in
`user.sandcastle.v2.public-hostnames`. A machine served entirely by the
project certificate has `user.sandcastle.v2.cert-state=project` and no
`cert-not-after`. Mixed machines retain per-name states, using `project`
for covered names and the earliest installed *per-name* expiry. `sc ls`
resolves the project's current state and expiry through the Auth App.

The reconciler pushes `/etc/sandcastle/project-domain` to select the active
shared certificate directory. On instance start and renewal it verifies
and installs `/etc/sandcastle/tls/<domain>/{cert,key}.pem` independently on
each machine. Caddy refresh renders exact one-label names against that
directory, preferring it to old per-machine certificates. It does not render
`*.<machine>.<domain>` unless explicitly requested with `sc hostname add`.
Clearing the selector on unset-domain prevents stale files from selecting
the old project certificate. The domain apex is not added to each machine's
hostname list. Private tenant-CA files and names are unchanged.

Raw `incus copy` needs no user-key overrides. The reconciler derives the new
name from the destination machine, discards copied aliases (their registry
reservations belong to the source), clears stale certificate metadata, and
converges DNS and Caddy. Deleting a machine removes its DNS records and has
no derived-name/alias certificate row to retain. Existing per-name orders
outside project coverage retain their previous renewal and retention rules.

All affected mutations support `--dry-run` and describe their certificate
decision. Deployment requires the updated Auth App, CLI and shared platform
payload (`caddy-setup`); updating only the CLI cannot change server issuance.
