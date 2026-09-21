# Shared Tenants

Status: implemented 2026-09-21 (ADR-0029). E2E: `docs/e2e-sc2.md` Phase 13,
`scripts/e2e-shared-tenant.sh`.

## Problem

Every tenant used to be a Personal Tenant: the Auth App decided "who may act
on tenant X" by comparing X with the caller's GitHub username, every
tenant-plane API acted on the caller's own tenant, the admin grant only
covered the `default` project, and a tenant's machines authorized exactly one
SSH key. Two people could not share one tenant.

## Prerequisites

- Every member has completed `sc login` on the install. Their Personal
  Tenant is where the member's login SSH key lives (`v2.sshkey` on
  `<prefix>-<member>`), and their client keypair is already trusted by the
  daemon. A member without a Personal Tenant is refused, never silently
  added.
- Every member and the shared tenant's sidecar are nodes on the same tailnet
  (the tenant's tailnet is BYO, ADR-0017).

## Model

| Where | What |
|---|---|
| infra project `<prefix>-<tenant>`, key `user.sandcastle.v2.members` | comma-separated normalized user keys: the Tenant Members. Absent on a Personal Tenant. |
| infra project, key `user.sandcastle.v2.sshkey` | the tenant's own keys, one per line. First line: the tenant's login key (rotated by the owner's login). Further lines: `sc-adm tenant add-ssh-key`. |
| app project profiles (`default`, `homeshare`) | `ssh_authorized_keys` = own keys + every member's Personal Tenant keys, re-rendered on every membership or key change. |
| the members' restricted certificates | extended with the infra project and **every** app project (not only `default`); `sc project create` by one member extends the others'. A member's devices are found by certificate name or, under shared client identity (one keypair enrolled by several logins), by the entries holding the member's own Personal Tenant projects. |

Access rule (`tenant.Summary.Accessible`): a Personal Tenant belongs to the
user whose key names it; a Shared Tenant admits its members. The Auth App
uses it in `/api/tenants` (`sc tenant list/switch`), the shares APIs, the
workload authorization, and the machines web UI.

Request scoping: the CLI sends its Current Tenant as `X-Sandcastle-Tenant`
on every Auth App call. The projects APIs, sidecar update, and the shares
default read it; hostnames, certificates, routes, and resources already
carried an explicit tenant field. No header means the caller's Personal
Tenant, so pre-existing clients are unaffected.

## Commands

Admin (direct Incus, no Auth App needed):

```
sc-adm create tenant moyn-dev --member thieso2 --member skorfmann \
    --tailscale-authkey tskey-… --dns-suffix moyn [--ssh-key … --ssh-key …]
sc-adm tenant grant  moyn-dev alice     # cert scope + membership + profiles + running machines' key
sc-adm tenant revoke moyn-dev alice
sc-adm tenant users  moyn-dev
sc-adm tenant add-ssh-key    moyn-dev "ssh-ed25519 …"
sc-adm tenant remove-ssh-key moyn-dev "ssh-ed25519 …"   # the last key cannot go
sc-adm tenant set-ssh-key    moyn-dev "ssh-ed25519 …"   # replace the whole list
```

The web page `/admin/access` performs the same grant/revoke transition,
fingerprint-first against the member's recorded client certificate.

Member:

```
sc tenant list                # Role column: owner | member
sc tenant switch moyn-dev     # enrols the remote "<dns suffix>" at the tenant
                              # sidecar's tailnet IP, pins the default project,
                              # records token/broker/install for that remote
sc create web; sc connect web # as usual — the machine authorizes every member's key
sc tenant switch thieso2      # back: re-activates the personal remote
```

`sc login` is unchanged: it always provisions the caller's Personal Tenant;
memberships appear through `sc tenant list`. A member's key rotation at
login re-renders every shared tenant they belong to and enrols the new key
on those tenants' running machines.

## Not in scope

Per-member roles, per-project grants, and member-specific unix users. All
members log in as the tenant's unix user.
