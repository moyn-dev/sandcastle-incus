# ADR-0032: The Sandcastle Path starts at the install

Date: 2026-11-14. Status: proposed. Amends ADR-0030 decision 1 (the first
path level) and the printed form in its Consequences. Builds on ADR-0017
(Incus Reach), ADR-0021 (one remote per install) and ADR-0029 (Shared
Tenants).

## Context

ADR-0030 defines the Sandcastle Path as `/remote/tenant/project/machine` and
reads the first level as "remote (install)". That held while ADR-0021 gave
each install one Incus remote. It no longer holds. Since ADR-0017 every
tenant has its own sidecar, and a client's Incus remote points at that
sidecar's tailnet address. ADR-0029 then let one user reach several tenants
on one install, each through its own remote.

So the first level is a remote per (install, tenant), not an install. A
client enrolled in obelix (four tenants), idefix (one) and miraculix (two)
sees this root:

```
/asterix              obelix     tenant skorfmann   (remote named after the tenant's DNS suffix)
/obelix               obelix     tenant thieso2
/moyn-dev             obelix     tenant moyn-dev
/sevenhaven           obelix     tenant sevenhaven
/idefix               idefix     tenant thieso2
/thies                miraculix  tenant thies
/moyn-dev-miraculix   miraculix  tenant moyn-dev
```

Four faults follow:

1. **The install is invisible.** Nothing in the tree says that the first
   four entries share one Auth App, or that `/thies` and
   `/moyn-dev-miraculix` share another.
2. **The second level carries no information.** A remote serves exactly one
   tenant, so `/X` always has one child.
3. **Names mislead.** `/obelix` is thieso2's DNS suffix, not the obelix
   install. `/asterix` names no install at all.
4. **Tenant names collide across installs.** obelix and miraculix both have
   `moyn-dev`. The client needs a second remote name (`moyn-dev-miraculix`,
   v0.22.5), and that name leaks into every printed path.

## Decision

1. **The first level is the install.** A Sandcastle Path is
   `/install/tenant/project/machine`. The install segment is the **Install
   Name**: the first DNS label of the install's Auth Hostname (`obelix` for
   `https://obelix.thieso2.dev`, `miraculix` for
   `https://miraculix.moyn.dev`). When two enrolled installs share a first
   label, both use the full Install Label of `InstallLabelFromAuthHostname`
   (`obelix-thieso2-dev`). The set of installs is the set of distinct Auth
   Hostnames in the client config (`installs`, `auth_tokens`).
2. **The second level is every tenant the user can reach on that install.**
   `sc ls /miraculix` asks that install's Auth App (`/api/tenants`) and
   lists its accessible tenants. Offline, it lists the tenants recorded for
   the install's remotes (`remote_tenants`) and says the list may be
   incomplete.
3. **The remote becomes a resolved detail.** A path resolves
   (install, tenant) to the enrolled remote whose `installs` entry is the
   install's Auth Hostname and whose `remote_tenants` entry is the tenant.
   Remote names keep their current rules (DNS suffix, plus the install
   suffix of v0.22.5 on a clash) and stay what raw `incus <remote>:` and the
   colon grammar use. They no longer appear in paths.
4. **Entering a tenant enrols it.** `sc cd /miraculix/moyn-dev` with no
   enrolled remote for that pair runs the `sc tenant switch` enrollment
   against that install's Auth App, as ADR-0029 already does for members.
   ADR-0030's rule "never auto-enrolled" covers remotes only; a tenant the
   Auth App lists is one the user may enter. A tenant the Auth App does not
   list is an error naming the install.
5. **Old paths keep working.** When the first segment is not an Install Name
   but is an enrolled remote, the path is rewritten to
   `/<install>/<remote's tenant>/…` and the command prints the canonical path
   once. When a segment is both an Install Name and a remote name (`obelix`,
   `idefix` today), the install reading wins. On this client both readings
   reach the same tenant for `/obelix/thieso2` and `/idefix/thieso2`, so no
   existing path changes its target.
6. **`.sandcastle` keeps its fields.** `remote`, `project` and `tenant` stay
   the stored position; the install is derived from `remote`. `level` gains
   the value `install`; `remote` stays accepted as its alias, so a binary
   from this ADR reads every existing selection. `previous` is written in the
   new form and read in either.
7. **Printed paths and JSON.** Messages print the install form
   (`/miraculix/moyn-dev/default/smoke`). Machine-bearing JSON keeps `path`,
   now in the install form, and adds `remote_path` with the ADR-0030 form for
   one minor release, so scripts can move over.
8. **Completion** offers Install Names at the first level and the Auth App's
   tenant list at the second, within ADR-0030's 3 s budget.

## Consequences

- `sc ls -R /` groups machines the way the platform does: install, tenant,
  project (an Incus project `<prefix>-<tenant>-<project>`), machine (an
  Incus instance). The per-tenant remote, the infra project and the tenant
  bridge stay hidden, as before.
- The `moyn-dev` collision disappears from paths: `/obelix/moyn-dev` and
  `/miraculix/moyn-dev` are distinct by construction.
- `sc ls /miraculix` costs one Auth App call. Offline listings fall back to
  recorded state and say so.
- `path` in JSON changes value. `remote_path` covers the transition; drop it
  in the release after next.
- The colon grammar is unchanged and still addresses remotes. Unifying it
  with paths is out of scope.
- CONTEXT.md: **Sandcastle Path** becomes `/install/tenant/project/machine`;
  add **Install Name**; **Current Position** lists the levels root, install,
  tenant, project.

## Alternatives considered

- **Keep remotes at the root, rename them `<install>-<tenant>`.** Fixes the
  misleading names but keeps faults 1 and 2, and every remote name changes
  for raw `incus` users.
- **`/tenant@install/project/machine`.** One level fewer, but it makes the
  install part of every tenant name and does not let `ls` list installs.
- **Install as a filter flag (`sc ls --install miraculix`).** Leaves the
  tree wrong and adds a second way to say the same thing.
