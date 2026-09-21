# ADR-0029: Shared Tenants — membership in Tenant Metadata

Date: 2026-09-21. Status: accepted.

## Context

Sandcastle tenants were personal by construction: the Auth App identified a
tenant's owner by name equality with the caller, every tenant-plane API acted
on the caller's tenant, and a tenant's machines carried one SSH key. Two
users (thieso2 and skorfmann) need one tenant, `moyn-dev`, they both operate.

## Decision

1. **Membership is Tenant Metadata.** A Shared Tenant's members live on its
   infra Incus project (`user.sandcastle.v2.members`), next to the tenant's
   other stored settings — not in the Auth Database. The admin CLI grants
   directly against Incus without an Auth App; a database table would let the
   two grant paths disagree. The Auth App reads the same key.
2. **Members' keys come from their Personal Tenants.** A member's login key is
   already stored on `<prefix>-<member>`; shared profiles render the union of
   the tenant's own keys and every member's keys. Keys are attributed to
   members by construction, so a revoke or a rotation never has to guess
   which key was whose. This makes "logged in on this install" the hard
   prerequisite for membership.
3. **Requests carry the Current Tenant.** The CLI stamps `X-Sandcastle-Tenant`
   on every Auth App call; the server authorizes it with one rule
   (`Summary.Accessible`). Absent header = the caller's Personal Tenant, so
   the change is additive.
4. **A member enrols the tenant's remote on `sc tenant switch`.** The Incus
   Reach is per tenant (the sidecar's tailnet IP), so the member's client gets
   a remote named after the tenant's DNS suffix (ADR-0021), certificate-based
   (their keypair is already trusted and the grant extended it). Login is not
   touched.

## Consequences

- `sc-adm tenant grant` now covers every app project of the tenant and, on
  `--prefix` installs, addresses the certificate a device login actually
  enrolled (`sandcastle-<prefix>-<user>`).
- The `v2.sshkey` value may hold several lines; every profile renderer and
  the profile key regexp handle the list.
- Per-member roles or project-scoped grants remain out of scope; all members
  share the tenant's unix user.
