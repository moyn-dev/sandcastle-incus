# Test protocol — e2e Phase 13, Shared Tenants (ADR-0029)

| | |
|---|---|
| Date | 2026-09-21 (UTC) |
| Branch / binary | `main` (uncommitted Shared Tenants work) @ `e13f22a`+, cross-compiled `bin/linux-amd64/sandcastle` |
| Operator | thies (driven by Claude Code from laptop `xp26`) |
| Install under test | **fresh**, nested Incus 7.4 in VM `big:sc-shared-e2e` (Debian 13, `sc-adm install-incus`), prefix `sh`, Auth Hostname `https://sh-shared.tc42.uk`, `--ingress cloudflare` (API-created tunnel), `--simulate-github-token`, CIDR pool `10.251.0.0/16`, Let's Encrypt staging |
| Client | container `big:e2e-pdz-client` (Debian trixie, tailnet node `100.103.96.69`); logins `thieso2` (key `~/.ssh/sandcastle_ed25519`) and `skorfmann` (`--ssh-public-key ~/.ssh/skorfmann_ed25519.pub`) |
| Protocol source | `docs/e2e-sc2.md` Phase 13; automation `scripts/e2e-shared-tenant.sh` driven from the laptop with `SANDCASTLE_E2E_ADMIN_EXEC="incus exec big:sc-shared-e2e --"` and `SANDCASTLE_E2E_CLIENT_EXEC="incus exec big:e2e-pdz-client --env HOME=/root --cwd /tmp --"` |
| Logs | `/tmp/e2e-phase13-run{1..6}.log` on the laptop |

## Result: ALL PASS (run 6)

| Step | Observed |
|---|---|
| 13a prerequisite | both Personal Tenants listed; `create tenant … --member never-logged-in` refused: ``member(s) never-logged-in have no Personal Tenant on this install; they must run `sc login` here first`` |
| 13b create | `Member thieso2 granted [sh-moyn-dev sh-moyn-dev-default]`, same for skorfmann; `tenant users moyn-dev` → both; `v2.members` = `skorfmann,thieso2`; sidecar `sh-moyn-dev` on the tailnet (`100.77.118.57`, route `10.251.2.0/24` auto-approved) |
| 13c switch | `sc tenant list` → `moyn-dev … member`; `sc tenant switch moyn-dev` → `Incus remote "moyn" points at shared tenant moyn-dev (project default)`; `sc remote list` shows `moyn` pinned to `sh-moyn-dev-default`; idempotent |
| 13d machine | `web` at `10.251.2.100`; `ssh -i sandcastle_ed25519 dev@…` and `ssh -i skorfmann_ed25519 dev@…` both `ok`; `authorized_keys` holds exactly the two members' keys |
| 13e project | skorfmann `sc project create api` (via the Auth App, `X-Sandcastle-Tenant: moyn-dev`); thieso2 after `sc tenant switch moyn-dev` sees `web` and creates `api:svc` (`10.251.2.247`) |
| 13f scoping | `sc hostname list web` answers for the shared tenant; `sc tenant switch thieso2` → `sc ls` no longer shows the shared machines |
| 13g revoke | `tenant revoke moyn-dev skorfmann` → `Tenant moyn-dev members: thieso2`; skorfmann's `sc tenant list` lacks it, `sc tenant switch moyn-dev` refused `not accessible`; the default profile's `ssh_authorized_keys` carries only thieso2's key afterwards |

## Defects caught live and fixed in the same session

1. **Shared client keypair, name-based grant** (run 1): two logins from one
   client share a keypair whose one trust entry is named after the first
   enrollment; `tenant create --member skorfmann` warned `restricted
   certificate "sandcastle-sh-skorfmann" not found`. Fixed: `GrantTenantMember`
   / `RevokeTenantMember` fall back to the entries holding the member's own
   Personal Tenant projects (never dead same-named entries).
2. **Directory selection overrides the switch** (run 2): `sc remote switch`
   writes a `.sandcastle` selection that wins over the global remote, so a
   member's `sc tenant switch` left commands on the personal remote. Fixed:
   the switch re-points the nearest selection file when one exists.
3. **Wrong user's token recorded for the shared remote** (run 5): the switch
   recorded the global config's last-login token under the shared remote; the
   other member's later switch was refused `not accessible`. Fixed: the
   caller's resolved credentials are recorded.
4. Script issues: `set -o pipefail` + `grep -q` reported successful commands
   as failures; `sc ls web` addresses a project, not a machine; the owner's
   key (`sandcastle_ed25519`) is not an ssh default identity.

## Environment notes

- The first install used `sh-shared.e2e.sc.tc42.uk`; Cloudflare's universal
  certificate covers one label under the zone, so the edge answered TLS
  handshake failures. Reinstalled as `sh-shared.tc42.uk` (tunnel + DNS of the
  first attempt deleted through the API).
- Post-run: the script's cleanup deleted the machines but `sc-adm tenant
  delete moyn-dev --yes` left the tenant's projects in place (needs
  `--purge`); the VM is disposable and was left running for inspection
  (`incus delete -f big:sc-shared-e2e` removes everything; the Cloudflare
  tunnel `sh-shared-tc42-uk` and DNS record remain to be deleted with it).
