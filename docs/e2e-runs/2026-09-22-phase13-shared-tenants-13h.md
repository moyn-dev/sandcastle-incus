# E2E run — Phase 13 (Shared Tenants) with 13h: a device enrolled after the grant

Date: 2026-09-22. Result: **13a–13h ALL PASS** (`scripts/e2e-shared-tenant.sh`, exit 0).

| | |
|---|---|
| Install | `big:sc-shared-e2e` (prefix `sh`, Auth Hostname `https://sh-shared.tc42.uk`, simulated GitHub); Auth App running the fixed binary (`0.19.5-memberfix`, pushed into `sh-infra/sh-auth-app`, service restarted) |
| Client | `big:e2e-pdz-client`, same binary as `sc`; driven from the laptop with `SANDCASTLE_E2E_ADMIN_EXEC="incus exec big:sc-shared-e2e --"` and `SANDCASTLE_E2E_CLIENT_EXEC="incus exec big:e2e-pdz-client --env HOME=/root --cwd /tmp --"`, `SANDCASTLE_E2E_PREFIX=sh`, `SANDCASTLE_E2E_AUTH_HOST` / `SANDCASTLE_E2E_SIMULATE_TOKEN` / `TAILSCALE_AUTH_KEY` read off the appliance's env |
| Why | `sc tunnel publish` in a shared project on a laptop enrolled after the membership answered `User does not have permission`: the login had minted a certificate scoped to the Personal Tenant only |

**13h**: as skorfmann with a fresh `HOME` on the client, `sc login … --simulate-token … --as skorfmann --ssh-public-key …` then `sc tenant switch moyn-dev`; `sc incus list` on the shared default project lists `web` and on `sh-moyn-dev-api` lists `svc`. Before the fix the new device's certificate carried `sh-skorfmann*` only and both calls were refused.

Three runs were needed; the first two failed in the harness, not the product:

1. 13d timed out waiting for sshd: the recreated tenant's `10.251.2.0/24` route stayed on the deleted sidecar's stale tailnet node until failover (several minutes). The wait is now 600 s.
2. 13h failed with `CLI Auth Token is required`: the new-device commands ran from `/tmp`, whose `.sandcastle` (the first identity's selection) named a remote the new config never enrolled, so its credentials were dropped. The new-device steps now run from inside the new HOME. The script also read the login user off the machine record (`moyn-dev`, not `dev`) and follows the names-only `sc tenant list` (`-l` for the role).

The cleanup deleted the tenant at the end; the client keeps the test binary.
