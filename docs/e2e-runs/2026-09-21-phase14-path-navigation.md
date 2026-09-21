# E2E run — Phase 14: Sandcastle Path navigation (ADR-0030)

Date: 2026-09-21. Result: **14a–14i PASS**, with the notes below. Binary:
branch `feat/path-navigation` cross-compiled (`0.18.27-pathnav4`), pushed to
the client as `/usr/local/bin/sc` for the run and restored afterwards.

| | |
|---|---|
| Install | `big:sc-shared-e2e` (prefix `sh`, Auth Hostname `https://sh-shared.tc42.uk`, simulated GitHub), the Phase 13 install |
| Client | container `big:e2e-pdz-client`, enrolled remotes `thieso2sh` (tenant thieso2), `moyn` (Shared Tenant moyn-dev), `skorfmannsh`, `tcpdz` (another install, unreachable during the run) |
| Fixtures | `sc project create web`, `sc create web:dev`; removed again at the end |
| Driver | `incus exec big:e2e-pdz-client --env HOME=/root --cwd /tmp -- sh /tmp/phase14.sh` (transcript in this session; the `.sandcastle` lives in `/tmp`) |

| Step | Result | Evidence |
|---|---|---|
| 14a pwd | PASS | `/thieso2sh/thieso2/default`; JSON `level: project`, `config_path: /tmp/.sandcastle` |
| 14b cd | PASS | `sc cd web` → `/thieso2sh/thieso2/web`, `.sandcastle` `project: web`, `previous: …/default`; `sc cd nope` → `project nope not found in tenant thieso2 (projects: default, web)`; `sc cd ./dev` → `is a machine` (the protocol said `sc cd web/dev`, which from inside a project is five segments deep and says so; criterion amended) |
| 14c up | PASS after fix | `sc cd ..` → `level: tenant`, `previous`, `project: web` kept; `sc ls` → `default web`; `sc create x` → `not in a project (position /thieso2sh/thieso2)`; `sc connect dev -- hostname` → `dev.web.thieso2sh` (first run looked in `default` — connect never had the tenant-wide lookup; fixed in this branch); `sc connect nope` → `no machine "nope" in any project of tenant thieso2`; `sc cd -` → back to web |
| 14d globs | PASS | `sc ls '../*'` headers per project; `-d`, `-l` (`PROJECT DOMAIN IMAGE`), `-R`; `sc ls ../web/d*` → the machine path; `sc ls -d '../**'` → tenant, both projects, `web/dev`; `sc ls '/**/web/*'` → `/thieso2sh/thieso2/web/dev` and `/moyn/thieso2/web/dev` (the moyn remote's Auth App lists tenant thieso2 too) with one `warning: /tcpdz: … 502` (was printed twice; deduplicated); `sc stop /…/web/dev`, `sc start ./dev` act on `web:dev`; `sc restart '/**/dev'` refused because `tcpdz` was unreachable — the existing rule that a lifecycle sweep never acts on a partial set |
| 14e mkdir/rm | PASS | `sc mkdir ../api` creates `sh-thieso2-api`; `sc mkdir -p ../api2/dev` creates the project and `api2:dev`; `sc rm ../api --yes` → `deleted project api`; `sc rm -r ../api2 --yes` → `delete api2:dev`, `deleted project api2`; `sc mkdir /` and `sc rm ..` refused with the guidance |
| 14f home/root | PASS | `sc cd /` → `/`; `sc ls` → four remotes; `sc ls -l /` → `REMOTE TENANT PROJECT AUTH`; `sc ls /thieso2sh` → `moyn-dev thieso2`; `sc cd` → `/thieso2sh/thieso2/default` |
| 14g cross-remote | PASS (see note) | `sc cd /moyn/moyn-dev/default` switches the remote (`sc remote list` marks `moyn`) and `sc ls` shows `moyn-dev@moyn:default web`; `sc cd /moyn/skorfmann` → `tenant skorfmann is not accessible`; from moyn, `sc c /thieso2sh/thieso2/web/dev -- hostname` and `sc c thieso2sh:web:dev` connect without a durable switch (`sc pwd` unchanged), `sc stop`/`start` by path likewise. **Note:** connecting to `moyn:default:web` from either grammar, and even after a full `cd` into moyn, fails with `User does not have permission for project "sh-moyn-dev-default"`: the client's single certificate no longer covers the Shared Tenant's project (Phase 13 state), a certificate issue outside this feature. Two real defects were found and fixed on the way: the connect cache path ran before the remote rebind, and a rebind kept the current tenant instead of the remote's recorded one (`sc ls moyn:default` now reads `moyn-dev@moyn:default`) |
| 14h completion | PASS | `sc completion zsh` emits the script; `sc __complete cd ../` → `../default ../web`; `sc __complete connect ../web/` → `../web/dev`; `sc __complete cd /` → the four remotes with trailing `/` and `NoSpace` |
| 14i compatibility | PASS | inside a project `sc ls`, `sc ls -a`, `sc ls 'web:*'`, `sc c web:dev`, `sc project switch`, `sc remote switch`, `sc tenant switch` produce their Phase 7c/13 output; `.sandcastle` keeps only the pre-existing keys plus `previous` |
