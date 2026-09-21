# Sandcastle troubleshooting

Symptom → what to check → fix. Start every diagnosis by confirming which install
and project you are on (`sc info`, `sc remote list`): acting on the wrong install
is the most common root cause and looks like every other failure.

## `sc ls` says "Sandcastle tenant … not found" or lists nothing

The active remote has no tenant for you, or you are on the wrong install.

```bash
sc remote list      # is the * on the install you meant?
sc info             # tenant + project as resolved
sc tenant list      # tenants this certificate can reach
```

`sc ls` is scoped to the active remote's install, so a same-named tenant of
another install on the same Incus daemon never shadows it. Switch with
`sc remote switch <name>`, or `SANDCASTLE_REMOTE=<name> sc ls` for one command.

An empty listing with a correct install simply means the **active project** has
no machines — try `sc ls -a`.

## `sc connect` hangs, times out, or cannot reach the machine

Work outward from the machine:

```bash
sc ls -a '*:<machine>'                 # does it exist, is it running, does it have an IP?
sc start <project>:<machine>
VERBOSE=1 sc c <project>:<machine> -- true 2>&1 | head -30
```

- **No IP in the listing** — the machine never got a DHCP lease. `sc create`
  polls for one (45s container / 90s VM) and can return with it still blank.
  Restart it and re-check.
- **Blank IP only on a cached listing** — `sc ls` detects that case and falls
  back to a live query, so a blank IP in the output is real, not staleness.
- **Reachability** — machines live on the tenant bridge and are reached over the
  tailnet subnet route. Confirm the route is both advertised and accepted:

```bash
tailscale status | head -20            # is this client a node?
tailscale status --json | grep -i route
ping -c1 <machine-ip>
```

  If the client is not on the tenant's tailnet with `--accept-routes`, or the
  sidecar's `/24` was never approved on the tailnet, nothing else will work.
  Approve it in the Tailscale admin console, or with an autoApprover rule for
  `tag:sandcastle`.

- **A machine created with `--bare`** has no sshd. `sc connect` reaches it over
  `incus exec` as root — a `bare` marker shows in `sc ls`.
- **Suspect the connect cache** — `SANDCASTLE_CONNECT_CACHE=0 sc c <m>` forces
  the live path. A rebuilt machine always takes the live path anyway, because its
  host key no longer matches what `known_hosts` pins.

## `REMOTE HOST IDENTIFICATION HAS CHANGED`

The machine was rebuilt and its host key changed. `sc c` is authoritative here —
it reads host keys over the Incus API and repairs the entry itself, printing
`known_hosts: update <fqdn> …` once. If a bare `ssh` produced the warning
instead, run `sc c <machine> -- true` to reconcile, then retry.

Accumulated debris from deleted machines:

```bash
sc ssh-key purge --dry-run    # see what would go
sc ssh-key purge --yes
```

## A hostname does not resolve

Query the tenant's own CoreDNS directly to separate a DNS-server problem from a
local-resolver problem:

```bash
sc status                                        # DNS suffix, and the sidecar's health
dig +short <machine>.<project>.<suffix> @<tenant-cidr>.3
dig +short <machine>.<suffix>          @<tenant-cidr>.3
```

- Answers at the sidecar but not locally → the local resolver is not forwarding
  the suffix. Re-run the client setup (`sc login` without `--skip-setup`), or
  clear stale state with `sc dns uninstall <tenant>` and log in again.
- No answer at the sidecar → the machine is not registered. Registration is
  event-driven within seconds, with a 30s reconcile loop as backstop; a machine
  that is stopped is not registered at all.
- The short `<machine>.<suffix>` alias exists **only** for the tenant's default
  project. NXDOMAIN for a machine in another project is correct.
- Nothing resolves at all → the sidecar or its tailnet route is down. Check
  `sc tailscale status`.

## A published route is `awaiting-dns` or serves no certificate

```bash
sc route                       # what this install supports, and the CNAME target
sc route status <hostname>
```

- `awaiting-dns` means the public DNS record does not exist yet. An auto-subdomain
  needs the operator's wildcard record; a custom `--hostname` needs your own CNAME
  onto the target `sc route` names.
- The **first HTTPS request issues the certificate** and is slow. A timeout on
  request one is not a failure.
- On a Cloudflare zone the record must be **DNS-only (grey cloud)**. A proxied
  record intercepts `:443`, HTTP-01 never reaches the host, and no certificate
  issues.
- A route that vanished after a rebuild is expected: deleting a machine prunes its
  routes within seconds. Re-publish.
- Every `sc route` command failing with "no route ingress" is an install-level
  decision — the operator must redeploy with `--route-ingress acme` or
  `acme-proxied`.

## `sc login` refuses to start or fails afterwards

- **"not a tailnet node"** — login requires the client to be on the tailnet
  *before* the device flow. Run `tailscale up --accept-routes` first, or pass
  `--skip-setup` to bypass both the precheck and the client-side setup.
- **The post-login verification halts** — it prints one ✓/✗ line per layer
  (tailscale up → accept-routes → route offered/primary → the probe egressing over
  the tailnet). Fix the first ✗; the advice is specific to that layer. "Answered
  via local address …, NOT the tailnet" means an overlapping local network is
  shadowing the route.
- **"the Tenant DNS Suffix is immutable"** — the tenant already exists with a
  different suffix. Use the existing one, or a different tenant.
- **`exec: "incus": executable file not found`** — login shells out to the Incus
  client. Install `incus-client`.
- **"Already logged in at …"** — the saved token still works. `--force` to
  re-authenticate.

## A command refuses without a prompt

Destructive commands prompt on a TTY and **error** without one. That is the
guard, not a bug: pass `--yes` when you mean it. Similarly, a bare machine name
matching two projects errors with the candidates listed rather than guessing —
qualify it as `project:machine`.

## A glob did nothing, or did too much

- Quote the pattern, always. An unquoted `*` is expanded by your shell first.
- A glob matching nothing is an error for lifecycle verbs. `sc ls` with a
  *project* glob that matches nothing lists nothing and exits 0; a *literal*
  project that does not exist is an error naming the tenant's projects.
- Globbing across installs needs all three parts (`'*:*:dev'`). A two-part
  reference is `[remote:]project` or `project:machine`.
- A lifecycle verb refuses the whole run if one install is unreachable, rather
  than acting on a partial sweep. `sc ls` does the opposite — it warns and shows
  what answered.

## Something looks stale or wrong and you want the truth

```bash
VERBOSE=1 sc ls -a 2>&1 | grep -i 'cache-backed\|incus api'
VERBOSE=1 sc c <m> -- true 2>&1 | grep 'connect cache'
sc-adm list <tenant>/<project>      # admin path: always live, never cached
sc incus list                       # raw incus against the tenant's project
```

The resource cache is fed by the Incus event bus and is silently stale by design;
`sc ls` refuses to pass on staleness it can detect. `sc-adm list` and `sc incus`
always query live.

## Appliance-side

```bash
sc-adm update --check      # appliance and sidecar versions vs the release
sc-adm tenant status <tenant>
sc-adm incus exec <remote>:<prefix>-auth-app --project <infra-project> -- \
  journalctl -u sandcastle-auth-app -n 100 --no-pager
```

Auth App and broker logs carry one line per request and per work span, with
durations. The Auth Hostname's signed-in `/logs` page shows the same rows, scoped
to the user (admins see everything).
