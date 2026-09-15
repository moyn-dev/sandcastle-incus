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

## A newly published public hostname does not resolve yet

`sc tailnet publish` claims a Machine Public Hostname; the Auth App then
asynchronously converges its DNS-only Cloudflare A record. Check the public
record before changing anything else:

```bash
dig @1.1.1.1 <hostname> A +short
```

If that returns the Machine private IP, Cloudflare has the record. A prior
NXDOMAIN is likely cached by the client; flush the local cache and retry:

```bash
# Linux (systemd-resolved)
resolvectl flush-caches

# Linux (nscd, if installed instead)
sudo nscd -i hosts

# macOS
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder

# Windows PowerShell (or use `ipconfig /flushdns` in Command Prompt)
Clear-DnsClientCache
```

Then compare the public and local views. If they differ, inspect the DNS
resolver and Secure DNS setting used by the application (browsers can bypass
the operating-system resolver):

```bash
dig @1.1.1.1 <hostname> A +short
getent ahostsv4 <hostname>       # Linux local resolver
```

## A machine with a public name shows `CERT pending`, Caddy is inactive, or HTTPS refuses

A machine with Machine Public Hostnames — the derived `<m>.<domain>` of a
project with a Project Domain and/or explicit `sc hostname` names (`sc ls`
FQDN `<first name> (+N)`) — gets **one certificate per name pushed by the Auth
App's zone reconciler**, not fetched at boot. The reconciler runs every 30 s,
on instance events and on every `sc hostname add|remove`; a fresh name
normally goes `pending` → (order, 1–3 min with DNS-01 propagation) → `issued` →
`installed` within about five minutes of cloud-init finishing. Until then
`pending` is the designed state; Caddy is running the whole time, serving the
Machine Private Hostname with the Tenant CA leaf.

**States are per name.** `user.sandcastle.v2.cert-state` reads
`<name>=<state>[,<name>=<state>…]` (sorted by name); `sc project status` shows
one row per name; `sc ls` CERT folds the machine to its **worst** name
(`failed` > `pending` > `issued` > `renewing` > `installed`), so a machine with
one name still pending reads `pending` even though the others already serve —
read `sc project status` (or the key) to see which one. `cert-not-after` is
the machine's earliest installed expiry.

```bash
sc ls                                                   # FQDN <m>.<domain>, CERT pending|ok|failed
sc project status <project>                             # per-machine PUBLIC NAME / CERT / NOT AFTER / DETAIL
sc incus config get <m> user.sandcastle.v2.public-hostnames  # the machine's public-name set (ADR-0028; the single public-hostname key is legacy)
sc incus config get <m> user.sandcastle.v2.cert-state   # <name>=<state>,… — pending | issued | installed | renewing | failed:<reason> per name
sc incus config get <m> user.sandcastle.v2.cert-not-after    # earliest expiry among the INSTALLED certificates
dig +short <m>.<domain> @1.1.1.1                        # the public A record → tenant-bridge IP
sc incus exec <m> -- cat /etc/sandcastle/caddy.ready    # marker: PRIVATE=<m>.<p>.<suffix> / PUBLIC=<name> per served name / RENDERED=<ts>
sc incus exec <m> -- cat /etc/sandcastle/hostnames      # the machine's public-name set, one per line
sc incus exec <m> -- systemctl is-active caddy          # active (always — the private name has a certificate from the first boot)
sc incus exec <m> -- ls -R /etc/sandcastle/tls          # cert.pem + key.pem (private leaf) + <name>/cert.pem,key.pem per pushed name
sc incus exec <m> -- /usr/local/sbin/sandcastle-caddy-setup --refresh   # re-render + reload by hand (idempotent)
openssl s_client -connect <bridge-ip>:443 -servername <m>.<domain> </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName -issuer     # both SANs + the Let's Encrypt issuer
sc-adm incus exec <remote>:<prefix>-auth-app --project <infra-project> -- \
  journalctl -u sandcastle-auth-app --no-pager | grep "zone reconcile: <m>.<domain>"
```

Reading the states (`sc project status` CERT column, one row per name; `sc ls`
folds a machine to its worst name):

| state | meaning | what to do |
|---|---|---|
| `pending` | no certificate yet, no error | wait; check the marker (below) and the auth-app log for the order |
| `issued` | certificate held by the Auth App, not on the machine yet | machine stopped, or the marker gate refused — start it / check the marker |
| `installed` | pushed and confirmed; `NOT AFTER` is its expiry | nothing |
| `renewing` | installed and past the ARI renewal window; a renewal order is due or failing | the old certificate still serves; a `DETAIL` here is the last renewal error |
| `failed:<reason>` | no valid certificate and the last order failed; in backoff (1m, 5m, 30m, 2h, 6h) | read `DETAIL` (the `<reason>` token) and the auth-app log for the full ACME problem; fix the cause, the reconciler retries on schedule |

`<reason>` is one of `rate-limited` (Let's Encrypt budget — 50 per zone per
week, 5 per identifier set per week; wait for the window), `dns-propagation`
(the `_acme-challenge` TXT was not visible in time — resolver or Cloudflare
lag), `cloudflare-rejected` (the zone token lost DNS:Edit — `sc-adm
public-dns-zone set-token`), `validation`, `auth-app-unreachable`, `expired`,
`other`.

- **Marker missing** (`cat` fails) — cloud-init has not finished
  (`sc incus exec <m> -- cloud-init status --wait`), the machine is a Dev Image
  machine (no Caddy, no certificate — by design), or `caddy-setup` failed
  (`sc incus exec <m> -- journalctl -u cloud-final`; a failed `caddy validate`
  leaves no marker). The Auth App never pushes without a per-name marker.
- **Marker says `MODE=…`** (a legacy ADR-0027 marker; the auth-app log reads
  `does not clear the push gate … (legacy)`) — the machine ran an older
  `caddy-setup`. Converge the payload (`sc payload-sync`) and recreate the
  machine; a machine created under the retired ADR-0027 contract has no private
  leaf and no per-name directories and is not migrated in place.
- **Marker has `PRIVATE=` but no `PUBLIC=<name>` line** — the name's
  certificate has not been pushed yet (`CERT pending`/`issued`), or
  `/etc/sandcastle/hostnames` does not list it. Check the file; after a push
  the block appears on the next `--refresh` (the reconciler runs it; running it
  by hand is safe).
- **Name listed, certificate directory complete, still not served** — run
  `sandcastle-caddy-setup --refresh` and read its output: a `caddy validate`
  failure names the offending block; the previous Caddyfile keeps serving.
- **Caddy `inactive`** — not expected any more (the private block always has
  a certificate). `journalctl -u caddy` for the reason; `--refresh` starts it
  when the render validates.
- **`CERT failed`** — `sc project status <project>` DETAIL carries the reason
  token only; the reconciler retries with backoff (see the table above). The
  raw error is in the auth-app log line `zone reconcile: <m>.<domain>: order
  failed: …` (the full ACME problem). No CLI command reads the Auth Database;
  the row's `last_error` is reachable only with `sqlite3` inside the appliance
  (`/var/lib/sandcastle/auth/auth.db`, table `machine_certificates`), which the
  stock image does not carry.
- **`CERT pending` for every machine of the tenant, with A records present and
  no marker anywhere** — the tenant's `/.sc` payload predates the zone-aware
  `caddy-setup` (provisioned by an older binary). Converge it once:
  `sc payload-sync` (tenant, after `sc update`) or `sc-adm tenant payload-sync
  <tenant>`; then recreate the affected machines (their setup already ran).
  The per-name `caddy-setup` of ADR-0028 is a new payload version too — the
  same convergence applies before machines get explicit hostnames.
- **`issued` that never becomes `installed`** — the machine is stopped (start
  it; `instance-started` pushes within seconds) or the push failed: the log
  shows `push certificate to … : command exited with status …`; run the
  `caddy.ready` / `systemctl` checks above.
- **No A record** (`dig` empty) — the machine has no tenant-bridge address yet
  (booting; records follow the DHCP lease), the project's domain has no claim
  row (auth-app log: `carries user.sandcastle.v2.domain without a claim` — run
  `sc project set-domain`), or the zone token cannot edit DNS (log:
  `zone <zone>: set … A record(s): …`). A public name answering with a private
  address is also what DNS-rebind filters drop — allowlist the zone on the
  resolver.
- **Certificate serves but `openssl` shows an old serial** — the drift check
  re-pushes within a pass once the machine is running; if the on-disk
  `cert.pem` was edited by hand it is overwritten.
- **A name is missing from `/etc/sandcastle/hostnames` or still listed after
  `sc hostname remove`** — the reconciler pushes the file whole whenever it
  differs from the machine's set (add, remove, `set-domain`/`unset-domain`, an
  empty first-boot seed); the log line is `<m>: hostnames file pushed (…)`.
  It only reads the file of a running machine with a per-name marker that
  has, or recently had, a public name; after an Auth App restart a machine
  whose last name was removed just before is the one case it does not revisit
  — run `sandcastle-caddy-setup --refresh` after fixing the file by hand, or
  add/remove a name.
- **`sc project set-domain`/`unset-domain` with machines** — allowed (ADR-0028
  slice 3): the reconciler re-derives every machine's name within a minute
  (`stamped … public-hostnames=…`, records, a fresh certificate — the released
  domain's rows are dropped, so expect a new order), and pushes the hostnames
  file. Explicit hostnames are untouched.
- **Siblings unreachable over HTTPS from a machine with public names** — they
  should not be: every machine trusts the Tenant CA and serves its private
  name. Check `/usr/local/share/ca-certificates/sandcastle-tenant.crt` exists
  and `openssl s_client -servername <m>.<p>.<suffix>` returns the tenant leaf.

## A published route is `awaiting-dns` or serves no certificate

```bash
sc route                       # what this install supports, and the CNAME target
sc route status <hostname>
```

- `awaiting-dns` means the public DNS record does not exist yet. An auto-subdomain
  needs the operator's wildcard record; a custom `--hostname` needs your own CNAME
  onto the target `sc route` names.
- The **first HTTPS request issues the certificate** and is slow for exact
  routes and for wildcard routes on default installs. Operators serving an
  open-ended hostname set can redeploy with
  `--route-dns-cloudflare-wildcard '<authorized-hostname>'` together with
  `--route-dns-cloudflare-api-token` so the wildcard certificate is obtained
  through DNS-01 during reconciliation.
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
