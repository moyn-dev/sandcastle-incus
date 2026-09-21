# Sandcastle operator plane (`sc-adm`)

`sc-adm` (aliases: `sandcastle-admin`; also reachable as `sc admin …`) manages
installs, tenants, users, images, and appliances. It uses the **global**
`~/.config/incus/` admin certificates, while the tenant CLI uses the per-remote
restricted certificates — that split must survive any change.

`sc admin update` targets the install `sc ls` is on. `sc-adm` on its own follows
the ambient Incus default remote unless `SANDCASTLE_REMOTE` or `admin_remote`
says otherwise. On a host with several sandcastles, name the target explicitly.

## Installing a sandcastle

```bash
sudo sc-adm install-incus            # Zabbly stable Incus + `incus admin init --minimal`; idempotent
sc-adm install \
  --auth-hostname auth.example.com \
  --admin-github-users alice,bob \
  --github-client-id … --github-client-secret … \
  --ingress cloudflare --cloudflare-api-token … \
  --route-ingress acme --acme-email ops@example.com \
  --prefix sc --cidr-pool 10.248.0.0/16
```

`sc-adm install` deploys both appliances — the **Auth App** (GitHub login, device
login, tenant provisioning, the OIDC provider, the DNS reconciler) and the
**Broker** (privileged tenant and project lifecycle) — sharing one tenant CIDR
pool. It refuses to run when an install under the same `--prefix` already exists
on the host. `sc-adm auth-app deploy` and `sc-adm bootstrap` deploy the two
pieces separately.

Decisions worth getting right the first time:

- **`--prefix`** scopes tenant project names and appliance names, so several
  sandcastles share one Incus host. It is baked into every name; changing it
  later means a new install.
- **`--ingress`** for the Auth Hostname: `cloudflare` (outbound tunnel, no
  inbound ports — the installer can create the tunnel, ingress rule, and DNS
  record itself given `--cloudflare-api-token`), `acme` (binds host `:80`/`:443`
  for Let's Encrypt; needs a public IP and an A record), or `none` (bring your
  own edge).
- **`--route-ingress`** is independent of `--ingress`, so public routes can run
  beside a tunnelled login host: `acme` binds the host ports, `acme-proxied`
  terminates route TLS in the appliance behind an upstream SNI proxy that owns
  them. Empty disables `sc route` for every tenant on the install.
- **`--cidr-pool`** must not overlap the host's own network, `incusbr0`, other
  bridges, or another install sharing a tailnet. The allocator sees existing
  tenants, not arbitrary host subnets — an overlap fails at bridge creation with
  `dnsmasq: Address already in use`.
- **`--bridge`** empty (the default) creates a per-install bridge `<prefix>-net`
  so appliances share no network object with another install.
- **`--simulate-github-token`** enables a token-gated `/oauth/github/simulate`
  endpoint for unattended login (`sc login --simulate-token … --as <user>`). It
  coexists with real OAuth. Treat the secret like a password; it is a dev and
  e2e facility.

## Tenants

```bash
sc-adm tenant list                 # every tenant on the install
sc-adm tenant list <tenant>        # every resource in one tenant
sc-adm tenant status <tenant>
sc-adm tenant create acme --dns-suffix acme --initial-project default \
  --unix-user dev --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" --tailscale-authkey …
sc-adm tenant grant acme alice     # give a restricted user access
sc-adm tenant revoke acme alice
sc-adm tenant users acme
sc-adm tenant set-ssh-key acme "ssh-ed25519 …"
sc-adm tenant payload-sync acme --check
sc-adm tenant delete acme --purge --yes
```

Normal tenants are provisioned automatically by the Auth App on a user's first
`sc login`; `sc-adm tenant create` is the admin-minted path. `--dry-run` renders
the plan first — use it.

**`sc-adm tenant create` re-run without `--unix-user` / `--ssh-key` overwrites the
stored values with defaults**, breaking login for that tenant. Repair through the
product path: an `sc login` against the auth-app re-renders the profile.

`--purge` on delete removes durable tenant volumes and the Incus project. Without
it the volumes survive. The Tenant DNS Suffix is immutable, so a tenant
provisioned before a fix keeps its original suffix — use a fresh tenant name to
retest.

## Users and projects

```bash
sc-adm user create alice --tenant acme     # restricted cert + join token
sc-adm user token alice --tenant acme      # another certificate add token
sc-adm user delete alice --yes
sc-adm project create acme backend         # scaffolding only; does NOT extend the cert
sc-adm project delete acme backend --yes   # machines, volumes, profiles, Incus project
sc-adm list acme/backend                   # machines in a tenant/project, queried live
```

The admin `project create` scaffolds only. The tenant's own `sc project create`
goes through the broker, which scaffolds **and extends the tenant's restricted
certificate** to cover the new project. Prefer the tenant path.

## Images

```bash
sc-adm image import base|ai|dev <source-ref>   # OCI image → Incus + Sandcastle alias
sc-adm image sync <image-ref>
sc-adm image build base|ai|dev                 # local OCI build (docker)
sc-adm image build-remote all --ghcr-repo …    # build in the Image Builder appliance, push to GHCR
sc-adm image builder provision|status|destroy
```

Sandcastle needs **no prebuilt images**: base, AI, and dev all default to stock
upstream images pulled on demand. These commands exist for deployments that want
custom ones.

OCI images run as *application* containers under Incus — systemd never boots, so
they are **not** usable as machine images. A machine image must be a system
container image (systemd as PID 1); build one by provisioning a throwaway machine
and publishing it (`sc image save`, or `mise run image:dev:build-in-project`).

## Fleet updates

```bash
sc-adm update --check                  # version table: appliances + every sidecar
sc-adm update --yes                    # update the install's global components
sc-adm update --version vX.Y.Z --yes   # pin, or roll back
sc-adm update --tenants acme,beta      # also force-roll named sidecars
sc-adm update --all-tenants
sc-adm update --prefix id              # when several installs share this remote
```

Sidecars are normally tenant-managed through `sc update`; `--tenants` /
`--all-tenants` force the roll. A row reading `unknown` means the instance
predates version stamping and is treated as outdated. Tunnel installs have no
broker appliance, so an auth-app-only table is correct there.

## Services and appliances

`sc-adm auth-app serve` and `sc-adm project broker-serve` are the long-running
services; the deploy commands install them under systemd inside their appliances.
`sc-adm sidecar tls-sign` runs on a tenant sidecar and serves the tenant-CA leaf
signer. You run these only when operating an appliance by hand — inspect them
with journalctl instead:

```bash
sc-adm incus exec <install>:<auth-app-instance> --project <infra-project> -- \
  journalctl -u sandcastle-auth-app -n 100 --no-pager
```

`sc-adm tld refresh` regenerates the embedded IANA TLD and special-use deny-list
snapshots used to validate Tenant DNS Suffixes; it writes Go source and belongs
in a commit, not on a server.
