# Sandcastle Incus

Sandcastle Incus is the Incus-backed implementation of Sandcastle.

The product CLI is `sandcastle`, with `sc` installed as an alias. The system
creates tenant-scoped Incus container machines for AI and development workflows,
connects them to a user-selected Tailscale network, serves private tenant DNS,
and supports direct-Machine Tailnet HTTPS plus opt-in Cloudflare Tunnels.
Machine Caddy and Cloudflare connector launchers are centrally versioned under
the project-shared `/.sc/platform` payload; Machine-specific Caddy
configuration and certificates remain on each Machine.

## Documents

- [Sandcastle v1 specification](docs/sandcastle-v1-spec.md)
- [Implementation plan](docs/implementation-plan.md)
- [End-to-end testing plan](docs/e2e-testing-plan.md)
- [Usage guide](docs/usage.html)
- [Admin and developer quickstart](docs/admin-developer-quickstart.html)

## Install

### Install script (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/thieso2/sandcastle-incus/main/install.sh | bash
```

Detects your OS/arch, downloads the matching release tarball, verifies it
against the release `checksums.txt`, and installs `sandcastle` into
`~/.local/bin` with an `sc` symlink beside it. Nothing outside the install
directory is touched — if it is not on your `PATH`, the script prints the line
to add.

Flags come after `-s --` when piping:

```bash
curl -fsSL .../install.sh | bash -s -- --version v0.8.0   # pin a release (or roll back)
curl -fsSL .../install.sh | bash -s -- --dir /usr/local/bin
curl -fsSL .../install.sh | bash -s -- --admin            # also link sc-adm / sandcastle-admin
```

`SANDCASTLE_VERSION`, `SANDCASTLE_INSTALL_DIR` and `SANDCASTLE_ADMIN=1` are the
env-var equivalents. Because the binary lands in a directory you own,
`sc update` self-replaces it in place on both Linux and macOS — a Homebrew
install deliberately cannot.

### Homebrew (macOS)

```bash
brew install thieso2/tap/sandcastle
```

This installs the `sandcastle` CLI plus the short `sc` alias. Upgrade with
`brew upgrade sandcastle`. (Homebrew Casks are macOS-only; on Linux, use the
release tarballs below.)

> The current macOS binaries are **not yet code-signed**, so Gatekeeper may warn
> on first run. The cask clears the quarantine attribute on install; if you still
> hit a block, run `xattr -dr com.apple.quarantine "$(brew --prefix)/bin/sandcastle"`.

### Release tarballs (Linux / macOS)

Prebuilt archives for `linux`/`darwin` × `amd64`/`arm64` are attached to each
[GitHub release](https://github.com/thieso2/sandcastle-incus/releases). Download
`sandcastle-<os>-<arch>.tar.gz`, verify against `checksums.txt`, extract, and put
`sandcastle` on your `PATH` (optionally symlinking `sc` to it).

## Build From Source

Build the product CLI locally:

```bash
make build
```

This writes `bin/sandcastle` and installs `bin/sc` as a symlink alias to the
same binary. Install the user CLI and alias into `~/.local/bin` when it is on
`PATH`, otherwise `/usr/local/bin`:

```bash
mise run install
```

Normal tenant users only need `sandcastle` and `sc`. `sandcastle-admin` and
`sc-adm` are operator tools.

## Testing

Run the normal test suite:

```bash
go test ./...
```

Run reproducible e2e tiers through the checked-in runner:

```bash
scripts/e2e.sh unit
scripts/e2e.sh gated
scripts/e2e.sh local
SANDCASTLE_E2E=1 scripts/e2e.sh incus
SANDCASTLE_E2E=1 SANDCASTLE_E2E_LOCAL_VM=1 scripts/e2e.sh local-vm
SANDCASTLE_E2E=1 SANDCASTLE_E2E_REMOTE=remote-incus SANDCASTLE_E2E_BASE_IMAGE_SOURCE=sandcastle/base:debian-13 SANDCASTLE_E2E_AI_IMAGE_SOURCE=sandcastle/ai:debian-13 scripts/e2e.sh restricted
SANDCASTLE_E2E=1 SANDCASTLE_E2E_BASE_IMAGE_SOURCE=sandcastle/base:debian-13 SANDCASTLE_E2E_AI_IMAGE_SOURCE=sandcastle/ai:debian-13 SANDCASTLE_E2E_TAILSCALE_AUTHKEY=tskey-auth-... scripts/e2e.sh tailscale
SANDCASTLE_E2E=1 SANDCASTLE_E2E_IMAGE_BUILD=1 SANDCASTLE_E2E_CODEX_VERSION=... SANDCASTLE_E2E_CLAUDE_CODE_VERSION=... SANDCASTLE_E2E_GEMINI_CLI_VERSION=... scripts/e2e.sh images
SANDCASTLE_E2E=1 SANDCASTLE_E2E_BASE_IMAGE_SOURCE=sandcastle/base:debian-13 SANDCASTLE_E2E_AI_IMAGE_SOURCE=sandcastle/ai:debian-13 scripts/e2e.sh route-broker
SANDCASTLE_E2E=1 SANDCASTLE_E2E_BASE_IMAGE_SOURCE=sandcastle/base:debian-13 SANDCASTLE_E2E_AI_IMAGE_SOURCE=sandcastle/ai:debian-13 SANDCASTLE_E2E_PUBLIC_DOMAIN=e2e.example.com SANDCASTLE_E2E_INFRA_HOST=203.0.113.10 SANDCASTLE_E2E_LETSENCRYPT_EMAIL=ops@example.com scripts/e2e.sh public-routes
SANDCASTLE_E2E=1 SANDCASTLE_E2E_MACHINE_PUBLICATIONS=1 SANDCASTLE_E2E_SIMULATED_GITHUB=1 SANDCASTLE_E2E_CLOUDFLARE_TOKEN=<token> SANDCASTLE_E2E_PUBLIC_DNS_ZONE=<zone> scripts/e2e.sh publications
SANDCASTLE_E2E=1 SANDCASTLE_E2E_RUN_ID=e2e-20260520-120000 scripts/e2e.sh cleanup
```

To run the VM-only local mutation tier from the host, use the disposable VM
harness. It creates a local Incus VM, installs the e2e toolchain, seeds nested
Incus image aliases from the host, starts a root user service manager for
`systemctl --user` coverage, copies this checkout, and runs the `local-vm` tier
inside the VM:

```bash
scripts/e2e-local-vm.sh
```

The destructive tiers refuse to run unless their required environment variables
are set. See the e2e testing plan for Incus, restricted HTTPS remote, image,
Tailscale, route broker, public route, cleanup, and disposable VM requirements. Safe
tiers run automatically in GitHub Actions; real environment gates are available
through the manual `Destructive e2e gates` workflow. Non-cleanup destructive
tiers use one generated `SANDCASTLE_E2E_RUN_ID` per runner invocation when no
explicit run id is provided; cleanup requires an explicit run id.
# klabauter-demo
