#!/usr/bin/env bash
#
# Sandcastle CLI installer.
#
#   curl -fsSL https://raw.githubusercontent.com/moyn-dev/sandcastle-incus/main/install.sh | bash
#
# Installs the release binary as `sandcastle` in ~/.local/bin with an `sc`
# symlink beside it (the busybox layout the fat binary dispatches on — see
# cmd/sandcastle/main.go). Because the binary then lives in a directory you
# own, `sc update` can self-replace it; a Homebrew install deliberately cannot.
#
# Options (also as env vars, flags win):
#   --version <tag>   SANDCASTLE_VERSION       release to install (default: latest)
#   --dir <path>      SANDCASTLE_INSTALL_DIR   install directory (default: ~/.local/bin)
#   --admin           SANDCASTLE_ADMIN=1       also link sc-adm / sandcastle-admin
#   --repo <o/r>      SANDCASTLE_REPO          release repository (for forks/testing)
#
# Piping into bash needs `-s --` before flags:
#   curl -fsSL <url> | bash -s -- --version v0.8.0 --dir /usr/local/bin

set -euo pipefail

REPO="${SANDCASTLE_REPO:-moyn-dev/sandcastle-incus}"
VERSION="${SANDCASTLE_VERSION:-}"
INSTALL_DIR="${SANDCASTLE_INSTALL_DIR:-$HOME/.local/bin}"
INSTALL_ADMIN="${SANDCASTLE_ADMIN:-}"

# Colour only when stderr is a terminal — a piped install logs plain text.
if [ -t 2 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi

say()  { printf '%s\n' "$*" >&2; }
warn() { printf '%s\n' "${YELLOW}warning:${RESET} $*" >&2; }
die()  { printf '%s\n' "${RED}error:${RESET} $*" >&2; exit 1; }

# Piped into bash, $0 is "bash" — the help text has to live in the script, not
# be read back out of it.
usage() {
  cat >&2 <<'USAGE'
Sandcastle CLI installer — installs `sandcastle` + an `sc` symlink into ~/.local/bin.

  curl -fsSL https://raw.githubusercontent.com/moyn-dev/sandcastle-incus/main/install.sh | bash

Options (env-var form in brackets; flags win):
  --version <tag>   [SANDCASTLE_VERSION]       release to install (default: latest)
  --dir <path>      [SANDCASTLE_INSTALL_DIR]   install directory (default: ~/.local/bin)
  --admin           [SANDCASTLE_ADMIN=1]       also link sc-adm / sandcastle-admin
  --repo <owner/n>  [SANDCASTLE_REPO]          release repository (forks/testing)
  --help

Piping into bash needs `-s --` before flags:
  curl -fsSL <url> | bash -s -- --version v0.8.0 --dir /usr/local/bin
USAGE
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version|-v) [ $# -ge 2 ] || die "--version needs a release tag"; VERSION="$2"; shift 2 ;;
    --version=*)  VERSION="${1#*=}"; shift ;;
    --dir|-d)     [ $# -ge 2 ] || die "--dir needs a path"; INSTALL_DIR="$2"; shift 2 ;;
    --dir=*)      INSTALL_DIR="${1#*=}"; shift ;;
    --repo)       [ $# -ge 2 ] || die "--repo needs owner/name"; REPO="$2"; shift 2 ;;
    --repo=*)     REPO="${1#*=}"; shift ;;
    --admin)      INSTALL_ADMIN=1; shift ;;
    --help|-h)    usage 0 ;;
    *)            say "unknown option: $1"; usage 1 ;;
  esac
done

# --- fetching -----------------------------------------------------------------
# curl or wget, whichever is there. fetch_to writes to a file; fetch_out to stdout.
if command -v curl >/dev/null 2>&1; then
  fetch_to()  { curl -fsSL --retry 3 -o "$2" "$1"; }
  fetch_out() { curl -fsSL --retry 3 "$1"; }
  final_url() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch_to()  { wget -qO "$2" "$1"; }
  fetch_out() { wget -qO- "$1"; }
  final_url() { wget -qS --spider --max-redirect=10 "$1" 2>&1 | awk '/^  Location: /{u=$2} END{print u}'; }
else
  die "neither curl nor wget is installed"
fi

# --- platform -----------------------------------------------------------------
os="$(uname -s)"
case "$os" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *)      die "unsupported operating system: $os (releases cover linux and darwin)" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *)             die "unsupported architecture: $arch (releases cover amd64 and arm64)" ;;
esac

# --- release ------------------------------------------------------------------
# The latest tag comes from the /releases/latest redirect rather than the API:
# unauthenticated api.github.com is rate-limited per IP, and an installer is
# exactly the thing that runs from a shared CI address.
if [ -z "$VERSION" ]; then
  latest_url="$(final_url "https://github.com/$REPO/releases/latest" || true)"
  VERSION="${latest_url##*/}"
  case "$VERSION" in
    v[0-9]*) ;;
    *) die "could not resolve the latest release of $REPO — pass --version vX.Y.Z" ;;
  esac
fi
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac

asset="sandcastle-${os}-${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$VERSION"

say "${BOLD}Sandcastle${RESET} $VERSION — $os/$arch → $INSTALL_DIR"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/sandcastle-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "${DIM}downloading $asset${RESET}"
fetch_to "$base/$asset" "$tmp/$asset" \
  || die "download failed: $base/$asset (does release $VERSION exist?)"

# --- checksum -----------------------------------------------------------------
# The release ships one sha256 manifest for every asset; verify ours or stop.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  die "no sha256sum or shasum on PATH — cannot verify the download"
fi

want="$(fetch_out "$base/checksums.txt" | awk -v a="$asset" '$2 == a || $2 == "*" a {print $1}' | head -n1)"
[ -n "$want" ] || die "checksums.txt for $VERSION has no entry for $asset"
got="$(sha256_of "$tmp/$asset")"
[ "$got" = "$want" ] || die "checksum mismatch for $asset
  got  $got
  want $want"
say "${DIM}checksum ok${RESET}"

tar -xzf "$tmp/$asset" -C "$tmp" || die "could not extract $asset"
[ -f "$tmp/sandcastle" ] || die "$asset does not contain a sandcastle binary"

# --- install ------------------------------------------------------------------
mkdir -p "$INSTALL_DIR" || die "cannot create $INSTALL_DIR"
[ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable — pick another with --dir, or re-run with sudo"

chmod 0755 "$tmp/sandcastle"
# Stage beside the target and rename: a running `sc` keeps its own inode, and a
# failed copy never leaves a half-written binary on PATH.
cp "$tmp/sandcastle" "$INSTALL_DIR/.sandcastle.new" || die "cannot write to $INSTALL_DIR"
mv -f "$INSTALL_DIR/.sandcastle.new" "$INSTALL_DIR/sandcastle"

# argv[0] selects the role, so every name is a symlink to the one binary.
links="sc"
if [ -n "$INSTALL_ADMIN" ]; then
  links="sc sc-adm sandcastle-admin"
fi
for link in $links; do
  ln -sf sandcastle "$INSTALL_DIR/$link"
done

# Gatekeeper: unsigned macOS builds are blocked when quarantined. curl does not
# set the attribute, but a proxy or a re-download by hand can — clear it anyway,
# the same thing the Homebrew cask does on install.
if [ "$os" = darwin ] && command -v xattr >/dev/null 2>&1; then
  xattr -dr com.apple.quarantine "$INSTALL_DIR/sandcastle" 2>/dev/null || true
fi

installed="$("$INSTALL_DIR/sandcastle" version 2>/dev/null || echo "$VERSION")"
say "${GREEN}installed${RESET} $INSTALL_DIR/sandcastle ($installed), linked as ${links// /, }"

# --- PATH ---------------------------------------------------------------------
case ":$PATH:" in
  *":$INSTALL_DIR:"*)
    onpath="$(command -v sc 2>/dev/null || true)"
    if [ -n "$onpath" ] && [ "$onpath" != "$INSTALL_DIR/sc" ]; then
      warn "another sc is earlier on PATH: $onpath
  It shadows the one just installed. Remove it (Homebrew: \`brew uninstall sandcastle\`)
  or put $INSTALL_DIR first."
    fi
    ;;
  *)
    say ""
    warn "$INSTALL_DIR is not on your PATH. Add it:"
    case "${SHELL##*/}" in
      zsh)  say "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.zshrc  && exec zsh" ;;
      fish) say "  fish_add_path $INSTALL_DIR" ;;
      *)    say "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc && exec bash" ;;
    esac
    ;;
esac

say ""
say "Next:  ${BOLD}sc login${RESET}      authenticate against your deployment"
say "       ${BOLD}sc update${RESET}     self-update in place (this install can; a Homebrew one cannot)"
