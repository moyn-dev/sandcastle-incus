#!/usr/bin/env bash
# `mise run setup`, which kitchen-setup runs on its box as the box's login user, after the clone and mise install:
# Incus from Zabbly (as scripts/setup-workvm.sh installs it) with a minimal init, for the e2e in docs/e2e-sc2.md,
# and Tailscale, installed but not joined. Every launch runs it again; each step skips what is there.
#   INCUS_BRIDGE_ADDRESS   default 172.30.0.1/24: incusbr0's address, outside the box's own routes
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
log() { printf '==> %s\n' "$*"; }
# It installs packages and inits Incus with sudo: never on a computer that is not a box.
[ -d "$HOME/.kitchen-setup" ] || { echo "scripts/kitchen-setup.sh runs on a kitchen-setup box only (no ~/.kitchen-setup here)" >&2; exit 1; }

# shellcheck disable=SC1091 # the box's own
. /etc/os-release
arch=$(dpkg --print-architecture)

if [ ! -f /etc/apt/sources.list.d/zabbly-incus-stable.sources ]; then
  log "Zabbly Incus stable repository"
  sudo install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://pkgs.zabbly.com/key.asc | sudo tee /etc/apt/keyrings/zabbly.asc >/dev/null
  gpg --show-keys --with-colons /etc/apt/keyrings/zabbly.asc | awk -F: '$1 == "fpr" { print $10 }' |
    grep -cx 4EFC590696CB15B87C73A3AD82CC8797C838DCFD >/dev/null || { echo "Unexpected Zabbly key fingerprint" >&2; exit 1; }
  sudo tee /etc/apt/sources.list.d/zabbly-incus-stable.sources >/dev/null <<EOF
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: ${VERSION_CODENAME}
Components: main
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF
fi

if [ ! -f /etc/apt/sources.list.d/tailscale.list ]; then
  log "Tailscale stable repository"
  base="https://pkgs.tailscale.com/stable/${ID}/${VERSION_CODENAME}"
  curl -fsSL "${base}.noarmor.gpg" | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
  curl -fsSL "${base}.tailscale-keyring.list" | sudo tee /etc/apt/sources.list.d/tailscale.list >/dev/null
fi

if ! command -v incus >/dev/null || ! command -v tailscale >/dev/null; then
  log "apt: incus, tailscale"
  sudo apt-get update -q
  sudo apt-get install -y -q incus tailscale
fi

# What `incus admin init --minimal` sets up, with incusbr0's subnet named: a box routes all of 10.0.0.0/8 and
# 100.64.0.0/10 to Sandcastle, so Incus finds no free subnet of its own. A daemon with a default root disk is set up.
bridge=${INCUS_BRIDGE_ADDRESS:-172.30.0.1/24}
if ! sudo incus profile device get default root pool >/dev/null 2>&1; then
  log "incus admin init: storage pool default (dir), incusbr0 on $bridge"
  sudo incus admin init --preseed <<EOF
networks:
- name: incusbr0
  type: bridge
  config:
    ipv4.address: $bridge
    ipv4.nat: "true"
    ipv6.address: none
storage_pools:
- name: default
  driver: dir
profiles:
- name: default
  devices:
    root: {path: /, pool: default, type: disk}
    eth0: {name: eth0, network: incusbr0, type: nic}
EOF
fi

# incus-admin reaches the socket from the next login on. The shells and T3 the launch starts now began before
# that; the ACL lets them in until the daemon makes its socket again.
sudo usermod -aG incus-admin "$USER"
sudo setfacl -m "u:$USER:rw" /var/lib/incus/unix.socket
incus info >/dev/null
log "incus $(incus version | sed -n 's/^Server version: //p') answers as $USER"

# Incus runs VMs only with /dev/kvm and /dev/vsock; kitchen-setup.toml's kvm asks the launch for both. Ask Incus
# (root) rather than test the devices as $USER: /dev/kvm is root:kvm 0660 and $USER is not in kvm.
if incus info | grep -q '^  driver: .*qemu'; then
  log "incus has the qemu driver: incus launch --vm can run"
else
  log "incus lacks the qemu driver (no /dev/kvm or /dev/vsock when it started): containers only"
fi
log "tailscale $(tailscale version | head -1) is installed, not joined; TAILSCALE_AUTH_KEY is in ~/.kitchen-setup/env when the vault grants it"
