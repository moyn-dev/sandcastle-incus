#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/e2e-local-vm.sh

Create a disposable Incus VM, install the local e2e toolchain inside it, seed
nested Incus image aliases from the host, start a root systemd user service
manager, copy this checkout, and run:

  SANDCASTLE_E2E=1 SANDCASTLE_E2E_LOCAL_VM=1 scripts/e2e.sh local-vm

Environment:
  SANDCASTLE_E2E_VM_NAME       VM name. Default: sc-e2e-local-vm-<timestamp>
  SANDCASTLE_E2E_VM_IMAGE      VM image. Default: images:debian/13
  SANDCASTLE_E2E_VM_DISK_SIZE  Root disk size. Default: 20GiB
  SANDCASTLE_E2E_VM_CPUS       CPU limit. Default: 2
  SANDCASTLE_E2E_VM_MEMORY     Memory limit. Default: 3GiB
  SANDCASTLE_E2E_VM_KEEP       Keep VM after exit when set to 1.
  SANDCASTLE_E2E_RUN_ID        Run id passed through to the inner e2e runner.
  SANDCASTLE_E2E_BASE_IMAGE_SOURCE  Host image alias to seed. Default: sandcastle/base:latest
  SANDCASTLE_E2E_AI_IMAGE_SOURCE    Host image alias to seed. Default: sandcastle/ai:latest
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  usage
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vm_name="${SANDCASTLE_E2E_VM_NAME:-sc-e2e-local-vm-$(date -u +%Y%m%d-%H%M%S)}"
vm_image="${SANDCASTLE_E2E_VM_IMAGE:-images:debian/13}"
vm_disk_size="${SANDCASTLE_E2E_VM_DISK_SIZE:-20GiB}"
vm_cpus="${SANDCASTLE_E2E_VM_CPUS:-2}"
vm_memory="${SANDCASTLE_E2E_VM_MEMORY:-3GiB}"
keep_vm="${SANDCASTLE_E2E_VM_KEEP:-0}"
run_id="${SANDCASTLE_E2E_RUN_ID:-e2e-local-vm-$(date -u +%Y%m%d-%H%M%S)}"
base_source="${SANDCASTLE_E2E_BASE_IMAGE_SOURCE:-sandcastle/base:latest}"
ai_source="${SANDCASTLE_E2E_AI_IMAGE_SOURCE:-sandcastle/ai:latest}"
go_version="$(awk '/^go / {print $2; exit}' "$repo_root/go.mod")"
host_arch="$(go env GOARCH)"

case "$host_arch" in
  amd64) go_arch="amd64" ;;
  arm64) go_arch="arm64" ;;
  *) echo "error: unsupported Go architecture $host_arch" >&2; exit 2 ;;
esac

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
  if [[ "$keep_vm" == "1" ]]; then
    echo "keeping VM $vm_name"
    return
  fi
  if incus info "$vm_name" >/dev/null 2>&1; then
    incus delete --force "$vm_name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log() {
  printf '+ %s\n' "$*"
}

vm_sh() {
  incus exec "$vm_name" -- bash -lc "$1"
}

wait_for_vm() {
  for _ in $(seq 1 120); do
    if incus exec "$vm_name" -- true >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "error: VM $vm_name did not become ready" >&2
  return 1
}

image_fingerprint() {
  incus image info "local:$1" | awk '/^Fingerprint:/ {print $2; exit}'
}

seed_image_alias() {
  local source_alias="$1"
  local target_alias="$2"
  local name="$3"
  local fingerprint
  fingerprint="$(image_fingerprint "$source_alias")"
  if [[ -z "$fingerprint" ]]; then
    echo "error: could not read fingerprint for host image alias $source_alias" >&2
    return 1
  fi
  if vm_sh "incus image info 'local:$target_alias' >/dev/null 2>&1"; then
    return
  fi
  if vm_sh "incus image info '$fingerprint' >/dev/null 2>&1"; then
    vm_sh "incus image alias create '$target_alias' '$fingerprint' >/dev/null 2>&1 || incus image alias set '$target_alias' '$fingerprint'"
    return
  fi

  local prefix="$tmp_dir/$name"
  log "export host image $source_alias"
  incus image export "local:$source_alias" "$prefix" >/dev/null
  vm_sh "mkdir -p '/root/e2e-images/$name'"
  shopt -s nullglob
  local files=("$prefix"*)
  shopt -u nullglob
  if [[ ${#files[@]} -eq 0 ]]; then
    echo "error: image export for $source_alias produced no files" >&2
    return 1
  fi
  for file in "${files[@]}"; do
    incus file push "$file" "$vm_name/root/e2e-images/$name/$(basename "$file")" >/dev/null
  done
  vm_sh "incus image import /root/e2e-images/$name/* --alias '$target_alias'"
}

log "launch $vm_image as $vm_name"
incus launch "$vm_image" "$vm_name" --vm \
  -c security.nesting=true \
  -c limits.cpu="$vm_cpus" \
  -c limits.memory="$vm_memory" \
  -d root,size="$vm_disk_size"

wait_for_vm

log "install VM packages"
vm_sh "export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y ca-certificates curl git make gcc pkg-config tar xz-utils uidmap iproute2 dnsutils sudo"

log "install Go $go_version"
vm_sh "curl -fsSL 'https://go.dev/dl/go${go_version}.linux-${go_arch}.tar.gz' -o /tmp/go.tgz; rm -rf /usr/local/go; tar -C /usr/local -xzf /tmp/go.tgz; ln -sf /usr/local/go/bin/go /usr/local/bin/go; ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt"

log "install mise"
vm_sh "curl -fsSL https://mise.run | sh"

log "copy checkout"
vm_sh "rm -rf /root/sandcastle-incus; mkdir -p /root/sandcastle-incus"
tar \
  --exclude=.git \
  --exclude=graphify-out \
  --exclude='*.test' \
  --exclude=bin \
  -C "$repo_root" -czf - . | incus exec "$vm_name" -- tar -xzf - -C /root/sandcastle-incus

log "install supported nested Incus"
vm_sh "cd /root/sandcastle-incus; /usr/local/go/bin/go build -o /usr/local/bin/sandcastle ./cmd/sandcastle; ln -sf sandcastle /usr/local/bin/sc-adm; sc-adm install-incus; incus admin waitready --timeout=120"

log "start root user service manager"
vm_sh "loginctl enable-linger root; systemctl start user@0.service; for _ in \$(seq 1 30); do test -S /run/user/0/bus && exit 0; sleep 1; done; echo 'error: root user service bus did not become ready' >&2; exit 1"

seed_image_alias "$base_source" "sandcastle/base:latest" "base"
seed_image_alias "$ai_source" "sandcastle/ai:latest" "ai"

log "run local-vm e2e tier inside $vm_name"
vm_sh "cd /root/sandcastle-incus; export PATH=/usr/local/go/bin:/root/.local/bin:\$PATH; export XDG_RUNTIME_DIR=/run/user/0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/0/bus; export SANDCASTLE_E2E=1 SANDCASTLE_E2E_LOCAL_VM=1 SANDCASTLE_E2E_RUN_ID='$run_id' SANDCASTLE_E2E_BASE_IMAGE_SOURCE='sandcastle/base:latest' SANDCASTLE_E2E_AI_IMAGE_SOURCE='sandcastle/ai:latest'; scripts/e2e.sh local-vm"
