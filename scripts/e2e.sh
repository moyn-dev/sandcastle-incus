#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/e2e.sh <tier>

Tiers:
  unit       Run all Incus-free Go tests.
  gated     Run e2e package with gates/default skips.
  incus     Run destructive real-Incus e2e flows. Requires SANDCASTLE_E2E=1.
  images    Run real image build e2e. Requires SANDCASTLE_E2E=1, image build env, and pinned AI CLI versions.
  cleanup   Remove managed disposable e2e projects for SANDCASTLE_E2E_RUN_ID. Requires SANDCASTLE_E2E=1 and an explicit run id.
  pdz       e2e Phase 12 — Public DNS Zones against Let's Encrypt staging (docs/e2e-sc2.md). Reads
            SANDCASTLE_E2E_CLOUDFLARE_TOKEN + SANDCASTLE_E2E_PUBLIC_DNS_ZONE from the environment or
            .env.sc2; SKIPPED (exit 0) when either is absent or SANDCASTLE_E2E is not 1.
  all       Run unit, gated, incus, images and pdz tiers.

Examples:
  scripts/e2e.sh unit
  SANDCASTLE_E2E=1 SANDCASTLE_E2E_REMOTE=local scripts/e2e.sh incus
  SANDCASTLE_E2E=1 SANDCASTLE_E2E_IMAGE_BUILD=1 SANDCASTLE_E2E_CODEX_VERSION=... SANDCASTLE_E2E_CLAUDE_CODE_VERSION=... SANDCASTLE_E2E_GEMINI_CLI_VERSION=... scripts/e2e.sh images
  SANDCASTLE_E2E=1 SANDCASTLE_E2E_RUN_ID=e2e-20260520-120000 scripts/e2e.sh cleanup
  SANDCASTLE_E2E=1 scripts/e2e.sh pdz          # .env.sc2 carries the Cloudflare token + test zone
USAGE
}

require_e2e() {
  if [[ "${SANDCASTLE_E2E:-}" != "1" ]]; then
    echo "error: set SANDCASTLE_E2E=1 to run destructive e2e tier '$1'" >&2
    exit 2
  fi
}

require_env() {
  if [[ -z "${!name:-}" ]]; then
    echo "error: set $name to run e2e tier '$tier'" >&2
    exit 2
  fi
}

ensure_run_id() {
  if [[ -z "${SANDCASTLE_E2E_RUN_ID:-}" ]]; then
    export SANDCASTLE_E2E_RUN_ID="e2e-$(date -u +%Y%m%d-%H%M%S)-$$"
  fi
  echo "SANDCASTLE_E2E_RUN_ID=$SANDCASTLE_E2E_RUN_ID"
}

run() {
  echo "+ $*"
  "$@"
}

run_unit() {
  run env -i HOME="$HOME" PATH="$PATH" USER="${USER:-}" SANDCASTLE_E2E=0 go test ./...
}

run_gated() {
  run env -i HOME="$HOME" PATH="$PATH" USER="${USER:-}" SANDCASTLE_E2E=0 go test ./internal/e2e -count=1 -v
}



run_incus() {
  require_e2e incus
  ensure_run_id incus
  run go test ./internal/e2e -run 'Test(TenantListingSmoke|DisposableTenantCreateAndPurge|DisposableInfrastructureCreateAndDelete|ImageSync.*AliasE2E)' -count=1 -v
}


run_images() {
  require_e2e images
  ensure_run_id images
  require_env images SANDCASTLE_E2E_IMAGE_BUILD
  if [[ "${SANDCASTLE_E2E_IMAGE_BUILD:-}" != "1" ]]; then
    echo "error: set SANDCASTLE_E2E_IMAGE_BUILD=1 to run real image build tier 'images'" >&2
    exit 2
  fi
  require_env images SANDCASTLE_E2E_CODEX_VERSION
  require_env images SANDCASTLE_E2E_CLAUDE_CODE_VERSION
  require_env images SANDCASTLE_E2E_GEMINI_CLI_VERSION
  run go test ./internal/e2e -run 'Test(ImageBuildBaseE2E|ImageBuildAIE2E)' -count=1 -v
}


require_route_broker_env() {
	local tier="$1"
	require_env "$tier" SANDCASTLE_E2E_BASE_IMAGE_SOURCE
	require_env "$tier" SANDCASTLE_E2E_AI_IMAGE_SOURCE
}



# Phase 12 (Public DNS Zones, ADR-0027). The two gate variables normally live in
# .env.sc2 next to the other e2e secrets; the tier sources it so `make e2e-safe`
# picks the phase up automatically once they are there, and skips — never
# fails — while they are not. The Go test carries the same gate (t.Skip), so
# the plain `gated` tier skips it too.
run_pdz() {
  local env_file="${SANDCASTLE_E2E_ENV_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.env.sc2}"
  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "$env_file"
    set +a
  fi
  if [[ -z "${SANDCASTLE_E2E_CLOUDFLARE_TOKEN:-}" || -z "${SANDCASTLE_E2E_PUBLIC_DNS_ZONE:-}" ]]; then
    echo "SKIP: e2e Phase 12 (Public DNS Zones) — set SANDCASTLE_E2E_CLOUDFLARE_TOKEN and SANDCASTLE_E2E_PUBLIC_DNS_ZONE (env or $env_file) to run it"
    return 0
  fi
  if [[ "${SANDCASTLE_E2E:-}" != "1" ]]; then
    echo "SKIP: e2e Phase 12 (Public DNS Zones) — zone + token present; set SANDCASTLE_E2E=1 to run it against the enrolled install"
    return 0
  fi
  ensure_run_id pdz
  run go test ./internal/e2e -run 'TestPublicDNSZonePhase12E2E' -count=1 -v
}

run_cleanup() {
  require_e2e cleanup
  require_env cleanup SANDCASTLE_E2E_RUN_ID
  run go test ./internal/e2e -run 'TestCleanupDisposableResourcesE2E' -count=1 -v
}

tier="${1:-}"
case "$tier" in
  unit)
    run_unit
    ;;
  gated)
    run_gated
    ;;
  incus)
    run_incus
    ;;
  images)
    run_images
    ;;
  cleanup)
    run_cleanup
    ;;
  pdz)
    run_pdz
    ;;
  all)
    run_unit
    run_gated
    run_incus
    run_images
    run_pdz
    ;;
  -h|--help|help|"")
    usage
    ;;
  *)
    echo "error: unknown e2e tier '$tier'" >&2
    usage >&2
    exit 2
    ;;
esac
