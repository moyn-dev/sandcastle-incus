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
  all       Run unit, gated, incus, images and cleanup tiers.

Examples:
  scripts/e2e.sh unit
  SANDCASTLE_E2E=1 SANDCASTLE_E2E_REMOTE=local scripts/e2e.sh incus
  SANDCASTLE_E2E=1 SANDCASTLE_E2E_IMAGE_BUILD=1 SANDCASTLE_E2E_CODEX_VERSION=... SANDCASTLE_E2E_CLAUDE_CODE_VERSION=... SANDCASTLE_E2E_GEMINI_CLI_VERSION=... scripts/e2e.sh images
  SANDCASTLE_E2E=1 SANDCASTLE_E2E_RUN_ID=e2e-20260520-120000 scripts/e2e.sh cleanup
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
  run go test ./internal/e2e -run 'Test(TenantListingSmoke|ImageSync.*AliasE2E)' -count=1 -v
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
  all)
    run_unit
    run_gated
    run_incus
    run_images
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
