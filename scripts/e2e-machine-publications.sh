#!/usr/bin/env bash
# Fresh nested-Incus Machine publication lifecycle (issue #186).
#
# This is intentionally an opt-in, destructive phase. It is run only after a
# NEW nested Incus VM has installed the Auth App with --ingress cloudflare and
# --simulate-github-token, and a separately enrolled Tailnet client has the
# tenant subnet route. Do not point it at an OAuth-backed or production install.
set -euo pipefail

TOKEN="${SANDCASTLE_E2E_CLOUDFLARE_TOKEN:-}"
ZONE="${SANDCASTLE_E2E_PUBLIC_DNS_ZONE:-}"
[[ "${SANDCASTLE_E2E_MACHINE_PUBLICATIONS:-}" == 1 ]] || { echo "SKIP: set SANDCASTLE_E2E_MACHINE_PUBLICATIONS=1"; exit 0; }
[[ "${SANDCASTLE_E2E_SIMULATED_GITHUB:-}" == 1 ]] || { echo "error: this phase requires a fresh --simulate-github-token installation (set SANDCASTLE_E2E_SIMULATED_GITHUB=1 after verifying it)" >&2; exit 2; }
[[ -n "$TOKEN" && -n "$ZONE" ]] || { echo "SKIP: set SANDCASTLE_E2E_CLOUDFLARE_TOKEN and SANDCASTLE_E2E_PUBLIC_DNS_ZONE"; exit 0; }
ZONE="$(printf %s "$ZONE" | tr 'A-Z' 'a-z' | sed 's/\.$//')"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${SANDCASTLE_E2E_SANDCASTLE_BIN:-${REPO_ROOT}/bin/sc}"
[[ -x "$BIN" ]] || BIN="$(command -v sc || true)"
[[ -n "$BIN" && -x "$BIN" ]] || { echo "error: set SANDCASTLE_E2E_SANDCASTLE_BIN or build bin/sc" >&2; exit 2; }
for tool in curl dig jq openssl; do command -v "$tool" >/dev/null || { echo "error: $tool is required" >&2; exit 2; }; done

sc() { "$BIN" "$@"; }
sc_adm() { "$BIN" admin "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
step() { echo; echo "== $*"; }
expect_fail() { local want="$1"; shift; local out rc=0; out="$("$@" 2>&1)" || rc=$?; [[ $rc -ne 0 && "$out" == *"$want"* ]] || fail "expected refusal containing $want, got: $out"; }

RUN="${SANDCASTLE_E2E_RUN_ID:-e2e-$(date -u +%Y%m%d-%H%M%S)}"
ID="$(printf %s "$RUN" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | sed 's/^-*//; s/-*$//' | cut -c1-30)"
PROJECT="mp-${ID#e2e-}"
MACHINE="web"
REF="$PROJECT:$MACHINE"
TUNNEL="tunnel-${ID#e2e-}.$ZONE"
TAILNET="tailnet-${ID#e2e-}.$ZONE"
RESOLVER="${SANDCASTLE_E2E_PDZ_RESOLVER:-1.1.1.1}"
DNS_TIMEOUT="${SANDCASTLE_E2E_PUBLICATION_DNS_TIMEOUT:-180}"
ZONE_PREREGISTERED=0

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 && "${SANDCASTLE_E2E_PUBLICATIONS_KEEP:-0}" == 1 ]]; then echo "KEEP: $REF, $TUNNEL, $TAILNET" >&2; return; fi
  sc tailnet unpublish "$REF" --hostname "$TAILNET" >/dev/null 2>&1 || true
  sc tunnel unpublish "$REF" --hostname "$TUNNEL" >/dev/null 2>&1 || true
  sc delete "$REF" --yes >/dev/null 2>&1 || true
  sc project delete "$PROJECT" --yes >/dev/null 2>&1 || true
  [[ $ZONE_PREREGISTERED -eq 1 ]] || sc_adm public-dns-zone remove "$ZONE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { local seconds="$1" what="$2"; shift 2; local start; start=$(date +%s); until "$@"; do (( $(date +%s) - start < seconds )) || fail "timed out waiting for $what"; sleep 5; done; }
dig_a() { dig +short A "$1" "@$RESOLVER" | grep -E '^[0-9.]+$' || true; }
dig_cname() { dig +short CNAME "$1" "@$RESOLVER" | sed 's/\.$//' | head -1; }
machine_ip() { sc ls "$REF" --json | jq -r --arg m "$MACHINE" '.machines[] | select(.name==$m) | .privateIP // empty'; }
tailnet_records_at_machine() { [[ "$(dig_a "$TAILNET")" == "$PRIVATE_IP" && "$(dig_a "x.$TAILNET")" == "$PRIVATE_IP" ]]; }
tailnet_records_gone() { [[ -z "$(dig_a "$TAILNET")" && -z "$(dig_a "x.$TAILNET")" ]]; }
assert_staging_machine_certificate() {
  local certificate
  certificate="$(openssl s_client -connect "$PRIVATE_IP:443" -servername "$TAILNET" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName -issuer 2>/dev/null || true)"
  [[ "$certificate" == *"DNS:$TAILNET"* && "$certificate" == *"DNS:*.$TAILNET"* ]] || fail "Machine certificate does not cover $TAILNET and *.$TAILNET: $certificate"
  [[ "$certificate" == *"STAGING"* ]] || fail "Machine certificate is not from Let's Encrypt staging: $certificate"
}
assert_no_sidecar_tailnet_artifact() {
  # A tenant-admin credential may not be allowed to inspect the infra project.
  # When it is, assert the direct path left no old Sidecar Caddy fragment. A
  # missing permission is reported, not treated as proof either way.
  if sc incus-infra ls >/dev/null 2>&1; then
    sc incus-infra exec sidecar -- sh -ceu 'test ! -e /etc/caddy/tailnet-publish && test ! -e /etc/sandcastle/tailnet-publish' \
      || fail "direct Tailnet publication created a legacy Sidecar tailnet-publish artifact"
    pass "no legacy Sidecar tailnet-publish artifact"
  else
    echo "NOTE: restricted credential cannot inspect Tenant Sidecar; direct DNS, Machine Caddy, and certificate assertions remain authoritative"
  fi
}

step "register disposable Public DNS Zone and create an HTTP Machine"
if sc_adm public-dns-zone list --output json | jq -e --arg z "$ZONE" 'map(select(.zone==$z)) | length > 0' >/dev/null; then ZONE_PREREGISTERED=1; else sc_adm public-dns-zone add "$ZONE" --token-file <(printf %s "$TOKEN"); fi
sc project create "$PROJECT"
sc create "$REF"
sc c "$REF" -- sh -ceu "mkdir -p /tmp/machine-publications; printf machine-publications > /tmp/machine-publications/index.html; nohup python3 -m http.server 3000 --directory /tmp/machine-publications >/tmp/machine-publications/http.log 2>&1 &"
PRIVATE_IP=""; wait_for 120 "Machine private address" bash -c 'test -n "$("$0" ls "$1" --json | jq -r --arg m "$2" '\'' .machines[] | select(.name==$m) | .privateIP // empty'\'' )"' "$BIN" "$REF" "$MACHINE"
PRIVATE_IP="$(machine_ip)"; [[ -n "$PRIVATE_IP" ]] || fail "Machine has no private address"

step "Machine Tunnel publish, idempotence, list, conflict, and cleanup"
TUNNEL_VERBOSE="$(VERBOSE=1 sc tunnel publish "$REF" --port 3000 --hostname "$TUNNEL" 2>&1)" || fail "$TUNNEL_VERBOSE"
[[ "$TUNNEL_VERBOSE" == *"Tunnel published: https://$TUNNEL"* ]] || fail "tunnel publish output missing hostname"
[[ "$TUNNEL_VERBOSE" != *"$TOKEN"* ]] || fail "verbose tunnel trace leaked Cloudflare credential"
curl --fail --retry 12 --retry-delay 5 "https://$TUNNEL" | grep -q machine-publications || fail "public tunnel response"
FIRST_CNAME="$(dig_cname "$TUNNEL")"; [[ "$FIRST_CNAME" == *.cfargotunnel.com ]] || fail "tunnel DNS is not a Cloudflare Tunnel CNAME: $FIRST_CNAME"
sc tunnel publish "$REF" --port 3000 --hostname "$TUNNEL" >/dev/null
[[ "$(dig_cname "$TUNNEL")" == "$FIRST_CNAME" ]] || fail "idempotent tunnel publish changed CNAME"
sc ls | grep -F "$TUNNEL" >/dev/null || fail "sc ls does not render TUNNEL hostname"
expect_fail "already" sc tailnet publish "$REF" --hostname "$TUNNEL"
sc tunnel unpublish "$REF" --hostname "$TUNNEL"
sc tunnel unpublish "$REF" --hostname "$TUNNEL"
wait_for "$DNS_TIMEOUT" "tunnel CNAME removal" bash -c '[[ -z "$(dig +short CNAME "$1" "@$2")" ]]' "$TUNNEL" "$RESOLVER"
pass "Machine Tunnel lifecycle"

step "direct-Machine Tailnet publication, idempotence, and cleanup"
TAILNET_VERBOSE="$(VERBOSE=1 sc tailnet publish "$REF" --hostname "$TAILNET" 2>&1)" || fail "$TAILNET_VERBOSE"
[[ "$TAILNET_VERBOSE" == *"Tailnet HTTPS published: https://$TAILNET → $MACHINE:443"* ]] || fail "tailnet publish output missing direct-Machine result"
[[ "$TAILNET_VERBOSE" == *"[verbose]"* && "$TAILNET_VERBOSE" != *"$TOKEN"* ]] || fail "verbose Tailnet trace missing progress or leaked credential"
wait_for "$DNS_TIMEOUT" "DNS-only A records to Machine private address" tailnet_records_at_machine
[[ -z "$(dig_cname "$TAILNET")" ]] || fail "Tailnet publication must not use a CNAME"
wait_for "$DNS_TIMEOUT" "Machine-Caddy Let's Encrypt staging certificate" assert_staging_machine_certificate
assert_no_sidecar_tailnet_artifact
# The fresh test install uses Let's Encrypt staging, so curl must not use the
# host trust store for this transport assertion; openssl-level certificate
# assertions belong in the certificate lifecycle phase.
curl -k --fail --connect-timeout 10 --resolve "$TAILNET:443:$PRIVATE_IP" "https://$TAILNET" | grep -q machine-publications || fail "Tailnet HTTPS did not reach Machine Caddy"
sc tailnet publish "$REF" --hostname "$TAILNET" >/dev/null
[[ "$(dig_a "$TAILNET")" == "$PRIVATE_IP" ]] || fail "idempotent Tailnet publish changed direct Machine target"
sc ls | grep -F "$TAILNET" >/dev/null || fail "sc ls does not render TAILNET hostname"
sc tailnet unpublish "$REF" --hostname "$TAILNET"
sc tailnet unpublish "$REF" --hostname "$TAILNET"
wait_for "$DNS_TIMEOUT" "Tailnet A record removal" tailnet_records_gone
pass "direct-Machine Tailnet lifecycle"

echo "ALL PASS: Machine publication lifecycle"
