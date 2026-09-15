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
for tool in curl dig jq openssl sha256sum timeout; do command -v "$tool" >/dev/null || { echo "error: $tool is required" >&2; exit 2; }; done

sc() { "$BIN" "$@"; }
sc_adm() { "$BIN" admin "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
step() { echo; echo "== $*"; }
expect_fail() { local want="$1"; shift; local out rc=0; out="$("$@" 2>&1)" || rc=$?; [[ $rc -ne 0 && "$out" == *"$want"* ]] || fail "expected refusal containing $want, got: $out"; }

RUN="${SANDCASTLE_E2E_RUN_ID:-e2e-$(date -u +%Y%m%d-%H%M%S)}"
# The Incus project is prefixed again by the install and tenant names. Keep the
# disposable suffix short enough for Incus's 63-character project-name limit
# even when the fresh E2E deliberately uses a long, timestamped install prefix.
ID="$(printf %s "$RUN" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | sed 's/^-*//; s/-*$//')"
if (( ${#ID} > 12 )); then ID="e2e-$(printf %s "$RUN" | sha256sum | cut -c1-8)"; fi
[[ -n "${ID#e2e-}" ]] || fail "run ID must contain a usable name"
PROJECT="mp-${ID#e2e-}"
MACHINE="web"
REF="$PROJECT:$MACHINE"
TUNNEL="tunnel-${ID#e2e-}.$ZONE"
TAILNET="tailnet-${ID#e2e-}.$ZONE"
SECOND_TUNNEL="second-tunnel-${ID#e2e-}.$ZONE"
SECOND_TAILNET="second-tailnet-${ID#e2e-}.$ZONE"
RESOLVER="${SANDCASTLE_E2E_PDZ_RESOLVER:-1.1.1.1}"
DNS_TIMEOUT="${SANDCASTLE_E2E_PUBLICATION_DNS_TIMEOUT:-420}"
ZONE_PREREGISTERED=0

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 && "${SANDCASTLE_E2E_PUBLICATIONS_KEEP:-0}" == 1 ]]; then echo "KEEP: $REF, $TUNNEL, $TAILNET" >&2; return; fi
  sc tailnet unpublish "$REF" >/dev/null 2>&1 || true
  sc tunnel unpublish "$REF" >/dev/null 2>&1 || true
  sc delete "$REF" --yes >/dev/null 2>&1 || true
  sc project delete "$PROJECT" --yes >/dev/null 2>&1 || true
  [[ $ZONE_PREREGISTERED -eq 1 ]] || sc_adm public-dns-zone remove "$ZONE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() { local seconds="$1" what="$2"; shift 2; local start; start=$(date +%s); until "$@"; do (( $(date +%s) - start < seconds )) || fail "timed out waiting for $what"; echo "Waiting for $what ($(( $(date +%s) - start ))s elapsed)"; sleep 5; done; }
dig_a() { dig +short A "$1" "@$RESOLVER" | grep -E '^[0-9.]+$' || true; }
dig_cname() { dig +short CNAME "$1" "@$RESOLVER" | sed 's/\.$//' | head -1; }
public_edge_ip() { dig_a "$1" | head -1; }
cf_get() {
  curl --fail --silent --show-error --max-time 30 --config <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN") "https://api.cloudflare.com/client/v4/$1" | jq -e 'if .success then .result else error("Cloudflare request failed") end'
}
tunnel_record() { cf_get "zones/$CF_ZONE_ID/dns_records?name=$TUNNEL" | jq -ce 'map(select(.type=="CNAME" and .proxied==true and (.content|endswith(".cfargotunnel.com")))) | if length==1 then .[0] | {id,content} else error("expected one proxied Tunnel CNAME") end'; }
public_dns_present() { [[ -n "$(public_edge_ip "$TUNNEL")" ]]; }
public_dns_gone() { [[ -z "$(dig_a "$TUNNEL")" ]]; }
public_tunnel_responds() {
  local host="$1" edge
  edge="$(public_edge_ip "$host")"
  [[ -n "$edge" ]] || return 1
  # The test driver may have cached NXDOMAIN before Cloudflare's proxied
  # CNAME was created. Resolve at the configured public resolver and pin the
  # resulting edge for this transport assertion; this proves both the public
  # DNS publication and the connector without depending on local DNS caches.
  curl --fail --silent --show-error --connect-timeout 10 --max-time 20 --resolve "$host:443:$edge" "https://$host" | grep -q machine-publications
}
machine_ip() { sc ls "$REF" --json | jq -r --arg m "$MACHINE" '.machines[] | select(.name==$m) | .privateIP // empty'; }
tailnet_records_at_machine() { [[ "$(dig_a "$TAILNET")" == "$PRIVATE_IP" && "$(dig_a "x.$TAILNET")" == "$PRIVATE_IP" ]]; }
tailnet_records_gone() { [[ -z "$(dig_a "$TAILNET")" && -z "$(dig_a "x.$TAILNET")" ]]; }
assert_staging_machine_certificate() {
  local certificate
  certificate="$(timeout 15 openssl s_client -connect "$PRIVATE_IP:443" -servername "$TAILNET" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName -issuer 2>/dev/null || true)"
  [[ "$certificate" == *"DNS:$TAILNET"* && "$certificate" == *"DNS:*.$TAILNET"* && "$certificate" == *"STAGING"* ]]
}
assert_no_sidecar_tailnet_artifact() {
  # A tenant-admin credential may not be allowed to inspect the infra project.
  # When it is, assert the direct path left no old Sidecar Caddy fragment. A
  # missing permission is reported, not treated as proof either way.
  local out
  if out="$(sc incus-infra exec sidecar -- sh -ceu 'test ! -e /etc/caddy/tailnet-publish && test ! -e /etc/sandcastle/tailnet-publish' 2>&1)"; then
    pass "no legacy Sidecar tailnet-publish artifact"
  elif [[ "$out" == *"does not have permission"* || "$out" == *"not authorized"* ]]; then
    echo "NOTE: restricted credential cannot inspect Tenant Sidecar; direct DNS, Machine Caddy, and certificate assertions remain authoritative"
  else
    fail "inspect legacy Sidecar tailnet-publish artifact: $out"
  fi
}
assert_machine_platform_launchers() {
  local incus_project
  incus_project="$(sc ls "$REF" --json | jq -r --arg p "$PROJECT" '.tenant.incusName | sub("-default$"; "-" + $p)')"
  sc incus --project "$incus_project" exec "$MACHINE" -- sh -ceu 'test -x /.sc/platform/sbin/cloudflared; test -x /.sc/platform/sbin/caddy' \
    || fail "Machine lacks platform connector launchers"
  sc incus --project "$incus_project" exec "$MACHINE" -- systemctl cat "sandcastle-cloudflared-$(printf %s "$TUNNEL" | tr . -).service" | grep -Fq 'ExecStart=/.sc/platform/sbin/cloudflared' \
    || fail "Machine Tunnel unit does not start the platform cloudflared launcher"
  sc incus --project "$incus_project" exec "$MACHINE" -- systemctl cat caddy | grep -Fq '/.sc/platform/sbin/caddy run' \
    || fail "Machine Caddy unit does not start the platform Caddy launcher"
}

step "register disposable Public DNS Zone and create an HTTP Machine"
CF_ZONE_ID="$(cf_get "zones?name=$ZONE" | jq -er 'if length==1 then .[0].id else error("expected one zone") end')"
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
[[ "$TUNNEL_VERBOSE" == *"cloudflare api:"* ]] || fail "verbose tunnel trace lacks Cloudflare API calls"
printf '%s\n' "$TUNNEL_VERBOSE"
assert_machine_platform_launchers
FIRST_RECORD="$(tunnel_record)" || fail "Cloudflare Tunnel record missing"
wait_for "$DNS_TIMEOUT" "public tunnel DNS" public_dns_present
wait_for "$DNS_TIMEOUT" "public tunnel response" public_tunnel_responds "$TUNNEL"
sc tunnel publish "$REF" --port 3000 --hostname "$TUNNEL" >/dev/null
[[ "$(tunnel_record)" == "$FIRST_RECORD" ]] || fail "idempotent publish changed Cloudflare Tunnel record"
public_tunnel_responds "$TUNNEL" || fail "idempotent tunnel publish broke public tunnel response"
sc ls "$REF" | grep -F "$TUNNEL" >/dev/null || fail "sc ls does not render TUNNEL hostname"
expect_fail "already" sc tailnet publish "$REF" --hostname "$TUNNEL"
sc tunnel publish "$REF" --port 3000 --hostname "$SECOND_TUNNEL"
wait_for "$DNS_TIMEOUT" "second tunnel response" public_tunnel_responds "$SECOND_TUNNEL"
sc tunnel unpublish "$REF" --hostname "tunnel-*.$ZONE"
public_tunnel_responds "$SECOND_TUNNEL" || fail "wildcard unpublish removed unrelated tunnel"
sc tunnel unpublish "$REF"
[[ "$(cf_get "zones/$CF_ZONE_ID/dns_records?name=$SECOND_TUNNEL" | jq 'length')" == 0 ]] || fail "omitted hostname left second tunnel DNS"
sc tunnel unpublish "$REF"
[[ "$(cf_get "zones/$CF_ZONE_ID/dns_records?name=$TUNNEL" | jq 'length')" == 0 ]] || fail "Cloudflare record survived unpublish"
wait_for "$DNS_TIMEOUT" "tunnel DNS removal" public_dns_gone
pass "Machine Tunnel lifecycle"

step "direct-Machine Tailnet publication, idempotence, and cleanup"
TAILNET_VERBOSE="$(VERBOSE=1 sc tailnet publish "$REF" --hostname "$TAILNET" 2>&1)" || fail "$TAILNET_VERBOSE"
[[ "$TAILNET_VERBOSE" == *"Tailnet HTTPS published: https://$TAILNET → $MACHINE:443"* ]] || fail "tailnet publish output missing direct-Machine result"
[[ "$TAILNET_VERBOSE" == *"[verbose]"* && "$TAILNET_VERBOSE" != *"$TOKEN"* ]] || fail "verbose Tailnet trace missing progress or leaked credential"
printf '%s\n' "$TAILNET_VERBOSE"
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
sc ls "$REF" | grep -F "$TAILNET" >/dev/null || fail "sc ls does not render TAILNET hostname"
expect_fail "already" sc tunnel publish "$REF" --port 3000 --hostname "$TAILNET"
sc tailnet publish "$REF" --hostname "$SECOND_TAILNET"
wait_for "$DNS_TIMEOUT" "second Tailnet DNS" bash -c '[[ "$(dig +short A "$1" "@$2")" == "$3" ]]' _ "$SECOND_TAILNET" "$RESOLVER" "$PRIVATE_IP"
sc tailnet unpublish "$REF" --hostname "tailnet-*.$ZONE"
sc ls "$REF" | grep -F "$SECOND_TAILNET" >/dev/null || fail "wildcard removed unrelated Tailnet publication"
sc tailnet unpublish "$REF"
sc tailnet unpublish "$REF"
wait_for "$DNS_TIMEOUT" "second Tailnet removal" bash -c '[[ -z "$(dig +short A "$1" "@$2")" ]]' _ "$SECOND_TAILNET" "$RESOLVER"
wait_for "$DNS_TIMEOUT" "Tailnet A record removal" tailnet_records_gone
pass "direct-Machine Tailnet lifecycle"

echo "ALL PASS: Machine publication lifecycle"
