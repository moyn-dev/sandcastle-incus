#!/usr/bin/env bash
# e2e Phase 12 — Public DNS Zones (ADR-0027): Machine Public Hostnames with a
# Let's Encrypt STAGING certificate, driven non-interactively with `sc`/`sc-adm`.
# The human-readable protocol (with the extra 12d/12e steps this script does not
# automate) is docs/e2e-sc2.md, Phase 12.
#
# What it proves, in order:
#   12a  zone registry: add / list / duplicate / bad token / nesting refusals
#   12b  Project Domain claim + status, the claim refusals, set-domain no-op
#   12c  `sc create` prints the Public name line; both A records reach public
#        DNS; CERT goes pending → ok; `sc project status` shows installed + NOT
#        AFTER; `openssl s_client` serves both SANs from the STAGING issuer; the
#        wildcard vhost answers over the same Caddy
#   12f  unset-domain / zone remove refused while the machine exists; delete
#        → A records gone; project delete → claim released; zone removable
#
# SKIPPED (exit 0, "SKIP:") when SANDCASTLE_E2E_CLOUDFLARE_TOKEN or
# SANDCASTLE_E2E_PUBLIC_DNS_ZONE is unset — never a failure.
#
# Prereqs (a TEST install, never production — the zone gets real records):
#   - The install was deployed with
#         --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory
#     (staging: no production budget is spent; browser trust is NOT asserted).
#   - This client ran `sc login` as a Sandcastle Admin (the zone verbs need it)
#     and is on the tenant tailnet with the subnet route approved (the
#     openssl/curl checks dial the machine's tenant-bridge IP).
#   - `dig`, `openssl`, `curl`, `jq` on PATH.
#
# Env:
#   SANDCASTLE_E2E_CLOUDFLARE_TOKEN  Cloudflare API token: Zone>DNS>Edit + Zone>Zone>Read on the zone  [gate]
#   SANDCASTLE_E2E_PUBLIC_DNS_ZONE   the dedicated test zone, e.g. e2e.example.dev                    [gate]
#   SANDCASTLE_E2E_RUN_ID            run id; the project domain is e2e-<id>.<zone>  (default: date-based)
#   SANDCASTLE_E2E_SANDCASTLE_BIN    the fat binary (default: <repo>/bin/sc, else `sc` on PATH)
#   SANDCASTLE_E2E_PDZ_RESOLVER      public resolver for the A-record checks (default 1.1.1.1)
#   SANDCASTLE_E2E_PDZ_DNS_TIMEOUT   seconds to wait for A records to appear / vanish (default 180)
#   SANDCASTLE_E2E_PDZ_CERT_TIMEOUT  seconds to wait for CERT ok (default 600)
#   SANDCASTLE_E2E_PDZ_KEEP=1        leave the project + zone in place on failure (for inspection)
set -euo pipefail

TOKEN="${SANDCASTLE_E2E_CLOUDFLARE_TOKEN:-}"
ZONE="${SANDCASTLE_E2E_PUBLIC_DNS_ZONE:-}"
if [[ -z "$TOKEN" || -z "$ZONE" ]]; then
  echo "SKIP: Phase 12 (Public DNS Zones) — set SANDCASTLE_E2E_CLOUDFLARE_TOKEN and SANDCASTLE_E2E_PUBLIC_DNS_ZONE to run it"
  exit 0
fi
ZONE="$(printf %s "$ZONE" | tr 'A-Z' 'a-z' | sed 's/\.$//')"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${SANDCASTLE_E2E_SANDCASTLE_BIN:-}"
if [[ -z "$BIN" ]]; then
  if [[ -x "$REPO_ROOT/bin/sc" ]]; then BIN="$REPO_ROOT/bin/sc"; else BIN="$(command -v sc || true)"; fi
fi
[[ -n "$BIN" && -x "$BIN" ]] || { echo "error: no sandcastle binary (set SANDCASTLE_E2E_SANDCASTLE_BIN or make build)" >&2; exit 2; }
for tool in dig openssl curl jq; do
  command -v "$tool" >/dev/null || { echo "error: $tool is required on PATH" >&2; exit 2; }
done

sc()     { "$BIN" "$@"; }
sc_adm() { "$BIN" admin "$@"; }   # sc admin … is the sc-adm tree (same binary, same code)

RESOLVER="${SANDCASTLE_E2E_PDZ_RESOLVER:-1.1.1.1}"
DNS_TIMEOUT="${SANDCASTLE_E2E_PDZ_DNS_TIMEOUT:-180}"
CERT_TIMEOUT="${SANDCASTLE_E2E_PDZ_CERT_TIMEOUT:-600}"
RUN="${SANDCASTLE_E2E_RUN_ID:-e2e-$(date -u +%Y%m%d-%H%M%S)}"
RUN="$(printf %s "$RUN" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-\n' '-' | sed 's/^-*//; s/-*$//')"
ID="${RUN#e2e-}"
PROJECT="zp-${ID:0:30}"
PD="e2e-${ID}.${ZONE}"
MACHINE="web"
REF="${PROJECT}:${MACHINE}"
FQDN="${MACHINE}.${PD}"
STAGING_MARK="STAGING"

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

# expect_fail <substring> -- <command…>: the command must exit non-zero and
# print <substring> (stdout or stderr).
expect_fail() {
  local want="$1"; shift; [[ "$1" == "--" ]] && shift
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  [[ $rc -ne 0 ]] || fail "expected '$*' to be refused, it succeeded: $out"
  [[ "$out" == *"$want"* ]] || fail "expected '$*' to say \"$want\", got: $out"
  pass "refused: $want"
}

wait_for() { # wait_for <seconds> <description> <command…>  (command's exit 0 = done)
  local timeout="$1" what="$2"; shift 2
  local start; start=$(date +%s)
  while ! "$@"; do
    if (( $(date +%s) - start >= timeout )); then fail "timed out after ${timeout}s waiting for $what"; fi
    sleep 5
  done
}

ZONE_PREREGISTERED=0
cleanup() {
  local rc=$?
  if [[ $rc -ne 0 && "${SANDCASTLE_E2E_PDZ_KEEP:-0}" == "1" ]]; then
    echo "KEEP: leaving project $PROJECT and zone $ZONE in place" >&2; return
  fi
  sc delete "$REF" --yes >/dev/null 2>&1 || true
  sc project delete "$PROJECT" --yes >/dev/null 2>&1 || true
  if [[ $ZONE_PREREGISTERED -eq 0 ]]; then sc_adm public-dns-zone remove "$ZONE" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "Phase 12 — Public DNS Zones: zone=$ZONE domain=$PD project=$PROJECT machine=$MACHINE (Let's Encrypt staging)"

# ---- 12a — zone registry (admin) ---------------------------------------------
step "12a zone registry"
LIST="$(sc_adm public-dns-zone list --output json)" || fail "sc-adm public-dns-zone list failed — is this client logged in as a Sandcastle Admin?"
if echo "$LIST" | jq -e --arg z "$ZONE" 'map(select(.zone==$z)) | length > 0' >/dev/null; then
  ZONE_PREREGISTERED=1
  echo "note: $ZONE is already registered on this install; reusing it (it will not be removed at the end)"
else
  sc_adm public-dns-zone add "$ZONE" --token-file <(printf %s "$TOKEN") || fail "public-dns-zone add $ZONE"
fi
LIST="$(sc_adm public-dns-zone list --output json)"
echo "$LIST" | jq -e --arg z "$ZONE" 'map(select(.zone==$z)) | .[0] | (.cloudflareZoneID|length>0) and (.tokenFingerprint|length>0)' >/dev/null \
  || fail "zone $ZONE not listed with a Cloudflare id and a token fingerprint: $LIST"
pass "$ZONE listed with a Cloudflare id and a token fingerprint"
expect_fail "already registered" -- sc_adm public-dns-zone add "$ZONE" --token-file <(printf %s "$TOKEN")
expect_fail "Cloudflare rejected the token" -- sc_adm public-dns-zone add "garbage-$ID.$ZONE" --token-file <(printf %s "not-a-token")
expect_fail "zones may not nest" -- sc_adm public-dns-zone add "sub.$ZONE" --token-file <(printf %s "$TOKEN")
[[ "$(sc_adm public-dns-zone list --output json | jq -c 'map(.zone)|sort')" == "$(echo "$LIST" | jq -c 'map(.zone)|sort')" ]] \
  || fail "the registry changed after refused adds"
pass "registry unchanged after the refused adds"

# ---- 12b — Project Domain claim (tenant) ---------------------------------------
step "12b project domain"
sc project create "$PROJECT" --domain "$PD" || fail "sc project create $PROJECT --domain $PD"
STATUS="$(sc project status "$PROJECT" --json)"
echo "$STATUS" | jq -e --arg d "$PD" --arg z "$ZONE" '.domain==$d and .zone==$z' >/dev/null \
  || fail "sc project status $PROJECT: want domain=$PD zone=$ZONE, got: $STATUS"
pass "sc project status $PROJECT → Domain: $PD (zone $ZONE)"
sc_adm public-dns-zone list --output json | jq -e --arg z "$ZONE" 'map(select(.zone==$z))[0].claims >= 1' >/dev/null \
  || fail "zone $ZONE does not count the claim"
pass "public-dns-zone list counts the claim"
expect_fail "is a zone apex" -- sc project create "apex-$ID" --domain "$ZONE" --dry-run
expect_fail "no Public DNS Zone covers" -- sc project create "nz-$ID" --domain "e2e-$ID.nosuch.example" --dry-run
expect_fail "overlaps \"$PD\" claimed by project \"$PROJECT\"" -- sc project create "ov-$ID" --domain "a.$PD" --dry-run
sc project set-domain "$PROJECT" "$PD" | grep -q "already claimed by this project" \
  || fail "set-domain with the same domain must be a no-op"
pass "set-domain with the same domain is a no-op"

# ---- 12c — zone-mode machine: A records + certificate ---------------------------
step "12c machine contract"
OUT="$(sc create "$REF")" || fail "sc create $REF"
echo "$OUT"
[[ "$OUT" == *"Public name: $FQDN (A record pending, certificate pending — see: sc project status $PROJECT)"* ]] \
  || fail "sc create output lacks the Public name line"
[[ "$OUT" != *"DNS:"* ]] || fail "sc create printed a DNS: line for a zone-mode machine"
pass "sc create prints the Public name line (and no DNS: line)"

machine_json() { sc ls "$REF" --json | jq -c --arg m "$MACHINE" '.machines[] | select(.name==$m)'; }
IP=""
have_ip() { IP="$(machine_json | jq -r '.privateIP // empty')"; [[ -n "$IP" ]]; }
wait_for 120 "a tenant-bridge IP" have_ip
pass "$MACHINE has tenant-bridge IP $IP"
[[ "$(machine_json | jq -r .publicHostname)" == "$FQDN" ]] || fail "sc ls does not show publicHostname=$FQDN"

dig_a() { dig +short A "$1" "@$RESOLVER" | grep -E '^[0-9.]+$' || true; }
a_ok() { [[ "$(dig_a "$FQDN")" == "$IP" && "$(dig_a "x.$FQDN")" == "$IP" ]]; }
wait_for "$DNS_TIMEOUT" "A records $FQDN + x.$FQDN → $IP at $RESOLVER" a_ok
pass "both A records answer $IP"

cert_ok() { [[ "$(machine_json | jq -r '.certState // empty')" == "installed" ]]; }
wait_for "$CERT_TIMEOUT" "CERT installed on $FQDN" cert_ok
pass "cert-state installed"
sc ls "$REF" | awk -v m="$MACHINE" '$2==m' | grep -qw ok || fail "sc ls CERT column is not ok: $(sc ls "$REF")"
pass "sc ls CERT = ok"
STATUS="$(sc project status "$PROJECT" --json)"
echo "$STATUS" | jq -e --arg m "$MACHINE" '.machines[] | select(.machine==$m) | .certState=="installed" and (.certNotAfter|length>0)' >/dev/null \
  || fail "sc project status: $MACHINE not installed with a NOT AFTER: $STATUS"
pass "sc project status shows installed with NOT AFTER $(echo "$STATUS" | jq -r --arg m "$MACHINE" '.machines[]|select(.machine==$m)|.certNotAfter')"

X509="$(openssl s_client -connect "$IP:443" -servername "$FQDN" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName -issuer 2>/dev/null)" \
  || fail "openssl s_client to $IP:443 (SNI $FQDN) served no certificate — is this client on the tenant tailnet?"
echo "$X509"
[[ "$X509" == *"DNS:$FQDN"* && "$X509" == *"DNS:*.$FQDN"* ]] || fail "certificate lacks both SANs"
[[ "$X509" == *"$STAGING_MARK"* ]] || fail "issuer is not the Let's Encrypt STAGING hierarchy (was the Auth App deployed with --acme-directory staging?)"
pass "Caddy serves both SANs from the Let's Encrypt staging issuer"
CODE="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 --resolve "x.$FQDN:443:$IP" "https://x.$FQDN/_w/" || true)"
[[ "$CODE" == "200" ]] || fail "wildcard vhost https://x.$FQDN/_w/ answered $CODE"
pass "wildcard vhost x.$FQDN serves /_w/ over the same Caddy"

# ---- 12f — guards, then cleanup ---------------------------------------------------
step "12f guards"
expect_fail "has machines with a public name: $MACHINE" -- sc project unset-domain "$PROJECT"
expect_fail "still has claimed project domains" -- sc_adm public-dns-zone remove "$ZONE"

step "cleanup"
sc delete "$REF" --yes || fail "sc delete $REF"
a_gone() { [[ -z "$(dig_a "$FQDN")" && -z "$(dig_a "x.$FQDN")" ]]; }
wait_for "$DNS_TIMEOUT" "A records of $FQDN to disappear" a_gone
pass "both A records gone after delete"
sc project delete "$PROJECT" --yes || fail "sc project delete $PROJECT"
sc_adm public-dns-zone list --output json | jq -e --arg z "$ZONE" 'map(select(.zone==$z))[0].claims == 0' >/dev/null \
  || fail "claim $PD still counted after project delete"
pass "claim released"
if [[ $ZONE_PREREGISTERED -eq 0 ]]; then
  sc_adm public-dns-zone remove "$ZONE" || fail "public-dns-zone remove $ZONE after the claim was released"
  pass "zone removed"
fi
trap - EXIT
echo
echo "ALL PASS — Phase 12 Public DNS Zones e2e (Let's Encrypt staging, zone $ZONE)"
