#!/usr/bin/env bash
# e2e Phase 12 — Public DNS Zones (ADR-0027) + explicit Machine Public Hostnames
# (ADR-0028): public names with a Let's Encrypt STAGING certificate per name,
# driven non-interactively with `sc`/`sc-adm`. The human-readable protocol
# (with the extra 12d/12e steps this script does not automate) is
# docs/e2e-sc2.md, Phase 12.
#
# What it proves, in order:
#   12a  zone registry: add / list / duplicate / bad token / nesting refusals
#   12b  Project Domain claim + status, the claim refusals, set-domain no-op
#   12c  `sc create` prints the DNS: line AND the Public name line; both A
#        records reach public DNS; CERT goes pending → ok; `sc project status`
#        shows installed + NOT AFTER; `openssl s_client` serves both SANs from
#        the STAGING issuer; the wildcard vhost answers over the same Caddy
#   12g  `sc create --hostname` with an apex-level name under the zone: the
#        machine carries the derived name AND the explicit one, records + a
#        certificate per name, the private name still serves the tenant-CA
#        leaf; `sc hostname add` on the running machine → its own certificate
#        (the first one is not reissued); the refusals (inside a Project
#        Domain, name held by another machine, domain over a hostname, apex,
#        derived name not removable); `sc hostname remove` → records gone, the
#        name no longer served, the others untouched; `sc create --hostname`
#        of a taken name refused
#   12f  zone remove refused while the domain is claimed; delete → A records
#        gone (per machine); project delete → claim released; zone removable
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
#   SANDCASTLE_E2E_RUN_ID            run id; the project domain is e2e-<id>.<zone>, the explicit
#                                    hostnames api-<id>.<zone> and alt-<id>.<zone>  (default: date-based)
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
FQDN="${MACHINE}.${PD}"                 # web's derived Machine Public Hostname
# 12g: a second machine with an explicit, apex-level hostname under the zone
# (ADR-0028) — plus the derived name, since $PROJECT has a Project Domain.
MACHINE2="api"
REF2="${PROJECT}:${MACHINE2}"
HOST2="${MACHINE2}-${ID}.${ZONE}"       # explicit hostname given at create
ALT="alt-${ID}.${ZONE}"                 # explicit hostname added on the running machine
FQDN2="${MACHINE2}.${PD}"               # api's derived Machine Public Hostname
STAGING_MARK="STAGING"
SUFFIX=""                               # Tenant DNS Suffix, read from `sc ls --json` in 12c

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
  sc delete "$REF2" --yes >/dev/null 2>&1 || true
  sc delete "$REF" --yes >/dev/null 2>&1 || true
  sc project delete "$PROJECT" --yes >/dev/null 2>&1 || true
  if [[ $ZONE_PREREGISTERED -eq 0 ]]; then sc_adm public-dns-zone remove "$ZONE" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "Phase 12 — Public DNS Zones: zone=$ZONE domain=$PD project=$PROJECT machines=$MACHINE,$MACHINE2 hostnames=$HOST2,$ALT (Let's Encrypt staging)"

# ---- shared helpers ------------------------------------------------------------
# machine_json <machine>: that machine's `sc ls --json` record in $PROJECT.
machine_json() { sc ls "${PROJECT}:$1" --json | jq -c --arg m "$1" '.machines[] | select(.name==$m)'; }
dig_a() { dig +short A "$1" "@$RESOLVER" | grep -E '^[0-9.]+$' || true; }
# records_at <name> <ip>: base + wildcard A records of <name> answer <ip>.
records_at() { [[ "$(dig_a "$1")" == "$2" && "$(dig_a "x.$1")" == "$2" ]]; }
# records_gone <name>: neither the base nor the wildcard answers any more.
records_gone() { [[ -z "$(dig_a "$1")" && -z "$(dig_a "x.$1")" ]]; }
# cert_installed <machine> <name>: the per-name mirror reads installed for <name>.
cert_installed() { [[ "$(machine_json "$1" | jq -r --arg h "$2" '.certStates[$h] // .certState // empty')" == "installed" ]]; }
# served_cert <ip> <sni>: SANs + issuer + serial of the certificate Caddy
# serves for that SNI (empty output when the handshake yields none).
served_cert() { openssl s_client -connect "$1:443" -servername "$2" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName -issuer -serial 2>/dev/null || true; }
# assert_staging_cert <ip> <name>: the SNI <name> serves <name> + *.<name> from the STAGING issuer.
assert_staging_cert() {
  local x509; x509="$(served_cert "$1" "$2")"
  [[ -n "$x509" ]] || fail "openssl s_client to $1:443 (SNI $2) served no certificate — is this client on the tenant tailnet?"
  echo "$x509"
  [[ "$x509" == *"DNS:$2"* && "$x509" == *"DNS:*.$2"* ]] || fail "certificate for $2 lacks both SANs"
  [[ "$x509" == *"$STAGING_MARK"* ]] || fail "issuer for $2 is not the Let's Encrypt STAGING hierarchy (was the Auth App deployed with --acme-directory staging?)"
}
cert_serial() { served_cert "$1" "$2" | sed -n 's/^serial=//p'; }

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
# A sibling of $ZONE (not nested under it, so the nesting refusal cannot fire first)
# with a garbage token: Cloudflare must reject the token before anything is stored.
expect_fail "Cloudflare rejected the token" -- sc_adm public-dns-zone add "bad-$ID.${ZONE#*.}" --token-file <(printf %s "not-a-token")
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

# ---- 12c — machine with a derived public name: A records + certificate ---------
step "12c machine contract"
OUT="$(sc create "$REF")" || fail "sc create $REF"
echo "$OUT"
[[ "$OUT" == *"Public name: $FQDN (A record pending, certificate pending — see: sc project status $PROJECT)"* ]] \
  || fail "sc create output lacks the Public name line"
[[ "$OUT" == *"DNS: $MACHINE.$PROJECT."* ]] || fail "sc create printed no DNS: line — every machine keeps its Machine Private Hostname (ADR-0028)"
pass "sc create prints the DNS: line and the Public name line"

SUFFIX="$(sc ls "$REF" --json | jq -r '.tenant.dnsSuffix // empty')"
[[ -n "$SUFFIX" ]] || fail "sc ls --json carries no tenant.dnsSuffix"
PRIVATE="$MACHINE.$PROJECT.$SUFFIX"
[[ "$OUT" == *"DNS: $PRIVATE "* ]] || fail "sc create DNS: line is not the Machine Private Hostname $PRIVATE"
IP=""
have_ip() { IP="$(machine_json "$MACHINE" | jq -r '.privateIP // empty')"; [[ -n "$IP" ]]; }
wait_for 120 "a tenant-bridge IP" have_ip
pass "$MACHINE has tenant-bridge IP $IP (private name $PRIVATE)"
[[ "$(machine_json "$MACHINE" | jq -r .publicHostname)" == "$FQDN" ]] || fail "sc ls does not show publicHostname=$FQDN"
[[ "$(machine_json "$MACHINE" | jq -c '.publicHostnames')" == "[\"$FQDN\"]" ]] || fail "sc ls --json publicHostnames is not exactly [$FQDN]"

a_ok() { records_at "$FQDN" "$IP"; }
wait_for "$DNS_TIMEOUT" "A records $FQDN + x.$FQDN → $IP at $RESOLVER" a_ok
pass "both A records answer $IP"

cert_ok() { cert_installed "$MACHINE" "$FQDN"; }
wait_for "$CERT_TIMEOUT" "CERT installed on $FQDN" cert_ok
pass "cert-state installed"
sc ls "$REF" | awk -v m="$MACHINE" '$2==m' | grep -qw ok || fail "sc ls CERT column is not ok: $(sc ls "$REF")"
pass "sc ls CERT = ok"
STATUS="$(sc project status "$PROJECT" --json)"
echo "$STATUS" | jq -e --arg m "$MACHINE" --arg h "$FQDN" '.machines[] | select(.machine==$m and .publicHostname==$h) | .certState=="installed" and (.certNotAfter|length>0)' >/dev/null \
  || fail "sc project status: $MACHINE/$FQDN not installed with a NOT AFTER: $STATUS"
pass "sc project status shows installed with NOT AFTER $(echo "$STATUS" | jq -r --arg m "$MACHINE" '.machines[]|select(.machine==$m)|.certNotAfter' | head -1)"

assert_staging_cert "$IP" "$FQDN"
pass "Caddy serves both SANs from the Let's Encrypt staging issuer"
CODE="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 --resolve "x.$FQDN:443:$IP" "https://x.$FQDN/_w/" || true)"
[[ "$CODE" == "200" ]] || fail "wildcard vhost https://x.$FQDN/_w/ answered $CODE"
pass "wildcard vhost x.$FQDN serves /_w/ over the same Caddy"

# ---- 12g — explicit Machine Public Hostnames (ADR-0028) ------------------------
step "12g explicit hostnames"
PRIVATE2="$MACHINE2.$PROJECT.$SUFFIX"
OUT="$(sc create "$REF2" --hostname "$HOST2")" || fail "sc create $REF2 --hostname $HOST2"
echo "$OUT"
[[ "$OUT" == *"DNS: $PRIVATE2 "* ]] || fail "sc create --hostname output lacks the DNS: $PRIVATE2 line"
[[ "$OUT" == *"Public name: $HOST2 (A record pending, certificate pending"* ]] || fail "sc create output lacks the Public name line for $HOST2"
[[ "$OUT" == *"Public name: $FQDN2 (A record pending, certificate pending"* ]] || fail "sc create output lacks the Public name line for the derived $FQDN2"
pass "sc create --hostname prints the DNS: line and one Public name line per name (explicit + derived)"
[[ "$(machine_json "$MACHINE2" | jq -c '.publicHostnames')" == "$(jq -nc --arg a "$HOST2" --arg b "$FQDN2" '[$a,$b]|sort')" ]] \
  || fail "sc ls --json publicHostnames is not exactly {$HOST2, $FQDN2}: $(machine_json "$MACHINE2")"
sc ls "$REF2" | grep -q "$HOST2 (+1)" || fail "sc ls FQDN column does not read '$HOST2 (+1)': $(sc ls "$REF2")"
pass "sc ls shows the public name set ($HOST2 (+1); --json lists both)"
LISTING="$(sc hostname list "$REF2")"; echo "$LISTING"
echo "$LISTING" | grep -q "^$HOST2 *explicit *$ZONE" || fail "sc hostname list lacks the explicit row for $HOST2"
echo "$LISTING" | grep -q "^$FQDN2 *derived *$ZONE" || fail "sc hostname list lacks the derived row for $FQDN2"
pass "sc hostname list: $HOST2 explicit + $FQDN2 derived"

IP2=""
have_ip2() { IP2="$(machine_json "$MACHINE2" | jq -r '.privateIP // empty')"; [[ -n "$IP2" ]]; }
wait_for 120 "a tenant-bridge IP for $MACHINE2" have_ip2
pass "$MACHINE2 has tenant-bridge IP $IP2 (private name $PRIVATE2)"
a2_ok() { records_at "$HOST2" "$IP2" && records_at "$FQDN2" "$IP2"; }
wait_for "$DNS_TIMEOUT" "A records of $HOST2 and $FQDN2 (base + wildcard) → $IP2 at $RESOLVER" a2_ok
pass "A records for the apex-level $HOST2 and the derived $FQDN2 answer $IP2"
cert2_ok() { cert_installed "$MACHINE2" "$HOST2" && cert_installed "$MACHINE2" "$FQDN2"; }
wait_for "$CERT_TIMEOUT" "CERT installed on $HOST2 and $FQDN2" cert2_ok
sc ls "$REF2" | awk -v m="$MACHINE2" '$2==m' | grep -qw ok || fail "sc ls CERT column is not ok: $(sc ls "$REF2")"
pass "cert-state installed for both names; sc ls CERT = ok"
assert_staging_cert "$IP2" "$HOST2"
SERIAL_HOST2="$(cert_serial "$IP2" "$HOST2")"
pass "Caddy serves $HOST2 + *.$HOST2 from the staging issuer (serial $SERIAL_HOST2)"
X509="$(served_cert "$IP2" "$PRIVATE2")"
[[ -n "$X509" ]] || fail "openssl s_client (SNI $PRIVATE2) served no certificate — the private name must keep serving"
echo "$X509"
[[ "$X509" == *"DNS:$PRIVATE2"* ]] || fail "the private name's certificate lacks SAN $PRIVATE2"
[[ "$X509" == *"Sandcastle"* && "$X509" != *"$STAGING_MARK"* ]] || fail "SNI $PRIVATE2 is not served from the Sandcastle tenant CA: $X509"
pass "the Machine Private Hostname $PRIVATE2 still serves the tenant-CA leaf"

# add a second explicit name on the running machine
OUT="$(sc hostname add "$REF2" "$ALT")" || fail "sc hostname add $REF2 $ALT"
echo "$OUT"
[[ "$OUT" == *"Public name: $ALT (certificate pending"* ]] || fail "sc hostname add output lacks 'Public name: $ALT (certificate pending…)'"
echo "$OUT" | grep -q "^$ALT *explicit *$ZONE" || fail "sc hostname add table lacks $ALT"
echo "$OUT" | grep -q "^$HOST2 *explicit *$ZONE" || fail "sc hostname add table lacks $HOST2"
echo "$OUT" | grep -q "^$FQDN2 *derived *$ZONE" || fail "sc hostname add table lacks the derived $FQDN2"
pass "sc hostname add lists all three names (2 explicit + derived)"
three_names() { [[ "$(machine_json "$MACHINE2" | jq -c '.publicHostnames')" == "$(jq -nc --arg a "$HOST2" --arg b "$FQDN2" --arg c "$ALT" '[$a,$b,$c]|sort')" ]]; }
wait_for 60 "sc ls --json to list all three names of $MACHINE2" three_names
pass "sc ls --json lists all three public names"
alt_records() { records_at "$ALT" "$IP2"; }
wait_for "$DNS_TIMEOUT" "A records $ALT + x.$ALT → $IP2 at $RESOLVER" alt_records
pass "A records for $ALT answer $IP2"
alt_cert_ok() { cert_installed "$MACHINE2" "$ALT"; }
wait_for "$CERT_TIMEOUT" "CERT installed on $ALT" alt_cert_ok
pass "cert-state installed for $ALT"
alt_served() { [[ "$(served_cert "$IP2" "$ALT")" == *"DNS:$ALT"* ]]; }
wait_for 60 "Caddy to serve $ALT after the push's --refresh" alt_served
assert_staging_cert "$IP2" "$ALT"
pass "Caddy serves $ALT + *.$ALT from its own staging certificate"
assert_staging_cert "$IP2" "$HOST2"
[[ "$(cert_serial "$IP2" "$HOST2")" == "$SERIAL_HOST2" ]] || fail "adding $ALT reissued the certificate of $HOST2 (serial changed)"
pass "$HOST2 still serves its first certificate (serial $SERIAL_HOST2) — one certificate per hostname"

# refusals (all --dry-run: nothing changes)
expect_fail "machine hostname \"sub.$PD\" overlaps project domain \"$PD\" claimed by project \"$PROJECT\" in this tenant" -- sc hostname add "$REF2" "sub.$PD" --dry-run
expect_fail "machine hostname \"$HOST2\" overlaps \"$HOST2\" held by machine \"$REF2\" in this tenant" -- sc hostname add "$REF" "$HOST2" --dry-run
expect_fail "project domain \"$HOST2\" overlaps hostname \"$HOST2\" held by machine \"$REF2\" in this tenant" -- sc project create "x-$ID" --domain "$HOST2" --dry-run
expect_fail "is a zone apex" -- sc hostname add "$REF2" "$ZONE" --dry-run
expect_fail "machine hostname \"$FQDN2\" is not held by machine \"$REF2\"" -- sc hostname remove "$REF2" "$FQDN2" --dry-run
three_names || fail "a refused --dry-run changed the public-name set of $MACHINE2"
pass "the refused dry-runs changed nothing"

# remove the added name
OUT="$(sc hostname remove "$REF2" "$ALT")" || fail "sc hostname remove $REF2 $ALT"
echo "$OUT"
[[ "$OUT" == *"Released $ALT from machine $REF2."* ]] || fail "sc hostname remove output lacks 'Released $ALT from machine $REF2.'"
LISTING="$(sc hostname list "$REF2")"
echo "$LISTING" | grep -q "^$ALT " && fail "sc hostname list still shows $ALT after remove"
echo "$LISTING" | grep -q "^$HOST2 " || fail "sc hostname list lost $HOST2 on the remove of $ALT"
pass "sc hostname list no longer shows $ALT"
alt_gone() { records_gone "$ALT"; }
wait_for "$DNS_TIMEOUT" "A records of $ALT to disappear" alt_gone
pass "both A records of $ALT gone after remove"
two_names() { [[ "$(machine_json "$MACHINE2" | jq -c '.publicHostnames')" == "$(jq -nc --arg a "$HOST2" --arg b "$FQDN2" '[$a,$b]|sort')" ]]; }
wait_for 60 "sc ls --json to drop $ALT" two_names
alt_unmirrored() { [[ -z "$(machine_json "$MACHINE2" | jq -r --arg h "$ALT" '.certStates[$h] // empty')" ]]; }
wait_for 120 "cert-state to drop $ALT" alt_unmirrored
pass "sc ls --json lists two names again; cert-state no longer carries $ALT"
STATUS="$(sc project status "$PROJECT" --json)"
echo "$STATUS" | jq -e --arg m "$MACHINE2" --arg h "$ALT" '[.machines[] | select(.machine==$m and .publicHostname==$h)] | length == 0' >/dev/null \
  || fail "sc project status still lists $ALT for $MACHINE2: $STATUS"
echo "note: the retained machine_certificates row for $ALT is Auth-Database-only (sc project status reads the instance mirror) — verify it with sqlite3 in the appliance if needed (docs/e2e-sc2.md 12g)"
pass "sc project status lists $MACHINE2 without $ALT ($HOST2 and $FQDN2 remain)"
alt_not_served() { [[ "$(served_cert "$IP2" "$ALT")" != *"DNS:$ALT"* ]]; }
wait_for 120 "Caddy to stop serving $ALT (hostnames file pushed + --refresh)" alt_not_served
assert_staging_cert "$IP2" "$HOST2"
[[ "$(cert_serial "$IP2" "$HOST2")" == "$SERIAL_HOST2" ]] || fail "removing $ALT reissued the certificate of $HOST2 (serial changed)"
pass "SNI $ALT no longer served; $HOST2 still serves its certificate (serial $SERIAL_HOST2)"

# the explicit name is still reserved by api: a second machine cannot take it
expect_fail "machine hostname \"$HOST2\" overlaps \"$HOST2\" held by machine \"$REF2\" in this tenant" -- sc create "${PROJECT}:api2" --hostname "$HOST2" --dry-run
sc ls "${PROJECT}:api2" --json | jq -e '.machines | length == 0' >/dev/null || fail "sc create --dry-run created ${PROJECT}:api2"
pass "sc create --hostname of a taken name is refused and creates nothing"

# ---- 12f — guards, then cleanup ---------------------------------------------------
step "12f guards"
# ADR-0028 slice 3 retired the "has machines with a public name" refusal of
# unset-domain: with machines present it is allowed (dry-run here — a real
# unset would release web's and api's derived names).
sc project unset-domain "$PROJECT" --dry-run | grep -q "\[dry-run\]" \
  || fail "sc project unset-domain --dry-run with machines must be allowed (ADR-0028)"
pass "unset-domain is allowed with machines (dry-run)"
expect_fail "still has claimed project domains" -- sc_adm public-dns-zone remove "$ZONE"

step "cleanup"
sc delete "$REF2" --yes || fail "sc delete $REF2"
a2_gone() { records_gone "$HOST2" && records_gone "$FQDN2"; }
wait_for "$DNS_TIMEOUT" "A records of $HOST2 and $FQDN2 to disappear" a2_gone
pass "A records of $HOST2 and $FQDN2 gone after delete"
sc delete "$REF" --yes || fail "sc delete $REF"
a_gone() { records_gone "$FQDN"; }
wait_for "$DNS_TIMEOUT" "A records of $FQDN to disappear" a_gone
pass "both A records of $FQDN gone after delete"
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
echo "ALL PASS — Phase 12 Public DNS Zones + explicit hostnames e2e (Let's Encrypt staging, zone $ZONE)"
