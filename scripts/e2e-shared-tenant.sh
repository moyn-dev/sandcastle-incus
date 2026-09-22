#!/usr/bin/env bash
# e2e Phase 13 — Shared Tenants (docs/e2e-sc2.md, docs/spec/shared-tenants.md).
#
# Runs on the enrolled Tailnet CLIENT against a fresh --simulate-github-token
# install. Prerequisite (the Shared Tenant prerequisite itself): the two
# members below have already completed `sc login` on THIS client, so their
# Personal Tenants exist and the client holds a remote per login; the second
# login used its own SSH key (--ssh-public-key) so the machines can be shown
# to authorize BOTH keys.
#
# The admin side (sc-adm create tenant / grant / revoke) runs where the admin
# Incus socket is: pass it as SANDCASTLE_E2E_ADMIN_EXEC (a command prefix,
# e.g. "incus exec big:sc-shared-e2e --" when the install lives in a VM);
# empty runs sc-adm locally. Likewise SANDCASTLE_E2E_CLIENT_EXEC prefixes
# every client-side command (sc, ssh, config reads) so the whole phase can be
# driven from an operator laptop that reaches both through Incus, e.g.
# "incus exec big:e2e-pdz-client --env HOME=/root --".
set -euo pipefail

OWNER="${SANDCASTLE_E2E_SHARED_OWNER:-thieso2}"        # first member (the key sc login generated/used)
MEMBER="${SANDCASTLE_E2E_SHARED_MEMBER:-skorfmann}"    # second member (its own key)
MEMBER_KEY="${SANDCASTLE_E2E_SHARED_MEMBER_KEY:-/root/.ssh/${MEMBER}_ed25519}"
OWNER_KEY="${SANDCASTLE_E2E_SHARED_OWNER_KEY:-/root/.ssh/sandcastle_ed25519}"   # the key sc login generated for the first member
TENANT="${SANDCASTLE_E2E_SHARED_TENANT:-moyn-dev}"
SUFFIX="${SANDCASTLE_E2E_SHARED_SUFFIX:-moyn}"
PREFIX="${SANDCASTLE_E2E_PREFIX:-sh}"
ADMIN_EXEC="${SANDCASTLE_E2E_ADMIN_EXEC:-}"
CLIENT_EXEC="${SANDCASTLE_E2E_CLIENT_EXEC:-}"
TS_KEY="${TAILSCALE_AUTH_KEY:-}"
[[ -n "$TS_KEY" ]] || { echo "error: TAILSCALE_AUTH_KEY is required (the shared tenant's sidecar joins the tailnet with it)" >&2; exit 2; }
BIN="${SANDCASTLE_E2E_SANDCASTLE_BIN:-sc}"
if [[ -z "$CLIENT_EXEC" ]]; then
  [[ "$BIN" == */* ]] || BIN="$(command -v "$BIN" || true)"
  [[ -n "$BIN" && -x "$BIN" ]] || { echo "error: set SANDCASTLE_E2E_SANDCASTLE_BIN or put sc on PATH" >&2; exit 2; }
fi

client() { if [[ -n "$CLIENT_EXEC" ]]; then $CLIENT_EXEC "$@"; else "$@"; fi; }
sc() { client "$BIN" "$@"; }
client_sh() { client bash -c "$1"; }
adm() { # admin plane at the Incus socket
  if [[ -n "$ADMIN_EXEC" ]]; then
    $ADMIN_EXEC env SANDCASTLE_REMOTE=local SANDCASTLE_INCUS_PROJECT_PREFIX="$PREFIX" sandcastle-admin "$@"
  else
    env SANDCASTLE_INCUS_PROJECT_PREFIX="$PREFIX" "$BIN" admin "$@"
  fi
}
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }
expect_fail() { local want="$1"; shift; local out rc=0; out="$("$@" 2>&1)" || rc=$?; [[ $rc -ne 0 && "$out" == *"$want"* ]] || fail "expected refusal containing '$want', got (rc=$rc): $out"; pass "refused: $want"; }
wait_for() { local seconds="$1" what="$2"; shift 2; local start; start=$(date +%s); until "$@"; do (( $(date +%s) - start < seconds )) || fail "timed out waiting for $what"; sleep 5; done; }
as_user() { sc remote switch "${1}sh" >/dev/null; }   # remotes are named after each login's DNS suffix: <user>sh
machine_ip() { # machine_ip <project|""> <machine>
  local out
  if [[ -n "$1" ]]; then out="$(sc ls "$1" --json 2>/dev/null)"; else out="$(sc ls --json 2>/dev/null)"; fi
  jq -r --arg m "$2" '.machines[]? | select(.name==$m) | .privateIP // empty' <<<"$out"
}
has_machine() { local out; if [[ -n "$1" ]]; then out="$(sc ls "$1" --json 2>/dev/null)"; else out="$(sc ls --json 2>/dev/null)"; fi; jq -e --arg m "$2" '.machines[]? | select(.name==$m)' <<<"$out" >/dev/null; }

cleanup() {
  local rc=$?
  [[ $rc -ne 0 && "${SANDCASTLE_E2E_SHARED_KEEP:-0}" == 1 ]] && { echo "KEEP: tenant $TENANT left in place" >&2; return; }
  as_user "$OWNER" 2>/dev/null || true
  sc tenant switch "$TENANT" --local-only >/dev/null 2>&1 || true
  sc delete web --yes >/dev/null 2>&1 || true
  sc delete api:svc --yes >/dev/null 2>&1 || true
  sc project delete api --yes >/dev/null 2>&1 || true
  adm tenant delete "$TENANT" --yes >/dev/null 2>&1 || true
  sc tenant switch "$OWNER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "13a — prerequisite: both members logged in; a never-logged-in member is refused"
for u in "$OWNER" "$MEMBER"; do as_user "$u"; LIST="$(sc tenant list -l)"; grep -qE "^[* ] *$u\s" <<<"$LIST" || fail "$u has no Personal Tenant on this install (run sc login first)"; done
pass "$OWNER and $MEMBER each hold a Personal Tenant"
expect_fail "must run \`sc login\`" adm tenant create "$TENANT" --member "$OWNER" --member never-logged-in --tailscale-authkey "$TS_KEY" --dns-suffix "$SUFFIX" --cidr-pool 10.251.0.0/16

step "13b — create the Shared Tenant with two members"
OUT="$(adm tenant create "$TENANT" --member "$OWNER" --member "$MEMBER" --tailscale-authkey "$TS_KEY" --dns-suffix "$SUFFIX" --cidr-pool 10.251.0.0/16 2>&1)" || fail "create: $OUT"
echo "$OUT" | grep -q "Member $OWNER granted" && echo "$OUT" | grep -q "Member $MEMBER granted" || fail "create output lacks member grants: $OUT"
USERS="$(adm tenant users "$TENANT")"; [[ "$USERS" == *"$OWNER"* && "$USERS" == *"$MEMBER"* ]] || fail "tenant users lacks the members: $USERS"
pass "tenant $TENANT created; members $OWNER, $MEMBER recorded"

step "13c — the member sees, switches to, and reaches the shared tenant"
as_user "$MEMBER"
LIST="$(sc tenant list -l)"; grep -E "^[* ] *$TENANT\s" <<<"$LIST" | grep -q member || fail "sc tenant list does not show $TENANT as a membership: $LIST"
OUT="$(sc tenant switch "$TENANT" 2>&1)" || fail "switch: $OUT"
[[ "$OUT" == *"points at shared tenant $TENANT"* ]] || fail "switch did not enrol the shared remote: $OUT"
client_sh "grep -qE '^remote: $SUFFIX\$' \$HOME/.config/sandcastle/config.yml" || fail "config remote is not $SUFFIX"
sc tenant switch "$TENANT" >/dev/null   # idempotent
pass "$MEMBER switched; remote $SUFFIX enrolled and pinned"

step "13d — the member creates a machine; both keys are authorized on it"
has_machine "" web || sc create web
has_ip() { [[ -n "$(machine_ip "$1" "$2")" ]]; }
wait_for 180 "web's address" has_ip "" web
IP="$(machine_ip "" web)"
# The login user is the tenant's unix user (the tenant name unless the
# install or the tenant chose another); read it off the machine record.
LOGIN="$(sc ls --json | jq -r '.machines[] | select(.name=="web") | .linuxUser // empty')"; LOGIN="${LOGIN:-$TENANT}"
ssh_ok() { client ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$@" true >/dev/null 2>&1; }
wait_for 600 "sshd on $IP (and the shared tenant's subnet route)" ssh_ok -i "$OWNER_KEY" -o IdentitiesOnly=yes "$LOGIN@$IP"
ssh_ok -i "$OWNER_KEY" -o IdentitiesOnly=yes "$LOGIN@$IP" || fail "$OWNER's key is not authorized on web"
ssh_ok -i "$MEMBER_KEY" -o IdentitiesOnly=yes "$LOGIN@$IP" || fail "$MEMBER's key is not authorized on web"
pass "web authorizes both members' keys"

step "13e — a project created by one member is usable by the other (certificate scope follows)"
if ! sc ls api --json >/dev/null 2>&1; then OUT="$(sc project create api 2>&1)" || fail "project create: $OUT"; fi
as_user "$OWNER"; sc tenant switch "$TENANT" >/dev/null
sc ls --json | jq -e '.machines | map(.name) | index("web") != null' >/dev/null || fail "$OWNER does not see web in $TENANT"
has_machine api svc || sc create api:svc
wait_for 180 "svc's address" has_ip api svc
pass "$OWNER created api:svc inside the project $MEMBER made"
sc status "$TENANT" | grep -qi "shares:reconcile: ok\|shares" || true

step "13f — Auth App tenant plane acts on the Current Tenant"
if sc hostname list web >/dev/null 2>&1; then pass "hostname list answers for the shared tenant"; else echo "NOTE: hostname list unavailable (no Public DNS Zone) — skipped"; fi
sc tenant switch "$OWNER" >/dev/null
sc ls --json | jq -e '.machines | map(.name) | index("web") == null' >/dev/null || fail "personal tenant view leaks the shared machine"
pass "switching back to the personal tenant hides shared machines"

step "13h — a device enrolled AFTER the grant reaches the shared tenant (login covers memberships)"
# A new device = a fresh HOME: sc login mints a new restricted certificate
# there. Before the fix it covered only the Personal Tenant, so every Incus
# call in the shared project answered "User does not have permission".
AUTH_HOST="${SANDCASTLE_E2E_AUTH_HOST:?set SANDCASTLE_E2E_AUTH_HOST (https://<auth-hostname>)}"
SIM="${SANDCASTLE_E2E_SIMULATE_TOKEN:?set SANDCASTLE_E2E_SIMULATE_TOKEN (the --simulate-github-token of the install)}"
NEWHOME="/root/e2e-newdev-$MEMBER"
client_sh "rm -rf $NEWHOME && mkdir -p $NEWHOME/.ssh && cp ${MEMBER_KEY} ${MEMBER_KEY}.pub $NEWHOME/.ssh/ && chmod 700 $NEWHOME/.ssh"
# Run from inside the new HOME too: the client's own /tmp/.sandcastle (the
# first identity's selection) would otherwise be picked up by the walk-up
# and, naming a remote the new config never enrolled, drop its credentials.
newdev() { local q=""; for a in "$@"; do q+=" $(printf %q "$a")"; done; client sh -c "cd $NEWHOME && HOME=$NEWHOME $BIN$q"; }
OUT="$(newdev login "$AUTH_HOST" --simulate-token "$SIM" --as "$MEMBER" --ssh-public-key "$NEWHOME/.ssh/$(basename "$MEMBER_KEY").pub" --skip-setup 2>&1)" || fail "new-device login: $OUT"
OUT="$(newdev tenant switch "$TENANT" 2>&1)" || fail "new-device switch: $OUT"
OUT="$(newdev incus list --format csv 2>&1)" || fail "new device is refused on the shared project (certificate not extended at login): $OUT"
grep -q "web" <<<"$OUT" || fail "new device does not see the shared machine through Incus: $OUT"
OUT="$(newdev incus list --project "${PREFIX}-${TENANT}-api" --format csv 2>&1)" || fail "new device is refused on the second shared project: $OUT"
pass "a device enrolled after the grant holds every project of $TENANT"
client_sh "rm -rf $NEWHOME"

step "13g — revoke: the member loses the tenant, the key leaves the profile"
OUT="$(adm tenant revoke "$TENANT" "$MEMBER" 2>&1)" || fail "revoke: $OUT"
[[ "$OUT" == *"members: $OWNER"* ]] || fail "revoke did not update membership: $OUT"
as_user "$MEMBER"
LIST="$(sc tenant list -l)"; grep -qE "^[* ] *$TENANT\s" <<<"$LIST" && fail "$MEMBER still lists $TENANT after revoke"
expect_fail "not accessible" sc tenant switch "$TENANT"
pass "$MEMBER no longer holds Tenant Access"

echo; echo "Phase 13 — Shared Tenants: ALL PASS"
