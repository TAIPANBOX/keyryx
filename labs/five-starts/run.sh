#!/usr/bin/env bash
# Five starts of a real vouchryx against a real custody, each ended by kill -9,
# and a token asked for after each one that is meant to get one. Everything lives
# in a directory of its own and on loopback ports. See README.md here.
#
#   labs/five-starts/run.sh paced    each start waits for its token
#   labs/five-starts/run.sh burst    the first four are killed as soon as they
#                                    hold a key, and only the fifth asks for a token
set -euo pipefail

mode=${1:-paced}
case "$mode" in paced | burst) ;; *) echo "usage: $0 paced|burst" >&2; exit 2 ;; esac
: "${KEYRYX_BIN:?the keyryx binary under test}"
: "${VOUCHRYX_BIN:?the vouchryx binary}"
: "${VOUCHRYX_DEMO_BIN:?the vouchryx-demo binary}"
OLD_KEYRYX_BIN=${OLD_KEYRYX_BIN:-}
KPORT=${KPORT:-14340}
VPORT=${VPORT:-14310}
LAST_WAIT=${LAST_WAIT:-480}

dir=$(mktemp -d "${TMPDIR:-/tmp}/five-starts.XXXXXX")
chmod 700 "$dir"
custody="http://127.0.0.1:$KPORT"
vouchryx="http://127.0.0.1:$VPORT"
kpid=""
vpid=""
stop() {
	local pid
	for pid in "$vpid" "$kpid"; do
		[ -n "$pid" ] && kill -9 "$pid" 2>/dev/null || true
	done
}
trap stop EXIT
say() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }

# The credential, the root key and a policy of one delegated name, with the
# shortest overlap and publish-ahead custody takes, so a run lasts minutes.
secret=$(openssl rand -hex 24)
printf '%s' "$secret" >"$dir/bearer"
openssl rand -hex 32 | tr -d '\n' >"$dir/root.key"
chmod 400 "$dir/bearer" "$dir/root.key"
digest=$(printf '%s' "$secret" | sha256sum | cut -d' ' -f1)
cat >"$dir/policy.json" <<POLICY
{"version":1,
 "keys":[{"name":"vouchryx","alg":"ES256","mode":"delegated","max_lifetime":"72h","overlap":"1m"}],
 "consumers":[{"name":"vouchryx","auth":{"key_digest":"sha256:$digest"},"grants":{"vouchryx":["delegate"]}}]}
POLICY
mkdir -m 700 "$dir/data"

start_custody() { # the binary
	KEYRYX_DATA="$dir/data" KEYRYX_ROOT_KEY_FILE="$dir/root.key" KEYRYX_POLICY="$dir/policy.json" \
		KEYRYX_ADDR="127.0.0.1:$KPORT" KEYRYX_PUBLISH_AHEAD=1m "$1" custody >>"$dir/custody.log" 2>&1 &
	kpid=$!
	for _ in $(seq 1 50); do
		curl -fsS "$custody/healthz" >/dev/null 2>&1 && return 0
		sleep 0.2
	done
	say "FAIL: custody did not answer"
	tail -5 "$dir/custody.log"
	exit 1
}
start_custody "$KEYRYX_BIN"
pin=$(curl -fsS "$custody/v1/jwks/keyryx.delegation-root" | jq -r '[.keys[].kid] | join(",")')

"$VOUCHRYX_DEMO_BIN" keygen -out "$dir/idp" >/dev/null
"$VOUCHRYX_DEMO_BIN" keygen -out "$dir/holder" >/dev/null
idp_kid=$(jq -r '.keys[0].kid' "$dir/idp.jwks.json")

start_vouchryx() {
	VOUCHRYX_SIGNER=keyryx VOUCHRYX_KEYRYX_URL="$custody" VOUCHRYX_KEYRYX_CONSUMER=vouchryx \
		VOUCHRYX_KEYRYX_CREDENTIAL_FILE="$dir/bearer" VOUCHRYX_KEYRYX_ROOT_PIN="$pin" \
		VOUCHRYX_ADDR="127.0.0.1:$VPORT" VOUCHRYX_ISSUER="$vouchryx" \
		VOUCHRYX_TRUSTED_ISSUERS="https://idp.lab|vouchryx-lab|$dir/idp.jwks.json|unbound" \
		VOUCHRYX_ALLOWED_AUDIENCES="$vouchryx" VOUCHRYX_REVOCATIONS_PATH="$dir/revocations.ndjson" \
		VOUCHRYX_EVENTS_PATH="$dir/vouchryx.ndjson" "$VOUCHRYX_BIN" >>"$dir/vouchryx.log" 2>&1 &
	vpid=$!
}
kill_vouchryx() {
	kill -9 "$vpid" 2>/dev/null || true
	wait "$vpid" 2>/dev/null || true
	vpid=""
}
ask_token() { # prints the token, or fails
	"$VOUCHRYX_DEMO_BIN" exchange -url "$vouchryx" -idp-key "$dir/idp.pem" -kid "$idp_kid" \
		-iss https://idp.lab -aud vouchryx-lab -subject user://lab/ada -actor agent://lab/triage \
		-holder-key "$dir/holder.pem" 2>>"$dir/exchange.log"
}
token_kid() { # the kid in a token's header
	jq -Rr 'split(".")[0] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .kid' <<<"$1"
}
certified() { # how many keys custody has certified for vouchryx, any state
	curl -fsS "$custody/v1/keys" | jq '[.keys[] | select(.owner == "vouchryx")] | length'
}
wait_token() { # start, seconds; sets token
	local n=$1 limit=$2 began=$SECONDS
	token=""
	while [ $((SECONDS - began)) -lt "$limit" ]; do
		if token=$(ask_token) && [ -n "$token" ]; then
			local kid
			kid=$(token_kid "$token")
			say "start $n: token issued after $((SECONDS - began))s, signed by ${kid:0:12}"
			if ! curl -fsS "$custody/v1/jwks/vouchryx" | jq -e --arg k "$kid" 'any(.keys[]; .kid == $k)' >/dev/null; then
				say "FAIL: that key is not in the set custody publishes"
				return 1
			fi
			return 0
		fi
		token=""
		sleep 3
	done
	say "start $n: no token within ${limit}s"
	return 1
}

verdict=PASS
say "mode $mode, $("$KEYRYX_BIN" version 2>&1 | head -1), overlap 1m, publish-ahead 1m"
for n in 1 2 3 4 5; do
	before=$(certified)
	start_vouchryx
	if [ "$mode" = burst ] && [ "$n" -lt 5 ]; then
		for _ in $(seq 1 100); do
			[ "$(certified)" -gt "$before" ] && break
			sleep 0.1
		done
		say "start $n: holds key $(certified), killed before it signs"
		kill_vouchryx
		continue
	fi
	limit=200
	[ "$n" -eq 5 ] && limit=$LAST_WAIT
	wait_token "$n" "$limit" || verdict=FAIL
	kill_vouchryx
done

published=$(curl -fsS "$custody/v1/jwks/vouchryx" | jq '.keys | length')
say "custody's key set holds $published keys; what it says of each:"
curl -fsS "$custody/v1/keys" | jq -r '.keys[] | select(.owner == "vouchryx") | "  \(.kid[0:12]) \(.state) retired=\(.retired // 0)"'
{ grep -E 'too_many_live_keys|retired delegated key' "$dir/custody.log" || true; } | sed 's/^/  custody: /'
[ "$published" -le 4 ] || verdict=FAIL

if [ -n "$OLD_KEYRYX_BIN" ]; then
	say "rollback: the older custody opens this directory"
	kill -9 "$kpid"
	wait "$kpid" 2>/dev/null || true
	kpid=""
	start_custody "$OLD_KEYRYX_BIN"
	say "rollback: it answers, $(curl -fsS "$custody/v1/jwks/vouchryx" | jq '.keys | length') keys in the set, alarms $(curl -fsS "$custody/v1/state" | jq -c '.alarms')"
fi
say "$verdict ($mode)"
[ "$verdict" = PASS ]
