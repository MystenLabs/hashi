#!/usr/bin/env bash
# Runs wd-steady.sh against stub hashi and bitcoin-cli commands and checks what it
# submits, above all that a PTB whose response was lost is never submitted twice.
# Each failure case waits out wd-steady.sh's 15 s settle delay.
set -Eeuo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(mktemp -d "${TMPDIR:-/tmp}/load-test-steady.XXXXXXXX")
cleanup() {
  local status=$?
  trap - EXIT
  if ((status != 0)) && [[ -e "$root/stream.log" ]]; then
    cat "$root/stream.log" >&2
  fi
  rm -rf -- "$root"
  exit "$status"
}
trap cleanup EXIT
trap 'printf "FAIL at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

assert_equal() {
  if [[ $1 != "$2" ]]; then
    printf 'Expected <%s>, got <%s>\n' "$2" "$1" >&2
    return 1
  fi
}

mkdir "$root/bin" "$root/state" "$root/run"
# `mode` decides the next withdrawal PTB, then resets to ok:
#   ok           it lands and the CLI reports success
#   lost-reply   it lands but the CLI fails, as when the response is lost
#   rejected     it does not land and the CLI fails
cat > "$root/bin/hashi" << 'STUB'
#!/usr/bin/env bash
case "$1 $2" in
  "balance --json") printf '{"balance_sats": %s}\n' "$(cat "$STUB_STATE/balance")" ;;
  "withdraw request")
    amount=$4 address=$6 count=$8
    mode=$(cat "$STUB_STATE/mode")
    echo ok > "$STUB_STATE/mode"
    if [[ $mode != rejected ]]; then
      echo $(($(cat "$STUB_STATE/balance") - amount * count)) > "$STUB_STATE/balance"
      for _ in $(seq 1 "$count"); do echo $(($(date +%s) * 1000)) >> "$STUB_STATE/queued"; done
      echo "$address $count" >> "$STUB_STATE/landed"
    fi
    if [[ $mode != ok ]]; then
      echo "transport error" >&2
      exit 1
    fi
    ;;
  "withdraw list")
    jq -Rn --arg me "$SUI_ADDR" \
      '{queued: [inputs | {caller: $me, requested_ms: tonumber, status: "requested"}], withdrawal_txns: []}' \
      < "$STUB_STATE/queued"
    ;;
  *) exit 1 ;;
esac
STUB
cat > "$root/bin/bitcoin-cli" << 'STUB'
#!/usr/bin/env bash
# Called as: bitcoin-cli -rpcwallet=<wallet> getnewaddress <label> bech32
echo "address-$3"
STUB
chmod +x "$root/bin/hashi" "$root/bin/bitcoin-cli"

export STUB_STATE="$root/state" HASHI_BIN="$root/bin/hashi" BITCOIN_CLI="$root/bin/bitcoin-cli"
export LOADTEST_DIR="$root/run" BTC_NETWORK=regtest
export SUI_RPC_URL=unused HASHI_PACKAGE_ID=unused HASHI_OBJECT_ID=unused HASHI_KEYPAIR=unused
export SUI_ADDR=0x0000000000000000000000000000000000000000000000000000000000000001
reset() {
  echo "$1" > "$root/state/balance"
  echo ok > "$root/state/mode"
  : > "$root/state/queued"
  : > "$root/state/landed"
}
# <total> <tag>: 2 requests of 100 sats per tick, one tick per second.
stream() { bash "$here/wd-steady.sh" "$1" 2 1 100 "$2" > "$root/stream.log" 2>&1; }
ticks() { awk -F'\t' 'NR > 1 { printf "%s%s:%s", sep, $1, $4; sep = " " }' "$root/run/wd-$1-ticks.tsv"; }

reset 1000
stream 5 plain
assert_equal "$(ticks plain)" "0:2 1:2 2:1"
assert_equal "$(paste -sd' ' "$root/state/landed")" "address-wd-plain-0 2 address-wd-plain-1 2 address-wd-plain-2 1"
assert_equal "$(cat "$root/state/balance")" 500
grep -q '^stream exit=0' "$root/stream.log"
printf 'ok 1 - ticks of PER_TICK, a short last tick, one fresh address each\n'

stream 8 plain
assert_equal "$(ticks plain)" "0:2 1:2 2:1 3:2 4:1"
assert_equal "$(cat "$root/state/balance")" 200
printf 'ok 2 - a rerun with a larger total resumes from the tick file\n'

reset 1000
echo lost-reply > "$root/state/mode"
stream 4 lost
assert_equal "$(ticks lost)" "0:2 1:2"
assert_equal "$(wc -l < "$root/state/landed" | tr -d ' ')" 2
assert_equal "$(cat "$root/state/balance")" 600
grep -q 'tick 0 landed despite the error' "$root/stream.log"
printf 'ok 3 - a PTB that landed behind a failed reply is not submitted again\n'

reset 1000
echo rejected > "$root/state/mode"
stream 4 rejected
assert_equal "$(ticks rejected)" "0:2 1:2"
assert_equal "$(wc -l < "$root/state/landed" | tr -d ' ')" 2
assert_equal "$(cat "$root/state/balance")" 600
grep -q 'tick 0 PTB failed' "$root/stream.log"
printf 'ok 4 - a PTB that did not land is retried as the same tick\n'
