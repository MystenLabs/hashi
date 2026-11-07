# shellcheck shell=bash disable=SC2034
# Sourced by the load-test scripts: configuration, CLI wrappers and shared helpers.
# README.md lists the variables.

: "${HASHI_BIN:?set HASHI_BIN to a hashi CLI built from the deployed commit}"
: "${SUI_RPC_URL:?}" "${HASHI_PACKAGE_ID:?}" "${HASHI_OBJECT_ID:?}" "${HASHI_KEYPAIR:?}"
: "${SUI_ADDR:?set SUI_ADDR to the signer address, full length and lowercase}"
: "${BTC_NETWORK:?}"
: "${LOADTEST_DIR:?set LOADTEST_DIR to a directory for this series logs and state}"
if [ "$BTC_NETWORK" = mainnet ]; then
  echo "refusing to load-test Bitcoin mainnet" >&2
  exit 1
fi
BTC_WALLET=${BTC_WALLET:-mining}
BITCOIN_CLI=${BITCOIN_CLI:-bitcoin-cli -$BTC_NETWORK}
export SUI_RPC_URL HASHI_PACKAGE_ID HASHI_OBJECT_ID HASHI_KEYPAIR BTC_NETWORK
mkdir -p "$LOADTEST_DIR"
D=$LOADTEST_DIR
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

h() { NO_COLOR=1 "$HASHI_BIN" "$@" < /dev/null; }
bc() {
  # shellcheck disable=SC2086
  $BITCOIN_CLI ${BTC_RPC_USER:+"-rpcuser=$BTC_RPC_USER"} ${BTC_RPC_PASSWORD:+"-rpcpassword=$BTC_RPC_PASSWORD"} "$@"
}
bcw() { bc -rpcwallet="$BTC_WALLET" "$@"; }
now() { date -u +%H:%M:%SZ; }
utc_of() { date -u -r "$1" +%FT%TZ 2> /dev/null || date -u -d "@$1" +%FT%TZ; }

hbtc_sats() { h balance --json "$SUI_ADDR" 2> /dev/null | jq -er .balance_sats; }
# This address's withdrawal requests that no batch has committed yet.
my_queued() {
  h withdraw list --json 2> /dev/null \
    | jq -er --arg me "$SUI_ADDR" '[.queued[] | select(.caller == $me)] | length'
}
submitted_in() { awk -F'\t' 'NR > 1 { s += $4 } END { print s + 0 }' "$1" 2> /dev/null || echo 0; }

# Every PTB pays from the signer's one gas coin, and two transactions built on the
# same coin version equivocate, so concurrent drivers submit one at a time.
# SUBMITTED_AT is when the command started, after any wait for the lock.
SUI_LOCK="$D/sui-submit.lock"
submit() {
  local owner rc
  while ! mkdir "$SUI_LOCK" 2> /dev/null; do
    owner=$(cat "$SUI_LOCK/pid" 2> /dev/null)
    if [ -n "$owner" ] && ! kill -0 "$owner" 2> /dev/null; then
      rm -rf "$SUI_LOCK"
      continue
    fi
    sleep 1
  done
  echo $$ > "$SUI_LOCK/pid"
  SUBMITTED_AT=$(date +%s)
  "$@"
  rc=$?
  rm -rf "$SUI_LOCK"
  return $rc
}
