#!/usr/bin/env bash
# Read-only checks before a series spends anything: the CLI runs, the bridge is not
# paused, bitcoind is synced and on the bridge's chain, and the wallet, the
# withdrawal queue and the guardian limiter are readable. Exits non-zero if a check
# fails.
# Usage: preflight.sh
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
failed=0
ok() { echo "ok    $*"; }
bad() {
  echo "FAIL  $*"
  failed=1
}

if version=$(h --version 2> /dev/null); then ok "hashi CLI: $version"; else bad "cannot run $HASHI_BIN"; fi

# `hashi config on-chain` has no JSON form; values print as `key = Type(value)`.
config=$(h config on-chain 2> /dev/null) || bad "cannot read the on-chain config from $SUI_RPC_URL"
value() { sed -nE "s/^ *$1 = [A-Za-z0-9]+\((.*)\)\$/\1/p" <<< "$config"; }
if [ "$(value paused)" = false ]; then ok "bridge is not paused"; else bad "paused = $(value paused)"; fi
ok "mint gating: $(value bitcoin_confirmation_threshold) confirmations + $(($(value bitcoin_deposit_time_delay_ms) / 1000))s delay"
ok "minimums: deposit $(value bitcoin_deposit_minimum) sats, withdrawal $(value bitcoin_withdrawal_minimum) sats"

if info=$(bc getblockchaininfo 2> /dev/null) && jq -e '.initialblockdownload | not' <<< "$info" > /dev/null; then
  ok "bitcoind synced at height $(jq -r .blocks <<< "$info")"
else
  bad "bitcoind is unreachable or still syncing"
fi
# The chain id is the genesis hash in internal byte order.
rest=$(value bitcoin_chain_id | sed -nE 's/.*0x([0-9a-f]{64}).*/\1/p')
genesis=""
while [ -n "$rest" ]; do
  genesis="${rest:0:2}$genesis"
  rest=${rest:2}
done
if [ -n "$genesis" ] && [ "$genesis" = "$(bc getblockhash 0 2> /dev/null)" ]; then
  ok "bitcoind is on the bridge's chain"
else
  bad "bitcoind genesis $(bc getblockhash 0 2> /dev/null) is not the bridge's chain id ($genesis)"
fi

address=$(h deposit generate-address --recipient "$SUI_ADDR" 2> /dev/null | awk '$1 == "Address:" { print $2 }')
if [ -n "$address" ]; then ok "deposit address $address"; else bad "cannot derive a deposit address"; fi

# The input fund-deposits.sh needs for one full transaction.
per_tx=${OUTPUTS_PER_TX:-250}
funder=$((per_tx * ${DEPOSIT_SATS:-500000} + (per_tx * 43 + 200) * ${FUND_FEE_RATE:-10} * 2))
if funders=$(bcw listunspent 1 9999999 2> /dev/null | jq -e --argjson need "$funder" \
  '[.[] | select(.spendable and .solvable and (.amount * 1e8 | round) >= $need)] | length | select(. > 0)'); then
  ok "wallet $BTC_WALLET: $funders confirmed UTXOs of at least $funder sats (one per funding transaction)"
else
  bad "wallet $BTC_WALLET has no confirmed UTXO of at least $funder sats, or is unreadable"
fi

if balance=$(hbtc_sats); then ok "hBTC held: $balance sats"; else bad "cannot read the hBTC balance"; fi
if queued=$(my_queued); then ok "own queued withdrawal requests: $queued"; else bad "cannot read the withdrawal queue"; fi

guardian=$(value guardian_url | tr -d '"')
if limiter=$(curl -sS -m 15 "$guardian/info" 2> /dev/null | jq -ec '.limiter | {
    available_btc: (.state.numTokensAvailableSats | tonumber / 1e8),
    capacity_btc: (.config.maxBucketCapacitySats | tonumber / 1e8),
    refill_sats_per_sec: (.config.refillRateSatsPerSec | tonumber)}'); then
  ok "guardian limiter: $limiter"
else
  bad "cannot read the guardian limiter from $guardian/info"
fi
exit "$failed"
