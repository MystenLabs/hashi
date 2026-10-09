#!/usr/bin/env bash
# Read-only: the shape of every withdrawal transaction that paid a run's ticks, one
# TSV row per transaction in the order this node first saw them:
#   seen_utc  txid  inputs  outputs  payouts  weight  sat_per_vb  confirmations
# `payouts` counts this run's outputs; more than 40 outputs means a drain-mode batch.
# Usage: wd-batches.sh <ticks.tsv>
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
TSV=$1
addrs=$(awk -F'\t' 'NR > 1 { print $5 }' "$TSV" | jq -R . | jq -sc .)
since=$(bc getblockhash $(($(bc getblockcount) - ${TRACK_BLOCKS:-400}))) || exit 1
printf 'seen_utc\ttxid\tinputs\toutputs\tpayouts\tweight\tsat_per_vb\tconfirmations\n'
bcw listsinceblock "$since" 1 true \
  | jq -r --argjson a "$addrs" '[.transactions[] | select(.category == "receive" and (.address as $x | $a | index($x)))]
      | group_by(.txid) | map({txid: .[0].txid, seen: (map(.timereceived) | min), payouts: length})
      | sort_by(.seen)[] | [.seen, .txid, .payouts] | @tsv' \
  | while IFS=$'\t' read -r seen txid payouts; do
    # getrawtransaction reports a fee only once the transaction is in a block.
    mempool_fee=$(bc getmempoolentry "$txid" 2> /dev/null | jq '.fees.base') || mempool_fee=null
    bc getrawtransaction "$txid" 2 | jq -r --arg seen "$(utc_of "$seen")" --arg payouts "$payouts" --argjson mempool_fee "${mempool_fee:-null}" \
      '(.fee // $mempool_fee) as $fee
       | [$seen, .txid, (.vin | length), (.vout | length), $payouts, .weight,
          (if $fee then ($fee * 1e8 / .vsize * 10 | round / 10) else "?" end), (.confirmations // 0)] | @tsv'
  done
