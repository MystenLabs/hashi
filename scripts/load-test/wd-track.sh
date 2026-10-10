#!/usr/bin/env bash
# Read-only: per-tick withdrawal latency from the local wallet. For each tick row
# (wd-steady.sh or wd-worst.sh TSV): when its first payout reached this node's
# mempool, when the last of its payouts did, and the block time of the last
# confirmation, all relative to the submit time. Block header times can trail wall
# time by minutes on signet, so "paid" is the primary figure.
# Usage: wd-track.sh <ticks.tsv> [--per-tick]
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
TSV=$1 MODE=${2:-}
addrs=$(awk -F'\t' 'NR > 1 { print $5 }' "$TSV" | jq -R . | jq -sc .)
since=$(bc getblockhash $(($(bc getblockcount) - ${TRACK_BLOCKS:-400}))) || exit 1
received="$D/.track-$$.json"
bcw listsinceblock "$since" 1 true \
  | jq -c --argjson a "$addrs" '[.transactions[] | select(.category == "receive" and (.address as $x | $a | index($x)))
      | {address, txid, timereceived, blocktime, confirmations}]' > "$received"
jq -nr --slurpfile rx "$received" --rawfile tsv "$TSV" --arg mode "$MODE" '
  def pct(p): sort | if length == 0 then null else .[((length - 1) * p | floor)] end;
  def secs: if . == null then "-" else "\(.)s" end;
  ($tsv | split("\n") | .[1:] | map(select(length > 0) | split("\t")
     | {tick: (.[0] | tonumber), sub: (.[2] | tonumber), count: (.[3] | tonumber), address: .[4]})) as $ticks
  | [$ticks[] as $t | ($rx[0] | map(select(.address == $t.address))) as $o
     | ($o | length) as $paid
     | {tick: $t.tick, count: $t.count, paid: $paid, txs: ($o | map(.txid) | unique | length),
        first_s: (if $paid > 0 then ($o | map(.timereceived) | min) - $t.sub else null end),
        all_s: (if $paid >= $t.count then ($o | map(.timereceived) | max) - $t.sub else null end),
        conf_s: (if $paid >= $t.count and ($o | all(.confirmations > 0)) then ($o | map(.blocktime) | max) - $t.sub else null end)}] as $rows
  | (if $mode == "--per-tick" then ($rows[] | "tick \(.tick): \(.paid)/\(.count) paid in \(.txs) txs  first \(.first_s | secs)  all \(.all_s | secs)  confirmed \(.conf_s | secs)") else empty end),
    "ticks \($rows | length): requests \($rows | map(.count) | add // 0) submitted, \($rows | map(.paid) | add // 0) paid; ticks fully paid \($rows | map(select(.all_s != null)) | length), fully confirmed \($rows | map(select(.conf_s != null)) | length)",
    "submit->all paid (mempool): p50 \($rows | map(.all_s // empty) | pct(0.5) | secs)  p90 \($rows | map(.all_s // empty) | pct(0.9) | secs)  max \($rows | map(.all_s // empty) | max | secs)",
    "submit->confirmed: p50 \($rows | map(.conf_s // empty) | pct(0.5) | secs)  p90 \($rows | map(.conf_s // empty) | pct(0.9) | secs)  max \($rows | map(.conf_s // empty) | max | secs)"'
rm -f "$received"
