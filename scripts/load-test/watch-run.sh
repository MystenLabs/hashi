#!/usr/bin/env bash
# Read-only event feed for one run: deposit registration and errors, stream
# failures, waits, pauses and every 10th tick, and one status line every 5 minutes
# (deposits minted, this address's queue by status, in-flight transactions, per-tick
# latency, and the worst-case batch if any). Minted is (hBTC held + hBTC burned by
# submitted withdrawals) / deposit size, since the stream spends hBTC as it mints.
# Exits once the stream has ended and every submitted request is paid, or after
# MAX_HOURS.
# Usage: watch-run.sh <tag> <withdrawal_sats> [max_hours] [deposit_sats] [worst_case_sats]
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
TAG=$1 AMOUNT=$2 MAX_HOURS=${3:-12} DEPOSIT=${4:-$2} WORST_AMOUNT=${5:-0}
DEP_LOG="$D/dep-$TAG.log" WD_LOG="$D/wd-$TAG.log" TICKS="$D/wd-$TAG-ticks.tsv" WORST="$D/worst-$TAG-ticks.tsv"

# "ticks N: requests A submitted, B paid; ..." -> "A B"
submitted_paid() { bash "$HERE/wd-track.sh" "$1" | sed -nE 's/^ticks [0-9]+: requests ([0-9]+) submitted, ([0-9]+) paid.*/\1 \2/p'; }

dep_seen=0 wd_seen=0 last_status=0
end=$(($(date +%s) + MAX_HOURS * 3600))
while [ "$(date +%s)" -lt "$end" ]; do
  if [ -f "$DEP_LOG" ]; then
    n=$(wc -l < "$DEP_LOG")
    if [ "$n" -gt "$dep_seen" ]; then
      tail -n $((n - dep_seen)) "$DEP_LOG" | grep -E 'exit=|rror|failed|registered [0-9]+/|funded ' | sed "s/^/$(now) dep: /"
      dep_seen=$n
    fi
  fi
  if [ -f "$WD_LOG" ]; then
    n=$(wc -l < "$WD_LOG")
    if [ "$n" -gt "$wd_seen" ]; then
      tail -n $((n - wd_seen)) "$WD_LOG" | grep -E '  (!|~|==) |exit=|tick [0-9]*0: ' | sed "s/^/$(now) wd: /"
      wd_seen=$n
    fi
  fi
  t=$(date +%s)
  if [ $((t - last_status)) -ge 300 ]; then
    last_status=$t
    queue=$(h withdraw list --json 2> /dev/null | jq -c --arg me "$SUI_ADDR" '{
        mine: ([.queued[] | select(.caller == $me) | .status] | group_by(.) | map({(.[0]): length}) | add),
        queued_all: .queued_count,
        txns: (.withdrawal_txns | map(select(.status != "confirmed")) | group_by(.status) | map({(.[0].status): length}) | add),
        largest_batch: ([.withdrawal_txns[].request_count] | max)}' 2> /dev/null) || queue='{"list":"failed"}'
    latency=""
    [ -f "$TICKS" ] && latency=$(bash "$HERE/wd-track.sh" "$TICKS" | tr '\n' ' ' | sed 's/  */ /g')
    [ -f "$WORST" ] && latency="$latency | worst: $(bash "$HERE/wd-track.sh" "$WORST" | head -n 1)"
    submitted=$(submitted_in "$TICKS")
    worst=$(submitted_in "$WORST")
    minted=$(hbtc_sats | jq -er --argjson sub "$submitted" --argjson a "$AMOUNT" --argjson w "$worst" --argjson wa "$WORST_AMOUNT" --argjson d "$DEPOSIT" \
      '(. + $sub * $a + $w * $wa) / $d | floor') || minted="?"
    echo "$(now) status: minted ~$minted | queue $queue | ${latency:-no ticks yet}"
    if grep -q 'stream exit=' "$WD_LOG" 2> /dev/null; then
      read -r a b <<< "$(submitted_paid "$TICKS")"
      if [ -n "${a:-}" ] && [ "$a" = "$b" ]; then
        echo "$(now) run $TAG complete: all $a stream withdrawals paid"
        exit 0
      fi
    fi
  fi
  sleep 60
done
echo "$(now) watcher for $TAG timed out after $MAX_HOURS h"
