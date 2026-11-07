#!/usr/bin/env bash
# The 1K / 2K / 4K series, one stage per invocation. A stage waits for its gate,
# then starts that run's deposits, withdrawal stream and watcher in the background,
# all logging to $LOADTEST_DIR. Run each stage under nohup; README.md describes
# what each run exercises.
# Usage: series.sh 1k | 2k | 4k
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
DEPOSIT=${DEPOSIT_SATS:-500000}
# Ten deposit-sized UTXOs per request, so 40 requests fill the 400-input cap.
WORST=$((DEPOSIT * 10))
# Smaller than a deposit, so the 4K queue outgrows the UTXO pool.
OVERLOAD=${OVERLOAD_SATS:-300000}

spawn() {
  local log=$1 script=$2
  shift 2
  nohup bash "$HERE/$script" "$@" > "$D/$log" 2>&1 < /dev/null &
  echo "$(now) started $script $* (pid $!, log $log)"
}
fresh() {
  local f
  for f in "$D/dep-$1.log" "$D/wd-$1.log" "$D/wd-$1-ticks.tsv"; do
    if [ -e "$f" ]; then
      echo "refusing: $f already exists"
      exit 1
    fi
  done
}
stream_done() { grep -q 'stream exit=' "$D/wd-$1.log" 2> /dev/null; }
hbtc_at_least() {
  local balance
  balance=$(hbtc_sats) && [ "$balance" -ge "$1" ]
}
queue_empty() {
  local queued
  queued=$(my_queued) && [ "$queued" -eq 0 ]
}

case "${1:-}" in
  1k)
    fresh 1k
    touch "$D/wd-1k.pause"
    spawn dep-1k.log deposits.sh 1000 "$DEPOSIT" 1k
    spawn wd-1k.log wd-steady.sh 600 25 60 "$DEPOSIT" 1k
    spawn watch-1k.log watch-run.sh 1k "$DEPOSIT" 12 "$DEPOSIT" "$WORST"
    # The stream stays paused so the worst case runs alone at the head of the queue.
    until hbtc_at_least $((40 * WORST)) && queue_empty; do sleep 30; done
    bash "$HERE/wd-worst.sh" 40 "$WORST" 1k || {
      echo "$(now) worst-case submit failed; the stream stays paused"
      exit 1
    }
    sleep 20
    until queue_empty; do sleep 20; done
    echo "$(now) worst-case requests all committed; resuming the stream"
    rm -f "$D/wd-1k.pause"
    ;;
  2k)
    fresh 2k
    until stream_done 1k; do sleep 15; done
    echo "$(now) 1K stream finished; launching 2K"
    spawn dep-2k.log deposits.sh 2000 "$DEPOSIT" 2k
    spawn wd-2k.log wd-steady.sh 2000 50 60 "$DEPOSIT" 2k
    spawn watch-2k.log watch-run.sh 2k "$DEPOSIT"
    ;;
  4k)
    fresh 4k
    until [ "$(submitted_in "$D/wd-2k-ticks.tsv")" -ge 1400 ]; do sleep 30; done
    echo "$(now) 2K stream at 1,400 submitted; launching 4K"
    touch "$D/wd-4k.pause"
    spawn dep-4k.log deposits.sh 4000 "$DEPOSIT" 4k
    spawn wd-4k.log wd-steady.sh 4000 100 60 "$OVERLOAD" 4k
    spawn watch-4k.log watch-run.sh 4k "$OVERLOAD" 12 "$DEPOSIT"
    # Hold the stream until 1,000 deposits have minted, so requests then arrive
    # faster than batches clear.
    until stream_done 2k && hbtc_at_least $((1000 * DEPOSIT)); do sleep 30; done
    rm -f "$D/wd-4k.pause"
    echo "$(now) released the 4K stream"
    until batch=$(h withdraw list --json 2> /dev/null \
      | jq -ec '[.withdrawal_txns[] | select(.request_count > 40) | {request_count, outflow_sats, status}] | select(length > 0)'); do
      sleep 60
    done
    echo "$(now) drain-mode batch seen: $batch"
    ;;
  *)
    echo "usage: $0 1k | 2k | 4k" >&2
    exit 1
    ;;
esac
