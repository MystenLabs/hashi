#!/usr/bin/env bash
# Steady withdrawal load: every INTERVAL seconds, submit PER_TICK requests of AMOUNT
# sats to a fresh wallet address (labelled wd-<tag>-<tick>) until TOTAL are
# submitted. A tick that hBTC can't cover waits for minting and the clock restarts
# from it, so the load never bursts to catch up. Touching $LOADTEST_DIR/wd-<tag>.pause
# holds the stream. One TSV row per tick feeds wd-track.sh. Ends with "stream exit=".
# Usage: wd-steady.sh <total> <per_tick> <interval_s> <amount_sats> <tag>
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
TOTAL=$1 PER_TICK=$2 INTERVAL=$3 AMOUNT=$4 TAG=$5
TICKS="$D/wd-$TAG-ticks.tsv"
OUT="$D/wd-$TAG-out"
mkdir -p "$OUT"

# This address's queued requests created at or after the given unix second.
queued_since() {
  h withdraw list --json 2> /dev/null \
    | jq -e --arg me "$SUI_ADDR" --argjson t "$(($1 * 1000 - 5000))" \
      '[.queued[] | select(.caller == $me and .requested_ms >= $t)] | length'
}

[ -e "$TICKS" ] || printf 'tick\tsubmitted_utc\tsubmitted_s\tcount\taddress\n' > "$TICKS"
submitted=$(submitted_in "$TICKS")
tick=$(awk 'END { print NR - 1 }' "$TICKS")
echo "$(now)  steady withdrawals: $TOTAL x $AMOUNT sats, $PER_TICK every ${INTERVAL}s (resuming at $submitted)"

next=$(date +%s)
waiting=0 paused=0
while [ "$submitted" -lt "$TOTAL" ]; do
  if [ -e "$D/wd-$TAG.pause" ]; then
    [ "$paused" = 0 ] && echo "$(now)  ~ paused (wd-$TAG.pause)"
    paused=1
    sleep 15
    next=$(date +%s)
    continue
  fi
  [ "$paused" = 1 ] && echo "$(now)  ~ resumed"
  paused=0
  t=$(date +%s)
  [ "$t" -lt "$next" ] && sleep $((next - t))
  count=$((TOTAL - submitted < PER_TICK ? TOTAL - submitted : PER_TICK))
  need=$((count * AMOUNT))
  if ! before=$(hbtc_sats); then
    echo "$(now)  ! balance read failed; retrying"
    sleep 15
    next=$(date +%s)
    continue
  fi
  if [ "$before" -lt "$need" ]; then
    [ "$waiting" = 0 ] && echo "$(now)  ~ tick $tick waits for minting (hBTC $before < $need sats)"
    waiting=1
    sleep 20
    next=$(date +%s)
    continue
  fi
  waiting=0
  addr=$(bcw getnewaddress "wd-$TAG-$tick" bech32) || {
    echo "$(now)  ! getnewaddress failed; retrying"
    sleep 15
    continue
  }
  if submit h withdraw request --amount "$AMOUNT" --btc-address "$addr" --count "$count" > "$OUT/tick-$tick.out" 2> "$OUT/tick-$tick.err"; then
    landed=1
  else
    echo "$(now)  ! tick $tick PTB failed: $(tail -n 1 "$OUT/tick-$tick.err" | cut -c1-200)"
    # A lost response can hide a PTB that landed, and a blind retry would burn the
    # hBTC twice, so look for requests created since.
    sleep 15
    if seen=$(queued_since "$SUBMITTED_AT") && [ "$seen" -ge "$count" ]; then
      landed=1
      echo "$(now)  . tick $tick landed despite the error ($seen requests queued since)"
    else
      landed=0
    fi
  fi
  t_sub=$SUBMITTED_AT
  if [ "$landed" = 1 ]; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$tick" "$(utc_of "$t_sub")" "$t_sub" "$count" "$addr" >> "$TICKS"
    submitted=$((submitted + count))
    echo "$(now)  . tick $tick: submitted $submitted/$TOTAL (hBTC before $before sats)"
    tick=$((tick + 1))
  fi
  next=$((t_sub + INTERVAL))
done
echo "$(now)  == all $TOTAL withdrawals submitted"
echo "stream exit=0 end: $(date -u +%FT%TZ)"
