#!/usr/bin/env bash
# Worst-case withdrawal: one PTB of COUNT requests of AMOUNT sats to a fresh wallet
# address (labelled worst-<tag>). With AMOUNT at ten deposit-sized UTXOs and COUNT
# at 40, the batch fills the 400-input cap. Records the submit time in the TSV
# shape wd-steady.sh writes, and refuses to run twice for a tag.
# Usage: wd-worst.sh <count> <amount_sats> <tag>
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
COUNT=$1 AMOUNT=$2 TAG=$3
TICKS="$D/worst-$TAG-ticks.tsv"
if [ -e "$TICKS" ]; then
  echo "refusing: $TICKS already exists"
  exit 1
fi
balance=$(hbtc_sats) || {
  echo "balance read failed"
  exit 1
}
if [ "$balance" -lt $((COUNT * AMOUNT)) ]; then
  echo "hBTC $balance < $((COUNT * AMOUNT)) sats"
  exit 1
fi
addr=$(bcw getnewaddress "worst-$TAG" bech32) || exit 1
if submit h withdraw request --amount "$AMOUNT" --btc-address "$addr" --count "$COUNT" > "$D/worst-$TAG.out" 2> "$D/worst-$TAG.err"; then
  printf 'tick\tsubmitted_utc\tsubmitted_s\tcount\taddress\n0\t%s\t%s\t%s\t%s\n' "$(utc_of "$SUBMITTED_AT")" "$SUBMITTED_AT" "$COUNT" "$addr" > "$TICKS"
  echo "$(now)  submitted $COUNT x $AMOUNT sats to $addr (hBTC before $balance sats)"
else
  echo "PTB failed (check the queue before retrying): $(tail -n 1 "$D/worst-$TAG.err" | cut -c1-300)"
  exit 1
fi
