#!/usr/bin/env bash
# End-of-series cleanup: withdraw the signer's whole hBTC balance as requests of
# AMOUNT sats, CHUNK per PTB, each PTB to a fresh wallet address (labelled
# drain-<n>). Waits up to 30 minutes for this address's pending deposits to mint
# first. A remainder of at least MIN sats goes out as one last request.
# Usage: drain.sh <amount_sats> <min_sats> [chunk]
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
AMOUNT=$1 MIN=$2 CHUNK=${3:-100}
OUT="$D/drain-out"
mkdir -p "$OUT"
pending() { h deposit list --json 2> /dev/null | jq -er --arg me "$SUI_ADDR" '[.deposits[] | select(.caller == $me)] | length'; }

deadline=$(($(date +%s) + 1800))
while :; do
  p=$(pending) || p="?"
  echo "$(now) pending deposits: $p, balance: $(hbtc_sats || echo '?') sats"
  [ "$p" = 0 ] && break
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "$(now) deposits still pending after 30 min; withdrawing what has minted"
    break
  fi
  sleep 30
done

balance=$(hbtc_sats) || {
  echo "$(now) balance read failed; stopping"
  exit 1
}
n=$((balance / AMOUNT))
remainder=$((balance - n * AMOUNT))
echo "$(now) balance $balance sats -> $n x $AMOUNT, remainder $remainder"
i=0
request() {
  local label=$1 amount=$2 count=$3 addr
  addr=$(bcw getnewaddress "drain-$label" bech32) || return 1
  if submit h withdraw request --amount "$amount" --btc-address "$addr" --count "$count" > "$OUT/batch-$label.out" 2> "$OUT/batch-$label.err"; then
    echo "$(now) batch $label: $count x $amount sats -> $addr"
  else
    echo "$(now) batch $label FAILED (check the queue before retrying): $(tail -c 400 "$OUT/batch-$label.err")"
    return 1
  fi
}
while [ "$n" -gt 0 ]; do
  k=$((n < CHUNK ? n : CHUNK))
  i=$((i + 1))
  request "$i" "$AMOUNT" "$k" || exit 1
  n=$((n - k))
done
if [ "$remainder" -ge "$MIN" ]; then
  request rem "$remainder" 1 || exit 1
elif [ "$remainder" -gt 0 ]; then
  echo "$(now) remainder $remainder sats is under the $MIN-sat minimum; left in place"
fi
echo "$(now) submitted; balance now $(hbtc_sats || echo '?') sats; drain exit=0"
