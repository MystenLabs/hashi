#!/usr/bin/env bash
# Burst deposits for one run: fund COUNT outputs of AMOUNT sats (fund-deposits.sh),
# register every funding transaction, then report minting until none of this
# run's deposits is pending. A rerun with the same tag resumes.
# Usage: deposits.sh <count> <amount_sats> <tag>
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
COUNT=$1 AMOUNT=$2 TAG=$3
JOURNAL="$D/dep-$TAG-funding.tsv"
REGISTERED="$D/dep-$TAG-registered.txt"

echo "$(now)  run $TAG: $COUNT deposits of $AMOUNT sats"
bash "$HERE/fund-deposits.sh" "$COUNT" "$AMOUNT" "$TAG" || exit 1

touch "$REGISTERED"
registered=0
while IFS=$'\t' read -r -u 3 txid outputs; do
  if ! grep -qxF "$txid" "$REGISTERED"; then
    attempt=1
    # A PTB that lands twice is harmless here: the UTXO replay check blocks a second mint.
    until submit h deposit request --txid "$txid" > "$D/dep-$TAG-$txid.out" 2>&1; do
      if [ "$attempt" -ge 5 ]; then
        echo "$(now)  ! registering $txid failed $attempt times: $(tail -n 1 "$D/dep-$TAG-$txid.out" | cut -c1-300)"
        exit 1
      fi
      attempt=$((attempt + 1))
      sleep 6
    done
    echo "$txid" >> "$REGISTERED"
    # Leave a gap for a withdrawal stream waiting on the submit lock.
    sleep 2
  fi
  registered=$((registered + outputs))
  echo "$(now)  registered $registered/$COUNT deposits"
done 3< "$JOURNAL"

deadline=$(($(date +%s) + ${MINT_TIMEOUT_S:-43200}))
while :; do
  if pending=$(h deposit list --json 2> /dev/null | jq -er --arg me "$SUI_ADDR" --rawfile journal "$JOURNAL" '
      ($journal | split("\n") | map(split("\t")[0])) as $txids
      | [.deposits[] | select(.caller == $me and (.utxo.txid as $t | $txids | index($t)))] | length'); then
    echo "$(now)  minted $((COUNT - pending))/$COUNT"
    [ "$pending" -eq 0 ] && break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "$(now)  ! deposits still pending at the mint timeout"
    exit 1
  fi
  sleep "${MINT_POLL_S:-120}"
done
echo "deposits exit=0 end: $(date -u +%FT%TZ)"
