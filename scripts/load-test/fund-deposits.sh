#!/usr/bin/env bash
# Pay COUNT outputs of AMOUNT sats to the signer's deposit address, OUTPUTS_PER_TX
# (default 250) per transaction. Each broadcast appends "txid<TAB>outputs" to
# $LOADTEST_DIR/dep-<tag>-funding.tsv, and a rerun resumes from that file.
# Usage: fund-deposits.sh <count> <amount_sats> <tag>
set -u
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
COUNT=$1 AMOUNT=$2 TAG=$3
PER_TX=${OUTPUTS_PER_TX:-250}
FEE_RATE=${FUND_FEE_RATE:-10}
JOURNAL="$D/dep-$TAG-funding.tsv"
die() {
  echo "fund-deposits: $*" >&2
  exit 1
}

# <value> <bytes>, little-endian hex.
le() {
  local v=$1 n=$2 out=""
  while [ "$n" -gt 0 ]; do
    out="$out$(printf '%02x' $((v & 255)))"
    v=$((v >> 8))
    n=$((n - 1))
  done
  printf '%s' "$out"
}
rev_bytes() {
  local s=$1 out=""
  while [ -n "$s" ]; do
    out="${s:0:2}$out"
    s=${s:2}
  done
  printf '%s' "$out"
}
varint() {
  if [ "$1" -lt 253 ]; then
    le "$1" 1
  else
    printf 'fd'
    le "$1" 2
  fi
}

addr=$(h deposit generate-address --recipient "$SUI_ADDR" 2> /dev/null | awk '$1 == "Address:" { print $2 }')
[ -n "$addr" ] || die "could not derive the deposit address for $SUI_ADDR"
spk=$(bc validateaddress "$addr" | jq -er 'select(.isvalid) | .scriptPubKey') || die "bitcoind rejects $addr on $BTC_NETWORK"
output="$(le "$AMOUNT" 8)$(varint $((${#spk} / 2)))$spk"

touch "$JOURNAL"
remaining=$((COUNT - $(awk -F'\t' '{ s += $2 } END { print s + 0 }' "$JOURNAL")))
while [ "$remaining" -gt 0 ]; do
  n=$((remaining < PER_TX ? remaining : PER_TX))
  # Wallet coin selection can fund from over a thousand dust inputs, which makes a
  # transaction too large for signet blocks, so one input is pinned instead.
  need=$((n * AMOUNT + (n * 43 + 200) * FEE_RATE * 2))
  input=$(bcw listunspent 1 9999999 | jq -er --argjson need "$need" '
    map(select(.spendable and .solvable) | . + {sats: (.amount * 1e8 | round)} | select(.sats >= $need))
    | sort_by(.sats) | .[0] // error("none") | "\(.txid) \(.vout)"') \
    || die "no confirmed UTXO in wallet $BTC_WALLET covers $need sats; run split-funders.sh"
  read -r in_txid in_vout <<< "$input"

  # createrawtransaction rejects duplicate output addresses, so the transaction is
  # serialized here. Sequence 0xfffffffe opts out of RBF: a replacement would change
  # the txid the deposits are registered against.
  outputs="" i=0
  while [ "$i" -lt "$n" ]; do
    outputs="$outputs$output"
    i=$((i + 1))
  done
  raw="0200000001$(rev_bytes "$in_txid")$(le "$in_vout" 4)00feffffff$(varint "$n")${outputs}00000000"

  funded=$(bcw fundrawtransaction "$raw" "{\"add_inputs\":false,\"fee_rate\":$FEE_RATE,\"replaceable\":false,\"changePosition\":$n}") \
    || die "fundrawtransaction failed for input $in_txid:$in_vout"
  signed=$(bcw signrawtransactionwithwallet "$(jq -r .hex <<< "$funded")") || die "signing failed"
  [ "$(jq -r .complete <<< "$signed")" = true ] || die "wallet $BTC_WALLET could not fully sign"
  hex=$(jq -r .hex <<< "$signed")
  paid=$(bc decoderawtransaction "$hex" | jq --arg spk "$spk" --argjson amount "$AMOUNT" \
    '[.vout[] | select(.scriptPubKey.hex == $spk and (.value * 1e8 | round) == $amount)] | length')
  [ "$paid" = "$n" ] || die "built transaction pays $paid deposit outputs, expected $n"
  accept=$(bc testmempoolaccept "[\"$hex\"]") || die "testmempoolaccept failed"
  jq -e '.[0].allowed' <<< "$accept" > /dev/null || die "mempool rejects it: $(jq -r '.[0]["reject-reason"]' <<< "$accept")"

  txid=$(bc sendrawtransaction "$hex") || die "broadcast failed"
  printf '%s\t%s\n' "$txid" "$n" >> "$JOURNAL"
  echo "$(now)  funded $txid: $n x $AMOUNT sats (fee $(jq -r .fee <<< "$funded") BTC)"
  remaining=$((remaining - n))
done
