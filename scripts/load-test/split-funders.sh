#!/usr/bin/env bash
# Split one large wallet UTXO into COUNT outputs of AMOUNT sats (fresh bech32
# addresses, change to a fresh address), so fund-deposits.sh finds one confirmed
# input per funding transaction. Prints the mempool verdict and shape; broadcasts
# only with --send.
# Usage: split-funders.sh <txid> <vout> <count> <amount_sats> [--send]
set -euo pipefail
# shellcheck source=scripts/load-test/lib.sh
. "$(dirname "$0")/lib.sh"
txid=$1 vout=$2 count=$3 amount=$4 mode=${5:-}
amount_btc=$(printf '%d.%08d' $((amount / 100000000)) $((amount % 100000000)))
outputs="["
for i in $(seq 1 "$count"); do
  outputs+="{\"$(bcw getnewaddress "funder-$i" bech32)\":$amount_btc},"
done
outputs="${outputs%,}]"
change=$(bcw getnewaddress funder-change bech32)
options="{\"inputs\":[{\"txid\":\"$txid\",\"vout\":$vout}],\"add_inputs\":false,\"change_address\":\"$change\",\"fee_rate\":${FUND_FEE_RATE:-10},\"replaceable\":false,\"add_to_wallet\":false}"
hex=$(bcw send "$outputs" null unset null "$options" | jq -r .hex)
bc testmempoolaccept "[\"$hex\"]" | jq -c '.[0] | {allowed, vsize, fees, "reject-reason"}'
bc decoderawtransaction "$hex" | jq -c --argjson amount "$amount" \
  '{txid, vin: (.vin | length), vout: (.vout | length), funders: ([.vout[] | select((.value * 1e8 | round) == $amount)] | length)}'
if [ "$mode" = --send ]; then
  bc sendrawtransaction "$hex"
fi
