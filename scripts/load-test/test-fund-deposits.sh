#!/usr/bin/env bash
# Runs fund-deposits.sh against a throwaway regtest bitcoind and a stub hashi CLI,
# then checks every broadcast transaction output by output.
set -Eeuo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(mktemp -d "${TMPDIR:-/tmp}/load-test-funding.XXXXXXXX")
rpcport=$((20000 + RANDOM % 20000))
cli() { bitcoin-cli -regtest -datadir="$root/btc" -rpcport="$rpcport" "$@"; }
cleanup() {
  local status=$?
  trap - EXIT
  if ((status != 0)) && [[ -e "$root/fund.log" ]]; then
    cat "$root/fund.log" >&2
  fi
  cli stop > /dev/null 2>&1 || true
  # bitcoind removes its pid file last.
  for _ in $(seq 1 50); do
    [[ -e "$root/btc/regtest/bitcoind.pid" ]] || break
    sleep 0.2
  done
  rm -rf -- "$root"
  exit "$status"
}
trap cleanup EXIT
trap 'printf "FAIL at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

assert_equal() {
  if [[ $1 != "$2" ]]; then
    printf 'Expected <%s>, got <%s>\n' "$2" "$1" >&2
    return 1
  fi
}

mkdir "$root/btc" "$root/run"
# macOS's default descriptor limit is below what bitcoind asks for.
ulimit -n 10240 2> /dev/null || true
bitcoind -regtest -datadir="$root/btc" -rpcport="$rpcport" -listen=0 -daemonwait > /dev/null
cli createwallet mining > /dev/null
cli createwallet recipient > /dev/null
# Four mature coinbase outputs: one confirmed input per funding transaction below.
cli generatetoaddress 104 "$(cli -rpcwallet=mining getnewaddress '' bech32)" > /dev/null
deposit_address=$(cli -rpcwallet=recipient getnewaddress '' bech32m)
script=$(cli validateaddress "$deposit_address" | jq -r .scriptPubKey)

cat > "$root/hashi" << 'STUB'
#!/usr/bin/env bash
[[ "$1 $2" == "deposit generate-address" ]] || exit 1
printf '\nDeposit Address\n  Address: %s\n  Network: Regtest\n' "$STUB_DEPOSIT_ADDRESS"
STUB
chmod +x "$root/hashi"

export STUB_DEPOSIT_ADDRESS=$deposit_address
export HASHI_BIN="$root/hashi" LOADTEST_DIR="$root/run" BTC_NETWORK=regtest
export BITCOIN_CLI="bitcoin-cli -regtest -datadir=$root/btc -rpcport=$rpcport"
export SUI_RPC_URL=unused HASHI_PACKAGE_ID=unused HASHI_OBJECT_ID=unused HASHI_KEYPAIR=unused
export SUI_ADDR=0x0000000000000000000000000000000000000000000000000000000000000001
fund() { bash "$here/fund-deposits.sh" "$@" > "$root/fund.log" 2>&1; }

# Each journal row is one transaction: a single non-replaceable input, and exactly
# its recorded number of deposit outputs.
check_journal() {
  local txid outputs tx
  while IFS=$'\t' read -r txid outputs; do
    tx=$(cli getrawtransaction "$txid" 1)
    assert_equal "$(jq '.vin | length' <<< "$tx")" 1
    assert_equal "$(jq '.vin[0].sequence' <<< "$tx")" 4294967294
    assert_equal "$(jq --arg script "$script" --argjson amount "$2" \
      '[.vout[] | select(.scriptPubKey.hex == $script and (.value * 1e8 | round) == $amount)] | length' <<< "$tx")" "$outputs"
    assert_equal "$(jq '.vout | length' <<< "$tx")" "$((outputs + 1))"
  done < "$1"
}

# 300 outputs needs the three-byte output count; 250 and 50 the one-byte form.
OUTPUTS_PER_TX=300 fund 300 12345 wide
assert_equal "$(cut -f2 "$root/run/dep-wide-funding.tsv")" 300
check_journal "$root/run/dep-wide-funding.tsv" 12345
printf 'ok 1 - one transaction with more than 252 outputs\n'

fund 300 20000 split
assert_equal "$(cut -f2 "$root/run/dep-split-funding.tsv" | paste -sd, -)" 250,50
check_journal "$root/run/dep-split-funding.tsv" 20000
printf 'ok 2 - a count above OUTPUTS_PER_TX splits across transactions\n'

before=$(cat "$root/run/dep-split-funding.tsv")
fund 300 20000 split
assert_equal "$(cat "$root/run/dep-split-funding.tsv")" "$before"
fund 400 20000 split
assert_equal "$(cut -f2 "$root/run/dep-split-funding.tsv" | paste -sd, -)" 250,50,100
check_journal "$root/run/dep-split-funding.tsv" 20000
printf 'ok 3 - a rerun pays only the outputs the journal lacks\n'

# Every mature coinbase is spent and the change is unconfirmed, so nothing qualifies.
if fund 10 20000 starved; then
  printf 'Funding succeeded without a confirmed input\n' >&2
  exit 1
fi
assert_equal "$(wc -c < "$root/run/dep-starved-funding.tsv" | tr -d ' ')" 0
printf 'ok 4 - no confirmed input fails without broadcasting\n'

cli generatetoaddress 1 "$(cli -rpcwallet=mining getnewaddress '' bech32)" > /dev/null
total=$((300 * 12345 + 400 * 20000))
assert_equal "$(cli -rpcwallet=recipient getbalance)" "$(printf '%d.%08d' $((total / 100000000)) $((total % 100000000)))"
printf 'ok 5 - the recipient holds exactly the funded total after one block\n'
