# Load-test drivers

Bash drivers for a deposit and withdrawal load series against a deployed bridge on a
Bitcoin test network. They drive the `hashi` CLI and `bitcoin-cli`, so they exercise
the same paths a user does. `lib.sh` refuses Bitcoin mainnet.

## Setup

You need `bitcoin-cli` with a synced node and a funded wallet, `jq`, `curl`, and a
`hashi` binary built from the commit the deployment runs.

| Variable | |
| --- | --- |
| `HASHI_BIN` | path to that `hashi` binary |
| `SUI_RPC_URL`, `HASHI_PACKAGE_ID`, `HASHI_OBJECT_ID`, `HASHI_KEYPAIR` | read by the CLI |
| `SUI_ADDR` | the keypair's address, full length and lowercase; it signs, pays gas and receives hBTC |
| `BTC_NETWORK` | `signet`, `testnet4` or `regtest` |
| `BTC_RPC_URL`, `BTC_RPC_USER`, `BTC_RPC_PASSWORD` | the CLI reads each funding transaction from this node |
| `BTC_WALLET` | wallet that funds deposits and receives payouts (default `mining`) |
| `BITCOIN_CLI` | base command (default `bitcoin-cli -$BTC_NETWORK`) |
| `LOADTEST_DIR` | logs and state for one series; use a fresh directory per series |

Then check the deployment and take the operators' gas balances for later comparison:

```sh
bash scripts/load-test/preflight.sh
GRAPHQL_URL=https://graphql.testnet.sui.io/graphql bash scripts/load-test/operator-gas.sh > "$LOADTEST_DIR/operator-gas-before.tsv"
```

`fund-deposits.sh` spends one confirmed wallet UTXO per 250 deposits. If
`preflight.sh` reports too few, split a large one (28 covers the whole series):

```sh
bash scripts/load-test/split-funders.sh <txid> <vout> 28 127000000 --send
```

## The series

Each stage waits for its gate and then runs in the background, so all three can be
started at once:

```sh
for stage in 1k 2k 4k; do
  nohup bash scripts/load-test/series.sh "$stage" > "$LOADTEST_DIR/series-$stage.log" 2>&1 < /dev/null &
done
tail -f "$LOADTEST_DIR"/watch-*.log
```

| Stage | Starts when | Deposits | Withdrawals |
| --- | --- | --- | --- |
| `1k` | at once | 1,000 × 0.005 BTC | one PTB of 40 × 0.05 BTC once 400 deposits have minted, then 600 × 0.005 BTC at 25/min |
| `2k` | the 1K stream has submitted everything | 2,000 × 0.005 BTC | 2,000 × 0.005 BTC at 50/min |
| `4k` | the 2K stream has submitted 1,400 | 4,000 × 0.005 BTC | 4,000 × 0.003 BTC at 100/min, held until 1,000 deposits have minted |

- The 40 × 0.05 BTC batch is the worst case: ten deposit-sized inputs per request
  fill the 400-input cap of one withdrawal transaction.
- The 4K stream submits faster than 40-request batches clear. Once the queue is
  deeper than the available UTXO pool the leader switches to batches of up to 447
  (drain mode), and `series.sh 4k` logs the first one it sees.
- How soon that happens depends on the fee rate. Below 10 sat/vB every 40-request
  batch also consolidates up to 400 UTXOs, so the pool shrinks to a few UTXOs within
  the first batches and drain mode shows up in every stage.

When the 4K is paid, `drain.sh 4000000 30000` withdraws what the series left behind
(4,000 × 0.002 BTC) in 0.04 BTC requests; its second argument is the on-chain
`bitcoin_withdrawal_minimum`.

## Reading a run

- `watch-<tag>.log` prints a status line every 5 minutes: deposits minted, this
  address's queue by status, in-flight transactions and the largest batch, and
  latency per tick. It exits with `run <tag> complete` once every stream withdrawal
  is paid.
- `wd-track.sh "$LOADTEST_DIR/wd-<tag>-ticks.tsv" --per-tick` gives the same latency
  per tick. "Paid" is when the payout reached the local mempool; block header times
  trail wall time on signet, so `block-arrivals.sh` logs when blocks really arrived.
- `wd-batches.sh "$LOADTEST_DIR/wd-<tag>-ticks.tsv"` lists the withdrawal
  transactions that paid a run: inputs, outputs, weight and fee rate.
- Minting is gated by `bitcoin_confirmation_threshold` and
  `bitcoin_deposit_time_delay_ms`, which `preflight.sh` prints.
- Every input signature spends a presignature, so consolidation batches empty the
  pool in bursts: watch `hashi_presig_pool_remaining`,
  `hashi_mpc_sign_failures_total` and `hashi_withdrawal_oldest_unsigned_age_seconds`.

## What a series costs

Measured on Sui testnet in October 2026:

- The signer pays about 0.006 SUI per deposit request and 0.007 per withdrawal
  request, so roughly 90 SUI for the whole series.
- Leaders pay for every approval, confirmation and withdrawal step: about 0.009 SUI
  per deposit alone. The 1K cost the committee 16 SUI, and whoever led during the
  bursts paid most of it, up to 1.7 SUI for one operator. An operator funded near
  the 2 SUI minimum can run dry mid-series, so read `operator-gas.sh` first.
- Deposits come back as payouts to the wallet, less miner fees.

## Retries

Every PTB pays from the signer's one gas coin, so the drivers submit one at a time
(`submit` in `lib.sh`); run one series per signer. A deposit PTB that fails is
retried, since a duplicate request can't mint twice. A withdrawal PTB is not: a lost
response could hide one that landed, so `wd-steady.sh` looks for the requests in the
queue first, and `wd-worst.sh` and `drain.sh` stop and leave the check to you.

## Tests

- `test-fund-deposits.sh` runs `fund-deposits.sh` against a throwaway regtest
  `bitcoind` and checks the transactions it broadcasts. It needs `bitcoind` and
  `bitcoin-cli` on `PATH`.
- `test-wd-steady.sh` runs `wd-steady.sh` against stub CLIs and checks its ticks,
  resumption and both failure paths. It takes about 40 seconds.
