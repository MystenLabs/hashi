# hashi-monitor

A continuous auditor for the Hashi bridge. It reads Sui, the guardian's S3
logs, and Bitcoin, and reports a finding when they disagree or when a flow
breaks its timing bounds. It trusts Move, not the committee: it checks what
Move cannot see.

## What it checks

- **Withdrawals (Sui → Bitcoin).** Each withdrawal has three events: E1, the
  Hashi approval on Sui; E2, the guardian's signature in its S3 log; E3, the
  Bitcoin transaction with six confirmations. The monitor joins them by
  withdrawal id. It checks the timing bounds, that Sui and the guardian
  state the same transaction, and that the txid matches the transaction.
- **Deposits (Bitcoin → Sui).** Each `DepositRequested` is looked up on
  Bitcoin. Each `DepositApproved` must match a Bitcoin output with the same
  amount and bridge script, confirmed in time. Move delays the mint after
  the approval, so a finding can come before the mint.
- **The UTXO pool.** The monitor keeps its own pool of the UTXOs the bridge
  holds, changed only by Bitcoin facts. It checks each UTXO on Bitcoin once a
  day, and it checks that the pool backs the hBTC supply on Sui.
- **The guardian.** Each withdrawal log has a `seq` that the guardian's
  limiter takes once, in order. A repeat, a gap, or a jump is a finding.
- **Itself.** A source that falls behind, or a snapshot that cannot be saved,
  is a finding.

The module headers in `src/` give the details of each check.

## Findings

Every finding needs an operator action, so all findings have one level. Each
finding is an ERROR log line `monitor finding`, and it sets the metric
`hashi_monitor_last_finding_timestamp_seconds{kind="<kind>"}`.

| Kind | Meaning |
|---|---|
| `WithdrawalEventLate`, `WithdrawalEventMissing` | A withdrawal event is late or missing past its bound. |
| `WithdrawalTxidMismatch`, `WithdrawalTxUnbuildable` | A Hashi approval's txid does not match its inputs and outputs. |
| `WithdrawalMismatch` | Sui and the guardian state different inputs, payouts, or change. |
| `InvalidEventAdded` | An event contradicts its withdrawal. |
| `DepositUnbacked`, `DepositMismatch`, `DepositLate` | An approved deposit has no matching, timely Bitcoin output. |
| `UtxoUnexpectedSpend` | A pool UTXO was spent outside a Hashi withdrawal. |
| `UtxoUnknownInputSpent` | A withdrawal spent a UTXO the pool does not hold. |
| `UtxoTooOld` | A pool UTXO is older than 40 days. The committee can spend it alone at 60. |
| `HbtcSupplyExceedsPool` | The hBTC supply has exceeded the pool value for 3 hours. |
| `GuardianInconsistency` | Two logs for one `seq`, a missing `seq`, or a skip of more than 10 seqs. |
| `GuardianClockSkew` | A guardian log's signed time differs from S3's time by more than 30 s. |
| `BtcRpcInconsistency` | A Bitcoin answer contradicts an earlier one: a lying node or a reorg. |
| `SourceStale` | Sui, the guardian, or Bitcoin is checked more than 3 hours behind. |
| `SnapshotStale` | No snapshot save has succeeded for 12 hours. |

## Running the monitor

You need:

- a config file. Start from `audit.sample.yaml`;
- AWS credentials that can read the guardian bucket, from the default chain or
  the `s3_credentials` block;
- a Bitcoin JSON-RPC endpoint that serves `getrawtransaction`, so a node
  with `txindex` or a hosted provider, in `BITCOIN_RPC_URL`;
- a Sui node that keeps the history from the bridge's genesis for the first
  run, for example `archive.<network>.sui.io`. The public testnet fullnode
  keeps only about ten days;
- a GCS bucket for the snapshot, with read and write access through
  `GOOGLE_APPLICATION_CREDENTIALS` or, on GKE, the workload identity.

From `crates/hashi-monitor`:

```bash
cargo run -p hashi-monitor -- \
  --config audit.sample.yaml \
  --snapshot-bucket my-hashi-monitor-snapshot
```

### The snapshot

- After each state check, the monitor saves `snapshot.json` in the bucket:
  the position of each source, every open flow, and the UTXO pool.
- A restart continues from the snapshot. It reads no event twice and skips
  none.
- The first run has no snapshot. It starts at the bridge's genesis with an
  empty pool, so it sees every UTXO enter. It reads Sui in ranges of 10,000
  checkpoints; on a busy network this takes hours.
- The monitor does not start on a Sui node that has pruned its start
  checkpoint, because the pool would then be incomplete.
- The monitor must be the bucket's only writer. A snapshot of another
  deployment is ignored. A snapshot that does not parse stops the monitor;
  delete `snapshot.json` to start again from genesis.
- The snapshot is durable state, not a cache. Without it, the next start is a
  first run from genesis.

## Config

The config file holds the identity of one deployment. `audit.sample.yaml` is a
complete example.

- `deployment` gives the expected Bitcoin network, the guardian's S3 bucket and
  region, the retention environment, and the PCR allowlist. Every guardian
  session that writes a log must match it. Keep a replaced build in
  `prev_builds` until the guardian cursor, logged at each state check, passes
  its last log. A first run from genesis needs every build.
- `sui.rpc_url` and `sui.package_id` name the Sui node and the Hashi package.
- `btc.rpc_url` names the Bitcoin node. `btc.http_headers` is optional, for
  hosted providers.
- Any string value may be `env:NAME`. The monitor replaces it with the
  environment variable `NAME` at startup.
- An unknown key is an error.

The timing bounds of the flows are protocol constants in `src/timing.rs`, not
configuration.

## Alerting

The monitor decides what is wrong. An alerting system needs only these rules:

1. `time() - hashi_monitor_last_finding_timestamp_seconds < 3600`: a finding
   in the last hour. Each `kind` fires on its own. The details are in the
   `monitor finding` ERROR lines.
2. `up < 1`: the monitor cannot be scraped.
3. `absent(up)`: no monitor runs.

A restart clears the finding metric. The restart reads the events after the
last save again, so their findings come again.

## Metrics

- `hashi_monitor_last_finding_timestamp_seconds{kind}`: the time of the last
  finding of each kind.
- `hashi_monitor_checked_through_timestamp_seconds{source}`: how far each
  source is checked, for `sui`, `guardian`, `btc`, `utxo`, and `snapshot`.
- `hashi_monitor_pool_utxo_count` and
  `hashi_monitor_oldest_utxo_timestamp_seconds`: the held UTXOs, and the
  earliest block time among them. An empty pool gives 0.
- `hashi_monitor_pool_value_sats` and `hashi_monitor_hbtc_supply_sats`: the
  pool value and the hBTC supply.

The hBTC supply less the pool value is zero or below in an honest bridge:

```promql
hashi_monitor_hbtc_supply_sats - hashi_monitor_pool_value_sats
```

The age of the oldest held UTXO, in days:

```promql
((time() - hashi_monitor_oldest_utxo_timestamp_seconds) / 86400)
and (hashi_monitor_pool_utxo_count > 0)
```
