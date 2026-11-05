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
  day, and it checks that the pool backs the hBTC supply on Sui. A deposit
  with no Sui approval stays in the pool, but only the UTXOs in Move's pool
  count in the pool value.
- **The guardian.** Each withdrawal log has a `seq` that the guardian's
  limiter takes once, in order. A repeat, a gap, or a jump is a finding.
- **Itself.** A source that falls behind, or a snapshot that cannot be saved,
  is a finding.

The module headers in `src/` give the details of each check.

## Findings

Every finding needs an operator action. A finding that alerts is an ERROR
log line `monitor finding`, and it sets the metric
`hashi_monitor_last_finding_timestamp_seconds{kind="<kind>"}`. The config
key `alert_mode` picks the findings that alert:

- `strict`, the default: every finding alerts.
- `essential`: only the essential findings alert. The other findings are
  WARN log lines `monitor finding`, and they do not set the metric.

Every operator must act on an essential finding. The other findings show no
loss of Bitcoin backing.

| Kind | Essential | Meaning |
|---|---|---|
| `WithdrawalEventLate`, `WithdrawalEventMissing` | Yes | A withdrawal event is late or missing past its bound. |
| `WithdrawalTxidMismatch`, `WithdrawalTxUnbuildable` | Yes | A Hashi approval's txid does not match its inputs and outputs. |
| `WithdrawalMismatch` | Yes | Sui and the guardian state different inputs, payouts, or change. |
| `InvalidEventAdded` | Yes | An event contradicts its withdrawal. |
| `DepositUnbacked` | Yes | An approved deposit's outpoint holds no unspent Bitcoin output. |
| `DepositMismatch` | Yes | Two events of one deposit request disagree: the approval and the Bitcoin payment, the approval and its request, or two requests. |
| `DepositLate` | No | An approved deposit's Bitcoin block is more than 2 hours after the approval. Hashi approved before Bitcoin confirmed the payment, or a miner dated the block late. The payment came, so Bitcoin now backs the hBTC. |
| `DepositNotApproved` | No | A paid deposit has no approval 2 days after its latest request. The finding names the causes that the monitor can infer: a wrong amount, or a block more than 1 day after the request. If neither is true, the cause is a sanction or a committee that withholds the approval. The daily pool check reports it again until an approval comes. |
| `UtxoUnexpectedSpend` | Yes | A pool UTXO was spent outside a Hashi withdrawal. |
| `UtxoOutsideMovePoolSpent` | Yes | A withdrawal spent a UTXO that is not in Move's pool: the pool never held it, or held it as a deposit with no approval. The monitor missed an event, or Move has a fault. |
| `UtxoOriginConflict` | Yes | A deposit and a withdrawal's change claim one outpoint. Move refuses a request for held change, so an insider or a Move fault is the cause. |
| `UtxoTooOld` | Yes | A pool UTXO is older than 40 days, approved or not. The committee can spend it alone at 60. |
| `HbtcSupplyExceedsPool` | Yes | The hBTC supply has exceeded the pool value for 3 hours. |
| `GuardianInconsistency` | Yes | Two logs for one `seq`, a missing `seq`, or a skip of more than 10 seqs. |
| `GuardianClockSkew` | No | A guardian log's signed time differs from S3's time by more than 30 s. The cause is the guardian's clock or a slow S3 write. |
| `BtcRpcInconsistency` | Yes | A Bitcoin answer contradicts an earlier one: a lying node or a reorg. |
| `SourceStale` | Yes | Sui, the guardian, or Bitcoin is checked more than 3 hours behind, no daily pool check succeeded for 27 hours, or no hBTC supply read succeeded for 3 hours. |
| `SnapshotStale` | Yes | No snapshot save has succeeded for 12 hours. |

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

- About once an hour, and after the initial catch-up, the monitor saves
  `snapshot.json` in the bucket:
  the position of each source, every open flow, and the UTXO pool.
- A restart continues from the snapshot. It reads no event twice and skips
  none.
- The first run has no snapshot. It starts at the bridge's genesis with an
  empty pool, so it sees every UTXO enter. It reads Sui in ranges of 10,000
  checkpoints; on a busy network this takes hours.
- The monitor does not start on a Sui node that has pruned its start
  checkpoint, because the pool would then be incomplete.
- The monitor must be the bucket's only writer. A snapshot of another
  deployment or one that does not parse stops the monitor. Check the config,
  or delete `snapshot.json` to start again from genesis.
- The snapshot is durable state, not a cache. Without it, the next start is a
  first run from genesis.
- A snapshot from a monitor before unapproved deposits were tracked loads
  every held deposit as approved. That monitor did not record approvals.
  Deposits paid after the upgrade are exact. To make the old ones exact too,
  delete `snapshot.json` and start again from genesis.

## Config

The config file holds the identity of one deployment. `audit.sample.yaml` is a
complete example.

- `deployment` gives the expected Bitcoin network, the guardian's S3 bucket and
  region, the retention environment, and the PCR allowlist. Every guardian
  session that writes a log must match it. Keep a replaced build in
  `prev_builds` until the guardian cursor, logged at each guardian poll, passes
  its last log. A first run from genesis needs every build.
- `sui.rpc_url` and `sui.package_id` name the Sui node and the Hashi package.
- `btc.rpc_url` names the Bitcoin node. `btc.http_headers` is optional, for
  hosted providers.
- `alert_mode` is optional. It picks the findings that alert: `strict`, the
  default, or `essential`. See [Findings](#findings).
- Any string value may be `env:NAME`. The monitor replaces it with the
  environment variable `NAME` at startup.
- An unknown key is an error.

The timing bounds of the flows are protocol constants in `src/timing.rs`, not
configuration.

The monitor reads Hashi's Bitcoin confirmation threshold and deposit time
delay once, at startup. Restart the monitor after a governance change of
either value. Until the restart, the monitor uses the old values and can
report false findings.

## Alerting

The monitor decides what is wrong. An alerting system needs only these rules:

1. `time() - hashi_monitor_last_finding_timestamp_seconds < 3600`: a finding
   in the last hour. Each `kind` fires on its own. The details are in the
   `monitor finding` ERROR lines. With `alert_mode: essential`, only the
   essential findings set this metric.
2. `up < 1`: the monitor cannot be scraped.
3. `absent(up)`: no monitor runs.

A restart clears the finding metric. The restart reads the events after the
last save again, so their findings come again.

## Metrics

- `hashi_monitor_last_finding_timestamp_seconds{kind}`: the time of the last
  finding of each kind that alerts. See `alert_mode`.
- `hashi_monitor_checked_through_timestamp_seconds{source}`: how far each
  source is checked, for `sui`, `guardian`, `btc`, `utxo`, and `snapshot`.
- `hashi_monitor_pool_utxo_count` and
  `hashi_monitor_oldest_utxo_timestamp_seconds`: the UTXOs in Move's pool,
  and the earliest block time among them. With no such UTXO, both are 0.
- `hashi_monitor_pool_value_sats`: the total amount of the UTXOs in Move's
  pool.
  - A deposit counts when the monitor has seen both its Bitcoin confirmation
    and its Sui `DepositApproved`.
  - A change output counts from the Bitcoin confirmation of its withdrawal.
  - A UTXO stops counting at the Bitcoin confirmation of the withdrawal that
    spends it.
  - A deposit with no approval does not count.
- `hashi_monitor_hbtc_supply_sats`: the hBTC supply.
- `hashi_monitor_open_flows{kind}`: the open `withdrawal` and `deposit` flows,
  set at each maintenance tick and after the initial catch-up.

The hBTC supply less the pool value is zero or below in an honest bridge:

```promql
hashi_monitor_hbtc_supply_sats - hashi_monitor_pool_value_sats
```

The age of the oldest UTXO in Move's pool, in days:

```promql
((time() - hashi_monitor_oldest_utxo_timestamp_seconds) / 86400)
and (hashi_monitor_pool_utxo_count > 0)
```
