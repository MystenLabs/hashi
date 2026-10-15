# Alerting

hashi's Prometheus alerting rules live in [`monitoring/`](../monitoring/), one
file per component. Load the file for each component you run from `main`: the
rules work with every release since testnet-1.0 and mainnet-1.0, and a rule
whose metric your release doesn't export yet stays silent.

| You run | Load |
| --- | --- |
| a hashi node | [`monitoring/hashi-node.rules.yml`](../monitoring/hashi-node.rules.yml) |
| hashi-monitor (continuous mode) | [`monitoring/hashi-monitor.rules.yml`](../monitoring/hashi-monitor.rules.yml) |

Each rule's description says what fired and what to do, and a comment above a
rule explains a threshold that isn't obvious. Every rules file has a sibling
`*.test.yml` of `promtool` tests. `make check-alerts` runs them, checks the
rules, and fails on any metric name the code doesn't export; it needs
`promtool` 3.4.2 on `PATH`, the version CI uses. Use `absent()` only on a
metric every supported release exports, or it fires on older nodes.

Two principles shape the rules:

1. **Node-local vs bridge-wide.** Some `hashi_*` metrics describe *your node*
   (BTC view, mirror freshness, task liveness, gas); others mirror *shared
   bridge state* (presig pool, queue sizes, pause flag). Alerting a node
   operator on shared state produces alerts nobody at the node can act on.
2. **Never alert on activity-gated values.** A gauge that only updates when
   some activity happens cannot distinguish "quiet bridge" from "broken node".
   Every rule is driven by a value that updates unconditionally.

## Alerts to add yourself

The rules read only hashi's own metrics. Cover these with whatever already
watches your other services:

- The scrape target is down (`up == 0` for your hashi job).
- The volume holding the node's database is filling up. A full disk poisons
  the database (`HashiDbPoisoned`).
- The process keeps restarting. hashi exports no `process_*` metrics, but
  `resets(uptime{hashi_object_id!=""}[1h])` counts its restarts.

## Dashboard-worthy, not alerts

- `hashi_package_version_active` / `hashi_package_version_supported_max` —
  which version the node operates at, and the highest version the build
  implements. During a rollout, `supported_max` is how the fleet's binary
  upgrade progress is counted before the on-chain upgrade flips `active`.
- `hashi_mpc_presig_batch_repair_total` — a nonce batch the allocation cursor
  outran, and what this node did about it, by `outcome`.
- `hashi_is_leader` — leadership rotates; useful context when reading other
  metrics, meaningless to alert on.
- `hashi_db_keyspace_disk_bytes` — live table bytes per keyspace. Each one
  should fall at every epoch boundary; one that climbs across epochs is
  leaking. Alert on the volume itself, not on this.
- `hashi_deposit_outpoint_confirmations{status="not_found"}` — expected for
  unbroadcast transactions. It is suspicious only when your node reports it
  while peers report confirmations for the same deposits.
- `hashi_withdrawal_bitcoin_check_total{result="unavailable"}` and
  `hashi_withdrawal_bitcoin_check_latency_seconds` — finalize checks that got
  no answer in time, and how long answers take. A steady share of
  `unavailable` means the check is not running; `rejected_other` is normal.
- `hashi_peer_inflight_max`, `hashi_peer_inflight_max_bytes`,
  `hashi_peer_connections_max` — each peer's peak since start, against limits
  such as `hashi_peer_inflight_limit_bytes`.

## What NOT to alert on

- **`hashi_presig_pool_remaining == 0`.** This mirrors the *shared* presig
  pool, not your node's health. Mysten monitors pool exhaustion fleet-side.
  (Before the periodic sampler landed, this gauge also read 0 after any
  restart until the next withdrawal — the archetypal activity-gated trap.)
- **Failure ratios of `hashi_sui_tx_submissions_total{operation="confirm_deposit"}`.**
  Deposit confirmation is a leader-submitted, aggressively-retried race with
  several benign abort paths (already confirmed, reconfig window in progress,
  approval from a previous committee awaiting re-approval). Per-node failure
  ratios between 30% and 100% are all normal.
- **Ratios of raw counters.** `a_total / b_total` spans the whole process
  lifetime and drifts with history, not health. Always window both sides:
  `increase(a_total[1h]) / increase(b_total[1h])`.
- **`hashi_withdrawal_signing_refused_total{reason="cap"}`.** Noisy on testnet
  until the signing cap is tuned.

## Scope reference

| Metric | Scope |
| --- | --- |
| `hashi_kyoto_*` | node |
| `hashi_deposit_outpoint_confirmations` | node |
| `hashi_latest_checkpoint_*`, `hashi_task_last_iteration_timestamp_seconds` | node |
| `hashi_sui_balance`, `hashi_package_version_*`, `hashi_is_leader` | node |
| `hashi_withdrawal_commitment_left_out_total` | node (counts only while leading) |
| `hashi_db_*` | node |
| `hashi_withdrawal_bitcoin_check_*` | node |
| `hashi_peer_*`, `hashi_mpc_unguarded_spawn_blocking_total` | node |
| `hashi_presig_pool_remaining`, `hashi_num_consumed_presigs` | bridge |
| `hashi_deposit_queue_size`, `hashi_withdrawal_queue_*`, `hashi_withdrawal_oldest_unsigned_age_seconds`, `hashi_utxo_pool_*` | bridge |
| `hashi_paused`, `hashi_reconfig_in_progress`, `hashi_epoch`, `hashi_sui_epoch` | bridge (visible per node) |
