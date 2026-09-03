# Validator alerting guide

Recommended Prometheus alerts for hashi validator operators. A ready-to-use
rules file lives at [`monitoring/validator-alerts.example.yml`](../monitoring/validator-alerts.example.yml).

Two principles shape this list:

1. **Node-local vs bridge-wide.** Some `hashi_*` metrics describe *your node*
   (BTC view, mirror freshness, task liveness, gas); others mirror *shared
   bridge state* (presig pool, queue sizes, pause flag). Alerting a node
   operator on shared state produces alerts nobody at the node can act on.
2. **Never alert on activity-gated values.** A gauge that only updates when
   some activity happens cannot distinguish "quiet bridge" from "broken node".
   Every alert below is driven by a value that updates unconditionally.

## Per-node alerts

| Alert                   | Expression                                                            | Why this threshold                                                                                                                                                                                                        |
|-------------------------|-----------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| BTC view frozen         | `changes(hashi_kyoto_best_height[90m]) == 0`                          | Signet produces ~1 block/10 min, so a healthy tip ticks ~6×/hour. 90 minutes of silence is a stuck BTC view, not a quiet chain.                                                                                           |
| BTC not synced          | `hashi_kyoto_synced == 0` for 15m                                     | Brief resyncs are normal after restarts; sustained unsync is not.                                                                                                                                                         |
| No BTC peers            | `hashi_kyoto_connected_peers < 1` for 10m                             | No peers means no blocks, ahead of the tip going stale.                                                                                                                                                                   |
| Sui mirror stale        | `time() - (hashi_latest_checkpoint_timestamp_ms / 1000) > 120` for 5m | The state watcher applies checkpoints continuously. Two minutes without an applied checkpoint means the watcher, mirror, or fullnode RPC is wedged — the node acts on stale bridge state while looking healthy elsewhere. |
| Task wedged             | `time() - hashi_task_last_iteration_timestamp_seconds > 600`          | Each labeled task loop (`state_watcher`, `leader_loop`, `mpc_service`) iterates at least every 15s. A stale heartbeat catches a panicked or deadlocked task inside an otherwise-alive process.                            |
| Reconfig not tracking   | `changes(hashi_epoch[3h]) == 0`                                       | Testnet reconfigures roughly every 40 minutes. If the committee epoch stops moving, either your node stopped following reconfig or the fleet itself stalled — check the operator channel before assuming local fault.     |
| Low gas                 | `hashi_sui_balance < 1e9`                                             | Below 1 SUI the operator wallet is close to unable to submit. Refill.                                                                                                                                                     |
| Binary behind chain     | `hashi_package_version_unsupported == 1`                              | The chain moved to a package version this binary does not implement; autonomous writes are halted. Upgrade the binary immediately.                                                                                        |
| Database poisoned       | `hashi_db_poisoned == 1`                                              | fjall refuses every write after a failed flush or fsync (usually a full disk) until the process restarts, while reads and signing carry on looking healthy. Free the disk, then restart.                                  |
| Crash looping           | `changes(process_start_time_seconds{job="<your-node>"}[1h]) > 3`      | Uses the standard process exporter if you run one; any restart-count source works.                                                                                                                                        |
| Previous shares missing | `increase(hashi_mpc_rotation_previous_shares_missing_total[1h]) > 0`  | The node owed shares to a rotation and had none, so its weight did not reach the new key.                                                                                                                                 |

Dashboard-worthy but **not** alerts:

- `hashi_package_version_active` / `hashi_package_version_supported_max` —
  which version the node operates at, and the highest version the build
  implements. During a rollout, `supported_max` is how the fleet's binary
  upgrade progress is counted before the on-chain upgrade flips `active`.
- `hashi_is_leader` — leadership rotates; useful context when reading other
  metrics, meaningless to alert on.
- `hashi_db_keyspace_disk_bytes` — live table bytes per keyspace. Each one
  should fall at every epoch boundary; one that climbs across epochs is
  leaking. Alert on the volume itself, not on this.
- `hashi_deposit_outpoint_confirmations{status="not_found"}` — expected for
  unbroadcast transactions. It is suspicious only when your node reports it
  while peers report confirmations for the same deposits.

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

## Scope reference

| Metric | Scope |
| --- | --- |
| `hashi_kyoto_*` | node |
| `hashi_deposit_outpoint_confirmations` | node |
| `hashi_latest_checkpoint_*`, `hashi_task_last_iteration_timestamp_seconds` | node |
| `hashi_sui_balance`, `hashi_package_version_*`, `hashi_is_leader` | node |
| `hashi_db_*` | node |
| `hashi_presig_pool_remaining`, `hashi_num_consumed_presigs` | bridge |
| `hashi_deposit_queue_size`, `hashi_withdrawal_queue_*`, `hashi_utxo_pool_*` | bridge |
| `hashi_paused`, `hashi_reconfig_in_progress`, `hashi_epoch`, `hashi_sui_epoch` | bridge (visible per node) |
