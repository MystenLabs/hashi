# Lossless onchain watcher — plan of attack

## Motivation

The watcher's correctness currently depends on every Move state mutation
either emitting an event rich enough to reconstruct the new state, or being
chased by bespoke re-fetch code. Any Move path that mutates state without an
event silently poisons the mirror (`reassign_presigs_for_withdrawal_txn`,
`cleanup_spent_utxos`, `finish_publish`). Today we paper over this with a
10-minute unconditional rescrape, a config poll, reconnect rescrapes, and
the GC's out-of-band fresh-snapshot reads.

This redesign makes the changed object contents themselves the source of
truth: subscribe to exactly the transactions that touched the Hashi root
object, receive the full BCS of every object those transactions changed,
and apply those objects to the local mirror. Events stop driving state.
Forgetting to add an event can no longer corrupt the mirror.

Unlike the abandoned `chain-watcher` branch (which built a general-purpose
ECS framework, `sui-ecs`), this iteration tracks Hashi's state directly:
a structural apply into the existing `types::Hashi` shape, with a small
routing table instead of an abstract World/component/scheduler system.

## Key findings

### The SDK already has everything we need

The workspace pins sui-rust-sdk at git rev `5b4525bd`, which is
byte-identical to the released v0.3.2 in proto and generated-code surface
(verified: `git diff 5b4525bd sui-rpc-0.3.2 -- vendored/proto src/proto`
is empty). The filtered APIs are available right now:

- `SubscriptionService.SubscribeTransactions(read_mask, filter)` — server
  stream of `ExecutedTransaction` matching a `TransactionFilter`. The
  filter is DNF (OR of terms, each an AND of literals); the predicate we
  want is `AffectedObjectFilter { object_id }`: "transactions whose
  effects include a change for the specified object." Builder:
  `TransactionFilter::matching(filter::transaction::affected_object(id))`.
- `LedgerService.ListTransactions(read_mask, start_checkpoint,
  end_checkpoint, filter, options)` — the same filter over history, with
  watermark cursors (`QueryOptions.after`) and a `QueryEnd` reason on the
  final frame. This is the gap-replay counterpart of the subscription.
- `ExecutedTransaction.objects` (`ObjectSet`) carries the full `Object`
  (including `bcs`, the complete `sui_sdk_types::Object` encoding — id,
  version, type, owner, and contents) for objects referenced as inputs or
  produced as outputs. No follow-up `BatchGetObjects` needed.
- Every subscription frame carries a `Watermark { cursor, checkpoint }`;
  `checkpoint` is the inclusive checkpoint through which all matching
  transactions have been delivered.
- Subscriptions cannot resume; a fresh subscription starts at the tip.
  Gap-free coverage across reconnects = replay `ListTransactions` from the
  last watermark until it overlaps the new subscription's start.

The only functional change between our pin and v0.3.2 is #287
(`execute_transaction_and_wait_for_checkpoint` answers duplicate
executions from the ledger) — a robustness win for `sui_tx_executor.rs`.
The bump is a version-number change, not a migration.

### Facts to reuse from the chain-watcher branch's design doc

- A dynamic object field (DOF) is two objects: a wrapper
  `Field<Wrapper<Name>, ID>` owned by the container's UID, and the value
  object owned by the wrapper's id. A value-only mutation shows only the
  value in `changed_objects` (owner = wrapper id); the wrapper appears in
  the object set as an unchanged loaded runtime input.
- A plain dynamic field `Field<Name, Value>` is one object owned by the
  container's UID; value mutations rewrite the Field object itself.
- An object moving between containers (e.g. proposal active → executed)
  looks like: old wrapper deleted, new wrapper created, value's owner
  changes. Routing must consider both the pre- and post-state owners.
- Active vs. executed proposals are the same `Proposal<T>` type; only the
  owning bag distinguishes them. Routing must be by ownership, not type.
- BCS-direct ingest works well: decode `sui_sdk_types::Object` straight
  from the proto `Object.bcs` field; classification comes from
  `changed_objects.output_state` (`OBJECT_WRITE` upsert /
  `DOES_NOT_EXIST` removal).

### Current-state constraints (from the consumer map)

- All reads flow through `OnchainState` accessors; `state_mut()` is
  module-private. Consumers (leader, MPC service, gRPC bridge, UTXO pool,
  CLI, guardian-init, internal-tools, e2e) never see the internals, so we
  can rebuild the update path without touching read sites.
- The leader ticks on `subscribe_checkpoint()` (every checkpoint) and
  reads `CheckpointInfo.timestamp_ms` as a clock; these must keep
  advancing even when no Hashi transaction lands.
- `wait_until_checkpoint(seq)` promises "the watcher has observed
  everything through seq." Under a filtered stream this maps exactly to
  `Watermark.checkpoint >= seq`.
- Two side effects ride the event path today and need transition-derived
  replacements: the local withdrawal limiter advance (on
  `WithdrawalSigned`) and the `Notification` channel
  (`ValidatorInfoUpdated`, `StartReconfig`, `SuiEpochChanged`).

## Design

### Two streams

1. **Clock stream** — unfiltered `subscribe_checkpoints` with a minimal
   mask (`sequence_number`, `summary.timestamp`, `summary.epoch`). Keeps
   `CheckpointInfo` (leader tick, timestamps, Sui epoch-change detection)
   fresh regardless of Hashi activity, and keeps the existing 120s stall
   detector meaningful. This stream is a few scalar fields per checkpoint.

2. **State stream** — `subscribe_transactions` filtered on
   `affected_object == hashi_root_id`, with read mask:

   ```text
   transaction.digest
   transaction.checkpoint
   transaction.effects.status
   transaction.effects.changed_objects.object_id
   transaction.effects.changed_objects.input_version
   transaction.effects.changed_objects.output_version
   transaction.effects.changed_objects.input_owner
   transaction.effects.changed_objects.output_owner
   transaction.effects.changed_objects.id_operation
   transaction.effects.changed_objects.output_state
   transaction.effects.unchanged_loaded_runtime_objects
   transaction.objects.objects.bcs
   transaction.events.events.contents   (transition only; dropped at cleanup)
   ```

   Every object a Hashi-touching transaction changed arrives inline as
   full BCS. Bandwidth now scales with Hashi activity, not total chain
   write volume.

`OnchainState` tracks two positions: the clock position (drives
`CheckpointInfo`) and the state watermark (drives
`wait_until_checkpoint`). The state watermark must never be reported
ahead of what has been applied.

### Mirror shape: keep `types::Hashi`, add object metadata

Consumers keep the `BTreeMap`-shaped, enriched `types::*` view. The
additions live alongside it in `State`:

- `object_versions: BTreeMap<Address, u64>` — last-applied version per
  tracked object. Makes every apply idempotent and order-safe: skip a
  write unless `output_version` is newer; skip a delete unless it
  post-dates what we hold. This is what lets bootstrap, replay, and live
  frames overlap freely.
- `routing: RoutingTable` — maps container UIDs to logical slots:

  ```rust
  enum Slot {
      MembersBag, CommitteesBag, TreasuryBag,
      ProposalsActive, ProposalsExecuted,
      DepositRequests, DepositProcessed,
      WithdrawalRequests, WithdrawalProcessed,
      WithdrawalTxns, ConfirmedTxns,
      UtxoRecords, SpentUtxos, Tob,
  }
  ```

  Built from the decoded root and `BitcoinState` contents (these ids are
  already stored today as `members_id`, `active_id`, `utxo_records_id`,
  etc.); refreshed whenever the root or `BitcoinState` object is applied.
- `wrapper_parents: BTreeMap<Address, Address>` — DOF wrapper field id →
  container UID. Populated at scrape time (the `DynamicField` proto
  exposes `field_id`) and maintained from wrapper create/delete writes in
  the stream. Used as a fallback when a value's wrapper is not present in
  the transaction's object set.

### Apply: structural walk per transaction

For each `ExecutedTransaction` (skip if `effects.status` failed):

1. Decode every `objects.objects.bcs` into `sui_sdk_types::Object`;
   index by id.
2. Root first: if the Hashi root changed, decode `move_types::Hashi`;
   update config, `num_consumed_presigs`, committee-set scalars (epoch,
   pending epoch change, MPC public key), and refresh the routing table.
   Same for the `BitcoinState` dynamic field.
3. For each entry in `changed_objects`:
   - `OBJECT_WRITE`: resolve the owner (post-state) to a slot. Owner is a
     container UID directly (plain DF) or a wrapper id (DOF value —
     resolve via the wrapper object in the set, else `wrapper_parents`).
     Decode by the slot's statically known type
     (`Field<Address, MemberInfo>`, `Field<u64, Committee>`,
     `Proposal<T>`, `WithdrawalTransaction`, ...) and upsert into the
     matching `types::Hashi` map. A write whose pre-state owner resolved
     to a *different* slot is a move: remove from the old slot too.
   - `DOES_NOT_EXIST`: resolve the pre-state owner to a slot and remove.
     Wrapper deletions update `wrapper_parents`.
   - Unroutable objects: address-owned (gas coins) and package writes are
     explicitly ignored; anything owned by a UID we track but with no
     handler, or carrying a hashi-package type we don't recognize,
     increments `hashi_watcher_unrouted_objects_total` and logs. This is
     the tripwire that replaces "we forgot to add an event."
4. Version guards apply at every upsert/remove via `object_versions`.

Package upgrades: the filter gains a second OR term,
`package_write`, or simply relies on the upgrade transaction touching the
root (proposal execution does); the `PackageUpgraded` bookkeeping moves to
detecting the new package object / root `versioning` change.

### Side effects derived from state transitions, not events

The apply step sees old and new values, so triggers become diffs:

- `WithdrawalTransaction` transitions to fully signed → advance the local
  limiter and observe `pick_to_sign`, using the transaction's checkpoint
  timestamp. Idempotency comes from the same version guard plus the
  existing `is_fully_signed` gate.
- `WithdrawalTransaction` removed → `sign_to_confirm` / `total` metrics.
- Member `Field<Address, MemberInfo>` upsert/remove → rebuild only that
  validator's gRPC client, update the TLS reverse map, and emit
  `Notification::ValidatorInfoUpdated`.
- Root `pending_epoch_change` set → `Notification::StartReconfig`.
- `SuiEpochChanged` comes from the clock stream.

Events remain parsed for logging during the transition and are removed
from the mask at cleanup. `UtxoRecord.spent_by` / `produced_by` /
`spent_epoch` are on-chain fields, so the event-driven bookkeeping for
locks and change UTXOs disappears entirely — the object writes carry it.

### Bootstrap and reconnect (both lossless)

Bootstrap:
1. Open the filtered subscription; buffer frames.
2. Run the existing scrape fan-out, extended to record each object's id,
   version, and (for DOFs) wrapper `field_id`. Track the minimum
   checkpoint height across all scrape responses.
3. Replay `ListTransactions(filter, start_checkpoint = scrape floor)` to
   the ledger tip, applying with version guards.
4. Drain the buffered subscription frames (version guards make the
   overlap harmless), then go live.

Reconnect: identical minus the scrape — resubscribe, replay from the last
watermark cursor (`QueryOptions.after`), drain, live. Because the List
index can trail the live tip, replay loops until it overlaps the new
subscription's first frame. Only if replay fails (e.g. the server pruned
the range after a long outage) do we fall back to a full rescrape.

This deletes rescrape-on-reconnect as a correctness mechanism. The
10-minute periodic rescrape is demoted to a divergence audit during
burn-in (scrape, compare against the mirror, emit
`hashi_watcher_divergence_total`, do not install) and then removed or
left as a config-gated audit.

## What this fixes and what it deletes

Fixed by construction: eventless writes (`cleanup_spent_utxos`,
`finish_publish`, reassigned presigs), stale `num_consumed_presigs`,
lingering spent `UtxoRecord`s, subscription-gap drift, limiter drift after
gaps (replay re-derives transitions in order).

Deleted at cutover: `handle_events`'s state mutations,
`fetch_withdrawal_txn`, `fetch_treasury_cap`, `scrape_member_info`,
`scrape_committee` (single-epoch), `scrape_hashi_config` + the config
poll (`launch_pending`), rescrape-on-reconnect, the periodic rescrape as a
correctness mechanism. Later candidates: the GC's out-of-band
`scrape_utxo_records_snapshot` (the mirror plus the watermark floor now
provides the same freshness guarantee), and caching TOB certs in the
mirror instead of on-demand fetches.

## Verification items (before or during step 3)

1. Confirm every state-mutating entry point in the Move package takes the
   Hashi root (shared) object, so `affected_object(root)` captures all
   mutations — including TOB dealer submissions and guardian paths. Any
   exception needs an extra OR term in the filter.
2. Confirm the per-transaction `ObjectSet` includes unchanged loaded
   runtime objects (the DOF wrappers) like `Checkpoint.objects` does; the
   `wrapper_parents` fallback covers it either way, but inline resolution
   is preferable.
3. Confirm the filtered subscription emits watermark-bearing progress
   frames during inactivity (affects stall detection on the state stream;
   the clock stream covers liveness regardless).
4. Check retention of the transaction index on the fullnodes we operate
   against (bounds the replay window before the rescrape fallback kicks
   in).

## PR sequence

Each PR builds, passes `cargo nextest run`, and is independently
revertible.

1. **meta: move sui sdk pins to crates.io v0.3.2.** Drops the git revs;
   picks up the duplicate-execution fix for `sui_tx_executor`.
2. **hashi-types: one `MoveStruct` trait.** Replace the duplicated
   `MoveType` traits (one in `hashi-types`, one in `hashi::onchain`) with
   a single trait carrying module/name matching helpers
   (`is_field_with_value`, DOF wrapper detection). Migrate event impls.
   No behavior change.
3. **hashi: routing table + apply, as pure functions.**
   `onchain/route.rs` (Slot, RoutingTable, wrapper resolution) and
   `onchain/apply.rs` (per-transaction structural walk into
   `types::Hashi`, version guards, transition-derived side effects
   returned as a value — e.g. `Vec<Effect>` — so the caller owns limiter,
   metrics, and notifications). Unit tests with synthesized
   `sui_sdk_types::Object`s: every slot type, DOF add/mutate/remove, the
   bag-to-bag move edge, out-of-order and duplicate delivery, unrouted
   tripwire.
4. **hashi: scrape records object metadata.** Extend the scrape masks
   with `field_id` / `child_object.version` / `object_id` and populate
   `object_versions` + `wrapper_parents` + scrape floor.
5. **hashi: new watcher loop, shadow mode.** Clock stream + filtered
   state stream + bootstrap/replay logic feeding a shadow `State`. The
   existing 10-minute rescrape tick becomes the divergence audit between
   legacy state, shadow state, and fresh scrape. e2e parity assertion in
   the harness (the chain-watcher branch's parity test is prior art).
6. **Cutover.** The shadow path becomes the mirror; `handle_events` state
   mutations and bespoke fetchers are deleted; the config poll dies;
   rescrape survives only as the replay-failure fallback and optional
   audit. Notifications and the limiter now come from apply's `Effect`s.
7. **Cleanup and follow-ups.** Drop events from the read mask (keep
   parsing only for logs if wanted), reconsider the GC snapshot path,
   decide on TOB cert mirroring, remove dead scrape helpers.

## Testing

- Unit: route/apply table-driven tests per slot; property test that any
  interleaving of {scrape snapshot, replayed transactions, live frames}
  with duplicates converges to the same mirror (version-guard
  idempotency).
- e2e (`ulimit -n 4096 &&` for bitcoind): full deposit/withdrawal/reconfig
  flow with the shadow comparison enabled and
  `hashi_watcher_divergence_total == 0` asserted at the end; a
  kill-and-reconnect test that lands transactions during the outage and
  asserts the replay path (not rescrape) recovers them; an eventless-write
  test that performs `cleanup_spent_utxos` and asserts the mirror updates
  without a rescrape.
- Metrics to watch in staging: divergence counter, unrouted-objects
  counter, replay-window length on reconnects.
