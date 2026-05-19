# Onchain mirror redesign

## Motivation

The withdrawal-stuck bug from the recent load test traces to a single root
cause: `reassign_presigs_for_withdrawal_txn` mutates on-chain state without
an `event::emit`, so the watcher's local mirror never sees the update. The
leader keeps reading a stale `txn.epoch`, retries `reassign` every iteration,
and never falls through to MPC signing.

This is a class of bug, not a one-off. The watcher's correctness depends on
every Move state mutation either (a) emitting an event with enough payload
to reconstruct the new state or (b) being followed up by code that re-reads
chain state. Any future Move code path that mutates an object without an
event re-introduces the bug.

The redesign shifts the canonical signal of "state changed" from events to
`TransactionEffects.changed_objects` and `Checkpoint.objects`. Events stay,
but only as hints driving notifications and routing — not as the source of
truth for state.

## Current architecture (what we're replacing)

Three layers exist today:

1. **`hashi-types/src/move_types/mod.rs`** — BCS-shaped Rust mirrors of Move
   structs. `serde_derive::Deserialize` for each struct in BCS field order.
   `MoveType` trait carries `MODULE` and `NAME`, used only by events. No
   object metadata (version, digest, owner) is captured.

2. **`hashi/src/onchain/types.rs`** — enriched mirror with mixed
   responsibilities. Some types are pure re-exports of layer 1. Others wrap
   layer 1 with semantic enrichment (BLS key parsing, encryption key
   parsing, `TypeTag` dispatch for treasury entries / proposals, `Config`
   flattening). Bag/Table-backed maps are flattened into Rust `BTreeMap`s
   with no record of the underlying field IDs or versions.

3. **`hashi/src/onchain/mod.rs` + `watcher.rs`** — scrape and event-driven
   mirror. `scrape_hashi` does one `get_object` on the root, then fans out
   `list_dynamic_fields` per Bag/Table to pre-warm every container. The
   watcher reads only events and applies per-event mutations directly to
   the layer-2 maps. Whenever an event can't reconstruct state on its own
   (`WithdrawalPickedForProcessingEvent`, `StartReconfigEvent`, mint/burn,
   etc.) it does a bespoke one-off RPC: `fetch_withdrawal_txn`,
   `scrape_committee`, `fetch_treasury_cap`, `scrape_member_info`,
   `scrape_hashi_config`.

The duplicated `MoveType` trait (one in each crate) is a smaller symptom of
the same problem: the type system doesn't know what an object is, only
what its BCS payload looks like.

## Key facts that inform the redesign

### DOF (dynamic object field) memory layout

From `sui-framework/sources/dynamic_object_field.move:257-306` a DOF is
*two* objects:

1. A wrapper `Field<Wrapper<Name>, ID>` parented to the outer UID. Its
   address is `derive_dynamic_child_id(parent_uid,
   type_tag_of(Wrapper<Name>), bcs(name))`.

2. The actual `Value` object, parented to the wrapper field's address via
   `add_child_object(field.to_address(), value)`.

When the `Value` mutates, only the `Value` appears in `changed_objects`
with `output_owner = Object(wrapper_id)`. The wrapper itself is unchanged.
The wrapper *does* appear in `changed_objects` (with `id_operation =
CREATED` or `DELETED`) on add or remove.

### Regular DF (no DOF)

`Field<Name, Value>` is parented to the outer UID. The value lives inside
the Field object, so a value mutation rewrites the Field object itself —
`output_owner = Object(parent_uid)`. No intermediate hop.

### `Checkpoint.objects` includes unchanged loaded runtime objects

From `sui-types/storage/read_store.rs:233-256`, `Checkpoint.object_set` is
built from `get_transaction_object_set(transaction, effects,
unchanged_loaded_runtime_objects)`. This means the deduped object set in
`Checkpoint.objects` always contains the DOF wrapper Field even when only
the Value was mutated, because the wrapper was loaded as a runtime input
to access the Value.

The consequence: **routing for DOF Value mutations can be resolved from
`Checkpoint.objects` alone**, with no persistent wrapper map required.
For a Value with `output_owner = Object(addr)`, look `addr` up in
`Checkpoint.objects`, decode it as `Field<Wrapper<…>, ID>`, and check the
wrapper's own owner against our known ObjectBag/ObjectTable parent IDs.

We still maintain a persistent wrapper map as a cache (and as a backstop
for the unlikely case where the wrapper is not in the object set) but it
is no longer load-bearing for the data flow.

### `Checkpoint.objects` and `subscribe_checkpoints`

`Checkpoint.objects` is a deduped `ObjectSet` mask-selectable in
`SubscribeCheckpointsRequest.read_mask`. When populated,
`transactions[].objects` is omitted, per the proto comment. One read mask
covers it; no follow-up `BatchGetObjects` is needed per checkpoint.

### Heterogeneous bags

`bag.move` and `object_bag.move` allow different K/V types per entry.
Hashi's bags happen to be homogeneous today but the design must keep raw
storage tolerant of unknown types so an unrecognized entry doesn't drop
mirror coverage. Tables and ObjectTables are homogeneous by construction.

### `Owner` in proto

From `sui/rpc/v2/owner.proto`, `Owner` has a `kind` enum
(`ADDRESS`/`OBJECT`/`SHARED`/`IMMUTABLE`/`CONSENSUS_ADDRESS`), an
`address` string, and a `version` for shared objects. `output_owner` and
`input_owner` carry it inside `ChangedObject`.

## Design

### Top-level data model

```rust
pub struct OnchainMirror {
    state: HashiState,
    routing: Routing,
}

pub struct HashiState {
    pub root: Option<MoveObject<move_types::Hashi>>,
    pub bitcoin_state: Option<MoveObject<BitcoinStateField>>,
    pub config: ConfigProjection,

    pub members: BagSlot<Address, MemberInfoProjection>,
    pub committees: BagSlot<u64, CommitteeProjection>,
    pub deposit_requests: ObjectBagSlot<Address, DepositRequestProjection>,
    pub withdrawal_requests: ObjectBagSlot<Address, WithdrawalRequestProjection>,
    pub withdrawal_txns: ObjectBagSlot<Address, WithdrawalTransactionProjection>,
    pub utxo_records: BagSlot<UtxoId, UtxoRecordProjection>,
    pub spent_utxos: BagSlot<UtxoId, u64>,
    pub treasury: ObjectBagSlot<TreasuryKey, TreasuryEntryProjection>,
    pub proposals_active: ObjectBagSlot<Address, ProposalProjection>,
    pub proposals_executed: ObjectBagSlot<Address, ProposalProjection>,
    pub tob: BagSlot<TobKey, EpochCertsProjection>,
}
```

`BagSlot` carries the parent UID, last-seen Bag header, projected entries,
and a reverse index for deletes:

```rust
pub struct BagSlot<K, V> {
    pub parent_id: Address,
    pub size: u64,
    pub entries: BTreeMap<K, BagEntry<V>>,
    pub by_field_id: BTreeMap<Address, K>,
}

pub struct BagEntry<V> {
    pub field_id: Address,
    pub field_version: u64,
    pub value: V,
}

pub struct ObjectBagSlot<K, V> {
    pub parent_id: Address,
    pub size: u64,
    pub entries: BTreeMap<K, ObjectBagEntry<V>>,
    pub by_wrapper_id: BTreeMap<Address, K>,
    pub by_value_id: BTreeMap<Address, K>,
}

pub struct ObjectBagEntry<V> {
    pub wrapper_id: Address,
    pub wrapper_version: u64,
    pub value_id: Address,
    pub value_version: u64,
    pub value: V,
}
```

The container header (size, parent_id) is updated when the *enclosing*
object is rewritten — Hashi root for bags inside it, BitcoinState DF for
bags inside that. There is no separate "container header apply" branch.

### `MoveStruct` trait and `MoveObject<T>` envelope

Replace both `MoveType` traits (one in `hashi-types`, one in
`hashi/src/onchain/mod.rs`) with one trait in `hashi-types`:

```rust
pub trait MoveStruct: serde::de::DeserializeOwned {
    const MODULE: &'static str;
    const NAME: &'static str;
    const TYPE_PARAMS: usize = 0;

    fn matches(tag: &StructTag) -> bool {
        tag.module() == Self::MODULE
            && tag.name() == Self::NAME
            && tag.type_params().len() == Self::TYPE_PARAMS
    }
}

pub struct MoveObject<T> {
    pub id: Address,
    pub version: u64,
    pub type_: StructTag,
    pub value: T,
}

impl<T: MoveStruct> MoveObject<T> {
    /// Returns:
    ///   Ok(Some(_))  the object's StructTag matches `T` and BCS
    ///                decoded cleanly.
    ///   Ok(None)     the StructTag does not match `T`. Not an error;
    ///                the caller fed an unrelated object.
    ///   Err(_)       the StructTag matched but BCS decoding failed.
    pub fn try_from_object(obj: &proto::Object) -> Result<Option<Self>, BcsError>;

    /// Like try_from_object but treats type mismatch as an error.
    pub fn from_object(obj: &proto::Object) -> Result<Self, FromObjectError>;
}
```

Package version gating lives in `Routing`, not on the envelope.

### Raw container types

`Bag` and `ObjectBag` differ; same for `Table` vs `ObjectTable`. Each
raw representation matches the on-chain layout.

```rust
pub struct RawDynamicField {
    pub field_id: Address,
    pub field_version: u64,
    pub name: RawValue,
    pub value: RawValue,
}

pub struct RawDynamicObjectField {
    pub wrapper_id: Address,
    pub wrapper_version: u64,
    pub name: RawValue,
    pub child: RawObject,
}

pub struct RawObject {
    pub id: Address,
    pub version: u64,
    pub type_: StructTag,
    pub contents: Vec<u8>,
}

pub struct RawValue {
    pub type_: TypeTag,
    pub bcs: Vec<u8>,
}

pub struct Bag {
    pub id: Address,
    pub size: u64,
    pub entries: BTreeMap<Vec<u8>, RawDynamicField>,
}

pub struct ObjectBag {
    pub id: Address,
    pub size: u64,
    pub entries: BTreeMap<Vec<u8>, RawDynamicObjectField>,
}

pub struct Table<K, V> {
    pub id: Address,
    pub size: u64,
    pub name_type: TypeTag,
    pub value_type: TypeTag,
    pub entries: BTreeMap<K, MoveObject<move_types::Field<K, V>>>,
}

pub struct ObjectTable<K, T: MoveStruct> {
    pub id: Address,
    pub size: u64,
    pub name_type: TypeTag,
    pub value_type: StructTag,
    pub entries: BTreeMap<K, ObjectTableEntry<K, T>>,
}

pub struct ObjectTableEntry<K, T: MoveStruct> {
    pub wrapper: MoveObject<move_types::Field<move_types::Wrapper<K>, Address>>,
    pub value: MoveObject<T>,
}

pub struct LinkedTable<K, V> { /* head, tail, plus DF entries */ }
```

`Bag` and `ObjectBag` keep entries in raw form so unknown types don't get
dropped. A typed projection over a `Bag`/`ObjectBag` is a separate
operation that may partially fail.

### Routing

```rust
pub struct Routing {
    pub hashi_id: Address,
    pub bitcoin_state_field_id: Address,
    pub package_ids: BTreeSet<Address>,

    /// Regular DF parents. Used when an object's owner is
    /// Object(parent_uid) and the object's type is Field<Name, Value>.
    pub df_parents: BTreeMap<Address, ContainerSlotKind>,

    /// DOF parents. Used to interpret newly CREATED Field<Wrapper, ID>
    /// objects (whose owner is Object(parent_uid)).
    pub dof_parents: BTreeMap<Address, ContainerSlotKind>,

    /// DOF wrapper cache. Optional but maintained as fast-path: the
    /// authoritative source is the wrapper itself, which is always in
    /// Checkpoint.objects when its Value is touched (because the wrapper
    /// is a loaded runtime object even when unchanged).
    pub dof_wrappers: BTreeMap<Address, ContainerSlotKind>,
}

#[derive(Clone, Copy)]
pub enum ContainerSlotKind {
    Members, Committees,
    DepositRequests, WithdrawalRequests, WithdrawalTxns,
    UtxoRecords, SpentUtxos,
    Treasury, ProposalsActive, ProposalsExecuted, Tob,
}
```

### Object-centric apply

```rust
pub enum ObjectUpdate {
    Written  { id: Address, version: u64, type_: StructTag, owner: Owner, contents: Vec<u8> },
    Deleted  { id: Address, type_: StructTag, prior_owner: Owner },
}

pub enum Classification {
    HashiRoot,
    BitcoinState,
    DfWrite          { slot: ContainerSlotKind, field: RawDynamicField },
    DfDelete         { slot: ContainerSlotKind, field_id: Address },
    DofWrapperWrite  { slot: ContainerSlotKind, wrapper: WrapperField, child: Option<RawObject> },
    DofWrapperDelete { slot: ContainerSlotKind, wrapper_id: Address },
    DofValueWrite    { slot: ContainerSlotKind, value: RawObject },
    DofValueDelete   { slot: ContainerSlotKind, value_id: Address },
    Ignored,
}
```

`Classification` is the output of a pure function that takes one
`ObjectUpdate`, the per-checkpoint `ObjectIndex` (lookup by id into
`Checkpoint.objects`), and `&Routing`. It does not mutate.

`apply` dispatches on `Classification`:

```rust
fn apply(state: &mut HashiState, routing: &mut Routing, class: Classification) -> Result<()> {
    match class {
        Classification::HashiRoot => apply_hashi_root(state, routing, ...),
        Classification::BitcoinState => apply_bitcoin_state(state, routing, ...),
        Classification::DfWrite { slot, field } => apply_df_entry(state, slot, field),
        Classification::DfDelete { slot, field_id } => apply_df_delete(state, slot, field_id),
        Classification::DofWrapperWrite { slot, wrapper, child } => {
            routing.dof_wrappers.insert(wrapper.id, slot);
            apply_dof_wrapper_write(state, slot, wrapper, child)
        }
        Classification::DofWrapperDelete { slot, wrapper_id } => {
            routing.dof_wrappers.remove(&wrapper_id);
            apply_dof_wrapper_delete(state, slot, wrapper_id)
        }
        Classification::DofValueWrite { slot, value } => apply_dof_value(state, slot, value),
        Classification::DofValueDelete { slot, value_id } => apply_dof_value_delete(state, slot, value_id),
        Classification::Ignored => Ok(()),
    }
}
```

When `apply_hashi_root` runs, it deserializes `move_types::Hashi` and
copies `committees.members.size` into `state.members.size`,
`committees.committees.size` into `state.committees.size`, etc. Same for
`apply_bitcoin_state` and its four nested bag headers. Container header
updates fall out for free.

### Classification rules

Given one `ObjectUpdate`, the per-checkpoint `ObjectIndex`, and `&Routing`:

| Update                                                                                                                                       | Match against              | Becomes                               |
| -------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ------------------------------------- |
| Written, `id == routing.hashi_id`                                                                                                            | direct id match            | `HashiRoot`                           |
| Written, `id == routing.bitcoin_state_field_id`                                                                                              | direct id match            | `BitcoinState`                        |
| Written, type is `Field<Wrapper<…>, ID>`, owner is `Object(p)`, `p` in `dof_parents`                                                         | direct owner match         | `DofWrapperWrite`                     |
| Written, type is `Field<…, …>`, owner is `Object(p)`, `p` in `df_parents`                                                                    | direct owner match         | `DfWrite`                             |
| Written, owner is `Object(w)`, `w` in `dof_wrappers` OR `ObjectIndex[w]` decodes as `Field<Wrapper<…>, ID>` whose owner is in `dof_parents`  | cache or lookup            | `DofValueWrite`                       |
| Deleted, `id == hashi_id` or `bitcoin_state_field_id`                                                                                        | direct id match            | catastrophic — surface a hard error   |
| Deleted, type is `Field<Wrapper<…>, ID>`, `prior_owner = Object(p)`, `p` in `dof_parents`                                                    | direct owner               | `DofWrapperDelete`                    |
| Deleted, type is `Field<…, …>`, `prior_owner = Object(p)`, `p` in `df_parents`                                                               | direct owner               | `DfDelete`                            |
| Deleted, `prior_owner = Object(w)`, `w` in `dof_wrappers` OR input-version `ObjectIndex[w]` decodes as a wrapper whose owner is in `dof_parents` | cache or lookup        | `DofValueDelete`                      |
| Anything else                                                                                                                                | —                          | `Ignored`                             |

The `ObjectIndex` is `BTreeMap<Address, &Object>` built once per
checkpoint from `Checkpoint.objects.objects`. Because `Checkpoint.objects`
includes input objects (including unchanged loaded runtime objects), the
wrapper is always available even for pure Value mutations.

The `dof_wrappers` cache is checked first for speed; the `ObjectIndex`
lookup is the authoritative fallback. On every wrapper write/delete the
cache is updated, so subsequent checkpoints can hit the fast path.

### Per-checkpoint algorithm

```text
build object_index: BTreeMap<Address, &Object> from Checkpoint.objects.objects

for each tx in checkpoint.transactions:
    if not tx.effects.status.success: continue

    for each co in tx.effects.changed_objects:
        let update = ObjectUpdate::from(co, &object_index);
        let class = classify(&update, &object_index, &routing);
        apply(&mut state, &mut routing, class)?;

    for each event in tx.events.events:
        // Notifications only. Not state mutation.
        emit_notification(event);

update latest_checkpoint_info(seq, timestamp, epoch).
update metrics.
```

Single pass — wrappers and values within one tx no longer need ordered
processing because routing for DOF values comes from `object_index`, not
from the persistent cache.

### Why this fixes the bug class

Walk the scenarios:

- **`reassign_presigs_for_withdrawal_txn` (the active bug).** The
  `WithdrawalTransaction` Value object is rewritten with no event.
  - `changed_objects` includes the Value with `owner = Object(wrapper_id)`.
  - Classifier hits `dof_wrappers[wrapper_id] -> WithdrawalTxns` (or
    falls back to the `ObjectIndex` wrapper lookup).
  - `apply_dof_value` replaces the entry from fresh contents. Bug fixed.

- **`committee::add_committee` (Bag.size 17 -> 18).** Hashi root is
  rewritten because `committees.committees.size` is a field of `Hashi`.
  A new `Field<u64, Committee>` is also written.
  - Hashi root -> `apply_hashi_root` refreshes
    `state.committees.size = 18`.
  - Field -> `apply_df_entry` inserts the new committee.

- **`withdraw::pick_for_processing` (new DOF entry).** Both wrapper and
  Value are CREATED in the same tx. BitcoinState is rewritten.
  - BitcoinState -> `apply_bitcoin_state` refreshes
    `state.withdrawal_requests.size` and `state.withdrawal_txns.size`.
  - Wrapper CREATED -> `apply_dof_wrapper_write`, updates routing cache.
  - Value CREATED -> `apply_dof_value`. Routes via the wrapper (either
    cache or `ObjectIndex`) regardless of intra-tx ordering.

- **`update_config` proposal executes.** Hashi root is rewritten with a
  new `config` field.
  - Hashi root -> `apply_hashi_root` re-projects `state.config`. No more
    bespoke `scrape_hashi_config` follow-up.

- **`withdraw::confirm_withdrawal` (DOF delete).** Wrapper and Value are
  both DELETED.
  - Wrapper DELETED -> `apply_dof_wrapper_delete`. Removes the entry
    from the slot and clears the routing cache.
  - Value DELETED -> classification routes through the prior_owner; if
    the cache was already cleared, `ObjectIndex` (which carries the
    input version of the wrapper) still resolves it.

In every case the unit of work is "object update" and dispatch is uniform.

### Where enrichment happens

Each `apply_*` function deserializes raw BCS into `MoveObject<RawT>` and
projects into the slot's enriched type. Projection lives in free
functions per slot, not in a trait:

```rust
fn project_member_info(raw: &MoveObject<move_types::MemberInfo>) -> Result<MemberInfoProjection> { ... }
```

Some slots project at apply time (small per-row work — `MemberInfo`,
`Committee`). Some keep raw and project lazily on read
(`WithdrawalTransaction` is useful as-is). The choice is per-slot and
can be tuned without touching the apply framework.

### Subscription read mask

```text
Checkpoint.sequence_number
Checkpoint.summary.timestamp
Checkpoint.summary.epoch
Checkpoint.transactions.digest
Checkpoint.transactions.effects.status
Checkpoint.transactions.effects.changed_objects.object_id
Checkpoint.transactions.effects.changed_objects.object_type
Checkpoint.transactions.effects.changed_objects.input_owner
Checkpoint.transactions.effects.changed_objects.output_owner
Checkpoint.transactions.effects.changed_objects.output_version
Checkpoint.transactions.effects.changed_objects.id_operation
Checkpoint.transactions.events.events.contents
Checkpoint.objects.objects.object_id
Checkpoint.objects.objects.version
Checkpoint.objects.objects.owner
Checkpoint.objects.objects.object_type
Checkpoint.objects.objects.contents
```

### Scrape and bootstrap

Initial scrape stays similar to today's `scrape_hashi`:

1. `get_object(hashi_id)` for the root.
2. Derive the `BitcoinStateField` id via `derive_dynamic_child_id` and
   `get_object` it.
3. For each Bag/ObjectBag parent uncovered in the root contents, run
   `Bag::scrape` / `ObjectBag::scrape` (one helper per kind, parameterized
   on the parent id and entry projection).
4. Populate `Routing` with `df_parents`, `dof_parents`, and a fully
   populated `dof_wrappers` cache.

On subscription drop the existing rescrape-on-resubscribe behavior stays
as a backstop.

## Commit plan

Each step is one PR; each PR builds and passes tests on its own.

### Step 1 — `MoveStruct` trait and `MoveObject<T>` envelope

- Land `MoveStruct` and `MoveObject<T>` in `hashi-types`.
- Implement `try_from_object` and `from_object`.
- Delete the two duplicated `MoveType` traits, migrate event impls to
  `MoveStruct`.
- No behavior change.

### Step 2 — Raw container types

- Land `RawDynamicField`, `RawDynamicObjectField`, `RawObject`, `RawValue`.
- Land `Bag`, `ObjectBag`, `Table<K, V>`, `ObjectTable<K, T>`,
  `LinkedTable<K, V>`.
- Add `Bag::scrape` and `ObjectBag::scrape` helpers (heterogeneous-first).
- No call-site changes.

### Step 3 — Migrate one scrape helper

- Replace `scrape_all_member_info` with `Bag::scrape` + typed projection.
- Members is the smallest, simplest Bag — safe first migration.
- No watcher change.

### Step 4 — Introduce `OnchainMirror`, `HashiState` skeleton, `Routing`

- Land the new mirror skeleton next to the existing
  `crate::onchain::types::Hashi`.
- Populate it from a parallel scrape (running alongside the existing
  scrape) and compare results in tests / staging.
- Routing is populated, including `dof_wrappers`, but unused.

### Step 5 — `ObjectUpdate`, `Classification`, `apply` framework + shadow path

- Land the classifier and apply functions.
- Widen the watcher's `read_mask` to include `changed_objects` and
  `Checkpoint.objects`.
- Process every checkpoint twice — events-driven (existing) into the
  live state, and object-driven into a *shadow* `HashiState`. Emit
  metrics on divergence between the two.
- Production state stays on the event-driven path.

### Step 6 — Per-slot cutover

Switch slots from event-driven to object-driven one at a time. Each
cutover deletes one branch of `handle_events` and one bespoke `fetch_*`
helper.

Order (active bug first, then by surface area):

1. `withdrawal_txns` — fixes the load-test bug.
2. `withdrawal_requests`, `deposit_requests`.
3. `utxo_records`, `spent_utxos`.
4. `committees`, `members`.
5. `treasury`, `proposals_active`, `proposals_executed`, `tob`.
6. Hashi root (`config`, `num_consumed_presigs`), `BitcoinState`.

### Step 7 — Cleanup

- Delete the layer-2 re-exports in `hashi/src/onchain/types.rs` that
  were pure renames.
- Delete the shadow path.
- Drop dead bespoke helpers (`fetch_withdrawal_txn`,
  `fetch_treasury_cap`, `scrape_member_info`, `scrape_committee`,
  `scrape_hashi_config`).

## Tradeoffs

- **Bandwidth.** Widening the read mask to include
  `Checkpoint.objects.contents` scales with total checkpoint write
  volume, not hashi-package activity. Acceptable until the filtered
  subscription API exists. The `bcs` representation is more compact
  than JSON.
- **Routing memory.** O(total DOF entries) for `dof_wrappers`. Hashi's
  hot bags currently sit in the low thousands. Negligible.
- **Subscription gap robustness.** Because routing for DOF values can
  be rebuilt from `Checkpoint.objects` alone, the persistent
  `dof_wrappers` cache being stale doesn't cause incorrect
  classification — only a slow path lookup. Periodic reconciliation
  (list DF children of known parents) is no longer strictly required
  for correctness.
- **Storage cost of raw heterogeneous entries.** `Bag`/`ObjectBag` carry
  every entry as raw BCS plus type tags. For Hashi's current sizes this
  is fine; if it ever becomes a concern, the typed projection layer
  can cache projections alongside the raw entries.
- **Generics density.** `MoveObject<T>` + the typed container generics
  produce a few generic-heavy signatures. Worth it to delete the per-bag
  scrape/fetch dance.

## Open questions deferred

- **Raw vs projected per slot.** Some slots want both (committees need
  raw `move_types::Committee` for BCS-signed messages plus enriched
  parsed BLS keys for runtime); others only enriched; a few only raw.
  Decide per slot during step 6.
- **Failure modes.** Whether to hard-fail on classifier "ignored but
  should-have-routed" or just log + metric. Start with log + metric
  during the shadow phase; escalate after confidence.
- **Future filtered subscription.** When the Sui side ships a filtered
  `subscribe_changed_objects(filter)`, only the subscription wrapper
  changes; downstream code already works in terms of `ObjectUpdate`.
