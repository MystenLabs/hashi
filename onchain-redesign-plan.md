# Onchain mirror redesign

## Motivation

The withdrawal-stuck bug from the recent load test traces to a single root
cause: `reassign_presigs_for_withdrawal_txn` mutates on-chain state without
an `event::emit`, so the watcher's local mirror never sees the update. The
leader keeps reading a stale `txn.epoch`, retries `reassign` every iteration,
and never falls through to MPC signing.

This is a class of bug, not a one-off. The watcher's correctness depends on
every Move state mutation either (a) emitting an event with enough payload
to reconstruct the new state or (b) being followed up by bespoke code that
re-reads chain state. Any future Move code path that mutates an object
without an event re-introduces the bug.

The redesign shifts the canonical signal of "state changed" from events to
`TransactionEffects.changed_objects` and `Checkpoint.objects`. Events stay,
but only as hints driving notifications — not as the source of truth for
mirrored state.

## Current architecture (what we're replacing)

Three layers exist today:

1. **`hashi-types/src/move_types/mod.rs`** — BCS-shaped Rust mirrors of
   Move structs. `serde_derive::Deserialize` for each struct in BCS field
   order. A `MoveType` trait carries `MODULE` and `NAME`, used only by
   events. No object metadata (version, owner) is captured. Generic
   containers (`Bag`, `Field<N,V>`, `LinkedTable<K>`) are modeled only as
   their on-chain headers — `Bag { id, size }` says "go look up dynamic
   fields under `id` yourself."

2. **`hashi/src/onchain/types.rs`** — enriched mirror with mixed
   responsibilities. Some types are pure re-exports of layer 1. Others
   wrap layer 1 with semantic enrichment (BLS key parsing, encryption-key
   parsing, `TypeTag` dispatch for treasury entries / proposals, `Config`
   flattening). Bag-backed maps are flattened into Rust `BTreeMap`s with
   no record of the underlying field IDs or versions. A second `MoveType`
   trait is defined in this crate, duplicating the one in `hashi-types`.

3. **`hashi/src/onchain/mod.rs` + `watcher.rs`** — scrape and event-driven
   mirror. `scrape_hashi` does one `get_object` on the root, then fans
   out `list_dynamic_fields` per Bag to pre-warm every container. The
   watcher subscribes to checkpoints, reads only events, and applies
   per-event mutations directly to the layer-2 maps. Whenever an event
   can't reconstruct state on its own
   (`WithdrawalPickedForProcessingEvent`, `StartReconfigEvent`, mint/burn,
   etc.) it does a bespoke one-off RPC: `fetch_withdrawal_txn`,
   `scrape_committee`, `fetch_treasury_cap`, `scrape_member_info`,
   `scrape_hashi_config`.

The duplicated `MoveType` trait is a smaller symptom of the same problem:
the type system knows what a BCS payload looks like but not what an
object *is*.

## Key facts that inform the redesign

### DOF (dynamic object field) memory layout

From `sui-framework/sources/dynamic_object_field.move:257-306` a DOF is
*two* on-chain objects:

1. A wrapper `Field<Wrapper<Name>, ID>` parented to the outer UID. Its
   address is
   `derive_dynamic_child_id(parent_uid, type_tag_of(Wrapper<Name>), bcs(name))`.

2. The actual `Value` object, parented to the wrapper field's address
   via `add_child_object(field.to_address(), value)`.

When the Value mutates, only the Value appears in `changed_objects`
with `output_owner = Object(wrapper_id)`. The wrapper itself is
unchanged. The wrapper *does* appear in `changed_objects` (with
`id_operation = CREATED` or `DELETED`) on add or remove.

### Regular DF (no DOF)

`Field<Name, Value>` is parented to the outer UID. The value lives inside
the Field object, so a value mutation rewrites the Field object itself —
`output_owner = Object(parent_uid)`. No intermediate hop.

### `Checkpoint.objects` includes unchanged loaded runtime objects

From `sui-types/storage/read_store.rs:233-256`, `Checkpoint.object_set`
is built from
`get_transaction_object_set(transaction, effects, unchanged_loaded_runtime_objects)`.
So the deduped object set in `Checkpoint.objects` always contains the
DOF wrapper Field even when only the Value was mutated, because the
wrapper was loaded as a runtime input to access the Value.

The consequence: routing for DOF Value mutations can be resolved from
`Checkpoint.objects` alone, with no persistent wrapper cache required.
For a Value with `output_owner = Object(addr)`, look `addr` up in
`Checkpoint.objects`, decode it as `Field<Wrapper<…>, ID>`, and walk
up from there to confirm it belongs to a container we track.

### `Checkpoint.objects` and `subscribe_checkpoints`

`Checkpoint.objects` is a deduped `ObjectSet` (proto field 7 of
`Checkpoint`) and is mask-selectable in
`SubscribeCheckpointsRequest.read_mask`. When populated,
`transactions[].objects` is omitted per the proto comment. One read
mask covers it; no follow-up `BatchGetObjects` is needed per checkpoint.

### Inner UIDs

A Move object's identity is not just its `ObjectId`. An object's
contents may hold container fields — `Bag`, `Table`, `ObjectBag`,
`LinkedTable`, etc. — each of which carries its own UID. Children of
those inner UIDs are logically descendants of the outer object. The
mirror must track these to walk ownership transitively.

Example: `Hashi` (one object) holds `Bag` members, committees, tob, and
ObjectBag treasury/proposals — six inner UIDs. `BitcoinState` (one DF
object) holds nine inner UIDs across deposit/withdrawal/UTXO queues.
`EpochCertsV1` holds a `LinkedTable.id`, whose children are dealer
submission nodes.

### Heterogeneous bags

`bag.move` and `object_bag.move` make no requirement that all entries
share a K/V type. Hashi's bags happen to be homogeneous today but the
design keeps raw storage tolerant of unknown types so an unrecognized
entry doesn't drop mirror coverage. Tables and ObjectTables are
homogeneous by construction.

### `Owner` in proto

From `sui/rpc/v2/owner.proto`, `Owner` has a `kind` enum
(`ADDRESS`/`OBJECT`/`SHARED`/`IMMUTABLE`/`CONSENSUS_ADDRESS`), an
`address` string, and a `version` for shared objects. `output_owner`
and `input_owner` carry it inside `ChangedObject`.

## Design

The new mirror is an ECS-style object pool: every Move object we
recognize is stored by id, with secondary indices for owner and type.
Each stored value advertises the inner UIDs it contains. The unit of
update is a per-transaction tree assembled from `Checkpoint.objects`;
applying it is a structural walk where each tree position has a
statically known type.

### Layers

The framework piece is project-agnostic. To start it lives as a new
module under `hashi-types` (`hashi-types::mirror`) — same crate, but
walled off from anything domain-specific so it can be lifted into its
own crate later without changes. It contains:

- `MoveStruct` trait and `MoveObject<T>` envelope.
- Raw container types: `Bag`, `ObjectBag`, `Table`, `ObjectTable`,
  `LinkedTable`, plus their scrape helpers.
- `MoveObjectKind` trait (with `inner_uids`).
- `ObjectPool` with the entity map and indices (`by_owner`, `by_type`,
  `inner_uid_owner`).
- `TxTree` and `SubtreeView`.
- A small set of pool helpers (`apply_typed`, `containing_object`,
  `uid_set_for`) that handlers compose into typed apply steps.

Hashi's binding (in the `hashi` crate) is thin:

- `MoveObjectKind` impls (including `inner_uids`) for the Move structs
  Hashi mirrors.
- A `HashiMirror` that owns the pool and a `apply_tx` method which is
  Hashi's structural walk.
- Typed accessors (`withdrawal_txn`, `member_info`, ...) replacing the
  current `types::*` containers.

### `MoveStruct` and `MoveObject<T>`

Replace both `MoveType` traits (one in `hashi-types`, one in
`hashi/src/onchain/mod.rs`) with one trait in the framework:

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

Package-version gating is a caller concern, not part of the envelope.

### Raw container types

`Bag` and `ObjectBag` differ in on-chain layout; same for `Table` vs
`ObjectTable`. Each raw type matches its Move shape exactly.

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
    pub owner: Owner,
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

`Bag` and `ObjectBag` keep entries in raw form so unknown types don't
get dropped. The typed variants are useful for the initial scrape of
known-shape containers.

### `MoveObjectKind` and the object pool

```rust
/// Anything that can live in the pool. Blanket-implemented over any
/// 'static type, so concrete domain types implement it for free.
pub trait MoveObjectKind: std::any::Any + Send + Sync + std::fmt::Debug + 'static {
    fn as_any(&self) -> &dyn std::any::Any;

    /// UIDs this object holds inside its contents — Bag.id, Table.id,
    /// ObjectBag.id, LinkedTable.id, anything that owns children.
    /// Default: empty (a leaf with no inner storage).
    fn inner_uids(&self) -> Vec<Address> { Vec::new() }
}

pub struct ObjectMeta {
    pub id: Address,
    pub version: u64,
    pub type_: StructTag,
    pub owner: Owner,
}

pub struct PooledObject {
    pub meta: ObjectMeta,
    pub value: Box<dyn MoveObjectKind>,
}

pub struct ObjectPool {
    objects: BTreeMap<Address, PooledObject>,
    by_owner: BTreeMap<Address, BTreeSet<Address>>,
    by_type: BTreeMap<StructTag, BTreeSet<Address>>,
    /// Reverse map: inner UID -> the object id whose contents hold it.
    /// Maintained on every upsert / remove. This is what makes
    /// "transitively part of my tree" answerable without a project-side
    /// parent cache.
    inner_uid_owner: BTreeMap<Address, Address>,
}

impl ObjectPool {
    pub fn get<T: MoveObjectKind>(&self, id: &Address) -> Option<&T>;
    pub fn meta(&self, id: &Address) -> Option<&ObjectMeta>;
    pub fn iter_owned_by<T: MoveObjectKind>(&self, parent: &Address) -> impl Iterator<Item = (&Address, &T)>;
    pub fn iter_by_type<T: MoveObjectKind>(&self) -> impl Iterator<Item = (&Address, &T)>;

    pub fn upsert<T: MoveObjectKind>(&mut self, meta: ObjectMeta, value: T);
    pub fn remove(&mut self, id: &Address) -> Option<PooledObject>;

    /// Generic helper: decode `obj.after` as MoveObject<T>, upsert into
    /// the pool; or remove on delete. Handlers call this directly.
    pub fn apply_typed<T>(&mut self, obj: &TxObject) -> Result<()>
    where T: MoveStruct + 'static;

    /// Walk up the ownership chain: given a UID an Owner::Object(...)
    /// might point at, return the pooled object id that contains it.
    /// Handles "owner is a Bag's UID" and arbitrary nesting depth.
    pub fn containing_object(&self, uid: &Address) -> Option<Address> {
        if self.objects.contains_key(uid) { return Some(*uid); }
        self.inner_uid_owner.get(uid).copied()
    }

    /// All UIDs that belong to this object: its own id plus inner UIDs.
    pub fn uid_set_for(&self, id: &Address) -> impl Iterator<Item = Address> + '_;
}
```

`upsert` maintains the four indices; in particular, when replacing an
existing entry it retires the old object's inner UIDs from
`inner_uid_owner` before registering the new ones. The pool asserts
that a newly-registered inner UID isn't already mapped to a different
owner — that would indicate a Move-level invariant violation worth
surfacing loudly.

### Per-tx tree

```rust
pub enum TxObject {
    Written  { before: Option<RawObject>, after: RawObject },
    Deleted  { before: RawObject },
    Loaded   { object: RawObject },   // unchanged loaded runtime input
}

pub struct TxTree {
    objects: BTreeMap<Address, TxObject>,
    /// Owner index: parent_addr -> direct children ids. Built from
    /// the union of pre-owner and post-owner (so a move from parent A
    /// to parent B shows the value under both, with the slot's apply
    /// disambiguating via `(was_mine, is_mine)`).
    children_before: BTreeMap<Address, BTreeSet<Address>>,
    children_after:  BTreeMap<Address, BTreeSet<Address>>,
}

impl TxTree {
    pub fn build(tx: &ExecutedTransaction, idx: &CheckpointObjectIndex) -> Self;
    pub fn at(&self, root: Address) -> SubtreeView<'_>;
    pub fn object(&self, id: &Address) -> Option<&TxObject>;
}

pub struct SubtreeView<'a> {
    tree: &'a TxTree,
    root: Address,
}

impl<'a> SubtreeView<'a> {
    pub fn root(&self) -> Option<&'a TxObject>;
    /// Union of children-before and children-after. The caller
    /// distinguishes via the contained TxObject.
    pub fn direct_children(&self) -> impl Iterator<Item = (Address, &'a TxObject)>;
    pub fn descendants(&self) -> impl Iterator<Item = (Address, &'a TxObject)>;
}
```

Build is pure data assembly: union the input/output versions of every
`changed_object` plus every `unchanged_loaded_runtime_object`, look each
up in `Checkpoint.objects.objects` by `(id, version)`, attach. No
classification logic in the tree.

### Apply: project-specific structural walk

The framework does *not* dispatch types. Each tree position has a
statically known expected type, and the project's handler decodes
inline. For Hashi:

```rust
impl HashiMirror {
    fn apply_tx(&mut self, tree: &TxTree) -> Result<()> {
        // Roots: known ids, known types.
        if let Some(obj) = tree.object(&self.hashi_id) {
            self.pool.apply_typed::<move_types::Hashi>(obj)?;
        }
        // The BitcoinState DF id is derivable from hashi_id at startup.
        if let Some(obj) = tree.object(&self.bitcoin_state_field_id) {
            self.pool.apply_typed::<BitcoinStateField>(obj)?;
        }

        // Bag children: each parent's children are Field<K, V> objects
        // with K and V known by position.
        if let Some(p) = self.members_bag_id() {
            for (_, obj) in tree.direct_children_of(p) {
                self.pool.apply_typed::<move_types::Field<Address, move_types::MemberInfo>>(obj)?;
            }
        }
        if let Some(p) = self.committees_bag_id() {
            for (_, obj) in tree.direct_children_of(p) {
                self.pool.apply_typed::<move_types::Field<u64, move_types::Committee>>(obj)?;
            }
        }
        if let Some(p) = self.utxo_records_bag_id() {
            for (_, obj) in tree.direct_children_of(p) {
                self.pool.apply_typed::<move_types::Field<UtxoId, move_types::UtxoRecord>>(obj)?;
            }
        }
        // ... spent_utxos, tob, etc.

        // ObjectBag children: direct children are DOF wrappers, the
        // actual values live one level deeper.
        if let Some(p) = self.withdrawal_txns_bag_id() {
            for (wrapper_id, wrapper_obj) in tree.direct_children_of(p) {
                self.pool.apply_typed::<DofWrapper<Address>>(wrapper_obj)?;
                let value_id = wrapper_value_id(wrapper_obj);
                if let Some(value_obj) = tree.object(&value_id) {
                    self.pool.apply_typed::<move_types::WithdrawalTransaction>(value_obj)?;
                }
            }
        }
        // ... deposit_requests, withdrawal_requests, treasury, proposals.

        Ok(())
    }

    /// Bag IDs are inner UIDs of the Hashi root and BitcoinState DF.
    /// Recompute on demand from current pool state — cheap, no cache.
    fn members_bag_id(&self) -> Option<Address> {
        Some(self.pool.get::<MoveObject<move_types::Hashi>>(&self.hashi_id)?
            .value.committees.members.id)
    }
    // ... committees_bag_id, withdrawal_txns_bag_id, etc.
}
```

Each handler statically knows the type. Compile-time errors if a Move
struct's BCS layout drifts. No registry, no first-match-wins ordering
hazard, no per-position `Option<Box<dyn …>>` cascade.

Relevance falls out of the walk: the handler only visits positions it
cares about, so anything else in the tx tree (gas coins, system objects,
unrelated packages) is invisible to the mirror.

### Why this fixes the bug class

- **`reassign_presigs_for_withdrawal_txn` (the active bug).** The
  `WithdrawalTransaction` Value is rewritten with no event.
  `changed_objects` carries the Value with
  `output_owner = Object(wrapper_id)`. The walk visits the
  withdrawal_txns bag, iterates its direct children, decodes the wrapper
  (which is in the tree as either changed or unchanged-loaded), and
  finds the Value object id from the wrapper's contents. The Value is
  upserted from fresh BCS. Bug fixed.

- **`committee::add_committee` (Bag.size 17 → 18).** Hashi root is
  rewritten because `committees.committees.size` is a field of `Hashi`.
  A new `Field<u64, Committee>` is also written. The root's
  `apply_typed::<move_types::Hashi>` refreshes the root entry; the new
  Field's `apply_typed::<…>` inserts the committee. `members_bag_id()`
  and friends remain valid because they're computed from the pool's
  current root contents.

- **`withdraw::pick_for_processing` (new DOF entry).** Both wrapper and
  Value are CREATED in the same tx; BitcoinState is rewritten. The walk
  applies BitcoinState (updates the Hashi descendant), iterates the
  withdrawal_txns bag's direct children (the new wrapper), decodes the
  wrapper, looks up and decodes the value. The events emitted by this
  tx still drive notifications, but no longer drive state.

- **`update_config` proposal executes.** Hashi root is rewritten with a
  new `config` field. Root apply refreshes the entry. No bespoke
  `scrape_hashi_config` follow-up.

- **`withdraw::confirm_withdrawal` (DOF delete).** Wrapper and Value
  are both DELETED. The walk sees both, removes both. The wrapper's
  prior contents (`before`) is still in the tx tree because
  `Checkpoint.objects` carries pre-deletion input state.

In every case, the unit of work is "object update at known tree
position" and dispatch is by walk structure, not by event payload.

### Move semantics (object changes owner)

If an object V moves from owner A to owner B (e.g., a DOF transferred
between two ObjectBags), the tx looks like:

- Wrapper W1 deleted under A.
- Wrapper W2 created under B.
- V: `before.owner = Object(W1)`, `after.owner = Object(W2)`. Contents
  may or may not change.

The tx tree's owner index is the **union** of before-owner and
after-owner edges. The walk visits A's subtree (sees W1 deleted, finds
V via W1, removes the V entry from the pool — actually, more precisely:
removes W1, and the V removal arrives via the W2-path delete-rewrite
distinction); visits B's subtree (sees W2 created, finds V via W2,
upserts V). Since `ObjectPool` is keyed by id and not by slot, V's pool
entry simply gets its `owner` field updated.

This handles the simple move case for free. For the harder case — a
moved object that has child objects via inner UIDs — the children's
owners point at V's id (or V's inner UIDs), which are stable, so the
children stay in place in the pool and are still reachable from B's
subtree through the same `containing_object` lookups. The pool doesn't
need to rewrite anything for the children.

We add a move-detection metric for observability: if a single tx
removes and adds entries with the same value id across different
parent subtrees, increment `hashi_object_relocated_total{from, to}`.
For hashi today this should be 0; any non-zero is a real signal.

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
Checkpoint.transactions.effects.changed_objects.input_version
Checkpoint.transactions.effects.changed_objects.output_version
Checkpoint.transactions.effects.changed_objects.id_operation
Checkpoint.transactions.effects.unchanged_loaded_runtime_objects
Checkpoint.transactions.events.events.contents
Checkpoint.objects.objects.object_id
Checkpoint.objects.objects.version
Checkpoint.objects.objects.owner
Checkpoint.objects.objects.object_type
Checkpoint.objects.objects.contents
```

### Scrape and bootstrap

Initial scrape stays similar in shape to today's `scrape_hashi`, but
populates the pool directly:

1. `get_object(hashi_id)`. Construct `MoveObject<move_types::Hashi>`,
   `pool.upsert`. Its inner UIDs are now in `inner_uid_owner`.
2. Derive the BitcoinState DF id via `derive_dynamic_child_id` and
   `get_object` it. Upsert as `MoveObject<BitcoinStateField>`.
3. For each Bag/ObjectBag inner UID in the now-pooled root and
   BitcoinState, run `Bag::scrape` or `ObjectBag::scrape` and upsert
   each child entry. For ObjectBags, the scrape produces both the
   wrapper and the value object per entry; both get upserted.
4. For nested LinkedTables (e.g., `tob`'s `EpochCertsV1.certs`), repeat
   per entry as needed.

After scrape the pool contains every hashi-relevant object indexed by
id, owner, type, and inner-UID containment. Reads work immediately.

On subscription drop the existing rescrape-on-resubscribe behavior
stays as a backstop.

## Commit plan

Each step is one PR; each PR builds and passes tests on its own.

### Step 1 — Land the framework as a `hashi-types::mirror` module

The foundation the rest of the plan builds on. Lands the entire
project-agnostic framework in one new module under `hashi-types`,
plus replaces the two duplicate `MoveType` traits and migrates event
impls. No call-site changes to scrape or watcher.

Module layout:

```
hashi-types/src/mirror/
  mod.rs            -- pub use's and module docs
  move_struct.rs    -- MoveStruct trait, MoveObject<T>
  raw.rs            -- RawObject, RawValue, RawDynamicField,
                       RawDynamicObjectField
  containers.rs     -- Bag, ObjectBag, Table, ObjectTable,
                       LinkedTable, with scrape helpers
  pool.rs           -- MoveObjectKind trait, ObjectMeta,
                       PooledObject, ObjectPool
  tx_tree.rs        -- TxObject, TxTree, SubtreeView,
                       CheckpointObjectIndex
```

Contents:

- `MoveStruct` trait with `try_from_object` / `from_object`.
  `MoveObject<T>` envelope.
- Raw container types and typed `Bag::scrape` / `ObjectBag::scrape` /
  `Table::scrape` / `ObjectTable::scrape` / `LinkedTable::scrape`.
- `MoveObjectKind` trait with `as_any` and `inner_uids`. Blanket impl
  over any `'static + Send + Sync + Debug`.
- `ObjectMeta`, `PooledObject`, and `ObjectPool` with the four
  indices (`objects`, `by_owner`, `by_type`, `inner_uid_owner`).
  Methods: `get<T>`, `meta`, `iter_owned_by<T>`, `iter_by_type<T>`,
  `upsert<T>`, `remove`, `containing_object`, `uid_set_for`,
  `apply_typed<T>`.
- `TxObject`, `TxTree` with `build`, `at`, `object`. `SubtreeView`
  with `direct_children`, `descendants`. `CheckpointObjectIndex` for
  the `(id, version) -> Object` lookup.
- Delete `hashi_types::move_types::MoveType` and
  `hashi::onchain::MoveType`; migrate all event impls to
  `MoveStruct`.

Acceptance: the module is fully exercised by unit tests — pool index
invariants (especially inner-UID upsert/remove and conflict assert),
move-edge `containing_object` lookup, scrape against a synthesized
object set, BCS roundtrip of `MoveObject<T>` for each container kind.
The framework module references no Hashi domain types.

Sub-PRs are fine if a single PR is too large; the natural split is
(a) `MoveStruct` + `MoveObject<T>` + duplicate-trait removal, then
(b) raw containers + scrape, then (c) `MoveObjectKind` + `ObjectPool`
+ `TxTree`. The plan tracks them as one step because they form one
coherent foundation.

### Step 2 — Migrate one scrape helper

- Replace `scrape_all_member_info` with `Bag::scrape` + typed projection.
- Smallest, simplest container — first end-to-end exercise of the
  typed scrape API against real data.
- No watcher change.

### Step 3 — Hashi binding on top of the framework

- Add a `HashiMirror` struct in `hashi/src/onchain/`: owns an
  `ObjectPool` (from `hashi_types::mirror`), the well-known
  `hashi_id`, and the derived `bitcoin_state_field_id`.
- Implement `MoveObjectKind` for every Hashi Move type the mirror
  stores (`MoveObject<move_types::Hashi>`, `MoveObject<BitcoinStateField>`,
  `MoveObject<move_types::Field<Address, move_types::MemberInfo>>`,
  `MoveObject<DofWrapper<Address>>`,
  `MoveObject<move_types::WithdrawalTransaction>`, etc.). Provide
  `inner_uids` for the types that contain inner UIDs (Hashi root,
  BitcoinState DF, `EpochCertsV1`).
- Replace the existing `scrape_hashi` body with a version that
  populates `HashiMirror` via `Bag::scrape` / `ObjectBag::scrape` and
  `pool.upsert`. Old `crate::onchain::types::*` containers stay
  untouched alongside.
- Land typed accessor methods on `HashiMirror`
  (`withdrawal_txn(id)`, `member_info(validator)`, etc.) that return
  the same shapes consumers expect today.
- Watcher is unchanged; the new mirror is parallel state, not yet
  load-bearing.

Acceptance: scraping a fixture environment yields identical results
between the new pool-backed accessors and the existing `types::*`
view. No production read path uses the pool yet.

### Step 4 — Shadow apply path

- Widen the watcher's `SubscribeCheckpointsRequest.read_mask` to the
  fields listed in "Subscription read mask" above.
- Per tx, build a `TxTree` from `changed_objects +
  unchanged_loaded_runtime_objects + Checkpoint.objects`.
- Call `HashiMirror::apply_tx(&tree)` against a *shadow* mirror that
  exists alongside the live event-driven state.
- Emit metrics on divergence between the shadow pool's view and the
  live state for each key bag (member count, committee map, withdrawal
  txns, deposit/withdrawal requests, utxo records, treasury, proposals,
  config, num_consumed_presigs). Add the
  `hashi_object_relocated_total{from, to}` move-detection metric here
  too.
- Production state still goes through `handle_events`.

Acceptance: running locally and in staging shows zero divergence
across a representative workload. Any divergence is investigated
before the cutover step.

### Step 5 — Per-slot cutover

Switch read paths from the old `types::*` containers to
`HashiMirror`'s accessors one slot at a time. Each cutover deletes the
matching event-driven mutation branch in `handle_events` and any
bespoke `fetch_*` / `scrape_*` helper it relied on. The shadow path
becomes the live path slot-by-slot.

Order (active bug first, then by surface area):

1. `withdrawal_txns` — fixes the load-test bug.
2. `withdrawal_requests`, `deposit_requests`.
3. `utxo_records`, `spent_utxos`.
4. `committees`, `members`.
5. `treasury`, `proposals_active`, `proposals_executed`, `tob`.
6. Hashi root fields (`config`, `num_consumed_presigs`),
   `BitcoinState` DF.

### Step 6 — Cleanup

- Delete `crate::onchain::types::{Hashi, CommitteeSet, Config,
  DepositRequestQueue, WithdrawalRequestQueue, UtxoPool, Proposals,
  Treasury, MemberInfo}` and their helpers.
- Delete the now-dead `fetch_withdrawal_txn`, `fetch_treasury_cap`,
  `scrape_member_info`, `scrape_committee`, `scrape_hashi_config`,
  `scrape_proposals`, `scrape_treasury`, `scrape_utxo_pool`, etc.
- Delete the shadow-comparison code.
- Final tightening: remove `OnchainState::rescrape` if no longer
  needed (the subscription-drop path may still want it as a backstop).

## Tradeoffs

- **Bandwidth.** Widening the read mask to include
  `Checkpoint.objects.contents` scales with total checkpoint write
  volume, not hashi-package activity. Acceptable until the filtered
  subscription API exists. The `bcs` representation is more compact
  than JSON.
- **Pool memory.** Each pooled object is the BCS-decoded value plus an
  `ObjectMeta`. For hashi's hot bags (low thousands of entries) this
  is bounded; well under a few MB total.
- **Downcast cost on reads.** One `TypeId` compare per typed lookup.
  Negligible at our access rates.
- **No exhaustive type match.** Trade-off for the open-set ECS shape.
  Mitigated by: (a) the structural walk uses concrete types at every
  position so compile-time errors catch missed BCS-layout updates;
  (b) a pool audit method that reports pooled objects of types no
  handler reads — easy to wire into a CI test.
- **Subscription gap robustness.** The structural walk is stateless
  per checkpoint (no persistent routing cache), so a missed event no
  longer poisons future state. Subscription-drop rescrape remains as
  a backstop.

## Open questions deferred

- **Raw vs projected per type.** Some Hashi types want both forms
  (committees need raw `move_types::Committee` for BCS-signed messages
  plus enriched parsed BLS keys for runtime); others only enriched
  (`MemberInfo`); a few only raw (`WithdrawalTransaction`). Decide per
  type during step 5. The pool accepts either: store the projection
  directly, or store the raw `MoveObject<RawT>` and project at the
  accessor.
- **Failure modes for divergence.** Whether to hard-fail on a shadow-
  vs-live mismatch during step 4 or just log + metric. Start with
  log + metric; escalate after a clean staging burn-in window.
- **Future filtered subscription.** When the Sui side ships a filtered
  `subscribe_changed_objects(filter)`, only the subscription wrapper
  changes; downstream code already works in terms of `TxTree` /
  `MoveObjectKind`.
- **Mirroring `tob`'s LinkedTable.** Today the dealer submissions are
  fetched on demand. With `inner_uids()` declaring the LinkedTable id
  on `EpochCertsV1`, mirroring is a one-handler addition in step 5 if
  we decide to. Defer the decision.
