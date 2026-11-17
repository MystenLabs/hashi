# Issue 1: `insert_pending` bypasses the spent-UTXO replay check

| | |
|---|---|
| **Severity** | Low. Requires an off-chain fault to trigger, with no permissionless path. |
| **Location** | `packages/hashi/sources/btc/utxo_pool.move:89`, compare `:68-70` |
| **Reviewed against** | `main` at `2656f2c5` |
| **Date** | 2026-09-17 |

## Summary

`insert_active` calls `assert_not_spent_or_active` (`:70`), which checks both
`utxo_records` and `spent_utxos` (`:105-111`). `insert_pending` (`:89`)
performs no such check. Its only protection is `Bag::add`, which rejects a
duplicate key in `utxo_records` and has no visibility into `spent_utxos`.

So once a UTXO has been spent and garbage collected by `cleanup_spent`
(`:146-155`), its outpoint can be re-inserted into `utxo_records` through
`insert_pending` with `spent_by = None`, making it selectable again. The
module header at `:7` states the opposite invariant: "so an already-spent
outpoint can never be re-inserted."

## Assumption

The off-chain leader signs a commitment whose `txid` field does not match the
Bitcoin transaction it actually builds and broadcasts, and the change outpoint
derived from that `txid` collides with an outpoint the bridge has already
spent. A stale or cached `txid` carried forward from a previous batch would
produce this.

Everything else in the sequence below is ordinary protocol operation.

## Why a wrong `txid` reaches the pool

Change output IDs are derived rather than observed. `build_change_utxos`
(`withdrawal_queue.move:779-788`) computes each change ID as
`(txid, withdrawal_outputs.length() + j)`, where `txid` arrives in the
committee-signed `WithdrawalCommitmentMessage`. Nothing on chain checks that
value against Bitcoin, and nothing checks it for uniqueness, so a wrong `txid`
is accepted on the committee's signature alone.

## Sequence

Write `(T, 1)` for the outpoint at vout 1 of Bitcoin transaction `T`, and
`W1`, `W2` for two withdrawal transactions.

**1. A deposit at `(T, 1)` is confirmed.** `confirm_deposit` calls
`insert_active` (`deposit.move:244`), which passes its replay check and adds
the record with `spent_by = None`.

**2. `W1` is committed selecting `(T, 1)` as an input.** `lock` sets
`spent_by = Some(W1)`. `W1` confirms on Bitcoin, spending `(T, 1)`, and
`confirm_withdrawal` runs `mark_spent` on it (`withdraw.move:303`).

**3. `cleanup_spent_utxos([(T, 1)])` runs.** The record is removed from
`utxo_records` and `(T, 1)` is written into `spent_utxos`
(`utxo_pool.move:146-155`). `(T, 1)` now exists only as a tombstone. This
entry point (`withdraw.move:396`) takes no certificate and is callable by
anyone.

Steps 1 through 3 are correct, normal operation. The tombstone's origin is
immaterial: an earlier withdrawal's change output that was later spent reaches
the same state.

**4. `W2` is committed.** Its inputs are genuinely available UTXOs, and the
transaction the committee builds and broadcasts hashes to some other txid.
Under the assumption, the commitment declares `txid = T`, and with one
withdrawal output `build_change_utxos` derives the change ID `(T, 1)`.

**5. `insert_pending((T, 1), W2)` succeeds.** `utxo_records` does not contain
`(T, 1)`, so `Bag::add` is satisfied. `spent_utxos` does contain it, but
`insert_pending` never reads that bag. A record is created with
`spent_by = None`. Had this gone through `insert_active`,
`assert_not_spent_or_active` would have aborted here with `EUtxoAlreadyUsed`.

**6. `W2` confirms on Bitcoin under its real txid.** `(T, 1)` is an output
`W2` creates rather than an input it consumes, so `W2`'s validity is
unaffected by `(T, 1)` having been spent at step 2. `confirm_withdrawal(W2)`
is legitimately certified, since `WithdrawalConfirmationMessage`
(`withdraw.move:84-86`) binds only `withdrawal_id` and never re-attests the
txid. `confirm_pending((T, 1))` clears `produced_by`, leaving the record
indistinguishable from a confirmed deposit output. `W2`'s real change output
was never banked.

## Impact

Coin selection can now pick `(T, 1)` for a later withdrawal.
`commit_withdrawal_tx` validates inputs only against Move state, so `get_utxo`
(`withdraw.move:143`) finds it, `lock` accepts it, and the fee arithmetic
counts its amount. The commitment succeeds and user hBTC is burned at
`withdraw.move:181` against a Bitcoin transaction whose input was already
spent at step 2.

That withdrawal cannot be unwound on chain:

- Committing sets each request's `withdrawal_txn_id` and drains its balance in
  the same step (`withdrawal_queue.move:376-377`). That link makes
  `is_request_processing` (`:426-435`) return true, so `cancel_withdrawal`
  refuses at the entry gate (`withdraw.move:459-462`) and again at
  `withdrawal_queue.move:395` with `ERequestNotCancellable`.
- There is no abandon or re-commit path for a `WithdrawalTransaction`.
  `remove_withdrawal_txn` exists at `withdrawal_queue.move:540` but has no
  callers.
- `lock` only ever writes `Some` to `spent_by`, so the batch's other real
  input UTXOs stay reserved permanently.
- No module outside `deposit.move` and `withdraw.move` can reach
  `utxo_pool_mut`.

Forcing that withdrawal to `Confirmed` to release the requests is worse.
Signature bytes are stored without cryptographic validation
(`mpc_signing.move:104-121` checks only lengths and indices), so the committee
can complete it, but `confirm_withdrawal` then runs `mark_spent` over every
input including the real ones. After `cleanup_spent`, those real UTXOs sit in
`spent_utxos`, so `lock` and `insert_active` both reject them permanently and
the BTC behind them becomes unreachable.

Separately, `cleanup_spent` (`:153`) calls `spent_utxos.add` with no
`contains` guard. Cleaning up `(T, 1)` a second time aborts, and because
`cleanup_spent_utxos` takes a vector, one such ID reverts the entire batch.

## Recommendation

Add the same guard `insert_active` already uses:

```move
public(package) fun insert_pending(self: &mut UtxoPool, utxo: Utxo, withdrawal_id: address) {
    let utxo_id = utxo.id();
    self.assert_not_spent_or_active(utxo_id);
    ...
```

This converts step 5 into a clean `EUtxoAlreadyUsed` abort, before any hBTC is
burned, leaving the committee free to re-sign a correct commitment. It costs
nothing in the cases where `Bag::add` already aborts. Consider also guarding
`spent_utxos.add` in `cleanup_spent` with a `contains` check so garbage
collection cannot wedge.

## Related observation

The broader exposure is that `txid` is committee-supplied, unvalidated, and
used to derive change outpoints. The assumption alone causes the bridge to
bank its change under an outpoint that does not exist and to lose track of the
real change output, whether or not it collides with `spent_utxos`. Binding
`txid` to the transaction the committee actually signs would close the general
case.

---

# Issue 2: Config proposals validate their entries at execution, not at proposal time

| | |
|---|---|
| **Severity** | Informational. A wasted governance cycle. No funds, state, or availability at risk. |
| **Location** | `packages/hashi/sources/core/proposal/types/update_config.move:43-62`, and the same pattern in `add_config.move` and `update_epoch_config.move` |
| **Reviewed against** | `main` at `2656f2c5` |
| **Date** | 2026-09-17 |

## Summary

`update_config::propose` (`:43-62`) validates only that the entry map is
non-empty (`:52`). Every substantive check runs in `execute` (`:64-75`):

- `config::is_governable_key(&key) && btc_config::is_governable_key(&key)`
  (`:68-71`), refusing the two keys the package pins for the deployment's
  lifetime.
- `hashi.config().is_valid_config_update(&key, &value)` (`:72`), requiring the
  key to exist and the value to match its stored variant.

So a proposal naming a pinned key, an unknown key, or the right key with the
wrong value type can be created, gather a full 6667-bps quorum
(`update_config.move:21`) over as much as seven days
(`proposal.move:19`), and only then abort.

`add_config.move` and `update_epoch_config.move` share the pattern: both check
only `!entries.is_empty()` at propose time and defer all key, type, and
protected-key validation to `execute`.

## The failure is durable

`proposal::execute` (`:219-248`) removes the proposal from the active bag
(`:234`) and adds it to the executed bag (`:244`) before the type module's
asserts run. When one of those asserts fires the whole transaction reverts, so
the proposal returns to `active` and can be re-attempted until it expires. The
payload is immutable once created: `Proposal.data` is only ever read
(`proposal.move:241`, `:283`), never written after `create`.

Whether a retry can ever succeed depends on which check failed:

- **Pinned key.** Permanently doomed. `is_governable_key` compares against
  compile-time constants in `config.move:109-111` and `btc_config.move:43-45`.
- **Wrong value type.** Permanently doomed. A key's variant is fixed once it
  exists: `is_valid_config_update` requires `same_variant`
  (`config.move:99-102`), and `add_config::execute` refuses a key that already
  exists.
- **Unknown key.** Recoverable only by landing a separate `add_config`
  proposal first, which is a second full governance cycle inside whatever
  remains of the seven-day window.

## Impact

A committee coordinates votes for up to seven days on a proposal that could
have been rejected at creation. Nothing else is affected:

- Execution is atomic, so the interleaved `upsert` calls in the loop cannot
  partially apply. A failure at entry `n` reverts entries `1..n-1`.
- `proposal::create` (`:160-184`) admits only an authorized member of the
  current committee, so this is not reachable as an external griefing vector.
- A doomed proposal is an independent object in the active bag and blocks no
  other proposal. `delete_expired` (`:141`) reclaims it after expiry.

## Recommendation

Run the execute-time checks at propose time as well. For `update_config` that
is the pair at `:68-72`; `add_config` and `update_epoch_config` have their own
equivalents.

This cannot replace the execute-time checks, because config contents can
change between proposal and execution, so both must stay. The codebase already
establishes the pattern and pre-acknowledges the limitation:
`ignore_member::propose` validates its target at creation under the comment
"Fast feedback for the proposer; state can still drift before execute."
Applying the same treatment to the three config proposal types would make the
governance surface consistent.

---

# Issue 3: `UpdateConfig` can overwrite the write-once guardian BTC public key

| | |
|---|---|
| **Severity** | Medium. Needs a 6667-bps `UpdateConfig` quorum. It breaks an invariant that the code, the module docs and the protocol docs all state, and a changed key strands BTC behind the 60-day recovery leaf. |
| **Location** | `packages/hashi/sources/core/proposal/types/update_config.move:56-67`, `core/config/config.move:99-102`, `:128-139`, `core/mpc_config.move:34-47` |
| **Reviewed against** | `packages/hashi` at `15e30f1d` |
| **Date** | 2026-09-29 |

## Summary

The guardian's x-only BTC key is meant to be written once. `finish_publish`
sets it at launch (`hashi.move:89`) through `set_guardian_btc_public_key`
(`config.move:130-139`). That setter requires exactly 32 bytes (`:131`), and
if a different key is already stored it aborts with
`EGuardianBtcPublicKeyImmutable` (`:132-137`). The comment above it (`:128-129`)
gives the reason: "rotating it would invalidate every 2-of-2 deposit address
derived against it." `update_guardian.move:4-8` and
`design/docs/governance-actions.mdx` ("Only the URL is governable") make the
same claim.

`update_config::execute` (`:56-67`) never goes through that setter. For each
entry it checks two things and then calls the raw `upsert` (`:65`):

- `is_valid_config_update` (`config.move:99-102`): the key exists and the new
  value has the same `Value` variant as the stored one.
- `mpc_config::is_valid_value` (`mpc_config.move:34-47`): range checks for the
  four `mpc_*` keys, and `true` for every other key (`:44-45`).

After launch, `guardian_btc_public_key` always exists and holds a
`Value::Bytes`. So an entry `{ "guardian_btc_public_key": Bytes(b) }` passes
both checks for any `b` of any length, and the write skips both the
immutability latch and the 32-byte check. Nothing in `packages/hashi` restricts
which keys governance may write: there is no deny-list and no allow-list.

The FV rule `update_config_preserves_guardian_btc_public_key`
(`certora/specs/proposal/sources/proposals_integrity.move:156-176`) asserts
that a successful `update_config::execute` leaves the key unchanged. The Prover
reports it **VIOLATED**.

## What a changed key does

The Move package never reads the key after writing it. Nodes and clients
rely on it:

- **Deposit addresses.** Every deposit and change address is
  `tr(NUMS, {multi_a(2, guardian, h), and_v(v:older(60 days), pk(h))})`
  (`crates/hashi/src/deposits.rs:330-350`,
  `crates/hashi-types/src/bitcoin/taproot.rs:37-42`, `:170`). The TS SDK
  generates these addresses from the on-chain key
  (`design/docs/ts-sdk.mdx:330-336`).
- **Node pinning.** `verify_and_pin_guardian_btc_pubkey`
  (`crates/hashi/src/lib.rs:1002-1016`) fetches the live guardian's BTC key
  and compares it with the on-chain value. On a mismatch the node logs
  `FATAL` and refuses to seed or reconcile its local limiter (`:1240-1270`).
  The first matching key is cached in a per-process `OnceLock` (`:67`,
  `:1013`), so a running node keeps the key it pinned until it restarts. A
  node with no pinned key can't derive deposit addresses (`deposits.rs:219`,
  `:281-285`) or validate guardian withdrawal signatures
  (`withdrawals.rs:666-668`).

What happens next depends on the new value.

**The new key doesn't match the running guardian.** This covers a typo, a
33-byte compressed encoding, or a rotation voted before the new guardian is
deployed. Every node's cross-check now fails, and a node that restarts never
pins a key, so it stops deriving deposit addresses and validating
withdrawals. SDK clients meanwhile keep generating deposit addresses from the
new on-chain value. The guardian holds no signing key for those addresses'
2-of-2 leaf, so BTC sent there can only be recovered through the MPC-only
leaf after 60 days.

**The new key matches a replacement guardian.** The same 6667-bps quorum can
also repoint the guardian's URL, either with `UpdateGuardian` or with
`UpdateConfig` on the String-valued `guardian_url` key. Once restarted, nodes
pin the new key. But every UTXO already in the pool, deposits and change
alike, commits to the old key in its 2-of-2 leaf. The node builds spend
artifacts from whichever key it has pinned (`deposits.rs:240`), and the new
guardian can't sign for the old leaf. The existing reserve can then only be
spent through the 60-day recovery leaf. This is exactly the outcome the latch
exists to prevent.

## The same gap covers `bitcoin_chain_id`

`design/docs/config.mdx:180-190` says `bitcoin_chain_id` is "Set at genesis and
not updatable through the `UpdateConfig` proposal." It is an ordinary
`Value::Address` entry, so the same two checks let `UpdateConfig` overwrite it.
Nodes compare their local chain id against the on-chain value on every
restart and before taking part in a reconfiguration
(`crates/hashi/src/lib.rs:657-667`). After an overwrite, every node therefore
fails that check.

## Default thresholds can be overwritten with arbitrary values

Every other key also accepts any value of the right type. The most
consequential are `governance_emergency_pause_threshold_bps` and
`governance_emergency_unpause_threshold_bps` (`config.move:26-28`), whose
defaults of 500 and 6667 (`:53-54`) can be replaced with any `u64`.
`emergency_pause::propose` reads the value (`:31-35`) and stores it as the
proposal's `quorum_threshold_bps`. Nothing checks its range.

- **Above 10000.** `proposal::create` (`proposal.move:153-185`) doesn't
  evaluate quorum, so the proposal is created. After that, every `vote`
  (`:105`) and every `execute` (`:205`) calls `quorum_reached`, which calls
  `threshold::weight_threshold`. That function asserts
  `threshold_bps <= MAX_BPS` (`threshold.move:36`), so each call aborts with
  `EThresholdBpsTooHigh`. On the pause key, this disables the 500-bps fast
  brake until another 6667-bps `UpdateConfig` restores it, which can take the
  full seven-day proposal window. On the unpause key, no emergency unpause can
  pass.
- **Zero.** `weight_threshold(total, 0) == 0`, so `quorum_reached` holds from
  the moment the proposal is created. `emergency_pause::execute` (`:47-51`) has
  no caller check. A single committee member can therefore create and execute
  a pause or unpause in one transaction. A zero unpause threshold is the
  dangerous case: from then on, any one member can reverse any emergency
  pause.

Raising the unpause threshold above 6667 also has no effect. `paused` is
itself a `Value::Bool` config key, so `UpdateConfig { "paused": false }`
unpauses at the fixed `THRESHOLD_BPS = 6667` (`update_config.move:17`),
whatever the configured unpause threshold says.

## Impact

Every case needs a 6667-bps quorum, and `Upgrade` has the same bar
(`upgrade.move:24`). So this gives a malicious quorum no power it doesn't
already have. The concern is that `UpdateConfig` is the routine
parameter-tuning path and gets reviewed as one, while the docs place the
guardian key outside its reach. A single mistaken entry in a batch, or a
well-meant rotation, strands both the existing reserve and new deposits
behind a 60-day timelock. A package upgrade would make the change explicit
and would go through code review. An `UpdateConfig` entry does neither. The
threshold misconfigurations do less damage but last just as long: they
persist until another full governance cycle reverts them.

## Recommendation

Make `update_config::execute` refuse `guardian_btc_public_key`, so that
`set_guardian_btc_public_key` is the key's only writer. The robust form is an
allow-list of governable keys in place of the current accept-anything
default, so that any key added later is refused unless someone makes it
governable on purpose. The same list should also leave out `bitcoin_chain_id`
and `paused`, which makes `emergency_pause` the only path that can write
`paused`.

Range-check the two threshold keys at the governance write, the way
`mpc_config::is_valid_value` already checks the MPC keys. Require
`1 <= bps <= MAX_BPS`, and consider a floor of 6667 on the unpause key. Run
these checks at propose time as well as execute time (see Issue 2).

---

# Issue 4: `end_reconfig` accepts an empty `mpc_public_key` at genesis, permanently disabling the committee handoff requirement

| | |
|---|---|
| **Severity** | Low. Needs an incoming-committee certificate over an empty key at genesis. There is no permissionless path, but the effect cannot be undone without a package upgrade. |
| **Location** | `packages/hashi/sources/core/committee/committee_set.move:454-479`, `core/reconfig.move:105-157` |
| **Reviewed against** | `main` at `2656f2c5` |
| **Date** | 2026-09-25 |

## Summary

`CommitteeSet::end_reconfig` decides whether a reconfiguration is the
initial one by testing `self.mpc_public_key.is_empty()` (`:467`). On that
branch it stores the caller-supplied key without checking it (`:468`). The
key-constancy check `assert!(self.mpc_public_key == mpc_public_key)` (`:475`)
runs after the assignment, so on this branch it always passes.
`reconfig::end_reconfig` makes the same `is_empty()` test (`reconfig.move:139`)
and takes `mpc_public_key` directly from its entry-point argument (`:107`).
Nothing requires the key to be non-empty.

If genesis completes with `mpc_public_key = vector[]`, the stored key remains
empty. Every later reconfiguration is then treated as the initial one, with
these permanent consequences:

1. **The handoff certificate is never required.** Future `end_reconfig`
   calls take the `:467-468` branch and never reach
   `assert!(committee_handoff_cert.is_some())` (`:470`). `reconfig.move:145-146`
   discards the certificate if one was supplied.
2. **The certificate cannot be supplied deliberately either.**
   `submit_committee_handoff` aborts with `EInitialReconfig` whenever the key
   is empty (`reconfig.move:196`).
3. **The next reconfiguration can install any key.** At `:468` the first
   non-empty key is assigned without a constancy check. The
   `ReconfigCompletionMessage` certificate is verified against the incoming
   committee (`reconfig.move:131-138`), so the new committee chooses the
   bridge's MPC key with no approval from the outgoing committee.
4. **The genesis gate never lifts.** `assert_genesis_launch_authorized`
   (`reconfig.move:246-250`) keeps applying to every `start_reconfig`. This is
   harmless once the upgrade cap is in custody, but it shows the system never
   leaves genesis mode.

## Reachability

The genesis `end_reconfig` must be submitted with an empty vector and a
valid next-committee certificate over
`ReconfigCompletionMessage { epoch, mpc_public_key: vector[] }`. The entry
point checks nothing else, and anyone holding the certificate can submit it.
This is realistically a launch-time operational fault, such as a node-side
bug that emits an empty key, rather than an attack. However, nothing on chain
rejects it. The failure removes the outgoing committee's control over
committee succession for the lifetime of the deployment, and only a package
upgrade can repair it.

## Recommendation

Reject an empty key in `CommitteeSet::end_reconfig` before the assignment:

```move
if (self.mpc_public_key.is_empty()) {
    assert!(!mpc_public_key.is_empty(), EEmptyMpcPublicKey);
    self.mpc_public_key = mpc_public_key;
} else {
    ...
```

A length check against the expected key encoding would be stronger and costs
no more.

---

# Issue 5: `mark_spent` requires neither a prior `lock` nor an unset `spent_epoch`

| | |
|---|---|
| **Severity** | Informational. Not reachable today. Defense in depth. |
| **Location** | `packages/hashi/sources/btc/utxo_pool.move:126-130`, compare `:120-124` |
| **Reviewed against** | `main` at `2656f2c5` |
| **Date** | 2026-09-25 |

## Summary

`mark_spent` writes `spent_epoch = Some(epoch)` (`:128`) with no
precondition:

- It does not assert `record.spent_by.is_some()`, so it can mark a UTXO spent
  even though no withdrawal ever locked it.
- It does not assert `record.spent_epoch.is_none()`, so it can overwrite an
  earlier spent epoch. `cleanup_spent` (`:151`, `:153`) would then record the
  UTXO in `spent_utxos` under the later epoch.
- It does not check which withdrawal holds the lock, so it cannot tell
  whether the confirming withdrawal is the one that locked the UTXO.

By contrast, `lock` (`:120-124`) does guard its own transition with
`assert!(record.spent_by.is_none(), EUtxoAlreadyLocked)`.

## Why it holds today

The only caller is `confirm_withdrawal`, which iterates the transaction's own
`inputs` (`withdraw.move:302-304`). The following facts together make the
missing checks unreachable:

- `commit_withdrawal_tx` locks every input to the new withdrawal
  (`withdraw.move:174`). Because `lock` refuses a UTXO that is already
  locked, no two transactions can share an input.
- `confirm_withdrawal` runs at most once per transaction. `mark_txn_confirmed`
  aborts on a second confirmation (`withdrawal_queue.move:602`), and the
  fully-signed gate (`withdraw.move:278-281`) runs before it.

So every UTXO that reaches `mark_spent` is locked, and locked by the
confirming withdrawal, and each one reaches it at most once. The safety of the
`mark_spent → cleanup_spent → spent_utxos` sequence therefore rests on a
three-part argument spread across two modules. Two local asserts would
guarantee the same thing directly.

## Recommendation

Pass the confirming withdrawal ID in and assert both preconditions at the
callee:

```move
public(package) fun mark_spent(self: &mut UtxoPool, utxo_id: UtxoId, withdrawal_id: address, epoch: u64) {
    let record: &mut UtxoRecord = self.utxo_records.borrow_mut(utxo_id);
    assert!(record.spent_by == option::some(withdrawal_id), EUtxoNotLockedByWithdrawal);
    assert!(record.spent_epoch.is_none(), EUtxoAlreadySpent);
    ...
```

The replay latch in `cleanup_spent` already guards its own ordering locally,
since `spent_epoch.destroy_some()` at `:151` aborts if `mark_spent` never ran.
These asserts would give the preceding step the same local guarantee, and the
whole `lock → mark_spent → cleanup_spent` sequence would then be enforced by
the callee at each step.
