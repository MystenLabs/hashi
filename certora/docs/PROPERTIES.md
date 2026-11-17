# Hashi Protocol — Critical Mathematical Properties

This document states, in concrete terms grounded in the actual Move structs and
functions, the mathematical properties Hashi must uphold. Each property names
the exact types and functions that establish or could break it, and notes
where a property is only partially enforced on-chain (Move) vs. relies on
off-chain (`crates/`) or Bitcoin-consensus-level guarantees.

Companion reading: [PROTOCOL.md](../../PROTOCOL.md) §1 (protocol description) and §3
(audit plan) for the informal versions of these properties.

---

## P1 — Global conservation (the peg)

**Statement**: at any point, the total `hBTC` supply is at most the total BTC
value the pool has committed to holding.

```
Σ hBTC.value()  <=  Σ { utxo.amount : record ∈ UtxoPool.utxo_records, record.spent_by == none }
```

**`pool_btc` must be characterized by `spent_by == none`, not "all of
`utxo_records`".** Confirmed directly against `btc/utxo.move` and
`btc/utxo_pool.move` (not from the summary in a prior draft of this doc,
which used the whole bag and was wrong — see "Why the bag-membership
version doesn't work" below):
- `Utxo { id: UtxoId, amount: u64, derivation_path: Option<address> }`
  (`utxo.move:22-27`) — `amount` in satoshis.
- `UtxoRecord { utxo: Utxo, produced_by: Option<address>, spent_by:
  Option<address>, spent_epoch: Option<u64> }` (`utxo_pool.move:39-44`).
  `spent_by`: `none` = selectable for a future withdrawal; `Some(id)` =
  locked to withdrawal `id`, permanently — "there is no unlock" (doc
  comment, `:33-34`), confirmed by grep: `lock` (`:120-124`) is the only
  writer of `spent_by`, and it only ever writes `Some`.
- `UtxoPool { utxo_records: Bag, spent_utxos: Bag }` (`:46-49`) —
  `spent_utxos: UtxoId -> u64` (spent epoch only, no amount) is permanent
  replay-protection, excluded from the sum regardless of which
  characterization of `utxo_records` is used.

**Structs**:
- `Treasury` (`core/treasury.move`) — wraps the `TreasuryCap<BTC>` whose
  `total_supply()` is the LHS.

**Critical functions** (mint/burn and pool add/spend are each single-call-site):
| Side | Function | Location | Effect |
|---|---|---|---|
| mint | `Treasury::mint_balance<T>` | `core/treasury.move:56` | increases LHS |
| mint caller | `confirm_deposit` | `btc/deposit.move:239` (entry, `:193`) | only caller of `mint_balance`; conditional — see gap below |
| pool add | `insert_active` | `btc/utxo_pool.move:68` | increases RHS (`spent_by: none` on insert); called only from `confirm_deposit`, unconditionally |
| burn | `Treasury::burn<T>` | `core/treasury.move:61` | decreases LHS |
| burn caller | `commit_withdrawal_tx` | `btc/withdraw.move:182` (entry, `:113`) | only caller of `burn` |
| pool lock (removes from RHS) | `lock` | `btc/utxo_pool.move:120-124` | flips `spent_by: none -> Some`, same transaction as the burn above (`withdraw.move:174-176`, then `:182`) |
| pool re-add (change) | `insert_pending` | `btc/utxo_pool.move:89` | change UTXO enters RHS with `spent_by: none`, same transaction (`withdraw.move:188`) |

**Why the bag-membership version (`Σ over all of utxo_records`) doesn't
work.** `mark_spent` (`utxo_pool.move:126-130`, called from
`confirm_withdrawal`, `withdraw.move:304`) only sets `record.spent_epoch` —
it does **not** remove the record from `utxo_records`. The record is only
actually removed later, by `cleanup_spent` (`utxo_pool.move:146-155`),
called from a separate, ungated, arbitrarily-batched entry function,
`cleanup_spent_utxos` (`withdraw.move:348-353`), which can run any time
after `mark_spent` for a batch of UTXO IDs spanning many unrelated
withdrawals. If `pool_btc` is defined as the sum over the whole bag, its
decrease for a given withdrawal happens in a *different, later transaction*
than the corresponding burn — there is no local, per-transaction argument
that `cleanup_spent_utxos`'s effect on `pool_btc` is matched by anything,
short of an explicit ghost variable tracking "locked but not yet
bag-removed" value.

Defining `pool_btc` over `spent_by == none` instead moves the decrease to
`lock()`, which runs inside `commit_withdrawal_tx` — the same transaction
as the burn (`withdraw.move:174-176` then `:182`). Under this definition,
`mark_spent` and `cleanup_spent` are **provable no-ops on `pool_btc`**:
`mark_spent` never touches `spent_by`, and any record `cleanup_spent`
removes already has `spent_by = Some(...)` and so was already excluded from
the sum. This is what makes a per-transaction step invariant possible at
all — `cleanup_spent_utxos` drops out of the proof entirely instead of
needing its own justification.

This `pool_btc` is also a **safe lower bound** on the BTC the pool actually
controls on Bitcoin: a record with `spent_by = Some(...)` is locked
Move-side for a future withdrawal, but the real UTXO isn't spent on Bitcoin
until that withdrawal actually confirms (`confirm_withdrawal` requires a
committee cert attesting Bitcoin-side confirmation, `withdraw.move:265-283`
comment). So real BTC held >= `pool_btc` always, and proving the invariant
against this smaller, exactly-tractable quantity implies it for the real
figure too.

**Confirmed gap — this is not the equality it might look like, and the
correction runs the opposite direction from a prior draft of this doc.**
Worked through `new_withdrawal_txn` (`btc/withdrawal_queue.move:403-487`),
with `R` = request count, `f = miner_fee / R` (floor), `r = miner_fee mod R`:

- hBTC burned per batch = `burn_amount = Σ request.btc_amount` (full
  pre-fee claim amounts), drained via `commit_requests`
  (`withdrawal_queue.move:313-334`).
- Each user output is asserted to equal `btc_amount_i - f`
  (`withdrawal_queue.move:451-453`), so pool debit (input consumed minus
  change returned) works out to `pool_debit = burn_amount + r`.

Concrete check (`R=2`, input=2001, two user outputs of 998 each so
`output_amount=1996`, `miner_fee=5`, `f=2`, `r=1`, `burn_amount=2000`): the
pool loses 2001 sats, hBTC loses 2000 — **the gap `pool_btc - hBTC_supply`
shrinks by `r`**, every time `R` doesn't evenly divide `miner_fee`, with
nothing in Move asserting `r == 0`. This is the opposite of what a prior
draft of this section claimed (that the gap is "monotonically
non-decreasing"); that direction was wrong.

There is a separate mechanism that pushes the gap the *other* way:
`confirm_deposit` (`deposit.move:230-250`) unconditionally calls
`insert_active(utxo)`, but only calls `mint_balance` **if
`derivation_path.is_some()`** (`:245-249`). A deposited UTXO with no
derivation path adds its full amount to `pool_btc` while minting nothing —
pure gap growth. This is likely what the prior draft's "accumulated dust"
language was describing, just attributed to the wrong side (withdrawal
rounding shrinks the gap; no-derivation-path deposits are what grow it).

```
pool_btc  >=  hBTC_supply   —  NOT yet shown to hold unconditionally;
                                depends on whether accumulated no-mint-deposit
                                surplus always dominates accumulated
                                withdrawal-rounding leakage (see note below).
```

**Note for future — open, unresolved by this pass**: whether `pool_btc >=
hBTC_supply` can actually be violated by an adversarial-or-just-unlucky
sequence of multi-recipient withdrawal batches (each with `r > 0`) that
isn't offset by enough no-derivation-path deposits. Nothing found in
`packages/hashi/sources` bounds this — no assert forces `miner_fee mod R ==
0`, and no invariant ties the two mechanisms together. Before encoding this
as a CVL rule, check whether such a bound is enforced off-chain
(`crates/`, not inspected here) on the withdrawal-transaction construction
side, or whether the initial/expected deployment relies on
no-derivation-path "sweep" deposits accumulating enough surplus in
practice. If neither holds, this is a real (if likely small,
satoshi-scale-per-batch) solvency leak worth flagging on its own, separate
from the definitional fix above.

---

## P2 — Withdrawal transaction balance identity & fee-bound soundness

**Statement**: for every constructed Bitcoin withdrawal transaction —
(a) `input_total = user_output_total + change_total + miner_fee` holds by
construction; (b) the per-user miner fee is capped such that it can never
underflow and can never drive a user's output to zero, negative, or below
Bitcoin's dust-relay minimum; and (c) the fee is deducted from the
**user's** output only, never from the pool's principal. These three used
to be written up as separate properties (P2, P7, P16) but they're really
one story — a single construction function enforcing an identity, a
separate config module supplying the cap that identity checks against, and
the composed result of the two.

**Structs** (`btc/withdrawal_queue.move`):
```
public struct WithdrawalTransaction has key, store {
    id: UID,
    txid: address,
    request_ids: vector<address>,
    inputs: vector<Utxo>,                  // :110
    withdrawal_outputs: vector<OutputUtxo>, // :111
    change_outputs: vector<OutputUtxo>,     // :116
    ...
    signing: SigningBatch,
    guardian_signatures: Option<vector<vector<u8>>>,
}                                                          // :103-133
public struct OutputUtxo { amount: u64, bitcoin_address: vector<u8> }        // :135-139
public struct CommittedRequestInfo { btc_amount: u64, bitcoin_address: vector<u8> } // :142-145
```

**Critical function**: `new_withdrawal_txn` — `withdrawal_queue.move:403-487`.
This is where the balance identity is **enforced by construction**, not
merely assumed:
- `input_amount` summed over `inputs` — `:418-421`
- `output_amount` summed over all outputs (requests + change) — `:423-426`
- `assert!(input_amount >= output_amount, EInputsBelowOutputs);` — `:428`
- `let miner_fee = input_amount - output_amount;` — `:429`
- Per-output check that fee is deducted from the **user's** amount, not the
  pool: `let expected = info.btc_amount - per_user_miner_fee;` then
  `assert!(output.amount == expected, EOutputAmountMismatch);` — `:451-453`
- Fee is capped, not just computed: `assert!(per_user_miner_fee <=
  max_network_fee, EMinerFeeExceedsMax);` — `:444`, where `max_network_fee =
  config.worst_case_network_fee()`, derived below.

**Entry point wiring inputs from the pool**: `commit_withdrawal_tx`,
`btc/withdraw.move:113-194` — draws `inputs` via `utxo_pool().get_utxo`
(`:144`), locks them (`:174-176`, see P3), then burns and inserts change
(`:179-189`).

**Where `max_network_fee` comes from — fee-bound arithmetic**, all in
`btc/btc_config.move`:
```
const DUST_RELAY_MIN_VALUE: u64 = 546;                                    // :14

public(package) fun bitcoin_withdrawal_minimum(self: &Config): u64 {
    self.get(b"bitcoin_withdrawal_minimum").as_u64().max(DUST_RELAY_MIN_VALUE + 1)  // :42-44
}
public(package) fun worst_case_network_fee(self: &Config): u64 {
    bitcoin_withdrawal_minimum(self) - DUST_RELAY_MIN_VALUE                // :80-82
}
```
Because `bitcoin_withdrawal_minimum` is floored at `DUST_RELAY_MIN_VALUE + 1`,
`worst_case_network_fee >= 1` **by construction** — no underflow possible.
Defaults: `init_defaults` sets both `bitcoin_deposit_minimum` and
`bitcoin_withdrawal_minimum` to `30_000` sats (`btc_config.move:21-27`).

**Composed result — dust-floor soundness holds end-to-end.** Chaining the
two pieces above together:
- `bitcoin_withdrawal_minimum >= DUST_RELAY_MIN_VALUE + 1` (`btc_config.move:42-44`)
- `worst_case_network_fee = bitcoin_withdrawal_minimum - DUST_RELAY_MIN_VALUE >= 1` (`:80-82`)
- `per_user_miner_fee <= worst_case_network_fee` (`withdrawal_queue.move:444`)
- `output.amount == btc_amount - per_user_miner_fee`, and separately
  `output.amount >= dust_relay_min_value()` is asserted directly
  (`:451-453`)

Since `request_withdrawal` already enforces `btc.value() >=
bitcoin_withdrawal_minimum` at request time (`withdraw.move:374`, error
`EBelowMinimumWithdrawal`), and the minimum is floored strictly above
`DUST_RELAY_MIN_VALUE`, a withdrawal can never net the user zero or
negative BTC after the fee is deducted — and the output is guaranteed
`>= DUST_RELAY_MIN_VALUE` by the explicit dust check at `:452`, not just by
the arithmetic margin. **This is the one property in this document that is
fully Move-verifiable end-to-end from a single, traceable chain of
asserts** — a good first candidate to encode as a CVL rule.

**Confirmed gap — off-chain fee bound is out of Move's reach.** PROTOCOL.md
describes an `estimatesmartfee`-derived fee validated within **[1 sat/vB,
3× each member's own estimate]** by other committee members before
submission. **No such range-check exists anywhere in
`packages/hashi/sources`** — grep for `estimatesmartfee`, `sat/vB`, `3x`
finds nothing in Move. That validation, if it exists, lives entirely
off-chain (`crates/`, not inspected here) and only its *result* (the
constructed outputs) reaches Move, checked solely against the
`worst_case_network_fee` cap derived above. If this bound needs formal
verification, it is out of Move's scope — flag for Phase 9 (off-chain/
on-chain consistency).

**Note**: the balance identity and the fee/dust bound both hold exactly as
coded — it's the *split* of `miner_fee` across multiple requests (P1's
finding) where a dust leak enters the pool-vs-hBTC accounting, not
anything in this per-transaction construction itself.

---

## P3 — Uniqueness / no double-processing

**Statement**: every withdrawal request, deposit request, and UTXO undergoes
each state transition **at most once**, and once spent, a UTXO can never be
reused as an input or re-inserted as active.

**Withdrawal state machine** — since `testnet-1.0`, no status enum. State is
derived from `WithdrawalRequest.approval_cert`/`withdrawal_txn_id` and from
the linked `WithdrawalTransaction`'s `guardian_signatures`/
`confirmed_timestamp_ms`, plus bag membership (`btc/withdrawal_queue.move`).
One-way:

| Transition | Function | Location | Guard |
|---|---|---|---|
| → Requested | `create_withdrawal` + `insert_withdrawal` | `:263-296` | — |
| Requested → Approved (or re-approval) | `approve_withdrawal` | `:300-322` | `!is_committed` (`:310`); a stored cert must be from a strictly older epoch (`:315-319`) |
| Approved → Committed | `commit_requests` | `:358-377` | `is_approved` (`:367`); `!is_committed` (`:370`) — blocks double-commit |
| txn → Fully signed | `finalize_withdrawal_txn` | `:575-587` | not already fully signed (`:582`); every MPC slot signed (`:583`) |
| txn → Confirmed | `mark_txn_confirmed` | `:595-604` | `confirmed_timestamp_ms.is_none()` (`:601`) — blocks double-confirm |
| Committed → Archived | `archive_withdrawal_txn`/`archive_request` | `:613-647` | txn confirmed (`:620`); request linked to this txn (`:645`) |

Storage: `WithdrawalRequestQueue { requests, processed, withdrawal_txns,
confirmed_txns }` (`:105-118`), all `ObjectBag`. A committed request stays
in `requests` until archival moves it to `processed`. `is_request_processing`
(`:421-431`) reads the request's link first and gates `cancel_withdrawal`
(`btc/withdraw.move:158-161`); the queue-level `cancel_withdrawal` also
asserts `!is_committed` (`:391`) — this is the mutual exclusion between
cancel and commit. Full treatment: [PROPERTIES_WITHDRAW.md](PROPERTIES_WITHDRAW.md) W0.

**Deposit state**: no explicit enum — tracked via `Option` fields on
`DepositRequest` (`btc/deposit_queue.move:35-50`): `approval_cert:
Option<CommitteeSignature>`, `approved_timestamp_ms`, `confirmed_timestamp_ms`
(unset until `confirm`, `:112-114`). Bag-level guard: `delete_expired`
asserts `!self.processed.contains(request_id)` (`EDepositAlreadyProcessed`,
`:135`).

**UTXO replay protection**:
```
public struct UtxoId has copy, drop, store { txid: address, vout: u32 }  // utxo.move:15-20
public struct UtxoPool { utxo_records: Bag, spent_utxos: Bag }           // utxo_pool.move:46-49
public struct UtxoRecord { utxo: Utxo, produced_by: Option<address>, spent_by: Option<address>, spent_epoch: Option<u64> } // :39-44
```
- `assert_not_spent_or_active` (`:109-111`), built on `is_spent_or_active`
  (`:105-107` — `utxo_records.contains(id) || spent_utxos.contains(id)`) —
  called from `insert_active` (`:68-82`, `:70`), error `EUtxoAlreadyUsed`.
- `lock` (`:120-124`) asserts `record.spent_by.is_none()`
  (`EUtxoAlreadyLocked`) before reserving a UTXO for a withdrawal.
- `cleanup_spent` (`:146-155`) moves a record `utxo_records → spent_utxos`
  **permanently** — after this, `assert_not_spent_or_active` will always
  reject re-insertion of that `UtxoId`.

---

## P4 — Quorum/threshold soundness

**Statement**: a certificate is accepted iff the aggregate stake weight of
valid signers is at least `⌈2/3 · total_weight⌉`; no rounding error admits a
sub-quorum certificate.

**Formula** — `core/threshold.move`:
```
const CERTIFICATE_THRESHOLD_BPS: u64 = 6667;   // :16  (66.67% ≈ >2/3)
const MAX_BPS: u64 = 10000;                    // :13

public(package) fun weight_threshold(total_weight: u64, threshold_bps: u64): u64 {
    (total_weight * threshold_bps).divide_and_round_up(MAX_BPS)   // :35-38 — ceiling division
}
public(package) fun certificate_threshold(total_weight: u16): u16 {
    weight_threshold(total_weight as u64, CERTIFICATE_THRESHOLD_BPS) as u16  // :28-30
}
```
`divide_and_round_up` makes this a genuine `ceil(total_weight * 6667 /
10000)` — the required weight is never below the true fractional 2/3.

**Consumer** — `verify_certificate`, `core/committee/committee.move:198-273`:
1. `assert!(signature.epoch == self.epoch());` (`:205`) — epoch pin, see P6.
2. Decode `signature.signers_bitmap`, sum `weight` per set bit into
   `aggregate_weight`, collect `signer_public_keys` — `:208-239`.
3. `assert!(aggregate_weight >= threshold, ENotEnoughStake);` — `:242` — this
   is where P4's threshold is actually enforced; `threshold` is passed in by
   the caller (`hashi.move:129-131`), computed fresh from
   `current_committee().total_weight()` each call, never cached.
4. BLS aggregate-key sum + `bls12381_min_pk_verify` — `:244-267`.

**Struct**: `Committee { epoch: u64, members: vector<CommitteeMember>,
total_weight: u64, config: Config }` (`committee.move:42-53`);
`CommitteeMember { validator_address, public_key, encryption_public_key,
weight: u64 }` (`:34-39`), with `assert!(weight > 0, EIncorrectCommittee)`
enforced per-member at construction (`new_committee`, `:84-105`).

---

## P5 — 2-of-2 structural guarantee (escape hatch excluded)

**Statement**: no Bitcoin UTXO under Hashi's control can move without both
the committee's and the guardian's signature, except via the 60-day-timelocked
committee-alone escape hatch.

**This property is not represented or verified in Move at all.** A full grep
of `packages/hashi/sources` for the Taproot script tree
(`multi_a`, `older(`, script-tree terms) returns only two doc comments — no
struct, no validation function:
- `withdrawal_queue.move:130` — comment on `guardian_signatures` field:
  "together they form the 2-of-2 taproot witness."
- `hashi.move:64-66` — comment above `finish_publish`.

**What Move *does* enforce** is narrower and indirect: the guardian's BTC
public key, once set, cannot change — since changing it would silently
redefine every previously-derived deposit address's spending conditions.

```
// core/config/config.move:128-138
public(package) fun set_guardian_btc_public_key(self: &mut Config, btc_public_key: vector<u8>) {
    assert!(btc_public_key.length() == GUARDIAN_BTC_PUBLIC_KEY_LEN, EBadGuardianBtcPublicKeyLength);
    let existing = self.guardian_btc_public_key();
    if (existing.is_some()) {
        assert!(existing.destroy_some() == btc_public_key, EGuardianBtcPublicKeyImmutable);  // abort if changing
    } else { existing.destroy_none(); };
    self.upsert(GUARDIAN_BTC_PUBLIC_KEY_KEY, config_value::new_bytes(btc_public_key));
}
```
Set exactly once, from `entry fun finish_publish` (`hashi.move:68-112, :89`).
No proposal type can reach it — `core/proposal/types/update_guardian.move`
governs **only the URL**:
```
public struct UpdateGuardian has copy, drop, store { url: String }  // :21-23
public fun execute(...) { hashi.config_mut().set_guardian_url(url); }  // :47-50, unconditional upsert
```

**Conclusion**: the actual 2-of-2 + timelock guarantee is a **Bitcoin-script /
off-chain guarantee** (PSBT/script construction presumably in `crates/`, not
inspected here) that Move cannot verify. The only on-chain contribution to
this property is guaranteeing the guardian key input to address derivation
never silently changes post-genesis. If this needs formal verification, the
Move-side scope is exactly `set_guardian_btc_public_key`'s immutability —
everything else is out of Move's reach and belongs in Phase 7/9 of
[PROTOCOL.md](../../PROTOCOL.md) (Bitcoin-side specifics / off-chain consistency).

---

## P6 — Certificate binding (domain separation + epoch pinning)

**Statement**: a valid signature for intent `X` at epoch `E` cannot be
accepted as a valid signature for a different intent `X'` or a different
epoch `E'`.

**Domain tags** — `core/intent.move`:
```
const PROOF_OF_POSSESSION: u16 = 0x0000;        // :24
const COMMITTEE_TRANSITION: u16 = 0x0001;       // :26
const RECONFIG_COMPLETION: u16 = 0x0002;        // :28
const DEALER_MESSAGES_HASH: u16 = 0x0003;       // :31
const DEPOSIT_CONFIRMATION: u16 = 0x0100;       // :36
const WITHDRAWAL_REQUEST_APPROVAL: u16 = 0x0101; // :38
const WITHDRAWAL_COMMITMENT: u16 = 0x0102;      // :40
const MPC_INPUT_SIGNATURES: u16 = 0x0103;       // :42
const WITHDRAWAL_SIGNED: u16 = 0x0104;          // :44
const WITHDRAWAL_CONFIRMATION: u16 = 0x0105;    // :46
const GUARDIAN_WITHDRAWAL_REQUEST: u16 = 0x0106; // :49
```
Module doc (`:4-16`): signing preimage is `intent (u16 LE) || bcs(epoch) ||
bcs(message)`; **must stay in sync with `crates/hashi-types/src/intent.rs`**
— a cross-repo consistency item for Phase 9.

**Epoch pin, enforced in the verifier itself** —
`committee.move:205`:
```
assert!(signature.epoch == self.epoch());
```
This runs *before* the BLS check — a certificate for epoch N structurally
cannot verify against a `Committee` for epoch M≠N, independent of signature
validity.

**Epoch → Committee mapping** — `core/committee/committee_set.move`:
```
public struct CommitteeSet has store {
    members: Bag,
    epoch: u64,
    committees: Bag,   // u64 (epoch) -> Committee   :25-33
    pending_epoch_change: Option<PendingEpochChange>,
    mpc_public_key: vector<u8>,
}
```
`committees` is a `Bag`, not a `Table<u64, Committee>` — insertion via
`insert_committee` (`self.committees.add(committee.epoch(), committee)`,
`:379-381`), existence via `has_committee`
(`contains_with_type<u64, Committee>`, `:341-343`).
- Current: `current_committee(self): &Committee { &self.committees[self.epoch()] }` (`:333-335`)
- Specific epoch: `get_committee(self, epoch): &Committee { &self.committees[epoch] }` (`:337-339`)

**Both paths wired through `Hashi`** — `hashi.move:123-145`:
`verify` uses `current_committee()`; `verify_with_committee` takes an
explicit `committee: &Committee` (used by reconfig to check the *next*
epoch's committee, per its own doc comment). Withdraw stamps every
message/signing-batch with `hashi.committee_set().epoch()` at commit time
(`withdraw.move:129, 298, 332`), so a certificate can't be produced under one
epoch and settled under another.

---

## P7 — Guard completeness

**Statement**: every state-mutating entry function calls
`assert_unpaused`, `assert_not_reconfiguring`, and `assert_version_enabled`
(in some order, before any mutation) — this is a property over the entire
entry-point surface, not any single function.

```
public(package) fun assert_unpaused(self: &Hashi) {
    assert!(!self.config().paused(), ESystemPaused);          // hashi.move:116-119
}
public(package) fun assert_not_reconfiguring(self: &Hashi) {
    assert!(!self.committee_set().is_reconfiguring(), EReconfiguring);
    assert!(self.committee_set().has_committee(self.committee_set().epoch()), ENoCommittee);
                                                                 // hashi.move:147-152
}
```
Version gate lives in `core/versioning.move` (`assert_version_enabled`,
referenced at `hashi.move:79` inside `finish_publish` itself).

**No single struct captures this** — it must be checked per entry function.
Per [PROTOCOL.md](../../PROTOCOL.md) Phase 1/6, the concrete task is: enumerate
every `entry fun` across `btc/` and `core/`, and for each, confirm all three
guards run before the first state write. A missing guard on even one
function (e.g. a withdrawal-queue mutator added later without the pause
check) breaks the property invisibly — this can't be verified by reading
`hashi.move` alone.

---

## P8 — `finish_publish` write-once latch

**Statement**: `finish_publish` (and the config/capabilities it sets)
transition `None → Some` **at most once**; no code path resets any of them
back to `None`.

`entry fun finish_publish` — `hashi.move:68-112`. Two independent
call-once mechanisms:
1. `versioning_mut().set_upgrade_cap(upgrade_cap)` (`:85`) — relies on
   `Option::fill` semantics inside `versioning.move` (aborts if already
   `Some`; not shown here but implied by the doc comment `hashi.move:60-62`:
   "`Option::fill` inside `set_upgrade_cap` ... make this call-once").
2. `set_guardian_btc_public_key` (`config.move:128-138`, see P5) — same
   `None`-then-immutable pattern, explicit `EGuardianBtcPublicKeyImmutable`
   abort on a differing second write.

Also gated by `self.versioning.assert_version_enabled();` (`:79`) and an
upgrade-cap package-identity check: `assert!(upgrade_cap.package() ==
this_package_id, EWrongUpgradeCap);` (`:83`) — this prevents calling
`finish_publish` with a cap from a different package entirely.

**To verify**: confirm `register_treasury_cap`/`register_metadata_cap`
(`core/treasury.move`, called at `hashi.move:110-111`) have the same
abort-on-already-set behavior — not shown in this file, worth checking
directly in `treasury.move`.

---

## P9 — Presignature/nonce range disjointness

**Statement**: no two Schnorr signing sessions are ever allocated
overlapping nonce indices — nonce reuse in threshold Schnorr directly leaks
the committee's private key share.

```
public(package) fun allocate_presigs(self: &mut Hashi, count: u64): u64 {
    let start = self.num_consumed_presigs;
    self.num_consumed_presigs = self.num_consumed_presigs + count;   // hashi.move:230-234
    start
}
public(package) fun reset_num_consumed_presigs(self: &mut Hashi) {
    self.num_consumed_presigs = 0;                                   // hashi.move:236-238
}
```
For any two calls to `allocate_presigs`, the returned ranges `[start₁,
start₁+count₁)` and `[start₂, start₂+count₂)` must never overlap — this
holds trivially *within* a monotonically-increasing counter (each call moves
`start` strictly forward), **but `reset_num_consumed_presigs` breaks that
monotonicity by design** (used across epoch boundaries). The actual property
to verify is:

> `reset_num_consumed_presigs` is only ever called at a point where every
> presignature allocated under the old counter value is provably discarded
> — i.e. no in-flight signing session references a range from the prior
> epoch after reset.

This needs to be checked against every call site of both functions, and
cross-referenced with `core/mpc_signing.move`'s own documented nonce-safety
invariants (per [PROTOCOL.md](../../PROTOCOL.md) Phase 3, item 6) — this file
alone only establishes the counter mechanics, not the call-site safety.

---

## P10 — Threshold/committee coherence

**Statement**: the stake threshold used in a certificate check is always
computed from the *same* committee whose signatures are being verified —
never a threshold from one epoch applied to a certificate from another.

```
public(package) fun verify<T>(self: &Hashi, intent: u16, message: T, sig: CommitteeSignature): CertifiedMessage<T> {
    let threshold = threshold::certificate_threshold(self.current_committee().total_weight() as u16) as u64;
    self.current_committee().verify_certificate(intent, message, sig, threshold)   // hashi.move:123-132
}
public(package) fun verify_with_committee<T>(_self: &Hashi, committee: &Committee, intent: u16, message: T, sig: CommitteeSignature): CertifiedMessage<T> {
    let threshold = threshold::certificate_threshold(committee.total_weight() as u16) as u64;
    committee.verify_certificate(intent, message, sig, threshold)                  // hashi.move:136-145
}
```
Both functions compute `threshold` from the **same** `committee` reference
passed to `verify_certificate` in the same call — there's no path where a
stale/cached threshold from a different committee is used. This holds
structurally as written; the thing worth checking at call sites is that
`verify_with_committee`'s callers (reconfig) pass the *correct* committee
(the next epoch's, per the doc comment) and not accidentally the current one.

---

## P11 — Dynamic-field / Bag key injectivity

**Statement**: distinct logical purposes never collide on the same storage
key — a key collision means one write silently overwrites or aliases another
purpose's state.

Two live instances today:
- `Hashi.id` dynamic field: `df::add(&mut hashi.id, bitcoin_state::key(),
  bitcoin_state::new(ctx))` (`hashi.move:260`), read via `df::borrow(&self.id,
  bitcoin_state::key())` (`:203`). Only one DF key exists today
  (`bitcoin_state::key()`); the property becomes load-bearing the moment a
  second chain's state is added as another DF on the same `id` — its key
  must be provably distinct from `bitcoin_state::key()`.
- `tob: Bag` keyed by `TobKey` (epoch, batch_index) —
  `epoch_certs(self, key: TobKey, ctx): &mut EpochCertsV1` (`hashi.move:214-224`),
  lazily inserting `hashi::tob::create(epoch, key.protocol_type(), ctx)` if
  absent. Injectivity here means two distinct `(epoch, batch_index,
  protocol_type)` triples never produce the same `TobKey` — worth checking
  `TobKey`'s equality/hash derivation in `core/tob.move` directly.

**To verify**: there's no single function that enforces this — it's a
property of the key-construction functions (`bitcoin_state::key()`,
`TobKey` construction) being injective over their input domains. Check both
directly in `btc/bitcoin_state.move` and `core/tob.move`.

---

## P12 — Reconfig as mutual exclusion

**Statement**: while `committee_set().is_reconfiguring()` is true, no
deposit/withdrawal state transition can execute; epoch is a strictly
monotonic counter, incremented by exactly 1 per completed reconfig.

Enforced at the guard level by `assert_not_reconfiguring`
(`hashi.move:147-152`, see P7) — checked via `CommitteeSet.epoch: u64` and
whatever boolean/`PendingEpochChange` state backs `is_reconfiguring()`
(`committee_set.move`, `PendingEpochChange { epoch: u64,
committee_handoff_cert: Option<CommitteeSignature> }`, `:40-43`).

**To verify** in `core/reconfig.move` directly (not covered by this file):
that `start_reconfig` sets the reconfiguring flag *before* any
handoff-cert processing, that `end_reconfig` increments `epoch` by exactly
1, and that no entry point outside `reconfig.move` can flip
`pending_epoch_change` — otherwise the "lock" is only a naming convention,
not an actual mutual-exclusion guarantee.

---

## P13 — Governance quorum asymmetry is non-invertible

**Statement**: `emergency_pause`'s low quorum-to-pause / supermajority
quorum-to-unpause asymmetry cannot be circumvented by any sequence of
proposals, and no proposal executes after its 7-day expiry.

Not directly visible in `hashi.move` — needs `core/proposal/proposal.move`
(generic quorum engine) and `core/proposal/types/emergency_pause.move`
cross-read. The property to check there: the two directions (`pause`,
`unpause`) use genuinely different threshold constants (not just different
runtime parameters that happen to default the same), and proposal execution
asserts `clock.timestamp_ms() - proposal.created_at_ms <= EXPIRY_MS` on
every execution path, not just the happy path.

---

## P14 — Version gating is a strict allow-list

**Statement**: once a package version is disabled, zero further entry calls
process under it; re-enabling requires the same governance path as
disabling — no silent auto-recovery.

`assert_version_enabled` is referenced at `hashi.move:79` (inside
`finish_publish`) but defined in `core/versioning.move` (not read in this
pass). The property to check there: `disable_version` /
`enable_version` (`core/proposal/types/{disable_version,enable_version}.move`)
are the *only* writers of the enabled-set, and `assert_version_enabled` is
called by every entry function package-wide (this overlaps with P7 — same
enumeration exercise, different guard).

---

## P15 — Governance proposal lifecycle & committee reconfiguration state machine

**Statement**: every governance proposal moves through its lifecycle
(created → voted → quorum reached → executed, or → expired → deleted) with
no path to double-execution or post-expiry execution; the committee
reconfiguration process — a related but **separately implemented** state
machine, not built on the generic proposal engine — is a strict
one-in-flight-reconfig-at-a-time sequence per epoch, with cancellation
routed back through a dedicated governance proposal type.

**Generic proposal lifecycle** — `core/proposal/proposal.move`:
```
public struct Proposal<T> has key, store {
    id: UID,
    creator: address,
    votes: vector<address>,
    quorum_threshold_bps: u64,
    created_timestamp_ms: u64,
    executed_timestamp_ms: Option<u64>,   // None until executed
    metadata: VecMap<String, String>,
    data: T,
}                                                          // :40-50
```
No explicit status enum — state is tracked by bag membership in
`Proposals { active: ObjectBag, executed: ObjectBag }`
(`proposals.move:17-23`) plus expiry-clock arithmetic:

| Transition | Function | Location | Guard |
|---|---|---|---|
| → Created (in `active`) | `create` | `proposal.move:153-185` | caller must be an authorized committee member (`:165`) |
| Created → voted | `vote` (entry) | `:87-108` | `!votes.contains(voter)` (`EVoteAlreadyCounted`, `:99`); `!is_expired` (`:100`) |
| voted → un-voted | `remove_vote` (entry) | `:111-131` | voter must have an existing vote (`ENoVoteFound`, `:124`) |
| Created/voted → Executed (`active` → `executed`) | `execute` | `:187-216` | `!executed.contains(id)` (`EProposalAlreadyExecuted`, `:198-201`, checked **before** removing from `active`); `!is_expired` (`:204`); `quorum_reached` (`:205`) |
| Created/voted, unexecuted → deleted, once expired | `delete_expired` | `:135-149` | re-checks `!executed.contains(id)` (`:141-144`, same defensive-error-surface pattern as `execute`) **before** removing from `active`; then `is_expired` (`:147`) |

The two guards doing the real work: `execute`'s `executed.contains` check
(`:198-201`) is what makes execution **at-most-once** and, combined with
the identical check in `delete_expired`, is what prevents an already-
executed proposal from ever being deleted via the expiry path (comment at
`:138-140`: "Executed proposals... must never be deletable, even after
they expire"). `is_expired` (`:229-231`,
`clock.timestamp_ms() > created_timestamp_ms + MAX_PROPOSAL_DURATION_MS`,
7 days) gates both `vote` and `execute` — there's no separate "quorum
locked in" snapshot that could go stale between quorum being reached and
`execute` running; `quorum_reached` (`:218-227`) recomputes live from
`hashi.current_committee()` every call (see P9).

This engine is reused, uninstantiated, by every concrete proposal type
under `core/proposal/types/`: `emergency_pause.move` (asymmetric
pause/unpause thresholds — see P13), `update_guardian.move` (URL only —
see P5), `disable_version.move`/`enable_version.move` (see P14),
`update_config.move`, `upgrade.move`, and `abort_reconfig.move` (below).
Each wraps `proposal::create`/`proposal::execute` with its own payload
struct and applies the payload's effect right after (e.g.
`emergency_pause::execute`, `emergency_pause.move:47-51`, calls
`config_mut().set_paused(pause)` once `proposal::execute` hands back the
payload) — so the generic engine's at-most-once guarantee is exactly what
makes every concrete governance action at-most-once too.

**Committee reconfiguration — a separate, hand-rolled state machine, not
built on `Proposal<T>`.** Tracked independently by `CommitteeSet`
(`committee_set.move:24-31`) via
`pending_epoch_change: Option<PendingEpochChange>`,
`PendingEpochChange { epoch: u64, committee_handoff_cert:
Option<CommitteeSignature> }` (`:38-43`):

| Transition | Function | Location | Guard |
|---|---|---|---|
| Idle → Reconfiguring (pending committee formed) | `start_reconfig` (entry) → `CommitteeSet::start_reconfig` | `reconfig.move:59-79`, `committee_set.move:222-241` | `!is_reconfiguring()` (`:66`/`:224`); no committee already exists for `ctx.epoch()` (`:226`); genesis gated on `finish_publish` (`assert_genesis_launch_authorized`, `reconfig.move:149-153`) |
| Reconfiguring → handoff cert recorded (non-initial only) | `submit_committee_handoff` (entry) → `set_pending_committee_handoff_cert` | `reconfig.move:119-138`, `committee_set.move:246-252` | `is_reconfiguring()` (`:125`); current committee's cert over `CommitteeTransitionRequest` (`:131-136`); `committee_handoff_cert.is_none()` before writing (`:249`) — write-once, same pattern as P8's latches |
| Reconfiguring → Idle, epoch advances | `end_reconfig` (entry) → `CommitteeSet::end_reconfig` | `reconfig.move:81-117`, `committee_set.move:254-274` | `is_reconfiguring()` (`:88`/`:257`); next committee's cert over `ReconfigCompletionMessage` (`:93-98`); non-initial reconfigs require `committee_handoff_cert.is_some()` (`:266`); `mpc_public_key` pinned equal across reconfigs once set (`:269`) |
| Reconfiguring → Idle, epoch does **not** advance (cancel) | `abort_reconfig::execute` (governance-gated) → `CommitteeSet::abort_reconfig` | `types/abort_reconfig.move:61-71`, `committee_set.move:276-286` | routed through the generic `Proposal<AbortReconfig>` engine above (`THRESHOLD_BPS = 6667`, `abort_reconfig.move:18`) — deliberately requiring the **current** (not pending) committee's quorum, per the module doc: "the last committed committee is the only committee with stable on-chain voting power" |

So there are, in effect, two independent state machines here: the generic
quorum-vote engine (reusable, `Proposal<T>`-shaped, one execution per
`ID`), and the committee-reconfig lifecycle (bespoke,
one-in-flight-reconfig-at-a-time via `Option<PendingEpochChange>`); the
only place they touch is `abort_reconfig`, which lets the *first* engine
cancel a state in the *second*. This is the analogous table to P3's for
the governance/committee-transition side — P3 covers withdrawal/deposit/
UTXO, this covers proposals/reconfig; a "no double-processing" CVL
parametric rule would need to cover both independently.

**To verify**: `abort_reconfig::execute` re-checks `is_reconfiguring()` and
that the pending epoch still matches the proposal's captured epoch
(`abort_reconfig.move:63-70`) *after* `proposal::execute` already
consumed/archived the proposal — worth confirming this re-check is
load-bearing (i.e. there's a real reachable scenario where a proposal is
created/voted against one pending reconfig, and by the time quorum is
reached and `execute` is called, `end_reconfig` has already resolved that
same reconfig out from under it) rather than defensive-but-dead code —
nothing else found in this pass suggests `pending_epoch_change` can change
between a proposal's creation and its execution except through `end_reconfig`
or another `abort_reconfig`.

---

## Summary — where to focus first

| Property | Status | Priority |
|---|---|---|
| P1 | `pool_btc` now correctly scoped to `spent_by == none`; `>=` direction of the fee-rounding leak **not yet shown to hold** | **High — open solvency question, see note in P1** |
| P2 | Balance identity + fee cap + dust-floor composition (former P2/P7/P16) all hold on-chain, fully traceable; off-chain `estimatesmartfee` bound unverifiable in Move | Low for the on-chain part (good first CVL rule) — flag off-chain gap for Phase 9 |
| P3 | Holds via bag-membership guards, needs call-site enumeration for completeness | Medium |
| P4 | Holds, ceiling-division correct | Low — already sound |
| P5 | **Not Move-verifiable** — off-chain/Bitcoin-script scope only | Scope down to `set_guardian_btc_public_key` immutability |
| P6 | Holds, epoch pin + domain tag both enforced pre-BLS-check | Low — cross-check `intent.rs` sync (Phase 9) |
| P7 | **Unverified in this pass** — needs full entry-point enumeration | High |
| P8 | Holds via `Option`-fill semantics, one accessor unconfirmed (`treasury.move`) | Medium |
| P9 | Counter mechanics sound; `reset` safety **unverified** | **High — nonce reuse is catastrophic** |
| P10 | Holds structurally | Low |
| P11 | Only one live key today; **becomes load-bearing on next chain addition** | Medium, revisit before adding a second chain |
| P12 | Guard exists; `reconfig.move` internals **unverified** in this pass | High |
| P13 | **Unverified in this pass** — needs `proposal.move` + `emergency_pause.move` read | Medium |
| P14 | **Unverified in this pass** — needs `versioning.move` read | Medium |
| P15 | Generic proposal engine's at-most-once/expiry guards hold; reconfig's separate state machine holds structurally; `abort_reconfig`'s re-check load-bearing-ness **unverified** | Medium |
