# Hashi Withdrawal Flow — Concrete Properties (P3 refinement)

This document expands [PROPERTIES.md](PROPERTIES.md)'s P3 ("Uniqueness /
no double-processing") into a complete, concrete property list for the
**withdrawal flow** specifically — grounded in `btc/withdraw.move`,
`btc/withdrawal_queue.move`, `core/mpc_signing.move`, `btc/utxo_pool.move`,
`btc/utxo.move`, and `btc/bitcoin_state.move` — and translates each property
into the `assume / call / assert` shape used by hand-written CVLM rules.

Companion reading: [PROPERTIES_DEPOSIT.md](PROPERTIES_DEPOSIT.md) (the
deposit-side sibling of this document, same structure), PROPERTIES.md's P3
(informal version, shared across deposit/withdrawal/UTXO), and its P1
(solvency), P2 (balance identity), P7 (guard completeness) and P9
(presignature disjointness) sections — all four interlock with the
withdrawal state machine and are cross-referenced below.

Encoded withdrawal specs, all in `specs/withdraw`:
- `WITHDRAW-STATE-MACHINE` (W0, W2b, W3–W6):
  [withdraw_request_lifecycle.move](../specs/withdraw/sources/withdraw_request_lifecycle.move),
  [withdraw_txn_lifecycle.move](../specs/withdraw/sources/withdraw_txn_lifecycle.move).
- `WITHDRAW-QUEUE-MUTUAL-EXCLUSION` (W1, W2):
  [withdraw_request_mutual_exclusion.move](../specs/withdraw/sources/withdraw_request_mutual_exclusion.move),
  [withdraw_mutual_exclusion.move](../specs/withdraw/sources/withdraw_mutual_exclusion.move).
- `WITHDRAW-GATE-CHECKS` (W13):
  [withdraw_unpaused.move](../specs/withdraw/sources/withdraw_unpaused.move),
  [withdraw_not_reconfiguring.move](../specs/withdraw/sources/withdraw_not_reconfiguring.move),
  [withdraw_version_enabled.move](../specs/withdraw/sources/withdraw_version_enabled.move).
- Sanity: [withdraw_sanity.move](../specs/withdraw/sources/withdraw_sanity.move).

This document was rewritten for `testnet-1.0`, which removed the
`WithdrawalStatus` enum. W0–W6, W13 and the findings cite `testnet-1.0`
line numbers. **W7–W12 and W14–W16 still cite the pre-rebase sources**:
their substance was rechecked, and the differences are noted inline.

---

## W0 — State model

**Statement (English)**: a withdrawal request moves only forward through its
state machine: created unapproved and uncommitted, then approved, then
committed to exactly one withdrawal transaction, then archived once that
transaction is confirmed. It can be cancelled only before it is committed.
Its approval fields are always set together and never cleared, it is never
committed without approval, and once committed its link to the transaction
never changes. A withdrawal transaction also moves only forward: created
unsigned and unconfirmed, then fully signed, then confirmed at most once,
then archived.

This is the withdrawal counterpart of PROPERTIES_DEPOSIT.md's D0 and the
`DEPOSIT-STATE-MACHINE` rules in
[deposit_field_consistency.move](../specs/deposit/sources/deposit_field_consistency.move),
and the text of the `WITHDRAW-STATE-MACHINE` property.

Since `testnet-1.0`, a withdrawal request has **no status enum**, the same as
a deposit request. Its state comes from two `Option` fields plus the bag it
is in. The old `Signed` and `Confirmed` request states are gone: they are now
states of the `WithdrawalTransaction` the request is linked to.

Line numbers are from the unpatched `testnet-1.0` sources
(`btc/withdrawal_queue.move` unless stated).

```
WithdrawalRequest {
    btc_amount: u64,                                // :88  recorded at creation, never updated
    approval_cert: Option<CommitteeSignature>,      // :93  None until approve_request
    approved_timestamp_ms: Option<u64>,             // :96  None until approve_request
    withdrawal_txn_id: Option<address>,             // :100 None until commit; the "committed" marker
    btc: Balance<BTC>,                              // :102 drained at commit (burned) or cancel (refunded)
}                                                   // :85-103

WithdrawalRequestQueue {
    requests:        ObjectBag, // request_id -> WithdrawalRequest (Requested, Approved, Committed) :109
    processed:       ObjectBag, // request_id -> WithdrawalRequest (Archived only)                  :112
    withdrawal_txns: ObjectBag, // withdrawal_id -> WithdrawalTransaction (in flight or confirmed)  :115
    confirmed_txns:  ObjectBag, // withdrawal_id -> WithdrawalTransaction (archived)                :117
}                                                   // :105-118

WithdrawalTransaction {
    request_ids: vector<address>,                   // :128 the requests committed into it
    inputs: vector<Utxo>,                           // :132 locked pool UTXOs
    change_outputs: vector<OutputUtxo>,             // :138 trailing outputs
    signed_timestamp_ms: Option<u64>,               // :142 None until finalize
    confirmed_timestamp_ms: Option<u64>,            // :145 None until confirm
    signing: SigningBatch,                          // :150 per-input MPC accumulator
    guardian_signatures: Option<vector<vector<u8>>>, // :154 None until finalize (one-shot)
}                                                   // :125-155

SigningBatch { signatures: vector<MpcSig>, epoch: u64 }   // mpc_signing.move:82
MpcSig = Pending(Presig) | Signed(bytes)                  // mpc_signing.move:71-77

UtxoPool { utxo_records: Bag, spent_utxos: Bag }           // utxo_pool.move:45-48
UtxoRecord { utxo, produced_by: Option<address>,
             spent_by: Option<address>, spent_epoch: Option<u64> }  // utxo_pool.move:38-43
```

### Request states

| State | Bag | `approval_cert`, `approved_timestamp_ms` | `withdrawal_txn_id` | `btc` |
|---|---|---|---|---|
| Requested | `requests` | `None`, `None` | `None` | full |
| Approved | `requests` | `Some`, `Some` | `None` | full |
| Committed | `requests` | `Some`, `Some` | `Some(w)` | zero (burned) |
| Archived | `processed` | `Some`, `Some` | `Some(w)` | zero |
| Cancelled | none (object deleted) | — | — | refunded |

A committed request **stays in `requests`**. Only archival moves it to
`processed`. So the bag no longer separates "approved" from "committed";
`withdrawal_txn_id` does. `is_request_processing` (:421-431) reads it that
way: the link if the request is in `requests`, otherwise membership in
`processed`.

### Transaction states

| State | Bag | `guardian_signatures`, `signed_timestamp_ms` | `confirmed_timestamp_ms` |
|---|---|---|---|
| Unsigned or partly MPC-signed | `withdrawal_txns` | `None`, `None` | `None` |
| Fully signed | `withdrawal_txns` | `Some`, `Some` | `None` |
| Confirmed | `withdrawal_txns` | `Some`, `Some` | `Some` |
| Archived | `confirmed_txns` | `Some`, `Some` | `Some` |

"Fully signed" is `txn_fully_signed` (:919-921): every `signing` slot is
`Signed` **and** `guardian_signatures.is_some()`. Per-slot MPC progress
(`Pending` → `Signed`) is a separate state machine, covered by W10–W11.
Confirmation no longer moves the transaction either; archival does.

The two machines are linked: a request is Committed to `w` exactly when its
id is in `w.request_ids`, and it can only become Archived once `w` is
Confirmed.

**Four state machines run in parallel here**, and P3 for withdrawals is the
conjunction of "no double-processing" over each:

1. **Request lifecycle** (W1, W3–W6, W14): Requested → Approved → Committed →
   Archived, or → destroyed by cancel before commit.
2. **Transaction lifecycle** (W2, W9): unsigned → fully signed → confirmed →
   archived.
3. **Per-input signature accumulation** (W10–W11): `Pending` → `Signed`, per
   slot, out of order.
4. **UTXO lifecycle** (W7–W8, W12): insert → lock → mark_spent → cleanup,
   one-way.

### Entry-point → transition map

Entry points are in `btc/withdraw.move`; queue-level writers in
`btc/withdrawal_queue.move`.

| Transition | Entry | Queue-level writer | Guard |
|---|---|---|---|
| → Requested | `request_withdrawal` (:105-136) | `create_withdrawal` (:263-285) + `insert_withdrawal` (:290-296) | min amount (withdraw.move:115), address length (:119); `requests.add` aborts on a duplicate key |
| Requested → Approved, or re-approval | `approve_request` (:186-203) | `approve_withdrawal` (:300-322) | cert; `!is_committed` (:310, `ECannotApproveCommittedRequest`); no stored cert, or the new cert's epoch is strictly later (:315-319, `EApprovalCertNotNewer`); `requests.borrow_mut` aborts if absent, so an archived request can't be approved |
| Approved → Committed; txn → Unsigned | `commit_withdrawal_tx` (:208-288) | `commit_requests` (:358-377), `insert_withdrawal_txn` (:525-530) | cert; `is_approved` (:367); `!is_committed` (:370, `ERequestAlreadyCommitted`); `requests.borrow_mut` aborts if absent. The txn is built and inserted in the same call (withdraw.move:250, :287) |
| txn: record MPC signatures | `commit_input_signatures` (:295-314) | `record_input_signatures` (:556-570) | cert; not fully signed (:563) |
| txn: → Fully signed | `finalize_withdrawal` (:320-350) | `finalize_withdrawal_txn` (:575-587) | cert; not already fully signed (:582); every MPC slot signed (:583) |
| txn: reassign presigs | `reallocate_presigs` (:472-490) | `reallocate_presigs_for_withdrawal_txn` (:704-719) | no cert; stale-epoch guard in `mpc_signing` |
| txn: Fully signed → Confirmed | `confirm_withdrawal` (:352-407) | `mark_txn_confirmed` (:595-604) | cert; fully signed (withdraw.move:373-376); `confirmed_timestamp_ms.is_none()` (:601, `EWithdrawalAlreadyConfirmed`) |
| Committed → Archived; txn Confirmed → Archived | `archive_confirmed_withdrawals` (:421-426) | `archive_withdrawal_txn` (:613-630) + `archive_request` (:638-647) | no cert, no pause or reconfig gate; no-op if `w` isn't in `withdrawal_txns` (:617); txn confirmed (:620); per request: skipped if not in `requests` (:643), link must equal `w` (:645, `ERequestTxnMismatch`) |
| Committed → Archived, chunked | `archive_withdrawal_requests` (:436-446) | `archive_withdrawal_requests` (:656-667) + `archive_request` | as above, but over **caller-supplied** request ids, so the :645 link check is what stops a caller archiving another withdrawal's live request |
| txn Confirmed → Archived, chunked | `finish_archive_withdrawal_txns` (:455-460) | `finish_archive_withdrawal_txn` (:678-700) | no cert, no gate; txn confirmed (:685); silent no-op unless every one of its requests is in `processed` (:693) |
| Requested/Approved → destroyed | `cancel_withdrawal` (:150-184) | `cancel_withdrawal` (:382-407) | `!is_request_processing` (withdraw.move:158-161), sender (:166), cooldown (:170-173); `!is_committed` (:391, `ERequestNotCancellable`); `requests.remove` aborts if absent; no pause gate |

### What changed from the pre-rebase model

- The `WithdrawalStatus` enum is gone, and so are its writers
  `update_requests_signed`/`update_requests_confirmed`. F2 below is moot.
- Commit no longer moves a request from `requests` to `processed`; archival
  does. `processed` now means "archived", not "committed".
- `confirm_withdrawal` no longer moves the transaction. The only barrier
  against a replayed confirmation is now the `confirmed_timestamp_ms` guard
  (:601), not an `ObjectBag::remove` abort.
- `commit_requests` has an explicit double-commit guard (:370). Before, a
  second commit aborted only because the request had left `requests`.
- `approve_withdrawal` now rejects a committed request (:310) and requires a
  cert from a strictly later epoch to re-approve (:315-319), so W4b's "no
  epoch guard" no longer holds. It still differs from deposits:
  `approve_deposit` compares the stored cert's epoch with the **current
  committee** epoch (`!= current_epoch`, deposit.move:161), while
  `approve_withdrawal` compares it with the **new cert's** epoch (`<`).
- Three new archival entry points. They need no cert and are not gated on
  pause or reconfiguration, only on the package version.
- Both archival paths re-insert under the key they removed with
  (`processed.add(request_id, …)` :646, `confirmed_txns.add(withdrawal_id, …)`
  :629), not under the object's own id. `insert_confirmed_txn` (:547-552) and
  `remove_withdrawal_txn` (:539-544) are now unused.
- `archive_request`'s link check (:645) is a structural `==` on
  `Option<address>` **in production code**. Under the cvlm `Option` summary
  that comparison is unconstrained; see
  [Option `==` in production code](#option--in-production-code) for how
  the rules handle it.

---

## Rule-writing conventions used below

Same three readings as PROPERTIES_DEPOSIT.md — **the Prover only models
non-aborting executions**, so an abort prunes a path rather than being a
checkable outcome:

- **assert** — "if the call succeeded, X was/became true". Restates a guard
  the code already enforces as a checked postcondition. Where the guard is
  on the pre-state, snapshot it before the call and assert the snapshot
  after (the D2 technique), e.g. `was_committed` in
  `cancel_destroys_uncommitted_request`.
- **expect-unreachable** — "this sequence can never complete successfully".
  Written as: run the sequence, then `cvlm_assert(false)`. Desired result:
  **Verified / not violated** (no non-aborting path reaches the assert).
  **This supersedes PROPERTIES_DEPOSIT.md's `cvlm_satisfy_msg(true, ...)`
  formulation** — the encoded rules in
  [deposit_integrity.move](../specs/deposit/sources/deposit_integrity.move)
  (`confirm_deposit_at_most_once`, `no_same_epoch_reapproval`,
  `insert_active_rejects_duplicate`) all use `cvlm_assert(false)`, and this
  document follows that. The two-call shape (`confirm_withdrawal_at_most_once`)
  still reports `-rule_not_vacuous_tac` **Violated**, the same as D3, because
  the first call alone is a reachable execution.
- **expect-reachable** — `cvlm_satisfy_msg(true, ...)` used the normal way,
  desired result **satisfiable**, as a positive witness that intended
  behavior works (deliberate guard omissions, W14b).

**Parametric invoke signature** — the encoded withdraw rules all use the
two-argument invoker

```
native fun invoke(target: Function, hashi: &mut Hashi);
```

and read the observed `request_id`/`withdrawal_id` as a free rule
parameter. Every target argument is then nondet, which includes the case
where it equals the observed id, so this is never weaker than forwarding the
id. Forwarding is unsafe here anyway: an invoker binds an extra argument to
the target's **first parameter of that type**, and in `withdraw.move` the
first `address` parameter is `request_id` for `approve_request` and
`cancel_withdrawal`, `withdrawal_id` for five other entry points, and
`txid` for `commit_withdrawal_tx` (see the invoker gotcha in
[CLAUDE.md](../README.md)). The cost is solver focus, not coverage.

The two entry points that **create** an object are left out of the
parametric rule that would see the fresh object, and get a base-case rule
instead, exactly as `deposit` is left out of D1: `request_withdrawal` (a new
request) and `commit_withdrawal_tx` (a new transaction). A nondet pre-state
can hold the fresh id already, which no reachable state can.

**`commit_requests` is summarized, for one request.** Its loop over
`request_ids` is beyond the Prover, so
[summaries_utxo_pool.move](../specs/withdraw/sources/summaries_utxo_pool.move)
replaces it. The summary runs the real loop body, `commit_request`
(extracted by the `withdrawal_queue.move` patch), for the one ghost request
`tracked_request()`, and only if `vector::contains` reports it in the
transaction's `request_ids`. Every rule about a request pins it with
`cvlm_assume(tracked_request() == request_id)`. Two consequences:

- `contains` is a ghost, not tied to the vector's contents, so the summary
  may commit the tracked request into a transaction that doesn't list it,
  or skip it. That over-approximates, and it's harmless for rules that only
  look at the tracked request's own fields. A rule that calls
  `commit_withdrawal_tx` directly assumes `request_ids.contains(&request_id)`
  on the same vector value, so it reads the same ghost slot the summary does.
- Requests other than the tracked one are left untouched, so no rule may
  observe a second request across a commit.

Before the rebase this summary returned an opaque balance and touched no
request at all, so the old W3 rules never exercised the commit transition.

**Modeling gotchas** (the first three are from [CLAUDE.md](../README.md)):

1. **Never `==`/`!=` on `Option<T>`** — `approval_cert`,
   `approved_timestamp_ms`, `withdrawal_txn_id`, `guardian_signatures`,
   `signed_timestamp_ms`, `confirmed_timestamp_ms`, `produced_by`,
   `spent_by`, `spent_epoch` are all `Option`. Compare via
   `is_none()`/`is_some()` (+ `borrow()` for the inner value). Production
   code does it once, in `archive_request`'s link check (:645); see
   [Option `==` in production code](#option--in-production-code) below.
2. **Assume all four bags are distinct objects, not just the pair a rule
   reads.** A fully-`nondet` `WithdrawalRequestQueue` may model any two of
   its four `ObjectBag`s as one backing object, which makes a write to one
   visible through the other. The first run of the mutual-exclusion rules hit
   this on five pairs: e.g. `request_withdrawal`'s insert into `requests`
   showed up in `withdrawal_txns`, because the pre-state gave both the same
   UID. Every withdraw rule assumes
   `withdraw_queue_helpers::queue_bags_distinct` (all six pairs), which holds
   in every reachable state because `withdrawal_queue::create` gives each bag
   a fresh UID.
3. **Bag keys vs. object ids.** The pre-rebase flow re-inserted a removed
   object under its *own* id (`insert_confirmed_txn`), which needed the
   `key_matches_object` assumption. On `testnet-1.0` both archival moves
   re-insert under the key they removed with (`processed.add(request_id, …)`
   :646, `confirmed_txns.add(withdrawal_id, …)` :629), and the only
   own-id inserts are of fresh objects (`insert_withdrawal`,
   `insert_withdrawal_txn`). The encoded rules don't need the assumption.
4. **Conjoin the invariants already proven.** A fully-`nondet` pre-state
   breaks invariants that other rules prove, and two of them caused spurious
   counterexamples here:
   - A request in **both** `requests` and `processed`. After
     `cancel_withdrawal` removes the live copy, `borrow_either` reads the
     archived copy instead. So every rule that reads through
     `exists_request`/`borrow_either` (or the transaction equivalents) assumes
     W1's (or W2's) mutual exclusion for the observed id, through
     `withdraw_queue_helpers::request_in_one_bag`/`txn_in_one_bag`.
   - A transaction with `guardian_signatures` set but `signed_timestamp_ms`
     unset. `confirm_withdrawal` checks only the guardian half, so
     `confirmed_implies_signed` also assumes `signed_fields_paired` before
     the call.

   The same counterexample showed two `withdrawal_txns` keys resolving to
   one `WithdrawalTransaction` object, the pre-rebase W3 artifact. None of
   the encoded rules depends on it.

### Option `==` in production code

`archive_request` checks `request.withdrawal_txn_id == option::some(withdrawal_id)`
(:645). Under the cvlm summary, `option::some` returns a nondet `Option` with
a separate shadow, and `==` compares the underlying values, not the shadows.
The guard is **not patched**: `archive_moves_only_linked_request` and
`archived_implies_committed`, the two rules that depend on it, verify
non-vacuously with it as written (see the summary table). So in practice
the comparison never let an unlinked request through. A spurious failure of
the check would only prune paths, which the non-vacuity results rule out as
a blanket effect. *Why* a spurious pass never happens is not established; a
likely reason is that the shadow is keyed by the underlying value, so equal
values imply equal shadows. If either rule ever gets a counterexample
through :645, the patch is to rewrite the check as
`withdrawal_txn_id.is_some() && *withdrawal_txn_id.borrow() == withdrawal_id`,
which means the same in Move.

---

## W1 — Request bag-membership mutual exclusion

**Statement (English)**: for every `request_id`, it is in **at most one** of
`{requests, processed}` — never both. Direct analogue of D1.

**Grounding**: `insert_withdrawal` (:290-296) is the only writer of
`requests` and only inserts a fresh object. `cancel_withdrawal` (:386) and
`archive_request` (:644) are the only removers, both via `ObjectBag::remove`,
which aborts if the key is absent. `archive_request` (:646) is the only
writer of `processed`, and **nothing removes from `processed`**. The
remove-then-add in `archive_request` (:644 → :646) is the only transfer
between the two bags; `processed.add` aborts on a duplicate key.

Commit no longer moves a request (W0), so before the rebase this property
was about commit, and now it is about archival. `finish_archive_withdrawal_txn`
(:688-693) relies on it in its comment: "a committed request lives in
exactly one bag", so probing `processed` alone tells whether it is archived.

**Encoded** as
[withdraw_request_mutual_exclusion.move](../specs/withdraw/sources/withdraw_request_mutual_exclusion.move)
(`WITHDRAW-QUEUE-MUTUAL-EXCLUSION`):

- `withdrawal_request_mutual_exclusion` — parametric over every withdraw
  entry point except `request_withdrawal`.
- `request_withdrawal_does_not_create_duplicate_request` — the base case,
  assuming the observed id starts absent from **both** bags (nothing ties a
  nondet key in `processed` to Sui's object-freshness ghost).

---

## W2 — Transaction bag-membership mutual exclusion

**Statement (English)**: for every `withdrawal_id`, it is in **at most one**
of `{withdrawal_txns, confirmed_txns}` — never both.

**Grounding**: `insert_withdrawal_txn` (:525-530) is the only writer of
`withdrawal_txns`, called once from `commit_withdrawal_tx`
(withdraw.move:287) with a fresh object. The only removers are
`archive_withdrawal_txn` (:624) and `finish_archive_withdrawal_txn` (:694),
and each re-adds the same key to `confirmed_txns` right after (:629, :699);
`confirmed_txns.add` aborts on a duplicate. Nothing removes from
`confirmed_txns`. `remove_withdrawal_txn` and `insert_confirmed_txn` still
exist but have no callers.

**Before the rebase, `confirm_withdrawal` did this move.** It now confirms
in place (W0), so the rule's old target list (`commit_input_signatures`,
`finalize_withdrawal`, `confirm_withdrawal`, `reallocate_presigs`) contained
no entry point that moves a transaction between the bags at all.

**Encoded** as
[withdraw_mutual_exclusion.move](../specs/withdraw/sources/withdraw_mutual_exclusion.move)
(`WITHDRAW-QUEUE-MUTUAL-EXCLUSION`):

- `withdrawal_txn_mutual_exclusion` — now parametric over every withdraw
  entry point except `commit_withdrawal_tx`, including the three archival
  ones, with the two-argument invoker (see the conventions above).
- `commit_withdrawal_tx_does_not_create_duplicate_txn` — the base case,
  unchanged.

**W2b — no double confirm.** `confirm_withdrawal` succeeds at most once per
`withdrawal_id`. The transaction stays in `withdrawal_txns` after
confirmation, so the barrier is no longer an `ObjectBag::remove` abort.
It is now `mark_txn_confirmed`'s `confirmed_timestamp_ms.is_none()` guard
(:601, `EWithdrawalAlreadyConfirmed`). The comment at :589-594 calls it
"load-bearing replay protection". After archival, the second call aborts
earlier, in `withdrawal_txn_is_fully_signed`'s borrow from
`withdrawal_txns`. Encoded as `confirm_withdrawal_at_most_once` in
[withdraw_txn_lifecycle.move](../specs/withdraw/sources/withdraw_txn_lifecycle.move),
under `WITHDRAW-STATE-MACHINE`.

---

## W3 — Field/bag coherence

**Statement (English)**: a request's fields agree with each other and with
its bag. Its two approval fields are both set or both unset; a committed
request is approved; and a request in `processed` is committed. A
transaction's two signing fields are both set or both unset; a confirmed
transaction is signed; and a transaction in `confirmed_txns` is confirmed.

This replaces the pre-rebase status/bag coherence. The enum is gone, so the
redundancy is now between `Option` fields and bag membership.

**Grounding**:

- `approve_withdrawal` writes both approval fields together (:320-321);
  nothing clears either.
- `commit_requests` asserts `is_approved` (:367) before setting the link
  (:373).
- `archive_request` moves a request to `processed` only after checking its
  link equals the archiving `withdrawal_id` (:645), which implies committed.
- `finalize_withdrawal_txn` writes both signing fields together (:584-585).
- `confirm_withdrawal` asserts the transaction is fully signed
  (withdraw.move:373-376) before `mark_txn_confirmed` sets the timestamp.
- Both archival paths move a transaction only after asserting
  `confirmed_timestamp_ms.is_some()` (:620, :685).

**Encoded** in
[withdraw_request_lifecycle.move](../specs/withdraw/sources/withdraw_request_lifecycle.move)
(`approval_fields_paired`, `committed_implies_approved`,
`archived_implies_committed`) and
[withdraw_txn_lifecycle.move](../specs/withdraw/sources/withdraw_txn_lifecycle.move)
(`signed_fields_paired`, `confirmed_implies_signed`,
`archived_txn_is_confirmed`), all parametric under `WITHDRAW-STATE-MACHINE`.

---

## W4a — Forward-only lifecycle

**Statement (English)**: no field that marks progress is ever cleared or
changed. An approved request stays approved. A committed request stays
committed **to the same transaction**, and is never destroyed. A signed
transaction stays signed, and a confirmed one stays confirmed; neither is
ever removed.

**Grounding**: no writer assigns `None` to `approval_cert`,
`withdrawal_txn_id`, `guardian_signatures`, `signed_timestamp_ms` or
`confirmed_timestamp_ms`. `commit_requests` sets the link only on an
uncommitted request (:370). `cancel_withdrawal` is the only destroyer of a
request, and it asserts `!is_committed` (:391) after
`!is_request_processing` (withdraw.move:158-161) has already refused. The
old monotonicity gap is gone with its writers: `update_requests_signed`
could write `Signed` over `Confirmed` (old F1, F2).

**Encoded** as `approval_never_reset` and `commit_link_never_changes`
(request) and `signed_never_reset` and `confirmed_never_reset`
(transaction), all parametric under `WITHDRAW-STATE-MACHINE`.

---

## W4b — Re-approval needs a later-epoch certificate

**Statement (English)**: `approve_request` on an already-approved request
succeeds only with a certificate from a strictly later epoch than the stored
one, and never on a committed request.

**Grounding**: `approve_withdrawal` asserts `!is_committed` (:310,
`ECannotApproveCommittedRequest`) and
`approval_cert.is_none() || stored.signature_epoch() < cert.signature_epoch()`
(:315-319, `EApprovalCertNotNewer`). The pre-rebase version had neither
guard, which is what the old W4b documented.

This is **not** the deposit guard. `approve_deposit` compares the stored
cert's epoch with the **current committee** epoch (`!= current_epoch`,
deposit.move:161), so it allows any re-approval in a new epoch.
`approve_withdrawal` compares it with the **new cert's** epoch (`<`), so
re-approval needs a strictly newer cert. The withdrawal timestamp is still
write-only bookkeeping: `commit_requests` reads only `is_approved`, and the
cancellation cooldown is measured from `created_timestamp_ms`.

**Encoded** as `reapproval_requires_later_epoch` and
`approve_request_sets_approval_fields` (which also asserts the request
was uncommitted), under `WITHDRAW-STATE-MACHINE`.

---

## W5 — Commit consumes each request exactly once

**Statement (English)**: a request is committed to a `WithdrawalTransaction`
**at most once**, only when approved, and a single `commit_withdrawal_tx`
cannot commit the same request twice.

**Grounding**: `commit_requests`' loop body (:365-374; the patch extracts it
as `commit_request`), per request:

1. `self.requests.borrow_mut(id)` — aborts if absent, so an archived or
   cancelled request can't be committed.
2. `assert!(is_approved, ERequestNotApproved)` (:367).
3. `assert!(!is_committed, ERequestAlreadyCommitted)` (:370) — the only
   double-commit guard now that the request stays in `requests`. The
   comment explains why it matters: "a second commit would pay the user's
   Bitcoin output again without burning any BTC". A duplicate id within one
   `request_ids` hits it on its second iteration.

**Duplicate inputs** still run arithmetic before the abort.
`extract_request_infos` (:339-350) borrows a duplicated request twice and
`count_requests` counts it twice, lowering `per_user_miner_fee`, before
`commit_requests` aborts at (3). A duplicated `selected_utxo` is double-counted
by `sum_input_amounts` before `lock` aborts on it (`EUtxoAlreadyLocked`).
Both abort as a whole, so nothing is persisted.

**Encoded** as `commit_links_approved_request`: a successful commit
of a listed request was called when it was approved and uncommitted, and
leaves it live, approved and linked to a transaction in `withdrawal_txns`.
The within-call duplicate isn't encoded. The summary applies the body once
per call, so it can't see a second iteration.

---

## W6 — Burn/refund mutual exclusion (the double-spend core)

**Statement (English)**: a request's BTC is either **burned** (committed) or
**refunded** (cancelled) — never both.

**Grounding**:

- Burn path: `commit_requests` drains `request.btc.withdraw_all()` (:372)
  and links the request; `commit_withdrawal_tx` burns the merged balance
  (withdraw.move:276). The request stays in `requests` until archival, then
  in `processed` for good.
- Refund path: `cancel_withdrawal` (:382-407) removes the request, asserts
  `!is_committed` (:391), destructures it and returns the balance; the
  object is deleted.

After commit, cancel is blocked **twice**: the entry-level
`!is_request_processing` (withdraw.move:158-161), which reads the link
first, and the queue-level `!is_committed` (:391). The second is new and
is the real backstop: before the rebase, cancel was blocked by bag
membership, and a committed request is now still in `requests`. After
cancel, the object no longer exists, so commit's `borrow_mut` aborts.

**Encoded** as `cancel_destroys_uncommitted_request` (a successful cancel
was on an uncommitted request and leaves it in neither bag) plus
`commit_link_never_changes` (a committed request is never destroyed by any
entry point). The balance side (`btc.value() == 0` after commit) is W15.

---

## W7 — UTXO lock is write-once (no input double-spend)

**Statement (English)**: every pool UTXO is locked to **at most one**
withdrawal transaction, ever; `spent_by` transitions `None → Some(id)` at
most once and is never cleared.

**Grounding**: `lock` (utxo_pool.move:120-124) is the **only** writer of
`spent_by` — confirmed by grep — and it asserts `record.spent_by.is_none()`
(`EUtxoAlreadyLocked`, :122) before writing `Some` (:123). There is no
unlock: the doc comment says so explicitly (":32-34", "there is no unlock,
so this withdrawal will spend it"), and `confirm_pending` (:136-141)
deliberately clears only `produced_by` (:139), leaving `spent_by` intact —
called out in its own comment (:133-135). This is the same one-way-latch
shape as P8's `finish_publish` write-once fields.

Two `commit_withdrawal_tx` calls selecting the same UTXO therefore cannot
both succeed: the second's `lock_input_utxos` (withdraw.move:194-198) aborts.

**Selection does not check the lock.** `get_utxo` (:114-117) reads
`record.utxo` with no `spent_by` consultation, so `commit_withdrawal_tx`
copies an already-locked UTXO (withdraw.move:144), sums it into
`input_amount`, builds and *creates* the `WithdrawalTransaction` object
(:156-168) — and only then aborts at `lock` (:174 → :196). Correct outcome
(the whole transaction rolls back, a VM guarantee), but the eligibility
check lives at the writer, not at selection. Exactly D6's shape, and the
same caveat applies: the ordering argument rests on Move/Sui transaction
atomicity, **not** on anything a `cvlm_assert` can characterize — an audit
note, not a rule.

**Rule shape**: expect-unreachable at the pool level (no entry-point
plumbing needed, `lock` is already public), plus an assert-style
never-cleared invariant.

```
fun lock_rejects_already_locked(pool: &mut UtxoPool, utxo_id: UtxoId, w1: address, w2: address) {
    pool.lock(utxo_id, w1);   // succeeds
    pool.lock(utxo_id, w2);   // same UtxoId, second withdrawal

    cvlm_assert(false);       // desired: Verified (unreachable)
}

fun spent_by_never_cleared(hashi: &mut Hashi, utxo_id: UtxoId, target: Function) {
    let was_locked = hashi.bitcoin().utxo_pool().get_utxo_record_spent_by(utxo_id).is_some();

    invoke(target, hashi, utxo_id);   // parametric over confirm_withdrawal, cleanup_spent_utxos, commit_withdrawal_tx

    let pool2 = hashi.bitcoin().utxo_pool();
    // a cleaned-up record leaves utxo_records entirely (W8) — only assert while present
    if (pool2.has_active_record(utxo_id)) {
        cvlm_assert(pool2.get_utxo_record_spent_by(utxo_id).is_some() || !was_locked);
    };
}
```

Note the `has_active_record` guard: `get_utxo_record_spent_by` (:222-229)
returns `option::none()` for an *absent* record, which is indistinguishable
from a present-but-unlocked one. Without the guard, `cleanup_spent`
removing the record reads as `spent_by` being cleared — a spurious
counterexample. This aliasing of "absent" and "unlocked" in the existing
test accessor is worth keeping in mind for every rule that reads it.

**Needs**: nothing — `lock` is already `public` (:120),
`get_utxo_record_spent_by` and `has_active_record` are already
`#[test_only] public` (:222, :160).

---

## W8 — Spend bookkeeping is one-way, and the replay latch is permanent

**Statement (English)**: `mark_spent` → `cleanup_spent` is a one-way
sequence ending in a permanent `spent_utxos` entry; after cleanup, that
`UtxoId` can never re-enter `utxo_records` via `insert_active`.

**Grounding**:
- `mark_spent` (:126-130) sets `spent_epoch = Some(epoch)` (:128). Called
  only from `confirm_withdrawal` over `txn.inputs` (withdraw.move:317-319).
- `cleanup_spent` (:146-155) is guarded by `if contains` (:147) — so it
  **no-ops** if already cleaned, making it idempotent — removes the record
  (:148-150), requires `spent_epoch.destroy_some()` (:151, aborts if
  `mark_spent` never ran), and adds to `spent_utxos` (:153).
- `assert_not_spent_or_active` (:109-111) on `is_spent_or_active` (:105-107,
  `utxo_records.contains || spent_utxos.contains`) then blocks
  re-insertion forever, from `insert_active` (:70).

**Ordering is enforced locally here**, unlike most of this module:
`cleanup_spent` cannot precede `mark_spent`, because `destroy_some` on
`spent_epoch` aborts. That's the one place in the UTXO lifecycle where the
sequence is guarded by the callee rather than by call-site reachability. It
is also why P1's argument works: `cleanup_spent` provably only ever removes
records that were already excluded from `pool_btc` (they have
`spent_by = Some`, since `mark_spent` only runs on a locked txn input).

**Two unenforced links**, both call-site-reachability arguments:

1. `mark_spent` does **not** assert `spent_by.is_some()`, nor that
   `spent_epoch` was previously `None`. It can mark a never-locked UTXO
   spent, and can overwrite an existing `spent_epoch` with a different one.
   Safe today only because its sole caller iterates `txn.inputs`, every one
   of which was locked at commit time (W7) and whose txn can only be
   confirmed once (W2b). See **Finding F4**.
2. ~~`insert_pending` omits `assert_not_spent_or_active`~~ — fixed on
   `testnet-1.0`, which added the check (Finding F3). The latch is now
   symmetric between the two insert paths.

**Rule shape**: expect-unreachable for the latch, assert-style for the
ordering.

```
fun cleanup_makes_reinsertion_impossible(pool: &mut UtxoPool, utxo: Utxo, epoch: u64) {
    let utxo_id = utxo.id();
    pool.mark_spent(utxo_id, epoch);
    pool.cleanup_spent(utxo_id);
    pool.insert_active(utxo);       // same UtxoId, now in spent_utxos

    cvlm_assert(false);             // desired: Verified (unreachable)
}

fun cleanup_requires_mark_spent(pool: &mut UtxoPool, utxo_id: UtxoId) {
    cvlm_assume_msg(pool.has_active_record(utxo_id), b"record present, so cleanup won't no-op");
    let was_marked = pool.get_utxo_record_spent_epoch(utxo_id).is_some();

    pool.cleanup_spent(utxo_id);

    cvlm_assert(was_marked);        // restates the destroy_some guard (:151)
    cvlm_assert(pool.has_spent_record(utxo_id));
    cvlm_assert(!pool.has_active_record(utxo_id));
}

// The pending-insert counterpart; testnet-1.0 added the guard (Finding F3):
fun insert_pending_rejects_spent(pool: &mut UtxoPool, utxo: Utxo, epoch: u64, w: address) {
    let utxo_id = utxo.id();
    pool.mark_spent(utxo_id, epoch);
    pool.cleanup_spent(utxo_id);    // utxo_id now permanently in spent_utxos
    pool.insert_pending(utxo, w);   // assert_not_spent_or_active aborts

    cvlm_assert(false);             // desired: Verified (unreachable)
}
```

The `has_active_record` assumption in the second rule matters: without it,
`cleanup_spent`'s `if contains` guard (:147) lets the whole call no-op, and
`was_marked` is then unconstrained — the rule would pass vacuously for the
wrong reason.

**Needs**: `get_utxo_record_spent_epoch` (**new**), `has_spent_record` (bump
from `#[test_only] public(package)` → `public`, :165), `insert_pending`
(bump `public(package)` → `public`, :89). `mark_spent`, `cleanup_spent`,
`insert_active` are already `public`.

---

## W9 — Guardian signatures write-once; fully-signed is a latch

**Statement (English)**: `guardian_signatures` transitions `None → Some` **at
most once** per withdrawal transaction, and only when every input already
has an MPC signature; once set, the transaction is permanently
"fully signed" and neither signature array can change.

**Grounding**, and this one is a genuinely *composed* argument rather than a
single assert:

- `finalize_withdrawal_txn` (:526-538) asserts `!txn.txn_fully_signed()`
  (:533, `EWithdrawalAlreadyFinalized`) and `txn.signing.is_complete()`
  (:534, `EWithdrawalNotFullySigned`), then writes
  `guardian_signatures = some(...)` (:535) and `signed_timestamp_ms` (:536).
- `txn_fully_signed` (:757-759) is **derived, not stored**:
  `signing.is_complete() && guardian_signatures.is_some()`. Its own comment
  (:754-756) says this is deliberate, so it "can't fall out of sync".
- So after a successful finalize, both conjuncts hold ⇒ `txn_fully_signed()`
  is true ⇒ a second finalize aborts at :533. **Write-once.**

The latch only holds if `signing.is_complete()` is **monotone** — if a
signature could be un-recorded, `is_complete()` could go false again and
re-open finalize. It is monotone, for two reasons in `mpc_signing`:
`record` (:104-121) writes a slot only `if (self.signatures.borrow(i).is_pending())`
(:116-118), so `Signed` slots are never overwritten (W10); and `reallocate`
(:132-151) rewrites **only** `Pending` slots (:144-145), never touching
`Signed` ones. Hence `signed_count` (:170-181) is non-decreasing and
`is_complete()` (:162-164) is a latch. **W9 depends on W10 — prove W10
first.**

`record_input_signatures` (:507-521) carries the same
`!txn_fully_signed()` guard (:514), so no signature chunk can land after
finalization either.

**Rule shape**: expect-unreachable for double-finalize, assert-style for the
precondition and the latch.

```
fun finalize_at_most_once(hashi: &mut Hashi, withdrawal_id: address, ids: vector<address>, gsigs: vector<vector<u8>>, cert1: CommitteeSignature, cert2: CommitteeSignature, clock: &Clock) {
    hashi::withdraw::finalize_withdrawal(hashi, withdrawal_id, gsigs, cert1, clock);
    hashi::withdraw::finalize_withdrawal(hashi, withdrawal_id, gsigs, cert2, clock);

    cvlm_assert(false);   // desired: Verified (unreachable)
}

fun finalize_requires_complete_mpc_set(hashi: &mut Hashi, withdrawal_id: address, /* ... */) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"txn is in flight pre-call");
    let txn = queue.borrow_withdrawal_txn(withdrawal_id);
    let pending_before = txn.txn_pending_count();
    let had_guardian_sigs = txn.txn_guardian_signatures_set();

    hashi::withdraw::finalize_withdrawal(hashi, withdrawal_id, gsigs, cert, clock);

    cvlm_assert(pending_before == 0);      // restates signing.is_complete() (:534)
    cvlm_assert(!had_guardian_sigs);       // restates !txn_fully_signed() (:533)

    let txn2 = hashi.bitcoin().withdrawal_queue().borrow_withdrawal_txn(withdrawal_id);
    cvlm_assert(txn2.txn_guardian_signatures_set());
    cvlm_assert(txn2.txn_signed_timestamp_ms().is_some());
}

fun fully_signed_is_a_latch(hashi: &mut Hashi, withdrawal_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"txn is in flight pre-call");
    let was_fully_signed = queue.borrow_withdrawal_txn(withdrawal_id).txn_is_fully_signed();

    invoke(target, hashi, withdrawal_id);   // commit_input_signatures, finalize_withdrawal, reallocate_presigs

    let queue2 = hashi.bitcoin().withdrawal_queue();
    if (queue2.contains_withdrawal_txn(withdrawal_id)) {
        cvlm_assert(queue2.borrow_withdrawal_txn(withdrawal_id).txn_is_fully_signed() || !was_fully_signed);
    };   // archival moves it to confirmed_txns, hence the guard
}
```

Note `finalize_requires_complete_mpc_set` uses `pending_count() == 0` rather
than an `is_complete()` accessor — one fewer accessor to add, and equivalent
by :162-164.

**On `testnet-1.0`**: `finalize_withdrawal` no longer takes `request_ids`
(F1). Part of W9 is encoded under `WITHDRAW-STATE-MACHINE`:
`signed_fields_paired`, `signed_never_reset` and
`finalize_sets_signed_fields`. The write-once half (`finalize_at_most_once`)
and the `is_complete` precondition are not, because they need the
signing-batch accessors.

**Needs** (object-level accessors on `&WithdrawalTransaction`, so they work
for txns in **either** bag): `txn_is_fully_signed`, `txn_pending_count`,
`txn_signing_epoch` — **new**. Already added: `borrow_withdrawal_txn`,
`borrow_confirmed_txn`, `withdrawal_txn_has_guardian_signatures` (the
sketch's `txn_guardian_signatures_set`),
`withdrawal_txn_signed_timestamp_ms`, `withdrawal_txn_confirmed_timestamp_ms`.

---

## W10 — Per-input signature slot is write-once (first-writer-wins)

**Statement (English)**: once input `i`'s slot is `Signed(bytes)`, those
bytes are immutable — no later `record` or `reallocate` can change or
un-set them.

**Grounding**: `record` (:104-121) gates the write on
`if (self.signatures.borrow(i).is_pending())` (:116) — an already-`Signed`
slot is skipped, not overwritten. The doc comment (:92-95) states this as
first-writer-wins "both within a call and across calls", making retries,
duplicate indices within one `indices` vector, and briefly overlapping
leaders all idempotent. `reallocate` (:132-151) touches only `Pending` slots
(:144). Nothing else writes `signatures`.

**Why it's load-bearing, not just tidy**: `finalize_withdrawal` reads the
completed MPC set back out of the batch
(`withdrawal_txn_mpc_signatures`, withdraw.move:254-257) and includes it in
the `WithdrawalSignedMessage` the committee certifies (:259-265). If a slot
could be overwritten after that read, the certified bytes and the bytes
`emit_withdrawal_signed` (:722-729) publishes for broadcast could diverge —
the cert would attest to a witness that isn't the one broadcast. W9's
`!txn_fully_signed()` guard on `record_input_signatures` (:514) closes the
window after finalize; W10 closes it before.

This is also the nonce-safety-adjacent half of P9: a slot that flipped
`Signed → Pending` would get a **fresh** presig index from the next
`reallocate` while its old signature was already published — signing two
different sighashes under one nonce. `record`'s `is_pending` gate is what
prevents that, so this rule is worth proving even though it looks like a
one-liner.

**Rule shape**: assert-style, direct.

```
fun signed_slot_is_immutable(hashi: &mut Hashi, withdrawal_id: address, i: u64, indices: vector<u64>, sigs: vector<vector<u8>>, cert: CommitteeSignature) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"txn is in flight pre-call");
    let txn = queue.borrow_withdrawal_txn(withdrawal_id);
    cvlm_assume_msg(i < txn.txn_num_inputs(), b"i is a valid input index");
    let was_signed = txn.txn_input_is_signed(i);
    let sig_before = txn.txn_input_signature(i);   // Option<vector<u8>>

    hashi::withdraw::commit_input_signatures(hashi, withdrawal_id, indices, sigs, cert);

    let txn2 = hashi.bitcoin().withdrawal_queue().borrow_withdrawal_txn(withdrawal_id);
    if (was_signed) {
        cvlm_assert(txn2.txn_input_is_signed(i));
        cvlm_assert(*txn2.txn_input_signature(i).borrow() == *sig_before.borrow());
    };
    cvlm_assert(txn2.txn_input_is_signed(i) || !was_signed);   // monotone: never un-signs
}

fun signed_count_is_monotone(hashi: &mut Hashi, withdrawal_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"txn is in flight pre-call");
    let pending_before = queue.borrow_withdrawal_txn(withdrawal_id).txn_pending_count();

    invoke(target, hashi, withdrawal_id);   // commit_input_signatures, reallocate_presigs, finalize_withdrawal

    let queue2 = hashi.bitcoin().withdrawal_queue();
    if (queue2.contains_withdrawal_txn(withdrawal_id)) {
        cvlm_assert(queue2.borrow_withdrawal_txn(withdrawal_id).txn_pending_count() <= pending_before);
    };
}
```

`signed_count_is_monotone` is the cheaper of the two and is the one W9
actually depends on — `pending_count` non-increasing is exactly
`signed_count` non-decreasing (:157-159). Prove it first.

**Needs**: `txn_num_inputs`, `txn_input_is_signed`, `txn_input_signature`
(**new** object-level; `mpc_signing::is_signed` (:192-195) exists but
`SigningBatch`'s fields are private to that module and the batch is embedded
field-private in `WithdrawalTransaction`, so the accessor must be added on
the *queue* side and delegate). `txn_pending_count` as in W9.

---

## W11 — Presignature index disjointness (withdrawal instance of P9)

**Statement (English)**: no presignature index is ever assigned to two
different input slots — within one batch, across batches in one epoch, or
across a stale-epoch reallocation. Nonce reuse in threshold Schnorr leaks
the committee's key share, so this is the highest-severity property in the
withdrawal flow.

**Grounding**, four mechanisms that must hold *together*:

1. **Within a fresh batch**: `mpc_signing::new` (:79-88) assigns
   `Pending(presig_base + i)` for `i ∈ [0, num_inputs)` (:84) — distinct by
   construction. `assert!(num_inputs > 0, EZeroInputs)` (:80).
2. **Across batches in one epoch**: the caller's block is reserved by
   `hashi::allocate_presigs` (`hashi.move:230-234`), a strictly-monotonic
   counter. `commit_withdrawal_tx` reserves `inputs.length()`
   (withdraw.move:150) and passes the returned `start` straight into
   `new_withdrawal_txn` (:164) → `mpc_signing::new` (:458). Block sizes
   match exactly, so blocks are disjoint.
3. **On reallocation**: `reallocate` (:132-151) assigns `Pending(new_base + j)`
   to the *j*-th still-`Pending` slot in ascending order (:144-146), and
   asserts `allocated_count == pending_count(self)` (:139,
   `EAllocationMismatch`). Its comment (:126-130) spells out why: under-
   allocating would assign indices past the reserved block, letting the
   monotonic allocator hand the same index to another batch. The caller
   satisfies this by construction — `reallocate_presigs`
   (withdraw.move:342-353) reads `pending_count` (:347), allocates exactly
   that many (:348), and passes both (:349-352).
4. **No double reallocation within an epoch**:
   `assert!(self.epoch != current_epoch, ENotStale)` (:138), with
   `self.epoch = current_epoch` at the end (:150). So a batch can be
   reallocated **at most once per epoch** — this is what bounds
   `reallocate_presigs`'s otherwise **uncertified** entry point
   (documented at withdraw.move:337-341: "Carries no committee cert ...
   bounded to once-per-withdrawal-per-epoch by the `mpc_signing`
   stale-epoch guard").

That last point deserves emphasis: `reallocate_presigs` is the **only**
withdrawal entry function with no `hashi.verify` call, so `ENotStale` is the
sole thing standing between a permissionless caller and unbounded presig
consumption. Worth its own rule.

Note the *cross-epoch* claim (an index from epoch N is never reused in
epoch N+1) is **not** established by anything in `mpc_signing` — it depends
on `reset_num_consumed_presigs` (`hashi.move:236-238`), which deliberately
breaks the allocator's monotonicity at epoch boundaries. That is exactly
PROPERTIES.md **P9's open question**, and it is out of scope for this
document: it must be discharged against `reconfig.move`'s call sites, not
against the withdrawal flow. Everything provable *here* is within-epoch.

**Rule shape**: assert-style for the allocation-size link and the
once-per-epoch bound; expect-unreachable for double reallocation.

```
fun reallocate_at_most_once_per_epoch(hashi: &mut Hashi, withdrawal_id: address) {
    hashi::withdraw::reallocate_presigs(hashi, withdrawal_id);   // succeeds (batch was stale)
    hashi::withdraw::reallocate_presigs(hashi, withdrawal_id);   // no epoch change in between

    cvlm_assert(false);   // desired: Verified (unreachable) — ENotStale (:138)
}

fun reallocate_leaves_batch_on_current_epoch(hashi: &mut Hashi, withdrawal_id: address) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"txn is in flight pre-call");
    let epoch_before = queue.borrow_withdrawal_txn(withdrawal_id).txn_signing_epoch();
    let current_epoch = hashi.committee_set().epoch();
    let pending_before = queue.borrow_withdrawal_txn(withdrawal_id).txn_pending_count();

    hashi::withdraw::reallocate_presigs(hashi, withdrawal_id);

    cvlm_assert(epoch_before != current_epoch);   // restates ENotStale
    let txn2 = hashi.bitcoin().withdrawal_queue().borrow_withdrawal_txn(withdrawal_id);
    cvlm_assert(txn2.txn_signing_epoch() == current_epoch);
    cvlm_assert(txn2.txn_pending_count() == pending_before);   // reallocation re-points, never re-opens slots
}

fun reallocated_indices_are_within_the_reserved_block(hashi: &mut Hashi, withdrawal_id: address, i: u64) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"txn is in flight pre-call");
    let txn = queue.borrow_withdrawal_txn(withdrawal_id);
    cvlm_assume_msg(i < txn.txn_num_inputs(), b"i is a valid input index");
    let pending_before = txn.txn_pending_count();
    let consumed_before = hashi.num_consumed_presigs();

    hashi::withdraw::reallocate_presigs(hashi, withdrawal_id);

    let txn2 = hashi.bitcoin().withdrawal_queue().borrow_withdrawal_txn(withdrawal_id);
    let idx = txn2.txn_input_pending_index(i);
    if (idx.is_some()) {
        let v = *idx.borrow();
        cvlm_assert(v >= consumed_before);
        cvlm_assert(v < consumed_before + pending_before);
    };
}
```

The third rule is the one that actually catches an off-by-one in the
`allocated_count == pending_count` link — it says every re-pointed index
falls inside the block `[consumed_before, consumed_before + pending_count)`
that `allocate_presigs` just reserved. **Pairwise distinctness** of the
indices within the batch is the natural companion, but needs a quantified
statement over two indices; write it as a two-index rule
(`i != j ⇒ pending_index(i) != pending_index(j)`) rather than trying to
express a whole-vector property.

**Needs**: `txn_signing_epoch`, `txn_pending_count`, `txn_num_inputs`,
`txn_input_pending_index` (**new** object-level, delegating to
`mpc_signing::pending_index`, :198-204), and `num_consumed_presigs`
(**new** on `Hashi` — the field is read only via the `public(package)`
`allocate_presigs`, `hashi.move:230-234`).

---

## W12 — Change UTXO id derivation is injective and consistent

**Statement (English)**: the change UTXO ids a withdrawal inserts into the
pool are exactly the ids it later promotes and reports — and within one
transaction they are pairwise distinct.

**Grounding**: two functions independently derive the same thing:
- `build_change_utxos` (:621-630) — `utxo_id(self.txid, base_vout + (j as u32))`
  (:626), `base_vout = withdrawal_outputs.length()` (:622). Used by
  `insert_change_utxos` (withdraw.move:203-208) to `insert_pending` (:206).
- `change_utxo_ids` (:634-641) — the *same* expression (:638), same
  `base_vout` (:635). Used by `confirm_withdrawal` to `confirm_pending`
  (withdraw.move:324-327) and by `emit_withdrawal_confirmed` (:732).

**These are duplicated logic that must stay equal** — see **Finding F7**. If
they diverged, `insert_pending` would create a record under one id and
`confirm_pending` would look up another; since `confirm_pending` (:136-141)
is a silent no-op when the key is absent (`if contains`, :137), the
divergence produces **no abort** — the inserted change record simply keeps
`produced_by = Some(...)` forever, permanently mislabelled as unconfirmed.
That's a silent-failure mode, which makes this worth a rule rather than a
comment.

Within one transaction, distinctness follows from `j` ranging over
`[0, change_outputs.length())` with a fixed `txid` and `base_vout`. The
`u32` cast is the thing to watch: `new_withdrawal_txn` asserts
`output_count <= u32::max_value!()` (:433, `EOutputCountMismatch`) precisely
so `base_vout + (j as u32)` can't wrap two change outputs onto one id — the
comment at :431-432 says the assert exists to "make the cast explicit".

Across transactions, distinctness rests on `txid` uniqueness, a
**Bitcoin-consensus** property outside Move's reach (and the reason F3
matters at all).

**Rule shape**: assert-style, direct — the two derivations agree, and the
insert/promote round-trip actually lands.

```
fun change_derivations_agree(txn: &WithdrawalTransaction, j: u64) {
    let built = hashi::withdrawal_queue::build_change_utxos(txn);
    let ids = txn.change_utxo_ids();
    cvlm_assert(built.length() == ids.length());
    cvlm_assume_msg(j < ids.length(), b"j is a valid change index");
    cvlm_assert(built.borrow(j).id() == *ids.borrow(j));
}

fun change_utxos_are_pairwise_distinct(txn: &WithdrawalTransaction, j: u64, k: u64) {
    let ids = txn.change_utxo_ids();
    cvlm_assume_msg(j < ids.length() && k < ids.length() && j != k, b"two distinct valid change indices");
    cvlm_assert(*ids.borrow(j) != *ids.borrow(k));
}

fun confirm_promotes_every_change_utxo(hashi: &mut Hashi, withdrawal_id: address, j: u64, cert: CommitteeSignature, clock: &Clock) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_withdrawal_txn(withdrawal_id), b"txn is in flight pre-call");
    let ids = queue.borrow_withdrawal_txn(withdrawal_id).change_utxo_ids();
    cvlm_assume_msg(j < ids.length(), b"j is a valid change index");
    let change_id = *ids.borrow(j);
    cvlm_assume_msg(
        hashi.bitcoin().utxo_pool().get_utxo_record_produced_by(change_id).is_some(),
        b"change record is present and still marked unconfirmed",
    );

    hashi::withdraw::confirm_withdrawal(hashi, withdrawal_id, cert, clock);

    let pool2 = hashi.bitcoin().utxo_pool();
    if (pool2.has_active_record(change_id)) {
        cvlm_assert(pool2.get_utxo_record_produced_by(change_id).is_none());
    };
}
```

`UtxoId` is `{txid: address, vout: u32}` (`utxo.move:15-20`) with **no
nested `Option`** — safe to compare with `==`/`!=` directly. `Utxo` itself
(`:22-27`) *does* contain `derivation_path: Option<address>`, so compare
`utxo.id()`, never two `Utxo`s.

**Needs**: `change_utxo_ids` (bump, :634), `build_change_utxos` (bump,
:621), `get_utxo_record_produced_by` (**new**), `borrow_withdrawal_txn`
(bump).

---

## W13 — Guard completeness (withdrawal instance of PROPERTIES.md P7)

**Statement (English)**: enumerate exactly what each withdrawal entry
function checks before any state mutation. Line numbers are
`btc/withdraw.move` on `testnet-1.0`.

| Function | `version_enabled` | `unpaused` | `not_reconfiguring` |
|---|---|---|---|
| `request_withdrawal` (:105-136) | ✓ (:112) | ✓ (:113) | **not checked** — *no comment* |
| `cancel_withdrawal` (:150-184) | ✓ (:156) | **not checked** — *no comment* (F6) | **not checked** — *no comment* |
| `approve_request` (:186-203) | ✓ (:192) | ✓ (:193) | ✓ (:194) |
| `commit_withdrawal_tx` (:208-288) | ✓ (:219) | ✓ (:220) | ✓ (:222, commented :221) |
| `commit_input_signatures` (:295-314) | ✓ (:302) | ✓ (:303) | ✓ (:304) |
| `finalize_withdrawal` (:320-350) | ✓ (:327) | ✓ (:328) | ✓ (:329) |
| `confirm_withdrawal` (:352-407) | ✓ (:358) | ✓ (:359) | **not checked** — *no comment* (F5) |
| `archive_confirmed_withdrawals` (:421-426) | ✓ (:422) | **not checked** — deliberate (:419-420) | **not checked** — deliberate (:419-420) |
| `archive_withdrawal_requests` (:436-446) | ✓ (:441) | **not checked** — deliberate (:434-435) | **not checked** — deliberate (:434-435) |
| `finish_archive_withdrawal_txns` (:455-460) | ✓ (:456) | **not checked** — deliberate (:453-454) | **not checked** — deliberate (:453-454) |
| `reallocate_presigs` (:472-490) | ✓ (:478) | ✓ (:479) | ✓ (:480, commented :466-471) |
| `cleanup_spent_utxos` (:499-504) | ✓ (:500) | **not checked** — deliberate (:497-498) | **not checked** — deliberate (:497-498) |

**Encoded** — the ✓ cells are covered by the three parametric rules
([withdraw_unpaused.move](../specs/withdraw/sources/withdraw_unpaused.move),
[withdraw_not_reconfiguring.move](../specs/withdraw/sources/withdraw_not_reconfiguring.move),
[withdraw_version_enabled.move](../specs/withdraw/sources/withdraw_version_enabled.move)),
whose target lists match this table. The three archival entry points were
added to `withdraw_version_enabled.move` (and to `withdraw_sanity.move`)
after the rebase; they had been missing from both.

The archival entry points carry **no cert**. Their doc comment
(withdraw.move:413-417) argues every write is derivable from already-certified
state: `confirmed_timestamp_ms` is only set under a confirmation cert, and
the request list was bound by the commitment cert. W3's
`archived_txn_is_confirmed` and `archive_moves_only_linked_request` are the
checks that make that argument hold.

**Still to write** — expect-reachable witnesses for the deliberate
omissions, proving the intentional bypass really works (the pattern D10
used):

```
fun gc_callable_while_paused(hashi: &mut Hashi, utxo_ids: vector<UtxoId>) {
    cvlm_assume_msg(hashi.config().paused(), b"system is paused");
    hashi::withdraw::cleanup_spent_utxos(hashi, utxo_ids);
    cvlm_satisfy_msg(true, b"cleanup_spent_utxos succeeded while paused");
    // desired result: satisfiable
}

fun cancel_callable_while_paused(hashi: &mut Hashi, request_id: address, clock: &Clock, ctx: &mut TxContext) {
    cvlm_assume_msg(hashi.config().paused(), b"system is paused");
    let refund = hashi::withdraw::cancel_withdrawal(hashi, request_id, clock, ctx);
    sui::balance::destroy_for_testing(refund);   // must consume the returned Balance
    cvlm_satisfy_msg(true, b"cancel_withdrawal succeeded while paused");
}

fun confirm_callable_while_reconfiguring(hashi: &mut Hashi, withdrawal_id: address, cert: CommitteeSignature, clock: &Clock) {
    cvlm_assume_msg(hashi.committee_set().is_reconfiguring(), b"reconfiguration in progress");
    hashi::withdraw::confirm_withdrawal(hashi, withdrawal_id, cert, clock);
    cvlm_satisfy_msg(true, b"confirm_withdrawal succeeded mid-reconfig");
}
```

The last one is the interesting case, and it is **not** merely
documentation: confirming mid-reconfig marks input UTXOs spent
(withdraw.move:397-399) and reads `hashi.committee_set().epoch()` (:392) to
stamp `spent_epoch` — during a reconfiguration that epoch is precisely the
value in flux. See **Finding F5**.

**Needs**: nothing — mirrors the three existing guard rules.

---

## W14a — Cancellation authorization and cooldown

**Statement (English)**: `cancel_withdrawal` succeeds only for the original
requester, only after the cooldown has elapsed **measured from request
creation**, and only while the request is uncommitted.

**Grounding**, three asserts in `withdraw.move` (`testnet-1.0` lines):
```
assert!(!hashi.bitcoin().withdrawal_queue().is_request_processing(request_id),
        ECannotCancelProcessingWithdrawal);                       // :158-161
assert!(request.request_sender() == ctx.sender(), EUnauthorizedCancellation);  // :166
assert!(clock.timestamp_ms() >= request.request_created_timestamp_ms() + cooldown,
        ECooldownNotElapsed);                                     // :170-173
```
with `cooldown = hashi.config().withdrawal_cancellation_cooldown_ms()`
(:169). Plus the queue-level `!is_committed` backstop
(withdrawal_queue.move:391). `is_request_processing` now reads the request's
link first, since a committed request stays in `requests`.

Note the cooldown is measured from **`created_timestamp_ms`**, never from
approval — the same "measured from creation, not from the intermediate
step" shape as deposits' `is_expired`, and the opposite of deposits'
`confirm_deposit` delay (D11, measured from *approval*). So re-approval
(W4b) does **not** move a withdrawal's cancellation window. Worth stating
explicitly since the deposit-side reader will expect the D11 behavior.

**Rule shape**: assert-style, restating each guard as a postcondition.

```
fun cancel_requires_sender_and_cooldown(hashi: &mut Hashi, request_id: address, clock: &Clock, ctx: &mut TxContext) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_request(request_id), b"request is active pre-call");
    let req = queue.borrow_request(request_id);
    let sender = req.request_sender();
    let created = req.request_created_timestamp_ms();
    let cooldown = hashi.config().withdrawal_cancellation_cooldown_ms();
    let was_processing = queue.is_request_processing(request_id);

    let refund = hashi::withdraw::cancel_withdrawal(hashi, request_id, clock, ctx);
    sui::balance::destroy_zero(refund);   // must consume the returned Balance

    cvlm_assert(sender == ctx.sender());
    cvlm_assert(clock.timestamp_ms() >= created + cooldown);
    cvlm_assert(!was_processing);
}
```

Careful with `destroy_zero` — the refund is generally **non-zero**, so this
would abort and make the rule vacuous. Use `sui::balance::destroy_for_testing`
instead, as `cancel_destroys_uncommitted_request` does: the Prover builds
with `--test`, so it is available. The `!was_processing` half is already
encoded by that rule (as `!was_committed`).

**Needs**: `request_sender` (:665, bump), `request_created_timestamp_ms`
(:669, bump), `withdrawal_cancellation_cooldown_ms` (`btc_config.move:92`,
bump), `contains_request`/`is_request_processing` as in W1.

---

## W14b — An approved-but-uncommitted request CAN still be cancelled

**Statement (English)**: a request the committee has already `Approved` is
still in `requests` and remains cancellable by its requester — nothing
checks approval status in the cancel path. Direct analogue of D9b, and
intentional for the same reason (no hBTC is burned until commit, per W6, so
refunding an approved request is safe).

**Grounding**: `cancel_withdrawal` (withdraw.move:150-184) reads only
`is_request_processing`, `request_sender`, and
`request_created_timestamp_ms` — never `approval_cert`. The queue-level
`cancel_withdrawal` (withdrawal_queue.move:382-407) checks only
`!is_committed` (:391). The doc comment (withdraw.move:138-143) states the
intent: "Cancellation is allowed while the request awaits approval or
commitment".

Worth proving as a positive witness so W1/W3's parametric rules don't get
misread as implying "approved ⇒ protected from cancellation".

**Rule shape**: expect-reachable.

```
fun approved_request_is_cancellable(hashi: &mut Hashi, request_id: address, clock: &Clock, ctx: &mut TxContext) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(queue.contains_request(request_id), b"request is active pre-call");
    cvlm_assume_msg(
        queue.borrow_request(request_id).request_approval_cert().is_some(),
        b"request has already been approved",
    );

    let refund = hashi::withdraw::cancel_withdrawal(hashi, request_id, clock, ctx);
    // ... consume refund ...

    cvlm_satisfy_msg(true, b"cancelled an approved-but-uncommitted request");
    // desired result: satisfiable
}
```

**Needs**: as W14a plus `request_approval_cert` (bump, shared with W4b).

---

## W15 — `btc_amount` vs. `btc.value()`: the P1/P2 bridge

**Statement (English)**: for every uncommitted request,
`btc_amount == btc.value()`. For every committed request, in either bag, the
balance is zero while `btc_amount` retains its historical value.

**On `testnet-1.0`** a committed request stays in `requests` until archival,
so "in `requests`" no longer means "uncommitted": condition on
`!is_committed()`, not on the bag. The sketches below are updated
accordingly. Line numbers in the grounding are pre-rebase; on `testnet-1.0`
the drain is withdrawal_queue.move:372, `extract_request_infos` runs at
withdraw.move:242 and `commit_requests` at :273.

**Grounding**: `create_withdrawal` sets `btc_amount = btc.value()` (:241)
alongside the balance itself (:254) — equal at birth, and **no function ever
updates `btc_amount` again** (grep: it is read at :304, :674, :697, :748,
never assigned outside :246). `commit_requests` drains the balance with
`withdraw_all()` (:325) but leaves `btc_amount` untouched, so the two
diverge exactly at commit.

**Why this is load-bearing, and not just a field-consistency nicety**: the
two quantities feed *different* halves of the withdrawal accounting, and
PROPERTIES.md's P1 and P2 are each stated over one of them.

- **P2's balance identity** is checked against `btc_amount`:
  `extract_request_infos` (:297-308) copies `request.btc_amount` (:304) into
  `CommittedRequestInfo`, and `check_withdrawal_outputs` (:800-814) asserts
  `output.amount == info.btc_amount - per_user_miner_fee` (:809-811).
- **P1's burn** is over the *balance*: `commit_requests` returns
  `Σ request.btc.withdraw_all()` (:325), which `commit_withdrawal_tx` burns
  (withdraw.move:180).

Crucially, `extract_request_infos` runs at withdraw.move:147 — **before**
`commit_requests` at :177 — so it reads `btc_amount` while the request is
still in `requests` and the balance is still full. If `btc_amount` could
ever exceed `btc.value()` for an uncommitted request, the constructed
outputs would promise users more BTC than the hBTC actually burned, breaking
P1's `pool_btc >= hBTC_supply` directly. **W15 is what licenses P1 and P2 to
be stated over different quantities**, and it should be proven before either.

**Rule shape**: assert-style, parametric — an invariant over all targets.

```
fun btc_amount_matches_balance_while_active(hashi: &mut Hashi, request_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(key_matches_object(queue, request_id), b"bag key matches the object's own id");
    if (queue.contains_request(request_id) && !queue.borrow_request(request_id).is_committed()) {
        let req = queue.borrow_request(request_id);
        cvlm_assume_msg(
            req.request_btc_amount() == req.request_btc_balance_value(),
            b"recorded amount matches the held balance pre-call",
        );
    };

    invoke(target, hashi, request_id);

    let queue2 = hashi.bitcoin().withdrawal_queue();
    if (queue2.contains_request(request_id) && !queue2.borrow_request(request_id).is_committed()) {
        let req2 = queue2.borrow_request(request_id);
        cvlm_assert(req2.request_btc_amount() == req2.request_btc_balance_value());
    };
}

fun committed_request_holds_no_balance(hashi: &mut Hashi, request_id: address, target: Function) {
    let queue = hashi.bitcoin().withdrawal_queue();
    cvlm_assume_msg(key_matches_object(queue, request_id), b"bag key matches the object's own id");

    invoke(target, hashi, request_id);

    let queue2 = hashi.bitcoin().withdrawal_queue();
    if (exists_request(queue2, request_id) && borrow_either(queue2, request_id).is_committed()) {
        cvlm_assert(borrow_either(queue2, request_id).request_btc_balance_value() == 0);
    };
}
```

The base case (`request_withdrawal` establishing `btc_amount == btc.value()`
at creation) needs its own direct rule, same reason as W1's base case.

Both rules need the `tracked_request()` pin and four-bag distinctness, as
the W3 rules do.

**Needs**: `request_btc_balance_value` (**new**, shared with W6).
`request_btc_amount`, `borrow_processed` and the `exists_request`/`borrow_either`
helpers in `withdraw_request_lifecycle.move` already exist.

---

## W16 — User index is tied to the request, at most once

**Statement (English)**: `request_id` is added to exactly one user's index
(the requester's) exactly once, and removed only on cancellation — a
committed, confirmed or archived withdrawal stays indexed.

**On `testnet-1.0`** the call sites are withdraw.move:135 (index) and :181
(unindex), and the sender check is :166. The archival entry points don't
touch the index either.

**Grounding**: `index_user_request` (`bitcoin_state.move:83-93`) is called
from the withdrawal flow at exactly one site (withdraw.move:408, with
`ctx.sender()`), and `unindex_user_request` (:96-112) at exactly one
(withdraw.move:448, also `ctx.sender()`). The `Bag::add` (:92) aborts on a
duplicate key, so double-indexing is impossible — safe because the
`request_id` comes from a freshly-minted UID (:401 via `object::new`, :244).
`unindex_user_request` is defensively guarded (`if contains` at :101 and
:103) so it no-ops rather than aborting on an absent entry, and cleans up
the empty per-user `Bag` (:107-110) to avoid leaking table storage.

The unindex uses `ctx.sender()`, which the :433 assert has already
established equals `request.sender` — so it always targets the right user's
bag. Worth noting because the two are different expressions reaching the
same value via a guard several lines apart.

**Note (shared namespace, relates to P11)**: deposits and withdrawals index
into the **same** `user_requests: Table<address, Bag>`
(`bitcoin_state.move:31`, doc comment says "deposits and withdrawals"), with
deposits indexing under the derivation-path recipient at *confirm* time
(D8) and withdrawals under the sender at *request* time. A key collision
would require a deposit `request_id` equal to a withdrawal `request_id`,
impossible with fresh Sui UIDs — but it means the index's `Bag::add`
duplicate-abort is a *cross-flow* guard, not a within-flow one. Flag for
P11's key-injectivity treatment rather than duplicating it here.

**Rule shape**: assert-style, direct, mirroring D8a.

```
fun request_withdrawal_indexes_sender_only(hashi: &mut Hashi, u: address, btc: Balance<BTC>, addr: vector<u8>, clock: &Clock, ctx: &mut TxContext) {
    cvlm_assume_msg(!hashi.bitcoin().has_user_requests(u) || /* ... */ true, b"");
    let sender = ctx.sender();

    hashi::withdraw::request_withdrawal(hashi, clock, btc, addr, ctx);

    // the new request_id isn't knowable pre-call (fresh UID), so assert the
    // frame instead: no *other* user's index gained an entry.
    cvlm_assert(u == sender || !hashi.bitcoin().has_user_requests(u) || /* unchanged */ true);
}

fun cancel_unindexes_the_requester(hashi: &mut Hashi, request_id: address, clock: &Clock, ctx: &mut TxContext) {
    cvlm_assume_msg(
        hashi.bitcoin().user_has_request(ctx.sender(), request_id),
        b"request is indexed under the caller pre-call",
    );

    let refund = hashi::withdraw::cancel_withdrawal(hashi, request_id, clock, ctx);
    // ... consume refund ...

    cvlm_assert(!hashi.bitcoin().user_has_request(ctx.sender(), request_id));
}

fun commit_does_not_unindex(hashi: &mut Hashi, request_id: address, u: address, /* commit args */) {
    let was_indexed = hashi.bitcoin().user_has_request(u, request_id);

    hashi::withdraw::commit_withdrawal_tx(hashi, vector[request_id], /* ... */);

    cvlm_assert(hashi.bitcoin().user_has_request(u, request_id) == was_indexed);
}
```

`request_withdrawal_indexes_sender_only` is awkward as written — the fresh
`request_id` can't be named before the call, so unlike D8a (where
`confirm_deposit`'s request already existed) there's no id to thread
through. Prefer the two clean rules (`cancel_unindexes_the_requester` and
`commit_does_not_unindex`) and treat the creation-side indexing as covered
by `Bag::add`'s duplicate-abort plus UID freshness, stated in English only.

**Needs**: `user_has_request` (bump — **already listed** in
PROPERTIES_DEPOSIT.md's consolidated accessor list), `has_user_requests`
(bump, `bitcoin_state.move:115`).

---

## Findings and audit notes

These came out of writing the properties above. **None is confirmed as
exploitable**; each is either a defense-in-depth gap or an unenforced
assumption that currently holds by call-site reachability. Each was
rechecked against `testnet-1.0`: F1–F3 are resolved upstream, the rest still
hold.

### F1 — Resolved upstream: `finalize_withdrawal`'s `request_ids` was never checked against the transaction's own

Before the rebase, `finalize_withdrawal` took a caller-supplied
`request_ids` and wrote `WithdrawalStatus::Signed` onto each of them through
`update_requests_signed`, without checking they belonged to `withdrawal_id`.
Inside the committee trust boundary, that allowed a status regression
(`Signed` over `Confirmed`).

On `testnet-1.0`, `finalize_withdrawal` (withdraw.move:320-350) no longer
takes `request_ids`, `WithdrawalSignedMessage` binds only
`(withdrawal_id, signatures, guardian_signatures)`, and request status is no
longer stored at all. The finding no longer applies.

### F2 — Moot: `update_requests_signed`/`update_requests_confirmed` had no status precondition

Both writers are deleted along with `WithdrawalStatus`. Their replacements
on the transaction are guarded: `finalize_withdrawal_txn` asserts not already
fully signed (:582), and `mark_txn_confirmed` asserts not already confirmed
(:601).

### F3 — Resolved upstream: `insert_pending` omitted the replay check that `insert_active` performs

`utxo_pool::insert_pending` now calls `assert_not_spent_or_active` before
inserting, the same as `insert_active`, so the replay latch is symmetric.
`insert_pending_reimpl` in the `utxo_pool.move` patch was updated to match.
W8's `insert_pending_bypasses_replay_latch` witness would now come back
**unsatisfiable**; restate it as expect-unreachable if encoded.

### F4 — `mark_spent` doesn't require the UTXO to be locked, or to be unmarked

Still holds. `mark_spent` writes `spent_epoch = Some(epoch)` with no
`assert!(record.spent_by.is_some())` and no check that `spent_epoch` was
previously `None`. Compare `lock`, which asserts `spent_by.is_none()`. So it
can mark a never-locked UTXO spent, and can overwrite an existing
`spent_epoch`, after which `cleanup_spent` would file it under the *later*
epoch in `spent_utxos`.

Safe today because the only caller iterates `txn.inputs`
(withdraw.move:397-399), all locked at commit time (W7), on a transaction
confirmable at most once (W2b). That is a three-property argument for
something a one-line assert would establish locally.

### F5 — `confirm_withdrawal` omits `assert_not_reconfiguring` with no comment

Still holds. Every other deliberate guard omission in `withdraw.move` is
documented at the call site: the three archival entry points and
`cleanup_spent_utxos` say they are "deliberately NOT gated on
pause/reconfig", and `reallocate_presigs` explains why it *is* gated.
`confirm_withdrawal` (:352-407) silently omits `assert_not_reconfiguring`
while keeping the other two guards (:358-359).

Plausibly intentional: a withdrawal already confirmed on Bitcoin should be
recordable regardless of Sui-side reconfiguration state. But it stamps
`spent_epoch` from `hashi.committee_set().epoch()` (:392), read *during* a
reconfiguration, when that value is exactly what's in flux. Confirm whether
the recorded epoch is meant to be pre- or post-transition, and add the
comment either way. Note that
[withdraw_not_reconfiguring.move](../specs/withdraw/sources/withdraw_not_reconfiguring.move)
says this omission is deliberate ("see their comments in withdraw.move"), a
comment that does not exist for this function.

### F6 — `cancel_withdrawal` omits `assert_unpaused` with no comment

Still holds. [withdraw_unpaused.move](../specs/withdraw/sources/withdraw_unpaused.move)
says `cancel_withdrawal` is deliberately not gated on pause, but its doc
comment (withdraw.move:138-149) discusses only which states allow
cancellation and why it is private `entry`, not the pause guard.

Letting users retrieve escrowed hBTC during an emergency pause is defensible
— arguably desirable — but it is the one path that moves user funds while
paused, so the intent should be recorded in the source rather than inferred
from the spec. Either add the comment or add the guard.

### F7 — `build_change_utxos` and `change_utxo_ids` duplicate the same derivation

Still holds. `build_change_utxos` (withdrawal_queue.move:777-788) and
`change_utxo_ids` (:790-799) independently compute
`utxo_id(self.txid, base_vout + (j as u32))` with
`base_vout = self.withdrawal_outputs.length()`. The first feeds
`insert_pending`; the second feeds `confirm_pending` (withdraw.move:404-406)
and `emit_withdrawal_confirmed`.

Divergence would **not abort**: `confirm_pending` is a silent no-op on an
absent key, so the inserted change record would keep `produced_by = Some(...)`
forever, permanently marked unconfirmed while being freely selectable.
Collapse the two by having `change_utxo_ids` map over `build_change_utxos`,
or the reverse.

**Verify with**: W12's `change_derivations_agree`.

### F8 — Input eligibility is enforced at `lock`, not at selection

Still holds. `get_utxo` returns a UTXO copy without consulting `spent_by`,
so `commit_withdrawal_tx` selects (withdraw.move:239), sums, validates fees,
and **constructs the `WithdrawalTransaction` object** (:250-262) before
locking discovers the UTXO was already locked and aborts. Correct outcome by
Move/Sui transaction atomicity, but — exactly as D6 noted for
`mint_balance`-before-`insert_active` — that atomicity is a **VM guarantee,
not model state**, so it is not expressible as a `cvlm_assert` property.
Audit note only.

### F9 — `remove_withdrawal_txn` and `insert_confirmed_txn` are dead code

New on `testnet-1.0`. Both still exist (withdrawal_queue.move:539-552), but
nothing calls them since confirmation became in-place and archival does its
own `remove`/`add`. `insert_confirmed_txn` keys by the transaction's own id,
unlike archival, which keys by `withdrawal_id`. A future caller that pairs
the two the old way would bring back the key/object-id mismatch the
pre-rebase conventions had to assume away. Suggest deleting both.

---

## Required accessors (consolidated)

All changes go directly into `packages/hashi/sources` as plain `public fun`.
`certora/patches/withdrawal_queue.move.patch` and `withdraw.move.patch` are
left for the user to regenerate from the tree.

### In place on `testnet-1.0` (used by the encoded rules)

`btc/withdrawal_queue.move`:
- Membership and borrows: `contains_request`, `contains_processed` (new),
  `borrow_request`, `borrow_processed`, `contains_withdrawal_txn`,
  `contains_confirmed_txn`, `borrow_withdrawal_txn` (bumped),
  `borrow_confirmed_txn` (new).
- Bag identity: `requests_ref`, `processed_ref`, `withdrawal_txns_ref`,
  `confirmed_txns_ref`.
- Request fields: `request_id`, `request_btc_amount`,
  `request_withdrawal_txn_id`, `is_approved`, `is_committed`,
  `is_request_processing`, and `request_approval_cert`,
  `request_approved_timestamp_ms` (bumped).
- Transaction fields: `withdrawal_txn_id`, `withdrawal_txn_request_ids`
  (bumped), `withdrawal_txn_signed_timestamp_ms`,
  `withdrawal_txn_confirmed_timestamp_ms`,
  `withdrawal_txn_has_guardian_signatures` (new). These are object-level,
  so they work for a transaction in either bag.
- `commit_request` (new): the loop body of `commit_requests`, extracted so
  the withdraw package's `commit_requests_summary` can run it for one
  request. `commit_requests` now calls it, so the two can't drift.
- Unchanged extractions used by solvency summaries: `sum_input_amounts`,
  `sum_output_amounts`, `count_requests`, `count_outputs`,
  `check_withdrawal_outputs`.

`btc/withdraw.move`: `request_withdrawal`, `cancel_withdrawal`,
`approve_request`, `commit_withdrawal_tx`, `finalize_withdrawal`,
`confirm_withdrawal` and `archive_withdrawal_requests` widened from private
`entry` to `public entry`, because rules call them directly. The others stay
private: `target()` reaches private `entry` functions without help. Plus the
`lock_input_utxos`/`insert_change_utxos` extractions.

### Still needed by unencoded properties

`btc/withdrawal_queue.move`:
- `request_btc_balance_value(self: &WithdrawalRequest): u64` —
  `self.btc.value()`, distinct from the recorded `request_btc_amount`
  (W6, W15).
- `request_sender`, `request_created_timestamp_ms` (bump, W14a).
- Signing-batch accessors on `&WithdrawalTransaction`, delegating to
  `mpc_signing`: `txn_pending_count`, `txn_signing_epoch`, `txn_num_inputs`,
  `txn_input_is_signed(i)`, `txn_input_signature(i): Option<vector<u8>>`,
  `txn_input_pending_index(i): Option<u64>` (W9–W11). `SigningBatch` is
  embedded field-private in `WithdrawalTransaction`, so there is no route
  to it from spec code without a delegating accessor here.
- `change_utxo_ids`, `build_change_utxos`, `withdrawal_txn_inputs`, `txid`
  (bump, W12).

`btc/utxo_pool.move`:
- `get_utxo_record_produced_by(self, id): Option<address>` (W12) and
  `get_utxo_record_spent_epoch(self, id): Option<u64>` (W8), mirroring
  `get_utxo_record_spent_by`, **including its absent-vs-none aliasing**:
  guard reads with `has_active_record` (see W7).
- `has_spent_record` (bump, W8), `confirm_pending` (bump, W12).

`btc/bitcoin_state.move`: `user_has_request`, `has_user_requests` (bump,
W16).

`btc/btc_config.move`: `withdrawal_cancellation_cooldown_ms` (bump, W14a);
`bitcoin_withdrawal_minimum` (once `request_withdrawal`'s
`EBelowMinimumWithdrawal` guard gets its own P2-style rule).

`hashi.move`: `num_consumed_presigs(self: &Hashi): u64` (new, W11).

---

## Summary — rule shape and status per property

Status as of 2026-10-16, from local runs on `testnet-1.0`. The `@status`/`@report`
annotations are not updated yet; they wait for a cloud run.

| Property | Encoded as | Report property | Status |
|---|---|---|---|
| W1 request bag exclusion | `withdrawal_request_mutual_exclusion` (parametric, 11 targets) + `request_withdrawal_does_not_create_duplicate_request` | `WITHDRAW-QUEUE-MUTUAL-EXCLUSION` | **verified locally**, non-vacuous |
| W2 txn bag exclusion | `withdrawal_txn_mutual_exclusion` (parametric, 11 targets) + `commit_withdrawal_tx_does_not_create_duplicate_txn` | `WITHDRAW-QUEUE-MUTUAL-EXCLUSION` | **verified locally**, non-vacuous |
| W2b no double confirm | `confirm_withdrawal_at_most_once` | `WITHDRAW-STATE-MACHINE` | **verified locally**, non-vacuous |
| W3 field/bag coherence | `approval_fields_paired`, `committed_implies_approved`, `archived_implies_committed`, `signed_fields_paired`, `confirmed_implies_signed`, `archived_txn_is_confirmed` (all parametric) | `WITHDRAW-STATE-MACHINE` | **verified locally**, non-vacuous |
| W4a forward-only lifecycle | `approval_never_reset`, `commit_link_never_changes`, `signed_never_reset`, `confirmed_never_reset` (all parametric) | `WITHDRAW-STATE-MACHINE` | **verified locally**, non-vacuous |
| W4b later-epoch re-approval | `reapproval_requires_later_epoch`, `approve_request_sets_approval_fields` | `WITHDRAW-STATE-MACHINE` | **verified locally**, non-vacuous |
| W5 commit-once | `commit_links_approved_request`; within-call duplicates not encoded | `WITHDRAW-STATE-MACHINE` | **verified locally**, non-vacuous |
| W6 burn/refund exclusion | `cancel_destroys_uncommitted_request` + `commit_link_never_changes`; balance side is W15 | `WITHDRAW-STATE-MACHINE` | **verified locally**, non-vacuous |
| Creation and transition steps | `request_withdrawal_creates_fresh_request`, `commit_creates_unsigned_txn`, `finalize_sets_signed_fields`, `confirm_sets_confirmed_field`, `archive_moves_only_linked_request` | `WITHDRAW-STATE-MACHINE` | **verified locally**, non-vacuous |
| W7 lock write-once | sketch only | — | not encoded; no accessor work needed |
| W8 spend one-way | sketch only | — | not encoded; F3 fixed upstream, so `insert_pending_rejects_spent` is now expect-unreachable |
| W9 guardian sigs write-once | partly, through W3/W4a's signing rules and `finalize_sets_signed_fields` | `WITHDRAW-STATE-MACHINE` | write-once half not encoded; needs W10's accessors |
| W10 signed slot immutable | sketch only | — | not encoded |
| W11 presig disjointness | sketch only | — | not encoded; **highest severity — nonce reuse** |
| W12 change id consistency | sketch only | — | not encoded; verifies F7 |
| W13 guard completeness | `withdraw_is_unpaused`, `withdraw_is_not_reconfiguring`, `withdraw_is_version_enabled` | `WITHDRAW-GATE-CHECKS` | ✓ cells encoded (archival targets added); omission witnesses to write |
| W14a cancel auth/cooldown | `!committed` half in `cancel_destroys_uncommitted_request` | — | sender/cooldown half not encoded |
| W14b approved is cancellable | sketch only | — | not encoded |
| W15 `btc_amount` vs balance | sketch only | — | not encoded; **prove before P1/P2** |
| W16 user index | sketch only | — | not encoded |

### Suggested order for what's left

1. **W15** — the P1/P2 bridge, needing one accessor. Reuse the request
   lifecycle module's helpers and the `tracked_request()` pin.
2. **W10 → W9's write-once half** — in that order (W9's latch argument
   depends on W10's monotonicity). Both need the signing-batch accessors.
3. **W11** — highest severity, but the most accessor work, and its
   cross-epoch half is P9's.
4. **W7, W8, W12, W13's omission witnesses, W14, W16** — the remainder, in
   any order. W7 needs no accessor work.
