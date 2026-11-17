# Hashi Deposit Flow — Concrete Properties (P3 refinement)

This document expands [PROPERTIES.md](PROPERTIES.md)'s P3 ("Uniqueness /
no double-processing") into a complete, concrete property list for the
**deposit flow** specifically — grounded in `btc/deposit.move`,
`btc/deposit_queue.move`, `btc/utxo_pool.move`, `btc/utxo.move`, and
`btc/bitcoin_state.move` — and translates each property into the
`assume / call / assert` (or `satisfy`) shape used by hand-written CVLM
rules (see [CVLM.md](../../CVLM.md) and
[certora/specs/deposit/sources/deposit_unpaused.move](../specs/deposit/sources/deposit_unpaused.move)
for the conventions this follows).

Companion reading: PROPERTIES.md's P3 section (informal version, shared
with the withdrawal/UTXO side) and its P1/P7 sections (solvency and guard
completeness, both touched on below since they interlock with the deposit
state machine).

---

## D0 — State model

Deposit status has **no explicit enum** (unlike `WithdrawalStatus`) — it's
inferred from which bag a `DepositRequest` object lives in, plus which of
two `Option` fields are set:

```
DepositRequest.approval_cert:         Option<CommitteeSignature>  // None until approve_deposit
DepositRequest.approved_timestamp_ms: Option<u64>                 // None until approve_deposit
DepositRequest.confirmed_timestamp_ms: Option<u64>                // None until confirm_deposit
                                                                    // (btc/deposit_queue.move:35-50)

DepositRequestQueue.requests:  ObjectBag  // request_id -> DepositRequest, active (pre-confirm)
DepositRequestQueue.processed: ObjectBag  // request_id -> DepositRequest, terminal
                                                                    // (deposit_queue.move:52-58)

UtxoPool.utxo_records: Bag  // UtxoId -> UtxoRecord, contains iff "active or pending"
UtxoPool.spent_utxos:  Bag  // UtxoId -> spent_epoch, permanent      (utxo_pool.move:46-49)

BitcoinState.user_requests: Table<address, Bag>  // user -> Bag<request_id, bool>
                                                                    // (bitcoin_state.move:22-32)
```

The properties below (D1–D11) are exactly what has to hold for this
inferred state machine to actually behave like one.

---

## Rule-writing conventions used below

**The Prover only models non-aborting executions** — an abort inside a
call prunes that path; it is not itself a checkable "bad outcome" via
`cvlm_assert`. This splits every property below into one of two rule
shapes:

- **Assert-style** ("if the call succeeded, X was/became true"). This is
  the shape of `insert_active_pool_inv`
  ([deposit_sanity.move:36-52](../specs/deposit/sources/deposit_sanity.move)) —
  it restates a guard the code already enforces (an `assert!` or
  `Option::destroy_some`) as a checked postcondition. Works with the
  non-aborting-only model because the property is entirely about what's
  true along *successful* runs — no need to model the abort branch at all.
- **Satisfy-style** ("this exact scenario can never complete
  successfully"). Properties like "no double confirm" are fundamentally
  claims that a *second* call must abort. There is nothing to `cvlm_assert`
  on that pruned path, so these are instead written as: run the sequence,
  then `cvlm_satisfy(true, ...)` after it. The **desired** result is that
  the Prover finds **no satisfying trace** (not-satisfiable) — an inverted
  reading, similar in spirit to the `rule_not_vacuous_tac` inversion
  documented in [the main README](../../README.md) for `--rule` results, but for
  the opposite conclusion (unreachability is the good outcome here, not a
  companion check). A small number of properties (D9b, D10's deliberate
  guard omissions) use `cvlm_satisfy` the *normal* way instead — proving a
  scenario **is** reachable, as a positive witness that intended behavior
  works. Each rule below is labeled with which of these three readings
  applies (**assert / expect-unreachable / expect-reachable**).

**Parametric invoke signature**: rules that need to pass `request_id`
(or another value) through to the invoked target function should declare
the invoker with that value as an extra parameter, forwarded to the
target — same pattern as CVLM.md's `score_only_increases` example
(`native fun invoke(target: Function, id: ID);`). E.g.:

```
native fun invoke(target: Function, hashi: &mut Hashi, request_id: address);
```

so that a snapshot taken via `request_id` before the call and the call
itself agree on which request is being acted on.

---

## D1 — Bag-membership mutual exclusion (request-level uniqueness)

**Statement (English)**: for every `request_id`, at every point after
`deposit()` creates it, `request_id` is in **exactly one** of
`{requests, processed}`, or in neither (post-GC) — never both, never
neither while "live". This is the core P3 claim for deposits, checked
parametrically across every deposit target function.

**Grounding**: `insert_deposit` (`deposit_queue.move:88-91`) is the only
writer of `requests`; `remove_request` (`:94-99`) the only remover — Sui's
`ObjectBag::remove` **aborts if the key is absent**, which is the
load-bearing fact behind D3 below. `insert_processed` (`:118-126`) is the
only writer of `processed`; nothing ever removes from it. `delete_expired`
(`:130-151`) explicitly re-checks `!processed.contains(request_id)`
(`:135`, `EDepositAlreadyProcessed`) before removing from `requests` — a
defensive, structurally-redundant check (same double-guard shape as
PROPERTIES.md P15's `execute`/`delete_expired` pair) worth confirming
really is redundant (i.e. nothing else re-inserts into `requests` after
processing) rather than assumed from the comment alone.

**Rule shape**: assert-style, parametric over all four deposit target
functions (`deposit`, `approve_deposit`, `confirm_deposit`,
`delete_expired_deposit`).

```
target(@hashi, b"deposit", b"deposit");
target(@hashi, b"deposit", b"approve_deposit");
target(@hashi, b"deposit", b"confirm_deposit");
target(@hashi, b"deposit", b"delete_expired_deposit");
invoker(b"invoke");   // native fun invoke(target: Function, hashi: &mut Hashi, request_id: address);

fun deposit_request_mutual_exclusion(hashi: &mut Hashi, request_id: address, target: Function) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume(!(queue.contains(request_id) && queue.contains_processed(request_id)));

    invoke(target, hashi, request_id);

    let queue2 = hashi.bitcoin().deposit_queue();
    cvlm_assert(!(queue2.contains(request_id) && queue2.contains_processed(request_id)));
}
```

**Needs**: `contains_processed` (new — no equivalent exists today, only
`contains` checks `requests`), `contains` bumped from `public(package)` to
`#[test_only] public`.

---

## D2 — No confirm without approve

**Statement (English)**: `confirm_deposit` cannot succeed unless
`approve_deposit` previously succeeded for the same `request_id` and the
approval survived.

**Grounding**: `confirm_deposit` (`deposit.move:207-210`) does
`request.approval_cert().destroy_some()` and
`request.approved_timestamp_ms().destroy_some()` — `Option::destroy_some`
**aborts on `None`**. Both fields are only ever set together, by `approve`
(`deposit_queue.move:104-107`) — confirm this pairing is truly atomic (no
path sets one without the other) before relying on checking just one of
them as a proxy for both.

**Rule shape**: assert-style (restates the `destroy_some` guard as a
checked postcondition on a pre-call snapshot).

```
fun confirm_requires_prior_approval(hashi: &mut Hashi, request_id: address) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume(queue.contains(request_id));
    let req = queue.borrow_request(request_id);
    let had_cert = req.approval_cert().is_some();
    let had_ts = req.approved_timestamp_ms().is_some();

    invoke_confirm_deposit(hashi, request_id);   // non-parametric invoker: confirm_deposit only

    cvlm_assert(had_cert);
    cvlm_assert(had_ts);
}
```

**Needs**: `borrow_request`, `approval_cert`, `approved_timestamp_ms`
bumped to `#[test_only] public`.

**Note**: pair with the auto-generated `-rule_not_vacuous_tac` companion
(see the main README's note on reading it) to confirm this isn't
vacuously true because `confirm_deposit` can never actually be reached in
a state where it succeeds.

---

## D3 — No double confirm

**Statement (English)**: for a fixed `request_id`, `confirm_deposit` can
succeed **at most once**, ever.

**Grounding**: mechanically, `confirm_deposit` empties `requests` via
`remove_request` (`:207`) then unconditionally calls `insert_processed`
(`:247`), never adding back to `requests`. A second call for the same
`request_id` hits `remove_request` on an already-empty key and aborts —
via the framework-level `ObjectBag` abort, not a `hashi`-defined error (a
minor observability gap if you rely on grepping named `EDeposit*` errors
to enumerate every guard).

**Rule shape**: expect-unreachable (`cvlm_satisfy`, desired result:
**not satisfiable**). **This is a corollary of D1**, not an independently
necessary rule — if D1 holds (a `request_id` is never in both `requests`
and `processed`, preserved across all four targets), the second
`confirm_deposit` has nothing left in `requests` to remove and must
abort; proving D1 already proves this. Write it standalone only if you
want a direct check that doesn't lean on D1's generality.

```
fun confirm_deposit_at_most_once(hashi: &mut Hashi, request_id: address) {
    invoke_confirm_deposit(hashi, request_id);   // call 1 — allowed to succeed
    invoke_confirm_deposit(hashi, request_id);   // call 2, same request_id
    cvlm_satisfy_msg(true, b"reached second successful confirm_deposit");
    // desired Prover result: NOT satisfiable
}
```

---

## D4a — No same-epoch reapproval

**Statement (English)**: `approve_deposit` cannot succeed twice for the
same `request_id` while the current committee epoch is unchanged between
the two calls.

**Grounding**:
```
let existing = request.approval_cert();
assert!(existing.is_none() || existing.borrow().signature_epoch() != current_epoch,
        EAlreadyApprovedThisEpoch);                              // deposit.move:156-160
```
`current_epoch = hashi.current_committee().epoch()`, read fresh at
approval time (`:155`) — not stored on the request itself.

**Rule shape**: expect-unreachable (`cvlm_satisfy`, desired result:
**not satisfiable**). **Not** a corollary of D1 (D1 is about the
`requests`/`processed` bags, not committee epochs) — needs its own check
if you want it proven rather than just read off the guard in the code.

```
fun no_same_epoch_reapproval(hashi: &mut Hashi, request_id: address, cert1: CommitteeSignature, cert2: CommitteeSignature) {
    invoke_approve_deposit(hashi, request_id, cert1);   // succeeds, records epoch E
    invoke_approve_deposit(hashi, request_id, cert2);   // no committee rotation between calls
    cvlm_satisfy_msg(true, b"reached second same-epoch approval");
    // desired Prover result: NOT satisfiable
}
```

---

## D4b — Reapproval overwrites, doesn't append

**Statement (English)**: a *successful* reapproval (necessarily in a
different epoch, per D4a) **overwrites** `approval_cert`/
`approved_timestamp_ms` rather than accumulating them — only the latest
approval is ever live for `confirm_deposit` to consume.

**Grounding**: `request.approve(...)` (`deposit_queue.move:104-107`)
unconditionally overwrites both fields on every call. This means
"approved" is not a monotone one-way latch the way `Approved` is in the
withdrawal enum — it's a mutable single-slot cache of "last valid
approval," a materially different design worth stating explicitly.

**Rule shape**: assert-style, direct.

```
fun reapproval_overwrites_stored_cert(hashi: &mut Hashi, request_id: address, cert2: CommitteeSignature) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume(queue.contains(request_id) && queue.borrow_request(request_id).approval_cert().is_some());

    invoke_approve_deposit(hashi, request_id, cert2);   // succeeds only in a new epoch, per D4a

    let queue2 = hashi.bitcoin().deposit_queue();
    cvlm_assert(queue2.borrow_request(request_id).approval_cert() == option::some(cert2));
}
```

`CommitteeSignature` (`committee.move:55-59`) is a plain
`{epoch: u64, signature: vector<u8>, signers_bitmap: vector<u8>}` struct
with **no nested `Option`** — safe to compare with `==` directly, unlike
the `Option<T>` gotcha documented in [CLAUDE.md](../README.md).

**Needs**: same as D4a — `borrow_request`, `approval_cert` bumped to
`#[test_only] public` (already listed under D2).

---

## D5 — Approve/confirm re-verify against the *current* committee

**Statement (English)**: both `approve_deposit` and `confirm_deposit`
independently re-verify the same signed `DepositConfirmationMessage`
against whichever committee is current *at the time each is called* — not
a cached/stale committee from an earlier point in the flow.

**Grounding**: `hashi.verify(deposit_confirmation(), DepositConfirmationMessage{request_id, utxo}, cert)`
at `deposit.move:163-167` and `:215-219`. Epoch pin enforced inside
`verify_certificate` itself (`committee.move:205`,
`signature.epoch == self.epoch()`), *before* the BLS check.

**Status: deferred.** This is really an instance of PROPERTIES.md's P6
(epoch pin) and P10 (threshold computed from the same committee being
verified against), both already general properties of `hashi.verify` with
no deposit-specific behavior. Reproducing it here would mean
mocking/summarizing BLS verification just to force a stale-epoch cert
through `confirm_deposit` — redundant with encoding P6/P10 once as their
own rules. **No deposit-specific rule planned**; rely on P6/P10 coverage
of `verify`/`verify_with_committee` instead.

---

## D6 — UTXO replay protection is enforced by `insert_active`, not by call-site ordering

**Statement (English)**: two `DepositRequest`s can validly co-exist
referencing the same `UtxoId` all the way through creation and approval
(request identity is the `DepositRequest`'s own `UID`, unrelated to
`UtxoId`) — the only point that provably prevents the same UTXO being
credited twice is `insert_active`'s own internal check.

**Grounding**: `deposit()`'s and `approve_deposit()`'s calls to
`assert_not_spent_or_active` (`:100`, `:148`) only consult **pool** state
(`utxo_records`/`spent_utxos`), never sibling requests in the deposit
queue — so they cannot themselves prevent two requests over the same
UTXO from both reaching `confirm_deposit`. The actual protection is
`insert_active`'s internal `assert_not_spent_or_active`
(`utxo_pool.move:70`), which the **first** successful `confirm_deposit`
for a `UtxoId` satisfies, and a **second** would hit `EUtxoAlreadyUsed`.

Note: `mint_balance`/`send_funds` (`deposit.move:239-240`) execute
**before** `insert_active` (`:244`) in `confirm_deposit` — this ordering
concern is **not itself a provable CVL property**; it relies on Move/Sui
transaction atomicity (an abort anywhere in the call rolls back the whole
transaction, a VM guarantee, not model state) rather than anything a
`cvlm_assert`/`cvlm_satisfy` rule can characterize. Flagging it here as an
audit note, not as a rule to write.

**Rule shape**: expect-unreachable (`cvlm_satisfy`, desired result:
**not satisfiable**). One level down from D3/D4a — a `UtxoPool`-level
check, needing only the already-public `insert_active` (no new accessor).

```
fun insert_active_rejects_duplicate(pool: &mut UtxoPool, utxo1: Utxo, dup: Utxo) {
    cvlm_assume(dup.id() == utxo1.id());
    pool.insert_active(utxo1);
    pool.insert_active(dup);
    cvlm_satisfy_msg(true, b"reached second insert_active for same UtxoId");
    // desired Prover result: NOT satisfiable
}
```

---

## D7 — Mint iff `derivation_path.is_some()`; `insert_active` unconditional; amount matches

**Statement (English)**: `insert_active(utxo)` is called **unconditionally**
exactly once per successful `confirm_deposit`; `mint_balance`/`send_funds`
are called **iff** `utxo.derivation_path().is_some()`, for exactly
`utxo.amount()`.

**Grounding**: `deposit.move:234-244` — `if (derivation_path.is_some())`
gate around mint, unconditional `insert_active(utxo)` after. This is the
exact mechanism behind PROPERTIES.md P1's confirmed gap (no-derivation-path
deposits grow `pool_btc - hBTC_supply`) — D7 is the deposit-side property
P1's solvency argument depends on; any change coupling mint to a different
condition than `insert_active` breaks both P1 and this property
simultaneously.

**Rule shape**: assert-style, direct.

```
fun confirm_deposit_mint_matches_condition(hashi: &mut Hashi, request_id: address) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume(queue.contains(request_id));
    let utxo = queue.borrow_request(request_id).utxo();   // Utxo has `copy`
    let derivation = utxo.derivation_path();
    cvlm_assume(!hashi.bitcoin().utxo_pool().has_active_record(utxo.id()));

    let supply_before = sui::coin::total_supply(hashi.treasury().treasury_cap_ref<BTC>());

    invoke_confirm_deposit(hashi, request_id);

    cvlm_assert(hashi.bitcoin().utxo_pool().has_active_record(utxo.id()));

    let supply_after = sui::coin::total_supply(hashi.treasury().treasury_cap_ref<BTC>());
    if (derivation.is_some()) {
        cvlm_assert(supply_after == supply_before + utxo.amount());
    } else {
        cvlm_assert(supply_after == supply_before);
    };
}
```

**Needs**: `utxo()` bumped to `#[test_only] public` (already
`public(package)`). `total_supply` is reachable **today, no new
accessor** — via the already-public `treasury_cap_ref` +
`sui::coin::total_supply` (`treasury.move:70`).

---

## D8 — Recipient indexing tied to mint, at most once

**Statement (English)**: `index_user_request` is called with a given
`request_id` **at most once**, and **only** for a request whose
`confirm_deposit` succeeded with `derivation_path.is_some()` (i.e. a mint
occurred) — indexed under exactly that derivation-path recipient.

**Grounding**: `BitcoinState.user_requests: Table<address, Bag>`
(`bitcoin_state.move:31`, per-user `Bag<request_id, bool>`).
`index_user_request` (`:83-93`) has **exactly one call site**
(`deposit.move:251`, inside the `if (recipient_opt.is_some())` branch —
the `else` branch explicitly calls `recipient_opt.destroy_none()` and
indexes nothing, `:253`). `Bag::add` (used at `:92`) aborts on a duplicate
key, which would matter if `index_user_request` were ever called twice for
the same `request_id` — but per D1/D3, `confirm_deposit` (its only caller)
succeeds at most once per `request_id`, so that can never actually be
attempted.

**Rule shape**: split into two parts:

**D8a — frame + correctness** (assert-style, direct — mirrors the
`insert_active_pool_inv` pattern: pick an arbitrary user `u`, assume they
don't yet have `request_id` indexed, call `confirm_deposit`, assert the
index now reflects exactly the mint condition):

```
fun confirm_deposit_indexes_recipient_only(hashi: &mut Hashi, request_id: address, u: address) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume(queue.contains(request_id));
    let derivation = queue.borrow_request(request_id).utxo().derivation_path();
    cvlm_assume(!hashi.bitcoin().user_has_request(u, request_id));

    invoke_confirm_deposit(hashi, request_id);

    let expected = derivation.is_some() && u == *derivation.borrow();
    cvlm_assert(hashi.bitcoin().user_has_request(u, request_id) == expected);
}
```

**D8b — at-most-once** (English only, no separate rule): fully a
corollary of D1/D3 as described above — not worth a standalone
`cvlm_satisfy` check unless D1/D3 themselves are left unproven.

**Needs**: `user_has_request` bumped from `public(package)` to
`#[test_only] public` in `bitcoin_state.move`. `utxo()`/
`derivation_path()` bumps already listed under D7/D2.

---

## D9a — `delete_expired` requires not-yet-processed

**Statement (English)**: `delete_expired_deposit` cannot succeed for a
`request_id` that has already reached the `processed` bag.

**Grounding**: explicit `assert!(!self.processed.contains(request_id), EDepositAlreadyProcessed)`
(`deposit_queue.move:135`).

**Rule shape**: assert-style, same shape as D2 (restates the guard as a
checked postcondition; mostly useful paired with the
`-rule_not_vacuous_tac` companion to confirm the branch is truly
reachable, not just trivially satisfied).

```
fun delete_expired_requires_not_processed(hashi: &mut Hashi, request_id: address) {
    let queue = hashi.bitcoin().deposit_queue();
    let was_processed = queue.contains_processed(request_id);

    invoke_delete_expired_deposit(hashi, request_id);

    cvlm_assert(!was_processed);
}
```

**Needs**: `contains_processed` (new, already listed under D1).

---

## D9b — An approved-but-unconfirmed request CAN still be deleted

**Statement (English)**: unlike the withdrawal state machine, an
`Approved`-equivalent deposit (has a stored `approval_cert`) is still
sitting in `requests` and remains GC-able if the 1-day window measured
from **creation** (not approval) lapses — this is intentional (nothing is
minted until `confirm_deposit`, per D7, so deleting an approved-but-
unconfirmed request is safe), not a bug. Worth proving as a positive
witness so a parametric rule doesn't mistake this reachability for a
violation of "approved implies protected from deletion."

**Grounding**: `is_expired` (`deposit_queue.move:215-216`) —
`clock.timestamp_ms() > created_timestamp_ms + MAX_DEPOSIT_REQUEST_AGE_MS`
(1 day, `:18`) — measured from `created_timestamp_ms`, never touched by
`approve`. `delete_expired` (`:130-151`) has no separate check that would
exclude an approved request.

**Rule shape**: expect-reachable (`cvlm_satisfy`, desired result:
**satisfiable** — a positive witness, not a violation).

```
fun approved_unconfirmed_request_is_deletable(hashi: &mut Hashi, request_id: address) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume(queue.contains(request_id) && queue.borrow_request(request_id).approval_cert().is_some());
    // (assume clock has advanced past created_timestamp_ms + MAX_DEPOSIT_REQUEST_AGE_MS)

    invoke_delete_expired_deposit(hashi, request_id);

    cvlm_satisfy_msg(true, b"deleted an approved-but-unconfirmed request");
    // desired Prover result: satisfiable
}
```

**D9c** (confirmed ⟹ can never be GC'd) — fully subsumed by D1 + D9a
together (once confirmed, `request_id ∈ processed`, so D9a's guard blocks
`delete_expired`); no separate rule needed.

---

## D10 — Guard completeness (deposit-flow instance of PROPERTIES.md P7)

**Statement (English)**: enumerate exactly what each deposit entry
function checks before any state mutation.

| Function | `version_enabled` | `unpaused` | `not_reconfiguring` |
|---|---|---|---|
| `deposit` (`:85-118`) | ✓ (`:91`) | ✓ (`:94`) | **not checked** — deliberate (`:92-93`) |
| `approve_deposit` (`:131-181`) | ✓ (`:138`) | ✓ (`:139`) | ✓ (`:142`) |
| `confirm_deposit` (`:193-255`) | ✓ (`:199`) | ✓ (`:200`) | ✓ (`:203`) |
| `delete_expired_deposit` (`:260-269`) | ✓ (`:265`) | **not checked** — deliberate (`:257-259`) | **not checked** |

**Rule shape**: mixed.

*Positive cases* (guard really is checked) — assert-style, same shape as
the existing `deposit_is_unpaused` rule in
[deposit_unpaused.move](../specs/deposit/sources/deposit_unpaused.move) —
one rule per `(target, guard)` cell marked ✓ above:

```
fun approve_deposit_is_unpaused(hashi: &mut Hashi, target: Function) {
    invoke(target, hashi);
    cvlm_assert(!hashi.config().paused());
}
```

*Deliberate omissions* — expect-reachable witnesses (`cvlm_satisfy`,
desired result: **satisfiable** — proves the intentional bypass really
works, not a violation):

```
fun deposit_callable_while_reconfiguring(hashi: &mut Hashi) {
    cvlm_assume(hashi.committee_set().is_reconfiguring());
    invoke_deposit(hashi, ...);
    cvlm_satisfy_msg(true, b"deposit() succeeded mid-reconfig");
}

fun gc_callable_while_paused(hashi: &mut Hashi, request_id: address) {
    cvlm_assume(hashi.config().paused());
    invoke_delete_expired_deposit(hashi, request_id);
    cvlm_satisfy_msg(true, b"delete_expired_deposit() succeeded while paused");
}
```

---

## D11 — Time-delay measured from `approved_timestamp_ms`

**Statement (English)**: `confirm_deposit` enforces its time-delay against
the **currently stored** `approved_timestamp_ms` — which, per D4b, is
always the timestamp of the *most recent* successful approval, not
necessarily the first. Re-approval after rotation restarts the delay
window from the new approval's timestamp — the intended
"faulty-approval detection window," per the module doc, but worth stating
explicitly since a naive reading ("delay since request creation") would
be wrong.

**Grounding**: `assert!(approved_timestamp_ms + hashi.config().deposit_time_delay_ms() <= clock.timestamp_ms(), EDepositTimeDelayNotPassed)`
(`deposit.move:222-225`).

**Rule shape**: assert-style, same shape as D2/D9a.

```
fun confirm_deposit_time_delay_holds(hashi: &mut Hashi, request_id: address, clock: &Clock) {
    let queue = hashi.bitcoin().deposit_queue();
    cvlm_assume(queue.contains(request_id));
    let approved_ts_before = queue.borrow_request(request_id).approved_timestamp_ms();
    cvlm_assume(approved_ts_before.is_some());
    let ts = *approved_ts_before.borrow();
    let delay = hashi.config().deposit_time_delay_ms();

    invoke_confirm_deposit(hashi, request_id);   // must have succeeded (non-abort)

    cvlm_assert(ts + delay <= clock.timestamp_ms());
}
```

**Needs**: `deposit_time_delay_ms` bumped from `public(package)` to
`#[test_only] public` in `btc_config.move` (currently accessed in
`deposit.move` only via the package-visible `use fun` alias
`Config.deposit_time_delay_ms`, invisible to the `deposit` spec package).

---

## Findings and audit notes

These came from a dedicated pass over `deposit.move`, `deposit_queue.move`,
the deposit-facing parts of `utxo_pool.move`/`bitcoin_state.move`/
`btc_config.move`, and, where the Move code alone was not decisive, the
node's deposit path (`crates/hashi/src/deposits.rs`,
`crates/hashi/src/leader/deposits.rs`) and the screener
(`crates/hashi-screener`). Move line numbers are against `HEAD` (unpatched
sources). **None allows minting hBTC without a matching BTC deposit.** DF1 is
a compliance control that does nothing on mainnet. DF2 is a gap in the
fault-response story the time delay exists to support. Listed
highest-concern first.

Already covered elsewhere and deliberately **not** repeated here: mint
before `insert_active` (D6's audit note), no-derivation-path deposits
widening `pool_btc - hBTC_supply` (PROPERTIES.md P1), `update_config`
writing any key unvalidated (PROPOSAL_GOVERNANCE.md G11/GF4; DF3 below adds
only the deposit-specific consequences), and `insert_pending`'s missing
replay check (PROPERTIES_WITHDRAW.md F3, fv_findings.md Issue 1).

### DF1 — AML screening checks the deposit request's object id, not the hBTC recipient

`screen_deposit` (`crates/hashi/src/deposits.rs:48-82`) builds the screener
request as:

```rust
// sui
let destination_address = deposit_request.id.to_string();   // :62
```

`deposit_request.id` is the `DepositRequest`'s `UID`, a fresh object id
created by `object::new(ctx)` in `create_deposit` (`deposit_queue.move:74`).
The address that actually receives the minted hBTC is
`utxo.derivation_path` (`deposit.move:234-240`), and it is never sent to the
screener.

The screener treats the value as the funds' destination. The proto documents
the field as "Address on the destination chain receiving the funds"
(`screener_service.proto:17-18`). The screener validates it as a Sui address
(`hashi-screener/src/main.rs:201`) and runs
`query_address_risk_level(dest_addr, ...)` on it (`:122`). A freshly created
object id has no on-chain history, so on mainnet this half of the check
should always come back clean. Only the source-transaction check (`:114-120`,
keyed on the BTC txid) does any work.

The withdrawal side does it correctly. `screen_withdrawal`
(`crates/hashi/src/withdrawals.rs:1312`) screens the real Bitcoin
destination decoded from `request.bitcoin_address`.

A side effect: the screener's cache key is
`"{type}:{tx_hash}:{dest_addr}"` (`main.rs:106`). A per-request object id
therefore never hits the cache for deposits, so re-screening the same
recipient, or re-approving after a committee rotation, always calls the
MerkleScience API again.

**Impact**: a sanctioned Sui address can receive minted hBTC as long as the
source Bitcoin transaction itself scores below the threshold. No funds are
at risk. The damage is to compliance: PROTOCOL.md's deposit step 2 treats
screening as part of approval, and on the recipient side it currently checks
nothing.

**Suggested fix**: screen `deposit_request.utxo.derivation_path` as the
destination. When it is `None`, nothing is minted (`deposit.move:236`), so
destination screening can be skipped or the request rejected, depending on
policy. Add a unit test asserting the screener receives the recipient
address, since nothing on-chain can catch this.

**Verify with**: off-chain only. No Move property is involved.

### DF2 — A faulty approval can be paused but not revoked, and expiry does not stop it confirming

The module doc (`deposit.move:6-7`, `:124-130`) says the time delay exists
so that "a faulty or fraudulent committee signature" can be caught and "the
service paused before funds are minted". It then says that while paused
"`confirm_deposit` is rejected, leaving the approval **parked**". Nothing
un-parks it except confirmation:

- No entry point rejects, cancels or clears the approval on a
  `DepositRequest`. `approve` only ever writes `Some` into
  `approval_cert`/`approved_timestamp_ms` (`deposit_queue.move:104-107`).
- `confirm_deposit` never calls `is_expired`
  (`deposit.move:193-255`; `is_expired` is private to `deposit_queue` and
  called only from `delete_expired`, `deposit_queue.move:137`). Neither does
  `approve_deposit`. The 1-day `MAX_DEPOSIT_REQUEST_AGE_MS` (`:18`) only
  decides when a request **may be deleted**. It does not stop an expired
  request from being approved or confirmed.
- The leader confirms every parked approval as soon as the pause lifts.
  `check_halt_deposit_processing` (`leader/deposits.rs:308-325`) only
  suspends work. `process_approved_deposit_requests` (`:124-225`) filters
  candidates by `cert.epoch == current_epoch` and the time delay, and by
  nothing else.

So the operator's options after catching a faulty approval are:
1. **Stay paused until `created_timestamp_ms + 1 day`, then call
   `delete_expired_deposit(faulty_id)`.** This works because GC is
   deliberately not pause-gated (`deposit.move:257-259`). But it holds the
   entire bridge paused for up to a day, withdrawals included, and it is a
   manual step. If governance unpauses before someone runs the delete, the
   expired faulty request confirms anyway.
2. **Rotate the committee.** `confirm_deposit` re-verifies against the
   current committee (`:215-219`), so a new epoch invalidates the stored
   cert. It also invalidates **every** legitimate parked approval, and it
   requires a full reconfiguration.

A faulty approval here means one the committee should not have produced:
for example, a node validation bug in `validate_deposit_request_on_bitcoin`,
or a reorged deposit that met a governable `bitcoin_confirmation_threshold`
(see DF3).

**Suggested fix**: add `assert!(!is_expired(request, clock), ...)` to
`confirm_deposit` (via a `public(package)` wrapper), so that "expired" means
invalid and not merely deletable. That makes option 1 safe without a
manual GC step. For a direct remedy, add a governance or committee-certified
`reject_deposit(request_id)` that clears the approval, or deletes the
request while paused.

**Verify with**: a new expect-reachable rule, `confirm_deposit_ignores_expiry`.
Assume `clock > created_timestamp_ms + MAX_DEPOSIT_REQUEST_AGE_MS`, invoke
`confirm_deposit`, then `cvlm_satisfy(true)`. Expect **satisfiable** to
confirm the finding, and **not satisfiable** once the fix lands. It needs
`request_created_timestamp_ms` bumped to `public`, plus a constant accessor
for `MAX_DEPOSIT_REQUEST_AGE_MS`.

### DF3 — Deposit timing parameters are not bounded against the fixed 1-day expiry

PROPOSAL_GOVERNANCE.md G11 establishes that `bitcoin_deposit_time_delay_ms`
and `bitcoin_confirmation_threshold` can be set to any `u64`. It does not
work out what that does to the deposit flow, which interacts with a
**non-governable** constant: `MAX_DEPOSIT_REQUEST_AGE_MS = 1 day`
(`deposit_queue.move:18`), measured from `created_timestamp_ms` (`:215-216`).

- **Delay ≥ 1 day: every deposit is deletable before it can confirm.**
  `confirm_deposit` needs `approved_ts + delay <= now` (`deposit.move:222-225`).
  Since `approved_ts >= created_ts`, the request is already past expiry when
  the delay elapses. `delete_expired_deposit` is permissionless, and Sui pays
  the storage rebate for the deleted `DepositRequest` and its `Field` wrapper
  to whoever sends the deleting transaction. That makes the deletion race a
  profitable bot strategy, not just griefing. The same race exists at
  default settings for any request approved within `delay` of its expiry: a
  long pause or reconfiguration, or a re-approval after rotation (which
  restarts the delay, D11, but never the expiry), pushes approvals into that
  window. D9b records that approved requests stay deletable. The new point
  is that the delay config can make this the normal case, and that the
  rebate pays third parties to win the race.
- **Delay = 0** removes the fault-detection window entirely, which is the
  mechanism DF2 depends on.
- **Delay near `u64::MAX`** makes `approved_ts + delay` overflow and abort,
  so every `confirm_deposit` fails. (The leader uses `saturating_add`,
  `leader/deposits.rs:198`, so it just never attempts one.)
- **`bitcoin_confirmation_threshold`** (`btc_config.move:84-86`) is read
  live by each member (`crates/hashi/src/deposits.rs:160`). Setting it low
  weakens reorg protection for every deposit approved afterwards.

**Impact**: liveness only. An expired deposit's UTXO never reached the pool,
so the user can re-register it, and nothing is lost. But the misconfiguration
fails silently, and a GC bot can repeatedly delete approved deposits.

**Suggested fix**: put the invariant in the reader, the pattern
`bitcoin_withdrawal_minimum` already uses (PROPOSAL_GOVERNANCE.md G11).
Clamp `bitcoin_deposit_time_delay_ms` into
`[MIN_DELAY, MAX_DEPOSIT_REQUEST_AGE_MS / 2]` and floor
`bitcoin_confirmation_threshold` at a safe minimum. Alternatively, measure
expiry from `approved_timestamp_ms` once a request is approved.

### DF4 — Duplicate requests for one UTXO are each approved on-chain at the leader's expense

`deposit()` rejects a UTXO only if it is already in the **pool**
(`deposit.move:100`), and D6 establishes that any number of requests for
the same `UtxoId` can coexist. Every such request carries valid data (right
amount, right derivation path), so each one passes node validation
(`deposits.rs:84-138`, `:150-185`). The unapproved worklist
(`leader/deposits.rs:56-91`) does **not** deduplicate by `UtxoId`. The
approved path does (`filter_deposit_confirmation_candidates`, `:558`), which
shows the leader already knows duplicates exist.

So anyone who sees a pending deposit can register N copies of it. Each copy
gets its own quorum signature round and its own `approve_deposit`
transaction paid for by the leader. Only one confirms; the rest sit approved
until GC. On-chain rejection (`DuplicateOrSpentOnSui`, `deposits.rs:129-135`)
only kicks in after the first copy confirms, which is at least
`bitcoin_deposit_time_delay_ms` after the approvals went out. On storage:
`approve` enlarges the stored request with the cert bytes, and the leader
pays for that. The rebate for the whole object goes to whoever later deletes
it, and that can be the attacker (see DF3).

**Impact**: gas and signing-bandwidth griefing that costs the attacker
roughly one `deposit()` per copy (with its storage refundable through
self-GC). No mint impact: copies share the UTXO, derivation path included,
so whichever confirms pays the same recipient, and `insert_active`
blocks the rest (D6).

**Suggested fix**: in the unapproved worklist, approve only the
earliest-created request per `UtxoId` among those not yet approved, as the
approved path already does. A stronger on-chain fix is to index pending
`UtxoId`s in `DepositRequestQueue` and reject a second `deposit()` for one.

### DF5 — `derivation_path = None` and `Some(@0x0)` pass the same address check but diverge on-chain

The node maps both to the zero path: `normalized_derivation_path` returns
`derivation_path.copied().unwrap_or(Address::ZERO)`
(`crates/hashi/src/deposits.rs:355-361`), and `get_deposit_address` uses it
(`:201-203`, `:214-226`). So a UTXO paying the bridge's **change address**
passes `validate_deposit_request_derivation_path` under either value. The
cert binds the `Option` exactly, but on-chain the two differ:
`None` mints nothing, while `Some(@0x0)` mints `amount` hBTC to `@0x0`
(`deposit.move:236-240`), where nobody can ever spend it.

**Impact**: none on safety. Anyone can send BTC to the change address, and
the two encodings only choose between the P1 gap growing and the hBTC being
burned. But PROPERTIES.md P1's accounting treats "no derivation path" and
"mint happened" as a clean dichotomy, and this breaks it at the address
level. Worth either rejecting `Some(@0x0)` in `deposit()`, or having the
node refuse to sign it.

### DF6 — Minor notes

- **`bitcoin_deposit_minimum` is only checked at request time**
  (`deposit.move:97`). If governance raises it, requests created earlier
  still approve and confirm below the new minimum. This is probably
  intended; document it if so.
- **`processed` is documented wrongly.** The field comment says "Completed
  deposits (confirmed or expired)" (`deposit_queue.move:56`), but expired
  requests are destroyed by `delete_expired` (`:139-150`) and never reach
  `processed`. Only confirmed ones do (`deposit.move:247`).
- **`processed` and the user index grow without bound.** Nothing removes
  from `processed`, and `unindex_user_request`
  (`bitcoin_state.move:96-112`) has no deposit-side caller. Each processed
  request keeps its full `approval_cert` (signature plus signer bitmap).
  This is a storage cost, paid by whoever calls `confirm_deposit`, and not
  a correctness issue.

---

## Required test-only accessors (consolidated)

None of these have been added yet — **do not edit
`packages/hashi/sources` for this without going through the patch
workflow in [CLAUDE.md](../README.md)** ("Saving a new patch to
`certora/patches/`"). Every accessor below should be `#[test_only] public
fun` (visible to any package, compiled out of production builds), not
`public(package)` — the `deposit` spec package is a different package from
`hashi` even though it depends on it locally, so `public(package)` stays
invisible regardless of build flags.

**`btc/deposit_queue.move`**:
- `contains_processed(self: &DepositRequestQueue, id: address): bool` —
  **new**, no equivalent exists (only `contains` checks `requests`).
- `contains` — bump `public(package)` → `#[test_only] public`.
- `borrow_request` — bump `public(package)` → `#[test_only] public`.
- `approval_cert` — bump `public(package)` → `#[test_only] public`.
- `approved_timestamp_ms` — bump `public(package)` → `#[test_only] public`.
- `confirmed_timestamp_ms` — bump `public(package)` → `#[test_only] public`
  (not used directly above but symmetric with the other two timestamp
  fields; needed if any future rule reads it directly instead of via bag
  membership).
- `utxo` — bump `public(package)` → `#[test_only] public`.

**`btc/bitcoin_state.move`**:
- `user_has_request` — bump `public(package)` → `#[test_only] public`.

**`btc/btc_config.move`**:
- `deposit_time_delay_ms` — bump `public(package)` → `#[test_only] public`.
- `deposit_minimum` (aka `bitcoin_deposit_minimum`) — bump
  `public(package)` → `#[test_only] public` (not directly used by D1–D11
  above, but likely needed once `deposit()`'s `EBelowMinimumDeposit` guard
  gets its own rule under P7/P2-style coverage).

Nothing in `utxo_pool.move` needs new accessors — `insert_active`,
`has_active_record`, and `get_utxo_record_spent_by` are already public/
test-only-public, per the existing `insert_active_pool_inv`/
`insert_active_adds_to_pool` rules.

---

## Summary — rule shape and status per property

| Property | Rule shape | Corollary of another? | Accessor gaps | Status |
|---|---|---|---|---|
| D1 | assert (parametric, all 4 targets) | — | `contains_processed` (new), `contains` (bump) | ready to write once accessors land |
| D2 | assert | — | `borrow_request`, `approval_cert`, `approved_timestamp_ms` (bump) | ready |
| D3 | expect-unreachable (`satisfy`) | yes — D1 | none beyond D1's | optional; write only if D1 alone isn't enough assurance |
| D4a | expect-unreachable (`satisfy`) | no | none | ready |
| D4b | assert | — | `borrow_request`, `approval_cert` (bump, shared w/ D2) | ready |
| D5 | — (deferred) | subsumed by P6/P10 | — | not planned as a deposit-specific rule |
| D6 | expect-unreachable (`satisfy`) | no | none (uses public `insert_active`) | ready |
| D7 | assert | — | `utxo` (bump); `total_supply` needs **no** new accessor | ready |
| D8a | assert | — | `user_has_request` (bump), `utxo`/`derivation_path` (shared) | ready |
| D8b | English only, no rule | yes — D1/D3 | — | documented, not encoded |
| D9a | assert | — | `contains_processed` (shared w/ D1) | ready |
| D9b | expect-reachable (`satisfy`) | no | `borrow_request`, `approval_cert` (shared) | ready |
| D9c | English only, no rule | yes — D1 + D9a | — | documented, not encoded |
| D10 | assert (✓ cells) + expect-reachable (omission cells) | — | none (mirrors existing `deposit_is_unpaused`) | ready |
| D11 | assert | — | `approved_timestamp_ms` (shared), `deposit_time_delay_ms` (bump) | ready |
