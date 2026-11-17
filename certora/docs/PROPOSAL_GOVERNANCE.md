# Hashi Governance & Reconfiguration — Concrete Properties (P15 refinement)

This document expands [PROPERTIES.md](PROPERTIES.md)'s P15 ("Governance
proposal lifecycle & committee reconfiguration state machine") into a
complete, concrete property list — grounded in
`core/proposal/proposal.move`, `core/proposal/proposals.move`, the seven
payload modules under `core/proposal/types/`, `core/reconfig.move`,
`core/committee/committee_set.move`, `core/committee/committee.move`,
`core/config/config.move`, `core/mpc_config.move`, `core/threshold.move`
and `core/versioning.move` — and translates each property into the
`assume / call / assert` shape used by hand-written CVLM rules.

It also absorbs and refines three neighbouring properties that turn out to
be the *same* machinery seen from different angles:

- **P13** (emergency-pause quorum asymmetry is non-invertible) — G10/G11.
- **P12** (reconfig as mutual exclusion; epoch monotonic, +1 per reconfig)
  — G12/G14. The "+1" half of P12's statement is **wrong**; see G14 and
  Finding **GF5**.
- **P14** (version gating is a strict allow-list) — the governance half is
  G8's instantiation table; the entry-point-enumeration half stays with P7.

Companion reading: [PROPERTIES_DEPOSIT.md](PROPERTIES_DEPOSIT.md) and
[PROPERTIES_WITHDRAW.md](PROPERTIES_WITHDRAW.md) (the two sibling documents,
same structure — D-numbers and W-numbers are cross-referenced throughout),
PROPERTIES.md's P3 (the "no double-processing" shape this reuses), P5
(guardian-key immutability — **contradicted** by Finding **GF1** below), P7
(guard completeness) and P9 (presignature safety, which `end_reconfig`
touches via `reset_num_consumed_presigs`).

No governance or reconfiguration rules are encoded yet — unlike the deposit
and withdrawal sides, `certora/specs/setup/sources/` contains nothing for
this flow. Everything below is to-write.

---

## G0 — State model

Two genuinely independent state machines live here, sharing only one edge.

### 1. The generic proposal engine

```
public struct Proposal<T> has key, store {
    id: UID,
    creator: address,                    // the validator address that created it (auto-votes)
    votes: vector<address>,              // validator addresses, de-duplicated by the vote guard
    quorum_threshold_bps: u64,           // PINNED at creation, never updated
    created_timestamp_ms: u64,           // PINNED at creation, never updated
    executed_timestamp_ms: Option<u64>,  // None until execute
    metadata: VecMap<String, String>,
    data: T,                             // the payload; T is one of the seven types below
}                                                          // proposal.move:40-50

public struct Proposals has store {
    active:   ObjectBag,   //  ID      -> Proposal<T>   (created, not yet executed)
    executed: ObjectBag,   //  address -> Proposal<T>   (executed; never removed)
}                                                          // proposals.move:17-23
```

There is **no status enum** — state is `(bag membership, executed_timestamp_ms,
clock vs. created_timestamp_ms)`. Exactly the deposit-side shape (D0), not
the withdrawal-side dual representation (W0), so there is no G-analogue of
W3's status/bag coherence property. What there *is* instead is G7: the
`executed_timestamp_ms` field and `executed`-bag membership are the
redundant pair, and they are written in the same statement sequence
(`proposal.move:207` then `:212`).

**Note the key-type asymmetry** — `active` is keyed by `ID`
(`active_mut().add(proposal_id, proposal)`, `:182`), `executed` by
`address` (`executed_mut().add(id.to_address(), proposal)`, `:212`), and
membership is tested as `executed().contains(proposal_id.to_address())`
(`:199`, `:142`). Dynamic-field keys are type-tagged, so `ID` and `address`
occupy disjoint namespaces and this is not a collision risk — but it means
every spec accessor must take the *right* key type, and
`executed.contains(some_ID)` would silently be `false` forever. See Finding
**GF7**.

### 2. The committee-reconfiguration state machine

Hand-rolled, not built on `Proposal<T>`:

```
public struct CommitteeSet has store {
    members: Bag,                                   // address -> MemberInfo (registered nodes)
    epoch: u64,                                     // the CURRENT Hashi epoch
    committees: Bag,                                // u64 -> Committee  AND
                                                    // CommitteeHandoffKey -> CommitteeHandoff
    pending_epoch_change: Option<PendingEpochChange>,  // Some(..) == "reconfiguring"
    mpc_public_key: vector<u8>,                     // empty == "genesis not yet completed"
}                                                          // committee_set.move:25-33

public struct PendingEpochChange has copy, drop, store {
    epoch: u64,                                            // the NEXT epoch
    committee_handoff_cert: Option<CommitteeSignature>,    // None until submit_committee_handoff
}                                                          // :40-43

public struct CommitteeHandoffKey has copy, drop, store { epoch: u64 }  // :49-51
public struct CommitteeHandoff     has store { next_epoch: u64, cert: CommitteeSignature }  // :57-60
```

`committees` is one `Bag` carrying **two different key types** — `u64` for
the per-epoch `Committee` (`insert_committee`, `:379-381`;
`has_committee`, `:341-343`) and `CommitteeHandoffKey` for the archived
handoff certs (`insert_committee_handoff`, `:317-326`). Another P11
instance, same shape as the `active`/`executed` asymmetry above; see G17.

### State-machine → entry-point map

**Proposal engine** (every row is version-gated and nothing else; see G9):

| Transition | Entry / function | Location | Guard |
|---|---|---|---|
| → Created (in `active`, creator auto-voted) | `<type>::propose` → `proposal::create` | e.g. `emergency_pause.move:22-45`, `proposal.move:153-185` | `member_authorized(validator_address, ctx)` (`:165`); `active.add` aborts on dup key (`:182`) |
| Created → voted | `proposal::vote<T>` (entry) | `:87-108` | `member_authorized` (`:95`); `!votes.contains(voter)` (`EVoteAlreadyCounted`, `:99`); `!is_expired` (`EProposalExpired`, `:100`); `active.borrow_mut` aborts if absent (`:97`) |
| voted → un-voted | `proposal::remove_vote<T>` (entry) | `:111-131` | `member_authorized` (`:118`); vote must exist (`ENoVoteFound`, `:124`); **no expiry check** |
| Created/voted → Executed (`active` → `executed`) | `<type>::execute` → `proposal::execute` | e.g. `emergency_pause.move:47-51`, `proposal.move:187-216` | `!executed.contains(..)` (`EProposalAlreadyExecuted`, `:198-201`, **before** the remove); `active.remove` aborts if absent (`:202`); `!is_expired` (`:204`); `quorum_reached` (`:205`) |
| Created/voted → deleted (expired, unexecuted) | `proposal::delete_expired<T>` (public) | `:135-149` | `!executed.contains(..)` (`:141-144`); `active.remove` aborts if absent (`:145`); `is_expired` (`EProposalNotExpired`, `:147`); **permissionless — no member check** |

**Reconfiguration** (all version-gated; none pause- or reconfig-gated):

| Transition | Entry / function | Location | Guard |
|---|---|---|---|
| Idle → Reconfiguring | `reconfig::start_reconfig` → `CommitteeSet::start_reconfig` | `reconfig.move:59-79`, `committee_set.move:235-264` | `!is_reconfiguring()` (`reconfig:66` / `cs:242`, both bare); `!has_committee(ctx.epoch())` (`cs:245`); `epoch == 0 \|\| epoch != ctx.epoch()` (`cs:248`); genesis gated on `finish_publish` (`assert_genesis_launch_authorized`, `reconfig:67`, `:149-153`) |
| Reconfiguring → handoff recorded | `reconfig::submit_committee_handoff` → `set_pending_committee_handoff_cert` | `reconfig.move:119-138`, `committee_set.move:266-274` | `is_reconfiguring()` (`reconfig:125`); `!mpc_public_key.is_empty()` (`EInitialReconfig`, `:126`); **current** committee's cert over `CommitteeTransitionRequest` (`:131-136`); `committee_handoff_cert.is_none()` (`cs:271`, bare) |
| Reconfiguring → Idle, epoch advances | `reconfig::end_reconfig` → `CommitteeSet::end_reconfig` | `reconfig.move:81-117`, `committee_set.move:276-301` | `is_reconfiguring()` (`reconfig:88` / `cs:281`); **next** committee's cert over `ReconfigCompletionMessage` (`:93-98`); `has_committee(next_epoch)` (`cs:285`); non-initial requires `committee_handoff_cert.is_some()` (`cs:292`); `mpc_public_key` pinned (`cs:297`) |
| Reconfiguring → Idle, epoch does **not** advance | `abort_reconfig::execute` → `CommitteeSet::abort_reconfig` | `types/abort_reconfig.move:61-71`, `committee_set.move:303-315` | routed through the proposal engine at `THRESHOLD_BPS = 6667` (`abort_reconfig.move:18`); post-execute re-checks `is_reconfiguring()` (`:64`) and `pending_epoch == proposal.epoch` (`:65-68`, `:70`) |

**The single edge between the two machines** is that last row: the generic
engine can cancel a state in the bespoke one. Nothing goes the other way.

---

## Rule-writing conventions used below

Same three readings as the deposit and withdrawal documents — **the Prover
only models non-aborting executions**, so an abort prunes a path rather
than being a checkable outcome:

- **assert** — "if the call succeeded, X was/became true". Restates a guard
  the code already enforces as a checked postcondition.
- **expect-unreachable** — "this sequence can never complete successfully".
  Written as: run the sequence, then `cvlm_assert(false)`; desired result
  **Verified**. Follows the encoded convention in
  [deposit_integrity.move](../specs/deposit/sources/deposit_integrity.move)
  and [withdraw_mutual_exclusion.move](../specs/withdraw/sources/withdraw_mutual_exclusion.move),
  not PROPERTIES_DEPOSIT.md's older `cvlm_satisfy_msg(true, ...)` spelling.
- **expect-reachable** — `cvlm_satisfy_msg(true, ...)` used the normal way,
  desired result **satisfiable**, as a positive witness that an intended
  bypass really works.

The two modeling gotchas from [CLAUDE.md](../README.md) apply as usual:
**never `==`/`!=` on `Option<T>`** (`executed_timestamp_ms`,
`pending_epoch_change`, `committee_handoff_cert`,
`CommitteeSet::pending_epoch_change()`'s returned `Option<u64>`, and
`config::try_get`'s `Option<Value>` are all `Option`s here), and **assume
bag keys match the stored object's own id** wherever a rule inspects the
same id before *and* after a call. `proposal::execute` is a
remove-then-reinsert keyed by the **removed object's own**
`proposal.id.to_inner().to_address()` (`:210`, `:212`), *not* by the
`proposal_id` argument used to remove it — precisely the
`approve_deposit`/`confirm_deposit` shape documented in CLAUDE.md, so G1,
G2 and G7 all need the `key_matches_object` assumption.

Three conventions are **specific to this document**:

**1. `Proposal<T>` is generic; rules must be monomorphic.** Every rule
below has to instantiate `T` at a concrete payload type. Instantiate at
`EmergencyPause` (`emergency_pause.move:16-18`) by default — it is the
smallest `copy + drop + store` payload and the one P13 is about — and
argue the generic case by parametricity: `proposal::create`/`vote`/
`remove_vote`/`execute`/`delete_expired` contain no `T`-dependent
branching whatsoever, so a proof at one payload type is a proof at all
seven. State that argument explicitly in the module docstring rather than
leaving it implicit; it is the one place this document leans on a
meta-argument instead of the Prover.

**2. Prefer the monomorphic `types/*` wrappers over the generic engine
functions.** `emergency_pause::propose` and `emergency_pause::execute`
(`:22-45`, `:47-51`) are already **plain `public fun` and non-generic** —
directly callable from spec code with no patch at all. The generic
`proposal::vote<T>`/`remove_vote<T>` are private `entry`, and
`delete_expired<T>` is `public` but generic. Whether cvlm's `target()` and
direct-call machinery can name a *generic* Move function is an **open
toolchain question** — every target in the encoded deposit/withdrawal specs
is monomorphic. The cheap, robust answer is to add thin monomorphic
wrappers in the patch (`vote_emergency_pause`, `remove_vote_emergency_pause`,
`delete_expired_emergency_pause`) rather than to find out the hard way; see
the accessor list.

**3. `quorum_reached` reads live committee state, so rules that assume
anything about voting weight must pin the committee.** `quorum_reached`
(`:218-227`) folds `hashi.current_committee().get_member_weight(&voter)`
over the votes and compares against
`threshold::weight_threshold(total_weight, proposal.quorum_threshold_bps)`.
`get_member_weight` returns **0** for a non-member
(`committee.move:158-160`, `find_index(..).destroy_or!(0)`), which is what
makes stale votes harmless across a reconfig (G6) — but it also means a
fully-`nondet` `Committee` can have `total_weight` bearing no relation to
the sum of its members' weights. Assume `total_weight >= get_member_weight(v)`
for any voter `v` you reason about, or state the rule so it doesn't depend
on the relationship.

---

## G1 — Proposal bag-membership mutual exclusion

**Statement (English)**: for every `proposal_id`, at every point after
`create` mints it, it is in **exactly one** of `{active, executed}`, or in
neither (never created, or deleted as expired) — never both. Direct
analogue of D1 and W1.

**Grounding**: `create` (`:182`) is the only writer of `active`;
`execute` (`:202`) and `delete_expired` (`:145`) are the only removers,
both via `ObjectBag::remove`, which **aborts if the key is absent**.
`execute` (`:212`) is the only writer of `executed`, and **nothing ever
removes from `executed`** (`proposals.move:20-22` states the intent:
"Kept indefinitely so historical governance actions remain inspectable").
The remove-then-add in `execute` (`:202` → `:212`) is the only transfer
between the two bags.

**Rule shape**: assert-style, parametric over the targets that take an
existing `proposal_id`; `propose` needs its own base case, exactly as
`deposit()` did in
[deposit_mutual_exclusion.move](../specs/deposit/sources/deposit_mutual_exclusion.move).

```
target(@hashi, b"emergency_pause", b"execute");
target(@hashi, b"proposal", b"delete_expired_emergency_pause");
target(@hashi, b"proposal", b"vote_emergency_pause");
target(@hashi, b"proposal", b"remove_vote_emergency_pause");
invoker(b"invoke");   // native fun invoke(target: Function, hashi: &mut Hashi, proposal_id: ID);

fun proposal_mutual_exclusion(hashi: &mut Hashi, proposal_id: ID, target: Function) {
    let ps = hashi.proposals();
    cvlm_assume_msg(
        object::id(ps.active()) != object::id(ps.executed()),
        b"active and executed are distinct ObjectBags, as in any reachable state",
    );
    cvlm_assume_msg(
        !(ps.contains_active(proposal_id) && ps.contains_executed(proposal_id.to_address())),
        b"proposal_id starts in at most one of {active, executed}",
    );

    invoke(target, hashi, proposal_id);

    let ps2 = hashi.proposals();
    cvlm_assert(!(ps2.contains_active(proposal_id) && ps2.contains_executed(proposal_id.to_address())));
}
```

**Base case** (`emergency_pause::propose`, which takes no `proposal_id`):
same treatment as `deposit_does_not_create_duplicate_request` — assume
`proposal_id` starts absent from **both** bags, not merely "not in both",
because nothing ties a pre-existing nondet key in `executed` to Sui's
object-freshness ghost, so the Prover could otherwise have `create`'s
`object::new` (`:171`) mint exactly a colliding id.

**Needs**: `proposals` (bump on `Hashi`), `active`/`executed` (bump on
`Proposals`), `contains_active`/`contains_executed` (new, and the place to
encapsulate the `ID`-vs-`address` key-type asymmetry so no rule gets it
wrong).

---

## G2 — Execution is at most once, ever

**Statement (English)**: for a fixed `proposal_id`, `proposal::execute` can
succeed **at most once** — and therefore so can every concrete governance
action built on it.

**Grounding**, two independent mechanisms, in this order:
1. `assert!(!executed.contains(proposal_id.to_address()), EProposalAlreadyExecuted)`
   (`:198-201`), checked **before** the `active.remove`. The comment
   (`:194-197`) says this exists purely to improve the failure surface —
   "so the failure surface is `EProposalAlreadyExecuted` rather than the
   ObjectBag's generic missing-key abort".
2. `active.remove(proposal_id)` (`:202`) — aborts on an absent key, which
   is what actually makes re-execution impossible, given G1.

So (1) is **structurally redundant given G1** — the same
defensive-double-guard shape as D1's note on `delete_expired`'s
`EDepositAlreadyProcessed` and W6's note on
`ECannotCancelProcessingWithdrawal`. Proving G1 turns (1) into a nicer
error message rather than a security boundary, which is worth establishing
rather than assuming from the comment.

**Rule shape**: expect-unreachable.

```
fun execute_at_most_once(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    hashi::emergency_pause::execute(hashi, proposal_id, clock);   // call 1, allowed to succeed
    hashi::emergency_pause::execute(hashi, proposal_id, clock);   // call 2, same id

    cvlm_assert(false);   // desired result: Verified (unreachable)
}
```

Expect the `-rule_not_vacuous_tac` companion to come back **Violated**, as
it does for the two-call shape in `deposit_integrity::confirm_deposit_at_most_once`
and `withdraw_mutual_exclusion::confirm_withdrawal_at_most_once` — not
Verified, despite the general prediction for expect-unreachable rules.

**Needs**: nothing beyond G1's — `emergency_pause::execute` is already
`public fun`.

---

## G3 — No post-expiry execution, and the expiry window is not governable

**Statement (English)**: `execute` cannot succeed once
`clock.timestamp_ms() > created_timestamp_ms + 7 days`; `vote` likewise;
and no governance action can extend that window for an existing proposal.

**Grounding**: `is_expired` (`:229-231`) is
`clock.timestamp_ms() > proposal.created_timestamp_ms + MAX_PROPOSAL_DURATION_MS`,
with `MAX_PROPOSAL_DURATION_MS: u64 = 1000*60*60*24*7` (`:19`) a
**compile-time constant, not a config key** — so unlike the emergency
thresholds (G11) it is outside `update_config`'s reach and can only change
via a package upgrade. Checked at `vote` (`:100`) and `execute` (`:204`).
`created_timestamp_ms` is written once at creation (`:168`, `:175`) and
never assigned again — grep confirms it is read at `:230` and nowhere else
assigned.

Note the strict `>`: a proposal is executable exactly *at*
`created + 7 days`, not one millisecond past. Minor, but a rule stating
`<=` rather than `<` would be wrong.

**Rule shape**: assert-style, restating both guards as postconditions.

```
fun execute_within_expiry_window(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let ps = hashi.proposals();
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    let created = ps.borrow_active(proposal_id).proposal_created_timestamp_ms();

    hashi::emergency_pause::execute(hashi, proposal_id, clock);

    cvlm_assert(clock.timestamp_ms() <= created + hashi::proposal::max_proposal_duration_ms());
}

fun expiry_deadline_is_immutable(hashi: &mut Hashi, proposal_id: ID, target: Function) {
    let ps = hashi.proposals();
    cvlm_assume_msg(key_matches_object(ps, proposal_id), b"bag key matches the object's own id");
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    let created_before = ps.borrow_active(proposal_id).proposal_created_timestamp_ms();

    invoke(target, hashi, proposal_id);   // vote, remove_vote, execute

    let ps2 = hashi.proposals();
    if (ps2.contains_active(proposal_id)) {
        cvlm_assert(ps2.borrow_active(proposal_id).proposal_created_timestamp_ms() == created_before);
    };
}
```

**Needs**: `borrow_active` (new), `proposal_created_timestamp_ms` (new),
`max_proposal_duration_ms` (new — exposes the private constant).

---

## G4 — An executed proposal can never be deleted

**Statement (English)**: `delete_expired` cannot succeed for a
`proposal_id` that has already executed, regardless of how much time has
passed.

**Grounding**: `assert!(!executed.contains(proposal_id.to_address()), EProposalAlreadyExecuted)`
(`:141-144`), with the comment at `:137-140` stating the intent directly:
"Executed proposals are archived in the executed bag and must never be
deletable, even after they expire." Structurally this is the same
defensive check as G2's (1), and it is redundant for the same reason —
an executed proposal is no longer in `active`, so `active.remove` (`:145`)
would abort anyway.

`delete_expired` is **permissionless** — it is `public fun` with no
`member_authorized` check, unlike `vote`/`remove_vote`/`create`. That is
intentional GC (anyone may clean up a dead proposal) and is worth an
expect-reachable witness so a reader doesn't mistake it for a missing
guard. Direct analogue of D9a (deposit GC) and W13's `cleanup_spent_utxos`.

**Rule shape**: assert-style for the guard, expect-reachable for the
permissionless-GC witness.

```
fun delete_expired_requires_not_executed(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let was_executed = hashi.proposals().contains_executed(proposal_id.to_address());

    let _payload = hashi::proposal::delete_expired_emergency_pause(hashi, proposal_id, clock);

    cvlm_assert(!was_executed);
}

fun delete_expired_requires_expiry(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let ps = hashi.proposals();
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    let created = ps.borrow_active(proposal_id).proposal_created_timestamp_ms();

    let _payload = hashi::proposal::delete_expired_emergency_pause(hashi, proposal_id, clock);

    cvlm_assert(clock.timestamp_ms() > created + hashi::proposal::max_proposal_duration_ms());
}
```

**G4c** (an executed proposal stays in `executed` forever) — fully a
corollary of G1 plus "nothing removes from `executed`" (a grep-level fact:
`executed_mut()` has exactly one call site, `proposal.move:212`, an `add`).
No separate rule needed; state it in English, the same way D9c and W16's
creation-side indexing are handled.

**Needs**: as G3, plus the monomorphic `delete_expired_emergency_pause`
wrapper.

---

## G5 — Vote-set integrity

**Statement (English)**: a proposal's `votes` vector contains no
duplicates, contains only addresses that were authorized committee members
at the moment their vote was cast, and changes only through `vote` and
`remove_vote`.

**Grounding**:
- `assert!(!proposal.votes.contains(&validator_address), EVoteAlreadyCounted)`
  (`:99`) — the only thing keeping `votes` duplicate-free, and therefore
  the only thing keeping `quorum_reached`'s fold (`:219-221`) from
  double-counting one member's weight.
- `member_authorized(validator_address, ctx)` (`:95`, `:118`, `:165`) →
  `has_member(..) && member(..).is_authorized(ctx)`
  (`committee_set.move:144-150`). **Note what this checks**: membership in
  the `members` bag — every *registered* node — and that `ctx.sender()` is
  that member's validator or delegated operator address
  (`:440-443`). It does **not** check current-committee membership. So a
  registered validator that is not in `current_committee()` may vote; its
  weight is then 0 (`get_member_weight`, `committee.move:158-160`), so the
  vote is inert. That is a deliberate and benign decoupling, but it means
  "votes ⊆ current committee" is **not** an invariant and no rule should
  assume it.
- `remove_vote` (`:111-131`) removes by index found via `find_index!`
  (`:121-124`), aborting `ENoVoteFound` if absent. It carries **no expiry
  check**, unlike `vote` — so votes on an expired proposal can still be
  withdrawn. Harmless (an expired proposal can't execute anyway) but
  asymmetric; worth a witness rather than a comment.

**Rule shape**: assert-style for the duplicate guard, expect-unreachable
for the double vote, expect-reachable for the expired-remove asymmetry.

```
fun no_duplicate_votes(hashi: &mut Hashi, proposal_id: ID, v: address, clock: &Clock, ctx: &mut TxContext) {
    hashi::proposal::vote_emergency_pause(hashi, v, proposal_id, clock, ctx);
    hashi::proposal::vote_emergency_pause(hashi, v, proposal_id, clock, ctx);

    cvlm_assert(false);   // desired: Verified (unreachable) — EVoteAlreadyCounted (:99)
}

fun vote_requires_authorized_member(hashi: &mut Hashi, proposal_id: ID, v: address, clock: &Clock, ctx: &mut TxContext) {
    let was_authorized = hashi.committee_set().member_authorized(v, ctx);

    hashi::proposal::vote_emergency_pause(hashi, v, proposal_id, clock, ctx);

    cvlm_assert(was_authorized);
    cvlm_assert(hashi.proposals().borrow_active(proposal_id).proposal_has_vote(v));
}

fun remove_vote_works_after_expiry(hashi: &mut Hashi, proposal_id: ID, v: address, ctx: &mut TxContext) {
    let ps = hashi.proposals();
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    // (assume the clock has advanced past created_timestamp_ms + MAX_PROPOSAL_DURATION_MS)

    hashi::proposal::remove_vote_emergency_pause(hashi, v, proposal_id, ctx);

    cvlm_satisfy_msg(true, b"removed a vote from an expired proposal");
    // desired result: satisfiable
}
```

**Needs**: `member_authorized` (bump), `proposal_has_vote` (new — `votes`
is `public(package)` and returns the raw vector; a predicate is cheaper to
reason about), the two monomorphic vote wrappers.

---

## G6 — Quorum is live, but the threshold is pinned

**Statement (English)**: `execute` admits a proposal iff, **at execution
time**, the aggregate weight of its voters under the **current** committee
meets `ceil(total_weight · quorum_threshold_bps / 10000)`, where
`quorum_threshold_bps` is the value captured **at creation time**. There is
no "quorum locked in" snapshot that can go stale between quorum being
reached and `execute` running.

**Grounding**: `quorum_reached` (`:218-227`) recomputes from
`hashi.current_committee()` on every call — used both for the informational
`QuorumReached` event at `vote` (`:105-107`) and, authoritatively, at
`execute` (`:205`). `quorum_threshold_bps` is written once at creation
(`:174`) and never assigned again. `weight_threshold`
(`threshold.move:35-38`) is `divide_and_round_up`, i.e. genuine ceiling
division, guarded by `assert!(threshold_bps <= MAX_BPS, EThresholdBpsTooHigh)`
(`:36`).

**Two consequences worth stating as separate sub-properties**, because they
pull in opposite directions and both are load-bearing for P13:

- **G6a — committee rotation can revoke a reached quorum.** A proposal that
  reached quorum in epoch N may fail `execute` in epoch N+1 if its voters
  lost weight or left the committee (`get_member_weight → 0`). This is the
  *safe* direction and is what P15's original write-up meant by "no stale
  snapshot".
- **G6b — committee rotation can also *create* a quorum.** The same
  recomputation means a proposal whose voters' weight was insufficient at
  vote time can become executable later, without any new vote, purely
  because the committee shrank or re-weighted. Nothing pins the proposal to
  the committee that voted on it. The `abort_reconfig` module doc
  (`:6-9`) shows the authors reasoned about which committee should govern
  ("the last committed committee is the only committee with stable on-chain
  voting power") — but that reasoning is about *which* committee, not about
  the fact that it can change underneath a live proposal. Worth confirming
  this is intended.

**Rule shape**: assert-style for the threshold link; expect-reachable for
G6b.

```
fun execute_requires_quorum(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let ps = hashi.proposals();
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    let p = ps.borrow_active(proposal_id);
    let bps = p.proposal_quorum_threshold_bps();
    let weight = p.proposal_voting_weight(hashi);          // the same fold quorum_reached does
    let total = hashi.current_committee().total_weight();

    hashi::emergency_pause::execute(hashi, proposal_id, clock);

    cvlm_assert(weight >= hashi::threshold::weight_threshold(total, bps));
}

fun threshold_bps_is_immutable(hashi: &mut Hashi, proposal_id: ID, target: Function) {
    let ps = hashi.proposals();
    cvlm_assume_msg(key_matches_object(ps, proposal_id), b"bag key matches the object's own id");
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    let bps_before = ps.borrow_active(proposal_id).proposal_quorum_threshold_bps();

    invoke(target, hashi, proposal_id);   // vote, remove_vote, execute

    let ps2 = hashi.proposals();
    if (ps2.contains_active(proposal_id)) {
        cvlm_assert(ps2.borrow_active(proposal_id).proposal_quorum_threshold_bps() == bps_before);
    };
}
```

Pair `threshold_bps_is_immutable` with G11's `update_config` rules: together
they say "an in-flight proposal's bar cannot be moved, but the bar for the
*next* proposal of the same kind can be" — which is exactly the shape P13
has to reason about.

**Needs**: `quorum_reached` (bump) or `proposal_voting_weight` (new —
preferable, since it lets the rule assert the arithmetic rather than
re-assert the predicate), `proposal_quorum_threshold_bps` (new),
`weight_threshold` (bump), `total_weight`/`current_committee` (bump).

---

## G7 — `executed_timestamp_ms` and bag membership agree

**Statement (English)**: for every proposal, `executed_timestamp_ms.is_some()`
**iff** it lives in the `executed` bag — the two redundant encodings of
"has executed" never diverge.

**Grounding**: `create` sets `executed_timestamp_ms: option::none()`
(`:176`) and inserts into `active` (`:182`). `execute` sets
`option::some(clock.timestamp_ms())` (`:207`) in the same statement
sequence that adds to `executed` (`:212`). Nothing else writes the field —
grep confirms `:176` and `:207` are the only assignments. So the property
holds by construction, atomically; but it holds **entirely by call-site
discipline**, with no assert anywhere, which is exactly why W3 was worth
proving on the withdrawal side.

Unlike W3 this one is cheap: there is only one writer pair, not four.

**Rule shape**: assert-style, parametric — an invariant over all targets.
This is the G-analogue of W3.

```
fun executed_flag_matches_bag(hashi: &mut Hashi, proposal_id: ID, target: Function) {
    let ps = hashi.proposals();
    cvlm_assume_msg(key_matches_object(ps, proposal_id), b"bag key matches the object's own id");
    cvlm_assume_msg(
        object::id(ps.active()) != object::id(ps.executed()),
        b"active and executed are distinct ObjectBags",
    );
    cvlm_assume_msg(executed_flag_coherent(ps, proposal_id), b"flag agrees with bag membership pre-call");

    invoke(target, hashi, proposal_id);

    cvlm_assert(executed_flag_coherent(hashi.proposals(), proposal_id));
}

// helper, in the spec module — a conjunction, not an if/else chain, for the
// same reason the pre-rebase withdraw_status_coherence helper was (see git history).
fun executed_flag_coherent(ps: &Proposals, id: ID): bool {
    (!ps.contains_active(id) || ps.borrow_active(id).proposal_executed_timestamp_ms().is_none())
        && (!ps.contains_executed(id.to_address())
            || ps.borrow_executed(id.to_address()).proposal_executed_timestamp_ms().is_some())
}
```

Heed W3's second deviation note: `key_matches_object` must hold for the key
the call *writes*, not merely the key the rule *observes*, or a nondet
`Proposals` can have `active[j]` and `executed[k]` resolve to the same
`Proposal` object for unrelated `j`, `k` — after which a write through one
bag is visible through the other and no flag value satisfies both. Here
both keys are the same `proposal_id`, so one pin suffices and no module
split is needed — a genuine simplification over W3.

**Needs**: `borrow_active`/`borrow_executed` (new),
`proposal_executed_timestamp_ms` (new), `active`/`executed` (bump).

---

## G8 — Each concrete governance action applies exactly once

**Statement (English)**: each of the seven payload types applies its effect
exactly once per proposal, and only after `proposal::execute` has released
the payload — so the engine's at-most-once guarantee (G2) is inherited by
every governance action.

**Grounding**: every `types/*::execute` has the identical shape —
destructure the payload out of `proposal::execute(...)`, then apply:

| Payload | `execute` | Effect | Effect location |
|---|---|---|---|
| `EmergencyPause { pause }` | `emergency_pause.move:47-51` | `config_mut().set_paused(pause)` | `:50` |
| `AbortReconfig { epoch }` | `abort_reconfig.move:61-71` | `committee_set_mut().abort_reconfig(ctx)` | `:69` |
| `DisableVersion { version }` | `disable_version.move:47-50` | `versioning_mut().disable_version(version)` | `:49` |
| `EnableVersion { version }` | `enable_version.move:47-50` | `versioning_mut().enable_version(version)` | `:49` |
| `UpdateConfig { entries }` | `update_config.move:56-67` | per-entry `config_mut().upsert(..)` | `:65` |
| `UpdateGuardian { url }` | `update_guardian.move:47-50` | `config_mut().set_guardian_url(url)` | `:49` |
| `Upgrade { digest }` | `upgrade.move:66-69` | `versioning_mut().authorize_upgrade(digest)` → `UpgradeTicket` | `:68` |

**Two things this table makes visible.**

First, **the effect runs *after* the proposal has already been archived
into `executed`** (`proposal.move:212` precedes every row's effect). If the
effect aborts, the whole transaction rolls back — including the archival —
so the proposal stays `active` and remains executable. That is the correct
outcome, but note *why* it is correct: it rests on **Move/Sui transaction
atomicity, a VM guarantee, not model state**, so it is not expressible as a
`cvlm_assert` property. Exactly the same caveat D6 recorded for
`mint_balance`-before-`insert_active` and F8 for
selection-before-`lock`. **Audit note, not a rule.**

Effects that can genuinely abort after archival, and are therefore worth
knowing about: `enable_version` on an already-enabled version
(`VecSet::insert` aborts on duplicate, `versioning.move:61`),
`disable_version` on a version that isn't enabled (`VecSet::remove` aborts
on absent, `:57`) or on the current one (`EDisableCurrentVersion`, `:56`),
and `update_config` on an entry that fails validation (`EInvalidConfigEntry`,
`update_config.move:60-64` — see **GF10**).

Second, **`Upgrade` is the one payload whose effect is not self-contained**:
`execute` returns an `UpgradeTicket` that must be consumed by
`sui::package::upgrade` in the same PTB, with the resulting receipt fed to
`upgrade::finalize_upgrade` (`:71-77`), which calls `commit_upgrade`
(`versioning.move:75-79`) and auto-enables the new version (`:78`). The
at-most-once guarantee covers the *authorization*, not the completion — a
ticket obtained and then dropped leaves the proposal executed with no
upgrade performed and no way to retry it (a second `execute` hits
`EProposalAlreadyExecuted`). Worth confirming that is the intended
failure mode; it is the only governance action that can be consumed
without taking effect.

**Rule shape**: assert-style, one per payload, checking the effect landed.
The at-most-once half needs no new rule — it is G2 instantiated.

```
fun emergency_pause_execute_sets_paused(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let ps = hashi.proposals();
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    let pause = ps.borrow_active(proposal_id).proposal_data().emergency_pause_flag();

    hashi::emergency_pause::execute(hashi, proposal_id, clock);

    cvlm_assert(hashi.config().paused() == pause);
    cvlm_assert(hashi.proposals().contains_executed(proposal_id.to_address()));
}
```

**Needs**: `proposal_data` (the existing `#[test_only] public fun data`,
`proposal.move:249-252`, is already callable under the Prover's `--test`
build — no patch needed), `emergency_pause_flag` (new accessor on the
payload struct, whose field is private).

---

## G9 — Guard completeness (governance instance of PROPERTIES.md P7)

**Statement (English)**: enumerate exactly what each governance and
reconfiguration entry point checks before any state mutation.

| Function | `version_enabled` | `unpaused` | `not_reconfiguring` | member auth |
|---|---|---|---|---|
| `proposal::vote` (`:87-108`) | ✓ (`:94`) | **not checked** | **not checked** | ✓ (`:95`) |
| `proposal::remove_vote` (`:111-131`) | ✓ (`:117`) | **not checked** | **not checked** | ✓ (`:118`) |
| `proposal::delete_expired` (`:135-149`) | ✓ (`:136`) | **not checked** | **not checked** | **not checked** — permissionless GC |
| `proposal::create` (`:153-185`) | **not checked** — every caller does it (GF8) | **not checked** | **not checked** | ✓ (`:165`) |
| `proposal::execute` (`:187-216`) | ✓ (`:192`) | **not checked** | **not checked** | **not checked** — permissionless once quorum holds |
| `<type>::propose` ×7 | ✓ (each, e.g. `emergency_pause.move:30`) | **not checked** | **not checked** | via `create` |
| `<type>::execute` ×7 | ✓ via `proposal::execute`; `emergency_pause` (`:48`) and `abort_reconfig` (`:63`) also check directly | **not checked** | **not checked** | — |
| `upgrade::finalize_upgrade` (`:71-77`) | ✓ (`:72`) | **not checked** | **not checked** | **not checked** — holding the receipt is the authorization |
| `reconfig::start_reconfig` (`:59-79`) | ✓ (`:64`) | **not checked** | n/a — asserts the *negation* (`:66`) | **not checked** |
| `reconfig::submit_committee_handoff` (`:119-138`) | ✓ (`:124`) | **not checked** | n/a — **requires** reconfiguring (`:125`) | cert-gated (`:131-136`) |
| `reconfig::end_reconfig` (`:81-117`) | ✓ (`:87`) | **not checked** | n/a — **requires** reconfiguring (`:88`) | cert-gated (`:93-98`) |

**The pause omissions are necessary, not accidental** — the whole point of
`emergency_pause` is to be usable while paused, and unpausing is impossible
if `vote`/`execute` are pause-gated. Likewise, governance must keep
functioning during a reconfiguration, and `abort_reconfig` exists
*specifically* to be callable then. But **not one of these omissions
carries a source comment**, where `withdraw.move` documents its deliberate
omissions inline (`:360-361`, `:339-341`). Same shape as W13's findings F5
and F6; see **GF6**.

**Rule shape**: assert-style for the ✓ cells (mirroring the existing
[deposit_version_enabled.move](../specs/deposit/sources/deposit_version_enabled.move) /
[withdraw_version_enabled.move](../specs/withdraw/sources/withdraw_version_enabled.move)
rules, which is the cheapest new rule in this document); expect-reachable
witnesses for the omissions.

```
fun governance_is_version_enabled(hashi: &mut Hashi, proposal_id: ID, target: Function) {
    invoke(target, hashi, proposal_id);
    cvlm_assert(hashi.versioning().is_version_enabled());
}

fun governance_callable_while_paused(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    cvlm_assume_msg(hashi.config().paused(), b"system is paused");
    hashi::emergency_pause::execute(hashi, proposal_id, clock);
    cvlm_satisfy_msg(true, b"emergency_pause::execute succeeded while paused");
    // desired result: satisfiable — this is what makes unpausing possible at all
}

fun governance_callable_while_reconfiguring(hashi: &mut Hashi, proposal_id: ID, clock: &Clock, ctx: &TxContext) {
    cvlm_assume_msg(hashi.committee_set().is_reconfiguring(), b"reconfiguration in progress");
    hashi::abort_reconfig::execute(hashi, proposal_id, clock, ctx);
    cvlm_satisfy_msg(true, b"abort_reconfig::execute succeeded mid-reconfig");
}
```

**Needs**: `is_version_enabled` (already added by
`certora/patches/versioning.move.patch`), `paused` (already patched),
`is_reconfiguring` (already patched). The positive-case rule needs **no new
accessors at all** — it is the natural first rule to write here.

---

## G10 — The emergency-pause asymmetry is not invertible (P13, part 1)

**Statement (English)**: unpausing can never be achieved with less
committee weight than the unpause threshold requires — no sequence of
proposals lets a sub-supermajority coalition unpause the bridge.

**Grounding**: the asymmetry is real and lives in two config defaults
(`config.move:52-54`):
```
paused                                    = false
governance_emergency_pause_threshold_bps  =  500   //  5%     — fast response
governance_emergency_unpause_threshold_bps= 6667   // 66.67%  — supermajority
```
`emergency_pause::propose` picks between them on the `pause` flag
(`:31-35`) and pins the choice into the proposal's `quorum_threshold_bps`
(`proposal.move:174`), which G6 shows is immutable thereafter.

**The circumvention question has exactly three candidate paths, and all
three require ≥ 6667 bps**, i.e. at least as much weight as unpausing
directly:

1. **`update_config` setting `paused = false` directly.** This *works* —
   `PAUSED_KEY` is an ordinary `bool` config entry
   (`config.move:22`, `:52`), `is_valid_config_update` (`:99-102`) only
   requires the key to exist with a matching variant, and
   `update_config::execute` calls `config_mut().upsert(..)` (`:65`)
   directly rather than going through `set_paused`. But
   `update_config`'s `THRESHOLD_BPS = 6667` (`update_config.move:17`) is a
   hard-coded constant, equal to the unpause threshold. **No weakening.**
2. **`update_config` lowering `governance_emergency_unpause_threshold_bps`,
   then unpausing cheaply.** Also possible (see G11) — and also costs 6667
   bps up front, at which point the coalition could simply have unpaused.
   **No weakening**, but it *does* permanently weaken *future* unpauses.
3. **`upgrade`, replacing the pause logic entirely.** `THRESHOLD_BPS = 6667`
   (`upgrade.move:24`). **No weakening.**

So P13's statement holds, and the reason is uniform and checkable: **every
governance path that can clear `paused` costs at least
`governance_emergency_unpause_threshold_bps`, because all the alternatives
are hard-coded at 6667 and the default unpause threshold is 6667.** Note
carefully what that argument depends on: it is *not* structural, it is a
numeric coincidence between a config default and four `const`s. If
`governance_emergency_unpause_threshold_bps` were ever governed *above*
6667, paths (1)–(3) would become strictly cheaper than the direct one and
the asymmetry would invert. See **GF4**.

The converse direction is uninteresting but worth recording: pausing via
`update_config` costs 6667 rather than 500, i.e. the "fast response" lane
is not reachable through any other path. That is the safe direction.

**Rule shape**: assert-style on the proposal-creation side, because the
"no sequence of proposals" claim is a statement about the *set* of
threshold constants, not about any single execution. Encode the pieces the
Prover can actually see:

```
fun pause_proposal_threshold_matches_config(hashi: &mut Hashi, v: address, pause: bool, md: VecMap<String, String>, clock: &Clock, ctx: &mut TxContext) {
    let expected = if (pause) { hashi.config().emergency_pause_threshold_bps() }
                   else       { hashi.config().emergency_unpause_threshold_bps() };

    let id = hashi::emergency_pause::propose(hashi, v, pause, md, clock, ctx);

    cvlm_assert(hashi.proposals().borrow_active(id).proposal_quorum_threshold_bps() == expected);
}

fun unpause_requires_unpause_threshold(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let was_paused = hashi.config().paused();
    let ps = hashi.proposals();
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    let p = ps.borrow_active(proposal_id);
    let bps = p.proposal_quorum_threshold_bps();
    let weight = p.proposal_voting_weight(hashi);
    let total = hashi.current_committee().total_weight();

    hashi::emergency_pause::execute(hashi, proposal_id, clock);

    // if this call cleared the pause, it cleared it at the unpause bar
    if (was_paused && !hashi.config().paused()) {
        cvlm_assert(bps == hashi.config().emergency_unpause_threshold_bps());
        cvlm_assert(weight >= hashi::threshold::weight_threshold(total, bps));
    };
}
```

The second rule is the load-bearing one, and note it deliberately reads
`emergency_unpause_threshold_bps` **post-call** — `emergency_pause::execute`
never touches that key, so pre and post agree, and reading it post-call
keeps the rule honest if that ever changes.

The **"no other path clears `paused`"** half cannot be stated this way; it
is a whole-package frame property. Encode it as a separate parametric
frame rule over every governance target (G11's
`config_writes_are_governance_gated`), which is where it naturally belongs.

**Needs**: `emergency_pause_threshold_bps`, `emergency_unpause_threshold_bps`
(bump), plus G6's accessors.

---

## G11 — `update_config` is an unvalidated write to every config key (P13, part 2)

**Statement (English)**: `update_config` can set **any already-present
config key** to **any type-correct value**, bypassing every domain-specific
setter and its invariants. The only keys with value validation are the four
MPC parameters.

**Grounding**, and this is the single most consequential fact in this
document:
```
// update_config.move:56-67
let UpdateConfig { entries } = proposal::execute(hashi, proposal_id, clock);
let (keys, values) = entries.into_keys_values();
keys.zip_do!(values, |key, value| {
    assert!(
        hashi.config().is_valid_config_update(&key, &value)      // key exists && same variant
            && mpc_config::is_valid_value(&key, &value),          // ranges — MPC KEYS ONLY
        EInvalidConfigEntry,
    );
    hashi.config_mut().upsert(*key.as_bytes(), value);            // RAW upsert, not the setter
});
```
- `is_valid_config_update` (`config.move:99-102`) — "key is present" plus
  `same_variant`. No allow-list, no deny-list, no range.
- `mpc_config::is_valid_value` (`mpc_config.move:33-47`) — ranges exactly
  four keys (`mpc_threshold_in_basis_points`,
  `mpc_weight_reduction_allowed_delta`, `mpc_max_faulty_in_basis_points`,
  `mpc_nonce_generation_protocol`) and returns **`true` for everything
  else** (`:44-46`).
- `upsert` (`config.move:87-95`) is the raw store write. Every
  domain-specific setter (`set_paused`, `set_guardian_btc_public_key`,
  `set_bitcoin_withdrawal_minimum`, …) is a *wrapper* around it, and
  `update_config` calls the raw one.

**The governable surface**, i.e. every key present in a live config, is
therefore: `paused`, `guardian_url`, `guardian_btc_public_key`,
`governance_emergency_pause_threshold_bps`,
`governance_emergency_unpause_threshold_bps` (`config.move:22-28`, `:52-54`);
the four MPC keys (`mpc_config.move:26-29`, ranged); and
`bitcoin_deposit_time_delay_ms`, `bitcoin_deposit_minimum`,
`bitcoin_withdrawal_minimum`, `bitcoin_confirmation_threshold`,
`withdrawal_cancellation_cooldown_ms` (`btc_config.move:21-27`), plus
`bitcoin_chain_id` once `finish_publish` sets it.

**Three of those are load-bearing for properties stated elsewhere in this
audit**, and each needs re-reading with "governance can set this to
anything type-correct" in mind:

- `guardian_btc_public_key` — **directly contradicts P5**. See **GF1**; it
  is the headline finding of this pass.
- `governance_emergency_*_threshold_bps` — G10's numeric argument, and the
  `> MAX_BPS` footgun. See **GF4**.
- `bitcoin_withdrawal_minimum` — P2's dust-floor chain. **This one is
  safe**, and it is worth saying why: the accessor floors it,
  `bitcoin_withdrawal_minimum(self) = get(..).max(DUST_RELAY_MIN_VALUE + 1)`
  (`btc_config.move:42-44`), so `worst_case_network_fee >= 1` holds for any
  stored value whatsoever, including 0. P2's chain survives arbitrary
  governance because the invariant lives in the *reader*, not the writer.
  That is exactly the pattern the other two keys lack, and the cheapest fix
  for both.

**Rule shape**: expect-reachable witnesses for the reachability claims
(this is the rare case where the *satisfiable* result is the finding), plus
an assert-style frame rule for G10's "no other path".

```
// GF1, as an expect-REACHABLE witness. If SATISFIABLE, P5's Move-side
// guarantee is broken.
fun update_config_can_rotate_guardian_btc_key(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let before = hashi.config().guardian_btc_public_key();
    cvlm_assume_msg(before.is_some(), b"guardian key already set by finish_publish");
    let old = *before.borrow();

    hashi::update_config::execute(hashi, proposal_id, clock);

    let after = hashi.config().guardian_btc_public_key();
    cvlm_assume_msg(after.is_some(), b"key still present post-call");
    cvlm_satisfy_msg(*after.borrow() != old, b"governance rotated the immutable guardian BTC key");
    // desired result: SATISFIABLE — confirms GF1
}

// The complement: the immutability latch does hold on its own path.
fun set_guardian_btc_public_key_is_immutable(config: &mut Config, key: vector<u8>) {
    let before = config.guardian_btc_public_key();
    cvlm_assume_msg(before.is_some(), b"key already set");
    let old = *before.borrow();

    config.set_guardian_btc_public_key(key);

    cvlm_assert(key == old);   // restates EGuardianBtcPublicKeyImmutable (config.move:134)
}

// G10's frame half: only update_config and emergency_pause can move `paused`.
fun paused_only_changes_through_governance(hashi: &mut Hashi, proposal_id: ID, target: Function) {
    let was_paused = hashi.config().paused();

    invoke(target, hashi, proposal_id);   // every non-emergency_pause, non-update_config target

    cvlm_assert(hashi.config().paused() == was_paused);
}
```

The pair of guardian-key rules together is the clearest possible statement
of GF1: the latch is correct, and the governance path does not go through
it.

**Needs**: `guardian_btc_public_key`, `set_guardian_btc_public_key`,
`is_valid_config_update`, `contains`, `try_get` (bump);
`update_config::execute` is already `public fun`.

---

## G12 — One reconfiguration in flight at a time

**Statement (English)**: `pending_epoch_change` is a mutex — at most one
reconfiguration is pending at any time, and every transition into or out of
the reconfiguring state goes through exactly one of `start_reconfig`,
`end_reconfig`, `abort_reconfig`.

**Grounding**: `is_reconfiguring()` is literally
`pending_epoch_change.is_some()` (`committee_set.move:357-359`).
`pending_epoch_change` has exactly four writers — grep-confirmed:
`start_reconfig` (`:257-261`, `None → Some`, guarded by
`assert!(!self.is_reconfiguring())` at `:242`),
`set_pending_committee_handoff_cert` (`:270`, `:273` — `extract` then
put back, so `Some → Some`, never changing the `epoch` field),
`end_reconfig` (`:282-284`, `extract`, `Some → None`, guarded `:281`),
and `abort_reconfig` (`:305-307`, `extract`, `Some → None`, guarded `:304`).
The `#[test_only] set_pending_reconfig_for_testing` (`:528-539`) is a fifth
writer, compiled out of production but **visible to the Prover**, since
`certoraSuiProver` always builds with `--test` — exclude it from target
lists explicitly, or it will show up as a spurious way to enter the
reconfiguring state.

Note `set_pending_committee_handoff_cert`'s `extract()`-then-reassign
(`:270`, `:273`): between those two statements the option is `None`. That
is invisible to any external observer (no call can interleave inside a
Move function), but a rule reading `is_reconfiguring()` from *inside* a
summary of that function would see it. Don't summarize that function.

**Rule shape**: assert-style, parametric — the mutex as an invariant, plus
expect-unreachable for the double-start.

```
fun reconfig_is_mutually_exclusive(hashi: &mut Hashi, target: Function) {
    let was_reconfiguring = hashi.committee_set().is_reconfiguring();

    invoke(target, hashi);   // start_reconfig, submit_committee_handoff, end_reconfig, abort_reconfig::execute

    // entering requires having been idle; leaving requires having been busy
    let is_reconfiguring = hashi.committee_set().is_reconfiguring();
    cvlm_assert(is_reconfiguring == was_reconfiguring || true);   // see note
}

fun cannot_start_two_reconfigs(hashi: &mut Hashi, sui_system: &SuiSystemState, ctx: &TxContext) {
    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);
    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);

    cvlm_assert(false);   // desired: Verified (unreachable) — committee_set.move:242
}

fun start_requires_idle(hashi: &mut Hashi, sui_system: &SuiSystemState, ctx: &TxContext) {
    let was_reconfiguring = hashi.committee_set().is_reconfiguring();

    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);

    cvlm_assert(!was_reconfiguring);
    cvlm_assert(hashi.committee_set().is_reconfiguring());
}
```

The first rule as sketched is vacuous — that is deliberate, to flag a
drafting trap. The mutex is not a "flag doesn't change" invariant (every
transition changes it); the checkable content is the **per-target
pre/postcondition pairs** in `start_requires_idle` and its three siblings
(`submit_requires_busy`, `end_requires_busy`, `abort_requires_busy`).
Write those four, not a parametric one.

**Needs**: `is_reconfiguring` (already patched), `start_reconfig`
(`entry` → `public entry` — it has no `#[test_only]` forwarder, unlike
`end_reconfig` and `submit_committee_handoff`, which do: `reconfig.move:161-168`,
`:174-180`, both already `#[test_only] public` and therefore already
callable under the Prover's `--test` build).

---

## G13 — Handoff cert is write-once and required for non-initial reconfigs

**Statement (English)**: `PendingEpochChange.committee_handoff_cert`
transitions `None → Some` **at most once** per reconfiguration; and
`end_reconfig` cannot complete a non-initial reconfiguration without it.

**Grounding**:
- `set_pending_committee_handoff_cert` (`:266-274`) asserts
  `pending.committee_handoff_cert.is_none()` (`:271`) before writing
  `Some(cert)` (`:272`) — same `None`-then-immutable latch shape as P8's
  `finish_publish` fields and W9's `guardian_signatures`. The assert is
  **bare, with no named error** (GF9).
- Its only caller, `reconfig::submit_committee_handoff` (`:119-138`),
  further requires `is_reconfiguring()` (`:125`),
  `!mpc_public_key.is_empty()` (`EInitialReconfig`, `:126`), and a
  **current**-committee certificate over `CommitteeTransitionRequest { new_committee }`
  (`:129-136`) — i.e. the outgoing committee signing off on the incoming
  one. Note the committee is read out of the pending epoch's slot and
  **copied** (`:129`, `let new_committee = *next_committee;`) into the
  signed message, so the cert binds the full committee contents, not just
  its epoch number. That is stronger than `AbortReconfig`'s binding and is
  the contrast **GF3** turns on.
- `end_reconfig` (`committee_set.move:276-301`) branches on
  `self.mpc_public_key.is_empty()` (`:289`): the initial reconfig sets the
  key (`:290`), every subsequent one asserts
  `committee_handoff_cert.is_some()` (`:292`, bare).

**So the handoff requirement is gated on `mpc_public_key` being non-empty,
not on the epoch number** — and nothing asserts the key is non-empty when
it is first stored. That is **GF2**, and it is the sharpest thing in this
section: a single `end_reconfig` completing genesis with an empty
`mpc_public_key` leaves `mpc_public_key.is_empty()` true forever, which
(a) permanently routes every future `end_reconfig` down the initial branch,
so the outgoing committee's approval is **never** required again, and (b)
permanently blocks `submit_committee_handoff` on `EInitialReconfig`
(`reconfig.move:126`), so no cert could be supplied even voluntarily.

**Rule shape**: expect-unreachable for the double-submit; assert-style for
the requirement; expect-reachable for GF2.

```
fun handoff_cert_written_once(hashi: &mut Hashi, cert1: CommitteeSignature, cert2: CommitteeSignature, ctx: &TxContext) {
    hashi::reconfig::submit_committee_handoff_for_testing(hashi, cert1, ctx);
    hashi::reconfig::submit_committee_handoff_for_testing(hashi, cert2, ctx);

    cvlm_assert(false);   // desired: Verified (unreachable) — committee_set.move:271
}

fun end_reconfig_requires_handoff_when_not_initial(hashi: &mut Hashi, key: vector<u8>, cert: CommitteeSignature, ctx: &TxContext) {
    let was_initial = hashi.committee_set().mpc_public_key().is_empty();
    let had_cert = hashi.committee_set().pending_handoff_cert_is_set();

    hashi::reconfig::end_reconfig_for_testing(hashi, key, cert, ctx);

    cvlm_assert(was_initial || had_cert);   // restates committee_set.move:292
}

// GF2, as an expect-REACHABLE witness.
fun genesis_can_complete_with_empty_mpc_key(hashi: &mut Hashi, cert: CommitteeSignature, ctx: &TxContext) {
    cvlm_assume_msg(hashi.committee_set().mpc_public_key().is_empty(), b"genesis: no MPC key yet");

    hashi::reconfig::end_reconfig_for_testing(hashi, vector[], cert, ctx);

    cvlm_satisfy_msg(
        hashi.committee_set().mpc_public_key().is_empty(),
        b"genesis completed with an empty mpc_public_key; handoff certs now permanently optional",
    );
    // desired result: SATISFIABLE — confirms GF2
}
```

Note the `mpc_public_key` pin at `:297` (`assert!(self.mpc_public_key == mpc_public_key)`)
is a plain `vector<u8>` comparison, not an `Option` — safe to state
directly, unlike most equalities in these documents.

**Needs**: `mpc_public_key`, `epoch`, `has_committee` (bump);
`pending_handoff_cert_is_set` (**new** — `PendingEpochChange.committee_handoff_cert`
has no accessor of any kind today; `pending_epoch_change()` (`:345-351`)
exposes only the `epoch` field). `end_reconfig_for_testing` and
`submit_committee_handoff_for_testing` are already usable.

---

## G14 — Epoch advances forward, but **not** by one (corrects P12)

**Statement (English)**: a completed reconfiguration sets
`CommitteeSet.epoch` to the Sui epoch that was current when
`start_reconfig` ran. It is **not** `epoch + 1`, and Move asserts nothing
about the direction of the change — forward progress is inherited from
Sui's `TxContext::epoch()`, not enforced locally.

**Grounding**, and this is a straight correction to PROPERTIES.md P12's
"incremented by exactly 1 per completed reconfig":
- `new_committee_from_validator_set` takes `let epoch = ctx.epoch();`
  (`committee_set.move:393`) and stamps it on the new `Committee`.
- `start_reconfig` reads that back as the pending epoch
  (`let epoch = committee.epoch();`, `:256`) and stores it in
  `PendingEpochChange` (`:257-261`).
- `end_reconfig` assigns `self.epoch = next_epoch;` (`:299`) — a plain
  assignment of Sui's epoch number, not an increment.

So if no one calls `start_reconfig` for three Sui epochs, `CommitteeSet.epoch`
jumps by three. **Epoch numbers are Sui epoch numbers, and the sequence of
Hashi epochs is a subsequence of Sui's, not a contiguous range.** Anything
that assumes contiguity — an off-chain indexer walking `epoch, epoch+1, …`,
or a future Move function computing a previous epoch as `epoch - 1` — is
wrong. Worth checking `crates/` for exactly that assumption (Phase 9).

**What *is* guarded** at `start_reconfig` is weaker than monotonicity:
```
assert!(!self.is_reconfiguring());                       // :242 — the mutex, G12
assert!(!self.has_committee(ctx.epoch()));               // :245 — no committee for that epoch yet
assert!(self.epoch == 0 || self.epoch != ctx.epoch());   // :248 — INEQUALITY, not >
```
`:248` is `!=`, not `>`. There is **no** `assert!(ctx.epoch() > self.epoch)`
anywhere. Backwards movement is prevented only by `:245` (a past epoch that
completed still has its `Committee` in the bag) plus the fact that Sui's
`ctx.epoch()` is itself monotone — neither of which is a Move-local
argument. And `:245`'s protection has a hole: `abort_reconfig` calls
`remove_committee(next_epoch)` (`:313`), so an aborted epoch's slot becomes
free again. See G15 and **GF3**.

Also note `:248`'s `self.epoch == 0` disjunct makes the whole assert
vacuous while `epoch == 0`, which is every state before the first
successful `end_reconfig`. That is required for genesis (Sui's epoch may
legitimately be 0), but it means the only real guard at genesis is `:245`.

**Rule shape**: assert-style — state what actually holds, not P12's claim.

```
fun end_reconfig_sets_epoch_to_pending(hashi: &mut Hashi, key: vector<u8>, cert: CommitteeSignature, ctx: &TxContext) {
    let pending = hashi.committee_set().pending_epoch_change();
    cvlm_assume_msg(pending.is_some(), b"a reconfiguration is pending");
    let next = *pending.borrow();
    let before = hashi.committee_set().epoch();

    hashi::reconfig::end_reconfig_for_testing(hashi, key, cert, ctx);

    cvlm_assert(hashi.committee_set().epoch() == next);
    cvlm_assert(!hashi.committee_set().is_reconfiguring());
    // deliberately NOT asserted, because it does not hold:
    //   cvlm_assert(hashi.committee_set().epoch() == before + 1);
    let _ = before;
}

fun epoch_only_changes_at_end_reconfig(hashi: &mut Hashi, target: Function) {
    let before = hashi.committee_set().epoch();

    invoke(target, hashi);   // every target EXCEPT end_reconfig

    cvlm_assert(hashi.committee_set().epoch() == before);
}
```

`epoch_only_changes_at_end_reconfig` is the more valuable of the two — it
is the frame property that licenses every epoch-pinning argument elsewhere
(P6's certificate epoch pin, W11's presig allocator, `abort_reconfig`'s
epoch match). Write it parametrically over the whole governance and
reconfiguration surface.

**A `+1` variant is worth writing too, expecting it to fail**, exactly as
W4a's `status_never_regresses` was written expecting F1's counterexample —
it converts GF5 from a reading of the code into a Prover-confirmed fact.

**Needs**: `epoch`, `pending_epoch_change` (bump).

---

## G15 — `abort_reconfig` restores the pre-reconfig state exactly

**Statement (English)**: `abort_reconfig` returns the `CommitteeSet` to
precisely the state `start_reconfig` found it in — pending change cleared,
pending committee removed, current epoch untouched — and it can never
remove the *current* committee.

**Grounding** (`committee_set.move:303-315`):
```
assert!(self.is_reconfiguring());                                     // :304
let PendingEpochChange { epoch: next_epoch, committee_handoff_cert }  // :305-307
    = self.pending_epoch_change.extract();
if (committee_handoff_cert.is_some()) { ..destroy_some(); }           // :308-312
else { ..destroy_none(); };
self.remove_committee(next_epoch);                                    // :313
next_epoch                                                            // :314
```
`self.epoch` is never assigned — so the current epoch survives, which is
the whole point (`abort_reconfig.move:6-9`: the last committed committee
retains voting power). `remove_committee` (`:383-385`) is the mirror of
`start_reconfig`'s `insert_committee` (`:262`), and these are its only two
call sites, so `committees` returns to its prior contents.

**"Never removes the current committee" is not asserted, and is worth
proving.** The argument: `remove_committee(next_epoch)` would destroy
`current_committee()` iff `next_epoch == self.epoch`. `start_reconfig`
established `!has_committee(ctx.epoch())` (`:245`) with
`next_epoch = ctx.epoch()`, while `current_committee()` (`:333-335`)
indexes `committees[self.epoch]` — so whenever a current committee exists,
`has_committee(self.epoch)` is true and `:245` forces
`next_epoch != self.epoch`. The one state where they can coincide is
pre-genesis (`self.epoch == 0`, no `committees[0]` yet), where removing it
is exactly the intended rollback. A clean two-line argument, but it spans
two functions and one disjunctive assert — precisely the kind of thing to
hand to the Prover rather than to a reader.

The `if / else` at `:308-312` is a no-op oddity worth noting: both branches
merely destroy the `Option<CommitteeSignature>`, and `CommitteeSignature`
is `copy, drop, store` (`committee.move:55-59`), so the whole block could
be `let _ = committee_handoff_cert;`. Harmless; flag as style, not as a
finding.

**Rule shape**: assert-style.

```
fun abort_preserves_current_epoch_and_committee(hashi: &mut Hashi, proposal_id: ID, clock: &Clock, ctx: &TxContext) {
    let cs = hashi.committee_set();
    cvlm_assume_msg(cs.is_reconfiguring(), b"a reconfiguration is pending");
    let epoch_before = cs.epoch();
    let had_current = cs.has_committee(epoch_before);
    let pending = cs.pending_epoch_change();
    let next = *pending.borrow();

    hashi::abort_reconfig::execute(hashi, proposal_id, clock, ctx);

    let cs2 = hashi.committee_set();
    cvlm_assert(cs2.epoch() == epoch_before);
    cvlm_assert(!cs2.is_reconfiguring());
    cvlm_assert(!cs2.has_committee(next));
    if (had_current) {
        cvlm_assert(cs2.has_committee(epoch_before));   // the current committee survived
    };
}

fun abort_reconfig_requires_matching_epoch(hashi: &mut Hashi, proposal_id: ID, clock: &Clock, ctx: &TxContext) {
    let pending = hashi.committee_set().pending_epoch_change();
    cvlm_assume_msg(pending.is_some(), b"a reconfiguration is pending");
    let next = *pending.borrow();
    let ps = hashi.proposals();
    cvlm_assume_msg(ps.contains_active(proposal_id), b"proposal is active pre-call");
    let proposed = ps.borrow_active(proposal_id).proposal_data().abort_reconfig_epoch();

    hashi::abort_reconfig::execute(hashi, proposal_id, clock, ctx);

    cvlm_assert(proposed == next);   // restates EWrongReconfigEpoch (abort_reconfig.move:66, :70)
}
```

**Needs**: `has_committee`, `epoch`, `pending_epoch_change` (bump);
`abort_reconfig_epoch` (new accessor on the payload struct, whose `epoch`
field is private).

---

## G16 — `AbortReconfig` binds the epoch number, not the reconfiguration

**Statement (English)**: an `AbortReconfig` proposal's `epoch` field
identifies a *Sui epoch number*, not a particular reconfiguration attempt —
so a proposal created against one attempt can execute against a later,
unrelated attempt that happens to carry the same epoch number.

**This is the direct answer to PROPERTIES.md P15's open "To verify"
question**, which asked whether `abort_reconfig::execute`'s post-execute
re-checks are load-bearing or defensive-but-dead, and noted that "nothing
else found in this pass suggests `pending_epoch_change` can change between
a proposal's creation and its execution except through `end_reconfig` or
another `abort_reconfig`". The answer is: the re-checks **are**
load-bearing, *and* they are insufficient, because those two exceptions are
enough.

**Grounding** — the loop that makes this reachable:
1. `start_reconfig` at Sui epoch `E` → `pending_epoch_change = Some({epoch: E, ..})`,
   `committees[E] = C₁` (`committee_set.move:257-262`).
2. `abort_reconfig::propose(epoch: E)` ×2, both reaching quorum
   (`abort_reconfig.move:36-59` — `propose` requires `is_reconfiguring()`
   and `pending == E`, both true, so both proposals are validly created).
3. `abort_reconfig::execute(P₁)` → `abort_reconfig` clears the pending
   change and calls `remove_committee(E)` (`:313`), so `committees[E]` is
   **gone**.
4. `start_reconfig` again, still at Sui epoch `E`: `!is_reconfiguring()` ✓
   (cleared in step 3), `!has_committee(E)` ✓ (**removed in step 3**),
   `self.epoch == 0 || self.epoch != E` ✓ (unchanged). A **new**
   reconfiguration for the same epoch `E`, with a freshly-built committee
   `C₂` reflecting whatever the validator set now looks like.
5. `abort_reconfig::execute(P₂)` — `is_reconfiguring()` ✓, pending epoch
   `== E ==` `P₂.epoch` ✓, `aborted_epoch == epoch` ✓. **It aborts `C₂`**,
   a reconfiguration that did not exist when `P₂` was created or voted on.

Contrast `submit_committee_handoff`, which signs over
`CommitteeTransitionRequest { new_committee }` — the **whole committee
struct**, copied out of the pending slot (`reconfig.move:129-130`). That
message could not be replayed against `C₂`. `AbortReconfig` carries only
`{ epoch: u64 }` (`abort_reconfig.move:30-32`), so it can.

**Impact**: liveness/griefing, not safety. Each stockpiled proposal is
single-use (G2), so a coalition holding 6667 bps can block *n* reconfiguration
attempts with *n* proposals created during a single pending window — and
they must all be created while that first window is open, since `propose`
requires `is_reconfiguring()`. Since 6667 bps is also enough to simply
refuse to produce the `end_reconfig` certificate, this grants no capability
a supermajority lacks. It is a **defence-in-depth gap and a surprising
semantic**, not an exploit. See **GF3**.

**Rule shape**: expect-reachable — the whole point is that the scenario
*is* reachable.

```
fun stale_abort_proposal_aborts_a_later_reconfig(
    hashi: &mut Hashi, p1: ID, p2: ID, sui_system: &SuiSystemState, clock: &Clock, ctx: &mut TxContext,
) {
    cvlm_assume_msg(p1 != p2, b"two distinct abort proposals");
    cvlm_assume_msg(hashi.committee_set().is_reconfiguring(), b"attempt #1 pending");
    let e = *hashi.committee_set().pending_epoch_change().borrow();

    hashi::abort_reconfig::execute(hashi, p1, clock, ctx);       // aborts attempt #1
    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);     // attempt #2, same Sui epoch
    cvlm_assume_msg(*hashi.committee_set().pending_epoch_change().borrow() == e, b"same epoch number");
    hashi::abort_reconfig::execute(hashi, p2, clock, ctx);       // aborts attempt #2

    cvlm_satisfy_msg(true, b"a pre-existing abort proposal cancelled a reconfiguration created after it");
    // desired result: SATISFIABLE — confirms GF3
}
```

Threading a real `SuiSystemState` through will be the awkward part; if it
proves impractical, the queue-level equivalent (call
`committee_set::start_reconfig`/`abort_reconfig` directly with a nondet
`Committee`) isolates the same guard without the entry-point plumbing —
the same one-level-down move D6 and W5 both took.

**Needs**: as G15, plus `start_reconfig` bumped to `public entry` (or the
queue-level `committee_set::start_reconfig`/`abort_reconfig` bumped).

---

## G17 — Bag key injectivity across shared namespaces (P11 instance)

**Statement (English)**: the two `Bag`s that carry more than one key type
never alias one purpose's storage onto another's.

**Two instances, both introduced in this flow**:
- `CommitteeSet.committees` holds `u64 → Committee` (`insert_committee`,
  `:379-381`; `has_committee`, `:341-343`) **and**
  `CommitteeHandoffKey → CommitteeHandoff` (`insert_committee_handoff`,
  `:317-326`; the `#[test_only] has_committee_handoff_for_testing`,
  `:519-526`).
- `Proposals` uses `ID` keys for `active` and `address` keys for
  `executed` (G0) — two bags, but the same underlying address value
  appearing under two different key types.

Both are safe: Sui's dynamic-field keys are `(type, value)` pairs, so
`u64(5)` and `CommitteeHandoffKey{epoch: 5}` are distinct fields, as are
`ID(x)` and `address(x)`. The property is therefore **discharged by the
framework, not by Hashi code** — which is exactly why it is worth writing
down rather than proving: a rule asserting it would be testing Sui's
dynamic-field implementation, not Hashi's.

**What *is* worth checking** is the spec-side mirror of it: every accessor
this document adds must take the same key type the production code writes,
or it will silently read an always-empty namespace. That is a code-review
item on the patch, not a CVL rule. **No rule planned**; see **GF7** for the
one place the asymmetry is most likely to trip someone up.

---

## Findings and audit notes

GF1–GF10 came out of writing the properties above. **None of those is
confirmed as exploitable without committee supermajority**, but GF1 and GF2
both break guarantees stated elsewhere in this audit. Listed highest-concern
first. GF11–GF20 come from a second, dedicated pass (see below). **GF11 is
exploitable by a single committee member.**

### GF1 — `update_config` bypasses the guardian BTC key's immutability latch

`config::set_guardian_btc_public_key` (`config.move:130-139`) exists to make
the guardian's x-only BTC pubkey write-once — its own doc comment
(`:128-129`) says "Immutable once set — rotating it would invalidate every
2-of-2 deposit address derived against it", enforced by
`assert!(existing.destroy_some() == btc_public_key, EGuardianBtcPublicKeyImmutable)`
(`:134`). PROPERTIES.md **P5** concludes that this immutability is "the only
on-chain contribution" to the 2-of-2 structural guarantee, and P8 lists it as
one of `finish_publish`'s two write-once latches.

`update_config::execute` (`:56-67`) does not call that setter. It calls
`hashi.config_mut().upsert(*key.as_bytes(), value)` (`:65`) — the raw store
write — after a validation that consists solely of
`is_valid_config_update` ("key exists && same variant",
`config.move:99-102`) and `mpc_config::is_valid_value`, which returns
`true` for every key outside its four MPC parameters
(`mpc_config.move:44-46`). `guardian_btc_public_key` is present in the
config (written by `finish_publish` → `set_guardian_btc_public_key`,
`hashi.move:89`) and is a `bytes` value, so an `UpdateConfig` proposal
carrying `{"guardian_btc_public_key": <32 new bytes>}` passes both checks
and overwrites it.

Note the upsert does not even re-check the 32-byte length — that assert
lives in the setter (`config.move:131`), which is bypassed too. So a
malformed key of any length can be stored.

**Impact**: a 6667-bps governance quorum can silently redefine the spending
conditions of every previously-derived deposit address. Nothing in Move
reads the key back (grep: `hashi.move:73`, `:89`, `:314`, `:323` are the
only occurrences outside `config.move`), so the consequences land entirely
off-chain in `crates/` address derivation and PSBT construction — which is
precisely why the on-chain latch was the thing P5 could point to.

**Suggested fix**: give `update_config` a deny-list (or, better, an
allow-list) of governable keys, or route it through the domain setters. The
cheapest targeted fix is to reject `GUARDIAN_BTC_PUBLIC_KEY_KEY` inside
`is_valid_config_update`. The structural fix is the pattern
`bitcoin_withdrawal_minimum` already uses — put the invariant in the
*reader*, so no writer can violate it (see G11).

**Verify with**: G11's `update_config_can_rotate_guardian_btc_key`. Expect
**satisfiable**.

### GF2 — `end_reconfig` accepts an empty `mpc_public_key` at genesis, permanently disabling the handoff requirement

`CommitteeSet::end_reconfig` (`:276-301`) uses `mpc_public_key.is_empty()`
as its "is this the initial reconfig?" test (`:289`). On the initial path it
assigns whatever was passed in (`:290`) with **no non-emptiness check**;
`assert!(self.mpc_public_key == mpc_public_key)` (`:297`) is then trivially
satisfied. `reconfig::end_reconfig` (`:99`) computes `is_initial_reconfig`
the same way and takes `mpc_public_key` straight from its caller (`:83`).

If genesis completes with an empty key, `mpc_public_key.is_empty()` stays
true forever, and three things follow permanently:
1. Every future `end_reconfig` takes the initial branch (`:289-291`), so
   `assert!(committee_handoff_cert.is_some())` (`:292`) — the outgoing
   committee's approval of the incoming one — is **never** required again.
2. `submit_committee_handoff` aborts on `EInitialReconfig`
   (`reconfig.move:126`), so the cert cannot be supplied even deliberately.
3. `assert_genesis_launch_authorized` (`:149-153`) keeps applying to every
   `start_reconfig` — harmless once the upgrade cap is set, but it shows
   the system genuinely never leaves "genesis" mode.

The `ReconfigCompletionMessage` cert (`reconfig.move:92-98`) is verified
against the **next** committee, i.e. the incoming one self-certifies; the
outgoing committee's sign-off is exactly what the handoff cert provides and
exactly what this removes.

**Reachability**: requires the genesis `end_reconfig` to be called with an
empty vector and a valid next-committee cert over
`ReconfigCompletionMessage { epoch, mpc_public_key: vector[] }`. That is a
single operational mistake at launch by the party running genesis, not an
attack — but it is silent, unrecoverable without an upgrade, and removes a
security control for the lifetime of the deployment.

**Suggested fix**: `assert!(!mpc_public_key.is_empty(), E...)` in
`CommitteeSet::end_reconfig` before `:290`. One line.

**Verify with**: G13's `genesis_can_complete_with_empty_mpc_key`. Expect
**satisfiable**.

### GF3 — `AbortReconfig` binds only an epoch number, so abort proposals can be stockpiled

Full scenario in **G16**. In short: `AbortReconfig { epoch: u64 }`
(`abort_reconfig.move:30-32`) identifies a Sui epoch, not a reconfiguration
attempt; `abort_reconfig` frees the epoch's committee slot
(`committee_set.move:313`); and `start_reconfig`'s guards (`:242`, `:245`,
`:248`) are all satisfied again immediately afterwards in the same Sui
epoch. So a second, already-quorate proposal created during the first
attempt aborts the second attempt.

This resolves PROPERTIES.md P15's open question in the direction it did not
anticipate: the post-execute re-checks at `abort_reconfig.move:64-70` are
load-bearing (they prevent execution when nothing is pending) but are
**not sufficient** to bind a proposal to the attempt it was voted on.

**Impact**: liveness only, and only for holders of 6667 bps — who can
already stall reconfiguration by withholding the `end_reconfig` cert. Still
worth closing, because the current semantics are surprising and because the
sibling message (`CommitteeTransitionRequest`) already demonstrates the
right pattern.

**Suggested fix**: bind the pending committee, not the epoch — e.g. carry
`committee_digest: vector<u8>` (or the `Committee` itself, as
`CommitteeTransitionRequest` does, `reconfig.move:40-42`) in the
`AbortReconfig` payload and re-check it at `:65-68`. Alternatively give
`PendingEpochChange` a monotonically-increasing attempt counter and bind
that.

**Verify with**: G16's `stale_abort_proposal_aborts_a_later_reconfig`.
Expect **satisfiable**.

### GF4 — Emergency thresholds are governable with no range validation

`governance_emergency_pause_threshold_bps` and
`governance_emergency_unpause_threshold_bps` (`config.move:26-28`, defaults
500 / 6667 at `:53-54`) are ordinary `u64` config entries, so `update_config`
can set either to any `u64` (GF1's mechanism, benign target). Two edge
values matter:

- **`> 10000`**: `threshold::weight_threshold` asserts
  `threshold_bps <= MAX_BPS` (`threshold.move:36`,
  `EThresholdBpsTooHigh`). `proposal::create` does not call it, so the
  proposal is created fine — but `vote` (`:105`, via `quorum_reached`) and
  `execute` (`:205`) both abort. The result is a proposal type that can be
  created and never voted on or executed, failing with an error raised
  three modules away from its cause. For the unpause key specifically, this
  means **no unpause proposal can ever pass** until a further
  `update_config` (itself still executable at 6667) puts the value back.
  Recoverable, but a sharp footgun.
- **`0`**: `weight_threshold(total, 0) = 0`, and `quorum_reached`'s
  `valid_voting_power >= 0` is vacuously true — so a proposal created at
  0 bps is executable **with zero voting weight**, by anyone, immediately
  (`execute` is permissionless, G9). Creation still requires an authorized
  member, so this is a "one member can pause the bridge" lever rather than
  a fully open one.

Neither is reachable below 6667 bps, so neither inverts G10's asymmetry
today. But G10's argument is a numeric coincidence between one config
default and four `const THRESHOLD_BPS = 6667` declarations
(`abort_reconfig.move:18`, `disable_version.move:17`,
`enable_version.move:17`, `update_config.move:17`, `update_guardian.move:17`,
`upgrade.move:24`) — governance can move the config value but not the
constants, and the moment
`governance_emergency_unpause_threshold_bps > 6667` the asymmetry inverts:
`update_config`-then-set-`paused=false` becomes strictly cheaper than a
direct unpause.

**Suggested fix**: range-validate both keys the way `mpc_config::is_valid_value`
ranges the MPC keys — extend it (or `is_valid_config_update`) with
`1 <= bps <= MAX_BPS` for both, and consider a floor on the unpause key.

### GF5 — `CommitteeSet.epoch` is not incremented by one, and its monotonicity is not asserted

PROPERTIES.md **P12** states "epoch is a strictly monotonic counter,
incremented by exactly 1 per completed reconfig". Neither half is enforced
in Move. `end_reconfig` assigns `self.epoch = next_epoch`
(`committee_set.move:299`) where `next_epoch` is Sui's `ctx.epoch()` as read
at `start_reconfig` (`:393`), so Hashi epochs are a *subsequence* of Sui
epochs and can jump. The only directional guard is
`assert!(self.epoch == 0 || self.epoch != ctx.epoch())` (`:248`) — an
inequality, not a `>` — plus `!has_committee(ctx.epoch())` (`:245`), which
GF3 shows is not permanent for aborted epochs. Forward progress is
inherited from Sui's own epoch monotonicity, which is correct in practice
but is not a Move-local argument and is not written down anywhere.

**Impact**: none on-chain today. It matters for (a) P12's write-up, which
should be corrected, and (b) anything off-chain that walks epochs
contiguously — a `crates/` review item for Phase 9.

**Suggested fix**: add `assert!(ctx.epoch() > self.epoch || self.epoch == 0, E...)`
at `:248` to make monotonicity local, and correct P12's wording to
"strictly increasing, not necessarily by 1".

### GF6 — Governance's pause/reconfig guard omissions are undocumented

None of the eleven governance and reconfiguration entry points in G9's
table calls `assert_unpaused` or `assert_not_reconfiguring`. Every one of
those omissions is *necessary* — `emergency_pause` must work while paused,
`abort_reconfig` must work while reconfiguring — but not one carries a
source comment saying so, where `withdraw.move` documents its two
deliberate omissions inline (`:360-361` for `cleanup_spent_utxos`,
`:339-341` for `reallocate_presigs`). Identical shape to W13's findings F5
and F6. A reader auditing guard completeness (P7) has no way to distinguish
"deliberately omitted" from "forgotten" here.

**Suggested fix**: one comment per module, on `proposal.move` and
`reconfig.move`, stating that governance is deliberately ungated on
pause/reconfig and why.

### GF7 — `active` and `executed` use different key types for the same identifier

`Proposals.active` is keyed by `ID` (`proposal.move:182`), `Proposals.executed`
by `address` (`:212`), and every membership test on the latter converts
explicitly (`proposal_id.to_address()`, `:142`, `:199`). Correct as written,
and not a collision risk (dynamic-field keys are type-tagged). But it is a
latent trap: `executed().contains(proposal_id)` with an `ID` compiles, type-
checks, and returns `false` unconditionally — which in both call sites
(`:141-144`, `:198-201`) would silently disable the
`EProposalAlreadyExecuted` guard. Both currently rely on the `ObjectBag`
remove-abort as backstop (G2, G4), so even that mistake would not be
exploitable today — but the defence-in-depth check would be gone with no
visible symptom.

**Suggested fix**: key both bags the same way, or wrap both membership tests
in named helpers on `Proposals` (which the spec accessors need anyway, see
G1) so the conversion happens in exactly one place.

### GF8 — `proposal::create` does not check `assert_version_enabled`

`create` (`:153-185`) is the only one of the five engine functions without
the version gate — `vote` (`:94`), `remove_vote` (`:117`), `delete_expired`
(`:136`) and `execute` (`:192`) all have it. In practice every caller
checks first (all seven `types/*::propose` functions open with
`hashi.versioning().assert_version_enabled()`), so the gate is never
actually missing. Defence-in-depth only; worth one line for uniformity,
given `create` is `public(package)` and a future caller could omit it.

### GF9 — Bare `assert!`s without error codes in the reconfiguration path

`committee_set.move` uses unnamed asserts at `:242` (`!is_reconfiguring`),
`:245` (`!has_committee`), `:248` (epoch inequality), `:271`
(handoff-cert write-once), `:281` / `:304` (`is_reconfiguring`), `:285`
(`has_committee(next_epoch)`), `:292` (handoff cert required), `:297`
(mpc key pinned) — plus `reconfig.move:66`. Every one is a
security-relevant guard and none produces a distinguishable error.

This is more than cosmetic here: `reconfig.move:18-20` records that the
node's abort classifier (`crates/hashi/src/mpc/service.rs`) **matches
`ENotReconfiguring` by name** to detect the benign "end_reconfig already
completed by another node" race. That works for `reconfig::end_reconfig`'s
own `:88` check, but the identical condition re-asserted inside
`CommitteeSet::end_reconfig` (`:281`) is bare — so a race that slips past
the outer check surfaces as an unclassifiable generic abort. Worth naming
these, with `:281` and `:304` first.

### GF10 — `update_config` validates entries at execution, not at proposal time

`update_config::propose` (`:35-54`) checks only `!entries.is_empty()`
(`:44`); the key-existence and type checks run in `execute` (`:60-64`). So a
proposal naming an unknown key, or the right key with the wrong variant,
can be created, gather a full 6667-bps quorum over up to seven days, and
then abort — permanently, since the inputs never change. A wasted
governance cycle, and (per G8's atomicity note) the proposal stays `active`
and can be re-attempted forever with the same result until it expires.

**Suggested fix**: run the same `is_valid_config_update && is_valid_value`
loop in `propose`. It cannot fully replace the execute-time check (config
contents can change between proposal and execution) but it catches every
typo at creation.

### Second pass — reconfiguration and governance (GF11–GF20)

A second, dedicated review of `reconfig.move`, `committee_set.move`,
`committee.move`, `cert_submission.move`, `tob.move`, the proposal engine
and the seven payload modules. Unlike GF1–GF10, several of these depend on
how the node (`crates/hashi`) consumes on-chain state, so the node was read
where the Move behaviour alone was not decisive; those citations are
marked. Line numbers are against `HEAD` (unpatched sources). Listed
highest-concern first.

### GF11 — Dealer-certificate signer weight is never checked; one committee member can stall every DKG and key rotation

**On-chain.** `cert_submission::submit_cert_internal`
(`cert_submission.move:74-98`) checks only that the sender is authorized for
`dealer` (`:87`) and that `epoch` is current or pending (`:88-89`).
`tob::submit_cert_with_signature` (`tob.move:116-130`, doc: "deferred
verification") stores the `CommitteeSignature` **without verifying it at
all**, first-submission-wins per dealer (`:124-126`).

**Off-chain.** The node's DKG and rotation party loops verify each stored cert
with `Committee::verify_signature` (`crates/hashi/src/mpc/mpc_except_signing.rs:1288-1297`,
`:1560-1566`). That function checks the epoch, the bitmap bounds and the
aggregate BLS signature, but **not the signing weight**
(`crates/hashi-types/src/committee.rs:296-318`). The weight-checking variant,
`verify_signature_and_weight` (`:323-336`), is not used on this path. The
dealer itself requires `t + f` reduced weight before submitting
(`mpc_except_signing.rs:3939`), but that is a self-imposed check that a
malicious dealer skips.

**Attack.** A single member `M` of the pending committee does the following as
soon as `start_reconfig` lands:
1. It signs `DealerMessagesHash { dealer: M, messages_hash: h }` with its own
   BLS key alone.
2. It posts that signature with a one-bit bitmap via `submit_dkg_cert` or
   `submit_rotation_cert`, and never sends the underlying messages to anyone.

Every honest party then receives `M`'s cert from the TOB, accepts the
signature, finds the message missing, and calls `retrieve_dealer_message`
from the cert's signers, which is only `M`. That call fails, and the error
propagates out of `run_dkg_as_party` with `?`
(`mpc_except_signing.rs:1311-1329`). The attempt fails. Retries re-read the
same bucket, and `M`'s entry can't be replaced (first-submission-wins) or
destroyed (`tob.move:136` needs `current_epoch >= epoch + 2`), so every retry
fails the same way.

**Impact.** Liveness, but severe:
- **Non-genesis.** While the reconfig is pending, deposits and withdrawals are
  halted (`assert_not_reconfiguring`) until governance passes an
  `abort_reconfig` at 6667 bps. `M` can repeat this every Sui epoch, so the
  committee can never rotate, and each attempt halts the bridge until it's
  aborted.
- **Genesis.** No abort path exists (**GF12**), so one malicious validator in
  the genesis committee bricks the deployment permanently.

Only one registered member of the pending committee is needed. No weight
threshold applies to the attacker.

**Suggested fix.** Check the weight wherever the cert is trusted:
- **Off-chain (minimum fix):** use `verify_signature_and_weight` with the
  `t + f` reduced-weight bound the dealer already applies to itself.
- **On-chain (better):** verify the cert in `submit_cert_internal` against
  `committees[epoch]` with a stake threshold, so an under-weight cert can't
  occupy the dealer's single first-submission slot at all.

### GF12 — A stuck genesis reconfiguration can never be aborted, and no governance action works before genesis completes

Before genesis completes, `CommitteeSet.epoch == 0` and `committees[0]` doesn't
exist (`committee_set.move:100-108`). `current_committee()` indexes
`committees[self.epoch]` (`:333-335`), so it aborts. Every governance
`execute` reaches `quorum_reached` (`proposal.move:200` → `:216`), which
calls `current_committee()`. So before genesis:
- `abort_reconfig::execute` can't run, so the pending genesis committee can't
  be cleared.
- `upgrade::execute` can't run, so the package can't be upgraded. The
  `UpgradeCap` is already in `Versioning` custody at this point, because
  `finish_publish` is a precondition of genesis
  (`reconfig.move:149-153`, `hashi.move:85`), and `authorize_upgrade` is only
  reachable through `upgrade::execute`.
- `emergency_pause`, `update_config` and the others are equally dead.

The only way out of a pending genesis is `end_reconfig`, which needs a
6667-bps certificate from the **pending** committee
(`reconfig.move:92-98`). If that committee can't produce one, because DKG
fails (GF11), members lose keys, or more than ⅓ of its weight never comes
online, the deployment is dead for good. This is permanent, not a temporary
halt. The `abort_reconfig` module doc (`:6-9`) says the last committed
committee is the fallback governor, but at genesis there isn't one.

**Impact.** No funds are at risk, since nothing has been deposited before
genesis. The deployment itself is lost, and the only recovery is a fresh
publish (new package ID, new object IDs, new addresses).

**Suggested fix.** Give genesis a dedicated escape hatch. For example, allow
`abort_reconfig` pre-genesis when authorized by the publisher (the party that
just called `finish_publish`), or after a timeout. Alternatively, keep the
`UpgradeCap` out of custody until genesis completes, by making the handover
part of the first `end_reconfig`.

**Verify with** an expect-unreachable rule: assume
`mpc_public_key().is_empty()`, `epoch() == 0` and `!has_committee(0)`; call
`abort_reconfig::execute`; `cvlm_assert(false)`. "Verified" confirms that
no execution can abort genesis.

### GF13 — The genesis committee has no participation floor, and the permissionless `start_reconfig` fixes its membership

`start_reconfig` (`reconfig.move:59-79`) has no sender restriction. At
genesis its only gate is `has_upgrade_cap()` (`:149-153`).
`new_committee_from_validator_set` (`committee_set.move:387-436`) admits
every registered member that has *already* set both a BLS key and an
encryption key, and skips everyone else. Nothing requires a minimum member
count or a minimum fraction of Sui voting power. `new_committee` rejects
only an **empty** committee (`committee.move:89`).

The `finish_publish` doc (`hashi.move:59-61`) says the publisher calls it
"once the expected committee has registered", but it can't enforce that. Once
`finish_publish` executes, anyone can call `start_reconfig`, and the genesis
committee is whoever has keys at that moment. A validator that has registered
but hasn't yet set its keys is excluded for this epoch. The comment at
`reconfig.move:143-148` argues against a floor *after* bootstrap, and that
reasoning doesn't carry over to genesis.

**Impact.**
- **Worst case.** The genesis committee is tiny, down to a single validator,
  who then runs "DKG" alone and knows the full Bitcoin private key. Resharing
  keeps that key forever (`committee_set.move:297`), so that validator can
  later drain every deposit (see GF17). The same applies to any coalition
  holding at least ⅓ of a small genesis committee's weight.
- **Milder case.** Stake is concentrated or keys are missing, and the
  committee's security fraction is far below what Sui's validator set
  implies.

**Suggested fix.** Have `finish_publish` take a minimum genesis weight (in bps
of Sui's total voting power) and a minimum member count, and check them in
`start_reconfig` when `mpc_public_key` is empty. Alternatively, make
`finish_publish` call `start_reconfig` in the same transaction, so the
publisher alone chooses the snapshot moment.

### GF14 — After an abort, retrying in the same Sui epoch reuses epoch-keyed state from the aborted attempt

GF3/G16 establish that after `abort_reconfig`, `start_reconfig` can run
again in the same Sui epoch `E`, possibly with a different committee `C₂`.
Everything the MPC ceremony uses is keyed by `E` alone, not by attempt:
- **On-chain.** The TOB buckets are keyed by `TobKey { epoch: E, None, Dkg | KeyRotation }`
  (`cert_submission.move:23`, `:35`). Attempt 1's dealer entries stay there,
  first-submission-wins (`tob.move:124-126`), and can't be destroyed until the
  Hashi epoch reaches `E + 2` (`:136`), which needs a successful reconfig.
  Attempt 2's dealers can't overwrite their entries.
- **Node (not runtime-tested).**
  - The TOB publish skips dealers that already have an entry
    (`crates/hashi/src/communication/sui_tob.rs:177-185`).
  - The MPC session ID depends only on `(chain_id, epoch, protocol)`
    (`mpc/types.rs:150-153`).
  - Persisted dealer messages are keyed by `(epoch, dealer)`, and
    `prepare_*_dealer_flow` reloads attempt 1's messages instead of dealing
    fresh ones to `C₂` (`mpc_except_signing.rs:3826-3874`).
  - The `MpcManager` is rebuilt only when its epoch changes
    (`mpc/service.rs:1164-1168`).

Where `C₂ ≠ C₁`, attempt 1's certs don't verify against `C₂` and are dropped,
which permanently excludes those dealers for `E`. That is the GF11 failure
mode without an attacker.

**Impact.** Liveness only. In practice, an abort pushes rotation back to the
next Sui epoch, and the old committee keeps operating in the meantime. It
also means GF3's "restart in the same epoch" is an attack on a path that
doesn't work anyway, so it's worth deciding which way to resolve it.

**Suggested fix.** Either forbid restarting in the same epoch, by recording
aborted epochs and asserting `ctx.epoch()` is not among them in
`start_reconfig`, or add an attempt counter to `PendingEpochChange` and
include it in `TobKey`, the session ID and the node's DB keys. The attempt
counter also fixes GF3 and GF15.

### GF15 — `ReconfigCompletionMessage` binds neither the committee nor its pinned MPC config

The incoming committee certifies `ReconfigCompletionMessage { epoch, mpc_public_key }`
(`reconfig.move:33-38`, `:92-98`). The handoff message it pairs with,
`CommitteeTransitionRequest { new_committee }` (`:40-42`), binds the whole
`Committee`, including membership, weights and the pinned `config`. The
completion message binds only the epoch number.

In the abort-then-restart case (GF3, GF14), consider this sequence:
1. Attempt 1's `end_reconfig` transaction lost the race to the abort and
   failed. Its cert is public, because failed transactions' inputs are on-chain.
2. `start_reconfig` builds `C₂` with the same members at the same indices,
   but with different pinned MPC parameters, for example because governance
   changed `mpc_threshold_in_basis_points` between attempts.
3. Replaying attempt 1's cert against `C₂` verifies.
4. `C₂` activates, recording parameters its shares were never dealt under.

For non-genesis reconfigs the handoff cert over `C₂` is still needed, so the
outgoing committee has to have approved `C₂`. At genesis there's no handoff,
and the completion cert is the only one.

**Impact.** Low. The on-chain record of a committee's MPC parameters can
disagree with the dealing actually performed, and nodes read those parameters
from the pinned config (`crates/hashi-types/src/committee.rs:241-251`).

**Suggested fix.** Add a digest of the pending `Committee` (or the attempt
counter from GF14) to `ReconfigCompletionMessage`.

### GF16 — Upgrades don't retire the previous version, and a pre-enabled version number blocks the upgrade

`versioning::commit_upgrade` (`versioning.move:75-79`) adds the new version
to `enabled_versions` and leaves the old one enabled. After an upgrade that
fixes a vulnerability, the vulnerable version stays callable until a
separate `DisableVersion` proposal passes at 6667 bps. That proposal has to
be executed through the *new* package, because the old package's
`disable_version` refuses its own `PACKAGE_VERSION` (`:56`).

Separately, `EnableVersion` accepts any `u64`, including versions not yet
published (`enable_version.move:47-50` → `versioning.move:60-62`). If
governance pre-enables version `N+1`, the next upgrade's
`commit_upgrade` → `VecSet::insert` aborts on the duplicate. That rolls
back the whole publish PTB, including the ticket from `upgrade::execute`, so
the upgrade proposal stays active. The upgrade can't land until someone
passes `DisableVersion { N+1 }`. G8 notes that inserting a duplicate aborts,
but not this interaction with upgrades.

**Impact.** Low. There's a window after a security upgrade in which the old
version still works, and a governance footgun.

**Suggested fix.**
- Let `commit_upgrade` optionally disable the previous version, or document
  that a `DisableVersion` must follow every security upgrade.
- Make `enable_version` reject `version > upgrade_cap.version()`.
- Make `commit_upgrade` tolerate an already-present entry.

### GF17 — Trust assumption: any ⅓ of any past committee can rebuild the Bitcoin key, and old shares are never securely destroyed

This isn't a Move bug. It's a protocol-level assumption that nothing in the
audit so far writes down:
- The key never changes after genesis (`committee_set.move:297`), and no
  "rotate to a new key" path exists.
- Resharing gives out new shares of the **same** secret, so every past
  committee's shares still rebuild it.
- The reconstruction threshold is `t = ceil(W · mpc_threshold_in_basis_points / 10000)`
  with a default of **3334 bps, about ⅓** (`crates/hashi/src/mpc/mpc_except_signing.rs:6004-6007`;
  fastcrypto-tbls `Parameters.t`, "≥ t valid shares reconstruct a secret").
  This is well below the 6667-bps certificate threshold.
- The node doesn't zeroize shares. It keeps old epochs' encryption keys,
  which are enough to re-derive old shares from the public dealer messages,
  on disk for `RETENTION_EXTRA_EPOCHS = 7` epochs after rotation
  (`crates/hashi/src/db.rs:104`, `mpc/service.rs:1249-1281`), using plain
  key-value deletion.

**Consequence.** Security requires that for **every** epoch `e`, holders of
less than ⅓ of committee(`e`)'s reduced weight ever keep and pool their
shares. That includes validators that have since left Sui and have nothing
left to lose. Such a coalition can sign a Bitcoin transaction that moves
every UTXO without touching Sui. It's also enough to steal share material
(or ≤7-epoch-old encryption keys) from the disks or backups of ⅓ of one past
committee.

**Suggested fix.** Document this as an explicit assumption in the report.
Consider:
- a higher `mpc_threshold_in_basis_points` floor, validated in
  `mpc_config::is_valid_value` (`mpc_config.move:37`, currently `> 0` only);
- a governed "fresh DKG and sweep to a new key" path;
- zeroizing shares and encryption keys as soon as the handoff completes.

### GF18 — Committee authority has no time bound relative to Sui epochs

- **No lag limit.** Nothing requires the Hashi epoch to keep up with Sui's.
  If `start_reconfig` is never called, the current committee keeps
  certifying deposits and withdrawals indefinitely
  (`hashi.move:123-132`, `:147-152`), including members that have since left
  Sui.
- **No staleness check at activation.** A pending committee is built from the
  validator set at `start_reconfig` time. `end_reconfig` can activate it any
  number of Sui epochs later, with no check (`reconfig.move:81-117`).
- **Entrenchment.** The outgoing committee can keep itself in place by
  withholding the handoff cert and then aborting, both at 6667 bps
  (`committee_set.move:292`, `abort_reconfig.move:18`). Resharing inherently
  needs the old committee's cooperation, so this can't be fully removed.

**Impact.** Informational, a trust assumption. Hashi's security is tied to
whichever committee last completed a reconfig, not to Sui's current stake.

**Suggested fix.** Document it. Optionally, emit or record the Sui-epoch lag
so monitoring (`crates/hashi-monitor`) can alert on it. Consider a maximum
lag in `start_reconfig` for activation (`end_reconfig` requiring
`ctx.epoch() - next_epoch <= K`).

### GF19 — Membership is never revoked

`new_member` requires an active Sui validator (`committee_set.move:122`), but
nothing ever removes a `MemberInfo`. `member_authorized`
(`:144-150`) checks only that the member is registered. An ex-validator
therefore keeps the ability to:
- create unlimited proposals (`proposal.move:160`), each a stored object that
  lasts until someone runs `delete_expired`;
- vote, with the vote recorded but worth 0 weight;
- create TOB buckets for any `batch_index: u32` in the current or pending
  epoch (`cert_submission.move:39-54`, `:87-89`).

**Impact.** Informational: storage and indexing spam that nodes have to
iterate over or filter. It can't change a quorum.

**Suggested fix.** In `create`, `vote` and `submit_cert_internal`, require the
sender to be a member of the current (or pending) committee rather than
merely registered.

### GF20 — `certificate_threshold` narrows total weight to `u16`

`hashi::verify` and `verify_with_committee` pass
`committee.total_weight() as u16` (`hashi.move:130`, `:143`), and
`certificate_threshold` works in `u16` (`threshold.move:28-30`). This is safe
today, because Sui normalizes voting power to 10000 and a committee's total is
at most that. If that normalization ever exceeded 65535, every certificate
check would abort on the cast. Governance quorum (`quorum_reached`) already
uses `u64`.

**Suggested fix.** Use `u64` throughout, matching `weight_threshold`.

---

## Required accessors (consolidated)

**None of these have been added yet** — do not edit `packages/hashi/sources`
directly without going through the patch workflow in [CLAUDE.md](../README.md)
("Saving a new patch to `certora/patches/`").

**Visibility convention**: plain `public fun`, matching the withdrawal-side
convention and the three existing governance-adjacent patches
(`certora/patches/committee_set.move.patch` bumps `is_reconfiguring`;
`config.move.patch` bumps `paused`; `versioning.move.patch` adds
`is_version_enabled`). Either form solves the real problem — that
`public(package)` is invisible to `certora/specs/proposal`, a *different*
package from `hashi` — but plain `public` keeps the patched tree building
under a plain `sui move build`.

**Already usable, no patch needed** — worth knowing before writing any
patch, since it is more than on the deposit/withdrawal side:
- All seven `types/*::propose` and `types/*::execute` functions are
  **plain `public fun` and monomorphic**.
- `proposal::delete_expired<T>` is `public` (but generic — see below).
- `reconfig::end_reconfig_for_testing` (`:161-168`) and
  `submit_committee_handoff_for_testing` (`:174-180`) are
  `#[test_only] public`, hence visible under the Prover's `--test` build.
- `committee_set::has_committee_handoff_for_testing` (`:519-526`), same.
- `proposal::data<T>` (`:249-252`), same.
- `hashi::config`, `hashi::versioning`, `hashi::committee_set`,
  `config::paused`, `versioning::is_version_enabled`,
  `committee_set::is_reconfiguring` — already exposed by the applied
  patches.

**Exclude from every target list**: `committee_set::set_pending_reconfig_for_testing`
(`:528-539`), `set_mpc_public_key_for_testing` (`:541-544`) and
`create_for_testing` (`:546-572`) are `#[test_only] public` and therefore
*also* visible to the Prover — they write `pending_epoch_change`,
`mpc_public_key` and `epoch` directly, bypassing every guard in G12–G15.
Leaving them in a parametric target list will produce counterexamples that
look like protocol bugs and are not.

### New: monomorphic wrappers for the generic engine functions

The one piece of real engineering work. `proposal::vote<T>`,
`remove_vote<T>` and `delete_expired<T>` are generic, and `vote`/`remove_vote`
are additionally private `entry`. Add, in `proposal.move`:

```
public entry fun vote_emergency_pause(hashi: &mut Hashi, v: address, id: ID, clock: &Clock, ctx: &mut TxContext) {
    vote<hashi::emergency_pause::EmergencyPause>(hashi, v, id, clock, ctx)
}
public entry fun remove_vote_emergency_pause(hashi: &mut Hashi, v: address, id: ID, ctx: &mut TxContext) { .. }
public fun delete_expired_emergency_pause(hashi: &mut Hashi, id: ID, clock: &Clock): EmergencyPause { .. }
```

`EmergencyPause` is already a `public struct` (`emergency_pause.move:16-18`),
so no visibility change is needed on the payload type itself. Instantiate
further payload types only if a rule actually needs one.

### `core/proposal/proposal.move`

**New**:
- `borrow_active<T>(hashi: &Hashi, id: ID): &Proposal<T>` and
  `borrow_executed<T>(hashi: &Hashi, id: address): &Proposal<T>` — or the
  equivalent on `Proposals`; there is no way to reach a `&Proposal<T>` from
  spec code today.
- Field accessors on `&Proposal<T>` (all fields are private):
  `proposal_creator`, `proposal_created_timestamp_ms`,
  `proposal_executed_timestamp_ms: Option<u64>`,
  `proposal_quorum_threshold_bps`, `proposal_vote_count`,
  `proposal_has_vote(v: address): bool`.
- `proposal_voting_weight<T>(p: &Proposal<T>, hashi: &Hashi): u64` — the
  same fold `quorum_reached` performs (`:219-221`), exposed so G6/G10 can
  assert the arithmetic rather than re-assert the predicate.
- `max_proposal_duration_ms(): u64` — exposes the private
  `MAX_PROPOSAL_DURATION_MS` (`:19`) for G3.
- The three monomorphic wrappers above.

**Bump `public(package)` → `public`**: `is_expired` (`:229`),
`quorum_reached` (`:218`), `votes` (`:243`). `create` (`:153`) and
`execute` (`:187`) only if engine-level rules are preferred over the
`types/*` wrappers — they should not be needed.

### `core/proposal/proposals.move`

**New**:
- `contains_active(self: &Proposals, id: ID): bool` and
  `contains_executed(self: &Proposals, id: address): bool` — the place to
  encapsulate GF7's key-type asymmetry once, so no rule repeats it.

**Bump**: `active` (`:34`), `executed` (`:42`) — needed both for membership
and for the `object::id(..) != object::id(..)` bag-distinctness assumption
G1/G7 require (mirroring `deposit_queue`'s `requests_ref`/`processed_ref`).
`active_mut`/`executed_mut` are not needed by any rule here.

### `core/proposal/types/*`

**New** payload-field accessors (all payload fields are private):
- `emergency_pause::emergency_pause_flag(self: &EmergencyPause): bool` (G8).
- `abort_reconfig::abort_reconfig_epoch(self: &AbortReconfig): u64` (G15).

Add others only as rules need them (`DisableVersion.version`,
`UpdateGuardian.url`, `Upgrade.digest`, `UpdateConfig.entries`).

### `core/committee/committee_set.move`

**New**:
- `pending_handoff_cert_is_set(self: &CommitteeSet): bool` — the
  `PendingEpochChange.committee_handoff_cert` field has **no accessor of
  any kind**; `pending_epoch_change()` (`:345-351`) exposes only `epoch`.
  Required by G13.

**Bump `public(package)` → `public`**: `epoch` (`:329`),
`current_committee` (`:333`), `get_committee` (`:337`), `has_committee`
(`:341`), `pending_epoch_change` (`:345`), `mpc_public_key` (`:353`),
`member_authorized` (`:144`), `has_member` (`:152`). Plus
`start_reconfig` (`:235`), `end_reconfig` (`:276`), `abort_reconfig`
(`:303`) and `set_pending_committee_handoff_cert` (`:266`) **only** if
G16's queue-level fallback form is used.

`is_reconfiguring` (`:357`) is already public via the applied patch.

### `core/committee/committee.move`

**Bump**: `total_weight`, `epoch`, `get_member_weight` (`:158`) — G6, G10.
(`CommitteeSignature` is already constructible via the public
`new_committee_signature`, `:69-79`, so certs can be built in rules.)

### `core/reconfig.move`

**Bump**: `start_reconfig` — `entry` → `public entry`. It is the one
reconfiguration entry point with no `#[test_only]` forwarder, and G12/G14/
G16 all need to call it directly. The other two are already reachable via
their `*_for_testing` forwarders.

### `core/config/config.move`

**Bump `public(package)` → `public`**: `guardian_btc_public_key` (`:118`),
`set_guardian_btc_public_key` (`:130`), `emergency_pause_threshold_bps`
(`:141`), `emergency_unpause_threshold_bps` (`:145`),
`is_valid_config_update` (`:99`), `contains` (`:81`), `try_get` (`:71`).
`paused` (`:106`) is already public via the applied patch.

### `core/threshold.move`

**Bump**: `weight_threshold` (`:35`) — G6, G10 assert against it directly.

### `hashi.move`

**Bump**: `proposals` (`:194`), `current_committee` (`:186`).
`proposals_mut` (`:198`) is not needed.

---

## Summary — rule shape and status per property

| Property | Rule shape | Depends on / corollary of | Accessor gaps | Status |
|---|---|---|---|---|
| G1 proposal bag exclusion | assert (parametric, 4 targets) + base case | — | `contains_active`/`contains_executed` (new), `active`/`executed` (bump) | ready once accessors land |
| G2 execute at most once | expect-unreachable | corollary of G1 | none beyond G1's | ready |
| G3 expiry window | assert ×2 | — | `borrow_active`, `proposal_created_timestamp_ms`, `max_proposal_duration_ms` (new) | ready |
| G4 executed ⇒ undeletable | assert ×2 | corollary of G1 | as G3 + `delete_expired_emergency_pause` wrapper | ready |
| G5 vote-set integrity | assert ×2 + expect-unreachable + expect-reachable | — | `proposal_has_vote` (new), `member_authorized` (bump), vote wrappers | ready |
| G6 live quorum / pinned threshold | assert ×2 | — | `proposal_voting_weight`, `proposal_quorum_threshold_bps` (new), `weight_threshold`/`total_weight` (bump) | ready — **G6b worth confirming as intended** |
| G7 executed flag/bag coherence | assert (parametric) | — | `borrow_active`/`borrow_executed`, `proposal_executed_timestamp_ms` (new) | ready — the G-analogue of W3, but single-key so no module split |
| G8 per-type effect applies once | assert ×7 (one per payload) | inherits G2 | payload-field accessors (new); `data` already usable | ready; the archive-then-effect atomicity half is an **audit note, not a rule** |
| G9 guard completeness | assert (✓ cells) + expect-reachable (omissions) | — | **none** | **ready today, no patch needed — write this first** |
| G10 pause asymmetry non-invertible | assert ×2 + G11's frame rule | needs G6 | emergency threshold accessors (bump) | ready — **P13's core**; argument is numeric, see GF4 |
| G11 `update_config` write surface | expect-reachable ×1 + assert ×2 | — | guardian/config accessors (bump) | ready — **confirms GF1, the headline finding** |
| G12 one reconfig in flight | assert ×4 (one per transition) + expect-unreachable | — | `start_reconfig` (bump to `public entry`) | ready — do **not** write the parametric form (vacuous) |
| G13 handoff cert write-once | expect-unreachable + assert + expect-reachable | — | `pending_handoff_cert_is_set` (new), `mpc_public_key` (bump) | ready — **confirms GF2** |
| G14 epoch advance | assert ×2 (+ a `+1` variant expected to fail) | — | `epoch`, `pending_epoch_change` (bump) | ready — **corrects P12; expect the `+1` variant to produce a counterexample** |
| G15 abort restores prior state | assert ×2 | needs G12 | `has_committee` (bump), `abort_reconfig_epoch` (new) | ready |
| G16 abort binds epoch, not attempt | expect-reachable | needs G15 | as G15 + `start_reconfig` | ready — **confirms GF3; answers P15's open question** |
| G17 bag key injectivity | — (English only) | discharged by Sui's typed DF keys | — | documented, not encoded; see GF7 |

### Suggested order

1. **G9's positive cases** — the only rules in this document needing **no
   accessor work at all** (`is_version_enabled`, `paused`,
   `is_reconfiguring` are all already patched). Mirrors the three existing
   deposit/withdrawal guard rules almost verbatim, so it also validates that
   the governance targets wire up at all before any harder rule depends on
   that.
2. **G1, then G2/G4/G7** — the bag-exclusion invariant and the three
   properties that fall out of it. `contains_active`/`contains_executed`/
   `borrow_active` unblock the most downstream rules of any accessor here.
3. **G11, then G10** — GF1 first, because it is the finding with the
   clearest suggested code change and it reframes P5; G10's asymmetry
   argument then rests on a known write surface rather than an assumed one.
4. **G13 and G16** — the two reconfiguration findings (GF2, GF3). Both are
   expect-reachable witnesses, so a *satisfiable* result is the deliverable;
   neither depends on anything above.
5. **G12, G14, G15** — the reconfiguration invariants proper. G14's
   `epoch_only_changes_at_end_reconfig` is the most reusable rule in this
   group: it is the frame property that licenses every epoch-pinning
   argument in P6, P9 and W11.
6. **G3, G5, G6, G8** — the remainder, in any order. G6b is the one worth
   raising with the protocol team before encoding, since "is this intended?"
   is a design question, not a verification one.
