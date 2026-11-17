# Hashi Protocol

## 1. Protocol Description

Hashi is a Sui-native Bitcoin orchestrator. Its purpose is to provide
**trust-minimized custody for BTC so it can be represented 1:1 as a usable Sui
asset (`hBTC`) and redeemed back to native BTC.** No value is created or
destroyed and no swap occurs: BTC is locked under threshold custody, and
`hBTC` is a claim ticket on that locked BTC — minted on deposit, burned on
withdrawal, always redeemable 1:1. There is no `$HASHI` governance/utility
token; the Sui validator set governs the protocol by voting onchain with
stake weight.

### Two signers, one 2-of-2

Every Bitcoin UTXO Hashi controls sits behind a **P2TR (Taproot) address**
requiring two independent signatures. Neither party alone can move funds.

- **MPC committee**: a subset of Sui validators (>90% expected) who
  separately register (BLS key, service endpoint, TLS key) and jointly hold a
  single Bitcoin private key via threshold Schnorr signing (DKG, key
  rotation, distributed signing). Parametrized by `f` (liveness threshold,
  ~20-33%) and `t` (safety/collusion threshold, ~33-50%). This is the
  decentralization leg.
- **Guardian**: an independently operated cloud enclave (TEE), not part of
  the validator set. It enforces its own policy — verifies committee
  certificates, runs a token-bucket rate limiter on withdrawals, and
  independently validates each request before signing. This is the
  defense-in-depth leg: it stops fund movement even if the entire MPC
  committee is compromised or colluding, and vice versa.

The Taproot script tree encodes this directly (see
[design/docs/address-scheme.mdx](design/docs/address-scheme.mdx)):

```
tr(NUMS_point, {multi_a(2, H_derived, guardian_key), and_v(v:older(60days), pk(H_derived))})
```

- **Leaf 1 (normal path)**: 2-of-2 multisig(committee key, guardian key) — used
  for every ordinary withdrawal.
- **Leaf 2 (escape hatch)**: committee key alone, spendable only after a
  60-day relative timelock — recovery path if the guardian key is ever lost.
- The internal key is a NUMS point (no known private key), so funds can only
  move through one of the two explicit scripts.

Each Sui address gets its own uniquely derived Bitcoin deposit address
(purpose-built unhardened derivation over secp256k1, keyed by the Sui
address — not BIP-32), while the master signing key stays shared across the
committee.

### Deposit flow — Request → Approve → Confirm → Mint

1. **Request**: user sends BTC to their unique deposit address (must clear
   Bitcoin dust minimum and the protocol's `bitcoin_deposit_minimum`), then
   calls `hashi::deposit::deposit` on Sui with a `Utxo` (txid, vout, amount,
   derivation path). Deposits are free — no protocol fee.
2. **Approve**: committee watches Bitcoin for `bitcoin_confirmation_threshold`
   confirmations (reorg protection), each member independently screens the
   source address for sanctions, and a stake-weighted quorum cert is
   submitted via `approve_deposit`. No `hBTC` is minted yet.
3. **Confirm**: a mandatory `bitcoin_deposit_time_delay_ms` window must
   elapse after approval — a buffer for operators to catch a fraudulent/buggy
   approval and pause before funds move. `confirm_deposit` re-verifies the
   stored certificate against the *current* committee (invalidated by a
   mid-window committee rotation) and checks the delay has elapsed.
4. **Mint**: `hBTC` is minted 1:1 to the user's Sui address; the UTXO joins
   the shared pool for future withdrawal coin-selection.

### Withdraw flow — Request → Approve → Build TX → Sign → Broadcast

1. **Request**: user calls `request_withdrawal` with `hBTC` (burned later) and
   a destination Bitcoin address (P2WPKH/P2TR), subject to
   `bitcoin_withdrawal_minimum`. Cancellable before approval (with cooldown).
2. **Approve**: gated by the Guardian's rate limiter capacity; committee
   screens the destination address for sanctions; quorum cert submitted via
   `approve_request`.
3. **Build TX**: a leader batches approved requests into one Bitcoin
   transaction, selects UTXOs (with opportunistic small-UTXO consolidation),
   computes the miner fee via `estimatesmartfee` (capped, validated by other
   members within [1 sat/vB, 3x their own estimate]). **The user pays the
   miner fee**, keeping the invariant `input_total = user_output + change` so
   the pool never shrinks by more than what's withdrawn. Committed onchain via
   `commit_withdrawal_tx` (burns hBTC, marks UTXOs spent).
4. **Sign**: two-step, matching the 2-of-2 script — the Guardian enclave
   independently validates and Schnorr-signs each input; the committee
   separately runs threshold MPC signing for the second signature per input.
   Combined into the taproot script-path witness via `sign_withdrawal`.
5. **Broadcast**: fully signed tx sent to Bitcoin; once confirmed,
   `confirm_withdrawal` releases the change output back to the pool. Stuck
   transactions are bumped via CPFP, not RBF.

See [design/docs/deposit.mdx](design/docs/deposit.mdx),
[design/docs/withdraw.mdx](design/docs/withdraw.mdx),
[design/docs/fees.mdx](design/docs/fees.mdx), and
[design/docs/guardian.mdx](design/docs/guardian.mdx) for full detail.

## 2. Files Overview

`packages/hashi/sources/` has 31 modules in three groups: the root, `btc/`
(chain-specific logic), and `core/` (chain-agnostic protocol machinery).

### Root

- **[hashi.move](packages/hashi/sources/hashi.move)** — the shared `Hashi`
  object aggregating committee set, config, versioning, treasury, proposals,
  and TOB cert storage; hangs `BitcoinState` off it as a dynamic field.
  Provides package-wide guards (pause, reconfig, committee-signature
  verification) and the one-time `finish_publish` launch switch.

### `btc/` — deposit/withdraw pipeline and the BTC asset

| File | Role |
|---|---|
| [bitcoin_state.move](packages/hashi/sources/btc/bitcoin_state.move) | Bundles the deposit queue, withdrawal queue, UTXO pool; per-user request index |
| [utxo.move](packages/hashi/sources/btc/utxo.move) | Value types: `UtxoId` (txid:vout) and `Utxo` (+ amount, derivation path) |
| [utxo_pool.move](packages/hashi/sources/btc/utxo_pool.move) | Tracked UTXO set — `utxo_records` (spendable) vs. `spent_utxos` (permanent replay protection) |
| [deposit_queue.move](packages/hashi/sources/btc/deposit_queue.move) | Storage/bookkeeping for deposit requests (active → confirmed bags) |
| [deposit.move](packages/hashi/sources/btc/deposit.move) | Drives Request → Approve → Confirm → Mint |
| [withdrawal_queue.move](packages/hashi/sources/btc/withdrawal_queue.move) | Storage/state machine: Requested → Approved → Processing → Signed → Confirmed |
| [withdraw.move](packages/hashi/sources/btc/withdraw.move) | Drives Request → Approve → Build → Sign → Broadcast, incremental MPC + guardian signature collection |
| [btc.move](packages/hashi/sources/btc/btc.move) | Defines the `hBTC` coin type (8 decimals) |
| [btc_config.move](packages/hashi/sources/btc/btc_config.move) | BTC-specific config accessors and fee math |

### `core/` — committee, MPC, and governance machinery

**Committee / MPC identity:**

| File | Role |
|---|---|
| [validator.move](packages/hashi/sources/core/validator.move) | Validators register as Hashi committee members (BLS key, endpoint, TLS key) |
| [committee/committee.move](packages/hashi/sources/core/committee/committee.move) | A `Committee` pins one epoch's members + weights + MPC params; verifies aggregate BLS certificates against stake threshold |
| [committee/committee_set.move](packages/hashi/sources/core/committee/committee_set.move) | Registry across epochs: member metadata, per-epoch `Committee`s, current epoch, MPC threshold pubkey, in-flight reconfiguration state |
| [reconfig.move](packages/hashi/sources/core/reconfig.move) | Committee hand-off between epochs (start → handoff cert → end) |
| [threshold.move](packages/hashi/sources/core/threshold.move) | >2/3 stake-weight quorum math used everywhere certificates are checked |
| [mpc_config.move](packages/hashi/sources/core/mpc_config.move) | Governed MPC parameters (signing threshold, max-faulty bound), snapshotted per-committee |
| [mpc_signing.move](packages/hashi/sources/core/mpc_signing.move) | Presignature/nonce bookkeeping for threshold Schnorr signing; documents explicit nonce-safety invariants |
| [tob.move](packages/hashi/sources/core/tob.move) | Totally-Ordered-Broadcast storage for DKG/key-rotation/nonce-generation MPC ceremonies |
| [cert_submission.move](packages/hashi/sources/core/cert_submission.move) | Entry points for submitting TOB dealer certificates |
| [intent.move](packages/hashi/sources/core/intent.move) | Domain-separation tags so a signature for one message type can never be replayed as another (must stay in sync with `crates/hashi-types/src/intent.rs`) |

**Config & assets:**

| File | Role |
|---|---|
| [config/config.move](packages/hashi/sources/core/config/config.move) | Generic typed key-value config store (pause state, guardian URL/key, fee params) |
| [config/config_value.move](packages/hashi/sources/core/config/config_value.move) | Typed value wrapper for config entries |
| [treasury.move](packages/hashi/sources/core/treasury.move) | Custodies `TreasuryCap`/`MetadataCap`, exposes mint/burn used by deposit/withdraw |

**Governance:**

| File | Role |
|---|---|
| [proposal/proposal.move](packages/hashi/sources/core/proposal/proposal.move) | Generic quorum-voting engine |
| [proposal/proposals.move](packages/hashi/sources/core/proposal/proposals.move) | Storage for active/executed proposals |
| [proposal/types/abort_reconfig.move](packages/hashi/sources/core/proposal/types/abort_reconfig.move) | Abort a stuck reconfiguration |
| [proposal/types/disable_version.move](packages/hashi/sources/core/proposal/types/disable_version.move) | Disable a package version |
| [proposal/types/emergency_pause.move](packages/hashi/sources/core/proposal/types/emergency_pause.move) | Pause (low quorum) / unpause (supermajority) the bridge |
| [proposal/types/enable_version.move](packages/hashi/sources/core/proposal/types/enable_version.move) | Re-enable a disabled package version |
| [proposal/types/update_config.move](packages/hashi/sources/core/proposal/types/update_config.move) | Update global config entries (type-checked, no new keys) |
| [proposal/types/update_guardian.move](packages/hashi/sources/core/proposal/types/update_guardian.move) | Update the guardian's URL only (BTC key is immutable once set) |
| [proposal/types/upgrade.move](packages/hashi/sources/core/proposal/types/upgrade.move) | Package upgrade governance flow |
| [versioning.move](packages/hashi/sources/core/versioning.move) | Package version gating + `UpgradeCap` custody |

**In one sentence**: `btc/` is the user-facing deposit/withdraw state
machine; `core/` is what makes the certificates in that state machine
trustworthy — who's on the committee, how they sign as a threshold group,
and how governance changes the few things that aren't hardcoded.

## 3. Audit Plan

### Phase 0 — Threat model

Before reading code line-by-line, write down what each of these would look
like on-chain:

- Committee colludes (< `t`) — should still be stopped by the Guardian's
  independent signature.
- Guardian is compromised alone — should still be stopped by the committee.
- A single malicious/buggy validator (not quorum) — should never move funds
  or corrupt state.
- Committee handoff/reconfig happens mid-flight (e.g. deposit approved, then
  epoch rotates before confirm).
- Replay: a certificate, UTXO, or withdrawal gets processed twice.
- Governance capture: a proposal type over-reaches its stated scope (e.g.
  `update_config` sneaking in a guardian-key change).

Ground this in: [design/docs/user-flows.mdx](design/docs/user-flows.mdx),
[design/docs/guardian.mdx](design/docs/guardian.mdx),
[design/docs/committee.mdx](design/docs/committee.mdx),
[design/docs/mpc-protocol.mdx](design/docs/mpc-protocol.mdx),
[design/docs/fees.mdx](design/docs/fees.mdx).

### Phase 1 — Attack-surface inventory

Order by entry-point density, riskiest first:

| # | File | entry / public | Why here |
|---|---|---|---|
| 1 | [btc/withdraw.move](packages/hashi/sources/btc/withdraw.move) | 7 entry / 2 public | Largest surface; moves real BTC out |
| 2 | [core/reconfig.move](packages/hashi/sources/core/reconfig.move) | 3 entry / 4 public | Committee hand-off — wrong here breaks everything downstream |
| 3 | [core/validator.move](packages/hashi/sources/core/validator.move) | 6 entry / 0 | Who gets to be committee — check each mutation's auth check |
| 4 | [btc/deposit.move](packages/hashi/sources/btc/deposit.move) | 4 entry / 1 public | Mints hBTC — second highest fund-movement surface |
| 5 | [core/cert_submission.move](packages/hashi/sources/core/cert_submission.move) | 4 entry / 0 | Feeds DKG/rotation/nonce ceremonies — upstream of all signing |
| 6 | [core/proposal/proposal.move](packages/hashi/sources/core/proposal/proposal.move) | 2 entry / 2 public | Generic voting engine every governance action relies on |
| 7 | [hashi.move](packages/hashi/sources/hashi.move) | 1 entry / 2 public | `finish_publish` is call-once — confirm it truly can't replay |
| 8 | [core/proposal/types/upgrade.move](packages/hashi/sources/core/proposal/types/upgrade.move) | 0 / 3 | Can brick or take over the whole package |
| 9 | [core/proposal/types/{update_guardian,update_config,enable_version,disable_version,abort_reconfig,emergency_pause}.move](packages/hashi/sources/core/proposal/types/) | 0 / 2 each | Six near-identical shapes — diff them against each other for inconsistency |
| 10 | [btc/utxo.move](packages/hashi/sources/btc/utxo.move) | 0 / 2 | Just constructors, but feeds every Phase 2 check |
| 11 | [core/committee/committee.move](packages/hashi/sources/core/committee/committee.move) / [committee_set.move](packages/hashi/sources/core/committee/committee_set.move) | 0/1, 0/4 | Read-heavy, not entry, but every `verify` call in Phases 2–3 routes through here |
| 12 | [core/tob.move](packages/hashi/sources/core/tob.move), [btc/withdrawal_queue.move](packages/hashi/sources/btc/withdrawal_queue.move) | 0 / 1 each | Low surface, skim only |
| — | [core/config/config_value.move](packages/hashi/sources/core/config/config_value.move) | 0 / 7 | Deprioritize — pure value constructors, not state-mutating |

For each entry, check: who can call it, does it check
`assert_unpaused`/`assert_not_reconfiguring` where it should, and can it be
reordered/front-run inside a PTB.

### Phase 2 — Money-movement state machines

Read in transaction order, deposit then withdraw:

1. [btc/utxo.move](packages/hashi/sources/btc/utxo.move) — value types
2. [btc/deposit_queue.move](packages/hashi/sources/btc/deposit_queue.move) — storage/state shape
3. [btc/deposit.move](packages/hashi/sources/btc/deposit.move) — Request→Approve→Confirm→Mint logic
4. [btc/utxo_pool.move](packages/hashi/sources/btc/utxo_pool.move) — check `spent_utxos` insert-order against every caller
5. [btc/withdrawal_queue.move](packages/hashi/sources/btc/withdrawal_queue.move) — storage/state shape
6. [btc/withdraw.move](packages/hashi/sources/btc/withdraw.move) — the five-phase logic
7. [btc/btc_config.move](packages/hashi/sources/btc/btc_config.move) — fee math behind deposit minimums / withdrawal bounds
8. [btc/bitcoin_state.move](packages/hashi/sources/btc/bitcoin_state.move) — confirm the per-user index can't desync from the queues it mirrors
9. [btc/btc.move](packages/hashi/sources/btc/btc.move) — confirm mint/burn are only reachable through `treasury.move`

Key questions: can any state be skipped, can a request be processed twice
(double-mint/burn/spend), are cooldown/delay comparisons off-by-one-safe, can
cancellation race with pickup.

### Phase 3 — Certificate & signature verification

Read in dependency order, primitives → verification → consumers:

1. [core/intent.move](packages/hashi/sources/core/intent.move) — domain-separation tags; cross-check against `crates/hashi-types/src/intent.rs` immediately
2. [core/threshold.move](packages/hashi/sources/core/threshold.move) — quorum arithmetic; check ceiling-division edge cases by hand
3. [core/committee/committee.move](packages/hashi/sources/core/committee/committee.move) — `verify_certificate`, the single choke point every cert flows through
4. [core/committee/committee_set.move](packages/hashi/sources/core/committee/committee_set.move) — per-epoch committee storage, epoch pinning
5. [core/mpc_config.move](packages/hashi/sources/core/mpc_config.move) — governed params snapshotted per-committee; confirm `pin` fires at the right point in reconfig
6. [core/mpc_signing.move](packages/hashi/sources/core/mpc_signing.move) — walk every call site of `record`/`reallocate` against its own documented nonce-safety invariants
7. [core/tob.move](packages/hashi/sources/core/tob.move) + [core/cert_submission.move](packages/hashi/sources/core/cert_submission.move) — DKG/rotation/nonce-gen ceremony cert storage, first-submission-wins semantics

### Phase 4 — Committee lifecycle / reconfiguration

`committee_set.move`, `reconfig.move`: genesis vs. non-genesis handoff
gating; stuck-reconfiguration recovery via `abort_reconfig`; state validity
in the window between `start_reconfig` and `end_reconfig`.

### Phase 5 — Governance

`proposal.move`, `proposals.move`, `proposal/types/*`: no ambient authority
leak beyond a proposal's stated payload; `emergency_pause`'s asymmetric
quorum (low to pause / supermajority to unpause) can't be confused; 7-day
expiry can't be bypassed for unexecuted proposals.

### Phase 6 — Object model / storage safety

Dynamic-field/`ObjectBag`/`Table` key collisions across purposes (e.g.
`BitcoinStateKey` vs. future chain keys on the same `Hashi.id`); confirm
`assert_version_enabled` is called on every entry point, not just most.

### Phase 7 — Bitcoin-side specifics

Address derivation vs. [design/docs/address-scheme.mdx](design/docs/address-scheme.mdx)
(NUMS point, timelock encoding); fee math floor/ceiling/per-user-cap checks
from [design/docs/fees.mdx](design/docs/fees.mdx) for integer truncation.

### Phase 8 — Cross-check against existing tests

Map each file in [packages/hashi/tests/](packages/hashi/tests/) to the
invariants above (e.g. `utxo_spent_tests.move`, `threshold_tests.move`,
`mpc_signing_tests.move` line up with Phases 2–3) — skip/spot-check what's
already covered, spend time on genuinely untested areas.

### Phase 9 — Off-chain/on-chain consistency

Spot-check `crates/hashi-guardian`, `hashi-monitor`, `hashi-screener` against
the Move side for places docs call out manual sync (intent registry, fee
estimation bounds, sanctions screening logic).

**Suggested execution order**: Phase 0 → 1 first (cheap, gives a checklist),
then 2 and 3 (highest value: fund-movement + crypto), then whichever of 4–7
matches the biggest concern, use 8 to validate/deprioritize, and 9 last since
it's slower cross-repo work.
