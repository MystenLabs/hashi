# Hashi — Manual audit of the remaining components

| | |
|---|---|
| **Reviewed against** | `nisarg/setup` at `f2fb7843` (unpatched `packages/hashi`) |
| **Date** | 2026-09-25 |
| **Status** | Draft for review |

## Scope

This pass covers what [PROPERTIES_DEPOSIT.md](PROPERTIES_DEPOSIT.md),
[PROPERTIES_WITHDRAW.md](PROPERTIES_WITHDRAW.md) and
[PROPOSAL_GOVERNANCE.md](PROPOSAL_GOVERNANCE.md) do not.

**Already covered elsewhere, not re-audited here:** `deposit.move`,
`deposit_queue.move`, `withdraw.move`, `withdrawal_queue.move`,
`utxo_pool.move`, the presig allocation half of `mpc_signing.move` (W10/W11),
`proposal.move`, `proposals.move`, `proposal/types/*`, the reconfig half of
`committee_set.move`, `reconfig.move`, `config.move`'s governable surface
(G11/GF1/GF4), `versioning.move` (GF16), `threshold.move`'s `u16` narrowing
(GF20), and the TOB/cert-submission issues GF11, GF14 and GF19.

**In scope, Move:**

| Module | Focus |
|---|---|
| `core/committee/committee.move` | `verify_certificate`: bitmap parsing, stake sum, preimage |
| `core/committee/committee_set.move` (member half) | registration, proof of possession, operator delegation, key setters |
| `core/validator.move` | entry points over the above |
| `core/intent.move` | registry, call sites, Rust mirror |
| `core/mpc_signing.move` (recording half) | `record`, `to_signatures` |
| `core/tob.move`, `core/cert_submission.move` | residual issues not in GF11/GF14/GF19 |
| `core/mpc_config.move` | parameter validation |
| `core/treasury.move`, `btc/btc.move` | cap custody, mint/burn reachability |
| `btc/btc_config.move`, `core/config/config_value.move` | accessors, floors |
| `btc/bitcoin_state.move`, `btc/utxo.move` | per-user index, value types |
| `hashi.move` | `init`, `finish_publish`, `verify` wrappers, presig counter |

**In scope, off-chain:** targeted cross-checks of the places where the Move
code trusts off-chain behaviour: the Rust signing-preimage mirror, the node's
deposit and withdrawal signing checks, `hashi-screener`, `hashi-monitor`, and
`hashi-guardian`. This is not a full audit of the ~100k lines under `crates/`.

## Summary

| ID | Title | Severity | Where |
|---|---|---|---|
| R1 | A single validator with a malformed encryption key blocks every committee handoff | High | `committee_set.move:211`, `crates/hashi/src/onchain/mod.rs:1420-1425`, `crates/hashi-types/src/move_types/mod.rs:1470-1477` |
| R2 | Deposit AML screening checks the request's object ID, not the recipient | Medium | `crates/hashi/src/deposits.rs:62` |
| R3 | The monitor doesn't read Sui, so nothing watches the deposit time-delay window | Medium | `crates/hashi-monitor/src/audit/mod.rs:262-265` |
| R4 | A workspace-wide `cargo build` turns off Nitro attestation checks in every binary | Medium | `crates/e2e-tests/Cargo.toml:8-11`, `crates/hashi-types/src/guardian/attestation.rs:67-82` |
| R5 | Screening can be off with no error: optional endpoint, and unknown chain IDs are auto-approved | Low | `crates/hashi/src/lib.rs:749-767`, `crates/hashi-screener/src/main.rs:91-103` |
| R6 | MPC parameters are range-checked one at a time, never against each other | Low | `core/mpc_config.move:34-47` |
| R7 | The guardian rate limiter can be reset, or charged twice for one withdrawal | Low | `crates/hashi-types/src/guardian/mod.rs:965-970`, `crates/hashi-guardian/src/s3_reader/limiter_recovery.rs:51-55` |
| R8 | Signing preimages are not bound to a Hashi deployment | Info | `committee.move:256-258`, `committee_set.move:504-508` |
| R9 | `finish_publish` doesn't validate its launch parameters or the cap's upgrade policy | Info | `hashi.move:68-112` |
| R10 | An operator key controls the member's next-epoch BLS key | Info | `committee_set.move:157-233` |
| R11 | `mpc_signing::record` accepts stale-epoch batches and drops conflicting signatures without a trace | Info | `core/mpc_signing.move:104-121` |
| R12 | `derivation_path = None` and `Some(@0x0)` give the same Bitcoin address but behave differently in Move | Info | `crates/hashi/src/deposits.rs:355-360`, `btc/deposit.move:234-240` |
| R13 | The node's fee-rate ceiling is 5×, not the documented 3× | Info | `crates/hashi/src/withdrawals.rs:46` |
| R14 | `MetadataCap` is held with no way to use it | Info | `core/treasury.move:47-49`, `:72-75` |
| R15 | Bare `assert!`s outside the reconfig path | Info | several |
| R16 | Dead code in security-relevant modules | Info | `committee.move:176-192`, `tob.move:97-113`, `treasury.move:51-54` |
| R17 | No Move tests for proof of possession, bitmap edge cases, or the treasury | Info | `packages/hashi/tests/` |

R1 is the one to look at first. It's a cross-language bug: each side looks
correct on its own, and neither the Move tests nor PROPOSAL_GOVERNANCE.md's
reconfig properties can see it.

---

## R1 — A single validator with a malformed encryption key blocks every committee handoff

**Severity:** High, for availability. Any one active Sui validator can halt
committee rotation permanently. It can also stop deposits and withdrawals
over and over, at the cost of one transaction per round. No funds are lost.

**Location:**

- Move: `committee_set.move:204-216`, `:414-417`, `reconfig.move:120-137`,
  `committee_set.move:292`
- Rust: `crates/hashi/src/onchain/mod.rs:55-58`, `:1410-1426`, `:503-509`;
  `crates/hashi-types/src/move_types/mod.rs:1470-1477`;
  `crates/hashi/src/withdrawals.rs:862-867`; `crates/hashi/src/leader/guardian.rs:355-357`

### The two halves

**Move** accepts any 32 bytes as an encryption key.
`set_next_epoch_encryption_public_key` checks only
`length() == 32` (`:211`). `new_committee_from_validator_set` skips a
member only when the key is *empty* (`:415`). Anything else goes into the
pending `Committee` verbatim.

**Rust** replaces a key it can't decode. When the node loads a committee
from chain, `convert_move_committee_member` decodes each encryption key as
a Ristretto point. On failure, it swaps in a fixed placeholder:

```rust
parse_encryption_public_key(encryption_public_key.as_slice())
    .map(Into::into)
    .unwrap_or_else(fallback_encryption_public_key),   // onchain/mod.rs:1423-1425
```

The rich `Committee` in memory therefore no longer matches the on-chain
bytes. The code comment at `:1435-1436` shows the authors wanted
round-tripping ("Carry the pinned config verbatim so the rich committee
re-serializes to the exact on-chain bytes"), but that was done for `config`
only, not for member keys.

### Where they collide

To produce a handoff signature, the outgoing committee signs a
`CommitteeTransitionRequest` built by *re-serializing* that in-memory
committee:

```rust
new_committee: hashi_types::move_types::Committee::from(&new_committee),   // withdrawals.rs:862-864
// From<&CommitteeMember>: encryption_public_key: m.encryption_public_key().to_bcs()   // move_types/mod.rs:1475
```

`submit_committee_handoff` checks the cert against the **on-chain**
committee, copied verbatim (`reconfig.move:128-137`). For the malformed
member, the signed bytes contain the placeholder key while the verified
bytes contain the original 32 bytes. Every honest signature therefore fails
`ESigVerification`, and no handoff cert can ever be submitted.
`end_reconfig` then requires one for every non-initial reconfig
(`committee_set.move:292`), so the reconfig can't complete.

### Exploit

1. Any active Sui validator calls `register`, sets a valid BLS key with a
   proof of possession, and sets 32 bytes that are not a canonical
   Ristretto encoding as its encryption key. Almost any random 32 bytes
   will do. Its stake can be arbitrarily small, since the only requirement
   is weight > 0.
2. Anyone calls `start_reconfig`, which is permissionless. The member is
   included in the pending committee.
3. The handoff can never be certified. Meanwhile `assert_not_reconfiguring`
   blocks `approve_deposit`, `confirm_deposit`, `commit_withdrawal_tx`,
   `finalize_withdrawal` and so on.
4. Governance recovers with `AbortReconfig` (6667 bps). But
   `abort_reconfig` removes the pending committee (`committee_set.move:313`),
   so `start_reconfig`'s guards pass again right away: `!is_reconfiguring`,
   `!has_committee(ctx.epoch())`, and `epoch != ctx.epoch()`. The attacker,
   or anyone else, re-triggers it in the next transaction, and the bad
   member is included again. Membership is never revoked (GF19).

So each abort buys only as long as it takes someone to call
`start_reconfig` again. The committee can never rotate as long as the
validator is active. The bridge stays on its last committee indefinitely,
which makes GF18's entrenchment concern permanent. This can also happen by
accident: a buggy operator tool that writes a bad key has the same effect.

DKG and key rotation themselves tolerate the placeholder. The fallback
member simply can't decrypt its shares (`onchain/mod.rs:1421-1422`). The
handoff certificate is the only step that breaks.

### Recommendation

Fix both sides:

- **Rust:** keep the raw on-chain member bytes in the `Committee` (or in
  `committee_transition`) and sign the verbatim `move_types::Committee`,
  never one re-serialized from the decoded form. This is the actual bug.
- **Move:** don't let a key that no node can use into a committee. Either
  validate the point on-chain, if a Ristretto decode native is available,
  or have `new_committee_from_validator_set` skip members whose key fails
  validation, as it already does for empty keys.

Separately, consider rate-limiting `start_reconfig` after an abort, for
example one attempt per Sui epoch. That closes the "re-trigger immediately"
amplification, which GF14 touches from a different angle.

**Not yet reproduced.** This follows from reading the code on both sides;
I haven't run it. To confirm: write an e2e test that registers one
validator with `[0xff; 32]` as its encryption key, runs a normal
(non-genesis) reconfig, and expects `submit_committee_handoff` to fail.

---

## R2 — Deposit AML screening checks the request's object ID, not the recipient

**Severity:** Medium. A compliance control that looks like it's running
isn't doing anything useful. No funds are at direct risk.

**Location:** `crates/hashi/src/deposits.rs:57-73`

```rust
// bitcoin
let source_tx_hash = deposit_request.utxo.id.txid.to_string();
...
// sui
let destination_address = deposit_request.id.to_string();   // :62
```

`deposit_request.id` is the `DepositRequest` object's own UID, created fresh
by `deposit()`. The address that actually receives hBTC is
`deposit_request.utxo.derivation_path`: `confirm_deposit` mints to it
(`btc/deposit.move:234-240`).

The screener only checks that the destination parses as a Sui address
(`crates/hashi-screener/src/main.rs:201`) and then asks MerkleScience about
it. A brand-new object ID has no history, so it will almost always score
low-risk. In practice, only the BTC source txid is screened on deposits. The
Sui recipient is never screened, even though PROTOCOL.md §Deposit step 2 says
it is.

**Recommendation:** screen `normalized_derivation_path(utxo.derivation_path)`.
For `None`, skip the Sui-side check, since nothing is minted. Add a test that
feeds a sanctioned recipient through `screen_deposit`.

---

## R3 — The monitor doesn't read Sui, so nothing watches the deposit time-delay window

**Severity:** Medium, a detection gap. The on-chain design depends on this
component for defence in depth.

**Location:** `crates/hashi-monitor/src/audit/mod.rs:262-265`

```rust
pub async fn poll_sui(&mut self) -> anyhow::Result<PollOutcome> {
    // TODO: Implement me
    Ok(PollOutcome::CursorUnmoved)
}
```

`bitcoin_deposit_time_delay_ms` exists, in the words of its own doc
(`btc_config.move:65-68`, `deposit.move:124-128`), "to detect a faulty or
fraudulent committee signature and pause the service before funds are
minted". The monitor is the natural thing to do that detecting, but its Sui
poller is a stub. As a result:

- No `DepositApproved` or `Minted` event is ever ingested. The deposit state
  machine is never instantiated, so deposit auditing never runs.
- The Sui cursor never advances, so the "missing E1" withdrawal check can
  never fire (`state_machine.rs:218-247`, `domain.rs:122-129`).
- The only live check is that each guardian approval is followed by a
  confirmed Bitcoin transaction before its deadline.

The monitor also has no checks on hBTC supply against pool balance, epoch
lag (GF18) or stuck reconfig. A grep for `supply|pause|epoch` in the crate
finds nothing. Violations are only logged via `tracing::error!`
(`audit/mod.rs:46-56`, `continuous.rs:105-108`), with no pause path.

Even the planned checks wouldn't catch a bad approval:

- The deposit check is "txid is confirmed on BTC" (`state_machine.rs:287-325`).
  It ignores vout, amount and scriptPubKey.
- The withdrawal events carry no amount or destination
  (`domain.rs:47-59`). The code itself flags this as insecure (IOP-203,
  `domain.rs:14-15`).

**Impact:** the time delay is currently useful only if a human is watching.
A committee quorum that signs a `DepositConfirmationMessage` for a
non-existent or mis-sized UTXO is caught by nothing automated, and mints
after 10 minutes (the default delay, `btc_config.move:22`).

**Recommendation:**

- Implement `poll_sui`.
- Add a deposit check that re-verifies `(txid, vout, amount, scriptPubKey)`
  independently of the committee.
- Add a global `total_supply(hBTC) <= Σ pool UTXO amounts` check.
- Wire violations to an alert that an operator can turn into an
  `EmergencyPause` vote within the delay window.

Until then, write down that the delay window depends on manual monitoring.

---

## R4 — A workspace-wide `cargo build` turns off Nitro attestation checks in every binary

**Severity:** Medium. This is build hygiene, but it silently disables the
check that key provisioners (KPs) rely on to know they are talking to a
real enclave.

**Location:** `crates/e2e-tests/Cargo.toml:8-11`, `Cargo.toml:2-3`,
`crates/hashi-types/Cargo.toml:49-50`,
`crates/hashi-types/src/guardian/attestation.rs:67-82`

`e2e-tests` depends on `hashi-guardian` with
`features = ["test-utils", "non-enclave-dev"]` as a normal
`[dependencies]` entry. That feature forwards to
`hashi-types/non-enclave-dev`. Under `resolver = "2"`, features are unified
per build invocation across all selected packages. The workspace is
`members = ["crates/*"]` with no `default-members`. A plain `cargo build`,
`cargo build --release` or `cargo build --workspace` at the repo root
therefore compiles `hashi-types` **once, with `non-enclave-dev`**, and
every binary in that build links it. That includes `hashi-guardian-init`,
the KP tool, and the `hashi` node.

In that build, `verify_at` becomes:

```rust
#[cfg(any(test, feature = "non-enclave-dev"))]
{
    let _ = (signing_pubkey, build_pcrs, verify_time);
    ... tracing::warn!("Nitro attestation verification DISABLED (non-enclave-dev build)");
    Ok(())
}
```

A KP running a tool built this way will accept any "enclave" and encrypt
its share of the guardian key to it. The only signal is one `warn!` line.

What's fine and what isn't:

- The production enclave image builds `-p hashi-guardian` alone without the
  feature (`docker/hashi-guardian/Containerfile:152`), so it is unaffected.
- `docker/hashi-guardian-k8s/Containerfile:40,56` always builds with
  `non-enclave-dev`. Confirm that image is dev-only.

**Recommendation:**

- Move the `e2e-tests` features into `[dev-dependencies]`, or add
  `default-members` that excludes `e2e-tests`.
- Add a `compile_error!` when `non-enclave-dev` is enabled together with a
  `production` or release profile marker.
- Have `hashi-guardian-init` refuse to run (not just warn) when built with
  the stub, unless an explicit `--insecure-dev` flag is passed.

---

## R5 — Screening can be off with no error: optional endpoint, and unknown chain IDs are auto-approved

**Severity:** Low (operational).

**Location:** `crates/hashi/src/config.rs:133`, `crates/hashi/src/lib.rs:749-767`,
`crates/hashi/src/deposits.rs:52-55`, `crates/hashi/src/withdrawals.rs:1302-1305`,
`crates/hashi-screener/src/main.rs:91-103`, `crates/hashi-screener/src/chain.rs:55-67`

There are two ways screening ends up off without any error:

1. **Node.** `screener_endpoint` is optional. If it's missing, or the client
   fails to build, the node logs a warning and sets `screener_client = None`.
   Both `screen_deposit` and `screen_withdrawal` then return `Ok(())` after a
   `debug!` log. Nothing requires a screener on mainnet. The only signal is
   the `screener_enabled` metric (`lib.rs:771`).
2. **Screener.** A request is auto-approved unless *both* chain IDs map to a
   known mainnet genesis prefix. Unknown CAIP-2 suffixes count as
   non-mainnet. A typo in the node's `bitcoin_chain_id` or `sui_chain_id`
   config therefore approves everything.

Failure modes that are handled correctly: if the screener is configured
but unreachable, the node fails closed and retries (`AmlServiceError`). A
definite rejection is never retried. Results are cached for 10 minutes
(`hashi-screener/src/cache.rs:13`), so a newly sanctioned address can still
pass within that window.

**Recommendation:** refuse to start on a production chain without a
screener. In the screener, reject unknown suffixes instead of auto-approving
them, and keep the auto-approve only for chain IDs known to be test networks.

---

## R6 — MPC parameters are range-checked one at a time, never against each other

**Severity:** Low. Governance-only. Recoverable after genesis, but not
during it.

**Location:** `core/mpc_config.move:34-47`, consumed at
`crates/hashi/src/mpc/mpc_except_signing.rs:5985-6029`

`is_valid_value` checks each key on its own:

| Key | Accepted |
|---|---|
| `mpc_threshold_in_basis_points` | `1..=10000` |
| `mpc_max_faulty_in_basis_points` | `0..=10000` |
| `mpc_weight_reduction_allowed_delta` | `0..=10000` |
| `mpc_nonce_generation_protocol` | `0..=1` |

No cross-key relation is checked. The node computes
`t = ceil(W · threshold_bps / 10000)` and `f = ceil(W · max_faulty_bps / 10000)`
over the reduced weight and hands both to `Nodes::prop_reduce`. DKG and
signing need, at minimum, `t > f` for safety and `t ≤ W − f` for liveness.
Both can be broken by a single `UpdateConfig`, for example
`{threshold: 9000}` with the default `max_faulty = 3333`. So can a
multi-key update that is valid key-by-key.

`pin` (`:102-121`) snapshots whatever is in the config at `start_reconfig`.
Bad parameters therefore surface only when the node fails to build its
`MpcConfig`, after the committee is pinned:

- **Non-genesis:** recoverable via `AbortReconfig`, then a fixing
  `UpdateConfig`, then retry. That is two governance cycles at 6667 bps,
  during which deposits and withdrawals are halted by
  `assert_not_reconfiguring`.
- **Genesis:** not recoverable, since `abort_reconfig` is unavailable there
  (GF12).

GF17 already recommends a higher floor on `threshold_bps`. This finding is
about the missing *joint* check.

**Recommendation:** in `update_config::execute`, validate the *resulting*
MPC parameter set after all entries are applied. Require
`threshold_bps > max_faulty_bps` and `threshold_bps + max_faulty_bps <= 10000`,
or whatever `prop_reduce` actually needs. Do it in Move, so a bad set can't
be pinned.

---

## R7 — The guardian rate limiter can be reset, or charged twice for one withdrawal

**Severity:** Low. Each variant needs a compromised or faulty committee and
an operator or KP error on top. The limiter is the guardian's only
independent control, so its edges are worth recording.

**Context:** the guardian doesn't check that outputs match on-chain
withdrawal requests. It signs any transaction covered by a ≥6667-bps
`GuardianWithdrawalRequest` cert (intent `0x0106`). It does rebuild the
sighash itself from typed inputs and outputs
(`crates/hashi-guardian/src/enclave.rs:138-151`,
`crates/hashi-guardian/src/bitcoin/utxo.rs:366-386`). Against a fully
compromised committee, the token-bucket limit (in sats of external outflow
plus fee) is therefore the only thing the guardian adds.

1. **The S3 log bucket is not part of the KP-authenticated config.**
   - `InitConfigRepr` covers only `limiter_config`,
     `hashi_btc_master_pubkey`, `pcr_allowlist` and `network`
     (`crates/hashi-types/src/guardian/mod.rs:965-970`).
   - The bucket name is checked only in the KPs' own tooling
     (`hashi-guardian-init/src/kp_provision.rs`).
   - `recover_limiter_state` falls back to `LimiterState::genesis` (a full
     bucket, `seq = 0`) when it finds no success logs
     (`s3_reader/limiter_recovery.rs:51-55`).
   - So an operator who stands the enclave up against a copy of the
     ceremony and genesis objects, minus the withdrawal logs, gets a
     refilled limiter.
   - The operator also supplies `expected_state_hash`, so that pin doesn't
     help when the operator is the adversary.
2. **Retention is operator-chosen.** `retention_environment` isn't
   KP-authenticated, and `Devnet` means a 90-day object lock instead of 10
   years (`crates/hashi-guardian/src/log/mod.rs:59-84`). That shortens how
   long the history in (1) stays tamper-proof.
3. **No per-withdrawal dedupe inside the enclave.**
   - Only the proxy cache deduplicates by withdrawal ID
     (`hashi-guardian-proxy/src/cache.rs:353-384`).
   - A leader that reaches the enclave directly, with a fresh valid cert
     for each `seq`, can have the same withdrawal re-signed at
     `seq = N, N+1, …`, draining the bucket.
   - There is no double spend, because signing is deterministic BIP-340
     over the same inputs (`utxo.rs:413`). The impact is liveness:
     legitimate withdrawals are starved.
4. **Clock skew.** Timestamps up to 5 minutes ahead are accepted
   (`standard_withdrawal.rs:94-102`). That allows a one-off pre-credit of
   `300 · refill_rate` sats.

**Recommendation:**

- Bind the S3 bucket and the retention mode into `InitConfigRepr`.
- Refuse genesis limiter state once the on-chain `num_consumed_presigs`
  shows any withdrawal has ever happened, or some equivalent on-chain
  counter.
- Dedupe by withdrawal ID inside the enclave, alongside `seq`.

---

## R8 — Signing preimages are not bound to a Hashi deployment

**Severity:** Info.

**Location:** `committee.move:256-258`, `committee_set.move:504-508`,
`crates/hashi-types/src/committee.rs:750-754`

Every committee preimage is `intent ‖ epoch ‖ bcs(message)`. The PoP is
`0x0000 ‖ epoch ‖ address ‖ pk`. Neither contains the `Hashi` object ID,
the package ID or a chain ID.

- **Safe today:** deposit and withdrawal messages carry object IDs, which
  are unique per chain. `ReconfigCompletionMessage` carries the
  deployment's own MPC key.
- **Replayable:** `CommitteeTransitionRequest` and the PoP contain only
  epochs, keys, weights and addresses. With two Hashi deployments on the
  same Sui network (for example a redeploy, or a second chain's instance),
  validators that reuse their BLS key sign byte-identical handoff messages.
  The same Sui epoch and the same `active_validator_voting_powers` order
  give the same committee. So a handoff cert from one deployment verifies
  in the other.

That is harmless as long as the two committees are genuinely identical. It
does mean "this deployment's outgoing committee approved this" isn't what
the cert proves.

**Recommendation:** add the `Hashi` object ID, or an equivalent instance
tag, to the preimage prefix. The prefix is already versioned by intent, so
this is a one-time coordinated change on both the Move and Rust sides.

Also checked for this finding: PoP and certificates share fastcrypto's
`min_pk` NUL DST (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_`). Their only
separation is intent `0x0000`. That is sound today, since nothing else is
signed under intent 0, but it rests on that single convention. A dedicated
`POP_` DST would remove it.

---

## R9 — `finish_publish` doesn't validate its launch parameters or the cap's upgrade policy

**Severity:** Info. The publisher is trusted until this call, but this is
the one irreversible configuration step.

**Location:** `hashi.move:68-112`

`finish_publish` validates only two things:

- `upgrade_cap.package() == original_id<Hashi>()` (`:83`)
- the 32-byte length of `guardian_btc_public_key`, inside the setter
  (`config.move:131`)

Everything else is accepted as given:

- `bitcoin_confirmation_threshold = Some(0)` and
  `bitcoin_deposit_time_delay_ms = Some(0)` are accepted. The first leaves
  no reorg protection on the node side. The second removes the fraud window
  that R3 already weakens.
- `guardian_btc_public_key` is not checked to be a valid x-only secp256k1
  point. An off-curve key makes every deposit address underivable, and the
  latch (`config.move:133-135`) keeps it there, apart from the GF1 bypass.
- `bitcoin_chain_id` is an arbitrary `address`, with no check that it is a
  known network's genesis hash.
- `guardian_url` may be empty, although the comment at `:64-67` says the
  guardian is load-bearing.
- The cap's **upgrade policy** is not checked. A publisher that first calls
  `sui::package::only_additive_upgrades`/`only_dep_upgrades` on the cap
  permanently narrows what governance `Upgrade` proposals can do.
- If the publisher upgrades the package *before* `finish_publish`, then
  `UpgradeCap.package` points at the new package ID. The equality at `:83`
  fails permanently, and the deployment can never launch.

**Recommendation:**

- Assert `bitcoin_confirmation_threshold >= 1` and a minimum delay.
- Assert `upgrade_cap.policy() == compatible`.
- Validate the x-only key (for example, via `ecdsa_k1` decompression of
  `0x02 || key`), or at least document it as a publisher responsibility.
- Consider whether `bitcoin_chain_id` should be checked against a small
  allow-list.

---

## R10 — An operator key controls the member's next-epoch BLS key

**Severity:** Info. This is a trust assumption worth stating.

**Location:** `committee_set.move:157-233`, `:440-447`

`assert_authorized` accepts either the validator address or the delegated
`operator_address`, and every setter uses it. That includes
`set_next_epoch_public_key` and `set_operator_address`. A compromised
operator key can therefore:

1. Install an attacker-controlled BLS key with a valid proof of possession.
   The attacker knows the new secret, so the PoP is easy to produce.
2. Wait for `start_reconfig`, which is permissionless, so the attacker can
   trigger it right after step 1.
3. Hold that validator's full weight in the next committee's certificates.

The validator key can take authority back (`:221-223`), but only by racing
the operator. A `start_reconfig` that lands first bakes the attacker's key
into the pending committee for a whole epoch. Nothing on-chain separates
routine operator actions (endpoint, TLS key) from key-material actions (BLS
key, encryption key, operator rotation).

**Recommendation:** document that the operator key is equivalent to the
validator key for Hashi signing. Optionally, restrict
`set_next_epoch_public_key`, `set_next_epoch_encryption_public_key` and
`set_operator_address` to the validator address only.

---

## R11 — `mpc_signing::record` accepts stale-epoch batches and drops conflicting signatures without a trace

**Severity:** Info (defence in depth). W10/W11 cover the write-once and
index-disjointness properties. This finding is about what `record` doesn't
check.

**Location:** `core/mpc_signing.move:104-121`, `btc/withdraw.move:201-219`

- **No epoch check.** `record` is deliberately epoch-agnostic (`:97-103`),
  and `commit_input_signatures` doesn't check `txn.signing.epoch()` against
  the current epoch either. The nonce-safety comment at `:26-28` says the
  caller must `reallocate` whenever `epoch` is stale, but nothing on-chain
  forces that before signatures are recorded. The node does enforce it: it
  refuses to sign a stale batch (`crates/hashi/src/withdrawals.rs:931-940`),
  and the leader reallocates first (`leader/withdrawal_transactions.rs:48-53`,
  `:276`). So this is a single off-chain guard, with no on-chain backstop.
- **No length check.** Signature bytes are stored without a length check. A
  BIP-340 signature is 64 bytes.
- **Silent drop.** If a slot is already `Signed`, a later cert-backed write
  with *different* bytes is dropped silently. First-writer-wins is intended.
  But two committee-certified signatures for the same input differing is
  exactly the event that indicates a signing fault, and it leaves no event
  or abort.

**Recommendation:**

- In `commit_input_signatures`, assert
  `txn.signing.epoch() == committee_set().epoch()`. This is cheap, and it
  makes the documented invariant enforceable.
- Assert 64-byte signatures.
- Emit an event when a `Signed` slot receives different bytes.

---

## R12 — `derivation_path = None` and `Some(@0x0)` give the same Bitcoin address but behave differently in Move

**Severity:** Info.

**Location:** `crates/hashi/src/deposits.rs:355-360`, `btc/deposit.move:234-240`

`normalized_derivation_path` maps both `None` and `Some(@0x0)` to
`Address::ZERO`, so both derive the pool's change address. Move treats them
differently:

- `None` adds the UTXO to the pool without minting.
- `Some(@0x0)` mints hBTC to `@0x0`, where nobody can spend it.

A third party can pay the change address and file a deposit with
`Some(@0x0)`. The node will approve it, since the address check passes. The
result is permanently unspendable hBTC with real BTC backing it. Solvency
holds, but `total_supply` then overstates circulating hBTC, which matters to
any supply-based monitor (R3).

Withdrawal change outputs can't be re-deposited this way. They are
`insert_pending`'d at commit (`withdraw.move:186-189`), so `deposit()`'s
`assert_not_spent_or_active` rejects them, and so does the node
(`deposits.rs:129-134`).

**Recommendation:** reject `derivation_path == Some(@0x0)` in `deposit()`.

---

## R13 — The node's fee-rate ceiling is 5×, not the documented 3×

**Severity:** Info.

**Location:** `crates/hashi/src/withdrawals.rs:46`, `:434-465`

PROTOCOL.md (Withdraw step 3) and `design/docs/fees.mdx` describe follower
validation as "within [1 sat/vB, 3× their own estimate]". The code uses
`FEE_RATE_TOLERANCE_MULTIPLIER = 5`, applied to
`max(own estimate, configured min) × weight`, plus the CPFP shortfall of
unconfirmed ancestors. The leader caps itself at
`DEFAULT_HIGH_FEE_RATE_THRESHOLD` (`:1148-1150`), but followers don't apply
that cap when validating. The per-user Move cap
`worst_case_network_fee = bitcoin_withdrawal_minimum − 546` still bounds
what any single user pays.

**Recommendation:** make the docs and the constant agree, and decide whether
followers should also enforce the leader's absolute ceiling.

---

## R14 — `MetadataCap` is held with no way to use it

**Severity:** Info.

**Location:** `core/treasury.move:47-49`, `:72-75`; `btc/btc.move:15-19`

`finish_publish` takes custody of `MetadataCap<BTC>`, but the only accessor,
`metadata_cap`, is private and `#[allow(unused_function)]`, and no proposal
type reaches it. The coin's name, description and icon URL are therefore
fixed forever, unless a package upgrade adds a path. In particular,
`ICON_URL` points at an external domain (`icons.hashi.sui.io`). If that domain
lapses, whoever takes it over controls the image wallets display for hBTC.

Separately, `NAME = "BTC"` (the symbol is `hBTC`) means wallets that show the
name, not the symbol, will show plain "BTC".

**Recommendation:** add a governance path for metadata updates, or accept
and document the immutability. Consider `NAME = "Hashi BTC"`.

---

## R15 — Bare `assert!`s outside the reconfig path

**Severity:** Info. GF9 covers the reconfig path. These are the rest:

| Location | Check |
|---|---|
| `committee.move:89` | non-empty committee |
| `committee.move:205` | `signature.epoch == self.epoch()`, the epoch pin every cert relies on (P6) |
| `committee_set.move:122` | sender is an active Sui validator |
| `committee_set.move:197`, `:211` | TLS and encryption key length |
| `committee_set.move:447` | `assert_authorized` |
| `committee_set.move:485-492` | proof-of-possession verification |
| `cert_submission.move:87`, `:89` | dealer authorized, epoch is current or pending |

Without error codes, off-chain classifiers can't tell these apart.
`reconfig.move:18-20` shows the node already matches aborts by name.
`committee.move:205` is the one worth fixing first, because a stale-epoch
cert is the most common legitimate failure.

---

## R16 — Dead code in security-relevant modules

**Severity:** Info.

- `committee::verify_proposal` (`committee.move:176-192`,
  `#[allow(unused_function)]`) is a second stake-summing verifier with
  different semantics: signer set, with no signature.
- `tob::submit_cert` (`tob.move:97-113`) duplicates
  `submit_cert_with_signature` and has no callers.
- `treasury::mint` returning `Coin<T>` (`treasury.move:51-54`) has no
  callers. Only `mint_balance` is used (`deposit.move:239`).

These are all `public(package)`, so an upgrade could call them. Removing
them keeps the mint and verification surfaces to one path each.

---

## R17 — No Move tests for proof of possession, bitmap edge cases, or the treasury

**Severity:** Info.

`packages/hashi/tests/` has no test that exercises:

- `verify_proof_of_possession` / `update_next_epoch_public_key`, positive or
  negative. This is the rogue-key defence for BLS aggregation.
- `verify_certificate`'s rejection paths: an over-long bitmap
  (`EInvalidBitmap`, `:216`), set bits past `n_members` (`:228`),
  insufficient stake (`ENotEnoughStake`, `:242`), and a wrong epoch (`:205`).
  Only `ESigVerification` is exercised (`withdraw_tests.move:170`).
- `treasury` mint/burn accounting, or `register_*_cap` being call-once.
- `tob::destroy_all` timing (`current_epoch >= epoch + 2`).

All of these are cheap FV targets as well. See the candidate rules below.

---

## Checked and found OK

**`committee::verify_certificate`** (`committee.move:198-274`):

- The epoch pin comes before the BLS check.
- The bitmap is bounded to `ceil(n/8)` bytes, and trailing bits past `n`
  must be zero.
- Each index maps to one member, so no double-counting is possible.
- `threshold >= 1` always holds: `new_committee` rejects empty committees
  and zero weights (`:89`, `:95`), so an empty bitmap can't pass.
- The preimage leads with the intent.
- A `return` inside the `do!` lambda returns from the lambda, not from the
  function, as intended.

**Proof of possession** (`committee_set.move:478-515`): the PoP is bound
to intent `0x0000`, the Sui epoch, the validator address and the key bytes.
No other verifier uses intent `0x0000`, so a PoP can't double as a
certificate. Keys are subgroup-checked by `g1_from_bytes`. The identity
point is the "unset" sentinel and is skipped when committees are built
(`:410`).

**Intent registry:** the Move constants (`intent.move:24-49`) match
`crates/hashi-types/src/intent.rs:31-56` exactly, and the Rust side pins
them in `intent_values_are_stable`. All 10 Move call sites use the intent
matching their message type (`deposit.move:164,216`,
`withdraw.move:101,138,213,251,268`, `reconfig.move:95,133`,
`committee_set.move:505`). `approve_deposit` and `confirm_deposit` share an
intent and a message on purpose: confirm re-verifies the stored cert (D5).

**Rust ↔ Move preimage layouts:** every committee-signed message matches
byte for byte:

- `DepositConfirmationMessage`
- `WithdrawalRequestApproval`, `WithdrawalTxCommitment`,
  `MpcInputSignaturesMessage`, `WithdrawalTxSigning`,
  `WithdrawalConfirmationMessage`
- `ReconfigCompletionMessage`
- the `CommitteeTransitionRequest` layout, including `Element<UncompressedG1>`
  as a length-prefixed `Vec<u8>`, `ConfigValue` variant order, and
  `mpc_config::pin` key order
- the proof of possession, where fastcrypto's fixed `[_; 48]` pubkey
  serialization has no length prefix

The Rust framing `bcs(&(intent, epoch, msg))` is a plain concatenation
(`crates/hashi-types/src/committee.rs:750-754`). Member order is read from
the on-chain `Committee`, never rebuilt from the validator set, so the
`VecMap::pop` order carries through. The one divergence is in *content*,
not layout: see R1.

**MPC params are read from the pinned committee config, not the global
config** (`mpc_except_signing.rs:195-205`, `:263-282`), so mid-epoch
governance changes don't affect an in-flight MPC. `from_onchain` rejects
protocol values other than 0 and 1, matching `mpc_config.move:43`.

**Presig counter:** `allocate_presigs` is monotonic. The only reset is in
`end_reconfig` (`reconfig.move:101`), and none happens in `abort_reconfig`,
so an aborted reconfig doesn't reuse indices. The node refuses to MPC-sign
a batch whose `signing.epoch` isn't current (`withdrawals.rs:931-940`).

**Treasury / hBTC:**

- The only mint site is `deposit.move:239` and the only burn is
  `withdraw.move:182`.
- The caps live in an `ObjectBag` whose `add` aborts on a duplicate key,
  so registration is call-once.
- `BTC` has no constructor, and `TreasuryCap<BTC>` never leaves the
  `Treasury`.
- `init` creates no cap before `finish_publish`, and
  `assert_not_reconfiguring` blocks `confirm_deposit` until a committee
  exists.

**`btc_config` floors:** `bitcoin_deposit_minimum >= 546` and
`bitcoin_withdrawal_minimum >= 547` are enforced in the readers, so
`worst_case_network_fee >= 1` holds for any stored value (as G11 notes).

**`bitcoin_state` user index:** `index_user_request` uses `Bag::add`, which
aborts on a duplicate. `unindex_user_request` is tolerant of absent entries
and cleans up empty bags.

**Node deposit approval** (`crates/hashi/src/deposits.rs:24-212`,
`btc_monitor/monitor.rs:855-1050`). Before signing, the node checks:

- The request's fields, including the whole `Utxo`, match on-chain state.
- The UTXO is neither active nor spent.
- The block hash is cross-checked against the kyoto light client.
- Confirmations are at least the on-chain threshold.
- The txid is recomputed from the block, and the vout exists and is still
  unspent.
- The amount matches exactly.
- The scriptPubKey equals `derive_deposit_address(G, guardian_pk, path)`.

**Node withdrawal commitment** (`crates/hashi/src/withdrawals.rs:240-479`):

- Duplicate request IDs and duplicate UTXOs are rejected.
- Every request must be approved.
- Every input must be pooled, unlocked, and have fewer than 25 unconfirmed
  ancestors.
- Each user output must equal `btc_amount − per_user_fee`, paid to the
  requested address, with `per_user_fee ≤ worst_case_network_fee`.
- Every change output must pay the pool's change address. Move doesn't check
  this, so the node is the only guard.
- The txid is independently rebuilt and compared, both here (`:468-476`)
  and again at signing (`:901-908`). This narrows fv_findings Issue 1's
  premise: a wrong `txid` needs a committee quorum running modified code, not
  a stale cache in one leader.

**Guardian signing path**
(`crates/hashi-guardian/src/withdraw_mode/standard_withdrawal.rs:65-131`):

- The cert is checked at ≥6667 bps under intent `0x0106`, with the epoch
  pinned and bitmap bounds checked.
- The committee is anchored at genesis by KP-signed state. After that it
  advances only through `update_committee`, which needs an
  outgoing-committee cert and a strictly higher epoch.
- The transaction is rebuilt inside the enclave. Prevout scripts are
  re-derived from the enclave key, `master_g` and the path. `SIGHASH_DEFAULT`
  commits to every input amount.
- Change (`Internal`) outputs can only pay a derived 2-of-2 address.
- The guardian signs only leaf 0 (`multi_a`). The recovery leaf has no
  guardian key in it, and the internal key is NUMS, so there is no key-path
  spend.
- The limiter lock is held until the S3 success log is durably written, and
  a failed write aborts the process, so no signature is released without a
  log.
- The proxy blocks all operator and provisioning RPCs
  (`hashi-guardian-proxy/src/forward.rs:101-134`).

---

## Candidate FV rules from this pass

These are cheap and self-contained. None of them touch the `Bag`/`ObjectBag`
aliasing gotchas in CLAUDE.md.

| Rule | Shape | Target |
|---|---|---|
| `verify_rejects_wrong_epoch` | assert: `verify_certificate` succeeded ⇒ `sig.epoch == committee.epoch` | `committee.move:205` |
| `verify_stake_meets_threshold` | assert: `result.stake_support >= threshold` | `:242` |
| `verify_bitmap_bounded` | assert: success ⇒ `bitmap.length() <= ceil(n/8)` | `:216` |
| `certificate_threshold_is_supermajority` | assert: `3 * certificate_threshold(w) > 2 * w` for `w ∈ [1, 10000]` | `threshold.move:28-30` |
| `allocate_presigs_disjoint` | assert: two calls return `[s1, s1+c1)` and `[s2, s2+c2)` with `s2 = s1 + c1` | `hashi.move:230-234` |
| `record_is_first_writer_wins` | assert: slot `i` signed before ⇒ bytes unchanged after `record` | `mpc_signing.move:104-121` |
| `treasury_cap_registered_once` | expect-unreachable: two `register_treasury_cap<BTC>` | `treasury.move:43-45` |
| `mpc_params_jointly_valid` | expect-reachable today (documents R6): `update_config` leaves `threshold_bps <= max_faulty_bps` | `update_config.move:56-67` |

BLS verification is a native call, so the rules that go through
`verify_certificate` need `bls12381_min_pk_verify` summarized as `nondet`.
With that summary, they check the arithmetic and bitmap logic only, not the
cryptography.
