-- Copyright (c) Mysten Labs, Inc.
-- SPDX-License-Identifier: Apache-2.0
/-
The statement that Lean proves about the Guardian withdrawal handler.

Why it exists:
This file is the claim of the proof. A wrong statement makes the proof worthless, so read each line.
The other files that need a review are in this folder: `sync-copy.patch` and `extract.sh`.

How it works:
1. `extract.sh` copies the workspace and applies `sync-copy.patch` to the copy.
   The patch makes a sync copy of the handler.
2. Charon and Aeneas translate the copy to `no-review/HashiGuardian.lean`.
3. This file states `WithdrawalOutflowBound` about the translated handler.
4. `no-review/WithdrawalProof.lean` proves the statement. Lean checks that proof.

Reading notes:
- `U64` is a Rust `u64`. `x.val` is its value as a natural number, with no overflow.
- `Result` is the Aeneas type for a Rust computation. `ok v` means "returned `v`, no panic".
- `standard_withdrawal enclave wire now` returns the Rust result and the enclave after the call.
  The Rust result is `.Ok response` for an accepted call, and `.Err e` for a rejected call.
- `wire` is the request that the handler gets, before each check of the handler.
  It is the decoded Rust value, not the bytes on the network.

Assumptions:
- The sync copy has the same behaviour as the `async` handler. The reasons:
  - `run_rpc` in `service.rs` runs each handler from start to end with the enclave lock.
  - The removed `tracing` lines have no effect on the result of the handler.
  - `LogWriter::write` stops the enclave if an S3 write fails.
    `log_withdraw` returns an error only if the S3 logger is not set. The handler then panics.
    The copy has a list in the enclave in place of the S3 log. The list accepts each record.
    Thus the copy can accept a call where the handler stops after the debit.
    Such a call can put its signatures in S3 before the stop. The copy counts its outflow.
    Thus this difference is safe for the outflow bound.
- A Rust function with no body in `HashiGuardian.lean` has no effect other than its
  return value. For example, `sign_btc_tx` does not change the limiter.
  Random data and clock reads are part of the return value. The proof does not compare
  two return values.
- A panic stops the Guardian process. `abort_on_panic` in `main.rs` does this.
- `wireOutflow` is the BTC that leaves the pool. The statement does not show this.
  It needs three facts:
  - The Guardian signs only the transaction of an accepted request: the transaction with the
    inputs and outputs of that request. See the TODO below.
    Read the handler, `EnclaveConfig::btc_sign`, `signing_messages_and_txid`, and `sign_btc_tx`.
    The handler is the only caller of `btc_sign`, and the BTC key is a private field.
  - The input amounts in a request are the on-chain amounts.
    A Taproot signature is valid only for the input amounts that the signer used.
  - An internal output goes back to the pool.
    `OutputUTXO::to_txout` gives each internal output a script that needs the enclave key.

Scope notes:
- The statement holds for each function in the place of a function with no body.
  `verify_hashi_cert` is one of them, because `extract.sh` removes its body.
  Thus the bound also holds for a flawed verify_hashi_cert that accepts every request.
- The statement is about calls to `standard_withdrawal` only. It does not include the
  other handlers, which can change the enclave between two calls.
- The statement is about one enclave session, and about one live enclave with the BTC key.
  A new session has a new limiter.
- The statement is about the signatures of the Guardian only. After
  `HASHI_MPC_RECOVERY_DELAY_SECONDS`, the committee key can spend a pool UTXO alone.
- `a` and `b` bound the Guardian clock readings, not real time.
- The statement is about a run with no panic. For a run with a panic, it applies to the
  calls before the panic. A call that does not return is the same case.
  The statement does not count the call that panics. That call gives no response, but its
  signatures are in S3 if the panic comes after the log write.
  An integer overflow in the translated code is a panic, in the model and in the binary.
  Each addition is checked or saturating, and the one subtraction comes after a check.

TODO, the signed transaction:
- Goal: a second statement in this file. An accepted call signs only the sighash of one
  transaction. That transaction has the inputs of `wire`, and the outputs of `wire` in the
  same order with the same amounts. Each internal output has a pool script.
- Work: translate the Hashi code that builds the transaction. The functions are
  `signing_messages_and_txid`, `unsigned_tx`, `compute_all_outputs`, `construct_tx`,
  `InputUTXO::txin`, and `OutputUTXO::to_txout`.
  Some of them use iterator chains, so they need plain loops first.
- Start: `no-review/WithdrawalProof.lean` has a draft, `AcceptedCallSigns`. Lean checks it.
  It shows that the handler gives the UTXOs of `wire` and the enclave BTC key to
  `signing_messages_and_txid` and `sign_btc_tx`. It does not look inside the two functions.
- Not in the extent of this work, so these facts stay as assumptions:
  - The `bitcoin` and `miniscript` crates, and the key derivation in `fastcrypto`:
    the Taproot sighash, the scripts, and the txid.
    That code is large, and it uses Rust features that Aeneas cannot translate.
  - The Schnorr signer. It is C code in `libsecp256k1`, and Charon reads only Rust.
  - A person cannot make a valid Schnorr signature without the key.
  - The Bitcoin rules: a valid transaction moves exactly the amounts of its inputs and outputs.

TODO, no panic from a request:
- Goal: a statement in this file. No request makes `standard_withdrawal` panic, from each
  enclave and clock value with these properties:
  - The enclave has the BTC keys and the S3 logger.
  - `next_seq` of the limiter is less than `u64::MAX`.
  - The clock value is at most `u64::MAX - MAX_CLOCK_SKEW_SECS`.
  - The list `mock_withdrawal_log` is not full. Only the sync copy has this list.
- Value: a panic stops the enclave. The statement shows that a request cannot cause one.
  It also shows that the three `expect` calls in `gross_outflow_amount` cannot fail
  after the checks.
- Work: translate `assert_positive_fees`, which `TxUTXOs::new` calls.
  It uses iterator chains, so it needs plain loops first.
- Not in the extent of this work: a panic in a function with no body.
  The assumption that each such function returns stays.
-/
import HashiGuardian
open Aeneas Aeneas.Std Result
open hashi_guardian hashi_types guardian.limiter
open hashi_guardian.enclave (Enclave)
open hashi_guardian.withdraw_mode.standard_withdrawal (standard_withdrawal)

noncomputable section

/-- One call to `standard_withdrawal`. -/
structure Request where
  /-- Guardian clock at the call, in seconds. -/
  now : U64
  /-- The request with the signature of the Hashi committee. -/
  wire : guardian.SignedStandardWithdrawalRequestWire

/-- The amount of an internal output, in sats. An external output gives `none`.
An internal output is change. It goes back to the pool. -/
def internalAmount : bitcoin.utxo.OutputUTXOWire → Option ℕ
  | .Internal output => some output.amount.val
  | .External _ => none

/-- The outflow of a request, in sats: the input amounts minus the internal output amounts.
This is the amount that leaves the pool: the external outputs plus the miner fee.
The definition reads the request as the caller sends it. It uses no Rust function.
Subtraction of natural numbers stops at 0. This has no effect on an accepted call:
the handler stops if the internal outputs are more than the inputs. -/
def wireOutflow (wire : guardian.SignedStandardWithdrawalRequestWire) : ℕ :=
  (wire.data.utxos.inputs.val.map (·.amount.val)).sum -
    (wire.data.utxos.outputs.val.filterMap internalAmount).sum

-- Aeneas replaces the `do` notation with a form that has no loops.
-- This option selects the standard Lean `do` notation for the next definition.
set_option Aeneas.customDoElab false in
/-- Make the calls in order, from enclave `initial`.
Return the last enclave and `signedOut`, the total outflow of the accepted calls. -/
def applyRequests (initial : Enclave) (requests : List Request) : Result (Enclave × ℕ) := do
  let mut enclave := initial
  let mut signedOut : ℕ := 0
  for r in requests do
    let (result, next) ← standard_withdrawal enclave r.wire r.now
    match result with
    | .Ok _ => signedOut := signedOut + wireOutflow r.wire
    | .Err _ => pure ()
    enclave := next
  return (enclave, signedOut)

/-- Outflow bound for the handler.

Start from any enclave `initial`. Make any list of calls to `standard_withdrawal`.
If each Guardian clock value is in `[a, b]`, then:
- With no limiter in `initial`, the outflow of the accepted calls is 0.
- With limiter `l` in `initial`, the outflow of the accepted calls is at most the bucket
  capacity plus the refill for `b - a + 2100` seconds.

Note that we do not assume time monotonically increases between requests.
-/
def WithdrawalOutflowBound : Prop :=
  ∀ (initial final : Enclave) (requests : List Request) (a b signedOut : ℕ),
    (∀ r ∈ requests, a ≤ r.now.val ∧ r.now.val ≤ b) →
    applyRequests initial requests = ok (final, signedOut) →
    match initial.state.rate_limiter with
    | none => signedOut = 0
    | some l =>
      signedOut ≤ l.config.max_bucket_capacity.val + (b - a + 2100) * l.config.refill_rate.val

end
