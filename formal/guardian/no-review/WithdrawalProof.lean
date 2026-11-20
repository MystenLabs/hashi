-- Copyright (c) Mysten Labs, Inc.
-- SPDX-License-Identifier: Apache-2.0
/-
The proof of the statement in `review/WithdrawalSpec.lean`.
Lean checks this file. It needs no human review.
The result is `withdrawal_outflow_bound`.
`AcceptedCallSigns` and its proof are a draft for the TODO in `review/WithdrawalSpec.lean`.
`handler_cases` also has facts about the log record, for a later theorem about restarts.
-/
import WithdrawalSpec
import LimiterProof
import RequestProof
open Aeneas Aeneas.Std Result
open hashi_guardian hashi_types guardian.limiter
open hashi_guardian.enclave (Enclave EnclaveState)
open hashi_guardian.withdraw_mode.standard_withdrawal (standard_withdrawal)
open core.result.Result.Insts (CoreOpsTry.branch CoreOpsTry_traitFromResidualResult.from_residual)

/-! ## The timestamp check -/

theorem skew_eq : withdraw_mode.standard_withdrawal.MAX_CLOCK_SKEW_SECS = ok 300#u64 := by
  unfold withdraw_mode.standard_withdrawal.MAX_CLOCK_SKEW_SECS; rfl

theorem age_eq : withdraw_mode.standard_withdrawal.MAX_REQUEST_AGE_SECS = ok 1800#u64 := by
  unfold withdraw_mode.standard_withdrawal.MAX_REQUEST_AGE_SECS; rfl

/-- An accepted timestamp is near the Guardian clock. -/
theorem validate_ok {ts now : U64}
    (h : withdraw_mode.standard_withdrawal.validate_request_timestamp ts now
      = ok (core.result.Result.Ok ())) :
    ts.val ≤ now.val + 300 ∧ now.val ≤ ts.val + 1800 := by
  unfold withdraw_mode.standard_withdrawal.validate_request_timestamp at h
  simp only [skew_eq, age_eq, bind_ok, lift] at h
  obtain ⟨i1, hi1, h⟩ := bind_eq_ok.mp h
  have hi1 := checked_add_expect hi1
  split at h
  · simp [bind_eq_ok] at h
  · rename_i h1
    split at h
    · simp [bind_eq_ok] at h
    · rename_i h2
      have hs := sat_sub_val now ts
      simp at h1 h2 hi1
      omega

/-! ## `consume_from_limiter` -/

/-- An accepted `consume_from_limiter` call is an accepted `consume` call on the limiter. -/
theorem consume_ok {s s' : EnclaveState} {seq ts amt : U64} {post : LimiterState}
    (h : s.consume_from_limiter seq ts amt = ok (.Ok post, s')) :
    ∃ l l', s.rate_limiter = some l ∧ l.consume seq ts amt = ok (.Ok (), l') ∧
      s'.rate_limiter = some l' ∧ post = l'.state := by
  simp only [EnclaveState.consume_from_limiter] at h
  split at h
  · obtain ⟨_, _, h⟩ := bind_eq_ok.mp h
    simp at h
  · rename_i l hl
    obtain ⟨⟨r0, l'⟩, h0, h⟩ := bind_eq_ok.mp h
    cases r0 with
    | Ok u =>
      cases u
      simp [CoreOpsTry.branch, RateLimiter.impl.state] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨l, l', hl, h0, rfl, rfl⟩
    | Err e =>
      simp [CoreOpsTry.branch, CoreOpsTry_traitFromResidualResult.from_residual] at h

/-- A rejected `consume_from_limiter` call keeps the limiter. -/
theorem consume_err {s s' : EnclaveState} {seq ts amt : U64} {e : guardian.errors.GuardianError}
    (h : s.consume_from_limiter seq ts amt = ok (.Err e, s')) :
    s'.rate_limiter = s.rate_limiter := by
  simp only [EnclaveState.consume_from_limiter] at h
  split at h
  · obtain ⟨_, _, h⟩ := bind_eq_ok.mp h
    simp at h
    obtain ⟨_, rfl⟩ := h
    rfl
  · rename_i l hl
    obtain ⟨⟨r0, l'⟩, h0, h⟩ := bind_eq_ok.mp h
    cases r0 with
    | Ok u => simp [CoreOpsTry.branch, RateLimiter.impl.state] at h
    | Err e' =>
      simp [CoreOpsTry.branch, CoreOpsTry_traitFromResidualResult.from_residual] at h
      obtain ⟨_, rfl⟩ := h
      rcases consume_step h0 with ⟨_, rfl⟩ | ⟨hr, _⟩
      · exact hl.symm
      · cases hr

/-! ## One call to the handler -/

/-- The trait instance that `Enclave::sign` uses for a withdrawal response. -/
noncomputable abbrev responseIntent :=
  guardian.crypto.signing.GuardianResponseStandardWithdrawalResponse.Insts.Hashi_typesGuardianCryptoSigningGuardianSigningIntent

/-- The Rust conversion `From<StandardWithdrawalRequest> for StandardWithdrawalRequestWire`. -/
noncomputable abbrev requestToWire :=
  guardian.StandardWithdrawalRequestWire.Insts.CoreConvertFromStandardWithdrawalRequest.from

/-- The three ways in which one call to the handler can end. -/
theorem handler_cases {g g' : Enclave} {wire : guardian.SignedStandardWithdrawalRequestWire}
    {now : U64} {result : core.result.Result _ guardian.errors.GuardianError}
    (h : standard_withdrawal g wire now = ok (result, g')) :
    -- 1. A check before the limiter rejects the call. The enclave does not change.
    ((∃ e, result = .Err e) ∧ g' = g) ∨
    ∃ network utxos sig amount seq ts r es,
      g.config.bitcoin_network = ok (.Ok network) ∧
      utxos.inputs = wire.data.utxos.inputs ∧
      List.Forall₂ (CheckedOutput network) wire.data.utxos.outputs.val utxos.outputs.val ∧
      committee.CommitteeSignature.from_bytes wire.signature.epoch
        (alloc.vec.Vec.deref wire.signature.signature)
        (alloc.vec.Vec.deref wire.signature.signers_bitmap) = ok (.Ok sig) ∧
      amount.val = wireOutflow wire ∧
      ts.val ≤ now.val + 300 ∧ now.val ≤ ts.val + 1800 ∧
      g.state.consume_from_limiter seq ts amount = ok (r, es) ∧
      -- 2. The limiter rejects the call. Only the enclave state changes.
      ((∃ e, r = .Err e) ∧ (∃ e, result = .Err e) ∧ g' = { g with state := es } ∨
      -- 3. The limiter accepts the call. The handler signs, logs, and returns the response.
       ∃ post signatures record response log,
        r = .Ok post ∧ result = .Ok response ∧
        record.post_state = post ∧ record.request_sign = sig ∧
        requestToWire
          { wid := wire.data.wid, utxos, timestamp_secs := wire.data.timestamp_secs,
            seq := wire.data.seq } = ok record.request_data ∧
        g.config.btc_sign utxos = ok (.Ok (record.txid, signatures)) ∧
        guardian.StandardWithdrawalResponse.Insts.CoreCloneClone.clone
          { enclave_signatures := signatures } = ok record.response ∧
        log.val = g.mock_withdrawal_log.val ++ [record] ∧
        g' = { g with state := es, mock_withdrawal_log := log } ∧
        g'.sign responseIntent { enclave_signatures := signatures } = ok response) := by
  unfold standard_withdrawal at h
  -- The checks before the limiter. Each `split` gives the `Ok` goal and the `Err` goal.
  replace h := bind_eq_ok.mp h; obtain ⟨rnet, hnet, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf, hcf, h⟩ := h
  split at h
  rotate_left
  · exact Or.inl (early_exit hcf h).2
  obtain rfl := branch_continue hcf
  replace h := bind_eq_ok.mp h; obtain ⟨rval, hval, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf1, hcf1, h⟩ := h
  split at h
  rotate_left
  · exact Or.inl (early_exit hcf1 h).2
  obtain rfl := branch_continue hcf1
  obtain ⟨utxos, hin, hout, hmsg, hsig⟩ := validate_addr_ok hval
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf2, hcf2, h⟩ := h
  split at h
  rotate_left
  · exact Or.inl (early_exit hcf2 h).2
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf3, hcf3, h⟩ := h
  split at h
  rotate_left
  · exact Or.inl (early_exit hcf3 h).2
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf4, hcf4, h⟩ := h
  split at h
  rotate_left
  · exact Or.inl (early_exit hcf4 h).2
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf5, hcf5, h⟩ := h
  split at h
  rotate_left
  · exact Or.inl (early_exit hcf5 h).2
  -- The request and the timestamp check.
  replace h := bind_eq_ok.mp h; obtain ⟨⟨sign, request⟩, hparts, h⟩ := h
  simp only [committee.SignedMessage.into_parts] at hparts
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj (ok_injective hparts)
  replace h := bind_eq_ok.mp h; obtain ⟨ts, hts, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨rts, hvalidate, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf6, hcf6, h⟩ := h
  split at h
  rotate_left
  · exact Or.inl (early_exit hcf6 h).2
  obtain rfl := branch_continue hcf6
  obtain ⟨hskew, hage⟩ := validate_ok hvalidate
  -- The limiter call.
  have hrutxos := congrArg (·.utxos) hmsg
  simp only at hrutxos
  replace h := bind_eq_ok.mp h; obtain ⟨tu0, hutxos0, h⟩ := h
  simp only [guardian.StandardWithdrawalRequest.impl.utxos, hrutxos] at hutxos0
  obtain rfl := ok_injective hutxos0
  replace h := bind_eq_ok.mp h; obtain ⟨gross, hgross, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨amount, hamount, h⟩ := h
  simp only [bitcoin_units.amount.Amount.to_sat] at hamount
  obtain rfl := ok_injective hamount
  replace h := bind_eq_ok.mp h; obtain ⟨seq, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨⟨r, es⟩, hconsume, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf7, hcf7, h⟩ := h
  refine Or.inr ⟨_, utxos, _, gross, seq, ts, r, es, hnet, hin, hout, hsig,
    wire_outflow_ok hin hout hgross, hskew, hage, hconsume, ?_⟩
  split at h
  rotate_left
  · exact Or.inl (early_exit hcf7 h)
  -- The limiter accepted the call.
  obtain rfl := branch_continue hcf7
  replace h := bind_eq_ok.mp h; obtain ⟨rsign, hsign, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨⟨txid, signatures⟩, hexpect, h⟩ := h
  obtain rfl := expect_ok hexpect
  replace h := bind_eq_ok.mp h; obtain ⟨data, hdata, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨logged, hclone, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨⟨rlog, g1⟩, hlog, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨response, hresponse, h⟩ := h
  simp at h
  obtain ⟨rfl, rfl⟩ := h
  simp only [Enclave.log_withdraw] at hlog
  obtain ⟨log, hpush, hlog⟩ := bind_eq_ok.mp hlog
  simp at hlog
  obtain ⟨_, rfl⟩ := hlog
  rw [hmsg] at hdata
  exact Or.inr ⟨_, signatures, _, response, log, rfl, rfl, rfl, rfl, hdata, hsign,
    hclone, push_ok hpush, rfl, hresponse⟩

/-! ## What an accepted call signs -/

theorem ok_or_ok {α E : Type} {o : Option α} {e : E} {v : α}
    (h : core.option.Option.ok_or o e = ok (.Ok v)) : o = some v := by
  cases o <;> simp [core.option.Option.ok_or] at h
  rw [h]

/-- An accepted `btc_sign` call: the keys, the sighash messages, and the signer call. -/
theorem btc_sign_ok {config : enclave.EnclaveConfig} {utxos : bitcoin.utxo.TxUTXOs}
    {txid : bitcoin.blockdata.transaction.Txid}
    {signatures : alloc.vec.Vec bitcoin.crypto.taproot.Signature}
    (h : config.btc_sign utxos = ok (.Ok (txid, signatures))) :
    ∃ keypair pubkey parity masterKey messages,
      init_once.InitOnce.get config.enclave_btc_keypair = ok (some keypair) ∧
      secp256k1_1.key.Keypair.x_only_public_key keypair = ok (pubkey, parity) ∧
      init_once.InitOnce.get config.hashi_btc_master_pubkey = ok (some masterKey) ∧
      utxos.signing_messages_and_txid pubkey masterKey = ok (messages, txid) ∧
      bitcoin.utxo.sign_btc_tx (alloc.vec.Vec.deref messages) keypair = ok signatures := by
  unfold enclave.EnclaveConfig.btc_sign at h
  replace h := bind_eq_ok.mp h; obtain ⟨o, ho, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨r, hr, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf, hcf, h⟩ := h
  split at h
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcf h
    cases he
  obtain rfl := branch_continue hcf
  obtain rfl := ok_or_ok hr
  replace h := bind_eq_ok.mp h; obtain ⟨o1, ho1, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨_, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨r1, hr1, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf1, hcf1, h⟩ := h
  split at h
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcf1 h
    cases he
  obtain rfl := branch_continue hcf1
  obtain rfl := ok_or_ok hr1
  replace h := bind_eq_ok.mp h; obtain ⟨⟨pubkey, parity⟩, hpk, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨⟨messages, txid'⟩, hmsgs, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨v, hv, h⟩ := h
  simp at h
  obtain ⟨rfl, rfl⟩ := h
  exact ⟨_, pubkey, parity, _, messages, ho, hpk, ho1, hmsgs, hv⟩

/-- Draft for the TODO in `review/WithdrawalSpec.lean`: what an accepted call signs.

The signatures in the response are the output of `sign_btc_tx` for one transaction:
- `utxos` has the inputs of `wire`, and the outputs of `wire` in the same order,
  each after the address check.
- `messages` is the output of `signing_messages_and_txid` for `utxos`.
- `keypair` is the BTC key of the enclave. -/
noncomputable def AcceptedCallSigns : Prop :=
  ∀ (enclave next : Enclave) (wire : guardian.SignedStandardWithdrawalRequestWire) (now : U64)
    response,
    standard_withdrawal enclave wire now = ok (.Ok response, next) →
    ∃ network, ∃ utxos : bitcoin.utxo.TxUTXOs,
    ∃ keypair pubkey parity masterKey messages txid signatures,
      enclave.config.bitcoin_network = ok (.Ok network) ∧
      utxos.inputs = wire.data.utxos.inputs ∧
      List.Forall₂ (CheckedOutput network) wire.data.utxos.outputs.val utxos.outputs.val ∧
      init_once.InitOnce.get enclave.config.enclave_btc_keypair = ok (some keypair) ∧
      secp256k1_1.key.Keypair.x_only_public_key keypair = ok (pubkey, parity) ∧
      init_once.InitOnce.get enclave.config.hashi_btc_master_pubkey = ok (some masterKey) ∧
      utxos.signing_messages_and_txid pubkey masterKey = ok (messages, txid) ∧
      bitcoin.utxo.sign_btc_tx (alloc.vec.Vec.deref messages) keypair = ok signatures ∧
      next.sign responseIntent { enclave_signatures := signatures } = ok response

theorem accepted_call_signs : AcceptedCallSigns := by
  intro g g' wire now response h
  rcases handler_cases h with ⟨⟨e, he⟩, _⟩ |
    ⟨network, utxos, _, _, _, _, r, es, hnet, hin, hout, _, _, _, _, _, hcase⟩
  · cases he
  rcases hcase with ⟨_, ⟨e, he⟩, _⟩ |
    ⟨post, signatures, record, response', log, _, hresp, _, _, _, hsign, _, _, _, hresponse⟩
  · cases he
  obtain rfl := core.result.Result.Ok.inj hresp
  obtain ⟨keypair, pubkey, parity, masterKey, messages, hkp, hpk, hmk, hmsgs, hsigs⟩ :=
    btc_sign_ok hsign
  exact ⟨network, utxos, keypair, pubkey, parity, masterKey, messages, _, signatures, hnet, hin,
    hout, hkp, hpk, hmk, hmsgs, hsigs, hresponse⟩

/-! ## The outflow bound -/

/-- With no limiter, the handler rejects the call and installs no limiter. -/
theorem step_none {g g' : Enclave} {wire : guardian.SignedStandardWithdrawalRequestWire}
    {now : U64} {result : core.result.Result _ guardian.errors.GuardianError}
    (hl : g.state.rate_limiter = none) (h : standard_withdrawal g wire now = ok (result, g')) :
    (∃ e, result = .Err e) ∧ g'.state.rate_limiter = none := by
  rcases handler_cases h with ⟨he, rfl⟩ |
    ⟨_, _, _, _, _, _, r, es, _, _, _, _, _, _, _, hconsume, hcase⟩
  · exact ⟨he, hl⟩
  rcases hcase with ⟨⟨e, rfl⟩, he, rfl⟩ | ⟨post, _, _, _, _, rfl, _⟩
  · exact ⟨he, (consume_err hconsume).trans hl⟩
  · obtain ⟨l, _, hl', _⟩ := consume_ok hconsume
    rw [hl] at hl'; cases hl'

/-- With limiter `l`, one call keeps the run invariant. An accepted call adds its outflow. -/
theorem step_some {l0 l : RateLimiter} {a b spent : ℕ} {g g' : Enclave}
    {wire : guardian.SignedStandardWithdrawalRequestWire} {now : U64}
    {result : core.result.Result _ guardian.errors.GuardianError}
    (hnow : a ≤ now.val ∧ now.val ≤ b) (hl : g.state.rate_limiter = some l)
    (hinv : RunInv l0 a b l spent) (h : standard_withdrawal g wire now = ok (result, g')) :
    match result with
    | .Err _ => ∃ l', g'.state.rate_limiter = some l' ∧ RunInv l0 a b l' spent
    | .Ok _ => ∃ l', g'.state.rate_limiter = some l' ∧
        RunInv l0 a b l' (spent + wireOutflow wire) := by
  rcases handler_cases h with ⟨⟨e, rfl⟩, rfl⟩ |
    ⟨_, _, _, amount, _, _, r, es, _, _, _, _, hamount, hskew, hage, hconsume, hcase⟩
  · exact ⟨l, hl, hinv⟩
  rcases hcase with ⟨⟨e, rfl⟩, ⟨e', rfl⟩, rfl⟩ | ⟨post, _, _, _, _, rfl, rfl, _, _, _, _, _, _, rfl, _⟩
  · exact ⟨l, (consume_err hconsume).trans hl, hinv⟩
  · obtain ⟨l1, l', hl1, hat, hl', _⟩ := consume_ok hconsume
    rw [hl] at hl1; cases hl1
    rw [← hamount]
    exact ⟨l', hl', runInv_accept hnow hskew hage hinv hat⟩

/-- The loop of `applyRequests` as a recursive function, from any `signedOut` value. -/
noncomputable def runRequests (g : Enclave) (signedOut : ℕ) : List Request → Result (Enclave × ℕ)
  | [] => ok (g, signedOut)
  | r :: rest => do
    let (result, next) ← standard_withdrawal g r.wire r.now
    match result with
    | .Ok _ => runRequests next (signedOut + wireOutflow r.wire) rest
    | .Err _ => runRequests next signedOut rest

theorem applyRequests_eq (g : Enclave) (requests : List Request) :
    applyRequests g requests = runRequests g 0 requests := by
  unfold applyRequests
  generalize (0 : ℕ) = signedOut
  induction requests generalizing g signedOut with
  | nil => simp [runRequests]; rfl
  | cons r rest ih =>
    simp only [List.forIn_cons, runRequests, bind_assoc]
    show Std.bind _ _ = Std.bind _ _
    congr 1
    funext ⟨result, next⟩
    cases result with
    | Ok response => simpa using ih next (signedOut + wireOutflow r.wire)
    | Err e => simpa using ih next signedOut

theorem run_none (requests : List Request) :
    ∀ {g final : Enclave} {signedOut : ℕ}, g.state.rate_limiter = none →
      runRequests g 0 requests = ok (final, signedOut) → signedOut = 0 := by
  induction requests with
  | nil =>
    intro g final signedOut _ h
    obtain ⟨_, rfl⟩ := Prod.mk.inj (ok_injective h)
    rfl
  | cons r rest ih =>
    intro g final signedOut hl h
    rw [runRequests] at h
    obtain ⟨⟨result, next⟩, h1, h2⟩ := bind_eq_ok.mp h
    obtain ⟨⟨e, rfl⟩, hnext⟩ := step_none hl h1
    exact ih hnext h2

theorem run_some {l0 : RateLimiter} {a b : ℕ} (requests : List Request) :
    ∀ {g final : Enclave} {l : RateLimiter} {spent signedOut : ℕ},
      (∀ r ∈ requests, a ≤ r.now.val ∧ r.now.val ≤ b) → g.state.rate_limiter = some l →
      RunInv l0 a b l spent → runRequests g spent requests = ok (final, signedOut) →
      ∃ l', RunInv l0 a b l' signedOut := by
  induction requests with
  | nil =>
    intro g final l spent signedOut _ _ hinv h
    obtain ⟨_, rfl⟩ := Prod.mk.inj (ok_injective h)
    exact ⟨l, hinv⟩
  | cons r rest ih =>
    intro g final l spent signedOut hclock hl hinv h
    obtain ⟨hnow, hrest⟩ := List.forall_mem_cons.mp hclock
    rw [runRequests] at h
    obtain ⟨⟨result, next⟩, h1, h2⟩ := bind_eq_ok.mp h
    have hstep := step_some hnow hl hinv h1
    cases result with
    | Err e =>
      obtain ⟨l', hl', hinv'⟩ := hstep
      exact ih hrest hl' hinv' h2
    | Ok response =>
      obtain ⟨l', hl', hinv'⟩ := hstep
      exact ih hrest hl' hinv' h2

/-- The result. `WithdrawalOutflowBound` is the statement in `WithdrawalSpec.lean`. -/
theorem withdrawal_outflow_bound : WithdrawalOutflowBound := by
  intro initial final requests a b signedOut hclock hrun
  rw [applyRequests_eq] at hrun
  split
  · next hl => exact run_none requests hl hrun
  · next l hl =>
    obtain ⟨l', hinv⟩ := run_some (l0 := l) requests hclock hl ⟨rfl, Or.inl rfl⟩ hrun
    exact runInv_bound hinv

#print axioms withdrawal_outflow_bound
#print axioms accepted_call_signs
