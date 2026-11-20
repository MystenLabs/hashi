-- Copyright (c) Mysten Labs, Inc.
-- SPDX-License-Identifier: Apache-2.0
/-
Facts about the request that the handler builds from the wire request.
Lean checks this file. It needs no human review.

How it works:
- `loop_ok` is an induction rule for a Rust loop that returns.
- `check_output_addresses_ok` and `new_ok` show that `TxUTXOs::new` keeps the inputs,
  the order of the outputs, and each amount.
- `gross_outflow_ok` shows that `gross_outflow_amount` is the inputs minus the internal outputs.
- `wire_outflow_ok` is the result: the amount that the handler gives to the limiter is
  `wireOutflow` of the wire request.
-/
import WithdrawalSpec
import LimiterProof
open Aeneas Aeneas.Std Result
open hashi_guardian hashi_types
open core.result.Result.Insts (CoreOpsTry.branch CoreOpsTry_traitFromResidualResult.from_residual)

/-! ## The `?` operator, `expect`, and `push` -/

theorem branch_continue {α E : Type} {r : core.result.Result α E} {v : α}
    (h : CoreOpsTry.branch r = ok (.Continue v)) : r = .Ok v := by
  cases r <;> simp [CoreOpsTry.branch] at h
  rw [h]

/-- The `Err` branch of the `?` operator: the function returns an error. -/
theorem residual_err {α β E : Type} {r : core.result.Result α E}
    {residual : core.result.Result Never E} {result : core.result.Result β E}
    (hcf : CoreOpsTry.branch r = ok (.Break residual))
    (h : CoreOpsTry_traitFromResidualResult.from_residual β (core.convert.FromSame E) residual
      = ok result) :
    ∃ e, result = .Err e := by
  cases r with
  | Ok v => simp [CoreOpsTry.branch] at hcf
  | Err e =>
    simp [CoreOpsTry.branch] at hcf
    subst hcf
    simp [CoreOpsTry_traitFromResidualResult.from_residual] at h
    exact ⟨_, h.symm⟩

/-- The `Err` branch of the `?` operator: the function returns the error and state `g`. -/
theorem early_exit {α β E S : Type} {r : core.result.Result α E}
    {residual : core.result.Result Never E} {g g' : S} {result : core.result.Result β E}
    (hcf : CoreOpsTry.branch r = ok (.Break residual))
    (h : (do
      let r1 ← CoreOpsTry_traitFromResidualResult.from_residual β (core.convert.FromSame E) residual
      ok (r1, g)) = ok (result, g')) :
    (∃ e, r = .Err e) ∧ (∃ e, result = .Err e) ∧ g' = g := by
  cases r with
  | Ok v => simp [CoreOpsTry.branch] at hcf
  | Err e =>
    simp [CoreOpsTry.branch] at hcf
    subst hcf
    simp [CoreOpsTry_traitFromResidualResult.from_residual] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨⟨_, rfl⟩, ⟨_, rfl⟩, rfl⟩

theorem expect_ok {α E : Type} {inst : core.fmt.Debug E} {r : core.result.Result α E} {msg : Str}
    {v : α} (h : core.result.Result.expect inst r msg = ok v) : r = .Ok v := by
  cases r <;> simp [core.result.Result.expect] at h
  rw [h]

theorem push_ok {α : Type} {v v' : alloc.vec.Vec α} {x : α}
    (h : alloc.vec.Vec.push v x = ok v') : v'.val = v.val ++ [x] := by
  simp only [alloc.vec.Vec.push] at h
  split at h
  · simp at h
    rw [← h]
    simp
  · simp at h

/-- `map_err` keeps an `Ok` value. -/
theorem map_err_ok_inv {T E F O : Type} {inst : core.ops.function.FnOnce O E F}
    {r : core.result.Result T E} {f : O} {v : T}
    (h : core.result.Result.map_err inst r f = ok (.Ok v)) : r = .Ok v := by
  cases r with
  | Ok w => simp at h; rw [h]
  | Err e =>
    replace h := bind_eq_ok.mp h; obtain ⟨m, _, h⟩ := h
    simp at h

/-! ## Loops over a slice -/

/-- Induction rule for a loop that returns. `inv` holds at each step, and `measure` goes down. -/
theorem loop_ok {α β : Type} (body : α → Result (ControlFlow α β)) (measure : α → ℕ)
    (inv : α → Prop) (post : β → Prop)
    (hbody : ∀ x r, inv x → body x = ok r →
      match r with
      | .done y => post y
      | .cont x' => inv x' ∧ measure x' < measure x) :
    ∀ x y, inv x → loop body x = ok y → post y := by
  intro x
  induction hm : measure x using Nat.strong_induction_on generalizing x with
  | _ n ih =>
    intro y hinv hl
    unfold loop at hl
    replace hl := bind_eq_ok.mp hl; obtain ⟨r, hr, hl⟩ := hl
    have hb := hbody x r hinv hr
    cases r with
    | done z =>
      obtain rfl := ok_injective hl
      exact hb
    | cont x' => exact ih (measure x') (hm ▸ hb.2) x' rfl y hb.1 hl

/-- One `next` call on a slice iterator: the end, or the element at index `i`. -/
theorem iter_next {T : Type} {it it' : core.slice.iter.Iter T} {o : Option T}
    (h : core.slice.iter.IteratorSliceIter.next it = ok (o, it')) :
    it'.slice = it.slice ∧
    ((o = none ∧ it.slice.val.length ≤ it.i) ∨
     (∃ x, o = some x ∧ it'.i = it.i + 1 ∧ it.i < it.slice.val.length ∧
       it.slice.val.take (it.i + 1) = it.slice.val.take it.i ++ [x])) := by
  unfold core.slice.iter.IteratorSliceIter.next at h
  split at h
  · rename_i hlt
    simp at h
    obtain ⟨rfl, rfl⟩ := h
    have hlt' : it.i < it.slice.val.length := by simpa using hlt
    refine ⟨rfl, Or.inr ⟨_, rfl, rfl, hlt', ?_⟩⟩
    rw [List.take_add_one, List.getElem?_eq_getElem hlt']
    rfl
  · rename_i hlt
    simp at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, Or.inl ⟨rfl, by simpa using hlt⟩⟩

/-! ## `TxUTXOs::new` -/

/-- `checked` is the wire output `output` after the address check for `network`.
An internal output does not change. An external output keeps its amount. -/
def CheckedOutput (network : bitcoin.network.Network) :
    bitcoin.utxo.OutputUTXOWire → bitcoin.utxo.OutputUTXO → Prop
  | .Internal output, .Internal checked => checked = output
  | .External output, .External checked =>
    checked.amount = output.amount ∧
    bitcoin.utxo.validate_address_for_network output.address network = ok (.Ok checked.address)
  | _, _ => False

theorem check_output_address_ok {output : bitcoin.utxo.OutputUTXOWire}
    {network : bitcoin.network.Network} {checked : bitcoin.utxo.OutputUTXO}
    (h : bitcoin.utxo.check_output_address output network = ok (.Ok checked)) :
    CheckedOutput network output checked := by
  unfold bitcoin.utxo.check_output_address at h
  cases output with
  | External ext =>
    simp only at h
    replace h := bind_eq_ok.mp h; obtain ⟨r, hr, h⟩ := h
    replace h := bind_eq_ok.mp h; obtain ⟨cf, hcf, h⟩ := h
    split at h
    · obtain rfl := branch_continue hcf
      simp at h
      subst h
      exact ⟨rfl, hr⟩
    · obtain ⟨e, he⟩ := residual_err hcf h
      cases he
  | Internal int =>
    simp [bitcoin.utxo.InternalOutputUTXO.Insts.CoreCloneClone.clone,
      sui_sdk_types.address.Address.Insts.CoreCloneClone.clone,
      bitcoin_units.amount.Amount.Insts.CoreCloneClone.clone] at h
    subst h
    rfl

/-- `check_output_addresses` keeps the order of the outputs, and checks each of them. -/
theorem check_output_addresses_ok {outputs : Slice bitcoin.utxo.OutputUTXOWire}
    {network : bitcoin.network.Network} {checked : alloc.vec.Vec bitcoin.utxo.OutputUTXO}
    (h : bitcoin.utxo.check_output_addresses outputs network = ok (.Ok checked)) :
    List.Forall₂ (CheckedOutput network) outputs.val checked.val := by
  unfold bitcoin.utxo.check_output_addresses bitcoin.utxo.check_output_addresses_loop at h
  simp only [core.slice.Slice.iter, bind_ok] at h
  refine loop_ok _ (fun x => outputs.val.length - x.1.i)
    (fun x => x.1.slice = outputs ∧
      List.Forall₂ (CheckedOutput network) (outputs.val.take x.1.i) x.2.val)
    (fun r => ∀ v, r = .Ok v → List.Forall₂ (CheckedOutput network) outputs.val v.val)
    ?_ _ _ ?_ h checked rfl
  · rintro ⟨it, acc⟩ r ⟨hs, hacc⟩ hb
    simp only [bitcoin.utxo.check_output_addresses_loop.body] at hb
    replace hb := bind_eq_ok.mp hb; obtain ⟨⟨o, it1⟩, hnext, hb⟩ := hb
    obtain ⟨hs1, hcase⟩ := iter_next hnext
    simp only at hs
    rw [hs] at hs1 hcase
    rcases hcase with ⟨rfl, hlen⟩ | ⟨x, rfl, hi1, hlt, htake⟩
    · simp at hb
      subst hb
      intro v hv
      cases hv
      simpa [List.take_of_length_le hlen] using hacc
    · replace hb := bind_eq_ok.mp hb; obtain ⟨r1, hr1, hb⟩ := hb
      replace hb := bind_eq_ok.mp hb; obtain ⟨cf, hcf, hb⟩ := hb
      split at hb
      · obtain rfl := branch_continue hcf
        replace hb := bind_eq_ok.mp hb; obtain ⟨acc1, hpush, hb⟩ := hb
        obtain rfl := ok_injective hb
        refine ⟨⟨hs1, ?_⟩, by simp only; omega⟩
        simp only [hi1, htake, push_ok hpush]
        exact List.rel_append hacc (.cons (check_output_address_ok hr1) .nil)
      · replace hb := bind_eq_ok.mp hb; obtain ⟨r2, hr2, hb⟩ := hb
        obtain rfl := ok_injective hb
        obtain ⟨e, rfl⟩ := residual_err hcf hr2
        intro v hv
        cases hv
  · exact ⟨rfl, by simp [alloc.vec.Vec.with_capacity]⟩

/-- `TxUTXOs::new` keeps the inputs, the order of the outputs, and each amount. -/
theorem new_ok {inputs : alloc.vec.Vec bitcoin.utxo.InputUTXO}
    {outputs : alloc.vec.Vec bitcoin.utxo.OutputUTXOWire} {network : bitcoin.network.Network}
    {utxos : bitcoin.utxo.TxUTXOs}
    (h : bitcoin.utxo.TxUTXOs.new inputs outputs network = ok (.Ok utxos)) :
    utxos.inputs = inputs ∧
    List.Forall₂ (CheckedOutput network) outputs.val utxos.outputs.val := by
  unfold bitcoin.utxo.TxUTXOs.new at h
  replace h := bind_eq_ok.mp h; obtain ⟨b, _, h⟩ := h
  split at h
  · simp [bind_eq_ok] at h
  replace h := bind_eq_ok.mp h; obtain ⟨b1, _, h⟩ := h
  split at h
  · simp [bind_eq_ok] at h
  replace h := bind_eq_ok.mp h; obtain ⟨r, hr, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf, hcf, h⟩ := h
  split at h
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcf h
    cases he
  obtain rfl := branch_continue hcf
  replace h := bind_eq_ok.mp h; obtain ⟨r1, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf1, hcf1, h⟩ := h
  split at h
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcf1 h
    cases he
  replace h := bind_eq_ok.mp h; obtain ⟨r2, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf2, hcf2, h⟩ := h
  split at h
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcf2 h
    cases he
  replace h := bind_eq_ok.mp h; obtain ⟨r3, _, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf3, hcf3, h⟩ := h
  split at h
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcf3 h
    cases he
  simp at h
  subst h
  have hout := check_output_addresses_ok hr
  exact ⟨rfl, by simpa [alloc.vec.Vec.deref] using hout⟩

/-! ## `gross_outflow_amount` -/

/-- The amount of an internal output after the address check. -/
def checkedInternalAmount : bitcoin.utxo.OutputUTXO → Option ℕ
  | .Internal output => some output.amount.val
  | .External _ => none

/-- The address check keeps the internal amounts. -/
theorem internal_amounts_eq {network : bitcoin.network.Network}
    {wire : List bitcoin.utxo.OutputUTXOWire} {checked : List bitcoin.utxo.OutputUTXO}
    (h : List.Forall₂ (CheckedOutput network) wire checked) :
    checked.filterMap checkedInternalAmount = wire.filterMap internalAmount := by
  induction h with
  | nil => rfl
  | @cons w c ws cs hx _ ih =>
    cases w <;> cases c <;> simp only [CheckedOutput] at hx
    · simp [List.filterMap_cons, checkedInternalAmount, internalAmount, ih]
    · subst hx
      simp [checkedInternalAmount, internalAmount, ih]

/-- A checked addition that returns gives the exact sum. -/
theorem checked_add_expect {x y z : U64} {msg}
    (h : core.option.Option.expect (U64.checked_add x y) msg = ok z) :
    z.val = x.val + y.val := by
  have hs := U64.checked_add_bv_spec x y
  split at hs
  · rename_i w hw
    simp [hw, core.option.Option.expect, Result.ofOption] at h
    subst h
    omega
  · rename_i hw
    simp [hw, core.option.Option.expect, Result.ofOption] at h

theorem inputs_loop_ok {s : Slice bitcoin.utxo.InputUTXO} {total : U64}
    (h : bitcoin.utxo.TxUTXOs.gross_outflow_amount_loop0 ⟨s, 0⟩ 0#u64 = ok total) :
    total.val = (s.val.map (·.amount.val)).sum := by
  unfold bitcoin.utxo.TxUTXOs.gross_outflow_amount_loop0 at h
  refine loop_ok _ (fun x => s.val.length - x.1.i)
    (fun x => x.1.slice = s ∧ x.2.val = ((s.val.take x.1.i).map (·.amount.val)).sum)
    (fun r => r.val = (s.val.map (·.amount.val)).sum) ?_ _ _ ?_ h
  · rintro ⟨it, acc⟩ r ⟨hs, hacc⟩ hb
    simp only [bitcoin.utxo.TxUTXOs.gross_outflow_amount_loop0.body] at hb
    replace hb := bind_eq_ok.mp hb; obtain ⟨⟨o, it1⟩, hnext, hb⟩ := hb
    obtain ⟨hs1, hcase⟩ := iter_next hnext
    simp only at hs hacc
    rw [hs] at hs1 hcase
    rcases hcase with ⟨rfl, hlen⟩ | ⟨x, rfl, hi1, hlt, htake⟩
    · simp at hb
      subst hb
      simpa [List.take_of_length_le hlen] using hacc
    · simp only [bitcoin_units.amount.Amount.to_sat, bind_ok, lift] at hb
      replace hb := bind_eq_ok.mp hb; obtain ⟨acc1, hadd, hb⟩ := hb
      obtain rfl := ok_injective hb
      have := checked_add_expect hadd
      refine ⟨⟨hs1, ?_⟩, by simp only; omega⟩
      simp only [hi1, htake, List.map_append, List.sum_append, List.map_cons, List.map_nil,
        List.sum_cons, List.sum_nil]
      omega
  · exact ⟨rfl, by simp⟩

theorem internal_loop_ok {s : Slice bitcoin.utxo.OutputUTXO} {total : U64}
    (h : bitcoin.utxo.TxUTXOs.gross_outflow_amount_loop1 ⟨s, 0⟩ 0#u64 = ok total) :
    total.val = (s.val.filterMap checkedInternalAmount).sum := by
  unfold bitcoin.utxo.TxUTXOs.gross_outflow_amount_loop1 at h
  refine loop_ok _ (fun x => s.val.length - x.1.i)
    (fun x => x.1.slice = s ∧
      x.2.val = ((s.val.take x.1.i).filterMap checkedInternalAmount).sum)
    (fun r => r.val = (s.val.filterMap checkedInternalAmount).sum) ?_ _ _ ?_ h
  · rintro ⟨it, acc⟩ r ⟨hs, hacc⟩ hb
    simp only [bitcoin.utxo.TxUTXOs.gross_outflow_amount_loop1.body] at hb
    replace hb := bind_eq_ok.mp hb; obtain ⟨⟨o, it1⟩, hnext, hb⟩ := hb
    obtain ⟨hs1, hcase⟩ := iter_next hnext
    simp only at hs hacc
    rw [hs] at hs1 hcase
    rcases hcase with ⟨rfl, hlen⟩ | ⟨x, rfl, hi1, hlt, htake⟩
    · simp at hb
      subst hb
      simpa [List.take_of_length_le hlen] using hacc
    · cases x with
      | External ext =>
        simp at hb
        subst hb
        refine ⟨⟨hs1, ?_⟩, by simp only; omega⟩
        simp [hi1, htake, List.filterMap_append, List.filterMap_cons, checkedInternalAmount, hacc]
      | Internal int =>
        simp only [bitcoin_units.amount.Amount.to_sat, bind_ok, lift] at hb
        replace hb := bind_eq_ok.mp hb; obtain ⟨acc1, hadd, hb⟩ := hb
        obtain rfl := ok_injective hb
        have := checked_add_expect hadd
        refine ⟨⟨hs1, ?_⟩, by simp only; omega⟩
        simp [hi1, htake, List.filterMap_append, checkedInternalAmount]
        omega
  · exact ⟨rfl, by simp⟩

/-- `gross_outflow_amount` is the input amounts minus the internal output amounts. -/
theorem gross_outflow_ok {utxos : bitcoin.utxo.TxUTXOs} {amount : bitcoin_units.amount.Amount}
    (h : utxos.gross_outflow_amount = ok amount) :
    amount.val = (utxos.inputs.val.map (·.amount.val)).sum -
      (utxos.outputs.val.filterMap checkedInternalAmount).sum := by
  unfold bitcoin.utxo.TxUTXOs.gross_outflow_amount at h
  simp only [core.slice.Slice.iter, bind_ok, lift] at h
  replace h := bind_eq_ok.mp h; obtain ⟨inputs, hin, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨internal, hint, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨outflow, hexp, h⟩ := h
  have hin := inputs_loop_ok hin
  have hint := internal_loop_ok hint
  simp only [bitcoin_units.amount.Amount.from_sat] at h
  obtain rfl := ok_injective h
  have hsub := U64.checked_sub_bv_spec inputs internal
  split at hsub
  · rename_i z hz
    simp [hz, core.option.Option.expect, Result.ofOption] at hexp
    subst hexp
    simp only [alloc.vec.Vec.deref] at hin hint
    simp_all
  · rename_i hz
    simp [hz, core.option.Option.expect, Result.ofOption] at hexp

/-! ## The request of the handler -/

/-- The request that the handler gets from `wire`: the same fields, with checked outputs. -/
theorem validate_addr_ok {wire : guardian.SignedStandardWithdrawalRequestWire}
    {network : bitcoin.network.Network}
    {signed : committee.SignedMessage guardian.StandardWithdrawalRequest}
    (h : committee.SignedMessageStandardWithdrawalRequest.Insts.Hashi_typesGuardianAddressValidationSignedStandardWithdrawalRequestWire.validate_addr
      wire network = ok (.Ok signed)) :
    ∃ utxos,
      utxos.inputs = wire.data.utxos.inputs ∧
      List.Forall₂ (CheckedOutput network) wire.data.utxos.outputs.val utxos.outputs.val ∧
      signed.message =
        { wid := wire.data.wid, utxos, timestamp_secs := wire.data.timestamp_secs,
          seq := wire.data.seq } ∧
      committee.CommitteeSignature.from_bytes wire.signature.epoch
        (alloc.vec.Vec.deref wire.signature.signature)
        (alloc.vec.Vec.deref wire.signature.signers_bitmap) = ok (.Ok signed.signature) := by
  unfold committee.SignedMessageStandardWithdrawalRequest.Insts.Hashi_typesGuardianAddressValidationSignedStandardWithdrawalRequestWire.validate_addr at h
  replace h := bind_eq_ok.mp h; obtain ⟨r, hr, h⟩ := h
  replace h := bind_eq_ok.mp h; obtain ⟨cf, hcf, h⟩ := h
  split at h
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcf h
    cases he
  obtain rfl := branch_continue hcf
  replace h := bind_eq_ok.mp h; obtain ⟨r1, hnew, h⟩ := h
  obtain rfl := map_err_ok_inv h
  -- The request.
  unfold guardian.StandardWithdrawalRequest.Insts.Hashi_typesGuardianAddressValidationStandardWithdrawalRequestWire.validate_addr at hr
  replace hr := bind_eq_ok.mp hr; obtain ⟨ru, hru, hr⟩ := hr
  replace hr := bind_eq_ok.mp hr; obtain ⟨ru1, hmap, hr⟩ := hr
  replace hr := bind_eq_ok.mp hr; obtain ⟨cfu, hcfu, hr⟩ := hr
  split at hr
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcfu hr
    cases he
  obtain rfl := branch_continue hcfu
  obtain rfl := map_err_ok_inv hmap
  simp at hr
  subst hr
  obtain ⟨hin, hout⟩ := new_ok hru
  -- The committee signature.
  unfold committee.SignedMessage.new at hnew
  replace hnew := bind_eq_ok.mp hnew; obtain ⟨rs, hrs, hnew⟩ := hnew
  replace hnew := bind_eq_ok.mp hnew; obtain ⟨cfs, hcfs, hnew⟩ := hnew
  split at hnew
  rotate_left
  · obtain ⟨e, he⟩ := residual_err hcfs hnew
    cases he
  obtain rfl := branch_continue hcfs
  simp at hnew
  subst hnew
  exact ⟨_, hin, hout, rfl, hrs⟩

/-- The amount that the handler gives to the limiter is `wireOutflow` of the wire request. -/
theorem wire_outflow_ok {wire : guardian.SignedStandardWithdrawalRequestWire}
    {network : bitcoin.network.Network} {utxos : bitcoin.utxo.TxUTXOs} {amount : U64}
    (hin : utxos.inputs = wire.data.utxos.inputs)
    (hout : List.Forall₂ (CheckedOutput network) wire.data.utxos.outputs.val utxos.outputs.val)
    (h : utxos.gross_outflow_amount = ok amount) : amount.val = wireOutflow wire := by
  rw [gross_outflow_ok h, hin, internal_amounts_eq hout, wireOutflow]
