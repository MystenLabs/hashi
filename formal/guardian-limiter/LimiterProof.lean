-- Copyright (c) Mysten Labs, Inc.
-- SPDX-License-Identifier: Apache-2.0
/-
The proof of `OutflowBound` from `LimiterSpec.lean`.
Lean checks this file. It needs no human review.
The last theorem, `outflow_bound`, is the result.
-/
import LimiterSpec
open Aeneas Aeneas.Std Result
open hashi_types guardian.limiter

theorem bind_eq_ok {α β} {m : Result α} {f : α → Result β} {v : β} :
    Std.bind m f = ok v ↔ ∃ a, m = ok a ∧ f a = ok v := by
  constructor
  · intro h
    induction m using Result.cases with
    | ret a => exact ⟨a, rfl, by simpa using h⟩
    | vis i k => have := congrArg Result.match h; simp at this
    | div => have := congrArg Result.match h; simp at this
  · rintro ⟨a, rfl, h⟩
    simpa using h

theorem add_eq_ok {x y z : U64} (h : x + y = ok z) : z.val = x.val + y.val := by
  have := UScalar.add_equiv x y
  rw [h] at this
  simp at this
  omega

theorem sub_eq_ok {x y z : U64} (h : x - y = ok z) : z.val + y.val = x.val := by
  have := UScalar.sub_equiv x y
  rw [h] at this
  simp at this
  omega

theorem toNat_ofNat_u64 (n : ℕ) (h : n ≤ U64.max) :
    (BitVec.ofNat UScalarTy.U64.numBits n).toNat = n := by
  simp only [BitVec.toNat_ofNat, UScalarTy.U64_numBits_eq]
  exact Nat.mod_eq_of_lt (by simp [U64.max_eq] at h; omega)

theorem sat_add_val (x y : U64) :
    (core.num.U64.saturating_add x y).val = min U64.max (x.val + y.val) := by
  simp only [core.num.U64.saturating_add, UScalar.saturating_add, UScalar.val,
    UScalar.max_UScalarTy_U64_eq]
  exact toNat_ofNat_u64 _ (Nat.min_le_left _ _)

theorem sat_sub_val (x y : U64) : (core.num.U64.saturating_sub x y).val = x.val - y.val := by
  have hx : x.val ≤ U64.max := by scalar_tac
  simp only [core.num.U64.saturating_sub, UScalar.saturating_sub, UScalar.val]
  rw [toNat_ofNat_u64 _ (by simp only [UScalar.val] at hx; omega)]
  omega

theorem capacity_at_le {s : LimiterState} {c : LimiterConfig} {t cap : U64}
    (h : LimiterState.capacity_at s c t = ok cap) :
    cap.val ≤ c.max_bucket_capacity.val ∧
    cap.val ≤ s.num_tokens_available.val + (t.val - s.last_updated_at.val) * c.refill_rate.val := by
  simp only [LimiterState.capacity_at, lift, bind_ok] at h
  obtain rfl := ok_injective h
  have he := Nat.le_of_eq (sat_sub_val t s.last_updated_at)
  have hm := U64.checked_mul_bv_spec (core.num.U64.saturating_sub t s.last_updated_at) c.refill_rate
  have hr : (core.option.Option.unwrap_or
      (U64.checked_mul (core.num.U64.saturating_sub t s.last_updated_at) c.refill_rate)
      core.num.U64.MAX).val ≤ (t.val - s.last_updated_at.val) * c.refill_rate.val := by
    have hmono := Nat.mul_le_mul_right c.refill_rate.val he
    split at hm
    · rename_i z hz
      simp only [hz, core.option.Option.unwrap_or_some]
      omega
    · rename_i hz
      simp only [hz, core.option.Option.unwrap_or_none]
      have : core.num.U64.MAX.val = U64.max := by
        simp [core.num.U64.MAX, U64.rMax, U64.max_eq]
      omega
  have ha := sat_add_val s.num_tokens_available (core.option.Option.unwrap_or
      (U64.checked_mul (core.num.U64.saturating_sub t s.last_updated_at) c.refill_rate)
      core.num.U64.MAX)
  simp only [core.cmp.impls.OrdU64.min_val]
  omega

theorem skew_eq : MAX_CLOCK_SKEW_SECS = ok 300#u64 := by
  unfold MAX_CLOCK_SKEW_SECS; rfl

theorem age_eq : MAX_REQUEST_AGE_SECS = ok 1800#u64 := by
  unfold MAX_REQUEST_AGE_SECS; rfl

theorem validate_ok {ts now : U64}
    (h : validate_request_timestamp ts now = ok (core.result.Result.Ok ())) :
    ts.val ≤ now.val + 300 ∧ now.val ≤ ts.val + 1800 := by
  unfold validate_request_timestamp at h
  simp only [skew_eq, age_eq, bind_ok, lift] at h
  obtain ⟨i1, hi1, h⟩ := bind_eq_ok.mp h
  have hi1 := add_eq_ok hi1
  split at h
  · simp [bind_eq_ok] at h
  · rename_i h1
    split at h
    · simp [bind_eq_ok] at h
    · rename_i h2
      have hs := sat_sub_val now ts
      simp at h1 h2 hi1
      omega

/-- One `consume_at` call. A rejected call keeps the limiter. An accepted call passed each check. -/
theorem consume_at_ok {l l' : RateLimiter} {now seq ts amt : U64}
    {r : core.result.Result Unit guardian.errors.GuardianError}
    (h : RateLimiter.consume_at l now seq ts amt = ok (r, l')) :
    ((∃ e, r = core.result.Result.Err e) ∧ l' = l) ∨
    (r = core.result.Result.Ok () ∧
      ts.val ≤ now.val + 300 ∧ now.val ≤ ts.val + 1800 ∧
      l.state.last_updated_at.val ≤ ts.val ∧
      l'.config = l.config ∧ l'.state.last_updated_at = ts ∧
      l'.state.num_tokens_available.val + amt.val ≤ l.config.max_bucket_capacity.val ∧
      l'.state.num_tokens_available.val + amt.val ≤ l.state.num_tokens_available.val +
        (ts.val - l.state.last_updated_at.val) * l.config.refill_rate.val) := by
  unfold RateLimiter.consume_at at h
  obtain ⟨v, hv, h⟩ := bind_eq_ok.mp h
  cases v with
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual] at h
    obtain ⟨rfl, rfl⟩ := h
    exact Or.inl ⟨⟨_, rfl⟩, rfl⟩
  | Ok u =>
    cases u
    obtain ⟨hskew, hage⟩ := validate_ok hv
    simp [core.result.Result.Insts.CoreOpsTry.branch] at h
    unfold RateLimiter.consume at h
    split at h
    · simp at h
      obtain ⟨rfl, rfl⟩ := h
      exact Or.inl ⟨⟨_, rfl⟩, rfl⟩
    · split at h
      · simp [bind_eq_ok] at h
        obtain ⟨_, _, _, _, _, _, _, _, _, _, rfl, rfl⟩ := h
        exact Or.inl ⟨⟨_, rfl⟩, rfl⟩
      · rename_i hts
        obtain ⟨cap, hcap, h⟩ := bind_eq_ok.mp h
        obtain ⟨hc1, hc2⟩ := capacity_at_le hcap
        split at h
        · simp at h
          obtain ⟨rfl, rfl⟩ := h
          exact Or.inl ⟨⟨_, rfl⟩, rfl⟩
        · obtain ⟨i, hi, h⟩ := bind_eq_ok.mp h
          obtain ⟨i1, hi1, h⟩ := bind_eq_ok.mp h
          have hs := sub_eq_ok hi
          simp at h hts
          obtain ⟨rfl, rfl⟩ := h
          refine Or.inr ⟨rfl, hskew, hage, hts, rfl, rfl, ?_, ?_⟩ <;> simp only [] <;> omega

/-- The loop of `applyCalls` as a recursive function, from any `spent` value. -/
noncomputable def runFrom (l : RateLimiter) (spent : ℕ) : List Call → Result (RateLimiter × ℕ)
  | [] => ok (l, spent)
  | c :: rest => do
    let (result, l') ← l.consume_at c.now c.seq c.ts c.amt
    match result with
    | .Ok () => runFrom l' (spent + c.amt.val) rest
    | .Err _ => runFrom l' spent rest

theorem applyCalls_eq (l : RateLimiter) (calls : List Call) :
    applyCalls l calls = runFrom l 0 calls := by
  unfold applyCalls
  generalize (0 : ℕ) = spent
  induction calls generalizing l spent with
  | nil => simp [runFrom]; rfl
  | cons c cs ih =>
    simp only [List.forIn_cons, runFrom, bind_assoc]
    show Std.bind _ _ = Std.bind _ _
    congr 1
    funext ⟨r, l1⟩
    cases r with
    | Ok u => simpa using ih l1 (spent + c.amt.val)
    | Err e => simpa using ih l1 spent

/-- Run invariant. `t0` is the timestamp of the first accepted call. -/
def RunInv (l0 : RateLimiter) (a b : ℕ) (l : RateLimiter) (spent : ℕ) : Prop :=
  l.config = l0.config ∧
  (spent = 0 ∨ ∃ t0, a ≤ t0 + 1800 ∧ t0 ≤ l.state.last_updated_at.val ∧
    l.state.last_updated_at.val ≤ b + 300 ∧
    spent + l.state.num_tokens_available.val ≤
      l0.config.max_bucket_capacity.val +
        (l.state.last_updated_at.val - t0) * l0.config.refill_rate.val)

theorem run_inv {l0 : RateLimiter} {a b : ℕ} (calls : List Call) :
    ∀ {l l' : RateLimiter} {spent spent' : ℕ}, (∀ c ∈ calls, a ≤ c.now.val ∧ c.now.val ≤ b) →
      RunInv l0 a b l spent → runFrom l spent calls = ok (l', spent') →
      RunInv l0 a b l' spent' := by
  induction calls with
  | nil =>
    intro l l' spent spent' _ hinv h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (ok_injective h)
    exact hinv
  | cons c cs ih =>
    intro l l' spent spent' hc hinv h
    obtain ⟨hnow, hrest⟩ := List.forall_mem_cons.mp hc
    obtain ⟨hcfg, hinv⟩ := hinv
    rw [runFrom] at h
    obtain ⟨⟨r, l1⟩, h1, h2⟩ := bind_eq_ok.mp h
    rcases consume_at_ok h1 with ⟨⟨e, rfl⟩, rfl⟩ |
      ⟨rfl, hskew, hage, hts, hcfg', hlast, hcap, hrefill⟩
    · exact ih hrest ⟨hcfg, hinv⟩ h2
    · refine ih hrest ⟨hcfg'.trans hcfg, Or.inr ?_⟩ h2
      rw [hcfg] at hcap hrefill
      rw [hlast]
      rcases hinv with h0 | ⟨t0, ht0, hle, _, hb⟩
      · exact ⟨c.ts.val, by omega, le_refl _, by omega, by omega⟩
      · refine ⟨t0, ht0, by omega, by omega, ?_⟩
        have key : (c.ts.val - t0) * l0.config.refill_rate.val =
            (l.state.last_updated_at.val - t0) * l0.config.refill_rate.val +
            (c.ts.val - l.state.last_updated_at.val) * l0.config.refill_rate.val := by
          rw [← Nat.add_mul]; congr 1; omega
        omega

/-- The result. `OutflowBound` is the statement in `LimiterSpec.lean`. -/
theorem outflow_bound : OutflowBound := by
  intro l l' calls a b spent hclock hrun
  rw [applyCalls_eq] at hrun
  obtain ⟨hcfg, h0 | ⟨t0, ht0, hle, hb, hbound⟩⟩ :=
    run_inv (l0 := l) calls hclock ⟨rfl, Or.inl rfl⟩ hrun
  · exact ⟨hcfg, by omega⟩
  · have := Nat.mul_le_mul_right l.config.refill_rate.val
      (show l'.state.last_updated_at.val - t0 ≤ b - a + 2100 by omega)
    exact ⟨hcfg, by omega⟩

#print axioms outflow_bound
