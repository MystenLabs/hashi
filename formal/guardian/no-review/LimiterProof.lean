-- Copyright (c) Mysten Labs, Inc.
-- SPDX-License-Identifier: Apache-2.0
/-
Facts about `RateLimiter::consume` that the withdrawal proof uses.
Lean checks this file. It needs no human review.

How it works:
- `consume_step` gives the two ways in which one `consume` call can end.
- `RunInv` is the invariant of a run of calls, for one clock window. `runInv_accept` shows
  that an accepted call in the window keeps it and adds its amount. `runInv_skip` shows that
  each other accepted call keeps it. `runInv_bound` gets the outflow bound from it.
-/
import HashiGuardian
open Aeneas Aeneas.Std Result
open hashi_guardian hashi_types guardian.limiter

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

/-- One `consume` call. A rejected call keeps the limiter. An accepted call passed each check. -/
theorem consume_step {l l' : RateLimiter} {seq ts amt : U64}
    {r : core.result.Result Unit guardian.errors.GuardianError}
    (h : RateLimiter.consume l seq ts amt = ok (r, l')) :
    ((∃ e, r = core.result.Result.Err e) ∧ l' = l) ∨
    (r = core.result.Result.Ok () ∧
      l.state.last_updated_at.val ≤ ts.val ∧
      l'.config = l.config ∧ l'.state.last_updated_at = ts ∧
      l'.state.num_tokens_available.val + amt.val ≤ l.config.max_bucket_capacity.val ∧
      l'.state.num_tokens_available.val + amt.val ≤ l.state.num_tokens_available.val +
        (ts.val - l.state.last_updated_at.val) * l.config.refill_rate.val) := by
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
        simp only [lift, bind_ok] at h
        obtain ⟨i1, hi1, h⟩ := bind_eq_ok.mp h
        have hs := sub_eq_ok hi
        simp at h hts
        obtain ⟨rfl, rfl⟩ := h
        refine Or.inr ⟨rfl, hts, rfl, rfl, ?_, ?_⟩ <;> simp only [] <;> omega

/-- Run invariant, from limiter `l0`, for the clock window `[a, b]`. `l` is the limiter now.
`spent` is the amount of the accepted calls with a clock value in the window. It is at most
the outflow bound. `t0` is the timestamp of the first such call. The token bound from `t0`
applies while `last_updated_at ≤ b + 300`. After that, the handler accepts no window call. -/
def RunInv (l0 : RateLimiter) (a b : ℕ) (l : RateLimiter) (spent : ℕ) : Prop :=
  l.config = l0.config ∧
  spent ≤ l0.config.max_bucket_capacity.val + (b - a + 2100) * l0.config.refill_rate.val ∧
  (l.state.last_updated_at.val ≤ b + 300 →
    spent = 0 ∨ ∃ t0, a ≤ t0 + 1800 ∧ t0 ≤ l.state.last_updated_at.val ∧
      spent + l.state.num_tokens_available.val ≤
        l0.config.max_bucket_capacity.val +
          (l.state.last_updated_at.val - t0) * l0.config.refill_rate.val)

/-- An accepted `consume` call in the window keeps the run invariant and adds its amount,
if its timestamp is near the clock. -/
theorem runInv_accept {l0 l l' : RateLimiter} {a b spent : ℕ} {now seq ts amt : U64}
    (hnow : a ≤ now.val ∧ now.val ≤ b)
    (hskew : ts.val ≤ now.val + 300) (hage : now.val ≤ ts.val + 1800)
    (hinv : RunInv l0 a b l spent)
    (h : l.consume seq ts amt = ok (.Ok (), l')) : RunInv l0 a b l' (spent + amt.val) := by
  obtain ⟨hcfg, _, hinv⟩ := hinv
  rcases consume_step h with ⟨⟨e, he⟩, _⟩ | ⟨_, hts, hcfg', hlast, hcap, hrefill⟩
  · cases he
  · rw [hcfg] at hcap hrefill
    have hstep : ∃ t0, a ≤ t0 + 1800 ∧ t0 ≤ ts.val ∧
        spent + amt.val + l'.state.num_tokens_available.val ≤
          l0.config.max_bucket_capacity.val + (ts.val - t0) * l0.config.refill_rate.val := by
      rcases hinv (by omega) with h0 | ⟨t0, ht0, hle, hb⟩
      · exact ⟨ts.val, by omega, le_refl _, by omega⟩
      · refine ⟨t0, ht0, by omega, ?_⟩
        have key : (ts.val - t0) * l0.config.refill_rate.val =
            (l.state.last_updated_at.val - t0) * l0.config.refill_rate.val +
            (ts.val - l.state.last_updated_at.val) * l0.config.refill_rate.val := by
          rw [← Nat.add_mul]; congr 1; omega
        omega
    obtain ⟨t0, ht0, hle, hb⟩ := hstep
    refine ⟨hcfg'.trans hcfg, ?_, fun _ => Or.inr ⟨t0, ht0, ?_, ?_⟩⟩
    · have := Nat.mul_le_mul_right l0.config.refill_rate.val
        (show ts.val - t0 ≤ b - a + 2100 by omega)
      omega
    · rw [hlast]; exact hle
    · rw [hlast]; exact hb

/-- An accepted `consume` call keeps the run invariant with the same `spent`.
The theorem has no clock condition. The proof uses it for a call out of the window. -/
theorem runInv_skip {l0 l l' : RateLimiter} {a b spent : ℕ} {seq ts amt : U64}
    (hinv : RunInv l0 a b l spent)
    (h : l.consume seq ts amt = ok (.Ok (), l')) : RunInv l0 a b l' spent := by
  obtain ⟨hcfg, hbound, hinv⟩ := hinv
  rcases consume_step h with ⟨⟨e, he⟩, _⟩ | ⟨_, hts, hcfg', hlast, hcap, hrefill⟩
  · cases he
  · rw [hcfg] at hrefill
    refine ⟨hcfg'.trans hcfg, hbound, ?_⟩
    rw [hlast]
    intro hb
    rcases hinv (by omega) with h0 | ⟨t0, ht0, hle, hsp⟩
    · exact Or.inl h0
    · refine Or.inr ⟨t0, ht0, by omega, ?_⟩
      have key : (ts.val - t0) * l0.config.refill_rate.val =
          (l.state.last_updated_at.val - t0) * l0.config.refill_rate.val +
          (ts.val - l.state.last_updated_at.val) * l0.config.refill_rate.val := by
        rw [← Nat.add_mul]; congr 1; omega
      omega

/-- The run invariant gives the outflow bound. -/
theorem runInv_bound {l0 l : RateLimiter} {a b spent : ℕ} (h : RunInv l0 a b l spent) :
    spent ≤ l0.config.max_bucket_capacity.val + (b - a + 2100) * l0.config.refill_rate.val :=
  h.2.1
