-- Copyright (c) Mysten Labs, Inc.
-- SPDX-License-Identifier: Apache-2.0
/-
Sanity check for `OutflowBound`. It shows that the hypotheses are not empty:
a run with an accepted call exists, and its `spent` value is more than zero.
Lean checks this file.
-/
import LimiterProof
open Aeneas Aeneas.Std Result
open hashi_types guardian.limiter

/-- A full bucket of 100 sats, with a refill of 1 sat per second. -/
abbrev fullBucket : RateLimiter :=
  { config := { refill_rate := 1#u64, max_bucket_capacity := 100#u64 },
    state := { num_tokens_available := 100#u64, last_updated_at := 0#u64, next_seq := 0#u64 } }

theorem spec_eq_ok {α} {m : Result α} {p : WP.Post α} (h : WP.spec m p) :
    ∃ v, m = ok v ∧ p v := by
  induction m using Result.cases with
  | ret a => exact ⟨a, rfl, (WP.spec_ok a).mp h⟩
  | vis i k => exact absurd h (by simp [WP.spec_vis])
  | div => exact absurd h (by simp [WP.spec_div])

/-- The limiter accepts a call for 50 sats at clock 1000. -/
theorem accepted_call : WP.spec (RateLimiter.consume_at fullBucket
    1000#u64 0#u64 1000#u64 50#u64) (fun x => x.1 = core.result.Result.Ok ()) := by
  unfold RateLimiter.consume_at validate_request_timestamp RateLimiter.consume
    LimiterState.capacity_at
  simp only [skew_eq, age_eq, lift, bind_ok, core.result.Result.Insts.CoreOpsTry.branch]
  step as ⟨x, hx⟩
  have h1 : ¬ (1000#u64 > x) := by scalar_tac
  have h2 : ¬ (core.num.U64.saturating_sub 1000#u64 1000#u64 > 1800#u64) := by
    have := sat_sub_val 1000#u64 1000#u64; scalar_tac
  simp only [h1, h2, ↓reduceIte, bind_ok]
  generalize core.option.Option.unwrap_or
    (U64.checked_mul (core.num.U64.saturating_sub 1000#u64 0#u64) 1#u64) core.num.U64.MAX = refill
  have hc : (core.cmp.impls.OrdU64.min (core.num.U64.saturating_add 100#u64 refill) 100#u64).val
      = 100 := by
    simp only [core.cmp.impls.OrdU64.min_val, sat_add_val, U64.max_eq]; scalar_tac
  have h3 : ¬ ((0#u64 != 0#u64) = true) := by simp
  have h4 : ¬ (1000#u64 < 0#u64) := by scalar_tac
  have h5 : ¬ (core.cmp.impls.OrdU64.min (core.num.U64.saturating_add 100#u64 refill) 100#u64
      < 50#u64) := by scalar_tac
  simp only [h3, h4, h5, ↓reduceIte]
  simp only [Bool.false_eq_true, ↓reduceIte]
  step as ⟨i, hi⟩
  step as ⟨i1, hi1⟩

/-- The run of that one call has `spent = 50`. -/
example : ∃ l', applyCalls fullBucket [⟨1000#u64, 0#u64, 1000#u64, 50#u64⟩] = ok (l', 50) := by
  obtain ⟨⟨r, l1⟩, h, hr⟩ := spec_eq_ok accepted_call
  simp only [] at hr
  subst hr
  exact ⟨l1, by simp [applyCalls_eq, runFrom, h]⟩
