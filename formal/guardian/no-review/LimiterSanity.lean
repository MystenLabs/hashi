-- Copyright (c) Mysten Labs, Inc.
-- SPDX-License-Identifier: Apache-2.0
/-
Sanity check for the limiter facts. It shows that an accepted `consume` call exists.
Thus the hypothesis of `runInv_accept` is not empty. Lean checks this file.
-/
import LimiterProof
open Aeneas Aeneas.Std Result
open hashi_guardian hashi_types guardian.limiter

/-- A full bucket of 100 sats, with a refill of 1 sat per second. -/
abbrev fullBucket : RateLimiter :=
  { config := { refill_rate := 1#u64, max_bucket_capacity := 100#u64 },
    state := { num_tokens_available := 100#u64, last_updated_at := 0#u64, next_seq := 0#u64 } }

/-- The limiter accepts a call for 50 sats with timestamp 1000. -/
theorem accepted_call : WP.spec (RateLimiter.consume fullBucket 0#u64 1000#u64 50#u64)
    (fun x => x.1 = core.result.Result.Ok ()) := by
  unfold RateLimiter.consume LimiterState.capacity_at
  simp only [lift, bind_ok]
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
  obtain ⟨next, hnext⟩ : ∃ next, U64.checked_add 0#u64 1#u64 = some next := by
    have hs := U64.checked_add_bv_spec 0#u64 1#u64
    split at hs
    · exact ⟨_, by assumption⟩
    · scalar_tac
  simp only [hnext, core.option.Option.expect, Result.ofOption, bind_ok]
  step as ⟨i, hi⟩
