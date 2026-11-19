-- Copyright (c) Mysten Labs, Inc.
-- SPDX-License-Identifier: Apache-2.0
/-
The statement that Lean proves about the Guardian rate limiter.

Why it exists:
This is the only hand-written file that needs human review.
A wrong statement makes the proof worthless, so read each line.

How it works:
1. `extract.sh` translates the Rust limiter to `HashiTypes.lean` with Charon and Aeneas.
2. This file states `OutflowBound` about the translated function `RateLimiter.consume_at`.
3. `LimiterProof.lean` proves `OutflowBound`. Lean checks that proof.

Reading notes:
- `U64` is a Rust `u64`. `x.val` is its value as a natural number, with no overflow.
- `Result` is the Aeneas type for a Rust computation. `ok v` means "returned `v`, no panic".
- `RateLimiter.consume_at` returns the Rust result (`.Ok ()` or `.Err e`) and the limiter
  after the call.

Assumptions:
- Charon and Aeneas translate the Rust code correctly.
- The model stops on integer overflow. The release binary wraps. The two differ only if
  `next_seq + 1` or `guardian_now + MAX_CLOCK_SKEW_SECS` is more than `u64::MAX`.
- `format!` returns. The model has no definition for it. `OutflowBound` says nothing about
  a run in which `format!` does not return. Three rejection paths use `format!`.
- `a` and `b` bound the Guardian clock readings, not real time.
-/
import HashiTypes
open Aeneas Aeneas.Std Result
open hashi_types guardian.limiter

noncomputable section

/-- One call to `RateLimiter::consume_at`. -/
structure Call where
  /-- Guardian clock at the call, in seconds. -/
  now : U64
  /-- Sequence number in the request. -/
  seq : U64
  /-- Timestamp in the request, in seconds. -/
  ts : U64
  /-- Amount in the request, in sats. -/
  amt : U64

-- Aeneas replaces the `do` notation with a form that has no loops.
-- This option selects the standard Lean `do` notation for the next definition.
set_option Aeneas.customDoElab false in
/-- Make the calls in order, from limiter `initial`.
Return the last limiter and `spent`, the total amount of the accepted calls. -/
def applyCalls (initial : RateLimiter) (calls : List Call) : Result (RateLimiter × ℕ) := do
  let mut limiter := initial
  let mut spent : ℕ := 0
  for c in calls do
    let (result, next) ← limiter.consume_at c.now c.seq c.ts c.amt
    limiter := next
    match result with
    | .Ok () => spent := spent + c.amt.val
    | .Err _ => pure ()
  return (limiter, spent)

/-- Outflow bound.

Start from any limiter `initial`. Make any list of calls.
If each Guardian clock value is in `[a, b]`, then:
- The calls do not change the limiter config.
- The accepted amounts sum to at most the bucket capacity plus the refill for
  `b - a + 2100` seconds. The 2100 seconds is `MAX_CLOCK_SKEW_SECS + MAX_REQUEST_AGE_SECS`. -/
def OutflowBound : Prop :=
  ∀ (initial final : RateLimiter) (calls : List Call) (a b spent : ℕ),
    (∀ c ∈ calls, a ≤ c.now.val ∧ c.now.val ≤ b) →
    applyCalls initial calls = ok (final, spent) →
    final.config = initial.config ∧
    spent ≤ initial.config.max_bucket_capacity.val +
      (b - a + 2100) * initial.config.refill_rate.val

end
