# Guardian rate limiter proof

A Lean proof that bounds the amount that the Guardian rate limiter accepts.
The proof is about the Aeneas translation of the Rust function `RateLimiter::consume_at`,
not about a hand-written model.

## What it proves

Start from any limiter. Make any list of `RateLimiter::consume_at` calls.
If each Guardian clock value is in `[a, b]`, then:

- The calls do not change the limiter config.
- The accepted amounts sum to at most `max_bucket_capacity` plus
  `refill_rate` × (`b - a` + 2100 seconds).

The 2100 seconds is `MAX_CLOCK_SKEW_SECS + MAX_REQUEST_AGE_SECS`.
The exact statement is `OutflowBound` in `LimiterSpec.lean`.

## Files

| File | Author | Review |
|---|---|---|
| `LimiterSpec.lean` | Hand-written | Yes. This is the statement. |
| `LimiterProof.lean` | Hand-written | No. Lean checks it. |
| `LimiterSanity.lean` | Hand-written | No. It shows that an accepted call exists. |
| `HashiTypes.lean` | Aeneas | No. It is generated and not committed. |

## How to run

1. Install [elan](https://github.com/leanprover/elan), the Lean version manager.
2. Download the Aeneas release `nightly-2026.11.19-8f4466d` for your platform.
   It contains `aeneas`, `charon`, and `charon-driver`.
3. Install the Rust toolchain in the `rust-toolchain` file of that release.
4. Run the commands below from this directory.

```sh
CHARON=/path/to/charon AENEAS=/path/to/aeneas ./extract.sh
lake exe cache get
lake build
```

The build is correct if it completes and the axiom report shows only these names:
`propext`, `Classical.choice`, `Quot.sound`, `alloc.fmt.format`, `core.hint.must_use`.
The first three are standard Lean axioms. The last two are opaque Rust functions that
`format!` uses in error paths.

## What the proof does not include

- The handler `standard_withdrawal` calls `consume_from_limiter` before it signs.
- The debited amount equals the BTC that leaves the pool.
- Restarts. The bound is for one enclave session. The proof does not show that a new
  session starts from the last logged limiter state.
- The Guardian clock. `a` and `b` bound the clock readings, not real time. A clock that
  jumps forward makes `b - a` larger, and thus the bound larger.
- Integer overflow. The model stops on overflow, and the release binary wraps. The two
  differ only if `next_seq + 1` or `guardian_now + MAX_CLOCK_SKEW_SECS` is more than
  `u64::MAX`.
- `format!`. The model has no definition for it. The theorem says nothing about a run in
  which `format!` does not return. Three rejection paths use `format!`.
- The correctness of Charon, Aeneas, and Lean.

## When the Rust code changes

Run `./extract.sh` and `lake build` again. If the change breaks the bound, the build fails.
No CI job runs these commands at this time, so a person must run them.
A change to the constants or to the statement needs a new review of `LimiterSpec.lean`.
