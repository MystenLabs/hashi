# Guardian proofs

Lean proofs about the Guardian rate limiter and the withdrawal handler.
The proofs are about the Aeneas translation of the Rust code, not about a hand-written model.
For the handler, Aeneas translates a sync copy that a script makes. See "The sync copy".

## What it proves

Start from any enclave. Make any list of calls to the handler `standard_withdrawal`.
If each Guardian clock value is in `[a, b]`, then:

- `WithdrawalOutflowBound`: the outflow of the accepted calls is at most `max_bucket_capacity`
  plus `refill_rate` × (`b - a` + 2100 seconds).
  The outflow of one call is `wireOutflow`: the input amounts minus the internal output amounts.
  Lean computes it from the request as the caller sends it, with no Rust function.
  With no limiter in the enclave, the outflow of the accepted calls is 0.

The 2100 seconds is `MAX_CLOCK_SKEW_SECS + MAX_REQUEST_AGE_SECS`.
The exact statement is in `review/WithdrawalSpec.lean`.

## Files

`review/` has each file that a person must read.

| File | What to check |
|---|---|
| `review/WithdrawalSpec.lean` | The statement, the assumptions, and two TODO items. Read each line. |
| `review/sync-copy.patch` | The edits that make the sync copy. Read each line. |
| `review/extract.sh` | It applies only that patch, and it gives the correct flags to Charon. |

`no-review/` has the files that Lean checks, and one tool.

| File | Content |
|---|---|
| `no-review/WithdrawalProof.lean` | The proof of the statement. |
| `no-review/RequestProof.lean` | Facts about the path from the wire request to the limiter amount. |
| `no-review/LimiterProof.lean` | Facts about the rate limiter. |
| `no-review/LimiterSanity.lean` | An example that shows that an accepted limiter call exists. |
| `no-review/HashiGuardian.lean` | The Aeneas output. It is generated and not committed. |
| `no-review/make_patch.py` | A tool that writes `sync-copy.patch`. The build does not use it. |

## The sync copy

Aeneas cannot translate an `async` function, the `tracing` macros, or the `serde` traits.
`extract.sh` copies the workspace and applies `sync-copy.patch` to the copy:

- The handler becomes a sync function.
- The log lines go away.
- The S3 withdrawal log becomes a list in the enclave, `mock_withdrawal_log`.
- The signing traits `IntentMessage` and `GuardianSigningIntent` get a `payload_bytes` method
  in place of the `Serialize` supertrait. The signed bytes do not change.

`extract.sh` stops if a line of the patch does not match the Rust code.
Then run `python3 no-review/make_patch.py` and review the new patch.

## How to run

1. Install [elan](https://github.com/leanprover/elan), the Lean version manager.
2. Download the Aeneas release `nightly-2026.11.19-8f4466d` for your platform.
   It contains `aeneas`, `charon`, and `charon-driver`.
3. Install the Rust toolchain in the `rust-toolchain` file of that release.
4. Run the commands below from this directory.

```sh
CHARON=/path/to/charon AENEAS=/path/to/aeneas ./review/extract.sh
lake exe cache get
lake build
```

`extract.sh` gives Charon the option `--sysroot default`, the standard library files of the
Rust toolchain. The Charon default is its own copy with the body of each standard function.
The dependency `crc-fast` does not link against that copy, and the proofs do not need those bodies.

The build is correct if it completes and no axiom report contains `sorryAx`.
Each report starts with `propext`, `Classical.choice`, and `Quot.sound`, the standard Lean axioms.
The other names are Rust types and functions that have no body in `HashiGuardian.lean`.
Lean models each such function as a pure function. The proof holds for each such function.

## What the proofs do not include

- The other handlers. They can change the enclave between two withdrawal calls.
- The transaction content. The statement does not show that an accepted call signs only the
  transaction of its request. `review/WithdrawalSpec.lean` has a TODO for the part that Lean
  can check. It also does not show that the input amounts in a request are the on-chain amounts.
- The log. The statement does not show which record the handler writes to S3.
- The certificate check. `verify_hashi_cert` has no body in Lean. The bound also holds for a
  committee that signs each request.
- The recovery path. After `HASHI_MPC_RECOVERY_DELAY_SECONDS`, the committee key can spend a
  pool UTXO with no Guardian signature.
- The service. The proof assumes that `run_rpc` in `service.rs` runs one handler at a time,
  from start to end. It also assumes that a failed S3 write stops the enclave.
- A call that panics. A panic stops the Guardian process, and the model also stops.
  The statement applies to the calls before the panic. An integer overflow is such a panic.
  `review/WithdrawalSpec.lean` has a TODO for a statement that a request cannot cause a panic.
- Hidden effects of functions with no body, for example `sign_btc_tx`. The proof assumes that
  such a function has no effect other than its return value.
- Restarts. The bound is for one enclave session. The proof does not show that a new
  session starts from the last logged limiter state.
- The Guardian clock. `a` and `b` bound the clock readings, not real time. A clock that
  jumps forward makes `b - a` larger, and thus the bound larger.
- A sanity example for the handler. Many functions that the handler calls have no body in
  Lean, so Lean cannot run an accepted call.
- The correctness of Charon, Aeneas, and Lean.

## When the Rust code changes

Run `./review/extract.sh` and `lake build` again. If the change breaks a statement, the build fails.
No CI job runs these commands at this time, so a person must run them.
A change to a file in `review/` needs a new review of that file.
