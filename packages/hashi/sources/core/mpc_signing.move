// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Durable, out-of-order accumulator for a withdrawal's per-input threshold
/// Schnorr signatures. This is the MPC-protocol side of incremental signing:
/// the dangerous presignature / nonce bookkeeping lives here, behind a
/// module boundary, and is embedded (field-private) inside the BTC
/// `WithdrawalTransaction` rather than stored as a separate object.
///
/// Each input occupies one slot that is either:
///   - `Pending(pair)` — awaiting its signature; carries the pair of
///     presignature indices it will consume (valid within `epoch`), or
///   - `Signed(bytes)` — the completed per-input MPC signature.
///
/// Every signature consumes a pair of presignatures, which the signer binds
/// to the message (FROST-style), so the nonce stays safe whether the
/// presignatures were generated before or after the message was fixed.
///
/// Signatures are filled in any order (`record`), survive leader timeouts /
/// rotation / restart because they live on chain, and survive committee
/// reconfiguration: on an epoch change only the still-`Pending` slots are
/// reassigned fresh presignatures (`reallocate`); `Signed` slots are final
/// and epoch-independent (the committee group key is stable across rotation).
///
/// NONCE SAFETY (a violation leaks the group secret share):
///   - every index in every `Pending` pair is unique within (batch, epoch) —
///     `new` / `reallocate` assign distinct offsets from a freshly allocated
///     block whose size they check against `presigs_for_inputs`;
///   - indices are globally disjoint within an epoch — the allocator is
///     monotonic (see `hashi::allocate_presigs`);
///   - a stale-epoch index is never used after a reconfig — `reallocate`
///     overwrites EVERY `Pending` slot before any signing happens in the new
///     epoch, and the caller must `reallocate` whenever `epoch` is stale;
///   - a `Signed` slot holds no index, so there is nothing stale to reuse.
module hashi::mpc_signing;

// ~~~~~~~ Errors ~~~~~~~

#[error]
const EZeroInputs: vector<u8> = b"signing batch must have at least one input";
#[error]
const EIndexOutOfRange: vector<u8> = b"input index is out of range";
#[error]
const ELengthMismatch: vector<u8> = b"indices and signatures lengths differ";
#[error]
const ENotStale: vector<u8> = b"signing batch is already on the current epoch";
#[error]
const EAllocationMismatch: vector<u8> = b"allocated presig count does not match pending count";
#[error]
const ENotComplete: vector<u8> = b"signing batch is not fully signed";

// ~~~~~~~ Constants ~~~~~~~

/// Presignatures consumed by one input's signature.
const PRESIGS_PER_INPUT: u64 = 2;

// ~~~~~~~ Structs ~~~~~~~

/// The two presignature indices one input's signature consumes, in the order
/// the signer binds them.
public struct PresigPair has copy, drop, store {
    first: u64,
    second: u64,
}

/// Per-input signing slot.
public enum MpcSig has drop, store {
    /// Awaiting signature; holds the presignature pair this input will
    /// consume, valid within the owning batch's `epoch`.
    Pending(PresigPair),
    /// Completed per-input MPC Schnorr signature bytes.
    Signed(vector<u8>),
}

/// Out-of-order accumulator for one withdrawal's per-input MPC signatures.
/// Owned by this module (fields are private); embedded in the BTC
/// `WithdrawalTransaction`.
public struct SigningBatch has store {
    /// One slot per input; same length/order as the withdrawal's inputs.
    signatures: vector<MpcSig>,
    /// Epoch the `Pending` presignature pairs belong to.
    epoch: u64,
}

// ~~~~~~~ Package Functions ~~~~~~~

// === Constructors ===

// TODO(presig-allocation-centralization): `new` and `reallocate` take a
// pre-allocated `presig_base`/`new_base` from the caller (hashi::allocate_presigs),
// so allocation and reassignment live across call sites. A follow-up could thread
// an &mut to the consumed-presig counter through here to centralize it in one
// place. Left as-is for now (see PR #667 review).
/// Create a batch for `num_inputs`, contiguously assigning presignature pairs
/// so that input `i` uses `presig_base + 2i` and `presig_base + 2i + 1`.
/// `allocated_count` is the size of the block the caller reserved; it MUST
/// equal `presigs_for_inputs(num_inputs)` for the same reason as in
/// `reallocate`.
public(package) fun new(
    num_inputs: u64,
    presig_base: u64,
    epoch: u64,
    allocated_count: u64,
): SigningBatch {
    assert!(num_inputs > 0, EZeroInputs);
    assert!(allocated_count == presigs_for_inputs(num_inputs), EAllocationMismatch);
    let mut signatures = vector[];
    let mut i = 0;
    while (i < num_inputs) {
        signatures.push_back(MpcSig::Pending(pair_at(presig_base, i)));
        i = i + 1;
    };
    SigningBatch { signatures, epoch }
}

/// Number of presignatures to allocate for `num_inputs` signatures.
public(package) fun presigs_for_inputs(num_inputs: u64): u64 {
    num_inputs * PRESIGS_PER_INPUT
}

// === Mutation ===

/// Fill the given slots with completed signatures. First-writer-wins applies
/// both within a call and across calls: a slot that is already `Signed` is left
/// untouched, so retries, duplicate indices, and briefly overlapping leaders
/// are all idempotent.
///
/// Intentionally epoch-agnostic: a completed aggregated signature validates
/// against the stable committee group key forever, so it may be recorded under
/// any epoch (this is what lets signed slots survive a reconfig). Nonce safety
/// is NOT enforced here — it lives in presig assignment (`new`/`reallocate`)
/// and in the off-chain rule that each presig index signs exactly one sighash
/// and a stale-epoch index is never signed with. Caller must cert-gate the
/// write (the entry verifies a current-epoch committee cert over these bytes).
public(package) fun record(
    self: &mut SigningBatch,
    indices: vector<u64>,
    sigs: vector<vector<u8>>,
) {
    let n = indices.length();
    assert!(n == sigs.length(), ELengthMismatch);
    let len = self.signatures.length();
    let mut k = 0;
    while (k < n) {
        let i = *indices.borrow(k);
        assert!(i < len, EIndexOutOfRange);
        if (self.signatures.borrow(i).is_pending()) {
            *self.signatures.borrow_mut(i) = MpcSig::Signed(*sigs.borrow(k));
        };
        k = k + 1;
    };
}

/// Reassign fresh presignature pairs to every still-`Pending` slot for a new
/// epoch. `Signed` slots are untouched (their signatures are final and
/// epoch-independent). The j-th still-`Pending` slot (ascending input order)
/// gets `new_base + 2j` and `new_base + 2j + 1`, so the caller must allocate
/// exactly `presigs_for_inputs(pending_count)` presignatures starting at
/// `new_base` for `current_epoch`. `allocated_count` is the size of the block
/// the caller reserved; it MUST equal that — under-allocating would assign
/// indices past the reserved block, letting the monotonic allocator hand the
/// same index to another batch (nonce reuse).
/// Aborts if the batch is not actually stale (guards against double reallocation).
public(package) fun reallocate(
    self: &mut SigningBatch,
    new_base: u64,
    current_epoch: u64,
    allocated_count: u64,
) {
    assert!(self.epoch != current_epoch, ENotStale);
    assert!(allocated_count == presigs_for_inputs(pending_count(self)), EAllocationMismatch);
    let len = self.signatures.length();
    let mut i = 0;
    let mut j = 0;
    while (i < len) {
        if (self.signatures.borrow(i).is_pending()) {
            *self.signatures.borrow_mut(i) = MpcSig::Pending(pair_at(new_base, j));
            j = j + 1;
        };
        i = i + 1;
    };
    self.epoch = current_epoch;
}

// === Views ===

/// Number of still-`Pending` slots (the inputs that must be re-presigned on a
/// stale-epoch `reallocate`).
public(package) fun pending_count(self: &SigningBatch): u64 {
    self.signatures.length() - self.signed_count()
}

/// True once every input has a signature.
public(package) fun is_complete(self: &SigningBatch): bool {
    self.signed_count() == self.signatures.length()
}

/// Number of `Signed` slots. Derived by counting (not stored) so it can never
/// fall out of sync with `signatures`: it is load-bearing for `reallocate`'s
/// presig allocation, where an over-count would under-allocate the pending block
/// and let the monotonic allocator hand a live index to another batch (reuse).
public(package) fun signed_count(self: &SigningBatch): u64 {
    let len = self.signatures.length();
    let mut count = 0;
    let mut i = 0;
    while (i < len) {
        if (!self.signatures.borrow(i).is_pending()) {
            count = count + 1;
        };
        i = i + 1;
    };
    count
}

public(package) fun num_inputs(self: &SigningBatch): u64 {
    self.signatures.length()
}

public(package) fun epoch(self: &SigningBatch): u64 {
    self.epoch
}

/// True if input `i` has been signed.
public(package) fun is_signed(self: &SigningBatch, i: u64): bool {
    assert!(i < self.signatures.length(), EIndexOutOfRange);
    !self.signatures.borrow(i).is_pending()
}

/// The presignature pair input `i` will use, or `none` if already signed.
public(package) fun pending_pair(self: &SigningBatch, i: u64): Option<PresigPair> {
    assert!(i < self.signatures.length(), EIndexOutOfRange);
    match (self.signatures.borrow(i)) {
        MpcSig::Pending(pair) => option::some(*pair),
        MpcSig::Signed(_) => option::none(),
    }
}

public(package) fun first(self: &PresigPair): u64 {
    self.first
}

public(package) fun second(self: &PresigPair): u64 {
    self.second
}

/// Dense per-input signature vector for the final witness. Aborts unless every
/// input is signed.
public(package) fun to_signatures(self: &SigningBatch): vector<vector<u8>> {
    assert!(self.is_complete(), ENotComplete);
    let len = self.signatures.length();
    let mut out = vector[];
    let mut i = 0;
    while (i < len) {
        match (self.signatures.borrow(i)) {
            MpcSig::Signed(sig) => out.push_back(*sig),
            MpcSig::Pending(_) => abort ENotComplete,
        };
        i = i + 1;
    };
    out
}

// ~~~~~~~ Private Functions ~~~~~~~

/// The pair for the `j`-th slot of a block starting at `base`. Every block
/// is a whole number of pairs, so `base` stays even and a pair never straddles
/// an even-sized presignature batch; the signer still takes a pair atomically
/// in case a batch is odd-sized.
fun pair_at(base: u64, j: u64): PresigPair {
    let first = base + j * PRESIGS_PER_INPUT;
    PresigPair { first, second: first + 1 }
}

fun is_pending(self: &MpcSig): bool {
    match (self) {
        MpcSig::Pending(_) => true,
        MpcSig::Signed(_) => false,
    }
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
public(package) fun new_pair_for_testing(first: u64, second: u64): PresigPair {
    PresigPair { first, second }
}

#[test_only]
public(package) fun destroy_for_testing(self: SigningBatch) {
    let SigningBatch { signatures: _, epoch: _ } = self;
}
