// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Module: mpc_signing
///
/// Durable, out-of-order accumulator for a withdrawal's per-input threshold
/// Schnorr signatures. This is the MPC-protocol side of incremental signing:
/// the dangerous presignature / nonce bookkeeping lives here, behind a
/// module boundary, and is embedded (field-private) inside the BTC
/// `WithdrawalTransaction` rather than stored as a separate object.
///
/// Each input occupies one slot that is either:
///   - `Pending(presig_index)` — awaiting its signature; carries the
///     presignature index it will consume (valid within `epoch`), or
///   - `Signed(bytes)`         — the completed per-input MPC signature.
///
/// Signatures are filled in any order (`record`), survive leader timeouts /
/// rotation / restart because they live on chain, and survive committee
/// reconfiguration: on an epoch change only the still-`Pending` slots are
/// reassigned fresh presignatures (`reallocate`); `Signed` slots are final
/// and epoch-independent (the committee group key is stable across rotation).
///
/// NONCE SAFETY (a violation leaks the group secret share):
///   - every `Pending` index is unique within (batch, epoch) — `new` /
///     `reallocate` assign distinct offsets from a freshly allocated block;
///   - indices are globally disjoint within an epoch — the allocator is
///     monotonic (see `hashi::allocate_presigs`);
///   - a stale-epoch index is never used after a reconfig — `reallocate`
///     overwrites EVERY `Pending` slot before any signing happens in the new
///     epoch, and the caller must `reallocate` whenever `epoch` is stale;
///   - a `Signed` slot holds no index, so there is nothing stale to reuse.
module hashi::mpc_signing;

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

/// Per-input signing slot.
public enum InputSig has drop, store {
    /// Awaiting signature; holds the presignature index this input will
    /// consume, valid within the owning batch's `epoch`.
    Pending(u64),
    /// Completed per-input MPC Schnorr signature bytes.
    Signed(vector<u8>),
}

/// Out-of-order accumulator for one withdrawal's per-input MPC signatures.
/// Owned by this module (fields are private); embedded in the BTC
/// `WithdrawalTransaction`.
public struct SigningBatch has store {
    /// One slot per input; same length/order as the withdrawal's inputs.
    signatures: vector<InputSig>,
    /// Number of `Signed` slots — a cardinality, NOT an in-order prefix.
    signed_count: u64,
    /// Epoch the `Pending` presignature indices belong to.
    epoch: u64,
}

// ======== Constructors ========

/// Create a batch for `num_inputs`, contiguously assigning presignature
/// indices so that input `i` uses `presig_base + i`.
public(package) fun new(num_inputs: u64, presig_base: u64, epoch: u64): SigningBatch {
    assert!(num_inputs > 0, EZeroInputs);
    let mut signatures = vector[];
    let mut i = 0;
    while (i < num_inputs) {
        signatures.push_back(InputSig::Pending(presig_base + i));
        i = i + 1;
    };
    SigningBatch { signatures, signed_count: 0, epoch }
}

// ======== Mutation ========

/// Fill the given slots with completed signatures. First-writer-wins applies
/// both within a call and across calls: a slot that is already `Signed` is left
/// untouched, so retries, duplicate indices, and briefly overlapping leaders
/// are all idempotent. `signed_count` is bumped only on a fresh fill.
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
            *self.signatures.borrow_mut(i) = InputSig::Signed(*sigs.borrow(k));
            self.signed_count = self.signed_count + 1;
        };
        k = k + 1;
    };
}

/// Reassign fresh presignature indices to every still-`Pending` slot for a new
/// epoch. `Signed` slots are untouched (their signatures are final and
/// epoch-independent). The j-th still-`Pending` slot (ascending input order)
/// gets `new_base + j`, so the caller must allocate exactly `pending_count`
/// presignatures starting at `new_base` for `current_epoch`. `allocated_count`
/// is the size of the block the caller reserved; it MUST equal `pending_count`
/// — under-allocating would assign indices past the reserved block, letting the
/// monotonic allocator hand the same index to another batch (nonce reuse).
/// Aborts if the batch is not actually stale (guards against double reallocation).
public(package) fun reallocate(
    self: &mut SigningBatch,
    new_base: u64,
    current_epoch: u64,
    allocated_count: u64,
) {
    assert!(self.epoch != current_epoch, ENotStale);
    assert!(allocated_count == pending_count(self), EAllocationMismatch);
    let len = self.signatures.length();
    let mut i = 0;
    let mut j = 0;
    while (i < len) {
        if (self.signatures.borrow(i).is_pending()) {
            *self.signatures.borrow_mut(i) = InputSig::Pending(new_base + j);
            j = j + 1;
        };
        i = i + 1;
    };
    self.epoch = current_epoch;
}

// ======== Views ========

/// Number of still-`Pending` slots (the count that must be re-presigned on a
/// stale-epoch `reallocate`).
public(package) fun pending_count(self: &SigningBatch): u64 {
    self.signatures.length() - self.signed_count
}

/// True once every input has a signature.
public(package) fun is_complete(self: &SigningBatch): bool {
    self.signed_count == self.signatures.length()
}

public(package) fun signed_count(self: &SigningBatch): u64 {
    self.signed_count
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

/// The presignature index input `i` will use, or `none` if already signed.
public(package) fun pending_index(self: &SigningBatch, i: u64): Option<u64> {
    assert!(i < self.signatures.length(), EIndexOutOfRange);
    match (self.signatures.borrow(i)) {
        InputSig::Pending(idx) => option::some(*idx),
        InputSig::Signed(_) => option::none(),
    }
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
            InputSig::Signed(sig) => out.push_back(*sig),
            InputSig::Pending(_) => abort ENotComplete,
        };
        i = i + 1;
    };
    out
}

// ======== Internal ========

fun is_pending(self: &InputSig): bool {
    match (self) {
        InputSig::Pending(_) => true,
        InputSig::Signed(_) => false,
    }
}

// ======== Test helpers ========

#[test_only]
public(package) fun destroy_for_testing(self: SigningBatch) {
    let SigningBatch { signatures: _, signed_count: _, epoch: _ } = self;
}
