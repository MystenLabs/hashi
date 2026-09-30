// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Durable, out-of-order accumulator for a withdrawal's per-input threshold
/// Schnorr signatures. This is the MPC-protocol side of incremental signing:
/// the dangerous presignature / nonce bookkeeping lives here, behind a
/// module boundary, and is embedded (field-private) inside the BTC
/// `WithdrawalTransaction` rather than stored as a separate object.
///
/// Each input occupies one slot that is either:
///   - `Pending(presig)` — awaiting its signature; carries the presignature
///     it will consume (valid within `epoch`), or
///   - `Signed(bytes)`   — the completed per-input MPC signature.
///
/// Signatures are filled in any order (`record`), survive leader timeouts /
/// rotation / restart because they live on chain, and survive committee
/// reconfiguration: on an epoch change only the still-`Pending` slots are
/// reassigned fresh presignatures (`reallocate`); `Signed` slots are final
/// and epoch-independent (the committee group key is stable across rotation).
///
/// NONCE SAFETY (a violation leaks the group secret share):
///   - every `Pending` index is unique within an epoch — a `Presig` can only
///     be minted by the monotonic `PresigAllocator` (reset only at reconfig)
///     and is not `copy`, so each minted index lands in at most one slot;
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
const EAllocationMismatch: vector<u8> = b"presig count does not match slot count";
#[error]
const ENotComplete: vector<u8> = b"signing batch is not fully signed";

// ~~~~~~~ Structs ~~~~~~~

/// The presignature index one input's signature consumes. Only
/// `PresigAllocator::allocate` mints these, and the type is deliberately not
/// `copy`: a presig moves into exactly one slot, so handing the same index to
/// two inputs does not type-check. Dropping one is harmless (the presignature
/// is merely wasted). A one-field struct, so its BCS encoding is exactly the
/// `u64` index that the off-chain mirror reads.
public struct Presig has drop, store {
    index: u64,
}

/// Monotonic per-epoch presignature allocator, embedded in `Hashi`. Recovering
/// nodes read `num_consumed` to derive `(batch_index, index_in_batch)`, so its
/// BCS layout (a single `u64`) is mirrored off chain.
public struct PresigAllocator has store {
    /// Number of presignatures consumed in the current epoch.
    num_consumed: u64,
}

/// Per-input signing slot.
public enum MpcSig has drop, store {
    /// Awaiting signature; holds the presignature this input will consume,
    /// valid within the owning batch's `epoch`.
    Pending(Presig),
    /// Completed per-input MPC Schnorr signature bytes.
    Signed(vector<u8>),
}

/// Out-of-order accumulator for one withdrawal's per-input MPC signatures.
/// Owned by this module (fields are private); embedded in the BTC
/// `WithdrawalTransaction`.
public struct SigningBatch has store {
    /// One slot per input; same length/order as the withdrawal's inputs.
    signatures: vector<MpcSig>,
    /// Epoch the `Pending` presignature indices belong to.
    epoch: u64,
}

// ~~~~~~~ Package Functions ~~~~~~~

// === Allocation ===

public(package) fun new_allocator(): PresigAllocator {
    PresigAllocator { num_consumed: 0 }
}

/// Mint `count` fresh presigs from the next contiguous block, so presig `j`
/// has index `start + j`.
public(package) fun allocate(self: &mut PresigAllocator, count: u64): vector<Presig> {
    let start = self.num_consumed;
    self.num_consumed = start + count;
    vector::tabulate!(count, |j| Presig { index: start + j })
}

/// Restart numbering for a new epoch, whose committee generates a fresh
/// presignature pool. Only sound at reconfig, when every `Pending` slot of the
/// old epoch is stale and must be `reallocate`d before signing.
public(package) fun reset(self: &mut PresigAllocator) {
    self.num_consumed = 0;
}

// === Constructors ===

/// Create a batch with one `Pending` slot per presig, in order. `num_inputs`
/// is the caller's own input count, which is independent of the allocation;
/// it cross-checks that the presigs were allocated for this many inputs,
/// since the batch is the last place a miscounted allocation is visible.
public(package) fun new(num_inputs: u64, presigs: vector<Presig>, epoch: u64): SigningBatch {
    assert!(num_inputs > 0, EZeroInputs);
    assert!(presigs.length() == num_inputs, EAllocationMismatch);
    let signatures = presigs.map!(|presig| MpcSig::Pending(presig));
    SigningBatch { signatures, epoch }
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
/// is NOT enforced here — it lives in presig allocation (`allocate`) and in
/// the off-chain rule that each presig index signs exactly one sighash and a
/// stale-epoch index is never signed with. Caller must cert-gate the
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

/// Reassign fresh presignatures, allocated in `current_epoch`, to every
/// still-`Pending` slot. `Signed` slots are untouched (their signatures are
/// final and epoch-independent). The j-th still-`Pending` slot (ascending
/// input order) gets the j-th presig; `presigs` must hold exactly
/// `pending_count()` presigs so that no slot keeps a stale-epoch index.
/// Aborts if the batch is not actually stale (guards against double reallocation).
public(package) fun reallocate(
    self: &mut SigningBatch,
    mut presigs: vector<Presig>,
    current_epoch: u64,
) {
    assert!(self.epoch != current_epoch, ENotStale);
    assert!(presigs.length() == pending_count(self), EAllocationMismatch);
    // Popping from the back walks the slots in reverse to keep the j-th presig
    // on the j-th pending slot.
    let mut i = self.signatures.length();
    while (i > 0) {
        i = i - 1;
        if (self.signatures.borrow(i).is_pending()) {
            *self.signatures.borrow_mut(i) = MpcSig::Pending(presigs.pop_back());
        };
    };
    presigs.destroy_empty();
    self.epoch = current_epoch;
}

// === Views ===

/// Number of still-`Pending` slots (the count that must be re-presigned on a
/// stale-epoch `reallocate`).
public(package) fun pending_count(self: &SigningBatch): u64 {
    self.signatures.length() - self.signed_count()
}

/// True once every input has a signature.
public(package) fun is_complete(self: &SigningBatch): bool {
    self.signed_count() == self.signatures.length()
}

/// Number of `Signed` slots. Derived by counting (not stored) so it can never
/// fall out of sync with `signatures`, which `reallocate`'s presig count check
/// relies on.
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

fun is_pending(self: &MpcSig): bool {
    match (self) {
        MpcSig::Pending(_) => true,
        MpcSig::Signed(_) => false,
    }
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
public(package) fun new_allocator_for_testing(num_consumed: u64): PresigAllocator {
    PresigAllocator { num_consumed }
}

#[test_only]
public(package) fun destroy_allocator_for_testing(self: PresigAllocator) {
    let PresigAllocator { num_consumed: _ } = self;
}

#[test_only]
public(package) fun num_consumed(self: &PresigAllocator): u64 {
    self.num_consumed
}

/// Presigs `base`, `base + 1`, and so on, as a fresh allocator that had
/// already consumed `base` presignatures would mint them.
#[test_only]
public(package) fun presigs_for_testing(base: u64, count: u64): vector<Presig> {
    let mut allocator = new_allocator_for_testing(base);
    let presigs = allocator.allocate(count);
    allocator.destroy_allocator_for_testing();
    presigs
}

/// The presignature index input `i` will use, or `none` if already signed.
#[test_only]
public(package) fun pending_index(self: &SigningBatch, i: u64): Option<u64> {
    assert!(i < self.signatures.length(), EIndexOutOfRange);
    match (self.signatures.borrow(i)) {
        MpcSig::Pending(presig) => option::some(presig.index),
        MpcSig::Signed(_) => option::none(),
    }
}

#[test_only]
public(package) fun destroy_for_testing(self: SigningBatch) {
    let SigningBatch { signatures: _, epoch: _ } = self;
}
