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
///   - every index in every `Pending` pair is unique within an epoch — a
///     `PresigPair` can only be minted by the monotonic `PresigAllocator`
///     (reset only at reconfig) and is not `copy`, so each minted pair lands
///     in at most one slot;
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
const EAllocationMismatch: vector<u8> = b"presig pair count does not match slot count";
#[error]
const ENotComplete: vector<u8> = b"signing batch is not fully signed";

// ~~~~~~~ Constants ~~~~~~~

/// Presignatures consumed by one input's signature.
const PRESIGS_PER_INPUT: u64 = 2;

// ~~~~~~~ Structs ~~~~~~~

/// The two presignature indices one input's signature consumes, in the order
/// the signer binds them. Only `PresigAllocator::allocate` mints these, and
/// the type is deliberately not `copy`: a pair moves into exactly one slot, so
/// handing the same indices to two inputs does not type-check. Dropping one is
/// harmless (the presignatures are merely wasted).
public struct PresigPair has drop, store {
    first: u64,
    second: u64,
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

// === Allocation ===

public(package) fun new_allocator(): PresigAllocator {
    PresigAllocator { num_consumed: 0 }
}

/// Mint `count` fresh pairs from the next contiguous block, so pair `j` is
/// `(start + 2j, start + 2j + 1)`. Every block is a whole number of pairs, so
/// `num_consumed` stays even and a pair never straddles an even-sized
/// presignature batch; the signer still takes a pair atomically in case a
/// batch is odd-sized.
public(package) fun allocate(self: &mut PresigAllocator, count: u64): vector<PresigPair> {
    let mut pairs = vector[];
    count.do!(|_| {
        let first = self.num_consumed;
        pairs.push_back(PresigPair { first, second: first + 1 });
        self.num_consumed = first + PRESIGS_PER_INPUT;
    });
    pairs
}

/// Restart numbering for a new epoch, whose committee generates a fresh
/// presignature pool. Only sound at reconfig, when every `Pending` slot of the
/// old epoch is stale and must be `reallocate`d before signing.
public(package) fun reset(self: &mut PresigAllocator) {
    self.num_consumed = 0;
}

public(package) fun num_consumed(self: &PresigAllocator): u64 {
    self.num_consumed
}

// === Constructors ===

/// Create a batch with one `Pending` slot per pair, in order. `num_inputs` is
/// the caller's input count; it must equal the number of pairs so that no
/// input is left without a pair.
public(package) fun new(num_inputs: u64, pairs: vector<PresigPair>, epoch: u64): SigningBatch {
    assert!(num_inputs > 0, EZeroInputs);
    assert!(pairs.length() == num_inputs, EAllocationMismatch);
    let signatures = pairs.map!(|pair| MpcSig::Pending(pair));
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
/// is NOT enforced here — it lives in pair allocation (`allocate`)
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

/// Reassign fresh presignature pairs, allocated in `current_epoch`, to every
/// still-`Pending` slot. `Signed` slots are untouched (their signatures are
/// final and epoch-independent). The j-th still-`Pending` slot (ascending
/// input order) gets the j-th pair; `pairs` must hold exactly
/// `pending_count()` pairs so that no slot keeps a stale-epoch pair.
/// Aborts if the batch is not actually stale (guards against double reallocation).
public(package) fun reallocate(
    self: &mut SigningBatch,
    mut pairs: vector<PresigPair>,
    current_epoch: u64,
) {
    assert!(self.epoch != current_epoch, ENotStale);
    assert!(pairs.length() == pending_count(self), EAllocationMismatch);
    // Popping from the back walks the slots in reverse to keep the j-th pair
    // on the j-th pending slot.
    let mut i = self.signatures.length();
    while (i > 0) {
        i = i - 1;
        if (self.signatures.borrow(i).is_pending()) {
            *self.signatures.borrow_mut(i) = MpcSig::Pending(pairs.pop_back());
        };
    };
    pairs.destroy_empty();
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
/// fall out of sync with `signatures`, which `reallocate`'s pair count check
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

/// True if input `i` is pending on exactly the pair `(first, second)`.
#[test_only]
public(package) fun is_pending_on(self: &SigningBatch, i: u64, first: u64, second: u64): bool {
    assert!(i < self.signatures.length(), EIndexOutOfRange);
    match (self.signatures.borrow(i)) {
        MpcSig::Pending(pair) => pair.first == first && pair.second == second,
        MpcSig::Signed(_) => false,
    }
}

#[test_only]
public(package) fun destroy_for_testing(self: SigningBatch) {
    let SigningBatch { signatures: _, epoch: _ } = self;
}
