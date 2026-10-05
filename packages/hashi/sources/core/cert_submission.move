// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::cert_submission;

use hashi::{committee::CommitteeSignature, hashi::Hashi};
use sui::random::Random;

// ~~~~~~~ Constants ~~~~~~~

/// Key-generation cert buckets stay on-chain until their Sui epoch number is
/// at least 8 below the current one. This strictly exceeds the node DB's
/// retention window (`RETENTION_EXTRA_EPOCHS = 7` in `db.rs`, anchored to the
/// same committee-epoch counter): buckets hold only committee certificates
/// over dealer-message hashes — the dealt payloads live exclusively in node
/// DBs — so a bucket is only useful alongside DB material, and every epoch
/// whose payloads may still exist under that window keeps its bucket. The
/// previous committee's bucket is protected separately and at any age by
/// `is_before_previous_committee`, mirroring the DB pruner's previous-epoch
/// exemption. This is an epoch-number distance, not a count of finalized
/// committee generations (committee epochs can gap). Enforced on-chain
/// because destruction is permissionless.
const KEY_GEN_CERT_RETENTION_EPOCHS: u64 = 8;

/// Nonce cert buckets are only ever read during their own epoch; +2 mirrors
/// the `tob::destroy_all` backstop.
const NONCE_CERT_MIN_AGE_EPOCHS: u64 = 2;

// ~~~~~~~ Errors ~~~~~~~

#[error]
const ETooEarlyToDestroyNonceCerts: vector<u8> =
    b"Nonce cert buckets may only be destroyed two epochs after their epoch";
#[error]
const ETooEarlyToDestroyKeyGenCerts: vector<u8> =
    b"Key-generation cert buckets are retained for break-glass key recovery";
#[error]
const EKeyGenCertsStillNeeded: vector<u8> =
    b"Key-generation cert buckets must be strictly older than the previous committee, whose bucket seeds the next rotation";
#[error]
const ENoNonceBucket: vector<u8> = b"No nonce cert bucket exists for this batch";
#[error]
const EDealerNotInCommittee: vector<u8> =
    b"The dealer is not a member of the committee that deals this certificate";

// ~~~~~~~ Structs ~~~~~~~

public struct PresigDealerSetMessage has copy, drop, store {
    epoch: u64,
    batch_index: u32,
    dealer_set_digest: vector<u8>,
}

// ~~~~~~~ Entry Functions ~~~~~~~

entry fun submit_dkg_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    cert: CommitteeSignature,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    let key = hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_dkg());
    submit_cert_internal(hashi, key, epoch, dealer, messages_hash, &cert, clock, ctx);
}

entry fun submit_rotation_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    cert: CommitteeSignature,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    let key = hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_key_rotation());
    submit_cert_internal(hashi, key, epoch, dealer, messages_hash, &cert, clock, ctx);
}

entry fun submit_nonce_cert(
    hashi: &mut Hashi,
    epoch: u64,
    batch_index: u32,
    dealer: address,
    messages_hash: vector<u8>,
    cert: CommitteeSignature,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    let key = hashi::tob::tob_key(
        epoch,
        option::some(batch_index),
        hashi::tob::protocol_type_nonce_generation(),
    );
    submit_cert_internal(hashi, key, epoch, dealer, messages_hash, &cert, clock, ctx);
}

entry fun submit_presig_dealer_set(
    hashi: &mut Hashi,
    batch_index: u32,
    dealer_set_digest: vector<u8>,
    cert: CommitteeSignature,
    r: &Random,
    ctx: &mut TxContext,
) {
    let mut rng = sui::random::new_generator(r, ctx);
    let randomness = rng.generate_bytes(32);
    submit_presig_dealer_set_internal(hashi, batch_index, dealer_set_digest, cert, randomness);
}

/// Destroy the key-generation (DKG or rotation) cert buckets of `epoch`.
/// Garbage collection: permissionless and deliberately NOT gated on
/// pause/reconfig. It moves no funds and must stay callable during a pause
/// or a reconfiguration.
///
/// A key-generation bucket stays live longer than its certs' epoch: the NEXT
/// rotation reads the PREVIOUS committee's bucket to seed the handoff, and
/// committee epochs can gap, so an age floor alone cannot identify the
/// previous committee's bucket. Both floors are asserted unconditionally
/// (premature calls abort even when the bucket is absent); an
/// eligible-but-absent bucket is a no-op so batched GC transactions and
/// permissionless racers cannot poison each other.
entry fun destroy_key_gen_certs(hashi: &mut Hashi, epoch: u64) {
    hashi.versioning().assert_version_enabled();
    let current_epoch = hashi.committee_set().epoch();
    assert!(current_epoch >= epoch + KEY_GEN_CERT_RETENTION_EPOCHS, ETooEarlyToDestroyKeyGenCerts);
    assert!(hashi.committee_set().is_before_previous_committee(epoch), EKeyGenCertsStillNeeded);
    // One entry covers both key-generation protocols: callers never need to
    // know whether `epoch` was a genesis (DKG) or rotation epoch.
    destroy_bucket_if_present(
        hashi,
        hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_dkg()),
        current_epoch,
    );
    destroy_bucket_if_present(
        hashi,
        hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_key_rotation()),
        current_epoch,
    );
}

/// Destroy the nonce-generation cert bucket of `(epoch, batch_index)`.
/// Garbage collection: permissionless and deliberately NOT gated on
/// pause/reconfig. It moves no funds and must stay callable during a pause
/// or a reconfiguration. Nonce buckets are only ever read during their own
/// epoch, so no committee-awareness is needed. The floor is asserted
/// unconditionally; an eligible-but-absent bucket is a no-op (see
/// `destroy_key_gen_certs`).
entry fun destroy_nonce_certs(hashi: &mut Hashi, epoch: u64, batch_index: u32) {
    hashi.versioning().assert_version_enabled();
    let current_epoch = hashi.committee_set().epoch();
    assert!(current_epoch >= epoch + NONCE_CERT_MIN_AGE_EPOCHS, ETooEarlyToDestroyNonceCerts);
    destroy_bucket_if_present(
        hashi,
        hashi::tob::tob_key(
            epoch,
            option::some(batch_index),
            hashi::tob::protocol_type_nonce_generation(),
        ),
        current_epoch,
    );
}

// ~~~~~~~ Private Functions ~~~~~~~

fun submit_presig_dealer_set_internal(
    hashi: &mut Hashi,
    batch_index: u32,
    dealer_set_digest: vector<u8>,
    cert: CommitteeSignature,
    randomness: vector<u8>,
) {
    hashi.versioning().assert_version_enabled();
    let epoch = hashi.committee_set().epoch();
    hashi.verify(
        hashi::intent::presig_dealer_set(),
        PresigDealerSetMessage { epoch, batch_index, dealer_set_digest: copy dealer_set_digest },
        cert,
    );
    let key = hashi::tob::tob_key(
        epoch,
        option::some(batch_index),
        hashi::tob::protocol_type_nonce_generation(),
    );
    let tob = hashi.tob_mut();
    assert!(tob.contains(key), ENoNonceBucket);
    let bucket: &mut hashi::tob::EpochCertsV1 = tob.borrow_mut(key);
    if (bucket.is_sealed()) {
        return
    };
    bucket.seal(randomness, dealer_set_digest);
}

/// Remove and drain the bucket stored under `key`. An absent bucket is an
/// idempotent no-op. Presence is probed without a value type, so a value that
/// is not an `EpochCertsV1` aborts in the typed `remove` instead of being
/// skipped.
fun destroy_bucket_if_present(hashi: &mut Hashi, key: hashi::tob::TobKey, current_epoch: u64) {
    let tob = hashi.tob_mut();
    if (tob.contains(key)) {
        let epoch_certs: hashi::tob::EpochCertsV1 = tob.remove(key);
        hashi::tob::destroy_all(epoch_certs, current_epoch);
    }
}

fun submit_cert_internal(
    hashi: &mut Hashi,
    key: hashi::tob::TobKey,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    cert: &CommitteeSignature,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    assert_can_submit(hashi, key, epoch, dealer, ctx);
    let epoch_certs = hashi.epoch_certs(key, ctx);
    hashi::tob::submit_cert_with_signature(
        epoch_certs,
        epoch,
        dealer,
        messages_hash,
        cert,
        clock.timestamp_ms(),
    );
}

fun assert_can_submit(
    hashi: &Hashi,
    key: hashi::tob::TobKey,
    epoch: u64,
    dealer: address,
    ctx: &TxContext,
) {
    hashi.versioning().assert_version_enabled();
    let committee_set = hashi.committee_set();
    assert!(committee_set.member_authorized(dealer, ctx));
    let pending = committee_set.pending_epoch_change();
    assert!(epoch == committee_set.epoch() || pending.contains(&epoch));
    let in_dealing_committee = if (
        key.protocol_type() == hashi::tob::protocol_type_key_rotation()
    ) {
        let dealers_epoch = if (pending.contains(&epoch)) {
            option::some(committee_set.epoch())
        } else {
            committee_set.committee_epoch_before(epoch)
        };
        dealers_epoch.map!(|e| in_committee(hashi, e, dealer)).destroy_or!(false)
    } else {
        in_committee(hashi, epoch, dealer)
    };
    assert!(in_dealing_committee, EDealerNotInCommittee);
}

fun in_committee(hashi: &Hashi, epoch: u64, dealer: address): bool {
    let committee_set = hashi.committee_set();
    committee_set.has_committee(epoch) && committee_set.get_committee(epoch).has_member(&dealer)
}

#[test_only]
public fun submit_presig_dealer_set_for_testing(
    hashi: &mut Hashi,
    batch_index: u32,
    dealer_set_digest: vector<u8>,
    cert: CommitteeSignature,
    seed: vector<u8>,
) {
    let mut rng = sui::random::new_generator_from_seed_for_testing(seed);
    let randomness = rng.generate_bytes(32);
    submit_presig_dealer_set_internal(hashi, batch_index, dealer_set_digest, cert, randomness);
}

#[test_only]
public fun new_presig_dealer_set_message(
    epoch: u64,
    batch_index: u32,
    dealer_set_digest: vector<u8>,
): PresigDealerSetMessage {
    PresigDealerSetMessage { epoch, batch_index, dealer_set_digest }
}
