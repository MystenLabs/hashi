// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::cert_submission;

use hashi::{committee::CommitteeSignature, hashi::Hashi, tob::ProtocolType};

// ~~~~~~~ Constants ~~~~~~~

/// Key-generation cert buckets for the last N committee epochs are retained
/// for break-glass key recovery: the `key_recovery` internal tool pairs a
/// node's local DB — which keeps dealer/rotation messages for the trailing 7
/// epochs — with the on-chain bucket of the epoch being reconstructed.
/// Enforced on-chain because destruction is permissionless.
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
    b"The previous committee's key-generation certs seed the next rotation";

// ~~~~~~~ Entry Functions ~~~~~~~

entry fun submit_dkg_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    cert: CommitteeSignature,
    ctx: &mut TxContext,
) {
    let key = hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_dkg());
    submit_cert_internal(hashi, key, epoch, dealer, messages_hash, &cert, ctx);
}

entry fun submit_rotation_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    cert: CommitteeSignature,
    ctx: &mut TxContext,
) {
    let key = hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_key_rotation());
    submit_cert_internal(hashi, key, epoch, dealer, messages_hash, &cert, ctx);
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
    submit_stamped_cert_internal(hashi, key, epoch, dealer, messages_hash, &cert, clock, ctx);
}

/// Garbage collection: deliberately NOT gated on pause/reconfig — cert
/// buckets old enough to destroy (see `tob::destroy_all`) carry no live
/// state, and GC must stay callable during an emergency pause.
entry fun destroy_all_certs(
    hashi: &mut Hashi,
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
) {
    hashi.versioning().assert_version_enabled();
    let is_nonce_generation = protocol_type.is_nonce_generation();
    let key = hashi::tob::tob_key(epoch, batch_index, protocol_type);
    let current_epoch = hashi.committee_set().epoch();
    if (is_nonce_generation) {
        let epoch_certs: hashi::tob::StampedEpochCertsV1 = hashi.tob_mut().remove(key);
        hashi::tob::destroy_all_stamped(epoch_certs, current_epoch);
    } else {
        let epoch_certs: hashi::tob::EpochCertsV1 = hashi.tob_mut().remove(key);
        hashi::tob::destroy_all(epoch_certs, current_epoch);
    };
}

/// Destroy the key-generation (DKG or rotation) cert buckets of `epoch`.
/// Garbage collection: permissionless and deliberately NOT gated on
/// pause/reconfig — see `destroy_all_certs`.
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
/// pause/reconfig — see `destroy_all_certs`. Nonce buckets are only ever
/// read during their own epoch, so no committee-awareness is needed. The
/// floor is asserted unconditionally; an eligible-but-absent bucket is a
/// no-op (see `destroy_key_gen_certs`).
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

/// Remove and destroy the bucket at `key` if one is stored as an
/// `EpochCertsV1`; otherwise do nothing. Probing by STORED type (not by the
/// requested protocol) means a bucket written under a future value layout is
/// left in place for the module version that understands it, instead of
/// aborting the whole transaction or being destroyed as the wrong type.
fun destroy_bucket_if_present(hashi: &mut Hashi, key: hashi::tob::TobKey, current_epoch: u64) {
    let tob = hashi.tob_mut();
    if (tob.contains_with_type<hashi::tob::TobKey, hashi::tob::EpochCertsV1>(key)) {
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
    ctx: &mut TxContext,
) {
    assert_can_submit(hashi, epoch, dealer, ctx);
    let epoch_certs = hashi.epoch_certs(key, ctx);
    hashi::tob::submit_cert_with_signature(epoch_certs, epoch, dealer, messages_hash, cert);
}

fun submit_stamped_cert_internal(
    hashi: &mut Hashi,
    key: hashi::tob::TobKey,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    cert: &CommitteeSignature,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
) {
    assert_can_submit(hashi, epoch, dealer, ctx);
    if (hashi.nonce_write_stays_bare(key)) {
        let epoch_certs = hashi.epoch_certs(key, ctx);
        hashi::tob::submit_cert_with_signature(epoch_certs, epoch, dealer, messages_hash, cert);
    } else {
        let epoch_certs = hashi.epoch_certs_stamped(key, ctx);
        hashi::tob::submit_stamped_cert_with_signature(
            epoch_certs,
            epoch,
            dealer,
            messages_hash,
            cert,
            clock.timestamp_ms(),
        );
    };
}

fun assert_can_submit(hashi: &Hashi, epoch: u64, dealer: address, ctx: &TxContext) {
    hashi.versioning().assert_version_enabled();
    assert!(hashi.committee_set().member_authorized(dealer, ctx));
    let pending = hashi.committee_set().pending_epoch_change();
    assert!(epoch == hashi.committee_set().epoch() || pending.contains(&epoch));
}
