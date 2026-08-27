// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::cert_submission;

use hashi::{committee::CommitteeSignature, hashi::Hashi, tob::ProtocolType};

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
const EUnsupportedCertBucketLayout: vector<u8> =
    b"TOB cert bucket has a layout this package version cannot prune";

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

/// Deprecated entry, retained as defense in depth. Non-public `entry`
/// functions are not linkage-checked, so the upgrade policy would permit
/// deleting this; it is kept so any historical caller path routes through
/// the protocol-specific floors below instead of the legacy `+2` rule.
/// `ProtocolType` has no public constructors and cannot currently be
/// supplied as a PTB pure argument, so this entry is unreachable today;
/// the routing guards against that restriction ever loosening.
entry fun destroy_all_certs(
    hashi: &mut Hashi,
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
) {
    if (protocol_type.is_nonce_generation()) {
        destroy_nonce_certs(hashi, epoch, batch_index.destroy_some());
    } else {
        destroy_key_gen_certs(hashi, epoch);
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
    destroy_bare_bucket_if_present(
        hashi,
        hashi::tob::tob_key(epoch, option::none(), hashi::tob::protocol_type_dkg()),
        current_epoch,
    );
    destroy_bare_bucket_if_present(
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
    destroy_nonce_bucket_if_present(
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

/// Remove a key-generation bucket only when it has the layout this version
/// understands. An absent bucket is an idempotent no-op; a present bucket with
/// an unknown layout aborts loudly so the off-chain sweep cannot report false
/// success while state keeps accumulating.
fun destroy_bare_bucket_if_present(hashi: &mut Hashi, key: hashi::tob::TobKey, current_epoch: u64) {
    let tob = hashi.tob_mut();
    if (tob.contains_with_type<hashi::tob::TobKey, hashi::tob::EpochCertsV1>(key)) {
        let epoch_certs: hashi::tob::EpochCertsV1 = tob.remove(key);
        hashi::tob::destroy_all(epoch_certs, current_epoch);
    } else {
        assert!(!tob.contains(key), EUnsupportedCertBucketLayout);
    }
}

/// Nonce buckets may use either the legacy bare layout or the stamped layout
/// introduced in v2. As above, absence is idempotent and an unknown present
/// layout aborts instead of being silently skipped.
fun destroy_nonce_bucket_if_present(
    hashi: &mut Hashi,
    key: hashi::tob::TobKey,
    current_epoch: u64,
) {
    let tob = hashi.tob_mut();
    if (tob.contains_with_type<hashi::tob::TobKey, hashi::tob::EpochCertsV1>(key)) {
        let epoch_certs: hashi::tob::EpochCertsV1 = tob.remove(key);
        hashi::tob::destroy_all(epoch_certs, current_epoch);
    } else if (tob.contains_with_type<hashi::tob::TobKey, hashi::tob::StampedEpochCertsV1>(key)) {
        let epoch_certs: hashi::tob::StampedEpochCertsV1 = tob.remove(key);
        hashi::tob::destroy_all_stamped(epoch_certs, current_epoch);
    } else {
        assert!(!tob.contains(key), EUnsupportedCertBucketLayout);
    }
}

#[test_only]
public fun destroy_all_certs_for_testing(
    hashi: &mut Hashi,
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
) {
    destroy_all_certs(hashi, epoch, batch_index, protocol_type)
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
