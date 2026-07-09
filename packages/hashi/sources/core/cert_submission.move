// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::cert_submission;

use hashi::{committee::CommitteeSignature, hashi::Hashi, tob::ProtocolType};

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
    ctx: &mut TxContext,
) {
    let key = hashi::tob::tob_key(
        epoch,
        option::some(batch_index),
        hashi::tob::protocol_type_nonce_generation(),
    );
    submit_cert_internal(hashi, key, epoch, dealer, messages_hash, &cert, ctx);
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
    hashi.versioning().assert_version_enabled();
    // The dealer's own validator key, or the operator key it has delegated to,
    // may submit the dealer's certificate. `member_authorized` also enforces
    // that the dealer is a registered committee member.
    assert!(hashi.committee_set().member_authorized(dealer, ctx));
    let pending = hashi.committee_set().pending_epoch_change();
    assert!(epoch == hashi.committee_set().epoch() || pending.contains(&epoch));
    let epoch_certs = hashi.epoch_certs(key, ctx);
    hashi::tob::submit_cert_with_signature(
        epoch_certs,
        epoch,
        dealer,
        messages_hash,
        cert,
    );
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
    let key = hashi::tob::tob_key(epoch, batch_index, protocol_type);
    let current_epoch = hashi.committee_set().epoch();
    let epoch_certs: hashi::tob::EpochCertsV1 = hashi.tob_mut().remove(key);
    hashi::tob::destroy_all(epoch_certs, current_epoch);
}
