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
    let key = hashi::tob::tob_key(epoch, option::none());
    submit_cert_internal(
        hashi,
        key,
        epoch,
        hashi::tob::protocol_type_dkg(),
        dealer,
        messages_hash,
        &cert,
        ctx,
    );
}

entry fun submit_rotation_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    cert: CommitteeSignature,
    ctx: &mut TxContext,
) {
    let key = hashi::tob::tob_key(epoch, option::none());
    submit_cert_internal(
        hashi,
        key,
        epoch,
        hashi::tob::protocol_type_key_rotation(),
        dealer,
        messages_hash,
        &cert,
        ctx,
    );
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
    let key = hashi::tob::tob_key(epoch, option::some(batch_index));
    submit_cert_internal(
        hashi,
        key,
        epoch,
        hashi::tob::protocol_type_nonce_generation(),
        dealer,
        messages_hash,
        &cert,
        ctx,
    );
}

fun submit_cert_internal(
    hashi: &mut Hashi,
    key: hashi::tob::TobKey,
    epoch: u64,
    protocol_type: ProtocolType,
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
    let epoch_certs = hashi.epoch_certs(key, protocol_type, ctx);
    hashi::tob::submit_cert_with_signature(
        epoch_certs,
        epoch,
        dealer,
        messages_hash,
        cert,
    );
}

entry fun destroy_all_certs(hashi: &mut Hashi, epoch: u64, batch_index: Option<u32>) {
    hashi.versioning().assert_version_enabled();
    let key = hashi::tob::tob_key(epoch, batch_index);
    let current_epoch = hashi.committee_set().epoch();
    let epoch_certs: hashi::tob::EpochCertsV1 = hashi.tob_mut().remove(key);
    hashi::tob::destroy_all(epoch_certs, current_epoch);
}
