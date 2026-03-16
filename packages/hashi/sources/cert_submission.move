module hashi::cert_submission;

use hashi::{hashi::Hashi, tob::ProtocolType};

entry fun submit_dkg_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
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
        signature,
        signers_bitmap,
        ctx,
    );
}

entry fun submit_rotation_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
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
        signature,
        signers_bitmap,
        ctx,
    );
}

entry fun submit_nonce_cert(
    hashi: &mut Hashi,
    epoch: u64,
    batch_index: u32,
    dealer: address,
    messages_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
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
        signature,
        signers_bitmap,
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
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    assert!(ctx.sender() == dealer);
    assert!(hashi.committee_set().has_member(dealer));
    let pending = hashi.committee_set().pending_epoch_change();
    assert!(epoch == hashi.committee_set().epoch() || pending.contains(&epoch));
    let epoch_certs = hashi.epoch_certs(key, protocol_type, ctx);
    hashi::tob::submit_cert(
        epoch_certs,
        epoch,
        dealer,
        messages_hash,
        signature,
        signers_bitmap,
    );
}

entry fun destroy_all_certs(hashi: &mut Hashi, epoch: u64, batch_index: Option<u32>) {
    hashi.config().assert_version_enabled();
    let key = hashi::tob::tob_key(epoch, batch_index);
    let current_epoch = hashi.committee_set().epoch();
    let epoch_certs: hashi::tob::EpochCertsV1 = hashi.tob_mut().remove(key);
    hashi::tob::destroy_all(epoch_certs, current_epoch);
}
