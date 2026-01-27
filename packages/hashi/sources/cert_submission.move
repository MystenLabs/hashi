module hashi::cert_submission;

use hashi::{hashi::Hashi, tob::ProtocolType};

// TODO: Make threshold configurable.
const THRESHOLD_NUMERATOR: u64 = 2;
const THRESHOLD_DENOMINATOR: u64 = 3;

entry fun submit_dkg_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    ctx: &mut TxContext,
) {
    submit_cert_internal(
        hashi,
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
    submit_cert_internal(
        hashi,
        epoch,
        hashi::tob::protocol_type_key_rotation(),
        dealer,
        messages_hash,
        signature,
        signers_bitmap,
        ctx,
    );
}

fun submit_cert_internal(
    hashi: &mut Hashi,
    epoch: u64,
    protocol_type: ProtocolType,
    dealer: address,
    messages_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    assert!(epoch == hashi.committee_set().epoch());
    let (epoch_certs, committee) = hashi.epoch_certs_and_committee(epoch, protocol_type, ctx);
    let threshold = (committee.total_weight() as u64) * THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR;
    hashi::tob::submit_cert(
        epoch_certs,
        committee,
        epoch,
        dealer,
        messages_hash,
        signature,
        signers_bitmap,
        threshold,
    );
}

entry fun destroy_all_certs(hashi: &mut Hashi, epoch: u64) {
    hashi.config().assert_version_enabled();
    let current_epoch = hashi.committee_set().epoch();
    let epoch_certs: hashi::tob::EpochCertsV1 = hashi.tob_mut().remove(epoch);
    hashi::tob::destroy_all(epoch_certs, current_epoch);
}
