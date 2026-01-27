module hashi::cert_submission;

use hashi::hashi::Hashi;

// TODO: Make threshold configurable.
const THRESHOLD_NUMERATOR: u64 = 2;
const THRESHOLD_DENOMINATOR: u64 = 3;

entry fun submit_dkg_cert(
    hashi: &mut Hashi,
    epoch: u64,
    dealer: address,
    message_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    ctx: &mut TxContext,
) {
    hashi.config().assert_version_enabled();
    assert!(epoch == hashi.committee_set().epoch());
    let (epoch_certs, committee) = hashi.epoch_certs_and_committee(epoch, ctx);
    let threshold = (committee.total_weight() * THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR);
    hashi::tob::submit_dkg_cert(
        epoch_certs,
        committee,
        epoch,
        dealer,
        message_hash,
        signature,
        signers_bitmap,
        threshold,
    );
}

entry fun destroy_all_dkg_certs(hashi: &mut Hashi, epoch: u64) {
    hashi.config().assert_version_enabled();
    let current_epoch = hashi.committee_set().epoch();
    let epoch_certs: hashi::tob::EpochCertsV1 = hashi.tob_mut().remove(epoch);
    hashi::tob::destroy_all(epoch_certs, current_epoch);
}
