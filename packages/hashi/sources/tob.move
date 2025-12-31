/// Totally Ordered Broadcast (TOB)

module hashi::tob;

use hashi::committee::{Committee, CertifiedMessage};
use sui::linked_table::{Self, LinkedTable};

const EWrongEpoch: u64 = 0;
const ETooEarlyToDestroy: u64 = 1;

/// Certificates for a single epoch.
public struct EpochCerts has store {
    epoch: u64,
    /// DKG certificates v1 indexed by dealer address (first-cert-wins).
    dkg_certs_v1: LinkedTable<address, CertifiedMessage<DkgDealerMessageHashV1>>,
}

public struct DkgDealerMessageHashV1 has copy, drop, store {
    dealer_address: address,
    message_hash: vector<u8>,
}

public(package) fun create(epoch: u64, ctx: &mut TxContext): EpochCerts {
    EpochCerts {
        epoch,
        dkg_certs_v1: linked_table::new(ctx),
    }
}

/// Remove all DKG certificates and destroy the EpochCerts in one transaction.
/// Can only be called when current_epoch >= epoch + 2.
public(package) fun destroy_all(epoch_certs: EpochCerts, current_epoch: u64) {
    let EpochCerts { epoch, mut dkg_certs_v1 } = epoch_certs;
    assert!(current_epoch >= epoch + 2, ETooEarlyToDestroy);
    while (!dkg_certs_v1.is_empty()) {
        let (_, _) = dkg_certs_v1.pop_front();
    };
    dkg_certs_v1.destroy_empty();
}

public(package) fun submit_dkg_cert(
    epoch_certs: &mut EpochCerts,
    committee: &Committee,
    epoch: u64,
    dealer: address,
    message_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    threshold: u16,
) {
    assert!(epoch == epoch_certs.epoch, EWrongEpoch);
    if (epoch_certs.dkg_certs_v1.contains(dealer)) {
        return
    };
    let message = DkgDealerMessageHashV1 { dealer_address: dealer, message_hash };
    let sig = hashi::committee::new_committee_signature(epoch, signature, signers_bitmap);
    let cert = committee.verify_certificate(message, sig, threshold);
    epoch_certs.dkg_certs_v1.push_back(dealer, cert);
}
