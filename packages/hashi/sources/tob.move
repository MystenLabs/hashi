/// Totally Ordered Broadcast (TOB)

module hashi::tob;

use hashi::committee::Committee;
use sui::linked_table::{Self, LinkedTable};

const EWrongEpoch: u64 = 0;
const ETooEarlyToDestroy: u64 = 1;

/// Certificates for a single epoch.
public struct EpochCerts has store {
    epoch: u64,
    /// DKG certificates indexed by dealer address (first-cert-wins).
    dkg_certs: LinkedTable<address, DkgCertV1>,
}

public struct DkgCertV1 has copy, store {
    message_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
}

public struct DkgDealerMessageHash has copy, drop {
    dealer_address: address,
    message_hash: vector<u8>,
}

public(package) fun create(epoch: u64, ctx: &mut TxContext): EpochCerts {
    EpochCerts {
        epoch,
        dkg_certs: linked_table::new(ctx),
    }
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
    if (epoch_certs.dkg_certs.contains(dealer)) {
        return
    };
    let message = hashi::committee::new_message(
        epoch,
        DkgDealerMessageHash { dealer_address: dealer, message_hash },
    );
    committee.verify_certificate(
        &signature,
        &signers_bitmap,
        message,
        threshold,
    );
    let cert = DkgCertV1 {
        message_hash,
        signature,
        signers_bitmap,
    };
    epoch_certs.dkg_certs.push_back(dealer, cert);
}

/// Remove all DKG certificates and destroy the EpochCerts in one transaction.
/// Can only be called when current_epoch >= epoch + 2.
public(package) fun destroy_all(epoch_certs: EpochCerts, current_epoch: u64) {
    let EpochCerts { epoch, mut dkg_certs } = epoch_certs;
    assert!(current_epoch >= epoch + 2, ETooEarlyToDestroy);
    while (!dkg_certs.is_empty()) {
        let (
            _,
            DkgCertV1 { message_hash: _, signature: _, signers_bitmap: _ },
        ) = dkg_certs.pop_front();
    };
    dkg_certs.destroy_empty();
}
