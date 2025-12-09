/// Totally Ordered Broadcast (TOB)

module hashi::tob;

use hashi::committee::Committee;
use sui::table::{Self, Table};

const EWrongEpoch: u64 = 0;
const ETooEarlyToDestroy: u64 = 1;

public struct EpochCerts has store {
    epoch: u64,
    /// DKG certificates indexed by dealer address (first-cert-wins).
    dkg_certs: Table<address, DkgCertV1>,
}

public(package) fun destroy_epoch_certs(registry: EpochCerts, current_epoch: u64) {
    let EpochCerts { epoch, dkg_certs } = registry;
    assert!(current_epoch >= epoch + 2, ETooEarlyToDestroy);
    dkg_certs.destroy_empty();
}

public struct DkgCertV1 has copy, store {
    message_hash: vector<u8>, // 32 bytes
    signature: vector<u8>, // BLS aggregate signature
    signers_bitmap: vector<u8>, // Bitmap of signers
}

/// Remove a DKG certificate from the registry and destroy it.
public(package) fun remove_dkg_cert(registry: &mut EpochCerts, dealer: address) {
    let cert = table::remove(&mut registry.dkg_certs, dealer);
    destroy_dkg_cert(cert);
}

public(package) fun destroy_dkg_cert(cert: DkgCertV1) {
    let DkgCertV1 { message_hash: _, signature: _, signers_bitmap: _ } = cert;
}

public struct DkgDealerMessageHash has copy, drop {
    dealer_address: address,
    message_hash: vector<u8>,
}

public(package) fun create(epoch: u64, ctx: &mut TxContext): EpochCerts {
    EpochCerts {
        epoch,
        dkg_certs: table::new(ctx),
    }
}

/// Submit a DKG certificate to the TOB.
/// Returns early (no error) if certificate already exists for this dealer.
public(package) fun submit_dkg_cert(
    registry: &mut EpochCerts,
    committee: &Committee,
    epoch: u64,
    dealer: address,
    message_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    threshold: u16,
) {
    assert!(epoch == registry.epoch, EWrongEpoch);
    if (table::contains(&registry.dkg_certs, dealer)) {
        return
    };
    let message = hashi::committee::new_message(
        epoch,
        DkgDealerMessageHash { dealer_address: dealer, message_hash },
    );
    hashi::committee::verify_certificate(
        committee,
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
    table::add(&mut registry.dkg_certs, dealer, cert);
}
