/// Totally Ordered Broadcast (TOB)

module hashi::tob;

use hashi::committee::Committee;
use sui::table::{Self, Table};

const EWrongEpoch: u64 = 0;

public struct TobRegistry has store {
    epoch: u64,
    /// Certificates indexed by dealer address (first-cert-wins).
    certificates: Table<address, StoredMpcCertificateV1>,
}

public struct StoredMpcCertificateV1 has copy, drop, store {
    epoch: u64,
    dealer: address,
    message_hash: vector<u8>, // 32 bytes
    signature: vector<u8>, // BLS aggregate signature
    signers_bitmap: vector<u8>, // Bitmap of signers
}

public struct DkgDealerMessageHash has copy, drop {
    dealer_address: address,
    message_hash: vector<u8>,
}

public(package) fun create(epoch: u64, ctx: &mut TxContext): TobRegistry {
    TobRegistry {
        epoch,
        certificates: table::new(ctx),
    }
}

/// Submit a certificate to the TOB.
/// Returns early (no error) if certificate already exists for this dealer.
public(package) fun submit_certificate(
    registry: &mut TobRegistry,
    committee: &Committee,
    epoch: u64,
    dealer: address,
    message_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    threshold: u16,
) {
    assert!(epoch == registry.epoch, EWrongEpoch);
    if (table::contains(&registry.certificates, dealer)) {
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
    let cert = StoredMpcCertificateV1 {
        epoch,
        dealer,
        message_hash,
        signature,
        signers_bitmap,
    };
    table::add(&mut registry.certificates, dealer, cert);
}
