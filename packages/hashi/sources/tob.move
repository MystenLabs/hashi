/// Totally Ordered Broadcast (TOB)

module hashi::tob;

use hashi::committee::CommitteeSignature;
use sui::linked_table::{Self, LinkedTable};

const EWrongEpoch: u64 = 0;
const ETooEarlyToDestroy: u64 = 1;

public enum ProtocolType has copy, drop, store {
    Dkg,
    KeyRotation,
    NonceGeneration,
}

public fun protocol_type_dkg(): ProtocolType {
    ProtocolType::Dkg
}

public fun protocol_type_key_rotation(): ProtocolType {
    ProtocolType::KeyRotation
}

public fun protocol_type_nonce_generation(): ProtocolType {
    ProtocolType::NonceGeneration
}

public struct TobKey has copy, drop, store {
    epoch: u64,
    batch_index: Option<u32>,
}

public fun tob_key(epoch: u64, batch_index: Option<u32>): TobKey {
    TobKey { epoch, batch_index }
}

public fun epoch(self: &TobKey): u64 {
    self.epoch
}

/// Certificates for a single epoch.
public struct EpochCertsV1 has store {
    epoch: u64,
    protocol_type: ProtocolType,
    /// Dealer submissions indexed by dealer address (first-submission-wins).
    certs: LinkedTable<address, DealerSubmissionV1>,
}

public struct DealerMessagesHashV1 has copy, drop, store {
    dealer_address: address,
    messages_hash: vector<u8>,
}

public struct DealerSubmissionV1 has copy, drop, store {
    message: DealerMessagesHashV1,
    signature: CommitteeSignature,
}

public(package) fun create(
    epoch: u64,
    protocol_type: ProtocolType,
    ctx: &mut TxContext,
): EpochCertsV1 {
    EpochCertsV1 {
        epoch,
        protocol_type,
        certs: linked_table::new(ctx),
    }
}

/// Remove all certificates and destroy the EpochCertsV1 in one transaction.
/// Can only be called when current_epoch >= epoch + 2.
public(package) fun destroy_all(epoch_certs: EpochCertsV1, current_epoch: u64) {
    let EpochCertsV1 { epoch, protocol_type: _, mut certs } = epoch_certs;
    assert!(current_epoch >= epoch + 2, ETooEarlyToDestroy);
    while (!certs.is_empty()) {
        let (_, _) = certs.pop_front();
    };
    certs.destroy_empty();
}

public(package) fun submit_cert(
    epoch_certs: &mut EpochCertsV1,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
) {
    assert!(epoch == epoch_certs.epoch, EWrongEpoch);
    if (epoch_certs.certs.contains(dealer)) {
        return
    };
    let message = DealerMessagesHashV1 { dealer_address: dealer, messages_hash };
    let sig = hashi::committee::new_committee_signature(epoch, signature, signers_bitmap);
    let submission = DealerSubmissionV1 { message, signature: sig };
    epoch_certs.certs.push_back(dealer, submission);
}
