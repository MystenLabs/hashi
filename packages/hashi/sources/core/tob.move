// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::tob;

use hashi::committee::CommitteeSignature;
use sui::linked_table::{Self, LinkedTable};

// ~~~~~~~ Errors ~~~~~~~

#[error]
const EWrongEpoch: vector<u8> = b"Certificate epoch does not match the bucket's epoch";
#[error]
const ETooEarlyToDestroy: vector<u8> =
    b"TOB certificates may only be destroyed two epochs after their epoch";

// ~~~~~~~ Structs ~~~~~~~

public enum ProtocolType has copy, drop, store {
    Dkg,
    KeyRotation,
    NonceGeneration,
}

public struct TobKey has copy, drop, store {
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
}

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

public struct StampedDealerSubmissionV1 has copy, drop, store {
    submission: DealerSubmissionV1,
    timestamp_ms: u64,
}

public struct StampedEpochCertsV1 has store {
    epoch: u64,
    protocol_type: ProtocolType,
    /// Stamped nonce submissions indexed by dealer address (first-submission-wins).
    certs: LinkedTable<address, StampedDealerSubmissionV1>,
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun protocol_type_dkg(): ProtocolType {
    ProtocolType::Dkg
}

public(package) fun protocol_type_key_rotation(): ProtocolType {
    ProtocolType::KeyRotation
}

public(package) fun protocol_type_nonce_generation(): ProtocolType {
    ProtocolType::NonceGeneration
}

public(package) fun is_nonce_generation(self: &ProtocolType): bool {
    match (self) {
        ProtocolType::NonceGeneration => true,
        _ => false,
    }
}

public(package) fun tob_key(
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
): TobKey {
    TobKey { epoch, batch_index, protocol_type }
}

public(package) fun epoch(self: &TobKey): u64 {
    self.epoch
}

public(package) fun protocol_type(self: &TobKey): ProtocolType {
    self.protocol_type
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

public(package) fun create_stamped(
    epoch: u64,
    protocol_type: ProtocolType,
    ctx: &mut TxContext,
): StampedEpochCertsV1 {
    StampedEpochCertsV1 {
        epoch,
        protocol_type,
        certs: linked_table::new(ctx),
    }
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

public(package) fun submit_cert_with_signature(
    epoch_certs: &mut EpochCertsV1,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    sig: &CommitteeSignature,
) {
    assert!(epoch == epoch_certs.epoch, EWrongEpoch);
    if (epoch_certs.certs.contains(dealer)) {
        return
    };
    let message = DealerMessagesHashV1 { dealer_address: dealer, messages_hash };
    let submission = DealerSubmissionV1 { message, signature: *sig };
    epoch_certs.certs.push_back(dealer, submission);
}

public(package) fun submit_stamped_cert_with_signature(
    epoch_certs: &mut StampedEpochCertsV1,
    epoch: u64,
    dealer: address,
    messages_hash: vector<u8>,
    sig: &CommitteeSignature,
    timestamp_ms: u64,
) {
    assert!(epoch == epoch_certs.epoch, EWrongEpoch);
    if (epoch_certs.certs.contains(dealer)) {
        return
    };
    let message = DealerMessagesHashV1 { dealer_address: dealer, messages_hash };
    let submission = DealerSubmissionV1 { message, signature: *sig };
    let stamped = StampedDealerSubmissionV1 { submission, timestamp_ms };
    epoch_certs.certs.push_back(dealer, stamped);
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

/// Remove all stamped certificates and destroy the StampedEpochCertsV1.
/// Can only be called when current_epoch >= epoch + 2.
public(package) fun destroy_all_stamped(epoch_certs: StampedEpochCertsV1, current_epoch: u64) {
    let StampedEpochCertsV1 { epoch, protocol_type: _, mut certs } = epoch_certs;
    assert!(current_epoch >= epoch + 2, ETooEarlyToDestroy);
    while (!certs.is_empty()) {
        let (_, _) = certs.pop_front();
    };
    certs.destroy_empty();
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
public fun submission_timestamp_ms(self: &StampedEpochCertsV1, dealer: address): u64 {
    self.certs.borrow(dealer).timestamp_ms
}

#[test_only]
public fun num_certs(self: &EpochCertsV1): u64 {
    self.certs.length()
}

#[test_only]
public fun num_stamped_certs(self: &StampedEpochCertsV1): u64 {
    self.certs.length()
}
