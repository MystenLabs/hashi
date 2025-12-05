#[allow(unused_const)]
module hashi::committee;

use sui::{
    bcs,
    bls12381::{Self, bls12381_min_pk_verify, G1, UncompressedG1},
    group_ops::{Self, Element},
    vec_map::{Self, VecMap}
};

// Error codes
/// The signers bitmap is invalid.
const EInvalidBitmap: u64 = 0;
/// The signature is invalid.
const ESigVerification: u64 = 1;
/// The certificate does not have enough stake support.
const ENotEnoughStake: u64 = 2;
/// The committee has members with a zero weight.
const EIncorrectCommittee: u64 = 3;

public struct CommitteeMember has copy, drop, store {
    validator_address: address,
    public_key: Element<UncompressedG1>,
    encryption_key: vector<u8>,
    weight: u16,
}

/// This represents a BLS signing committee for a given epoch.
public struct Committee has copy, drop, store {
    /// The epoch in which the committee is active.
    epoch: u64,
    /// A vector of committee members
    members: vector<CommitteeMember>,
    /// Total voting weight of the committee.
    total_weight: u16,
    total_aggregated_key: Element<G1>,
}

/// Constructor for committee.
public(package) fun new_committee(epoch: u64, members: vector<CommitteeMember>): Committee {
    assert!(!members.is_empty());

    // Compute the total weight
    let mut total_weight = 0;
    members.do_ref!(|member| {
        let weight = member.weight;
        assert!(weight > 0, EIncorrectCommittee);
        total_weight = total_weight + weight;
    });

    // Compute the total aggregated key, e.g. the sum of all public keys in the committee.
    let total_aggregated_key = bls12381::uncompressed_g1_to_g1(
        &bls12381::uncompressed_g1_sum(
            &members.map!(|member| member.public_key),
        ),
    );

    Committee { members, total_weight, epoch, total_aggregated_key }
}

/// Constructor for committee member.
public(package) fun new_committee_member(
    validator_address: address,
    public_key: Element<UncompressedG1>,
    encryption_key: vector<u8>,
    weight: u16,
): CommitteeMember {
    assert!(weight > 0, EIncorrectCommittee);
    CommitteeMember {
        validator_address,
        public_key,
        encryption_key,
        weight,
    }
}

// === Accessors for CommitteeMember ===

/// Get the node id of the committee member.
public(package) fun validator_address(self: &CommitteeMember): address {
    self.validator_address
}

// === Accessors for Committee ===

/// Get the epoch of the committee.
public(package) fun epoch(self: &Committee): u64 {
    self.epoch
}

/// Returns the number of total_weight held by the committee.
public(package) fun total_weight(self: &Committee): u16 {
    self.total_weight
}

/// Returns the number of members in the committee.
public(package) fun n_members(self: &Committee): u64 {
    self.members.length()
}

/// Returns the member at given index.
public(package) fun get_idx(self: &Committee, idx: u64): &CommitteeMember {
    &self.members[idx]
}

/// Checks if the committee contains a given node.
public(package) fun has_member(self: &Committee, validator_address: &address): bool {
    self.find_index(validator_address).is_some()
}

/// Returns the member weight if it is part of the committee or 0 otherwise
public(package) fun get_member_weight(self: &Committee, validator_address: &address): u16 {
    self.find_index(validator_address).map!(|idx| self.members[idx].weight).destroy_or!(0)
}

/// Finds the index of the member by validator_address
public(package) fun find_index(self: &Committee, validator_address: &address): Option<u64> {
    self.members.find_index!(|member| &member.validator_address == validator_address)
}

/// Returns the members of the committee with their weights.
public(package) fun to_vec_map(self: &Committee): VecMap<address, u16> {
    let mut result = vec_map::empty();
    self.members.do_ref!(|member| {
        result.insert(member.validator_address, member.weight)
    });
    result
}

#[allow(unused_function)]
fun verify_proposal(self: &Committee, signers: sui::vec_set::VecSet<address>, threshold: u16): u16 {
    // Compute the total signed weight
    let mut aggregate_weight = 0;
    signers.keys().do_ref!(|validator_address| {
        aggregate_weight = aggregate_weight + self.get_member_weight(validator_address);
    });

    // Check if the aggregate weight is enough to satisfy the required weight.
    assert!(aggregate_weight >= threshold, ENotEnoughStake);

    aggregate_weight
}

/// Verify an aggregate BLS signature is a certificate in the epoch, and return
/// the total stake of the signers.
/// The `signers_bitmap` is a bitmap of the indices of the signers in the committee.
/// The `weight_verification_type` is the type of weight verification to perform,
/// either check that the signers forms a quorum or includes at least one correct node.
/// If there is a certificate, the function returns the total stake. Otherwise, it aborts.
#[allow(unused_function)]
fun verify_certificate<T>(
    self: &Committee,
    signature: &vector<u8>,
    signers_bitmap: &vector<u8>,
    message: Message<T>,
    threshold: u16, //XXX threshold could be lookedup by type in the config
): CertifiedMessage<T> {
    assert!(message.epoch == self.epoch());

    // Use the signers_bitmap to construct the key and the weights.
    let mut non_signer_aggregate_weight = 0;
    let mut non_signer_public_keys: vector<Element<UncompressedG1>> = vector::empty();
    let mut offset: u64 = 0;
    let n_members = self.n_members();
    let max_bitmap_len_bytes = n_members.divide_and_round_up(8);

    // The signers bitmap must not be longer than necessary to hold all members.
    // It may be shorter, in which case the excluded members are treated as non-signers.
    assert!(signers_bitmap.length() <= max_bitmap_len_bytes, EInvalidBitmap);

    // Iterate over the signers bitmap and check if each member is a signer.
    max_bitmap_len_bytes.do!(|i| {
        // Get the current byte or 0 if we've reached the end of the bitmap.
        let byte = if (i < signers_bitmap.length()) {
            signers_bitmap[i]
        } else {
            0
        };

        (8u8).do!(|i| {
            let index = offset + (i as u64);
            let is_signer = (byte >> i) & 1 == 1;

            // If the index is out of bounds, the bit must be 0 to ensure
            // uniqueness of the signers_bitmap.
            if (index >= n_members) {
                assert!(!is_signer, EInvalidBitmap);
                return
            };

            // There will be fewer non-signers than signers, so we handle
            // non-signers here.
            if (!is_signer) {
                let member = self.members[index];
                non_signer_aggregate_weight = non_signer_aggregate_weight + member.weight;
                non_signer_public_keys.push_back(member.public_key);
            };
        });
        offset = offset + 8;
    });

    //XXX we should tally up both signers and non-signers and based on which is
    //shorter we can either build up an aggregate_key from the signers or
    //substract the non-signers from the total_aggregated_key in order to
    //optimize for gas costs.

    // Compute the aggregate weight as the difference between the total weight
    // and the total weight of the non-signers.
    let aggregate_weight = self.total_weight - non_signer_aggregate_weight;

    // Check if the aggregate weight is enough to satisfy the required weight.
    assert!(aggregate_weight >= threshold, ENotEnoughStake);

    // Compute the aggregate public key as the difference between the total
    // aggregated key and the sum of the non-signer public keys.
    let aggregate_key = bls12381::g1_sub(
        &self.total_aggregated_key,
        &bls12381::uncompressed_g1_to_g1(
            &bls12381::uncompressed_g1_sum(&non_signer_public_keys),
        ),
    );

    // Verify the signature
    let pub_key_bytes = group_ops::bytes(&aggregate_key);
    let message_bytes = bcs::to_bytes(&message);
    assert!(
        bls12381_min_pk_verify(
            signature,
            pub_key_bytes,
            &message_bytes,
        ),
        ESigVerification,
    );

    let Message {
        epoch,
        message,
    } = message;

    CertifiedMessage {
        epoch,
        message,
        stake_support: aggregate_weight as u16,
    }
}

public struct Message<T> has drop {
    epoch: u64,
    message: T,
}

public struct CertifiedMessage<T> has drop {
    epoch: u64,
    message: T,
    stake_support: u16,
}

// === Accessors for CertifiedMessage ===

public(package) fun cert_epoch<T>(self: &CertifiedMessage<T>): u64 {
    self.epoch
}

public(package) fun stake_support<T>(self: &CertifiedMessage<T>): u16 {
    self.stake_support
}

public(package) fun message<T>(self: &CertifiedMessage<T>): &T {
    &self.message
}

public(package) fun into_message<T>(self: CertifiedMessage<T>): T {
    let CertifiedMessage {
        epoch: _,
        message,
        stake_support: _,
    } = self;

    message
}
