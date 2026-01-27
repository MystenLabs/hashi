#[allow(unused_const)]
module hashi::committee;

use sui::{
    bcs,
    bls12381::{Self, bls12381_min_pk_verify, UncompressedG1},
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
    encryption_public_key: vector<u8>,
    weight: u64,
}

/// This represents a BLS signing committee for a given epoch.
public struct Committee has copy, drop, store {
    /// The epoch in which the committee is active.
    epoch: u64,
    /// A vector of committee members
    members: vector<CommitteeMember>,
    /// Total voting weight of the committee.
    total_weight: u64,
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

    Committee { members, total_weight, epoch }
}

/// Constructor for committee member.
public(package) fun new_committee_member(
    validator_address: address,
    public_key: Element<UncompressedG1>,
    encryption_public_key: vector<u8>,
    weight: u64,
): CommitteeMember {
    assert!(weight > 0, EIncorrectCommittee);
    CommitteeMember {
        validator_address,
        public_key,
        encryption_public_key,
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
public(package) fun total_weight(self: &Committee): u64 {
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
public(package) fun get_member_weight(self: &Committee, validator_address: &address): u64 {
    self.find_index(validator_address).map!(|idx| self.members[idx].weight).destroy_or!(0)
}

/// Finds the index of the member by validator_address
public(package) fun find_index(self: &Committee, validator_address: &address): Option<u64> {
    self.members.find_index!(|member| &member.validator_address == validator_address)
}

/// Returns the members of the committee with their weights.
public(package) fun to_vec_map(self: &Committee): VecMap<address, u64> {
    let mut result = vec_map::empty();
    self.members.do_ref!(|member| {
        result.insert(member.validator_address, member.weight)
    });
    result
}

#[allow(unused_function)]
public(package) fun verify_proposal(
    self: &Committee,
    signers: sui::vec_set::VecSet<address>,
    threshold: u64,
): u64 {
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
/// If there is a certificate, the function returns the total stake. Otherwise, it aborts.
public(package) fun verify_certificate<T>(
    self: &Committee,
    message: T,
    signature: CommitteeSignature,
    threshold: u64, //XXX threshold could be lookedup by type in the config
): CertifiedMessage<T> {
    assert!(signature.epoch == self.epoch());

    // Use the signers_bitmap to construct the key and the weights.
    let mut aggregate_weight = 0;
    let mut signer_public_keys: vector<Element<UncompressedG1>> = vector::empty();
    let mut offset: u64 = 0;
    let n_members = self.n_members();
    let max_bitmap_len_bytes = n_members.divide_and_round_up(8);

    // The signers bitmap must not be longer than necessary to hold all members.
    // It may be shorter, in which case the excluded members are treated as non-signers.
    assert!(signature.signers_bitmap.length() <= max_bitmap_len_bytes, EInvalidBitmap);

    // Iterate over the bitmap, adding up signing weight and collecting public keys
    signature.signers_bitmap.do!(|byte| {
        (8u8).do!(|bit_index| {
            // The member index
            let index = offset + (bit_index as u64);
            let is_signer = (byte & (1 << (7 - bit_index))) != 0;

            // If the index is out of bounds, the bit must be 0 to ensure
            // a wellformed bitmap.
            if (index >= n_members) {
                assert!(!is_signer, EInvalidBitmap);
                return
            };

            if (is_signer) {
                let member = self.members[index];
                aggregate_weight = aggregate_weight + member.weight;
                signer_public_keys.push_back(member.public_key);
            };
        });
        offset = offset + 8;
    });

    // Check if the aggregate weight is enough to satisfy the required weight.
    assert!(aggregate_weight >= threshold, ENotEnoughStake);

    let aggregate_key = bls12381::uncompressed_g1_to_g1(
        &bls12381::uncompressed_g1_sum(
            &signer_public_keys,
        ),
    );

    // Verify the signature
    let pub_key_bytes = group_ops::bytes(&aggregate_key);

    // Signing message is always prefixed with the epoch
    let mut message_bytes = bcs::to_bytes(&signature.epoch);
    message_bytes.append(bcs::to_bytes(&message));

    assert!(
        bls12381_min_pk_verify(
            &signature.signature,
            pub_key_bytes,
            &message_bytes,
        ),
        ESigVerification,
    );

    CertifiedMessage {
        message,
        signature,
        stake_support: aggregate_weight,
    }
}

public struct CommitteeSignature has copy, drop, store {
    epoch: u64,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
}

public fun new_committee_signature(
    epoch: u64,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
): CommitteeSignature {
    CommitteeSignature {
        epoch,
        signature,
        signers_bitmap,
    }
}

public struct CertifiedMessage<T> has copy, drop, store {
    message: T,
    signature: CommitteeSignature,
    stake_support: u64,
}

// === Accessors for CertifiedMessage ===

public(package) fun cert_epoch<T>(self: &CertifiedMessage<T>): u64 {
    self.signature.epoch
}

public(package) fun cert_signature<T>(self: &CertifiedMessage<T>): &CommitteeSignature {
    &self.signature
}

public(package) fun stake_support<T>(self: &CertifiedMessage<T>): u64 {
    self.stake_support
}

public(package) fun message<T>(self: &CertifiedMessage<T>): &T {
    &self.message
}

public(package) fun into_message<T>(self: CertifiedMessage<T>): T {
    let CertifiedMessage {
        message,
        signature: _,
        stake_support: _,
    } = self;

    message
}
