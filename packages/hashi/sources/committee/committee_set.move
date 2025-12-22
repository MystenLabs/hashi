#[allow(unused_function, unused_field)]
module hashi::committee_set;

use hashi::committee::{Self, Committee};
use std::string::String;
use sui::{
    bag::Bag,
    bcs,
    bls12381::{UncompressedG1, bls12381_min_pk_verify, g1_from_bytes, g1_to_uncompressed_g1},
    group_ops::Element
};

//
// CommitteeSet
//

public struct CommitteeSet has store {
    members: Bag,
    /// The current epoch.
    epoch: u64,
    committees: Bag,
}

public(package) fun create(ctx: &mut TxContext): CommitteeSet {
    CommitteeSet {
        members: sui::bag::new(ctx),
        epoch: 0,
        committees: sui::bag::new(ctx),
    }
}

fun member(self: &CommitteeSet, validator_address: address): &MemberInfo {
    &self.members[validator_address]
}

public(package) fun has_member(self: &CommitteeSet, validator_address: address): bool {
    self.members.contains_with_type<_, MemberInfo>(validator_address)
}

fun member_mut(self: &mut CommitteeSet, validator_address: address): &mut MemberInfo {
    &mut self.members[validator_address]
}

fun insert_member(self: &mut CommitteeSet, member: MemberInfo) {
    self.members.add(member.validator_address, member)
}

fun committee(self: &CommitteeSet, epoch: u64): &Committee {
    &self.committees[epoch]
}

public(package) fun has_committee(self: &CommitteeSet, epoch: u64): bool {
    self.committees.contains_with_type<u64, Committee>(epoch)
}

fun insert_committee(self: &mut CommitteeSet, committee: Committee) {
    self.committees.add(committee.epoch(), committee)
}

public(package) fun current_committee(self: &CommitteeSet): &Committee {
    &self.committees[self.epoch()]
}

//
// MemberInfo
//

public struct MemberInfo has store {
    /// Sui Validator Address of this node
    validator_address: address,
    /// Sui Address of an operations account
    operator_address: address,
    /// bls12381 public key to be used in the next epoch.
    ///
    /// The public key for this node which is active in the current epoch can
    /// be found in the `Committee` struct.
    ///
    /// This public key can be rotated but will only take effect at the
    /// beginning of the next epoch.
    next_epoch_public_key: Element<UncompressedG1>,
    /// The HTTPS network address where the instance of the `hashi` service for
    /// this validator can be reached.
    ///
    /// This HTTPS address can be rotated and any such updates will take effect
    /// immediately.
    https_address: String,
    /// ed25519 public key used to verify TLS self-signed x509 certs
    ///
    /// This public key can be rotated and any such updates will take effect
    /// immediately.
    tls_public_key: vector<u8>,
    /// A 32-byte ristretto255 Ristretto encryption public key (ristretto255
    /// RistrettoPoint) for MPC ECIES, to be used in the next epoch.
    ///
    /// This public key can be rotated but will only take effect at the
    /// beginning of the next epoch.
    next_epoch_encryption_public_key: vector<u8>,
}

/// Register as a member of Hashi.
///
/// Only BLS key is required at registration time, other info can be set in
/// other PTB commands or at some point in the future.
public(package) fun new_member(
    committee_set: &mut CommitteeSet,
    sui_system: &sui_system::sui_system::SuiSystemState,
    public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    encryption_public_key: vector<u8>,
    ctx: &TxContext,
) {
    let validator_address = ctx.sender();

    // Only allow Sui Validators to register as Hashi members
    assert!(sui_system.active_validator_addresses_ref().contains(&validator_address));

    let next_epoch_public_key = verify_bls_public_key(
        ctx.epoch(),
        validator_address,
        public_key,
        proof_of_possession_signature,
    );

    assert!(encryption_public_key.length() == 32);

    let member = MemberInfo {
        validator_address: validator_address,
        operator_address: validator_address,
        next_epoch_public_key: next_epoch_public_key,
        https_address: std::vector::empty().to_string(),
        tls_public_key: std::vector::empty(),
        next_epoch_encryption_public_key: encryption_public_key,
    };

    committee_set.insert_member(member);
}

fun assert_update_permitted(self: &MemberInfo, ctx: &TxContext) {
    assert!(ctx.sender() == self.validator_address || ctx.sender() == self.operator_address);
}

/// Set the public key of the member.
public(package) fun set_next_epoch_public_key(
    self: &mut CommitteeSet,
    validator_address: address,
    next_epoch_public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    ctx: &TxContext,
) {
    let next_epoch_public_key = verify_bls_public_key(
        ctx.epoch(),
        validator_address,
        next_epoch_public_key,
        proof_of_possession_signature,
    );

    let member = self.member_mut(validator_address);
    member.assert_update_permitted(ctx);

    member.next_epoch_public_key = next_epoch_public_key;
}

/// Set the https_address of the member.
public(package) fun set_https_address(
    self: &mut CommitteeSet,
    validator_address: address,
    https_address: String,
    ctx: &TxContext,
) {
    let member = self.member_mut(validator_address);
    member.assert_update_permitted(ctx);

    member.https_address = https_address;
}

/// Set the tls_public_key of the member.
public(package) fun set_tls_public_key(
    self: &mut CommitteeSet,
    validator_address: address,
    tls_public_key: vector<u8>,
    ctx: &TxContext,
) {
    assert!(tls_public_key.length() == 32);

    let member = self.member_mut(validator_address);
    member.assert_update_permitted(ctx);
    member.tls_public_key = tls_public_key;
}

/// Set the next_epoch_encryption_public_key of the member.
public(package) fun set_next_epoch_encryption_public_key(
    self: &mut CommitteeSet,
    validator_address: address,
    next_epoch_encryption_public_key: vector<u8>,
    ctx: &TxContext,
) {
    assert!(next_epoch_encryption_public_key.length() == 32);

    let member = self.member_mut(validator_address);
    member.assert_update_permitted(ctx);
    member.next_epoch_encryption_public_key = next_epoch_encryption_public_key;
}

/// Set the operator_address of the member.
public(package) fun set_operator_address(
    self: &mut CommitteeSet,
    validator_address: address,
    operator_address: address,
    ctx: &TxContext,
) {
    let member = self.member_mut(validator_address);
    member.assert_update_permitted(ctx);
    member.operator_address = operator_address;
}

// === Accessors ===

/// Return the address of the node.
fun validator_address(self: &MemberInfo): &address {
    &self.validator_address
}

/// Return the next epoch public key of the node.
fun next_epoch_public_key(self: &MemberInfo): &Element<UncompressedG1> {
    &self.next_epoch_public_key
}

/// Return the https_address of the node.
fun https_address(self: &MemberInfo): &String {
    &self.https_address
}

/// Return the tls_public_key of the node.
fun tls_public_key(self: &MemberInfo): &vector<u8> {
    &self.tls_public_key
}

/// Return the next epoch encryption public key of the node.
fun next_epoch_encryption_public_key(self: &MemberInfo): &vector<u8> {
    &self.next_epoch_encryption_public_key
}

/// Return the current epoch.
public(package) fun epoch(self: &CommitteeSet): u64 {
    self.epoch
}

// Verifies that the provided bls public key is valid and there is a valid
// proof of possession.
fun verify_bls_public_key(
    epoch: u64,
    validator_address: address,
    bls_public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
): Element<UncompressedG1> {
    // Verify the proof of possession of the private key
    assert!(
        verify_proof_of_possession(
            epoch,
            &validator_address,
            &bls_public_key,
            &proof_of_possession_signature,
        ),
    );

    // Convert the public key to its Uncompressed form
    g1_to_uncompressed_g1(&g1_from_bytes(&bls_public_key))
}

fun verify_proof_of_possession(
    epoch: u64,
    validator_address: &address,
    bls_public_key: &vector<u8>,
    proof_of_possession_signature: &vector<u8>,
): bool {
    let mut message = vector[];
    message.append(bcs::to_bytes(&epoch));
    message.append(bcs::to_bytes(validator_address));
    bls_public_key.do_ref!(|key_byte| message.append(bcs::to_bytes(key_byte)));

    bls12381_min_pk_verify(
        proof_of_possession_signature,
        bls_public_key,
        &message,
    )
}

fun new_committee_from_validator_set(
    self: &CommitteeSet,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
): Committee {
    let epoch = ctx.epoch();
    let mut validator_set = sui_system.active_validator_voting_powers();

    let mut committee_members = vector[];

    while (!validator_set.is_empty()) {
        let (validator_address, weight) = validator_set.pop();

        // If there is no registered info for this validator, skip them
        if (!self.has_member(validator_address)) {
            continue
        };

        let member = self.member(validator_address);

        let committee_member = committee::new_committee_member(
            validator_address,
            member.next_epoch_public_key,
            member.next_epoch_encryption_public_key,
            weight as u16, // XXX is this ok?
        );

        committee_members.push_back(committee_member);
    };

    // XXX do we sort by address or weight?

    committee::new_committee(epoch, committee_members)
}

public(package) fun bootstrap(
    self: &mut CommitteeSet,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
) {
    assert!(self.epoch() == 0);
    assert!(!self.has_committee(ctx.epoch()));

    let committee = self.new_committee_from_validator_set(sui_system, ctx);

    // assert voting weight
    let mut sui_system_weight = 0;
    let (_, weights) = sui_system.active_validator_voting_powers().into_keys_values();
    weights.do!(|weight| {
        sui_system_weight = sui_system_weight + weight;
    });

    // Ensure 95% of stake has registered
    assert!(committee.total_weight() as u64 >= ((9500 * sui_system_weight) / 10000));

    self.epoch = committee.epoch();
    self.insert_committee(committee)
}
