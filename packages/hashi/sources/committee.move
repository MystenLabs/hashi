#[allow(unused_function, unused_field)]
module hashi::committee;

use hashi::bls::verify_proof_of_possession;
use std::string::String;
use sui::{bls12381::{UncompressedG1, g1_from_bytes, g1_to_uncompressed_g1}, group_ops::Element};

public struct HashiNodeInfo has copy, drop, store {
    /// Sui Validator Address of this node
    validator_address: address,
    /// Sui Address of an operations account
    operator_address: address,
    /// bls12381 public key to be used in the next epoch.
    ///
    /// The public key for this node which is active in the current epoch can
    /// be found in the `BlsCommittee` struct.
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
}

public struct Committee has copy, drop, store {
    members: vector<HashiNodeInfo>,
    /// The current epoch.
    epoch: u64,
    // active_committee: BlsCommittee,
}

// updates

/// Set the public key of the node.
fun set_next_epoch_public_key(
    self: &mut Committee,
    next_epoch_public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    ctx: &TxContext,
) {
    assert!(
        verify_proof_of_possession(
            self.epoch,
            &ctx.sender(),
            &next_epoch_public_key,
            &proof_of_possession_signature,
        ),
    );

    let public_key = g1_to_uncompressed_g1(&g1_from_bytes(&next_epoch_public_key));

    let node = self.lookup_sender_info(ctx);
    node.next_epoch_public_key = public_key;
}

/// Set the https_address of the node.
fun set_https_address(self: &mut Committee, https_address: String, ctx: &TxContext) {
    let node = self.lookup_sender_info(ctx);
    node.https_address = https_address;
}

/// Set the tls_public_key of the node.
fun set_tls_public_key(self: &mut Committee, tls_public_key: vector<u8>, ctx: &TxContext) {
    let node = self.lookup_sender_info(ctx);
    node.tls_public_key = tls_public_key;
}

// === Accessors ===

/// Return the address of the node.
fun validator_address(self: &HashiNodeInfo): &address {
    &self.validator_address
}

/// Return the public key of the node.
fun next_epoch_public_key(self: &HashiNodeInfo): &Element<UncompressedG1> {
    &self.next_epoch_public_key
}

/// Return the https_address of the node.
fun https_address(self: &HashiNodeInfo): &String {
    &self.https_address
}

/// Return the tls_public_key of the node.
fun tls_public_key(self: &HashiNodeInfo): &vector<u8> {
    &self.tls_public_key
}

/// Return the members of the committee.
fun members(self: &Committee): &vector<HashiNodeInfo> {
    &self.members
}

/// Return the current epoch.
fun epoch(self: &Committee): u64 {
    self.epoch
}

fun lookup_sender_info(self: &mut Committee, ctx: &TxContext): &mut HashiNodeInfo {
    let idx = self.members.find_index!(|v| v.validator_address() == ctx.sender()).destroy_some();
    &mut self.members[idx]
}
