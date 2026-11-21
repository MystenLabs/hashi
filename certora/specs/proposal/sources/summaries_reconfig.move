module proposal::summaries_reconfig;

use cvlm::asserts::cvlm_assume_msg;
use cvlm::ghost::ghost_destroy;
use cvlm::manifest::summary;
use cvlm::nondet::nondet;
use hashi::committee::{Committee, CommitteeSignature, CertifiedMessage};
use hashi::committee_set::CommitteeSet;
use hashi::config::Config;
use hashi::hashi::Hashi;
use sui::bls12381::{G1, UncompressedG1};
use sui::group_ops::Element;
use sui::vec_map::VecMap;

public fun cvlm_manifest() {
    summary(
        b"new_committee_from_voting_powers_summary",
        @hashi,
        b"committee_set",
        b"new_committee_from_voting_powers",
    );
    summary(b"verify_with_committee_summary", @hashi, b"hashi", b"verify_with_committee");
    summary(b"verify_bls_public_key_summary", @hashi, b"committee_set", b"verify_bls_public_key");
    summary(b"g1_to_uncompressed_g1_summary", @sui, b"bls12381", b"g1_to_uncompressed_g1");
}

/// Returns an arbitrary committee stamped with `epoch` (the only caller,
/// `start_reconfig_from_voting_powers`, passes the current Sui epoch); the
/// validator-set loop and its aborts are skipped.
public fun new_committee_from_voting_powers_summary(
    _self: &CommitteeSet,
    epoch: u64,
    _validator_set: VecMap<address, u64>,
    _epoch_config: Config,
): Committee {
    let committee: Committee = nondet();
    cvlm_assume_msg(
        committee.epoch() == epoch,
        b"the new committee is stamped with the requested epoch",
    );
    committee
}

/// Accepts every reconfiguration certificate: signature, quorum, epoch and weight checks
/// are skipped.
public fun verify_with_committee_summary<T>(
    _self: &Hashi,
    _committee: &Committee,
    _intent: u16,
    message: T,
    _sig: CommitteeSignature,
): CertifiedMessage<T> {
    ghost_destroy(message);
    nondet()
}

/// Returns an arbitrary key without checking the proof of possession.
public fun verify_bls_public_key_summary(
    _hashi_id: address,
    _epoch: u64,
    _validator_address: address,
    _bls_public_key: vector<u8>,
    _proof_of_possession_signature: vector<u8>,
): Element<UncompressedG1> {
    nondet()
}

/// Returns an arbitrary element; two calls on the same input may differ.
public fun g1_to_uncompressed_g1_summary(_e: &Element<G1>): Element<UncompressedG1> {
    nondet()
}
