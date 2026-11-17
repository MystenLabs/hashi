module solvency::summaries_hashi;

use cvlm::ghost::ghost_destroy;
use cvlm::manifest::summary;
use cvlm::nondet::nondet;
use hashi::{
    committee::{CommitteeSignature, CertifiedMessage},
    hashi::Hashi,
    mpc_signing::SigningBatch,
};
use sui::random::{Random, RandomGenerator};

public fun cvlm_manifest() {
    summary(b"verify_summary", @hashi, b"hashi", b"verify");
    summary(b"new_generator_summary", @sui, b"random", b"new_generator");
    summary(b"generate_bytes_summary", @sui, b"random", b"generate_bytes");
    summary(b"to_signatures_summary", @hashi, b"mpc_signing", b"to_signatures");
}

public fun verify_summary<T>(
    self: &Hashi,
    _intent: u16,
    message: T,
    sig: CommitteeSignature,
): CertifiedMessage<T> {
    // Keep `verify_certificate`'s epoch check: the BLS and quorum checks are
    // skipped, but a certificate from another epoch must still abort.
    assert!(sig.signature_epoch() == self.current_committee().epoch());
    ghost_destroy(message);
    nondet()
}

public fun new_generator_summary(_r: &Random, _ctx: &mut TxContext): RandomGenerator {
    nondet()
}

public fun generate_bytes_summary(_g: &mut RandomGenerator, _num_of_bytes: u16): vector<u8> {
    nondet()
}

public fun to_signatures_summary(_self: &SigningBatch): vector<vector<u8>> {
    nondet()
}
