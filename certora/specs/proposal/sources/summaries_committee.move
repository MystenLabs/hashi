module proposal::summaries_committee;

use cvlm::ghost::ghost_destroy;
use cvlm::manifest::summary;
use cvlm::nondet::nondet;
use hashi::committee::{Committee, CommitteeSignature, CertifiedMessage};

public fun cvlm_manifest() {
    summary(b"verify_certificate_summary", @hashi, b"committee", b"verify_certificate");
}

/// Accepts every certificate: the epoch, quorum and BLS signature checks are skipped.
public fun verify_certificate_summary<T>(
    _self: &Committee,
    _hashi_id: address,
    _intent: u16,
    message: T,
    _signature: CommitteeSignature,
    _threshold: u64,
): CertifiedMessage<T> {
    ghost_destroy(message);
    nondet()
}
