/// @module Reconfiguration Integrity Properties
/// @contract hashi::reconfig
/// @contract hashi::committee_set
/// @contract hashi::validator
module proposal::reconfig_handoff;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::committee::CommitteeSignature;
use hashi::hashi::Hashi;

public fun cvlm_manifest() {
    target(@hashi, b"reconfig", b"start_reconfig");
    target(@hashi, b"reconfig", b"submit_committee_handoff");
    target(@hashi, b"reconfig", b"end_reconfig");
    target(@hashi, b"reconfig", b"abort_reconfig");
    target(@hashi, b"validator", b"register");
    target(@hashi, b"validator", b"update_next_epoch_public_key");
    target(@hashi, b"validator", b"update_operator_address");
    target(@hashi, b"validator", b"update_endpoint_url");
    target(@hashi, b"validator", b"update_tls_public_key");
    target(@hashi, b"validator", b"update_next_epoch_encryption_public_key");
    invoker(b"invoke");

    rule(b"handoff_cert_written_once");
    rule(b"handoff_cert_is_latched");
    rule(b"end_reconfig_requires_handoff_when_not_initial");
    rule(b"genesis_completes_with_non_empty_mpc_key");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title The handoff certificate cannot be submitted twice
/// @description Two submit_committee_handoff calls in a row never both succeed, even
///   with different certificates.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun handoff_cert_written_once(
    hashi: &mut Hashi,
    epoch: u64,
    cert1: CommitteeSignature,
    cert2: CommitteeSignature,
    ctx: &TxContext,
) {
    hashi::reconfig::submit_committee_handoff_for_testing(hashi, epoch, cert1, ctx);
    hashi::reconfig::submit_committee_handoff_for_testing(hashi, epoch, cert2, ctx);

    cvlm_assert(false);
}

/// @title The handoff certificate stays set while reconfiguring
/// @description For each entry point that can modify the committee set, if the handoff
///   certificate was set before a successful call and a reconfiguration is still
///   pending after it, the certificate is still set.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun handoff_cert_is_latched(hashi: &mut Hashi, target: Function) {
    let had_cert = hashi.committee_set().pending_handoff_cert_is_set();

    invoke(target, hashi);

    let cs = hashi.committee_set();
    if (had_cert && cs.is_reconfiguring()) {
        cvlm_assert(cs.pending_handoff_cert_is_set());
    };
}

/// @title end_reconfig requires the handoff certificate after genesis
/// @description A successful end_reconfig requires that either the MPC public key was
///   empty before the call (the initial reconfiguration) or the handoff certificate was
///   set.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun end_reconfig_requires_handoff_when_not_initial(
    hashi: &mut Hashi,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    let was_initial = hashi.committee_set().mpc_public_key().is_empty();
    let had_cert = hashi.committee_set().pending_handoff_cert_is_set();

    hashi::reconfig::end_reconfig_for_testing(hashi, mpc_public_key, mpc_cert, ctx);

    cvlm_assert(was_initial || had_cert);
}

/// @title Genesis completes with a non-empty MPC public key
/// @description After a successful end_reconfig called with an empty MPC public key, the
///   committee set's MPC public key is non-empty. If it could stay empty, every later
///   end_reconfig would count as initial and require no handoff certificate.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun genesis_completes_with_non_empty_mpc_key(
    hashi: &mut Hashi,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    hashi::reconfig::end_reconfig_for_testing(hashi, vector[], mpc_cert, ctx);

    cvlm_assert(hashi.committee_set().mpc_public_key().length() > 0);
}
