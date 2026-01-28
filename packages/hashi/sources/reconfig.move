/// Module: reconfig
module hashi::reconfig;

use hashi::{committee, hashi::Hashi, threshold};

const ENotReconfiguring: u64 = 0;

/// Message that committee members sign to confirm successful key rotation.
public struct ReconfigCompletionMessage has copy, drop, store {
    /// The epoch of the new committee.
    epoch: u64,
    /// The MPC committee's threshold public key.
    mpc_public_key: vector<u8>,
}

entry fun start_reconfig(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
) {
    self.config().assert_version_enabled();
    // Assert that we are not already reconfiguring
    assert!(!self.committee_set().is_reconfiguring());

    let epoch = self
        .committee_set_mut()
        .start_reconfig(
            sui_system,
            ctx,
        );

    sui::event::emit(StartReconfigEvent { epoch });
}

entry fun end_reconfig(
    self: &mut Hashi,
    mpc_public_key: vector<u8>,
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    ctx: &TxContext,
) {
    self.config().assert_version_enabled();
    assert!(self.committee_set().is_reconfiguring(), ENotReconfiguring);
    let next_epoch = self.committee_set().pending_epoch_change().destroy_some();
    let next_committee = self.committee_set().get_committee(next_epoch);
    let message = ReconfigCompletionMessage { epoch: next_epoch, mpc_public_key };
    let sig = committee::new_committee_signature(next_epoch, signature, signers_bitmap);
    let threshold = threshold::certificate_threshold(next_committee.total_weight() as u16) as u64;
    let _cert = next_committee.verify_certificate(message, sig, threshold);
    let epoch = self.committee_set_mut().end_reconfig(ctx);
    sui::event::emit(EndReconfigEvent { epoch });
}

// TODO include a cert from the current committee to abort a failed reconfig.
entry fun abort_reconfig(self: &mut Hashi, ctx: &TxContext) {
    self.config().assert_version_enabled();
    // Assert that we are reconfiguring
    assert!(self.committee_set().is_reconfiguring());
    let epoch = self.committee_set_mut().abort_reconfig(ctx);

    sui::event::emit(AbortReconfigEvent { epoch });
}

public struct StartReconfigEvent has copy, drop {
    epoch: u64,
}

public struct EndReconfigEvent has copy, drop {
    epoch: u64,
}

public struct AbortReconfigEvent has copy, drop {
    epoch: u64,
}
