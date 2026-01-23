/// Module: reconfig
module hashi::reconfig;

use hashi::{committee, hashi::Hashi, threshold};
use sui::table::{Self, Table};

const ENotReconfiguring: u64 = 0;
const ENotInCommittee: u64 = 1;
const ETooEarlyToCleanup: u64 = 2;

/// Marker message that committee members sign to confirm successful key rotation.
public struct ReconfigCompletionMessage has copy, drop, store {}

public struct ReconfigCompletionSignature has copy, drop, store {
    signature: vector<u8>,
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
    signature: vector<u8>,
    signers_bitmap: vector<u8>,
    ctx: &TxContext,
) {
    self.config().assert_version_enabled();
    assert!(self.committee_set().is_reconfiguring(), ENotReconfiguring);
    let next_epoch = self.committee_set().pending_epoch_change().destroy_some();
    let next_committee = self.committee_set().get_committee(next_epoch);
    let message = ReconfigCompletionMessage {};
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

entry fun publish_reconfig_completion_signature(
    self: &mut Hashi,
    signature: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
    assert!(self.committee_set().is_reconfiguring(), ENotReconfiguring);
    let next_epoch = self.committee_set().pending_epoch_change().destroy_some();
    let signer = ctx.sender();
    let next_committee = self.committee_set().get_committee(next_epoch);
    assert!(next_committee.has_member(&signer), ENotInCommittee);
    let reconfig_sigs = self.reconfig_signatures_mut();
    if (!reconfig_sigs.contains(next_epoch)) {
        reconfig_sigs.add(next_epoch, table::new<address, ReconfigCompletionSignature>(ctx));
    };
    let epoch_sigs: &mut Table<address, ReconfigCompletionSignature> = reconfig_sigs.borrow_mut(
        next_epoch,
    );
    if (!epoch_sigs.contains(signer)) {
        let sig = ReconfigCompletionSignature { signature };
        epoch_sigs.add(signer, sig);
    };
}

entry fun cleanup_reconfig_signatures(self: &mut Hashi, epoch: u64) {
    self.config().assert_version_enabled();
    let current_epoch = self.committee_set().epoch();
    assert!(current_epoch >= epoch + 2, ETooEarlyToCleanup);
    let reconfig_sigs = self.reconfig_signatures_mut();
    if (reconfig_sigs.contains(epoch)) {
        let sigs: Table<address, ReconfigCompletionSignature> = reconfig_sigs.remove(epoch);
        sigs.drop();
    };
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
