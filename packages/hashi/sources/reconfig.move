/// Module: reconfig
module hashi::reconfig;

use hashi::hashi::Hashi;

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

//TODO include a cert from the next committee to confirm the handover.
entry fun end_reconfig(self: &mut Hashi, ctx: &TxContext) {
    self.config().assert_version_enabled();
    // Assert that we are reconfiguring
    assert!(self.committee_set().is_reconfiguring());
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
