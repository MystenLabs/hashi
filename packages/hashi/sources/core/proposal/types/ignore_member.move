// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for ignoring (or re-admitting) a registered committee
/// member. An ignored member is treated as no longer part of the committee:
/// the next committee formation skips them, so their voting weight drops out
/// of total stake and every downstream threshold (certificates, proposal
/// quorums, MPC parameters) re-derives without them.
///
/// Semantics and limits:
/// - The flag takes effect at the next committee FORMATION (`start_reconfig`).
///   If a reconfiguration is already in flight when the proposal executes,
///   that is one epoch later — the pending committee is immutable once formed.
///   The current epoch's committee is never altered: bitmap indices, MPC
///   party ids, and leader rotation all stay intact until the boundary.
/// - The proposal targets the validator ADDRESS; it applies to whatever
///   registration holds that address at execute time, including a
///   re-registration after a deregistration cycle.
/// - Exclusion is only reachable while governance itself is live: this
///   proposal needs 6667 bps of the full current denominator, and the epoch
///   transition enacting it needs the outgoing committee's handoff
///   certificate at the same threshold (whose denominator still includes the
///   ignored member). Non-participating weight must therefore stay at or
///   below 3333 bps of the current committee — the standard BFT bound —
///   for the mechanism to help; beyond it the system is already stuck.
/// - Ignoring does not touch the registry: the member stays registered,
///   keeps proposal/vote authorization, and can be re-admitted by executing
///   the same proposal type with `ignored: false`. If every registered
///   member were ignored, committee formation would abort and the current
///   committee would simply continue — recoverable by un-ignoring.
module hashi::ignore_member;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Errors ~~~~~~~

#[error(code = 0)]
const EMemberNotRegistered: vector<u8> = b"Target validator is not a registered member";
#[error(code = 1)]
const EAlreadyInRequestedState: vector<u8> = b"Member is already in the requested ignored state";

// ~~~~~~~ Structs ~~~~~~~

public struct IgnoreMember has copy, drop, store {
    validator_address: address,
    ignored: bool,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun propose(
    hashi: &mut Hashi,
    validator_address: address,
    target_validator_address: address,
    ignored: bool,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    // Fast feedback for the proposer; state can still drift before execute.
    assert!(hashi.committee_set().has_member(target_validator_address), EMemberNotRegistered);
    assert!(
        hashi.committee_set().is_member_ignored(target_validator_address) != ignored,
        EAlreadyInRequestedState,
    );
    proposal::create(
        hashi,
        validator_address,
        IgnoreMember { validator_address: target_validator_address, ignored },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    hashi.versioning().assert_version_enabled();
    let IgnoreMember { validator_address, ignored } = proposal::execute(hashi, proposal_id, clock);
    // Registered-ness is re-asserted inside the setter (state may have
    // drifted since propose). The no-op condition is deliberately not
    // re-asserted: racing proposals degrade to an idempotent write, never a
    // wrong state, and any outcome is revocable by the opposite proposal.
    hashi.committee_set_mut().set_member_ignored(validator_address, ignored);
}
