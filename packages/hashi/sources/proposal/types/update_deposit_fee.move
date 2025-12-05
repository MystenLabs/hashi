// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::update_deposit_fee;

use hashi::{hashi::Hashi, proposal::{Self, Proposal}};
use std::string::String;
use sui::vec_map::VecMap;

const THRESHOLD_BPS: u64 = 10000;

public struct UpdateDepositFee has drop, store {
    fee: u64,
}

public fun new(fee: u64): UpdateDepositFee {
    UpdateDepositFee { fee }
}

public fun propose(
    hashi: &mut Hashi,
    fee: u64,
    metadata: VecMap<String, String>,
    ctx: &mut TxContext,
) {
    proposal::create(hashi, UpdateDepositFee { fee }, THRESHOLD_BPS, metadata, ctx)
}

public fun execute(hashi: &mut Hashi, proposal: Proposal<UpdateDepositFee>) {
    let UpdateDepositFee { fee } = proposal.execute(hashi);
    hashi.config_mut().set_deposit_fee(fee);
}
