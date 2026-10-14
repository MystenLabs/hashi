// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::mpc::count_check;
use crate::mpc::count_check::CountCheckError;
use crate::mpc::shape_params::CommitteeShape;
use crate::mpc::shape_params::ShapeParams;
use crate::mpc::types::AvidRoundState;
use crate::mpc::types::HeldAvidEchoes;
use crate::mpc::types::Messages;
use crate::mpc::types::MessagesHash;
use crate::mpc::types::MpcError;
use crate::mpc::types::MpcResult;
use crate::mpc::types::RotationMessages;
use fastcrypto::hash::Blake2b256;
use fastcrypto::hash::HashFunction;
use fastcrypto_tbls::threshold_schnorr::avss;
use serde::de::DeserializeOwned;
use sui_sdk_types::Address;

pub(crate) fn dkg_message(
    shape: &ShapeParams,
    epoch: u64,
    dealer: &Address,
    bytes: &[u8],
) -> MpcResult<avss::Message> {
    let avss = avss_shape(shape, epoch, dealer)?;
    decode(dealer, bytes, count_check::check_avss_message(bytes, avss))
}

pub(crate) fn rotation_messages(
    shape: &ShapeParams,
    epoch: u64,
    dealer: &Address,
    bytes: &[u8],
) -> MpcResult<RotationMessages> {
    let avss = avss_shape(shape, epoch, dealer)?;
    let owned = shape
        .dealing_committee_for_epoch(epoch)
        .ok_or_else(|| {
            refused(
                dealer,
                format!("no dealing committee known for epoch {epoch}"),
            )
        })?
        .share_ids_of(dealer)
        .ok_or_else(|| {
            refused(
                dealer,
                format!("no shares in epoch {epoch}'s dealing committee"),
            )
        })?;
    decode(
        dealer,
        bytes,
        count_check::check_rotation_messages(bytes, avss, &owned).map(drop),
    )
}

pub(crate) fn avid_round_state(
    shape: &ShapeParams,
    epoch: u64,
    dealer: &Address,
    bytes: &[u8],
) -> MpcResult<AvidRoundState> {
    let dealer_party = avid_committee(shape, epoch, dealer)?
        .party_of(dealer)
        .ok_or_else(|| refused(dealer, "not in the committee".into()))?;
    decode(
        dealer,
        bytes,
        count_check::check_avid_avss_message(bytes, shape.avid_shape(), dealer_party),
    )
}

pub(crate) fn held_avid_echoes(
    shape: &ShapeParams,
    epoch: u64,
    dealer: &Address,
    bytes: &[u8],
) -> MpcResult<HeldAvidEchoes> {
    let current = avid_committee(shape, epoch, dealer)?;
    let holder = current
        .own_party()
        .ok_or_else(|| refused(dealer, "this node is not in the committee".into()))?;
    decode(
        dealer,
        bytes,
        count_check::check_held_avid_echoes(bytes, current.weights(), holder),
    )
}

pub(crate) fn dkg_message_hash(bytes: &[u8]) -> MessagesHash {
    variant_hash(Messages::DKG_VARIANT, bytes)
}

pub(crate) fn rotation_messages_hash(bytes: &[u8]) -> MessagesHash {
    variant_hash(Messages::ROTATION_VARIANT, bytes)
}

fn variant_hash(variant: u8, bytes: &[u8]) -> MessagesHash {
    let mut hasher = Blake2b256::default();
    hasher.update([variant]);
    hasher.update(bytes);
    MessagesHash::from(hasher.finalize().digest)
}

fn avss_shape(
    shape: &ShapeParams,
    epoch: u64,
    dealer: &Address,
) -> MpcResult<count_check::AvssShape> {
    shape
        .committee_for_epoch(epoch)
        .map(CommitteeShape::avss_shape)
        .ok_or_else(|| refused(dealer, format!("no committee known for epoch {epoch}")))
}

fn avid_committee<'a>(
    shape: &'a ShapeParams,
    epoch: u64,
    dealer: &Address,
) -> MpcResult<&'a CommitteeShape> {
    (epoch == shape.epoch())
        .then(|| shape.current())
        .ok_or_else(|| refused(dealer, format!("no AVID parameters for epoch {epoch}")))
}

fn decode<T: DeserializeOwned>(
    dealer: &Address,
    bytes: &[u8],
    checked: Result<(), CountCheckError>,
) -> MpcResult<T> {
    checked.map_err(|e| refused(dealer, format!("count check: {e}")))?;
    bcs::from_bytes(bytes).map_err(|e| refused(dealer, e.to_string()))
}

fn refused(dealer: &Address, reason: String) -> MpcError {
    MpcError::StoredRowRefused {
        dealer: *dealer,
        reason,
    }
}
