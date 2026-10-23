// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::caller_membership::Refusal;
use crate::mpc::count_check;
use crate::mpc::count_check::AvssShape;
use crate::mpc::count_check::CountCheckError;
use crate::mpc::shape_params::CommitteeShape;
use crate::mpc::shape_params::ShapeParams;
use crate::mpc::types::MpcError;
use crate::mpc::types::MpcResult;
use crate::mpc::types::ProtocolType;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::types::ShareIndex;
use hashi_types::proto;
use std::collections::BTreeSet;
use sui_rpc::proto::sui::rpc::v2::Bcs;
use sui_sdk_types::Address;

pub(super) fn check_send_messages(
    shape: &ShapeParams,
    sender: Address,
    request: &proto::SendMessagesRequest,
) -> MpcResult<()> {
    use proto::send_messages_request::Messages;
    let current = shape.current();
    let holder = current
        .own_party()
        .ok_or_else(|| MpcError::InvalidMessage {
            sender,
            reason: format!(
                "not in the epoch {} committee: no receiver role this epoch",
                shape.epoch()
            ),
        })?;
    match &request.messages {
        Some(Messages::DkgMessage(message)) => {
            reject_kind_mismatch(shape, sender, ProtocolType::Dkg)?;
            member_party(current, sender, "Dealer")?;
            count_checked(
                sender,
                count_check::check_avss_message(bytes(message), current.avss_shape()),
            )
        }
        Some(Messages::RotationMessages(rotation)) => {
            reject_kind_mismatch(shape, sender, ProtocolType::KeyRotation)?;
            let owned = rotation_shares_of(shape, sender)?;
            count_checked(
                sender,
                check_rotation_map(rotation, &owned, current.avss_shape()),
            )
        }
        Some(Messages::AvidNonceMessage(avid)) => {
            check_avid_nonce_message(shape, sender, holder, avid)
        }
        None => Ok(()),
    }
}

pub(super) fn complain_committee<'a>(
    shape: &'a ShapeParams,
    epoch: u64,
    caller: &Address,
) -> Result<&'a CommitteeShape, Refusal> {
    let committee = shape
        .committee_for_epoch(epoch)
        .ok_or(Refusal::CommitteeUnknown)?;
    committee.party_of(caller).ok_or(Refusal::NotMember)?;
    Ok(committee)
}

pub(super) fn check_complain(
    shape: &ShapeParams,
    committee: &CommitteeShape,
    caller: Address,
    epoch: u64,
    request: &proto::ComplainRequest,
) -> MpcResult<()> {
    committee
        .own_party()
        .ok_or_else(|| MpcError::InvalidMessage {
            sender: caller,
            reason: format!("not in the epoch {epoch} committee: no receiver role this epoch"),
        })?;
    if request.protocol_type == Some(proto::MpcProtocolType::KeyRotation as i32) {
        check_complained_share(shape, caller, epoch, request)?;
    }
    request.complaint.as_ref().map_or(Ok(()), |complaint| {
        count_checked(
            caller,
            count_check::check_protocol_complaint(bytes(complaint), committee.weights()),
        )
    })
}

fn check_avid_nonce_message(
    shape: &ShapeParams,
    sender: Address,
    holder: PartyId,
    avid: &proto::AvidNonceMessage,
) -> MpcResult<()> {
    use proto::avid_nonce_message::Kind;
    let current = shape.current();
    let dealer = weighted_party(current, sender, "Dealer")?;
    let avss_message = |encoded: Option<&Bcs>| {
        encoded.map_or(Ok(()), |payload| {
            count_checked(
                sender,
                count_check::check_avid_avss_message(bytes(payload), shape.avid_shape(), dealer),
            )
        })
    };
    match &avid.kind {
        Some(Kind::Optimistic(optimistic)) => avss_message(optimistic.message.as_ref()),
        Some(Kind::Dispersal(dispersal)) => {
            let dispersal_shape = shape.avid_dispersal_shape(dealer).ok_or_else(|| {
                MpcError::InvalidConfig(format!(
                    "epoch {} has no AVID data shards: reduced weight is at most twice max_faulty",
                    shape.epoch()
                ))
            })?;
            dispersal.dispersal.as_ref().map_or(Ok(()), |rows| {
                count_checked(
                    sender,
                    count_check::check_dispersal(bytes(rows), dispersal_shape, holder),
                )
            })?;
            dispersal.confirm_cert.as_ref().map_or(Ok(()), |cert| {
                count_checked(
                    sender,
                    count_check::check_confirm_certificate(bytes(cert), current.weights()),
                )
            })?;
            avss_message(dispersal.optimistic_message.as_ref())
        }
        Some(Kind::Echo(_)) => Err(MpcError::InvalidMessage {
            sender,
            reason: "AVID echoes are pull-served, not pushed".into(),
        }),
        None => Ok(()),
    }
}

fn check_complained_share(
    shape: &ShapeParams,
    caller: Address,
    epoch: u64,
    request: &proto::ComplainRequest,
) -> MpcResult<()> {
    let share_index = request
        .share_index
        .and_then(|index| u16::try_from(index).ok())
        .and_then(ShareIndex::new)
        .ok_or_else(|| MpcError::InvalidMessage {
            sender: caller,
            reason: "Rotation complaint requires a non-zero u16 share_index".into(),
        })?;
    let dealer = request
        .dealer
        .as_deref()
        .and_then(|dealer| dealer.parse::<Address>().ok())
        .ok_or_else(|| MpcError::InvalidMessage {
            sender: caller,
            reason: "Rotation complaint requires a valid dealer".into(),
        })?;
    shape
        .dealing_committee_for_epoch(epoch)
        .ok_or_else(|| {
            MpcError::InvalidConfig(format!("no dealing committee known for epoch {epoch}"))
        })?
        .share_ids_of(&dealer)
        .filter(|owned| owned.contains(&share_index))
        .map(drop)
        .ok_or_else(|| MpcError::InvalidMessage {
            sender: caller,
            reason: format!("Share index {share_index} does not belong to dealer {dealer}"),
        })
}

fn rotation_shares_of(shape: &ShapeParams, dealer: Address) -> MpcResult<Vec<ShareIndex>> {
    shape
        .dealing_committee_for_epoch(shape.epoch())
        .ok_or_else(|| MpcError::InvalidConfig("Key rotation requires previous committee".into()))?
        .share_ids_of(&dealer)
        .ok_or_else(|| MpcError::InvalidMessage {
            sender: dealer,
            reason: "Dealer not in previous committee".into(),
        })
}

fn check_rotation_map(
    rotation: &proto::RotationMessages,
    owned: &[ShareIndex],
    shape: AvssShape,
) -> Result<(), CountCheckError> {
    const FIELD: &str = "rotation_messages";
    (rotation.len() <= owned.len())
        .then_some(())
        .ok_or(CountCheckError::TooMany {
            field: FIELD,
            found: rotation.len(),
            max: owned.len(),
        })?;
    let mut seen = BTreeSet::new();
    rotation.iter().try_for_each(|entry| {
        let (key, message) = entry.map_err(|e| CountCheckError::BadEntry {
            field: FIELD,
            reason: e.to_string(),
        })?;
        let index =
            u16::try_from(key).map_err(|_| CountCheckError::KeyRange { field: FIELD, key })?;
        ShareIndex::new(index)
            .filter(|share_index| owned.contains(share_index))
            .ok_or(CountCheckError::UnownedKey {
                field: FIELD,
                index,
            })?;
        seen.insert(index)
            .then_some(())
            .ok_or(CountCheckError::DuplicateKey {
                field: FIELD,
                index,
            })?;
        count_check::check_avss_message(bytes(&message), shape)
    })
}

fn reject_kind_mismatch(shape: &ShapeParams, sender: Address, kind: ProtocolType) -> MpcResult<()> {
    (*shape.protocol_type() == kind)
        .then_some(())
        .ok_or_else(|| MpcError::InvalidMessage {
            sender,
            reason: format!(
                "{kind:?} message rejected: this epoch runs {:?}",
                shape.protocol_type()
            ),
        })
}

fn member_party(committee: &CommitteeShape, address: Address, role: &str) -> MpcResult<PartyId> {
    committee
        .party_of(&address)
        .ok_or_else(|| MpcError::InvalidMessage {
            sender: address,
            reason: format!("{role} not in committee"),
        })
}

fn weighted_party(committee: &CommitteeShape, address: Address, role: &str) -> MpcResult<PartyId> {
    let party = member_party(committee, address, role)?;
    (committee.weight_of(party) > 0)
        .then_some(party)
        .ok_or_else(|| MpcError::InvalidMessage {
            sender: address,
            reason: format!("{role} has zero reduced weight in this committee"),
        })
}

fn count_checked(sender: Address, checked: Result<(), CountCheckError>) -> MpcResult<()> {
    checked.map_err(|e| MpcError::CountCheckRefused {
        sender,
        reason: e.to_string(),
    })
}

fn bytes(bcs: &Bcs) -> &[u8] {
    bcs.value.as_deref().unwrap_or(&[])
}
