// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::mpc::PreparedMessages;
use crate::mpc::count_check;
use crate::mpc::count_check::CountCheckError;
use crate::mpc::message_cache::Cached;
use crate::mpc::shape_params::ShapeParams;
use crate::mpc::types::AvidNonceRetrievalMessage;
use crate::mpc::types::GetPublicMpcOutputResponse;
use crate::mpc::types::Messages;
use crate::mpc::types::MessagesHash;
use crate::mpc::types::ProtocolTypeIndicator;
use crate::mpc::types::RetrieveMessagesResponse;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss_avid;
use hashi_types::proto;
use std::collections::BTreeMap;
use sui_rpc::proto::sui::rpc::v2::Bcs;
use sui_sdk_types::Address;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Refused {
    #[error("count check: {0}")]
    Count(#[from] CountCheckError),
    #[error("{0}")]
    Variant(String),
    #[error("share index {0} is not a non-zero u16")]
    Shape(u32),
    #[error("responder not in the committee")]
    Member,
    #[error("bytes don't match the certificate's hash")]
    Hash,
    #[error("{0}")]
    Decode(String),
}

impl Refused {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Count(_) => "count",
            Self::Variant(_) => "variant",
            Self::Shape(_) => "shape",
            Self::Member => "member",
            Self::Hash => "hash",
            Self::Decode(_) => "decode",
        }
    }
}

pub(crate) fn certified_retrieval(
    protocol_type: ProtocolTypeIndicator,
    response: proto::RetrieveMessagesResponse,
    expected: MessagesHash,
) -> Result<PreparedMessages, Refused> {
    use proto::retrieve_messages_response::Messages as Wire;
    match (protocol_type, response.messages) {
        (ProtocolTypeIndicator::Dkg, Some(Wire::DkgMessage(message))) => {
            Cached::certified(bytes(&message), expected).map(PreparedMessages::Dkg)
        }
        (ProtocolTypeIndicator::KeyRotation, Some(Wire::RotationMessages(map))) => {
            rotation_blob(map)
                .and_then(|blob| Cached::certified(&blob, expected).map(PreparedMessages::Rotation))
        }
        (protocol_type, _) => Err(Refused::Variant(format!(
            "not a {protocol_type:?} retrieval response"
        ))),
    }
}

pub(crate) fn avid_bundle(
    signer: Address,
    shape: &ShapeParams,
    dealer: PartyId,
    response: &proto::RetrieveMessagesResponse,
) -> Result<AvidNonceRetrievalMessage, Refused> {
    use proto::retrieve_messages_response::Messages as Wire;
    let not_avid = || Refused::Variant("not an AVID retrieval response".into());
    let Some(Wire::AvidNonceRetrievalMessage(bundle)) = &response.messages else {
        return Err(not_avid());
    };
    let current = shape.current();
    let responder = current.party_of(&signer).ok_or(Refused::Member)?;
    bundle
        .common
        .as_ref()
        .map_or(Ok(()), |common| {
            count_check::check_avss_common_message(bytes(common), shape.avid_shape(), dealer)
        })
        .and_then(|()| {
            bundle.echo.as_ref().map_or(Ok(()), |echo| {
                count_check::check_echo(bytes(echo), current.weights(), responder)
            })
        })
        .and_then(|()| {
            bundle.avid_vote.as_ref().map_or(Ok(()), |vote| {
                count_check::check_avid_vote(bytes(vote), current.weights())
            })
        })?;
    match RetrieveMessagesResponse::try_from(response)
        .map_err(|e| Refused::Decode(e.to_string()))?
        .messages
    {
        Messages::AvidNonceRetrieval(bundle) => Ok(bundle),
        _ => Err(not_avid()),
    }
}

pub(crate) fn avss_complaint_response(
    protocol_type: ProtocolTypeIndicator,
    responder_weight: Option<u16>,
    response: &proto::ComplainResponse,
) -> Result<avss::ComplaintResponse, Refused> {
    use proto::complain_response::Responses;
    let shares = match (protocol_type, &response.responses) {
        (ProtocolTypeIndicator::Dkg, Some(Responses::DkgResponse(shares)))
        | (ProtocolTypeIndicator::KeyRotation, Some(Responses::RotationResponse(shares))) => {
            bytes(shares)
        }
        (protocol_type, _) => {
            return Err(Refused::Variant(format!(
                "not a {protocol_type:?} complaint response"
            )));
        }
    };
    let weight = responder_weight.ok_or(Refused::Member)?;
    count_check::check_avss_complaint_response(shares, weight)?;
    bcs::from_bytes(shares).map_err(complaint_decode_refused)
}

pub(crate) fn avid_complaint_response(
    response: &proto::ComplainResponse,
) -> Result<batch_avss_avid::ComplaintResponse, Refused> {
    use proto::complain_response::Responses;
    let Some(Responses::AvidNonceResponse(avid)) = &response.responses else {
        return Err(Refused::Variant("not an AVID complaint response".into()));
    };
    count_check::check_avid_complaint_response(bytes(avid))?;
    bcs::from_bytes(bytes(avid)).map_err(complaint_decode_refused)
}

pub(crate) fn public_output(
    response: &proto::GetPublicMpcOutputResponse,
    total_weight: u16,
) -> Result<GetPublicMpcOutputResponse, Refused> {
    let max = usize::from(total_weight);
    (response.commitments.len() <= max)
        .then_some(())
        .ok_or(CountCheckError::TooMany {
            field: "commitments",
            found: response.commitments.len(),
            max,
        })?;
    GetPublicMpcOutputResponse::try_from(response).map_err(|e| Refused::Decode(e.to_string()))
}

pub(crate) fn complaint_response_limit(responder_weight: u16) -> usize {
    2 * count_check::avss_complaint_response_size(responder_weight) + 1024
}

fn rotation_blob(map: proto::RotationMessages) -> Result<Vec<u8>, Refused> {
    const FIELD: &str = "rotation_messages";
    let max = usize::from(u16::MAX);
    (map.len() <= max)
        .then_some(())
        .ok_or(CountCheckError::TooMany {
            field: FIELD,
            found: map.len(),
            max,
        })?;
    let mut entries = BTreeMap::new();
    for entry in map.into_entries() {
        let (key, message) = entry.map_err(|e| Refused::Decode(format!("{FIELD}: {e}")))?;
        let index = u16::try_from(key)
            .ok()
            .filter(|index| *index != 0)
            .ok_or(Refused::Shape(key))?;
        if entries
            .insert(index.to_le_bytes(), message.value.unwrap_or_default())
            .is_some()
        {
            return Err(Refused::Count(CountCheckError::DuplicateKey {
                field: FIELD,
                index,
            }));
        }
    }
    let mut blob = Vec::with_capacity(
        5 + entries
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>(),
    );
    let mut count = entries.len();
    while count >= 0x80 {
        blob.push(count as u8 | 0x80);
        count >>= 7;
    }
    blob.push(count as u8);
    for (key, value) in &entries {
        blob.extend_from_slice(key);
        blob.extend_from_slice(value);
    }
    Ok(blob)
}

fn complaint_decode_refused(e: bcs::Error) -> Refused {
    Refused::Decode(format!("complaint response: {e}"))
}

fn bytes(bcs: &Bcs) -> &[u8] {
    bcs.value.as_deref().unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::rpc::public_output_response_limit;
    use crate::mpc::types::ComplaintResponse;
    use crate::mpc::types::PublicMpcOutput;
    use fastcrypto::groups::GroupElement;
    use fastcrypto_tbls::polynomial::Eval;
    use fastcrypto_tbls::threshold_schnorr::G;
    use fastcrypto_tbls::threshold_schnorr::S;
    use fastcrypto_tbls::types::ShareIndex;
    use prost::Message;

    fn honest_public_output(total_weight: u16) -> proto::GetPublicMpcOutputResponse {
        proto::GetPublicMpcOutputResponse::from(&GetPublicMpcOutputResponse {
            output: PublicMpcOutput {
                public_key: G::generator(),
                commitments: (1..=total_weight)
                    .map(|index| (ShareIndex::new(index).unwrap(), G::generator()))
                    .collect(),
            },
        })
    }

    #[test]
    fn complaint_and_signature_reply_limits_admit_the_largest_honest_replies() {
        for weight in [0u16, 1, 127, 128, 10_000] {
            let response =
                proto::ComplainResponse::from(&ComplaintResponse::Dkg(avss::ComplaintResponse {
                    shares: avss::SharesForNode {
                        shares: (1..=weight)
                            .map(|index| Eval {
                                index: ShareIndex::new(index).unwrap(),
                                value: S::zero(),
                            })
                            .collect(),
                    },
                }));
            assert!(response.encoded_len() <= complaint_response_limit(weight));
            avss_complaint_response(ProtocolTypeIndicator::Dkg, Some(weight), &response).unwrap();
        }
        let reply = proto::SendMessagesResponse {
            signature: Some(vec![0; 96].into()),
        };
        assert!(reply.encoded_len() <= crate::grpc::SIGNATURE_REPLY_LIMIT);
    }

    #[test]
    fn a_held_rotation_map_is_refused_before_its_blob_is_rebuilt() {
        let held = |entries: Vec<(u32, Bcs)>| {
            let wire = proto::RetrieveMessagesResponse {
                messages: Some(
                    proto::retrieve_messages_response::Messages::RotationMessages(
                        entries.into_iter().collect(),
                    ),
                ),
            }
            .encode_to_vec();
            proto::RetrieveMessagesResponse::decode(wire.as_slice()).unwrap()
        };
        let refused = |response: proto::RetrieveMessagesResponse| {
            certified_retrieval(
                ProtocolTypeIndicator::KeyRotation,
                response,
                MessagesHash::from([7; 32]),
            )
            .err()
            .unwrap()
        };

        assert!(matches!(
            refused(held(
                (0..=u32::from(u16::MAX))
                    .map(|key| (key, Bcs::default()))
                    .collect()
            )),
            Refused::Count(CountCheckError::TooMany { found: 65_536, .. })
        ));
        assert!(matches!(
            refused(held(vec![(1, Bcs::default()), (1, Bcs::default())])),
            Refused::Count(CountCheckError::DuplicateKey { index: 1, .. })
        ));
        assert!(matches!(
            refused(
                proto::RetrieveMessagesResponse::decode(&[0x12, 3, 0x0a, 1, 0x08][..]).unwrap()
            ),
            Refused::Decode(_)
        ));
    }

    #[test]
    fn public_output_limit_admits_the_largest_honest_reply() {
        for total_weight in [1, 100, 10_000] {
            assert!(
                honest_public_output(total_weight).encoded_len()
                    <= public_output_response_limit(total_weight)
            );
        }
    }

    #[test]
    fn a_public_output_with_more_commitments_than_shares_is_refused_before_decoding() {
        let honest = honest_public_output(4);
        assert!(public_output(&honest, 4).is_ok());
        let mut padded = honest;
        padded.commitments.insert(5, Bcs::from(vec![0xff; 33]));
        assert!(matches!(
            public_output(&padded, 4),
            Err(Refused::Count(CountCheckError::TooMany {
                found: 5,
                max: 4,
                ..
            }))
        ));
    }
}
