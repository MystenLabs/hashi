use crate::mpc::types;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::complaint;
use fastcrypto_tbls::types::ShareIndex;
use hashi_types::committee::BLS12381Signature;
use hashi_types::proto;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use sui_rpc::proto::TryFromProtoError;
use sui_rpc::proto::sui::rpc::v2::Bcs;
use sui_sdk_types::Address;

/// Get a required field from a proto message.
#[allow(clippy::result_large_err)]
fn required<T>(field: Option<T>, name: &str) -> Result<T, TryFromProtoError> {
    field.ok_or_else(|| TryFromProtoError::missing(name))
}

/// Parse an address from a hex string.
#[allow(clippy::result_large_err)]
fn parse_address(s: &str, field: &str) -> Result<Address, TryFromProtoError> {
    s.parse::<Address>()
        .map_err(|e| TryFromProtoError::invalid(field, e))
}

/// Deserialize a BCS-encoded proto field.
#[allow(clippy::result_large_err)]
fn deserialize_bcs<'de, T: Deserialize<'de>>(
    bcs: &'de Bcs,
    field: &str,
) -> Result<T, TryFromProtoError> {
    bcs.deserialize()
        .map_err(|e| TryFromProtoError::invalid(field, e))
}

/// Serialize a value to BCS with a type name.
fn serialize_bcs<T: Serialize>(value: &T) -> Bcs {
    Bcs::serialize(value)
        .expect("serialization should succeed")
        .with_name(std::any::type_name::<T>())
}

/// Parse a share index map from proto.
#[allow(clippy::result_large_err)]
fn parse_rotation_messages_map(
    map: &std::collections::HashMap<u32, Bcs>,
) -> Result<BTreeMap<ShareIndex, avss::Message>, TryFromProtoError> {
    let mut messages = BTreeMap::new();
    for (&index, bcs) in map {
        let share_index = ShareIndex::new(index as u16).ok_or_else(|| {
            TryFromProtoError::invalid("rotation_messages.key", "index must be non-zero")
        })?;
        let message: avss::Message = deserialize_bcs(bcs, "rotation_messages.value")?;
        messages.insert(share_index, message);
    }
    Ok(messages)
}

/// Convert rotation messages map to proto format.
fn rotation_messages_to_proto(
    messages: &BTreeMap<ShareIndex, avss::Message>,
) -> std::collections::HashMap<u32, Bcs> {
    messages
        .iter()
        .map(|(idx, msg)| (idx.get() as u32, serialize_bcs(msg)))
        .collect()
}

//
// SendMessagesRequest
//

impl types::SendMessagesRequest {
    pub fn to_proto(&self, epoch: u64) -> proto::SendMessagesRequest {
        use proto::send_messages_request::Messages;
        let messages = match &self.messages {
            types::Messages::Dkg(message) => Messages::DkgMessage(serialize_bcs(message)),
            types::Messages::Rotation(messages) => {
                Messages::RotationMessages(proto::RotationMessages {
                    messages: rotation_messages_to_proto(messages),
                })
            }
        };
        proto::SendMessagesRequest {
            epoch: Some(epoch),
            messages: Some(messages),
        }
    }
}

impl TryFrom<&proto::SendMessagesRequest> for types::SendMessagesRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::SendMessagesRequest) -> Result<Self, Self::Error> {
        use proto::send_messages_request::Messages;
        let messages = match &value.messages {
            Some(Messages::DkgMessage(dkg_message)) => {
                let message: avss::Message = deserialize_bcs(dkg_message, "dkg_message")?;
                types::Messages::Dkg(message)
            }
            Some(Messages::RotationMessages(rotation)) => {
                types::Messages::Rotation(parse_rotation_messages_map(&rotation.messages)?)
            }
            None => {
                return Err(TryFromProtoError::missing(
                    "dkg_message or rotation_messages",
                ));
            }
        };
        Ok(Self { messages })
    }
}

//
// SendMessagesResponse
//

impl From<&types::SendMessagesResponse> for proto::SendMessagesResponse {
    fn from(value: &types::SendMessagesResponse) -> Self {
        Self {
            signature: Some(value.signature.as_ref().to_vec().into()),
        }
    }
}

impl TryFrom<&proto::SendMessagesResponse> for types::SendMessagesResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::SendMessagesResponse) -> Result<Self, Self::Error> {
        let signature =
            BLS12381Signature::from_bytes(required(value.signature.as_ref(), "signature")?)
                .map_err(|e| TryFromProtoError::invalid("signature", e))?;
        Ok(Self { signature })
    }
}

//
// RetrieveMessagesRequest
//

impl types::RetrieveMessagesRequest {
    pub fn to_proto(&self, epoch: u64) -> proto::RetrieveMessagesRequest {
        proto::RetrieveMessagesRequest {
            epoch: Some(epoch),
            dealer: Some(self.dealer.to_string()),
        }
    }
}

impl TryFrom<&proto::RetrieveMessagesRequest> for types::RetrieveMessagesRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::RetrieveMessagesRequest) -> Result<Self, Self::Error> {
        let dealer = parse_address(required(value.dealer.as_ref(), "dealer")?, "dealer")?;
        Ok(Self { dealer })
    }
}

//
// RetrieveMessagesResponse
//

impl From<&types::RetrieveMessagesResponse> for proto::RetrieveMessagesResponse {
    fn from(value: &types::RetrieveMessagesResponse) -> Self {
        use proto::retrieve_messages_response::Messages;
        let messages = match &value.messages {
            types::Messages::Dkg(message) => Messages::DkgMessage(serialize_bcs(message)),
            types::Messages::Rotation(messages) => {
                Messages::RotationMessages(proto::RotationMessages {
                    messages: rotation_messages_to_proto(messages),
                })
            }
        };
        Self {
            messages: Some(messages),
        }
    }
}

impl TryFrom<&proto::RetrieveMessagesResponse> for types::RetrieveMessagesResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::RetrieveMessagesResponse) -> Result<Self, Self::Error> {
        use proto::retrieve_messages_response::Messages;
        let messages = match &value.messages {
            Some(Messages::DkgMessage(dkg_message)) => {
                let message: avss::Message = deserialize_bcs(dkg_message, "dkg_message")?;
                types::Messages::Dkg(message)
            }
            Some(Messages::RotationMessages(rotation)) => {
                types::Messages::Rotation(parse_rotation_messages_map(&rotation.messages)?)
            }
            None => {
                return Err(TryFromProtoError::missing(
                    "dkg_message or rotation_messages",
                ));
            }
        };
        Ok(Self { messages })
    }
}

//
// ComplainRequest
//

impl types::ComplainRequest {
    pub fn to_proto(&self, epoch: u64) -> proto::ComplainRequest {
        proto::ComplainRequest {
            epoch: Some(epoch),
            dealer: Some(self.dealer.to_string()),
            share_index: self.share_index.map(|idx| idx.get() as u32),
            complaint: Some(serialize_bcs(&self.complaint)),
        }
    }
}

impl TryFrom<&proto::ComplainRequest> for types::ComplainRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::ComplainRequest) -> Result<Self, Self::Error> {
        let dealer = parse_address(required(value.dealer.as_ref(), "dealer")?, "dealer")?;
        let share_index = value
            .share_index
            .map(|idx| {
                std::num::NonZeroU16::new(idx as u16)
                    .ok_or_else(|| TryFromProtoError::invalid("share_index", "must be non-zero"))
            })
            .transpose()?;
        let complaint: complaint::Complaint = deserialize_bcs(
            required(value.complaint.as_ref(), "complaint")?,
            "complaint",
        )?;
        Ok(Self {
            dealer,
            share_index,
            complaint,
        })
    }
}

//
// ComplainResponse
//

/// Parse rotation responses map from proto.
#[allow(clippy::result_large_err)]
fn parse_rotation_responses_map(
    map: &std::collections::HashMap<u32, Bcs>,
) -> Result<
    BTreeMap<ShareIndex, complaint::ComplaintResponse<avss::SharesForNode>>,
    TryFromProtoError,
> {
    let mut responses = BTreeMap::new();
    for (&index, bcs) in map {
        let share_index = ShareIndex::new(index as u16).ok_or_else(|| {
            TryFromProtoError::invalid("rotation_responses.key", "index must be non-zero")
        })?;
        let response: complaint::ComplaintResponse<avss::SharesForNode> =
            deserialize_bcs(bcs, "rotation_responses.value")?;
        responses.insert(share_index, response);
    }
    Ok(responses)
}

/// Convert rotation responses map to proto format.
fn rotation_responses_to_proto(
    responses: &BTreeMap<ShareIndex, complaint::ComplaintResponse<avss::SharesForNode>>,
) -> std::collections::HashMap<u32, Bcs> {
    responses
        .iter()
        .map(|(idx, resp)| (idx.get() as u32, serialize_bcs(resp)))
        .collect()
}

impl From<&types::ComplaintResponses> for proto::ComplainResponse {
    fn from(value: &types::ComplaintResponses) -> Self {
        use proto::complain_response::Responses;
        let responses = match value {
            types::ComplaintResponses::Dkg(response) => {
                Responses::DkgResponse(serialize_bcs(response))
            }
            types::ComplaintResponses::Rotation(responses) => {
                Responses::RotationResponses(proto::RotationResponses {
                    responses: rotation_responses_to_proto(responses),
                })
            }
        };
        Self {
            responses: Some(responses),
        }
    }
}

impl TryFrom<&proto::ComplainResponse> for types::ComplaintResponses {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::ComplainResponse) -> Result<Self, Self::Error> {
        use proto::complain_response::Responses;
        match &value.responses {
            Some(Responses::DkgResponse(dkg_response)) => {
                let response: complaint::ComplaintResponse<avss::SharesForNode> =
                    deserialize_bcs(dkg_response, "dkg_response")?;
                Ok(types::ComplaintResponses::Dkg(response))
            }
            Some(Responses::RotationResponses(rotation)) => {
                Ok(types::ComplaintResponses::Rotation(
                    parse_rotation_responses_map(&rotation.responses)?,
                ))
            }
            None => Err(TryFromProtoError::missing(
                "dkg_response or rotation_responses",
            )),
        }
    }
}

//
// GetPublicDkgOutputRequest
//

impl types::GetPublicDkgOutputRequest {
    pub fn to_proto(&self) -> proto::GetPublicDkgOutputRequest {
        proto::GetPublicDkgOutputRequest {
            epoch: Some(self.epoch),
        }
    }
}

impl TryFrom<&proto::GetPublicDkgOutputRequest> for types::GetPublicDkgOutputRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::GetPublicDkgOutputRequest) -> Result<Self, Self::Error> {
        let epoch = required(value.epoch, "epoch")?;
        Ok(Self { epoch })
    }
}

//
// GetPublicDkgOutputResponse
//

impl From<&types::GetPublicDkgOutputResponse> for proto::GetPublicDkgOutputResponse {
    fn from(value: &types::GetPublicDkgOutputResponse) -> Self {
        Self {
            public_key: Some(serialize_bcs(&value.output.public_key)),
            commitments: value
                .output
                .commitments
                .iter()
                .map(|(&index, value)| (index.get() as u32, serialize_bcs(value)))
                .collect(),
        }
    }
}

impl TryFrom<&proto::GetPublicDkgOutputResponse> for types::GetPublicDkgOutputResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::GetPublicDkgOutputResponse) -> Result<Self, Self::Error> {
        use fastcrypto_tbls::threshold_schnorr::G;

        let public_key = deserialize_bcs(
            required(value.public_key.as_ref(), "public_key")?,
            "public_key",
        )?;
        let mut commitments = BTreeMap::new();
        for (&index, bcs) in &value.commitments {
            let share_index = ShareIndex::new(index as u16).ok_or_else(|| {
                TryFromProtoError::invalid("commitments.key", "index must be non-zero")
            })?;
            let commitment_value: G = deserialize_bcs(bcs, "commitments.value")?;
            commitments.insert(share_index, commitment_value);
        }
        Ok(Self {
            output: types::PublicDkgOutput {
                public_key,
                commitments,
            },
        })
    }
}
