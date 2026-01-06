use crate::committee::BLS12381Signature;
use crate::dkg::types;
use crate::proto;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::complaint;
use serde::Deserialize;
use serde::Serialize;
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

//
// SendMessageRequest
//

impl types::SendMessageRequest {
    pub fn to_proto(&self, epoch: u64) -> proto::SendMessageRequest {
        proto::SendMessageRequest {
            epoch: Some(epoch),
            message: Some(serialize_bcs(&self.message)),
        }
    }
}

impl TryFrom<&proto::SendMessageRequest> for types::SendMessageRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::SendMessageRequest) -> Result<Self, Self::Error> {
        let message: avss::Message =
            deserialize_bcs(required(value.message.as_ref(), "message")?, "message")?;
        Ok(Self { message })
    }
}

//
// SendMessageResponse
//

impl From<&types::SendMessageResponse> for proto::SendMessageResponse {
    fn from(value: &types::SendMessageResponse) -> Self {
        Self {
            signature: Some(value.signature.as_ref().to_vec().into()),
        }
    }
}

impl TryFrom<&proto::SendMessageResponse> for types::SendMessageResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::SendMessageResponse) -> Result<Self, Self::Error> {
        let signature =
            BLS12381Signature::from_bytes(required(value.signature.as_ref(), "signature")?)
                .map_err(|e| TryFromProtoError::invalid("signature", e))?;
        Ok(Self { signature })
    }
}

//
// RetrieveMessageRequest
//

impl types::RetrieveMessageRequest {
    pub fn to_proto(&self, epoch: u64) -> proto::RetrieveMessageRequest {
        proto::RetrieveMessageRequest {
            epoch: Some(epoch),
            dealer: Some(self.dealer.to_string()),
        }
    }
}

impl TryFrom<&proto::RetrieveMessageRequest> for types::RetrieveMessageRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::RetrieveMessageRequest) -> Result<Self, Self::Error> {
        let dealer = parse_address(required(value.dealer.as_ref(), "dealer")?, "dealer")?;
        Ok(Self { dealer })
    }
}

//
// RetrieveMessageResponse
//

impl From<&types::RetrieveMessageResponse> for proto::RetrieveMessageResponse {
    fn from(value: &types::RetrieveMessageResponse) -> Self {
        Self {
            message: Some(serialize_bcs(&value.message)),
        }
    }
}

impl TryFrom<&proto::RetrieveMessageResponse> for types::RetrieveMessageResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::RetrieveMessageResponse) -> Result<Self, Self::Error> {
        let message: avss::Message =
            deserialize_bcs(required(value.message.as_ref(), "message")?, "message")?;
        Ok(Self { message })
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
            complaint: Some(serialize_bcs(&self.complaint)),
        }
    }
}

impl TryFrom<&proto::ComplainRequest> for types::ComplainRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::ComplainRequest) -> Result<Self, Self::Error> {
        let dealer = parse_address(required(value.dealer.as_ref(), "dealer")?, "dealer")?;
        let complaint: complaint::Complaint = deserialize_bcs(
            required(value.complaint.as_ref(), "complaint")?,
            "complaint",
        )?;
        Ok(Self { dealer, complaint })
    }
}

//
// ComplainResponse
//

impl From<&types::ComplainResponse> for proto::ComplainResponse {
    fn from(value: &types::ComplainResponse) -> Self {
        Self {
            response: Some(serialize_bcs(&value.response)),
        }
    }
}

impl TryFrom<&proto::ComplainResponse> for types::ComplainResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::ComplainResponse) -> Result<Self, Self::Error> {
        let response: complaint::ComplaintResponse<avss::SharesForNode> =
            deserialize_bcs(required(value.response.as_ref(), "response")?, "response")?;
        Ok(Self { response })
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

//
// RotationComplainRequest
//

impl types::RotationComplainRequest {
    pub fn to_proto(&self, epoch: u64) -> proto::RotationComplainRequest {
        proto::RotationComplainRequest {
            epoch: Some(epoch),
            dealer: Some(self.dealer.to_string()),
            share_index: Some(self.share_index.get() as u32),
            complaint: Some(serialize_bcs(&self.complaint)),
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
        use fastcrypto_tbls::types::ShareIndex;
        use std::collections::BTreeMap;

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

impl TryFrom<&proto::RotationComplainRequest> for types::RotationComplainRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::RotationComplainRequest) -> Result<Self, Self::Error> {
        let dealer = parse_address(required(value.dealer.as_ref(), "dealer")?, "dealer")?;
        let share_index = required(value.share_index, "share_index")?;
        let share_index = std::num::NonZeroU16::new(share_index as u16)
            .ok_or_else(|| TryFromProtoError::invalid("share_index", "must be non-zero"))?;
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
// RotationShareComplaintResponse
//

impl From<&types::RotationShareComplaintResponse> for proto::RotationShareComplaintResponse {
    fn from(value: &types::RotationShareComplaintResponse) -> Self {
        Self {
            share_index: Some(value.share_index.get() as u32),
            response: Some(serialize_bcs(&value.response)),
        }
    }
}

impl TryFrom<&proto::RotationShareComplaintResponse> for types::RotationShareComplaintResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::RotationShareComplaintResponse) -> Result<Self, Self::Error> {
        let share_index = required(value.share_index, "share_index")?;
        let share_index = std::num::NonZeroU16::new(share_index as u16)
            .ok_or_else(|| TryFromProtoError::invalid("share_index", "must be non-zero"))?;
        let response: complaint::ComplaintResponse<avss::SharesForNode> =
            deserialize_bcs(required(value.response.as_ref(), "response")?, "response")?;
        Ok(Self {
            share_index,
            response,
        })
    }
}

//
// RotationComplainResponse
//

impl From<&types::RotationComplainResponse> for proto::RotationComplainResponse {
    fn from(value: &types::RotationComplainResponse) -> Self {
        Self {
            responses: value.responses.iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<&proto::RotationComplainResponse> for types::RotationComplainResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::RotationComplainResponse) -> Result<Self, Self::Error> {
        let responses: Result<Vec<_>, _> = value
            .responses
            .iter()
            .map(types::RotationShareComplaintResponse::try_from)
            .collect();
        Ok(Self {
            responses: responses?,
        })
    }
}
