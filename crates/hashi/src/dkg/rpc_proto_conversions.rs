use crate::bls::BLS12381Signature;
use crate::dkg::types;
use crate::proto;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::{avss, complaint};
use serde::{Deserialize, Serialize};
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
fn serialize_bcs<T: Serialize>(value: &T, name: &str) -> Bcs {
    let mut bcs = Bcs::serialize(value).expect("serialization should succeed");
    bcs.name = Some(name.to_owned());
    bcs
}

//
// SendMessageRequest
//

impl From<&types::SendMessageRequest> for proto::SendMessageRequest {
    fn from(value: &types::SendMessageRequest) -> Self {
        Self {
            epoch: None,
            message: Some(serialize_bcs(
                &value.message,
                "fastcrypto_tbls::threshold_schnorr::avss::Message",
            )),
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

impl From<&types::RetrieveMessageRequest> for proto::RetrieveMessageRequest {
    fn from(value: &types::RetrieveMessageRequest) -> Self {
        Self {
            epoch: None,
            dealer: Some(value.dealer.to_string()),
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
            message: Some(serialize_bcs(
                &value.message,
                "fastcrypto_tbls::threshold_schnorr::avss::Message",
            )),
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

impl From<&types::ComplainRequest> for proto::ComplainRequest {
    fn from(value: &types::ComplainRequest) -> Self {
        Self {
            epoch: None,
            dealer: Some(value.dealer.to_string()),
            complaint: Some(serialize_bcs(
                &value.complaint,
                "fastcrypto_tbls::threshold_schnorr::complaint::Complaint",
            )),
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
            response: Some(serialize_bcs(
                &value.response,
                "fastcrypto_tbls::threshold_schnorr::complaint::ComplaintResponse<avss::SharesForNode>",
            )),
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
