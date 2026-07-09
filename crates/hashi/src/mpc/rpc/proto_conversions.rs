// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::mpc::types;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss_avid;
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

/// Convert a domain AVID nonce message to its grouped proto form.
fn avid_nonce_message_to_proto(avid: &types::AvidNonceMessage) -> proto::AvidNonceMessage {
    use proto::avid_nonce_message::Kind;
    let kind = match &avid.kind {
        types::AvidNonceMessageKind::Optimistic(message) => {
            Kind::Optimistic(proto::AvidNonceOptimistic {
                message: Some(serialize_bcs(message)),
            })
        }
        types::AvidNonceMessageKind::Dispersal {
            dispersal,
            confirm_cert,
        } => Kind::Dispersal(proto::AvidNonceDispersal {
            dispersal: Some(serialize_bcs(dispersal)),
            confirm_cert: Some(serialize_bcs(confirm_cert)),
        }),
        types::AvidNonceMessageKind::Echo { dealer, echo } => Kind::Echo(proto::AvidNonceEcho {
            dealer: Some(dealer.to_string()),
            echo: Some(serialize_bcs(echo)),
        }),
    };
    proto::AvidNonceMessage {
        batch_index: Some(avid.batch_index),
        kind: Some(kind),
    }
}

/// Parse a grouped proto AVID nonce message into its domain form.
#[allow(clippy::result_large_err)]
fn avid_nonce_message_from_proto(
    avid: &proto::AvidNonceMessage,
) -> Result<types::AvidNonceMessage, TryFromProtoError> {
    use proto::avid_nonce_message::Kind;
    let batch_index = required(avid.batch_index, "avid_nonce_message.batch_index")?;
    let kind = match avid.kind.as_ref() {
        Some(Kind::Optimistic(optimistic)) => {
            let message: batch_avss_avid::AvssMessage = deserialize_bcs(
                required(
                    optimistic.message.as_ref(),
                    "avid_nonce_message.optimistic.message",
                )?,
                "avid_nonce_message.optimistic.message",
            )?;
            types::AvidNonceMessageKind::Optimistic(message)
        }
        Some(Kind::Dispersal(dispersal_msg)) => {
            let dispersal: batch_avss_avid::Dispersal = deserialize_bcs(
                required(
                    dispersal_msg.dispersal.as_ref(),
                    "avid_nonce_message.dispersal.dispersal",
                )?,
                "avid_nonce_message.dispersal.dispersal",
            )?;
            let confirm_cert: types::AvidConfirmCertificate = deserialize_bcs(
                required(
                    dispersal_msg.confirm_cert.as_ref(),
                    "avid_nonce_message.dispersal.confirm_cert",
                )?,
                "avid_nonce_message.dispersal.confirm_cert",
            )?;
            types::AvidNonceMessageKind::Dispersal {
                dispersal,
                confirm_cert,
            }
        }
        Some(Kind::Echo(echo_msg)) => {
            let dealer = parse_address(
                required(echo_msg.dealer.as_ref(), "avid_nonce_message.echo.dealer")?,
                "avid_nonce_message.echo.dealer",
            )?;
            let echo: batch_avss_avid::Echo = deserialize_bcs(
                required(echo_msg.echo.as_ref(), "avid_nonce_message.echo.echo")?,
                "avid_nonce_message.echo.echo",
            )?;
            types::AvidNonceMessageKind::Echo { dealer, echo }
        }
        None => return Err(TryFromProtoError::missing("avid_nonce_message.kind")),
    };
    Ok(types::AvidNonceMessage { batch_index, kind })
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
            types::Messages::NonceGeneration(nonce) => {
                Messages::NonceMessage(proto::NonceMessage {
                    batch_index: Some(nonce.batch_index),
                    message: Some(serialize_bcs(&nonce.message)),
                })
            }
            types::Messages::NonceGenerationAvid(avid) => {
                Messages::AvidNonceMessage(avid_nonce_message_to_proto(avid))
            }
            types::Messages::AvidNonceRetrieval(_) => {
                unreachable!("retrieval messages are response-only")
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
            Some(Messages::NonceMessage(nonce)) => {
                let batch_index = required(nonce.batch_index, "nonce_message.batch_index")?;
                let message: batch_avss::Message = deserialize_bcs(
                    required(nonce.message.as_ref(), "nonce_message.message")?,
                    "nonce_message.message",
                )?;
                types::Messages::NonceGeneration(types::NonceMessage {
                    batch_index,
                    message,
                })
            }
            Some(Messages::AvidNonceMessage(avid)) => {
                types::Messages::NonceGenerationAvid(avid_nonce_message_from_proto(avid)?)
            }
            None => {
                return Err(TryFromProtoError::missing("messages"));
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
    pub fn to_proto(&self) -> proto::RetrieveMessagesRequest {
        proto::RetrieveMessagesRequest {
            epoch: Some(self.epoch),
            dealer: Some(self.dealer.to_string()),
            protocol_type: Some(mpc_protocol_type_to_proto(self.protocol_type) as i32),
            batch_index: self.batch_index,
        }
    }
}

impl TryFrom<&proto::RetrieveMessagesRequest> for types::RetrieveMessagesRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::RetrieveMessagesRequest) -> Result<Self, Self::Error> {
        let epoch = *required(value.epoch.as_ref(), "epoch")?;
        let dealer = parse_address(required(value.dealer.as_ref(), "dealer")?, "dealer")?;
        let protocol_type = mpc_protocol_type_from_proto(*required(
            value.protocol_type.as_ref(),
            "protocol_type",
        )?)?;
        Ok(Self {
            dealer,
            protocol_type,
            epoch,
            batch_index: value.batch_index,
        })
    }
}

fn mpc_protocol_type_to_proto(pt: types::ProtocolTypeIndicator) -> proto::MpcProtocolType {
    match pt {
        types::ProtocolTypeIndicator::Dkg => proto::MpcProtocolType::Dkg,
        types::ProtocolTypeIndicator::KeyRotation => proto::MpcProtocolType::KeyRotation,
        types::ProtocolTypeIndicator::NonceGeneration => proto::MpcProtocolType::NonceGeneration,
    }
}

#[allow(clippy::result_large_err)]
fn mpc_protocol_type_from_proto(
    value: i32,
) -> Result<types::ProtocolTypeIndicator, TryFromProtoError> {
    match proto::MpcProtocolType::try_from(value) {
        Ok(proto::MpcProtocolType::Dkg) => Ok(types::ProtocolTypeIndicator::Dkg),
        Ok(proto::MpcProtocolType::KeyRotation) => Ok(types::ProtocolTypeIndicator::KeyRotation),
        Ok(proto::MpcProtocolType::NonceGeneration) => {
            Ok(types::ProtocolTypeIndicator::NonceGeneration)
        }
        _ => Err(TryFromProtoError::missing("valid protocol_type")),
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
            types::Messages::NonceGeneration(nonce) => {
                Messages::NonceMessage(proto::NonceMessage {
                    batch_index: Some(nonce.batch_index),
                    message: Some(serialize_bcs(&nonce.message)),
                })
            }
            types::Messages::NonceGenerationAvid(_) => {
                unreachable!("AVID nonce generation send message in a RetrieveMessagesResponse")
            }
            types::Messages::AvidNonceRetrieval(retrieval) => {
                Messages::AvidNonceRetrievalMessage(proto::AvidNonceRetrievalMessage {
                    common: retrieval.common.as_ref().map(serialize_bcs),
                    echo: retrieval.echo.as_ref().map(serialize_bcs),
                    avid_vote: retrieval.avid_vote.as_ref().map(serialize_bcs),
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
            Some(Messages::NonceMessage(nonce)) => {
                let batch_index = required(nonce.batch_index, "nonce_message.batch_index")?;
                let message: batch_avss::Message = deserialize_bcs(
                    required(nonce.message.as_ref(), "nonce_message.message")?,
                    "nonce_message.message",
                )?;
                types::Messages::NonceGeneration(types::NonceMessage {
                    batch_index,
                    message,
                })
            }
            Some(Messages::AvidNonceRetrievalMessage(retrieval)) => {
                types::Messages::AvidNonceRetrieval(types::AvidNonceRetrievalMessage {
                    common: retrieval
                        .common
                        .as_ref()
                        .map(|b| deserialize_bcs(b, "avid_nonce_retrieval_message.common"))
                        .transpose()?,
                    echo: retrieval
                        .echo
                        .as_ref()
                        .map(|b| deserialize_bcs(b, "avid_nonce_retrieval_message.echo"))
                        .transpose()?,
                    avid_vote: retrieval
                        .avid_vote
                        .as_ref()
                        .map(|b| deserialize_bcs(b, "avid_nonce_retrieval_message.avid_vote"))
                        .transpose()?,
                })
            }
            None => {
                return Err(TryFromProtoError::missing("messages"));
            }
        };
        Ok(Self { messages })
    }
}

//
// ComplainRequest
//

impl types::ComplainRequest {
    pub fn to_proto(&self) -> proto::ComplainRequest {
        proto::ComplainRequest {
            epoch: Some(self.epoch),
            dealer: Some(self.dealer.to_string()),
            share_index: self.share_index.map(|idx| idx.get() as u32),
            complaint: Some(serialize_bcs(&self.complaint)),
            protocol_type: Some(mpc_protocol_type_to_proto(self.protocol_type) as i32),
            batch_index: self.batch_index,
        }
    }
}

impl TryFrom<&proto::ComplainRequest> for types::ComplainRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::ComplainRequest) -> Result<Self, Self::Error> {
        let epoch = *required(value.epoch.as_ref(), "epoch")?;
        let dealer = parse_address(required(value.dealer.as_ref(), "dealer")?, "dealer")?;
        let share_index = if let Some(idx) = value.share_index {
            Some(
                std::num::NonZeroU16::new(idx as u16)
                    .ok_or_else(|| TryFromProtoError::invalid("share_index", "must be non-zero"))?,
            )
        } else {
            None
        };
        let protocol_type =
            mpc_protocol_type_from_proto(required(value.protocol_type, "protocol_type")?)?;
        let complaint_bytes = required(value.complaint.as_ref(), "complaint")?;
        let complaint = deserialize_bcs(complaint_bytes, "complaint")?;
        Ok(Self {
            dealer,
            share_index,
            batch_index: value.batch_index,
            complaint,
            protocol_type,
            epoch,
        })
    }
}

//
// ComplainResponse
//

impl From<&types::ComplaintResponse> for proto::ComplainResponse {
    fn from(value: &types::ComplaintResponse) -> Self {
        use proto::complain_response::Responses;
        let responses = match value {
            types::ComplaintResponse::Dkg(response) => {
                Responses::DkgResponse(serialize_bcs(response))
            }
            types::ComplaintResponse::Rotation(response) => {
                Responses::RotationResponse(serialize_bcs(response))
            }
            types::ComplaintResponse::NonceGeneration(response) => {
                Responses::NonceResponse(serialize_bcs(response))
            }
            types::ComplaintResponse::NonceGenerationAvid(response) => {
                Responses::AvidNonceResponse(serialize_bcs(response))
            }
        };
        Self {
            responses: Some(responses),
        }
    }
}

impl TryFrom<&proto::ComplainResponse> for types::ComplaintResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::ComplainResponse) -> Result<Self, Self::Error> {
        use proto::complain_response::Responses;
        match &value.responses {
            Some(Responses::DkgResponse(dkg_response)) => {
                let response: avss::ComplaintResponse =
                    deserialize_bcs(dkg_response, "dkg_response")?;
                Ok(types::ComplaintResponse::Dkg(response))
            }
            Some(Responses::RotationResponse(rotation_response)) => {
                let response: avss::ComplaintResponse =
                    deserialize_bcs(rotation_response, "rotation_response")?;
                Ok(types::ComplaintResponse::Rotation(response))
            }
            Some(Responses::AvidNonceResponse(avid_response)) => {
                let response: batch_avss_avid::ComplaintResponse =
                    deserialize_bcs(avid_response, "avid_nonce_response")?;
                Ok(types::ComplaintResponse::NonceGenerationAvid(response))
            }
            Some(Responses::NonceResponse(nonce_response)) => {
                let response: complaint::ComplaintResponse<batch_avss::SharesForNode> =
                    deserialize_bcs(nonce_response, "nonce_response")?;
                Ok(types::ComplaintResponse::NonceGeneration(response))
            }
            None => Err(TryFromProtoError::missing("responses")),
        }
    }
}

//
// GetPublicMpcOutputRequest
//

impl types::GetPublicMpcOutputRequest {
    pub fn to_proto(&self) -> proto::GetPublicMpcOutputRequest {
        proto::GetPublicMpcOutputRequest {
            epoch: Some(self.epoch),
        }
    }
}

impl TryFrom<&proto::GetPublicMpcOutputRequest> for types::GetPublicMpcOutputRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::GetPublicMpcOutputRequest) -> Result<Self, Self::Error> {
        let epoch = required(value.epoch, "epoch")?;
        Ok(Self { epoch })
    }
}

//
// GetPublicMpcOutputResponse
//

impl From<&types::GetPublicMpcOutputResponse> for proto::GetPublicMpcOutputResponse {
    fn from(value: &types::GetPublicMpcOutputResponse) -> Self {
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

impl TryFrom<&proto::GetPublicMpcOutputResponse> for types::GetPublicMpcOutputResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::GetPublicMpcOutputResponse) -> Result<Self, Self::Error> {
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
            output: types::PublicMpcOutput {
                public_key,
                commitments,
            },
        })
    }
}

//
// GetPartialSignaturesRequest
//

impl types::GetPartialSignaturesRequest {
    pub fn to_proto(&self, epoch: u64) -> proto::GetPartialSignaturesRequest {
        proto::GetPartialSignaturesRequest {
            epoch: Some(epoch),
            signing_ids: self.signing_ids.iter().map(|id| id.to_string()).collect(),
        }
    }
}

impl TryFrom<&proto::GetPartialSignaturesRequest> for types::GetPartialSignaturesRequest {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::GetPartialSignaturesRequest) -> Result<Self, Self::Error> {
        let signing_ids = value
            .signing_ids
            .iter()
            .map(|s| parse_address(s, "signing_ids"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { signing_ids })
    }
}

//
// GetPartialSignaturesResponse
//

impl From<&types::GetPartialSignaturesResponse> for proto::GetPartialSignaturesResponse {
    fn from(value: &types::GetPartialSignaturesResponse) -> Self {
        Self {
            partial_sigs: value
                .partial_sigs
                .iter()
                .map(|(id, sigs)| (id.to_string(), serialize_bcs(sigs)))
                .collect(),
        }
    }
}

impl TryFrom<&proto::GetPartialSignaturesResponse> for types::GetPartialSignaturesResponse {
    type Error = TryFromProtoError;

    fn try_from(value: &proto::GetPartialSignaturesResponse) -> Result<Self, Self::Error> {
        let partial_sigs = value
            .partial_sigs
            .iter()
            .map(|(id, bcs)| {
                let id = parse_address(id, "partial_sigs key")?;
                let sigs = deserialize_bcs(bcs, "partial_sigs")?;
                Ok((id, sigs))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(Self { partial_sigs })
    }
}

#[cfg(test)]
mod avid_conversion_tests {
    use super::*;
    use crate::mpc::types;
    use fastcrypto::hash::Blake2b256;
    use fastcrypto::hash::HashFunction;
    use fastcrypto_tbls::ecies_v1;
    use fastcrypto_tbls::nodes::Node;
    use fastcrypto_tbls::nodes::Nodes;
    use fastcrypto_tbls::nodes::PartyId;
    use fastcrypto_tbls::threshold_schnorr::Certificate;
    use fastcrypto_tbls::threshold_schnorr::Parameters;
    use hashi_types::committee::BLS12381AggregateSignature;
    use hashi_types::committee::SignedMessage;
    use std::collections::BTreeSet;

    /// Minimal test [`Certificate`] over an `AvssVote`, mirroring fastcrypto's test cert.
    #[derive(Clone, Debug)]
    struct StubAvssCert {
        voters: BTreeSet<PartyId>,
        vote: batch_avss_avid::AvssVote,
    }

    impl Certificate for StubAvssCert {
        type Payload = batch_avss_avid::AvssVote;
        fn signers(&self) -> &BTreeSet<PartyId> {
            &self.voters
        }
        fn payload(&self) -> &batch_avss_avid::AvssVote {
            &self.vote
        }
        fn verify(&self) -> fastcrypto::error::FastCryptoResult<()> {
            Ok(())
        }
    }

    /// Run a minimal AVID dealer/receiver flow to mint the three opaque fastcrypto
    /// payloads — their innards are private, so they can only come from the protocol.
    /// Parties `0..=7` confirm; pending recipients `{8, 9}` have weight `2 < f = 3`.
    fn avid_artifacts() -> (
        batch_avss_avid::AvssMessage,
        batch_avss_avid::Dispersal,
        batch_avss_avid::Echo,
    ) {
        let (t, f, n, batch) = (3u16, 3u16, 10u16, 3u16);
        let mut rng = rand::thread_rng();
        let sks: Vec<_> = (0..n)
            .map(|_| ecies_v1::PrivateKey::<types::EncryptionGroupElement>::new(&mut rng))
            .collect();
        let nodes = Nodes::new(
            sks.iter()
                .enumerate()
                .map(|(id, sk)| Node {
                    id: id as u16,
                    pk: ecies_v1::PublicKey::from_private_key(sk),
                    weight: 1,
                })
                .collect(),
        )
        .unwrap();
        let sid = b"avid conversion test".to_vec();
        let params = Parameters { t, f };
        let dealer =
            batch_avss_avid::Dealer::new(nodes.clone(), 0, params, sid.clone(), batch).unwrap();
        let builder = dealer.create_avss_messages(&mut rng).unwrap();
        let own_message = builder.message_for(0).unwrap();
        let cert = StubAvssCert {
            voters: (0u16..=7).collect(),
            vote: batch_avss_avid::AvssVote {
                common_message_hash: own_message.common.hash(),
            },
        };
        let messages = dealer.create_avid_messages(&builder, cert).unwrap();
        // Receiver 0 processes the message addressed to it (its shards verify against its
        // own Merkle leaf), then echoes for a pending recipient.
        let pending: PartyId = 8;
        let avid_message = messages.message_for(0).unwrap();
        let dispersal = avid_message.dispersal.clone();
        let receiver =
            batch_avss_avid::Receiver::new(nodes, 0, 0, params, sid, sks[0].clone(), batch)
                .unwrap();
        let verified_common = receiver
            .verify_common_message(own_message.common.clone())
            .unwrap();
        let (echo_builder, _) = receiver
            .process_avid_message(&verified_common, avid_message)
            .unwrap();
        let echo = echo_builder.create_echo(pending).unwrap();
        (own_message, dispersal, echo)
    }

    fn confirm_cert() -> types::AvidConfirmCertificate {
        // Cert contents are arbitrary here — the round-trip test only checks BCS serialization.
        let message = types::DealerMessagesHash {
            dealer_address: Address::new([0u8; 32]),
            messages_hash: Blake2b256::digest(b"confirm cert").digest.into(),
        };
        let signature = BLS12381AggregateSignature::default();
        SignedMessage::new(7, message, signature.as_bytes(), &[1u8]).unwrap()
    }

    fn assert_round_trips(messages: types::Messages) {
        let request = types::SendMessagesRequest { messages };
        let proto = request.to_proto(7);
        let back = types::SendMessagesRequest::try_from(&proto).unwrap();
        assert_eq!(
            bcs::to_bytes(&request.messages).unwrap(),
            bcs::to_bytes(&back.messages).unwrap(),
        );
    }

    fn avid_message(kind: types::AvidNonceMessageKind) -> types::Messages {
        types::Messages::NonceGenerationAvid(types::AvidNonceMessage {
            batch_index: 4,
            kind,
        })
    }

    #[test]
    fn optimistic_message_round_trips() {
        let (optimistic, _, _) = avid_artifacts();
        assert_round_trips(avid_message(types::AvidNonceMessageKind::Optimistic(
            optimistic,
        )));
    }

    #[test]
    fn dispersal_message_round_trips() {
        let (_, dispersal, _) = avid_artifacts();
        assert_round_trips(avid_message(types::AvidNonceMessageKind::Dispersal {
            dispersal,
            confirm_cert: confirm_cert(),
        }));
    }

    #[test]
    fn echo_message_round_trips() {
        let (_, _, echo) = avid_artifacts();
        assert_round_trips(avid_message(types::AvidNonceMessageKind::Echo {
            dealer: Address::new([7u8; 32]),
            echo,
        }));
    }
}
