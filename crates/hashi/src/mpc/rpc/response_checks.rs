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
    #[error("{0}")]
    Config(String),
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
            Self::Config(_) => "config",
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
    if let Some(common) = &bundle.common {
        count_check::check_avss_common_message(bytes(common), shape.avid_shape(), dealer)?;
    }
    if let Some(echo) = &bundle.echo {
        let shard_bytes = own_echo_shard_bytes(shape, dealer)?;
        count_check::check_echo(bytes(echo), current.weights(), responder, shard_bytes)?;
    }
    if let Some(vote) = &bundle.avid_vote {
        count_check::check_avid_vote(bytes(vote), current.weights())?;
    }
    match RetrieveMessagesResponse::try_from(response)
        .map_err(|e| Refused::Decode(e.to_string()))?
        .messages
    {
        Messages::AvidNonceRetrieval(bundle) => Ok(bundle),
        _ => Err(not_avid()),
    }
}

fn own_echo_shard_bytes(shape: &ShapeParams, dealer: PartyId) -> Result<usize, Refused> {
    let current = shape.current();
    let own_party = current
        .own_party()
        .ok_or_else(|| Refused::Config("this node has no row in the committee".into()))?;
    let dispersal = shape.avid_dispersal_shape(dealer).ok_or_else(|| {
        Refused::Config(format!(
            "epoch {} has no AVID data shards: reduced weight is at most twice max_faulty",
            shape.epoch()
        ))
    })?;
    Ok(count_check::avid_shard_bytes(
        current.weight_of(own_party).into(),
        dispersal.batch_size,
        dispersal.data_shards,
    ))
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
    use crate::config::DEFAULT_GRPC_MAX_DECODING_MESSAGE_SIZE;
    use crate::mpc::rpc::public_output_response_limit;
    use crate::mpc::shape_params::CommitteeShape;
    use crate::mpc::types::AvidVoteMessagesHash;
    use crate::mpc::types::ComplaintResponse;
    use crate::mpc::types::EncryptionGroupElement;
    use crate::mpc::types::ProtocolComplaint;
    use crate::mpc::types::ProtocolType;
    use crate::mpc::types::PublicMpcOutput;
    use fastcrypto::error::FastCryptoResult;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::hash::Blake2b256;
    use fastcrypto::merkle::MerkleProof;
    use fastcrypto::merkle::MerkleTree;
    use fastcrypto::traits::ToFromBytes as _;
    use fastcrypto_tbls::ecies_v1::PrivateKey;
    use fastcrypto_tbls::ecies_v1::PublicKey;
    use fastcrypto_tbls::nodes::Node;
    use fastcrypto_tbls::nodes::Nodes;
    use fastcrypto_tbls::polynomial::Eval;
    use fastcrypto_tbls::threshold_schnorr::Certificate;
    use fastcrypto_tbls::threshold_schnorr::G;
    use fastcrypto_tbls::threshold_schnorr::Parameters;
    use fastcrypto_tbls::threshold_schnorr::S;
    use fastcrypto_tbls::threshold_schnorr::VerifiedCertificate;
    use fastcrypto_tbls::types::ShareIndex;
    use hashi_types::committee::BLS12381AggregateSignature;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::Committee;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::RuntimeCommittee;
    use hashi_types::committee::SignedMessage;
    use prost::Message;
    use std::collections::BTreeSet;

    const WEIGHTS: [u16; 7] = [2; 7];
    const THRESHOLD: u16 = 10;
    const MAX_FAULTY: u16 = 2;
    const BATCH_SIZE_PER_WEIGHT: u16 = 3;
    const RECIPIENT: PartyId = 0;
    const DEALER: PartyId = 1;
    const WRONG_SIZE_SENDER: PartyId = 2;

    #[derive(Clone)]
    struct TestCert<P> {
        signers: BTreeSet<PartyId>,
        payload: P,
    }

    impl<P> Certificate for TestCert<P> {
        type Payload = P;

        fn signers(&self) -> &BTreeSet<PartyId> {
            &self.signers
        }

        fn payload(&self) -> &P {
            &self.payload
        }

        fn verify(&self) -> FastCryptoResult<()> {
            Ok(())
        }
    }

    struct Retrieval {
        committee: RuntimeCommittee,
        nodes: Nodes<EncryptionGroupElement>,
        receivers: Vec<batch_avss_avid::Receiver>,
        avss_messages: Vec<batch_avss_avid::AvssMessage>,
        verified_commons: BTreeMap<PartyId, batch_avss_avid::VerifiedAvssCommonMessage>,
        responses: BTreeMap<PartyId, proto::RetrieveMessagesResponse>,
        avid_cert: VerifiedCertificate<TestCert<batch_avss_avid::AvidVote>>,
    }

    impl Retrieval {
        fn shape(&self, own_address: Address, max_faulty: u16) -> ShapeParams {
            ShapeParams::new(
                1,
                0,
                ProtocolType::NonceGeneration { batch_index: 0 },
                BATCH_SIZE_PER_WEIGHT,
                1,
                max_faulty,
                CommitteeShape::new(&self.committee, &self.nodes, THRESHOLD, &own_address),
                None,
                None,
            )
        }
    }

    fn address(party: PartyId) -> Address {
        Address::new([party as u8; 32])
    }

    fn avid_response(common: Bcs, echo: Option<Bcs>, vote: Bcs) -> proto::RetrieveMessagesResponse {
        proto::RetrieveMessagesResponse {
            messages: Some(
                proto::retrieve_messages_response::Messages::AvidNonceRetrievalMessage(
                    proto::AvidNonceRetrievalMessage {
                        common: Some(common),
                        echo,
                        avid_vote: Some(vote),
                    },
                ),
            ),
        }
    }

    fn with_committed_shard_of_len(
        dispersals: &[batch_avss_avid::Dispersal],
        disperser: usize,
        len: usize,
    ) -> Vec<batch_avss_avid::Dispersal> {
        type Row = (Vec<Vec<u8>>, MerkleProof, MerkleProof);
        let mut leaves: Vec<Vec<Vec<u8>>> = dispersals
            .iter()
            .map(|dispersal| {
                let row: Row =
                    bcs::from_bytes(&bcs::to_bytes(&dispersal[&RECIPIENT]).unwrap()).unwrap();
                row.0
            })
            .collect();
        leaves[disperser][0] = vec![0; len];
        let row_tree = MerkleTree::<Blake2b256>::build_from_unserialized(leaves.iter()).unwrap();
        let top_tree =
            MerkleTree::<Blake2b256>::build_from_unserialized([row_tree.root()].iter()).unwrap();
        leaves
            .iter()
            .enumerate()
            .map(|(leaf, shards)| {
                let row = (
                    shards,
                    row_tree.get_proof(leaf).unwrap(),
                    top_tree.get_proof(0).unwrap(),
                );
                BTreeMap::from([(
                    RECIPIENT,
                    bcs::from_bytes(&bcs::to_bytes(&row).unwrap()).unwrap(),
                )])
            })
            .collect()
    }

    fn retrieval(committed_shard_len: Option<usize>) -> Retrieval {
        let mut rng = rand::thread_rng();
        let keys: Vec<PrivateKey<EncryptionGroupElement>> =
            WEIGHTS.iter().map(|_| PrivateKey::new(&mut rng)).collect();
        let public_keys: Vec<_> = keys.iter().map(PublicKey::from_private_key).collect();
        let nodes = Nodes::new(
            WEIGHTS
                .iter()
                .zip(&public_keys)
                .enumerate()
                .map(|(id, (&weight, pk))| Node {
                    id: id as u16,
                    pk: pk.clone(),
                    weight,
                })
                .collect(),
        )
        .unwrap();
        let committee = RuntimeCommittee::from(Committee::new(
            public_keys
                .iter()
                .enumerate()
                .map(|(party, pk)| {
                    CommitteeMember::new(
                        address(party as PartyId),
                        Bls12381PrivateKey::generate(&mut rng).public_key(),
                        pk.clone(),
                        1,
                    )
                })
                .collect(),
            1,
            0,
            3333,
        ));
        let params = Parameters {
            t: THRESHOLD,
            f: MAX_FAULTY,
        };
        let sid = b"response-checks-avid".to_vec();
        let dealer = batch_avss_avid::Dealer::new(
            nodes.clone(),
            DEALER,
            params,
            sid.clone(),
            BATCH_SIZE_PER_WEIGHT,
        )
        .unwrap();
        let receivers: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(id, key)| {
                batch_avss_avid::Receiver::new(
                    nodes.clone(),
                    id as PartyId,
                    DEALER,
                    params,
                    sid.clone(),
                    key.clone(),
                    BATCH_SIZE_PER_WEIGHT,
                )
                .unwrap()
            })
            .collect();
        let builder = dealer.create_avss_messages(&mut rng).unwrap();
        let avss_messages: Vec<_> = (0..WEIGHTS.len() as PartyId)
            .map(|id| builder.message_for(id).unwrap())
            .collect();
        let signers: BTreeSet<PartyId> = (0..WEIGHTS.len() as PartyId)
            .filter(|id| *id != RECIPIENT)
            .collect();
        let mut verified_commons = BTreeMap::new();
        let mut avss_vote = None;
        for &id in &signers {
            let (_, vote, verified_common) = receivers[usize::from(id)]
                .process_avss_message(&avss_messages[usize::from(id)])
                .unwrap();
            avss_vote = Some(vote);
            verified_commons.insert(id, verified_common);
        }
        let avid_builder = dealer
            .create_avid_messages(
                &builder,
                TestCert {
                    signers: signers.clone(),
                    payload: avss_vote.unwrap(),
                },
            )
            .unwrap();
        let mut messages: Vec<_> = (0..WEIGHTS.len() as PartyId)
            .map(|id| avid_builder.message_for(id).unwrap())
            .collect();
        if let Some(len) = committed_shard_len {
            let dispersals: Vec<_> = messages.iter().map(|m| m.dispersal.clone()).collect();
            let recommitted =
                with_committed_shard_of_len(&dispersals, usize::from(WRONG_SIZE_SENDER), len);
            for (message, dispersal) in messages.iter_mut().zip(recommitted) {
                message.dispersal = dispersal;
            }
        }
        let common = Bcs::from(bcs::to_bytes(&avss_messages[0].common).unwrap());
        let mut votes = Vec::new();
        let mut responses = BTreeMap::new();
        for message in messages.into_iter().skip(1).zip(signers.iter().copied()) {
            let (message, id) = message;
            let (echo_builder, vote) = receivers[usize::from(id)]
                .process_avid_message(&verified_commons[&id], message)
                .unwrap();
            let echo = echo_builder.create_echo(RECIPIENT).unwrap();
            responses.insert(
                id,
                avid_response(
                    common.clone(),
                    Some(Bcs::from(bcs::to_bytes(&echo).unwrap())),
                    Bcs::from(bcs::to_bytes(&vote).unwrap()),
                ),
            );
            votes.push(vote);
        }
        let avid_cert = TestCert {
            signers,
            payload: votes.remove(0),
        }
        .to_verified()
        .unwrap();
        Retrieval {
            committee,
            nodes,
            receivers,
            avss_messages,
            verified_commons,
            responses,
            avid_cert,
        }
    }

    fn with_echo(
        response: &proto::RetrieveMessagesResponse,
        echo: Option<Vec<u8>>,
    ) -> proto::RetrieveMessagesResponse {
        let Some(proto::retrieve_messages_response::Messages::AvidNonceRetrievalMessage(bundle)) =
            &response.messages
        else {
            panic!("not an AVID bundle");
        };
        avid_response(
            bundle.common.clone().unwrap(),
            echo.map(Bcs::from),
            bundle.avid_vote.clone().unwrap(),
        )
    }

    #[test]
    fn avid_bundles_with_an_echo_fail_closed_without_a_row_size() {
        let session = retrieval(None);
        let sender = 3;
        let honest = &session.responses[&sender];
        let refused = |shape: &ShapeParams, response: &proto::RetrieveMessagesResponse| {
            avid_bundle(address(sender), shape, DEALER, response)
                .err()
                .map(|refused| refused.label())
        };
        let no_data_shards = session.shape(address(RECIPIENT), 7);
        let no_row = session.shape(Address::new([0xee; 32]), MAX_FAULTY);
        for shape in [&no_data_shards, &no_row] {
            assert_eq!(refused(shape, honest), Some("config"));
            assert_eq!(refused(shape, &with_echo(honest, None)), None);
        }
    }

    #[test]
    fn a_retrieval_with_one_wrong_sized_echo_still_recovers_the_shares() {
        let limit = DEFAULT_GRPC_MAX_DECODING_MESSAGE_SIZE;
        let session = retrieval(Some(limit));
        let shape = session.shape(address(RECIPIENT), MAX_FAULTY);
        let receiver = &session.receivers[usize::from(RECIPIENT)];
        let mut refused = Vec::new();
        let mut bundles = Vec::new();
        for (&sender, response) in &session.responses {
            match avid_bundle(address(sender), &shape, DEALER, response) {
                Ok(bundle) => bundles.push((sender, bundle)),
                Err(Refused::Count(CountCheckError::WrongBytes { .. })) => refused.push(sender),
                Err(other) => panic!("unexpected refusal: {other}"),
            }
        }
        assert_eq!(refused, [WRONG_SIZE_SENDER]);

        let verified_common = receiver
            .verify_common_message(&session.avid_cert, bundles[0].1.common.clone().unwrap())
            .unwrap();
        let echoes: Vec<_> = bundles
            .iter()
            .map(|(sender, bundle)| {
                receiver
                    .verify_avid_echo_message(
                        bundle.echo.clone().unwrap(),
                        *sender,
                        &session.avid_cert,
                    )
                    .unwrap()
            })
            .collect();
        let mut rng = rand::thread_rng();
        let batch_avss_avid::DecodeAndDecryptOutcome::InvalidDispersal(complaint) = receiver
            .decode_and_decrypt(&echoes, &verified_common, &mut rng)
            .unwrap()
        else {
            panic!("expected a dispersal complaint");
        };

        let protocol_complaint = bcs::to_bytes(&ProtocolComplaint::AvidBlame {
            complaint: complaint.clone(),
            vote_cert: SignedMessage::new(
                1,
                AvidVoteMessagesHash {
                    dealer_address: address(DEALER),
                    messages_hash: MessagesHash::from([7; 32]),
                    batch_index: 0,
                },
                BLS12381AggregateSignature::default().as_bytes(),
                &[0b0111_1111],
            )
            .unwrap(),
        })
        .unwrap();
        count_check::check_protocol_complaint(&protocol_complaint, shape.current().weights())
            .unwrap();
        let request = proto::ComplainRequest {
            complaint: Some(Bcs::from(protocol_complaint)),
            ..Default::default()
        };
        assert!(request.encoded_len() < limit);

        let responses = bundles
            .iter()
            .map(|(sender, _)| {
                let response = session.receivers[usize::from(*sender)]
                    .handle_avid_complaint(
                        &complaint,
                        RECIPIENT,
                        &session.verified_commons[sender],
                        &session.avid_cert,
                        session.avss_messages[usize::from(*sender)]
                            .ciphertext
                            .clone(),
                        &mut rng,
                    )
                    .unwrap();
                receiver
                    .verify_complaint_response(*sender, response, &verified_common)
                    .unwrap()
            })
            .collect();
        let recovered = receiver.recover(&verified_common, responses).unwrap();
        let (dealt, _, _) = receiver
            .process_avss_message(&session.avss_messages[usize::from(RECIPIENT)])
            .unwrap();
        assert_eq!(
            bcs::to_bytes(&recovered.my_shares).unwrap(),
            bcs::to_bytes(&dealt.my_shares).unwrap()
        );
    }

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
