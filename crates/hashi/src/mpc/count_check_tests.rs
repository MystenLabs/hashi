// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::mpc::types::AvidNonceMessage;
use crate::mpc::types::AvidNonceMessageKind;
use crate::mpc::types::AvidRoundState;
use crate::mpc::types::AvidVoteMessagesHash;
use crate::mpc::types::AvssVoteMessagesHash;
use crate::mpc::types::EncryptionGroupElement;
use crate::mpc::types::HeldAvidEchoes;
use crate::mpc::types::Messages;
use crate::mpc::types::MessagesHash;
use crate::mpc::types::ProtocolComplaint;
use crate::mpc::types::RotationMessages;
use fastcrypto::error::FastCryptoResult;
use fastcrypto::groups::Scalar as _;
use fastcrypto::merkle;
use fastcrypto::traits::ToFromBytes as _;
use fastcrypto_tbls::ecies_v1::Ciphertext;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::ecies_v1::PublicKey;
use fastcrypto_tbls::nodes::Node;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::threshold_schnorr::Certificate;
use fastcrypto_tbls::threshold_schnorr::Parameters;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss_avid;
use hashi_types::committee::BLS12381AggregateSignature;
use hashi_types::committee::SignedMessage;
use hashi_types::intent::IntentMessage;
use proptest::prelude::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::LazyLock;
use sui_sdk_types::Address;
use test_strategy::proptest;

fn dealer_message(weights: &[u16], t: u16, f: u16) -> (avss::Message, AvssShape) {
    let mut rng = rand::thread_rng();
    let nodes = Nodes::new(
        weights
            .iter()
            .enumerate()
            .map(|(id, &weight)| Node {
                id: id as u16,
                pk: PublicKey::<EncryptionGroupElement>::from_private_key(&PrivateKey::new(
                    &mut rng,
                )),
                weight,
            })
            .collect(),
    )
    .unwrap();
    let shape = AvssShape {
        threshold: t,
        num_nodes: nodes.num_nodes() as u16,
    };
    let dealer = avss::Dealer::new(
        None,
        nodes,
        Parameters { t, f },
        b"count-check".to_vec(),
        &mut rng,
    )
    .unwrap();
    (dealer.create_message(&mut rng), shape)
}

fn share_indices(indices: &[u16]) -> Vec<ShareIndex> {
    indices
        .iter()
        .map(|&index| ShareIndex::new(index).unwrap())
        .collect()
}

fn uleb128(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let digit = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            bytes.push(digit);
            return bytes;
        }
        bytes.push(digit | 0x80);
    }
}

fn crafted_message(points: usize, ciphertext_lens: &[usize]) -> Vec<u8> {
    let mut bytes = uleb128(points);
    bytes.resize(bytes.len() + points * POINT + 2 * EG_POINT, 0);
    bytes.extend(uleb128(ciphertext_lens.len()));
    for &len in ciphertext_lens {
        bytes.extend(uleb128(len));
        bytes.resize(bytes.len() + len, 0);
    }
    bytes.resize(bytes.len() + DDH_NIZK, 0);
    bytes
}

fn crafted_rotation_map(keys: &[u16], message: &[u8]) -> Vec<u8> {
    let mut bytes = uleb128(keys.len());
    for key in keys {
        bytes.extend(key.to_le_bytes());
        bytes.extend(message);
    }
    bytes
}

static SKEWED_MESSAGE: LazyLock<(Vec<u8>, AvssShape)> = LazyLock::new(|| {
    let (message, shape) = dealer_message(&[5, 3, 1, 0, 1], 4, 2);
    (bcs::to_bytes(&message).unwrap(), shape)
});

#[test]
fn dealer_messages_pass_and_are_consumed_exactly() {
    for (weights, t, f) in [
        (vec![1, 1, 1, 1], 3, 1),
        (vec![5, 3, 1, 1], 4, 2),
        (vec![3, 0, 2, 0, 1], 3, 1),
        (vec![1; 130], 129, 1),
    ] {
        let (message, shape) = dealer_message(&weights, t, f);
        let bytes = bcs::to_bytes(&message).unwrap();
        assert_eq!(check_avss_message(&bytes, shape), Ok(()));
    }
}

#[test]
fn counts_off_by_one_are_refused() {
    let (bytes, shape) = &*SKEWED_MESSAGE;
    for threshold in [shape.threshold - 1, shape.threshold + 1] {
        assert!(matches!(
            check_avss_message(
                bytes,
                AvssShape {
                    threshold,
                    ..*shape
                }
            ),
            Err(CountCheckError::WrongCount {
                field: "feldman_commitment",
                ..
            })
        ));
    }
    for num_nodes in [shape.num_nodes - 1, shape.num_nodes + 1] {
        assert!(matches!(
            check_avss_message(
                bytes,
                AvssShape {
                    num_nodes,
                    ..*shape
                }
            ),
            Err(CountCheckError::WrongCount {
                field: "ciphertext.encs",
                ..
            })
        ));
    }
}

#[test]
fn trailing_or_missing_bytes_are_refused() {
    let (bytes, shape) = &*SKEWED_MESSAGE;
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        check_avss_message(&longer, *shape),
        Err(CountCheckError::Trailing(1))
    );
    assert!(matches!(
        check_avss_message(&bytes[..bytes.len() - 1], *shape),
        Err(CountCheckError::Truncated { .. })
    ));
}

#[test]
fn oversized_ciphertexts_with_valid_counts_pass() {
    let shape = AvssShape {
        threshold: 3,
        num_nodes: 3,
    };
    assert_eq!(
        check_avss_message(&crafted_message(3, &[1 << 20, 0, 7]), shape),
        Ok(())
    );
}

#[test]
fn a_count_is_refused_before_its_elements_are_read() {
    let shape = AvssShape {
        threshold: 3,
        num_nodes: 3,
    };
    assert_eq!(
        check_avss_message(&uleb128(1 << 30), shape),
        Err(CountCheckError::WrongCount {
            field: "feldman_commitment",
            found: 1 << 30,
            expected: 3,
        })
    );
    let weights = PartyWeights(&[2, 2, 1, 0]);
    let dispersal_shape = DispersalShape {
        weights,
        batch_size: 0,
        data_shards: NonZeroUsize::MIN,
    };
    assert_eq!(
        check_dispersal(&uleb128(5), dispersal_shape, 0),
        Err(CountCheckError::TooMany {
            field: "dispersal",
            found: 5,
            max: 4,
        })
    );
    assert_eq!(
        check_protocol_complaint(&[uleb128(2), uleb128(5)].concat(), weights),
        Err(CountCheckError::TooMany {
            field: "complaint.shards",
            found: 5,
            max: 4,
        })
    );
}

#[test]
fn non_canonical_or_oversized_lengths_are_refused() {
    for prefix in [
        vec![0x80, 0x00],
        vec![0xff, 0xff, 0xff, 0xff, 0x7f],
        vec![0x80, 0x80, 0x80, 0x80, 0x08],
        vec![0xff; 6],
    ] {
        assert!(bcs::from_bytes::<Vec<u8>>(&prefix).is_err());
        assert!(matches!(
            check_avss_complaint_response(&prefix, 0),
            Err(CountCheckError::BadLength { .. })
        ));
    }
}

#[test]
fn rotation_map_passes_and_returns_each_entry() {
    let owned = share_indices(&[1, 2, 3]);
    let map: RotationMessages = owned
        .iter()
        .map(|&index| (index, dealer_message(&[5, 3, 1, 1], 4, 2).0))
        .collect();
    let shape = AvssShape {
        threshold: 4,
        num_nodes: 4,
    };
    let bytes = bcs::to_bytes(&map).unwrap();
    let entries = check_rotation_messages(&bytes, shape, &owned).unwrap();
    assert_eq!(entries.keys().copied().collect::<Vec<_>>(), owned);
    for (index, range) in entries {
        assert_eq!(bytes[range], bcs::to_bytes(&map[&index]).unwrap()[..]);
    }
    let empty = bcs::to_bytes(&RotationMessages::new()).unwrap();
    assert_eq!(
        check_rotation_messages(&empty, shape, &[]),
        Ok(BTreeMap::new())
    );
}

#[test]
fn rotation_map_keys_follow_bcs_byte_order() {
    let (message, shape) = dealer_message(&[1, 1, 1, 1], 3, 1);
    let owned = share_indices(&[1, 256]);
    let map: RotationMessages = owned
        .iter()
        .map(|&index| (index, message.clone()))
        .collect();
    let bytes = bcs::to_bytes(&map).unwrap();
    let keys: Vec<u16> = check_rotation_messages(&bytes, shape, &owned)
        .unwrap()
        .into_keys()
        .map(|index| index.get())
        .collect();
    assert_eq!(keys, vec![1, 256]);
}

#[test]
fn rotation_map_refuses_unowned_surplus_and_unordered_keys() {
    let (bytes, shape) = &*SKEWED_MESSAGE;
    let owned = share_indices(&[1, 2]);
    assert_eq!(
        check_rotation_messages(&crafted_rotation_map(&[1, 3], bytes), *shape, &owned),
        Err(CountCheckError::UnownedKey {
            field: "rotation_messages",
            index: 3,
        })
    );
    assert_eq!(
        check_rotation_messages(&crafted_rotation_map(&[0], bytes), *shape, &owned),
        Err(CountCheckError::UnownedKey {
            field: "rotation_messages",
            index: 0,
        })
    );
    assert_eq!(
        check_rotation_messages(&crafted_rotation_map(&[1, 2, 2], bytes), *shape, &owned),
        Err(CountCheckError::TooMany {
            field: "rotation_messages",
            found: 3,
            max: 2,
        })
    );
    for keys in [[1, 1], [2, 1]] {
        let map = crafted_rotation_map(&keys, bytes);
        assert!(bcs::from_bytes::<RotationMessages>(&map).is_err());
        assert_eq!(
            check_rotation_messages(&map, *shape, &owned),
            Err(CountCheckError::KeyOrder {
                field: "rotation_messages",
            })
        );
    }
}

#[test]
fn complaint_response_carries_exactly_the_responder_weight() {
    let mut rng = rand::thread_rng();
    let response = avss::ComplaintResponse {
        shares: avss::SharesForNode {
            shares: share_indices(&[4, 5, 6])
                .into_iter()
                .map(|index| Eval {
                    index,
                    value: S::rand(&mut rng),
                })
                .collect(),
        },
    };
    let bytes = bcs::to_bytes(&response).unwrap();
    assert_eq!(check_avss_complaint_response(&bytes, 3), Ok(()));
    for weight in [2, 4] {
        assert!(matches!(
            check_avss_complaint_response(&bytes, weight),
            Err(CountCheckError::WrongCount { .. })
        ));
    }
}

#[proptest(cases = 32)]
fn dealer_messages_of_random_shapes_pass(
    #[strategy(prop::collection::vec(0u16..5, 2..8))] weights: Vec<u16>,
    t_seed: u16,
) {
    let total: u16 = weights.iter().sum();
    prop_assume!(total >= 2);
    let t = 1 + t_seed % (total - 1);
    let (message, shape) = dealer_message(&weights, t, 1);
    prop_assert_eq!(
        check_avss_message(&bcs::to_bytes(&message).unwrap(), shape),
        Ok(())
    );
}

#[proptest]
fn arbitrary_bytes_never_panic(
    #[strategy(prop::collection::vec(any::<u8>(), 0..1024))] bytes: Vec<u8>,
    threshold: u16,
    num_nodes: u16,
    #[strategy(prop::collection::vec(1u16.., 0..8))] owned: Vec<u16>,
) {
    let shape = AvssShape {
        threshold,
        num_nodes,
    };
    let _ = check_avss_message(&bytes, shape);
    let _ = check_rotation_messages(&bytes, shape, &share_indices(&owned));
    let _ = check_avss_complaint_response(&bytes, threshold);
}

#[proptest]
fn mutated_dealer_messages_never_panic(position: prop::sample::Index, byte: u8, cut: u16) {
    let (bytes, shape) = &*SKEWED_MESSAGE;
    let mut mutated = bytes.clone();
    mutated[position.index(bytes.len())] = byte;
    mutated.truncate(bytes.len().saturating_sub(cut as usize % 64));
    let _ = check_avss_message(&mutated, *shape);
    let _ = check_rotation_messages(
        &crafted_rotation_map(&[1], &mutated),
        *shape,
        &share_indices(&[1]),
    );
}

#[derive(Clone)]
struct TestAvssCert {
    signers: BTreeSet<PartyId>,
    vote: batch_avss_avid::AvssVote,
}

impl Certificate for TestAvssCert {
    type Payload = batch_avss_avid::AvssVote;

    fn signers(&self) -> &BTreeSet<PartyId> {
        &self.signers
    }

    fn payload(&self) -> &batch_avss_avid::AvssVote {
        &self.vote
    }

    fn verify(&self) -> FastCryptoResult<()> {
        Ok(())
    }
}

struct AvidPayloads {
    weights: Vec<u16>,
    common: Vec<u8>,
    avss_message: Vec<u8>,
    dispersals: Vec<batch_avss_avid::Dispersal>,
    echo: batch_avss_avid::Echo,
    avid_vote: batch_avss_avid::AvidVote,
}

impl AvidPayloads {
    fn shape(&self) -> AvidShape<'_> {
        AvidShape {
            threshold: 4,
            weights: PartyWeights(&self.weights),
            batch_size_per_weight: 64,
        }
    }

    fn dispersal_shape(&self) -> DispersalShape<'_> {
        DispersalShape::new(PartyWeights(&self.weights), 0, 64, 1).unwrap()
    }
}

static AVID: LazyLock<AvidPayloads> =
    LazyLock::new(|| avid_payloads(vec![2, 2, 2, 1, 0], BTreeSet::from([0, 1, 2])));

fn avid_payloads(weights: Vec<u16>, signers: BTreeSet<PartyId>) -> AvidPayloads {
    let mut rng = rand::thread_rng();
    let params = Parameters { t: 4, f: 1 };
    let keys: Vec<PrivateKey<EncryptionGroupElement>> =
        weights.iter().map(|_| PrivateKey::new(&mut rng)).collect();
    let nodes = Nodes::new(
        weights
            .iter()
            .zip(&keys)
            .enumerate()
            .map(|(id, (&weight, key))| Node {
                id: id as u16,
                pk: PublicKey::from_private_key(key),
                weight,
            })
            .collect(),
    )
    .unwrap();
    let sid = b"count-check-avid".to_vec();
    let dealer = batch_avss_avid::Dealer::new(nodes.clone(), 0, params, sid.clone(), 64).unwrap();
    let receiver =
        batch_avss_avid::Receiver::new(nodes, 0, 0, params, sid, keys[0].clone(), 64).unwrap();
    let avss_builder = dealer.create_avss_messages(&mut rng).unwrap();
    let avss_message = avss_builder.message_for(0).unwrap();
    let (_, vote, verified_common) = receiver.process_avss_message(&avss_message).unwrap();
    let avid_builder = dealer
        .create_avid_messages(&avss_builder, TestAvssCert { signers, vote })
        .unwrap();
    let dispersals = (0..weights.len() as u16)
        .map(|holder| avid_builder.message_for(holder).unwrap().dispersal)
        .collect();
    let (echo_builder, avid_vote) = receiver
        .process_avid_message(&verified_common, avid_builder.message_for(0).unwrap())
        .unwrap();
    AvidPayloads {
        common: bcs::to_bytes(&avss_message.common).unwrap(),
        avss_message: bcs::to_bytes(&avss_message).unwrap(),
        dispersals,
        echo: echo_builder.create_echo(3).unwrap(),
        avid_vote,
        weights,
    }
}

fn avss_complaint() -> avss::Complaint {
    let mut rng = rand::thread_rng();
    let keys: Vec<PrivateKey<EncryptionGroupElement>> =
        (0..4).map(|_| PrivateKey::new(&mut rng)).collect();
    let honest: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(id, key)| Node {
            id: id as u16,
            pk: PublicKey::from_private_key(key),
            weight: 1,
        })
        .collect();
    let mut misdirected = honest.clone();
    misdirected[0].pk = PublicKey::from_private_key(&PrivateKey::new(&mut rng));
    let params = Parameters { t: 3, f: 1 };
    let message = avss::Dealer::new(
        None,
        Nodes::new(misdirected).unwrap(),
        params,
        b"count-check".to_vec(),
        &mut rng,
    )
    .unwrap()
    .create_message(&mut rng);
    let receiver = avss::Receiver::new(
        Nodes::new(honest).unwrap(),
        0,
        params,
        b"count-check".to_vec(),
        None,
        keys[0].clone(),
    )
    .unwrap();
    match receiver.process_message(&message, &mut rng).unwrap() {
        avss::ProcessedMessage::Complaint(complaint) => complaint,
        avss::ProcessedMessage::Valid(_) => panic!("a misdirected share verified"),
    }
}

fn vote_certificate<T: IntentMessage>(message: T) -> SignedMessage<T> {
    SignedMessage::new(
        1,
        message,
        BLS12381AggregateSignature::default().as_bytes(),
        &[0b1110_0000],
    )
    .unwrap()
}

#[test]
fn avid_payloads_pass_and_are_consumed_exactly() {
    let avid = &*AVID;
    let shape = avid.shape();
    assert_eq!(&avid.common[..2], uleb128(128).as_slice());
    assert_eq!(check_avss_common_message(&avid.common, shape, 0), Ok(()));
    assert_eq!(
        check_avid_avss_message(&avid.avss_message, shape, 0),
        Ok(())
    );
    let message: batch_avss_avid::AvssMessage = bcs::from_bytes(&avid.avss_message).unwrap();
    let round_state = AvidRoundState {
        common: message.common,
        own_ciphertext: message.ciphertext,
    };
    assert_eq!(
        check_avid_avss_message(&bcs::to_bytes(&round_state).unwrap(), shape, 0),
        Ok(())
    );
    for (holder, dispersal) in avid.dispersals.iter().enumerate() {
        assert_eq!(
            check_dispersal(
                &bcs::to_bytes(dispersal).unwrap(),
                avid.dispersal_shape(),
                holder as u16
            ),
            Ok(())
        );
    }
    assert_eq!(
        check_echo(&bcs::to_bytes(&avid.echo).unwrap(), shape.weights, 0),
        Ok(())
    );
    assert_eq!(
        check_avid_vote(&bcs::to_bytes(&avid.avid_vote).unwrap(), shape.weights),
        Ok(())
    );
}

#[test]
fn avid_counts_follow_the_dealer_holder_and_sender() {
    let avid = &*AVID;
    let shape = avid.shape();
    assert_eq!(
        check_avss_common_message(&avid.common, shape, 3),
        Err(CountCheckError::WrongCount {
            field: "full_public_keys",
            found: 128,
            expected: 64,
        })
    );
    assert_eq!(
        check_avss_common_message(&avid.common, shape, 9),
        Err(CountCheckError::UnknownParty {
            field: "full_public_keys",
            party: 9,
        })
    );
    assert!(matches!(
        check_avss_common_message(
            &avid.common,
            AvidShape {
                threshold: 5,
                ..shape
            },
            0
        ),
        Err(CountCheckError::WrongCount {
            field: "response_polynomial",
            ..
        })
    ));
    assert!(matches!(
        check_avss_common_message(
            &avid.common,
            AvidShape {
                weights: PartyWeights(&avid.weights[..4]),
                ..shape
            },
            0
        ),
        Err(CountCheckError::WrongCount {
            field: "ciphertext_hashes",
            ..
        })
    ));
    assert_eq!(
        check_dispersal(
            &bcs::to_bytes(&avid.dispersals[0]).unwrap(),
            avid.dispersal_shape(),
            3
        ),
        Err(CountCheckError::WrongCount {
            field: "shards",
            found: 2,
            expected: 1,
        })
    );
    assert_eq!(
        check_echo(&bcs::to_bytes(&avid.echo).unwrap(), shape.weights, 4),
        Err(CountCheckError::WrongCount {
            field: "shards",
            found: 2,
            expected: 0,
        })
    );
}

#[derive(Clone, Serialize, Deserialize)]
enum MirroredNode {
    Empty,
    Digest([u8; 32]),
}

type MirroredRow = (Vec<Vec<u8>>, Vec<MirroredNode>, Vec<MirroredNode>);

#[test]
fn dispersals_and_confirm_certificates_are_held_to_their_honest_lengths() {
    let avid = avid_payloads(vec![2, 2, 2, 1, 0, 0], BTreeSet::from([0, 1, 2]));
    let shape = avid.dispersal_shape();
    for (holder, dispersal) in avid.dispersals.iter().enumerate() {
        assert_eq!(
            check_dispersal(&bcs::to_bytes(dispersal).unwrap(), shape, holder as u16),
            Ok(())
        );
    }
    let rows: BTreeMap<u16, MirroredRow> =
        bcs::from_bytes(&bcs::to_bytes(&avid.dispersals[0]).unwrap()).unwrap();
    assert_eq!(rows.keys().copied().collect::<Vec<_>>(), [3, 4, 5]);
    let mut longer_shard = rows.clone();
    let (shards, _, _) = longer_shard.get_mut(&3).unwrap();
    shards[0].push(0);
    assert_eq!(
        check_dispersal(&bcs::to_bytes(&longer_shard).unwrap(), shape, 0),
        Err(CountCheckError::WrongBytes {
            field: "shards",
            found: 829,
            expected: 828,
        })
    );
    let mut deeper_proof = rows;
    let (_, _, top_proof) = deeper_proof.get_mut(&5).unwrap();
    top_proof.push(MirroredNode::Empty);
    assert_eq!(
        check_dispersal(&bcs::to_bytes(&deeper_proof).unwrap(), shape, 0),
        Err(CountCheckError::WrongCount {
            field: "top_proof",
            found: 3,
            expected: 2,
        })
    );
    let certificate = |signers: &[u8]| {
        let message = AvssVoteMessagesHash {
            dealer_address: Address::ZERO,
            messages_hash: MessagesHash::from([7; 32]),
            batch_index: 7,
        };
        let signature = BLS12381AggregateSignature::default();
        bcs::to_bytes(&SignedMessage::new(1, message, signature.as_bytes(), signers).unwrap())
            .unwrap()
    };
    assert_eq!(
        check_confirm_certificate(&certificate(&[0b1110_0000]), shape.weights),
        Ok(())
    );
    assert_eq!(
        check_confirm_certificate(&certificate(&[0b1110_0000, 0]), shape.weights),
        Err(CountCheckError::TooManyBytes {
            field: "certificate.signers",
            found: 2,
            max: 1,
        })
    );
}

#[test]
fn merkle_paths_are_refused_where_bcs_or_compute_root_refuse_them() {
    let weights = PartyWeights(&[2, 2, 2, 1, 0]);
    let echo = |row_proof: &[u8]| {
        let mut bytes = uleb128(2);
        bytes.extend([0, 0]);
        bytes.extend(row_proof);
        bytes.extend(uleb128(0));
        bytes
    };
    let walk_and_compute_root = |nodes: usize| {
        let path = [uleb128(nodes), vec![0; nodes]].concat();
        let proof: merkle::MerkleProof =
            merkle::MerkleProof::new(&vec![merkle::Node::Empty; nodes]);
        (
            check_echo(&echo(&path), weights, 0),
            proof.compute_root(&[], 0).is_some(),
        )
    };
    assert_eq!(walk_and_compute_root(MAX_MERKLE_PATH), (Ok(()), true));
    assert_eq!(
        walk_and_compute_root(MAX_MERKLE_PATH + 1),
        (
            Err(CountCheckError::TooMany {
                field: "row_proof",
                found: MAX_MERKLE_PATH + 1,
                max: MAX_MERKLE_PATH,
            }),
            false
        )
    );
    let unknown = echo(&[1, 2]);
    assert!(bcs::from_bytes::<batch_avss_avid::Echo>(&unknown).is_err());
    assert_eq!(
        check_echo(&unknown, weights, 0),
        Err(CountCheckError::BadVariant {
            field: "row_proof",
            variant: 2,
        })
    );
}

#[test]
fn protocol_complaints_are_walked_by_variant() {
    let avid = &*AVID;
    let weights = PartyWeights(&avid.weights);
    let complaint = avss_complaint();
    let reveal = ProtocolComplaint::AvidReveal(batch_avss_avid::AvssComplaint {
        ciphertext: Ciphertext(vec![1, 2, 3]),
        proof: complaint.proof.clone(),
    });
    for complaint in [ProtocolComplaint::Avss(complaint), reveal] {
        assert_eq!(
            check_protocol_complaint(&bcs::to_bytes(&complaint).unwrap(), weights),
            Ok(())
        );
    }
    let blame = batch_avss_avid::AvidComplaint {
        shards: [0u16, 1, 2]
            .into_iter()
            .map(|disperser| {
                (
                    disperser,
                    avid.dispersals[usize::from(disperser)][&3].clone(),
                )
            })
            .collect(),
    };
    let vote_cert = vote_certificate(AvidVoteMessagesHash {
        dealer_address: Address::ZERO,
        messages_hash: MessagesHash::from([7; 32]),
        batch_index: 7,
    });
    let blame_bytes = |complaint: &batch_avss_avid::AvidComplaint| {
        bcs::to_bytes(&ProtocolComplaint::AvidBlame {
            complaint: complaint.clone(),
            vote_cert: vote_cert.clone(),
        })
        .unwrap()
    };
    let mut bytes = blame_bytes(&blame);
    assert_eq!(check_protocol_complaint(&bytes, weights), Ok(()));
    bytes.push(0);
    assert_eq!(
        check_protocol_complaint(&bytes, weights),
        Err(CountCheckError::Trailing(1))
    );
    let mut misweighted = blame.clone();
    misweighted.shards.insert(3, avid.dispersals[0][&3].clone());
    assert_eq!(
        check_protocol_complaint(&blame_bytes(&misweighted), weights),
        Err(CountCheckError::WrongCount {
            field: "shards",
            found: 2,
            expected: 1,
        })
    );
    assert_eq!(
        check_protocol_complaint(&uleb128(3), weights),
        Err(CountCheckError::BadVariant {
            field: "complaint",
            variant: 3,
        })
    );
}

#[test]
fn avid_complaint_response_is_a_ciphertext_and_a_recovery_package() {
    let mut bytes = uleb128(5);
    bytes.extend([7; 5]);
    bytes.extend(bcs::to_bytes(&avss_complaint()).unwrap());
    bcs::from_bytes::<batch_avss_avid::ComplaintResponse>(&bytes).unwrap();
    assert_eq!(check_avid_complaint_response(&bytes), Ok(()));
    bytes.push(0);
    assert_eq!(
        check_avid_complaint_response(&bytes),
        Err(CountCheckError::Trailing(1))
    );
}

#[test]
fn held_avid_echoes_carry_the_holder_shards() {
    let avid = &*AVID;
    let weights = PartyWeights(&avid.weights);
    let held: HeldAvidEchoes = (
        avid.avid_vote.clone(),
        vec![(
            Address::ZERO,
            Messages::NonceGenerationAvid(AvidNonceMessage {
                batch_index: 7,
                kind: AvidNonceMessageKind::Echo {
                    dealer: Address::ZERO,
                    echo: avid.echo.clone(),
                },
            }),
        )],
        vote_certificate(AvssVoteMessagesHash {
            dealer_address: Address::ZERO,
            messages_hash: MessagesHash::from([7; 32]),
            batch_index: 7,
        }),
    );
    let mut bytes = bcs::to_bytes(&held).unwrap();
    assert_eq!(check_held_avid_echoes(&bytes, weights, 0), Ok(()));
    assert!(matches!(
        check_held_avid_echoes(&bytes, weights, 3),
        Err(CountCheckError::WrongCount {
            field: "shards",
            ..
        })
    ));
    bytes.push(0);
    assert_eq!(
        check_held_avid_echoes(&bytes, weights, 0),
        Err(CountCheckError::Trailing(1))
    );
}

#[proptest]
fn mutated_avid_payloads_never_panic(position: prop::sample::Index, byte: u8, cut: u16) {
    let avid = &*AVID;
    let shape = avid.shape();
    let payloads = [
        avid.common.clone(),
        avid.avss_message.clone(),
        bcs::to_bytes(&avid.dispersals[0]).unwrap(),
        bcs::to_bytes(&avid.echo).unwrap(),
        bcs::to_bytes(&avid.avid_vote).unwrap(),
    ];
    for bytes in payloads {
        let mut mutated = bytes.clone();
        mutated[position.index(bytes.len())] = byte;
        mutated.truncate(bytes.len().saturating_sub(cut as usize % 64));
        let _ = check_avss_common_message(&mutated, shape, 0);
        let _ = check_avid_avss_message(&mutated, shape, 0);
        let _ = check_dispersal(&mutated, avid.dispersal_shape(), 0);
        let _ = check_confirm_certificate(&mutated, shape.weights);
        let _ = check_echo(&mutated, shape.weights, 0);
        let _ = check_avid_vote(&mutated, shape.weights);
        let _ = check_protocol_complaint(&mutated, shape.weights);
        let _ = check_avid_complaint_response(&mutated);
        let _ = check_held_avid_echoes(&mutated, shape.weights, 0);
    }
}

#[proptest]
fn arbitrary_bytes_never_panic_in_avid_layouts(
    #[strategy(prop::collection::vec(any::<u8>(), 0..1024))] bytes: Vec<u8>,
    #[strategy(prop::collection::vec(any::<u16>(), 0..8))] weights: Vec<u16>,
    #[strategy(0usize..1 << 32)] batch_size: usize,
    #[strategy(1usize..1 << 16)] data_shards: usize,
    threshold: u16,
    batch_size_per_weight: u16,
    #[strategy(0u16..8)] party: u16,
) {
    let shape = AvidShape {
        threshold,
        weights: PartyWeights(&weights),
        batch_size_per_weight,
    };
    let dispersal_shape = DispersalShape {
        weights: shape.weights,
        batch_size,
        data_shards: NonZeroUsize::new(data_shards).unwrap(),
    };
    let _ = check_avss_common_message(&bytes, shape, party);
    let _ = check_avid_avss_message(&bytes, shape, party);
    let _ = check_dispersal(&bytes, dispersal_shape, party);
    let _ = check_confirm_certificate(&bytes, shape.weights);
    let _ = check_echo(&bytes, shape.weights, party);
    let _ = check_avid_vote(&bytes, shape.weights);
    let _ = check_protocol_complaint(&bytes, shape.weights);
    let _ = check_avid_complaint_response(&bytes);
    let _ = check_held_avid_echoes(&bytes, shape.weights, party);
}
