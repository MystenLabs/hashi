// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::mpc::types::EncryptionGroupElement;
use crate::mpc::types::RotationMessages;
use fastcrypto::groups::Scalar as _;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::ecies_v1::PublicKey;
use fastcrypto_tbls::nodes::Node;
use fastcrypto_tbls::nodes::Nodes;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::threshold_schnorr::Parameters;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::avss;
use proptest::prelude::*;
use std::sync::LazyLock;
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
