// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::mpc::types::AvidNonceMessageKind;
use crate::mpc::types::Messages;
use crate::mpc::types::ProtocolComplaint;
use fastcrypto::bls12381::BLS_G2_LENGTH;
use fastcrypto::groups::ristretto255::RISTRETTO_POINT_BYTE_LENGTH;
use fastcrypto::groups::ristretto255::RISTRETTO_SCALAR_BYTE_LENGTH;
use fastcrypto::groups::secp256k1::POINT_SIZE_IN_BYTES;
use fastcrypto::groups::secp256k1::SCALAR_SIZE_IN_BYTES;
use fastcrypto::hash::Blake2b256;
use fastcrypto::hash::HashFunction;
use fastcrypto::merkle::DIGEST_LEN;
use fastcrypto_tbls::nodes::PartyId;
use fastcrypto_tbls::types::ShareIndex;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::ops::Range;
use sui_sdk_types::Address;

const POINT: usize = POINT_SIZE_IN_BYTES;
const SCALAR: usize = SCALAR_SIZE_IN_BYTES;
const EG_POINT: usize = RISTRETTO_POINT_BYTE_LENGTH;
const DDH_NIZK: usize = 2 * EG_POINT + RISTRETTO_SCALAR_BYTE_LENGTH;
const SHARE: usize = size_of::<ShareIndex>() + SCALAR;
const HASH: usize = Blake2b256::OUTPUT_SIZE;
const MERKLE_DIGEST: usize = DIGEST_LEN;
const ADDRESS: usize = Address::LENGTH;
const PARTY_ID: usize = size_of::<PartyId>();
const BATCH_INDEX: usize = size_of::<u32>();
const EPOCH: usize = size_of::<u64>();
const AGGREGATE_SIGNATURE: usize = BLS_G2_LENGTH;
const SHARED_COMPONENTS: usize = 2 * EG_POINT + DDH_NIZK;
const RECOVERY_PACKAGE: usize = EG_POINT + DDH_NIZK;
const MAX_MERKLE_PATH: usize = usize::BITS as usize - 1;
const MESSAGES_NONCE_GENERATION_AVID: usize = Messages::NONCE_GENERATION_AVID_VARIANT as usize;
const AVID_NONCE_MESSAGE_KIND_ECHO: usize = AvidNonceMessageKind::ECHO_VARIANT as usize;
const PROTOCOL_COMPLAINT_AVSS: usize = ProtocolComplaint::AVSS_VARIANT as usize;
const PROTOCOL_COMPLAINT_AVID_REVEAL: usize = ProtocolComplaint::AVID_REVEAL_VARIANT as usize;
const PROTOCOL_COMPLAINT_AVID_BLAME: usize = ProtocolComplaint::AVID_BLAME_VARIANT as usize;
const RS_LENGTH_PREFIX: usize = size_of::<u32>();
const RS_ELEMENT: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CountCheckError {
    #[error("{field}: {found} entries, expected {expected}")]
    WrongCount {
        field: &'static str,
        found: usize,
        expected: usize,
    },
    #[error("{field}: {found} entries, at most {max} allowed")]
    TooMany {
        field: &'static str,
        found: usize,
        max: usize,
    },
    #[error("{field}: {found} bytes, expected {expected}")]
    WrongBytes {
        field: &'static str,
        found: usize,
        expected: usize,
    },
    #[error("{field}: {found} bytes, at most {max} allowed")]
    TooManyBytes {
        field: &'static str,
        found: usize,
        max: usize,
    },
    #[error("{field}: payload ends early")]
    Truncated { field: &'static str },
    #[error("{field}: invalid ULEB128 length or variant index")]
    BadLength { field: &'static str },
    #[error("{field}: keys are not in canonical BCS order")]
    KeyOrder { field: &'static str },
    #[error("{field}: share index {index} is zero or not owned by the dealer")]
    UnownedKey { field: &'static str, index: u16 },
    #[error("{field}: key {key} is not a u16 share index")]
    KeyRange { field: &'static str, key: u32 },
    #[error("{field}: share index {index} appears more than once")]
    DuplicateKey { field: &'static str, index: u16 },
    #[error("{field}: an entry doesn't parse: {reason}")]
    BadEntry { field: &'static str, reason: String },
    #[error("{field}: party {party} is not in the committee")]
    UnknownParty { field: &'static str, party: u16 },
    #[error("{field}: unknown variant {variant}")]
    BadVariant { field: &'static str, variant: usize },
    #[error("{0} bytes after the payload")]
    Trailing(usize),
}

type CountCheckResult<T> = Result<T, CountCheckError>;

#[derive(Clone, Copy, Debug)]
pub struct AvssShape {
    pub threshold: u16,
    pub num_nodes: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct PartyWeights<'a>(pub &'a [u16]);

impl PartyWeights<'_> {
    fn num_nodes(self) -> usize {
        self.0.len()
    }

    fn weight_of(self, field: &'static str, party: u16) -> CountCheckResult<usize> {
        self.0
            .get(usize::from(party))
            .map(|&weight| usize::from(weight))
            .ok_or(CountCheckError::UnknownParty { field, party })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AvidShape<'a> {
    pub threshold: u16,
    pub weights: PartyWeights<'a>,
    pub batch_size_per_weight: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct DispersalShape<'a> {
    pub weights: PartyWeights<'a>,
    pub batch_size: usize,
    pub data_shards: NonZeroUsize,
}

impl<'a> DispersalShape<'a> {
    pub fn new(
        weights: PartyWeights<'a>,
        dealer: u16,
        batch_size_per_weight: u16,
        max_faulty: u16,
    ) -> Option<Self> {
        let total_weight: usize = weights.0.iter().map(|&weight| usize::from(weight)).sum();
        let data_shards = total_weight
            .checked_sub(2 * usize::from(max_faulty))
            .and_then(NonZeroUsize::new)?;
        let dealer_weight = weights.0.get(usize::from(dealer)).copied().unwrap_or(0);
        Some(Self {
            weights,
            batch_size: usize::from(dealer_weight) * usize::from(batch_size_per_weight),
            data_shards,
        })
    }
}

#[derive(Clone, Copy)]
struct ExactShards {
    shard_bytes: usize,
    row_depth: usize,
    top_depth: usize,
}

fn avid_shard_bytes(row_weight: usize, batch_size: usize, data_shards: NonZeroUsize) -> usize {
    let share_batch = uleb128_len(batch_size) + (batch_size + 1) * SCALAR;
    let payload = uleb128_len(row_weight) + row_weight * share_batch;
    (RS_LENGTH_PREFIX + payload).div_ceil(RS_ELEMENT * data_shards.get()) * RS_ELEMENT
}

fn uleb128_len(value: usize) -> usize {
    (usize::BITS - value.leading_zeros()).div_ceil(7).max(1) as usize
}

pub fn check_avss_message(bytes: &[u8], shape: AvssShape) -> CountCheckResult<()> {
    let mut cursor = Cursor::new(bytes);
    walk_avss_message(&mut cursor, shape)?;
    cursor.finish()
}

pub fn check_rotation_messages(
    bytes: &[u8],
    shape: AvssShape,
    owned: &[ShareIndex],
) -> CountCheckResult<BTreeMap<ShareIndex, Range<usize>>> {
    const FIELD: &str = "rotation_messages";
    let mut cursor = Cursor::new(bytes);
    let mut entries = BTreeMap::new();
    walk_u16_map(&mut cursor, FIELD, owned.len(), |cursor, index| {
        let share_index = ShareIndex::new(index)
            .filter(|share_index| owned.contains(share_index))
            .ok_or(CountCheckError::UnownedKey {
                field: FIELD,
                index,
            })?;
        let start = cursor.position;
        walk_avss_message(cursor, shape)?;
        entries.insert(share_index, start..cursor.position);
        Ok(())
    })?;
    cursor.finish()?;
    Ok(entries)
}

pub fn avss_complaint_response_size(responder_weight: u16) -> usize {
    let weight = usize::from(responder_weight);
    uleb128_len(weight) + weight * SHARE
}

pub fn check_avss_complaint_response(bytes: &[u8], responder_weight: u16) -> CountCheckResult<()> {
    const FIELD: &str = "complaint_response.shares";
    let mut cursor = Cursor::new(bytes);
    let shares = cursor.length(FIELD)?;
    expect_count(FIELD, shares, responder_weight.into())?;
    cursor.skip_elements(FIELD, shares, SHARE)?;
    cursor.finish()
}

pub fn check_avss_common_message(
    bytes: &[u8],
    shape: AvidShape<'_>,
    dealer: u16,
) -> CountCheckResult<()> {
    let mut cursor = Cursor::new(bytes);
    walk_avss_common_message(&mut cursor, shape, dealer)?;
    cursor.finish()
}

pub fn check_avid_avss_message(
    bytes: &[u8],
    shape: AvidShape<'_>,
    dealer: u16,
) -> CountCheckResult<()> {
    let mut cursor = Cursor::new(bytes);
    walk_avss_common_message(&mut cursor, shape, dealer)?;
    walk_bytes(&mut cursor, "ciphertext")?;
    cursor.finish()
}

pub fn check_dispersal(
    bytes: &[u8],
    shape: DispersalShape<'_>,
    holder: u16,
) -> CountCheckResult<()> {
    const FIELD: &str = "dispersal";
    let shards = shape.weights.weight_of(FIELD, holder)?;
    let row_depth = merkle_depth(shape.weights.num_nodes());
    let top_depth = merkle_depth(Cursor::new(bytes).length(FIELD)?);
    let mut cursor = Cursor::new(bytes);
    walk_u16_map(
        &mut cursor,
        FIELD,
        shape.weights.num_nodes(),
        |cursor, row| {
            let row_weight = shape.weights.weight_of(FIELD, row)?;
            let exact = ExactShards {
                shard_bytes: avid_shard_bytes(row_weight, shape.batch_size, shape.data_shards),
                row_depth,
                top_depth,
            };
            walk_authenticated_shards(cursor, shards, Some(exact))
        },
    )?;
    cursor.finish()
}

pub fn check_confirm_certificate(bytes: &[u8], weights: PartyWeights<'_>) -> CountCheckResult<()> {
    let mut cursor = Cursor::new(bytes);
    walk_vote_certificate(&mut cursor, Some(weights.num_nodes().div_ceil(8)))?;
    cursor.finish()
}

pub fn check_echo(bytes: &[u8], weights: PartyWeights<'_>, sender: u16) -> CountCheckResult<()> {
    let shards = weights.weight_of("echo", sender)?;
    let mut cursor = Cursor::new(bytes);
    walk_authenticated_shards(&mut cursor, shards, None)?;
    cursor.finish()
}

pub fn check_avid_vote(bytes: &[u8], weights: PartyWeights<'_>) -> CountCheckResult<()> {
    let mut cursor = Cursor::new(bytes);
    walk_avid_vote(&mut cursor, weights)?;
    cursor.finish()
}

pub fn check_protocol_complaint(bytes: &[u8], weights: PartyWeights<'_>) -> CountCheckResult<()> {
    const FIELD: &str = "complaint";
    let mut cursor = Cursor::new(bytes);
    match cursor.variant(FIELD)? {
        PROTOCOL_COMPLAINT_AVSS => {
            cursor.take(FIELD, RECOVERY_PACKAGE)?;
        }
        PROTOCOL_COMPLAINT_AVID_REVEAL => {
            walk_bytes(&mut cursor, "complaint.ciphertext")?;
            cursor.take("complaint.proof", RECOVERY_PACKAGE)?;
        }
        PROTOCOL_COMPLAINT_AVID_BLAME => {
            walk_u16_map(
                &mut cursor,
                "complaint.shards",
                weights.num_nodes(),
                |cursor, disperser| {
                    let shards = weights.weight_of("complaint.shards", disperser)?;
                    walk_authenticated_shards(cursor, shards, None)
                },
            )?;
            walk_vote_certificate(&mut cursor, None)?;
        }
        variant => {
            return Err(CountCheckError::BadVariant {
                field: FIELD,
                variant,
            });
        }
    }
    cursor.finish()
}

pub fn check_avid_complaint_response(bytes: &[u8]) -> CountCheckResult<()> {
    let mut cursor = Cursor::new(bytes);
    walk_bytes(&mut cursor, "complaint_response.ciphertext")?;
    cursor.take("complaint_response.recovery_package", RECOVERY_PACKAGE)?;
    cursor.finish()
}

pub fn check_held_avid_echoes(
    bytes: &[u8],
    weights: PartyWeights<'_>,
    holder: u16,
) -> CountCheckResult<()> {
    const FIELD: &str = "held_echoes";
    let shards = weights.weight_of(FIELD, holder)?;
    let mut cursor = Cursor::new(bytes);
    walk_avid_vote(&mut cursor, weights)?;
    let echoes = cursor.length(FIELD)?;
    at_most(FIELD, echoes, weights.num_nodes())?;
    for _ in 0..echoes {
        cursor.take(FIELD, ADDRESS)?;
        cursor.expect_variant(FIELD, MESSAGES_NONCE_GENERATION_AVID)?;
        cursor.take(FIELD, BATCH_INDEX)?;
        cursor.expect_variant(FIELD, AVID_NONCE_MESSAGE_KIND_ECHO)?;
        cursor.take(FIELD, ADDRESS)?;
        walk_authenticated_shards(&mut cursor, shards, None)?;
    }
    walk_vote_certificate(&mut cursor, None)?;
    cursor.finish()
}

fn walk_avss_message(cursor: &mut Cursor<'_>, shape: AvssShape) -> CountCheckResult<()> {
    const COMMITMENT: &str = "feldman_commitment";
    const ENCS: &str = "ciphertext.encs";
    let points = cursor.length(COMMITMENT)?;
    expect_count(COMMITMENT, points, shape.threshold.into())?;
    cursor.skip_elements(COMMITMENT, points, POINT)?;
    cursor.take("ciphertext", 2 * EG_POINT)?;
    let encs = cursor.length(ENCS)?;
    expect_count(ENCS, encs, shape.num_nodes.into())?;
    for _ in 0..encs {
        walk_bytes(cursor, ENCS)?;
    }
    cursor.take("ciphertext.proof", DDH_NIZK)?;
    Ok(())
}

fn walk_avss_common_message(
    cursor: &mut Cursor<'_>,
    shape: AvidShape<'_>,
    dealer: u16,
) -> CountCheckResult<()> {
    const KEYS: &str = "full_public_keys";
    const HASHES: &str = "ciphertext_hashes";
    const POLYNOMIAL: &str = "response_polynomial";
    let batch_size =
        shape.weights.weight_of(KEYS, dealer)? * usize::from(shape.batch_size_per_weight);
    let keys = cursor.length(KEYS)?;
    expect_count(KEYS, keys, batch_size)?;
    cursor.skip_elements(KEYS, keys, POINT)?;
    cursor.take("blinding_commit", POINT)?;
    cursor.take("ciphertext_shared", SHARED_COMPONENTS)?;
    let hashes = cursor.length(HASHES)?;
    expect_count(HASHES, hashes, shape.weights.num_nodes())?;
    cursor.skip_elements(HASHES, hashes, HASH)?;
    let coefficients = cursor.length(POLYNOMIAL)?;
    expect_count(POLYNOMIAL, coefficients, shape.threshold.into())?;
    cursor.skip_elements(POLYNOMIAL, coefficients, SCALAR)
}

fn walk_authenticated_shards(
    cursor: &mut Cursor<'_>,
    expected_shards: usize,
    exact: Option<ExactShards>,
) -> CountCheckResult<()> {
    const SHARDS: &str = "shards";
    let shards = cursor.length(SHARDS)?;
    expect_count(SHARDS, shards, expected_shards)?;
    for _ in 0..shards {
        let len = cursor.length(SHARDS)?;
        exact.map_or(Ok(()), |exact| expect_bytes(SHARDS, len, exact.shard_bytes))?;
        cursor.take(SHARDS, len)?;
    }
    walk_merkle_path(cursor, "row_proof", exact.map(|exact| exact.row_depth))?;
    walk_merkle_path(cursor, "top_proof", exact.map(|exact| exact.top_depth))
}

fn walk_merkle_path(
    cursor: &mut Cursor<'_>,
    field: &'static str,
    depth: Option<usize>,
) -> CountCheckResult<()> {
    let nodes = cursor.length(field)?;
    depth.map_or_else(
        || at_most(field, nodes, MAX_MERKLE_PATH),
        |depth| expect_count(field, nodes, depth),
    )?;
    (0..nodes).try_for_each(|_| walk_merkle_node(cursor, field))
}

fn merkle_depth(leaves: usize) -> usize {
    leaves.next_power_of_two().trailing_zeros() as usize
}

fn walk_merkle_node(cursor: &mut Cursor<'_>, field: &'static str) -> CountCheckResult<()> {
    match cursor.variant(field)? {
        0 => Ok(()),
        1 => cursor.take(field, MERKLE_DIGEST).map(drop),
        variant => Err(CountCheckError::BadVariant { field, variant }),
    }
}

fn walk_avid_vote(cursor: &mut Cursor<'_>, weights: PartyWeights<'_>) -> CountCheckResult<()> {
    const RECIPIENTS: &str = "vote.recipients";
    walk_merkle_node(cursor, "vote.top_root")?;
    let recipients = cursor.length(RECIPIENTS)?;
    at_most(RECIPIENTS, recipients, weights.num_nodes())?;
    cursor.skip_elements(RECIPIENTS, recipients, PARTY_ID)?;
    cursor.take("common_message_hash", HASH).map(drop)
}

fn walk_vote_certificate(
    cursor: &mut Cursor<'_>,
    max_signers_bytes: Option<usize>,
) -> CountCheckResult<()> {
    const FIELD: &str = "certificate";
    const SIGNERS: &str = "certificate.signers";
    cursor.take(FIELD, EPOCH + AGGREGATE_SIGNATURE)?;
    let signers = cursor.length(SIGNERS)?;
    max_signers_bytes.map_or(Ok(()), |max| at_most_bytes(SIGNERS, signers, max))?;
    cursor.take(SIGNERS, signers)?;
    cursor.take(FIELD, ADDRESS)?;
    walk_bytes(cursor, "certificate.messages_hash")?;
    cursor.take(FIELD, BATCH_INDEX).map(drop)
}

fn walk_u16_map<'a>(
    cursor: &mut Cursor<'a>,
    field: &'static str,
    max_entries: usize,
    mut entry: impl FnMut(&mut Cursor<'a>, u16) -> CountCheckResult<()>,
) -> CountCheckResult<()> {
    let count = cursor.length(field)?;
    at_most(field, count, max_entries)?;
    let mut previous_key: Option<[u8; 2]> = None;
    for _ in 0..count {
        let key = cursor.array::<2>(field)?;
        if previous_key.is_some_and(|previous| key <= previous) {
            return Err(CountCheckError::KeyOrder { field });
        }
        previous_key = Some(key);
        entry(cursor, u16::from_le_bytes(key))?;
    }
    Ok(())
}

fn walk_bytes(cursor: &mut Cursor<'_>, field: &'static str) -> CountCheckResult<()> {
    let len = cursor.length(field)?;
    cursor.take(field, len).map(drop)
}

fn expect_count(field: &'static str, found: usize, expected: usize) -> CountCheckResult<()> {
    (found == expected)
        .then_some(())
        .ok_or(CountCheckError::WrongCount {
            field,
            found,
            expected,
        })
}

fn at_most(field: &'static str, found: usize, max: usize) -> CountCheckResult<()> {
    (found <= max)
        .then_some(())
        .ok_or(CountCheckError::TooMany { field, found, max })
}

fn expect_bytes(field: &'static str, found: usize, expected: usize) -> CountCheckResult<()> {
    (found == expected)
        .then_some(())
        .ok_or(CountCheckError::WrongBytes {
            field,
            found,
            expected,
        })
}

fn at_most_bytes(field: &'static str, found: usize, max: usize) -> CountCheckResult<()> {
    (found <= max)
        .then_some(())
        .ok_or(CountCheckError::TooManyBytes { field, found, max })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, field: &'static str, len: usize) -> CountCheckResult<&'a [u8]> {
        let bytes = self.bytes;
        let taken = self
            .position
            .checked_add(len)
            .and_then(|end| bytes.get(self.position..end))
            .ok_or(CountCheckError::Truncated { field })?;
        self.position += len;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self, field: &'static str) -> CountCheckResult<[u8; N]> {
        self.take(field, N)?
            .try_into()
            .map_err(|_| CountCheckError::Truncated { field })
    }

    fn skip_elements(
        &mut self,
        field: &'static str,
        count: usize,
        size: usize,
    ) -> CountCheckResult<()> {
        let len = count
            .checked_mul(size)
            .ok_or(CountCheckError::Truncated { field })?;
        self.take(field, len).map(drop)
    }

    fn length(&mut self, field: &'static str) -> CountCheckResult<usize> {
        let mut value: u64 = 0;
        for shift in (0..32).step_by(7) {
            let [byte] = self.array::<1>(field)?;
            let digit = byte & 0x7f;
            value |= u64::from(digit) << shift;
            if digit == byte {
                if shift > 0 && digit == 0 {
                    return Err(CountCheckError::BadLength { field });
                }
                return usize::try_from(value)
                    .ok()
                    .filter(|&len| len <= bcs::MAX_SEQUENCE_LENGTH)
                    .ok_or(CountCheckError::BadLength { field });
            }
        }
        Err(CountCheckError::BadLength { field })
    }

    fn variant(&mut self, field: &'static str) -> CountCheckResult<usize> {
        self.length(field)
    }

    fn expect_variant(&mut self, field: &'static str, expected: usize) -> CountCheckResult<()> {
        match self.variant(field)? {
            variant if variant == expected => Ok(()),
            variant => Err(CountCheckError::BadVariant { field, variant }),
        }
    }

    fn finish(self) -> CountCheckResult<()> {
        match self.bytes.len().saturating_sub(self.position) {
            0 => Ok(()),
            trailing => Err(CountCheckError::Trailing(trailing)),
        }
    }
}

#[cfg(test)]
#[path = "count_check_tests.rs"]
mod tests;
