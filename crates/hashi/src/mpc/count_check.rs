// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto_tbls::types::ShareIndex;
use std::collections::BTreeMap;
use std::ops::Range;

const POINT: usize = 33;
const SCALAR: usize = 32;
const EG_POINT: usize = 32;
const DDH_NIZK: usize = 3 * 32;
const SHARE: usize = 2 + SCALAR;

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
    #[error("{field}: payload ends early")]
    Truncated { field: &'static str },
    #[error("{field}: invalid length prefix")]
    BadLength { field: &'static str },
    #[error("{field}: keys are not strictly increasing")]
    KeyOrder { field: &'static str },
    #[error("{field}: share index {index} is zero or not owned by the dealer")]
    UnownedKey { field: &'static str, index: u16 },
    #[error("{0} bytes after the payload")]
    Trailing(usize),
}

type CountCheckResult<T> = Result<T, CountCheckError>;

#[derive(Clone, Copy, Debug)]
pub struct AvssShape {
    pub threshold: u16,
    pub num_nodes: u16,
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
    let count = cursor.length(FIELD)?;
    if count > owned.len() {
        return Err(CountCheckError::TooMany {
            field: FIELD,
            found: count,
            max: owned.len(),
        });
    }
    let mut entries = BTreeMap::new();
    let mut previous_key: Option<[u8; 2]> = None;
    for _ in 0..count {
        let key = cursor.array::<2>(FIELD)?;
        if previous_key.is_some_and(|previous| key <= previous) {
            return Err(CountCheckError::KeyOrder { field: FIELD });
        }
        previous_key = Some(key);
        let index = u16::from_le_bytes(key);
        let share_index = ShareIndex::new(index)
            .filter(|share_index| owned.contains(share_index))
            .ok_or(CountCheckError::UnownedKey {
                field: FIELD,
                index,
            })?;
        let start = cursor.position;
        walk_avss_message(&mut cursor, shape)?;
        entries.insert(share_index, start..cursor.position);
    }
    cursor.finish()?;
    Ok(entries)
}

pub fn check_avss_complaint_response(bytes: &[u8], responder_weight: u16) -> CountCheckResult<()> {
    const FIELD: &str = "complaint_response.shares";
    let mut cursor = Cursor::new(bytes);
    let shares = cursor.length(FIELD)?;
    expect_count(FIELD, shares, responder_weight.into())?;
    cursor.skip_elements(FIELD, shares, SHARE)?;
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
        let len = cursor.length(ENCS)?;
        cursor.take(ENCS, len)?;
    }
    cursor.take("ciphertext.proof", DDH_NIZK)?;
    Ok(())
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
