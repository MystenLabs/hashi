// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use anyhow::ensure;
use fastcrypto::groups::GroupElement;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::types::ShareIndex;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use sui_sdk_types::Address;

use crate::mpc::types::MpcOutput;

/// Versioned, owned recovery material, serialized with BCS inside the encrypted archive.
/// Deliberately does not implement `Debug`: private shares must not enter logs.
#[derive(Clone, Serialize, Deserialize)]
pub enum MpcRecoveryRecord {
    V1(MpcRecoveryRecordV1),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MpcRecoveryRecordV1 {
    pub chain_id: String,
    pub hashi_object_id: Address,
    pub epoch: u64,
    pub validator_address: Address,
    pub public_key: G,
    pub threshold: u16,
    /// Each private scalar retains its global share index from the MPC output.
    pub key_shares: avss::SharesForNode,
    pub commitments: BTreeMap<ShareIndex, G>,
}

impl MpcRecoveryRecord {
    /// Capture the completed output without retaining references to mutable epoch state.
    /// Public-only outputs have no local recovery material.
    pub fn from_output(
        chain_id: &str,
        hashi_object_id: Address,
        epoch: u64,
        validator_address: Address,
        output: &MpcOutput,
    ) -> Option<Self> {
        if output.key_shares.shares.is_empty() {
            return None;
        }
        Some(Self::V1(MpcRecoveryRecordV1 {
            chain_id: chain_id.to_owned(),
            hashi_object_id,
            epoch,
            validator_address,
            public_key: output.public_key,
            threshold: output.threshold,
            key_shares: output.key_shares.clone(),
            commitments: output.commitments.clone(),
        }))
    }

    /// Check local recovery material without requiring this validator to hold a quorum.
    pub fn validate(&self) -> Result<()> {
        let Self::V1(record) = self;
        ensure!(!record.chain_id.is_empty(), "Recovery chain ID is empty");
        ensure!(record.threshold > 0, "Recovery threshold is zero");
        ensure!(
            usize::from(record.threshold) <= record.commitments.len(),
            "Recovery threshold exceeds the number of public commitments"
        );
        ensure!(
            !record.key_shares.shares.is_empty(),
            "Recovery record contains no private shares"
        );
        let mut indices = BTreeSet::new();
        for share in &record.key_shares.shares {
            ensure!(
                indices.insert(share.index),
                "Recovery record contains duplicate private share indices"
            );
            let commitment = record
                .commitments
                .get(&share.index)
                .ok_or_else(|| anyhow::anyhow!("Recovery share has no public commitment"))?;
            ensure!(
                G::generator() * share.value == *commitment,
                "Recovery share does not match its public commitment"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn test_record() -> MpcRecoveryRecord {
    use fastcrypto_tbls::polynomial::Eval;
    use fastcrypto_tbls::threshold_schnorr::S;

    // Degree-one polynomial 7 + 3*x: one local share is less than the quorum of two.
    let index = ShareIndex::new(1).unwrap();
    let output = MpcOutput {
        public_key: G::generator() * S::from(7u128),
        key_shares: avss::SharesForNode {
            shares: vec![Eval {
                index,
                value: S::from(10u128),
            }],
        },
        commitments: (1..=3)
            .map(|i| {
                (
                    ShareIndex::new(i).unwrap(),
                    G::generator() * S::from(7u128 + 3 * u128::from(i)),
                )
            })
            .collect(),
        threshold: 2,
    };
    MpcRecoveryRecord::from_output(
        "test-chain",
        Address::new([1; 32]),
        42,
        Address::new([2; 32]),
        &output,
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto_tbls::threshold_schnorr::S;

    #[test]
    fn local_shares_need_not_meet_threshold() {
        let record = test_record();
        let MpcRecoveryRecord::V1(inner) = &record;
        assert!(inner.key_shares.shares.len() < usize::from(inner.threshold));
        record.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_recovery_material() {
        type Invalidate = fn(&mut MpcRecoveryRecordV1);
        let cases: &[(&str, Invalidate)] = &[
            ("empty chain", |r| r.chain_id.clear()),
            ("zero threshold", |r| r.threshold = 0),
            ("threshold exceeds commitments", |r| r.threshold = 4),
            ("no local shares", |r| r.key_shares.shares.clear()),
            ("duplicate share", |r| {
                r.key_shares.shares.push(r.key_shares.shares[0].clone());
            }),
            ("missing commitment", |r| {
                r.commitments.remove(&ShareIndex::new(1).unwrap());
            }),
            ("mismatched commitment", |r| {
                r.key_shares.shares[0].value = S::from(11u128);
            }),
        ];
        for (case, invalidate) in cases {
            let mut record = test_record();
            let MpcRecoveryRecord::V1(inner) = &mut record;
            invalidate(inner);
            assert!(record.validate().is_err(), "{case}");
        }
    }
}
