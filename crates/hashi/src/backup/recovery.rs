// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use fastcrypto::groups::GroupElement;
use fastcrypto_tbls::polynomial::Poly;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::types::ShareIndex;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;
use sui_sdk_types::Address;

use crate::mpc::types::MpcOutput;

use super::MPC_RECOVERY_FILE_NAME;
use super::read_backup_manifest;

/// Versioned root key recovered on a trusted machine. Contains secret material.
#[derive(Serialize, Deserialize)]
pub enum RecoveredMpcKey {
    V1(RecoveredMpcKeyV1),
}

#[derive(Serialize, Deserialize)]
pub struct RecoveredMpcKeyV1 {
    pub chain_id: String,
    pub hashi_object_id: Address,
    /// Historical sharing epoch; the full public key remains stable across resharings.
    pub epoch: u64,
    pub public_key: G,
    pub private_key: S,
}

/// Read only the recovery record from a decrypted backup TAR, without extracting files.
///
/// Consume the complete archive and underlying reader before returning secret material:
/// decryption authentication or subprocess exit errors may arrive only at EOF.
pub fn read_mpc_recovery_record<R: Read>(reader: R) -> Result<MpcRecoveryRecord> {
    let mut archive = tar::Archive::new(reader);
    let mut entries = archive.entries().context("Failed to read backup archive")?;
    let manifest_entry = entries
        .next()
        .context("Backup archive is missing its manifest")??;
    let (manifest, _) = read_backup_manifest(manifest_entry)?;
    ensure!(
        manifest.recovery.is_some(),
        "Backup manifest does not declare MPC recovery material"
    );
    let mut record = None;
    for entry in entries {
        let mut entry = entry.context("Failed to read backup archive entry")?;
        let path = entry.path().context("Invalid backup archive entry path")?;
        if path
            .file_name()
            .is_none_or(|name| name != MPC_RECOVERY_FILE_NAME)
        {
            continue;
        }
        ensure!(
            path.as_os_str() == std::ffi::OsStr::new(MPC_RECOVERY_FILE_NAME),
            "Recovery entry must be at the fixed tar root path"
        );
        ensure!(record.is_none(), "Duplicate recovery entry");
        ensure!(
            entry.header().entry_type() == tar::EntryType::Regular,
            "Recovery entry must be a regular file"
        );
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .context("Failed to read MPC recovery record")?;
        let decoded: MpcRecoveryRecord =
            bcs::from_bytes(&bytes).context("Malformed MPC recovery record")?;
        decoded.validate().context("Invalid MPC recovery record")?;
        record = Some(decoded);
    }
    std::io::copy(&mut archive.into_inner(), &mut std::io::sink())
        .context("Failed to finish reading decrypted backup")?;
    record.context("Missing recovery entry")
}

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
        for share in &record.key_shares.shares {
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

/// Reconstruct the root scalar from a quorum of distinct global shares.
///
/// `expected_public_key` must be trusted independently of the supplied records.
/// Matching commitment maps establish consistency, not authenticity. Every record
/// is validated, including surplus shares; validated duplicate indices count only
/// once. Interpolation uses the lowest `threshold` distinct indices without searching
/// alternative subsets. The returned scalar is secret material and must not be logged.
pub fn reconstruct_root_scalar(
    records: &[MpcRecoveryRecord],
    expected_public_key: &G,
) -> Result<S> {
    let MpcRecoveryRecord::V1(first) = records
        .first()
        .ok_or_else(|| anyhow::anyhow!("No MPC recovery records provided"))?;
    let mut share_count = 0;
    for (index, record) in records.iter().enumerate() {
        let record_number = index + 1;
        record
            .validate()
            .with_context(|| format!("Invalid MPC recovery record {record_number}"))?;
        let MpcRecoveryRecord::V1(record) = record;
        ensure!(
            record.chain_id == first.chain_id
                && record.hashi_object_id == first.hashi_object_id
                && record.epoch == first.epoch,
            "MPC recovery record {record_number} has different deployment metadata from record 1"
        );
        ensure!(
            record.public_key == first.public_key,
            "MPC recovery record {record_number} has a different public key from record 1"
        );
        ensure!(
            record.threshold == first.threshold,
            "MPC recovery record {record_number} has a different threshold from record 1"
        );
        ensure!(
            record.commitments == first.commitments,
            "MPC recovery record {record_number} has different public commitments from record 1"
        );
        share_count += record.key_shares.shares.len();
    }
    ensure!(
        first.public_key == *expected_public_key,
        "MPC recovery record 1 public key does not match the expected public key"
    );
    let mut shares = Vec::with_capacity(share_count);
    for MpcRecoveryRecord::V1(record) in records {
        shares.extend(record.key_shares.shares.iter());
    }
    shares.sort_unstable_by_key(|share| share.index);
    shares.dedup_by_key(|share| share.index);
    let threshold = usize::from(first.threshold);
    ensure!(
        shares.len() >= threshold,
        "Insufficient distinct MPC recovery shares: have {}, need {threshold}",
        shares.len()
    );
    let scalar = Poly::<S>::recover_c0(first.threshold, shares[..threshold].iter().copied())
        .context("Failed to reconstruct MPC root scalar")?;
    ensure!(
        G::generator() * scalar == *expected_public_key,
        "Reconstructed MPC root scalar does not match the expected public key"
    );
    Ok(scalar)
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

    fn recovery_records() -> Vec<MpcRecoveryRecord> {
        (1..=3)
            .map(|i| {
                let mut record = test_record();
                let MpcRecoveryRecord::V1(inner) = &mut record;
                inner.validator_address = Address::new([i as u8; 32]);
                inner.key_shares.shares[0].index = ShareIndex::new(i).unwrap();
                inner.key_shares.shares[0].value = S::from(7u128 + 3 * u128::from(i));
                record
            })
            .collect()
    }

    #[test]
    fn reconstructs_root_from_threshold_weighted_and_surplus_shares() {
        let secret = S::from(7u128);
        let expected = G::generator() * secret;
        let mut records = recovery_records();
        assert!(reconstruct_root_scalar(&records[..2], &expected).unwrap() == secret);
        records.reverse();
        assert!(reconstruct_root_scalar(&records, &expected).unwrap() == secret);

        // A single weighted validator can supply the threshold of global shares.
        let MpcRecoveryRecord::V1(other) = records.remove(1);
        let MpcRecoveryRecord::V1(weighted) = &mut records[0];
        weighted.key_shares.shares.extend(other.key_shares.shares);
        assert!(reconstruct_root_scalar(&records[..1], &expected).unwrap() == secret);
    }

    #[test]
    fn rejects_missing_or_insufficient_distinct_root_shares() {
        let expected = G::generator() * S::from(7u128);
        let mut records = vec![test_record(); 3];
        assert!(reconstruct_root_scalar(&[], &expected).is_err());
        assert!(reconstruct_root_scalar(&records[..1], &expected).is_err());
        assert!(reconstruct_root_scalar(&records, &expected).is_err());
        let MpcRecoveryRecord::V1(inner) = &mut records[0];
        inner
            .key_shares
            .shares
            .push(inner.key_shares.shares[0].clone());
        records[0].validate().unwrap();
        assert!(reconstruct_root_scalar(&records[..1], &expected).is_err());
    }

    #[test]
    fn reconstructs_root_with_duplicate_records_and_local_indices() {
        let secret = S::from(7u128);
        let expected = G::generator() * secret;
        let mut records = recovery_records();
        records.push(records[0].clone());
        assert!(reconstruct_root_scalar(&records, &expected).unwrap() == secret);

        let MpcRecoveryRecord::V1(other) = records.remove(1);
        let MpcRecoveryRecord::V1(inner) = &mut records[0];
        inner
            .key_shares
            .shares
            .push(inner.key_shares.shares[0].clone());
        inner.key_shares.shares.extend(other.key_shares.shares);
        records[0].validate().unwrap();
        assert!(reconstruct_root_scalar(&records[..1], &expected).unwrap() == secret);
    }

    #[test]
    fn rejects_conflicting_duplicate_after_valid_quorum() {
        let expected = G::generator() * S::from(7u128);
        let mut records = recovery_records();
        let mut duplicate = records[0].clone();
        let MpcRecoveryRecord::V1(inner) = &mut duplicate;
        inner.key_shares.shares[0].value += S::from(1u128);
        records.push(duplicate);
        assert!(reconstruct_root_scalar(&records, &expected).is_err());

        let MpcRecoveryRecord::V1(duplicate) = records.pop().unwrap();
        let MpcRecoveryRecord::V1(inner) = &mut records[0];
        inner.key_shares.shares.extend(duplicate.key_shares.shares);
        assert!(records[0].validate().is_err());
        assert!(reconstruct_root_scalar(&records, &expected).is_err());
    }

    #[test]
    fn rejects_inconsistent_root_recovery_records() {
        type Invalidate = fn(&mut MpcRecoveryRecordV1);
        let cases: &[(&str, Invalidate)] = &[
            ("chain", |r| r.chain_id.push_str("-other")),
            ("object", |r| r.hashi_object_id = Address::new([9; 32])),
            ("epoch", |r| r.epoch += 1),
            ("key", |r| r.public_key = G::generator()),
            ("threshold", |r| r.threshold = 3),
            ("commitments", |r| {
                r.commitments
                    .insert(ShareIndex::new(1).unwrap(), G::generator());
            }),
            ("invalid surplus share", |r| {
                r.key_shares.shares[0].value = S::from(99u128);
            }),
        ];
        let expected = G::generator() * S::from(7u128);
        for (case, invalidate) in cases {
            let mut records = recovery_records();
            let MpcRecoveryRecord::V1(surplus) = &mut records[2];
            invalidate(surplus);
            assert!(
                reconstruct_root_scalar(&records, &expected).is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn binds_reconstructed_root_to_independently_trusted_key() {
        let expected = G::generator() * S::from(7u128);
        let mut records = recovery_records();
        assert!(reconstruct_root_scalar(&records, &G::generator()).is_err());

        // Internally valid shares of 8 + 3*x still claim the trusted key for 7.
        for MpcRecoveryRecord::V1(record) in &mut records {
            for share in &mut record.key_shares.shares {
                share.value += S::from(1u128);
            }
            for commitment in record.commitments.values_mut() {
                *commitment += G::generator();
            }
        }
        for record in &records {
            record.validate().unwrap();
        }
        assert!(reconstruct_root_scalar(&records, &expected).is_err());
    }
}
