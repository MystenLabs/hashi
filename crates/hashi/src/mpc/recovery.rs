// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use fastcrypto::groups::GroupElement;
use fastcrypto_tbls::threshold_schnorr::G;
use hashi_types::committee::RuntimeCommittee;
use hashi_types::move_types::DealerSubmissionV1;
use hashi_types::move_types::ProtocolType;
use hashi_types::move_types::{self};
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use sui_sdk_types::Address;

use super::mpc_except_signing::build_reduced_nodes;
use super::types::DealerMessagesHash;
use crate::db::BackupRecoveryContext;

/// Public, bounded inputs for replaying the latest completed local MPC output.
/// Committee authority and TOB order must still be anchored to a trusted chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecoveryBundle {
    pub context: BackupRecoveryContext,
    /// Effective reduction override used by the producer (one in production).
    pub test_weight_divisor: u16,
    /// Oldest dependency first; raw Move values are never round-tripped through runtime views.
    pub committees: Vec<move_types::Committee>,
    /// Direct previous output (for rotation), followed by the target output.
    pub transcripts: Vec<BackupRecoveryTranscript>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecoveryTranscript {
    pub epoch: u64,
    pub protocol: ProtocolType,
    /// Original LinkedTable order, including dealer keys and unusable certificates.
    /// Validation requires sufficient verified dealer weight, not validity of every row.
    pub submissions: Vec<(Address, DealerSubmissionV1)>,
}

impl BackupRecoveryBundle {
    /// Validate public replay inputs without accessing live TOB buckets.
    /// This verifies certificate authority relative to the supplied committees,
    /// not their external chain authority. Message hashes must additionally be
    /// matched to stored AVSS messages by reconstruction, which checks the final key.
    pub fn validate(&self) -> Result<()> {
        let context = &self.context;
        ensure!(
            self.test_weight_divisor > 0
                && (!crate::constants::is_production_sui_chain(&context.deployment.sui_chain_id)
                    || self.test_weight_divisor == 1),
            "invalid recovery weight divisor"
        );
        ensure!(
            !context.deployment.sui_chain_id.is_empty()
                && !context.deployment.bitcoin_chain_id.is_empty()
                && context.deployment.package_id != Address::ZERO
                && context.deployment.hashi_object_id != Address::ZERO,
            "recovery deployment identity is incomplete"
        );
        let key_bytes =
            hex::decode(&context.mpc_public_key).context("invalid recovery public key")?;
        let key: G = bcs::from_bytes(&key_bytes).context("invalid recovery public key")?;
        ensure!(key != G::zero(), "recovery public key is identity");
        ensure!(
            bcs::to_bytes(&key)? == key_bytes && hex::encode(&key_bytes) == context.mpc_public_key,
            "recovery public key is not canonical"
        );
        let transcripts = &self.transcripts;
        ensure!(
            !transcripts.is_empty() && transcripts.len() <= 2,
            "invalid recovery transcript count"
        );
        let target = transcripts.last().unwrap();
        ensure!(
            target.epoch == context.recovery_epoch,
            "target recovery epoch mismatch"
        );
        let expected_committees = match target.protocol {
            ProtocolType::Dkg => {
                ensure!(
                    transcripts.len() == 1 && context.previous_committee_epoch.is_none(),
                    "DKG must not carry dependencies"
                );
                1
            }
            ProtocolType::KeyRotation => {
                ensure!(
                    transcripts.len() == 2,
                    "rotation requires its direct previous transcript"
                );
                let previous = &transcripts[0];
                ensure!(
                    Some(previous.epoch) == context.previous_committee_epoch
                        && previous.epoch < target.epoch,
                    "rotation predecessor mismatch"
                );
                match previous.protocol {
                    ProtocolType::Dkg => 2,
                    ProtocolType::KeyRotation => 3,
                    _ => anyhow::bail!("invalid previous recovery protocol"),
                }
            }
            _ => anyhow::bail!("invalid target recovery protocol"),
        };
        ensure!(
            self.committees.len() == expected_committees,
            "missing or excess recovery committees"
        );
        ensure!(
            self.committees
                .windows(2)
                .all(|pair| pair[0].epoch < pair[1].epoch),
            "recovery committees are not strictly ordered"
        );
        let mut runtime = Vec::with_capacity(expected_committees);
        for raw in &self.committees {
            ensure!(
                !raw.members.is_empty() && raw.members.len() <= usize::from(u16::MAX),
                "invalid committee size"
            );
            let mut addresses = BTreeSet::new();
            let mut total = 0u64;
            let mut operational_total = 0u64;
            for member in &raw.members {
                ensure!(
                    addresses.insert(member.validator_address),
                    "duplicate committee member"
                );
                total = total
                    .checked_add(member.weight)
                    .context("committee weight overflow")?;
                ensure!(
                    member.weight <= u64::from(u16::MAX),
                    "committee member weight exceeds MPC range"
                );
                operational_total = operational_total
                    .checked_add((member.weight / u64::from(self.test_weight_divisor)).max(1))
                    .context("committee weight overflow")?;
            }
            ensure!(
                total == raw.total_weight && operational_total <= u64::from(u16::MAX),
                "invalid raw committee total weight"
            );
            let committee = RuntimeCommittee::from_move_with_encryption_key_fallback(raw.clone())?;
            let (nodes, threshold, faulty) = build_reduced_nodes(
                &committee,
                self.test_weight_divisor,
                &context.deployment.sui_chain_id,
            )?;
            runtime.push((committee, nodes, threshold, faulty));
        }
        let offset = runtime.len() - transcripts.len();
        for (index, transcript) in transcripts.iter().enumerate() {
            let committee_index = offset + index;
            let (committee, nodes, threshold, faulty) = &runtime[committee_index];
            ensure!(
                committee.epoch() == transcript.epoch,
                "transcript committee epoch mismatch"
            );
            let (dealer_committee, dealer_nodes, required_dealer_weight) = match transcript.protocol
            {
                ProtocolType::Dkg => (committee, nodes, *threshold),
                ProtocolType::KeyRotation => {
                    ensure!(committee_index > 0, "rotation input committee is missing");
                    let (previous, previous_nodes, previous_threshold, _) =
                        &runtime[committee_index - 1];
                    (previous, previous_nodes, *previous_threshold)
                }
                _ => anyhow::bail!("invalid recovery protocol"),
            };
            ensure!(
                !transcript.submissions.is_empty(),
                "empty recovery transcript"
            );
            let mut dealers = BTreeSet::new();
            let mut dealer_weight = 0u32;
            let mut timestamp = 0;
            for (dealer, submission) in &transcript.submissions {
                ensure!(
                    *dealer == submission.message.dealer_address,
                    "TOB dealer key mismatch"
                );
                ensure!(dealers.insert(*dealer), "duplicate recovery dealer");
                ensure!(
                    submission.timestamp_ms >= timestamp,
                    "recovery TOB timestamps are out of order"
                );
                timestamp = submission.timestamp_ms;
                // Registration permits submissions from dealers outside the
                // effective input committee; they have no usable input weight.
                let Some(party) = dealer_committee.index_of(dealer) else {
                    continue;
                };
                let Ok(weight) = dealer_nodes.weight_of(party as u16) else {
                    continue;
                };
                // Live TOB reads skip undecodable certificates, and MPC consumers
                // skip certificates that fail signature or reduced-weight checks.
                // Keep those raw rows for fidelity, but never credit their dealers.
                // As in live admission, signatures are bound to the bucket epoch;
                // the raw signature.epoch field is not an authority for that epoch.
                let Ok(cert) = DealerMessagesHash::from_onchain_cert(submission, transcript.epoch)
                else {
                    continue;
                };
                if committee
                    .verify_signature_and_reduced_weight(
                        context.deployment.hashi_object_id,
                        &cert,
                        nodes,
                        u32::from(*threshold) + u32::from(*faulty),
                    )
                    .is_err()
                {
                    continue;
                }
                dealer_weight += u32::from(weight);
            }
            // For rotation these are the input shares owned by certified dealers.
            // Reconstruction separately checks the actual message/share-index selection.
            ensure!(
                dealer_weight >= u32::from(required_dealer_weight),
                "insufficient certified recovery dealer weight"
            );
        }
        Ok(())
    }

    /// Capture from one immutable mirror snapshot. The caller supplies a context
    /// bound to a completed local output and only publishes it after finalization.
    pub(crate) fn capture(
        context: BackupRecoveryContext,
        state: &crate::onchain::State,
        config: &crate::config::Config,
    ) -> Result<Self> {
        ensure!(
            context.deployment.sui_chain_id == config.sui_chain_id(),
            "recovery chain differs from configuration"
        );
        let committees = &state.hashi().committees;
        ensure!(
            state.hashi().id == context.deployment.hashi_object_id,
            "recovery Hashi object mismatch"
        );
        let target = context.recovery_epoch;
        ensure!(
            committees.epoch() == target || committees.pending_epoch_change() == Some(target),
            "recovery target is neither current nor pending"
        );
        let key = hex::decode(&context.mpc_public_key).context("invalid recovery context key")?;
        if committees.epoch() == target || !committees.mpc_public_key().is_empty() {
            ensure!(
                committees.mpc_public_key() == key,
                "completed recovery key differs from chain key"
            );
        }
        let previous = committees
            .committees()
            .range(..target)
            .next_back()
            .map(|(&epoch, _)| epoch);
        ensure!(
            previous == context.previous_committee_epoch,
            "recovery predecessor differs from snapshot"
        );
        let mut epochs = Vec::with_capacity(3);
        let mut transcripts = Vec::with_capacity(2);
        if let Some(previous) = previous {
            let input = committees
                .committees()
                .range(..previous)
                .next_back()
                .map(|(&epoch, _)| epoch);
            if let Some(input) = input {
                epochs.push(input);
            }
            epochs.push(previous);
            transcripts.push(capture_transcript(state, previous, input.is_some())?);
        }
        epochs.push(target);
        transcripts.push(capture_transcript(state, target, previous.is_some())?);
        let raw = epochs
            .into_iter()
            .map(|epoch| {
                committees
                    .raw_committee(epoch)
                    .cloned()
                    .with_context(|| format!("missing raw recovery committee {epoch}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            context,
            test_weight_divisor: config.test_weight_divisor(),
            committees: raw,
            transcripts,
        })
    }
}

fn capture_transcript(
    state: &crate::onchain::State,
    epoch: u64,
    rotation: bool,
) -> Result<BackupRecoveryTranscript> {
    let protocol = if rotation {
        ProtocolType::KeyRotation
    } else {
        ProtocolType::Dkg
    };
    let submissions = state
        .tob_certs(epoch, None, protocol)?
        .with_context(|| format!("missing recovery transcript for epoch {epoch}"))?;
    Ok(BackupRecoveryTranscript {
        epoch,
        protocol,
        submissions,
    })
}

/// A signed DKG fixture, not a local private-share reconstruction fixture.
#[cfg(test)]
pub(crate) fn test_recovery_bundle(
    epoch: u64,
    deployment: crate::db::BackupDeployment,
) -> BackupRecoveryBundle {
    test_recovery_bundle_with_signers(epoch, deployment, &[4, 4])
}

#[cfg(test)]
fn test_recovery_bundle_with_signers(
    epoch: u64,
    deployment: crate::db::BackupDeployment,
    signer_counts: &[usize],
) -> BackupRecoveryBundle {
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::BlsSignatureAggregator;
    use hashi_types::committee::Committee;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPrivateKey;
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(epoch);
    let keys: Vec<_> = (0..4)
        .map(|_| Bls12381PrivateKey::generate(&mut rng))
        .collect();
    let members = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            CommitteeMember::new(
                Address::new([index as u8 + 1; 32]),
                key.public_key(),
                EncryptionPrivateKey::new(&mut rng).public_key(),
                2500,
            )
        })
        .collect();
    let committee = Committee::new(members, epoch, 0, 3333);
    let submissions = signer_counts
        .iter()
        .enumerate()
        .map(|(index, &signer_count)| {
            let dealer = committee.members()[index].validator_address();
            let message = DealerMessagesHash {
                dealer_address: dealer,
                messages_hash: [index as u8 + 1; 32].into(),
            };
            let mut aggregator = BlsSignatureAggregator::new(
                deployment.hashi_object_id,
                &committee,
                message.clone(),
            );
            for (key, member) in keys.iter().zip(committee.members()).take(signer_count) {
                aggregator
                    .add_signature(key.sign(
                        deployment.hashi_object_id,
                        epoch,
                        member.validator_address(),
                        &message,
                    ))
                    .unwrap();
            }
            let signed = aggregator.finish().unwrap();
            (
                dealer,
                DealerSubmissionV1 {
                    message: move_types::DealerMessagesHashV1 {
                        dealer_address: dealer,
                        messages_hash: vec![index as u8 + 1; 32],
                    },
                    signature: move_types::CommitteeSignature {
                        epoch,
                        signature: signed.signature_bytes().to_vec(),
                        signers_bitmap: signed.signers_bitmap_bytes().to_vec(),
                    },
                    timestamp_ms: index as u64 + 1,
                },
            )
        })
        .collect();
    let key = bcs::to_bytes(&G::generator()).unwrap();
    BackupRecoveryBundle {
        context: BackupRecoveryContext {
            recovery_epoch: epoch,
            previous_committee_epoch: None,
            mpc_public_key: hex::encode(&key),
            deployment,
        },
        test_weight_divisor: 1,
        committees: vec![(&committee).into()],
        transcripts: vec![BackupRecoveryTranscript {
            epoch,
            protocol: ProtocolType::Dkg,
            submissions,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deployment() -> crate::db::BackupDeployment {
        crate::db::BackupDeployment {
            sui_chain_id: "test".into(),
            bitcoin_chain_id: "regtest".into(),
            package_id: Address::new([20; 32]),
            hashi_object_id: Address::new([21; 32]),
        }
    }

    fn fixture() -> BackupRecoveryBundle {
        test_recovery_bundle(9, deployment())
    }

    fn rotation_fixture(previous_rotation: bool) -> BackupRecoveryBundle {
        let mut bundle = fixture();
        let previous = test_recovery_bundle(5, bundle.context.deployment.clone());
        bundle.context.previous_committee_epoch = Some(5);
        bundle.transcripts[0].protocol = ProtocolType::KeyRotation;
        bundle.committees.insert(0, previous.committees[0].clone());
        bundle
            .transcripts
            .insert(0, previous.transcripts[0].clone());
        if previous_rotation {
            let mut input = bundle.committees[0].clone();
            input.epoch = 2;
            bundle.committees.insert(0, input);
            bundle.transcripts[0].protocol = ProtocolType::KeyRotation;
        }
        bundle
    }

    #[test]
    fn unusable_entries_preserve_complete_transcripts_and_raw_order() {
        for original in [fixture(), rotation_fixture(false), rotation_fixture(true)] {
            for transcript_index in 0..original.transcripts.len() {
                // Exercise an unusable prefix, middle entry, and suffix.
                for position in 0..=2 {
                    for malformed in 0..3 {
                        let mut bundle = original.clone();
                        let transcript = &mut bundle.transcripts[transcript_index];
                        let mut unusable = transcript.submissions[0].clone();
                        // An authorized, previously unused dealer with a signature
                        // over another message is decodable but unverifiable.
                        unusable.0 = Address::new([3; 32]);
                        unusable.1.message.dealer_address = unusable.0;
                        match malformed {
                            1 => unusable.1.message.messages_hash.clear(),
                            2 => unusable.1.signature.signature.clear(),
                            _ => {}
                        }
                        assert_eq!(
                            DealerMessagesHash::from_onchain_cert(&unusable.1, transcript.epoch)
                                .is_err(),
                            malformed != 0
                        );
                        transcript.submissions.insert(position, unusable);
                        for (index, (_, submission)) in
                            transcript.submissions.iter_mut().enumerate()
                        {
                            submission.timestamp_ms = index as u64 + 1;
                        }
                        bundle.validate().unwrap();

                        // Raw nonempty entries do not substitute for verified weight,
                        // even when another dealer has a valid certificate.
                        bundle.transcripts[transcript_index]
                            .submissions
                            .retain(|(dealer, _)| *dealer != Address::new([2; 32]));
                        assert!(
                            bundle
                                .validate()
                                .unwrap_err()
                                .to_string()
                                .contains("insufficient certified recovery dealer weight")
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn correctly_signed_underweight_entries_are_not_credited() {
        let mut bundle = test_recovery_bundle_with_signers(9, deployment(), &[4, 4, 1]);
        let committee =
            RuntimeCommittee::from_move_with_encryption_key_fallback(bundle.committees[0].clone())
                .unwrap();
        let cert = DealerMessagesHash::from_onchain_cert(
            &bundle.transcripts[0].submissions[2].1,
            bundle.context.recovery_epoch,
        )
        .unwrap();
        committee
            .verify_signature_any_weight(bundle.context.deployment.hashi_object_id, &cert)
            .unwrap();
        let (nodes, threshold, faulty) = build_reduced_nodes(
            &committee,
            bundle.test_weight_divisor,
            &bundle.context.deployment.sui_chain_id,
        )
        .unwrap();
        assert!(
            committee
                .verify_signature_and_reduced_weight(
                    bundle.context.deployment.hashi_object_id,
                    &cert,
                    &nodes,
                    u32::from(threshold) + u32::from(faulty),
                )
                .is_err()
        );
        bundle.validate().unwrap();
        bundle.transcripts[0].submissions.remove(0);
        assert!(
            bundle
                .validate()
                .unwrap_err()
                .to_string()
                .contains("insufficient certified recovery dealer weight")
        );
    }

    #[test]
    fn certificates_are_bound_to_bucket_epoch_not_raw_signature_epoch() {
        let mut bundle = test_recovery_bundle_with_signers(9, deployment(), &[4, 4, 4]);
        // Even an appended certificate's untrusted epoch field is irrelevant.
        bundle.transcripts[0].submissions[2].1.signature.epoch += 1;
        bundle.validate().unwrap();
        // The signature still verifies against the bucket epoch, so this row
        // must contribute rather than merely being skipped.
        bundle.transcripts[0].submissions.remove(0);
        bundle.validate().unwrap();

        // Conversely, moving the same committee keys and certificates to a
        // different bucket must not credit signatures made for the old epoch,
        // even if their raw epoch fields now match the destination bucket.
        bundle.context.recovery_epoch += 1;
        bundle.committees[0].epoch += 1;
        bundle.transcripts[0].epoch += 1;
        for (_, submission) in &mut bundle.transcripts[0].submissions {
            submission.signature.epoch = bundle.context.recovery_epoch;
        }
        assert!(
            bundle
                .validate()
                .unwrap_err()
                .to_string()
                .contains("insufficient certified recovery dealer weight")
        );
    }

    #[test]
    fn dealers_outside_input_committee_do_not_invalidate_or_add_weight() {
        for original in [fixture(), rotation_fixture(false), rotation_fixture(true)] {
            for invalid_signature in [false, true] {
                let mut bundle = original.clone();
                let target = bundle.transcripts.last_mut().unwrap();
                let extra = test_recovery_bundle_with_signers(
                    target.epoch,
                    bundle.context.deployment.clone(),
                    &[4, 4, 4],
                );
                let mut suffix = extra.transcripts[0].submissions[2].clone();
                if invalid_signature {
                    suffix.1.message.messages_hash[0] ^= 1;
                }
                target.submissions.push(suffix);
                let input_index = bundle.committees.len()
                    - if target.protocol == ProtocolType::Dkg {
                        1
                    } else {
                        2
                    };
                // A registered submitter need not belong to the effective input
                // committee. Preserve signer keys/order so a valid signature
                // alone cannot confer input shares on an absent dealer.
                bundle.committees[input_index].members[2].validator_address =
                    Address::new([99; 32]);
                bundle.validate().unwrap();
                bundle.transcripts.last_mut().unwrap().submissions.remove(0);
                assert!(
                    bundle
                        .validate()
                        .unwrap_err()
                        .to_string()
                        .contains("insufficient certified recovery dealer weight")
                );
            }
        }
    }

    #[test]
    fn unusable_certificates_do_not_hide_structural_errors() {
        for tamper in 0..3 {
            let mut bundle = fixture();
            let mut unusable = bundle.transcripts[0].submissions[0].clone();
            unusable.0 = Address::new([3; 32]);
            unusable.1.message.dealer_address = unusable.0;
            unusable.1.message.messages_hash.clear();
            unusable.1.timestamp_ms = 3;
            match tamper {
                0 => unusable.0 = Address::ZERO,
                1 => {
                    unusable.0 = Address::new([1; 32]);
                    unusable.1.message.dealer_address = unusable.0;
                }
                _ => unusable.1.timestamp_ms = 0,
            }
            bundle.transcripts[0].submissions.push(unusable);
            assert!(bundle.validate().is_err(), "tamper {tamper}");
        }
    }

    #[test]
    fn rotation_dependencies_are_direct_bounded_and_ordered() {
        for previous_rotation in [false, true] {
            let bundle = rotation_fixture(previous_rotation);
            bundle.validate().unwrap();
            let mut missing = bundle.clone();
            missing.committees.remove(0);
            assert!(missing.validate().is_err());
            let mut reordered = bundle.clone();
            reordered.transcripts.swap(0, 1);
            assert!(reordered.validate().is_err());
            let mut reordered = bundle.clone();
            reordered.committees.swap(0, 1);
            assert!(reordered.validate().is_err());
            let mut wrong_predecessor = bundle;
            wrong_predecessor.context.previous_committee_epoch = Some(4);
            assert!(wrong_predecessor.validate().is_err());
        }
    }

    #[test]
    fn accepts_invalid_encryption_bytes_using_runtime_fallback() {
        let mut bundle = fixture();
        bundle.committees[0].members[0].encryption_public_key = vec![0xff];
        bundle.validate().unwrap();
    }

    #[test]
    fn uses_effective_reduction_and_rejects_zero_divisor() {
        let mut bundle = fixture();
        bundle.test_weight_divisor = 2500;
        bundle.validate().unwrap();
        bundle.test_weight_divisor = 0;
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn rejects_signature_and_deployment_tampering() {
        let original = fixture();
        for tamper in 0..3 {
            let mut bundle = original.clone();
            let row = &mut bundle.transcripts[0].submissions[0];
            match tamper {
                0 => row.1.message.messages_hash[0] ^= 1,
                1 => row.1.signature.signers_bitmap.clear(),
                _ => bundle.context.deployment.hashi_object_id = Address::new([22; 32]),
            }
            assert!(bundle.validate().is_err(), "tamper {tamper}");
        }
    }

    #[test]
    fn rejects_metadata_key_and_raw_committee_tampering() {
        let mut bundle = fixture();
        bundle.context.mpc_public_key = hex::encode(bcs::to_bytes(&G::zero()).unwrap());
        assert!(bundle.validate().is_err());
        let mut bundle = fixture();
        bundle.committees[0].total_weight += 1;
        assert!(bundle.validate().is_err());
        let mut bundle = fixture();
        bundle.committees[0].members[1].validator_address =
            bundle.committees[0].members[0].validator_address;
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn rejects_missing_excess_and_misclassified_dependencies() {
        let original = fixture();
        for tamper in 0..5 {
            let mut bundle = original.clone();
            match tamper {
                0 => bundle.committees.clear(),
                1 => bundle.transcripts.clear(),
                2 => bundle.context.previous_committee_epoch = Some(8),
                3 => bundle.transcripts[0].protocol = ProtocolType::KeyRotation,
                _ => bundle.committees.push(bundle.committees[0].clone()),
            }
            assert!(bundle.validate().is_err(), "tamper {tamper}");
        }
    }
}
