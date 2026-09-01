// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::withdraw_mode::verify_hashi_cert;
use crate::Enclave;
use hashi_types::guardian::CommitteeActivationRequest;
use hashi_types::guardian::CommitteeTransitionRequest;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::HashiSigned;
use std::sync::Arc;
use tracing::info;

pub(crate) struct CommitteeUpdateRequest {
    pub(crate) transitions: Vec<HashiSigned<CommitteeTransitionRequest>>,
    pub(crate) activation: HashiSigned<CommitteeActivationRequest>,
}

fn verify_committee_update_cert<T: hashi_types::intent::IntentMessage>(
    committee: &HashiCommittee,
    signed: &HashiSigned<T>,
) -> GuardianResult<()> {
    signed
        .weight(committee)
        .map_err(|error| InvalidInputs(format!("malformed committee certificate: {error}")))?;
    verify_hashi_cert(committee, signed)
}

/// Validate the complete transition chain and final activation certificate
/// before one durable write and one committee replacement.
pub(crate) async fn update_committee_chain(
    enclave: Arc<Enclave>,
    request: CommitteeUpdateRequest,
) -> GuardianResult<u64> {
    enclave.require_fully_initialized()?;
    let CommitteeUpdateRequest {
        transitions,
        activation,
    } = request;
    let final_transition = transitions
        .last()
        .ok_or_else(|| InvalidInputs("committee transition chain is empty".to_string()))?;
    if activation.message().new_committee != final_transition.message().new_committee {
        return Err(InvalidInputs(
            "activation payload does not match final transition payload".to_string(),
        ));
    }

    let final_epoch = activation.message().new_committee.epoch;
    let final_committee: HashiCommittee = activation
        .message()
        .new_committee
        .clone()
        .try_into()
        .map_err(|error| {
            InvalidInputs(format!(
                "invalid final committee in activation certificate: {error}"
            ))
        })?;
    if activation.epoch() != final_epoch {
        return Err(InvalidInputs(format!(
            "activation signature epoch ({}) does not match final committee epoch ({final_epoch})",
            activation.epoch()
        )));
    }
    verify_committee_update_cert(&final_committee, &activation)?;

    let installed_committee = enclave.state.get_committee()?;
    let installed_epoch = installed_committee.epoch();
    if final_epoch == installed_epoch {
        if final_committee == *installed_committee {
            return Ok(installed_epoch);
        }
        return Err(InvalidInputs(format!(
            "activation targets a different committee at installed epoch {installed_epoch}"
        )));
    }
    if final_epoch < installed_epoch {
        return Err(InvalidInputs(format!(
            "activation target epoch {final_epoch} is older than installed epoch {installed_epoch}"
        )));
    }

    let mut preceding_committee = (*installed_committee).clone();
    for transition in &transitions {
        let raw_committee = &transition.message().new_committee;
        let target_epoch = raw_committee.epoch;
        let source_epoch = preceding_committee.epoch();
        if target_epoch <= source_epoch {
            return Err(InvalidInputs(format!(
                "committee transition does not advance: {source_epoch}->{target_epoch}"
            )));
        }
        let target_committee: HashiCommittee =
            raw_committee.clone().try_into().map_err(|error| {
                InvalidInputs(format!(
                    "invalid committee in transition to epoch {target_epoch}: {error}"
                ))
            })?;
        verify_committee_update_cert(&preceding_committee, transition)?;
        preceding_committee = target_committee;
    }

    let (request_sign, activation) = activation.into_parts();
    let message = CommitteeUpdateLogMessage::Success {
        from_epoch: installed_epoch,
        new_committee: activation.new_committee,
        request_sign,
    };
    enclave.log_committee_update(message).await?;
    enclave
        .state
        .replace_committee(final_committee, installed_epoch)
        .expect("committee initialized at installed_epoch under the update lock");
    info!(
        from_epoch = installed_epoch,
        to_epoch = final_epoch,
        "Committee updated"
    );
    Ok(final_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::activate_enclave_for_testing;
    use crate::test_utils::finalize_enclave;
    use crate::test_utils::mock_logger_capturing;
    use crate::test_utils::CapturedPuts;
    use crate::OperatorInitTestArgs;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::BlsSignatureAggregator;
    use hashi_types::committee::CommitteeSignature;
    use hashi_types::committee::EncryptionPrivateKey;
    use hashi_types::committee::EncryptionPublicKey;
    use hashi_types::committee::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
    use hashi_types::committee::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;
    use hashi_types::committee::VANILLA_MPC_NONCE_GENERATION_PROTOCOL;
    use hashi_types::guardian::GuardianError;
    use hashi_types::guardian::HashiCommitteeMember;
    use hashi_types::guardian::LimiterConfig;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::LogMessageV2;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::VersionedLogMessage;
    use hashi_types::guardian::WithdrawalID as SuiAddress;
    use hashi_types::intent::IntentMessage;
    use rand::SeedableRng;

    struct Fixture {
        committee: HashiCommittee,
        address: SuiAddress,
        key: Bls12381PrivateKey,
    }

    fn committee(epoch: u64, id: u8) -> Fixture {
        let address = SuiAddress::new([id; 32]);
        let mut key_rng = rand::rngs::StdRng::seed_from_u64(0x510000 + u64::from(id));
        let key = Bls12381PrivateKey::generate(&mut key_rng);
        let mut enc_rng = rand::rngs::StdRng::seed_from_u64(0xE10000 + u64::from(id));
        let enc_key = EncryptionPrivateKey::new(&mut enc_rng);
        let member = HashiCommitteeMember::new(
            address,
            key.public_key(),
            EncryptionPublicKey::from_private_key(&enc_key),
            10,
        );
        Fixture {
            committee: HashiCommittee::new(
                vec![member],
                epoch,
                DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
                DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
                VANILLA_MPC_NONCE_GENERATION_PROTOCOL,
            ),
            address,
            key,
        }
    }

    fn sign<T: IntentMessage + Clone>(signer: &Fixture, message: T) -> HashiSigned<T> {
        let epoch = signer.committee.epoch();
        let signature = signer.key.sign(epoch, signer.address, &message);
        let mut aggregator = BlsSignatureAggregator::new(&signer.committee, message);
        aggregator.add_signature(signature).unwrap();
        aggregator.finish().unwrap()
    }

    fn transition(signer: &Fixture, target: &Fixture) -> HashiSigned<CommitteeTransitionRequest> {
        sign(
            signer,
            CommitteeTransitionRequest {
                new_committee: (&target.committee).into(),
            },
        )
    }

    fn activation(signer: &Fixture, payload: &Fixture) -> HashiSigned<CommitteeActivationRequest> {
        sign(
            signer,
            CommitteeActivationRequest {
                new_committee: (&payload.committee).into(),
            },
        )
    }

    fn request(
        transitions: Vec<HashiSigned<CommitteeTransitionRequest>>,
        activation: HashiSigned<CommitteeActivationRequest>,
    ) -> CommitteeUpdateRequest {
        CommitteeUpdateRequest {
            transitions,
            activation,
        }
    }

    fn reuse_transition(
        signed: &HashiSigned<CommitteeTransitionRequest>,
    ) -> HashiSigned<CommitteeActivationRequest> {
        HashiSigned::new(
            signed.epoch(),
            CommitteeActivationRequest {
                new_committee: signed.message().new_committee.clone(),
            },
            signed.signature_bytes(),
            signed.signers_bitmap_bytes(),
        )
        .unwrap()
    }

    fn at_epoch<T: IntentMessage + Clone>(signed: &HashiSigned<T>, epoch: u64) -> HashiSigned<T> {
        HashiSigned::new(
            epoch,
            signed.message().clone(),
            signed.signature_bytes(),
            signed.signers_bitmap_bytes(),
        )
        .unwrap()
    }

    async fn enclave(installed: &Fixture) -> (Arc<Enclave>, CapturedPuts, usize) {
        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(logger),
        )
        .await;
        finalize_enclave(&enclave).unwrap();
        activate_enclave_for_testing(
            &enclave,
            installed.committee.clone(),
            LimiterConfig {
                refill_rate: 0,
                max_bucket_capacity: 1_000,
            },
            LimiterState {
                num_tokens_available: 1_000,
                last_updated_at: 0,
                next_seq: 0,
            },
        )
        .unwrap();
        let baseline = captures.lock().unwrap().len();
        (enclave, captures, baseline)
    }

    #[derive(Clone, Copy)]
    enum ErrorClass {
        Invalid,
        Unauthenticated,
    }

    async fn rejected(
        label: &str,
        installed: &Fixture,
        request: CommitteeUpdateRequest,
        class: ErrorClass,
    ) {
        let (enclave, captures, baseline) = enclave(installed).await;
        let error = match update_committee_chain(enclave.clone(), request).await {
            Ok(epoch) => panic!("{label}: request unexpectedly succeeded at epoch {epoch}"),
            Err(error) => error,
        };
        match class {
            ErrorClass::Invalid => assert!(
                matches!(error, GuardianError::InvalidInputs(_)),
                "{label}: expected invalid inputs, got {error:?}"
            ),
            ErrorClass::Unauthenticated => assert!(
                matches!(error, GuardianError::Unauthenticated(_)),
                "{label}: expected unauthenticated, got {error:?}"
            ),
        }
        assert_eq!(
            enclave.state.get_committee().unwrap().as_ref(),
            &installed.committee,
            "{label}: installed committee changed"
        );
        assert_eq!(
            captures.lock().unwrap().len(),
            baseline,
            "{label}: rejection wrote a committee update record"
        );
    }

    fn assert_record(
        captures: &CapturedPuts,
        baseline: usize,
        from: u64,
        to: u64,
        signature: &CommitteeSignature,
    ) {
        let captured = captures.lock().unwrap();
        assert_eq!(captured.len(), baseline + 1);
        let record: LogRecord = serde_json::from_slice(&captured[baseline].1).unwrap();
        let VersionedLogMessage::V2(LogMessageV2::CommitteeUpdate(message)) = record.message()
        else {
            panic!("expected committee update log");
        };
        let CommitteeUpdateLogMessage::Success {
            from_epoch,
            new_committee,
            request_sign,
        } = message.as_ref()
        else {
            panic!("expected success log");
        };
        assert_eq!((*from_epoch, new_committee.epoch), (from, to));
        assert_eq!(request_sign.epoch(), signature.epoch());
        assert_eq!(request_sign.signature_bytes(), signature.signature_bytes());
        assert_eq!(
            request_sign.signers_bitmap_bytes(),
            signature.signers_bitmap_bytes()
        );
    }

    #[tokio::test]
    async fn valid_single_hop() {
        let old = committee(5, 1);
        let new = committee(7, 2);
        let active = activation(&new, &new);
        let signature = active.committee_signature().clone();
        let (enclave, captures, baseline) = enclave(&old).await;
        let epoch = update_committee_chain(
            enclave.clone(),
            request(vec![transition(&old, &new)], active),
        )
        .await
        .unwrap();
        assert_eq!(epoch, 7);
        assert_eq!(
            enclave.state.get_committee().unwrap().as_ref(),
            &new.committee
        );
        assert_record(&captures, baseline, 5, 7, &signature);
    }

    #[tokio::test]
    async fn valid_sparse_multi_hop_writes_one_final_record() {
        let old = committee(5, 1);
        let middle = committee(8, 2);
        let new = committee(13, 3);
        let active = activation(&new, &new);
        let signature = active.committee_signature().clone();
        let (enclave, captures, baseline) = enclave(&old).await;
        let epoch = update_committee_chain(
            enclave.clone(),
            request(
                vec![transition(&old, &middle), transition(&middle, &new)],
                active,
            ),
        )
        .await
        .unwrap();
        assert_eq!(epoch, 13);
        assert_eq!(
            enclave.state.get_committee().unwrap().as_ref(),
            &new.committee
        );
        assert_record(&captures, baseline, 5, 13, &signature);
    }

    #[tokio::test]
    async fn exact_retry_is_a_noop() {
        let old = committee(5, 1);
        let new = committee(7, 2);
        let outgoing = transition(&old, &new);
        let active = activation(&new, &new);
        let (enclave, captures, baseline) = enclave(&old).await;
        update_committee_chain(
            enclave.clone(),
            request(vec![outgoing.clone()], active.clone()),
        )
        .await
        .unwrap();
        assert_eq!(captures.lock().unwrap().len(), baseline + 1);
        assert_eq!(
            update_committee_chain(enclave.clone(), request(vec![outgoing], active))
                .await
                .unwrap(),
            7
        );
        assert_eq!(captures.lock().unwrap().len(), baseline + 1);
    }

    #[tokio::test]
    async fn invalid_requests_have_no_side_effects() {
        let old = committee(5, 1);
        let middle = committee(8, 2);
        let new = committee(13, 3);
        let wrong_old = committee(5, 9);
        let wrong_middle = committee(8, 9);
        let wrong_new = committee(13, 9);
        let other_payload = committee(13, 4);
        let same_epoch = committee(5, 5);
        let older = committee(3, 6);
        let outgoing = transition(&old, &new);
        let valid_activation = activation(&new, &new);
        let cases = vec![
            (
                "empty chain",
                request(vec![], activation(&new, &new)),
                ErrorClass::Invalid,
            ),
            (
                "bad first transition",
                request(vec![transition(&wrong_old, &new)], activation(&new, &new)),
                ErrorClass::Unauthenticated,
            ),
            (
                "transition wrong epoch",
                request(vec![at_epoch(&outgoing, 4)], activation(&new, &new)),
                ErrorClass::Invalid,
            ),
            (
                "bad middle transition",
                request(
                    vec![transition(&old, &middle), transition(&wrong_middle, &new)],
                    activation(&new, &new),
                ),
                ErrorClass::Unauthenticated,
            ),
            (
                "outgoing certificate reused as activation",
                request(vec![outgoing.clone()], reuse_transition(&outgoing)),
                ErrorClass::Invalid,
            ),
            (
                "activation wrong epoch",
                request(
                    vec![transition(&old, &new)],
                    at_epoch(&valid_activation, 12),
                ),
                ErrorClass::Invalid,
            ),
            (
                "activation wrong committee",
                request(vec![transition(&old, &new)], activation(&wrong_new, &new)),
                ErrorClass::Unauthenticated,
            ),
            (
                "activation different payload",
                request(
                    vec![transition(&old, &new)],
                    activation(&other_payload, &other_payload),
                ),
                ErrorClass::Invalid,
            ),
            (
                "same-epoch different committee",
                request(
                    vec![transition(&old, &same_epoch)],
                    activation(&same_epoch, &same_epoch),
                ),
                ErrorClass::Invalid,
            ),
            (
                "older target",
                request(vec![transition(&old, &older)], activation(&older, &older)),
                ErrorClass::Invalid,
            ),
        ];
        for (label, request, class) in cases {
            rejected(label, &old, request, class).await;
        }
    }
}
