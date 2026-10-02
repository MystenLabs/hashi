// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::enclave::EnclaveState;
use crate::withdraw_mode::verify_hashi_cert;
use crate::Enclave;
use hashi_types::guardian::CommitteeTransitionRequest;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::RuntimeCommittee;
use std::sync::Arc;
use tracing::info;

/// Advance the committee to a future epoch with a cert from the outgoing
/// committee. Hashi epochs can skip values (reconfig is sparse), so the
/// proposed epoch is only required to be strictly greater than the
/// current one; sequentiality is not enforced.
/// Idempotent on already-applied or older transitions.
pub async fn update_committee(
    enclave: Arc<Enclave>,
    state: &mut EnclaveState,
    signed: HashiSigned<CommitteeTransitionRequest>,
) -> GuardianResult<u64> {
    state.require_fully_initialized()?;

    let current = state.get_committee()?;
    let current_epoch = current.epoch();
    let proposed_epoch = signed.message().new_committee.epoch;

    if proposed_epoch <= current_epoch {
        info!(current_epoch, proposed_epoch, "update_committee: no-op");
        return Ok(current_epoch);
    }

    verify_hashi_cert(enclave.hashi_object_id()?, &current, &signed)?;

    let new_committee = RuntimeCommittee::from_move_with_encryption_key_fallback(
        signed.message().new_committee.clone(),
    )
    .map_err(|e| InvalidInputs(format!("invalid new committee in transition: {e}")))?;

    if new_committee.epoch() != proposed_epoch {
        return Err(InvalidInputs(format!(
            "new committee epoch ({}) does not match transition epoch ({proposed_epoch})",
            new_committee.epoch()
        )));
    }

    // Log before the in-memory swap so failed S3 writes don't advance the committee.
    let (request_sign, request) = signed.into_parts();
    enclave
        .log_committee_update(CommitteeUpdateLogMessage {
            from_epoch: current_epoch,
            new_committee: request.new_committee,
            request_sign,
        })
        .await?;
    state
        .replace_committee(new_committee, current_epoch)
        .expect("committee initialized at current_epoch under the update lock");

    info!(
        from_epoch = current_epoch,
        to_epoch = proposed_epoch,
        "Committee updated"
    );
    Ok(proposed_epoch)
}

pub async fn update_committee_chain(
    enclave: Arc<Enclave>,
    state: &mut EnclaveState,
    transitions: Vec<HashiSigned<CommitteeTransitionRequest>>,
) -> GuardianResult<u64> {
    let mut current_epoch = state.get_committee()?.epoch();
    for signed in transitions {
        current_epoch = update_committee(enclave.clone(), state, signed).await?;
    }
    Ok(current_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task_spawner::update_committee;
    use crate::task_spawner::update_committee_chain;
    use crate::test_utils::create_fully_initialized_enclave;
    use crate::test_utils::FullyInitializedArgs;
    use bitcoin::Network;
    use hashi_types::bitcoin::BitcoinKeypair;
    use hashi_types::bitcoin::HashiMasterG;
    use hashi_types::bitcoin::BTC_LIB;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::BlsSignatureAggregator;
    use hashi_types::committee::EncryptionPublicKey;
    use hashi_types::committee::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
    use hashi_types::committee::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;
    use hashi_types::guardian::GuardianError;
    use hashi_types::guardian::HashiCommittee;
    use hashi_types::guardian::HashiCommitteeMember;
    use hashi_types::guardian::LimiterConfig;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::WithdrawalID as SuiAddress;

    fn mock_signer_address() -> SuiAddress {
        SuiAddress::new([1u8; 32])
    }

    fn mock_bls_sk() -> Bls12381PrivateKey {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x000C_0FFE_EBAD_F00D);
        Bls12381PrivateKey::generate(&mut rng)
    }

    fn mock_encryption_pk() -> EncryptionPublicKey {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xDEAD_BEEF);
        let sk = hashi_types::committee::EncryptionPrivateKey::new(&mut rng);
        sk.public_key()
    }

    fn committee_at(epoch: u64) -> HashiCommittee {
        let pk = mock_bls_sk().public_key();
        let member = HashiCommitteeMember::new(mock_signer_address(), pk, mock_encryption_pk(), 10);
        HashiCommittee::new(
            vec![member],
            epoch,
            DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
            DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
        )
    }

    fn sign_transition_at(
        signing_epoch: u64,
        new_committee: HashiCommittee,
    ) -> HashiSigned<CommitteeTransitionRequest> {
        let outgoing = committee_at(signing_epoch);
        let transition = CommitteeTransitionRequest {
            new_committee: hashi_types::move_types::Committee::from(&new_committee),
        };
        let sk = mock_bls_sk();
        let hashi_id = hashi_types::guardian::test_utils::TEST_HASHI_OBJECT_ID;
        let sig = sk.sign(hashi_id, signing_epoch, mock_signer_address(), &transition);
        let mut agg = BlsSignatureAggregator::new(hashi_id, &outgoing, transition);
        agg.add_signature(sig).expect("member sig should verify");
        agg.finish().expect("threshold should be met")
    }

    async fn enclave_at_epoch(epoch: u64) -> Arc<Enclave> {
        let kp =
            BitcoinKeypair::from_seckey_slice(&BTC_LIB, &[1u8; 32]).expect("valid test secret key");
        let master_pubkey =
            HashiMasterG::with_even_y_from_x_be_bytes(&kp.x_only_public_key().0.serialize())
                .expect("valid x-only public key");
        create_fully_initialized_enclave(FullyInitializedArgs {
            network: Network::Regtest,
            committee: committee_at(epoch),
            master_pubkey,
            limiter_config: LimiterConfig {
                refill_rate: 0,
                max_bucket_capacity: 1_000,
            },
            limiter_state: LimiterState {
                num_tokens_available: 1_000,
                last_updated_at: 0,
                next_seq: 0,
            },
        })
        .await
    }

    #[tokio::test]
    async fn happy_path_advances_committee() {
        let enclave = enclave_at_epoch(5).await;
        let signed = sign_transition_at(5, committee_at(6));

        let new_epoch = update_committee(enclave.clone(), signed).await.unwrap();
        assert_eq!(new_epoch, 6);
        assert_eq!(
            enclave.state.lock().await.get_committee().unwrap().epoch(),
            6
        );
    }

    #[tokio::test]
    async fn invalid_encryption_key_does_not_block_handoffs() {
        let enclave = enclave_at_epoch(5).await;
        let outgoing = committee_at(5);
        let mut new_committee = hashi_types::move_types::Committee::from(&committee_at(6));
        new_committee.members[0].encryption_public_key = vec![0xff; 32];
        assert!(HashiCommittee::try_from(new_committee.clone()).is_err());
        let transition = CommitteeTransitionRequest { new_committee };
        let hashi_id = hashi_types::guardian::test_utils::TEST_HASHI_OBJECT_ID;
        let sig = mock_bls_sk().sign(hashi_id, 5, mock_signer_address(), &transition);
        let mut agg = BlsSignatureAggregator::new(hashi_id, &outgoing, transition);
        agg.add_signature(sig).unwrap();

        assert_eq!(
            update_committee(enclave.clone(), agg.finish().unwrap())
                .await
                .unwrap(),
            6
        );
        assert_eq!(
            update_committee(enclave, sign_transition_at(6, committee_at(7)))
                .await
                .unwrap(),
            7
        );
    }

    #[tokio::test]
    async fn already_applied_is_noop() {
        let enclave = enclave_at_epoch(5).await;
        let signed = sign_transition_at(5, committee_at(5));

        let new_epoch = update_committee(enclave.clone(), signed).await.unwrap();
        assert_eq!(new_epoch, 5);
        assert_eq!(
            enclave.state.lock().await.get_committee().unwrap().epoch(),
            5
        );
    }

    #[tokio::test]
    async fn forward_skip_advances_committee() {
        // Hashi committee epochs can skip values (sparse reconfig). A cert
        // signed by the current committee for a future non-adjacent epoch
        // is legitimate and must be accepted.
        let enclave = enclave_at_epoch(5).await;
        let signed = sign_transition_at(5, committee_at(7));

        let new_epoch = update_committee(enclave.clone(), signed).await.unwrap();
        assert_eq!(new_epoch, 7);
        assert_eq!(
            enclave.state.lock().await.get_committee().unwrap().epoch(),
            7
        );
    }

    #[tokio::test]
    async fn update_committee_chain_advances_multiple_handoffs() {
        let enclave = enclave_at_epoch(5).await;
        let transitions = vec![
            sign_transition_at(5, committee_at(7)),
            sign_transition_at(7, committee_at(9)),
        ];

        let new_epoch = update_committee_chain(enclave.clone(), transitions)
            .await
            .unwrap();

        assert_eq!(new_epoch, 9);
        assert_eq!(
            enclave.state.lock().await.get_committee().unwrap().epoch(),
            9
        );
    }

    #[tokio::test]
    async fn update_committee_chain_rejects_bad_middle_handoff() {
        let enclave = enclave_at_epoch(5).await;
        let transitions = vec![
            sign_transition_at(5, committee_at(7)),
            sign_transition_at(6, committee_at(9)),
        ];

        let err = update_committee_chain(enclave.clone(), transitions)
            .await
            .expect_err("bad middle handoff must error");

        assert!(
            matches!(err, GuardianError::Unauthenticated(_)),
            "expected Unauthenticated, got {err:?}"
        );
        assert_eq!(
            enclave.state.lock().await.get_committee().unwrap().epoch(),
            7
        );
    }

    #[tokio::test]
    async fn wrong_signing_epoch_rejected() {
        let enclave = enclave_at_epoch(5).await;
        let signed = sign_transition_at(4, committee_at(6));

        let err = update_committee(enclave.clone(), signed)
            .await
            .expect_err("mismatched signing epoch must error");
        assert!(
            matches!(err, GuardianError::Unauthenticated(_)),
            "expected Unauthenticated, got {err:?}"
        );
        assert_eq!(
            enclave.state.lock().await.get_committee().unwrap().epoch(),
            5
        );
    }

    #[tokio::test]
    async fn replace_committee_rejects_stale_expected_epoch() {
        let enclave = enclave_at_epoch(5).await;

        let err = enclave
            .state
            .lock()
            .await
            .replace_committee(committee_at(6).into(), 4)
            .expect_err("stale expected_current_epoch must error");
        assert!(
            matches!(err, GuardianError::InvalidInputs(_)),
            "expected InvalidInputs, got {err:?}"
        );
        assert_eq!(
            enclave.state.lock().await.get_committee().unwrap().epoch(),
            5
        );
    }
}
