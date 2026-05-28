// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::withdraw::verify_hashi_cert;
use crate::Enclave;
use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::CommitteeTransition;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianError::EnclaveUninitialized;
use hashi_types::guardian::GuardianError::InternalError;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::HashiSigned;
use std::sync::Arc;
use tracing::error;
use tracing::info;

/// Advance the committee to a future epoch with a cert from the outgoing
/// committee. Hashi epochs can skip values (reconfig is sparse), so the
/// proposed epoch is only required to be strictly greater than the
/// current one; sequentiality is not enforced.
/// Idempotent on already-applied or older transitions.
pub async fn update_committee(
    enclave: Arc<Enclave>,
    signed: HashiSigned<CommitteeTransition>,
) -> GuardianResult<u64> {
    // Serialize so a stalled call can't roll the committee backwards.
    let _update_guard = enclave.state.committee_update_lock.lock().await;

    if !enclave.is_fully_initialized() {
        return Err(EnclaveUninitialized);
    }

    let current = enclave.state.get_committee()?;
    let current_epoch = current.epoch();
    let proposed_epoch = signed.message().new_committee.epoch;

    if proposed_epoch <= current_epoch {
        info!(current_epoch, proposed_epoch, "update_committee: no-op");
        return Ok(current_epoch);
    }

    // Match hashi's leader, which bails its sig collection at
    // `certificate_threshold(from_committee.total_weight())`. Using a
    // higher (configured) threshold here would reject otherwise-valid
    // certs.
    let threshold = certificate_threshold(current.total_weight());
    if let Err(e) = verify_hashi_cert(current.clone(), threshold, &signed) {
        log_failure(&enclave, current_epoch, &signed, &e).await?;
        return Err(e);
    }

    let new_committee: HashiCommittee = signed
        .message()
        .new_committee
        .clone()
        .try_into()
        .map_err(|e| InvalidInputs(format!("invalid new committee in transition: {e}")))?;

    if new_committee.epoch() != proposed_epoch {
        let err = InvalidInputs(format!(
            "new committee epoch ({}) does not match transition epoch ({proposed_epoch})",
            new_committee.epoch()
        ));
        log_failure(&enclave, current_epoch, &signed, &err).await?;
        return Err(err);
    }

    // Log before the in-memory swap so failed S3 writes don't advance the committee.
    log_success(&enclave, current_epoch, &signed).await?;
    enclave
        .state
        .replace_committee(new_committee, current_epoch)
        .expect("committee initialized at current_epoch under the update lock");

    info!(
        from_epoch = current_epoch,
        to_epoch = proposed_epoch,
        "Committee updated"
    );
    Ok(proposed_epoch)
}

async fn log_success(
    enclave: &Enclave,
    from_epoch: u64,
    signed: &HashiSigned<CommitteeTransition>,
) -> GuardianResult<()> {
    let msg = CommitteeUpdateLogMessage::Success {
        from_epoch,
        new_committee: signed.message().new_committee.clone(),
        request_sign: signed.committee_signature().clone(),
    };
    enclave.log_committee_update(msg).await
}

async fn log_failure(
    enclave: &Enclave,
    from_epoch: u64,
    signed: &HashiSigned<CommitteeTransition>,
    err: &GuardianError,
) -> GuardianResult<()> {
    let msg = CommitteeUpdateLogMessage::Failure {
        from_epoch,
        new_committee: signed.message().new_committee.clone(),
        request_sign: signed.committee_signature().clone(),
        error: err.clone(),
    };
    if let Err(log_err) = enclave.log_committee_update(msg).await {
        error!(
            from_epoch,
            "failed to log committee update failure to S3: {log_err:?}"
        );
        return Err(InternalError(format!(
            "Failed to log committee update error {err} due to S3 logging error {log_err}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_fully_initialized_enclave;
    use crate::test_utils::FullyInitializedArgs;
    use bitcoin::Network;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::BlsSignatureAggregator;
    use hashi_types::committee::EncryptionPublicKey;
    use hashi_types::committee::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
    use hashi_types::committee::DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS;
    use hashi_types::committee::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;
    use hashi_types::guardian::test_utils::create_btc_keypair;
    use hashi_types::guardian::HashiCommitteeMember;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::LimiterConfig;
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
        EncryptionPublicKey::from_private_key(&sk)
    }

    fn committee_at(epoch: u64) -> HashiCommittee {
        let pk = mock_bls_sk().public_key();
        let member = HashiCommitteeMember::new(mock_signer_address(), pk, mock_encryption_pk(), 10);
        HashiCommittee::new(
            vec![member],
            epoch,
            DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS,
            DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
            DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
        )
    }

    fn sign_transition_at(
        signing_epoch: u64,
        new_committee: HashiCommittee,
    ) -> HashiSigned<CommitteeTransition> {
        let outgoing = committee_at(signing_epoch);
        let transition = CommitteeTransition {
            new_committee: hashi_types::move_types::Committee::from(&new_committee),
        };
        let sk = mock_bls_sk();
        let sig = sk.sign(signing_epoch, mock_signer_address(), &transition);
        let mut agg = BlsSignatureAggregator::new(&outgoing, transition);
        agg.add_signature(sig).expect("member sig should verify");
        agg.finish().expect("threshold should be met")
    }

    async fn enclave_at_epoch(epoch: u64) -> Arc<Enclave> {
        let kp = create_btc_keypair(&[1u8; 32]);
        create_fully_initialized_enclave(FullyInitializedArgs {
            network: Network::Regtest,
            committee: committee_at(epoch),
            master_pubkey: kp.x_only_public_key().0,
            withdrawal_config: LimiterConfig {
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
        assert_eq!(enclave.state.get_committee().unwrap().epoch(), 6);
    }

    #[tokio::test]
    async fn already_applied_is_noop() {
        let enclave = enclave_at_epoch(5).await;
        let signed = sign_transition_at(5, committee_at(5));

        let new_epoch = update_committee(enclave.clone(), signed).await.unwrap();
        assert_eq!(new_epoch, 5);
        assert_eq!(enclave.state.get_committee().unwrap().epoch(), 5);
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
        assert_eq!(enclave.state.get_committee().unwrap().epoch(), 7);
    }

    #[tokio::test]
    async fn wrong_signing_epoch_rejected() {
        let enclave = enclave_at_epoch(5).await;
        let signed = sign_transition_at(4, committee_at(6));

        let err = update_committee(enclave.clone(), signed)
            .await
            .expect_err("mismatched signing epoch must error");
        assert!(
            matches!(err, GuardianError::InvalidInputs(_)),
            "expected InvalidInputs, got {err:?}"
        );
        assert_eq!(enclave.state.get_committee().unwrap().epoch(), 5);
    }

    #[tokio::test]
    async fn replace_committee_rejects_stale_expected_epoch() {
        let enclave = enclave_at_epoch(5).await;

        let err = enclave
            .state
            .replace_committee(committee_at(6), 4)
            .expect_err("stale expected_current_epoch must error");
        assert!(
            matches!(err, GuardianError::InvalidInputs(_)),
            "expected InvalidInputs, got {err:?}"
        );
        assert_eq!(enclave.state.get_committee().unwrap().epoch(), 5);
    }
}
