// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::LeaderService;
use super::parse_member_signature;
use crate::Hashi;
use crate::onchain::types::WithdrawalTransaction;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::SignedMessage;
use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::CommitteeTransitionRequest;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::proto_conversions::signed_committee_transition_to_pb;
use hashi_types::guardian::proto_conversions::signed_standard_withdrawal_request_to_pb;
use hashi_types::proto::SignCommitteeTransitionRequest;
use hashi_types::proto::SignGuardianWithdrawalRequestRequest;
use hashi_types::proto::UpdateCommitteeChainRequest;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

impl LeaderService {
    pub(super) fn check_reconcile_guardian_committee(&mut self) {
        if self.inner.guardian_client().is_none() {
            return;
        }
        // Don't overwrite an existing handle — finished or not. The select!
        // arm clears the slot and logs the result. Letting it run first
        // avoids dropping a completed task's error on the floor.
        if self.guardian_committee_reconcile_task.is_some() {
            return;
        }
        // Only kick a reconcile when the hashi epoch advances (or on the
        // first leader tick). A no-op reconcile still costs a GetGuardianInfo
        // RPC, so don't run it every checkpoint.
        let hashi_epoch = self.inner.onchain_state().epoch();
        if self.last_guardian_reconcile_epoch == Some(hashi_epoch) {
            return;
        }
        self.last_guardian_reconcile_epoch = Some(hashi_epoch);
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move { Self::reconcile_guardian_committee(&inner).await });
        self.guardian_committee_reconcile_task = Some(AbortOnDropHandle::new(handle));
    }

    // ========================================================================
    // Guardian: post-MPC enclave-signature RPC
    // ========================================================================

    /// Returns the per-input guardian Schnorr signatures (64 bytes each)
    /// for inclusion in the on-chain `sign_withdrawal` PTB.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, seq))]
    pub(super) async fn finalize_withdrawal_through_guardian(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        members: &[CommitteeMember],
        guardian: &crate::grpc::guardian_client::GuardianClient,
        timestamp_secs: u64,
        seq: u64,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let signed_request =
            Self::collect_guardian_withdrawal_signatures(inner, txn, members, timestamp_secs, seq)
                .await?;
        let proto_request = signed_standard_withdrawal_request_to_pb(&signed_request);

        let rpc_start = std::time::Instant::now();
        let rpc_result = guardian.standard_withdrawal(proto_request).await;
        let rpc_elapsed = rpc_start.elapsed().as_secs_f64();

        let response_pb = rpc_result.map_err(|status| {
            let (rpc_outcome, retry_label) = if status.message().contains("seq mismatch") {
                (
                    crate::metrics::GUARDIAN_RPC_OUTCOME_SEQ_MISMATCH,
                    "GuardianSeqMismatch",
                )
            } else if status.message().contains("Rate limit exceeded") {
                warn!("Guardian rate-limited withdrawal, will retry later");
                (
                    crate::metrics::GUARDIAN_RPC_OUTCOME_RATE_LIMITED,
                    "GuardianRateLimited",
                )
            } else {
                error!("Guardian call failed: {}", status.message());
                (
                    crate::metrics::GUARDIAN_RPC_OUTCOME_UNAVAILABLE,
                    "GuardianUnavailable",
                )
            };
            Self::record_guardian_rpc_outcome(inner, rpc_outcome, rpc_elapsed);
            inner
                .metrics
                .leader_retries_total
                .with_label_values(&["withdrawal_signing", retry_label])
                .inc();
            anyhow::anyhow!("Guardian rejected withdrawal: {}", status.message())
        })?;

        let pubkey = inner
            .guardian_signing_pubkey()
            .expect("guardian signing pubkey set during bootstrap");
        let signed_response: GuardianSigned<StandardWithdrawalResponse> = response_pb
            .try_into()
            .inspect_err(|_| {
                Self::record_guardian_rpc_outcome(
                    inner,
                    crate::metrics::GUARDIAN_RPC_OUTCOME_PARSE_ERROR,
                    rpc_elapsed,
                );
            })
            .map_err(|e| anyhow::anyhow!("Failed to parse guardian withdrawal response: {e}"))?;
        let response = signed_response
            .verify(pubkey)
            .inspect_err(|_| {
                Self::record_guardian_rpc_outcome(
                    inner,
                    crate::metrics::GUARDIAN_RPC_OUTCOME_SIGNATURE_ERROR,
                    rpc_elapsed,
                );
            })
            .map_err(|e| {
                anyhow::anyhow!("Guardian response signature verification failed: {e:?}")
            })?;

        anyhow::ensure!(
            response.enclave_signatures.len() == txn.inputs.len(),
            "Guardian returned {} enclave_signatures but tx has {} inputs",
            response.enclave_signatures.len(),
            txn.inputs.len(),
        );
        let guardian_signatures: Vec<Vec<u8>> = response
            .enclave_signatures
            .iter()
            .enumerate()
            .map(|(i, sig)| {
                let bytes = sig.to_vec();
                anyhow::ensure!(
                    bytes.len() == 64,
                    "Guardian enclave_signatures[{i}] is {} bytes, expected 64",
                    bytes.len(),
                );
                Ok(bytes)
            })
            .collect::<anyhow::Result<_>>()?;

        Self::record_guardian_rpc_outcome(
            inner,
            crate::metrics::GUARDIAN_RPC_OUTCOME_OK,
            rpc_elapsed,
        );
        info!(seq, "Guardian approved withdrawal");
        Ok(guardian_signatures)
    }

    fn record_guardian_rpc_outcome(inner: &Arc<Hashi>, outcome: &str, elapsed_secs: f64) {
        inner.metrics.record_guardian_rpc(
            crate::metrics::GUARDIAN_RPC_METHOD_STANDARD_WITHDRAWAL,
            outcome,
            elapsed_secs,
        );
    }

    async fn collect_guardian_withdrawal_signatures(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        members: &[CommitteeMember],
        timestamp_secs: u64,
        seq: u64,
    ) -> anyhow::Result<SignedMessage<StandardWithdrawalRequest>> {
        let guardian_request =
            crate::withdrawals::build_guardian_withdrawal_request(inner, txn, timestamp_secs, seq)?;

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let required_weight = certificate_threshold(committee.total_weight());

        let proto_request = SignGuardianWithdrawalRequestRequest {
            withdrawal_txn_id: txn.id.as_bytes().to_vec().into(),
            timestamp_secs,
            seq,
        };

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_guardian_withdrawal_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&committee, guardian_request);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(
                    withdrawal_txn_id = %txn.id,
                    "Failed to add guardian withdrawal signature: {e}"
                );
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient guardian withdrawal signatures: weight {weight} < {required_weight}"
            );
        }

        Ok(aggregator.finish()?)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_guardian_withdrawal_signature(
        inner: &Arc<Hashi>,
        proto_request: SignGuardianWithdrawalRequestRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting guardian withdrawal signature");

        let response = Self::call_peer_with_retry(
            inner,
            validator_address,
            "guardian withdrawal signature",
            move |mut client| {
                let request = proto_request.clone();
                async move { client.sign_guardian_withdrawal_request(request).await }
            },
        )
        .await?;

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse guardian withdrawal member signature from {validator_address}: {e}"
                );
            })
            .ok()
    }

    // ========================================================================
    // Guardian: committee handoff (post-rotation)
    // ========================================================================

    /// Replay stored guardian handoffs until the guardian matches the chain.
    async fn reconcile_guardian_committee(inner: &Arc<Hashi>) -> anyhow::Result<()> {
        let Some(guardian) = inner.guardian_client() else {
            return Ok(());
        };

        // Seed `guardian_epoch` once from `GetGuardianInfo`, then build the
        // full stored handoff chain and submit it to the guardian in one RPC.
        let info = inner.fetch_verified_guardian_info().await?;
        let Some(mut guardian_epoch) = info.current_committee_epoch else {
            // ProvisionerInit hasn't run yet; the bootstrap CLI seeds it.
            return Ok(());
        };
        inner
            .metrics
            .guardian_current_committee_epoch
            .set(guardian_epoch as i64);

        let hashi_epoch = inner.onchain_state().epoch();
        let initial_guardian_epoch = guardian_epoch;
        let mut transitions = Vec::new();
        let mut final_to_epoch = guardian_epoch;
        loop {
            if guardian_epoch > hashi_epoch {
                // The guardian only advances via certs that hashi signs, so
                // it should never run ahead of the hashi chain. If we see
                // this, something is wrong (e.g., a stale onchain read).
                warn!(
                    guardian_epoch,
                    hashi_epoch, "guardian is ahead of hashi — unexpected"
                );
                return Ok(());
            }
            if guardian_epoch == hashi_epoch {
                break;
            }

            let from_epoch = guardian_epoch;
            info!(
                from_epoch,
                hashi_epoch, "Queueing stored guardian committee handoff"
            );
            let signed = inner
                .onchain_state()
                .guardian_handoff(from_epoch)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing on-chain guardian handoff for epoch {from_epoch}; cannot advance guardian"
                    )
                })?;
            let to_epoch = signed.message().new_committee.epoch;
            if to_epoch <= from_epoch {
                anyhow::bail!("stored guardian handoff did not advance: {from_epoch}->{to_epoch}");
            }
            transitions.push(signed_committee_transition_to_pb(&signed));
            final_to_epoch = to_epoch;
            guardian_epoch = to_epoch;
        }

        if transitions.is_empty() {
            return Ok(());
        }

        let resp = guardian
            .update_committee_chain(UpdateCommitteeChainRequest { transitions })
            .await
            .map_err(|status| {
                anyhow::anyhow!("UpdateCommitteeChain failed: {}", status.message())
            })?;
        let new_guardian_epoch = resp.current_committee_epoch.ok_or_else(|| {
            anyhow::anyhow!("UpdateCommitteeChain response missing current_committee_epoch")
        })?;
        inner
            .metrics
            .guardian_current_committee_epoch
            .set(new_guardian_epoch as i64);
        info!(
            from_epoch = initial_guardian_epoch,
            to_epoch = new_guardian_epoch,
            "Advanced guardian committee"
        );

        if new_guardian_epoch < final_to_epoch {
            anyhow::bail!(
                "guardian failed to advance to {final_to_epoch}: ended at {new_guardian_epoch}"
            );
        }

        Ok(())
    }

    pub(crate) async fn collect_committee_transition_signatures(
        inner: &Arc<Hashi>,
        from_epoch: u64,
    ) -> anyhow::Result<SignedMessage<CommitteeTransitionRequest>> {
        let (to_epoch, from_committee, new_committee) = {
            let onchain = inner.onchain_state();
            let state = onchain.state();
            let committees_map = state.hashi().committees.committees();
            let from = committees_map
                .get(&from_epoch)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no on-chain committee for epoch {from_epoch}"))?;
            // Hashi committee epochs are sparse: each reconfig only adds a
            // new entry when Sui's epoch advances past hashi's AND the MPC
            // reconfig completes, so the next entry is generally not
            // `from_epoch + 1`. Both leader and followers derive the same
            // `to_epoch` from on-chain state, so they sign the same transition.
            let (to_epoch, to) = committees_map
                .range((from_epoch + 1)..)
                .next()
                .map(|(&k, c)| (k, c.clone()))
                .ok_or_else(|| anyhow::anyhow!("no on-chain committee epoch after {from_epoch}"))?;
            (to_epoch, from, to)
        };

        let transition = CommitteeTransitionRequest {
            new_committee: hashi_types::move_types::Committee::from(&new_committee),
        };
        let required_weight = certificate_threshold(from_committee.total_weight());

        let proto_request = SignCommitteeTransitionRequest { from_epoch };
        let mut sig_tasks = JoinSet::new();
        for member in from_committee.members() {
            let inner = inner.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_committee_transition_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&from_committee, transition);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(
                    from_epoch,
                    "Failed to add committee transition signature: {e}"
                );
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }
        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "insufficient committee transition signatures for {from_epoch}->{to_epoch}: weight {weight} < {required_weight}"
            );
        }
        Ok(aggregator.finish()?)
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(validator = %member.validator_address())
    )]
    async fn request_committee_transition_signature(
        inner: &Arc<Hashi>,
        proto_request: SignCommitteeTransitionRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;
        let response = rpc_client
            .sign_committee_transition(proto_request)
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get committee transition signature from {validator_address}: {e}"
                );
            })
            .ok()?;
        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse committee transition signature from {validator_address}: {e}"
                );
            })
            .ok()
    }
}
