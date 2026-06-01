// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::LEADER_TASK_TIMEOUT;
use super::LeaderService;
use super::WithdrawalBroadcastResult;
use super::parse_member_signature;
use crate::Hashi;
use crate::btc_monitor::monitor::TxStatus;
use crate::leader::garbage_collection::PendingUtxoCleanup;
use crate::onchain::types::UtxoId;
use crate::onchain::types::WithdrawalTransaction;
use crate::sui_tx_executor::SuiTxExecutor;
use crate::withdrawals::WithdrawalTxSigning;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::serde_helpers::ToFromByteArray;
use futures::future::join_all;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use hashi_types::proto::SignWithdrawalTxSigningRequest;
use std::sync::Arc;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

impl LeaderService {
    // ========================================================================
    // Step 3: MPC sign withdrawal transactions and store signatures on-chain
    // ========================================================================

    pub(super) fn process_unsigned_withdrawal_txns(&mut self) {
        debug!("Entering process_unsigned_withdrawal_txns");
        if self.is_reconfiguring() {
            debug!("Reconfig in progress, skipping withdrawal tx signing");
            return;
        }

        let mut withdrawal_txns = self.inner.onchain_state().withdrawal_txns();
        withdrawal_txns.retain(|p| p.signatures.is_none());
        withdrawal_txns.sort_by_key(|p| p.timestamp_ms);

        let pending_ids: Vec<Address> = withdrawal_txns.iter().map(|p| p.id).collect();
        self.inflight_withdrawal_signings
            .retain(|id| pending_ids.contains(id));

        // Cap to 1 when the limiter is in play: the watcher advances
        // `next_seq` per signed event, and the guardian rejects
        // out-of-order `timestamp_secs` — both serialise on this path.
        let max_concurrent = if self.inner.guardian_client().is_some() {
            1
        } else {
            self.inner.config.max_concurrent_leader_job_tasks()
        };
        for txn in withdrawal_txns {
            if self.withdrawal_signing_tasks.len() >= max_concurrent {
                break;
            }
            if self.inflight_withdrawal_signings.contains(&txn.id) {
                continue;
            }

            let txn_id = txn.id;
            let inner = self.inner.clone();

            self.inflight_withdrawal_signings.insert(txn_id);
            self.withdrawal_signing_tasks.spawn(async move {
                let result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::process_unsigned_withdrawal_txn(inner, txn),
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!(
                        "withdrawal signing for {txn_id} timed out after {LEADER_TASK_TIMEOUT:?}"
                    )),
                };

                (txn_id, result)
            });
        }
    }

    pub(super) fn handle_completed_withdrawal_signing_task(
        &mut self,
        result: Result<(Address, anyhow::Result<()>), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((withdrawal_id, inner)) => {
                self.inflight_withdrawal_signings.remove(&withdrawal_id);
                Ok(inner)
            }
            Err(e) => Err(e),
        };
        Self::log_task_result("withdrawal_signing", mapped);
    }

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id))]
    async fn process_unsigned_withdrawal_txn(
        inner: Arc<Hashi>,
        txn: WithdrawalTransaction,
    ) -> anyhow::Result<()> {
        // If the withdrawal transaction is from a previous epoch, reassign its presig
        // indices from the new epoch's counter before signing.
        // TODO: Batch multiple stale-epoch withdrawals into a single PTB.
        let current_epoch = inner.onchain_state().epoch();
        if txn.epoch != current_epoch {
            info!(
                "Withdrawal transaction from epoch {} (current {}), reassigning presig indices",
                txn.epoch, current_epoch,
            );
            let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
            executor
                .execute_allocate_presigs_for_withdrawal_txn(txn.id)
                .await?;
            info!("Presig indices reassigned, will sign on next checkpoint");
            // Return and let the next checkpoint iteration pick up the updated state.
            return Ok(());
        }
        info!("MPC signing withdrawal transaction");

        // Fresh per-attempt timestamp from the leader's current checkpoint;
        // using `txn.timestamp_ms` lets stuck batches age past the per-node
        // `GUARDIAN_TIMESTAMP_TOLERANCE_SECS` check on retries.
        let timestamp_secs = inner.onchain_state().latest_checkpoint_timestamp_ms() / 1000;

        // Fail fast before MPC if our own limiter would reject.
        let expected_limiter_seq = if let Some(limiter) = inner.local_limiter() {
            let amount_sats = crate::withdrawals::withdrawal_limiter_consumption_amount(&txn);
            let next_seq = limiter.next_seq();
            let result = limiter.validate_consume(next_seq, timestamp_secs, amount_sats);
            inner.metrics.record_limiter_validate(
                &result,
                crate::metrics::GUARDIAN_LIMITER_CALLSITE_LEADER_PRE_MPC,
            );
            if let Err(e) = result {
                warn!(
                    withdrawal_txn_id = %txn.id,
                    "Leader local limiter rejected withdrawal; will retry on next checkpoint: {e}"
                );
                return Ok(());
            }
            // Pace guardian finalize on the local limiter to avoid reusing a consumed seq.
            if inner.guardian_client().is_some()
                && inner.guardian_should_defer_finalize(next_seq, txn.id)
            {
                debug!(
                    withdrawal_txn_id = %txn.id,
                    next_seq,
                    "Deferring guardian finalize until local limiter catches up to guardian seq"
                );
                inner.metrics.guardian_finalize_deferred_total.inc();
                return Ok(());
            }
            Some(next_seq)
        } else {
            None
        };

        let members = inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        // 1. Request signed withdrawal tx witnesses from committee members.
        // MPC signing requires all threshold members to participate simultaneously
        // via P2P, so we must fan out requests in parallel.
        let signatures_by_input =
            Self::collect_withdrawal_tx_signatures(&inner, &txn.id, expected_limiter_seq, &members)
                .await
                .ok_or_else(|| {
                    anyhow::anyhow!("Failed to collect MPC signatures for {:?}", txn.id)
                })?;

        // 2. Extract raw signature bytes for on-chain storage
        let witness_signatures: Vec<Vec<u8>> = signatures_by_input
            .iter()
            .map(|s| s.to_byte_array().to_vec())
            .collect();

        // 3. Post-MPC: forward to guardian for the enclave signature. Reuses
        // the `timestamp_secs` from the pre-MPC validate so the BLS-signed
        // certificate covers a consistent `(timestamp, seq, amount)` triple.
        // The per-input enclave signatures are stored on-chain alongside the
        // MPC sigs to satisfy the 2-of-2 deposit witness.
        let guardian_signatures: Vec<Vec<u8>> =
            match (inner.guardian_client(), expected_limiter_seq) {
                (Some(guardian), Some(seq)) => {
                    let sigs = Self::finalize_withdrawal_through_guardian(
                        &inner,
                        &txn,
                        &members,
                        guardian,
                        timestamp_secs,
                        seq,
                    )
                    .await?;
                    inner.record_guardian_finalized(seq, txn.id);
                    sigs
                }
                _ => {
                    anyhow::bail!(
                        "Guardian endpoint or seq missing — refusing to sign \
                         a 2-of-2 withdrawal without the guardian half of the \
                         witness"
                    );
                }
            };

        // 4. Build the WithdrawalTxSigning (binds BOTH sig arrays) and get
        // the BLS certificate via fan-out.
        let signed_message = WithdrawalTxSigning {
            withdrawal_id: txn.id,
            request_ids: txn.request_ids.clone(),
            signatures: witness_signatures.clone(),
            guardian_signatures: guardian_signatures.clone(),
        };

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let required_weight = certificate_threshold(committee.total_weight());
        let proto_request = signed_message.to_proto();

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_tx_signing_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&committee, signed_message.clone());
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(withdrawal_txn_id = %txn.id, "Failed to add withdrawal sign message signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient signatures for sign_withdrawal: weight {weight} < {required_weight}"
            );
        }

        let signed = aggregator.finish()?;

        // 5. Submit sign_withdrawal to Sui (writes signatures on-chain).
        // Broadcast + confirm happens via process_signed_withdrawal_txns on the next tick.
        let included_checkpoint_seq = Self::submit_sign_withdrawal(
            &inner,
            &txn.id,
            &txn.request_ids.clone(),
            &witness_signatures,
            &guardian_signatures,
            signed.committee_signature(),
        )
        .await
        .inspect(|_| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["sign_withdrawal", "success"])
                .inc();
        })
        .inspect_err(|_| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["sign_withdrawal", "failure"])
                .inc();
        })?;

        // Wait for our watcher to catch up to the checkpoint that included
        // the sign_withdrawal txn before returning, so the next tick
        // doesn't respawn with stale state.
        const VISIBILITY_TIMEOUT: Duration = Duration::from_secs(30);
        if tokio::time::timeout(
            VISIBILITY_TIMEOUT,
            inner
                .onchain_state()
                .wait_until_checkpoint(included_checkpoint_seq),
        )
        .await
        .is_err()
        {
            warn!(
                withdrawal_txn_id = %txn.id,
                included_checkpoint_seq,
                "Timeout waiting for watcher to reach the included checkpoint; \
                 a duplicate sign attempt may follow"
            );
        }

        Ok(())
    }

    async fn collect_withdrawal_tx_signatures(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: &Address,
        expected_limiter_seq: Option<u64>,
        members: &[CommitteeMember],
    ) -> Option<Vec<SchnorrSignature>> {
        let futures: Vec<_> = members
            .iter()
            .map(|member| {
                Self::request_withdrawal_tx_signature(
                    inner,
                    withdrawal_txn_id,
                    expected_limiter_seq,
                    member,
                )
            })
            .collect();
        let results = join_all(futures).await;

        let mut results = results.into_iter();
        loop {
            match results.next() {
                Some(Ok(signatures)) => return Some(signatures),
                Some(Err(e)) => {
                    warn!("Could not get signatures from a node: {e}");
                }
                None => {
                    error!(
                        "Could not get mpc signatures for {:?}; stopping processing",
                        withdrawal_txn_id
                    );
                    return None;
                }
            }
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_tx_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: &Address,
        expected_limiter_seq: Option<u64>,
        member: &CommitteeMember,
    ) -> anyhow::Result<Vec<SchnorrSignature>> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal tx signature");

        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                )
            })?;

        let proto_request = SignWithdrawalTransactionRequest {
            withdrawal_txn_id: withdrawal_txn_id.as_bytes().to_vec().into(),
            expected_limiter_seq,
        };

        let response = rpc_client
            .sign_withdrawal_transaction(proto_request)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to get withdrawal tx signature from {validator_address}: {e}"
                )
            })?;

        trace!(
            "Retrieved withdrawal tx signature from {}",
            validator_address
        );

        response
            .into_inner()
            .signatures_by_input
            .iter()
            .map(|sig_bytes| {
                let bytes: [u8; 64] = sig_bytes.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!("Invalid Schnorr signature length from {validator_address}")
                })?;
                SchnorrSignature::from_byte_array(&bytes).map_err(|e| {
                    anyhow::anyhow!("Invalid Schnorr signature from {validator_address}: {e}")
                })
            })
            .collect()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_tx_signing_signature(
        inner: &Arc<Hashi>,
        proto_request: SignWithdrawalTxSigningRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal tx signing signature");

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
            .sign_withdrawal_tx_signing(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal tx signing signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved withdrawal tx signing signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal tx signing response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    async fn submit_sign_withdrawal(
        inner: &Arc<Hashi>,
        withdrawal_id: &Address,
        request_ids: &[Address],
        signatures: &[Vec<u8>],
        guardian_signatures: &[Vec<u8>],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<u64> {
        info!("Submitting sign_withdrawal for {:?}", withdrawal_id);

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_sign_withdrawal(
                withdrawal_id,
                request_ids,
                signatures,
                guardian_signatures,
                cert,
            )
            .await
    }

    // ========================================================================
    // Step 4-5: Broadcast signed tx and confirm on-chain
    // ========================================================================

    pub(super) fn process_signed_withdrawal_txns(&mut self) {
        debug!("Entering process_signed_withdrawal_txns");
        let mut withdrawal_txns = self.inner.onchain_state().withdrawal_txns();
        withdrawal_txns.retain(|p| p.signatures.is_some());
        withdrawal_txns.sort_by_key(|p| p.timestamp_ms);

        let pending_ids: Vec<Address> = withdrawal_txns.iter().map(|p| p.id).collect();
        self.inflight_withdrawal_broadcasts
            .retain(|id| pending_ids.contains(id));

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        for txn in withdrawal_txns {
            if self.withdrawal_broadcast_tasks.len() >= max_concurrent {
                break;
            }
            if self.inflight_withdrawal_broadcasts.contains(&txn.id) {
                continue;
            }

            let txn_id = txn.id;
            let inner = self.inner.clone();

            self.inflight_withdrawal_broadcasts.insert(txn_id);
            self.withdrawal_broadcast_tasks.spawn(async move {
                let result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::handle_signed_withdrawal(inner, txn),
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!(
                        "withdrawal broadcast for {txn_id} timed out after {LEADER_TASK_TIMEOUT:?}"
                    )),
                };

                (txn_id, result)
            });
        }
    }

    pub(super) fn handle_completed_withdrawal_broadcast_task(
        &mut self,
        result: Result<(Address, WithdrawalBroadcastResult), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((withdrawal_id, inner)) => {
                self.inflight_withdrawal_broadcasts.remove(&withdrawal_id);
                if let Ok(Some(utxo_ids)) = &inner {
                    self.pending_utxo_cleanups.push_back(PendingUtxoCleanup {
                        utxo_ids: utxo_ids.clone(),
                    });
                }
                Ok(inner.map(|_| ()))
            }
            Err(e) => Err(e),
        };
        Self::log_task_result("withdrawal_broadcast", mapped);
    }

    /// Check BTC tx status, broadcast/re-broadcast if needed, confirm when
    /// enough BTC confirmations are reached.
    ///
    /// Returns `Some(utxo_ids)` when the withdrawal was confirmed on Sui,
    /// signalling that UTXO cleanup should be scheduled.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, bitcoin_txid))]
    async fn handle_signed_withdrawal(
        inner: Arc<Hashi>,
        txn: WithdrawalTransaction,
    ) -> WithdrawalBroadcastResult {
        let confirmation_threshold = inner.onchain_state().bitcoin_confirmation_threshold();
        let txid: bitcoin::Txid = txn.txid.into();
        tracing::Span::current().record("bitcoin_txid", tracing::field::display(&txid));

        match inner.btc_monitor().get_transaction_status(txid).await {
            Ok(TxStatus::Confirmed { confirmations })
                if confirmations >= confirmation_threshold =>
            {
                info!(
                    confirmations,
                    "Withdrawal tx confirmed, proceeding to on-chain confirmation"
                );
                let utxo_ids: Vec<UtxoId> = txn.inputs.iter().map(|u| u.id).collect();
                Self::confirm_withdrawal_on_sui(&inner, &txn).await?;
                return Ok(Some(utxo_ids));
            }
            Ok(TxStatus::Confirmed { confirmations }) => {
                debug!(
                    confirmations,
                    confirmation_threshold, "Withdrawal tx waiting for more confirmations"
                );
            }
            Ok(TxStatus::InMempool) => {
                debug!("Withdrawal tx in mempool, waiting for confirmations");
            }
            Ok(TxStatus::NotFound) => {
                Self::rebuild_and_broadcast_withdrawal_btc_tx(&inner, &txn, txid).await;
            }
            Err(e) => {
                anyhow::bail!(
                    "failed to query transaction status for withdrawal transaction {}: {e}",
                    txn.id
                );
            }
        }
        Ok(None)
    }

    /// Rebuild a fully signed Bitcoin transaction from on-chain WithdrawalTransaction
    /// data (stored witness signatures) and broadcast it to the Bitcoin network.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, bitcoin_txid = %txid))]
    async fn rebuild_and_broadcast_withdrawal_btc_tx(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        txid: bitcoin::Txid,
    ) {
        warn!("Withdrawal tx not found, re-broadcasting from on-chain signatures");

        let tx = match Self::rebuild_signed_tx_from_onchain(inner, txn) {
            Ok(tx) => tx,
            Err(e) => {
                error!("Failed to rebuild signed withdrawal tx: {e}");
                return;
            }
        };

        match inner.btc_monitor().broadcast_transaction(tx).await {
            Ok(()) => {
                info!("Re-broadcast withdrawal tx");
            }
            Err(e) => {
                error!("Failed to re-broadcast withdrawal tx: {e}");
            }
        }
    }

    /// Rebuild a fully signed Bitcoin transaction from on-chain
    /// `WithdrawalTransaction` data and broadcast-ready 2-of-2 witness.
    ///
    /// Witness layout per input (BIP342 multi_a, verified against
    /// rust-miniscript's `Terminal::MultiA` satisfier):
    ///
    /// ```text
    /// [hashi_sig, guardian_sig, leaf_script, control_block]
    /// ```
    fn rebuild_signed_tx_from_onchain(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
    ) -> anyhow::Result<bitcoin::Transaction> {
        let raw_sigs = txn
            .signatures
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No MPC signatures on withdrawal transaction"))?;
        let raw_guardian_sigs = txn
            .guardian_signatures
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No guardian signatures on withdrawal transaction"))?;

        let mut tx = inner.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())?;

        anyhow::ensure!(
            raw_sigs.len() == tx.input.len(),
            "MPC signature count mismatch: tx has {} inputs, on-chain has {} signatures",
            tx.input.len(),
            raw_sigs.len()
        );
        anyhow::ensure!(
            raw_guardian_sigs.len() == tx.input.len(),
            "Guardian signature count mismatch: tx has {} inputs, on-chain has {} signatures",
            tx.input.len(),
            raw_guardian_sigs.len()
        );
        anyhow::ensure!(
            tx.input.len() == txn.inputs.len(),
            "Input count mismatch: tx has {} inputs, txn has {}",
            tx.input.len(),
            txn.inputs.len()
        );

        for (((input, txn_input), hashi_sig_bytes), guardian_sig_bytes) in tx
            .input
            .iter_mut()
            .zip(txn.inputs.iter())
            .zip(raw_sigs)
            .zip(raw_guardian_sigs)
        {
            let (script, control_block, _) =
                inner.deposit_spend_artifacts(txn_input.derivation_path.as_ref())?;
            let mut witness = bitcoin::Witness::new();
            // multi_a satisfier order: hashi_sig (bottom) then guardian_sig (top).
            witness.push(hashi_sig_bytes);
            witness.push(guardian_sig_bytes);
            witness.push(script.to_bytes());
            witness.push(control_block.serialize());
            input.witness = witness;
        }

        Ok(tx)
    }

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id))]
    async fn confirm_withdrawal_on_sui(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
    ) -> anyhow::Result<()> {
        let members = inner
            .onchain_state()
            .current_committee_members()
            .ok_or_else(|| anyhow::anyhow!("No current committee members for confirmation"))?;

        let confirmation_cert =
            Self::collect_withdrawal_confirmation_signature(inner, txn.id, &members).await?;

        Self::submit_confirm_withdrawal(inner, &txn.id, &confirmation_cert)
            .await
            .inspect(|()| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_withdrawal", "success"])
                    .inc();
                inner.metrics.withdrawals_finalized_total.inc();
            })
            .inspect_err(|_| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_withdrawal", "failure"])
                    .inc();
            })?;

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(withdrawal_txn_id = %withdrawal_txn_id))]
    async fn collect_withdrawal_confirmation_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: Address,
        members: &[CommitteeMember],
    ) -> anyhow::Result<CommitteeSignature> {
        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let confirmation = crate::withdrawals::WithdrawalConfirmation {
            withdrawal_id: withdrawal_txn_id,
        };

        let required_weight = certificate_threshold(committee.total_weight());

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_confirmation_signature(&inner, withdrawal_txn_id, &member)
                    .await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&committee, confirmation);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!("Failed to add withdrawal confirmation signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient withdrawal confirmation signatures for {:?}: weight {weight} < {required_weight}",
                withdrawal_txn_id
            );
        }

        Ok(aggregator.finish()?.into_parts().0)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_confirmation_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: Address,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal confirmation signature");

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
            .sign_withdrawal_confirmation(SignWithdrawalConfirmationRequest {
                withdrawal_txn_id: withdrawal_txn_id.as_bytes().to_vec().into(),
            })
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal confirmation signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved withdrawal confirmation signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal confirmation response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    async fn submit_confirm_withdrawal(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: &Address,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Confirming withdrawal {:?}", withdrawal_txn_id);

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_confirm_withdrawal(withdrawal_txn_id, cert)
            .await?;

        info!("Successfully confirmed withdrawal {:?}", withdrawal_txn_id);

        Ok(())
    }
}

impl WithdrawalTxSigning {
    fn to_proto(&self) -> SignWithdrawalTxSigningRequest {
        SignWithdrawalTxSigningRequest {
            withdrawal_id: self.withdrawal_id.as_bytes().to_vec().into(),
            request_ids: self
                .request_ids
                .iter()
                .map(|id| id.as_bytes().to_vec().into())
                .collect(),
            signatures: self
                .signatures
                .iter()
                .map(|sig| sig.clone().into())
                .collect(),
            guardian_signatures: self
                .guardian_signatures
                .iter()
                .map(|sig| sig.clone().into())
                .collect(),
        }
    }
}
