// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::TxOut;
use bitcoin::Weight;
use bitcoin::taproot::TapLeafHash;
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::hash::Blake2b256;
use fastcrypto::hash::HashFunction;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::S;
use hashi_types::bitcoin as hashi_bitcoin;
use hashi_types::bitcoin_txid::BitcoinTxid;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::time::Duration;
use sui_sdk_types::Address;

use crate::Hashi;
use crate::btc_monitor::monitor::TxStatus;
use crate::leader::RetryPolicy;
use crate::mpc::rpc::RpcP2PChannel;
use crate::onchain::types::OutputUtxo;
use crate::onchain::types::Utxo;
use crate::onchain::types::UtxoId;
use crate::onchain::types::UtxoRecord;
use crate::onchain::types::WithdrawalRequest;
use crate::onchain::types::WithdrawalTransaction;
use crate::utxo_pool;
use crate::utxo_pool::AncestorTx;
use crate::utxo_pool::CoinSelectionParams;
use crate::utxo_pool::SpendPath;
use crate::utxo_pool::UtxoCandidate;
use crate::utxo_pool::UtxoStatus;
use thiserror::Error;

const WITHDRAWAL_SIGNING_TIMEOUT: Duration = Duration::from_secs(5);

/// Fee rate tolerance multiplier for validation.
const FEE_RATE_TOLERANCE_MULTIPLIER: u64 = 5;

/// Max drift between the leader-supplied `timestamp_secs` and the follower's
/// own latest checkpoint timestamp before signing a guardian request.
const GUARDIAN_TIMESTAMP_TOLERANCE_SECS: u64 = 600;

fn select_withdrawal_signing_indices(
    signing: &hashi_types::move_types::SigningBatch,
    requested_input_indices: &[u64],
) -> anyhow::Result<Vec<usize>> {
    if requested_input_indices.is_empty() {
        return Ok(signing
            .unsigned_indices()
            .into_iter()
            .map(|i| i as usize)
            .collect());
    }

    let mut seen = BTreeSet::new();
    let mut selected = Vec::with_capacity(requested_input_indices.len());
    for &input_index in requested_input_indices {
        if !seen.insert(input_index) {
            anyhow::bail!("duplicate input index {input_index} in withdrawal signing request");
        }
        let i = usize::try_from(input_index)
            .map_err(|_| anyhow!("input index {input_index} out of range"))?;
        if i >= signing.num_inputs() {
            anyhow::bail!(
                "input index {input_index} out of range for withdrawal with {} inputs",
                signing.num_inputs()
            );
        }
        if signing.pending_index(i).is_none() {
            anyhow::bail!("input index {input_index} is already signed");
        }
        selected.push(i);
    }
    Ok(selected)
}

/// BTC that leaves the pool when this txn broadcasts — the amount that
/// consumes the guardian's limit. Equivalent to
/// `sum(withdrawal_outputs) + miner_fee`; we use `inputs - change` to
/// avoid relying on a separate fee field.
pub(crate) fn withdrawal_limiter_consumption_amount(txn: &WithdrawalTransaction) -> u64 {
    let inputs: u64 = txn.inputs.iter().map(|u| u.amount).sum();
    let change: u64 = txn.change_outputs.iter().map(|c| c.amount).sum();
    inputs.saturating_sub(change)
}

/// Conservative runtime-object budget for withdrawal commit transactions.
///
/// Sui's hard object-runtime cache limit is 1000 objects. Empirical
/// measurements put withdrawal commit transactions at roughly
/// `selected_utxos + 3 * requests + fixed_overhead` runtime objects. Target
/// 922 to leave 7.8% headroom below the hard 1000 cap.
const WITHDRAWAL_COMMIT_RUNTIME_OBJECT_BUDGET: usize = 922;
const WITHDRAWAL_COMMIT_FIXED_RUNTIME_OBJECTS: usize = 12;
const WITHDRAWAL_COMMIT_RUNTIME_OBJECTS_PER_REQUEST: usize = 3;
const WITHDRAWAL_COMMIT_RUNTIME_OBJECTS_PER_INPUT: usize = 1;

fn safe_withdrawal_commit_max_inputs(request_count: usize, configured_max_inputs: usize) -> usize {
    let request_objects =
        request_count.saturating_mul(WITHDRAWAL_COMMIT_RUNTIME_OBJECTS_PER_REQUEST);
    let runtime_input_budget = WITHDRAWAL_COMMIT_RUNTIME_OBJECT_BUDGET
        .saturating_sub(WITHDRAWAL_COMMIT_FIXED_RUNTIME_OBJECTS)
        .saturating_sub(request_objects);
    let input_budget = runtime_input_budget / WITHDRAWAL_COMMIT_RUNTIME_OBJECTS_PER_INPUT;
    configured_max_inputs.min(input_budget)
}

/// Confirm is no longer input-bound: spent UTXOs emit events only (0
/// objects per input). The confirm transaction's object count is
/// `requests + ~43` fixed overhead — well within the 1000-object limit
/// for any practical request count. The commit path is the binding
/// constraint.
fn safe_withdrawal_flow_max_inputs(request_count: usize, configured_max_inputs: usize) -> usize {
    let request_input_budget =
        request_count.saturating_mul(CoinSelectionParams::DEFAULT_INPUT_BUDGET);
    configured_max_inputs
        .min(request_input_budget)
        .min(safe_withdrawal_commit_max_inputs(
            request_count,
            configured_max_inputs,
        ))
}

/// The data that validators BLS-sign over to approve a single withdrawal request.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalRequestApproval {
    pub request_id: Address,
}

impl hashi_types::intent::IntentMessage for WithdrawalRequestApproval {
    const INTENT: u8 = hashi_types::intent::WITHDRAWAL_REQUEST_APPROVAL;
}

/// The data that validators BLS-sign over to commit to a withdrawal transaction.
/// This is the step 2 certificate with UTXO selection and tx construction.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalTxCommitment {
    pub request_ids: Vec<Address>,
    pub selected_utxos: Vec<UtxoId>,
    pub outputs: Vec<OutputUtxo>,
    pub txid: BitcoinTxid,
}

impl hashi_types::intent::IntentMessage for WithdrawalTxCommitment {
    const INTENT: u8 = hashi_types::intent::WITHDRAWAL_COMMITMENT;
}

/// The data that validators BLS-sign over to store witness signatures on-chain.
/// This is the step 3 certificate. The cert binds both signature arrays
/// — otherwise a malicious leader could pair valid MPC sigs with garbage
/// guardian sigs and the on-chain check would still pass.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalTxSigning {
    pub withdrawal_id: Address,
    pub request_ids: Vec<Address>,
    pub signatures: Vec<Vec<u8>>,
    pub guardian_signatures: Vec<Vec<u8>>,
}

impl hashi_types::intent::IntentMessage for WithdrawalTxSigning {
    const INTENT: u8 = hashi_types::intent::WITHDRAWAL_SIGNED;
}

/// The data validators BLS-sign over for one incremental chunk of per-input MPC
/// signatures (the step-3 chunk certificate). BCS must match Move
/// `hashi::withdraw::MpcInputSignaturesMessage` exactly: `(withdrawal_id,
/// indices, signatures)`.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct MpcInputSignaturesMessage {
    pub withdrawal_id: Address,
    pub indices: Vec<u64>,
    pub signatures: Vec<Vec<u8>>,
}

impl hashi_types::intent::IntentMessage for MpcInputSignaturesMessage {
    const INTENT: u8 = hashi_types::intent::MPC_INPUT_SIGNATURES;
}

#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalConfirmation {
    pub withdrawal_id: Address,
}

impl hashi_types::intent::IntentMessage for WithdrawalConfirmation {
    const INTENT: u8 = hashi_types::intent::WITHDRAWAL_CONFIRMATION;
}

impl Hashi {
    // --- Step 1: Request approval (lightweight) ---

    #[tracing::instrument(level = "info", skip_all, fields(request_id = %approval.request_id))]
    pub async fn validate_and_sign_withdrawal_request_approval(
        &self,
        approval: &WithdrawalRequestApproval,
    ) -> Result<hashi_types::proto::MemberSignature, WithdrawalApprovalError> {
        let request = self
            .onchain_state()
            .withdrawal_request(&approval.request_id)
            .ok_or_else(|| {
                WithdrawalApprovalError::NeverRetry(anyhow!(
                    "Withdrawal request {} not found in queue",
                    approval.request_id
                ))
            })?;
        if request.status.is_approved() {
            return Err(WithdrawalApprovalError::NeverRetry(anyhow!(
                "Withdrawal request {} is already approved",
                approval.request_id
            )));
        }

        self.screen_withdrawal(&request).await?;

        self.sign_message_proto(&approval)
            .map_err(WithdrawalApprovalError::NeverRetry)
    }

    // --- Step 2: Construction approval (with UTXO selection) ---

    #[tracing::instrument(level = "info", skip_all, fields(bitcoin_txid = %approval.txid))]
    pub async fn validate_and_sign_withdrawal_tx_commitment(
        &self,
        approval: &WithdrawalTxCommitment,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        self.validate_withdrawal_tx_commitment(approval).await?;
        self.sign_withdrawal_tx_commitment(approval)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(bitcoin_txid = %approval.txid))]
    pub async fn validate_withdrawal_tx_commitment(
        &self,
        approval: &WithdrawalTxCommitment,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!approval.request_ids.is_empty(), "No request IDs");
        anyhow::ensure!(!approval.selected_utxos.is_empty(), "No selected UTXOs");
        anyhow::ensure!(!approval.outputs.is_empty(), "No outputs");

        // Check for duplicate request IDs
        let unique_request_ids: std::collections::BTreeSet<_> =
            approval.request_ids.iter().collect();
        anyhow::ensure!(
            unique_request_ids.len() == approval.request_ids.len(),
            "Duplicate request IDs"
        );

        // Check for duplicate UTXO IDs
        let unique_utxo_ids: std::collections::BTreeSet<_> =
            approval.selected_utxos.iter().collect();
        anyhow::ensure!(
            unique_utxo_ids.len() == approval.selected_utxos.len(),
            "Duplicate UTXO IDs"
        );

        // 1. Verify each request_id exists and is approved
        let requests: Vec<WithdrawalRequest> = approval
            .request_ids
            .iter()
            .map(|id| {
                let request = self
                    .onchain_state()
                    .withdrawal_request(id)
                    .ok_or_else(|| anyhow!("Withdrawal request {id} not found in queue"))?;
                anyhow::ensure!(
                    request.status.is_approved(),
                    "Withdrawal request {id} has not been approved"
                );
                Ok(request)
            })
            .collect::<anyhow::Result<_>>()?;

        // 2. Verify each selected UTXO exists, is not locked, and collect
        //    full UTXO data. We look up via utxo_records so we can
        //    distinguish "missing" from "locked by another withdrawal" and
        //    also inspect the `produced_by` chain for ancestor depth.
        let (utxo_records, withdrawal_txns) = {
            let state = self.onchain_state().state();
            (
                state.hashi().utxo_pool.utxo_records().clone(),
                state.hashi().withdrawal_queue.withdrawal_txns().clone(),
            )
        };

        let selected_records: Vec<&UtxoRecord> = approval
            .selected_utxos
            .iter()
            .map(|id| {
                let record = utxo_records
                    .get(id)
                    .ok_or_else(|| anyhow!("UTXO {id:?} not found in the pool"))?;
                anyhow::ensure!(
                    record.locked_by.is_none(),
                    "UTXO {id:?} is locked by pending withdrawal {:?}",
                    record.locked_by.unwrap()
                );
                Ok(record)
            })
            .collect::<anyhow::Result<_>>()?;

        // 2b. Verify that no selected UTXO has an unconfirmed ancestor
        //     chain deeper than Bitcoin Core's relay limit. The limit
        //     (DEFAULT_ANCESTOR_LIMIT = 25) counts the candidate tx
        //     itself, so the existing chain must leave room for the
        //     transaction we are about to construct.
        for record in &selected_records {
            let depth = unconfirmed_ancestor_depth(record, &withdrawal_txns, &utxo_records);
            anyhow::ensure!(
                depth < MAX_ANCESTOR_DEPTH,
                "UTXO {:?} has an unconfirmed ancestor chain of depth {} \
                 which, together with the new transaction, would exceed \
                 Bitcoin Core's ancestor limit of {}",
                record.utxo.id,
                depth,
                MAX_ANCESTOR_DEPTH,
            );
        }

        let selected_utxos: Vec<Utxo> = selected_records.iter().map(|r| r.utxo.clone()).collect();

        // 3. Verify output count: one per request, followed by zero or more
        //    trailing change outputs.
        let request_count = requests.len();
        let output_count = approval.outputs.len();
        anyhow::ensure!(
            output_count >= request_count,
            "Expected at least {} outputs (one per request), got {}",
            request_count,
            output_count
        );

        // 4. Compute miner fee and verify the per-user fee split
        let input_total: u64 = selected_utxos.iter().map(|u| u.amount).sum();
        let output_total: u64 = approval.outputs.iter().map(|o| o.amount).sum();
        anyhow::ensure!(
            input_total >= output_total,
            "Inputs ({input_total}) < outputs ({output_total})"
        );
        let fee = input_total - output_total;

        let per_user_miner_fee = fee / request_count as u64;

        // Verify per-user miner fee does not exceed worst-case budget
        let max_network_fee = self.onchain_state().worst_case_network_fee();
        anyhow::ensure!(
            per_user_miner_fee <= max_network_fee,
            "Per-user miner fee {} sats exceeds worst-case budget {} sats",
            per_user_miner_fee,
            max_network_fee
        );

        // Verify each positional withdrawal output matches the expected amount and address.
        // request.btc_amount is the full withdrawal amount.
        for (i, request) in requests.iter().enumerate() {
            let output = &approval.outputs[i];
            let expected_amount = request.btc_amount - per_user_miner_fee;
            anyhow::ensure!(
                expected_amount >= utxo_pool::TR_DUST_RELAY_MIN_VALUE,
                "Withdrawal output {} sats is below dust threshold {} sats",
                expected_amount,
                utxo_pool::TR_DUST_RELAY_MIN_VALUE
            );
            anyhow::ensure!(
                output.amount == expected_amount,
                "Output {i} amount {} does not match expected {} for request {:?}",
                output.amount,
                expected_amount,
                request.id
            );
            anyhow::ensure!(
                output.bitcoin_address == request.bitcoin_address,
                "Output {i} address does not match request {:?}",
                request.id
            );
        }

        // 5. Verify every change output (the trailing outputs after the
        //    per-request ones) goes to the hashi root pubkey and is above dust.
        if output_count > request_count {
            let expected_address =
                hashi_bitcoin::witness_program_from_address(&self.get_deposit_address(None)?)?;
            for (j, change_output) in approval.outputs[request_count..].iter().enumerate() {
                anyhow::ensure!(
                    change_output.bitcoin_address == expected_address,
                    "Change output {j} does not go to hashi root pubkey"
                );
                anyhow::ensure!(
                    change_output.amount >= utxo_pool::TR_DUST_RELAY_MIN_VALUE,
                    "Change output {j} ({} sats) is below dust threshold {} sats",
                    change_output.amount,
                    utxo_pool::TR_DUST_RELAY_MIN_VALUE
                );
            }
        }

        // 6. Validate fee is reasonable.
        //
        // TODO: When spending unconfirmed change UTXOs the effective fee
        // rate that matters for mining is the *package* fee rate across
        // the entire ancestor chain (CPFP). This check currently
        // evaluates the transaction in isolation, which may over- or
        // under-estimate the true cost to get the package mined. A
        // future revision should compute the aggregate ancestor weight
        // and fees and validate the package fee rate instead.
        {
            // Estimate transaction weight.
            let num_inputs = selected_utxos.len() as u64;
            let input_weight = hashi_bitcoin::SCRIPT_PATH_2OF2_TXIN_WEIGHT * num_inputs;
            let output_weight: u64 = approval
                .outputs
                .iter()
                .map(|o| hashi_bitcoin::output_weight_for_witness_program(&o.bitcoin_address))
                .collect::<anyhow::Result<Vec<_>>>()?
                .iter()
                .sum();
            let tx_weight =
                Weight::from_wu(hashi_bitcoin::TX_FIXED_WEIGHT_WU + input_weight + output_weight);

            let min_fee_rate = FeeRate::from_sat_per_vb_unchecked(1);

            // Fee must be at least the minimum relay fee (1 sat/vB).
            let min_fee = min_fee_rate
                .fee_wu(tx_weight)
                .map(|a| a.to_sat())
                .unwrap_or(0);
            anyhow::ensure!(
                fee >= min_fee,
                "Fee {fee} sats is below minimum relay fee {min_fee} sats"
            );

            // Fee ceiling: clamp the fee rate from our Bitcoin node to
            // a floor of 1 sat/vB, then cap at the tolerance multiplier.
            let kyoto_fee_rate = self
                .btc_monitor()
                .get_recent_fee_rate(self.config.withdrawal_fee_conf_target())
                .await?;
            let clamped_fee_rate = std::cmp::max(kyoto_fee_rate, min_fee_rate);
            let estimated_fee = clamped_fee_rate
                .fee_wu(tx_weight)
                .map(|a| a.to_sat())
                .unwrap_or(0);
            let max_fee = estimated_fee.saturating_mul(FEE_RATE_TOLERANCE_MULTIPLIER);
            anyhow::ensure!(
                fee <= max_fee,
                "Fee {fee} sats exceeds maximum allowed {max_fee} sats \
                 ({FEE_RATE_TOLERANCE_MULTIPLIER}x the clamped estimate of \
                 {estimated_fee} sats at {clamped_fee_rate})"
            );
        }

        // 7. Rebuild unsigned tx and verify txid matches.
        let tx = self.build_unsigned_withdrawal_tx(&selected_utxos, &approval.outputs)?;
        let expected_txid = BitcoinTxid::from(tx.compute_txid());
        anyhow::ensure!(
            approval.txid == expected_txid,
            "Txid mismatch: approval has {:?}, rebuilt tx has {:?}",
            approval.txid,
            expected_txid
        );

        Ok(())
    }

    fn sign_withdrawal_tx_commitment(
        &self,
        approval: &WithdrawalTxCommitment,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        self.sign_message_proto(approval)
    }

    pub fn sign_withdrawal_confirmation(
        &self,
        withdrawal_txn_id: &Address,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        let txn = self
            .onchain_state()
            .withdrawal_txn(withdrawal_txn_id)
            .ok_or_else(|| {
                anyhow!("WithdrawalTransaction {withdrawal_txn_id} not found on-chain")
            })?;
        let confirmation = WithdrawalConfirmation {
            withdrawal_id: txn.id,
        };

        self.sign_message_proto(&confirmation)
    }

    // --- Guardian: validate and BLS-sign a `StandardWithdrawalRequest` ---

    /// Reject a leader-supplied `timestamp_secs` that skews beyond the tolerance
    /// from this node's checkpoint clock.
    fn bound_leader_timestamp(&self, timestamp_secs: u64) -> anyhow::Result<()> {
        let latest_checkpoint_secs = self.onchain_state().latest_checkpoint_timestamp_ms() / 1000;
        let drift = timestamp_secs.abs_diff(latest_checkpoint_secs);
        anyhow::ensure!(
            drift <= GUARDIAN_TIMESTAMP_TOLERANCE_SECS,
            "Withdrawal timestamp {timestamp_secs} is {drift}s away from local checkpoint \
             {latest_checkpoint_secs} (tolerance: {GUARDIAN_TIMESTAMP_TOLERANCE_SECS}s)"
        );
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all, fields(%withdrawal_txn_id, seq))]
    pub fn validate_and_sign_guardian_withdrawal_request(
        &self,
        withdrawal_txn_id: &Address,
        timestamp_secs: u64,
        seq: u64,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        self.bound_leader_timestamp(timestamp_secs)?;

        let txn = self
            .onchain_state()
            .withdrawal_txn(withdrawal_txn_id)
            .ok_or_else(|| {
                anyhow!("WithdrawalTransaction {withdrawal_txn_id} not found on-chain")
            })?;

        let guardian_request = build_guardian_withdrawal_request(self, &txn, timestamp_secs, seq)?;

        self.sign_message_proto(&guardian_request)
    }

    // --- Step 3: Sign withdrawal (store witness signatures on-chain) ---

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_id = %message.withdrawal_id))]
    pub fn validate_and_sign_withdrawal_tx_signing(
        &self,
        message: &WithdrawalTxSigning,
        expected_limiter_seq: Option<u64>,
        timestamp_secs: Option<u64>,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        let txn = self
            .onchain_state()
            .withdrawal_txn(&message.withdrawal_id)
            .ok_or_else(|| {
                anyhow!(
                    "WithdrawalTransaction {} not found on-chain",
                    message.withdrawal_id
                )
            })?;

        anyhow::ensure!(
            !txn.is_fully_signed(),
            "WithdrawalTransaction {} is already finalized",
            message.withdrawal_id
        );

        anyhow::ensure!(
            message.request_ids == txn.request_ids,
            "Request IDs mismatch for WithdrawalTransaction {}",
            message.withdrawal_id
        );

        anyhow::ensure!(
            message.signatures.len() == txn.inputs.len(),
            "MPC signature count ({}) does not match input count ({}) for WithdrawalTransaction {}",
            message.signatures.len(),
            txn.inputs.len(),
            message.withdrawal_id
        );
        anyhow::ensure!(
            message.guardian_signatures.len() == txn.inputs.len(),
            "Guardian signature count ({}) does not match input count ({}) for WithdrawalTransaction {}",
            message.guardian_signatures.len(),
            txn.inputs.len(),
            message.withdrawal_id
        );

        // Single committee-side rate-limit gate: signing is driven unconditionally,
        // so the committee independently re-validates the limit once here, before
        // certifying the finalize — refusing to sign blocks an over-limit broadcast
        // even if the guardian co-signed. Validate-only: the watcher advances the
        // limiter on `WithdrawalSignedEvent`, never from this path.
        //
        // TODO(guardian-seq-durability): this gate is necessarily *after* the
        // guardian co-signed (the cert binds the guardian sigs), so a rejection
        // here — which only happens when this mirror disagrees with the guardian
        // (the defense-in-depth case) — leaves the guardian's seq consumed with no
        // on-chain finalize, nudging that gap wider. It self-heals via the
        // reconcile loop and fires only when catching a guardian/mirror divergence,
        // so likely fine as-is; if it ever proves to matter, one option worth
        // exploring would be a separate committee limiter check *before* the
        // guardian co-signs (extra round-trip, but no consumed-but-not-finalized gap).
        match (self.local_limiter(), expected_limiter_seq) {
            (Some(limiter), Some(expected_seq)) => {
                let amount_sats = withdrawal_limiter_consumption_amount(&txn);
                // Leader's live checkpoint time (drift-bounded); pre-upgrade leaders omit it.
                let timestamp_secs = match timestamp_secs {
                    Some(ts) => {
                        self.bound_leader_timestamp(ts)?;
                        ts
                    }
                    None => txn.created_timestamp_ms / 1000,
                };
                let result = limiter.validate_consume(expected_seq, timestamp_secs, amount_sats);
                self.metrics.record_limiter_validate(
                    &result,
                    crate::metrics::GUARDIAN_LIMITER_CALLSITE_FINALIZE_CERT,
                );
                result.map_err(|e| {
                    anyhow!("Limiter rejected withdrawal {}: {e}", message.withdrawal_id)
                })?;
            }
            (None, None) => {}
            (Some(_), None) => anyhow::bail!(
                "Local limiter is configured but finalize request for withdrawal {} lacks expected_limiter_seq",
                message.withdrawal_id
            ),
            (None, Some(_)) => anyhow::bail!(
                "Finalize request for withdrawal {} carries expected_limiter_seq but local limiter is not configured",
                message.withdrawal_id
            ),
        }

        let tx = self.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())?;
        let signing_messages = self.withdrawal_signing_messages(&tx, &txn.inputs)?;
        let guardian_btc_pubkey = self.guardian_btc_pubkey().copied().ok_or_else(|| {
            anyhow!("Guardian BTC pubkey not yet pinned; cannot validate withdrawal")
        })?;
        let guardian_schnorr_pk =
            SchnorrPublicKey::from_byte_array(&guardian_btc_pubkey.serialize())
                .map_err(|e| anyhow!("Failed to convert guardian BTC pubkey: {e}"))?;

        for (i, ((mpc_sig_bytes, guardian_sig_bytes), sighash)) in message
            .signatures
            .iter()
            .zip(message.guardian_signatures.iter())
            .zip(signing_messages.iter())
            .enumerate()
        {
            // MPC: verify against the derived hashi child key.
            let mpc_arr: &[u8; 64] = mpc_sig_bytes.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "MPC signature {i} is not 64 bytes for WithdrawalTransaction {}",
                    message.withdrawal_id
                )
            })?;
            let mpc_sig = SchnorrSignature::from_byte_array(mpc_arr)
                .map_err(|e| anyhow!("Invalid MPC Schnorr signature at input {i}: {e}"))?;
            let input_pubkey = self.deposit_pubkey(txn.inputs[i].derivation_path.as_ref())?;
            let mpc_schnorr_pk = SchnorrPublicKey::from_byte_array(&input_pubkey.serialize())
                .map_err(|e| anyhow!("Failed to convert mpc pubkey for input {i}: {e}"))?;
            mpc_schnorr_pk
                .verify(sighash, &mpc_sig)
                .map_err(|e| anyhow!("MPC signature verification failed for input {i}: {e}"))?;

            // Guardian: verify against the on-chain enclave BTC pubkey.
            // Same sighash — both sigs commit to the same multi_a leaf.
            let guardian_arr: &[u8; 64] =
                guardian_sig_bytes.as_slice().try_into().map_err(|_| {
                    anyhow!(
                        "Guardian signature {i} is not 64 bytes for WithdrawalTransaction {}",
                        message.withdrawal_id
                    )
                })?;
            let guardian_sig = SchnorrSignature::from_byte_array(guardian_arr)
                .map_err(|e| anyhow!("Invalid guardian Schnorr signature at input {i}: {e}"))?;
            guardian_schnorr_pk
                .verify(sighash, &guardian_sig)
                .map_err(|e| {
                    anyhow!("Guardian signature verification failed for input {i}: {e}")
                })?;
        }

        self.sign_message_proto(message)
    }

    /// Validate and BLS-sign one incremental chunk of per-input MPC signatures
    /// (`MpcInputSignaturesMessage`). Each `(index, signature)` is verified
    /// against that input's sighash before the member signs the chunk cert, so a
    /// leader cannot obtain a cert over signatures the committee hasn't checked.
    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(withdrawal_id = %message.withdrawal_id, chunk_size = message.indices.len()),
    )]
    pub fn validate_and_sign_mpc_input_signatures(
        &self,
        message: &MpcInputSignaturesMessage,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        let txn = self
            .onchain_state()
            .withdrawal_txn(&message.withdrawal_id)
            .ok_or_else(|| {
                anyhow!(
                    "WithdrawalTransaction {} not found on-chain",
                    message.withdrawal_id
                )
            })?;

        anyhow::ensure!(
            !txn.is_fully_signed(),
            "WithdrawalTransaction {} is already finalized",
            message.withdrawal_id
        );
        anyhow::ensure!(
            message.indices.len() == message.signatures.len(),
            "Chunk indices ({}) and signatures ({}) length mismatch for WithdrawalTransaction {}",
            message.indices.len(),
            message.signatures.len(),
            message.withdrawal_id
        );

        let tx = self.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())?;
        let signing_messages = self.withdrawal_signing_messages(&tx, &txn.inputs)?;

        for (chunk_pos, (&input_index, mpc_sig_bytes)) in message
            .indices
            .iter()
            .zip(message.signatures.iter())
            .enumerate()
        {
            let i = input_index as usize;
            anyhow::ensure!(
                i < txn.inputs.len(),
                "Chunk input index {i} out of range ({}) for WithdrawalTransaction {}",
                txn.inputs.len(),
                message.withdrawal_id
            );
            let sighash = &signing_messages[i];
            let mpc_arr: &[u8; 64] = mpc_sig_bytes.as_slice().try_into().map_err(|_| {
                anyhow!("MPC signature at chunk position {chunk_pos} (input {i}) is not 64 bytes")
            })?;
            let mpc_sig = SchnorrSignature::from_byte_array(mpc_arr)
                .map_err(|e| anyhow!("Invalid MPC Schnorr signature at input {i}: {e}"))?;
            let input_pubkey = self.deposit_pubkey(txn.inputs[i].derivation_path.as_ref())?;
            let mpc_schnorr_pk = SchnorrPublicKey::from_byte_array(&input_pubkey.serialize())
                .map_err(|e| anyhow!("Failed to convert mpc pubkey for input {i}: {e}"))?;
            mpc_schnorr_pk
                .verify(sighash, &mpc_sig)
                .map_err(|e| anyhow!("MPC signature verification failed for input {i}: {e}"))?;
        }

        self.sign_message_proto(message)
    }

    // --- Generic BLS signing helper ---

    /// Proto-format BLS signing helper. Signs at the current on-chain epoch.
    fn sign_message_proto<T: hashi_types::intent::IntentMessage>(
        &self,
        message: &T,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        self.sign_message_proto_at_epoch(message, self.onchain_state().epoch())
    }

    /// Sign at a specific historical `epoch` using that epoch's DB key.
    pub(crate) fn sign_message_proto_at_epoch<T: hashi_types::intent::IntentMessage>(
        &self,
        message: &T,
        epoch: u64,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        let validator_address = self
            .config
            .validator_address()
            .map_err(|e| anyhow!("No validator address configured: {e}"))?;
        let committee = self
            .onchain_state()
            .state()
            .hashi()
            .committees
            .committees()
            .get(&epoch)
            .cloned()
            .ok_or_else(|| anyhow!("no committee for epoch {epoch}"))?;
        let private_key =
            self.find_signing_key_for_committee(&committee, validator_address, epoch)?;
        let public_key_bytes = private_key.public_key().as_bytes().to_vec().into();
        let signature_bytes = private_key
            .sign(epoch, validator_address, message)
            .signature()
            .as_bytes()
            .to_vec()
            .into();

        Ok(hashi_types::proto::MemberSignature {
            epoch: Some(epoch),
            address: Some(validator_address.to_string()),
            public_key: Some(public_key_bytes),
            signature: Some(signature_bytes),
        })
    }

    // --- Guardian: validate and BLS-sign a `CommitteeTransitionRequest` ---

    /// Rebuild the transition from on-chain state and sign with the historical key.
    #[tracing::instrument(level = "info", skip_all, fields(from_epoch))]
    pub fn validate_and_sign_committee_transition(
        &self,
        from_epoch: u64,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        if let Some(signature) = self.get_committee_handoff_signature(from_epoch) {
            return Ok(signature);
        }

        let validator_address = self
            .config
            .validator_address()
            .map_err(|e| anyhow!("No validator address configured: {e}"))?;

        let onchain = self.onchain_state();
        let state = onchain.state();
        let committees_map = state.hashi().committees.committees();
        let from_committee = committees_map
            .get(&from_epoch)
            .ok_or_else(|| anyhow!("no on-chain committee for epoch {from_epoch}"))?;
        if !from_committee
            .members()
            .iter()
            .any(|m| m.validator_address() == validator_address)
        {
            anyhow::bail!("not a member of the committee at epoch {from_epoch}");
        }

        // Hashi committee epochs are sparse: the next entry after `from_epoch`
        // is generally not `from_epoch + 1`. Both leader and followers derive
        // the same `to_epoch` from on-chain state, so they sign the same
        // transition.
        let new_committee = committees_map
            .range((from_epoch + 1)..)
            .next()
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("no on-chain committee epoch after {from_epoch}"))?;

        let transition = hashi_types::guardian::CommitteeTransitionRequest {
            new_committee: hashi_types::move_types::Committee::from(new_committee),
        };

        let signature = self.sign_message_proto_at_epoch(&transition, from_epoch)?;
        self.store_committee_handoff_signature(from_epoch, signature.clone());
        Ok(signature)
    }

    // --- MPC BTC tx signing ---

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %withdrawal_txn_id))]
    pub async fn validate_and_sign_withdrawal_tx(
        &self,
        withdrawal_txn_id: &Address,
        requested_input_indices: &[u64],
        sink: tokio::sync::mpsc::Sender<
            Result<hashi_types::proto::SignWithdrawalTransactionPartial, tonic::Status>,
        >,
    ) -> anyhow::Result<()> {
        let (txn, unsigned_tx) = self.validate_withdrawal_signing(withdrawal_txn_id).await?;
        self.mpc_sign_withdrawal_tx(&txn, &unsigned_tx, requested_input_indices, sink)
            .await
    }

    pub async fn validate_withdrawal_signing(
        &self,
        withdrawal_txn_id: &Address,
    ) -> anyhow::Result<(
        crate::onchain::types::WithdrawalTransaction,
        bitcoin::Transaction,
    )> {
        let txn = self
            .onchain_state()
            .withdrawal_txn(withdrawal_txn_id)
            .ok_or_else(|| {
                anyhow!("WithdrawalTransaction {withdrawal_txn_id} not found on-chain")
            })?;

        // Rebuild the unsigned BTC tx and verify the txid matches
        let tx = self.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())?;
        let expected_txid = BitcoinTxid::from(tx.compute_txid());
        anyhow::ensure!(
            txn.txid == expected_txid,
            "Txid mismatch: WithdrawalTransaction has {:?}, rebuilt tx has {:?}",
            txn.txid,
            expected_txid
        );

        Ok((txn.clone(), tx))
    }

    /// Produce MPC Schnorr signatures for an unsigned withdrawal transaction.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(withdrawal_txn_id = %txn.id, input_count = txn.inputs.len()),
    )]
    async fn mpc_sign_withdrawal_tx(
        &self,
        txn: &WithdrawalTransaction,
        unsigned_tx: &bitcoin::Transaction,
        requested_input_indices: &[u64],
        sink: tokio::sync::mpsc::Sender<
            Result<hashi_types::proto::SignWithdrawalTransactionPartial, tonic::Status>,
        >,
    ) -> anyhow::Result<()> {
        let onchain_state = self.onchain_state().clone();
        let epoch = onchain_state.epoch();
        if txn.signing.epoch != epoch {
            anyhow::bail!(
                "Stale presig assignment: pending withdrawal {} has signing epoch {}, current is {}. \
                 Either the leader hasn't called reallocate_presigs yet, \
                 or this node's on-chain state is behind.",
                txn.id,
                txn.signing.epoch,
                epoch,
            );
        }
        let p2p_channel =
            RpcP2PChannel::new(onchain_state, epoch, crate::metrics::MPC_LABEL_SIGNING);
        let signing_manager = self.signing_manager_for(epoch).ok_or_else(|| {
            anyhow::anyhow!(
                "SigningManager not available for epoch {epoch}; \
                 reconciliation may be catching up"
            )
        })?;
        let beacon = S::from_bytes_mod_order(&txn.randomness);
        let signing_messages = self.withdrawal_signing_messages(unsigned_tx, &txn.inputs)?;
        let signing_manager_ref = &signing_manager;
        let p2p_channel_ref = &p2p_channel;
        let beacon_ref = &beacon;
        let metrics_ref = &*self.metrics;
        let txn_id = txn.id;
        // Per-input presig index is read off the on-chain signing batch slot, so
        // out-of-order / resume works and the index is always the current-epoch
        // one assigned by `commit`/`reallocate`. Already-signed inputs are skipped.
        let signing = &txn.signing;
        let inputs = &txn.inputs;
        let sink_ref = &sink;
        let selected_input_indices =
            select_withdrawal_signing_indices(signing, requested_input_indices)?;
        let mut requests = Vec::with_capacity(selected_input_indices.len());
        let mut index_by_id: HashMap<Address, usize> =
            HashMap::with_capacity(selected_input_indices.len());
        for input_index in selected_input_indices {
            let message = signing_messages
                .get(input_index)
                .expect("validated input_index is in range for signing_messages");
            let global_presig_index = signing
                .pending_index(input_index)
                .expect("validated input_index is pending");
            let signing_id = withdrawal_input_signing_id(&txn_id, input_index as u32);
            // Change UTXOs (`derivation_path = None`) ride the `[0; 32]` path
            // everywhere else (leaf script, `deposit_pubkey`). MPC must too —
            // passing `None` signs for master `G`, not the `derive(G, [0; 32])`
            // child the 2-of-2 leaf binds.
            let derivation_address = inputs
                .get(input_index)
                .map(|input| {
                    crate::deposits::normalized_derivation_path(input.derivation_path.as_ref())
                        .into_inner()
                })
                .expect("validated input_index is in range for txn.inputs");
            index_by_id.insert(signing_id, input_index);
            requests.push(crate::mpc::SignInput {
                signing_id,
                message: message.to_vec(),
                global_presig_index,
                derivation_address: Some(derivation_address),
            });
        }
        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
        let batch_start = std::time::Instant::now();
        let collect = signing_manager_ref.sign(
            p2p_channel_ref,
            requests,
            beacon_ref,
            WITHDRAWAL_SIGNING_TIMEOUT,
            metrics_ref,
            result_tx,
        );
        let forward = async {
            while let Some((signing_id, sign_result)) = result_rx.recv().await {
                let input_index = index_by_id[&signing_id];
                let sign_duration = batch_start.elapsed().as_secs_f64();
                match &sign_result {
                    Ok(_) => {
                        metrics_ref
                            .mpc_sign_duration_seconds
                            .with_label_values(&["success"])
                            .observe(sign_duration);
                        metrics_ref
                            .presig_pool_remaining
                            .set(signing_manager_ref.presignatures_remaining() as i64);
                    }
                    Err(e) => {
                        metrics_ref
                            .mpc_sign_duration_seconds
                            .with_label_values(&["failure"])
                            .observe(sign_duration);
                        let reason = match e {
                            crate::mpc::types::SigningError::Timeout { .. } => "timeout",
                            crate::mpc::types::SigningError::PoolExhausted => "pool_exhausted",
                            crate::mpc::types::SigningError::TooManyInvalidSignatures {
                                ..
                            } => "too_many_invalid",
                            crate::mpc::types::SigningError::CryptoError(_) => "crypto_error",
                            _ => "other",
                        };
                        metrics_ref
                            .mpc_sign_failures_total
                            .with_label_values(&[reason])
                            .inc();
                    }
                }
                let partial = sign_result
                    .map(|sig| hashi_types::proto::SignWithdrawalTransactionPartial {
                        input_index: input_index as u32,
                        signature: sig.to_byte_array().to_vec().into(),
                    })
                    .map_err(|e| {
                        tonic::Status::internal(format!(
                            "Failed to sign withdrawal transaction input {input_index}: {e}"
                        ))
                    });
                let _ = sink_ref.send(partial).await;
            }
        };
        tokio::join!(collect, forward);
        Ok(())
    }

    pub(crate) fn withdrawal_signing_messages(
        &self,
        unsigned_tx: &bitcoin::Transaction,
        inputs: &[Utxo],
    ) -> anyhow::Result<Vec<[u8; 32]>> {
        let spend_inputs = inputs
            .iter()
            .map(|input| {
                let address = self.get_deposit_address(input.derivation_path.as_ref())?;
                let (_, _, leaf_hash) =
                    self.deposit_spend_artifacts(input.derivation_path.as_ref())?;
                Ok((
                    TxOut {
                        value: Amount::from_sat(input.amount),
                        script_pubkey: address.script_pubkey(),
                    },
                    leaf_hash,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let prevouts = spend_inputs
            .iter()
            .map(|(txout, _)| txout.clone())
            .collect::<Vec<_>>();
        let leaf_hashes = spend_inputs
            .iter()
            .map(|(_, leaf_hash)| *leaf_hash)
            .collect::<Vec<TapLeafHash>>();

        Ok(hashi_bitcoin::taproot_script_spend_sighashes(
            unsigned_tx,
            &prevouts,
            &leaf_hashes,
        ))
    }

    // --- UTXO selection and tx crafting ---

    /// Build an unsigned Bitcoin transaction for a withdrawal. This is used both
    /// by the leader when initially crafting the tx, and by validators when
    /// verifying that a proposed `WithdrawalTxCommitment` produces the expected txid.
    pub fn build_unsigned_withdrawal_tx(
        &self,
        selected_utxos: &[Utxo],
        outputs: &[OutputUtxo],
    ) -> anyhow::Result<bitcoin::Transaction> {
        let inputs: Vec<bitcoin::TxIn> = selected_utxos
            .iter()
            .map(|utxo| hashi_bitcoin::InputUTXO::from(utxo).txin())
            .collect();

        let tx_outputs: Vec<bitcoin::TxOut> = outputs
            .iter()
            .map(|output| {
                let script_pubkey =
                    hashi_bitcoin::script_pubkey_from_witness_program(&output.bitcoin_address)
                        .expect("invalid bitcoin address in output");
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(output.amount),
                    script_pubkey,
                }
            })
            .collect();

        Ok(hashi_bitcoin::construct_tx(inputs, tx_outputs))
    }

    /// Build a withdrawal commitment for a batch of approved requests: select
    /// UTXOs using the batching-aware coin selection algorithm, build the
    /// unsigned BTC tx, and return a `WithdrawalTxCommitment` covering the
    /// selected requests.
    #[tracing::instrument(level = "debug", skip_all, fields(request_count = requests.len()))]
    pub async fn build_withdrawal_tx_commitment(
        &self,
        requests: &[WithdrawalRequest],
    ) -> Result<WithdrawalTxCommitment, WithdrawalCommitmentError> {
        // Fetch current fee rate from the Bitcoin node, clamped to a high
        // fee rate threshold to avoid overpaying during fee spikes.
        let kyoto_fee_rate = self
            .btc_monitor()
            .get_recent_fee_rate(self.config.withdrawal_fee_conf_target())
            .await
            .map_err(|e| WithdrawalCommitmentError::FeeEstimateFailed(anyhow!(e)))?;
        let min_fee_rate = CoinSelectionParams::DEFAULT_MIN_FEE_RATE;
        let max_fee_rate = CoinSelectionParams::DEFAULT_HIGH_FEE_RATE_THRESHOLD;
        let fee_rate = kyoto_fee_rate.clamp(min_fee_rate, max_fee_rate);

        let change_address = self
            .get_deposit_address(None)
            .map_err(WithdrawalCommitmentError::BtcTxBuildFailed)?;

        let configured_max_inputs = CoinSelectionParams::DEFAULT_MAX_INPUTS;
        let configured_long_term_fee_rate = CoinSelectionParams::DEFAULT_LONG_TERM_FEE_RATE;
        let configured_max_requests = self.config.withdrawal_max_batch_size().min(requests.len());

        // Snapshot both maps under a single read-lock so they are always
        // mutually consistent (e.g., a WithdrawalConfirmedEvent cannot update
        // one map but not the other between the two reads).
        let (withdrawal_txns, utxo_records) = {
            let state = self.onchain_state().state();
            (
                state.hashi().withdrawal_queue.withdrawal_txns().clone(),
                state.hashi().utxo_pool.utxo_records().clone(),
            )
        };

        // Query Bitcoin in parallel for the confirmation count of every
        // pending withdrawal so we can accurately fill AncestorTx::confirmations
        // instead of always hardcoding 0.
        let tx_confirmations = fetch_withdrawal_tx_confirmations(self, &withdrawal_txns).await;

        // Map available (unlocked) UTXOs to UtxoCandidates.
        let candidates: Vec<UtxoCandidate> = utxo_records
            .values()
            .filter(|r| r.locked_by.is_none())
            .map(|r| {
                let status =
                    build_utxo_status(self, r, &withdrawal_txns, &tx_confirmations, &utxo_records);
                UtxoCandidate {
                    id: r.utxo.id,
                    amount: r.utxo.amount,
                    spend_path: SpendPath::TaprootScriptPath2of2,
                    status,
                }
            })
            .collect();

        // Map on-chain WithdrawalRequests to the coin-selector view.
        // btc_amount is the full withdrawal amount.
        let mapped_requests: Vec<utxo_pool::WithdrawalRequest> = requests
            .iter()
            .map(|r| utxo_pool::WithdrawalRequest {
                id: r.id,
                recipient: r.bitcoin_address.clone(),
                amount: r.btc_amount,
                timestamp_ms: r.created_timestamp_ms,
            })
            .collect();

        let mut last_selection_error = None;
        let mut result = None;
        for request_count in (1..=configured_max_requests).rev() {
            let max_inputs = safe_withdrawal_flow_max_inputs(request_count, configured_max_inputs);
            if max_inputs == 0 {
                continue;
            }

            let params = CoinSelectionParams {
                max_inputs,
                long_term_fee_rate: configured_long_term_fee_rate,
                max_fee_per_request: self.onchain_state().worst_case_network_fee(),
                max_withdrawal_requests: request_count,
                max_mempool_chain_depth: self.config.max_mempool_chain_depth(),
                ..CoinSelectionParams::new(change_address.clone())
            };

            match utxo_pool::select_coins(&candidates, &mapped_requests, &params, fee_rate) {
                Ok(selection) => {
                    if request_count < configured_max_requests {
                        tracing::info!(
                            selected_requests = selection.selected_requests.len(),
                            selected_inputs = selection.inputs.len(),
                            configured_max_requests,
                            configured_max_inputs,
                            max_inputs,
                            "Reduced withdrawal batch to stay within Sui commit limits",
                        );
                    }
                    result = Some(selection);
                    break;
                }
                Err(e) => last_selection_error = Some(e),
            }
        }

        let result = result.ok_or_else(|| {
            WithdrawalCommitmentError::UtxoSelectionFailed(anyhow!(
                last_selection_error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no withdrawal request count fits Sui commit limits".into())
            ))
        })?;

        // Build outputs: one per selected request (net amount already deducted),
        // plus an optional change output.
        let mut outputs: Vec<OutputUtxo> = result
            .withdrawal_outputs
            .iter()
            .map(|o| OutputUtxo {
                amount: o.amount,
                bitcoin_address: o.recipient.clone(),
            })
            .collect();

        if let Some(change_amount) = result.change {
            outputs.push(OutputUtxo {
                amount: change_amount,
                bitcoin_address: hashi_bitcoin::witness_program_from_address(&change_address)
                    .map_err(WithdrawalCommitmentError::BtcTxBuildFailed)?,
            });
        }

        let selected_utxos: Vec<UtxoId> = result.inputs.iter().map(|u| u.id).collect();
        let request_ids: Vec<Address> = result.selected_requests.iter().map(|r| r.id).collect();

        // Resolve UtxoCandidates back to full Utxo objects for tx building.
        let selected_input_utxos: Vec<Utxo> = result
            .inputs
            .iter()
            .map(|c| self.onchain_state().active_utxo(&c.id))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                WithdrawalCommitmentError::BtcTxBuildFailed(anyhow!(
                    "a selected UTXO disappeared from the pool between selection and tx build"
                ))
            })?;

        let tx = self
            .build_unsigned_withdrawal_tx(&selected_input_utxos, &outputs)
            .map_err(WithdrawalCommitmentError::BtcTxBuildFailed)?;
        let txid = BitcoinTxid::from(tx.compute_txid());

        Ok(WithdrawalTxCommitment {
            request_ids,
            selected_utxos,
            outputs,
            txid,
        })
    }

    /// Run AML/Sanctions checks for a withdrawal request.
    /// If no screener client is configured, checks are skipped.
    #[tracing::instrument(level = "debug", skip_all, fields(request_id = %request.id))]
    pub(crate) async fn screen_withdrawal(
        &self,
        request: &WithdrawalRequest,
    ) -> Result<(), WithdrawalApprovalError> {
        let Some(screener) = self.screener_client() else {
            tracing::debug!("AML checks skipped: no screener configured");
            return Ok(());
        };

        // Source: Sui tx digest (base58 string)
        let source_tx_hash = request.sui_tx_digest.to_string();

        // Destination: Bitcoin address (raw witness bytes -> bech32 string)
        let destination_address = hashi_bitcoin::address_string_from_witness_program(
            &request.bitcoin_address,
            self.config.bitcoin_network(),
        )
        .map_err(WithdrawalApprovalError::NeverRetry)?;

        let approved = screener
            .approve_withdrawal(
                &source_tx_hash,
                &destination_address,
                self.config.sui_chain_id(),
                self.config.bitcoin_chain_id(),
            )
            .await
            .map_err(|e| WithdrawalApprovalError::AmlServiceError(anyhow!(e)))?;

        if !approved {
            return Err(WithdrawalApprovalError::NeverRetry(anyhow!(
                "AML checks failed for withdrawal request {:?} to {}",
                request.id,
                destination_address,
            )));
        }

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WithdrawalApprovalErrorKind {
    AmlServiceError,
    FailedQuorum,
    TimedOut,
    TaskFailed,
    NeverRetry,
}

impl RetryPolicy for WithdrawalApprovalErrorKind {
    fn retry_base_delay_ms(self) -> u64 {
        match self {
            Self::AmlServiceError | Self::FailedQuorum | Self::TaskFailed | Self::TimedOut => {
                5 * 1000
            }
            Self::NeverRetry => u64::MAX,
        }
    }

    fn max_delay_ms(self) -> u64 {
        2 * 60 * 1000
    }

    fn max_retries(self) -> u32 {
        match self {
            Self::AmlServiceError | Self::FailedQuorum | Self::TaskFailed | Self::TimedOut => {
                u32::MAX
            }
            Self::NeverRetry => 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum WithdrawalApprovalError {
    #[error("Screener service error: {0}")]
    AmlServiceError(#[source] anyhow::Error),

    #[error("Never retry: {0}")]
    NeverRetry(#[source] anyhow::Error),
}

impl WithdrawalApprovalError {
    pub fn kind(&self) -> WithdrawalApprovalErrorKind {
        match self {
            Self::AmlServiceError(_) => WithdrawalApprovalErrorKind::AmlServiceError,
            Self::NeverRetry(_) => WithdrawalApprovalErrorKind::NeverRetry,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WithdrawalCommitmentErrorKind {
    BtcTxBuildFailed,
    FailedQuorum,
    FeeEstimateFailed,
    UtxoSelectionFailed,
    TimedOut,
    TaskFailed,
}

impl RetryPolicy for WithdrawalCommitmentErrorKind {
    fn retry_base_delay_ms(self) -> u64 {
        5 * 1000
    }

    fn max_delay_ms(self) -> u64 {
        60 * 1000
    }

    fn max_retries(self) -> u32 {
        u32::MAX
    }
}

#[derive(Debug, Error)]
pub enum WithdrawalCommitmentError {
    #[error("BTC tx build failed: {0}")]
    BtcTxBuildFailed(#[source] anyhow::Error),

    #[error("Fee estimate failed: {0}")]
    FeeEstimateFailed(#[source] anyhow::Error),

    #[error("UTXO selection failed: {0}")]
    UtxoSelectionFailed(#[source] anyhow::Error),
}

impl WithdrawalCommitmentError {
    pub fn kind(&self) -> WithdrawalCommitmentErrorKind {
        match self {
            Self::BtcTxBuildFailed(_) => WithdrawalCommitmentErrorKind::BtcTxBuildFailed,
            Self::FeeEstimateFailed(_) => WithdrawalCommitmentErrorKind::FeeEstimateFailed,
            Self::UtxoSelectionFailed(_) => WithdrawalCommitmentErrorKind::UtxoSelectionFailed,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WithdrawalBroadcastErrorKind {
    BitcoinRpc,
    SuiConfirmation,
    TaskFailed,
}

impl RetryPolicy for WithdrawalBroadcastErrorKind {
    fn retry_base_delay_ms(self) -> u64 {
        30 * 1000
    }

    fn max_delay_ms(self) -> u64 {
        10 * 60 * 1000
    }

    fn max_retries(self) -> u32 {
        u32::MAX
    }
}

#[derive(Debug, Error)]
#[error("{kind:?}: {source}")]
pub struct WithdrawalBroadcastError {
    kind: WithdrawalBroadcastErrorKind,
    #[source]
    source: anyhow::Error,
}

impl WithdrawalBroadcastError {
    pub fn new(kind: WithdrawalBroadcastErrorKind, source: anyhow::Error) -> Self {
        Self { kind, source }
    }

    pub fn kind(&self) -> WithdrawalBroadcastErrorKind {
        self.kind
    }
}

fn withdrawal_input_signing_id(withdrawal_txn_id: &Address, input_index: u32) -> Address {
    let bytes =
        bcs::to_bytes(&(withdrawal_txn_id, input_index)).expect("serialization should succeed");
    Address::new(Blake2b256::digest(&bytes).digest)
}

/// Query Bitcoin in parallel for the confirmation count of every pending
/// withdrawal transaction. Returns a map from withdrawal ID to confirmation
/// count. Withdrawals that are in the mempool, not found, or whose RPC call
/// fails are mapped to 0 (treated as unconfirmed).
async fn fetch_withdrawal_tx_confirmations(
    hashi: &Hashi,
    withdrawal_txns: &BTreeMap<Address, WithdrawalTransaction>,
) -> HashMap<Address, u32> {
    let futures: Vec<_> = withdrawal_txns
        .iter()
        .map(|(id, txn)| async {
            let btc_txid = txn.txid.into();
            let confs = match hashi.btc_monitor().get_transaction_status(btc_txid).await {
                Ok(TxStatus::Confirmed { confirmations }) => confirmations,
                // Mempool, not found, or RPC error — treat as unconfirmed.
                _ => 0,
            };
            (*id, confs)
        })
        .collect();
    futures::future::join_all(futures)
        .await
        .into_iter()
        .collect()
}

/// Build the [`UtxoStatus`] for a UTXO record using a pre-fetched snapshot.
///
/// For confirmed UTXOs (`produced_by = None`) this is simply
/// [`UtxoStatus::Confirmed`]. For unconfirmed change outputs
/// (`produced_by = Some(withdrawal_id)`) we walk the full ancestor chain
/// so that CPFP weight and mempool depth are accurately computed even for
/// multi-level chains. If the producing withdrawal has already been removed
/// from `withdrawal_txns` (confirmed and cleared), we promote the UTXO
/// to `Confirmed` — it is safe to spend immediately.
fn build_utxo_status(
    hashi: &Hashi,
    record: &UtxoRecord,
    withdrawal_txns: &BTreeMap<Address, WithdrawalTransaction>,
    tx_confirmations: &HashMap<Address, u32>,
    utxo_records: &BTreeMap<UtxoId, UtxoRecord>,
) -> UtxoStatus {
    let Some(producing_id) = record.produced_by else {
        return UtxoStatus::Confirmed;
    };

    let chain = build_ancestor_chain(
        hashi,
        producing_id,
        withdrawal_txns,
        tx_confirmations,
        utxo_records,
    );

    if chain.is_empty() {
        // The producing withdrawal was confirmed and removed from
        // withdrawal_txns. The UTXO is safe to spend.
        UtxoStatus::Confirmed
    } else {
        UtxoStatus::Pending { chain }
    }
}

/// Maximum ancestor depth permitted by Bitcoin Core's relay policy
/// (`DEFAULT_ANCESTOR_LIMIT = 25`). Bitcoin Core counts the candidate
/// transaction itself in the ancestor set, so a UTXO whose existing
/// unconfirmed ancestor depth is already `MAX_ANCESTOR_DEPTH - 1` is
/// the deepest we can safely spend.
pub const MAX_ANCESTOR_DEPTH: usize = 25;

/// Count the number of unconfirmed ancestors for a UTXO record by walking
/// the `produced_by` chain. Every ancestor that still appears in
/// `withdrawal_txns` is conservatively treated as unconfirmed (we skip
/// querying Bitcoin for actual confirmation counts). This is used during
/// commitment validation to reject UTXOs whose ancestor chain would exceed
/// Bitcoin Core's relay limit.
///
/// The walk is a BFS over the ancestor DAG. Each item on the queue is a
/// `(producing_withdrawal_id, depth)` pair. We track the maximum depth
/// seen across all branches.
fn unconfirmed_ancestor_depth(
    record: &UtxoRecord,
    withdrawal_txns: &BTreeMap<Address, WithdrawalTransaction>,
    utxo_records: &BTreeMap<UtxoId, UtxoRecord>,
) -> usize {
    let Some(producing_id) = record.produced_by else {
        return 0;
    };

    let mut max_depth: usize = 0;
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((producing_id, 1usize));

    while let Some((wid, depth)) = queue.pop_front() {
        if depth > MAX_ANCESTOR_DEPTH {
            return depth;
        }

        let Some(txn) = withdrawal_txns.get(&wid) else {
            // The producing withdrawal has been confirmed and removed;
            // it does not contribute to the unconfirmed chain.
            continue;
        };

        max_depth = std::cmp::max(max_depth, depth);

        // Enqueue any inputs that are themselves unconfirmed change
        // outputs of an earlier withdrawal.
        for input_utxo in &txn.inputs {
            if let Some(input_record) = utxo_records.get(&input_utxo.id)
                && let Some(parent_id) = input_record.produced_by
            {
                queue.push_back((parent_id, depth + 1));
            }
        }
    }

    max_depth
}

/// Build the ancestor chain for a UTXO produced by `producing_id`. Each
/// unconfirmed ancestor that still appears in `withdrawal_txns` gets
/// one [`AncestorTx`] entry with its confirmation count, weight, and fee.
/// The walk is a BFS over the ancestor DAG, capped at
/// [`MAX_ANCESTOR_DEPTH`] levels.
fn build_ancestor_chain(
    hashi: &Hashi,
    producing_id: Address,
    withdrawal_txns: &BTreeMap<Address, WithdrawalTransaction>,
    tx_confirmations: &HashMap<Address, u32>,
    utxo_records: &BTreeMap<UtxoId, UtxoRecord>,
) -> Vec<AncestorTx> {
    let mut chain = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((producing_id, 0usize));

    while let Some((wid, depth)) = queue.pop_front() {
        if depth >= MAX_ANCESTOR_DEPTH {
            continue;
        }

        let Some(txn) = withdrawal_txns.get(&wid) else {
            continue;
        };

        let Ok(tx) = hashi.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs()) else {
            continue;
        };

        let confirmations = tx_confirmations.get(&wid).copied().unwrap_or(0);
        let input_total: u64 = txn.inputs.iter().map(|u| u.amount).sum();
        let output_total: u64 = txn.all_outputs().iter().map(|o| o.amount).sum();

        chain.push(AncestorTx {
            confirmations,
            tx_weight: tx.weight(),
            tx_fee: input_total.saturating_sub(output_total),
        });

        for input_utxo in &txn.inputs {
            if let Some(input_record) = utxo_records.get(&input_utxo.id)
                && let Some(parent_id) = input_record.produced_by
            {
                queue.push_back((parent_id, depth + 1));
            }
        }
    }

    chain
}

/// Deterministic from on-chain state and the leader-supplied
/// `(timestamp_secs, seq)`, so every validator reconstructs the same request.
pub fn build_guardian_withdrawal_request(
    hashi: &Hashi,
    txn: &WithdrawalTransaction,
    timestamp_secs: u64,
    seq: u64,
) -> anyhow::Result<hashi_types::guardian::StandardWithdrawalRequest> {
    use hashi_types::bitcoin::InputUTXO;
    use hashi_types::bitcoin::OutputUTXOWire;
    use hashi_types::bitcoin::TxUTXOs;

    let network = hashi.config.bitcoin_network();

    let inputs: Vec<_> = txn.inputs.iter().map(InputUTXO::from).collect();

    // First N outputs are external payouts; any trailing output is internal change.
    let all_outputs = txn.all_outputs();
    let num_requests = txn.request_ids.len();
    let outputs = all_outputs
        .iter()
        .enumerate()
        .map(|(i, output)| {
            if i < num_requests {
                let script_pubkey =
                    hashi_bitcoin::script_pubkey_from_witness_program(&output.bitcoin_address)?;
                let address =
                    hashi_bitcoin::BitcoinAddress::from_script(&script_pubkey, network)
                        .map_err(|e| anyhow!("Cannot derive address from output script: {e}"))?;
                Ok(OutputUTXOWire::external(
                    address.into_unchecked(),
                    Amount::from_sat(output.amount),
                ))
            } else {
                Ok(OutputUTXOWire::internal(
                    sui_sdk_types::Address::ZERO,
                    Amount::from_sat(output.amount),
                ))
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let utxos = TxUTXOs::new(inputs, outputs, network)
        .map_err(|e| anyhow!("Failed to build guardian TxUTXOs: {e}"))?;

    // The on-chain `WithdrawalTransaction` UID doubles as the guardian-side `wid`.
    let wid: hashi_types::guardian::WithdrawalID = txn.id;

    Ok(hashi_types::guardian::StandardWithdrawalRequest::new(
        wid,
        utxos,
        timestamp_secs,
        seq,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onchain::types::OutputUtxo;
    use crate::onchain::types::Utxo;
    use crate::onchain::types::UtxoId;
    use crate::utxo_pool::CoinSelectionParams;
    use hashi_types::bitcoin_txid::BitcoinTxid;

    fn input(amount: u64) -> Utxo {
        Utxo {
            id: UtxoId {
                txid: BitcoinTxid::ZERO,
                vout: 0,
            },
            amount,
            derivation_path: None,
        }
    }

    fn output(amount: u64) -> OutputUtxo {
        OutputUtxo {
            amount,
            bitcoin_address: vec![0; 32],
        }
    }

    fn make_txn(
        inputs: Vec<u64>,
        withdrawal_outputs: Vec<u64>,
        change: Vec<u64>,
    ) -> WithdrawalTransaction {
        let num_inputs = inputs.len() as u64;
        WithdrawalTransaction {
            id: Address::ZERO,
            txid: BitcoinTxid::ZERO,
            request_ids: vec![],
            inputs: inputs.into_iter().map(input).collect(),
            withdrawal_outputs: withdrawal_outputs.into_iter().map(output).collect(),
            change_outputs: change.into_iter().map(output).collect(),
            created_timestamp_ms: 0,
            signed_timestamp_ms: None,
            confirmed_timestamp_ms: None,
            randomness: vec![],
            signing: hashi_types::move_types::SigningBatch {
                signatures: (0..num_inputs)
                    .map(hashi_types::move_types::MpcSig::Pending)
                    .collect(),
                epoch: 0,
            },
            guardian_signatures: None,
        }
    }

    fn signing(
        signatures: Vec<hashi_types::move_types::MpcSig>,
    ) -> hashi_types::move_types::SigningBatch {
        hashi_types::move_types::SigningBatch {
            signatures,
            epoch: 7,
        }
    }

    #[test]
    fn requested_signing_indices_empty_request_defaults_to_unsigned_inputs() {
        let signing = signing(vec![
            hashi_types::move_types::MpcSig::Pending(10),
            hashi_types::move_types::MpcSig::Signed(vec![1; 64]),
            hashi_types::move_types::MpcSig::Pending(12),
        ]);

        let selected = select_withdrawal_signing_indices(&signing, &[]).unwrap();

        assert_eq!(selected, vec![0, 2]);
    }

    #[test]
    fn requested_signing_indices_accepts_pending_subset() {
        let signing = signing(vec![
            hashi_types::move_types::MpcSig::Pending(10),
            hashi_types::move_types::MpcSig::Signed(vec![1; 64]),
            hashi_types::move_types::MpcSig::Pending(12),
        ]);

        let selected = select_withdrawal_signing_indices(&signing, &[2]).unwrap();

        assert_eq!(selected, vec![2]);
    }

    #[test]
    fn requested_signing_indices_rejects_duplicate_indices() {
        let signing = signing(vec![
            hashi_types::move_types::MpcSig::Pending(10),
            hashi_types::move_types::MpcSig::Pending(11),
        ]);

        let err = select_withdrawal_signing_indices(&signing, &[1, 1]).unwrap_err();

        assert!(err.to_string().contains("duplicate input index 1"));
    }

    #[test]
    fn requested_signing_indices_rejects_already_signed_indices() {
        let signing = signing(vec![
            hashi_types::move_types::MpcSig::Pending(10),
            hashi_types::move_types::MpcSig::Signed(vec![1; 64]),
        ]);

        let err = select_withdrawal_signing_indices(&signing, &[1]).unwrap_err();

        assert!(err.to_string().contains("input index 1 is already signed"));
    }

    #[test]
    fn requested_signing_indices_rejects_out_of_range_indices() {
        let signing = signing(vec![hashi_types::move_types::MpcSig::Pending(10)]);

        let err = select_withdrawal_signing_indices(&signing, &[1]).unwrap_err();

        assert!(err.to_string().contains("input index 1 out of range"));
    }

    #[test]
    fn consumption_amount_no_change() {
        // 1_000 input, 950 to user, 50 fee, no change.
        let txn = make_txn(vec![1_000], vec![950], vec![]);
        assert_eq!(withdrawal_limiter_consumption_amount(&txn), 1_000);
    }

    #[test]
    fn consumption_amount_with_change() {
        // 10_000 input, 7_000 to user, 50 fee, 2_950 change.
        let txn = make_txn(vec![10_000], vec![7_000], vec![2_950]);
        assert_eq!(withdrawal_limiter_consumption_amount(&txn), 7_050);
    }

    #[test]
    fn consumption_amount_multi_input_multi_output() {
        // Two inputs: 6_000 + 4_000. Three users: 2_000 + 1_500 + 5_500. Fee 100, change 900.
        let txn = make_txn(vec![6_000, 4_000], vec![2_000, 1_500, 5_500], vec![900]);
        let expected = 10_000 - 900; // inputs - change
        let by_outputs = 9_000 + 100; // user_outputs + fee
        assert_eq!(expected, by_outputs);
        assert_eq!(withdrawal_limiter_consumption_amount(&txn), expected);
    }

    #[test]
    fn consumption_amount_multiple_change() {
        // 10_000 input, 3_000 to user, two change outputs (2_000 + 4_900), fee 100.
        let txn = make_txn(vec![10_000], vec![3_000], vec![2_000, 4_900]);
        let expected = 10_000 - 6_900; // inputs - total change
        let by_outputs = 3_000 + 100; // user_output + fee
        assert_eq!(expected, by_outputs);
        assert_eq!(withdrawal_limiter_consumption_amount(&txn), expected);
    }

    #[test]
    fn consumption_amount_no_inputs_returns_zero() {
        let txn = make_txn(vec![], vec![], vec![]);
        assert_eq!(withdrawal_limiter_consumption_amount(&txn), 0);
    }

    #[test]
    fn withdrawal_flow_budget_at_absolute_cap() {
        assert_eq!(CoinSelectionParams::MAX_WITHDRAWAL_REQUESTS, 70);
        assert_eq!(
            safe_withdrawal_commit_max_inputs(70, 700),
            700,
            "70 requests × 10 inputs = 700, exactly fits the 922 commit budget",
        );
        assert_eq!(
            safe_withdrawal_flow_max_inputs(70, 700),
            700,
            "commit and per-request budgets align at 70 requests / 700 inputs",
        );
    }

    #[test]
    fn withdrawal_flow_budget_scales_inputs_with_request_count() {
        assert_eq!(
            safe_withdrawal_flow_max_inputs(10, CoinSelectionParams::DEFAULT_MAX_INPUTS),
            10 * CoinSelectionParams::DEFAULT_INPUT_BUDGET,
            "at low request counts, the per-request input budget is binding",
        );
    }

    #[test]
    fn withdrawal_flow_budget_at_default_batch_size() {
        assert_eq!(
            safe_withdrawal_flow_max_inputs(50, CoinSelectionParams::DEFAULT_MAX_INPUTS),
            500,
            "50 requests × 10 inputs/request = 500, per-request budget is binding",
        );
    }
}
