// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use bitcoin::Address as BitcoinAddress;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::TxOut;
use bitcoin::Weight;
use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use bitcoin::hashes::Hash;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::TapLeafHash;
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::hash::Blake2b256;
use fastcrypto::hash::HashFunction;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::S;
use hashi_types::bitcoin_txid::BitcoinTxid;
use hashi_types::guardian::bitcoin_utils;
use std::collections::BTreeMap;
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

/// Full input weight (WU) for a 2-of-2 taproot script-path spend.
/// TXIN_BASE_WEIGHT (164 WU) + satisfaction (234 WU) = 398 WU (100 vB).
/// Used in fee validation where we calculate weight directly without
/// going through Candidate::new().
const SCRIPT_PATH_2OF2_TXIN_WEIGHT: u64 = 164 + 234;

/// Non-witness fixed overhead for a segwit transaction:
/// nVersion(4×4) + nLockTime(4×4) = 32 WU, plus the segwit marker/flag (2 WU).
const TX_FIXED_WEIGHT_WU: u64 = 34;

/// P2TR output weight: TXOUT_BASE(36) + OP_1 OP_PUSHBYTES_32 <32 bytes>(136) = 172 WU.
const P2TR_OUTPUT_WEIGHT_WU: u64 = 172;

/// P2WPKH output weight: TXOUT_BASE(36) + OP_0 OP_PUSHBYTES_20 <20 bytes>(88) = 124 WU.
const P2WPKH_OUTPUT_WEIGHT_WU: u64 = 124;

/// The data that validators BLS-sign over to approve a single withdrawal request.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalRequestApproval {
    pub request_id: Address,
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

/// The data that validators BLS-sign over to store witness signatures on-chain.
/// This is the step 3 certificate.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalTxSigning {
    pub withdrawal_id: Address,
    pub request_ids: Vec<Address>,
    pub signatures: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalConfirmation {
    pub withdrawal_id: Address,
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

        // 3. Verify output count: one per request, plus at most one change output
        let request_count = requests.len();
        let output_count = approval.outputs.len();
        anyhow::ensure!(
            output_count == request_count || output_count == request_count + 1,
            "Expected {} or {} outputs, got {}",
            request_count,
            request_count + 1,
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

        // 5. Verify change output (if present) goes to hashi root pubkey
        if output_count == request_count + 1 {
            let change_output = &approval.outputs[request_count];
            let hashi_pubkey = self.get_hashi_pubkey()?;
            let expected_address =
                witness_program_from_address(&self.get_deposit_address(&hashi_pubkey, None)?)?;
            anyhow::ensure!(
                change_output.bitcoin_address == expected_address,
                "Change output does not go to hashi root pubkey"
            );
            anyhow::ensure!(
                change_output.amount >= utxo_pool::TR_DUST_RELAY_MIN_VALUE,
                "Change output {} sats is below dust threshold {} sats",
                change_output.amount,
                utxo_pool::TR_DUST_RELAY_MIN_VALUE
            );
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
            let input_weight = SCRIPT_PATH_2OF2_TXIN_WEIGHT * num_inputs;
            let output_weight: u64 = approval
                .outputs
                .iter()
                .map(|o| output_weight_for_address(&o.bitcoin_address))
                .collect::<anyhow::Result<Vec<_>>>()?
                .iter()
                .sum();
            let tx_weight = Weight::from_wu(TX_FIXED_WEIGHT_WU + input_weight + output_weight);

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

    // --- Step 3: Sign withdrawal (store witness signatures on-chain) ---

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_id = %message.withdrawal_id))]
    pub fn validate_and_sign_withdrawal_tx_signing(
        &self,
        message: &WithdrawalTxSigning,
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
            txn.signatures.is_none(),
            "WithdrawalTransaction {} is already signed",
            message.withdrawal_id
        );

        anyhow::ensure!(
            message.request_ids == txn.request_ids,
            "Request IDs mismatch for WithdrawalTransaction {}",
            message.withdrawal_id
        );

        anyhow::ensure!(
            message.signatures.len() == txn.inputs.len(),
            "Signature count ({}) does not match input count ({}) for WithdrawalTransaction {}",
            message.signatures.len(),
            txn.inputs.len(),
            message.withdrawal_id
        );

        let tx = self.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())?;
        let signing_messages = self.withdrawal_signing_messages(&tx, &txn.inputs)?;
        let hashi_pubkey = self.get_hashi_pubkey()?;

        for (i, (sig_bytes, sighash)) in message
            .signatures
            .iter()
            .zip(signing_messages.iter())
            .enumerate()
        {
            let arr: &[u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "Signature {i} is not 64 bytes for WithdrawalTransaction {}",
                    message.withdrawal_id
                )
            })?;
            let sig = SchnorrSignature::from_byte_array(arr)
                .map_err(|e| anyhow!("Invalid Schnorr signature at input {i}: {e}"))?;

            let input_pubkey =
                self.deposit_pubkey(&hashi_pubkey, txn.inputs[i].derivation_path.as_ref())?;
            let schnorr_pk = SchnorrPublicKey::from_byte_array(&input_pubkey.serialize())
                .map_err(|e| anyhow!("Failed to convert pubkey for input {i}: {e}"))?;

            schnorr_pk
                .verify(sighash, &sig)
                .map_err(|e| anyhow!("Signature verification failed for input {i}: {e}"))?;
        }

        self.sign_message_proto(message)
    }

    // --- Generic BLS signing helper ---

    /// Proto-format BLS signing helper for gRPC responses.
    fn sign_message_proto<T: serde::Serialize>(
        &self,
        message: &T,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        let epoch = self.onchain_state().epoch();
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

    // --- MPC BTC tx signing ---

    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %withdrawal_txn_id))]
    pub async fn validate_and_sign_withdrawal_tx(
        &self,
        withdrawal_txn_id: &Address,
    ) -> anyhow::Result<Vec<SchnorrSignature>> {
        let (txn, unsigned_tx) = self.validate_withdrawal_signing(withdrawal_txn_id).await?;
        self.mpc_sign_withdrawal_tx(&txn, &unsigned_tx).await
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
        txn: &crate::onchain::types::WithdrawalTransaction,
        unsigned_tx: &bitcoin::Transaction,
    ) -> anyhow::Result<Vec<SchnorrSignature>> {
        let onchain_state = self.onchain_state().clone();
        let epoch = onchain_state.epoch();
        if txn.epoch != epoch {
            anyhow::bail!(
                "Stale presig assignment: pending withdrawal {} has epoch {}, current is {}. \
                 Either the leader hasn't called allocate_presigs_for_withdrawal_txn yet, \
                 or this node's on-chain state is behind.",
                txn.id,
                txn.epoch,
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
        let mut signatures_by_input = Vec::with_capacity(signing_messages.len());
        for (input_index, message) in signing_messages.iter().enumerate() {
            let request_id = withdrawal_input_signing_request_id(&txn.id, input_index as u32);
            let derivation_address = txn
                .inputs
                .get(input_index)
                .and_then(|input| input.derivation_path.as_ref().map(|path| path.into_inner()));
            let sign_start = std::time::Instant::now();
            let global_presig_index = txn.presig_start_index + input_index as u64;
            let sign_result = signing_manager
                .sign(
                    &p2p_channel,
                    request_id,
                    message,
                    global_presig_index,
                    &beacon,
                    derivation_address.as_ref(),
                    WITHDRAWAL_SIGNING_TIMEOUT,
                    &self.metrics,
                )
                .await;
            let sign_duration = sign_start.elapsed().as_secs_f64();

            match &sign_result {
                Ok(_) => {
                    self.metrics
                        .mpc_sign_duration_seconds
                        .with_label_values(&["success"])
                        .observe(sign_duration);
                    self.metrics
                        .presig_pool_remaining
                        .set(signing_manager.presignatures_remaining() as i64);
                }
                Err(e) => {
                    self.metrics
                        .mpc_sign_duration_seconds
                        .with_label_values(&["failure"])
                        .observe(sign_duration);
                    let reason = match e {
                        crate::mpc::types::SigningError::Timeout { .. } => "timeout",
                        crate::mpc::types::SigningError::PoolExhausted => "pool_exhausted",
                        crate::mpc::types::SigningError::TooManyInvalidSignatures { .. } => {
                            "too_many_invalid"
                        }
                        crate::mpc::types::SigningError::CryptoError(_) => "crypto_error",
                        _ => "other",
                    };
                    self.metrics
                        .mpc_sign_failures_total
                        .with_label_values(&[reason])
                        .inc();
                }
            }

            let signature = sign_result.map_err(|e| {
                anyhow!("Failed to sign withdrawal transaction input {input_index}: {e}")
            })?;

            signatures_by_input.push(signature);
        }
        Ok(signatures_by_input)
    }

    pub(crate) fn withdrawal_signing_messages(
        &self,
        unsigned_tx: &bitcoin::Transaction,
        inputs: &[Utxo],
    ) -> anyhow::Result<Vec<[u8; 32]>> {
        let hashi_pubkey = self.get_hashi_pubkey()?;
        let spend_inputs = inputs
            .iter()
            .map(|input| {
                let pubkey = self.deposit_pubkey(&hashi_pubkey, input.derivation_path.as_ref())?;
                let address = self.bitcoin_address_from_pubkey(&pubkey);
                let (_, _, leaf_hash) =
                    bitcoin_utils::single_key_taproot_script_path_spend_artifacts(&pubkey);
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

        (0..inputs.len())
            .map(|input_index| {
                let mut sighasher = SighashCache::new(unsigned_tx);
                let sighash = sighasher
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &Prevouts::All(&prevouts),
                        leaf_hashes[input_index],
                        TapSighashType::Default,
                    )
                    .map_err(|e| {
                        anyhow!("Failed to construct taproot script spend sighash: {e}")
                    })?;
                Ok(*sighash.as_byte_array())
            })
            .collect()
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
            .map(|utxo| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: utxo.id.txid.into(),
                    vout: utxo.id.vout,
                },
                script_sig: bitcoin::ScriptBuf::default(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::default(),
            })
            .collect();

        let tx_outputs: Vec<bitcoin::TxOut> = outputs
            .iter()
            .map(|output| {
                let script_pubkey = script_pubkey_from_raw_address(&output.bitcoin_address)
                    .expect("invalid bitcoin address in output");
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(output.amount),
                    script_pubkey,
                }
            })
            .collect();

        Ok(bitcoin_utils::construct_tx(inputs, tx_outputs))
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

        let hashi_pubkey = self
            .get_hashi_pubkey()
            .map_err(WithdrawalCommitmentError::BtcTxBuildFailed)?;
        let change_address = self
            .get_deposit_address(&hashi_pubkey, None)
            .map_err(WithdrawalCommitmentError::BtcTxBuildFailed)?;

        // Build coin selection parameters from on-chain config. Override
        // max_fee_per_request to match the Move contract's worst-case cap,
        // and max_withdrawal_requests to honour the leader's configured
        // batch cap.
        let params = CoinSelectionParams {
            max_fee_per_request: self.onchain_state().worst_case_network_fee(),
            max_withdrawal_requests: self.config.withdrawal_max_batch_size(),
            max_mempool_chain_depth: self.config.max_mempool_chain_depth(),
            ..CoinSelectionParams::new(change_address.clone())
        };

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
                timestamp_ms: r.timestamp_ms,
            })
            .collect();

        let result = utxo_pool::select_coins(&candidates, &mapped_requests, &params, fee_rate)
            .map_err(|e| WithdrawalCommitmentError::UtxoSelectionFailed(anyhow!(e)))?;

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
                bitcoin_address: witness_program_from_address(&change_address)
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
        let destination_address = self
            .bitcoin_address_string_from_raw(&request.bitcoin_address)
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

    /// Convert raw witness program bytes to a human-readable Bitcoin address string.
    fn bitcoin_address_string_from_raw(&self, address_bytes: &[u8]) -> anyhow::Result<String> {
        let version = match address_bytes.len() {
            32 => WitnessVersion::V1,
            20 => WitnessVersion::V0,
            len => anyhow::bail!("Unsupported bitcoin address length: {len}"),
        };
        let program = WitnessProgram::new(version, address_bytes)
            .map_err(|e| anyhow!("Invalid witness program: {e}"))?;
        let script = bitcoin::ScriptBuf::new_witness_program(&program);
        let address = bitcoin::Address::from_script(&script, self.config.bitcoin_network())
            .map_err(|e| anyhow!("Failed to convert script to address: {e}"))?;
        Ok(address.to_string())
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

pub fn witness_program_from_address(address: &BitcoinAddress) -> anyhow::Result<Vec<u8>> {
    let script = address.script_pubkey();
    let bytes = script.as_bytes();
    match bytes {
        [0x00, 0x14, rest @ ..] if rest.len() == 20 => Ok(rest.to_vec()),
        [0x51, 0x20, rest @ ..] if rest.len() == 32 => Ok(rest.to_vec()),
        _ => anyhow::bail!("Unsupported script pubkey for withdrawal output: {script}"),
    }
}

fn output_weight_for_address(bitcoin_address: &[u8]) -> anyhow::Result<u64> {
    match bitcoin_address.len() {
        32 => Ok(P2TR_OUTPUT_WEIGHT_WU),
        20 => Ok(P2WPKH_OUTPUT_WEIGHT_WU),
        len => anyhow::bail!("Unsupported bitcoin address length: {len}"),
    }
}

fn withdrawal_input_signing_request_id(withdrawal_txn_id: &Address, input_index: u32) -> Address {
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

/// Convert raw bitcoin address bytes (witness program) to a `ScriptBuf`.
/// 32-byte addresses are P2TR (witness v1), 20-byte addresses are P2WPKH (witness v0).
fn script_pubkey_from_raw_address(address_bytes: &[u8]) -> anyhow::Result<bitcoin::ScriptBuf> {
    let version = match address_bytes.len() {
        32 => WitnessVersion::V1,
        20 => WitnessVersion::V0,
        len => anyhow::bail!("Unsupported bitcoin address length: {len}"),
    };
    let program = WitnessProgram::new(version, address_bytes)
        .map_err(|e| anyhow!("Invalid witness program: {e}"))?;
    Ok(bitcoin::ScriptBuf::new_witness_program(&program))
}
