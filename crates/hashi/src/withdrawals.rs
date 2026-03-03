use anyhow::anyhow;
use bdk_coin_select::Candidate;
use bdk_coin_select::ChangePolicy;
use bdk_coin_select::CoinSelector;
use bdk_coin_select::DrainWeights;
use bdk_coin_select::FeeRate;
use bdk_coin_select::TR_DUST_RELAY_MIN_VALUE;
use bdk_coin_select::Target;
use bdk_coin_select::TargetFee;
use bdk_coin_select::TargetOutputs;
use bdk_coin_select::metrics::LowestFee;
use bitcoin::Address as BitcoinAddress;
use bitcoin::Amount;
use bitcoin::TxOut;
use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use bitcoin::hashes::Hash;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::sighash::TapSighashType;
use bitcoin::taproot::TapLeafHash;
use fastcrypto::groups::GroupElement;
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::S;
use hashi_types::guardian::bitcoin_utils;
use std::time::Duration;
use sui_sdk_types::Address;

use crate::Hashi;
use crate::mpc::SigningManager;
use crate::mpc::rpc::RpcP2PChannel;
use crate::onchain::types::OutputUtxo;
use crate::onchain::types::Utxo;
use crate::onchain::types::UtxoId;
use crate::onchain::types::WithdrawalRequest;

const WITHDRAWAL_SIGNING_TIMEOUT: Duration = Duration::from_secs(5);

/// Default confirmation target for fee estimation (3 blocks ~ 30 minutes).
const WITHDRAWAL_FEE_CONF_TARGET: u16 = 3;

/// Fee rate tolerance multiplier for validation.
const FEE_RATE_TOLERANCE_MULTIPLIER: u64 = 3;

/// Long-term fee rate (10 sat/vB). Used for the waste metric when evaluating
/// whether to create a change output vs. paying a slightly higher fee.
const LONG_TERM_FEE_RATE_SAT_PER_VB: f32 = 10.0;

/// Maximum BnB iterations before falling back to greedy selection.
const BNB_MAX_ROUNDS: usize = 1_000;

pub struct UtxoSelection {
    pub selected_utxos: Vec<Utxo>,
    pub fee: u64,
    pub change: Option<u64>,
}

/// The data that validators BLS-sign over to approve a single withdrawal request.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct RequestApproval {
    pub request_id: Address,
}

/// The data that validators BLS-sign over to commit to a withdrawal transaction.
/// This is the step 2 certificate with UTXO selection and tx construction.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalTxCommitment {
    pub request_ids: Vec<Address>,
    pub selected_utxos: Vec<UtxoId>,
    pub outputs: Vec<OutputUtxo>,
    pub txid: Address,
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

    pub fn validate_and_sign_request_approval(
        &self,
        approval: &RequestApproval,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        let request = self
            .onchain_state()
            .withdrawal_request(&approval.request_id)
            .ok_or_else(|| {
                anyhow!(
                    "Withdrawal request {} not found in queue",
                    approval.request_id
                )
            })?;
        anyhow::ensure!(
            !request.approved,
            "Withdrawal request {} is already approved",
            approval.request_id
        );

        self.sign_message_proto(&approval)
    }

    // --- Step 2: Construction approval (with UTXO selection) ---

    pub async fn validate_and_sign_withdrawal_tx_commitment(
        &self,
        approval: &WithdrawalTxCommitment,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        self.validate_withdrawal_tx_commitment(approval).await?;
        self.sign_withdrawal_tx_commitment(approval)
    }

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
                    request.approved,
                    "Withdrawal request {id} has not been approved"
                );
                Ok(request)
            })
            .collect::<anyhow::Result<_>>()?;

        // 1b. Screen each withdrawal request for AML/sanctions
        for request in &requests {
            self.screen_withdrawal(request).await?;
        }

        // 2. Verify each selected UTXO exists and collect full UTXO data
        let selected_utxos: Vec<Utxo> = approval
            .selected_utxos
            .iter()
            .map(|id| {
                self.onchain_state()
                    .active_utxo(id)
                    .ok_or_else(|| anyhow!("UTXO {id:?} not found in active pool"))
            })
            .collect::<anyhow::Result<_>>()?;

        // 3. Verify each withdrawal request has a matching output
        for request in &requests {
            let has_matching_output = approval.outputs.iter().any(|output| {
                output.amount == request.btc_amount
                    && output.bitcoin_address == request.bitcoin_address
            });
            anyhow::ensure!(
                has_matching_output,
                "No matching output for withdrawal request {:?}",
                request.id
            );
        }

        // 4. Verify change output goes to hashi root pubkey (if present)
        let non_request_outputs: Vec<&OutputUtxo> = approval
            .outputs
            .iter()
            .filter(|output| {
                !requests.iter().any(|r| {
                    output.amount == r.btc_amount && output.bitcoin_address == r.bitcoin_address
                })
            })
            .collect();
        anyhow::ensure!(
            non_request_outputs.len() <= 1,
            "Expected at most 1 change output, found {}",
            non_request_outputs.len()
        );
        if let Some(change_output) = non_request_outputs.first() {
            let hashi_pubkey = self.get_hashi_pubkey();
            let expected_address =
                witness_program_from_address(&self.get_deposit_address(&hashi_pubkey, None)?)?;
            anyhow::ensure!(
                change_output.bitcoin_address == expected_address,
                "Change output does not go to hashi root pubkey"
            );
        }

        // 5. Verify inputs >= outputs (positive fee)
        let input_total: u64 = selected_utxos.iter().map(|u| u.amount).sum();
        let output_total: u64 = approval.outputs.iter().map(|o| o.amount).sum();
        anyhow::ensure!(
            input_total >= output_total,
            "Inputs ({input_total}) < outputs ({output_total})"
        );
        let fee = input_total - output_total;

        // 5a. Validate fee is reasonable
        {
            // Estimate transaction weight
            let num_inputs = selected_utxos.len() as u64;
            let input_weight = bdk_coin_select::TR_KEYSPEND_TXIN_WEIGHT * num_inputs;
            let output_weight: u64 = approval
                .outputs
                .iter()
                .map(|o| output_weight_for_address(&o.bitcoin_address))
                .collect::<anyhow::Result<Vec<_>>>()?
                .iter()
                .sum();
            let tx_weight =
                bdk_coin_select::TX_FIXED_FIELD_WEIGHT + input_weight + output_weight + 2; // +2 for segwit marker/flag

            // Fee must be at least the minimum relay fee (1 sat/vB)
            let min_fee_rate = FeeRate::from_sat_per_vb(1.0);
            let min_fee = min_fee_rate.implied_fee(tx_weight);
            anyhow::ensure!(
                fee >= min_fee,
                "Fee {fee} sats is below minimum relay fee {min_fee} sats"
            );

            // Fee must not exceed FEE_RATE_TOLERANCE_MULTIPLIER x our own estimate
            let kyoto_fee_rate = self
                .btc_monitor()
                .get_recent_fee_rate(WITHDRAWAL_FEE_CONF_TARGET)
                .await?;
            let our_fee_rate =
                FeeRate::from_sat_per_wu(kyoto_fee_rate.to_sat_per_kwu() as f32 / 1000.0);
            let our_estimated_fee = our_fee_rate.implied_fee(tx_weight);
            let max_fee = our_estimated_fee.saturating_mul(FEE_RATE_TOLERANCE_MULTIPLIER);
            anyhow::ensure!(
                fee <= max_fee,
                "Fee {fee} sats exceeds maximum allowed {max_fee} sats \
                 ({FEE_RATE_TOLERANCE_MULTIPLIER}x our estimate of {our_estimated_fee} sats)"
            );
        }

        // 5b. Validate change output is above dust threshold
        if let Some(change_output) = non_request_outputs.first() {
            anyhow::ensure!(
                change_output.amount >= TR_DUST_RELAY_MIN_VALUE,
                "Change output {} sats is below dust threshold {} sats",
                change_output.amount,
                TR_DUST_RELAY_MIN_VALUE
            );
        }

        // 6. Rebuild unsigned tx and verify txid matches
        let tx = self.build_unsigned_withdrawal_tx(&selected_utxos, &approval.outputs)?;
        let expected_txid = Address::new(tx.compute_txid().to_byte_array());
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
        pending_withdrawal_id: &Address,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        let pending = self
            .onchain_state()
            .pending_withdrawal(pending_withdrawal_id)
            .ok_or_else(|| {
                anyhow!("PendingWithdrawal {pending_withdrawal_id} not found on-chain")
            })?;
        let confirmation = WithdrawalConfirmation {
            withdrawal_id: pending.id,
        };

        self.sign_message_proto(&confirmation)
    }

    // --- Step 3: Sign withdrawal (store witness signatures on-chain) ---

    pub fn validate_and_sign_withdrawal_tx_signing(
        &self,
        message: &WithdrawalTxSigning,
    ) -> anyhow::Result<hashi_types::proto::MemberSignature> {
        let pending = self
            .onchain_state()
            .pending_withdrawal(&message.withdrawal_id)
            .ok_or_else(|| {
                anyhow!(
                    "PendingWithdrawal {} not found on-chain",
                    message.withdrawal_id
                )
            })?;

        anyhow::ensure!(
            pending.signatures.is_none(),
            "PendingWithdrawal {} is already signed",
            message.withdrawal_id
        );

        anyhow::ensure!(
            message.request_ids == pending.request_ids,
            "Request IDs mismatch for PendingWithdrawal {}",
            message.withdrawal_id
        );

        anyhow::ensure!(
            message.signatures.len() == pending.inputs.len(),
            "Signature count ({}) does not match input count ({}) for PendingWithdrawal {}",
            message.signatures.len(),
            pending.inputs.len(),
            message.withdrawal_id
        );

        let tx = self.build_unsigned_withdrawal_tx(&pending.inputs, &pending.outputs)?;
        let signing_messages = self.withdrawal_signing_messages(&tx, &pending.inputs)?;
        let hashi_pubkey = self.get_hashi_pubkey();

        for (i, (sig_bytes, sighash)) in message
            .signatures
            .iter()
            .zip(signing_messages.iter())
            .enumerate()
        {
            let arr: &[u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
                anyhow!(
                    "Signature {i} is not 64 bytes for PendingWithdrawal {}",
                    message.withdrawal_id
                )
            })?;
            let sig = SchnorrSignature::from_byte_array(arr)
                .map_err(|e| anyhow!("Invalid Schnorr signature at input {i}: {e}"))?;

            let input_pubkey =
                self.deposit_pubkey(&hashi_pubkey, pending.inputs[i].derivation_path.as_ref())?;
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
        let private_key = self
            .config
            .protocol_private_key()
            .ok_or_else(|| anyhow!("No protocol private key configured"))?;
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

    pub async fn validate_and_sign_withdrawal_tx(
        &self,
        pending_withdrawal_id: &Address,
    ) -> anyhow::Result<Vec<SchnorrSignature>> {
        let (pending, unsigned_tx) = self
            .validate_withdrawal_signing(pending_withdrawal_id)
            .await?;
        self.mpc_sign_withdrawal_tx(&pending, &unsigned_tx).await
    }

    pub async fn validate_withdrawal_signing(
        &self,
        pending_withdrawal_id: &Address,
    ) -> anyhow::Result<(
        crate::onchain::types::PendingWithdrawal,
        bitcoin::Transaction,
    )> {
        let pending = self
            .onchain_state()
            .pending_withdrawal(pending_withdrawal_id)
            .ok_or_else(|| {
                anyhow!("PendingWithdrawal {pending_withdrawal_id} not found on-chain")
            })?;

        // Rebuild the unsigned BTC tx and verify the txid matches
        let tx = self.build_unsigned_withdrawal_tx(&pending.inputs, &pending.outputs)?;
        let expected_txid = Address::new(tx.compute_txid().to_byte_array());
        anyhow::ensure!(
            pending.txid == expected_txid,
            "Txid mismatch: PendingWithdrawal has {:?}, rebuilt tx has {:?}",
            pending.txid,
            expected_txid
        );

        Ok((pending.clone(), tx))
    }

    /// Produce MPC Schnorr signatures for an unsigned withdrawal transaction.
    async fn mpc_sign_withdrawal_tx(
        &self,
        pending: &crate::onchain::types::PendingWithdrawal,
        unsigned_tx: &bitcoin::Transaction,
    ) -> anyhow::Result<Vec<SchnorrSignature>> {
        let onchain_state = self.onchain_state().clone();
        let epoch = onchain_state.epoch();
        let p2p_channel = RpcP2PChannel::new(onchain_state, epoch);
        let signing_manager = self.signing_manager();
        let beacon = S::zero();
        let signing_messages = self.withdrawal_signing_messages(unsigned_tx, &pending.inputs)?;
        let mut signatures_by_input = Vec::with_capacity(signing_messages.len());
        for (input_index, message) in signing_messages.iter().enumerate() {
            let request_id = withdrawal_signing_request_id(&pending.id, input_index as u32);
            let derivation_address = pending
                .inputs
                .get(input_index)
                .and_then(|input| input.derivation_path.as_ref().map(|path| path.into_inner()));
            let signature = SigningManager::sign(
                &signing_manager,
                &p2p_channel,
                request_id,
                message,
                &beacon,
                derivation_address.as_ref(),
                WITHDRAWAL_SIGNING_TIMEOUT,
            )
            .await
            .map_err(|e| {
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
        let hashi_pubkey = self.get_hashi_pubkey();
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

    /// Select UTXOs for a withdrawal using Branch-and-Bound with LowestFee metric,
    /// falling back to greedy selection if BnB finds no solution.
    pub fn select_utxos_for_withdrawal(
        &self,
        withdrawal_amount: u64,
        recipient_address: &[u8],
        fee_rate: FeeRate,
    ) -> anyhow::Result<UtxoSelection> {
        let active_utxos = self.onchain_state().active_utxos();
        anyhow::ensure!(!active_utxos.is_empty(), "No active UTXOs available");

        let recipient_output_weight = output_weight_for_address(recipient_address)?;
        let long_term_fee_rate = FeeRate::from_sat_per_vb(LONG_TERM_FEE_RATE_SAT_PER_VB);

        // Map each UTXO to a bdk_coin_select Candidate (P2TR key-path spend)
        let candidates: Vec<Candidate> = active_utxos
            .iter()
            .map(|utxo| Candidate::new_tr_keyspend(utxo.amount))
            .collect();

        let mut cs = CoinSelector::new(&candidates);

        let target = Target {
            fee: TargetFee::from_feerate(fee_rate),
            outputs: TargetOutputs {
                value_sum: withdrawal_amount,
                weight_sum: recipient_output_weight,
                n_outputs: 1,
            },
        };

        let change_policy = ChangePolicy::min_value_and_waste(
            DrainWeights::TR_KEYSPEND,
            TR_DUST_RELAY_MIN_VALUE,
            fee_rate,
            long_term_fee_rate,
        );

        // Try BnB first (optimal), fall back to greedy
        let metric = LowestFee {
            target,
            long_term_feerate: long_term_fee_rate,
            change_policy,
        };
        if cs.run_bnb(metric, BNB_MAX_ROUNDS).is_err() {
            cs.sort_candidates_by_descending_value_pwu();
            cs.select_until_target_met(target).map_err(|e| {
                let total: u64 = active_utxos.iter().map(|u| u.amount).sum();
                anyhow::anyhow!(
                    "UTXO selection failed ({e}): need {withdrawal_amount} sats + fees, \
                     pool has {total} sats in {} UTXOs",
                    active_utxos.len()
                )
            })?;
        }

        let drain = cs.drain(target, change_policy);
        let selected_utxos: Vec<Utxo> = cs.apply_selection(&active_utxos).cloned().collect();
        let selected_value: u64 = selected_utxos.iter().map(|u| u.amount).sum();
        let fee = selected_value - withdrawal_amount - drain.value;
        let change = if drain.is_some() {
            Some(drain.value)
        } else {
            None
        };

        Ok(UtxoSelection {
            selected_utxos,
            fee,
            change,
        })
    }

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
                    txid: bitcoin::Txid::from_byte_array(utxo.id.txid.into()),
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

    /// Build a withdrawal approval: select UTXOs with fee awareness, compute
    /// outputs (withdrawal destination + optional change), build the unsigned
    /// BTC tx, and return a `WithdrawalTxCommitment` containing the txid.
    pub async fn build_withdrawal_tx_commitment(
        &self,
        request: &WithdrawalRequest,
    ) -> anyhow::Result<WithdrawalTxCommitment> {
        // Fetch current fee rate from the Bitcoin node
        let kyoto_fee_rate = self
            .btc_monitor()
            .get_recent_fee_rate(WITHDRAWAL_FEE_CONF_TARGET)
            .await?;
        // Convert kyoto FeeRate (sat/kwu) to bdk_coin_select FeeRate (sat/wu)
        let fee_rate = FeeRate::from_sat_per_wu(kyoto_fee_rate.to_sat_per_kwu() as f32 / 1000.0);

        let selection = self.select_utxos_for_withdrawal(
            request.btc_amount,
            &request.bitcoin_address,
            fee_rate,
        )?;

        let mut outputs = vec![OutputUtxo {
            amount: request.btc_amount,
            bitcoin_address: request.bitcoin_address.clone(),
        }];

        // Add change output back to hashi root pubkey if selection produced change
        if let Some(change_amount) = selection.change {
            let hashi_pubkey = self.get_hashi_pubkey();
            let change_address = self.get_deposit_address(&hashi_pubkey, None)?;
            outputs.push(OutputUtxo {
                amount: change_amount,
                bitcoin_address: witness_program_from_address(&change_address)?,
            });
        }

        let request_ids = vec![request.id];
        let utxo_ids: Vec<UtxoId> = selection.selected_utxos.iter().map(|u| u.id).collect();

        let tx = self.build_unsigned_withdrawal_tx(&selection.selected_utxos, &outputs)?;
        let txid_bytes: [u8; 32] = tx.compute_txid().to_byte_array();
        let txid = Address::new(txid_bytes);

        Ok(WithdrawalTxCommitment {
            request_ids,
            selected_utxos: utxo_ids,
            outputs,
            txid,
        })
    }

    /// Run AML/Sanctions checks for a withdrawal request.
    /// If no screener client is configured, checks are skipped.
    pub(crate) async fn screen_withdrawal(
        &self,
        request: &WithdrawalRequest,
    ) -> anyhow::Result<()> {
        let Some(screener) = self.screener_client() else {
            tracing::debug!("AML checks skipped: no screener configured");
            return Ok(());
        };

        // Source: Sui tx digest (base58 string)
        let source_tx_hash = request.sui_tx_digest.to_string();

        // Destination: Bitcoin address (raw witness bytes -> bech32 string)
        let destination_address = self.bitcoin_address_string_from_raw(&request.bitcoin_address)?;

        let approved = screener
            .approve_withdrawal(
                &source_tx_hash,
                &destination_address,
                self.config.sui_chain_id(),
                self.config.bitcoin_chain_id(),
            )
            .await
            .map_err(|e| anyhow!("Screener service error: {e}"))?;

        if !approved {
            anyhow::bail!(
                "AML checks failed for withdrawal request {:?} to {}",
                request.id,
                destination_address,
            );
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

fn witness_program_from_address(address: &BitcoinAddress) -> anyhow::Result<Vec<u8>> {
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
        // P2TR: TXOUT_BASE_WEIGHT(36) + TR_SPK_WEIGHT(136) = 172 WU
        32 => Ok(bdk_coin_select::TXOUT_BASE_WEIGHT + bdk_coin_select::TR_SPK_WEIGHT),
        // P2WPKH: (8 + 1 + 1 + 1 + 20) * 4 = 124 WU
        20 => Ok((8 + 1 + 1 + 1 + 20) * 4),
        len => anyhow::bail!("Unsupported bitcoin address length: {len}"),
    }
}

fn withdrawal_signing_request_id(pending_withdrawal_id: &Address, input_index: u32) -> Address {
    let mut bytes = [0u8; Address::LENGTH];
    bytes.copy_from_slice(pending_withdrawal_id.as_bytes());
    let index_bytes = input_index.to_le_bytes();
    for (i, b) in index_bytes.iter().enumerate() {
        let idx = bytes.len() - index_bytes.len() + i;
        bytes[idx] ^= *b;
    }
    Address::new(bytes)
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
