use anyhow::anyhow;
use bitcoin::Address as BitcoinAddress;
use bitcoin::Amount;
use bitcoin::TxOut;
use bitcoin::blockdata::script::witness_program::WitnessProgram;
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use bitcoin::hashes::Hash;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::sighash::TapSighashType;
use fastcrypto::groups::GroupElement;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::S;
use hashi_types::guardian::bitcoin_utils;
use hashi_types::proto::MemberSignature;
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

/// The data that validators BLS-sign over to approve a withdrawal transaction.
/// This represents the proposal that will eventually be passed to
/// `pick_withdrawal_for_processing` on-chain.
#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalApproval {
    pub request_ids: Vec<Address>,
    pub selected_utxos: Vec<UtxoId>,
    pub outputs: Vec<OutputUtxo>,
    pub txid: Address,
}

#[derive(Clone, Debug, serde_derive::Serialize)]
pub struct WithdrawalConfirmation {
    pub withdrawal_id: Address,
}

#[derive(Clone, Debug, serde_derive::Deserialize, serde_derive::Serialize)]
pub struct WithdrawalInputSignature {
    pub hashi_signature: Vec<u8>,
}

impl Hashi {
    // --- First endpoint: approval ---

    pub async fn validate_and_sign_withdrawal_approval(
        &self,
        approval: &WithdrawalApproval,
    ) -> anyhow::Result<MemberSignature> {
        self.validate_withdrawal_approval(approval).await?;
        self.sign_withdrawal_approval(approval)
    }

    pub async fn validate_withdrawal_approval(
        &self,
        approval: &WithdrawalApproval,
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

        // 1. Verify each request_id exists and collect the requests
        let requests: Vec<WithdrawalRequest> = approval
            .request_ids
            .iter()
            .map(|id| {
                self.onchain_state()
                    .withdrawal_request(id)
                    .ok_or_else(|| anyhow!("Withdrawal request {id} not found in queue"))
            })
            .collect::<anyhow::Result<_>>()?;

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
                witness_program_from_address(&self.get_deposit_address(&hashi_pubkey, None))?;
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
        let _fee = input_total - output_total;
        // TODO: check that the fee is reasonable (not too high, not too low)

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

    fn sign_withdrawal_approval(
        &self,
        approval: &WithdrawalApproval,
    ) -> anyhow::Result<MemberSignature> {
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
            .sign(epoch, validator_address, approval)
            .signature()
            .as_bytes()
            .to_vec()
            .into();

        Ok(MemberSignature {
            epoch: Some(epoch),
            address: Some(validator_address.to_string()),
            public_key: Some(public_key_bytes),
            signature: Some(signature_bytes),
        })
    }

    pub fn sign_withdrawal_confirmation(
        &self,
        pending_withdrawal_id: &Address,
    ) -> anyhow::Result<MemberSignature> {
        let pending = self
            .onchain_state()
            .pending_withdrawal(pending_withdrawal_id)
            .ok_or_else(|| {
                anyhow!("PendingWithdrawal {pending_withdrawal_id} not found on-chain")
            })?;
        let confirmation = WithdrawalConfirmation {
            withdrawal_id: pending.id,
        };

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
            .sign(epoch, validator_address, &confirmation)
            .signature()
            .as_bytes()
            .to_vec()
            .into();

        Ok(MemberSignature {
            epoch: Some(epoch),
            address: Some(validator_address.to_string()),
            public_key: Some(public_key_bytes),
            signature: Some(signature_bytes),
        })
    }

    // --- Second endpoint: BTC tx signing ---

    pub async fn validate_and_sign_withdrawal_tx(
        &self,
        pending_withdrawal_id: &Address,
    ) -> anyhow::Result<Vec<u8>> {
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

    /// Produce a partial MPC Schnorr signature for an unsigned withdrawal transaction.
    async fn mpc_sign_withdrawal_tx(
        &self,
        pending: &crate::onchain::types::PendingWithdrawal,
        unsigned_tx: &bitcoin::Transaction,
    ) -> anyhow::Result<Vec<u8>> {
        let onchain_state = self.onchain_state().clone();
        let epoch = onchain_state.epoch();
        let p2p_channel = RpcP2PChannel::new(onchain_state, epoch);
        let signing_manager = self.signing_manager();
        let beacon = S::zero();
        let signing_messages = self.withdrawal_signing_messages(unsigned_tx, &pending.inputs)?;
        let mut signatures_by_input = Vec::with_capacity(signing_messages.len());
        for (input_index, message) in signing_messages.iter().enumerate() {
            let request_id = withdrawal_signing_request_id(&pending.id, input_index as u32);
            let signature = SigningManager::sign(
                &signing_manager,
                &p2p_channel,
                request_id,
                message,
                &beacon,
                None,
                WITHDRAWAL_SIGNING_TIMEOUT,
            )
            .await
            .map_err(|e| {
                anyhow!("Failed to sign withdrawal transaction input {input_index}: {e}")
            })?;

            signatures_by_input.push(WithdrawalInputSignature {
                hashi_signature: signature.to_byte_array().to_vec(),
            });
        }
        bcs::to_bytes(&signatures_by_input)
            .map_err(|e| anyhow!("Failed to serialize partial signature: {e}"))
    }

    pub(crate) fn withdrawal_signing_messages(
        &self,
        unsigned_tx: &bitcoin::Transaction,
        inputs: &[Utxo],
    ) -> anyhow::Result<Vec<[u8; 32]>> {
        let hashi_pubkey = self.get_hashi_pubkey();
        let prevouts = inputs
            .iter()
            .map(|input| {
                let address =
                    self.get_deposit_address(&hashi_pubkey, input.derivation_path.as_ref());
                TxOut {
                    value: Amount::from_sat(input.amount),
                    script_pubkey: address.script_pubkey(),
                }
            })
            .collect::<Vec<_>>();

        (0..inputs.len())
            .map(|input_index| {
                let mut sighasher = SighashCache::new(unsigned_tx);
                let sighash = sighasher
                    .taproot_key_spend_signature_hash(
                        input_index,
                        &Prevouts::All(&prevouts),
                        TapSighashType::Default,
                    )
                    .map_err(|e| anyhow!("Failed to construct taproot key spend sighash: {e}"))?;
                Ok(*sighash.as_byte_array())
            })
            .collect()
    }

    // --- UTXO selection and tx crafting ---

    pub fn select_utxos_for_withdrawal(&self, amount: u64) -> anyhow::Result<Vec<Utxo>> {
        // This is a simple naive stub implementation
        // TODO: implement a sophisticated version of utxo selection
        let active_utxos = self.onchain_state().active_utxos();
        let mut selected = Vec::new();
        let mut total = 0u64;
        for utxo in &active_utxos {
            selected.push(utxo.clone());
            total += utxo.amount;
            if total >= amount {
                return Ok(selected);
            }
        }
        anyhow::bail!("Insufficient UTXOs: need {amount} sats, only have {total} sats available");
    }

    /// Build an unsigned Bitcoin transaction for a withdrawal. This is used both
    /// by the leader when initially crafting the tx, and by validators when
    /// verifying that a proposed `WithdrawalApproval` produces the expected txid.
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

    /// Build a withdrawal approval: select UTXOs, compute outputs (withdrawal
    /// destination + change to hashi root pubkey), build the unsigned BTC tx,
    /// and return a `WithdrawalApproval` containing the txid.
    pub fn build_withdrawal_approval(
        &self,
        request: &WithdrawalRequest,
    ) -> anyhow::Result<WithdrawalApproval> {
        // TODO: account for BTC transaction fees when selecting UTXOs
        let selected_utxos = self.select_utxos_for_withdrawal(request.btc_amount)?;
        let input_total: u64 = selected_utxos.iter().map(|u| u.amount).sum();

        let mut outputs = vec![OutputUtxo {
            amount: request.btc_amount,
            bitcoin_address: request.bitcoin_address.clone(),
        }];

        // Change output back to hashi root pubkey (no derivation)
        let change = input_total.saturating_sub(request.btc_amount);
        if change > 0 {
            let hashi_pubkey = self.get_hashi_pubkey();
            let change_address = self.get_deposit_address(&hashi_pubkey, None);
            outputs.push(OutputUtxo {
                amount: change,
                bitcoin_address: witness_program_from_address(&change_address)?,
            });
        }

        let request_ids = vec![request.id];
        let utxo_ids: Vec<UtxoId> = selected_utxos.iter().map(|u| u.id).collect();

        let tx = self.build_unsigned_withdrawal_tx(&selected_utxos, &outputs)?;
        let txid_bytes: [u8; 32] = tx.compute_txid().to_byte_array();
        let txid = Address::new(txid_bytes);

        Ok(WithdrawalApproval {
            request_ids,
            selected_utxos: utxo_ids,
            outputs,
            txid,
        })
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
