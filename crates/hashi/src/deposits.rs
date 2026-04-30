// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Hashi;
use crate::btc_monitor::monitor::DepositConfirmError;
use crate::onchain::types::DepositConfirmationMessage;
use crate::onchain::types::DepositRequest;
use anyhow::Context;
use anyhow::anyhow;
use bitcoin::ScriptBuf;

use bitcoin::secp256k1::XOnlyPublicKey;
use fastcrypto::groups::secp256k1::ProjectivePoint;
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::G;
use hashi_types::guardian::bitcoin_utils;
use hashi_types::proto::MemberSignature;
use thiserror::Error;

/// Derive a deposit address from a compressed MPC public key (33-byte ProjectivePoint),
/// an optional derivation path, and the target Bitcoin network.
pub fn derive_deposit_address(
    mpc_key: &ProjectivePoint,
    derivation_path: Option<&sui_sdk_types::Address>,
    btc_network: bitcoin::Network,
) -> anyhow::Result<bitcoin::Address> {
    let xonly = if let Some(path) = derivation_path {
        let derived = fastcrypto_tbls::threshold_schnorr::key_derivation::derive_verifying_key(
            mpc_key,
            &path.into_inner(),
        );
        XOnlyPublicKey::from_slice(&derived.to_byte_array()).context("valid 32-byte x-only key")?
    } else {
        let schnorr_pk = SchnorrPublicKey::try_from(mpc_key)
            .context("Failed to convert MPC key to schnorr key")?;
        XOnlyPublicKey::from_slice(&schnorr_pk.to_byte_array())
            .context("Failed to parse x-only key")?
    };

    Ok(bitcoin_utils::single_key_taproot_script_path_address(
        &xonly,
        btc_network,
    ))
}

impl Hashi {
    #[tracing::instrument(level = "info", skip_all, fields(deposit_id = %deposit_request.id))]
    pub async fn validate_and_sign_deposit_confirmation(
        &self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<MemberSignature> {
        self.validate_deposit_request(deposit_request).await?;
        self.sign_deposit_confirmation(deposit_request)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(deposit_id = %deposit_request.id))]
    pub async fn validate_deposit_request(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), DepositError> {
        self.validate_deposit_request_on_sui(deposit_request)?;
        self.validate_deposit_request_on_bitcoin(deposit_request)
            .await?;
        self.screen_deposit(deposit_request).await?;
        Ok(())
    }

    /// Run AML/Sanctions checks for the deposit request.
    /// If no screener client is configured, checks are skipped.
    #[tracing::instrument(level = "debug", skip_all, fields(deposit_id = %deposit_request.id))]
    async fn screen_deposit(&self, deposit_request: &DepositRequest) -> Result<(), DepositError> {
        let Some(screener) = self.screener_client() else {
            tracing::debug!("AML checks skipped: no screener configured");
            return Ok(());
        };

        // bitcoin
        let source_tx_hash = deposit_request.utxo.id.txid.to_string();
        let bitcoin_chain_id = self.config.bitcoin_chain_id().to_string();

        // sui
        let destination_address = deposit_request.id.to_string();
        let sui_chain_id = self.config.sui_chain_id().to_string();

        let approved = screener
            .approve_deposit(
                &source_tx_hash,
                &destination_address,
                &bitcoin_chain_id,
                &sui_chain_id,
            )
            .await
            .map_err(|e| DepositError::AmlServiceError(anyhow!(e)))?;

        if !approved {
            return Err(DepositError::AmlRejected(anyhow!(
                "AML checks failed for source tx {source_tx_hash}, destination {destination_address}, bitcoin chain {bitcoin_chain_id}, sui chain {sui_chain_id}"
            )));
        }

        Ok(())
    }

    /// Validate that the deposit request exists on Sui
    #[tracing::instrument(level = "debug", skip_all, fields(deposit_id = %deposit_request.id))]
    fn validate_deposit_request_on_sui(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), DepositError> {
        let state = self.onchain_state().state();
        let deposit_queue = &state.hashi().deposit_queue;
        match deposit_queue.requests().get(&deposit_request.id) {
            None => {
                return Err(DepositError::InvalidOnchainRequest(anyhow!(
                    "Deposit request not found on Sui"
                )));
            }
            Some(onchain_request) => {
                if onchain_request != deposit_request {
                    return Err(DepositError::InvalidOnchainRequest(anyhow!(
                        "Deposit request fields do not match on-chain state"
                    )));
                }
            }
        }

        let utxo_pool = &state.hashi().utxo_pool;
        if utxo_pool
            .utxo_records()
            .contains_key(&deposit_request.utxo.id)
            || utxo_pool
                .spent_utxos()
                .contains_key(&deposit_request.utxo.id)
        {
            return Err(DepositError::DuplicateOrSpentOnSui(anyhow!(
                "UTXO {:?} is already active or spent",
                deposit_request.utxo.id
            )));
        }

        Ok(())
    }

    /// Validate that there is a txout on Bitcoin that matches the deposit request
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            deposit_id = %deposit_request.id,
            bitcoin_txid = %deposit_request.utxo.id.txid,
            vout = deposit_request.utxo.id.vout,
        ),
    )]
    async fn validate_deposit_request_on_bitcoin(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), DepositError> {
        let outpoint = bitcoin::OutPoint {
            txid: deposit_request.utxo.id.txid.into(),
            vout: deposit_request.utxo.id.vout,
        };
        // Read the threshold live from on-chain state so governance
        // updates take effect for new deposits without a restart.
        let confirmation_threshold = self.onchain_state().bitcoin_confirmation_threshold();
        let txout = self
            .btc_monitor()
            .confirm_deposit(outpoint, confirmation_threshold)
            .await
            .map_err(|e| match e {
                DepositConfirmError::UtxoSpent { .. } => {
                    self.metrics.deposits_rejected_utxo_spent.inc();
                    DepositError::BitcoinUtxoSpent(anyhow!(e))
                }
                DepositConfirmError::Other(err) => DepositError::BitcoinConfirmFailed(err),
            })?;
        if txout.value.to_sat() != deposit_request.utxo.amount {
            return Err(DepositError::DepositDataMismatch(anyhow!(
                "Bitcoin deposit amount mismatch: got {}, onchain is {}",
                deposit_request.utxo.amount,
                txout.value.to_sat(),
            )));
        }

        self.validate_deposit_request_derivation_path(&txout.script_pubkey, deposit_request)
            .await?;
        Ok(())
    }

    async fn validate_deposit_request_derivation_path(
        &self,
        script_pubkey: &ScriptBuf,
        deposit_request: &DepositRequest,
    ) -> Result<(), DepositError> {
        let deposit_address =
            bitcoin::Address::from_script(script_pubkey, self.config.bitcoin_network()).map_err(
                |e| {
                    DepositError::DepositDataMismatch(anyhow!(
                        "Failed to extract address from script_pubkey: {e}"
                    ))
                },
            )?;
        let hashi_pubkey = self.get_hashi_pubkey().map_err(DepositError::NotReady)?;
        let expected_address = self
            .get_deposit_address(&hashi_pubkey, deposit_request.utxo.derivation_path.as_ref())
            .map_err(DepositError::DepositDataMismatch)?;

        if deposit_address != expected_address {
            return Err(DepositError::DepositDataMismatch(anyhow!(
                "Expected address {expected_address}, got address {deposit_address}",
            )));
        }

        Ok(())
    }

    pub fn get_deposit_address(
        &self,
        hashi_pubkey: &XOnlyPublicKey,
        derivation_path: Option<&sui_sdk_types::Address>,
    ) -> anyhow::Result<bitcoin::Address> {
        let pubkey = self.deposit_pubkey(hashi_pubkey, derivation_path)?;
        Ok(self.bitcoin_address_from_pubkey(&pubkey))
    }

    pub(crate) fn deposit_pubkey(
        &self,
        hashi_pubkey: &XOnlyPublicKey,
        derivation_path: Option<&sui_sdk_types::Address>,
    ) -> anyhow::Result<XOnlyPublicKey> {
        if let Some(path) = derivation_path {
            // Prefer the local signing manager (available after DKG preparation).
            // Fall back to the on-chain key, which is guaranteed present once the
            // initial committee has formed and `end_reconfig` has been processed.
            let verifying_key = self
                .signing_verifying_key()
                .map(Ok)
                .unwrap_or_else(|| self.onchain_verifying_key_g())
                .context("MPC public key not available yet")?;
            let derived = fastcrypto_tbls::threshold_schnorr::key_derivation::derive_verifying_key(
                &verifying_key,
                &path.into_inner(),
            );
            let pubkey = XOnlyPublicKey::from_slice(&derived.to_byte_array())
                .context("valid 32-byte x-only key")?;
            Ok(pubkey)
        } else {
            Ok(*hashi_pubkey)
        }
    }

    pub(crate) fn bitcoin_address_from_pubkey(&self, pubkey: &XOnlyPublicKey) -> bitcoin::Address {
        bitcoin_utils::single_key_taproot_script_path_address(pubkey, self.config.bitcoin_network())
    }

    pub fn get_hashi_pubkey(&self) -> anyhow::Result<XOnlyPublicKey> {
        let g = self
            .mpc_handle()
            .context("MpcHandle not initialized")?
            .public_key()
            .context("MPC public key not available yet")?;
        // Convert G (ProjectivePoint, 33 bytes compressed) to SchnorrPublicKey (32 bytes x-only)
        let schnorr_pk = SchnorrPublicKey::try_from(&g)
            .map_err(|e| anyhow!("invalid group element for schnorr key: {e}"))?;
        Ok(XOnlyPublicKey::from_slice(&schnorr_pk.to_byte_array())?)
    }

    /// Read the MPC public key from on-chain state.
    ///
    /// Unlike `get_hashi_pubkey`, this does not depend on the node's local DKG
    /// completion channel. The on-chain key is set during `end_reconfig` event
    /// processing, so it is guaranteed to be present once the initial committee
    /// has formed (i.e., after `HashiNetworkBuilder::build()` returns).
    pub fn get_onchain_mpc_pubkey(&self) -> anyhow::Result<XOnlyPublicKey> {
        let g = self.onchain_verifying_key_g()?;
        let schnorr_pk = SchnorrPublicKey::try_from(&g)
            .map_err(|e| anyhow!("invalid group element for schnorr key: {e}"))?;
        Ok(XOnlyPublicKey::from_slice(&schnorr_pk.to_byte_array())?)
    }

    /// Deserialize the BCS-encoded MPC group element from on-chain state.
    ///
    /// The on-chain key is stored as `bcs::to_bytes(&G)` in the `CommitteeSet`
    /// and is populated atomically with the `end_reconfig` event.
    fn onchain_verifying_key_g(&self) -> anyhow::Result<G> {
        let bytes = self.onchain_state().mpc_public_key();
        anyhow::ensure!(
            !bytes.is_empty(),
            "MPC public key not yet available on-chain"
        );
        bcs::from_bytes(&bytes).context("failed to deserialize on-chain MPC public key")
    }

    fn sign_deposit_confirmation(
        &self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<MemberSignature> {
        let epoch = self.onchain_state().epoch();
        let validator_address = self
            .config
            .validator_address()
            .map_err(|e| anyhow!("No validator address configured: {}", e))?;
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

        let message = DepositConfirmationMessage {
            request_id: deposit_request.id,
            utxo: deposit_request.utxo.clone(),
        };

        let signature_bytes = private_key
            .sign(epoch, validator_address, &message)
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum DepositErrorKind {
    RetryOnNextBlock,
    NeverRetry,
}

#[derive(Debug, Error)]
pub enum DepositError {
    #[error("Failed to confirm Bitcoin deposit: {0}")]
    BitcoinConfirmFailed(#[source] anyhow::Error),

    #[error("Screener service error: {0}")]
    AmlServiceError(#[source] anyhow::Error),

    #[error("Not ready: {0}")]
    NotReady(#[source] anyhow::Error),

    #[error("Invalid on-chain deposit request: {0}")]
    InvalidOnchainRequest(#[source] anyhow::Error),

    #[error("UTXO is already active or spent on Sui: {0}")]
    DuplicateOrSpentOnSui(#[source] anyhow::Error),

    #[error("Deposit UTXO has already been spent on Bitcoin: {0}")]
    BitcoinUtxoSpent(#[source] anyhow::Error),

    #[error("Deposit data mismatch: {0}")]
    DepositDataMismatch(#[source] anyhow::Error),

    #[error("AML checks rejected deposit: {0}")]
    AmlRejected(#[source] anyhow::Error),

    #[error("Failed quorum: weight {weight} < {required_weight}")]
    FailedQuorum { weight: u64, required_weight: u64 },

    #[error("Failed to build deposit certificate: {0}")]
    CertificateBuildFailed(#[source] anyhow::Error),

    #[error("Failed to create Sui transaction executor: {0}")]
    ExecutorInitFailed(#[source] anyhow::Error),

    #[error("Failed to confirm deposit on Sui: {0}")]
    ConfirmDepositFailed(#[source] anyhow::Error),

    #[error("Deposit processing timed out after {0:?}")]
    TimedOut(std::time::Duration),
}

impl DepositError {
    pub(crate) fn kind(&self) -> DepositErrorKind {
        match self {
            Self::BitcoinConfirmFailed(_)
            | Self::AmlServiceError(_)
            | Self::NotReady(_)
            | Self::FailedQuorum { .. }
            | Self::CertificateBuildFailed(_)
            | Self::ExecutorInitFailed(_)
            | Self::ConfirmDepositFailed(_)
            | Self::TimedOut(_) => DepositErrorKind::RetryOnNextBlock,
            Self::InvalidOnchainRequest(_)
            | Self::DuplicateOrSpentOnSui(_)
            | Self::BitcoinUtxoSpent(_)
            | Self::DepositDataMismatch(_)
            | Self::AmlRejected(_) => DepositErrorKind::NeverRetry,
        }
    }
}
