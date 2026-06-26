// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Hashi;
use crate::btc_monitor::monitor::DepositConfirmError;
use crate::leader::RetryPolicy;
use crate::onchain::types::DepositConfirmationMessage;
use crate::onchain::types::DepositRequest;
use anyhow::Context;
use anyhow::anyhow;
use bitcoin::ScriptBuf;

use bitcoin::secp256k1::XOnlyPublicKey;
use fastcrypto::groups::secp256k1::ProjectivePoint;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::G;
use hashi_types::bitcoin as hashi_bitcoin;
use hashi_types::proto::MemberSignature;
use thiserror::Error;

impl Hashi {
    #[tracing::instrument(level = "info", skip_all, fields(deposit_id = %deposit_request.id))]
    pub async fn validate_and_sign_deposit_confirmation(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<MemberSignature, UnapprovedDepositError> {
        self.validate_deposit_request(deposit_request).await?;
        self.sign_deposit_confirmation(deposit_request)
            .map_err(UnapprovedDepositError::SignDepositFailed)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(deposit_id = %deposit_request.id))]
    pub async fn validate_deposit_request(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), UnapprovedDepositError> {
        self.validate_deposit_request_on_sui(deposit_request)?;
        self.validate_deposit_request_on_bitcoin(deposit_request)
            .await?;
        self.screen_deposit(deposit_request).await?;
        Ok(())
    }

    /// Run AML/Sanctions checks for the deposit request.
    /// If no screener client is configured, checks are skipped.
    #[tracing::instrument(level = "debug", skip_all, fields(deposit_id = %deposit_request.id))]
    async fn screen_deposit(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), UnapprovedDepositError> {
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
            .map_err(|e| UnapprovedDepositError::AmlServiceError(anyhow!(e)))?;

        if !approved {
            return Err(UnapprovedDepositError::AmlRejected(anyhow!(
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
    ) -> Result<(), UnapprovedDepositError> {
        let state = self.onchain_state().state();
        let deposit_queue = &state.hashi().deposit_queue;
        match deposit_queue.requests().get(&deposit_request.id) {
            None => {
                return Err(UnapprovedDepositError::InvalidOnchainRequest(anyhow!(
                    "Deposit request not found on Sui"
                )));
            }
            Some(onchain_request) => {
                // Approval state lives on the on-chain request but is not
                // carried by `DepositRequest` constructed from the proto, so
                // compare the immutable core fields only.
                let core_matches = onchain_request.id == deposit_request.id
                    && onchain_request.sender == deposit_request.sender
                    && onchain_request.timestamp_ms == deposit_request.timestamp_ms
                    && onchain_request.sui_tx_digest == deposit_request.sui_tx_digest
                    && onchain_request.utxo == deposit_request.utxo;
                if !core_matches {
                    return Err(UnapprovedDepositError::InvalidOnchainRequest(anyhow!(
                        "Deposit request fields do not match on-chain state"
                    )));
                }

                // Refuse to sign a re-approval if the on-chain request is
                // already approved by the current committee. The on-chain
                // `approve_deposit` would reject it anyway, so we don't
                // want to waste a signature exchange or a transaction.
                let current_epoch = self.onchain_state().epoch();
                if let Some(cert) = &onchain_request.approval_cert
                    && cert.epoch == current_epoch
                {
                    return Err(UnapprovedDepositError::AlreadyApprovedThisEpoch);
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
            return Err(UnapprovedDepositError::DuplicateOrSpentOnSui(anyhow!(
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
    ) -> Result<(), UnapprovedDepositError> {
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
                    UnapprovedDepositError::BitcoinUtxoSpent(anyhow!(e))
                }
                DepositConfirmError::Other(err) => {
                    UnapprovedDepositError::BitcoinConfirmFailed(err)
                }
            })?;
        if txout.value.to_sat() != deposit_request.utxo.amount {
            return Err(UnapprovedDepositError::DepositDataMismatch(anyhow!(
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
    ) -> Result<(), UnapprovedDepositError> {
        let deposit_address = hashi_bitcoin::BitcoinAddress::from_script(
            script_pubkey,
            self.config.bitcoin_network(),
        )
        .map_err(|e| {
            UnapprovedDepositError::DepositDataMismatch(anyhow!(
                "Failed to extract address from script_pubkey: {e}"
            ))
        })?;
        let expected_address = self
            .get_deposit_address(deposit_request.utxo.derivation_path.as_ref())
            .map_err(UnapprovedDepositError::DepositDataMismatch)?;

        if deposit_address != expected_address {
            return Err(UnapprovedDepositError::DepositDataMismatch(anyhow!(
                "Expected address {expected_address}, got address {deposit_address}",
            )));
        }

        Ok(())
    }

    pub fn get_deposit_address(
        &self,
        derivation_path: Option<&sui_sdk_types::Address>,
    ) -> anyhow::Result<hashi_bitcoin::BitcoinAddress> {
        let mpc_g = self.mpc_master_g()?;
        let guardian_pubkey = self.require_guardian_btc_pubkey()?;
        derive_deposit_address(
            &mpc_g,
            &guardian_pubkey,
            derivation_path,
            self.config.bitcoin_network(),
        )
    }

    /// 2-of-2 taproot leaf artifacts (script, control block, leaf hash)
    /// for a deposit UTXO. Used by the withdrawal sighash and the
    /// rebroadcast witness builder.
    pub(crate) fn deposit_spend_artifacts(
        &self,
        derivation_path: Option<&sui_sdk_types::Address>,
    ) -> anyhow::Result<(
        bitcoin::ScriptBuf,
        bitcoin::taproot::ControlBlock,
        bitcoin::taproot::TapLeafHash,
    )> {
        let mpc_g = self.mpc_master_g()?;
        let guardian_pubkey = self.require_guardian_btc_pubkey()?;
        Ok(hashi_bitcoin::taproot_2of2_witness_artifacts(
            &guardian_pubkey,
            &mpc_g,
            &normalized_derivation_path(derivation_path),
        ))
    }

    /// Raw MPC verifying key (`G`) with y-parity preserved. Prefers the
    /// local signing manager (set immediately after DKG completes); falls
    /// back to the on-chain key. Both sources point at the same value.
    fn mpc_master_g(&self) -> anyhow::Result<G> {
        self.signing_verifying_key()
            .map(Ok)
            .unwrap_or_else(|| self.onchain_state().onchain_verifying_key_g())
            .context("MPC public key not available yet")
    }

    /// Hashi committee's child pubkey at `derivation_path`. `None` maps
    /// to a zero-byte path (change outputs).
    pub(crate) fn deposit_pubkey(
        &self,
        derivation_path: Option<&sui_sdk_types::Address>,
    ) -> anyhow::Result<XOnlyPublicKey> {
        // Prefer the local signing manager (available after DKG preparation).
        // Fall back to the on-chain key, which is guaranteed present once the
        // initial committee has formed and `end_reconfig` has been processed.
        let verifying_key = self
            .signing_verifying_key()
            .map(Ok)
            .unwrap_or_else(|| self.onchain_state().onchain_verifying_key_g())
            .context("MPC public key not available yet")?;
        let derivation_path = normalized_derivation_path(derivation_path).into_inner();
        let derived = fastcrypto_tbls::threshold_schnorr::key_derivation::derive_verifying_key(
            &verifying_key,
            &derivation_path,
        );
        XOnlyPublicKey::from_slice(&derived.to_byte_array()).context("valid 32-byte x-only key")
    }

    fn require_guardian_btc_pubkey(&self) -> anyhow::Result<XOnlyPublicKey> {
        self.guardian_btc_pubkey()
            .copied()
            .ok_or_else(|| anyhow!("Guardian BTC pubkey not yet pinned"))
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

/// `tr(NUMS, {multi_a(2, guardian_btc_pubkey, h), and_v(v:older(delay), pk(h))})`
/// where `h = derive(mpc_pubkey, path)`: an immediate guardian+MPC 2-of-2 leaf,
/// plus an MPC-only recovery leaf spendable after
/// `HASHI_MPC_RECOVERY_DELAY_SECONDS`.
/// `path = None` (change address) maps to a zero-byte path so deposit
/// and withdrawal sides agree on the leaf key without a special case.
///
/// `mpc_key` is the raw MPC verifying key (`G`). The derivation is taken
/// directly against this point — using only the x-only projection would
/// silently force the parent to even-y and produce a different child key
/// for ~half of all MPC vks, breaking the 2-of-2 leaf script.
pub fn derive_deposit_address(
    mpc_key: &ProjectivePoint,
    guardian_btc_pubkey: &XOnlyPublicKey,
    derivation_path: Option<&sui_sdk_types::Address>,
    btc_network: bitcoin::Network,
) -> anyhow::Result<hashi_bitcoin::BitcoinAddress> {
    Ok(hashi_bitcoin::taproot_address(
        guardian_btc_pubkey,
        mpc_key,
        &normalized_derivation_path(derivation_path),
        btc_network,
    ))
}

pub(crate) fn normalized_derivation_path(
    derivation_path: Option<&sui_sdk_types::Address>,
) -> sui_sdk_types::Address {
    derivation_path
        .copied()
        .unwrap_or(sui_sdk_types::Address::ZERO)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum UnapprovedDepositErrorKind {
    RetryOnNextBlock,
    NeverRetry,
}

#[derive(Debug, Error)]
pub enum UnapprovedDepositError {
    #[error("Failed to confirm Bitcoin deposit: {0}")]
    BitcoinConfirmFailed(#[source] anyhow::Error),

    #[error("Screener service error: {0}")]
    AmlServiceError(#[source] anyhow::Error),

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

    #[error("Failed to approve deposit on Sui: {0}")]
    ApproveDepositFailed(#[source] anyhow::Error),

    #[error("Failed to sign deposit confirmation: {0}")]
    SignDepositFailed(#[source] anyhow::Error),

    #[error("Deposit has already been approved by the current committee")]
    AlreadyApprovedThisEpoch,

    #[error("Deposit processing timed out after {0:?}")]
    TimedOut(std::time::Duration),
}

impl UnapprovedDepositError {
    pub(crate) fn kind(&self) -> UnapprovedDepositErrorKind {
        match self {
            Self::BitcoinConfirmFailed(_)
            | Self::AmlServiceError(_)
            | Self::FailedQuorum { .. }
            | Self::CertificateBuildFailed(_)
            | Self::ExecutorInitFailed(_)
            | Self::ApproveDepositFailed(_)
            | Self::SignDepositFailed(_)
            | Self::AlreadyApprovedThisEpoch
            | Self::TimedOut(_) => UnapprovedDepositErrorKind::RetryOnNextBlock,
            Self::InvalidOnchainRequest(_)
            | Self::DuplicateOrSpentOnSui(_)
            | Self::BitcoinUtxoSpent(_)
            | Self::DepositDataMismatch(_)
            | Self::AmlRejected(_) => UnapprovedDepositErrorKind::NeverRetry,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ApprovedDepositErrorKind {
    ExecutorInitFailed,
    ConfirmDepositFailed,
    TimedOut,
}

#[derive(Debug, Error)]
pub enum ApprovedDepositError {
    #[error("Failed to create Sui transaction executor: {0}")]
    ExecutorInitFailed(#[source] anyhow::Error),

    #[error("Failed to confirm deposit on Sui: {0}")]
    ConfirmDepositFailed(#[source] anyhow::Error),

    #[error("Deposit processing timed out after {0:?}")]
    TimedOut(std::time::Duration),
}

impl ApprovedDepositError {
    pub(crate) fn kind(&self) -> ApprovedDepositErrorKind {
        match self {
            Self::ExecutorInitFailed(_) => ApprovedDepositErrorKind::ExecutorInitFailed,
            Self::ConfirmDepositFailed(_) => ApprovedDepositErrorKind::ConfirmDepositFailed,
            Self::TimedOut(_) => ApprovedDepositErrorKind::TimedOut,
        }
    }
}

// This backoff only applies after an eligible approved deposit confirmation
// actually fails. Deposits whose time-delay has not elapsed are skipped before
// entering retry tracking.
impl RetryPolicy for ApprovedDepositErrorKind {
    fn retry_base_delay_ms(self) -> u64 {
        5 * 60 * 1000
    }

    fn max_delay_ms(self) -> u64 {
        30 * 60 * 1000
    }

    fn max_retries(self) -> u32 {
        u32::MAX
    }
}
