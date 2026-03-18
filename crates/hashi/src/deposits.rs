use crate::Hashi;
use crate::leader::RetryPolicy;
use crate::onchain::types::DepositRequest;
use anyhow::Context;
use anyhow::anyhow;
use bitcoin::ScriptBuf;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
use fastcrypto::groups::secp256k1::ProjectivePoint;
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
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
    pub async fn validate_and_sign_deposit_confirmation(
        &self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<MemberSignature> {
        self.validate_deposit_request(deposit_request).await?;
        self.sign_deposit_confirmation(deposit_request)
    }

    pub async fn validate_deposit_request(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), DepositValidationError> {
        self.validate_deposit_request_on_sui(deposit_request)?;
        self.validate_deposit_request_on_bitcoin(deposit_request)
            .await?;
        self.screen_deposit(deposit_request).await?;
        Ok(())
    }

    /// Run AML/Sanctions checks for the deposit request.
    /// If no screener client is configured, checks are skipped.
    async fn screen_deposit(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), DepositValidationError> {
        let Some(screener) = self.screener_client() else {
            tracing::debug!("AML checks skipped: no screener configured");
            return Ok(());
        };

        // bitcoin
        let txid_bytes: [u8; 32] = deposit_request.utxo.id.txid.into();
        let btc_txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let source_tx_hash = btc_txid.to_string();
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
            .map_err(|e| DepositValidationError::AmlServiceError(anyhow!(e)))?;

        if !approved {
            return Err(DepositValidationError::NeverRetry(anyhow!(
                "AML checks failed for source tx {source_tx_hash}, destination {destination_address}, bitcoin chain {bitcoin_chain_id}, sui chain {sui_chain_id}"
            )));
        }

        Ok(())
    }

    /// Validate that the deposit requests exists on Sui
    fn validate_deposit_request_on_sui(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), DepositValidationError> {
        let state = self.onchain_state().state();
        let deposit_queue = &state.hashi().deposit_queue;
        match deposit_queue.requests().get(&deposit_request.id) {
            None => {
                return Err(DepositValidationError::NeverRetry(anyhow!(
                    "Invalid deposit request state on Sui"
                )));
            }
            Some(onchain_request) => {
                if onchain_request != deposit_request {
                    return Err(DepositValidationError::NeverRetry(anyhow!(
                        "Invalid deposit request state on Sui"
                    )));
                }
            }
        }

        let utxo_pool = &state.hashi().utxo_pool;
        if utxo_pool
            .active_utxos()
            .contains_key(&deposit_request.utxo.id)
            || utxo_pool
                .spent_utxos()
                .contains_key(&deposit_request.utxo.id)
        {
            return Err(DepositValidationError::NeverRetry(anyhow!(
                "UTXO {:?} is already active or spent",
                deposit_request.utxo.id
            )));
        }

        Ok(())
    }

    /// Validate that there is a txout on Bitcoin that matches the deposit request
    async fn validate_deposit_request_on_bitcoin(
        &self,
        deposit_request: &DepositRequest,
    ) -> Result<(), DepositValidationError> {
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(deposit_request.utxo.id.txid.into()),
            vout: deposit_request.utxo.id.vout,
        };
        let txout = self
            .btc_monitor()
            .confirm_deposit(outpoint)
            .await
            .map_err(|e| DepositValidationError::BitcoinConfirmFailed(anyhow!(e)))?;
        if txout.value.to_sat() != deposit_request.utxo.amount {
            return Err(DepositValidationError::NeverRetry(anyhow!(
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
    ) -> Result<(), DepositValidationError> {
        let deposit_address =
            bitcoin::Address::from_script(script_pubkey, self.config.bitcoin_network()).map_err(
                |e| {
                    DepositValidationError::NeverRetry(anyhow!(
                        "Failed to extract address from script_pubkey: {e}"
                    ))
                },
            )?;
        let hashi_pubkey = self
            .get_hashi_pubkey()
            .map_err(DepositValidationError::NotReady)?;
        let expected_address = self
            .get_deposit_address(&hashi_pubkey, deposit_request.utxo.derivation_path.as_ref())
            .map_err(DepositValidationError::NeverRetry)?;

        if deposit_address != expected_address {
            return Err(DepositValidationError::NeverRetry(anyhow!(
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
            let verifying_key = self
                .signing_verifying_key()
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

    fn sign_deposit_confirmation(
        &self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<MemberSignature> {
        let epoch = self.onchain_state().epoch();
        let validator_address = self
            .config
            .validator_address()
            .map_err(|e| anyhow!("No validator address configured: {}", e))?;
        let private_key = self
            .config
            .protocol_private_key()
            .ok_or_else(|| anyhow!("No protocol private key configured"))?;
        let public_key_bytes = private_key.public_key().as_bytes().to_vec().into();

        let signature_bytes = private_key
            .sign(epoch, validator_address, deposit_request)
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
pub enum DepositValidationErrorKind {
    BitcoinConfirmFailed,
    AmlServiceError,
    NotReady,
    NeverRetry,
}

impl RetryPolicy for DepositValidationErrorKind {
    fn retry_base_delay_ms(self) -> u64 {
        match self {
            Self::AmlServiceError => 5 * 1000,
            Self::NotReady => 5 * 1000,
            Self::BitcoinConfirmFailed => 60 * 1000,
            Self::NeverRetry => u64::MAX,
        }
    }

    fn max_delay_ms(self) -> u64 {
        60 * 1000
    }

    fn max_retries(self) -> u32 {
        match self {
            Self::AmlServiceError | Self::NotReady => u32::MAX,
            Self::BitcoinConfirmFailed => 60 * 24,
            Self::NeverRetry => 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum DepositValidationError {
    #[error("Failed to confirm Bitcoin deposit: {0}")]
    BitcoinConfirmFailed(#[source] anyhow::Error),

    #[error("Screener service error: {0}")]
    AmlServiceError(#[source] anyhow::Error),

    #[error("Not ready: {0}")]
    NotReady(#[source] anyhow::Error),

    #[error("Never retry: {0}")]
    NeverRetry(#[source] anyhow::Error),
}

impl DepositValidationError {
    pub fn kind(&self) -> DepositValidationErrorKind {
        match self {
            Self::BitcoinConfirmFailed(_) => DepositValidationErrorKind::BitcoinConfirmFailed,
            Self::AmlServiceError(_) => DepositValidationErrorKind::AmlServiceError,
            Self::NotReady(_) => DepositValidationErrorKind::NotReady,
            Self::NeverRetry(_) => DepositValidationErrorKind::NeverRetry,
        }
    }
}
