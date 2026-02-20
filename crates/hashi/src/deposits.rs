use crate::Hashi;
use crate::onchain::types::DepositRequest;
use anyhow::anyhow;
use anyhow::bail;
use bitcoin::ScriptBuf;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use hashi_types::proto::MemberSignature;

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
    ) -> anyhow::Result<()> {
        self.validate_deposit_request_on_sui(deposit_request)?;
        self.validate_deposit_request_on_bitcoin(deposit_request)
            .await?;
        self.screen_deposit(deposit_request).await?;
        Ok(())
    }

    /// Run AML/Sanctions checks for the deposit request.
    /// If no screener client is configured, checks are skipped.
    async fn screen_deposit(&self, deposit_request: &DepositRequest) -> anyhow::Result<()> {
        let Some(screener) = self.screener_client() else {
            tracing::debug!("AML checks skipped: no screener configured");
            return Ok(());
        };

        // bitcoin
        let txid_bytes: [u8; 32] = deposit_request.utxo.id.txid.into();
        let btc_txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let source_tx_hash = btc_txid.to_string();

        // sui
        let destination_address = deposit_request.id.to_string();

        let approved = screener
            .approve_deposit(
                &source_tx_hash,
                &destination_address,
                self.config.bitcoin_chain_id(),
                self.config.sui_chain_id(),
            )
            .await
            .map_err(|e| anyhow!("Screener service error: {e}"))?;

        if !approved {
            bail!("AML checks failed for tx {source_tx_hash}");
        }

        Ok(())
    }

    /// Validate that the deposit requests exists on Sui
    fn validate_deposit_request_on_sui(
        &self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<()> {
        let state = self.onchain_state().state();
        let deposit_queue = &state.hashi().deposit_queue;
        match deposit_queue.requests().get(&deposit_request.id) {
            None => {
                bail!(
                    "Deposit request not found on Sui: {:?}",
                    deposit_request.utxo.id
                );
            }
            Some(onchain_request) => {
                if onchain_request != deposit_request {
                    bail!(
                        "Given deposit request does not match deposit request on sui. Given: {:?}, onchain: {:?}",
                        deposit_request,
                        onchain_request
                    );
                }
            }
        }
        Ok(())
    }

    /// Validate that there is a txout on Bitcoin that matches the deposit request
    async fn validate_deposit_request_on_bitcoin(
        &self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<()> {
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(deposit_request.utxo.id.txid.into()),
            vout: deposit_request.utxo.id.vout,
        };
        let txout = self
            .btc_monitor()
            .confirm_deposit(outpoint)
            .await
            .map_err(|e| anyhow!("Failed to confirm Bitcoin deposit: {}", e))?;
        if txout.value.to_sat() != deposit_request.utxo.amount {
            bail!(
                "Bitcoin deposit amount mismatch: got {}, onchain is {}",
                deposit_request.utxo.amount,
                txout.value
            );
        }

        let deposit_address = self.bitcoin_address_from_script_pubkey(&txout.script_pubkey)?;
        self.validate_deposit_request_derivation_path(deposit_address, deposit_request)
            .await?;
        Ok(())
    }

    async fn validate_deposit_request_derivation_path(
        &self,
        deposit_address: bitcoin::Address,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<()> {
        let hashi_pubkey = self.get_hashi_pubkey();
        let expected_address =
            self.get_deposit_address(&hashi_pubkey, deposit_request.utxo.derivation_path.as_ref());

        if deposit_address != expected_address {
            bail!(
                "Deposit address mismatch. Expected: {}, got: {}",
                expected_address,
                deposit_address
            );
        }

        Ok(())
    }

    pub fn get_deposit_address(
        &self,
        hashi_pubkey: &XOnlyPublicKey,
        derivation_path: Option<&sui_sdk_types::Address>,
    ) -> bitcoin::Address {
        let pubkey = if let Some(path) = derivation_path {
            let verifying_key = self.signing_verifying_key().or_else(|| {
                self.mpc_handle()
                    .expect("MpcHandle not initialized")
                    .public_key()
            })
            .expect("MPC public key not available yet");
            let derived = fastcrypto_tbls::threshold_schnorr::key_derivation::derive_verifying_key(
                &verifying_key,
                &path.into_inner(),
            );
            XOnlyPublicKey::from_slice(&derived.to_byte_array()).expect("valid 32-byte x-only key")
        } else {
            *hashi_pubkey
        };
        self.bitcoin_address_from_pubkey(&pubkey)
    }

    fn bitcoin_address_from_pubkey(&self, pubkey: &XOnlyPublicKey) -> bitcoin::Address {
        // let network = self.config.bitcoin_network();
        // let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        // bitcoin::Address::p2tr(&secp, *pubkey, None, network)
        let network = self.config.bitcoin_network();
        let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(*pubkey);
        bitcoin::Address::p2tr_tweaked(tweaked, network)
    }

    fn bitcoin_address_from_script_pubkey(
        &self,
        script_pubkey: &ScriptBuf,
    ) -> anyhow::Result<bitcoin::Address> {
        bitcoin::Address::from_script(script_pubkey, self.config.bitcoin_network())
            .map_err(|e| anyhow!("Failed to extract address from script_pubkey: {}", e))
    }

    pub fn get_hashi_pubkey(&self) -> XOnlyPublicKey {
        let g = self
            .mpc_handle()
            .expect("MpcHandle not initialized")
            .public_key()
            .expect("MPC public key not available yet");
        // Convert G (ProjectivePoint, 33 bytes compressed) to SchnorrPublicKey (32 bytes x-only)
        let schnorr_pk =
            SchnorrPublicKey::try_from(&g).expect("valid non-zero group element for schnorr key");
        XOnlyPublicKey::from_slice(&schnorr_pk.to_byte_array()).expect("valid 32-byte x-only key")
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
