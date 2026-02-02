use crate::Hashi;
use crate::onchain::types::DepositRequest;
use anyhow::anyhow;
use anyhow::bail;
use bitcoin::ScriptBuf;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
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
            hashi_guardian_shared::bitcoin_utils::get_derived_pubkey(
                hashi_pubkey,
                &path.into_inner(),
            )
        } else {
            *hashi_pubkey
        };
        self.bitcoin_address_from_pubkey(&pubkey)
    }
    fn bitcoin_address_from_script_pubkey(
        &self,
        script_pubkey: &ScriptBuf,
    ) -> anyhow::Result<bitcoin::Address> {
        bitcoin::Address::from_script(script_pubkey, self.config.bitcoin_network())
            .map_err(|e| anyhow!("Failed to extract address from script_pubkey: {}", e))
    }

    fn bitcoin_address_from_pubkey(&self, pubkey: &XOnlyPublicKey) -> bitcoin::Address {
        let network = self.config.bitcoin_network();
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        bitcoin::Address::p2tr(&secp, *pubkey, None, network)
    }

    /// TODO: Use the real key
    pub fn get_hashi_pubkey(&self) -> XOnlyPublicKey {
        let hardcoded_key_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        XOnlyPublicKey::from_slice(&hex::decode(hardcoded_key_hex).unwrap()).unwrap()
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
