use crate::Hashi;
use crate::onchain::types::DepositRequest;
use crate::proto::MemberSignature;
use anyhow::anyhow;
use anyhow::bail;
use bitcoin::hashes::Hash;
use fastcrypto::traits::ToFromBytes;

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
        self.validate_deposit_request_on_bitcoin(deposit_request)
            .await?;
        self.validate_deposit_request_on_sui(deposit_request)?;
        Ok(())
    }

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
        // TODO: check derivation_path/deposit address?
        Ok(())
    }

    fn validate_deposit_request_on_sui(
        &self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<()> {
        let state = self.onchain_state().state();
        let deposit_queue = &state.hashi().deposit_queue;
        match deposit_queue.requests().get(&deposit_request.utxo.id) {
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

    fn sign_deposit_confirmation(
        &self,
        deposit_request: &DepositRequest,
    ) -> anyhow::Result<MemberSignature> {
        let epoch = self.onchain_state().state().hashi().committees.epoch();
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
