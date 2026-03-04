use std::str::FromStr;
use std::time::Duration;

use hashi_types::proto::screener::ApproveRequest;
use hashi_types::proto::screener::TransactionType;
use hashi_types::proto::screener::screener_service_client::ScreenerServiceClient;
use tonic::transport::Channel;
use tonic::transport::Endpoint;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone, Debug)]
pub struct ScreenerClient {
    endpoint: String,
    channel: Channel,
}

impl ScreenerClient {
    pub fn new(endpoint: &str) -> Result<Self, tonic::Status> {
        let channel = Endpoint::new(endpoint.to_string())
            .map_err(Into::<BoxError>::into)
            .map_err(tonic::Status::from_error)?
            .connect_timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(5))
            .connect_lazy();
        Ok(Self {
            endpoint: endpoint.to_string(),
            channel,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn screener_service_client(&self) -> ScreenerServiceClient<Channel> {
        ScreenerServiceClient::new(self.channel.clone())
    }

    pub async fn approve_deposit(
        &self,
        source_tx_hash: &str,
        destination_address: &str,
        source_chain_id: &str,
        destination_chain_id: &str,
    ) -> Result<bool, tonic::Status> {
        let request = ApproveRequest {
            source_transaction_hash: source_tx_hash.to_string(),
            destination_address: destination_address.to_string(),
            source_chain_id: btc_chain_id_to_caip2(source_chain_id)?,
            destination_chain_id: sui_chain_id_to_caip2(destination_chain_id)?,
            transaction_type: TransactionType::Deposit.into(),
        };
        let response = self.screener_service_client().approve(request).await?;
        Ok(response.into_inner().approved)
    }

    pub async fn approve_withdrawal(
        &self,
        source_tx_hash: &str,
        destination_address: &str,
        source_chain_id: &str,
        destination_chain_id: &str,
    ) -> Result<bool, tonic::Status> {
        let request = ApproveRequest {
            source_transaction_hash: source_tx_hash.to_string(),
            destination_address: destination_address.to_string(),
            source_chain_id: sui_chain_id_to_caip2(source_chain_id)?,
            destination_chain_id: btc_chain_id_to_caip2(destination_chain_id)?,
            transaction_type: TransactionType::Withdrawal.into(),
        };
        let response = self.screener_service_client().approve(request).await?;
        Ok(response.into_inner().approved)
    }
}

/// Convert a full Bitcoin genesis block hash to CAIP-2 (BIP-122) chain ID.
/// Format: "bip122:" + first 16 bytes of the hex encoded genesis block hash.
fn btc_chain_id_to_caip2(genesis_block_hash: &str) -> Result<String, tonic::Status> {
    if genesis_block_hash.len() < 32 {
        return Err(tonic::Status::internal(format!(
            "invalid bitcoin chain id: expected at least 32 hex characters, got {}",
            genesis_block_hash.len()
        )));
    }
    Ok(format!("bip122:{}", &genesis_block_hash[..32]))
}

/// Convert a full Sui genesis checkpoint digest (base58) to CAIP-2 chain ID.
/// Format: "sui:" + first 4 bytes of decoded digest as hex.
fn sui_chain_id_to_caip2(genesis_checkpoint_digest: &str) -> Result<String, tonic::Status> {
    let digest = sui_sdk_types::Digest::from_str(genesis_checkpoint_digest)
        .map_err(|e| tonic::Status::internal(format!("invalid sui chain id: {e}")))?;
    Ok(format!("sui:{}", hex::encode(&digest.inner()[..4])))
}
