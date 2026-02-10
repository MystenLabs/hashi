use crate::error::HashiScreenerError;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;

/// Base URL for the MerkleScience API.
/// API docs: <https://docs.merklescience.com/reference>
const MERKLE_SCIENCE_BASE_URL: &str = "https://api.merklescience.com";
pub const RISK_THRESHOLD: i64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    Deposit,
    Withdrawal,
}

impl TransactionType {
    /// MerkleScience transaction type for advanced transaction screening.
    /// See: <https://docs.merklescience.com/reference/transaction-screening-1>
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Deposit => 1,
            Self::Withdrawal => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MerkleScienceRequest {
    identifier: String,
    blockchain: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    screening_type: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct MerkleScienceResponse {
    risk_level: Option<i64>,
}

pub async fn query_transaction_risk_level(
    client: &Client,
    api_key: &str,
    tx_hash: &str,
    blockchain: &str,
    screening_type: TransactionType,
) -> Result<i64, HashiScreenerError> {
    let url = format!("{}/api/v4.2/transactions/", MERKLE_SCIENCE_BASE_URL);
    query_risk_level(client, api_key, &url, tx_hash, blockchain, screening_type).await
}

pub async fn query_address_risk_level(
    client: &Client,
    api_key: &str,
    address: &str,
    blockchain: &str,
    screening_type: TransactionType,
) -> Result<i64, HashiScreenerError> {
    let url = format!("{}/api/v4.2/addresses/", MERKLE_SCIENCE_BASE_URL);
    query_risk_level(client, api_key, &url, address, blockchain, screening_type).await
}

async fn query_risk_level(
    client: &Client,
    api_key: &str,
    url: &str,
    identifier: &str,
    blockchain: &str,
    screening_type: TransactionType,
) -> Result<i64, HashiScreenerError> {
    // TODO: Implement exponential backoff retry for known API Errors (rate limits, chain indexing etc)
    let request_body = MerkleScienceRequest {
        identifier: identifier.to_string(),
        blockchain: blockchain.to_string(),
        screening_type: Some(screening_type.as_i32()),
    };

    let response = client
        .post(url)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("X-API-KEY", api_key)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| {
            HashiScreenerError::InternalError(format!("MerkleScience API request failed: {}", e))
        })?;

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(HashiScreenerError::InternalError(format!(
            "MerkleScience API returned HTTP {}: {}",
            status, body
        )));
    }

    let merkle_response: MerkleScienceResponse = response.json().await.map_err(|e| {
        HashiScreenerError::InternalError(format!(
            "MerkleScience API returned invalid response: {}",
            e
        ))
    })?;

    merkle_response
        .risk_level
        .ok_or(HashiScreenerError::InternalError(
            "MerkleScience API returned invalid response: missing risk_level field".to_string(),
        ))
}
