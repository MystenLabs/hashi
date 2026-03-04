use crate::error::HashiScreenerError;
use backon::ExponentialBuilder;
use backon::Retryable;
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;

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
) -> Result<i64, HashiScreenerError> {
    let url = format!("{}/api/v4.2/transactions/", MERKLE_SCIENCE_BASE_URL);
    query_risk_level(client, api_key, &url, tx_hash, blockchain).await
}

pub async fn query_address_risk_level(
    client: &Client,
    api_key: &str,
    address: &str,
    blockchain: &str,
) -> Result<i64, HashiScreenerError> {
    let url = format!("{}/api/v4.2/addresses/", MERKLE_SCIENCE_BASE_URL);
    query_risk_level(client, api_key, &url, address, blockchain).await
}

fn retry_policy() -> ExponentialBuilder {
    // Recommended retry policy from merkle science docs:
    // https://docs.merklescience.com/reference/retry-policy
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_secs(30))
        .with_max_delay(Duration::from_secs(3000))
        .with_max_times(10)
}

#[derive(Debug)]
enum ApiError {
    Retryable(String),
    Permanent(HashiScreenerError),
}

async fn query_risk_level(
    client: &Client,
    api_key: &str,
    url: &str,
    identifier: &str,
    blockchain: &str,
) -> Result<i64, HashiScreenerError> {
    let request_body = MerkleScienceRequest {
        identifier: identifier.to_string(),
        blockchain: blockchain.to_string(),
    };

    let result = (|| async {
        let response = client
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("X-API-KEY", api_key)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| ApiError::Retryable(format!("MerkleScience API request failed: {}", e)))?;

        if response.status().is_success() {
            let merkle_response: MerkleScienceResponse = response.json().await.map_err(|e| {
                ApiError::Permanent(HashiScreenerError::InternalError(format!(
                    "Failed to deserialize response: {}",
                    e
                )))
            })?;

            return merkle_response.risk_level.ok_or(ApiError::Permanent(
                HashiScreenerError::InternalError(
                    "Missing risk_level field in response".to_string(),
                ),
            ));
        }

        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        // Transaction not Indexed (400) , Rate limits (429) and server errors (5xx) are retryable.
        if status == 400 || status == 429 || status >= 500 {
            return Err(ApiError::Retryable(format!("HTTP {status}: {body}",)));
        }

        // Other client errors (4xx) are not retryable.
        Err(ApiError::Permanent(HashiScreenerError::InternalError(
            format!("HTTP {}: {}", status, body),
        )))
    })
    .retry(retry_policy())
    .when(|e| matches!(e, ApiError::Retryable(_)))
    .notify(|err, dur| {
        tracing::warn!(
            error = ?err,
            retry_after = ?dur,
            url = %url,
            identifier = %identifier,
            blockchain = %blockchain,
            "MerkleScience API - Retrying Request",
        );
    })
    .await;

    match result {
        Ok(risk_level) => Ok(risk_level),
        Err(ApiError::Permanent(e)) => {
            tracing::error!(
                error = %e,
                url = %url,
                identifier = %identifier,
                blockchain = %blockchain,
                "MerkleScience API - Permanent Error",
            );
            Err(e)
        }
        Err(ApiError::Retryable(msg)) => {
            tracing::error!(
                error = %msg,
                url = %url,
                identifier = %identifier,
                blockchain = %blockchain,
                "MerkleScience API - Retries Exhausted",
            );
            Err(HashiScreenerError::InternalError(msg))
        }
    }
}
