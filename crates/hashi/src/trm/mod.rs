// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AML screening through the TRM Labs Compliance API, using the node
//! operator's own API key.

use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::anyhow;
use sui_sdk_types::Address;
use tokio::time::Instant;

use crate::btc_monitor::config::Network;
use crate::config::Config;
use crate::onchain::types::DepositRequest;

const TRM_API_URL: &str = "https://api.trmlabs.com";
const BITCOIN_CHAIN: &str = "bitcoin";
const SUI_CHAIN: &str = "sui";

/// One deadline for a whole screening, across all of its requests.
const SCREENING_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a deposit screening keeps reading a transfer TRM is still
/// processing. TRM screens most confirmed transactions within seconds; a
/// slower transfer is reported pending and read again on a later attempt.
const TRANSFER_WAIT: Duration = Duration::from_secs(10);
const TRANSFER_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// TRM allows each account 10 requests per second per endpoint. Spacing
/// requests further apart makes a burst wait for its turn instead of failing
/// with 429.
const REQUEST_INTERVAL: Duration = Duration::from_millis(125);

/// TRM's "High" risk score level. Scores at or above it reject.
const HIGH_RISK_SCORE_LEVEL: u8 = 10;

pub struct TrmClient {
    http: reqwest::Client,
    base_url: reqwest::Url,
    api_key: String,
    transfer_submissions: Pacer,
    transfer_reads: Pacer,
    address_screenings: Pacer,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Approved,
    Rejected(String),
    /// TRM has not finished screening the transfer yet.
    Pending,
}

#[derive(Debug, thiserror::Error)]
pub enum TrmError {
    /// Timeouts, transport failures, rate limiting and TRM server errors.
    #[error("{0}")]
    Transient(anyhow::Error),
    #[error("{0}")]
    Permanent(anyhow::Error),
}

pub struct DepositScreening {
    request_id: Address,
    txid: String,
    deposit_address: String,
    amount_sats: u64,
    created_timestamp_ms: u64,
    recipient: Option<Address>,
    sender: Address,
}

impl DepositScreening {
    pub fn new(request: &DepositRequest, deposit_address: String) -> Self {
        Self {
            request_id: request.id,
            txid: request.utxo.id.txid.to_string(),
            deposit_address,
            amount_sats: request.utxo.amount,
            created_timestamp_ms: request.created_timestamp_ms,
            // `confirm_deposit` mints to the derivation path, not to the
            // request object, so that is the Sui address to screen.
            recipient: request.utxo.derivation_path,
            sender: request.sender,
        }
    }
}

impl TrmClient {
    /// Returns `None`, so screening is skipped, without an API key or off
    /// mainnet. TRM only screens mainnet, and startup pairs Bitcoin mainnet
    /// only with Sui mainnet.
    pub fn from_config(config: &Config) -> anyhow::Result<Option<Self>> {
        match (config.trm_api_key(), config.bitcoin_network()) {
            (Some(api_key), Network::Bitcoin) => Self::new(api_key.to_owned()).map(Some),
            (None, Network::Bitcoin) => {
                tracing::warn!("No TRM API key configured; AML screening is disabled");
                Ok(None)
            }
            (Some(_), _) => {
                tracing::warn!("TRM only screens mainnet; AML screening is disabled");
                Ok(None)
            }
            (None, _) => Ok(None),
        }
    }

    fn new(api_key: String) -> anyhow::Result<Self> {
        Self::with_base_url(api_key, TRM_API_URL)
    }

    fn with_base_url(api_key: String, base_url: &str) -> anyhow::Result<Self> {
        // reqwest would turn a redirected POST into a bodyless GET.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            base_url: reqwest::Url::parse(base_url)?,
            api_key,
            transfer_submissions: Pacer::new(),
            transfer_reads: Pacer::new(),
            address_screenings: Pacer::new(),
        })
    }

    /// Registers the Bitcoin deposit transaction with Transaction Monitoring,
    /// screens the Sui recipient, then waits briefly for the transfer's
    /// screening result.
    pub async fn screen_deposit(&self, deposit: &DepositScreening) -> Result<Verdict, TrmError> {
        let started = Instant::now();
        let deadline = started + SCREENING_TIMEOUT;
        with_deadline(deadline, async {
            let transfer = self.submit_deposit_transfer(deposit, deadline).await?;
            if let Some(recipient) = deposit.recipient {
                let recipient = recipient.to_string();
                let verdict = self
                    .screen_addresses(
                        &[AddressQuery {
                            address: &recipient,
                            chain: SUI_CHAIN,
                        }],
                        deadline,
                    )
                    .await?;
                if verdict != Verdict::Approved {
                    return Ok(verdict);
                }
            }
            let uuid = transfer.uuid.as_str();
            poll_transfer(
                || async move { self.get_transfer(uuid, deadline).await?.verdict() },
                started + TRANSFER_WAIT,
            )
            .await
        })
        .await
    }

    /// Screens the Bitcoin destination and the Sui address that requested
    /// the withdrawal.
    pub async fn screen_withdrawal(
        &self,
        bitcoin_address: &str,
        sender: Address,
    ) -> Result<Verdict, TrmError> {
        let sender = sender.to_string();
        let deadline = Instant::now() + SCREENING_TIMEOUT;
        with_deadline(
            deadline,
            self.screen_addresses(
                &[
                    AddressQuery {
                        address: bitcoin_address,
                        chain: BITCOIN_CHAIN,
                    },
                    AddressQuery {
                        address: &sender,
                        chain: SUI_CHAIN,
                    },
                ],
                deadline,
            ),
        )
        .await
    }

    async fn submit_deposit_transfer(
        &self,
        deposit: &DepositScreening,
        deadline: Instant,
    ) -> Result<Transfer, TrmError> {
        let submission = TransferSubmission {
            account_external_id: deposit.recipient.unwrap_or(deposit.sender).to_string(),
            asset: "btc",
            asset_amount: btc_amount(deposit.amount_sats),
            chain: BITCOIN_CHAIN,
            destination_address: &deposit.deposit_address,
            // TRM ignores a resubmitted externalId and returns the existing
            // transfer, so retries, restarts and leader changes don't duplicate it.
            external_id: format!("hashi-deposit-{}", deposit.request_id),
            fiat_currency: "USD",
            // Nodes have no price feed; TRM accepts 0 when no rule uses fiat value.
            fiat_value: "0",
            onchain_reference: &deposit.txid,
            timestamp: timestamp(deposit.created_timestamp_ms)?,
            transfer_type: "CRYPTO_DEPOSIT",
        };
        let url = self.url(&["public", "v2", "tm", "transfers"]);
        self.send(
            &self.transfer_submissions,
            self.http.post(url).json(&submission),
            deadline,
        )
        .await
    }

    async fn get_transfer(&self, uuid: &str, deadline: Instant) -> Result<Transfer, TrmError> {
        let mut url = self.url(&["public", "v2", "tm", "transfers"]);
        url.path_segments_mut()
            .expect("TRM base URL is an http(s) URL")
            .push(uuid);
        self.send(&self.transfer_reads, self.http.get(url), deadline)
            .await
    }

    async fn screen_addresses(
        &self,
        queries: &[AddressQuery<'_>],
        deadline: Instant,
    ) -> Result<Verdict, TrmError> {
        let url = self.url(&["public", "v2", "screening", "addresses"]);
        let results: Vec<AddressScreening> = self
            .send(
                &self.address_screenings,
                self.http.post(url).json(queries),
                deadline,
            )
            .await?;
        if let Some(missing) = queries.iter().find(|query| {
            !results
                .iter()
                .any(|result| result.address_submitted == query.address)
        }) {
            return Err(TrmError::Permanent(anyhow!(
                "TRM returned no screening result for {} address {}",
                missing.chain,
                missing.address
            )));
        }
        let rejections: Vec<String> = results
            .iter()
            .filter_map(AddressScreening::rejection)
            .collect();
        if rejections.is_empty() {
            Ok(Verdict::Approved)
        } else {
            Ok(Verdict::Rejected(rejections.join("; ")))
        }
    }

    fn url(&self, segments: &[&str]) -> reqwest::Url {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .expect("TRM base URL is an http(s) URL")
            .pop_if_empty()
            .extend(segments);
        url
    }

    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        pacer: &Pacer,
        request: reqwest::RequestBuilder,
        deadline: Instant,
    ) -> Result<T, TrmError> {
        pacer.wait_turn(deadline).await?;
        let response = request
            .basic_auth(&self.api_key, Some(&self.api_key))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| {
                if e.is_builder() {
                    TrmError::Permanent(e.into())
                } else {
                    TrmError::Transient(e.into())
                }
            })?;
        let status = response.status();
        if !status.is_success() {
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                pacer.hold_until(Instant::now() + retry_after(response.headers()));
            }
            let body = response.text().await.unwrap_or_default();
            let error = anyhow!(
                "TRM returned {status}: {}",
                body.chars().take(512).collect::<String>()
            );
            return Err(
                if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                    TrmError::Transient(error)
                } else {
                    TrmError::Permanent(error)
                },
            );
        }
        response.json().await.map_err(|e| {
            if e.is_decode() {
                TrmError::Permanent(anyhow!("unexpected TRM response: {e}"))
            } else {
                TrmError::Transient(e.into())
            }
        })
    }
}

#[derive(serde_derive::Serialize)]
struct AddressQuery<'a> {
    address: &'a str,
    chain: &'a str,
}

#[derive(serde_derive::Serialize)]
#[serde(rename_all = "camelCase")]
struct TransferSubmission<'a> {
    account_external_id: String,
    asset: &'a str,
    asset_amount: String,
    chain: &'a str,
    destination_address: &'a str,
    external_id: String,
    fiat_currency: &'a str,
    fiat_value: &'a str,
    onchain_reference: &'a str,
    timestamp: String,
    transfer_type: &'a str,
}

#[derive(serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressScreening {
    address_submitted: String,
    chain: String,
    address_risk_indicators: Vec<RiskIndicator>,
    trm_app_url: Option<String>,
}

#[derive(serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RiskIndicator {
    category: String,
    category_id: String,
    category_risk_score_level: Option<u8>,
    risk_type: String,
}

#[derive(serde_derive::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Transfer {
    uuid: String,
    screen_status: Option<String>,
    screen_status_failed_reason: Option<String>,
    risk_score_level: Option<u8>,
    trm_app_url: Option<String>,
}

impl AddressScreening {
    /// Rejects an address TRM attributes directly (OWNERSHIP) to a High or
    /// Severe category. Counterparty or indirect exposure alone doesn't
    /// reject, since dust sent from a flagged source would taint any address.
    fn rejection(&self) -> Option<String> {
        let categories: Vec<String> = self
            .address_risk_indicators
            .iter()
            .filter(|indicator| {
                indicator.risk_type == "OWNERSHIP"
                    && indicator
                        .category_risk_score_level
                        .is_some_and(|level| level >= HIGH_RISK_SCORE_LEVEL)
            })
            .map(|indicator| format!("{} ({})", indicator.category, indicator.category_id))
            .collect();
        if categories.is_empty() {
            return None;
        }
        Some(format!(
            "{} address {} is attributed to {} ({})",
            self.chain,
            self.address_submitted,
            categories.join(", "),
            self.trm_app_url.as_deref().unwrap_or("no TRM link"),
        ))
    }
}

impl Transfer {
    fn verdict(&self) -> Result<Verdict, TrmError> {
        let link = self.trm_app_url.as_deref().unwrap_or("no TRM link");
        match self.screen_status.as_deref() {
            Some("PROCESSING") => Ok(Verdict::Pending),
            Some("SUCCEEDED") => Ok(match self.risk_score_level {
                Some(level) if level >= HIGH_RISK_SCORE_LEVEL => Verdict::Rejected(format!(
                    "TRM transfer {} raised an alert at risk score level {level} ({link})",
                    self.uuid
                )),
                _ => Verdict::Approved,
            }),
            // TRM never rescreens a transfer under the same externalId.
            status => Err(TrmError::Permanent(anyhow!(
                "TRM could not screen transfer {} (status {}, reason {}) ({link})",
                self.uuid,
                status.unwrap_or("null"),
                self.screen_status_failed_reason
                    .as_deref()
                    .unwrap_or("none"),
            ))),
        }
    }
}

/// Spaces the requests to one TRM endpoint `REQUEST_INTERVAL` apart.
struct Pacer {
    next_turn: Mutex<Instant>,
}

impl Pacer {
    fn new() -> Self {
        Self {
            next_turn: Mutex::new(Instant::now()),
        }
    }

    /// Waits for the endpoint's next free turn. Refuses, without taking the
    /// turn, when it would start after `deadline`.
    async fn wait_turn(&self, deadline: Instant) -> Result<(), TrmError> {
        let turn = {
            let mut next_turn = self.next_turn.lock().unwrap();
            let turn = (*next_turn).max(Instant::now());
            if turn > deadline {
                return Err(TrmError::Transient(anyhow!(
                    "TRM requests are queued past the screening deadline"
                )));
            }
            *next_turn = turn + REQUEST_INTERVAL;
            turn
        };
        tokio::time::sleep_until(turn).await;
        Ok(())
    }

    /// Holds back every later turn until `until`.
    fn hold_until(&self, until: Instant) {
        let mut next_turn = self.next_turn.lock().unwrap();
        *next_turn = (*next_turn).max(until);
    }
}

async fn with_deadline(
    deadline: Instant,
    screening: impl Future<Output = Result<Verdict, TrmError>>,
) -> Result<Verdict, TrmError> {
    tokio::time::timeout_at(deadline, screening)
        .await
        .unwrap_or_else(|_| {
            Err(TrmError::Transient(anyhow!(
                "TRM screening timed out after {SCREENING_TIMEOUT:?}"
            )))
        })
}

/// Reads a transfer until TRM has finished screening it, or until another read
/// would start after `wait_until`.
async fn poll_transfer<F, Fut>(mut read: F, wait_until: Instant) -> Result<Verdict, TrmError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Verdict, TrmError>>,
{
    loop {
        let verdict = read().await?;
        if verdict != Verdict::Pending || Instant::now() + TRANSFER_POLL_INTERVAL > wait_until {
            return Ok(verdict);
        }
        tokio::time::sleep(TRANSFER_POLL_INTERVAL).await;
    }
}

/// How long TRM asks us to wait after a 429, capped so a bad header can't
/// stall screening.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Duration {
    let seconds = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok()?.trim().parse().ok())
        .unwrap_or(1);
    Duration::from_secs(seconds.min(60))
}

fn btc_amount(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

fn timestamp(ms: u64) -> Result<String, TrmError> {
    i64::try_from(ms)
        .ok()
        .and_then(|ms| jiff::Timestamp::from_millisecond(ms).ok())
        .map(|timestamp| timestamp.to_string())
        .ok_or_else(|| TrmError::Permanent(anyhow!("timestamp {ms}ms is out of range")))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;

    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::http::HeaderValue;
    use axum::http::Method;
    use axum::http::StatusCode;
    use axum::http::Uri;
    use axum::response::IntoResponse;
    use base64ct::Encoding as _;
    use serde_json::Value;
    use serde_json::json;
    use sui_sdk_types::Digest;

    use super::*;
    use crate::constants::BITCOIN_MAINNET_CHAIN_ID;
    use crate::constants::BITCOIN_TESTNET4_CHAIN_ID;
    use crate::onchain::types::Utxo;
    use crate::onchain::types::UtxoId;

    const API_KEY: &str = "test-key";
    const TRANSFER_UUID: &str = "00000000-0000-4000-8000-0000000000aa";
    const BITCOIN_ADDRESS: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

    /// Answers requests with scripted responses, in order, and records them.
    struct MockTrm {
        responses: VecDeque<(StatusCode, Value)>,
        requests: Vec<(String, Value)>,
    }

    type Mock = Arc<Mutex<MockTrm>>;

    async fn mock_trm<const N: usize>(responses: [(StatusCode, Value); N]) -> (TrmClient, Mock) {
        let mock = Arc::new(Mutex::new(MockTrm {
            responses: responses.into(),
            requests: Vec::new(),
        }));
        let app = axum::Router::new()
            .fallback(respond)
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (
            TrmClient::with_base_url(API_KEY.to_owned(), &base_url).unwrap(),
            mock,
        )
    }

    async fn respond(
        State(mock): State<Mock>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: String,
    ) -> axum::response::Response {
        if !authorized(&headers) {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        let mut mock = mock.lock().unwrap();
        mock.requests.push((
            format!("{method} {}", uri.path()),
            serde_json::from_str(&body).unwrap_or(Value::Null),
        ));
        let (status, response) = mock
            .responses
            .pop_front()
            .unwrap_or((StatusCode::NOT_IMPLEMENTED, json!("unexpected request")));
        let mut reply = (status, response.to_string()).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            reply.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                HeaderValue::from_static("2"),
            );
        }
        reply
    }

    fn authorized(headers: &HeaderMap) -> bool {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Basic "))
            .and_then(|encoded| base64ct::Base64::decode_vec(encoded).ok())
            .is_some_and(|decoded| decoded == format!("{API_KEY}:{API_KEY}").as_bytes())
    }

    fn address_screening(address: &str, chain: &str, indicators: Value) -> Value {
        json!({
            "addressSubmitted": address,
            "chain": chain,
            "addressRiskIndicators": indicators,
        })
    }

    fn indicator(risk_type: &str, risk_score_level: u8) -> Value {
        json!({
            "category": "Sanctions",
            "categoryId": "69",
            "categoryRiskScoreLevel": risk_score_level,
            "riskType": risk_type,
        })
    }

    fn transfer(screen_status: &str, risk_score_level: Option<u8>) -> Value {
        json!({
            "uuid": TRANSFER_UUID,
            "screenStatus": screen_status,
            "riskScoreLevel": risk_score_level,
        })
    }

    fn deposit_request(derivation_path: Option<Address>) -> DepositRequest {
        DepositRequest {
            id: Address::new([2; 32]),
            sender: Address::new([3; 32]),
            created_timestamp_ms: 1_789_464_112_688,
            sui_tx_digest: Digest::new([4; 32]),
            utxo: Utxo {
                id: UtxoId {
                    txid: Address::new([5; 32]).into(),
                    vout: 0,
                },
                amount: 12_345,
                derivation_path,
            },
            approval_cert: None,
            approved_timestamp_ms: None,
            confirmed_timestamp_ms: None,
        }
    }

    #[test]
    fn screening_needs_an_api_key_and_mainnet() {
        let mut config = Config::new_for_testing();
        config.bitcoin_chain_id = Some(BITCOIN_MAINNET_CHAIN_ID.to_owned());
        assert!(TrmClient::from_config(&config).unwrap().is_none());

        config.trm_api_key = Some(API_KEY.to_owned());
        assert!(TrmClient::from_config(&config).unwrap().is_some());

        // Startup accepts the chain id in either hex case.
        config.bitcoin_chain_id = Some(BITCOIN_MAINNET_CHAIN_ID.to_uppercase());
        assert!(TrmClient::from_config(&config).unwrap().is_some());

        config.bitcoin_chain_id = Some(BITCOIN_TESTNET4_CHAIN_ID.to_owned());
        assert!(TrmClient::from_config(&config).unwrap().is_none());
    }

    #[tokio::test]
    async fn deposit_screens_the_bitcoin_transfer_and_the_mint_recipient() {
        let request = deposit_request(Some(Address::new([1; 32])));
        let recipient = request.utxo.derivation_path.unwrap().to_string();
        let (client, mock) = mock_trm([
            (StatusCode::CREATED, transfer("PROCESSING", None)),
            (
                StatusCode::CREATED,
                json!([address_screening(&recipient, "sui", json!([]))]),
            ),
            (StatusCode::OK, transfer("SUCCEEDED", Some(0))),
        ])
        .await;

        let verdict = client
            .screen_deposit(&DepositScreening::new(&request, BITCOIN_ADDRESS.to_owned()))
            .await
            .unwrap();

        assert_eq!(verdict, Verdict::Approved);
        assert_eq!(
            mock.lock().unwrap().requests,
            [
                (
                    "POST /public/v2/tm/transfers".to_owned(),
                    json!({
                        "accountExternalId": recipient,
                        "asset": "btc",
                        "assetAmount": "0.00012345",
                        "chain": "bitcoin",
                        "destinationAddress": BITCOIN_ADDRESS,
                        "externalId": format!("hashi-deposit-{}", request.id),
                        "fiatCurrency": "USD",
                        "fiatValue": "0",
                        "onchainReference": request.utxo.id.txid.to_string(),
                        "timestamp": "2026-09-15T09:21:52.688Z",
                        "transferType": "CRYPTO_DEPOSIT",
                    }),
                ),
                (
                    "POST /public/v2/screening/addresses".to_owned(),
                    json!([{ "address": recipient, "chain": "sui" }]),
                ),
                (
                    format!("GET /public/v2/tm/transfers/{TRANSFER_UUID}"),
                    Value::Null,
                ),
            ]
        );
    }

    #[tokio::test]
    async fn deposit_is_rejected_when_the_recipient_is_high_risk() {
        let request = deposit_request(Some(Address::new([1; 32])));
        let recipient = request.utxo.derivation_path.unwrap().to_string();
        let (client, _) = mock_trm([
            (StatusCode::CREATED, transfer("PROCESSING", None)),
            (
                StatusCode::CREATED,
                json!([address_screening(
                    &recipient,
                    "sui",
                    json!([indicator("OWNERSHIP", 15)])
                )]),
            ),
        ])
        .await;

        let verdict = client
            .screen_deposit(&DepositScreening::new(&request, BITCOIN_ADDRESS.to_owned()))
            .await
            .unwrap();

        assert!(matches!(verdict, Verdict::Rejected(reason) if reason.contains(&recipient)));
    }

    #[tokio::test]
    async fn deposit_without_a_recipient_skips_address_screening() {
        let request = deposit_request(None);
        let (client, mock) = mock_trm([
            (StatusCode::CREATED, transfer("PROCESSING", None)),
            (StatusCode::OK, transfer("SUCCEEDED", Some(0))),
        ])
        .await;

        let verdict = client
            .screen_deposit(&DepositScreening::new(&request, BITCOIN_ADDRESS.to_owned()))
            .await
            .unwrap();

        assert_eq!(verdict, Verdict::Approved);
        assert_eq!(
            mock.lock().unwrap().requests[0].1["accountExternalId"],
            request.sender.to_string()
        );
    }

    #[tokio::test]
    async fn withdrawal_screens_the_destination_and_the_requester() {
        let requester = Address::new([1; 32]);
        let (client, mock) = mock_trm([(
            StatusCode::CREATED,
            json!([
                address_screening(BITCOIN_ADDRESS, "bitcoin", json!([])),
                address_screening(
                    &requester.to_string(),
                    "sui",
                    json!([indicator("OWNERSHIP", 10)])
                ),
            ]),
        )])
        .await;

        let verdict = client
            .screen_withdrawal(BITCOIN_ADDRESS, requester)
            .await
            .unwrap();

        assert!(
            matches!(verdict, Verdict::Rejected(reason) if reason.contains(&requester.to_string()))
        );
        assert_eq!(
            mock.lock().unwrap().requests,
            [(
                "POST /public/v2/screening/addresses".to_owned(),
                json!([
                    { "address": BITCOIN_ADDRESS, "chain": "bitcoin" },
                    { "address": requester.to_string(), "chain": "sui" },
                ]),
            )]
        );
    }

    #[test]
    fn only_high_risk_ownership_rejects_an_address() {
        let rejects = |indicators| {
            serde_json::from_value::<AddressScreening>(address_screening(
                BITCOIN_ADDRESS,
                "bitcoin",
                indicators,
            ))
            .unwrap()
            .rejection()
            .is_some()
        };

        assert!(!rejects(json!([])));
        assert!(rejects(json!([indicator("OWNERSHIP", 10)])));
        assert!(!rejects(json!([indicator("OWNERSHIP", 5)])));
        assert!(!rejects(json!([
            indicator("COUNTERPARTY", 15),
            indicator("INDIRECT", 15)
        ])));
    }

    #[test]
    fn transfer_verdict_follows_the_screen_status_and_alert_level() {
        let verdict = |value| serde_json::from_value::<Transfer>(value).unwrap().verdict();

        assert_eq!(
            verdict(transfer("PROCESSING", None)).unwrap(),
            Verdict::Pending
        );
        assert_eq!(
            verdict(transfer("SUCCEEDED", Some(5))).unwrap(),
            Verdict::Approved
        );
        assert!(matches!(
            verdict(transfer("SUCCEEDED", Some(10))),
            Ok(Verdict::Rejected(_))
        ));
        assert!(matches!(
            verdict(transfer("FAILED", None)),
            Err(TrmError::Permanent(_))
        ));
        assert!(matches!(
            verdict(json!({ "uuid": TRANSFER_UUID, "screenStatus": null })),
            Err(TrmError::Permanent(_))
        ));
    }

    #[tokio::test]
    async fn deposit_reads_the_transfer_until_trm_finishes() {
        let request = deposit_request(Some(Address::new([1; 32])));
        let recipient = request.utxo.derivation_path.unwrap().to_string();
        let (client, mock) = mock_trm([
            (StatusCode::CREATED, transfer("PROCESSING", None)),
            (
                StatusCode::CREATED,
                json!([address_screening(&recipient, "sui", json!([]))]),
            ),
            (StatusCode::OK, transfer("PROCESSING", None)),
            (StatusCode::OK, transfer("SUCCEEDED", Some(0))),
        ])
        .await;

        let verdict = client
            .screen_deposit(&DepositScreening::new(&request, BITCOIN_ADDRESS.to_owned()))
            .await
            .unwrap();

        assert_eq!(verdict, Verdict::Approved);
        assert_eq!(mock.lock().unwrap().requests.len(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn a_processing_transfer_is_read_until_trm_finishes() {
        let started = Instant::now();
        let mut reads = VecDeque::from([Verdict::Pending, Verdict::Pending, Verdict::Approved]);

        let verdict = poll_transfer(
            || std::future::ready(Ok(reads.pop_front().unwrap())),
            started + TRANSFER_WAIT,
        )
        .await
        .unwrap();

        assert_eq!(verdict, Verdict::Approved);
        assert_eq!(started.elapsed(), 2 * TRANSFER_POLL_INTERVAL);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transfer_still_processing_after_the_wait_is_pending() {
        let started = Instant::now();
        let mut reads = 0;

        let verdict = poll_transfer(
            || {
                reads += 1;
                std::future::ready(Ok(Verdict::Pending))
            },
            started + TRANSFER_WAIT,
        )
        .await
        .unwrap();

        assert_eq!(verdict, Verdict::Pending);
        assert_eq!(reads, 6);
        assert_eq!(started.elapsed(), TRANSFER_WAIT);
    }

    #[tokio::test]
    async fn only_rate_limits_and_server_errors_are_transient() {
        for (status, body, transient) in [
            (StatusCode::TOO_MANY_REQUESTS, json!({}), true),
            (StatusCode::SERVICE_UNAVAILABLE, json!({}), true),
            (StatusCode::BAD_REQUEST, json!({}), false),
            (StatusCode::UNAUTHORIZED, json!({}), false),
            (StatusCode::CREATED, json!({ "results": [] }), false),
            (StatusCode::CREATED, json!([]), false),
            (
                StatusCode::CREATED,
                json!([
                    address_screening(BITCOIN_ADDRESS, "bitcoin", json!([])),
                    address_screening(BITCOIN_ADDRESS, "bitcoin", json!([])),
                ]),
                false,
            ),
        ] {
            let (client, _) = mock_trm([(status, body.clone())]).await;

            let error = client
                .screen_withdrawal(BITCOIN_ADDRESS, Address::new([1; 32]))
                .await
                .unwrap_err();

            assert_eq!(
                matches!(error, TrmError::Transient(_)),
                transient,
                "{status} {body}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_trm_times_out_as_transient() {
        // Connections wait in the listener's backlog and never get a response.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let client = TrmClient::with_base_url(API_KEY.to_owned(), &base_url).unwrap();

        let error = client
            .screen_withdrawal(BITCOIN_ADDRESS, Address::new([1; 32]))
            .await
            .unwrap_err();

        assert!(matches!(error, TrmError::Transient(e) if e.to_string().contains("timed out")));
    }

    #[tokio::test(start_paused = true)]
    async fn requests_to_an_endpoint_take_turns() {
        let pacer = &Pacer::new();
        let started = Instant::now();
        let turn = || async move {
            pacer.wait_turn(started + SCREENING_TIMEOUT).await.unwrap();
            started.elapsed()
        };

        let turns = tokio::join!(turn(), turn(), turn());

        assert_eq!(
            turns,
            (Duration::ZERO, REQUEST_INTERVAL, 2 * REQUEST_INTERVAL)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_turn_after_the_deadline_is_refused_without_taking_it() {
        let pacer = Pacer::new();
        let started = Instant::now();

        pacer.wait_turn(started).await.unwrap();
        let refused = pacer.wait_turn(started).await;
        pacer.wait_turn(started + SCREENING_TIMEOUT).await.unwrap();

        assert!(matches!(refused, Err(TrmError::Transient(_))));
        assert_eq!(started.elapsed(), REQUEST_INTERVAL);
    }

    #[tokio::test]
    async fn a_rate_limited_endpoint_holds_its_turns_for_retry_after() {
        let (client, _) = mock_trm([(StatusCode::TOO_MANY_REQUESTS, json!({}))]).await;

        client
            .screen_withdrawal(BITCOIN_ADDRESS, Address::new([1; 32]))
            .await
            .unwrap_err();

        let next_turn = *client.address_screenings.next_turn.lock().unwrap();
        assert!(next_turn > Instant::now() + Duration::from_secs(1));
    }

    #[test]
    fn retry_after_is_read_in_seconds_and_capped() {
        let headers = |value: &'static str| {
            reqwest::header::HeaderMap::from_iter([(
                reqwest::header::RETRY_AFTER,
                reqwest::header::HeaderValue::from_static(value),
            )])
        };

        assert_eq!(retry_after(&headers("3")), Duration::from_secs(3));
        assert_eq!(retry_after(&headers("86400")), Duration::from_secs(60));
        assert_eq!(
            retry_after(&reqwest::header::HeaderMap::new()),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn btc_amounts_are_exact_decimal_strings() {
        assert_eq!(btc_amount(0), "0.00000000");
        assert_eq!(btc_amount(1), "0.00000001");
        assert_eq!(btc_amount(123_456_789), "1.23456789");
        assert_eq!(btc_amount(2_100_000_000_000_000), "21000000.00000000");
    }

    /// Calls the live TRM API:
    ///
    /// ```text
    /// TRM_API_KEY=<key> cargo nextest run -p hashi --run-ignored only trm::tests::live
    /// ```
    fn live_client() -> TrmClient {
        TrmClient::new(std::env::var("TRM_API_KEY").expect("TRM_API_KEY")).unwrap()
    }

    #[tokio::test]
    #[ignore = "calls the live TRM API: set TRM_API_KEY"]
    async fn live_withdrawal_screening() {
        let client = live_client();
        let requester = Address::new([1; 32]);

        // On OFAC's SDN list.
        let sanctioned = "149w62rY42aZBox8fGcmqNsXUzSStKeq8C";
        let verdict = client
            .screen_withdrawal(sanctioned, requester)
            .await
            .unwrap();
        assert!(matches!(verdict, Verdict::Rejected(reason) if reason.contains(sanctioned)));

        // The genesis block address: attributed to mining, with severe
        // counterparty exposure from dust sent to it.
        let verdict = client
            .screen_withdrawal("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", requester)
            .await
            .unwrap();
        assert_eq!(verdict, Verdict::Approved);
    }

    #[tokio::test]
    #[ignore = "calls the live TRM API: set TRM_API_KEY"]
    async fn live_deposit_screening() {
        let client = live_client();
        // A mainnet payment to a taproot address, like a hashi deposit.
        let mut request = deposit_request(Some(Address::new([1; 32])));
        request.utxo.id.txid = "2698d1571ba5b03f5866c80e1906a4237c9fdd03c15a8dea8d5856cbcb26b4a9"
            .parse()
            .unwrap();
        request.utxo.amount = 6_376_139;
        request.created_timestamp_ms = 1_789_464_853_000;
        let deposit = DepositScreening::new(
            &request,
            "bc1p7q7ds3239y334zus72d5m3gkf83mfcu8j8zrk49hws7yrf7k4vhqjqjauy".to_owned(),
        );

        let verdict = tokio::time::timeout(Duration::from_secs(300), async {
            loop {
                match client.screen_deposit(&deposit).await.unwrap() {
                    Verdict::Pending => tokio::time::sleep(Duration::from_secs(10)).await,
                    verdict => break verdict,
                }
            }
        })
        .await
        .expect("TRM is still screening the transfer");
        assert_eq!(verdict, Verdict::Approved);
    }
}
