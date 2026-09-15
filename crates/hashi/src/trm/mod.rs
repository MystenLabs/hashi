// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AML screening through the TRM Labs Compliance API, using the node
//! operator's own API key.

use std::future::Future;
use std::time::Duration;

use anyhow::anyhow;
use sui_sdk_types::Address;

const TRM_API_URL: &str = "https://api.trmlabs.com";
const BITCOIN_CHAIN: &str = "bitcoin";
const SUI_CHAIN: &str = "sui";

/// One deadline for a whole screening, across all of its requests.
const SCREENING_TIMEOUT: Duration = Duration::from_secs(20);

/// TRM's "High" risk score level. Scores at or above it reject.
const HIGH_RISK_SCORE_LEVEL: u8 = 10;

pub struct TrmClient {
    http: reqwest::Client,
    base_url: reqwest::Url,
    api_key: String,
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
    pub request_id: Address,
    pub txid: String,
    pub deposit_address: String,
    pub amount_sats: u64,
    pub created_timestamp_ms: u64,
    /// The Sui address credited with the minted BTC, if any.
    pub recipient: Option<Address>,
    pub sender: Address,
}

impl TrmClient {
    pub fn new(api_key: String) -> anyhow::Result<Self> {
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
        })
    }

    /// Registers the Bitcoin deposit transaction with Transaction Monitoring,
    /// screens the Sui recipient, then reads back the transfer's screening
    /// result.
    pub async fn screen_deposit(&self, deposit: &DepositScreening) -> Result<Verdict, TrmError> {
        with_deadline(async {
            let transfer = self.submit_deposit_transfer(deposit).await?;
            if let Some(recipient) = deposit.recipient {
                let recipient = recipient.to_string();
                let verdict = self
                    .screen_addresses(&[AddressQuery {
                        address: &recipient,
                        chain: SUI_CHAIN,
                    }])
                    .await?;
                if verdict != Verdict::Approved {
                    return Ok(verdict);
                }
            }
            Ok(self.get_transfer(&transfer.uuid).await?.verdict())
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
        with_deadline(self.screen_addresses(&[
            AddressQuery {
                address: bitcoin_address,
                chain: BITCOIN_CHAIN,
            },
            AddressQuery {
                address: &sender,
                chain: SUI_CHAIN,
            },
        ]))
        .await
    }

    async fn submit_deposit_transfer(
        &self,
        deposit: &DepositScreening,
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
        self.send(self.http.post(url).json(&submission)).await
    }

    async fn get_transfer(&self, uuid: &str) -> Result<Transfer, TrmError> {
        let mut url = self.url(&["public", "v2", "tm", "transfers"]);
        url.path_segments_mut()
            .expect("TRM base URL is an http(s) URL")
            .push(uuid);
        self.send(self.http.get(url)).await
    }

    async fn screen_addresses(&self, queries: &[AddressQuery<'_>]) -> Result<Verdict, TrmError> {
        let url = self.url(&["public", "v2", "screening", "addresses"]);
        let results: Vec<AddressScreening> = self.send(self.http.post(url).json(queries)).await?;
        if results.len() != queries.len() {
            return Err(TrmError::Permanent(anyhow!(
                "TRM returned {} screening results for {} addresses",
                results.len(),
                queries.len()
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
        request: reqwest::RequestBuilder,
    ) -> Result<T, TrmError> {
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
    fn verdict(&self) -> Verdict {
        let link = self.trm_app_url.as_deref().unwrap_or("no TRM link");
        match self.screen_status.as_deref() {
            Some("PROCESSING") => Verdict::Pending,
            Some("SUCCEEDED") => match self.risk_score_level {
                Some(level) if level >= HIGH_RISK_SCORE_LEVEL => Verdict::Rejected(format!(
                    "TRM transfer {} raised an alert at risk score level {level} ({link})",
                    self.uuid
                )),
                _ => Verdict::Approved,
            },
            status => Verdict::Rejected(format!(
                "TRM could not screen transfer {} (status {}, reason {}) ({link})",
                self.uuid,
                status.unwrap_or("null"),
                self.screen_status_failed_reason
                    .as_deref()
                    .unwrap_or("none"),
            )),
        }
    }
}

async fn with_deadline(
    screening: impl Future<Output = Result<Verdict, TrmError>>,
) -> Result<Verdict, TrmError> {
    tokio::time::timeout(SCREENING_TIMEOUT, screening)
        .await
        .unwrap_or_else(|_| {
            Err(TrmError::Transient(anyhow!(
                "TRM screening timed out after {SCREENING_TIMEOUT:?}"
            )))
        })
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
    use std::sync::Arc;
    use std::sync::Mutex;

    use axum::extract::Path;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::routing::post;
    use base64ct::Encoding as _;
    use serde_json::json;

    use super::*;

    const API_KEY: &str = "test-key";
    const TRANSFER_UUID: &str = "00000000-0000-4000-8000-0000000000aa";
    const BTC_DEPOSIT_ADDRESS: &str =
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    const TXID: &str = "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d";

    const ADDRESS_CLEAN: &str = include_str!("testdata/addresses_no_indicators.json");
    const ADDRESS_OWNERSHIP_HIGH: &str = include_str!("testdata/addresses_ownership_high.json");
    const ADDRESS_COUNTERPARTY_SEVERE: &str =
        include_str!("testdata/addresses_counterparty_severe.json");
    const TRANSFER_PROCESSING: &str = include_str!("testdata/transfer_processing.json");
    const TRANSFER_SUCCEEDED: &str = include_str!("testdata/transfer_succeeded.json");

    struct MockTrm {
        addresses: (StatusCode, String),
        transfer: String,
        requests: Vec<(String, serde_json::Value)>,
    }

    type Mock = Arc<Mutex<MockTrm>>;

    async fn start_mock(addresses: (StatusCode, &str), transfer: &str) -> (TrmClient, Mock) {
        let mock = Arc::new(Mutex::new(MockTrm {
            addresses: (addresses.0, addresses.1.to_owned()),
            transfer: transfer.to_owned(),
            requests: Vec::new(),
        }));
        let app = axum::Router::new()
            .route("/public/v2/screening/addresses", post(screen_addresses))
            .route("/public/v2/tm/transfers", post(submit_transfer))
            .route("/public/v2/tm/transfers/{uuid}", get(get_transfer))
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (
            TrmClient::with_base_url(API_KEY.to_owned(), &base_url).unwrap(),
            mock,
        )
    }

    fn authorized(headers: &HeaderMap) -> bool {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Basic "))
            .and_then(|encoded| base64ct::Base64::decode_vec(encoded).ok())
            .is_some_and(|decoded| decoded == format!("{API_KEY}:{API_KEY}").as_bytes())
    }

    async fn screen_addresses(
        State(mock): State<Mock>,
        headers: HeaderMap,
        body: String,
    ) -> (StatusCode, String) {
        if !authorized(&headers) {
            return (StatusCode::UNAUTHORIZED, String::new());
        }
        let mut mock = mock.lock().unwrap();
        mock.requests
            .push(("addresses".to_owned(), serde_json::from_str(&body).unwrap()));
        mock.addresses.clone()
    }

    async fn submit_transfer(
        State(mock): State<Mock>,
        headers: HeaderMap,
        body: String,
    ) -> (StatusCode, String) {
        if !authorized(&headers) {
            return (StatusCode::UNAUTHORIZED, String::new());
        }
        mock.lock()
            .unwrap()
            .requests
            .push(("transfers".to_owned(), serde_json::from_str(&body).unwrap()));
        (StatusCode::CREATED, TRANSFER_PROCESSING.to_owned())
    }

    async fn get_transfer(
        State(mock): State<Mock>,
        headers: HeaderMap,
        Path(uuid): Path<String>,
    ) -> (StatusCode, String) {
        if !authorized(&headers) {
            return (StatusCode::UNAUTHORIZED, String::new());
        }
        let mut mock = mock.lock().unwrap();
        mock.requests
            .push((format!("transfers/{uuid}"), serde_json::Value::Null));
        (StatusCode::OK, mock.transfer.clone())
    }

    fn batch(fixtures: &[&str]) -> String {
        let results: Vec<serde_json::Value> = fixtures
            .iter()
            .flat_map(|fixture| serde_json::from_str::<Vec<serde_json::Value>>(fixture).unwrap())
            .collect();
        serde_json::to_string(&results).unwrap()
    }

    fn transfer_with(fields: serde_json::Value) -> String {
        let mut transfer: serde_json::Value = serde_json::from_str(TRANSFER_SUCCEEDED).unwrap();
        for (key, value) in fields.as_object().unwrap() {
            transfer[key] = value.clone();
        }
        transfer.to_string()
    }

    fn deposit(recipient: Option<Address>) -> DepositScreening {
        DepositScreening {
            request_id: Address::new([2; 32]),
            txid: TXID.to_owned(),
            deposit_address: BTC_DEPOSIT_ADDRESS.to_owned(),
            amount_sats: 12_345,
            created_timestamp_ms: 1_789_464_112_688,
            recipient,
            sender: Address::new([3; 32]),
        }
    }

    #[tokio::test]
    async fn deposit_is_approved_when_trm_finishes_without_alerts() {
        let recipient = Address::new([1; 32]);
        let (client, mock) =
            start_mock((StatusCode::CREATED, ADDRESS_CLEAN), TRANSFER_SUCCEEDED).await;

        let verdict = client
            .screen_deposit(&deposit(Some(recipient)))
            .await
            .unwrap();

        assert_eq!(verdict, Verdict::Approved);
        let requests = mock.lock().unwrap().requests.clone();
        assert_eq!(
            requests,
            vec![
                (
                    "transfers".to_owned(),
                    json!({
                        "accountExternalId": recipient.to_string(),
                        "asset": "btc",
                        "assetAmount": "0.00012345",
                        "chain": "bitcoin",
                        "destinationAddress": BTC_DEPOSIT_ADDRESS,
                        "externalId": format!("hashi-deposit-{}", Address::new([2; 32])),
                        "fiatCurrency": "USD",
                        "fiatValue": "0",
                        "onchainReference": TXID,
                        "timestamp": "2026-09-15T09:21:52.688Z",
                        "transferType": "CRYPTO_DEPOSIT",
                    }),
                ),
                (
                    "addresses".to_owned(),
                    json!([{ "address": recipient.to_string(), "chain": "sui" }]),
                ),
                (
                    format!("transfers/{TRANSFER_UUID}"),
                    serde_json::Value::Null
                ),
            ]
        );
    }

    #[tokio::test]
    async fn deposit_is_pending_while_trm_is_processing() {
        let (client, _) =
            start_mock((StatusCode::CREATED, ADDRESS_CLEAN), TRANSFER_PROCESSING).await;

        let verdict = client
            .screen_deposit(&deposit(Some(Address::new([1; 32]))))
            .await
            .unwrap();

        assert_eq!(verdict, Verdict::Pending);
    }

    #[tokio::test]
    async fn deposit_is_rejected_when_the_transfer_raises_a_high_alert() {
        let transfer =
            transfer_with(json!({ "riskScoreLevel": 10, "riskScoreLevelLabel": "High" }));
        let (client, _) = start_mock((StatusCode::CREATED, ADDRESS_CLEAN), &transfer).await;

        let verdict = client
            .screen_deposit(&deposit(Some(Address::new([1; 32]))))
            .await
            .unwrap();

        assert!(
            matches!(verdict, Verdict::Rejected(reason) if reason.contains("risk score level 10"))
        );
    }

    #[tokio::test]
    async fn deposit_is_rejected_when_trm_cannot_screen_the_transfer() {
        let transfer = transfer_with(json!({
            "screenStatus": "FAILED",
            "screenStatusFailedReason": "INVALID_DESTINATION_ADDRESS",
        }));
        let (client, _) = start_mock((StatusCode::CREATED, ADDRESS_CLEAN), &transfer).await;

        let verdict = client
            .screen_deposit(&deposit(Some(Address::new([1; 32]))))
            .await
            .unwrap();

        assert!(
            matches!(verdict, Verdict::Rejected(reason) if reason.contains("INVALID_DESTINATION_ADDRESS"))
        );
    }

    #[tokio::test]
    async fn deposit_is_rejected_when_the_recipient_is_attributed_high_risk() {
        let (client, mock) = start_mock(
            (StatusCode::CREATED, ADDRESS_OWNERSHIP_HIGH),
            TRANSFER_SUCCEEDED,
        )
        .await;

        let verdict = client
            .screen_deposit(&deposit(Some(Address::new([1; 32]))))
            .await
            .unwrap();

        assert!(matches!(verdict, Verdict::Rejected(reason) if reason.contains("Scam (61)")));
        assert_eq!(mock.lock().unwrap().requests.len(), 2);
    }

    #[tokio::test]
    async fn deposit_without_a_recipient_skips_address_screening() {
        let (client, mock) =
            start_mock((StatusCode::CREATED, ADDRESS_CLEAN), TRANSFER_SUCCEEDED).await;

        let verdict = client.screen_deposit(&deposit(None)).await.unwrap();

        assert_eq!(verdict, Verdict::Approved);
        let requests = mock.lock().unwrap().requests.clone();
        let paths: Vec<&str> = requests.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(paths, ["transfers", &format!("transfers/{TRANSFER_UUID}")]);
        assert_eq!(
            requests[0].1["accountExternalId"],
            Address::new([3; 32]).to_string()
        );
    }

    #[tokio::test]
    async fn withdrawal_screens_the_destination_and_the_requester() {
        let sender = Address::new([1; 32]);
        let addresses = batch(&[ADDRESS_COUNTERPARTY_SEVERE, ADDRESS_CLEAN]);
        let (client, mock) =
            start_mock((StatusCode::CREATED, &addresses), TRANSFER_SUCCEEDED).await;

        let verdict = client
            .screen_withdrawal(BTC_DEPOSIT_ADDRESS, sender)
            .await
            .unwrap();

        assert_eq!(verdict, Verdict::Approved);
        assert_eq!(
            mock.lock().unwrap().requests,
            vec![(
                "addresses".to_owned(),
                json!([
                    { "address": BTC_DEPOSIT_ADDRESS, "chain": "bitcoin" },
                    { "address": sender.to_string(), "chain": "sui" },
                ]),
            )]
        );
    }

    #[tokio::test]
    async fn withdrawal_is_rejected_when_the_destination_is_attributed_high_risk() {
        let addresses = batch(&[ADDRESS_OWNERSHIP_HIGH, ADDRESS_CLEAN]);
        let (client, _) = start_mock((StatusCode::CREATED, &addresses), TRANSFER_SUCCEEDED).await;

        let verdict = client
            .screen_withdrawal(BTC_DEPOSIT_ADDRESS, Address::new([1; 32]))
            .await
            .unwrap();

        assert!(matches!(verdict, Verdict::Rejected(reason) if reason.contains("bitcoin address")));
    }

    #[tokio::test]
    async fn only_rate_limits_and_server_errors_are_transient() {
        for (status, transient) in [
            (StatusCode::TOO_MANY_REQUESTS, true),
            (StatusCode::BAD_GATEWAY, true),
            (StatusCode::BAD_REQUEST, false),
            (StatusCode::FORBIDDEN, false),
        ] {
            let (client, _) = start_mock((status, "{}"), TRANSFER_SUCCEEDED).await;

            let error = client
                .screen_withdrawal(BTC_DEPOSIT_ADDRESS, Address::new([1; 32]))
                .await
                .unwrap_err();

            assert_eq!(
                matches!(error, TrmError::Transient(_)),
                transient,
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn a_rejected_api_key_is_permanent() {
        let (client, _) =
            start_mock((StatusCode::CREATED, ADDRESS_CLEAN), TRANSFER_SUCCEEDED).await;
        let client =
            TrmClient::with_base_url("wrong-key".to_owned(), client.base_url.as_str()).unwrap();

        let error = client
            .screen_withdrawal(BTC_DEPOSIT_ADDRESS, Address::new([1; 32]))
            .await
            .unwrap_err();

        assert!(matches!(error, TrmError::Permanent(e) if e.to_string().contains("401")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_trm_times_out_as_transient() {
        let app = axum::Router::new().route(
            "/public/v2/screening/addresses",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(600)).await;
                (StatusCode::CREATED, "[]")
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = TrmClient::with_base_url(API_KEY.to_owned(), &base_url).unwrap();

        let error = client
            .screen_withdrawal(BTC_DEPOSIT_ADDRESS, Address::new([1; 32]))
            .await
            .unwrap_err();

        assert!(matches!(error, TrmError::Transient(e) if e.to_string().contains("timed out")));
    }

    #[test]
    fn btc_amounts_are_exact_decimal_strings() {
        assert_eq!(btc_amount(0), "0.00000000");
        assert_eq!(btc_amount(1), "0.00000001");
        assert_eq!(btc_amount(123_456_789), "1.23456789");
        assert_eq!(btc_amount(2_100_000_000_000_000), "21000000.00000000");
    }
}
