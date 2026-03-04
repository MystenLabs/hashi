//! Integration tests against a local / deployed hashi-screener service.
//!
//! These tests are `#[ignore]`d by default because they require a running
//! screener endpoint. Run them with:
//!
//! ```sh
//! SCREENER_ENDPOINT=https://hashi-screener-dev.mystenlabs.com:443 cargo nextest run -p hashi-screener --test screener --run-ignored ignored-only
//! ```
//!
//! The deployed service auto-approves requests with non-mainnet chain IDs.
//! For mainnet chain IDs, it queries the MerkleScience API for real risk screening.

use hashi_screener::chain::caip2;
use hashi_types::proto::screener::ApproveRequest;
use hashi_types::proto::screener::TransactionType;
use hashi_types::proto::screener::screener_service_client::ScreenerServiceClient;
use tokio::sync::OnceCell;
use tonic::transport::Channel;

/// Returns the screener endpoint from the environment.
///
/// Panics if `SCREENER_ENDPOINT` is not set — this is intentional because
/// these tests are `#[ignore]` and run only when explicitly requested.
fn endpoint() -> &'static str {
    static ENDPOINT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ENDPOINT.get_or_init(|| {
        std::env::var("SCREENER_ENDPOINT")
            .expect("SCREENER_ENDPOINT must be set when running ignored screener tests")
    })
}

static CHANNEL: OnceCell<Channel> = OnceCell::const_new();

async fn channel() -> Channel {
    CHANNEL
        .get_or_init(|| async {
            tonic::transport::Endpoint::new(endpoint().to_string())
                .expect("invalid endpoint URL")
                .connect_timeout(std::time::Duration::from_secs(10))
                .connect_lazy()
        })
        .await
        .clone()
}

async fn screener_client() -> ScreenerServiceClient<Channel> {
    ScreenerServiceClient::new(channel().await)
}

const VALID_BTC_TX_HASH: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
const VALID_BTC_ADDRESS: &str = "bc1quv7cu96jldavn2jk0h4dzh9ee0hk98dtxzq2za";
const SANCTIONED_BTC_ADDRESS: &str = "1La5BmmoKNntspBodPf6SP8Hjam4vdWaTD";
const VALID_SUI_TX_HASH: &str = "E2dZvPeQTcVs5jNujS5C92ezoUTNUTu8x5mNh1dgcEZW";
const VALID_SUI_ADDRESS: &str =
    "0x6e8bbbb8f111bcd4f995d23853d367666da444addbb1c0071b08543e84fa1ebe";

#[tokio::test]
#[ignore]
async fn health_check() {
    use tonic_health::pb::HealthCheckRequest;
    use tonic_health::pb::health_client::HealthClient;

    let mut health = HealthClient::new(channel().await);
    let response = health
        .check(HealthCheckRequest {
            service: String::new(),
        })
        .await
        .expect("health check failed");

    assert_eq!(
        response.into_inner().status,
        tonic_health::pb::health_check_response::ServingStatus::Serving as i32,
        "screener service should be serving"
    );
}

#[tokio::test]
#[ignore]
async fn testnet_deposit_auto_approves() {
    let mut client = screener_client().await;

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: VALID_BTC_TX_HASH.to_string(),
            destination_address: VALID_SUI_ADDRESS.to_string(),
            source_chain_id: caip2::BTC_TESTNET3.to_string(),
            destination_chain_id: caip2::SUI_TESTNET.to_string(),
            transaction_type: TransactionType::Deposit.into(),
        })
        .await
        .expect("testnet deposit request failed");

    assert!(
        response.into_inner().approved,
        "testnet deposit should be auto-approved"
    );
}

#[tokio::test]
#[ignore]
async fn testnet_withdrawal_auto_approved() {
    let mut client = screener_client().await;

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: VALID_SUI_TX_HASH.to_string(),
            destination_address: VALID_BTC_ADDRESS.to_string(),
            source_chain_id: caip2::SUI_TESTNET.to_string(),
            destination_chain_id: caip2::BTC_TESTNET3.to_string(),
            transaction_type: TransactionType::Withdrawal.into(),
        })
        .await
        .expect("testnet withdrawal request failed");

    assert!(
        response.into_inner().approved,
        "testnet withdrawal should be auto-approved"
    );
}

#[tokio::test]
#[ignore]
async fn mainnet_withdrawal_clean_address_approved() {
    let mut client = screener_client().await;

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: VALID_SUI_TX_HASH.to_string(),
            destination_address: VALID_BTC_ADDRESS.to_string(),
            source_chain_id: caip2::SUI_MAINNET.to_string(),
            destination_chain_id: caip2::BTC_MAINNET.to_string(),
            transaction_type: TransactionType::Withdrawal.into(),
        })
        .await
        .expect("mainnet clean withdrawal request failed");

    assert!(
        response.into_inner().approved,
        "withdrawal to clean address should be approved"
    );
}

#[tokio::test]
#[ignore]
async fn mainnet_withdrawal_sanctioned_address_rejected() {
    let mut client = screener_client().await;

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: VALID_SUI_TX_HASH.to_string(),
            destination_address: SANCTIONED_BTC_ADDRESS.to_string(),
            source_chain_id: caip2::SUI_MAINNET.to_string(),
            destination_chain_id: caip2::BTC_MAINNET.to_string(),
            transaction_type: TransactionType::Withdrawal.into(),
        })
        .await
        .expect("mainnet sanctioned withdrawal request failed");

    assert!(
        !response.into_inner().approved,
        "withdrawal to sanctioned address should be rejected"
    );
}

#[tokio::test]
#[ignore]
async fn rejects_invalid_input() {
    fn valid_deposit() -> ApproveRequest {
        ApproveRequest {
            source_transaction_hash: VALID_BTC_TX_HASH.to_string(),
            destination_address: VALID_SUI_ADDRESS.to_string(),
            source_chain_id: caip2::BTC_TESTNET3.to_string(),
            destination_chain_id: caip2::SUI_TESTNET.to_string(),
            transaction_type: TransactionType::Deposit.into(),
        }
    }

    let cases: Vec<(&str, ApproveRequest)> = vec![
        (
            "empty source_transaction_hash",
            ApproveRequest {
                source_transaction_hash: String::new(),
                ..valid_deposit()
            },
        ),
        (
            "empty destination_address",
            ApproveRequest {
                destination_address: String::new(),
                ..valid_deposit()
            },
        ),
        (
            "empty source_chain_id",
            ApproveRequest {
                source_chain_id: String::new(),
                ..valid_deposit()
            },
        ),
        (
            "empty destination_chain_id",
            ApproveRequest {
                destination_chain_id: String::new(),
                ..valid_deposit()
            },
        ),
        (
            "unspecified transaction_type",
            ApproveRequest {
                transaction_type: TransactionType::Unspecified.into(),
                ..valid_deposit()
            },
        ),
    ];

    let mut client = screener_client().await;
    for (label, request) in cases {
        let result = client.approve(request).await;
        assert!(
            result.is_err(),
            "{label}: expected gRPC error, got {result:?}"
        );
    }
}
