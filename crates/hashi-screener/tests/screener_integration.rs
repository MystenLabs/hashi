// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use hashi_screener::chain::caip2;
use hashi_screener::test_utils::start_configurable_mock_screener_server;
use hashi_screener::test_utils::start_mock_screener_server;
use hashi_types::proto::screener::ApproveRequest;
use hashi_types::proto::screener::TransactionType;
use hashi_types::proto::screener::screener_service_client::ScreenerServiceClient;

#[tokio::test]
async fn mock_screener_auto_approves_deposits() {
    let (addr, _service) = start_mock_screener_server().await;
    let mut client = ScreenerServiceClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: "abc123".to_string(),
            destination_address:
                "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            source_chain_id: caip2::BTC_TESTNET3.to_string(),
            destination_chain_id: caip2::SUI_TESTNET.to_string(),
            transaction_type: TransactionType::Deposit.into(),
        })
        .await
        .unwrap();

    assert!(response.into_inner().approved);
}

#[tokio::test]
async fn mock_screener_auto_approves_withdrawals() {
    let (addr, _service) = start_mock_screener_server().await;
    let mut client = ScreenerServiceClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: String::new(),
            destination_address: "bc1qtest".to_string(),
            source_chain_id: caip2::SUI_TESTNET.to_string(),
            destination_chain_id: caip2::BTC_TESTNET3.to_string(),
            transaction_type: TransactionType::Withdrawal.into(),
        })
        .await
        .unwrap();

    assert!(response.into_inner().approved);
}

#[tokio::test]
async fn configurable_mock_rejects_blocked_destination() {
    let blocked: HashSet<String> = ["bc1qblocked".to_string()].into();
    let (addr, _service) = start_configurable_mock_screener_server(blocked).await;
    let mut client = ScreenerServiceClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: "tx123".to_string(),
            destination_address: "bc1qblocked".to_string(),
            source_chain_id: caip2::SUI_MAINNET.to_string(),
            destination_chain_id: caip2::BTC_MAINNET.to_string(),
            transaction_type: TransactionType::Withdrawal.into(),
        })
        .await
        .unwrap();

    assert!(!response.into_inner().approved);
}

#[tokio::test]
async fn configurable_mock_rejects_blocked_deposit_destination() {
    let blocked: HashSet<String> =
        ["0x0000000000000000000000000000000000000000000000000000000000000bad".to_string()].into();
    let (addr, _service) = start_configurable_mock_screener_server(blocked).await;
    let mut client = ScreenerServiceClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: "tx123".to_string(),
            destination_address:
                "0x0000000000000000000000000000000000000000000000000000000000000bad".to_string(),
            source_chain_id: caip2::BTC_MAINNET.to_string(),
            destination_chain_id: caip2::SUI_MAINNET.to_string(),
            transaction_type: TransactionType::Deposit.into(),
        })
        .await
        .unwrap();

    assert!(!response.into_inner().approved);
}

#[tokio::test]
async fn configurable_mock_approves_non_blocked_address() {
    let blocked: HashSet<String> = ["bc1qblocked".to_string()].into();
    let (addr, _service) = start_configurable_mock_screener_server(blocked).await;
    let mut client = ScreenerServiceClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    let response = client
        .approve(ApproveRequest {
            source_transaction_hash: String::new(),
            destination_address: "bc1qallowed".to_string(),
            source_chain_id: caip2::SUI_MAINNET.to_string(),
            destination_chain_id: caip2::BTC_MAINNET.to_string(),
            transaction_type: TransactionType::Withdrawal.into(),
        })
        .await
        .unwrap();

    assert!(response.into_inner().approved);
}
