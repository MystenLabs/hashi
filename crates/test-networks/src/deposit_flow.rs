use anyhow::Result;
use anyhow::anyhow;
use bitcoin::Amount;
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use futures::StreamExt;
use hashi_types::move_types::DepositConfirmedEvent;
use std::time::Duration;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::GetBalanceRequest;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
use sui_sdk_types::Address;
use sui_sdk_types::StructTag;
use sui_sdk_types::bcs::FromBcs;
use tracing::debug;
use tracing::info;

use crate::TestNetworks;

/// Convert a Bitcoin transaction ID to a Sui Address.
///
/// Both are 32 bytes, so we just reinterpret the bytes.
pub fn txid_to_address(txid: &Txid) -> Address {
    let bytes: [u8; 32] = *txid.as_byte_array();
    Address::new(bytes)
}

pub async fn wait_for_deposit_confirmation(
    sui_client: &mut sui_rpc::Client,
    request_id: Address,
    timeout: Duration,
) -> Result<()> {
    info!(
        "Waiting for deposit confirmation for request_id: {}",
        request_id
    );

    let start = std::time::Instant::now();
    let subscription_read_mask = FieldMask::from_paths([Checkpoint::path_builder()
        .transactions()
        .events()
        .events()
        .contents()
        .finish()]);
    let mut subscription = sui_client
        .subscription_client()
        .subscribe_checkpoints(
            SubscribeCheckpointsRequest::default().with_read_mask(subscription_read_mask),
        )
        .await?
        .into_inner();

    while let Some(item) = subscription.next().await {
        // Check timeout
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "Timeout waiting for deposit confirmation after {:?}",
                timeout
            ));
        }

        let checkpoint = match item {
            Ok(checkpoint) => checkpoint,
            Err(e) => {
                debug!("Error in checkpoint stream: {}", e);
                continue;
            }
        };

        debug!(
            "Received checkpoint {}, checking for DepositConfirmedEvent...",
            checkpoint.cursor()
        );

        // Check all transactions in this checkpoint for DepositConfirmedEvent
        for txn in checkpoint.checkpoint().transactions() {
            for event in txn.events().events() {
                let event_type = event.contents().name();

                if event_type.contains("DepositConfirmedEvent") {
                    match DepositConfirmedEvent::from_bcs(event.contents().value()) {
                        Ok(event_data) => {
                            if event_data.request_id == request_id {
                                info!(
                                    "Deposit confirmed! Found DepositConfirmedEvent for request_id: {}",
                                    request_id
                                );
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            debug!("Failed to parse DepositConfirmedEvent: {}", e);
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await; // Help avoid hanging in CI
    }

    Err(anyhow!("Checkpoint subscription ended unexpectedly"))
}

pub async fn get_hbtc_balance(
    sui_client: &mut sui_rpc::Client,
    package_id: sui_sdk_types::Address,
    owner: Address,
) -> Result<u64> {
    let btc_type = format!("{}::btc::BTC", package_id);
    let btc_struct_tag: StructTag = btc_type.parse()?;
    let request = GetBalanceRequest::default()
        .with_owner(owner.to_string())
        .with_coin_type(btc_struct_tag.to_string());

    let response = sui_client
        .state_client()
        .get_balance(request)
        .await?
        .into_inner();

    let balance = response.balance().balance_opt().unwrap_or(0);
    debug!("hBTC balance for {}: {} sats", owner, balance);
    Ok(balance)
}

pub fn lookup_vout(
    networks: &TestNetworks,
    txid: Txid,
    address: bitcoin::Address,
    amount: u64,
) -> Result<usize> {
    use bitcoincore_rpc::RpcApi;

    let tx = networks
        .bitcoin_node
        .rpc_client()
        .get_raw_transaction(&txid, None)?;
    let vout = tx
        .output
        .iter()
        .position(|output| {
            output.value == Amount::from_sat(amount)
                && output.script_pubkey == address.script_pubkey()
        })
        .ok_or_else(|| {
            anyhow!(
                "Could not find output with amount {} and deposit address",
                amount
            )
        })?;
    debug!("Found deposit in tx output {}", vout);
    Ok(vout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestNetworksBuilder;
    use hashi::onchain::OnchainState;
    use hashi::sui_tx_executor::SuiTxExecutor;

    #[tokio::test]
    async fn test_bitcoin_deposit_e2e_flow() -> Result<()> {
        // Initialize tracing subscriber for test logs
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        info!("=== Starting Bitcoin Deposit E2E Test ===");

        info!("Setting up test networks...");
        let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

        info!("Test networks initialized");
        info!("  - Sui RPC: {}", networks.sui_network.rpc_url);
        info!("  - Bitcoin RPC: {}", networks.bitcoin_node.rpc_url());
        info!("  - Hashi nodes: {}", networks.hashi_network.nodes().len());

        let user_key = networks.sui_network.user_keys.first().unwrap();
        let hbtc_recipient = user_key.public_key().derive_address();
        let hashi = networks.hashi_network.nodes()[0].0.clone();
        let deposit_address =
            hashi.get_deposit_address(&hashi.get_hashi_pubkey(), Some(&hbtc_recipient));

        info!("Sending Bitcoin to deposit address...");
        let amount_sats = 31337u64;
        let txid = networks
            .bitcoin_node
            .send_to_address(&deposit_address, Amount::from_sat(amount_sats))?;
        info!("Transaction sent: {}", txid);

        info!("Mining blocks for confirmation...");
        let blocks_to_mine = 10;
        networks.bitcoin_node.generate_blocks(blocks_to_mine)?;
        info!("{blocks_to_mine} blocks mined");

        info!("Creating deposit request on Sui...");
        let vout = lookup_vout(&networks, txid, deposit_address, amount_sats)?;
        // Create OnchainState directly since hashi may not be fully initialized yet
        let onchain_state = OnchainState::new(
            &networks.sui_network.rpc_url,
            networks.hashi_network.ids(),
            None,
        )
        .await?;
        let mut executor = SuiTxExecutor::from_config(&hashi.config, &onchain_state)?
            .with_signer(user_key.clone());
        let request_id = executor
            .execute_create_deposit_request(
                txid_to_address(&txid),
                vout as u32,
                amount_sats,
                Some(hbtc_recipient),
            )
            .await?;
        info!("Deposit request created: {}", request_id);

        wait_for_deposit_confirmation(
            &mut networks.sui_network.client,
            request_id,
            Duration::from_secs(300),
        )
        .await?;
        info!("Deposit confirmed on Sui");

        // Verify hBTC was minted to the recipient
        let hbtc_balance = get_hbtc_balance(
            &mut networks.sui_network.client,
            networks.hashi_network.ids().package_id,
            hbtc_recipient,
        )
        .await?;
        info!("Recipient hBTC balance: {}", hbtc_balance);
        assert!(
            hbtc_balance == amount_sats,
            "Expected {} satoshis, got {}",
            amount_sats,
            hbtc_balance
        );

        info!("Test completed successfully");
        Ok(())
    }
}
