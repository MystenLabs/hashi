#[cfg(test)]
mod tests {
    use anyhow::Result;
    use anyhow::anyhow;
    use bitcoin::Amount;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash;
    use bitcoincore_rpc::RpcApi;
    use futures::StreamExt;
    use hashi::sui_tx_executor::SuiTxExecutor;
    use hashi_types::move_types::DepositConfirmedEvent;
    use hashi_types::move_types::WithdrawalConfirmedEvent;
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
    use crate::TestNetworksBuilder;

    fn init_test_logging() {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();
    }

    async fn setup_test_networks() -> Result<TestNetworks> {
        info!("Setting up test networks...");
        let networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

        info!("Test networks initialized");
        info!("  - Sui RPC: {}", networks.sui_network.rpc_url);
        info!("  - Bitcoin RPC: {}", networks.bitcoin_node.rpc_url());
        info!("  - Hashi nodes: {}", networks.hashi_network.nodes().len());

        info!("Waiting for MPC key to be ready...");
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(60))
            .await?;
        info!("MPC key ready");

        Ok(networks)
    }

    fn txid_to_address(txid: &Txid) -> Address {
        let bytes: [u8; 32] = *txid.as_byte_array();
        Address::new(bytes)
    }

    fn address_to_txid(addr: &Address) -> Txid {
        Txid::from_byte_array(addr.as_bytes().try_into().unwrap())
    }

    async fn wait_for_deposit_confirmation(
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
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Err(anyhow!("Checkpoint subscription ended unexpectedly"))
    }

    async fn wait_for_withdrawal_confirmation(
        sui_client: &mut sui_rpc::Client,
        timeout: Duration,
    ) -> Result<WithdrawalConfirmedEvent> {
        info!("Waiting for withdrawal confirmation...");

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
            if start.elapsed() > timeout {
                return Err(anyhow!(
                    "Timeout waiting for withdrawal confirmation after {:?}",
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
                "Received checkpoint {}, checking for WithdrawalConfirmedEvent...",
                checkpoint.cursor()
            );

            for txn in checkpoint.checkpoint().transactions() {
                for event in txn.events().events() {
                    let event_type = event.contents().name();

                    if event_type.contains("WithdrawalConfirmedEvent") {
                        match WithdrawalConfirmedEvent::from_bcs(event.contents().value()) {
                            Ok(event_data) => {
                                info!(
                                    "Withdrawal confirmed! pending_id={}, txid={}",
                                    event_data.pending_id, event_data.txid
                                );
                                return Ok(event_data);
                            }
                            Err(e) => {
                                debug!("Failed to parse WithdrawalConfirmedEvent: {}", e);
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Err(anyhow!("Checkpoint subscription ended unexpectedly"))
    }

    async fn get_hbtc_balance(
        sui_client: &mut sui_rpc::Client,
        package_id: Address,
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

    fn lookup_vout(
        networks: &TestNetworks,
        txid: Txid,
        address: bitcoin::Address,
        amount: u64,
    ) -> Result<usize> {
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

    async fn create_deposit_and_wait(
        networks: &mut TestNetworks,
        amount_sats: u64,
    ) -> Result<Address> {
        let user_key = networks.sui_network.user_keys.first().unwrap();
        let hbtc_recipient = user_key.public_key().derive_address();
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let deposit_address =
            hashi.get_deposit_address(&hashi.get_hashi_pubkey(), Some(&hbtc_recipient))?;

        info!("Sending Bitcoin to deposit address...");
        let txid = networks
            .bitcoin_node
            .send_to_address(&deposit_address, Amount::from_sat(amount_sats))?;
        info!("Transaction sent: {}", txid);

        info!("Mining blocks for confirmation...");
        let blocks_to_mine = 10;
        networks.bitcoin_node.generate_blocks(blocks_to_mine)?;
        info!("{blocks_to_mine} blocks mined");

        info!("Creating deposit request on Sui...");
        let vout = lookup_vout(networks, txid, deposit_address, amount_sats)?;
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
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

        Ok(hbtc_recipient)
    }

    fn extract_witness_program(address: &bitcoin::Address) -> Result<Vec<u8>> {
        let script = address.script_pubkey();
        let bytes = script.as_bytes();
        match bytes {
            [0x00, 0x14, rest @ ..] if rest.len() == 20 => Ok(rest.to_vec()),
            [0x51, 0x20, rest @ ..] if rest.len() == 32 => Ok(rest.to_vec()),
            _ => Err(anyhow!(
                "Unsupported script pubkey for withdrawal: {script}"
            )),
        }
    }

    async fn wait_for_withdrawal_tx_success(
        bitcoin_node: &crate::BitcoinNodeHandle,
        txid: &Txid,
        destination: &bitcoin::Address,
        amount: Amount,
        timeout: Duration,
    ) -> Result<()> {
        let start = std::time::Instant::now();

        loop {
            if bitcoin_node.rpc_client().get_mempool_entry(txid).is_ok() {
                info!("Withdrawal tx {} is in mempool", txid);
                break;
            }
            if start.elapsed() >= timeout {
                return Err(anyhow!(
                    "Withdrawal tx {} was not seen in mempool within {:?}",
                    txid,
                    timeout
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        loop {
            let mined_blocks = bitcoin_node.generate_blocks(1)?;
            let block_hash = mined_blocks
                .last()
                .copied()
                .ok_or_else(|| anyhow!("Expected at least one mined block"))?;
            let block = bitcoin_node.rpc_client().get_block(&block_hash)?;

            if !block.txdata.iter().any(|tx| tx.compute_txid() == *txid) {
                if start.elapsed() >= timeout {
                    return Err(anyhow!(
                        "Withdrawal tx {} did not confirm within {:?}",
                        txid,
                        timeout
                    ));
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }

            let tx = bitcoin_node
                .rpc_client()
                .get_raw_transaction(txid, Some(&block_hash))?;
            let pays_destination = tx.output.iter().any(|output| {
                output.value == amount && output.script_pubkey == destination.script_pubkey()
            });
            if !pays_destination {
                return Err(anyhow!(
                    "Withdrawal tx {} is confirmed but does not pay {} to {}",
                    txid,
                    amount,
                    destination
                ));
            }

            info!(
                "Withdrawal tx {} confirmed in block {} with expected output",
                txid, block_hash
            );
            return Ok(());
        }
    }

    #[tokio::test]
    async fn test_bitcoin_deposit_e2e_flow() -> Result<()> {
        init_test_logging();
        info!("=== Starting Bitcoin Deposit E2E Test ===");

        let mut networks = setup_test_networks().await?;
        let amount_sats = 31337u64;
        let hbtc_recipient = create_deposit_and_wait(&mut networks, amount_sats).await?;

        let hbtc_balance = get_hbtc_balance(
            &mut networks.sui_network.client,
            networks.hashi_network.ids().package_id,
            hbtc_recipient,
        )
        .await?;
        info!("Recipient hBTC balance: {}", hbtc_balance);
        assert_eq!(hbtc_balance, amount_sats, "Expected deposited hBTC amount");

        info!("=== Bitcoin Deposit E2E Test Passed ===");
        Ok(())
    }

    #[tokio::test]
    async fn test_bitcoin_withdrawal_e2e_flow() -> Result<()> {
        init_test_logging();
        info!("=== Starting Bitcoin Withdrawal E2E Test ===");

        let mut networks = setup_test_networks().await?;

        let deposit_amount_sats = 31337u64;
        let hbtc_recipient = create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        let hbtc_balance = get_hbtc_balance(
            &mut networks.sui_network.client,
            networks.hashi_network.ids().package_id,
            hbtc_recipient,
        )
        .await?;
        assert_eq!(
            hbtc_balance, deposit_amount_sats,
            "Expected deposited hBTC amount"
        );

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap();
        let withdrawal_amount_sats = 20_000u64;
        let btc_destination = networks.bitcoin_node.get_new_address()?;
        let destination_bytes = extract_witness_program(&btc_destination)?;
        info!(
            "Requesting withdrawal of {} sats to {}",
            withdrawal_amount_sats, btc_destination
        );

        let mut withdrawal_executor =
            SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
                .with_signer(user_key.clone());
        let withdrawal_request_id = withdrawal_executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes, 0)
            .await?;
        info!("Withdrawal request created: {}", withdrawal_request_id);

        let confirmed_event = wait_for_withdrawal_confirmation(
            &mut networks.sui_network.client,
            Duration::from_secs(30),
        )
        .await?;
        info!("Withdrawal confirmed on Sui");

        let hbtc_balance_after = get_hbtc_balance(
            &mut networks.sui_network.client,
            networks.hashi_network.ids().package_id,
            hbtc_recipient,
        )
        .await?;
        let expected_remaining = deposit_amount_sats - withdrawal_amount_sats;
        assert_eq!(
            hbtc_balance_after, expected_remaining,
            "Expected remaining hBTC after withdrawal"
        );

        let withdrawal_txid = address_to_txid(&confirmed_event.txid);
        info!(
            "Observed withdrawal Bitcoin txid in event: {}",
            withdrawal_txid
        );
        wait_for_withdrawal_tx_success(
            &networks.bitcoin_node,
            &withdrawal_txid,
            &btc_destination,
            Amount::from_sat(withdrawal_amount_sats),
            Duration::from_secs(30),
        )
        .await?;

        info!("=== Bitcoin Withdrawal E2E Test Passed ===");
        Ok(())
    }

    async fn withdraw_and_confirm(
        networks: &mut TestNetworks,
        hashi: &hashi::Hashi,
        signer: sui_crypto::ed25519::Ed25519PrivateKey,
        withdrawal_amount_sats: u64,
    ) -> Result<()> {
        let btc_destination = networks.bitcoin_node.get_new_address()?;
        let destination_bytes = extract_witness_program(&btc_destination)?;
        let mut executor =
            SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?.with_signer(signer);
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes, 0)
            .await?;
        let confirmed = wait_for_withdrawal_confirmation(
            &mut networks.sui_network.client,
            Duration::from_secs(60),
        )
        .await?;
        let withdrawal_txid = address_to_txid(&confirmed.txid);
        wait_for_withdrawal_tx_success(
            &networks.bitcoin_node,
            &withdrawal_txid,
            &btc_destination,
            Amount::from_sat(withdrawal_amount_sats),
            Duration::from_secs(30),
        )
        .await
    }

    #[tokio::test]
    async fn test_presigning_recovery_within_batch() -> Result<()> {
        init_test_logging();
        let mut networks = setup_test_networks().await?;
        let deposit_amount_sats = 100_000u64;
        let withdrawal_amount_sats = 20_000u64;
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();

        // First deposit
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        // First withdrawal
        {
            let hashi = networks.hashi_network.nodes()[0].hashi().clone();
            withdraw_and_confirm(
                &mut networks,
                &hashi,
                user_key.clone(),
                withdrawal_amount_sats,
            )
            .await?;
        }

        // Second deposit
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        // Restart nodes 0 and 1 — with 2 of 4 restarted,
        // at least one restarted node must participate in signing.
        networks.hashi_network_mut().nodes_mut()[0]
            .restart()
            .await?;
        networks.hashi_network_mut().nodes_mut()[1]
            .restart()
            .await?;
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(120))
            .await?;
        networks.hashi_network.nodes()[1]
            .wait_for_mpc_key(Duration::from_secs(120))
            .await?;

        // Second withdrawal
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        withdraw_and_confirm(
            &mut networks,
            &hashi,
            user_key.clone(),
            withdrawal_amount_sats,
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_presigning_recovery_across_batch_boundary() -> Result<()> {
        init_test_logging();

        // Use batch_size_per_weight=1 for small batches (~3 presigs each).
        let networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_batch_size_per_weight(1)
            .build()
            .await?;
        let mut networks = networks;
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(60))
            .await?;
        let deposit_amount_sats = 100_000u64;
        let withdrawal_amount_sats = 10_000u64;
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();

        // Perform 4 deposit+withdrawal cycles to exhaust batch 0 (~3 presigs)
        // and consume 1 presig from batch 1.
        let num_withdrawals = 4;
        for _ in 0..num_withdrawals {
            create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;
            let hashi = networks.hashi_network.nodes()[0].hashi().clone();
            withdraw_and_confirm(
                &mut networks,
                &hashi,
                user_key.clone(),
                withdrawal_amount_sats,
            )
            .await?;
        }

        // One more deposit to provide a UTXO for the post-recovery withdrawal.
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        // Restart nodes 0 and 1 — with 2 of 4 restarted,
        // at least one restarted node must participate in signing.
        networks.hashi_network_mut().nodes_mut()[0]
            .restart()
            .await?;
        networks.hashi_network_mut().nodes_mut()[1]
            .restart()
            .await?;
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(120))
            .await?;
        networks.hashi_network.nodes()[1]
            .wait_for_mpc_key(Duration::from_secs(120))
            .await?;

        // Final withdrawal — proves the recovered node can sign with batch 1 presigs.
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        withdraw_and_confirm(
            &mut networks,
            &hashi,
            user_key.clone(),
            withdrawal_amount_sats,
        )
        .await?;
        Ok(())
    }
}
