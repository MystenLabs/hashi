// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

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
    use hashi_types::move_types::WithdrawalPickedForProcessingEvent;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
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
            hashi.get_deposit_address(&hashi.get_hashi_pubkey()?, Some(&hbtc_recipient))?;

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

    /// Mines one block per second on Bitcoin regtest until stopped.
    /// Stops automatically when dropped.
    struct BackgroundMiner {
        stop_flag: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl BackgroundMiner {
        fn start(bitcoin_node: &crate::BitcoinNodeHandle) -> Self {
            let stop_flag = Arc::new(AtomicBool::new(false));
            let stop_clone = stop_flag.clone();
            let rpc_url = bitcoin_node.rpc_url().to_string();
            let handle = std::thread::spawn(move || {
                let rpc = bitcoincore_rpc::Client::new(
                    &rpc_url,
                    bitcoincore_rpc::Auth::UserPass(
                        crate::bitcoin_node::RPC_USER.to_string(),
                        crate::bitcoin_node::RPC_PASSWORD.to_string(),
                    ),
                )
                .expect("failed to create mining RPC client");
                let addr = rpc
                    .get_new_address(None, None)
                    .expect("failed to get mining address")
                    .assume_checked();
                while !stop_clone.load(Ordering::Relaxed) {
                    let _ = rpc.generate_to_address(1, &addr);
                    std::thread::sleep(Duration::from_secs(1));
                }
            });
            Self {
                stop_flag,
                handle: Some(handle),
            }
        }
    }

    impl Drop for BackgroundMiner {
        fn drop(&mut self) {
            self.stop_flag.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
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

    /// Wait for a withdrawal transaction to be confirmed on the Bitcoin chain.
    /// The output to `destination` must be at most `max_amount` and at least
    /// `min_amount` (to account for variable miner fees deducted from the user).
    async fn wait_for_withdrawal_tx_success(
        bitcoin_node: &crate::BitcoinNodeHandle,
        txid: &Txid,
        destination: &bitcoin::Address,
        max_amount: Amount,
        min_amount: Amount,
        timeout: Duration,
    ) -> Result<()> {
        let start = std::time::Instant::now();

        let check_output = |tx: &bitcoin::Transaction| -> bool {
            tx.output.iter().any(|output| {
                output.value <= max_amount
                    && output.value >= min_amount
                    && output.script_pubkey == destination.script_pubkey()
            })
        };

        // Wait until the tx is visible (either in mempool or already confirmed).
        loop {
            if bitcoin_node.rpc_client().get_mempool_entry(txid).is_ok() {
                info!("Withdrawal tx {} is in mempool", txid);
                break;
            }
            // The background miner may have already confirmed it.
            if let Ok(info) = bitcoin_node
                .rpc_client()
                .get_raw_transaction_info(txid, None)
                && info.confirmations.unwrap_or(0) > 0
            {
                info!("Withdrawal tx {} is already confirmed", txid);
                let tx = bitcoin_node.rpc_client().get_raw_transaction(txid, None)?;
                if !check_output(&tx) {
                    return Err(anyhow!(
                        "Withdrawal tx {} is confirmed but does not pay [{}, {}] to {}",
                        txid,
                        min_amount,
                        max_amount,
                        destination
                    ));
                }
                info!("Withdrawal tx {} confirmed with expected output", txid);
                return Ok(());
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
            if !check_output(&tx) {
                return Err(anyhow!(
                    "Withdrawal tx {} is confirmed but does not pay [{}, {}] to {}",
                    txid,
                    min_amount,
                    max_amount,
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

        let deposit_amount_sats = 100_000u64;
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
        let withdrawal_amount_sats = 30_000u64;
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
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes)
            .await?;
        info!("Withdrawal request created: {}", withdrawal_request_id);

        let miner = BackgroundMiner::start(&networks.bitcoin_node);

        let confirmed_event = wait_for_withdrawal_confirmation(
            &mut networks.sui_network.client,
            Duration::from_secs(60),
        )
        .await?;
        info!("Withdrawal confirmed on Sui");

        drop(miner);

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
        // The on-chain btc_amount is net of the protocol fee (deducted at request time).
        let net_amount = withdrawal_amount_sats - hashi.onchain_state().withdrawal_fee_btc();
        let max_output = Amount::from_sat(net_amount);
        let min_output = Amount::from_sat(
            net_amount.saturating_sub(hashi.onchain_state().worst_case_network_fee()),
        );
        wait_for_withdrawal_tx_success(
            &networks.bitcoin_node,
            &withdrawal_txid,
            &btc_destination,
            max_output,
            min_output,
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
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes)
            .await?;

        let miner = BackgroundMiner::start(&networks.bitcoin_node);

        let confirmed = wait_for_withdrawal_confirmation(
            &mut networks.sui_network.client,
            Duration::from_secs(60),
        )
        .await?;

        drop(miner);

        let withdrawal_txid = address_to_txid(&confirmed.txid);
        let net_amount = withdrawal_amount_sats - hashi.onchain_state().withdrawal_fee_btc();
        let max_output = Amount::from_sat(net_amount);
        let min_output = Amount::from_sat(
            net_amount.saturating_sub(hashi.onchain_state().worst_case_network_fee()),
        );
        wait_for_withdrawal_tx_success(
            &networks.bitcoin_node,
            &withdrawal_txid,
            &btc_destination,
            max_output,
            min_output,
            Duration::from_secs(30),
        )
        .await
    }

    #[tokio::test]
    async fn test_presigning_recovery_within_batch() -> Result<()> {
        init_test_logging();
        let mut networks = setup_test_networks().await?;
        let deposit_amount_sats = 100_000u64;
        let withdrawal_amount_sats = 30_000u64;
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
        let withdrawal_amount_sats = 30_000u64;
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

    /// Wait for the committee to commit a withdrawal (i.e., select UTXOs and
    /// broadcast the Bitcoin tx), without requiring Bitcoin confirmations.
    async fn wait_for_withdrawal_picked(
        sui_client: &mut sui_rpc::Client,
        timeout: Duration,
    ) -> Result<WithdrawalPickedForProcessingEvent> {
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
                    "Timeout waiting for WithdrawalPickedForProcessingEvent after {:?}",
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
            for txn in checkpoint.checkpoint().transactions() {
                for event in txn.events().events() {
                    if event
                        .contents()
                        .name()
                        .contains("WithdrawalPickedForProcessingEvent")
                    {
                        match WithdrawalPickedForProcessingEvent::from_bcs(event.contents().value())
                        {
                            Ok(data) => {
                                info!(
                                    "Withdrawal picked for processing: pending_id={}",
                                    data.pending_id
                                );
                                return Ok(data);
                            }
                            Err(e) => {
                                debug!("Failed to parse WithdrawalPickedForProcessingEvent: {}", e);
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(anyhow!("Checkpoint subscription ended unexpectedly"))
    }

    /// Wait for `n` withdrawal confirmations using a single checkpoint
    /// subscription, so no events are missed when two confirmations fall in
    /// the same checkpoint.
    async fn wait_for_n_withdrawal_confirmations(
        sui_client: &mut sui_rpc::Client,
        n: usize,
        timeout: Duration,
    ) -> Result<Vec<WithdrawalConfirmedEvent>> {
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

        let mut events = Vec::with_capacity(n);
        while events.len() < n {
            if start.elapsed() > timeout {
                return Err(anyhow!(
                    "Timeout waiting for {} withdrawal confirmations (got {}) after {:?}",
                    n,
                    events.len(),
                    timeout
                ));
            }
            let Some(item) = subscription.next().await else {
                return Err(anyhow!("Checkpoint subscription ended unexpectedly"));
            };
            let checkpoint = match item {
                Ok(checkpoint) => checkpoint,
                Err(e) => {
                    debug!("Error in checkpoint stream: {}", e);
                    continue;
                }
            };
            for txn in checkpoint.checkpoint().transactions() {
                for event in txn.events().events() {
                    if event.contents().name().contains("WithdrawalConfirmedEvent") {
                        match WithdrawalConfirmedEvent::from_bcs(event.contents().value()) {
                            Ok(data) => {
                                info!(
                                    "Withdrawal confirmed ({}/{}): pending_id={}",
                                    events.len() + 1,
                                    n,
                                    data.pending_id
                                );
                                events.push(data);
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
        Ok(events)
    }

    /// Verifies that the committee can commit a second withdrawal whose sole
    /// available input is the unconfirmed change UTXO from a prior pending
    /// withdrawal (i.e., before that first Bitcoin tx has 6 confirmations).
    ///
    /// Test outline:
    /// 1. Deposit 200 000 sats → one confirmed UTXO in the pool.
    /// 2. Submit withdrawal 1 (30 000 sats). Wait for the committee to commit
    ///    it (`WithdrawalPickedForProcessingEvent`). No Bitcoin blocks mined
    ///    yet, so the change UTXO is pending/unconfirmed.
    /// 3. Submit withdrawal 2 (30 000 sats) immediately. Wait for the
    ///    committee to commit it. Assert that it spent the pending change UTXO
    ///    from withdrawal 1.
    /// 4. Mine blocks and wait for both `WithdrawalConfirmedEvent`s.
    #[tokio::test]
    async fn test_withdrawal_chains_through_unconfirmed_change_utxo() -> Result<()> {
        init_test_logging();
        info!("=== Starting Unconfirmed Change UTXO Chaining Test ===");

        let mut networks = setup_test_networks().await?;

        // Deposit enough that after withdrawal 1 there is substantial change.
        let deposit_amount_sats = 200_000u64;
        let withdrawal_amount_sats = 30_000u64;
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();

        // Submit withdrawal 1. Do NOT mine any Bitcoin blocks yet.
        let btc_destination1 = networks.bitcoin_node.get_new_address()?;
        let destination_bytes1 = extract_witness_program(&btc_destination1)?;
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone());
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes1)
            .await?;
        info!("Withdrawal 1 request submitted");

        // Wait for the committee to commit withdrawal 1. At this point the
        // deposit UTXO is locked and the change UTXO is inserted as pending
        // (produced_by = Some, locked_by = None). No Bitcoin blocks have been
        // mined, so neither the deposit spend nor the change output is
        // confirmed on-chain.
        let picked1 =
            wait_for_withdrawal_picked(&mut networks.sui_network.client, Duration::from_secs(30))
                .await?;
        info!(
            "Withdrawal 1 committed: pending_id={}, txid={}",
            picked1.pending_id, picked1.txid
        );

        assert!(
            picked1.change_output.is_some(),
            "Withdrawal 1 must produce a change UTXO for this test to be meaningful \
             (deposit={deposit_amount_sats}, withdrawal={withdrawal_amount_sats})"
        );

        // The change UTXO id: same txid as withdrawal 1, vout after all
        // withdrawal outputs.
        let change_txid = picked1.txid;
        let change_vout = picked1.withdrawal_outputs.len() as u32;

        // Submit withdrawal 2 immediately — the deposit UTXO is now locked, so
        // the only available UTXO is the unconfirmed change from withdrawal 1.
        let btc_destination2 = networks.bitcoin_node.get_new_address()?;
        let destination_bytes2 = extract_witness_program(&btc_destination2)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes2)
            .await?;
        info!("Withdrawal 2 request submitted (no Bitcoin blocks mined yet)");

        // Wait for the committee to commit withdrawal 2. It must use the
        // pending change UTXO as its input.
        let picked2 =
            wait_for_withdrawal_picked(&mut networks.sui_network.client, Duration::from_secs(30))
                .await?;
        info!(
            "Withdrawal 2 committed: pending_id={}, txid={}",
            picked2.pending_id, picked2.txid
        );

        // Assert that withdrawal 2 spent the pending change UTXO from
        // withdrawal 1 (the only available UTXO at commit time).
        let spent_pending_change = picked2
            .inputs
            .iter()
            .any(|utxo| utxo.id.txid == change_txid && utxo.id.vout == change_vout);
        assert!(
            spent_pending_change,
            "Withdrawal 2 should have spent the unconfirmed change UTXO \
             (txid={change_txid}, vout={change_vout}) from withdrawal 1, \
             but its inputs were: {:?}",
            picked2
                .inputs
                .iter()
                .map(|u| (u.id.txid, u.id.vout))
                .collect::<Vec<_>>()
        );

        info!("Confirmed: withdrawal 2 spent the unconfirmed change UTXO from withdrawal 1");

        // Mine blocks and wait for both withdrawals to be confirmed on Sui.
        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        wait_for_n_withdrawal_confirmations(
            &mut networks.sui_network.client,
            2,
            Duration::from_secs(90),
        )
        .await?;
        drop(miner);

        info!("Both withdrawals confirmed on Sui");
        info!("=== Unconfirmed Change UTXO Chaining Test Passed ===");
        Ok(())
    }

    #[tokio::test]
    async fn test_create_update_config_proposal() -> Result<()> {
        init_test_logging();
        info!("=== Starting UpdateConfig Proposal E2E Test ===");

        // Stand up a minimal network (1 node). We only need the Sui chain
        // with the Hashi package deployed and a registered committee member.
        let networks = TestNetworksBuilder::new().with_nodes(1).build().await?;

        // Wait for the node to finish DKG so the committee is fully set up.
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(60))
            .await?;

        let hashi_ids = networks.hashi_network.ids();
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();

        // The operator key is a committee member — use it to sign the proposal.
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?;

        // Use the same builder logic the CLI uses.
        use hashi::cli::client::CreateProposalParams;
        use hashi::cli::client::build_create_proposal_transaction;

        let builder = build_create_proposal_transaction(
            hashi_ids,
            CreateProposalParams::UpdateConfig {
                key: "deposit_fee".to_string(),
                value: hashi_types::move_types::ConfigValue::U64(42),
                metadata: vec![],
            },
        );

        info!("Executing update_config::propose transaction...");
        let response = executor.execute(builder).await?;
        assert!(
            response.transaction().effects().status().success(),
            "update_config::propose transaction failed: {:?}",
            response.transaction().effects().status()
        );
        info!("Transaction succeeded: {}", response.transaction().digest());

        info!("=== UpdateConfig Proposal E2E Test Passed ===");
        Ok(())
    }

    /// Verify that `TestNetworksBuilder::with_onchain_config` applies the
    /// override automatically during `build()`: the full propose/vote/execute
    /// cycle runs and the new value is visible on-chain before the builder
    /// returns.
    #[tokio::test]
    async fn test_onchain_config_override_via_builder() -> Result<()> {
        init_test_logging();
        info!("=== Starting OnchainConfig Builder Override Test ===");

        // Use 4 nodes so quorum (66.67%) requires multiple votes. The builder
        // should handle collecting votes from all nodes automatically.
        let networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_onchain_config(
                "bitcoin_confirmation_threshold",
                hashi_types::move_types::ConfigValue::U64(3),
            )
            .build()
            .await?;

        let hashi = networks.hashi_network.nodes()[0].hashi();
        let threshold = hashi.onchain_state().bitcoin_confirmation_threshold();
        assert_eq!(
            threshold, 3,
            "expected bitcoin_confirmation_threshold=3 after builder override, got {threshold}"
        );

        info!("=== OnchainConfig Builder Override Test Passed ===");
        Ok(())
    }
}
