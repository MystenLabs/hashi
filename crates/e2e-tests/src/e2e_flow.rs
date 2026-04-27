// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use anyhow::anyhow;
    use bitcoin::Amount;
    use bitcoin::Txid;

    use futures::StreamExt;
    use hashi::sui_tx_executor::SuiTxExecutor;
    use hashi_types::move_types::WithdrawalConfirmedEvent;
    use hashi_types::move_types::WithdrawalPickedForProcessingEvent;
    use std::time::Duration;
    use sui_rpc::field::FieldMask;
    use sui_rpc::field::FieldMaskUtil;
    use sui_rpc::proto::sui::rpc::v2::Checkpoint;
    use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
    use sui_sdk_types::Address;
    use sui_sdk_types::bcs::FromBcs;
    use tracing::debug;
    use tracing::info;

    use crate::TestNetworks;
    use crate::TestNetworksBuilder;

    use crate::test_helpers::BackgroundMiner;
    use crate::test_helpers::create_deposit_and_wait;
    use crate::test_helpers::get_hbtc_balance;
    use crate::test_helpers::init_test_logging;
    use crate::test_helpers::lookup_vout;
    use crate::test_helpers::txid_to_address;

    async fn setup_test_networks(builder: TestNetworksBuilder) -> Result<TestNetworks> {
        info!("Setting up test networks...");
        let networks = builder.build().await?;

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
                                    withdrawal_txn_id = %event_data.withdrawal_txn_id,
                                    txid = %event_data.txid,
                                    "Withdrawal confirmed!"
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
            if bitcoin_node.rpc_client().get_mempool_entry(*txid).is_ok() {
                info!("Withdrawal tx {} is in mempool", txid);
                break;
            }
            // The background miner may have already confirmed it.
            if let Ok(info) = bitcoin_node.rpc_client().get_raw_transaction_verbose(*txid)
                && info.confirmations.unwrap_or(0) > 0
            {
                info!("Withdrawal tx {} is already confirmed", txid);
                let tx = bitcoin_node
                    .rpc_client()
                    .get_raw_transaction(*txid)
                    .and_then(|r| r.transaction().map_err(Into::into))?;
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
            let block = bitcoin_node.rpc_client().get_block(block_hash)?;

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
                .get_raw_transaction(*txid)
                .and_then(|r| r.transaction().map_err(Into::into))?;
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

        let mut networks = setup_test_networks(TestNetworksBuilder::new().with_nodes(4)).await?;
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
        run_bitcoin_withdrawal_e2e(false).await
    }

    #[tokio::test]
    async fn test_bitcoin_withdrawal_with_guardian_e2e_flow() -> Result<()> {
        run_bitcoin_withdrawal_e2e(true).await
    }

    async fn run_bitcoin_withdrawal_e2e(with_guardian: bool) -> Result<()> {
        init_test_logging();
        let label = if with_guardian {
            " (with guardian)"
        } else {
            ""
        };
        info!("=== Starting Bitcoin Withdrawal E2E Test{label} ===");

        let mut builder = TestNetworksBuilder::new().with_nodes(4);
        if with_guardian {
            builder = builder.with_guardian();
        }
        let mut networks = setup_test_networks(builder).await?;

        if with_guardian {
            for node in networks.hashi_network.nodes() {
                assert!(node.hashi().config.guardian_endpoint().is_some());
                assert!(node.hashi().guardian_client().is_some());
            }
            let harness = networks
                .guardian_harness
                .as_ref()
                .expect("harness present when .with_guardian() is set");
            assert!(harness.enclave().is_fully_initialized());
        }

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

        let withdrawal_txid: Txid = confirmed_event.txid.into();
        info!(
            "Observed withdrawal Bitcoin txid in event: {}",
            withdrawal_txid
        );
        // The full withdrawal amount is stored in the request (no protocol fee).
        let max_output = Amount::from_sat(withdrawal_amount_sats);
        let min_output = Amount::from_sat(
            withdrawal_amount_sats.saturating_sub(hashi.onchain_state().worst_case_network_fee()),
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

        info!("=== Bitcoin Withdrawal E2E Test{label} Passed ===");
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

        let withdrawal_txid: Txid = confirmed.txid.into();
        let max_output = Amount::from_sat(withdrawal_amount_sats);
        let min_output = Amount::from_sat(
            withdrawal_amount_sats.saturating_sub(hashi.onchain_state().worst_case_network_fee()),
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
        let mut networks = setup_test_networks(TestNetworksBuilder::new().with_nodes(4)).await?;
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
                                    withdrawal_txn_id = %data.withdrawal_txn_id,
                                    "Withdrawal picked for processing"
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
                                    withdrawal_txn_id = %data.withdrawal_txn_id,
                                    progress = %format!("{}/{}", events.len() + 1, n),
                                    "Withdrawal confirmed"
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

        let mut networks = setup_test_networks(TestNetworksBuilder::new().with_nodes(4)).await?;

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
            withdrawal_txn_id = %picked1.withdrawal_txn_id,
            txid = %picked1.txid,
            "Withdrawal 1 committed"
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
            withdrawal_txn_id = %picked2.withdrawal_txn_id,
            txid = %picked2.txid,
            "Withdrawal 2 committed"
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

    /// Waits for a `WithdrawalPickedForProcessingEvent` that contains at least
    /// `min_requests` request IDs in a single batch, indicating that the new
    /// multi-request coin selection algorithm batched them together.
    async fn wait_for_batched_withdrawal_picked(
        sui_client: &mut sui_rpc::Client,
        min_requests: usize,
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
                    "Timeout waiting for batched WithdrawalPickedForProcessingEvent \
                     (min_requests={min_requests}) after {:?}",
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
                            Ok(data) if data.request_ids.len() >= min_requests => {
                                info!(
                                    withdrawal_txn_id = %data.withdrawal_txn_id,
                                    request_count = %data.request_ids.len(),
                                    "Batched withdrawal picked"
                                );
                                return Ok(data);
                            }
                            Ok(data) => {
                                info!(
                                    "WithdrawalPickedForProcessingEvent with {} request(s) \
                                     (waiting for batch of ≥{})",
                                    data.request_ids.len(),
                                    min_requests,
                                );
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

    /// Verifies that the new multi-request coin selection algorithm batches
    /// multiple approved withdrawal requests into a single Bitcoin transaction.
    ///
    /// Test outline:
    /// 1. Deposit 200 000 sats → one confirmed UTXO in the pool.
    /// 2. Submit two withdrawal requests (20 000 sats each) back-to-back on
    ///    Sui, before either is committed. Both requests will be approved
    ///    independently by the committee, then the leader picks up both
    ///    approved requests and batches them into one Bitcoin tx.
    /// 3. Wait for a `WithdrawalPickedForProcessingEvent` whose `request_ids`
    ///    has length ≥ 2, confirming the batch.
    /// 4. Assert the Bitcoin tx has two withdrawal outputs (one per request).
    /// 5. Mine blocks and wait for the single `WithdrawalConfirmedEvent`.
    #[tokio::test]
    async fn test_batch_withdrawal() -> Result<()> {
        init_test_logging();
        info!("=== Starting Batch Withdrawal Test ===");

        // Use a 5 s batching delay and cap of 2 so both requests accumulate
        // before the leader commits, exercising the delay-trigger path.
        let mut networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_withdrawal_batching_delay_ms(5_000)
            .with_withdrawal_max_batch_size(2)
            .build()
            .await?;

        // Deposit enough to cover two withdrawals plus fees.
        // Each withdrawal must be at least bitcoin_withdrawal_minimum
        // (30,000 sats at default config).
        let deposit_amount_sats = 200_000u64;
        let withdrawal_amount_sats = 30_000u64;
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone());

        // Submit two withdrawal requests back-to-back without waiting for either
        // to be committed. The leader should approve both and then batch them
        // together into a single Bitcoin transaction.
        let btc_destination1 = networks.bitcoin_node.get_new_address()?;
        let destination_bytes1 = extract_witness_program(&btc_destination1)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes1)
            .await?;
        info!("Withdrawal request 1 submitted");

        let btc_destination2 = networks.bitcoin_node.get_new_address()?;
        let destination_bytes2 = extract_witness_program(&btc_destination2)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes2)
            .await?;
        info!("Withdrawal request 2 submitted");

        // Wait for a single WithdrawalPickedForProcessingEvent that batches both
        // requests into one Bitcoin transaction.
        let picked = wait_for_batched_withdrawal_picked(
            &mut networks.sui_network.client,
            2,
            Duration::from_secs(60),
        )
        .await?;

        info!(
            withdrawal_txn_id = %picked.withdrawal_txn_id,
            request_count = %picked.request_ids.len(),
            "Batched withdrawal committed"
        );

        assert_eq!(
            picked.request_ids.len(),
            2,
            "Expected both withdrawal requests to be batched into one transaction, \
             but got {} request(s)",
            picked.request_ids.len(),
        );

        // The Bitcoin tx should have exactly two withdrawal outputs (no change
        // needed since we have plenty of UTXO value).
        assert_eq!(
            picked.withdrawal_outputs.len(),
            2,
            "Expected two withdrawal outputs in the batched transaction, \
             but got {}",
            picked.withdrawal_outputs.len(),
        );

        // Mine blocks and wait for the single confirmation event covering both
        // requests.
        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        wait_for_n_withdrawal_confirmations(
            &mut networks.sui_network.client,
            1,
            Duration::from_secs(90),
        )
        .await?;
        drop(miner);

        info!("Batch withdrawal confirmed on Sui");
        info!("=== Batch Withdrawal Test Passed ===");
        Ok(())
    }

    /// Verify the batch fires immediately when `withdrawal_max_batch_size` is
    /// reached, even if `withdrawal_batching_delay_ms` has not elapsed yet.
    ///
    /// Steps:
    /// 1. Start a network with a 24-hour delay (would never expire in a test)
    ///    and a max batch size of 2.
    /// 2. Deposit and submit 2 withdrawal requests.
    /// 3. The batch should fire at capacity (2 requests) well before the delay
    ///    expires, producing a single `WithdrawalPickedForProcessingEvent` with
    ///    exactly 2 request IDs.
    #[tokio::test]
    async fn test_batch_withdrawal_fires_at_capacity() -> Result<()> {
        init_test_logging();
        info!("=== Starting Batch Withdrawal Fires At Capacity Test ===");

        // 24-hour delay ensures the delay path cannot trigger; only the
        // capacity path (batch.len() >= max_batch_size) should fire the batch.
        let mut networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_withdrawal_batching_delay_ms(86_400_000)
            .with_withdrawal_max_batch_size(2)
            .build()
            .await?;

        // Each withdrawal must be at least bitcoin_withdrawal_minimum
        // (30,000 sats at default config).
        let deposit_amount_sats = 200_000u64;
        let withdrawal_amount_sats = 30_000u64;
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone());

        let btc_destination1 = networks.bitcoin_node.get_new_address()?;
        let destination_bytes1 = extract_witness_program(&btc_destination1)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes1)
            .await?;
        info!("Withdrawal request 1 submitted");

        let btc_destination2 = networks.bitcoin_node.get_new_address()?;
        let destination_bytes2 = extract_witness_program(&btc_destination2)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes2)
            .await?;
        info!("Withdrawal request 2 submitted");

        // Both requests should be batched at capacity (before the 24 h delay).
        let picked = wait_for_batched_withdrawal_picked(
            &mut networks.sui_network.client,
            2,
            Duration::from_secs(90),
        )
        .await?;

        info!(
            withdrawal_txn_id = %picked.withdrawal_txn_id,
            request_count = %picked.request_ids.len(),
            "Capacity-triggered batch committed"
        );

        assert_eq!(
            picked.request_ids.len(),
            2,
            "Expected both withdrawal requests to be batched at capacity, \
             but got {} request(s)",
            picked.request_ids.len(),
        );

        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        wait_for_n_withdrawal_confirmations(
            &mut networks.sui_network.client,
            1,
            Duration::from_secs(90),
        )
        .await?;
        drop(miner);

        info!("=== Batch Withdrawal Fires At Capacity Test Passed ===");
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
                key: "bitcoin_deposit_minimum".to_string(),
                value: hashi_types::move_types::ConfigValue::U64(25_000),
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

    #[tokio::test]
    async fn test_mpc_config_defaults_match_rust() -> Result<()> {
        init_test_logging();

        let networks = TestNetworksBuilder::new().with_nodes(1).build().await?;
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(60))
            .await?;

        use hashi::onchain::types::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
        use hashi::onchain::types::DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS;
        use hashi::onchain::types::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;

        let hashi = networks.hashi_network.nodes()[0].hashi();
        let threshold_bps = hashi.onchain_state().mpc_threshold_in_basis_points();
        let weight_reduction_allowed_delta =
            hashi.onchain_state().mpc_weight_reduction_allowed_delta();
        let max_faulty_bps = hashi.onchain_state().mpc_max_faulty_in_basis_points();

        assert_eq!(
            threshold_bps, DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS,
            "on-chain mpc_threshold_in_basis_points ({threshold_bps}) != Rust default ({DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS})"
        );
        assert_eq!(
            weight_reduction_allowed_delta, DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
            "on-chain mpc_weight_reduction_allowed_delta ({weight_reduction_allowed_delta}) != Rust default ({DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA})"
        );
        assert_eq!(
            max_faulty_bps, DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
            "on-chain mpc_max_faulty_in_basis_points ({max_faulty_bps}) != Rust default ({DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS})"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_varying_t_and_allowed_delta_across_epochs() -> Result<()> {
        init_test_logging();

        let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

        use hashi::onchain::types::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
        use hashi::onchain::types::DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS;
        use hashi::onchain::types::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;

        // Wait for DKG (epoch 1 committee created with defaults).
        let nodes = networks.hashi_network.nodes();
        let futs: Vec<_> = nodes
            .iter()
            .map(|n| n.wait_for_mpc_key(Duration::from_secs(120)))
            .collect();
        for (i, r) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            r.unwrap_or_else(|e| panic!("Node {i} DKG failed: {e}"));
        }

        let initial_epoch = nodes[0].current_epoch().unwrap();
        let pk_before = nodes[0].hashi().mpc_handle().unwrap().public_key().unwrap();

        // Verify epoch 1 committee has defaults.
        let epoch1_committee = nodes[0]
            .hashi()
            .onchain_state()
            .current_committee()
            .unwrap();
        assert_eq!(
            epoch1_committee.mpc_threshold_in_basis_points(),
            DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS
        );
        assert_eq!(
            epoch1_committee.mpc_weight_reduction_allowed_delta(),
            DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA
        );
        assert_eq!(
            epoch1_committee.mpc_max_faulty_in_basis_points(),
            DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS
        );

        // Change config between epochs.
        let new_threshold: u64 = 5000;
        let new_delta: u64 = 1200;
        let new_max_faulty: u64 = 2000;
        crate::apply_onchain_config_overrides(
            &mut networks,
            &[
                (
                    "mpc_threshold_in_basis_points".into(),
                    hashi_types::move_types::ConfigValue::U64(new_threshold),
                ),
                (
                    "mpc_weight_reduction_allowed_delta".into(),
                    hashi_types::move_types::ConfigValue::U64(new_delta),
                ),
                (
                    "mpc_max_faulty_in_basis_points".into(),
                    hashi_types::move_types::ConfigValue::U64(new_max_faulty),
                ),
            ],
        )
        .await?;

        // Force key rotation → epoch 2 committee created with new config.
        let target_epoch = initial_epoch + 1;
        networks.sui_network.force_close_epoch().await?;
        let futs: Vec<_> = networks
            .hashi_network()
            .nodes()
            .iter()
            .map(|n| n.wait_for_epoch(target_epoch, Duration::from_secs(480)))
            .collect();
        for (i, r) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            r.unwrap_or_else(|e| panic!("Node {i} failed to reach epoch {target_epoch}: {e}"));
        }

        // Verify key rotation succeeded: all nodes agree and key is preserved.
        let nodes = networks.hashi_network().nodes();
        let pk_after = nodes[0].hashi().mpc_handle().unwrap().public_key().unwrap();
        assert_eq!(
            pk_before, pk_after,
            "MPC public key changed during rotation"
        );
        for (i, node) in nodes.iter().enumerate().skip(1) {
            let pk = node.hashi().mpc_handle().unwrap().public_key().unwrap();
            assert_eq!(
                pk, pk_after,
                "Node {i} MPC key differs from node 0 after rotation"
            );
        }

        // Epoch 1 committee retains original defaults.
        let state = networks.hashi_network.nodes()[0].hashi().onchain_state();
        let committees = {
            let s = state.state();
            s.hashi().committees.committees().clone()
        };
        let epoch1 = committees.get(&initial_epoch).expect("epoch 1 committee");
        assert_eq!(
            epoch1.mpc_threshold_in_basis_points(),
            DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS,
            "epoch {initial_epoch} committee should retain original threshold_basis_points"
        );
        assert_eq!(
            epoch1.mpc_weight_reduction_allowed_delta(),
            DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
            "epoch {initial_epoch} committee should retain original allowed_delta"
        );
        assert_eq!(
            epoch1.mpc_max_faulty_in_basis_points(),
            DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
            "epoch {initial_epoch} committee should retain original max_faulty_basis_points"
        );

        // Epoch 2 committee has new values.
        let epoch2 = committees.get(&target_epoch).expect("epoch 2 committee");
        assert_eq!(
            epoch2.mpc_threshold_in_basis_points(),
            new_threshold as u16,
            "epoch {target_epoch} committee should have updated threshold_basis_points"
        );
        assert_eq!(
            epoch2.mpc_weight_reduction_allowed_delta(),
            new_delta as u16,
            "epoch {target_epoch} committee should have updated allowed_delta"
        );
        assert_eq!(
            epoch2.mpc_max_faulty_in_basis_points(),
            new_max_faulty as u16,
            "epoch {target_epoch} committee should have updated max_faulty_basis_points"
        );

        Ok(())
    }

    /// Verify that a withdrawal can spend a change output whose producing
    /// transaction is mined on Bitcoin but not yet confirmed on Sui. The
    /// actual Bitcoin confirmation count must be queried from the node
    /// instead of hardcoded to 0. A UTXO whose ancestor has
    /// `confirmations >= 1` has `mempool_chain_depth() == 0` and is eligible
    /// for coin selection, even though the producing withdrawal is still a
    /// `WithdrawalTransaction` on Sui.
    ///
    /// We set `bitcoin_confirmation_threshold = 6` so that mining 2 blocks
    /// leaves withdrawal 1 in the `[1, threshold)` window: mined on Bitcoin
    /// but not yet confirmed on Sui. If confirmations were still hardcoded to
    /// 0, the change UTXO would appear to have `mempool_chain_depth == 1` and
    /// could be incorrectly filtered by the coin selector.
    ///
    /// Steps:
    /// 1. Deposit enough to produce change after two withdrawals.
    /// 2. Submit withdrawal 1 and wait for it to be picked for processing.
    /// 3. Mine 2 blocks (below threshold of 6). Withdrawal 1 is mined on
    ///    Bitcoin but the leader has not yet confirmed it on Sui.
    /// 4. Submit withdrawal 2. The only available UTXO is the change from
    ///    withdrawal 1. Its ancestor has 2 confirmations, so
    ///    `mempool_chain_depth() == 0` and it is eligible.
    /// 5. Mine to finality and verify both withdrawals are confirmed on Sui.
    #[tokio::test]
    async fn test_chained_withdrawal_spends_mined_change() -> Result<()> {
        init_test_logging();
        info!("=== Starting Chained Withdrawal Spends Mined Change Test ===");

        let mut networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_onchain_config(
                "bitcoin_confirmation_threshold",
                hashi_types::move_types::ConfigValue::U64(6),
            )
            .build()
            .await?;

        // A deposit large enough to produce a meaningful change output.
        let deposit_amount_sats = 500_000u64;
        let withdrawal_amount_sats = 30_000u64;
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone());

        // --- Withdrawal 1 ---
        let btc_destination1 = networks.bitcoin_node.get_new_address()?;
        let destination_bytes1 = extract_witness_program(&btc_destination1)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes1)
            .await?;
        info!("Withdrawal 1 submitted");

        let picked1 =
            wait_for_withdrawal_picked(&mut networks.sui_network.client, Duration::from_secs(60))
                .await?;
        info!(
            withdrawal_txn_id = %picked1.withdrawal_txn_id,
            has_change = %picked1.change_output.is_some(),
            "Withdrawal 1 picked"
        );
        assert!(
            picked1.change_output.is_some(),
            "Withdrawal 1 should have produced a change output (deposit was large enough)"
        );

        // Mine 2 blocks so withdrawal 1 has 2 Bitcoin confirmations, which is
        // below the on-chain threshold of 6. The leader will NOT call
        // confirm_withdrawal_on_sui yet, so withdrawal 1 remains a
        // WithdrawalTransaction and its change UTXO remains Pending { chain }.
        // The AncestorTx for withdrawal 1 will have confirmations=2, so
        // mempool_chain_depth() returns 0 — the change UTXO is eligible.
        networks.bitcoin_node.generate_blocks(2)?;
        info!("Mined 2 blocks; withdrawal 1 now has 2 Bitcoin confirmations (below threshold 6)");

        // --- Withdrawal 2 ---
        // The only available UTXO is the change from withdrawal 1. Its ancestor
        // is mined (confirmations=2 ≥ 1) so mempool_chain_depth()=0, making it
        // eligible even though withdrawal 1 is not yet confirmed on Sui.
        let btc_destination2 = networks.bitcoin_node.get_new_address()?;
        let destination_bytes2 = extract_witness_program(&btc_destination2)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes2)
            .await?;
        info!("Withdrawal 2 submitted (withdrawal 1 still pending on Sui)");

        let picked2 =
            wait_for_withdrawal_picked(&mut networks.sui_network.client, Duration::from_secs(60))
                .await?;
        info!(
            withdrawal_txn_id = %picked2.withdrawal_txn_id,
            "Withdrawal 2 picked"
        );

        // Mine to finality and wait for both withdrawals to be confirmed on Sui.
        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        wait_for_n_withdrawal_confirmations(
            &mut networks.sui_network.client,
            2,
            Duration::from_secs(120),
        )
        .await?;
        drop(miner);

        info!("=== Chained Withdrawal Spends Mined Change Test Passed ===");
        Ok(())
    }

    /// Verify that three consecutive withdrawals can chain through each other's
    /// change outputs while all three transactions remain unconfirmed in the
    /// mempool. The ancestor chain is now traversed recursively so that a UTXO
    /// at depth 3 in the mempool is correctly identified as such.
    ///
    /// `max_mempool_chain_depth` is set to 3 so that all three unconfirmed
    /// change outputs remain eligible for coin selection.
    ///
    /// Steps:
    /// 1. Deposit enough to produce change across three withdrawals.
    /// 2. Submit withdrawal A and wait for it to be picked (change UTXO_A at
    ///    mempool depth 1).
    /// 3. Submit withdrawal B; the leader should pick UTXO_A (depth 1 ≤ 3).
    ///    UTXO_B's full ancestor chain is now [B, A] at depth 2.
    /// 4. Submit withdrawal C; the leader should pick UTXO_B (depth 2 ≤ 3).
    /// 5. Mine to finality and verify all three withdrawals are confirmed.
    #[tokio::test]
    async fn test_chained_withdrawal_full_depth() -> Result<()> {
        init_test_logging();
        info!("=== Starting Chained Withdrawal Full Depth Test ===");

        let mut networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_max_mempool_chain_depth(3)
            .build()
            .await?;

        // Large deposit so all three withdrawals can produce meaningful change.
        let deposit_amount_sats = 500_000u64;
        let withdrawal_amount_sats = 30_000u64;
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone());

        // --- Withdrawal A ---
        let btc_destination_a = networks.bitcoin_node.get_new_address()?;
        executor
            .execute_create_withdrawal_request(
                withdrawal_amount_sats,
                extract_witness_program(&btc_destination_a)?,
            )
            .await?;
        info!("Withdrawal A submitted");

        let picked_a =
            wait_for_withdrawal_picked(&mut networks.sui_network.client, Duration::from_secs(60))
                .await?;
        info!(
            withdrawal_txn_id = %picked_a.withdrawal_txn_id,
            has_change = %picked_a.change_output.is_some(),
            "Withdrawal A picked"
        );
        assert!(
            picked_a.change_output.is_some(),
            "Withdrawal A must produce change to chain into B"
        );

        // --- Withdrawal B ---
        // UTXO_A has mempool depth 1 ≤ 3 → eligible.
        let btc_destination_b = networks.bitcoin_node.get_new_address()?;
        executor
            .execute_create_withdrawal_request(
                withdrawal_amount_sats,
                extract_witness_program(&btc_destination_b)?,
            )
            .await?;
        info!("Withdrawal B submitted");

        let picked_b =
            wait_for_withdrawal_picked(&mut networks.sui_network.client, Duration::from_secs(60))
                .await?;
        info!(
            withdrawal_txn_id = %picked_b.withdrawal_txn_id,
            has_change = %picked_b.change_output.is_some(),
            "Withdrawal B picked"
        );
        assert!(
            picked_b.change_output.is_some(),
            "Withdrawal B must produce change to chain into C"
        );

        // --- Withdrawal C ---
        // UTXO_B has full ancestor chain [B, A] at mempool depth 2 ≤ 3 → eligible.
        let btc_destination_c = networks.bitcoin_node.get_new_address()?;
        executor
            .execute_create_withdrawal_request(
                withdrawal_amount_sats,
                extract_witness_program(&btc_destination_c)?,
            )
            .await?;
        info!("Withdrawal C submitted");

        let picked_c =
            wait_for_withdrawal_picked(&mut networks.sui_network.client, Duration::from_secs(60))
                .await?;
        info!(
            withdrawal_txn_id = %picked_c.withdrawal_txn_id,
            "Withdrawal C picked"
        );

        // Mine to finality and wait for all three confirmation events.
        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        wait_for_n_withdrawal_confirmations(
            &mut networks.sui_network.client,
            3,
            Duration::from_secs(120),
        )
        .await?;
        drop(miner);

        info!("All three chained withdrawals confirmed on Sui");
        info!("=== Chained Withdrawal Full Depth Test Passed ===");
        Ok(())
    }

    /// Verify that the signature-commit chunking logic works correctly when a
    /// withdrawal transaction has enough inputs to push the BCS-encoded
    /// `signatures` vector past the 16 KiB pure-argument limit.
    ///
    /// Test outline:
    /// 1. Create 500 deposits (one UTXO each) so the pool has 500 UTXOs.
    /// 2. Submit 50 withdrawal requests that together require spending UTXOs;
    ///    consolidation at low fee rates pulls in all remaining UTXOs up to the
    ///    500-input cap.
    /// 3. Wait for a single `WithdrawalPickedForProcessingEvent` with all 50
    ///    requests batched and a large number of inputs selected.
    /// 4. Mine blocks and wait for `WithdrawalConfirmedEvent`, which implies the
    ///    signature-commit transaction succeeded (previously it would fail with
    ///    "maximum pure argument size is 16384").
    #[tokio::test]
    async fn test_large_withdrawal_signature_chunking() -> Result<()> {
        init_test_logging();
        info!("=== Starting Large Withdrawal Signature Chunking Test ===");

        // 24-hour batching delay: the batch fires only at capacity (50), not
        // on a timer. This ensures all 50 requests end up in one Bitcoin tx.
        // With 4 nodes at weight 25 each (total_weight=100), the presig pool
        // is batch_size_per_weight * total_weight. We need at least 500
        // presignatures for 500 inputs, so set batch_size_per_weight to 10
        // which gives 10 * 100 = 1000 presigs. However the pool is consumed
        // per-batch (20 at a time), so we need a larger pool to avoid
        // exhaustion during signing of 500 inputs.
        let mut networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_withdrawal_max_batch_size(50)
            .with_withdrawal_batching_delay_ms(86_400_000)
            .with_batch_size_per_weight(100)
            .build()
            .await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let hbtc_recipient = user_key.public_key().derive_address();

        let deposit_address =
            hashi.get_deposit_address(&hashi.get_onchain_mpc_pubkey()?, Some(&hbtc_recipient))?;

        // --- Create 500 Bitcoin deposits ---
        // Each deposit is 40,000 sats (above the 30,000 on-chain minimum),
        // totalling 20,000,000 sats. The withdrawals request
        // 50 x 30,000 = 1,500,000 sats. Coin selection picks enough UTXOs
        // for value and consolidation at low fee rates pulls in the rest up
        // to the 500-input cap.
        let deposit_amount_sats = 40_000u64;
        let num_deposits: usize = 500;
        // With 500 inputs and 64-byte Schnorr signatures, the BCS-encoded
        // signatures vector is ~32.5 KiB -- well above the 16 KiB per-pure-arg
        // limit that the chunking fix addresses.
        info!(
            "Creating {} Bitcoin deposits of {} sats each...",
            num_deposits, deposit_amount_sats
        );

        // Mine blocks every 20 transactions to avoid hitting Bitcoin Core's
        // mempool descendant chain limit (default 25).
        let mut btc_txids = Vec::with_capacity(num_deposits);
        for i in 0..num_deposits {
            let txid = networks
                .bitcoin_node
                .send_to_address(&deposit_address, Amount::from_sat(deposit_amount_sats))?;
            btc_txids.push(txid);
            if (i + 1) % 20 == 0 {
                networks.bitcoin_node.generate_blocks(1)?;
                if (i + 1) % 100 == 0 {
                    info!("  Bitcoin txns sent: {}/{}", i + 1, num_deposits);
                }
            }
        }

        info!("Mining blocks for confirmation...");
        networks.bitcoin_node.generate_blocks(10)?;

        // Look up vout for each tx and register deposits on Sui in batches.
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone());

        let deposits_data: Vec<(Address, u32, u64)> = btc_txids
            .iter()
            .map(|txid| {
                let vout = lookup_vout(
                    &networks,
                    *txid,
                    deposit_address.clone(),
                    deposit_amount_sats,
                )?;
                Ok((txid_to_address(txid), vout as u32, deposit_amount_sats))
            })
            .collect::<Result<Vec<_>>>()?;

        // PTB command limit is 1024; each deposit uses 3 commands, so batch
        // at 300 deposits per PTB to stay well within limits.
        for (batch_idx, chunk) in deposits_data.chunks(300).enumerate() {
            info!(
                "Submitting deposit batch {} ({} deposits)...",
                batch_idx + 1,
                chunk.len()
            );
            executor
                .execute_create_deposit_requests_multi(chunk, Some(hbtc_recipient))
                .await?;
        }
        info!("All {} deposit requests submitted on Sui", num_deposits);

        // Poll the on-chain deposit queue until all deposits are confirmed.
        // The hashi node's watcher keeps OnchainState up-to-date; confirmed
        // deposits leave the queue automatically.
        // Mine blocks in the background so the leader's BTC-block-driven
        // deposit processing loop keeps firing.
        let _deposit_miner = BackgroundMiner::start(&networks.bitcoin_node);
        info!("Waiting for {} deposit confirmations...", num_deposits);
        let deposit_timeout = Duration::from_secs(600);
        let deposit_start = std::time::Instant::now();
        let mut last_logged = 0usize;
        loop {
            if deposit_start.elapsed() > deposit_timeout {
                let remaining = hashi.onchain_state().deposit_requests().len();
                return Err(anyhow!(
                    "Timeout waiting for deposit confirmations: {} still pending after {:?}",
                    remaining,
                    deposit_timeout,
                ));
            }
            let remaining = hashi.onchain_state().deposit_requests().len();
            if remaining == 0 {
                break;
            }
            let confirmed = num_deposits - remaining;
            if confirmed / 50 > last_logged / 50 {
                info!("Deposit confirmations: {}/{}", confirmed, num_deposits);
                last_logged = confirmed;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        info!("All deposits confirmed");

        // --- Submit 50 withdrawal requests ---
        let withdrawal_amount_sats = 30_000u64;
        let num_withdrawals: usize = 50;
        info!(
            "Submitting {} withdrawal requests of {} sats each...",
            num_withdrawals, withdrawal_amount_sats
        );

        for i in 0..num_withdrawals {
            let btc_destination = networks.bitcoin_node.get_new_address()?;
            let destination_bytes = extract_witness_program(&btc_destination)?;
            executor
                .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes)
                .await?;
            if (i + 1) % 10 == 0 {
                info!(
                    "  Withdrawal requests submitted: {}/{}",
                    i + 1,
                    num_withdrawals
                );
            }
        }
        info!("All withdrawal requests submitted");

        // Wait for the batched withdrawal to be picked for processing. The
        // 24-hour delay means it fires only at capacity (50 requests).
        info!("Waiting for batched withdrawal to be picked...");
        let picked = wait_for_batched_withdrawal_picked(
            &mut networks.sui_network.client,
            num_withdrawals,
            Duration::from_secs(300),
        )
        .await?;

        info!(
            withdrawal_txn_id = %picked.withdrawal_txn_id,
            requests = %picked.request_ids.len(),
            inputs = %picked.inputs.len(),
            "Batched withdrawal picked"
        );

        assert_eq!(
            picked.request_ids.len(),
            num_withdrawals,
            "Expected all {} withdrawal requests to be batched",
            num_withdrawals,
        );

        // With 500 UTXOs at 4,000 sats and 1,500,000 sats of withdrawals,
        // coin selection should pick most UTXOs for value and consolidate the
        // rest. Verify that enough inputs were selected to exceed the old
        // 16 KiB per-pure-arg limit (~252 signatures at 65 BCS bytes each).
        assert!(
            picked.inputs.len() > 252,
            "Expected more than 252 inputs to exercise signature chunking, \
             but only got {}",
            picked.inputs.len(),
        );

        // Mine blocks and wait for the withdrawal to be confirmed. This
        // implicitly validates that the signature-commit transaction succeeded
        // -- previously it would fail with "maximum pure argument size is
        // 16384".
        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        wait_for_n_withdrawal_confirmations(
            &mut networks.sui_network.client,
            1,
            Duration::from_secs(600),
        )
        .await?;
        drop(miner);

        info!("=== Large Withdrawal Signature Chunking Test Passed ===");
        Ok(())
    }
}
