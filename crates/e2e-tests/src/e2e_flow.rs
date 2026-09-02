// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use anyhow::anyhow;
    use bitcoin::Amount;
    use bitcoin::Txid;

    use futures::StreamExt;
    use hashi::deposits::UnapprovedDepositError;
    use hashi::sui_tx_executor::SuiTxExecutor;
    use hashi_types::bitcoin::BitcoinAddress;
    use hashi_types::move_types::ProtocolType;
    use hashi_types::move_types::WithdrawalConfirmed;
    use hashi_types::move_types::WithdrawalPickedForProcessing;
    use hashi_types::move_types::WithdrawalSigned;
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
    use crate::test_helpers::assert_no_unrouted_objects;
    use crate::test_helpers::assert_tob_mirror_parity;
    use crate::test_helpers::create_deposit_and_wait;
    use crate::test_helpers::extract_witness_program;
    use crate::test_helpers::fetch_tob_certs_from_chain;
    use crate::test_helpers::get_hbtc_balance;
    use crate::test_helpers::init_test_logging;
    use crate::test_helpers::lookup_vout;
    use crate::test_helpers::subscribe_withdrawal_confirmations;
    use crate::test_helpers::txid_to_address;
    use crate::test_helpers::wait_for_deposit_confirmation;
    use crate::test_helpers::wait_for_spent_utxo_cleanup;
    use crate::test_helpers::wait_for_withdrawal_archival;

    const MAX_TX_SIZE_BYTES: usize = 131_072;
    const MAX_SERIALIZED_TX_EFFECTS_SIZE_BYTES: usize = 524_288;
    const MAX_NUM_CACHED_OBJECTS: usize = 1_000;

    struct EventWithEffects<T> {
        event: T,
        tx_size_bytes: usize,
        effects_size_bytes: usize,
        changed_objects: usize,
        unchanged_loaded_runtime_objects: usize,
    }

    fn assert_tx_size_under_sui_limit(stage: &str, tx_size_bytes: usize) {
        info!(
            stage,
            tx_size_bytes,
            limit = MAX_TX_SIZE_BYTES,
            "Observed serialized Sui transaction size"
        );
        assert!(
            tx_size_bytes <= MAX_TX_SIZE_BYTES,
            "{stage} transaction size ({tx_size_bytes} bytes) exceeded Sui's \
             max_tx_size_bytes ({MAX_TX_SIZE_BYTES} bytes)"
        );
    }

    fn assert_effects_size_under_sui_limit(stage: &str, effects_size_bytes: usize) {
        info!(
            stage,
            effects_size_bytes,
            limit = MAX_SERIALIZED_TX_EFFECTS_SIZE_BYTES,
            "Observed serialized Sui transaction effects size"
        );
        assert!(
            effects_size_bytes <= MAX_SERIALIZED_TX_EFFECTS_SIZE_BYTES,
            "{stage} effects size ({effects_size_bytes} bytes) exceeded Sui's \
             max_serialized_tx_effects_size_bytes ({MAX_SERIALIZED_TX_EFFECTS_SIZE_BYTES} bytes)"
        );
    }

    fn assert_changed_objects_under_sui_limit(stage: &str, changed_objects: usize) {
        info!(
            stage,
            changed_objects,
            limit = MAX_NUM_CACHED_OBJECTS,
            "Observed changed objects in Sui transaction effects"
        );
        assert!(
            changed_objects <= MAX_NUM_CACHED_OBJECTS,
            "{stage} changed objects ({changed_objects}) exceeded Sui's \
             max_num_cached_objects ({MAX_NUM_CACHED_OBJECTS})"
        );
    }

    fn assert_runtime_object_count_under_sui_limit(
        stage: &str,
        changed_objects: usize,
        unchanged_loaded_runtime_objects: usize,
    ) {
        let runtime_objects = changed_objects + unchanged_loaded_runtime_objects;
        info!(
            stage,
            runtime_objects,
            changed_objects,
            unchanged_loaded_runtime_objects,
            limit = MAX_NUM_CACHED_OBJECTS,
            "Observed runtime object count from Sui transaction effects"
        );
        assert!(
            runtime_objects <= MAX_NUM_CACHED_OBJECTS,
            "{stage} runtime object count ({runtime_objects}) exceeded Sui's \
             max_num_cached_objects ({MAX_NUM_CACHED_OBJECTS})"
        );
    }

    fn runtime_object_count(event: &EventWithEffects<impl Sized>) -> usize {
        event.changed_objects + event.unchanged_loaded_runtime_objects
    }

    fn tx_bcs_size(txn: &sui_rpc::proto::sui::rpc::v2::ExecutedTransaction) -> Result<usize> {
        txn.transaction()
            .bcs()
            .value_opt()
            .map(|bytes| bytes.len())
            .ok_or_else(|| anyhow!("transaction BCS bytes were not returned"))
    }

    fn effects_bcs_size(txn: &sui_rpc::proto::sui::rpc::v2::ExecutedTransaction) -> Result<usize> {
        txn.effects()
            .bcs()
            .value_opt()
            .map(|bytes| bytes.len())
            .ok_or_else(|| anyhow!("transaction effects BCS bytes were not returned"))
    }

    /// The builder's default boot already publishes the v1 bytecode snapshot
    /// and upgrades to the current source, so every test in this module
    /// exercises the post-upgrade configuration a real network is in — not a
    /// fresh single-version publish.
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

    async fn rotate_into_avid(networks: &mut TestNetworks) -> Result<()> {
        let initial_epoch = {
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
            assert_eq!(
                nodes[0]
                    .hashi()
                    .onchain_state()
                    .mpc_nonce_generation_protocol(),
                1,
                "the AVID protocol override must have landed"
            );
            nodes[0].current_epoch().unwrap()
        };
        networks.sui_network.force_close_epoch().await?;
        let target_epoch = initial_epoch + 1;
        let futs: Vec<_> = networks
            .hashi_network
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
        Ok(())
    }

    fn avid_override(builder: TestNetworksBuilder) -> TestNetworksBuilder {
        builder.with_onchain_config(
            "mpc_nonce_generation_protocol",
            hashi_types::move_types::ConfigValue::U64(1),
        )
    }

    async fn wait_for_deposit_approval(
        networks: &TestNetworks,
        request_id: Address,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(onchain_state) = networks.hashi_network.nodes()[0]
                .hashi()
                .onchain_state_opt()
                && onchain_state
                    .deposit_requests()
                    .iter()
                    .any(|request| request.id == request_id && request.approval_cert.is_some())
            {
                info!(deposit_id = %request_id, "Deposit approved");
                return Ok(());
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow!(
                    "Timeout waiting for deposit approval after {timeout:?}"
                ));
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn wait_until(
        what: &str,
        timeout: Duration,
        mut done: impl FnMut() -> bool,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if done() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow!("timeout waiting for {what}"));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn wait_for_kyoto_sync(networks: &TestNetworks, timeout: Duration) -> Result<()> {
        wait_until("every node to sync with Bitcoin", timeout, || {
            networks
                .hashi_network
                .nodes()
                .iter()
                .all(|node| node.hashi().metrics.kyoto_synced.get() == 1)
        })
        .await
    }

    async fn wait_for_kyoto_height(
        networks: &TestNetworks,
        expected_height: u64,
        timeout: Duration,
    ) -> Result<()> {
        let expected_height = i64::try_from(expected_height)?;
        wait_until(
            &format!("every synced Kyoto node to reach Bitcoin height {expected_height}"),
            timeout,
            || {
                networks.hashi_network.nodes().iter().all(|node| {
                    let metrics = &node.hashi().metrics;
                    metrics.kyoto_synced.get() == 1
                        && metrics.kyoto_best_height.get() >= expected_height
                })
            },
        )
        .await
    }

    fn outpoints_with_status(networks: &TestNetworks, status: &str) -> Vec<i64> {
        networks
            .hashi_network
            .nodes()
            .iter()
            .map(|node| {
                node.hashi()
                    .metrics
                    .deposit_outpoint_confirmations
                    .with_label_values(&[status])
                    .get()
            })
            .collect()
    }

    async fn wait_for_outpoint_status(
        networks: &TestNetworks,
        status: &str,
        baseline: &[i64],
        expected_nodes: usize,
        timeout: Duration,
    ) -> Result<()> {
        wait_until(
            &format!("{expected_nodes} node(s) to observe deposit status {status}"),
            timeout,
            || {
                outpoints_with_status(networks, status)
                    .iter()
                    .zip(baseline)
                    .filter(|(current, baseline)| current > baseline)
                    .count()
                    >= expected_nodes
            },
        )
        .await
    }

    /// Wait until every node's local mirror has applied the deposit request.
    /// Transaction execution finishing does not imply any node has seen it.
    async fn wait_for_deposit_request_mirrored(
        networks: &TestNetworks,
        request_id: Address,
        timeout: Duration,
    ) -> Result<()> {
        wait_until(
            &format!("every node to mirror deposit request {request_id}"),
            timeout,
            || {
                networks.hashi_network.nodes().iter().all(|node| {
                    node.hashi()
                        .onchain_state()
                        .has_deposit_request(&request_id)
                })
            },
        )
        .await
    }

    async fn assert_deposit_requires_confirmations(
        networks: &TestNetworks,
        request_id: Address,
        confirmations: u32,
        required_confirmations: u32,
    ) -> Result<()> {
        let expected = format!("has {confirmations}/{required_confirmations} confirmations");
        for (index, node) in networks.hashi_network.nodes().iter().enumerate() {
            let node_hashi = node.hashi();
            let deposit_request = node_hashi
                .onchain_state()
                .deposit_requests()
                .into_iter()
                .find(|request| request.id == request_id)
                .ok_or_else(|| anyhow!("node {index} has no deposit request {request_id}"))?;
            match node_hashi.validate_deposit_request(&deposit_request).await {
                Err(UnapprovedDepositError::BitcoinNotConfirmed(error)) => assert!(
                    error.to_string().contains(&expected),
                    "node {index} reported an unexpected confirmation error: {error}"
                ),
                Err(error) => panic!(
                    "node {index} returned an unexpected validation error at {confirmations} confirmations: {error}"
                ),
                Ok(()) => panic!(
                    "node {index} accepted the deposit at {confirmations}/{required_confirmations} confirmations"
                ),
            }
        }
        Ok(())
    }

    fn assert_deposit_request_unapproved(networks: &TestNetworks, request_id: Address) {
        let onchain_state = networks.hashi_network.nodes()[0].hashi().onchain_state();
        let deposit_request = onchain_state
            .deposit_requests()
            .into_iter()
            .find(|request| request.id == request_id)
            .unwrap_or_else(|| panic!("deposit request {request_id} not found"));
        assert!(
            deposit_request.approval_cert.is_none(),
            "deposit request should not be approved"
        );
    }

    /// Wait for a withdrawal transaction to be confirmed on the Bitcoin chain.
    /// The output to `destination` must be at most `max_amount` and at least
    /// `min_amount` (to account for variable miner fees deducted from the user).
    async fn wait_for_withdrawal_tx_success(
        bitcoin_node: &crate::BitcoinNodeHandle,
        txid: &Txid,
        destination: &BitcoinAddress,
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
    async fn test_passive_bitcoin_deposit_discovery() -> Result<()> {
        init_test_logging();
        info!("=== Starting Passive Bitcoin Deposit Discovery Test ===");

        let networks = setup_test_networks(
            TestNetworksBuilder::new()
                .with_nodes(4)
                .with_onchain_config(
                    "bitcoin_deposit_time_delay_ms",
                    hashi_types::move_types::ConfigValue::U64(60_000),
                ),
        )
        .await?;
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let hbtc_recipient = user_key.public_key().derive_address();
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let deposit_address = hashi.get_deposit_address(Some(&hbtc_recipient))?;
        let amount_sats = 31_337u64;
        let amount = Amount::from_sat(amount_sats);
        let rpc = networks.bitcoin_node.rpc_client();

        let miner_fee = Amount::from_sat(1_000);
        let unspent = rpc
            .list_unspent()?
            .into_model()?
            .0
            .into_iter()
            .find(|output| {
                output.spendable
                    && output
                        .amount
                        .to_unsigned()
                        .is_ok_and(|value| value > amount + miner_fee)
            })
            .ok_or_else(|| anyhow!("wallet has no spendable output for deposit transaction"))?;
        let input_amount = unspent.amount.to_unsigned()?;
        let change_address = networks.bitcoin_node.get_new_address()?;
        let raw_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::new(unspent.txid, unspent.vout),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::default(),
            }],
            output: vec![
                bitcoin::TxOut {
                    value: amount,
                    script_pubkey: deposit_address.script_pubkey(),
                },
                bitcoin::TxOut {
                    value: input_amount - amount - miner_fee,
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
        };
        let signed = rpc
            .sign_raw_transaction_with_wallet(&raw_tx)?
            .into_model()?;
        if !signed.complete {
            return Err(anyhow!(
                "wallet did not completely sign deposit transaction: {:?}",
                signed.errors
            ));
        }
        let deposit_tx = signed.tx;
        let txid = deposit_tx.compute_txid();

        wait_for_kyoto_sync(&networks, Duration::from_secs(30)).await?;
        let baseline_not_found = outpoints_with_status(&networks, "not_found");
        let baseline_one_confirmation = outpoints_with_status(&networks, "1");
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.into());
        let request_id = executor
            .execute_create_deposit_request(
                txid_to_address(&txid),
                0,
                amount_sats,
                Some(hbtc_recipient),
            )
            .await?;

        // Every node must track the outpoint before the deposit block is
        // mined; a node that misses the block's passive scan would stay
        // unchecked, as followers only run discovery when asked to sign.
        wait_for_deposit_request_mirrored(&networks, request_id, Duration::from_secs(30)).await?;
        wait_for_outpoint_status(
            &networks,
            "not_found",
            &baseline_not_found,
            1,
            Duration::from_secs(30),
        )
        .await?;
        assert_deposit_request_unapproved(&networks, request_id);

        let broadcast_txid = rpc.send_raw_transaction(&deposit_tx)?.txid()?;
        assert_eq!(
            broadcast_txid, txid,
            "Bitcoin Core broadcast a different txid"
        );
        networks.bitcoin_node.generate_blocks(1)?;
        wait_for_outpoint_status(
            &networks,
            "1",
            &baseline_one_confirmation,
            networks.hashi_network.nodes().len(),
            Duration::from_secs(30),
        )
        .await?;
        assert_deposit_request_unapproved(&networks, request_id);

        networks.bitcoin_node.generate_blocks(9)?;
        wait_for_deposit_approval(&networks, request_id, Duration::from_secs(120)).await?;

        info!("=== Passive Bitcoin Deposit Discovery Test Passed ===");
        Ok(())
    }

    #[tokio::test]
    async fn test_coinbase_deposit_waits_for_maturity() -> Result<()> {
        init_test_logging();
        info!("=== Starting Coinbase Deposit Maturity Test ===");

        let networks = setup_test_networks(
            TestNetworksBuilder::new()
                .with_nodes(4)
                .with_onchain_config(
                    "bitcoin_deposit_time_delay_ms",
                    hashi_types::move_types::ConfigValue::U64(600_000),
                ),
        )
        .await?;
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let hbtc_recipient = user_key.public_key().derive_address();
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let deposit_address = hashi.get_deposit_address(Some(&hbtc_recipient))?;
        let rpc = networks.bitcoin_node.rpc_client();

        let block_hashes = rpc
            .generate_to_address(1, &deposit_address)?
            .into_model()?
            .0;
        let [block_hash] = block_hashes.as_slice() else {
            return Err(anyhow!(
                "generate_to_address returned {} blocks instead of one",
                block_hashes.len()
            ));
        };
        let block = rpc.get_block(*block_hash)?;
        let coinbase_tx = block
            .txdata
            .first()
            .ok_or_else(|| anyhow!("generated block {block_hash} has no transactions"))?;
        assert!(
            coinbase_tx.is_coinbase(),
            "first transaction in generated block {block_hash} is not coinbase"
        );
        let (vout, txout) = coinbase_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, txout)| txout.script_pubkey == deposit_address.script_pubkey())
            .ok_or_else(|| {
                anyhow!(
                    "coinbase transaction {} has no output for {deposit_address}",
                    coinbase_tx.compute_txid()
                )
            })?;
        let txid = coinbase_tx.compute_txid();
        let vout = u32::try_from(vout)?;
        let amount_sats = txout.value.to_sat();

        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.into());
        let request_id = executor
            .execute_create_deposit_request(
                txid_to_address(&txid),
                vout,
                amount_sats,
                Some(hbtc_recipient),
            )
            .await?;
        wait_for_deposit_request_mirrored(&networks, request_id, Duration::from_secs(30)).await?;

        networks.bitcoin_node.generate_blocks(5)?;
        let height = networks.bitcoin_node.get_block_count()?;
        wait_for_kyoto_height(&networks, height, Duration::from_secs(120)).await?;
        assert_deposit_requires_confirmations(&networks, request_id, 6, 100).await?;

        networks.bitcoin_node.generate_blocks(93)?;
        let height = networks.bitcoin_node.get_block_count()?;
        wait_for_kyoto_height(&networks, height, Duration::from_secs(120)).await?;
        assert_deposit_requires_confirmations(&networks, request_id, 99, 100).await?;

        networks.bitcoin_node.generate_blocks(1)?;
        let height = networks.bitcoin_node.get_block_count()?;
        wait_for_kyoto_height(&networks, height, Duration::from_secs(120)).await?;
        wait_for_deposit_approval(&networks, request_id, Duration::from_secs(120)).await?;

        info!("=== Coinbase Deposit Maturity Test Passed ===");
        Ok(())
    }

    #[tokio::test]
    async fn test_stale_cert_deposit_reprocessed_after_epoch_change_without_btc_block() -> Result<()>
    {
        init_test_logging();
        info!("=== Starting Stale-Cert Deposit Epoch-Change Test ===");

        let mut networks = setup_test_networks(
            TestNetworksBuilder::new()
                .with_nodes(4)
                .with_onchain_config(
                    "bitcoin_deposit_time_delay_ms",
                    hashi_types::move_types::ConfigValue::U64(60_000),
                ),
        )
        .await?;

        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let hbtc_recipient = user_key.public_key().derive_address();
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let deposit_address = hashi.get_deposit_address(Some(&hbtc_recipient))?;
        let amount_sats = 42_000u64;

        info!("Sending Bitcoin to deposit address...");
        let txid = networks
            .bitcoin_node
            .send_to_address(&deposit_address, Amount::from_sat(amount_sats))?;
        networks.bitcoin_node.generate_blocks(10)?;

        info!("Creating deposit request on Sui...");
        let vout = lookup_vout(&networks, txid, deposit_address, amount_sats)?;
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone().into());
        let request_id = executor
            .execute_create_deposit_request(
                txid_to_address(&txid),
                vout as u32,
                amount_sats,
                Some(hbtc_recipient),
            )
            .await?;

        // One BTC block lets the current epoch approve the request. The
        // non-zero deposit delay prevents confirmation before rotation.
        networks.bitcoin_node.generate_blocks(1)?;
        wait_for_deposit_approval(&networks, request_id, Duration::from_secs(60)).await?;

        let unapproved_request_id = executor
            .execute_create_deposit_request(
                Address::new([0xCA; 32]),
                0,
                43_000,
                Some(hbtc_recipient),
            )
            .await?;
        wait_for_deposit_request_mirrored(
            &networks,
            unapproved_request_id,
            Duration::from_secs(30),
        )
        .await?;
        assert_deposit_request_unapproved(&networks, unapproved_request_id);

        let initial_epoch = networks.hashi_network.nodes()[0]
            .current_epoch()
            .ok_or_else(|| anyhow!("no current Hashi epoch"))?;
        let target_epoch = initial_epoch + 1;
        networks.sui_network.force_close_epoch().await?;
        let futs: Vec<_> = networks
            .hashi_network()
            .nodes()
            .iter()
            .map(|node| node.wait_for_epoch(target_epoch, Duration::from_secs(180)))
            .collect();
        for (i, result) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            result.unwrap_or_else(|e| panic!("Node {i} failed to reach epoch {target_epoch}: {e}"));
        }

        wait_for_deposit_confirmation(
            &mut networks.sui_network.client,
            request_id,
            Duration::from_secs(180),
        )
        .await?;
        assert_deposit_request_unapproved(&networks, unapproved_request_id);

        let hbtc_balance = get_hbtc_balance(
            &mut networks.sui_network.client,
            networks.hashi_network.ids().package_id,
            hbtc_recipient,
        )
        .await?;
        assert_eq!(hbtc_balance, amount_sats, "Expected deposited hBTC amount");

        info!("=== Stale-Cert Deposit Epoch-Change Test Passed ===");
        Ok(())
    }

    #[tokio::test]
    async fn test_bitcoin_withdrawal_e2e_flow() -> Result<()> {
        init_test_logging();
        info!("=== Starting Bitcoin Withdrawal E2E Test ===");

        let builder = TestNetworksBuilder::new().with_nodes(4);
        let mut networks = setup_test_networks(builder).await?;

        for node in networks.hashi_network.nodes() {
            // The harness injects no local guardian_endpoint, so a resolved
            // client proves the lazy on-chain path (guardian_url set by the
            // launch tx after these nodes booted) — guardian set up last.
            assert!(node.hashi().config.guardian_endpoint().is_none());
            assert!(node.hashi().guardian_client().is_some());
            // Harness waits for limiter bootstrap before returning.
            assert!(node.hashi().local_limiter().is_some());
        }
        let harness = networks
            .guardian_harness
            .as_ref()
            .expect("harness present after 2-of-2 cutover");
        assert!(harness.enclave().require_fully_initialized().is_ok());

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

        // The archival assertion below needs the deferred-archival flow,
        // which the squashed package carries from v1. Pin that the fresh
        // boot resolves it.
        assert_eq!(
            hashi.onchain_state().active_package_version(),
            Some(1),
            "the fresh v1 boot must resolve the active version the archival \
             flow runs at"
        );

        let user_key = networks.sui_network.user_keys.first().unwrap();
        let withdrawal_amount_sats = 30_000u64;
        let btc_destination = networks.bitcoin_node.get_new_address()?;
        let destination_bytes = extract_witness_program(&btc_destination)?;
        info!(
            "Requesting withdrawal of {} sats to {}",
            withdrawal_amount_sats, btc_destination
        );

        let confirmations =
            subscribe_withdrawal_confirmations(&mut networks.sui_network.client).await?;

        let mut withdrawal_executor =
            SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
                .with_signer(user_key.clone().into());
        let withdrawal_request_id = withdrawal_executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes)
            .await?;
        info!("Withdrawal request created: {}", withdrawal_request_id);

        let miner = BackgroundMiner::start(&networks.bitcoin_node);

        let confirmed_event = confirmations
            .wait_for(withdrawal_request_id, Duration::from_secs(60))
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

        // The confirm marked the withdrawal's inputs spent; the leader's GC
        // must now clean them from its mirror, and the eventless cleanup
        // deletions must reach every node's mirror via the object stream.
        wait_for_spent_utxo_cleanup(&networks, Duration::from_secs(60)).await?;

        // The confirm left the withdrawal txn (and its requests) in the hot
        // bags; the leader's deferred-archival GC must move them to the
        // archive bags on-chain, observable as the ids draining from every
        // node's mirror. This pins the deferred-archival GC end-to-end.
        wait_for_withdrawal_archival(&networks, Duration::from_secs(60)).await?;

        let guardian_state = networks
            .guardian_harness
            .as_ref()
            .expect("harness present after 2-of-2 cutover")
            .enclave()
            .state
            .limiter_snapshot()
            .expect("guardian limiter state present after a successful withdrawal");
        assert_eq!(guardian_state.next_seq, 1);
        let local_state = hashi
            .local_limiter()
            .expect("local limiter present after bootstrap")
            .snapshot();
        // `last_updated_at` can drift a few seconds — watcher uses the
        // event-carrying checkpoint, guardian the leader's signing one.
        assert_eq!(local_state.next_seq, guardian_state.next_seq);
        assert_eq!(
            local_state.num_tokens_available,
            guardian_state.num_tokens_available,
        );
        let drift = local_state
            .last_updated_at
            .checked_sub(guardian_state.last_updated_at);
        assert!(
            matches!(drift, Some(0..=60)),
            "local last_updated_at ({}) must be 0–60s after guardian's ({})",
            local_state.last_updated_at,
            guardian_state.last_updated_at,
        );

        assert_no_unrouted_objects(&networks);
        assert_tob_mirror_parity(&networks).await?;

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
        let confirmations =
            subscribe_withdrawal_confirmations(&mut networks.sui_network.client).await?;
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(signer.into());
        let withdrawal_request_id = executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes)
            .await?;

        let miner = BackgroundMiner::start(&networks.bitcoin_node);

        let confirmed = confirmations
            .wait_for(withdrawal_request_id, Duration::from_secs(60))
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
    async fn test_nonce_accumulation_window_open() -> Result<()> {
        init_test_logging();
        let mut networks = setup_test_networks(
            avid_override(TestNetworksBuilder::new().with_nodes(4)).with_onchain_config(
                "mpc_nonce_accumulation_window_ms",
                hashi_types::move_types::ConfigValue::U64(2_000),
            ),
        )
        .await?;
        rotate_into_avid(&mut networks).await?;
        {
            let hashi = networks.hashi_network.nodes()[0].hashi();
            let mpc_manager = hashi.mpc_manager().expect("mpc manager after rotation");
            let window_ms = mpc_manager
                .read()
                .unwrap()
                .mpc_config
                .nonce_accumulation_window_ms;
            assert!(
                window_ms > 0,
                "the accumulation window must be open for this test to mean anything. \
                 Asserting a specific value here would be vacuous: the override this \
                 harness applies is the compiled-in default, so an equality check passes \
                 whether or not governance ever set it. Governance tuning of this key is \
                 not covered by any test — see the update_config insert gap."
            );
            // On the squashed package every nonce bucket is stamped from
            // genesis, so the window path is the only one that exists; no
            // bare-only version guard is needed.
        }
        let deposit_amount_sats = 100_000u64;
        let withdrawal_amount_sats = 30_000u64;
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        withdraw_and_confirm(&mut networks, &hashi, user_key, withdrawal_amount_sats).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_presigning_recovery_within_batch() -> Result<()> {
        init_test_logging();
        let networks = setup_test_networks(TestNetworksBuilder::new().with_nodes(4)).await?;
        presigning_recovery_within_batch_flow(networks).await
    }

    #[tokio::test]
    async fn test_avid_presigning_recovery_within_batch() -> Result<()> {
        init_test_logging();
        let mut networks =
            setup_test_networks(avid_override(TestNetworksBuilder::new().with_nodes(4))).await?;
        rotate_into_avid(&mut networks).await?;
        presigning_recovery_within_batch_flow(networks).await
    }

    async fn presigning_recovery_within_batch_flow(mut networks: TestNetworks) -> Result<()> {
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
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(60))
            .await?;
        presigning_recovery_across_batch_boundary_flow(networks).await
    }

    #[tokio::test]
    async fn test_avid_presigning_recovery_across_batch_boundary() -> Result<()> {
        init_test_logging();
        let mut networks = avid_override(
            TestNetworksBuilder::new()
                .with_nodes(4)
                .with_batch_size_per_weight(1),
        )
        .build()
        .await?;
        rotate_into_avid(&mut networks).await?;
        presigning_recovery_across_batch_boundary_flow(networks).await
    }

    async fn presigning_recovery_across_batch_boundary_flow(
        mut networks: TestNetworks,
    ) -> Result<()> {
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
    ) -> Result<WithdrawalPickedForProcessing> {
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
                    "Timeout waiting for WithdrawalPickedForProcessing after {:?}",
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
                        .contains("WithdrawalPickedForProcessing")
                    {
                        match WithdrawalPickedForProcessing::from_bcs(event.contents().value()) {
                            Ok(data) => {
                                info!(
                                    withdrawal_txn_id = %data.withdrawal_txn_id,
                                    "Withdrawal picked for processing"
                                );
                                return Ok(data);
                            }
                            Err(e) => {
                                debug!("Failed to parse WithdrawalPickedForProcessing: {}", e);
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
    ) -> Result<Vec<WithdrawalConfirmed>> {
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
                    if event.contents().name().contains("WithdrawalConfirmed") {
                        match WithdrawalConfirmed::from_bcs(event.contents().value()) {
                            Ok(data) => {
                                info!(
                                    withdrawal_txn_id = %data.withdrawal_txn_id,
                                    progress = %format!("{}/{}", events.len() + 1, n),
                                    "Withdrawal confirmed"
                                );
                                events.push(data);
                            }
                            Err(e) => {
                                debug!("Failed to parse WithdrawalConfirmed: {}", e);
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
    ///    it (`WithdrawalPickedForProcessing`). No Bitcoin blocks mined
    ///    yet, so the change UTXO is pending/unconfirmed.
    /// 3. Submit withdrawal 2 (30 000 sats) immediately. Wait for the
    ///    committee to commit it. Assert that it spent the pending change UTXO
    ///    from withdrawal 1.
    /// 4. Mine blocks and wait for both `WithdrawalConfirmed`s.
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
            .with_signer(user_key.clone().into());
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes1)
            .await?;
        info!("Withdrawal 1 request submitted");

        // Wait for the committee to commit withdrawal 1. At this point the
        // deposit UTXO is locked and the change UTXO is inserted as pending
        // (produced_by = Some, spent_by = None). No Bitcoin blocks have been
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
            !picked1.change_outputs.is_empty(),
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

    // TODO(guardian): re-enable once the guardian is idempotent per withdrawal
    // id. With the guardian now always-on, a withdrawal finalized through the
    // guardian in epoch N consumes its limiter seq; if `sign_withdrawal` does
    // not land on-chain before the epoch-boundary reconfig (signing is blocked
    // during reconfig), the new epoch's leader re-finalizes the same withdrawal
    // with the same seq and the guardian rejects it ("seq mismatch"), so the
    // withdrawal never confirms. The real fix is guardian (wid)-idempotency
    // (the StandardWithdrawal response cache / the future out-of-enclave proxy),
    // which is out of scope for this stack.
    #[ignore = "cross-epoch guardian seq-replay; needs guardian wid-idempotency (see TODO)"]
    #[tokio::test]
    async fn test_withdrawal_signs_across_epoch_boundary() -> Result<()> {
        init_test_logging();

        let mut networks = setup_test_networks(TestNetworksBuilder::new().with_nodes(4)).await?;

        let deposit_amount_sats = 100_000u64;
        create_deposit_and_wait(&mut networks, deposit_amount_sats).await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let withdrawal_amount_sats = 30_000u64;
        let btc_destination = networks.bitcoin_node.get_new_address()?;
        let destination_bytes = extract_witness_program(&btc_destination)?;

        let initial_epoch = networks.hashi_network.nodes()[0]
            .current_epoch()
            .ok_or_else(|| anyhow!("no current Hashi epoch"))?;

        let confirmations =
            subscribe_withdrawal_confirmations(&mut networks.sui_network.client).await?;

        let mut withdrawal_executor =
            SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
                .with_signer(user_key.clone().into());
        let withdrawal_request_id = withdrawal_executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes)
            .await?;

        wait_for_withdrawal_picked(&mut networks.sui_network.client, Duration::from_secs(30))
            .await?;

        networks.sui_network.force_close_epoch().await?;
        let target_epoch = initial_epoch + 1;
        let futs: Vec<_> = networks
            .hashi_network()
            .nodes()
            .iter()
            .map(|n| n.wait_for_epoch(target_epoch, Duration::from_secs(120)))
            .collect();
        for (i, r) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            r.unwrap_or_else(|e| panic!("Node {i} failed to reach epoch {target_epoch}: {e}"));
        }

        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        confirmations
            .wait_for(withdrawal_request_id, Duration::from_secs(180))
            .await?;
        drop(miner);

        Ok(())
    }

    /// A committee-voted ignore takes effect at the epoch boundary: the next
    /// committee forms without the member, total weight re-sums, and the
    /// smaller committee still confirms deposits and withdrawals end to end
    /// (BLS certs, MPC reshare, and the guardian all follow the members
    /// vector).
    ///
    /// Runs on the default snapshot-v1 + upgrade harness, so it also proves
    /// the v2-only ignore_member surface is addressed at the upgraded
    /// package id.
    #[tokio::test]
    async fn test_ignored_member_excluded_at_epoch_boundary() -> Result<()> {
        init_test_logging();

        let mut networks = setup_test_networks(TestNetworksBuilder::new().with_nodes(4)).await?;

        let hashi_ids = networks.hashi_network.ids();

        let (latest_package_id, members_before, weight_before, target, initial_epoch) = {
            let nodes = networks.hashi_network.nodes();

            // The v2-only ignore_member surface lives at the upgraded
            // package id, not the snapshot-v1 publish id in `hashi_ids`.
            let latest_package_id = nodes[0]
                .hashi()
                .onchain_state()
                .package_id()
                .ok_or_else(|| anyhow!("no package versions known"))?;

            let committee = nodes[0]
                .hashi()
                .onchain_state()
                .current_committee()
                .ok_or_else(|| anyhow!("no current committee"))?;

            let mut executors: Vec<SuiTxExecutor> = nodes
                .iter()
                .map(|node| {
                    let hashi = node.hashi();
                    SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())
                })
                .collect::<Result<_>>()?;
            let target = executors
                .last()
                .ok_or_else(|| anyhow!("no executors"))?
                .sender();
            assert!(committee.index_of(&target).is_some());

            info!(
                v1 = %hashi_ids.package_id,
                latest = %latest_package_id,
                "package ids in play"
            );
            let ignore_member_type_tag =
                sui_sdk_types::TypeTag::Struct(Box::new(sui_sdk_types::StructTag::new(
                    latest_package_id,
                    sui_sdk_types::Identifier::from_static("ignore_member"),
                    sui_sdk_types::Identifier::from_static("IgnoreMember"),
                    vec![],
                )));
            let hashi_isv = hashi::cli::client::fetch_initial_shared_version(
                &mut networks.sui_network.client.clone(),
                hashi_ids.hashi_object_id,
            )
            .await?;
            crate::submit_proposal_through_quorum(
                hashi_ids,
                hashi_isv,
                latest_package_id,
                &mut executors,
                hashi::cli::client::CreateProposalParams::IgnoreMember {
                    target_validator_address: target,
                    ignored: true,
                    metadata: vec![],
                },
                ignore_member_type_tag,
                "ignore_member",
                "IgnoreMember",
            )
            .await?;

            let initial_epoch = nodes[0]
                .current_epoch()
                .ok_or_else(|| anyhow!("no current Hashi epoch"))?;

            (
                latest_package_id,
                committee.members().len(),
                committee.total_weight(),
                target,
                initial_epoch,
            )
        };
        info!(
            ?target,
            latest_package_id = %latest_package_id,
            "ignore executed on-chain; closing the epoch"
        );

        networks.sui_network.force_close_epoch().await?;
        let target_epoch = initial_epoch + 1;
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

        // The new committee excludes the ignored member and total weight
        // re-sums without them.
        {
            let nodes = networks.hashi_network.nodes();
            let committee = nodes[0]
                .hashi()
                .onchain_state()
                .current_committee()
                .ok_or_else(|| anyhow!("no committee after epoch change"))?;
            assert_eq!(committee.members().len(), members_before - 1);
            assert!(committee.index_of(&target).is_none());
            assert!(committee.total_weight() < weight_before);
        }

        // The smaller committee still drives the full deposit and
        // withdrawal paths: BLS certs, MPC signing with the reshared key,
        // and the guardian's committee-handoff-derived thresholds.
        create_deposit_and_wait(&mut networks, 100_000).await?;
        crate::test_helpers::create_withdrawal_and_wait(&mut networks, 30_000).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_resignation_during_pending_reconfig_is_recorded() -> Result<()> {
        init_test_logging();

        let mut networks = setup_test_networks(TestNetworksBuilder::new().with_nodes(4)).await?;
        let hashi_ids = networks.hashi_network.ids();

        let (latest_package_id, hashi_isv) = {
            let nodes = networks.hashi_network.nodes();
            let latest_package_id = nodes[0]
                .hashi()
                .onchain_state()
                .package_id()
                .ok_or_else(|| anyhow!("no package versions known"))?;
            let hashi_isv = hashi::cli::client::fetch_initial_shared_version(
                &mut networks.sui_network.client.clone(),
                hashi_ids.hashi_object_id,
            )
            .await?;
            (latest_package_id, hashi_isv)
        };

        let target = {
            let nodes = networks.hashi_network.nodes();
            let mut executors: Vec<SuiTxExecutor> = nodes
                .iter()
                .map(|node| {
                    let hashi = node.hashi();
                    SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())
                })
                .collect::<Result<_>>()?;
            let target = executors
                .last()
                .ok_or_else(|| anyhow!("no executors"))?
                .sender();
            let ignore_member_type_tag =
                sui_sdk_types::TypeTag::Struct(Box::new(sui_sdk_types::StructTag::new(
                    latest_package_id,
                    sui_sdk_types::Identifier::from_static("ignore_member"),
                    sui_sdk_types::Identifier::from_static("IgnoreMember"),
                    vec![],
                )));
            crate::submit_proposal_through_quorum(
                hashi_ids,
                hashi_isv,
                latest_package_id,
                &mut executors,
                hashi::cli::client::CreateProposalParams::IgnoreMember {
                    target_validator_address: target,
                    ignored: true,
                    metadata: vec![],
                },
                ignore_member_type_tag,
                "ignore_member",
                "IgnoreMember",
            )
            .await?;
            target
        };
        info!(?target, "node 3 ignored; the next formation excludes it");

        let initial_epoch = networks.hashi_network.nodes()[0]
            .current_epoch()
            .ok_or_else(|| anyhow!("no current Hashi epoch"))?;
        let target_epoch = initial_epoch + 1;

        networks.sui_network.force_close_epoch().await?;
        {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
            loop {
                let pending = networks.hashi_network.nodes()[3]
                    .hashi()
                    .onchain_state()
                    .pending_epoch_change();
                if pending == Some(target_epoch) {
                    break;
                }
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "node 3 never observed the pending reconfig"
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        info!("reconfig pending on node 3; resigning mid-window");

        let marker = {
            let nodes = networks.hashi_network.nodes();
            let resigning = nodes[3].hashi().clone();
            let mut executor =
                SuiTxExecutor::from_config(&resigning.config, resigning.onchain_state())?;
            assert_eq!(executor.sender(), target);
            let mut b = sui_transaction_builder::TransactionBuilder::new();
            let hashi_arg = b.object(
                sui_transaction_builder::ObjectInput::new(hashi_ids.hashi_object_id)
                    .with_version(hashi_isv)
                    .as_shared()
                    .with_mutable(true),
            );
            let validator_arg = b.pure(&target);
            b.move_call(
                sui_transaction_builder::Function::new(
                    latest_package_id,
                    sui_sdk_types::Identifier::from_static("validator"),
                    sui_sdk_types::Identifier::from_static("resign"),
                ),
                vec![hashi_arg, validator_arg],
            );
            let resp = executor.execute(b).await?;
            anyhow::ensure!(
                resp.transaction().effects().status().success(),
                "resign transaction failed"
            );
            resigning
                .config
                .resignation_marker_path()
                .ok_or_else(|| anyhow!("node 3 has no db path"))?
        };

        {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
            loop {
                if marker.exists() {
                    break;
                }
                let still_pending = networks.hashi_network.nodes()[3]
                    .hashi()
                    .onchain_state()
                    .pending_epoch_change()
                    == Some(target_epoch);
                anyhow::ensure!(
                    still_pending,
                    "epoch flipped before the mid-window resignation was recorded (marker \
                     missing at {})",
                    marker.display()
                );
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "mid-window resignation never recorded while pending"
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        info!("marker written while pending; letting the rotation finish");

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
        let committee = networks.hashi_network.nodes()[0]
            .hashi()
            .onchain_state()
            .current_committee()
            .ok_or_else(|| anyhow!("no committee after the epoch change"))?;
        assert!(committee.index_of(&target).is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_resigned_member_excluded_then_removed_permissionlessly() -> Result<()> {
        init_test_logging();

        let mut networks = setup_test_networks(TestNetworksBuilder::new().with_nodes(4)).await?;

        let hashi_ids = networks.hashi_network.ids();

        let (latest_package_id, hashi_isv, target, initial_epoch) = {
            let nodes = networks.hashi_network.nodes();
            let latest_package_id = nodes[0]
                .hashi()
                .onchain_state()
                .package_id()
                .ok_or_else(|| anyhow!("no package versions known"))?;
            let hashi_isv = hashi::cli::client::fetch_initial_shared_version(
                &mut networks.sui_network.client.clone(),
                hashi_ids.hashi_object_id,
            )
            .await?;

            // Node 3 resigns through its own executor (validator::resign is
            // v2-only surface: latest package + resolved shared inputs).
            let resigning = nodes[3].hashi().clone();
            let mut executor =
                SuiTxExecutor::from_config(&resigning.config, resigning.onchain_state())?;
            let target = executor.sender();

            let mut b = sui_transaction_builder::TransactionBuilder::new();
            let hashi_arg = b.object(
                sui_transaction_builder::ObjectInput::new(hashi_ids.hashi_object_id)
                    .with_version(hashi_isv)
                    .as_shared()
                    .with_mutable(true),
            );
            let validator_arg = b.pure(&target);
            b.move_call(
                sui_transaction_builder::Function::new(
                    latest_package_id,
                    sui_sdk_types::Identifier::from_static("validator"),
                    sui_sdk_types::Identifier::from_static("resign"),
                ),
                vec![hashi_arg, validator_arg],
            );
            let resp = executor.execute(b).await?;
            anyhow::ensure!(
                resp.transaction().effects().status().success(),
                "resign transaction failed"
            );

            let initial_epoch = nodes[0]
                .current_epoch()
                .ok_or_else(|| anyhow!("no current Hashi epoch"))?;
            (latest_package_id, hashi_isv, target, initial_epoch)
        };
        info!(?target, "resignation submitted; closing the epoch");

        // First boundary: formation skips the resigned member; the
        // registration survives the transition untouched.
        networks.sui_network.force_close_epoch().await?;
        let target_epoch = initial_epoch + 1;
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
        info!("all nodes reached the first boundary");

        {
            let nodes = networks.hashi_network.nodes();
            let committee = nodes[0]
                .hashi()
                .onchain_state()
                .current_committee()
                .ok_or_else(|| anyhow!("no committee after epoch change"))?;
            assert_eq!(committee.members().len(), 3);
            assert!(committee.index_of(&target).is_none());
            let member = nodes[0]
                .hashi()
                .onchain_state()
                .committee_member(&target)
                .expect("the transition must not remove the registration");
            assert!(
                member.resigned,
                "resignation flag must survive the boundary"
            );
        }

        info!("boundary assertions done; submitting permissionless removal");

        // The registration is now duty-free: remove it through the
        // permissionless entry, submitted by a DIFFERENT node's executor.
        // Under CI load the executor's short checkpoint wait can time out on
        // a transaction that still lands, so treat "mirror shows the member
        // gone" as the success condition and retry the submission otherwise.
        {
            let nodes = networks.hashi_network.nodes();
            let remover = nodes[0].hashi().clone();
            let mut executor =
                SuiTxExecutor::from_config(&remover.config, remover.onchain_state())?;

            let deadline = std::time::Instant::now() + Duration::from_secs(120);
            loop {
                let mut b = sui_transaction_builder::TransactionBuilder::new();
                let hashi_arg = b.object(
                    sui_transaction_builder::ObjectInput::new(hashi_ids.hashi_object_id)
                        .with_version(hashi_isv)
                        .as_shared()
                        .with_mutable(true),
                );
                // Genesis-created system object: initial shared version 1.
                let sui_system_arg = b.object(
                    sui_transaction_builder::ObjectInput::new(sui_sdk_types::Address::from_static(
                        "0x5",
                    ))
                    .with_version(1)
                    .as_shared()
                    .with_mutable(false),
                );
                let validator_arg = b.pure(&target);
                b.move_call(
                    sui_transaction_builder::Function::new(
                        latest_package_id,
                        sui_sdk_types::Identifier::from_static("validator"),
                        sui_sdk_types::Identifier::from_static("remove_inactive_member"),
                    ),
                    vec![hashi_arg, sui_system_arg, validator_arg],
                );
                match executor.execute(b).await {
                    Ok(resp) => {
                        anyhow::ensure!(
                            resp.transaction().effects().status().success(),
                            "remove_inactive_member transaction failed"
                        );
                        break;
                    }
                    Err(e) => {
                        // A checkpoint-wait timeout can hide a landed tx; the
                        // mirror is the source of truth.
                        let gone = nodes[0]
                            .hashi()
                            .onchain_state()
                            .committee_member(&target)
                            .is_none();
                        if gone {
                            info!("removal landed despite executor error: {e:#}");
                            break;
                        }
                        anyhow::ensure!(
                            std::time::Instant::now() < deadline,
                            "remove_inactive_member kept failing: {e:#}"
                        );
                        info!("removal submit failed ({e:#}); retrying");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        }
        info!("removal submitted; waiting for the mirror to observe it");

        // Wait for the mirror to observe the removal.
        {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            loop {
                let gone = networks.hashi_network.nodes()[0]
                    .hashi()
                    .onchain_state()
                    .committee_member(&target)
                    .is_none();
                if gone {
                    break;
                }
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "mirror never observed the registration removal"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        info!("registration removed; closing the second epoch");

        // Second boundary with the ex-member's node STILL RUNNING: the
        // resignation latch must keep it from auto-re-registering on the
        // epoch trigger.
        networks.sui_network.force_close_epoch().await?;
        let second_epoch = target_epoch + 1;
        let futs: Vec<_> = networks
            .hashi_network()
            .nodes()
            .iter()
            .take(3)
            .map(|n| n.wait_for_epoch(second_epoch, Duration::from_secs(480)))
            .collect();
        for (i, r) in futures::future::join_all(futs)
            .await
            .into_iter()
            .enumerate()
        {
            r.unwrap_or_else(|e| panic!("Node {i} failed to reach epoch {second_epoch}: {e}"));
        }

        {
            let nodes = networks.hashi_network.nodes();
            assert!(
                nodes[0]
                    .hashi()
                    .onchain_state()
                    .committee_member(&target)
                    .is_none(),
                "latched node must not re-register across epoch boundaries"
            );
            let committee = nodes[0]
                .hashi()
                .onchain_state()
                .current_committee()
                .ok_or_else(|| anyhow!("no committee after second epoch change"))?;
            assert!(committee.index_of(&target).is_none());
        }
        networks.hashi_network.nodes_mut()[3].restart().await?;
        {
            let nodes = networks.hashi_network.nodes();
            nodes[3]
                .wait_for_epoch(second_epoch, Duration::from_secs(120))
                .await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert!(
                nodes[0]
                    .hashi()
                    .onchain_state()
                    .committee_member(&target)
                    .is_none(),
                "a restarted resigned node must not re-register from its boot path"
            );
        }

        // Explicit re-registration re-admits the member (and clears the
        // node's latch once the mirror shows it registered and unflagged).
        {
            let nodes = networks.hashi_network.nodes();
            let rejoining = nodes[3].hashi().clone();
            let mut executor =
                SuiTxExecutor::from_config(&rejoining.config, rejoining.onchain_state())?;
            let mut b = sui_transaction_builder::TransactionBuilder::new();
            let hashi_arg = b.object(
                sui_transaction_builder::ObjectInput::new(hashi_ids.hashi_object_id)
                    .with_version(hashi_isv)
                    .as_shared()
                    .with_mutable(true),
            );
            let sui_system_arg = b.object(
                sui_transaction_builder::ObjectInput::new(Address::from_static("0x5"))
                    .with_version(1)
                    .as_shared()
                    .with_mutable(false),
            );
            b.move_call(
                sui_transaction_builder::Function::new(
                    latest_package_id,
                    sui_sdk_types::Identifier::from_static("validator"),
                    sui_sdk_types::Identifier::from_static("register"),
                ),
                vec![hashi_arg, sui_system_arg],
            );
            let resp = executor.execute(b).await?;
            anyhow::ensure!(
                resp.transaction().effects().status().success(),
                "re-registration failed"
            );
        }

        // The mirror on another node sees the fresh registration.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let registered = networks.hashi_network.nodes()[0]
                .hashi()
                .onchain_state()
                .committee_member(&target)
                .is_some();
            if registered {
                break;
            }
            if std::time::Instant::now() > deadline {
                anyhow::bail!("re-registration not observed by the mirror");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Ok(())
    }

    /// Waits for a `WithdrawalPickedForProcessing` that contains at least
    /// `min_requests` request IDs in a single batch, indicating that the new
    /// multi-request coin selection algorithm batched them together.
    async fn wait_for_batched_withdrawal_picked(
        sui_client: &mut sui_rpc::Client,
        min_requests: usize,
        timeout: Duration,
    ) -> Result<WithdrawalPickedForProcessing> {
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
                    "Timeout waiting for batched WithdrawalPickedForProcessing \
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
                        .contains("WithdrawalPickedForProcessing")
                    {
                        match WithdrawalPickedForProcessing::from_bcs(event.contents().value()) {
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
                                    "WithdrawalPickedForProcessing with {} request(s) \
                                     (waiting for batch of ≥{})",
                                    data.request_ids.len(),
                                    min_requests,
                                );
                            }
                            Err(e) => {
                                debug!("Failed to parse WithdrawalPickedForProcessing: {}", e);
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(anyhow!("Checkpoint subscription ended unexpectedly"))
    }

    async fn wait_for_event_with_effects<T>(
        sui_client: &mut sui_rpc::Client,
        event_name: &'static str,
        timeout: Duration,
        mut parse: impl FnMut(&[u8]) -> Result<Option<T>>,
    ) -> Result<EventWithEffects<T>> {
        let start = std::time::Instant::now();
        let subscription_read_mask = FieldMask::from_paths([
            Checkpoint::path_builder()
                .transactions()
                .events()
                .events()
                .contents()
                .finish(),
            Checkpoint::path_builder()
                .transactions()
                .transaction()
                .bcs()
                .value(),
            Checkpoint::path_builder()
                .transactions()
                .effects()
                .bcs()
                .value(),
            Checkpoint::path_builder()
                .transactions()
                .effects()
                .changed_objects()
                .object_id(),
            Checkpoint::path_builder()
                .transactions()
                .effects()
                .unchanged_loaded_runtime_objects()
                .object_id(),
        ]);
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
                    "Timeout waiting for {event_name} with effects after {:?}",
                    timeout,
                ));
            }
            let checkpoint = match item {
                Ok(checkpoint) => checkpoint,
                Err(e) => {
                    return Err(anyhow!(
                        "Checkpoint stream failed while waiting for {event_name}: {e}"
                    ));
                }
            };
            for txn in checkpoint.checkpoint().transactions() {
                for event in txn.events().events() {
                    if event.contents().name().contains(event_name) {
                        match parse(event.contents().value()) {
                            Ok(Some(data)) => {
                                return Ok(EventWithEffects {
                                    event: data,
                                    tx_size_bytes: tx_bcs_size(txn)?,
                                    effects_size_bytes: effects_bcs_size(txn)?,
                                    changed_objects: txn.effects().changed_objects().len(),
                                    unchanged_loaded_runtime_objects: txn
                                        .effects()
                                        .unchanged_loaded_runtime_objects()
                                        .len(),
                                });
                            }
                            Ok(None) => {}
                            Err(e) => debug!("Failed to parse {event_name}: {}", e),
                        }
                    }
                }
            }
        }
        Err(anyhow!("Checkpoint subscription ended unexpectedly"))
    }

    async fn wait_for_batched_withdrawal_picked_with_effects(
        sui_client: &mut sui_rpc::Client,
        min_requests: usize,
        timeout: Duration,
    ) -> Result<EventWithEffects<WithdrawalPickedForProcessing>> {
        wait_for_event_with_effects(
            sui_client,
            "WithdrawalPickedForProcessing",
            timeout,
            |bytes| {
                let data = WithdrawalPickedForProcessing::from_bcs(bytes)?;
                if data.request_ids.len() >= min_requests {
                    Ok(Some(data))
                } else {
                    info!(
                        "WithdrawalPickedForProcessing with {} request(s) \
                         (waiting for batch of ≥{})",
                        data.request_ids.len(),
                        min_requests,
                    );
                    Ok(None)
                }
            },
        )
        .await
    }

    async fn wait_for_withdrawal_signed_with_effects(
        sui_client: &mut sui_rpc::Client,
        withdrawal_id: Address,
        timeout: Duration,
    ) -> Result<EventWithEffects<WithdrawalSigned>> {
        wait_for_event_with_effects(sui_client, "WithdrawalSigned", timeout, |bytes| {
            let data = WithdrawalSigned::from_bcs(bytes)?;
            Ok((data.withdrawal_txn_id == withdrawal_id).then_some(data))
        })
        .await
    }

    async fn wait_for_withdrawal_confirmed_with_effects(
        sui_client: &mut sui_rpc::Client,
        withdrawal_id: Address,
        timeout: Duration,
    ) -> Result<EventWithEffects<WithdrawalConfirmed>> {
        wait_for_event_with_effects(sui_client, "WithdrawalConfirmed", timeout, |bytes| {
            let data = WithdrawalConfirmed::from_bcs(bytes)?;
            Ok((data.withdrawal_txn_id == withdrawal_id).then_some(data))
        })
        .await
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
    /// 3. Wait for a `WithdrawalPickedForProcessing` whose `request_ids`
    ///    has length ≥ 2, confirming the batch.
    /// 4. Assert the Bitcoin tx has two withdrawal outputs (one per request).
    /// 5. Mine blocks and wait for the single `WithdrawalConfirmed`.
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
            .with_signer(user_key.clone().into());

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

        // Wait for a single WithdrawalPickedForProcessing that batches both
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

        // The confirm left the batched txn (and both requests) in the hot
        // bags; the leader's deferred-archival GC must drain them from every
        // node's mirror. This pins the deferred-archival GC end-to-end for
        // the batched (multi-request) shape.
        wait_for_withdrawal_archival(&networks, Duration::from_secs(60)).await?;

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
    ///    expires, producing a single `WithdrawalPickedForProcessing` with
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
            .with_signer(user_key.clone().into());

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

        // Calls route through the chain's LATEST package: the default boot
        // upgrades to the current source and disables v1, so a call built
        // against the original id aborts at `versioning::assert_version_enabled`.
        let execute_package_id = hashi
            .onchain_state()
            .package_id()
            .unwrap_or(hashi_ids.package_id);

        let validator_address = executor.sender();
        let hashi_isv = hashi::cli::client::fetch_initial_shared_version(
            &mut networks.sui_network.client.clone(),
            hashi_ids.hashi_object_id,
        )
        .await?;
        let builder = build_create_proposal_transaction(
            hashi_ids,
            hashi_isv,
            execute_package_id,
            validator_address,
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

    /// Kill-and-reconnect: sever one node's Sui RPC connection, land
    /// Hashi transactions during the outage, and verify the watcher's
    /// replay path — not a re-bootstrap from a fresh scrape — recovers
    /// them once the connection returns.
    ///
    /// The outage transactions are inert update-config proposals:
    /// created but never voted on, each touches the Hashi root (so the
    /// filtered stream must deliver it) and lands in the active
    /// proposals bag where the recovered mirror must show it.
    #[tokio::test]
    async fn test_watcher_replay_recovers_outage_transactions() -> Result<()> {
        use hashi::cli::client::CreateProposalParams;
        use hashi::cli::client::build_create_proposal_transaction;
        use hashi::cli::upgrade::extract_proposal_id_from_response;

        init_test_logging();
        info!("=== Starting Watcher Kill-and-Reconnect Replay Test ===");

        const PROXIED_NODE: usize = 3;
        let networks = TestNetworksBuilder::new()
            .with_nodes(4)
            .with_sui_rpc_proxy_for_node(PROXIED_NODE)
            .build()
            .await?;
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(60))
            .await?;

        let proxied = networks.hashi_network.nodes()[PROXIED_NODE].hashi().clone();
        let proxy = networks
            .hashi_network
            .sui_rpc_proxy()
            .expect("proxy configured via the builder");
        assert_eq!(proxied.metrics.watcher_rebootstrap_total.get(), 0);

        info!("Severing node {PROXIED_NODE}'s Sui RPC connection...");
        proxy.sever();

        // Land the proposals through a healthy node's connection.
        let healthy = networks.hashi_network.nodes()[0].hashi().clone();
        let hashi_ids = networks.hashi_network.ids();
        let mut executor = SuiTxExecutor::from_config(&healthy.config, healthy.onchain_state())?;
        let creator = executor.sender();
        // Calls route through the chain's LATEST package: the default boot
        // disables v1, so the original id would abort at
        // `versioning::assert_version_enabled`.
        let execute_package_id = healthy
            .onchain_state()
            .package_id()
            .unwrap_or(hashi_ids.package_id);
        let hashi_isv = hashi::cli::client::fetch_initial_shared_version(
            &mut networks.sui_network.client.clone(),
            hashi_ids.hashi_object_id,
        )
        .await?;
        let mut proposal_ids = Vec::new();
        let mut last_checkpoint = 0u64;
        for i in 0..3u64 {
            let builder = build_create_proposal_transaction(
                hashi_ids,
                hashi_isv,
                execute_package_id,
                creator,
                CreateProposalParams::UpdateConfig {
                    // Never voted on or executed, so the values are inert.
                    key: "bitcoin_deposit_time_delay_ms".to_string(),
                    value: hashi_types::move_types::ConfigValue::U64(i),
                    metadata: vec![],
                },
            );
            let response = executor.execute(builder).await?;
            assert!(
                response.transaction().effects().status().success(),
                "update_config::propose transaction failed: {:?}",
                response.transaction().effects().status()
            );
            proposal_ids.push(extract_proposal_id_from_response(&response)?);
            last_checkpoint = response
                .transaction()
                .checkpoint_opt()
                .ok_or_else(|| anyhow!("propose response missing checkpoint"))?;
        }
        info!(
            "Landed {} proposals during the outage; last at checkpoint {last_checkpoint}",
            proposal_ids.len()
        );

        // Positive control: the outage must have been real.
        let severed_watermark = proxied.onchain_state().state_watermark();
        assert!(
            severed_watermark.is_none_or(|covered| covered < last_checkpoint),
            "the severed node's watermark ({severed_watermark:?}) covers the outage \
             transactions (checkpoint {last_checkpoint}); the outage was not effective"
        );
        {
            let state = proxied.onchain_state().state();
            let active = state.hashi().proposals.active();
            for id in &proposal_ids {
                assert!(
                    !active.contains_key(id),
                    "the severed node saw proposal {id} during the outage"
                );
            }
        }

        info!("Restoring the connection...");
        proxy.restore();

        // The watcher reconnects and replays the gap; the state watermark
        // passing the last landed checkpoint proves coverage, and the
        // replay applies transactions before claiming it.
        tokio::time::timeout(
            Duration::from_secs(60),
            proxied
                .onchain_state()
                .wait_until_checkpoint(last_checkpoint),
        )
        .await
        .map_err(|_| anyhow!("timed out waiting for the severed node to catch up via replay"))?;

        {
            let state = proxied.onchain_state().state();
            let active = state.hashi().proposals.active();
            for id in &proposal_ids {
                assert!(
                    active.contains_key(id),
                    "proposal {id} landed during the outage was not recovered by replay"
                );
            }
        }

        // The recovery must have come from the replay path, not the
        // fresh-scrape fallback.
        assert_eq!(
            proxied.metrics.watcher_rebootstrap_total.get(),
            0,
            "the mirror re-bootstrapped from a scrape instead of replaying the gap"
        );
        assert_no_unrouted_objects(&networks);

        info!("=== Watcher Kill-and-Reconnect Replay Test Passed ===");
        Ok(())
    }

    /// The leader's TOB cert GC prunes nonce buckets once the current
    /// epoch is two past theirs, while key-generation buckets ride out
    /// their longer retention floor: run genesis DKG, wait for the
    /// presig refill to write genesis-epoch nonce buckets, advance the
    /// Hashi epoch twice (two forced Sui epoch closes, each completing
    /// a rotation), and verify the expired nonce buckets disappear from
    /// every node's mirror and from the chain — with the genesis DKG
    /// bucket retained, the survivors still in parity, and nothing
    /// unrouted.
    #[tokio::test]
    async fn test_leader_destroys_expired_tob_cert_buckets() -> Result<()> {
        init_test_logging();
        info!("=== Starting TOB Cert GC E2E Test ===");

        let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;
        for node in networks.hashi_network.nodes() {
            node.wait_for_mpc_key(Duration::from_secs(120)).await?;
        }

        let state = networks.hashi_network.nodes()[0]
            .hashi()
            .onchain_state()
            .clone();
        let genesis_epoch = state.epoch();
        assert!(
            state.tob_bucket_keys().iter().any(
                |(key, _)| key.epoch == genesis_epoch && key.protocol_type == ProtocolType::Dkg
            ),
            "expected a genesis DKG bucket after DKG"
        );

        // The presig refill writes the nonce buckets the GC will prune;
        // wait for the first ones rather than racing the refill loop.
        info!("Waiting for genesis-epoch nonce buckets from the presig refill...");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        let genesis_nonce_batches: Vec<u32> = loop {
            let batches: Vec<u32> = state
                .tob_bucket_keys()
                .into_iter()
                .filter_map(|(key, _)| {
                    (key.epoch == genesis_epoch
                        && key.protocol_type == ProtocolType::NonceGeneration)
                        .then_some(key.batch_index)
                        .flatten()
                })
                .collect();
            if !batches.is_empty() {
                break batches;
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("no genesis-epoch nonce bucket appeared in the mirror");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        info!("Genesis nonce batches present: {genesis_nonce_batches:?}");

        // Two epoch advances put the genesis nonce buckets past the
        // Move floor (`current_epoch >= epoch + 2`); the key-generation
        // retention floor is longer, so the DKG bucket must survive.
        for step in 1..=2u64 {
            info!("Forcing Sui epoch close {step}/2...");
            networks.sui_network.force_close_epoch().await?;
            let target = genesis_epoch + step;
            for node in networks.hashi_network.nodes() {
                node.wait_for_epoch(target, Duration::from_secs(180))
                    .await?;
            }
            info!("All nodes rotated into epoch {target}");
        }

        // The leader GC runs on its checkpoint tick; wait until every
        // node's mirror shows no expired nonce bucket left.
        info!("Waiting for the leader to prune the expired nonce buckets...");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        'wait: loop {
            let current = state.epoch();
            let laggard =
                networks
                    .hashi_network
                    .nodes()
                    .iter()
                    .enumerate()
                    .find_map(|(index, node)| {
                        let expired: Vec<_> = node
                            .hashi()
                            .onchain_state()
                            .tob_bucket_keys()
                            .into_iter()
                            .filter(|(key, _)| {
                                key.protocol_type == ProtocolType::NonceGeneration
                                    && current >= key.epoch.saturating_add(2)
                            })
                            .collect();
                        (!expired.is_empty()).then_some((index, expired))
                    });
            let Some((index, expired)) = laggard else {
                break 'wait;
            };
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "node {index}'s mirror still holds expired nonce buckets: {expired:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        info!("Expired nonce buckets are gone from every node's mirror");

        // Chain truth: the genesis nonce buckets must be gone on-chain
        // too, not just from the mirrors — and the genesis DKG bucket
        // must still exist, held by the key-generation retention floor.
        for batch_index in genesis_nonce_batches {
            let onchain = fetch_tob_certs_from_chain(
                &networks,
                hashi_types::move_types::TobKey {
                    epoch: genesis_epoch,
                    batch_index: Some(batch_index),
                    protocol_type: ProtocolType::NonceGeneration,
                },
            )
            .await?;
            assert!(
                onchain.is_none(),
                "genesis nonce bucket (batch {batch_index}) still exists on-chain"
            );
        }
        let dkg_bucket = fetch_tob_certs_from_chain(
            &networks,
            hashi_types::move_types::TobKey {
                epoch: genesis_epoch,
                batch_index: None,
                protocol_type: ProtocolType::Dkg,
            },
        )
        .await?;
        assert!(
            dkg_bucket.is_some(),
            "the genesis DKG bucket was pruned below its retention floor"
        );

        // The destroy deletions routed cleanly, and the surviving
        // buckets still match the chain.
        assert_no_unrouted_objects(&networks);
        assert_tob_mirror_parity(&networks).await?;

        info!("=== TOB Cert GC E2E Test Passed ===");
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
        use hashi::onchain::types::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;

        let hashi = networks.hashi_network.nodes()[0].hashi();
        let weight_reduction_allowed_delta =
            hashi.onchain_state().mpc_weight_reduction_allowed_delta();
        let max_faulty_bps = hashi.onchain_state().mpc_max_faulty_in_basis_points();

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
        let networks = TestNetworksBuilder::new().with_nodes(4).build().await?;
        varying_t_and_allowed_delta_flow(networks).await
    }

    #[tokio::test]
    async fn test_avid_varying_t_and_allowed_delta_across_epochs() -> Result<()> {
        init_test_logging();
        let networks = avid_override(TestNetworksBuilder::new().with_nodes(4))
            .build()
            .await?;
        varying_t_and_allowed_delta_flow(networks).await
    }

    async fn varying_t_and_allowed_delta_flow(mut networks: TestNetworks) -> Result<()> {
        use hashi::onchain::types::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
        use hashi::onchain::types::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;

        // Governance-added keys the Move package knows nothing about.
        const EPOCH_KNOB: &str = "e2e_epoch_knob";
        const EPOCH_KNOB_VALUE: u64 = 7;
        const INSTANT_KNOB: &str = "e2e_instant_knob";
        const INSTANT_KNOB_VALUE: u64 = 9;

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
            epoch1_committee.mpc_weight_reduction_allowed_delta(),
            DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA
        );
        assert_eq!(
            epoch1_committee.mpc_max_faulty_in_basis_points(),
            DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS
        );

        // Change config between epochs.
        let new_delta: u64 = 1200;
        let new_max_faulty: u64 = 2000;
        crate::apply_onchain_config_overrides(
            &mut networks,
            &[
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

        // Add one key to each store. The epoch key rides the verbatim copy
        // into the next committee; the instant key applies at once and never
        // reaches a committee.
        {
            use hashi::cli::client::CreateProposalParams;
            use hashi::sui_tx_executor::SuiTxExecutor;
            use hashi_types::move_types::ConfigValue;

            let nodes = networks.hashi_network.nodes();
            let hashi_ids = networks.hashi_network.ids();
            let latest_package_id = nodes[0]
                .hashi()
                .onchain_state()
                .package_id()
                .unwrap_or(hashi_ids.package_id);
            let hashi_isv = hashi::cli::client::fetch_initial_shared_version(
                &mut networks.sui_network.client.clone(),
                hashi_ids.hashi_object_id,
            )
            .await?;
            let mut executors: Vec<SuiTxExecutor> = nodes
                .iter()
                .map(|node| {
                    let hashi = node.hashi();
                    SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())
                })
                .collect::<Result<_>>()?;
            let add_config_type_tag = hashi::cli::client::get_proposal_type_arg(
                latest_package_id,
                &hashi::onchain::types::ProposalType::AddConfig,
            )?;
            for (epoch, key, value) in [
                (true, EPOCH_KNOB, EPOCH_KNOB_VALUE),
                (false, INSTANT_KNOB, INSTANT_KNOB_VALUE),
            ] {
                crate::submit_proposal_through_quorum(
                    hashi_ids,
                    hashi_isv,
                    latest_package_id,
                    &mut executors,
                    CreateProposalParams::AddConfig {
                        epoch,
                        key: key.to_string(),
                        value: ConfigValue::U64(value),
                        metadata: vec![],
                    },
                    add_config_type_tag.clone(),
                    "add_config",
                    &format!("AddConfig({key})"),
                )
                .await?;
            }
        }

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
            epoch2.mpc_weight_reduction_allowed_delta(),
            new_delta as u16,
            "epoch {target_epoch} committee should have updated allowed_delta"
        );
        assert_eq!(
            epoch2.mpc_max_faulty_in_basis_points(),
            new_max_faulty as u16,
            "epoch {target_epoch} committee should have updated max_faulty_basis_points"
        );

        // The governance-added keys landed in exactly their stores.
        assert_eq!(
            epoch2.config().get_u64(EPOCH_KNOB, 0),
            EPOCH_KNOB_VALUE,
            "epoch {target_epoch} committee should carry the governance-added epoch key"
        );
        assert_eq!(
            epoch1.config().get_u64(EPOCH_KNOB, 0),
            0,
            "epoch {initial_epoch} committee predates the epoch key and must not carry it"
        );
        assert!(
            !epoch2
                .config()
                .entries()
                .iter()
                .any(|(key, _)| key == INSTANT_KNOB),
            "instant keys never reach a committee"
        );
        let (instant, governed_epoch) = {
            let s = state.state();
            (
                s.hashi().config.config.get(INSTANT_KNOB).cloned(),
                s.hashi().epoch_config.get_u64(EPOCH_KNOB, 0),
            )
        };
        assert_eq!(
            instant,
            Some(hashi_types::move_types::ConfigValue::U64(
                INSTANT_KNOB_VALUE
            )),
            "instant key should be readable from the Hashi object right away"
        );
        assert_eq!(governed_epoch, EPOCH_KNOB_VALUE);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_rotation_reconstruction_with_threshold_decrease() -> Result<()> {
        init_test_logging();

        let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

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
        let mut epoch = nodes[0].current_epoch().unwrap();
        crate::apply_onchain_config_overrides(
            &mut networks,
            &[(
                "mpc_max_faulty_in_basis_points".into(),
                hashi_types::move_types::ConfigValue::U64(3000),
            )],
        )
        .await?;
        epoch += 1;
        networks.sui_network.force_close_epoch().await?;
        {
            let futs: Vec<_> = networks
                .hashi_network()
                .nodes()
                .iter()
                .map(|n| n.wait_for_epoch(epoch, Duration::from_secs(480)))
                .collect();
            for (i, r) in futures::future::join_all(futs)
                .await
                .into_iter()
                .enumerate()
            {
                r.unwrap_or_else(|e| panic!("Node {i} failed to reach epoch {epoch}: {e}"));
            }
        }
        let pk_before = networks.hashi_network().nodes()[0]
            .hashi()
            .mpc_handle()
            .unwrap()
            .public_key()
            .unwrap();

        let raised_max_faulty_bps: u64 = 3333;
        let low_delta: u64 = 800;
        crate::apply_onchain_config_overrides(
            &mut networks,
            &[
                (
                    "mpc_max_faulty_in_basis_points".into(),
                    hashi_types::move_types::ConfigValue::U64(raised_max_faulty_bps),
                ),
                (
                    "mpc_weight_reduction_allowed_delta".into(),
                    hashi_types::move_types::ConfigValue::U64(low_delta),
                ),
            ],
        )
        .await?;

        let initial_epoch = epoch;
        for offset in 1..=2 {
            let target = initial_epoch + offset;
            networks.sui_network.force_close_epoch().await?;
            let futs: Vec<_> = networks
                .hashi_network()
                .nodes()
                .iter()
                .map(|n| n.wait_for_epoch(target, Duration::from_secs(480)))
                .collect();
            for (i, r) in futures::future::join_all(futs)
                .await
                .into_iter()
                .enumerate()
            {
                r.unwrap_or_else(|e| panic!("Node {i} failed to reach epoch {target}: {e}"));
            }
        }

        let nodes = networks.hashi_network().nodes();
        let pk_after = nodes[0].hashi().mpc_handle().unwrap().public_key().unwrap();
        assert_eq!(
            pk_before, pk_after,
            "MPC public key changed across rotations — \
             rotation reconstruction recovered a wrong master vk"
        );
        for (i, node) in nodes.iter().enumerate().skip(1) {
            let pk = node.hashi().mpc_handle().unwrap().public_key().unwrap();
            assert_eq!(
                pk, pk_after,
                "Node {i} MPC key differs from node 0 after rotations"
            );
        }

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
            .with_signer(user_key.clone().into());

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
            has_change = %(!picked1.change_outputs.is_empty()),
            "Withdrawal 1 picked"
        );
        assert!(
            !picked1.change_outputs.is_empty(),
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
            .with_signer(user_key.clone().into());

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
            has_change = %(!picked_a.change_outputs.is_empty()),
            "Withdrawal A picked"
        );
        assert!(
            !picked_a.change_outputs.is_empty(),
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
            has_change = %(!picked_b.change_outputs.is_empty()),
            "Withdrawal B picked"
        );
        assert!(
            !picked_b.change_outputs.is_empty(),
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

    /// Stress-test withdrawal at the production default batch size (40
    /// requests / 400 inputs). Verifies that commit, sign, confirm, and
    /// cleanup all stay within Sui's runtime-object and effects-size limits.
    ///
    /// The 400 input signatures exceed Sui's 16 KiB pure-argument limit, so
    /// this also exercises chunked signature commits at the production cap.
    ///
    /// Test outline:
    /// 1. Create 400 deposits (one UTXO each).
    /// 2. Submit 40 withdrawal requests; consolidation fills the
    ///    400-input cap.
    /// 3. Assert commit, sign, and confirm transactions are under all Sui
    ///    limits (tx size, effects size, runtime objects).
    /// 4. Mine blocks and wait for confirmation.
    /// 5. Run `cleanup_spent_utxos` and verify it succeeds.
    #[tokio::test]
    async fn test_large_withdrawal_signature_chunking() -> Result<()> {
        init_test_logging();
        info!("=== Starting Large Withdrawal Stress Test ===");

        let num_withdrawals: usize = 40;
        let num_deposits: usize = 400;

        // 24-hour batching delay: the batch fires only at capacity (40), not
        // on a timer. This ensures all 40 requests end up in one Bitcoin tx.
        // With 4 nodes at weight 25 each (total_weight=100), the presig pool
        // is batch_size_per_weight * total_weight. We need enough
        // presignatures for 400 inputs.
        let mut networks = avid_override(
            TestNetworksBuilder::new()
                .with_nodes(4)
                .with_withdrawal_max_batch_size(num_withdrawals)
                .with_withdrawal_batching_delay_ms(86_400_000)
                .with_batch_size_per_weight(100),
        )
        .build()
        .await?;
        rotate_into_avid(&mut networks).await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let hbtc_recipient = user_key.public_key().derive_address();

        let deposit_address = hashi.get_deposit_address(Some(&hbtc_recipient))?;

        // --- Create 400 Bitcoin deposits ---
        // Each deposit is 40,000 sats (above the 30,000 on-chain minimum),
        // totalling 16,000,000 sats. The withdrawals request
        // 40 x 200,001 = 8,000,040 sats, requiring 201 UTXOs for value.
        // Moderate-fee consolidation can add up to 200 more inputs, so it
        // pulls in the remaining 199 UTXOs and reaches the 400-input cap.
        let deposit_amount_sats = 40_000u64;
        // With 400 inputs and 64-byte Schnorr signatures, the BCS-encoded
        // signatures vector is ~26 KiB -- well above the 16 KiB per-pure-arg
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
            .with_signer(user_key.clone().into());

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

        // Poll the on-chain deposit queue until all deposits are confirmed
        // and visible in the UTXO pool. The stress measurement below assumes
        // coin selection has all UTXOs available.
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
            let state = hashi.onchain_state();
            let remaining = state.deposit_requests().len();
            let active_utxos = state.active_utxos().len();
            if remaining == 0 && active_utxos >= num_deposits {
                break;
            }
            let confirmed = num_deposits - remaining;
            if confirmed / 40 > last_logged / 40 {
                info!(
                    active_utxos,
                    "Deposit confirmations: {}/{}", confirmed, num_deposits
                );
                last_logged = confirmed;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        info!("All deposits confirmed");
        drop(_deposit_miner);

        // --- Submit 40 withdrawal requests ---
        let withdrawal_amount_sats = 200_001u64;
        info!(
            "Submitting {} withdrawal requests of {} sats each...",
            num_withdrawals, withdrawal_amount_sats
        );

        // Submit all but the last request first. With a 24-hour delay and max
        // batch size, the leader cannot pick the batch yet, which lets this
        // test subscribe for the picked event before the final request makes
        // the batch full.
        for i in 0..(num_withdrawals - 1) {
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

        // Wait for the batched withdrawal to be picked for processing. The
        // 24-hour delay means it fires only at the configured capacity.
        info!("Waiting for batched withdrawal to be picked...");
        let mut picked_client = networks.sui_network.client.clone();
        let picked_task = tokio::spawn(async move {
            wait_for_batched_withdrawal_picked_with_effects(
                &mut picked_client,
                num_withdrawals,
                Duration::from_secs(300),
            )
            .await
        });

        let btc_destination = networks.bitcoin_node.get_new_address()?;
        let destination_bytes = extract_witness_program(&btc_destination)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes)
            .await?;
        info!(
            "  Withdrawal requests submitted: {}/{}",
            num_withdrawals, num_withdrawals
        );
        info!("All withdrawal requests submitted");

        let picked_with_effects = picked_task.await??;
        assert_tx_size_under_sui_limit("commit_withdrawal_tx", picked_with_effects.tx_size_bytes);
        assert_effects_size_under_sui_limit(
            "commit_withdrawal_tx",
            picked_with_effects.effects_size_bytes,
        );
        assert_changed_objects_under_sui_limit(
            "commit_withdrawal_tx",
            picked_with_effects.changed_objects,
        );
        assert_runtime_object_count_under_sui_limit(
            "commit_withdrawal_tx",
            picked_with_effects.changed_objects,
            picked_with_effects.unchanged_loaded_runtime_objects,
        );
        let commit_runtime_objects = runtime_object_count(&picked_with_effects);
        let picked = picked_with_effects.event;

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

        // With 400 UTXOs at 40,000 sats and 8,000,040 sats of withdrawals,
        // coin selection should pick most UTXOs for value and consolidate the
        // rest. Verify that enough inputs were selected to exceed the old
        // 16 KiB per-pure-arg limit (~252 signatures at 65 BCS bytes each).
        assert!(
            picked.inputs.len() > 252,
            "Expected more than 252 inputs to exercise signature chunking, \
             but only got {}",
            picked.inputs.len(),
        );

        let signed_with_effects = wait_for_withdrawal_signed_with_effects(
            &mut networks.sui_network.client,
            picked.withdrawal_txn_id,
            Duration::from_secs(300),
        )
        .await?;
        assert_eq!(
            signed_with_effects.event.signatures.len(),
            picked.inputs.len(),
            "Expected one signature per selected input"
        );
        assert_effects_size_under_sui_limit(
            "sign_withdrawal",
            signed_with_effects.effects_size_bytes,
        );
        assert_changed_objects_under_sui_limit(
            "sign_withdrawal",
            signed_with_effects.changed_objects,
        );
        assert_runtime_object_count_under_sui_limit(
            "sign_withdrawal",
            signed_with_effects.changed_objects,
            signed_with_effects.unchanged_loaded_runtime_objects,
        );

        // Mine blocks and wait for the withdrawal to be confirmed. This also
        // records the confirmation transaction's serialized effects size.
        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        let confirmed_with_effects = wait_for_withdrawal_confirmed_with_effects(
            &mut networks.sui_network.client,
            picked.withdrawal_txn_id,
            Duration::from_secs(600),
        )
        .await?;
        assert_effects_size_under_sui_limit(
            "confirm_withdrawal",
            confirmed_with_effects.effects_size_bytes,
        );
        assert_changed_objects_under_sui_limit(
            "confirm_withdrawal",
            confirmed_with_effects.changed_objects,
        );
        assert_runtime_object_count_under_sui_limit(
            "confirm_withdrawal",
            confirmed_with_effects.changed_objects,
            confirmed_with_effects.unchanged_loaded_runtime_objects,
        );
        let confirm_runtime_objects = runtime_object_count(&confirmed_with_effects);
        info!(
            confirm_runtime_objects,
            commit_runtime_objects, "Compared withdrawal commit and confirm runtime object counts"
        );
        drop(miner);

        // --- Run cleanup_spent_utxos to finalize on-chain bookkeeping ---
        info!("Running cleanup_spent_utxos...");
        let utxo_ids: Vec<_> = picked.inputs.iter().map(|u| u.id).collect();
        executor.execute_cleanup_spent_utxos(&utxo_ids).await?;
        info!("cleanup_spent_utxos succeeded");

        info!("=== Large Withdrawal Stress Test Passed ===");
        Ok(())
    }

    /// Stress-test withdrawal in drain mode: a batch at the absolute
    /// request cap (298) funded by only a handful of UTXOs. This is the
    /// testnet-backlog shape — a deep withdrawal queue against a shallow
    /// UTXO pool — where the flow should spend the Sui commit object
    /// budget on requests instead of consolidation inputs.
    ///
    /// The commit transaction at this shape fills the modeled
    /// runtime-object budget exactly (12 fixed + 3 × 298 requests + 16
    /// inputs = 922 modeled objects), so this test empirically validates
    /// the cost model at its ceiling. The 298-address `request_ids` pure
    /// argument (~9.5 KiB) also probes the 16 KiB pure-argument limit, and
    /// the 298 approvals exercise the 200-per-PTB approval chunking.
    ///
    /// Test outline:
    /// 1. Create 16 large deposits (the entire UTXO pool, matching the
    ///    funding reserve the commit object budget leaves at the cap).
    /// 2. Submit 298 withdrawal requests (two batched PTBs, then one
    ///    single request to fill the batch).
    /// 3. Assert the batch is picked with all 298 requests and the full
    ///    16-input funding reserve.
    /// 4. Assert commit, sign, and confirm stay under all Sui limits.
    /// 5. Mine blocks, wait for confirmation, and run cleanup.
    #[tokio::test]
    async fn test_drain_mode_max_request_batch() -> Result<()> {
        init_test_logging();
        info!("=== Starting Drain Mode Max Batch Test ===");

        let num_withdrawals: usize = hashi::utxo_pool::CoinSelectionParams::MAX_WITHDRAWAL_REQUESTS;
        let num_deposits: usize = 16;

        // 24-hour batching delay: the batch fires only at capacity, not on
        // a timer, so every request lands in one Bitcoin transaction.
        let mut networks = avid_override(
            TestNetworksBuilder::new()
                .with_nodes(4)
                .with_withdrawal_max_batch_size(num_withdrawals)
                .with_withdrawal_batching_delay_ms(86_400_000),
        )
        .build()
        .await?;
        rotate_into_avid(&mut networks).await?;

        let hashi = networks.hashi_network.nodes()[0].hashi().clone();

        // The drain-mode cap this test fills is the deferred-archival cap,
        // which the squashed package resolves from v1. Pin that the fresh
        // boot resolves it.
        assert_eq!(
            hashi.onchain_state().active_package_version(),
            Some(1),
            "the fresh v1 boot must resolve the active version the batch cap \
             follows"
        );

        let user_key = networks.sui_network.user_keys.first().unwrap().clone();
        let hbtc_recipient = user_key.public_key().derive_address();

        let deposit_address = hashi.get_deposit_address(Some(&hbtc_recipient))?;

        // --- Create 16 large Bitcoin deposits ---
        // 16 × 2,000,000 sats = 32,000,000 sats against 298 × 40,001 =
        // 11,920,298 sats of withdrawals. Six largest-first inputs fund the
        // batch, and low-fee consolidation sweeps the ten leftovers —
        // exactly filling the 16-input funding reserve that the commit
        // object budget leaves at the request cap.
        let deposit_amount_sats = 2_000_000u64;
        info!(
            "Creating {} Bitcoin deposits of {} sats each...",
            num_deposits, deposit_amount_sats
        );

        let mut btc_txids = Vec::with_capacity(num_deposits);
        for _ in 0..num_deposits {
            let txid = networks
                .bitcoin_node
                .send_to_address(&deposit_address, Amount::from_sat(deposit_amount_sats))?;
            btc_txids.push(txid);
        }

        info!("Mining blocks for confirmation...");
        networks.bitcoin_node.generate_blocks(10)?;

        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone().into());

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
        executor
            .execute_create_deposit_requests_multi(&deposits_data, Some(hbtc_recipient))
            .await?;
        info!("All {} deposit requests submitted on Sui", num_deposits);

        // Mine blocks in the background so the leader's BTC-block-driven
        // deposit processing loop keeps firing.
        let _deposit_miner = BackgroundMiner::start(&networks.bitcoin_node);
        info!("Waiting for {} deposit confirmations...", num_deposits);
        let deposit_timeout = Duration::from_secs(300);
        let deposit_start = std::time::Instant::now();
        loop {
            if deposit_start.elapsed() > deposit_timeout {
                let remaining = hashi.onchain_state().deposit_requests().len();
                return Err(anyhow!(
                    "Timeout waiting for deposit confirmations: {} still pending after {:?}",
                    remaining,
                    deposit_timeout,
                ));
            }
            let state = hashi.onchain_state();
            if state.deposit_requests().is_empty() && state.active_utxos().len() >= num_deposits {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        info!("All deposits confirmed");
        drop(_deposit_miner);

        // --- Submit 298 withdrawal requests ---
        // Mirror the CLI's bulk-submission shape: batched PTBs of up to 250
        // requests (~3 commands each against the 1024-command cap), keeping
        // the final request out so the batch cannot fill before this test
        // subscribes for the picked event.
        let withdrawal_amount_sats = 40_001u64;
        info!(
            "Submitting {} withdrawal requests of {} sats each...",
            num_withdrawals, withdrawal_amount_sats
        );
        let mut remaining = num_withdrawals - 1;
        while remaining > 0 {
            let this_batch = remaining.min(250);
            let btc_destination = networks.bitcoin_node.get_new_address()?;
            let destination_bytes = extract_witness_program(&btc_destination)?;
            executor
                .execute_create_withdrawal_requests_batch(
                    withdrawal_amount_sats,
                    destination_bytes,
                    this_batch,
                )
                .await?;
            remaining -= this_batch;
            info!(
                "  Withdrawal requests submitted: {}/{}",
                num_withdrawals - 1 - remaining,
                num_withdrawals
            );
        }

        // Wait for the batched withdrawal to be picked for processing. The
        // 24-hour delay means it fires only at the configured capacity.
        info!("Waiting for batched withdrawal to be picked...");
        let mut picked_client = networks.sui_network.client.clone();
        let picked_task = tokio::spawn(async move {
            wait_for_batched_withdrawal_picked_with_effects(
                &mut picked_client,
                num_withdrawals,
                Duration::from_secs(300),
            )
            .await
        });

        let btc_destination = networks.bitcoin_node.get_new_address()?;
        let destination_bytes = extract_witness_program(&btc_destination)?;
        executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes)
            .await?;
        info!("All {} withdrawal requests submitted", num_withdrawals);

        let picked_with_effects = picked_task.await??;
        assert_tx_size_under_sui_limit("commit_withdrawal_tx", picked_with_effects.tx_size_bytes);
        assert_effects_size_under_sui_limit(
            "commit_withdrawal_tx",
            picked_with_effects.effects_size_bytes,
        );
        assert_changed_objects_under_sui_limit(
            "commit_withdrawal_tx",
            picked_with_effects.changed_objects,
        );
        assert_runtime_object_count_under_sui_limit(
            "commit_withdrawal_tx",
            picked_with_effects.changed_objects,
            picked_with_effects.unchanged_loaded_runtime_objects,
        );
        let commit_runtime_objects = runtime_object_count(&picked_with_effects);
        let picked = picked_with_effects.event;

        info!(
            withdrawal_txn_id = %picked.withdrawal_txn_id,
            requests = %picked.request_ids.len(),
            inputs = %picked.inputs.len(),
            commit_runtime_objects,
            "Batched withdrawal picked"
        );

        assert_eq!(
            picked.request_ids.len(),
            num_withdrawals,
            "Expected all {} withdrawal requests to be batched",
            num_withdrawals,
        );

        // The drain-mode property: the batch is output-heavy, not
        // input-heavy. Funding needs six of the sixteen UTXOs and low-fee
        // consolidation sweeps the rest, exactly filling the 16-input
        // reserve the commit object budget leaves at the request cap.
        assert_eq!(
            picked.inputs.len(),
            num_deposits,
            "Expected drain mode to fund from (and sweep) the whole pool",
        );

        // Each request moves between the requests and processed ObjectBags
        // at commit, so the commit must have rewritten at least one object
        // per request — proof this test actually stressed the runtime
        // object budget rather than trivially passing the limit asserts.
        assert!(
            picked_with_effects.changed_objects >= num_withdrawals,
            "Expected at least {} changed objects at commit, got {}",
            num_withdrawals,
            picked_with_effects.changed_objects,
        );

        let signed_with_effects = wait_for_withdrawal_signed_with_effects(
            &mut networks.sui_network.client,
            picked.withdrawal_txn_id,
            Duration::from_secs(300),
        )
        .await?;
        assert_eq!(
            signed_with_effects.event.signatures.len(),
            picked.inputs.len(),
            "Expected one signature per selected input"
        );
        assert_effects_size_under_sui_limit(
            "sign_withdrawal",
            signed_with_effects.effects_size_bytes,
        );
        assert_changed_objects_under_sui_limit(
            "sign_withdrawal",
            signed_with_effects.changed_objects,
        );
        assert_runtime_object_count_under_sui_limit(
            "sign_withdrawal",
            signed_with_effects.changed_objects,
            signed_with_effects.unchanged_loaded_runtime_objects,
        );

        // Mine blocks and wait for the withdrawal to be confirmed, then
        // check the confirm transaction against the same Sui limits — with
        // 298 requests it is the second-largest transaction in the flow.
        let miner = BackgroundMiner::start(&networks.bitcoin_node);
        let confirmed_with_effects = wait_for_withdrawal_confirmed_with_effects(
            &mut networks.sui_network.client,
            picked.withdrawal_txn_id,
            Duration::from_secs(600),
        )
        .await?;
        assert_effects_size_under_sui_limit(
            "confirm_withdrawal",
            confirmed_with_effects.effects_size_bytes,
        );
        assert_changed_objects_under_sui_limit(
            "confirm_withdrawal",
            confirmed_with_effects.changed_objects,
        );
        assert_runtime_object_count_under_sui_limit(
            "confirm_withdrawal",
            confirmed_with_effects.changed_objects,
            confirmed_with_effects.unchanged_loaded_runtime_objects,
        );
        let confirm_runtime_objects = runtime_object_count(&confirmed_with_effects);
        info!(
            commit_runtime_objects,
            confirm_runtime_objects, "Compared drain-mode commit and confirm runtime object counts"
        );
        drop(miner);

        // --- Run cleanup_spent_utxos to finalize on-chain bookkeeping ---
        info!("Running cleanup_spent_utxos...");
        let utxo_ids: Vec<_> = picked.inputs.iter().map(|u| u.id).collect();
        executor.execute_cleanup_spent_utxos(&utxo_ids).await?;
        info!("cleanup_spent_utxos succeeded");

        info!("=== Drain Mode Max Batch Test Passed ===");
        Ok(())
    }

    /// `hashi register` (the CLI path through
    /// `build_register_or_update_validator_tx`) must target a live package:
    /// every `validator::*` entry gates on the called package's
    /// `assert_version_enabled`, so the original publish id aborts once its
    /// version is retired. The node's startup registration already routes
    /// past it; this pins the CLI resolver to the highest enabled published
    /// version on a chain where v1 is disabled (IOP-558). The disable is
    /// driven here rather than by the harness boot because the fresh-cycle
    /// binary supports v1 only, and the resolver must not depend on that.
    #[tokio::test]
    async fn test_cli_register_targets_the_enabled_package() -> Result<()> {
        use sui_crypto::SuiSigner as _;
        use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;

        init_test_logging();

        let networks =
            setup_test_networks(TestNetworksBuilder::new().with_nodes(4).keep_v1_enabled()).await?;
        let hashi_ids = networks.hashi_network.ids();
        let sui_rpc_url = networks.sui_network.rpc_url.clone();
        let mut client = networks.sui_network.client.clone();
        let hashi_isv = hashi::cli::client::fetch_initial_shared_version(
            &mut client,
            hashi_ids.hashi_object_id,
        )
        .await?;

        // Retire v1 through governance, executed through the upgraded
        // package, so the configured (original) id is a dead target.
        let upgraded_package_id = {
            let nodes = networks.hashi_network.nodes();
            let upgraded_package_id = nodes[0]
                .hashi()
                .onchain_state()
                .package_id()
                .ok_or_else(|| anyhow!("no package versions known"))?;
            assert_ne!(upgraded_package_id, hashi_ids.package_id);
            let mut executors: Vec<SuiTxExecutor> = nodes
                .iter()
                .map(|node| {
                    let hashi = node.hashi();
                    SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())
                })
                .collect::<Result<_>>()?;
            crate::upgrade_flow::disable_version(
                &mut executors,
                hashi_ids,
                hashi_isv,
                1,
                upgraded_package_id,
            )
            .await?;
            upgraded_package_id
        };
        crate::upgrade_flow::wait_for_version_disabled(&networks, 1, Duration::from_secs(30))
            .await?;
        info!(%upgraded_package_id, "v1 retired; exercising the CLI register path");

        // The runbook's operator-key rotation: a validator points its member
        // record at a new operator address. In e2e the node signs with its
        // validator key, so the rotation never locks the node out.
        let node = networks.hashi_network.nodes()[3].hashi().clone();
        let config = &node.config;
        let signer = config.operator_private_key()?;
        let new_operator = Address::new(rand::random::<[u8; 32]>());

        // Against the configured (original) id the build's simulation must
        // abort inside `versioning::assert_version_enabled`.
        let err = hashi::sui_tx_executor::build_register_or_update_validator_tx(
            &mut client,
            &hashi_ids,
            hashi_ids.package_id,
            config,
            Some(new_operator),
            None,
            None,
            None,
        )
        .await
        .expect_err("a v1-targeted update_operator_address must not build");
        let simulation = err
            .chain()
            .find_map(
                |e| match e.downcast_ref::<sui_transaction_builder::Error>() {
                    Some(sui_transaction_builder::Error::SimulationFailure(failure)) => {
                        Some(failure)
                    }
                    _ => None,
                },
            )
            .unwrap_or_else(|| panic!("expected a simulation failure, got: {err:#}"));
        let abort = simulation
            .execution_error()
            .abort_opt()
            .expect("the retired package must abort, not fail some other way");
        assert_eq!(
            abort.location().module_opt(),
            Some("versioning"),
            "abort must come from assert_version_enabled"
        );
        if let Some(constant) = abort
            .clever_error
            .as_ref()
            .and_then(|clever| clever.constant_name.as_deref())
        {
            assert_eq!(constant, "EVersionDisabled");
        }

        // The CLI's resolver picks the highest enabled published version
        // (the upgraded package), and the same transaction lands through it.
        let call_package =
            hashi::cli::commands::resolve_latest_enabled_package(&sui_rpc_url, hashi_ids).await?;
        assert_eq!(call_package, upgraded_package_id);
        let tx = hashi::sui_tx_executor::build_register_or_update_validator_tx(
            &mut client,
            &hashi_ids,
            call_package,
            config,
            Some(new_operator),
            None,
            None,
            None,
        )
        .await?
        .expect("the rotation is a real metadata change");
        let signature = signer.sign_transaction(&tx)?;
        let response = client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(tx.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("*")),
                Duration::from_secs(30),
            )
            .await?
            .into_inner();
        anyhow::ensure!(
            response.transaction().effects().status().success(),
            "update_operator_address through the enabled package failed: {:?}",
            response.transaction().effects().status()
        );

        // The member record now carries the rotation: a second build against
        // the same config has nothing left to send.
        let again = hashi::sui_tx_executor::build_register_or_update_validator_tx(
            &mut client,
            &hashi_ids,
            call_package,
            config,
            Some(new_operator),
            None,
            None,
            None,
        )
        .await?;
        assert!(
            again.is_none(),
            "member record must already reflect the rotated operator address"
        );
        Ok(())
    }
}
