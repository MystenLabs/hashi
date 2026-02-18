// TODO: consolidate this file and deposit_flow.rs
use anyhow::Result;
use anyhow::anyhow;
use bitcoin::Txid;
use bitcoincore_rpc::RpcApi;
use futures::StreamExt;
use hashi_types::move_types::WithdrawalConfirmedEvent;
use std::time::Duration;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
use sui_sdk_types::bcs::FromBcs;
use tracing::debug;
use tracing::info;

use crate::BitcoinNodeHandle;

pub async fn wait_for_withdrawal_confirmation(
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

/// Extract the witness program bytes from a bitcoin::Address.
///
/// Returns 20 bytes for P2WPKH or 32 bytes for P2TR.
pub fn extract_witness_program(address: &bitcoin::Address) -> Result<Vec<u8>> {
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

/// Wait for a withdrawal transaction to be mined and pay the destination.
pub async fn wait_for_btc_confirmation(
    bitcoin_node: &BitcoinNodeHandle,
    txid: &Txid,
    destination: &bitcoin::Address,
    amount: bitcoin::Amount,
    timeout: Duration,
) -> Result<()> {
    info!(
        "Waiting for withdrawal tx {} paying {} to {}...",
        txid, amount, destination
    );
    let start = std::time::Instant::now();
    loop {
        bitcoin_node.generate_blocks(1)?;
        tokio::time::sleep(Duration::from_secs(2)).await;

        let tx = match bitcoin_node.rpc_client().get_raw_transaction(txid, None) {
            Ok(tx) => tx,
            Err(e) => {
                if start.elapsed() >= timeout {
                    return Err(anyhow!(
                        "Withdrawal tx {} not found after {:?}: {}",
                        txid,
                        timeout,
                        e
                    ));
                }
                debug!("Withdrawal tx {} not indexed yet: {}", txid, e);
                continue;
            }
        };

        let pays_destination = tx.output.iter().any(|output| {
            output.value == amount && output.script_pubkey == destination.script_pubkey()
        });
        if !pays_destination {
            return Err(anyhow!(
                "Withdrawal tx {} does not pay {} to destination {}",
                txid,
                amount,
                destination
            ));
        }

        let received = bitcoin_node
            .rpc_client()
            .get_received_by_address(destination, Some(1))?;
        if received >= amount {
            info!(
                "Withdrawal tx {} confirmed with {} at {}",
                txid, received, destination
            );
            return Ok(());
        }

        if start.elapsed() >= timeout {
            return Err(anyhow!(
                "BTC amount {} from tx {} not confirmed at {} after {:?}",
                amount,
                txid,
                destination,
                timeout
            ));
        }

        debug!("Destination not funded yet, waiting...");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestNetworksBuilder;
    use crate::deposit_flow::get_hbtc_balance;
    use crate::deposit_flow::lookup_vout;
    use crate::deposit_flow::txid_to_address;
    use crate::deposit_flow::wait_for_deposit_confirmation;
    use anyhow::Context;
    use bitcoin::Amount;
    use bitcoin::hashes::Hash;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::groups::Scalar;
    use fastcrypto_tbls::threshold_schnorr::G;
    use fastcrypto_tbls::threshold_schnorr::S;
    use fastcrypto_tbls::threshold_schnorr::avss;
    use fastcrypto_tbls::threshold_schnorr::batch_avss;
    use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
    use fastcrypto_tbls::types::ShareIndex;
    use hashi::sui_tx_executor::SuiTxExecutor;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use sui_sdk_types::Address;

    fn address_to_txid(addr: &Address) -> Txid {
        Txid::from_byte_array(addr.as_bytes().try_into().unwrap())
    }

    fn deterministic_presignatures(
        committee: &hashi_types::committee::Committee,
        epoch: u64,
        share_indices: &[ShareIndex],
        batch_size_per_weight: u16,
        max_faulty: usize,
    ) -> Result<Presignatures> {
        let outputs: Vec<batch_avss::ReceiverOutput> = committee
            .members()
            .iter()
            .map(|member| {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(member.validator_address().as_bytes());
                for (i, b) in epoch.to_le_bytes().iter().enumerate() {
                    seed[i] ^= *b;
                }
                let mut rng = rand::rngs::StdRng::from_seed(seed);
                let nonces: Vec<S> = (0..batch_size_per_weight)
                    .map(|_| S::rand(&mut rng))
                    .collect();
                let public_keys: Vec<G> =
                    nonces.iter().map(|nonce| G::generator() * *nonce).collect();
                let my_shares = batch_avss::SharesForNode {
                    shares: share_indices
                        .iter()
                        .map(|&index| batch_avss::ShareBatch {
                            index,
                            batch: nonces.clone(),
                            blinding_share: S::zero(),
                        })
                        .collect(),
                };
                batch_avss::ReceiverOutput {
                    my_shares,
                    public_keys,
                }
            })
            .collect();

        Presignatures::new(outputs, batch_size_per_weight, max_faulty)
            .map_err(|e| anyhow!("Failed to build presignatures: {e}"))
    }

    fn init_signing_managers(nodes: &[crate::HashiNodeHandle]) -> Result<()> {
        let batch_size_per_weight: u16 = 10;

        for node in nodes {
            let mpc_manager = node
                .hashi()
                .mpc_manager()
                .context("MpcManager not initialized")?;
            let mgr = mpc_manager.read().unwrap();

            let threshold = mgr.dkg_config.threshold;
            let mut dealer_weight_sum = 0u32;
            let mut outputs_by_party = HashMap::new();

            for member in mgr.committee.members() {
                let dealer = member.validator_address();
                let Some(output) = mgr
                    .dealer_outputs
                    .get(&hashi::mpc::DealerOutputsKey::Dkg(dealer))
                else {
                    continue;
                };

                let dealer_party_id =
                    mgr.committee
                        .index_of(&dealer)
                        .context("dealer must be in committee")? as u16;
                let weight = mgr
                    .dkg_config
                    .nodes
                    .weight_of(dealer_party_id)
                    .map_err(|_| anyhow!("Missing reduced weight for dealer {dealer}"))?;
                dealer_weight_sum += weight as u32;
                outputs_by_party.insert(dealer_party_id, output.clone());

                if dealer_weight_sum >= threshold as u32 {
                    break;
                }
            }

            anyhow::ensure!(
                dealer_weight_sum >= threshold as u32,
                "Insufficient certified dealer weight to reconstruct DKG output"
            );

            let combined = avss::ReceiverOutput::complete_dkg(
                threshold,
                &mgr.dkg_config.nodes,
                outputs_by_party,
            )
            .context("Failed to reconstruct DKG output for signing manager")?;

            let share_indices: Vec<ShareIndex> = combined
                .my_shares
                .shares
                .iter()
                .map(|share| share.index)
                .collect();
            let presignatures = deterministic_presignatures(
                &mgr.committee,
                mgr.dkg_config.epoch,
                &share_indices,
                batch_size_per_weight,
                mgr.dkg_config.max_faulty as usize,
            )?;

            let signing_manager = hashi::mpc::SigningManager::new(
                mgr.address,
                mgr.committee.clone(),
                threshold,
                combined.my_shares,
                combined.vk,
                presignatures,
            );
            drop(mgr);
            node.hashi().init_signing_manager(signing_manager);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_bitcoin_withdrawal_e2e_flow() -> Result<()> {
        tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            )
            .try_init()
            .ok();

        info!("=== Starting Bitcoin Withdrawal E2E Test ===");

        // ================================================================
        // Step 1: Set up test networks
        // ================================================================
        info!("Setting up test networks...");
        let mut networks = TestNetworksBuilder::new().with_nodes(4).build().await?;

        info!("Test networks initialized");
        info!("  - Sui RPC: {}", networks.sui_network.rpc_url);
        info!("  - Bitcoin RPC: {}", networks.bitcoin_node.rpc_url());
        info!("  - Hashi nodes: {}", networks.hashi_network.nodes().len());

        // ================================================================
        // Step 2: Wait for MPC key
        // ================================================================
        info!("Waiting for MPC key to be ready...");
        networks.hashi_network.nodes()[0]
            .wait_for_mpc_key(Duration::from_secs(60))
            .await?;
        init_signing_managers(networks.hashi_network.nodes())?;
        info!("MPC key ready");

        // ================================================================
        // Step 3: Deposit BTC to get hBTC (prerequisite for withdrawal)
        // ================================================================
        let user_key = networks.sui_network.user_keys.first().unwrap();
        let hbtc_recipient = user_key.public_key().derive_address();
        let hashi = networks.hashi_network.nodes()[0].hashi().clone();
        let deposit_address =
            hashi.get_deposit_address(&hashi.get_hashi_pubkey(), Some(&hbtc_recipient));

        let deposit_amount_sats = 31337u64;
        info!(
            "Depositing {} sats to get hBTC for withdrawal...",
            deposit_amount_sats
        );
        let deposit_txid = networks
            .bitcoin_node
            .send_to_address(&deposit_address, Amount::from_sat(deposit_amount_sats))?;
        info!("Deposit transaction sent: {}", deposit_txid);

        networks.bitcoin_node.generate_blocks(10)?;
        info!("10 blocks mined for deposit confirmation");

        let vout = lookup_vout(
            &networks,
            deposit_txid,
            deposit_address,
            deposit_amount_sats,
        )?;
        let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
            .with_signer(user_key.clone());
        let deposit_request_id = executor
            .execute_create_deposit_request(
                txid_to_address(&deposit_txid),
                vout as u32,
                deposit_amount_sats,
                Some(hbtc_recipient),
            )
            .await?;
        info!("Deposit request created: {}", deposit_request_id);

        wait_for_deposit_confirmation(
            &mut networks.sui_network.client,
            deposit_request_id,
            Duration::from_secs(300),
        )
        .await?;
        info!("Deposit confirmed on Sui");

        let hbtc_balance = get_hbtc_balance(
            &mut networks.sui_network.client,
            networks.hashi_network.ids().package_id,
            hbtc_recipient,
        )
        .await?;
        assert!(
            hbtc_balance == deposit_amount_sats,
            "Expected {} sats hBTC, got {}",
            deposit_amount_sats,
            hbtc_balance
        );
        info!("hBTC balance verified: {} sats", hbtc_balance);

        // ================================================================
        // Step 4: Create a withdrawal request
        // ================================================================
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
        let _withdrawal_request_id = withdrawal_executor
            .execute_create_withdrawal_request(withdrawal_amount_sats, destination_bytes, 0)
            .await?;
        info!("Withdrawal request created: {}", _withdrawal_request_id);

        // ================================================================
        // Step 5: Wait for the withdrawal to be confirmed on Sui
        // ================================================================
        let confirmed_event = wait_for_withdrawal_confirmation(
            &mut networks.sui_network.client,
            Duration::from_secs(30),
        )
        .await?;
        info!("Withdrawal confirmed on Sui");

        // ================================================================
        // Step 6: Verify hBTC was burned on Sui
        // ================================================================
        let hbtc_balance_after = get_hbtc_balance(
            &mut networks.sui_network.client,
            networks.hashi_network.ids().package_id,
            hbtc_recipient,
        )
        .await?;
        let expected_remaining = deposit_amount_sats - withdrawal_amount_sats;
        assert!(
            hbtc_balance_after == expected_remaining,
            "Expected {} sats hBTC remaining, got {}",
            expected_remaining,
            hbtc_balance_after
        );
        info!(
            "hBTC balance verified: {} sats (burned {} sats)",
            hbtc_balance_after, withdrawal_amount_sats
        );

        // ================================================================
        // Step 7: Verify BTC arrived on Bitcoin
        // ================================================================
        let btc_txid = address_to_txid(&confirmed_event.txid);
        info!("Observed withdrawal Bitcoin txid in event: {}", btc_txid);
        wait_for_btc_confirmation(
            &networks.bitcoin_node,
            &btc_txid,
            &btc_destination,
            Amount::from_sat(withdrawal_amount_sats),
            Duration::from_secs(30),
        )
        .await?;

        info!("=== Bitcoin Withdrawal E2E Test Passed ===");
        Ok(())
    }
}
