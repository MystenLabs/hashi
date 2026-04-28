// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::sync::Arc;

use futures::StreamExt;
use hashi_types::move_types::BurnEvent;
use hashi_types::move_types::MintEvent;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

use sui_sdk_types::TypeTag;

use crate::metrics::Metrics;
use crate::onchain::CheckpointInfo;
use crate::onchain::Notification;
use crate::onchain::OnchainState;
use crate::onchain::scrape_member_info;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::Proposal;
use crate::onchain::types::ProposalType;
use crate::onchain::types::WithdrawalRequest;
use hashi_types::move_types::HashiEvent;

#[tracing::instrument(name = "watcher", skip_all)]
pub async fn watcher(mut client: Client, state: OnchainState, metrics: Option<Arc<Metrics>>) {
    let subscription_read_mask = FieldMask::from_paths([
        Checkpoint::path_builder().sequence_number(),
        Checkpoint::path_builder().summary().timestamp(),
        Checkpoint::path_builder().summary().epoch(),
        Checkpoint::path_builder()
            .transactions()
            .events()
            .events()
            .contents()
            .finish(),
        Checkpoint::path_builder().transactions().digest(),
        Checkpoint::path_builder()
            .transactions()
            .effects()
            .status()
            .finish(),
    ]);

    let mut rescrape_state = false;

    loop {
        let mut subscription = match client
            .subscription_client()
            .subscribe_checkpoints(
                SubscribeCheckpointsRequest::default()
                    .with_read_mask(subscription_read_mask.clone()),
            )
            .await
        {
            Ok(subscription) => subscription,
            Err(e) => {
                tracing::warn!("error trying to subscribe to checkpoints: {e}");
                rescrape_state = true;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }
        .into_inner();

        // Rescrape the chain state in the event our subscription broke
        if rescrape_state {
            match super::scrape_hashi(
                client.clone(),
                state.hashi_id(),
                state.package_id_original(),
            )
            .await
            {
                Ok((checkpoint_info, hashi)) => {
                    state.replace_hashi_state(hashi);
                    state.update_latest_checkpoint_info(checkpoint_info);
                    if let Some(metrics) = &metrics {
                        metrics.update_onchain_state(&state);
                    }
                }
                Err(e) => {
                    tracing::warn!("error trying to rescrape hashi's state: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            }

            rescrape_state = false;
        }

        while let Some(item) = subscription.next().await {
            let checkpoint = match item {
                Ok(checkpoint) => checkpoint,
                Err(e) => {
                    tracing::warn!("error in checkpoint stream: {e}");
                    rescrape_state = true;
                    break;
                }
            };

            let ckpt = checkpoint.cursor();
            tracing::trace!("received checkpoint {ckpt}");
            let timestamp_ms = checkpoint
                .checkpoint()
                .summary()
                .timestamp
                .and_then(|t| proto_to_timestamp_ms(t).ok())
                .unwrap_or(0);
            let epoch = checkpoint.checkpoint().summary().epoch();
            let previous_epoch = state.latest_checkpoint_epoch();
            if epoch != previous_epoch {
                tracing::debug!("Sui epoch changed from {previous_epoch} to {epoch}");
                state.notify(Notification::SuiEpochChanged(epoch));
            }
            let mut events = Vec::new();
            {
                let state = state.state();

                for txn in checkpoint.checkpoint().transactions() {
                    // Skip txns that were not successful
                    if !txn.effects().status().success() {
                        continue;
                    }

                    for event in txn.events().events() {
                        match HashiEvent::try_parse(&state.package_ids, event.contents()) {
                            Ok(Some(event)) => {
                                tracing::debug!("found event {:?}", event);
                                events.push(event);
                            }
                            Ok(None) => {}
                            Err(e) => tracing::error!("unable to parse event: {e}"),
                        }
                    }
                }
            }

            handle_events(&mut client, &state, &events).await;

            // Finally update the latest checkpoint info
            state.update_latest_checkpoint_info(CheckpointInfo {
                height: ckpt,
                timestamp_ms,
                epoch,
            });

            if let Some(metrics) = &metrics {
                metrics.update_onchain_state(&state);
            }
        }
    }
}

async fn handle_events(client: &mut Client, state: &OnchainState, events: &[HashiEvent]) {
    if events.is_empty() {
        return;
    }

    let mut validator_updates = BTreeSet::new();

    for event in events {
        match event {
            HashiEvent::ValidatorRegistered(validator_registered) => {
                validator_updates.insert(validator_registered.validator);
            }
            HashiEvent::ValidatorUpdated(validator_updated) => {
                validator_updates.insert(validator_updated.validator);
            }
            HashiEvent::VoteCastEvent(_) => {}
            HashiEvent::VoteRemovedEvent(_) => {}
            HashiEvent::ProposalCreatedEvent(proposal_created_event) => {
                let proposal = Proposal {
                    id: proposal_created_event.proposal_id,
                    timestamp_ms: proposal_created_event.timestamp_ms,
                    proposal_type: parse_proposal_type_from_type_tag(
                        &proposal_created_event.proposal_type,
                    ),
                };
                state
                    .state_mut()
                    .hashi
                    .proposals
                    .active
                    .insert(proposal.id, proposal);
            }
            HashiEvent::ProposalDeletedEvent(proposal_deleted_event) => {
                state
                    .state_mut()
                    .hashi
                    .proposals
                    .active
                    .remove(&proposal_deleted_event.proposal_id);
            }
            HashiEvent::ProposalExecutedEvent(proposal_executed_event) => {
                // Move the entry from `active` to `executed` to mirror
                // the on-chain dual-bag layout. Scope the write lock so
                // it's released before the async config refetch below.
                {
                    let mut state_lock = state.state_mut();
                    let proposals = &mut state_lock.hashi.proposals;
                    if let Some(proposal) = proposals
                        .active
                        .remove(&proposal_executed_event.proposal_id)
                    {
                        proposals
                            .executed
                            .insert(proposal_executed_event.proposal_id, proposal);
                    }
                }

                // When an UpdateConfig or EmergencyPause proposal executes,
                // the Hashi object's config field changes on-chain. Re-fetch
                // the config from the Hashi object to keep the in-memory
                // state current. (The event now carries the typed `data`,
                // so this could be applied directly in the future.)
                if matches!(
                    parse_proposal_type_from_type_tag(&proposal_executed_event.proposal_type),
                    ProposalType::UpdateConfig | ProposalType::EmergencyPause
                ) {
                    match super::scrape_hashi_config(client.clone(), state.hashi_id()).await {
                        Ok(config) => {
                            state.state_mut().hashi.config = config;
                            tracing::info!(
                                "on-chain config refreshed after config-changing proposal"
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "failed to refresh config after config-changing proposal: {e}"
                            );
                        }
                    }
                }
            }
            HashiEvent::QuorumReachedEvent(_) => {}
            HashiEvent::PackageUpgradedEvent(package_upgraded_event) => {
                state.add_package_version(
                    package_upgraded_event.version,
                    package_upgraded_event.package,
                );
                // TODO notify
            }
            HashiEvent::MintEvent(MintEvent { coin_type, .. })
            | HashiEvent::BurnEvent(BurnEvent { coin_type, .. }) => {
                refresh_treasury_cap_supply(client, state, coin_type).await;
            }
            HashiEvent::DepositRequestedEvent(deposit_requested_event) => {
                tracing::info!(deposit_request_id = %deposit_requested_event.request_id, "Deposit request detected");
                let deposit_request = DepositRequest {
                    id: deposit_requested_event.request_id,
                    sender: deposit_requested_event.requester_address,
                    timestamp_ms: deposit_requested_event.timestamp_ms,
                    sui_tx_digest: deposit_requested_event.sui_tx_digest,
                    utxo: super::types::Utxo {
                        id: deposit_requested_event.utxo_id,
                        amount: deposit_requested_event.amount,
                        derivation_path: deposit_requested_event.derivation_path,
                    },
                };
                state
                    .state_mut()
                    .hashi
                    .deposit_queue
                    .requests
                    .insert(deposit_request.id, deposit_request);
                // TODO notify
            }
            HashiEvent::DepositConfirmedEvent(deposit_confirmed_event) => {
                tracing::info!(deposit_request_id = %deposit_confirmed_event.request_id, "Deposit confirmed");
                let mut state = state.state_mut();

                let utxo = super::types::Utxo {
                    id: deposit_confirmed_event.utxo_id,
                    amount: deposit_confirmed_event.amount,
                    derivation_path: deposit_confirmed_event.derivation_path,
                };

                state
                    .hashi
                    .deposit_queue
                    .requests
                    .remove(&deposit_confirmed_event.request_id);
                state.hashi.utxo_pool.utxo_records.insert(
                    utxo.id,
                    super::types::UtxoRecord {
                        utxo,
                        produced_by: None,
                        locked_by: None,
                    },
                );
                // TODO notify
            }
            HashiEvent::ExpiredDepositDeletedEvent(expired_deposit_deleted_event) => {
                tracing::info!(deposit_request_id = %expired_deposit_deleted_event.request_id, "Expired deposit deleted");
                state
                    .state_mut()
                    .hashi
                    .deposit_queue
                    .requests
                    .remove(&expired_deposit_deleted_event.request_id);
            }
            HashiEvent::WithdrawalRequestedEvent(withdrawal_requested_event) => {
                tracing::info!(withdrawal_request_id = %withdrawal_requested_event.request_id, "Withdrawal request detected");
                let withdrawal_request = WithdrawalRequest {
                    id: withdrawal_requested_event.request_id,
                    sender: withdrawal_requested_event.requester_address,
                    btc_amount: withdrawal_requested_event.btc_amount,
                    bitcoin_address: withdrawal_requested_event.bitcoin_address.clone(),
                    timestamp_ms: withdrawal_requested_event.timestamp_ms,
                    status: super::types::WithdrawalStatus::Requested,
                    withdrawal_txn_id: None,
                    sui_tx_digest: withdrawal_requested_event.sui_tx_digest,
                    btc: withdrawal_requested_event.btc_amount,
                };
                state
                    .state_mut()
                    .hashi
                    .withdrawal_queue
                    .requests
                    .insert(withdrawal_request.id, withdrawal_request);
            }
            HashiEvent::WithdrawalApprovedEvent(event) => {
                tracing::info!(withdrawal_request_id = %event.request_id, "Withdrawal approved");
                if let Some(request) = state
                    .state_mut()
                    .hashi
                    .withdrawal_queue
                    .requests
                    .get_mut(&event.request_id)
                {
                    request.status = super::types::WithdrawalStatus::Approved;
                }
            }
            HashiEvent::WithdrawalPickedForProcessingEvent(event) => {
                tracing::info!(withdrawal_txn_id = %event.withdrawal_txn_id, "Withdrawal picked for processing");
                // Remove requests from the queue
                {
                    let mut state = state.state_mut();
                    for request_id in &event.request_ids {
                        state.hashi.withdrawal_queue.requests.remove(request_id);
                    }
                }

                // Fetch the full withdrawal transaction from chain
                match super::fetch_withdrawal_txn(client, event.withdrawal_txn_id).await {
                    Ok(txn) => {
                        state
                            .state_mut()
                            .hashi
                            .withdrawal_queue
                            .withdrawal_txns
                            .insert(txn.id, txn);
                    }
                    Err(e) => {
                        tracing::error!(
                            withdrawal_txn_id = %event.withdrawal_txn_id,
                            "Failed to fetch withdrawal transaction: {e}",
                        );
                    }
                }

                // Lock each input UTXO in the pool and insert the pending
                // change UTXO (if any) so it is immediately selectable.
                {
                    let mut state = state.state_mut();
                    for input in &event.inputs {
                        if let Some(record) = state.hashi.utxo_pool.utxo_records.get_mut(&input.id)
                        {
                            record.locked_by = Some(event.withdrawal_txn_id);
                        }
                    }
                    if let Some(ref change_output) = event.change_output {
                        let change_vout = event.withdrawal_outputs.len() as u32;
                        let change_utxo_id = super::types::UtxoId {
                            txid: event.txid,
                            vout: change_vout,
                        };
                        let change_utxo = super::types::Utxo {
                            id: change_utxo_id,
                            amount: change_output.amount,
                            derivation_path: None,
                        };
                        state.hashi.utxo_pool.utxo_records.insert(
                            change_utxo_id,
                            super::types::UtxoRecord {
                                utxo: change_utxo,
                                produced_by: Some(event.withdrawal_txn_id),
                                locked_by: None,
                            },
                        );
                    }
                }
            }
            HashiEvent::WithdrawalSignedEvent(event) => {
                tracing::info!(withdrawal_txn_id = %event.withdrawal_txn_id, "Withdrawal signatures stored on-chain");
                let mut state = state.state_mut();
                if let Some(txn) = state
                    .hashi
                    .withdrawal_queue
                    .withdrawal_txns
                    .get_mut(&event.withdrawal_txn_id)
                {
                    txn.signatures = Some(event.signatures.clone());
                }
            }
            HashiEvent::WithdrawalConfirmedEvent(event) => {
                tracing::info!(withdrawal_txn_id = %event.withdrawal_txn_id, "Withdrawal confirmed on-chain");
                let mut state = state.state_mut();

                // Promote the change UTXO from pending to confirmed by
                // clearing `produced_by`. The UTXO was already inserted at
                // commit time; input UTXOs are removed via UtxoSpentEvent.
                if let Some(change_utxo_id) = event.change_utxo_id
                    && let Some(record) =
                        state.hashi.utxo_pool.utxo_records.get_mut(&change_utxo_id)
                {
                    record.produced_by = None;
                }

                state
                    .hashi
                    .withdrawal_queue
                    .withdrawal_txns
                    .remove(&event.withdrawal_txn_id);
            }
            HashiEvent::UtxoSpentEvent(utxo_spent_event) => {
                let mut state = state.state_mut();
                state
                    .hashi
                    .utxo_pool
                    .utxo_records
                    .remove(&utxo_spent_event.utxo_id);
                state
                    .hashi
                    .utxo_pool
                    .spent_utxos
                    .insert(utxo_spent_event.utxo_id, utxo_spent_event.spent_epoch);
            }
            HashiEvent::StartReconfigEvent(start_reconfig_event) => {
                let epoch = start_reconfig_event.epoch;
                // Fetch new committee
                let committees_id = state.state().hashi().committees.committees_id();
                //TODO maybe include info in the event
                let committee = super::scrape_committee(client.clone(), committees_id, epoch)
                    .await
                    .unwrap();
                {
                    let mut state = state.state_mut();
                    state
                        .hashi
                        .committees
                        .committees_mut()
                        .insert(epoch, committee);
                    state.hashi.committees.set_pending_epoch_change(Some(epoch));
                }
                state.notify(Notification::StartReconfig(epoch));
            }
            HashiEvent::EndReconfigEvent(end_reconfig_event) => {
                let mut state = state.state_mut();
                state
                    .hashi
                    .committees
                    .set_epoch(end_reconfig_event.epoch)
                    .set_pending_epoch_change(None)
                    .set_mpc_public_key(end_reconfig_event.mpc_public_key.clone());
            }
            HashiEvent::AbortReconfigEvent(abort_reconfig_event) => {
                let mut state = state.state_mut();
                state
                    .hashi
                    .committees
                    .committees_mut()
                    .remove(&abort_reconfig_event.epoch);
                state.hashi.committees.set_pending_epoch_change(None);
            }
        }
    }

    let members_id = state.state().hashi().committees.members_id();
    for validator in validator_updates {
        match scrape_member_info(client.clone(), members_id, validator).await {
            Ok(info) => {
                state.state_mut().hashi.committees.update_validator(info);
                state.notify(Notification::ValidatorInfoUpdated(validator));
            }
            Err(e) => tracing::error!("unable to query validator {validator}'s info: {e}"),
        }
    }
}

async fn refresh_treasury_cap_supply(
    client: &mut Client,
    state: &OnchainState,
    coin_type: &TypeTag,
) {
    let treasury_cap_id = state
        .state()
        .hashi
        .treasury
        .treasury_caps
        .get(coin_type)
        .map(|tc| tc.id);

    let Some(id) = treasury_cap_id else {
        return;
    };

    match super::fetch_treasury_cap(client, id).await {
        Ok(treasury_cap) => {
            state
                .state_mut()
                .hashi
                .treasury
                .treasury_caps
                .insert(coin_type.clone(), treasury_cap);
        }
        Err(e) => {
            tracing::error!("failed to fetch treasury cap for {coin_type}: {e}");
        }
    }
}

/// Parse the proposal type from the TypeTag extracted from the event's phantom type parameter.
fn parse_proposal_type_from_type_tag(type_tag: &TypeTag) -> ProposalType {
    let TypeTag::Struct(struct_tag) = type_tag else {
        return ProposalType::Unknown(format!("{:?}", type_tag));
    };

    match (struct_tag.module().as_str(), struct_tag.name().as_str()) {
        ("update_config", "UpdateConfig") => ProposalType::UpdateConfig,
        ("enable_version", "EnableVersion") => ProposalType::EnableVersion,
        ("disable_version", "DisableVersion") => ProposalType::DisableVersion,
        ("upgrade", "Upgrade") => ProposalType::Upgrade,
        ("emergency_pause", "EmergencyPause") => ProposalType::EmergencyPause,
        ("abort_reconfig", "AbortReconfig") => ProposalType::AbortReconfig,
        _ => ProposalType::Unknown(format!("{}::{}", struct_tag.module(), struct_tag.name())),
    }
}
