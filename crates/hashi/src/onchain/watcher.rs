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
            match super::scrape_hashi(client.clone(), state.hashi_id()).await {
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
            tracing::debug!("recieved checkpoint {ckpt}");
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
                    .proposals
                    .insert(proposal.id, proposal);
            }
            HashiEvent::ProposalDeletedEvent(proposal_deleted_event) => {
                state
                    .state_mut()
                    .hashi
                    .proposals
                    .proposals
                    .remove(&proposal_deleted_event.proposal_id);
            }
            HashiEvent::ProposalExecutedEvent(proposal_executed_event) => {
                state
                    .state_mut()
                    .hashi
                    .proposals
                    .proposals
                    .remove(&proposal_executed_event.proposal_id);
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
                let deposit_request = DepositRequest {
                    id: deposit_requested_event.request_id,
                    utxo: super::types::Utxo {
                        id: deposit_requested_event.utxo_id.into(),
                        amount: deposit_requested_event.amount,
                        derivation_path: deposit_requested_event.derivation_path,
                    },
                    timestamp_ms: deposit_requested_event.timestamp_ms,
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
                let mut state = state.state_mut();

                let utxo = super::types::Utxo {
                    id: deposit_confirmed_event.utxo_id.into(),
                    amount: deposit_confirmed_event.amount,
                    derivation_path: deposit_confirmed_event.derivation_path,
                };

                state
                    .hashi
                    .deposit_queue
                    .requests
                    .remove(&deposit_confirmed_event.request_id);
                state.hashi.utxo_pool.active_utxos.insert(utxo.id, utxo);
                // TODO notify
            }
            HashiEvent::ExpiredDepositDeletedEvent(expired_deposit_deleted_event) => {
                state
                    .state_mut()
                    .hashi
                    .deposit_queue
                    .requests
                    .remove(&expired_deposit_deleted_event.request_id);
            }
            HashiEvent::WithdrawalRequestedEvent(withdrawal_requested_event) => {
                let withdrawal_request = WithdrawalRequest {
                    id: withdrawal_requested_event.request_id,
                    btc_amount: withdrawal_requested_event.btc_amount,
                    bitcoin_address: withdrawal_requested_event.bitcoin_address.clone(),
                    timestamp_ms: withdrawal_requested_event.timestamp_ms,
                    requester_address: withdrawal_requested_event.requester_address,
                    sui_tx_digest: withdrawal_requested_event.sui_tx_digest,
                    approved: false,
                };
                state
                    .state_mut()
                    .hashi
                    .withdrawal_queue
                    .requests
                    .insert(withdrawal_request.id, withdrawal_request);
            }
            HashiEvent::WithdrawalApprovedEvent(event) => {
                if let Some(request) = state
                    .state_mut()
                    .hashi
                    .withdrawal_queue
                    .requests
                    .get_mut(&event.request_id)
                {
                    request.approved = true;
                }
            }
            HashiEvent::WithdrawalPickedForProcessingEvent(event) => {
                // Remove requests from the queue
                {
                    let mut state = state.state_mut();
                    for request_id in &event.request_ids {
                        state.hashi.withdrawal_queue.requests.remove(request_id);
                    }
                }

                // Fetch the full pending withdrawal from chain
                let pending_withdrawals_id = state
                    .state()
                    .hashi()
                    .withdrawal_queue
                    .pending_withdrawals_id()
                    .to_owned();
                match super::fetch_pending_withdrawal(
                    client,
                    pending_withdrawals_id,
                    event.pending_id,
                )
                .await
                {
                    Ok(pending) => {
                        state
                            .state_mut()
                            .hashi
                            .withdrawal_queue
                            .pending_withdrawals
                            .insert(pending.id, pending);
                    }
                    Err(e) => {
                        tracing::error!(
                            "failed to fetch pending withdrawal {}: {e}",
                            event.pending_id
                        );
                    }
                }
            }
            HashiEvent::WithdrawalSignedEvent(event) => {
                let mut state = state.state_mut();
                if let Some(pending) = state
                    .hashi
                    .withdrawal_queue
                    .pending_withdrawals
                    .get_mut(&event.withdrawal_id)
                {
                    pending.signatures = Some(event.signatures.clone());
                }
            }
            HashiEvent::WithdrawalConfirmedEvent(event) => {
                let mut state = state.state_mut();

                // If a change UTXO was created, add it to the active pool.
                if let (Some(change_utxo_id), Some(change_amount)) =
                    (event.change_utxo_id, event.change_utxo_amount)
                {
                    let utxo_id = change_utxo_id.into();
                    let utxo = super::types::Utxo {
                        id: utxo_id,
                        amount: change_amount,
                        derivation_path: None,
                    };
                    state.hashi.utxo_pool.active_utxos.insert(utxo_id, utxo);
                }

                state
                    .hashi
                    .withdrawal_queue
                    .pending_withdrawals
                    .remove(&event.pending_id);
            }
            HashiEvent::UtxoSpentEvent(utxo_spent_event) => {
                let mut state = state.state_mut();
                let utxo_id = utxo_spent_event.utxo_id.into();
                state.hashi.utxo_pool.active_utxos.remove(&utxo_id);
                state
                    .hashi
                    .utxo_pool
                    .spent_utxos
                    .insert(utxo_id, utxo_spent_event.spent_epoch);
            }
            HashiEvent::SpentUtxoDeletedEvent(spent_utxo_deleted_event) => {
                state
                    .state_mut()
                    .hashi
                    .utxo_pool
                    .spent_utxos
                    .remove(&spent_utxo_deleted_event.utxo_id.into());
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
        ("update_deposit_fee", "UpdateDepositFee") => ProposalType::UpdateDepositFee,
        ("enable_version", "EnableVersion") => ProposalType::EnableVersion,
        ("disable_version", "DisableVersion") => ProposalType::DisableVersion,
        ("upgrade", "Upgrade") => ProposalType::Upgrade,
        _ => ProposalType::Unknown(format!("{}::{}", struct_tag.module(), struct_tag.name())),
    }
}
