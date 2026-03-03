use std::collections::BTreeSet;

use futures::StreamExt;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

use sui_sdk_types::TypeTag;

use crate::onchain::CheckpointInfo;
use crate::onchain::Notification;
use crate::onchain::OnchainState;
use crate::onchain::scrape_member_info;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::PendingWithdrawal;
use crate::onchain::types::Proposal;
use crate::onchain::types::ProposalType;
use crate::onchain::types::WithdrawalRequest;
use hashi_types::move_types::HashiEvent;

pub async fn watcher(mut client: Client, state: OnchainState) {
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
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }
        .into_inner();

        while let Some(item) = subscription.next().await {
            let checkpoint = match item {
                Ok(checkpoint) => checkpoint,
                Err(e) => {
                    tracing::warn!("error in checkpoint stream: {e}");
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

            handle_events(&client, &state, &events).await;

            // Finally update the latest checkpoint info
            state.update_latest_checkpoint_info(CheckpointInfo {
                height: ckpt,
                timestamp_ms,
                epoch,
            });
        }
    }
}

async fn handle_events(client: &Client, state: &OnchainState, events: &[HashiEvent]) {
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
            HashiEvent::MintEvent(mint) => {
                if let Some(treasury) = state
                    .state_mut()
                    .hashi
                    .treasury
                    .treasury_caps
                    .get_mut(&mint.coin_type)
                {
                    treasury.supply += mint.amount;
                }
            }
            HashiEvent::BurnEvent(burn) => {
                if let Some(treasury) = state
                    .state_mut()
                    .hashi
                    .treasury
                    .treasury_caps
                    .get_mut(&burn.coin_type)
                {
                    treasury.supply -= burn.amount;
                }
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
                let mut state = state.state_mut();

                // Remove requests from the queue
                for request_id in &event.request_ids {
                    state.hashi.withdrawal_queue.requests.remove(request_id);
                }

                // Add to pending withdrawals
                let pending = PendingWithdrawal {
                    id: event.pending_id,
                    txid: event.txid,
                    request_ids: event.request_ids.clone(),
                    inputs: event
                        .inputs
                        .iter()
                        .map(|u| super::types::Utxo {
                            id: u.id.into(),
                            amount: u.amount,
                            derivation_path: u.derivation_path,
                        })
                        .collect(),
                    outputs: event
                        .outputs
                        .iter()
                        .map(|o| super::types::OutputUtxo {
                            amount: o.amount,
                            bitcoin_address: o.bitcoin_address.clone(),
                        })
                        .collect(),
                    timestamp_ms: event.timestamp_ms,
                    randomness: event.randomness.clone(),
                    signatures: None,
                };
                state
                    .hashi
                    .withdrawal_queue
                    .pending_withdrawals
                    .insert(pending.id, pending);
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
                state
                    .state_mut()
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
                    .set_pending_epoch_change(None);
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
