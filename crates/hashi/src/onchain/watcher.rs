use std::collections::BTreeSet;

use futures::StreamExt;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

use crate::onchain::Notification;
use crate::onchain::OnchainState;
use crate::onchain::scrape_member_info;
use crate::onchain::types::DepositRequest;
use hashi_types::move_types::HashiEvent;

pub async fn watcher(mut client: Client, state: OnchainState) {
    let subscription_read_mask = FieldMask::from_paths([
        Checkpoint::path_builder().sequence_number(),
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

            // Finally update the latest checkpoint
            state.update_latest_checkpoint(ckpt);
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
            HashiEvent::ProposalDeletedEvent(_) => {}
            HashiEvent::ProposalExecutedEvent(_) => {}
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
                        id: super::types::UtxoId {
                            txid: deposit_requested_event.utxo_id.txid,
                            vout: deposit_requested_event.utxo_id.vout,
                        },
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
                    .insert(deposit_request.utxo.id, deposit_request);
                // TODO notify
            }
            HashiEvent::DepositConfirmedEvent(deposit_confirmed_event) => {
                let mut state = state.state_mut();

                let utxo = super::types::Utxo {
                    id: super::types::UtxoId {
                        txid: deposit_confirmed_event.utxo_id.txid,
                        vout: deposit_confirmed_event.utxo_id.vout,
                    },
                    amount: deposit_confirmed_event.amount,
                    derivation_path: deposit_confirmed_event.derivation_path,
                };

                state.hashi.deposit_queue.requests.remove(&utxo.id);
                state.hashi.utxo_pool.utxos.insert(utxo.id, utxo);
                // TODO notify
            }
            HashiEvent::StartReconfigEvent(start_reconfig_event) => {
                let epoch = start_reconfig_event.epoch;
                // Fetch new committee
                let committees_id = state.state().hashi().committees.committees_id();
                //TODO maybe include info in the event
                let committee = super::scrape_committee(client.clone(), committees_id, epoch)
                    .await
                    .unwrap();
                let mut state = state.state_mut();
                state
                    .hashi
                    .committees
                    .committees_mut()
                    .insert(epoch, committee);
                state.hashi.committees.set_pending_epoch_change(Some(epoch));
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
