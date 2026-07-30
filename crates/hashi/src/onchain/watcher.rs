// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The watcher's two streams.
//!
//! 1. The clock stream (here): an unfiltered checkpoint subscription
//!    with a minimal scalar mask. It keeps [`CheckpointInfo`] — the
//!    leader tick, timestamps, and Sui epoch-change detection — fresh
//!    regardless of Hashi activity, and costs a few scalar fields per
//!    checkpoint.
//! 2. The state stream ([`super::mirror`]): the filtered transaction
//!    stream that applies every Hashi-touching transaction's changed
//!    objects to the mirror.

use std::sync::Arc;

use futures::StreamExt;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

use crate::metrics::Metrics;
use crate::onchain::CheckpointInfo;
use crate::onchain::Notification;
use crate::onchain::OnchainState;

/// Reconnect if the checkpoint stream goes silent this long. A half-open h2
/// stream yields neither an item nor an error, so an unbounded read hangs — the
/// SDK's keepalive only trips on a fully-dead connection, not a live one whose
/// server silently stopped sending checkpoints.
const CHECKPOINT_STREAM_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Run the clock stream and the object mirror side by side.
pub async fn watcher(
    sui_rpc_url: String,
    state: OnchainState,
    seed: super::route::MirrorSeed,
    metrics: Option<Arc<Metrics>>,
) {
    tokio::join!(
        clock_watcher(sui_rpc_url.clone(), state.clone(), metrics.clone()),
        super::mirror::run(sui_rpc_url, state, seed, metrics),
    );
}

#[tracing::instrument(name = "clock_watcher", skip_all)]
async fn clock_watcher(sui_rpc_url: String, state: OnchainState, metrics: Option<Arc<Metrics>>) {
    let read_mask = FieldMask::from_paths([
        Checkpoint::path_builder().sequence_number(),
        Checkpoint::path_builder().summary().timestamp(),
        Checkpoint::path_builder().summary().epoch(),
    ]);

    loop {
        // Reconnect with a fresh client each iteration: re-subscribing on
        // the same channel can reuse a wedged h2 connection — the one
        // whose stream just stalled — and silently hang again.
        let mut client = match crate::sui_rpc_client::new_sui_rpc_client(&sui_rpc_url) {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!("error creating Sui RPC client: {e}");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        let mut subscription = match client
            .subscription_client()
            .subscribe_checkpoints(
                SubscribeCheckpointsRequest::default().with_read_mask(read_mask.clone()),
            )
            .await
        {
            Ok(subscription) => subscription,
            Err(e) => {
                tracing::warn!("error trying to subscribe to checkpoints: {e}");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        }
        .into_inner();

        while let Ok(Some(item)) =
            tokio::time::timeout(CHECKPOINT_STREAM_STALL_TIMEOUT, subscription.next()).await
        {
            let checkpoint = match item {
                Ok(checkpoint) => checkpoint,
                Err(e) => {
                    tracing::warn!("error in checkpoint stream: {e}");
                    break;
                }
            };

            let height = checkpoint.cursor();
            tracing::trace!("received checkpoint {height}");
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

            state.update_latest_checkpoint_info(CheckpointInfo {
                height,
                timestamp_ms,
                epoch,
            });

            if let Some(metrics) = &metrics {
                metrics.update_onchain_state(&state);
            }
        }

        // The stream stalled, errored, or closed. Loop to rebuild the
        // client and re-subscribe; the clock carries no state, so
        // nothing needs recovering.
        tracing::warn!("clock checkpoint stream ended; reconnecting");
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}
