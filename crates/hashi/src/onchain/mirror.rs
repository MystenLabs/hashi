// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The lossless object mirror — the production state's update path.
//!
//! The transport is transaction-granular and filtered:
//! `SubscribeTransactions` with an `affected_object == hashi root`
//! filter delivers exactly the Hashi-touching transactions, each
//! rendered with its object set, checkpoint, and position within the
//! checkpoint; `ListTransactions` with the same filter replays history
//! from the watermark cursor, so bootstrap and reconnects are gap-free
//! without rescraping. Transactions arrive in chain order, and the
//! mirror ratchets over `(checkpoint, transaction_index)` so a
//! transaction delivered by both replay and the live stream applies
//! exactly once.
//!
//! Each applied transaction updates `OnchainState`'s `types::Hashi`
//! directly through the route/apply layers; side effects that used to
//! ride the event path come back as transition-derived
//! [`apply::Effect`]s and are acted on here: notifications, the local
//! withdrawal limiter, package-version reconciliation, and the
//! withdrawal duration metrics.
//!
//! The transport requires a server that renders per-transaction object
//! sets on the filtered APIs (Sui v1.76 with the object-set fix).
//! Older servers are not supported: the stream fails and the watcher
//! keeps reconnecting rather than degrading to a lossy mode.

use std::time::Duration;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use futures::StreamExt;
use sui_rpc::Client;
use sui_rpc::client::ResponseExt;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2 as proto;
use sui_rpc::proto::sui::rpc::v2::ListTransactionsRequest;
use sui_rpc::proto::sui::rpc::v2::QueryEndReason;
use sui_rpc::proto::sui::rpc::v2::QueryOptions;
use sui_rpc::proto::sui::rpc::v2::SubscribeTransactionsRequest;
use sui_rpc::proto::sui::rpc::v2::TransactionFilter;
use sui_rpc::proto::sui::rpc::v2::filter::transaction as tx_filter;

use crate::metrics::Metrics;
use crate::withdrawals::withdrawal_limiter_consumption_amount;

use super::Notification;
use super::OnchainState;
use super::apply;
use super::route;
use super::types;

/// Reconnect if the stream goes silent this long. The filtered stream
/// emits watermark or cursor progress frames periodically even when
/// nothing matches the filter, so silence genuinely means a broken
/// stream.
const STREAM_STALL_TIMEOUT: Duration = Duration::from_secs(120);

const RECONNECT_DELAY: Duration = Duration::from_secs(5);

/// Bound on the `list_package_versions` reconcile an upgrade triggers.
const PACKAGE_RECONCILE_TIMEOUT: Duration = Duration::from_secs(30);

/// Read mask for `ExecutedTransaction` frames on the transaction
/// stream and the replay list.
const TX_READ_MASK: [&str; 7] = [
    "digest",
    "checkpoint",
    "transaction_index",
    "timestamp",
    "effects.status",
    "effects.changed_objects",
    "objects.objects.bcs",
];

/// The mirror's transport bookkeeping. The mirrored values themselves
/// live in `OnchainState`; this is everything the loop needs alongside
/// them: the routing table, the per-object index, the delivery
/// ratchet, and the replay cursor.
struct Mirror {
    routing: route::RoutingTable,
    index: route::ObjectIndex,
    /// Checkpoint through which the mirror is complete (see
    /// `OnchainState::wait_until_checkpoint` for the one deliberate
    /// softness within an applied transaction's own checkpoint).
    watermark_checkpoint: u64,
    /// The last applied transaction's `(checkpoint, transaction_index)`.
    /// Transactions are delivered in chain order on every source, so
    /// anything at or below this position has already been applied.
    applied_position: (u64, u64),
    /// Opaque ledger cursor for resuming the transaction replay list;
    /// `None` until the first watermark arrives (replay then starts
    /// from `watermark_checkpoint`).
    watermark_cursor: Option<bytes::Bytes>,
}

impl Mirror {
    fn from_seed(seed: route::MirrorSeed) -> Self {
        Self {
            routing: seed.routing,
            index: seed.index,
            watermark_checkpoint: seed.floor,
            // The scrape reflects everything through the floor; skip any
            // replayed transaction at or before it.
            applied_position: (seed.floor, u64::MAX),
            watermark_cursor: None,
        }
    }
}

#[tracing::instrument(name = "state_watcher", skip_all)]
pub(super) async fn run(
    sui_rpc_url: String,
    state: OnchainState,
    seed: route::MirrorSeed,
    metrics: Option<std::sync::Arc<Metrics>>,
) {
    // The boot scrape seeded both the mirrored state and this
    // bookkeeping; `None` after a failed replay forces a re-bootstrap
    // from a fresh scrape.
    let mut mirror = Some(Mirror::from_seed(seed));
    loop {
        if let Err(e) =
            run_transactions(&sui_rpc_url, &state, &mut mirror, metrics.as_deref()).await
        {
            tracing::warn!("state watcher stream ended: {e:#}; reconnecting");
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

fn build_client(sui_rpc_url: &str, state: &OnchainState) -> Result<Client> {
    // A fresh client per attempt: re-subscribing on the same channel can
    // reuse a wedged h2 connection — the one whose stream just stalled —
    // and silently hang again.
    let mut client = Client::new(sui_rpc_url)?;
    if let Some(limit) = state.grpc_max_decoding_message_size() {
        client = client.with_max_decoding_message_size(limit);
    }
    Ok(client)
}

/// Re-bootstrap the mirror from a fresh scrape if a failed replay tore
/// it down. The scraped state is installed wholesale, so the local
/// limiter may have missed fully-signed transitions during the gap —
/// ask the reconcile loop to re-align it.
async fn ensure_bootstrapped(
    client: &Client,
    state: &OnchainState,
    mirror: &mut Option<Mirror>,
) -> Result<()> {
    if mirror.is_some() {
        return Ok(());
    }
    let (_, hashi, seed) = super::scrape_hashi(
        client.clone(),
        state.hashi_id(),
        state.package_id_original(),
    )
    .await?;
    tracing::info!(
        floor = seed.floor,
        objects = seed.index.len(),
        "object mirror re-bootstrapped from scrape"
    );
    state.replace_hashi_state(hashi);
    state.advance_state_watermark(seed.floor);
    *mirror = Some(Mirror::from_seed(seed));
    state.request_limiter_reconcile();
    Ok(())
}

fn require_mirror(mirror: &mut Option<Mirror>) -> Result<&mut Mirror> {
    mirror
        .as_mut()
        .ok_or_else(|| anyhow!("object mirror missing while frames are flowing"))
}

async fn run_transactions(
    sui_rpc_url: &str,
    state: &OnchainState,
    mirror: &mut Option<Mirror>,
    metrics: Option<&Metrics>,
) -> Result<()> {
    let mut client = build_client(sui_rpc_url, state)?;
    let filter = TransactionFilter::matching(tx_filter::affected_object(state.hashi_id()));

    let mut subscribe_request = SubscribeTransactionsRequest::default();
    subscribe_request.read_mask = Some(FieldMask::from_paths(TX_READ_MASK));
    subscribe_request.filter = Some(filter.clone());
    let mut subscription = client
        .subscription_client()
        .subscribe_transactions(subscribe_request)
        .await
        .context("subscribe_transactions failed")?
        .into_inner();

    // Wait for the first frame: it proves the stream is live. The
    // initial frame's watermark never carries `checkpoint` (verified
    // against testnet v1.76 — only later progress frames claim
    // coverage), so the replay target comes from the clock instead:
    // sampled after the subscription opened, the clock height
    // upper-bounds the subscription's start, and the position ratchet
    // absorbs the overlap between replay and stream.
    let first = tokio::time::timeout(STREAM_STALL_TIMEOUT, subscription.next())
        .await
        .context("timed out waiting for the first transaction frame")?
        .context("transaction stream closed before the first frame")??;
    ensure_bootstrapped(&client, state, mirror).await?;
    let target = state.latest_checkpoint_height();

    if let Err(e) = replay_transactions(&mut client, &filter, state, mirror, metrics, target).await
    {
        // A failed replay leaves an unknowable gap; rebuild.
        *mirror = None;
        return Err(e).context("transaction replay failed; object mirror reset");
    }
    tracing::info!(
        target,
        "object mirror caught up; consuming the filtered transaction stream"
    );

    handle_tx_frame(
        state,
        require_mirror(mirror)?,
        first.transaction.as_ref(),
        first.watermark.as_ref(),
        metrics,
    )
    .await?;
    loop {
        let item = tokio::time::timeout(STREAM_STALL_TIMEOUT, subscription.next())
            .await
            .context("transaction stream stalled")?;
        let response = item.context("transaction stream closed")??;
        handle_tx_frame(
            state,
            require_mirror(mirror)?,
            response.transaction.as_ref(),
            response.watermark.as_ref(),
            metrics,
        )
        .await?;
        // Coverage advances from the server's own watermark claims:
        // progress frames carry `Watermark.checkpoint` periodically
        // (observed every 25 checkpoints on quiet filters) — plus each
        // applied transaction's own checkpoint.
    }
}

/// Replay `ListTransactions` (same filter and mask as the
/// subscription) from the mirror's watermark until coverage reaches
/// `target` — the live stream's starting coverage point.
async fn replay_transactions(
    client: &mut Client,
    filter: &TransactionFilter,
    state: &OnchainState,
    mirror: &mut Option<Mirror>,
    metrics: Option<&Metrics>,
    target: u64,
) -> Result<()> {
    loop {
        let (cursor, floor) = {
            let mirror = require_mirror(mirror)?;
            (mirror.watermark_cursor.clone(), mirror.watermark_checkpoint)
        };
        if floor >= target {
            return Ok(());
        }
        let mut request = ListTransactionsRequest::default();
        request.read_mask = Some(FieldMask::from_paths(TX_READ_MASK));
        // The opaque cursor is authoritative once we have one; the
        // checkpoint floor covers the first pass after bootstrap.
        request.start_checkpoint = cursor.is_none().then_some(floor);
        request.filter = Some(filter.clone());
        request.options = cursor.map(|after| {
            let mut options = QueryOptions::default();
            options.after = Some(after);
            options
        });
        let response = client
            .ledger_client()
            .list_transactions(request)
            .await
            .context("list_transactions failed")?;
        // The response header carries the server's indexed checkpoint
        // height at request time — the coverage proof when watermark
        // checkpoints are unset.
        let indexed_height = response.checkpoint_height();
        let mut stream = response.into_inner();

        let mut end_reason = None;
        while let Some(item) = stream.next().await {
            let response = item.context("transaction replay stream errored")?;
            handle_tx_frame(
                state,
                require_mirror(mirror)?,
                response.transaction.as_ref(),
                response.watermark.as_ref(),
                metrics,
            )
            .await?;
            if let Some(end) = response.end.as_ref() {
                end_reason = end.reason.and_then(|r| QueryEndReason::try_from(r).ok());
            }
        }
        let reached = require_mirror(mirror)?.watermark_checkpoint;
        match end_reason {
            Some(QueryEndReason::LedgerTip) => {
                // LedgerTip means every matching transaction through
                // the indexed tip was delivered.
                if reached >= target {
                    return Ok(());
                }
                if let Some(height) = indexed_height
                    && height >= target
                {
                    advance_watermark(state, require_mirror(mirror)?, height);
                    return Ok(());
                }
                // The list index trails the live stream; give it a beat.
                tracing::debug!(target, ?indexed_height, "replay short of target; retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            // Item or scan limits: resume from the advanced cursor.
            Some(_) => {}
            None => anyhow::bail!("transaction replay stream ended without a QueryEnd frame"),
        }
    }
}

fn advance_watermark(state: &OnchainState, mirror: &mut Mirror, covered: u64) {
    mirror.watermark_checkpoint = mirror.watermark_checkpoint.max(covered);
    state.advance_state_watermark(mirror.watermark_checkpoint);
}

/// Handle one transaction-stream frame: apply the transaction (if the
/// frame carries one and the position ratchet hasn't passed it), then
/// fold in the watermark.
async fn handle_tx_frame(
    state: &OnchainState,
    mirror: &mut Mirror,
    tx: Option<&proto::ExecutedTransaction>,
    frame_watermark: Option<&proto::Watermark>,
    metrics: Option<&Metrics>,
) -> Result<()> {
    if let Some(tx) = tx {
        apply_tx_frame(state, mirror, tx, metrics).await?;
    }
    if let Some(watermark) = frame_watermark {
        if let Some(cursor) = watermark.cursor.as_ref() {
            mirror.watermark_cursor = Some(cursor.clone());
        }
        if let Some(checkpoint) = watermark.checkpoint {
            if tx.is_none() {
                tracing::debug!(checkpoint, "transaction stream coverage claim");
            }
            advance_watermark(state, mirror, checkpoint);
        }
    }
    Ok(())
}

/// Apply one filtered-stream transaction to the mirror, ratcheting on
/// its `(checkpoint, transaction_index)` position, then act on the
/// transition-derived effects.
async fn apply_tx_frame(
    state: &OnchainState,
    mirror: &mut Mirror,
    tx: &proto::ExecutedTransaction,
    metrics: Option<&Metrics>,
) -> Result<()> {
    let Some(view) = apply::TxView::from_proto(tx)? else {
        return Ok(());
    };
    if view.position() <= mirror.applied_position {
        tracing::debug!(position = ?view.position(), "skipping an already-applied transaction");
        return Ok(());
    }
    let out = {
        let mut guard = state.state_mut();
        apply::apply_transaction(
            &mut guard.hashi,
            &mut mirror.routing,
            &mut mirror.index,
            &view,
        )
    };
    for (id, type_) in &out.unrouted {
        tracing::warn!(object = %id, r#type = %type_, digest = tx.digest(),
            "object mirror could not route a changed object");
        if let Some(metrics) = metrics {
            metrics.watcher_unrouted_objects_total.inc();
        }
    }
    mirror.applied_position = view.position();
    // In-order delivery means everything before this transaction's
    // checkpoint has been delivered; its own checkpoint counts as
    // covered too, up to the same-burst stragglers documented on
    // `wait_until_checkpoint`.
    advance_watermark(state, mirror, view.checkpoint);
    if let Some(metrics) = metrics {
        metrics.watcher_applied_txns_total.inc();
    }
    handle_effects(state, view.timestamp_ms, out.effects).await;
    Ok(())
}

/// Act on the side effects one applied transaction derived from state
/// transitions. Replay re-derives the same effects in order, and the
/// apply layer's version guards make each transition fire exactly once
/// across replay/live overlap.
async fn handle_effects(state: &OnchainState, timestamp_ms: u64, effects: Vec<apply::Effect>) {
    for effect in effects {
        tracing::debug!(?effect, "object mirror effect");
        match effect {
            apply::Effect::ValidatorInfoUpdated(validator) => {
                state.notify(Notification::ValidatorInfoUpdated(validator));
            }
            apply::Effect::ReconfigStarted(epoch) => {
                state.notify(Notification::StartReconfig(epoch));
            }
            apply::Effect::PackageUpgraded { package } => {
                reconcile_package_versions(state, package).await;
            }
            apply::Effect::WithdrawalTxnFullySigned(txn) => {
                withdrawal_txn_fully_signed(state, timestamp_ms, &txn);
            }
            apply::Effect::WithdrawalTxnRemoved(txn) => {
                withdrawal_txn_removed(state, timestamp_ms, &txn);
            }
        }
    }
}

/// The root's `UpgradeCap` points at a new package: reconcile the
/// version map from `list_package_versions` (the cap's version counter
/// is not the package version). On failure the map goes stale until
/// the next upgrade or restart, so log loudly.
async fn reconcile_package_versions(state: &OnchainState, package: sui_sdk_types::Address) {
    let scrape = super::scrape_package_versions(state.client(), state.package_id_original());
    match tokio::time::timeout(PACKAGE_RECONCILE_TIMEOUT, scrape).await {
        Ok(Ok(versions)) => {
            tracing::info!(
                %package,
                versions = versions.len(),
                "package upgraded; version map reconciled"
            );
            state.set_package_versions(versions);
        }
        Ok(Err(e)) => {
            tracing::error!(%package, "failed to reconcile package versions after an upgrade: {e}");
        }
        Err(_) => {
            tracing::error!(%package, "timed out reconciling package versions after an upgrade");
        }
    }
}

/// A withdrawal transaction became fully signed (2-of-2 witness
/// complete): advance the local limiter and observe pick-to-sign.
///
/// The advance uses the applying transaction's checkpoint timestamp
/// (~sign time) rather than `txn.created_timestamp_ms` (creation time)
/// to stay in lockstep with the guardian's `last_updated_at`. The
/// apply layer emits this transition exactly once per signing (version
/// guards skip replayed and duplicated frames), so no additional
/// idempotency gate is needed.
fn withdrawal_txn_fully_signed(
    state: &OnchainState,
    timestamp_ms: u64,
    txn: &types::WithdrawalTransaction,
) {
    tracing::info!(withdrawal_txn_id = %txn.id, "Withdrawal signatures stored on-chain");
    state
        .state_mut()
        .withdrawal_signed_at_ms
        .insert(txn.id, timestamp_ms);
    if let Some(metrics) = state.metrics() {
        let pick_to_sign = timestamp_ms.saturating_sub(txn.created_timestamp_ms);
        metrics
            .withdrawal_duration_seconds
            .with_label_values(&["pick_to_sign"])
            .observe(Duration::from_millis(pick_to_sign).as_secs_f64());
    }

    let amount_sats = withdrawal_limiter_consumption_amount(txn);
    let timestamp_secs = timestamp_ms / 1000;
    let Some(limiter) = state.local_limiter() else {
        if let Some(metrics) = state.metrics() {
            metrics
                .guardian_limiter_apply_total
                .with_label_values(&[crate::metrics::GUARDIAN_LIMITER_OUTCOME_NO_LIMITER])
                .inc();
        }
        return;
    };
    let seq = limiter.next_seq();
    let result = limiter.apply_consume(seq, timestamp_secs, amount_sats);
    if let Some(metrics) = state.metrics() {
        metrics.record_limiter_apply(&result);
    }
    match &result {
        Ok(()) => {
            if let Some(metrics) = state.metrics() {
                metrics.guardian_limiter_anchor_events_total.inc();
                metrics.record_limiter_state(&limiter.snapshot(), limiter.config());
            }
            tracing::info!(
                seq,
                amount_sats,
                timestamp_secs,
                withdrawal_txn_id = %txn.id,
                "Local limiter advanced from the on-chain fully-signed transition",
            );
        }
        Err(e) => {
            if let Some(metrics) = state.metrics() {
                metrics.guardian_limiter_drifted.set(1);
            }
            tracing::error!(
                ?e,
                seq,
                withdrawal_txn_id = %txn.id,
                "Local limiter apply_consume failed; node is now drifted from guardian"
            );
        }
    }
}

/// A withdrawal transaction left the in-flight bag (confirmed and
/// moved to the historical record, or deleted): observe the
/// sign-to-confirm and total durations.
fn withdrawal_txn_removed(
    state: &OnchainState,
    timestamp_ms: u64,
    txn: &types::WithdrawalTransaction,
) {
    tracing::info!(withdrawal_txn_id = %txn.id, "Withdrawal transaction left the in-flight bag");
    let signed_at = state.state_mut().withdrawal_signed_at_ms.remove(&txn.id);
    let Some(metrics) = state.metrics() else {
        return;
    };
    if let Some(signed_at) = signed_at {
        let sign_to_confirm = timestamp_ms.saturating_sub(signed_at);
        metrics
            .withdrawal_duration_seconds
            .with_label_values(&["sign_to_confirm"])
            .observe(Duration::from_millis(sign_to_confirm).as_secs_f64());
    }
    let total = timestamp_ms.saturating_sub(txn.created_timestamp_ms);
    metrics
        .withdrawal_duration_seconds
        .with_label_values(&["total"])
        .observe(Duration::from_millis(total).as_secs_f64());
}
