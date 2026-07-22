// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shadow object mirror — the lossless watcher running alongside the
//! event-driven one, not yet load-bearing.
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
//! The transport requires a server that renders per-transaction object
//! sets on the filtered APIs (Sui v1.76 with the object-set fix).
//! Older servers are not supported: the stream fails and the watcher
//! keeps reconnecting rather than degrading to a lossy mode.

use std::sync::Arc;
use std::sync::Mutex;

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

use super::OnchainState;
use super::apply;
use super::route;
use super::types;

/// Reconnect if a stream goes silent this long. The filtered stream
/// emits watermark or cursor progress frames periodically even when
/// nothing matches the filter, so silence genuinely means a broken
/// stream.
const STREAM_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

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

/// The object-driven mirror plus the bookkeeping the transport needs.
pub(super) struct ShadowMirror {
    pub hashi: types::Hashi,
    pub routing: route::RoutingTable,
    pub index: route::ObjectIndex,
    /// Checkpoint through which the mirror is complete.
    pub watermark_checkpoint: u64,
    /// The last applied transaction's `(checkpoint, transaction_index)`.
    /// Transactions are delivered in chain order on every source, so
    /// anything at or below this position has already been applied.
    pub applied_position: (u64, u64),
    /// Opaque ledger cursor for resuming the transaction replay list;
    /// `None` until the first watermark arrives (replay then starts
    /// from `watermark_checkpoint`).
    pub watermark_cursor: Option<bytes::Bytes>,
}

/// `None` until the first bootstrap completes.
pub(super) type SharedShadow = Arc<Mutex<Option<ShadowMirror>>>;

#[tracing::instrument(name = "shadow_watcher", skip_all)]
pub(super) async fn run(
    sui_rpc_url: String,
    state: OnchainState,
    shadow: SharedShadow,
    metrics: Option<Arc<Metrics>>,
) {
    loop {
        if let Err(e) = run_transactions(&sui_rpc_url, &state, &shadow, metrics.as_deref()).await {
            tracing::warn!("shadow watcher stream ended: {e:#}; reconnecting");
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

fn build_client(sui_rpc_url: &str, state: &OnchainState) -> Result<Client> {
    // A fresh client per attempt, for the same wedged-h2 reason as the
    // legacy watcher.
    let mut client = Client::new(sui_rpc_url)?;
    if let Some(limit) = state.grpc_max_decoding_message_size() {
        client = client.with_max_decoding_message_size(limit);
    }
    Ok(client)
}

/// Bootstrap the mirror from a scrape if it isn't populated yet.
async fn ensure_bootstrapped(
    client: &Client,
    state: &OnchainState,
    shadow: &SharedShadow,
) -> Result<()> {
    if shadow.lock().unwrap().is_some() {
        return Ok(());
    }
    let (_, hashi, seed) = super::scrape_hashi(
        client.clone(),
        state.hashi_id(),
        state.package_id_original(),
    )
    .await?;
    let mirror = ShadowMirror {
        hashi,
        routing: seed.routing,
        index: seed.index,
        watermark_checkpoint: seed.floor,
        // The scrape reflects everything through the floor; skip any
        // replayed transaction at or before it.
        applied_position: (seed.floor, u64::MAX),
        watermark_cursor: None,
    };
    tracing::info!(
        floor = seed.floor,
        objects = mirror.index.len(),
        "shadow mirror bootstrapped from scrape"
    );
    *shadow.lock().unwrap() = Some(mirror);
    Ok(())
}

fn watermark(shadow: &SharedShadow) -> Result<u64> {
    shadow
        .lock()
        .unwrap()
        .as_ref()
        .map(|mirror| mirror.watermark_checkpoint)
        .ok_or_else(|| anyhow!("shadow mirror missing"))
}

// ---- transaction-granular transport -------------------------------------

async fn run_transactions(
    sui_rpc_url: &str,
    state: &OnchainState,
    shadow: &SharedShadow,
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
    ensure_bootstrapped(&client, state, shadow).await?;
    let target = state.latest_checkpoint_height();

    if let Err(e) = replay_transactions(&mut client, &filter, shadow, metrics, target).await {
        // A failed replay leaves an unknowable gap; rebuild.
        *shadow.lock().unwrap() = None;
        return Err(e).context("transaction replay failed; shadow mirror reset");
    }
    tracing::info!(
        target,
        "shadow mirror caught up; consuming the filtered transaction stream"
    );

    handle_tx_frame(
        shadow,
        first.transaction.as_ref(),
        first.watermark.as_ref(),
        metrics,
    )?;
    loop {
        let item = tokio::time::timeout(STREAM_STALL_TIMEOUT, subscription.next())
            .await
            .context("transaction stream stalled")?;
        let response = item.context("transaction stream closed")??;
        handle_tx_frame(
            shadow,
            response.transaction.as_ref(),
            response.watermark.as_ref(),
            metrics,
        )?;
        // Coverage advances from the server's own watermark claims:
        // progress frames carry `Watermark.checkpoint` periodically
        // (observed every 25 checkpoints on quiet filters); the initial
        // frame and transaction-bearing frames carry only the cursor.
    }
}

/// Replay `ListTransactions` (same filter and mask as the
/// subscription) from the mirror's watermark until coverage reaches
/// `target` — the live stream's starting coverage point.
async fn replay_transactions(
    client: &mut Client,
    filter: &TransactionFilter,
    shadow: &SharedShadow,
    metrics: Option<&Metrics>,
    target: u64,
) -> Result<()> {
    loop {
        let (cursor, floor) = {
            let guard = shadow.lock().unwrap();
            let mirror = guard
                .as_ref()
                .ok_or_else(|| anyhow!("shadow mirror missing during replay"))?;
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
                shadow,
                response.transaction.as_ref(),
                response.watermark.as_ref(),
                metrics,
            )?;
            if let Some(end) = response.end.as_ref() {
                end_reason = end.reason.and_then(|r| QueryEndReason::try_from(r).ok());
            }
        }
        match end_reason {
            Some(QueryEndReason::LedgerTip) => {
                // LedgerTip means every matching transaction through
                // the indexed tip was delivered.
                if watermark(shadow)? >= target {
                    return Ok(());
                }
                if let Some(height) = indexed_height
                    && height >= target
                {
                    advance_watermark(shadow, height, metrics);
                    return Ok(());
                }
                // The list index trails the live stream; give it a beat.
                tracing::debug!(target, ?indexed_height, "replay short of target; retrying");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            // Item or scan limits: resume from the advanced cursor.
            Some(_) => {}
            None => anyhow::bail!("transaction replay stream ended without a QueryEnd frame"),
        }
    }
}

/// Handle one transaction-stream frame: apply the transaction (if the
/// frame carries one and the position ratchet hasn't passed it), then
/// fold in the watermark.
fn handle_tx_frame(
    shadow: &SharedShadow,
    tx: Option<&proto::ExecutedTransaction>,
    frame_watermark: Option<&proto::Watermark>,
    metrics: Option<&Metrics>,
) -> Result<()> {
    if let Some(tx) = tx {
        apply_tx_frame(shadow, tx, metrics)?;
    }
    if let Some(watermark) = frame_watermark {
        if tx.is_none()
            && let Some(checkpoint) = watermark.checkpoint
        {
            tracing::debug!(checkpoint, "transaction stream coverage claim");
        }
        let mut guard = shadow.lock().unwrap();
        if let Some(mirror) = guard.as_mut() {
            if let Some(cursor) = watermark.cursor.as_ref() {
                mirror.watermark_cursor = Some(cursor.clone());
            }
            if let Some(checkpoint) = watermark.checkpoint {
                mirror.watermark_checkpoint = mirror.watermark_checkpoint.max(checkpoint);
            }
            if let Some(metrics) = metrics {
                metrics
                    .shadow_watermark_checkpoint
                    .set(mirror.watermark_checkpoint as i64);
            }
        }
    }
    Ok(())
}

/// Apply one filtered-stream transaction to the mirror, ratcheting on
/// its `(checkpoint, transaction_index)` position.
fn apply_tx_frame(
    shadow: &SharedShadow,
    tx: &proto::ExecutedTransaction,
    metrics: Option<&Metrics>,
) -> Result<()> {
    let Some(view) = apply::TxView::from_proto(tx)? else {
        return Ok(());
    };
    let mut guard = shadow.lock().unwrap();
    let mirror = guard
        .as_mut()
        .ok_or_else(|| anyhow!("shadow mirror missing while frames are flowing"))?;
    if view.position() <= mirror.applied_position {
        tracing::debug!(position = ?view.position(), "skipping an already-applied transaction");
        return Ok(());
    }
    let out = apply::apply_transaction(
        &mut mirror.hashi,
        &mut mirror.routing,
        &mut mirror.index,
        &view,
    );
    report_outcome(&out, tx.digest(), metrics);
    mirror.applied_position = view.position();
    // In-order delivery means everything before this transaction's
    // checkpoint has been delivered: coverage reaches the previous
    // checkpoint even when watermark checkpoints are unset.
    mirror.watermark_checkpoint = mirror
        .watermark_checkpoint
        .max(view.checkpoint.saturating_sub(1));
    if let Some(metrics) = metrics {
        metrics.shadow_applied_txns_total.inc();
    }
    Ok(())
}

fn advance_watermark(shadow: &SharedShadow, covered: u64, metrics: Option<&Metrics>) {
    let mut guard = shadow.lock().unwrap();
    let Some(mirror) = guard.as_mut() else {
        return;
    };
    mirror.watermark_checkpoint = mirror.watermark_checkpoint.max(covered);
    if let Some(metrics) = metrics {
        metrics
            .shadow_watermark_checkpoint
            .set(mirror.watermark_checkpoint as i64);
    }
}

/// Log and count an apply outcome's unrouted objects and effects.
fn report_outcome(out: &apply::ApplyOutcome, digest: &str, metrics: Option<&Metrics>) {
    for (id, type_) in &out.unrouted {
        tracing::warn!(object = %id, r#type = %type_, digest,
            "shadow mirror could not route a changed object");
        if let Some(metrics) = metrics {
            metrics.shadow_unrouted_objects_total.inc();
        }
    }
    for effect in &out.effects {
        tracing::debug!(?effect, "shadow mirror effect (shadow mode; not acted on)");
    }
}

/// Compare a freshly scraped mirror against the shadow. Returns `None`
/// when the shadow hasn't caught up to the scrape's height (comparison
/// would be noise), otherwise the list of divergent slots.
pub(super) fn compare_with_scrape(
    scraped: &types::Hashi,
    shadow: &ShadowMirror,
    scrape_height: u64,
) -> Option<Vec<String>> {
    if shadow.watermark_checkpoint < scrape_height {
        return None;
    }
    let mirror = &shadow.hashi;
    let mut diffs = Vec::new();

    diff_keys(
        "members",
        scraped.committees.members(),
        mirror.committees.members(),
        &mut diffs,
    );
    diff_keys(
        "committees",
        scraped.committees.committees(),
        mirror.committees.committees(),
        &mut diffs,
    );
    diff_keys(
        "committee_handoffs",
        scraped.committees.committee_handoffs(),
        mirror.committees.committee_handoffs(),
        &mut diffs,
    );
    diff_keys(
        "deposit_requests",
        scraped.deposit_queue.requests(),
        mirror.deposit_queue.requests(),
        &mut diffs,
    );
    diff_keys(
        "withdrawal_requests",
        scraped.withdrawal_queue.requests(),
        mirror.withdrawal_queue.requests(),
        &mut diffs,
    );
    diff_keys(
        "withdrawal_txns",
        scraped.withdrawal_queue.withdrawal_txns(),
        mirror.withdrawal_queue.withdrawal_txns(),
        &mut diffs,
    );
    for (id, scraped_txn) in scraped.withdrawal_queue.withdrawal_txns() {
        if let Some(mirror_txn) = mirror.withdrawal_queue.withdrawal_txns().get(id)
            && scraped_txn != mirror_txn
        {
            diffs.push(format!("withdrawal_txns[{id}] contents differ"));
        }
    }
    diff_keys(
        "utxo_records",
        scraped.utxo_pool.utxo_records(),
        mirror.utxo_pool.utxo_records(),
        &mut diffs,
    );
    for (id, scraped_record) in scraped.utxo_pool.utxo_records() {
        if let Some(mirror_record) = mirror.utxo_pool.utxo_records().get(id)
            && (scraped_record.spent_by != mirror_record.spent_by
                || scraped_record.spent_epoch != mirror_record.spent_epoch
                || scraped_record.produced_by != mirror_record.produced_by)
        {
            diffs.push(format!("utxo_records[{id:?}] lock state differs"));
        }
    }
    diff_keys(
        "spent_utxos",
        scraped.utxo_pool.spent_utxos(),
        mirror.utxo_pool.spent_utxos(),
        &mut diffs,
    );
    diff_keys(
        "treasury_caps",
        &scraped.treasury.treasury_caps,
        &mirror.treasury.treasury_caps,
        &mut diffs,
    );
    diff_keys(
        "proposals_active",
        scraped.proposals.active(),
        mirror.proposals.active(),
        &mut diffs,
    );
    diff_keys(
        "proposals_executed",
        scraped.proposals.executed(),
        mirror.proposals.executed(),
        &mut diffs,
    );

    if scraped.config != mirror.config {
        diffs.push("config differs".to_owned());
    }
    if scraped.num_consumed_presigs != mirror.num_consumed_presigs {
        diffs.push(format!(
            "num_consumed_presigs: scraped {} vs mirror {}",
            scraped.num_consumed_presigs, mirror.num_consumed_presigs
        ));
    }
    if scraped.committees.epoch() != mirror.committees.epoch() {
        diffs.push(format!(
            "epoch: scraped {} vs mirror {}",
            scraped.committees.epoch(),
            mirror.committees.epoch()
        ));
    }
    if scraped.committees.pending_epoch_change() != mirror.committees.pending_epoch_change() {
        diffs.push("pending_epoch_change differs".to_owned());
    }
    if scraped.committees.mpc_public_key() != mirror.committees.mpc_public_key() {
        diffs.push("mpc_public_key differs".to_owned());
    }

    Some(diffs)
}

/// Report keys present on one side but not the other.
fn diff_keys<K: Ord + std::fmt::Debug, A, B>(
    slot: &str,
    scraped: &std::collections::BTreeMap<K, A>,
    mirror: &std::collections::BTreeMap<K, B>,
    diffs: &mut Vec<String>,
) {
    for key in scraped.keys() {
        if !mirror.contains_key(key) {
            diffs.push(format!("{slot}: mirror is missing key {key:?}"));
        }
    }
    for key in mirror.keys() {
        if !scraped.contains_key(key) {
            diffs.push(format!("{slot}: mirror has extra key {key:?}"));
        }
    }
}
