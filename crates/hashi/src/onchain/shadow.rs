// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shadow object mirror — the lossless watcher running alongside the
//! event-driven one, not yet load-bearing.
//!
//! The transport is checkpoint-granular and filtered:
//! `SubscribeCheckpoints` with an `affected_object == hashi root`
//! filter delivers full payloads (including the checkpoint-level object
//! set) only for checkpoints containing a Hashi-touching transaction —
//! every other checkpoint arrives as a cursor-only progress frame, so
//! liveness and coverage remain continuously observable.
//! `ListCheckpoints` with the same filter replays any range the stream
//! missed, making reconnects gap-free without rescraping. Within a
//! matching checkpoint, only transactions whose effects touch the root
//! are applied (the Move audit established that every state-mutating
//! call takes `&mut Hashi`); everything else in the checkpoint is
//! skipped without touching the unrouted tripwire.
//!
//! Per-transaction object sets are not populated by the server as of
//! Sui v1.76 (`render_executed_transaction` builds the set internally
//! for effects rendering but never emits it), so the finer-grained
//! `SubscribeTransactions`/`ListTransactions` transport is not usable
//! yet; `TxView::from_proto` stays staged for it. On pre-1.76 servers
//! the subscription filter field is ignored (the stream is simply
//! unfiltered — same protocol, more traffic) and the replay API is
//! unimplemented, in which case a break falls back to re-bootstrapping
//! from a scrape.

use std::sync::Arc;
use std::sync::Mutex;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use futures::StreamExt;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2 as proto;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::ListCheckpointsRequest;
use sui_rpc::proto::sui::rpc::v2::QueryEndReason;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
use sui_rpc::proto::sui::rpc::v2::TransactionFilter;
use sui_rpc::proto::sui::rpc::v2::filter::transaction as tx_filter;

use crate::metrics::Metrics;

use super::OnchainState;
use super::apply;
use super::route;
use super::types;

/// Reconnect if the checkpoint stream goes silent this long. Progress
/// frames arrive for every checkpoint even when nothing matches the
/// filter, so silence genuinely means a broken stream.
const STREAM_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Read mask for the checkpoint stream and the replay list.
const CHECKPOINT_READ_MASK: [&str; 6] = [
    "sequence_number",
    "summary.timestamp",
    "transactions.digest",
    "transactions.effects.status",
    "transactions.effects.changed_objects",
    "objects.objects.bcs",
];

/// The object-driven mirror plus the bookkeeping the transport needs.
pub(super) struct ShadowMirror {
    pub hashi: types::Hashi,
    pub routing: route::RoutingTable,
    pub index: route::ObjectIndex,
    /// Checkpoint through which the mirror is complete.
    pub watermark_checkpoint: u64,
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
        if let Err(e) = run_once(&sui_rpc_url, &state, &shadow, metrics.as_deref()).await {
            tracing::warn!("shadow watcher stream ended: {e:#}; reconnecting");
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

async fn run_once(
    sui_rpc_url: &str,
    state: &OnchainState,
    shadow: &SharedShadow,
    metrics: Option<&Metrics>,
) -> Result<()> {
    // A fresh client per attempt, for the same wedged-h2 reason as the
    // legacy watcher.
    let mut client = Client::new(sui_rpc_url)?;
    if let Some(limit) = state.grpc_max_decoding_message_size() {
        client = client.with_max_decoding_message_size(limit);
    }

    let filter = TransactionFilter::matching(tx_filter::affected_object(state.hashi_id()));
    let mut subscribe_request = SubscribeCheckpointsRequest::default()
        .with_read_mask(FieldMask::from_paths(CHECKPOINT_READ_MASK));
    subscribe_request.filter = Some(filter.clone());
    let mut subscription = client
        .subscription_client()
        .subscribe_checkpoints(subscribe_request)
        .await
        .context("subscribe_checkpoints failed")?
        .into_inner();

    // The first frame bounds the replay: everything before its cursor
    // comes from the list, everything from it onward from this stream.
    let first = tokio::time::timeout(STREAM_STALL_TIMEOUT, subscription.next())
        .await
        .context("timed out waiting for the first checkpoint frame")?
        .context("checkpoint stream closed before the first frame")??;
    let first_cursor = first.cursor();

    ensure_bootstrapped(&client, state, shadow).await?;

    match replay(&mut client, &filter, shadow, metrics, first_cursor).await {
        Ok(()) => {}
        Err(e) if is_unimplemented(&e) => {
            // Pre-1.76 server: no filtered list replay. The scrape must
            // then be provably fresh relative to the stream start, or
            // the mirror is rebuilt.
            let floor = watermark(shadow)?;
            if floor < first_cursor {
                *shadow.lock().unwrap() = None;
                anyhow::bail!(
                    "no replay API and the scrape floor {floor} is behind the stream \
                     start {first_cursor}; re-bootstrapping"
                );
            }
            tracing::debug!(
                "checkpoint replay unavailable (pre-1.76 server); relying on scrape freshness"
            );
        }
        Err(e) => {
            // A failed replay leaves an unknowable gap; rebuild.
            *shadow.lock().unwrap() = None;
            return Err(e).context("replay failed; shadow mirror reset for re-bootstrap");
        }
    }

    tracing::info!(
        first_cursor,
        "shadow mirror caught up; consuming the filtered checkpoint stream"
    );

    handle_frame(shadow, first.checkpoint.as_ref(), first_cursor, metrics)?;
    let mut last_cursor = first_cursor;
    loop {
        let item = tokio::time::timeout(STREAM_STALL_TIMEOUT, subscription.next())
            .await
            .context("checkpoint stream stalled")?;
        let response = item.context("checkpoint stream closed")??;
        let cursor = response.cursor();
        // gRPC streams deliver in order without loss, so a cursor jump
        // means the skipped checkpoints matched nothing; only a
        // backward cursor indicates a broken server.
        anyhow::ensure!(
            cursor > last_cursor,
            "checkpoint cursor moved backward: {cursor} after {last_cursor}"
        );
        handle_frame(shadow, response.checkpoint.as_ref(), cursor, metrics)?;
        last_cursor = cursor;
    }
}

/// True when the error chain bottoms out in a gRPC `Unimplemented`
/// status — the server predates the filtered list APIs.
fn is_unimplemented(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<tonic::Status>())
        .any(|status| status.code() == tonic::Code::Unimplemented)
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

/// Replay matching checkpoints from the mirror's watermark until
/// coverage reaches `target` (exclusive) — the live stream's first
/// cursor.
async fn replay(
    client: &mut Client,
    filter: &TransactionFilter,
    shadow: &SharedShadow,
    metrics: Option<&Metrics>,
    target: u64,
) -> Result<()> {
    loop {
        let from = watermark(shadow)?;
        if from + 1 >= target {
            return Ok(());
        }
        let mut request = ListCheckpointsRequest::default();
        request.read_mask = Some(FieldMask::from_paths(CHECKPOINT_READ_MASK));
        // Start at the watermark itself: re-covering the boundary
        // checkpoint is idempotent, and the u64 bound avoids carrying
        // an opaque cursor across reconnects.
        request.start_checkpoint = Some(from);
        request.end_checkpoint = Some(target);
        request.filter = Some(filter.clone());
        let mut stream = client
            .ledger_client()
            .list_checkpoints(request)
            .await
            .context("list_checkpoints failed")?
            .into_inner();

        let mut end_reason = None;
        while let Some(item) = stream.next().await {
            let response = item.context("replay stream errored")?;
            if let Some(checkpoint) = response.checkpoint.as_ref() {
                let cursor = checkpoint.sequence_number();
                apply_checkpoint_frame(shadow, Some(checkpoint), cursor, metrics)?;
            }
            if let Some(watermark) = response.watermark.as_ref()
                && let Some(covered) = watermark.checkpoint
            {
                advance_watermark(shadow, covered, metrics);
            }
            if let Some(end) = response.end.as_ref() {
                end_reason = end.reason.and_then(|r| QueryEndReason::try_from(r).ok());
            }
        }
        let reached = watermark(shadow)?;
        match end_reason {
            // The requested bound was reached, or the indexed tip
            // already covers the target.
            Some(QueryEndReason::CheckpointBound) => return Ok(()),
            Some(QueryEndReason::LedgerTip) if reached + 1 >= target => return Ok(()),
            Some(QueryEndReason::LedgerTip) => {
                // The list index trails the live stream; give it a beat.
                tracing::debug!(reached, target, "replay at indexed tip but short of target");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            // Item or scan limits: resume from the advanced watermark.
            Some(_) => {}
            None => anyhow::bail!("replay stream ended without a QueryEnd frame"),
        }
    }
}

/// Handle one subscription frame: a payload checkpoint is applied, a
/// cursor-only progress frame just advances coverage (nothing in that
/// checkpoint matched the filter).
fn handle_frame(
    shadow: &SharedShadow,
    checkpoint: Option<&Checkpoint>,
    cursor: u64,
    metrics: Option<&Metrics>,
) -> Result<()> {
    match checkpoint {
        Some(checkpoint) => apply_checkpoint_frame(shadow, Some(checkpoint), cursor, metrics),
        None => {
            advance_watermark(shadow, cursor, metrics);
            Ok(())
        }
    }
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

/// True when the transaction's effects include a change to the Hashi
/// root — the sound and complete signal for "this transaction mutated
/// bridge state" (every mutating Move entry point takes `&mut Hashi`).
fn touches_root(tx: &proto::ExecutedTransaction, root: &str) -> bool {
    tx.effects.as_ref().is_some_and(|effects| {
        effects
            .changed_objects
            .iter()
            .any(|c| c.object_id() == root)
    })
}

/// Apply one checkpoint's Hashi-touching transactions to the mirror.
fn apply_checkpoint_frame(
    shadow: &SharedShadow,
    checkpoint: Option<&Checkpoint>,
    cursor: u64,
    metrics: Option<&Metrics>,
) -> Result<()> {
    let Some(checkpoint) = checkpoint else {
        anyhow::bail!("checkpoint frame {cursor} carried no checkpoint payload");
    };
    let timestamp_ms = checkpoint
        .summary()
        .timestamp
        .and_then(|t| proto_to_timestamp_ms(t).ok())
        .unwrap_or(0);
    let mut pool = apply::decode_object_pool(checkpoint.objects.as_ref())?;

    let mut guard = shadow.lock().unwrap();
    let mirror = guard
        .as_mut()
        .ok_or_else(|| anyhow!("shadow mirror missing while frames are flowing"))?;
    let root = mirror.routing.hashi_id().to_string();

    for tx in checkpoint.transactions() {
        // A matching checkpoint (and every checkpoint on an unfiltered
        // pre-1.76 server) also carries unrelated transactions; only
        // root-touching ones belong to the mirror.
        if !touches_root(tx, &root) {
            continue;
        }
        // Per-transaction object sets, if the server chose to populate
        // them instead of the checkpoint-level set, layer into the pool.
        if let Some(set) = tx.objects.as_ref() {
            pool.extend(apply::decode_object_pool(Some(set))?);
        }
        let Some(view) = apply::TxView::from_pool(tx, &mut pool, cursor, timestamp_ms)? else {
            continue;
        };
        let out = apply::apply_transaction(
            &mut mirror.hashi,
            &mut mirror.routing,
            &mut mirror.index,
            &view,
        );
        report_outcome(&out, tx.digest(), metrics);
        if let Some(metrics) = metrics {
            metrics.shadow_applied_txns_total.inc();
        }
    }

    mirror.watermark_checkpoint = mirror.watermark_checkpoint.max(cursor);
    if let Some(metrics) = metrics {
        metrics
            .shadow_watermark_checkpoint
            .set(mirror.watermark_checkpoint as i64);
    }
    Ok(())
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
