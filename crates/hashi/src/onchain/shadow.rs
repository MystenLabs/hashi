// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shadow object mirror — the lossless watcher running alongside the
//! event-driven one, not yet load-bearing.
//!
//! The shadow consumes the checkpoint subscription with the
//! checkpoint-level object set and applies every successful
//! transaction's changed objects through [`super::apply`], so mirror
//! correctness does not depend on events. Gap detection is checkpoint
//! sequence continuity; recovery from any break is a re-bootstrap from
//! scrape (the same guarantee as the legacy reconnect rescrape).
//!
//! Once the filtered `SubscribeTransactions` / `ListTransactions` APIs
//! are live server-side (Sui v1.76), this transport switches to the
//! filtered stream with watermark-cursor replay and the re-bootstrap
//! demotes to a fallback; the apply/route layers are unchanged by that
//! swap.

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
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

use crate::metrics::Metrics;

use super::OnchainState;
use super::apply;
use super::route;
use super::types;

/// Reconnect if the checkpoint stream goes silent this long; same
/// rationale as the legacy watcher's stall timeout.
const STREAM_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

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
            tracing::warn!("shadow watcher stream ended: {e:#}; re-bootstrapping");
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

    let read_mask = FieldMask::from_paths([
        "sequence_number",
        "summary.timestamp",
        "transactions.digest",
        "transactions.effects.status",
        "transactions.effects.changed_objects",
        "objects.objects.bcs",
    ]);
    let mut subscription = client
        .subscription_client()
        .subscribe_checkpoints(SubscribeCheckpointsRequest::default().with_read_mask(read_mask))
        .await?
        .into_inner();

    // Read the first frame before scraping so the scrape's freshness
    // can be checked against the subscription's start: a scrape page
    // served behind the first delivered checkpoint could hide writes
    // that the buffered frames don't cover either.
    let first = tokio::time::timeout(STREAM_STALL_TIMEOUT, subscription.next())
        .await
        .context("timed out waiting for the first checkpoint frame")?
        .context("checkpoint stream closed before the first frame")??;
    let first_cursor = first.cursor();

    let (_, hashi, seed) = super::scrape_hashi(
        client.clone(),
        state.hashi_id(),
        state.package_id_original(),
    )
    .await?;
    if seed.floor < first_cursor {
        anyhow::bail!(
            "scrape floor {} is behind the subscription start {first_cursor}; \
             a lagging fullnode served part of the scrape — retrying",
            seed.floor
        );
    }
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

    // The buffered first frame is older than the scrape; version guards
    // make re-applying it a no-op where the scrape already caught up.
    apply_checkpoint_frame(shadow, first.checkpoint.as_ref(), first_cursor, metrics)?;
    let mut next_expected = first_cursor + 1;

    loop {
        let item = tokio::time::timeout(STREAM_STALL_TIMEOUT, subscription.next())
            .await
            .context("checkpoint stream stalled")?;
        let response = item.context("checkpoint stream closed")??;
        let cursor = response.cursor();
        if cursor != next_expected {
            anyhow::bail!(
                "checkpoint stream gap: expected {next_expected}, got {cursor}; \
                 the mirror can no longer be lossless without a replay"
            );
        }
        apply_checkpoint_frame(shadow, response.checkpoint.as_ref(), cursor, metrics)?;
        next_expected = cursor + 1;
    }
}

/// Apply one checkpoint's transactions to the shadow mirror.
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

    for tx in checkpoint.transactions() {
        // Per-transaction object sets, if the server chose to populate
        // them instead of the checkpoint-level set, layer into the pool.
        if let Some(set) = tx.objects.as_ref() {
            pool.extend(apply::decode_object_pool(Some(set))?);
        }
        let Some(view) = apply::TxView::from_pool(tx, &mut pool, cursor, timestamp_ms)? else {
            continue;
        };
        if view.changes.is_empty() {
            continue;
        }
        let out = apply::apply_transaction(
            &mut mirror.hashi,
            &mut mirror.routing,
            &mut mirror.index,
            &view,
        );
        for (id, type_) in &out.unrouted {
            tracing::warn!(object = %id, r#type = %type_, digest = tx.digest(),
                "shadow mirror could not route a changed object");
            if let Some(metrics) = metrics {
                metrics.shadow_unrouted_objects_total.inc();
            }
        }
        for effect in &out.effects {
            tracing::debug!(?effect, "shadow mirror effect (shadow mode; not acted on)");
        }
        if let Some(metrics) = metrics {
            metrics.shadow_applied_txns_total.inc();
        }
    }

    mirror.watermark_checkpoint = cursor;
    if let Some(metrics) = metrics {
        metrics.shadow_watermark_checkpoint.set(cursor as i64);
    }
    Ok(())
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
