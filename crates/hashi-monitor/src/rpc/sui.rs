// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::HashiEvent;
use hashi_types::move_types::PackageVersions;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::Event;
use sui_rpc::proto::sui::rpc::v2::ExecutedTransaction;
use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;
use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
use sui_rpc::proto::sui::rpc::v2::ListTransactionsRequest;
use sui_rpc::proto::sui::rpc::v2::Ordering;
use sui_rpc::proto::sui::rpc::v2::QueryEndReason;
use sui_rpc::proto::sui::rpc::v2::QueryOptions;
use sui_rpc::proto::sui::rpc::v2::TransactionFilter;
use sui_rpc::proto::sui::rpc::v2::filter::transaction as tx_filter;
use sui_sdk_types::Address;

use crate::config::SuiConfig;
use crate::domain::DepositEventType;
use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use crate::domain::utc_timestamp;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const PAGE_SIZE: u32 = 1_000;
const MIN_CHECKPOINTS_PER_RETRY: u64 = 25;
const MAX_RANGE_ATTEMPTS: u32 = 3;
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);

struct TransactionScan {
    transactions: Vec<ExecutedTransaction>,
    completed_checkpoint: Option<u64>,
    end_reason: QueryEndReason,
}

fn completed_checkpoint_for_scan(
    start_checkpoint: u64,
    end_checkpoint: u64,
    end_reason: QueryEndReason,
    watermark_checkpoint: Option<u64>,
) -> anyhow::Result<Option<u64>> {
    anyhow::ensure!(
        start_checkpoint < end_checkpoint,
        "empty Sui transaction checkpoint range"
    );
    let completed_checkpoint = match (end_reason, watermark_checkpoint) {
        (QueryEndReason::CheckpointBound, None) => {
            anyhow::bail!(
                "Sui transaction scan reached checkpoint bound {end_checkpoint} without a completion watermark"
            );
        }
        (QueryEndReason::LedgerTip, None) => return Ok(None),
        (_, Some(completed_checkpoint)) => completed_checkpoint,
        (end_reason, None) => {
            anyhow::bail!("unexpected Sui transaction scan end reason {end_reason:?}");
        }
    };
    anyhow::ensure!(
        completed_checkpoint < end_checkpoint,
        "Sui transaction scan watermark checkpoint {completed_checkpoint} is outside requested range ending at {end_checkpoint}"
    );
    if end_reason == QueryEndReason::CheckpointBound {
        anyhow::ensure!(
            completed_checkpoint == end_checkpoint - 1,
            "Sui transaction scan reached checkpoint bound {end_checkpoint} but only covered checkpoint {completed_checkpoint}"
        );
    }
    Ok((completed_checkpoint >= start_checkpoint).then_some(completed_checkpoint))
}

pub struct SuiEventsPoller {
    /// Sui v2 gRPC client used for checkpoint and transaction requests.
    client: sui_rpc::Client,
    /// Deployed package versions used to decode Hashi event BCS.
    package_versions: PackageVersions,
    /// Current Hashi package used to construct server-side transaction filters.
    package_id: String,
    /// Latest timestamp through which the poller has completely scanned transactions.
    cursor_seconds: UnixSeconds,
    /// First checkpoint not yet scanned, once the initial timestamp lookup completes.
    next_checkpoint_to_scan: Option<u64>,
    /// Checkpoint timestamps cached to avoid repeating `GetCheckpoint` requests.
    checkpoint_timestamps: BTreeMap<u64, UnixSeconds>,
    /// Most recently fetched chain head as `(sequence_number, timestamp_secs)`.
    observed_chain_head: Option<(u64, UnixSeconds)>,
}

impl SuiEventsPoller {
    pub fn new(config: &SuiConfig, start: UnixSeconds) -> anyhow::Result<Self> {
        let package_id = Address::from_str(&config.package_id)
            .with_context(|| format!("invalid Hashi package ID {}", config.package_id))?;

        let package_versions = PackageVersions::new(BTreeMap::from([(1, package_id)]));
        let client = sui_rpc::Client::new(&config.rpc_url)
            .with_context(|| format!("invalid Sui RPC URL {}", config.rpc_url))?
            .request_layer(tower::timeout::TimeoutLayer::new(REQUEST_TIMEOUT));

        Ok(Self {
            client,
            package_versions,
            package_id: config.package_id.clone(),
            cursor_seconds: start,
            next_checkpoint_to_scan: None,
            checkpoint_timestamps: BTreeMap::new(),
            observed_chain_head: None,
        })
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor_seconds
    }

    /// Scan through the checkpoint covering `up_to`, or the observed chain head.
    ///
    /// The timestamp cursor advances only through `watermark.checkpoint`, which
    /// is the inclusive boundary that `ListTransactions` reports as fully
    /// covered. Transactions provide the
    /// checkpoint timestamp needed by `DepositConfirmed`, while their nested
    /// events provide the Hashi payloads. The server stream handles its own item
    /// and scan limits with resumable cursors. A partial response caused by an
    /// RPC failure is discarded; that range is retried and may be split.
    pub async fn poll(&mut self, up_to: UnixSeconds) -> anyhow::Result<PollOutcome> {
        if up_to <= self.cursor_seconds {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let start_checkpoint = match self.next_checkpoint_to_scan {
            Some(checkpoint) => checkpoint,
            None => self
                .checkpoint_bracket(self.cursor_seconds)
                .await?
                .map(|(before, _)| before)
                .context("Sui does not yet have a checkpoint at the poll start time")?,
        };
        let (mut latest_sequence, mut latest_timestamp) = self
            .observed_chain_head
            .context("latest Sui checkpoint was not resolved")?;
        if start_checkpoint > latest_sequence {
            (latest_sequence, latest_timestamp) = self.refresh_chain_head().await?;
            if start_checkpoint > latest_sequence {
                return Ok(PollOutcome::CursorUnmoved);
            }
        }

        let mut end_checkpoint = if latest_timestamp < up_to {
            latest_sequence.saturating_add(1)
        } else {
            let (_, boundary) = self
                .checkpoint_bracket_from_head(up_to, (latest_sequence, latest_timestamp))
                .await?
                .context("Sui does not yet have a checkpoint at the poll end time")?;
            boundary.saturating_add(1)
        };
        if end_checkpoint <= start_checkpoint {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let mut range_attempt = 0u32;
        let scan = loop {
            match self
                .list_transactions_in_range(start_checkpoint, end_checkpoint)
                .await
            {
                Ok(transactions) => break transactions,
                Err(error) if range_attempt + 1 < MAX_RANGE_ATTEMPTS => {
                    let delay = INITIAL_RETRY_DELAY.saturating_mul(1 << range_attempt);
                    range_attempt += 1;
                    tracing::warn!(
                        start_checkpoint,
                        end_checkpoint,
                        range_attempt,
                        ?delay,
                        ?error,
                        "Sui transaction scan failed; retrying range"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(error) => {
                    let checkpoint_count = end_checkpoint.saturating_sub(start_checkpoint);
                    if checkpoint_count <= MIN_CHECKPOINTS_PER_RETRY {
                        return Err(error).context("Sui transaction scan failed after retries");
                    }
                    end_checkpoint = start_checkpoint + checkpoint_count / 2;
                    tracing::warn!(
                        start_checkpoint,
                        end_checkpoint,
                        ?error,
                        "Sui transaction scan failed after retries; retrying a smaller range"
                    );
                    range_attempt = 0;
                }
            }
        };

        let Some(completed_checkpoint) = completed_checkpoint_for_scan(
            start_checkpoint,
            end_checkpoint,
            scan.end_reason,
            scan.completed_checkpoint,
        )?
        else {
            return Ok(PollOutcome::CursorUnmoved);
        };

        let mut events = Vec::with_capacity(scan.transactions.len());
        for transaction in scan.transactions {
            let checkpoint = transaction
                .checkpoint
                .context("filtered Sui transaction is missing checkpoint")?;
            // A LedgerTip response can include transactions from a checkpoint
            // that its watermark does not yet declare complete. Leave those
            // transactions for the next poll so the checkpoint is ingested
            // atomically and cannot be skipped as indexing catches up.
            if checkpoint > completed_checkpoint {
                continue;
            }
            events.extend(self.parse_transaction(transaction)?);
        }

        self.next_checkpoint_to_scan = Some(completed_checkpoint.saturating_add(1));
        let scanned_through_timestamp = self.checkpoint_timestamp(completed_checkpoint).await?;
        self.cursor_seconds = self.cursor_seconds.max(scanned_through_timestamp);
        tracing::info!(
            start_checkpoint,
            end_checkpoint,
            completed_checkpoint,
            end_reason = ?scan.end_reason,
            cursor = %utc_timestamp(self.cursor_seconds),
            events = events.len(),
            "completed Sui event range"
        );
        Ok(PollOutcome::CursorAdvanced(events))
    }

    /// Find a safe checkpoint bracket `(before, at_or_after)` for a timestamp.
    ///
    /// Exponential probing finds a lower bound, then binary search resolves the
    /// exact adjacent checkpoint boundary. When a predecessor checkpoint exists,
    /// the lower bound is before the timestamp and the upper bound is at or after
    /// it. At or before genesis, both bounds are checkpoint zero.
    async fn checkpoint_bracket(
        &mut self,
        timestamp_secs: UnixSeconds,
    ) -> anyhow::Result<Option<(u64, u64)>> {
        let head = self.refresh_chain_head().await?;
        self.checkpoint_bracket_from_head(timestamp_secs, head)
            .await
    }

    async fn checkpoint_bracket_from_head(
        &mut self,
        timestamp_secs: UnixSeconds,
        (latest_sequence, latest_timestamp): (u64, UnixSeconds),
    ) -> anyhow::Result<Option<(u64, u64)>> {
        tracing::info!(
            target = %utc_timestamp(timestamp_secs),
            latest_checkpoint = latest_sequence,
            latest_timestamp = %utc_timestamp(latest_timestamp),
            "resolving Sui checkpoint boundary"
        );
        if latest_timestamp < timestamp_secs {
            return Ok(None);
        }

        let elapsed = latest_timestamp.saturating_sub(timestamp_secs);
        let mut distance = elapsed.saturating_mul(6).max(1);
        let mut low_sequence = loop {
            let probe = latest_sequence.saturating_sub(distance);
            let timestamp = self.checkpoint_timestamp(probe).await?;
            if timestamp < timestamp_secs {
                break probe;
            }
            if probe == 0 {
                return Ok(Some((0, 0)));
            }
            distance = distance.saturating_mul(2);
        };
        let mut high_sequence = latest_sequence;

        // Resolve the exact adjacent checkpoint boundary. A previously capped
        // interpolation could leave a very wide but technically safe bracket
        // for historical timestamps, forcing ListTransactions to scan many
        // unrelated checkpoint ranges. Binary search keeps the lookup
        // logarithmic even when checkpoint production has varied over time.
        while high_sequence > low_sequence.saturating_add(1) {
            let midpoint = low_sequence + (high_sequence - low_sequence) / 2;
            let midpoint_timestamp = self.checkpoint_timestamp(midpoint).await?;
            if midpoint_timestamp < timestamp_secs {
                low_sequence = midpoint;
            } else {
                high_sequence = midpoint;
            }
        }

        tracing::info!(
            target = %utc_timestamp(timestamp_secs),
            before_checkpoint = low_sequence,
            at_or_after_checkpoint = high_sequence,
            "resolved Sui checkpoint boundary"
        );
        Ok(Some((low_sequence, high_sequence)))
    }

    async fn refresh_chain_head(&mut self) -> anyhow::Result<(u64, UnixSeconds)> {
        let service_info = self
            .client
            .ledger_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await
            .context("failed to fetch Sui service info")?
            .into_inner();
        let sequence_number = service_info
            .checkpoint_height
            .context("Sui service info is missing checkpoint_height")?;
        let timestamp = service_info
            .timestamp
            .context("Sui service info is missing timestamp")?;
        let timestamp_ms =
            proto_to_timestamp_ms(timestamp).context("invalid Sui service info timestamp")?;
        let latest = (sequence_number, timestamp_ms / 1_000);
        self.checkpoint_timestamps.insert(latest.0, latest.1);
        self.observed_chain_head = Some(latest);
        Ok(latest)
    }

    async fn checkpoint_timestamp(&mut self, sequence_number: u64) -> anyhow::Result<UnixSeconds> {
        if let Some(timestamp) = self.checkpoint_timestamps.get(&sequence_number) {
            return Ok(*timestamp);
        }
        let (actual_sequence, timestamp) = self
            .get_checkpoint(GetCheckpointRequest::by_sequence_number(sequence_number))
            .await?;
        anyhow::ensure!(
            actual_sequence == sequence_number,
            "requested Sui checkpoint {sequence_number}, received {actual_sequence}"
        );
        self.checkpoint_timestamps
            .insert(sequence_number, timestamp);
        Ok(timestamp)
    }

    async fn get_checkpoint(
        &mut self,
        request: GetCheckpointRequest,
    ) -> anyhow::Result<(u64, UnixSeconds)> {
        let request = request.with_read_mask(FieldMask::from_paths([
            "sequence_number",
            "summary.timestamp",
        ]));
        let response = self
            .client
            .ledger_client()
            .get_checkpoint(request)
            .await
            .context("failed to fetch Sui checkpoint")?
            .into_inner();
        let checkpoint = response.checkpoint.context("missing Sui checkpoint")?;
        let (sequence_number, timestamp_secs) =
            Self::checkpoint_sequence_and_timestamp(checkpoint)?;
        self.checkpoint_timestamps
            .insert(sequence_number, timestamp_secs);
        Ok((sequence_number, timestamp_secs))
    }

    fn checkpoint_sequence_and_timestamp(
        checkpoint: Checkpoint,
    ) -> anyhow::Result<(u64, UnixSeconds)> {
        let sequence_number = checkpoint
            .sequence_number
            .context("Sui checkpoint is missing sequence_number")?;
        let timestamp = checkpoint
            .summary
            .and_then(|summary| summary.timestamp)
            .context("Sui checkpoint is missing summary.timestamp")?;
        let timestamp_ms =
            proto_to_timestamp_ms(timestamp).context("invalid Sui checkpoint timestamp")?;
        let timestamp_secs = timestamp_ms / 1_000;
        Ok((sequence_number, timestamp_secs))
    }

    async fn list_transactions_in_range(
        &mut self,
        start_checkpoint: u64,
        end_checkpoint: u64,
    ) -> anyhow::Result<TransactionScan> {
        if start_checkpoint >= end_checkpoint {
            anyhow::bail!("empty Sui transaction checkpoint range");
        }

        let filter = self.transaction_filter();
        let mut after = None;
        let mut all_transactions = Vec::new();
        let mut completed_checkpoint = None;
        tracing::info!(
            start_checkpoint,
            end_checkpoint,
            "starting Sui transaction scan"
        );

        loop {
            let mut options = QueryOptions::default()
                .with_limit(PAGE_SIZE)
                .with_ordering(Ordering::Ascending);
            if let Some(cursor) = after.clone() {
                options = options.with_after(cursor);
            }
            let request = ListTransactionsRequest::default()
                .with_read_mask(FieldMask::from_paths([
                    "timestamp",
                    "checkpoint",
                    "events.events.event_type",
                    "events.events.contents",
                ]))
                .with_start_checkpoint(start_checkpoint)
                .with_end_checkpoint(end_checkpoint)
                .with_filter(filter.clone())
                .with_options(options);

            let mut stream = self
                .client
                .ledger_client()
                .list_transactions(request)
                .await
                .context("failed to list Sui transactions")?
                .into_inner();
            let mut end_reason = None;
            let mut page_cursor = None;

            while let Some(frame) = stream.next().await {
                let frame = frame.context("Sui ListTransactions stream failed")?;
                let watermark = frame
                    .watermark
                    .as_ref()
                    .context("Sui ListTransactions frame is missing watermark")?;
                page_cursor = Some(
                    watermark
                        .cursor
                        .clone()
                        .context("Sui ListTransactions watermark is missing cursor")?,
                );
                if let Some(checkpoint) = watermark.checkpoint {
                    if let Some(current) = completed_checkpoint {
                        anyhow::ensure!(
                            checkpoint >= current,
                            "Sui ListTransactions checkpoint watermark regressed from {current} to {checkpoint}"
                        );
                    }
                    completed_checkpoint = Some(checkpoint);
                }
                if let Some(transaction) = frame.transaction {
                    all_transactions.push(transaction);
                }
                if let Some(end) = frame.end {
                    end_reason = end
                        .reason
                        .and_then(|reason| QueryEndReason::try_from(reason).ok());
                    break;
                }
            }

            let end_reason = end_reason.context("Sui ListTransactions ended without QueryEnd")?;
            match end_reason {
                QueryEndReason::CheckpointBound | QueryEndReason::LedgerTip => {
                    return Ok(TransactionScan {
                        transactions: all_transactions,
                        completed_checkpoint,
                        end_reason,
                    });
                }
                QueryEndReason::ItemLimit | QueryEndReason::ScanLimit => {
                    tracing::info!(
                        start_checkpoint,
                        end_checkpoint,
                        transactions = all_transactions.len(),
                        ?end_reason,
                        "Sui transaction scan progress"
                    );
                    let next = page_cursor.context(
                        "Sui ListTransactions reached a page limit without a resume cursor",
                    )?;
                    anyhow::ensure!(
                        after.as_ref() != Some(&next),
                        "Sui ListTransactions resume cursor did not advance"
                    );
                    after = Some(next);
                }
                reason => anyhow::bail!(
                    "Sui ListTransactions stopped before checkpoint {end_checkpoint}: {reason:?}"
                ),
            }
        }
    }

    fn transaction_filter(&self) -> TransactionFilter {
        let event_types = [
            format!(
                "{}::withdrawal_queue::WithdrawalPickedForProcessing",
                self.package_id
            ),
            format!("{}::deposit::DepositConfirmed", self.package_id),
        ];
        TransactionFilter::any(event_types.into_iter().map(tx_filter::event_type))
    }

    fn parse_transaction(
        &self,
        transaction: ExecutedTransaction,
    ) -> anyhow::Result<Vec<MonitorEvent>> {
        let timestamp = transaction
            .timestamp
            .context("Sui transaction is missing checkpoint timestamp")?;
        let timestamp_ms =
            proto_to_timestamp_ms(timestamp).context("invalid Sui transaction timestamp")?;
        let timestamp_secs = unix_millis_to_seconds(timestamp_ms);
        let events = transaction
            .events
            .context("filtered Sui transaction is missing events")?
            .events;

        let mut parsed = Vec::new();
        for event in events {
            if let Some(event) = self.parse_event(event, timestamp_secs)? {
                parsed.push(event);
            }
        }
        Ok(parsed)
    }

    fn parse_event(
        &self,
        event: Event,
        transaction_timestamp_secs: UnixSeconds,
    ) -> anyhow::Result<Option<MonitorEvent>> {
        let contents = event
            .contents
            .context("Sui event is missing BCS contents")?;
        let event = HashiEvent::try_parse(&self.package_versions, &contents)
            .context("failed to parse Hashi Sui event")?;

        Ok(match event {
            Some(HashiEvent::WithdrawalPickedForProcessing(event)) => {
                Some(MonitorEvent::Withdrawal(MonitorWithdrawalEvent {
                    event_type: WithdrawalEventType::E1HashiApproved,
                    wid: event.withdrawal_txn_id,
                    timestamp_secs: unix_millis_to_seconds(event.timestamp_ms),
                    btc_txid: event.txid.into(),
                }))
            }
            Some(HashiEvent::DepositConfirmed(event)) => {
                Some(MonitorEvent::Deposit(MonitorDepositEvent {
                    event_type: DepositEventType::E2HashiDeposited,
                    // DepositConfirmed has no timestamp in its Move payload.
                    // ListTransactions supplies the containing checkpoint's
                    // timestamp alongside the nested events.
                    timestamp_secs: transaction_timestamp_secs,
                    deposit_id: DepositId::new(event.utxo.id.txid.into(), event.utxo.id.vout),
                }))
            }
            Some(_) | None => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_tip_only_advances_through_watermark() {
        let completed =
            completed_checkpoint_for_scan(100, 111, QueryEndReason::LedgerTip, Some(109)).unwrap();

        assert_eq!(completed, Some(109));
    }

    #[test]
    fn ledger_tip_without_newly_completed_checkpoint_does_not_advance() {
        let completed =
            completed_checkpoint_for_scan(110, 111, QueryEndReason::LedgerTip, Some(109)).unwrap();

        assert_eq!(completed, None);
    }

    #[test]
    fn checkpoint_bound_requires_full_requested_coverage() {
        assert!(
            completed_checkpoint_for_scan(100, 111, QueryEndReason::CheckpointBound, None,)
                .is_err()
        );
        assert!(
            completed_checkpoint_for_scan(100, 111, QueryEndReason::CheckpointBound, Some(109),)
                .is_err()
        );
        assert_eq!(
            completed_checkpoint_for_scan(100, 111, QueryEndReason::CheckpointBound, Some(110),)
                .unwrap(),
            Some(110)
        );
    }
}
