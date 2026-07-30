// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::move_types::HashiEvent;
use hashi_types::move_types::PackageVersions;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::Event;
use sui_rpc::proto::sui::rpc::v2::EventFilter;
use sui_rpc::proto::sui::rpc::v2::EventLiteral;
use sui_rpc::proto::sui::rpc::v2::EventTerm;
use sui_rpc::proto::sui::rpc::v2::EventTypeFilter;
use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;
use sui_rpc::proto::sui::rpc::v2::ListEventsRequest;
use sui_rpc::proto::sui::rpc::v2::Ordering;
use sui_rpc::proto::sui::rpc::v2::QueryEndReason;
use sui_rpc::proto::sui::rpc::v2::QueryOptions;
use sui_sdk_types::Address;

use crate::config::SuiConfig;
use crate::domain::DepositEventType;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const PAGE_SIZE: u32 = 1_000;
// Dense testnet checkpoints can carry hundreds of matching events. Keeping the
// range small avoids the public fullnode's shorter server-side query deadline.
const MAX_CHECKPOINTS_PER_POLL: u64 = 200;
const MIN_CHECKPOINTS_PER_POLL: u64 = 25;

pub struct SuiEventsPoller {
    client: sui_rpc::Client,
    package_versions: PackageVersions,
    package_id: String,
    cursor_seconds: UnixSeconds,
    next_checkpoint: Option<u64>,
    checkpoint_timestamps: BTreeMap<u64, UnixSeconds>,
    latest_checkpoint: Option<(u64, UnixSeconds)>,
}

impl SuiEventsPoller {
    pub fn new(config: &SuiConfig, start: UnixSeconds) -> anyhow::Result<Self> {
        let package_id = Address::from_str(&config.package_id)
            .with_context(|| format!("invalid Hashi package ID {}", config.package_id))?;
        Address::from_str(&config.hashi_object_id)
            .with_context(|| format!("invalid Hashi object ID {}", config.hashi_object_id))?;

        let package_versions = PackageVersions::new(BTreeMap::from([(1, package_id)]));
        let client = sui_rpc::Client::new(&config.rpc_url)
            .with_context(|| format!("invalid Sui RPC URL {}", config.rpc_url))?
            .request_layer(tower::timeout::TimeoutLayer::new(REQUEST_TIMEOUT));

        Ok(Self {
            client,
            package_versions,
            package_id: config.package_id.clone(),
            cursor_seconds: start,
            next_checkpoint: None,
            checkpoint_timestamps: BTreeMap::new(),
            latest_checkpoint: None,
        })
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor_seconds
    }

    /// Scan a bounded checkpoint chunk, stopping at `up_to`.
    ///
    /// The timestamp cursor advances only after `ListEvents` reports that the
    /// complete checkpoint range was scanned. A partial response is discarded
    /// and retried on the next poll.
    pub async fn poll(&mut self, up_to: UnixSeconds) -> anyhow::Result<PollOutcome> {
        if up_to <= self.cursor_seconds {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let start_checkpoint = match self.next_checkpoint {
            Some(checkpoint) => checkpoint,
            None => self
                .checkpoint_bracket(self.cursor_seconds)
                .await?
                .map(|(before, _)| before)
                .context("Sui does not yet have a checkpoint at the poll start time")?,
        };
        let (mut latest_sequence, _) = self
            .latest_checkpoint
            .context("latest Sui checkpoint was not resolved")?;
        if start_checkpoint > latest_sequence {
            latest_sequence = self.refresh_latest_checkpoint().await?.0;
            if start_checkpoint > latest_sequence {
                return Ok(PollOutcome::CursorUnmoved);
            }
        }

        let mut end_checkpoint = start_checkpoint
            .saturating_add(MAX_CHECKPOINTS_PER_POLL)
            .min(latest_sequence.saturating_add(1));
        let mut scanned_through = end_checkpoint
            .checked_sub(1)
            .context("empty Sui checkpoint range")?;
        let mut scanned_through_timestamp = self.checkpoint_timestamp(scanned_through).await?;

        if scanned_through_timestamp > up_to {
            let Some((_, boundary)) = self.checkpoint_bracket(up_to).await? else {
                return Ok(PollOutcome::CursorUnmoved);
            };
            end_checkpoint = boundary
                .saturating_add(1)
                .min(latest_sequence.saturating_add(1));
            scanned_through = end_checkpoint
                .checked_sub(1)
                .context("empty Sui checkpoint range")?;
            scanned_through_timestamp = self.checkpoint_timestamp(scanned_through).await?;
        }
        if end_checkpoint <= start_checkpoint {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let mut retry_same_range = true;
        let raw_events = loop {
            match self
                .list_events_in_range(start_checkpoint, end_checkpoint)
                .await
            {
                Ok(events) => break events,
                Err(error) if retry_same_range => {
                    tracing::warn!(
                        start_checkpoint,
                        end_checkpoint,
                        ?error,
                        "Sui event scan failed; retrying range"
                    );
                    retry_same_range = false;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => {
                    let checkpoint_count = end_checkpoint.saturating_sub(start_checkpoint);
                    if checkpoint_count <= MIN_CHECKPOINTS_PER_POLL {
                        return Err(error).context("Sui event scan failed after retries");
                    }
                    end_checkpoint = start_checkpoint + checkpoint_count / 2;
                    scanned_through = end_checkpoint
                        .checked_sub(1)
                        .context("empty Sui checkpoint range after retry split")?;
                    scanned_through_timestamp = self.checkpoint_timestamp(scanned_through).await?;
                    tracing::warn!(
                        start_checkpoint,
                        end_checkpoint,
                        ?error,
                        "Sui event scan failed twice; retrying a smaller range"
                    );
                    retry_same_range = true;
                }
            }
        };
        let mut events = Vec::with_capacity(raw_events.len());
        for event in raw_events {
            if let Some(event) = self.parse_event(event).await? {
                events.push(event);
            }
        }

        self.next_checkpoint = Some(end_checkpoint);
        self.cursor_seconds = self.cursor_seconds.max(scanned_through_timestamp);
        tracing::info!(
            start_checkpoint,
            end_checkpoint,
            cursor = self.cursor_seconds,
            events = events.len(),
            "completed Sui event range"
        );
        Ok(PollOutcome::CursorAdvanced(events))
    }

    /// Find a safe checkpoint bracket `(before, at_or_after)` for a timestamp.
    ///
    /// A few interpolation probes keep this well below public fullnode rate
    /// limits. The returned lower bound is known to be before the timestamp and
    /// the upper bound is known to be at or after it; callers may scan the
    /// slightly wider interval without risking an event gap.
    async fn checkpoint_bracket(
        &mut self,
        timestamp_secs: UnixSeconds,
    ) -> anyhow::Result<Option<(u64, u64)>> {
        let (latest_sequence, latest_timestamp) = self.refresh_latest_checkpoint().await?;
        if latest_timestamp < timestamp_secs {
            return Ok(None);
        }

        let elapsed = latest_timestamp.saturating_sub(timestamp_secs);
        let mut distance = elapsed.saturating_mul(6).max(1);
        let (mut low_sequence, mut low_timestamp) = loop {
            let probe = latest_sequence.saturating_sub(distance);
            let timestamp = self.checkpoint_timestamp(probe).await?;
            if timestamp < timestamp_secs {
                break (probe, timestamp);
            }
            if probe == 0 {
                return Ok(Some((0, 0)));
            }
            distance = distance.saturating_mul(2);
        };
        let mut high_sequence = latest_sequence;
        let mut high_timestamp = latest_timestamp;

        // Interpolation converges rapidly because recent checkpoint production
        // is close to linear. A fixed cap bounds RPC usage; an inexact bracket
        // merely scans a few additional checkpoints.
        for _ in 0..6 {
            if high_sequence <= low_sequence + 1 {
                break;
            }
            let sequence_span = high_sequence - low_sequence;
            let timestamp_span = high_timestamp.saturating_sub(low_timestamp);
            let estimate = if timestamp_span == 0 {
                low_sequence + sequence_span / 2
            } else {
                let target_offset = timestamp_secs.saturating_sub(low_timestamp);
                let interpolated = (u128::from(sequence_span) * u128::from(target_offset)
                    / u128::from(timestamp_span)) as u64;
                low_sequence.saturating_add(interpolated)
            }
            .clamp(low_sequence + 1, high_sequence - 1);
            let estimate_timestamp = self.checkpoint_timestamp(estimate).await?;
            if estimate_timestamp < timestamp_secs {
                low_sequence = estimate;
                low_timestamp = estimate_timestamp;
            } else {
                high_sequence = estimate;
                high_timestamp = estimate_timestamp;
            }
        }

        Ok(Some((low_sequence, high_sequence)))
    }

    async fn refresh_latest_checkpoint(&mut self) -> anyhow::Result<(u64, UnixSeconds)> {
        let latest = self.get_checkpoint(GetCheckpointRequest::latest()).await?;
        self.latest_checkpoint = Some(latest);
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
        self.checkpoint_timestamps
            .insert(sequence_number, timestamp_secs);
        Ok((sequence_number, timestamp_secs))
    }

    async fn list_events_in_range(
        &mut self,
        start_checkpoint: u64,
        end_checkpoint: u64,
    ) -> anyhow::Result<Vec<Event>> {
        if start_checkpoint >= end_checkpoint {
            return Ok(Vec::new());
        }

        let filter = self.event_filter();
        let mut after = None;
        let mut all_events = Vec::new();

        loop {
            let mut options = QueryOptions::default()
                .with_limit(PAGE_SIZE)
                .with_ordering(Ordering::Ascending);
            if let Some(cursor) = after.clone() {
                options = options.with_after(cursor);
            }
            let request = ListEventsRequest::default()
                .with_read_mask(FieldMask::from_paths([
                    "event_type",
                    "contents",
                    "checkpoint",
                ]))
                .with_start_checkpoint(start_checkpoint)
                .with_end_checkpoint(end_checkpoint)
                .with_filter(filter.clone())
                .with_options(options);

            let mut stream = self
                .client
                .ledger_client()
                .list_events(request)
                .await
                .context("failed to list Sui events")?
                .into_inner();
            let mut end_reason = None;
            let mut page_cursor = None;

            while let Some(frame) = stream.next().await {
                let frame = frame.context("Sui ListEvents stream failed")?;
                if let Some(watermark) = &frame.watermark
                    && let Some(cursor) = watermark.cursor.clone()
                {
                    page_cursor = Some(cursor);
                }
                if let Some(event) = frame.event {
                    all_events.push(event);
                }
                if let Some(end) = frame.end {
                    end_reason = end
                        .reason
                        .and_then(|reason| QueryEndReason::try_from(reason).ok());
                    break;
                }
            }

            match end_reason.context("Sui ListEvents ended without QueryEnd")? {
                QueryEndReason::CheckpointBound => return Ok(all_events),
                QueryEndReason::ItemLimit | QueryEndReason::ScanLimit => {
                    let next = page_cursor
                        .context("Sui ListEvents reached a page limit without a resume cursor")?;
                    anyhow::ensure!(
                        after.as_ref() != Some(&next),
                        "Sui ListEvents resume cursor did not advance"
                    );
                    after = Some(next);
                }
                reason => anyhow::bail!(
                    "Sui ListEvents stopped before checkpoint {end_checkpoint}: {reason:?}"
                ),
            }
        }
    }

    fn event_filter(&self) -> EventFilter {
        let event_types = [
            format!(
                "{}::withdrawal_queue::WithdrawalPickedForProcessing",
                self.package_id
            ),
            format!("{}::deposit::DepositConfirmed", self.package_id),
        ];
        EventFilter::default().with_terms(
            event_types
                .into_iter()
                .map(|event_type| {
                    EventTerm::default().with_literals(vec![
                        EventLiteral::default().with_event_type(
                            EventTypeFilter::default().with_event_type(event_type),
                        ),
                    ])
                })
                .collect(),
        )
    }

    async fn parse_event(&mut self, event: Event) -> anyhow::Result<Option<MonitorEvent>> {
        let checkpoint = event
            .checkpoint
            .context("Sui event is missing its checkpoint")?;
        let timestamp_secs = self.checkpoint_timestamp(checkpoint).await?;
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
                    timestamp_secs,
                    btc_txid: event.txid.into(),
                }))
            }
            Some(HashiEvent::DepositConfirmed(event)) => {
                Some(MonitorEvent::Deposit(MonitorDepositEvent {
                    event_type: DepositEventType::E2HashiDeposited,
                    timestamp_secs,
                    btc_txid: event.utxo.id.txid.into(),
                    btc_vout: event.utxo.id.vout,
                }))
            }
            Some(_) | None => None,
        })
    }
}
