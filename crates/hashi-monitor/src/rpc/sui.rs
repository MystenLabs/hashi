// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::HashiEvent;
use hashi_types::move_types::PackageVersions;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
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

pub struct SuiEventsPoller {
    /// Sui v2 gRPC client used for checkpoint and event requests.
    client: sui_rpc::Client,
    /// Deployed package versions used to decode Hashi event BCS.
    package_versions: PackageVersions,
    /// Current Hashi package used to construct server-side event type filters.
    package_id: String,
    /// Latest timestamp through which the poller has completely scanned events.
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
    /// The timestamp cursor advances only after `ListEvents` reports that the
    /// complete requested range was scanned. The server stream handles its own
    /// item and scan limits with resumable cursors. A partial response caused by
    /// an RPC failure is discarded; that range is retried and may be split.
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

        let (mut end_checkpoint, mut scanned_through_timestamp) = if latest_timestamp < up_to {
            (latest_sequence.saturating_add(1), latest_timestamp)
        } else {
            let (_, boundary) = self
                .checkpoint_bracket_from_head(up_to, (latest_sequence, latest_timestamp))
                .await?
                .context("Sui does not yet have a checkpoint at the poll end time")?;
            let timestamp = self.checkpoint_timestamp(boundary).await?;
            (boundary.saturating_add(1), timestamp)
        };
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
                    if checkpoint_count <= MIN_CHECKPOINTS_PER_RETRY {
                        return Err(error).context("Sui event scan failed after retries");
                    }
                    end_checkpoint = start_checkpoint + checkpoint_count / 2;
                    let scanned_through = end_checkpoint
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
            if let Some(event) = self.parse_event(event)? {
                events.push(event);
            }
        }

        self.next_checkpoint_to_scan = Some(end_checkpoint);
        self.cursor_seconds = self.cursor_seconds.max(scanned_through_timestamp);
        tracing::info!(
            start_checkpoint,
            end_checkpoint,
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
        // for historical timestamps, forcing ListEvents to scan many unrelated
        // checkpoint ranges. Binary search keeps the lookup logarithmic even
        // when checkpoint production has varied over time.
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
        let latest = self.get_checkpoint(GetCheckpointRequest::latest()).await?;
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
        tracing::info!(start_checkpoint, end_checkpoint, "starting Sui event scan");

        loop {
            let mut options = QueryOptions::default()
                .with_limit(PAGE_SIZE)
                .with_ordering(Ordering::Ascending);
            if let Some(cursor) = after.clone() {
                options = options.with_after(cursor);
            }
            let request = ListEventsRequest::default()
                .with_read_mask(FieldMask::from_paths(["event_type", "contents"]))
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

            let end_reason = end_reason.context("Sui ListEvents ended without QueryEnd")?;
            match end_reason {
                QueryEndReason::CheckpointBound => return Ok(all_events),
                QueryEndReason::ItemLimit | QueryEndReason::ScanLimit => {
                    tracing::info!(
                        start_checkpoint,
                        end_checkpoint,
                        events = all_events.len(),
                        ?end_reason,
                        "Sui event scan progress"
                    );
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
            format!("{}::deposit::DepositApproved", self.package_id),
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

    fn parse_event(&self, event: Event) -> anyhow::Result<Option<MonitorEvent>> {
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
            Some(HashiEvent::DepositApproved(event)) => {
                Some(MonitorEvent::Deposit(MonitorDepositEvent {
                    event_type: DepositEventType::E2HashiApproved,
                    timestamp_secs: unix_millis_to_seconds(event.approved_timestamp_ms),
                    deposit_id: DepositId::new(event.utxo.id.txid.into(), event.utxo.id.vout),
                }))
            }
            Some(_) | None => None,
        })
    }
}
