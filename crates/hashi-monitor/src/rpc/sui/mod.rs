// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use bitcoin::ScriptBuf;
use futures::StreamExt;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::PackageVersions;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::ExecutedTransaction;
use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
use sui_rpc::proto::sui::rpc::v2::ListTransactionsRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_rpc::proto::sui::rpc::v2::Ordering;
use sui_rpc::proto::sui::rpc::v2::QueryEndReason;
use sui_rpc::proto::sui::rpc::v2::QueryOptions;
use sui_rpc::proto::sui::rpc::v2::TransactionFilter;
use sui_rpc::proto::sui::rpc::v2::filter::transaction as tx_filter;
use sui_sdk_types::Address;

use crate::config::SuiConfig;
use crate::domain::MonitorEvent;
use crate::domain::PollOutcome;
use crate::domain::utc_timestamp;
use crate::findings::MonitorFinding;

pub mod approval;

use approval::HashiApproval;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const PAGE_SIZE: u32 = 1_000;
const MIN_CHECKPOINTS_PER_RETRY: u64 = 25;
const MAX_RANGE_ATTEMPTS: u32 = 3;
const MAX_LOOKUP_ATTEMPTS: u32 = 3;
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
/// Distance kept above a pruning node's reported oldest checkpoint: an hour at the probe's
/// six checkpoints per second, since the backends behind one endpoint prune unevenly.
const PRUNING_MARGIN_CHECKPOINTS: u64 = 6 * 60 * 60;

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
    let completed_checkpoint = match end_reason {
        QueryEndReason::CheckpointBound => end_checkpoint - 1,
        QueryEndReason::LedgerTip if watermark_checkpoint.is_none() => return Ok(None),
        _ => watermark_checkpoint.context(format!(
            "Sui transaction scan ended with {end_reason:?} without a completion watermark"
        ))?,
    };
    anyhow::ensure!(
        completed_checkpoint < end_checkpoint,
        "Sui transaction scan watermark checkpoint {completed_checkpoint} is outside requested range ending at {end_checkpoint}"
    );
    Ok((completed_checkpoint >= start_checkpoint).then_some(completed_checkpoint))
}

/// Connection-level failures that a fresh connection can clear, as the node's peer
/// retries classify them: a `GOAWAY` surfaces as `Internal`, a broken pipe as `Unknown`.
fn is_transient(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable
            | tonic::Code::Unknown
            | tonic::Code::Internal
            | tonic::Code::Cancelled
            | tonic::Code::DeadlineExceeded
    )
}

pub struct SuiEventsPoller {
    /// Sui v2 gRPC client used for checkpoint, transaction and object requests.
    client: sui_rpc::Client,
    /// Deployed package versions used to identify Hashi event and object types.
    package_versions: PackageVersions,
    /// The script every withdrawal change output must pay.
    change_script: ScriptBuf,
    /// Original Hashi package used to construct server-side transaction filters.
    package_id: String,
    /// Timestamp from which the poller scans every checkpoint.
    start_seconds: UnixSeconds,
    /// Latest timestamp through which the poller has completely scanned transactions.
    cursor_seconds: UnixSeconds,
    /// First checkpoint not yet scanned, once the initial timestamp lookup completes.
    next_checkpoint_to_scan: Option<u64>,
    /// Checkpoint timestamps cached to avoid repeating `GetCheckpoint` requests.
    checkpoint_timestamps: BTreeMap<u64, UnixSeconds>,
    /// Most recently fetched chain head as `(sequence_number, timestamp_secs)`.
    observed_chain_head: Option<(u64, UnixSeconds)>,
    /// Oldest checkpoint the node reported serving, 0 if it has not pruned.
    lowest_available_checkpoint: u64,
}

impl SuiEventsPoller {
    /// `change_script` is the script every withdrawal change output must pay.
    pub fn new(
        config: &SuiConfig,
        change_script: ScriptBuf,
        start: UnixSeconds,
    ) -> anyhow::Result<Self> {
        let package_id = Address::from_str(&config.package_id)
            .with_context(|| format!("invalid Hashi package ID {}", config.package_id))?;

        let package_versions = PackageVersions::new(BTreeMap::from([(1, package_id)]));
        let client = sui_rpc::Client::new(&config.rpc_url)
            .with_context(|| format!("invalid Sui RPC URL {}", config.rpc_url))?
            .request_layer(tower::timeout::TimeoutLayer::new(REQUEST_TIMEOUT));

        Ok(Self {
            client,
            package_versions,
            change_script,
            package_id: config.package_id.clone(),
            start_seconds: start,
            cursor_seconds: start,
            next_checkpoint_to_scan: None,
            checkpoint_timestamps: BTreeMap::new(),
            observed_chain_head: None,
            lowest_available_checkpoint: 0,
        })
    }

    pub fn start_seconds(&self) -> UnixSeconds {
        self.start_seconds
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor_seconds
    }

    /// Whether the scan covered `timestamp_secs`. The cursor's own second is
    /// excluded, since later unscanned checkpoints can share it.
    pub fn has_scanned(&self, timestamp_secs: UnixSeconds) -> bool {
        (self.start_seconds..self.cursor_seconds).contains(&timestamp_secs)
    }

    /// Scan through the checkpoint covering `up_to`, or the observed chain head.
    ///
    /// The timestamp cursor advances only through `watermark.checkpoint`, which
    /// is the inclusive boundary that `ListTransactions` reports as fully
    /// covered. Transactions provide the
    /// checkpoint timestamp needed by `DepositConfirmed`, while their nested
    /// events provide the Hashi payloads. The Sui SDK handles item and scan
    /// limits, resumable cursors, and retryable partial streams. A terminal
    /// failure discards the partial range; that range is retried and may be
    /// split.
    pub async fn poll(&mut self, up_to: UnixSeconds) -> anyhow::Result<PollOutcome> {
        if up_to <= self.cursor_seconds {
            return Ok(PollOutcome::CursorUnmoved);
        }

        let start_checkpoint = match self.next_checkpoint_to_scan {
            Some(checkpoint) => checkpoint,
            None => self.first_checkpoint_to_scan().await?,
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
            let scan = tokio::time::timeout(
                REQUEST_TIMEOUT,
                self.list_transactions_in_range(start_checkpoint, end_checkpoint),
            )
            .await
            .context("Sui transaction scan timed out")
            .and_then(|result| result);
            match scan {
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
        let mut findings = Vec::new();
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
            self.parse_transaction(transaction, &mut events, &mut findings)?;
        }

        let scanned_through_timestamp = self.checkpoint_timestamp(completed_checkpoint).await?;
        self.next_checkpoint_to_scan = Some(completed_checkpoint.saturating_add(1));
        self.cursor_seconds = self.cursor_seconds.max(scanned_through_timestamp);
        tracing::info!(
            start_checkpoint,
            end_checkpoint,
            completed_checkpoint,
            end_reason = ?scan.end_reason,
            cursor = %utc_timestamp(self.cursor_seconds),
            events = events.len(),
            findings = findings.len(),
            "completed Sui event range"
        );
        Ok(PollOutcome::CursorAdvanced { events, findings })
    }

    /// Read the Hashi approval of `wid` from its `WithdrawalTransaction` object, which is
    /// created alongside `WithdrawalPickedForProcessing` with the same txid and timestamp.
    pub async fn fetch_withdrawal_approval(
        &mut self,
        wid: WithdrawalID,
    ) -> anyhow::Result<Option<HashiApproval>> {
        let request = GetObjectRequest::new(&wid).with_read_mask(FieldMask::from_paths([
            Object::path_builder().object_type(),
            Object::path_builder().contents().finish(),
        ]));
        let lookup = async {
            let mut attempt = 0u32;
            loop {
                match self
                    .client
                    .ledger_client()
                    .get_object(request.clone())
                    .await
                {
                    Ok(response) => {
                        break response
                            .into_inner()
                            .object
                            .context("Sui GetObject response is missing the object")
                            .map(Some);
                    }
                    Err(status) if status.code() == tonic::Code::NotFound => break Ok(None),
                    Err(status) if attempt + 1 < MAX_LOOKUP_ATTEMPTS && is_transient(&status) => {
                        let delay = INITIAL_RETRY_DELAY.saturating_mul(1 << attempt);
                        attempt += 1;
                        tracing::warn!(%wid, attempt, ?delay, ?status, "Sui object lookup failed; retrying");
                        tokio::time::sleep(delay).await;
                    }
                    Err(status) => {
                        break Err(status).with_context(|| {
                            format!("failed to fetch withdrawal transaction {wid}")
                        });
                    }
                }
            }
        };
        // Retries share one request's timeout, so a lookup never stalls the audit longer than one request.
        let object = tokio::time::timeout(REQUEST_TIMEOUT, lookup)
            .await
            .with_context(|| format!("Sui lookup of withdrawal transaction {wid} timed out"))??;
        match object {
            Some(object) => approval::parse_withdrawal_object(
                &self.package_versions,
                &self.change_script,
                wid,
                &object,
            ),
            None => Ok(None),
        }
    }

    /// The checkpoint before the cursor or, once the node has pruned that far, the oldest
    /// one it serves, moving the scan's start past that checkpoint's second.
    async fn first_checkpoint_to_scan(&mut self) -> anyhow::Result<u64> {
        let (before, _) = self
            .checkpoint_bracket(self.cursor_seconds)
            .await?
            .context("Sui does not yet have a checkpoint at the poll start time")?;
        if before > 0 {
            let before_timestamp = self.checkpoint_timestamp(before).await?;
            if before_timestamp >= self.cursor_seconds {
                // Transactions in unscanned earlier checkpoints are at most this second.
                self.start_seconds = before_timestamp + 1;
                tracing::warn!(
                    requested_start = %utc_timestamp(self.cursor_seconds),
                    scan_start = %utc_timestamp(self.start_seconds),
                    checkpoint = before,
                    "Sui node has pruned the requested start; scanning from its oldest checkpoint"
                );
            }
        }
        Ok(before)
    }

    /// Find a safe checkpoint bracket `(before, at_or_after)` for a timestamp.
    ///
    /// Exponential probing finds a lower bound, then binary search resolves the
    /// exact adjacent checkpoint boundary. When a predecessor checkpoint exists,
    /// the lower bound is before the timestamp and the upper bound is at or after
    /// it. At or before the oldest checkpoint the node serves, genesis unless it
    /// prunes, both bounds are that checkpoint.
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

        let oldest = match self.lowest_available_checkpoint {
            0 => 0,
            lowest => lowest
                .saturating_add(PRUNING_MARGIN_CHECKPOINTS)
                .min(latest_sequence),
        };
        let elapsed = latest_timestamp.saturating_sub(timestamp_secs);
        let mut distance = elapsed.saturating_mul(6).max(1);
        let mut low_sequence = loop {
            let probe = latest_sequence.saturating_sub(distance).max(oldest);
            let timestamp = self.checkpoint_timestamp(probe).await?;
            if timestamp < timestamp_secs {
                break probe;
            }
            if probe == oldest {
                return Ok(Some((oldest, oldest)));
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
        self.lowest_available_checkpoint = service_info.lowest_available_checkpoint.unwrap_or(0);
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

        let request = ListTransactionsRequest::default()
            .with_read_mask(FieldMask::from_paths([
                "timestamp",
                "checkpoint",
                "events.events.event_type",
                "events.events.contents",
            ]))
            .with_start_checkpoint(start_checkpoint)
            .with_end_checkpoint(end_checkpoint)
            .with_filter(self.transaction_filter())
            .with_options(
                QueryOptions::default()
                    .with_limit(PAGE_SIZE)
                    .with_ordering(Ordering::Ascending),
            );
        let stream = self.client.list_transactions(request);
        futures::pin_mut!(stream);

        let mut all_transactions = Vec::new();
        let mut completed_checkpoint = None;
        let mut end_reason = None;
        tracing::info!(
            start_checkpoint,
            end_checkpoint,
            "starting Sui transaction scan"
        );

        while let Some(frame) = stream.next().await {
            // The SDK validates watermarks and transparently resumes page
            // limits and retryable partial streams before yielding frames.
            let frame = frame.context("Sui ListTransactions stream failed")?;
            if let Some(checkpoint) = frame
                .watermark
                .as_ref()
                .and_then(|watermark| watermark.checkpoint)
            {
                completed_checkpoint = Some(checkpoint);
            }
            if let Some(transaction) = frame.transaction {
                all_transactions.push(transaction);
            }
            if let Some(end) = frame.end {
                end_reason = end
                    .reason
                    .and_then(|reason| QueryEndReason::try_from(reason).ok());
            }
        }

        Ok(TransactionScan {
            transactions: all_transactions,
            completed_checkpoint,
            end_reason: end_reason.context("Sui ListTransactions ended without QueryEnd")?,
        })
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

    /// Parse the monitored events of one transaction into `events`. An event
    /// that fails a check adds its findings to `findings` instead.
    fn parse_transaction(
        &self,
        transaction: ExecutedTransaction,
        events: &mut Vec<MonitorEvent>,
        findings: &mut Vec<MonitorFinding>,
    ) -> anyhow::Result<()> {
        let timestamp = transaction
            .timestamp
            .context("Sui transaction is missing checkpoint timestamp")?;
        let timestamp_ms =
            proto_to_timestamp_ms(timestamp).context("invalid Sui transaction timestamp")?;
        let timestamp_secs = unix_millis_to_seconds(timestamp_ms);
        let sui_events = transaction
            .events
            .context("filtered Sui transaction is missing events")?
            .events;

        for sui_event in sui_events {
            approval::parse_event(
                &self.package_versions,
                &self.change_script,
                sui_event,
                timestamp_secs,
                events,
                findings,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::approval::tests::PACKAGE_ID;
    use super::approval::tests::WID;
    use super::approval::tests::object_at_wid;
    use super::approval::tests::test_change_address;
    use super::approval::tests::withdrawal_transaction;
    use super::*;
    use crate::domain::MonitorWithdrawalEvent;
    use crate::domain::WithdrawalEventType;
    use hashi_types::move_types::WithdrawalTransaction;

    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;

    use sui_rpc::proto::sui::rpc::v2::CheckpointSummary;
    use sui_rpc::proto::sui::rpc::v2::GetCheckpointResponse;
    use sui_rpc::proto::sui::rpc::v2::GetObjectResponse;
    use sui_rpc::proto::sui::rpc::v2::GetServiceInfoResponse;
    use sui_rpc::proto::sui::rpc::v2::get_checkpoint_request::CheckpointId;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerService;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerServiceServer;
    use sui_rpc::proto::timestamp_ms_to_proto;

    /// A ledger holding at most one object, answering every other id with
    /// `miss`. Like a fullnode, it serves only the fields in the read mask.
    #[derive(Clone)]
    struct OneObjectLedger {
        object: Option<Object>,
        miss: tonic::Code,
    }

    #[tonic::async_trait]
    impl LedgerService for OneObjectLedger {
        async fn get_object(
            &self,
            request: tonic::Request<GetObjectRequest>,
        ) -> Result<tonic::Response<GetObjectResponse>, tonic::Status> {
            let request = request.into_inner();
            let Some(stored) = self
                .object
                .as_ref()
                .filter(|object| object.object_id == request.object_id)
            else {
                return Err(tonic::Status::new(self.miss, "no such object"));
            };
            let paths = request.read_mask.map(|mask| mask.paths).unwrap_or_default();
            let mut object = Object::default();
            if paths.iter().any(|path| path == "object_type") {
                object.object_type = stored.object_type.clone();
            }
            if paths.iter().any(|path| path == "contents") {
                object.contents = stored.contents.clone();
            }
            Ok(tonic::Response::new(GetObjectResponse::new(object)))
        }
    }

    /// Answers the first requests with `failures`, in order, then defers to `ledger`.
    #[derive(Clone)]
    struct FlakyLedger {
        failures: Arc<Mutex<VecDeque<tonic::Code>>>,
        requests: Arc<Mutex<u32>>,
        ledger: OneObjectLedger,
    }

    impl FlakyLedger {
        fn new(failures: impl IntoIterator<Item = tonic::Code>, ledger: OneObjectLedger) -> Self {
            Self {
                failures: Arc::new(Mutex::new(failures.into_iter().collect())),
                requests: Arc::default(),
                ledger,
            }
        }
    }

    #[tonic::async_trait]
    impl LedgerService for FlakyLedger {
        async fn get_object(
            &self,
            request: tonic::Request<GetObjectRequest>,
        ) -> Result<tonic::Response<GetObjectResponse>, tonic::Status> {
            *self.requests.lock().unwrap() += 1;
            let failure = self.failures.lock().unwrap().pop_front();
            match failure {
                Some(code) => Err(tonic::Status::new(code, "injected failure")),
                None => self.ledger.get_object(request).await,
            }
        }
    }

    /// Checkpoints `lowest..=head`, one a second from `GENESIS_SECS`. Like a pruning
    /// fullnode, it reports `lowest` and answers older checkpoints with `NotFound`.
    #[derive(Clone)]
    struct PrunedLedger {
        lowest: u64,
        head: u64,
    }

    const GENESIS_SECS: UnixSeconds = 1_700_000_000;

    #[tonic::async_trait]
    impl LedgerService for PrunedLedger {
        async fn get_service_info(
            &self,
            _: tonic::Request<GetServiceInfoRequest>,
        ) -> Result<tonic::Response<GetServiceInfoResponse>, tonic::Status> {
            let mut info = GetServiceInfoResponse::default();
            info.checkpoint_height = Some(self.head);
            info.timestamp = Some(timestamp_ms_to_proto((GENESIS_SECS + self.head) * 1_000));
            info.lowest_available_checkpoint = Some(self.lowest);
            Ok(tonic::Response::new(info))
        }

        async fn get_checkpoint(
            &self,
            request: tonic::Request<GetCheckpointRequest>,
        ) -> Result<tonic::Response<GetCheckpointResponse>, tonic::Status> {
            let Some(CheckpointId::SequenceNumber(sequence)) = request.into_inner().checkpoint_id
            else {
                return Err(tonic::Status::invalid_argument(
                    "expected a sequence number",
                ));
            };
            if !(self.lowest..=self.head).contains(&sequence) {
                return Err(tonic::Status::not_found("pruned"));
            }
            let mut summary = CheckpointSummary::default();
            summary.timestamp = Some(timestamp_ms_to_proto((GENESIS_SECS + sequence) * 1_000));
            let mut checkpoint = Checkpoint::default();
            checkpoint.sequence_number = Some(sequence);
            checkpoint.summary = Some(summary);
            let mut response = GetCheckpointResponse::default();
            response.checkpoint = Some(checkpoint);
            Ok(tonic::Response::new(response))
        }
    }

    async fn poller_for(ledger: impl LedgerService) -> SuiEventsPoller {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let result = listener.accept().await.map(|(stream, _)| stream);
            Some((result, listener))
        });
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(LedgerServiceServer::new(ledger))
                .serve_with_incoming(incoming),
        );
        let config = SuiConfig {
            rpc_url: format!("http://{addr}"),
            package_id: PACKAGE_ID.to_string(),
        };
        SuiEventsPoller::new(&config, test_change_address().script_pubkey(), 0).unwrap()
    }

    /// The approval a lookup of `WID` returns from `poller_scanned`'s ledger.
    pub fn looked_up_approval() -> MonitorWithdrawalEvent {
        let txn = withdrawal_transaction(WID);
        MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E1HashiApproved,
            wid: WID,
            timestamp_secs: unix_millis_to_seconds(txn.created_timestamp_ms),
            btc_txid: txn.txid.into(),
        }
    }

    /// A poller over a ledger holding `WID`'s approval that has scanned `[start, cursor)`.
    pub async fn poller_scanned(start: UnixSeconds, cursor: UnixSeconds) -> SuiEventsPoller {
        poller_scanned_with(withdrawal_transaction(WID), start, cursor).await
    }

    /// A poller over a ledger holding `txn` at `WID` that has scanned `[start, cursor)`.
    pub async fn poller_scanned_with(
        txn: WithdrawalTransaction,
        start: UnixSeconds,
        cursor: UnixSeconds,
    ) -> SuiEventsPoller {
        let mut poller = poller_for(OneObjectLedger {
            object: Some(object_at_wid(PACKAGE_ID, &txn)),
            miss: tonic::Code::NotFound,
        })
        .await;
        poller.start_seconds = start;
        poller.cursor_seconds = cursor;
        poller
    }

    async fn fetch_approval(txn: &WithdrawalTransaction) -> HashiApproval {
        let mut poller = poller_for(OneObjectLedger {
            object: Some(object_at_wid(PACKAGE_ID, txn)),
            miss: tonic::Code::NotFound,
        })
        .await;
        poller
            .fetch_withdrawal_approval(WID)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn approval_is_read_from_the_withdrawal_transaction() {
        let txn = withdrawal_transaction(WID);

        assert_eq!(
            fetch_approval(&txn).await,
            HashiApproval::Valid(MonitorWithdrawalEvent {
                event_type: WithdrawalEventType::E1HashiApproved,
                wid: WID,
                timestamp_secs: 1_789_805_327,
                btc_txid: txn.txid.into(),
            })
        );
    }

    #[tokio::test]
    async fn a_missing_object_is_no_approval() {
        let mut poller = poller_for(OneObjectLedger {
            object: None,
            miss: tonic::Code::NotFound,
        })
        .await;
        assert_eq!(poller.fetch_withdrawal_approval(WID).await.unwrap(), None);
    }

    fn ledger_with_approval() -> OneObjectLedger {
        OneObjectLedger {
            object: Some(object_at_wid(PACKAGE_ID, &withdrawal_transaction(WID))),
            miss: tonic::Code::NotFound,
        }
    }

    fn status_code(error: &anyhow::Error) -> Option<tonic::Code> {
        error
            .downcast_ref::<tonic::Status>()
            .map(|status| status.code())
    }

    #[tokio::test]
    async fn transient_statuses_are_retried() {
        let ledger = FlakyLedger::new(
            [tonic::Code::Internal, tonic::Code::Unavailable],
            ledger_with_approval(),
        );
        let mut poller = poller_for(ledger.clone()).await;

        assert!(
            poller
                .fetch_withdrawal_approval(WID)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(*ledger.requests.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn a_transient_failure_before_not_found_is_no_approval() {
        let ledger = FlakyLedger::new(
            [tonic::Code::Unavailable],
            OneObjectLedger {
                object: None,
                miss: tonic::Code::NotFound,
            },
        );
        let mut poller = poller_for(ledger.clone()).await;

        assert_eq!(poller.fetch_withdrawal_approval(WID).await.unwrap(), None);
        assert_eq!(*ledger.requests.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn a_lookup_gives_up_after_its_last_attempt() {
        let ledger = FlakyLedger::new(
            [tonic::Code::Unavailable; MAX_LOOKUP_ATTEMPTS as usize],
            ledger_with_approval(),
        );
        let mut poller = poller_for(ledger.clone()).await;

        let error = poller.fetch_withdrawal_approval(WID).await.unwrap_err();
        assert_eq!(
            status_code(&error),
            Some(tonic::Code::Unavailable),
            "{error:#}"
        );
        assert_eq!(*ledger.requests.lock().unwrap(), MAX_LOOKUP_ATTEMPTS);
    }

    #[tokio::test]
    async fn other_statuses_fail_without_a_retry() {
        let ledger = FlakyLedger::new([tonic::Code::PermissionDenied], ledger_with_approval());
        let mut poller = poller_for(ledger.clone()).await;

        let error = poller.fetch_withdrawal_approval(WID).await.unwrap_err();
        assert_eq!(
            status_code(&error),
            Some(tonic::Code::PermissionDenied),
            "{error:#}"
        );
        assert_eq!(*ledger.requests.lock().unwrap(), 1);
    }

    #[test]
    fn connection_failures_are_transient_and_rejections_are_not() {
        for code in [
            tonic::Code::Unavailable,
            tonic::Code::Unknown,
            tonic::Code::Internal,
            tonic::Code::Cancelled,
            tonic::Code::DeadlineExceeded,
        ] {
            assert!(is_transient(&tonic::Status::new(code, "boom")), "{code:?}");
        }
        for code in [
            tonic::Code::NotFound,
            tonic::Code::InvalidArgument,
            tonic::Code::FailedPrecondition,
            tonic::Code::PermissionDenied,
            tonic::Code::Unauthenticated,
            tonic::Code::ResourceExhausted,
        ] {
            assert!(!is_transient(&tonic::Status::new(code, "nope")), "{code:?}");
        }
    }

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
    fn checkpoint_bound_advances_through_requested_range() {
        for watermark in [None, Some(109), Some(110)] {
            assert_eq!(
                completed_checkpoint_for_scan(
                    100,
                    111,
                    QueryEndReason::CheckpointBound,
                    watermark,
                )
                .unwrap(),
                Some(110)
            );
        }
    }

    #[tokio::test]
    async fn the_scan_covers_its_start_but_not_its_cursor_second() {
        let config = SuiConfig {
            rpc_url: "http://127.0.0.1:9".to_string(),
            package_id: PACKAGE_ID.to_string(),
        };
        let mut poller =
            SuiEventsPoller::new(&config, test_change_address().script_pubkey(), 100).unwrap();
        assert!(!poller.has_scanned(100));

        poller.cursor_seconds = 200;
        assert!(!poller.has_scanned(99));
        assert!(poller.has_scanned(100));
        assert!(poller.has_scanned(199));
        assert!(!poller.has_scanned(200));
    }

    async fn pruned_poller_starting_at(sequence: u64) -> SuiEventsPoller {
        let mut poller = poller_for(PrunedLedger {
            lowest: 100_000,
            head: 200_000,
        })
        .await;
        poller.start_seconds = GENESIS_SECS + sequence;
        poller.cursor_seconds = GENESIS_SECS + sequence;
        poller
    }

    #[tokio::test]
    async fn a_start_the_node_has_pruned_scans_from_its_oldest_checkpoint() {
        let mut poller = pruned_poller_starting_at(50_000).await;
        let oldest = 100_000 + PRUNING_MARGIN_CHECKPOINTS;

        assert_eq!(poller.first_checkpoint_to_scan().await.unwrap(), oldest);
        assert_eq!(poller.start_seconds(), GENESIS_SECS + oldest + 1);
    }

    #[tokio::test]
    async fn a_start_the_probe_would_overshoot_resolves_without_pruned_checkpoints() {
        let mut poller = pruned_poller_starting_at(130_000).await;

        assert_eq!(poller.first_checkpoint_to_scan().await.unwrap(), 129_999);
        assert_eq!(poller.start_seconds(), GENESIS_SECS + 130_000);
    }

    #[tokio::test]
    async fn an_unpruned_node_scans_from_genesis_for_an_earlier_start() {
        let mut poller = poller_for(PrunedLedger {
            lowest: 0,
            head: 1_000,
        })
        .await;
        poller.start_seconds = GENESIS_SECS - 10;
        poller.cursor_seconds = GENESIS_SECS - 10;

        assert_eq!(poller.first_checkpoint_to_scan().await.unwrap(), 0);
        assert_eq!(poller.start_seconds(), GENESIS_SECS - 10);
    }
}
