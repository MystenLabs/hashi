// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::HashiEvent;
use hashi_types::move_types::MoveType;
use hashi_types::move_types::PackageVersions;
use hashi_types::move_types::WithdrawalTransaction;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::Event;
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
use sui_sdk_types::StructTag;

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

/// The Hashi approval recorded by the object at `wid`, or `None` if that object
/// is not a Hashi `WithdrawalTransaction`.
fn withdrawal_approval(
    package_versions: &PackageVersions,
    wid: WithdrawalID,
    object: &Object,
) -> anyhow::Result<Option<MonitorWithdrawalEvent>> {
    let is_withdrawal_transaction = object
        .object_type_opt()
        .context("Sui object is missing its type")?
        .parse::<StructTag>()
        .is_ok_and(|tag| WithdrawalTransaction::matches(package_versions, &tag));
    if !is_withdrawal_transaction {
        return Ok(None);
    }
    let txn: WithdrawalTransaction = object
        .contents()
        .deserialize()
        .with_context(|| format!("failed to decode withdrawal transaction {wid}"))?;
    anyhow::ensure!(
        txn.id == wid,
        "Sui returned withdrawal transaction {} for {wid}",
        txn.id
    );
    Ok(Some(MonitorWithdrawalEvent {
        event_type: WithdrawalEventType::E1HashiApproved,
        wid,
        timestamp_secs: unix_millis_to_seconds(txn.created_timestamp_ms),
        btc_txid: txn.txid.into(),
    }))
}

pub struct SuiEventsPoller {
    /// Sui v2 gRPC client used for checkpoint, transaction and object requests.
    client: sui_rpc::Client,
    /// Deployed package versions used to identify Hashi event and object types.
    package_versions: PackageVersions,
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
            start_seconds: start,
            cursor_seconds: start,
            next_checkpoint_to_scan: None,
            checkpoint_timestamps: BTreeMap::new(),
            observed_chain_head: None,
        })
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
            "completed Sui event range"
        );
        Ok(PollOutcome::CursorAdvanced(events))
    }

    /// Read the Hashi approval of `wid` from its `WithdrawalTransaction` object, which is
    /// created alongside `WithdrawalPickedForProcessing` with the same txid and timestamp.
    pub async fn fetch_withdrawal_approval(
        &mut self,
        wid: WithdrawalID,
    ) -> anyhow::Result<Option<MonitorWithdrawalEvent>> {
        let request = GetObjectRequest::new(&wid).with_read_mask(FieldMask::from_paths([
            Object::path_builder().object_type(),
            Object::path_builder().contents().finish(),
        ]));
        let object = match self.client.ledger_client().get_object(request).await {
            Ok(response) => response
                .into_inner()
                .object
                .context("Sui GetObject response is missing the object")?,
            Err(status) if status.code() == tonic::Code::NotFound => return Ok(None),
            Err(status) => {
                return Err(status)
                    .with_context(|| format!("failed to fetch withdrawal transaction {wid}"));
            }
        };
        withdrawal_approval(&self.package_versions, wid, &object)
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

    use hashi_types::bitcoin_txid::BitcoinTxid;
    use hashi_types::move_types::SigningBatch;
    use sui_rpc::proto::sui::rpc::v2::Bcs;
    use sui_rpc::proto::sui::rpc::v2::GetObjectResponse;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerService;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerServiceServer;

    const PACKAGE_ID: Address = Address::new([0x11; 32]);
    const WID: Address = Address::new([0x3d; 32]);

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

    async fn poller_for(ledger: OneObjectLedger) -> SuiEventsPoller {
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
        SuiEventsPoller::new(&config, 0).unwrap()
    }

    fn withdrawal_transaction(id: Address) -> WithdrawalTransaction {
        WithdrawalTransaction {
            id,
            txid: BitcoinTxid::from(Address::new([0x47; 32])),
            request_ids: vec![],
            inputs: vec![],
            withdrawal_outputs: vec![],
            change_outputs: vec![],
            created_timestamp_ms: 1_789_805_327_448,
            signed_timestamp_ms: None,
            confirmed_timestamp_ms: None,
            randomness: vec![],
            signing: SigningBatch {
                signatures: vec![],
                epoch: 0,
            },
            guardian_signatures: None,
        }
    }

    fn object_at_wid(package_id: Address, txn: &WithdrawalTransaction) -> Object {
        let mut object = Object::default();
        object.object_id = Some(WID.to_string());
        object.object_type = Some(format!(
            "{package_id}::withdrawal_queue::WithdrawalTransaction"
        ));
        object.contents = Some(Bcs::serialize(txn).unwrap());
        object
    }

    #[tokio::test]
    async fn approval_is_read_from_the_withdrawal_transaction() {
        let txn = withdrawal_transaction(WID);
        let mut poller = poller_for(OneObjectLedger {
            object: Some(object_at_wid(PACKAGE_ID, &txn)),
            miss: tonic::Code::NotFound,
        })
        .await;

        assert_eq!(
            poller.fetch_withdrawal_approval(WID).await.unwrap(),
            Some(MonitorWithdrawalEvent {
                event_type: WithdrawalEventType::E1HashiApproved,
                wid: WID,
                timestamp_secs: 1_789_805_327,
                btc_txid: txn.txid.into(),
            })
        );
    }

    #[tokio::test]
    async fn lookup_and_event_scan_build_the_same_approval() {
        let txn = withdrawal_transaction(WID);
        let poller = poller_for(OneObjectLedger {
            object: None,
            miss: tonic::Code::NotFound,
        })
        .await;
        // `WithdrawalPickedForProcessing` fields, in declaration order.
        let mut contents = Bcs::serialize(&(
            txn.id,
            txn.txid,
            txn.request_ids.clone(),
            txn.inputs.clone(),
            txn.withdrawal_outputs.clone(),
            txn.change_outputs.clone(),
            txn.created_timestamp_ms,
            txn.randomness.clone(),
        ))
        .unwrap();
        contents.name = Some(format!(
            "{PACKAGE_ID}::withdrawal_queue::WithdrawalPickedForProcessing"
        ));
        let mut event = Event::default();
        event.contents = Some(contents);

        let looked_up = withdrawal_approval(
            &poller.package_versions,
            WID,
            &object_at_wid(PACKAGE_ID, &txn),
        )
        .unwrap();
        assert_eq!(
            poller.parse_event(event, 0).unwrap(),
            looked_up.map(MonitorEvent::Withdrawal)
        );
    }

    #[tokio::test]
    async fn a_missing_or_foreign_object_is_no_approval() {
        let foreign_type = object_at_wid(Address::new([0x22; 32]), &withdrawal_transaction(WID));
        let mut package = object_at_wid(PACKAGE_ID, &withdrawal_transaction(WID));
        package.object_type = Some("package".to_string());

        for object in [None, Some(foreign_type), Some(package)] {
            let mut poller = poller_for(OneObjectLedger {
                object,
                miss: tonic::Code::NotFound,
            })
            .await;
            assert_eq!(poller.fetch_withdrawal_approval(WID).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn unreadable_or_mismatched_contents_are_an_error() {
        let another_withdrawal = object_at_wid(
            PACKAGE_ID,
            &withdrawal_transaction(Address::new([0x3e; 32])),
        );
        let mut undecodable = object_at_wid(PACKAGE_ID, &withdrawal_transaction(WID));
        undecodable.contents = Some(Bcs::from(vec![1, 2, 3]));

        for object in [another_withdrawal, undecodable] {
            let mut poller = poller_for(OneObjectLedger {
                object: Some(object),
                miss: tonic::Code::NotFound,
            })
            .await;
            assert!(poller.fetch_withdrawal_approval(WID).await.is_err());
        }
    }

    #[tokio::test]
    async fn any_status_but_not_found_is_an_error() {
        let mut poller = poller_for(OneObjectLedger {
            object: None,
            miss: tonic::Code::Unavailable,
        })
        .await;

        let error = poller.fetch_withdrawal_approval(WID).await.unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<tonic::Status>()
                .map(|status| status.code()),
            Some(tonic::Code::Unavailable),
            "{error:#}"
        );
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
        let mut poller = SuiEventsPoller::new(&config, 100).unwrap();
        assert!(!poller.has_scanned(100));

        poller.cursor_seconds = 200;
        assert!(!poller.has_scanned(99));
        assert!(poller.has_scanned(100));
        assert!(poller.has_scanned(199));
        assert!(!poller.has_scanned(200));
    }
}
