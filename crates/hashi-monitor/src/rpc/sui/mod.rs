// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The Sui poller: the Hashi events read from Sui, in checkpoint order.
//!
//! Why it exists: the withdrawal E1 and the deposit E2 are Sui events. The
//! poller scans the checkpoints for them and gives each one its time.
//!
//! How it works:
//! 1. The poller starts at a checkpoint: on a first run, the one that holds
//!    the Hashi package's publish transaction; on a resume, the one the
//!    snapshot saved. Before the first poll, it checks that the node still
//!    serves the start. Its cursor in seconds is then the time of the
//!    checkpoint before the start.
//! 2. Each poll lists the transactions that emit a monitored event, from the
//!    next checkpoint through the checkpoint the caller names, but at most
//!    `MAX_CHECKPOINTS_PER_POLL` checkpoints. The caller names the chain head
//!    it read at the tick's start. A failed range is retried,
//!    then split.
//! 3. The cursor advances through the last checkpoint the node declared
//!    complete. The transactions of later checkpoints wait for the next poll,
//!    so a checkpoint is ingested whole.
//!
//! Assumptions:
//! - Every monitored event type keeps the original package's address across
//!   upgrades.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::Hashi;
use hashi_types::move_types::PackageVersions;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::proto_to_timestamp_ms;
use sui_rpc::proto::sui::rpc::v2::ExecutedTransaction;
use sui_rpc::proto::sui::rpc::v2::GetCheckpointRequest;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
use sui_rpc::proto::sui::rpc::v2::GetTransactionRequest;
use sui_rpc::proto::sui::rpc::v2::ListTransactionsRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_rpc::proto::sui::rpc::v2::Ordering;
use sui_rpc::proto::sui::rpc::v2::QueryEndReason;
use sui_rpc::proto::sui::rpc::v2::QueryOptions;
use sui_rpc::proto::sui::rpc::v2::TransactionFilter;
use sui_rpc::proto::sui::rpc::v2::filter::transaction as tx_filter;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;

use crate::config::SuiConfig;
use crate::domain::MonitorEvent;
use crate::domain::PollOutcome;
use crate::findings::MonitorFinding;
use crate::keys::HashiBTCKeys;
use crate::time::utc_timestamp;

pub mod approval;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const PAGE_SIZE: u32 = 1_000;
/// Checkpoints one poll scans at most. A backlog, such as a first run from
/// genesis, is walked in ranges of this size: each range fits one request
/// timeout, and its events are released before the next range is read.
const MAX_CHECKPOINTS_PER_POLL: u64 = 10_000;
const MIN_CHECKPOINTS_PER_RETRY: u64 = 25;
const MAX_RANGE_ATTEMPTS: u32 = 3;
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(250);
/// Distance kept above a pruning node's reported oldest checkpoint: about an hour
/// of checkpoints, since the backends behind one endpoint prune unevenly.
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

/// A Sui v2 gRPC client for `config`, with `REQUEST_TIMEOUT` on every request.
fn connect(config: &SuiConfig) -> anyhow::Result<sui_rpc::Client> {
    let client = sui_rpc::Client::new(&config.rpc_url)
        .with_context(|| format!("invalid Sui RPC URL {}", config.rpc_url))?
        .request_layer(tower::timeout::TimeoutLayer::new(REQUEST_TIMEOUT));
    Ok(client)
}

/// The bridge's genesis on Sui: the transaction that published the original
/// Hashi package. No Hashi event precedes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Genesis {
    /// The checkpoint that holds the publish transaction.
    pub checkpoint: u64,
    /// The time of that checkpoint.
    pub timestamp: UnixSeconds,
}

/// The genesis of the Hashi package in `config`.
pub async fn package_genesis(config: &SuiConfig) -> anyhow::Result<Genesis> {
    let mut client = connect(config)?;
    publish_genesis(&mut client, &config.package_id).await
}

/// The checkpoint and time of the transaction that published `package_id`.
/// The package object is immutable, so its previous transaction is its publish.
async fn publish_genesis(
    client: &mut sui_rpc::Client,
    package_id: &str,
) -> anyhow::Result<Genesis> {
    let address = Address::from_str(package_id)
        .with_context(|| format!("invalid Hashi package ID {package_id}"))?;
    let request = GetObjectRequest::new(&address)
        .with_read_mask(FieldMask::from_paths(["previous_transaction"]));
    let publish_digest = client
        .ledger_client()
        .get_object(request)
        .await
        .with_context(|| format!("failed to fetch Hashi package {package_id}"))?
        .into_inner()
        .object
        .with_context(|| format!("Sui GetObject response is missing package {package_id}"))?
        .previous_transaction
        .with_context(|| format!("Hashi package {package_id} is missing previous_transaction"))?;
    let digest = Digest::from_str(&publish_digest).with_context(|| {
        format!("invalid publish transaction digest {publish_digest} of Hashi package {package_id}")
    })?;
    let request = GetTransactionRequest::new(&digest)
        .with_read_mask(FieldMask::from_paths(["checkpoint", "timestamp"]));
    let transaction = client
        .ledger_client()
        .get_transaction(request)
        .await
        .with_context(|| format!("failed to fetch the publish transaction of Hashi package {package_id}"))?
        .into_inner()
        .transaction
        .with_context(|| format!("Sui GetTransaction response is missing the publish transaction of Hashi package {package_id}"))?;
    let checkpoint = transaction.checkpoint.with_context(|| {
        format!("publish transaction of Hashi package {package_id} is missing checkpoint")
    })?;
    let timestamp = transaction.timestamp.with_context(|| {
        format!("publish transaction of Hashi package {package_id} is missing timestamp")
    })?;
    let timestamp_ms = proto_to_timestamp_ms(timestamp).with_context(|| {
        format!("invalid publish transaction timestamp of Hashi package {package_id}")
    })?;
    Ok(Genesis {
        checkpoint,
        timestamp: unix_millis_to_seconds(timestamp_ms),
    })
}

/// Hashi's on-chain `bitcoin_confirmation_threshold`: the confirmations the
/// committee waits for. It is 6 when unset, as in the Hashi node.
pub async fn read_confirmation_threshold(
    config: &SuiConfig,
    hashi_object_id: Address,
) -> anyhow::Result<u64> {
    let mut client = connect(config)?;
    let request = GetObjectRequest::new(&hashi_object_id).with_read_mask(FieldMask::from_paths([
        Object::path_builder().contents().finish(),
    ]));
    let hashi: Hashi = client
        .ledger_client()
        .get_object(request)
        .await
        .with_context(|| format!("failed to fetch the Hashi object {hashi_object_id}"))?
        .into_inner()
        .object
        .with_context(|| {
            format!("Sui GetObject response is missing the Hashi object {hashi_object_id}")
        })?
        .contents()
        .deserialize()
        .with_context(|| format!("failed to decode the Hashi object {hashi_object_id}"))?;
    Ok(hashi.config.get_u64("bitcoin_confirmation_threshold", 6))
}

pub struct SuiEventsPoller {
    /// Sui v2 gRPC client used for checkpoint, transaction and object requests.
    client: sui_rpc::Client,
    /// Deployed package versions used to identify Hashi event and object types.
    package_versions: PackageVersions,
    /// The keys every bridge address derives from.
    hashi_btc_keys: HashiBTCKeys,
    /// Original Hashi package used to construct server-side transaction filters.
    package_id: String,
    /// The time of the last checkpoint scanned. `ensure_start_is_served`
    /// sets it for the start.
    cursor_seconds: UnixSeconds,
    /// The first checkpoint not yet scanned.
    next_checkpoint: u64,
}

impl SuiEventsPoller {
    /// A poller whose scan starts at checkpoint `start`.
    pub fn new(
        config: &SuiConfig,
        hashi_btc_keys: HashiBTCKeys,
        start: u64,
    ) -> anyhow::Result<Self> {
        let package_id = Address::from_str(&config.package_id)
            .with_context(|| format!("invalid Hashi package ID {}", config.package_id))?;

        let package_versions = PackageVersions::new(BTreeMap::from([(1, package_id)]));

        Ok(Self {
            client: connect(config)?,
            package_versions,
            hashi_btc_keys,
            package_id: config.package_id.clone(),
            cursor_seconds: 0,
            next_checkpoint: start,
        })
    }

    pub fn cursor_seconds(&self) -> UnixSeconds {
        self.cursor_seconds
    }

    /// The first checkpoint not yet scanned.
    pub fn next_checkpoint(&self) -> u64 {
        self.next_checkpoint
    }

    /// The newest checkpoint the node serves.
    pub async fn latest_checkpoint(&mut self) -> anyhow::Result<u64> {
        Ok(self.checkpoint_range().await?.1)
    }

    /// Scan up to checkpoint `up_to`, inclusive, but at most
    /// `MAX_CHECKPOINTS_PER_POLL` checkpoints.
    ///
    /// The timestamp cursor advances only through `watermark.checkpoint`, which
    /// is the inclusive boundary that `ListTransactions` reports as fully
    /// covered. Each transaction's nested events provide the Hashi payloads.
    /// The Sui SDK handles item and scan limits, resumable cursors,
    /// and retryable partial streams. A terminal failure discards the partial
    /// range; that range is retried and may be split.
    pub async fn poll(&mut self, up_to: u64) -> anyhow::Result<PollOutcome> {
        let start_checkpoint = self.next_checkpoint;
        if start_checkpoint > up_to {
            return Ok(PollOutcome::CursorUnmoved);
        }
        // A backlog is scanned in bounded ranges. The caller polls again while
        // the cursor advances, so the rest follows in the next polls.
        let mut end_checkpoint = up_to
            .saturating_add(1)
            .min(start_checkpoint.saturating_add(MAX_CHECKPOINTS_PER_POLL));

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
        self.next_checkpoint = completed_checkpoint.saturating_add(1);
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

    /// Fail unless the node still serves the start, then set the cursor to
    /// the time of the checkpoint before the start. A pruned start would
    /// leave the UTXO pool incomplete for good.
    pub async fn ensure_start_is_served(&mut self) -> anyhow::Result<()> {
        let (lowest, _) = self.checkpoint_range().await?;
        let previous = self.next_checkpoint.saturating_sub(1);
        anyhow::ensure!(
            lowest == 0 || lowest.saturating_add(PRUNING_MARGIN_CHECKPOINTS) <= previous,
            "the Sui node has pruned checkpoint {previous}, which the scan from checkpoint {} needs: it serves from {lowest}. Use a Sui node that keeps the history from there",
            self.next_checkpoint,
        );
        self.cursor_seconds = self.checkpoint_timestamp(previous).await?;
        Ok(())
    }

    /// The oldest and the newest checkpoint the node serves. The oldest is 0
    /// unless the node prunes.
    async fn checkpoint_range(&mut self) -> anyhow::Result<(u64, u64)> {
        let service_info = self
            .client
            .ledger_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await
            .context("failed to fetch Sui service info")?
            .into_inner();
        let latest = service_info
            .checkpoint_height
            .context("Sui service info is missing checkpoint_height")?;
        Ok((
            service_info.lowest_available_checkpoint.unwrap_or(0),
            latest,
        ))
    }

    /// The timestamp of checkpoint `sequence_number`, read from the node.
    async fn checkpoint_timestamp(&mut self, sequence_number: u64) -> anyhow::Result<UnixSeconds> {
        let request = GetCheckpointRequest::by_sequence_number(sequence_number).with_read_mask(
            FieldMask::from_paths(["sequence_number", "summary.timestamp"]),
        );
        let checkpoint = self
            .client
            .ledger_client()
            .get_checkpoint(request)
            .await
            .context("failed to fetch Sui checkpoint")?
            .into_inner()
            .checkpoint
            .context("missing Sui checkpoint")?;
        let actual_sequence = checkpoint
            .sequence_number
            .context("Sui checkpoint is missing sequence_number")?;
        let timestamp = checkpoint
            .summary
            .and_then(|summary| summary.timestamp)
            .context("Sui checkpoint is missing summary.timestamp")?;
        let timestamp_ms =
            proto_to_timestamp_ms(timestamp).context("invalid Sui checkpoint timestamp")?;
        let timestamp_secs = unix_millis_to_seconds(timestamp_ms);
        anyhow::ensure!(
            actual_sequence == sequence_number,
            "requested Sui checkpoint {sequence_number}, received {actual_sequence}"
        );
        Ok(timestamp_secs)
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
            format!("{}::deposit::DepositApproved", self.package_id),
            format!("{}::deposit::DepositRequested", self.package_id),
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
        let sui_events = transaction
            .events
            .context("filtered Sui transaction is missing events")?
            .events;

        for sui_event in sui_events {
            approval::parse_event(
                &self.package_versions,
                &self.hashi_btc_keys,
                sui_event,
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
    use super::approval::tests::approval_tx;
    use super::approval::tests::withdrawal_transaction;
    use super::*;
    use crate::domain::MonitorWithdrawalEvent;
    use crate::domain::WithdrawalEventType;
    use crate::test_utils::test_hashi_btc_keys;

    use std::sync::Arc;
    use std::sync::Mutex;

    use sui_rpc::proto::sui::rpc::v2::Checkpoint;
    use sui_rpc::proto::sui::rpc::v2::CheckpointSummary;
    use sui_rpc::proto::sui::rpc::v2::GetCheckpointResponse;
    use sui_rpc::proto::sui::rpc::v2::GetObjectResponse;
    use sui_rpc::proto::sui::rpc::v2::GetServiceInfoResponse;
    use sui_rpc::proto::sui::rpc::v2::GetTransactionResponse;
    use sui_rpc::proto::sui::rpc::v2::ListTransactionsResponse;
    use sui_rpc::proto::sui::rpc::v2::QueryEnd;
    use sui_rpc::proto::sui::rpc::v2::Watermark;
    use sui_rpc::proto::sui::rpc::v2::get_checkpoint_request::CheckpointId;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerService;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerServiceServer;
    use sui_rpc::proto::timestamp_ms_to_proto;

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

    /// A ledger holding the package `PACKAGE_ID`, published by the transaction
    /// `PUBLISH_DIGEST` at `PUBLISH_SECS`. Each `None` leaves that field out.
    #[derive(Clone)]
    struct PublishedPackageLedger {
        previous_transaction: Option<String>,
        timestamp: Option<UnixSeconds>,
    }

    const PUBLISH_DIGEST: &str = "11111111111111111111111111111111";
    const PUBLISH_CHECKPOINT: u64 = 4_200;
    const PUBLISH_SECS: UnixSeconds = 1_690_000_000;

    #[tonic::async_trait]
    impl LedgerService for PublishedPackageLedger {
        async fn get_object(
            &self,
            request: tonic::Request<GetObjectRequest>,
        ) -> Result<tonic::Response<GetObjectResponse>, tonic::Status> {
            if request.into_inner().object_id != Some(PACKAGE_ID.to_string()) {
                return Err(tonic::Status::not_found("no such object"));
            }
            let mut object = Object::default();
            object.previous_transaction = self.previous_transaction.clone();
            Ok(tonic::Response::new(GetObjectResponse::new(object)))
        }

        async fn get_transaction(
            &self,
            request: tonic::Request<GetTransactionRequest>,
        ) -> Result<tonic::Response<GetTransactionResponse>, tonic::Status> {
            if request.into_inner().digest.as_deref() != Some(PUBLISH_DIGEST) {
                return Err(tonic::Status::not_found("no such transaction"));
            }
            let mut transaction = ExecutedTransaction::default();
            transaction.checkpoint = Some(PUBLISH_CHECKPOINT);
            transaction.timestamp = self
                .timestamp
                .map(|seconds| timestamp_ms_to_proto(seconds * 1_000));
            Ok(tonic::Response::new(GetTransactionResponse::new(
                transaction,
            )))
        }
    }

    /// Serve `ledger` on a local port and return the config that reaches it.
    async fn serve(ledger: impl LedgerService) -> SuiConfig {
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
        SuiConfig {
            rpc_url: format!("http://{addr}"),
            package_id: PACKAGE_ID.to_string(),
        }
    }

    async fn poller_for(ledger: impl LedgerService) -> SuiEventsPoller {
        let config = serve(ledger).await;
        SuiEventsPoller::new(&config, test_hashi_btc_keys(), 0).unwrap()
    }

    #[tokio::test]
    async fn the_genesis_is_the_checkpoint_and_time_of_the_publish_transaction() {
        let config = serve(PublishedPackageLedger {
            previous_transaction: Some(PUBLISH_DIGEST.to_string()),
            timestamp: Some(PUBLISH_SECS),
        })
        .await;

        assert_eq!(
            package_genesis(&config).await.unwrap(),
            Genesis {
                checkpoint: PUBLISH_CHECKPOINT,
                timestamp: PUBLISH_SECS,
            }
        );
    }

    #[tokio::test]
    async fn a_package_without_a_previous_transaction_is_an_error() {
        let config = serve(PublishedPackageLedger {
            previous_transaction: None,
            timestamp: Some(PUBLISH_SECS),
        })
        .await;

        let error = format!("{:#}", package_genesis(&config).await.unwrap_err());

        assert!(
            error.contains(&format!(
                "Hashi package {PACKAGE_ID} is missing previous_transaction"
            )),
            "{error}"
        );
    }

    /// The Hashi approval of `withdrawal_transaction(WID)`.
    pub fn hashi_approval() -> MonitorWithdrawalEvent {
        let txn = withdrawal_transaction(WID);
        MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E1HashiApproved,
            wid: WID,
            timestamp_secs: unix_millis_to_seconds(txn.created_timestamp_ms),
            btc_txid: txn.txid.into(),
            tx: approval_tx(&txn),
        }
    }

    /// A poller whose cursor is at `cursor`. No Sui node serves it.
    pub fn poller_scanned(cursor: UnixSeconds) -> SuiEventsPoller {
        let config = SuiConfig {
            rpc_url: "http://127.0.0.1:9".to_string(),
            package_id: PACKAGE_ID.to_string(),
        };
        let mut poller = SuiEventsPoller::new(&config, test_hashi_btc_keys(), 0).unwrap();
        poller.cursor_seconds = cursor;
        poller
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

    /// A poller over `PrunedLedger` whose scan starts at checkpoint `start`.
    async fn pruned_poller_starting_at(start: u64) -> SuiEventsPoller {
        let config = serve(PrunedLedger {
            lowest: 100_000,
            head: 200_000,
        })
        .await;
        SuiEventsPoller::new(&config, test_hashi_btc_keys(), start).unwrap()
    }

    #[tokio::test]
    async fn a_start_the_node_serves_sets_the_cursor_to_the_checkpoint_before() {
        let mut poller = pruned_poller_starting_at(130_000).await;

        poller.ensure_start_is_served().await.unwrap();

        assert_eq!(poller.next_checkpoint(), 130_000);
        assert_eq!(poller.cursor_seconds(), GENESIS_SECS + 129_999);
    }

    #[tokio::test]
    async fn a_start_at_or_near_the_pruned_history_fails() {
        // Below the oldest checkpoint, and inside the margin above it.
        for start in [50_000, 100_000 + PRUNING_MARGIN_CHECKPOINTS] {
            let mut poller = pruned_poller_starting_at(start).await;

            let error = format!("{:#}", poller.ensure_start_is_served().await.unwrap_err());

            assert!(error.contains("has pruned checkpoint"), "{error}");
        }
    }

    /// `PrunedLedger`'s checkpoints, plus a `ListTransactions` that records each
    /// requested range and answers it with no transactions, up to its bound.
    #[derive(Clone)]
    struct ScanningLedger {
        checkpoints: PrunedLedger,
        ranges: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    #[tonic::async_trait]
    impl LedgerService for ScanningLedger {
        async fn get_service_info(
            &self,
            request: tonic::Request<GetServiceInfoRequest>,
        ) -> Result<tonic::Response<GetServiceInfoResponse>, tonic::Status> {
            self.checkpoints.get_service_info(request).await
        }

        async fn get_checkpoint(
            &self,
            request: tonic::Request<GetCheckpointRequest>,
        ) -> Result<tonic::Response<GetCheckpointResponse>, tonic::Status> {
            self.checkpoints.get_checkpoint(request).await
        }

        async fn list_transactions(
            &self,
            request: tonic::Request<ListTransactionsRequest>,
        ) -> Result<
            tonic::Response<tonic::codegen::BoxStream<ListTransactionsResponse>>,
            tonic::Status,
        > {
            let request = request.into_inner();
            let (start, end) = (
                request.start_checkpoint.unwrap_or(0),
                request.end_checkpoint.unwrap_or(0),
            );
            self.ranges.lock().unwrap().push((start, end));
            let mut watermark = Watermark::default();
            watermark.cursor = Some(b"bound".to_vec().into());
            watermark.checkpoint = Some(end - 1);
            let mut query_end = QueryEnd::default();
            query_end.reason = Some(QueryEndReason::CheckpointBound as i32);
            let mut frame = ListTransactionsResponse::default();
            frame.watermark = Some(watermark);
            frame.end = Some(query_end);
            Ok(tonic::Response::new(Box::pin(futures::stream::once(
                async { Ok(frame) },
            ))))
        }
    }

    #[tokio::test]
    async fn a_poll_scans_at_most_the_range_cap_and_the_next_poll_continues() {
        let ledger = ScanningLedger {
            checkpoints: PrunedLedger {
                lowest: 0,
                head: 3 * MAX_CHECKPOINTS_PER_POLL,
            },
            ranges: Arc::default(),
        };
        let mut poller = poller_for(ledger.clone()).await;

        for expected_cursor_checkpoint in [MAX_CHECKPOINTS_PER_POLL, 2 * MAX_CHECKPOINTS_PER_POLL] {
            assert!(matches!(
                poller.poll(3 * MAX_CHECKPOINTS_PER_POLL).await.unwrap(),
                PollOutcome::CursorAdvanced { .. }
            ));
            assert_eq!(poller.next_checkpoint(), expected_cursor_checkpoint);
            assert_eq!(
                poller.cursor_seconds(),
                GENESIS_SECS + expected_cursor_checkpoint - 1
            );
        }
        assert_eq!(
            *ledger.ranges.lock().unwrap(),
            vec![
                (0, MAX_CHECKPOINTS_PER_POLL),
                (MAX_CHECKPOINTS_PER_POLL, 2 * MAX_CHECKPOINTS_PER_POLL),
            ]
        );
    }
}
