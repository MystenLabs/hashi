// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The findings the monitor reports.
//!
//! Why it exists: every check in the pollers and the state machines reports
//! its result as one value of `MonitorFinding`. The auditor logs each
//! finding, and the metrics record the time of the last one.
//!
//! Assumptions:
//! - Every finding needs an operator action. A condition that needs no
//!   action is not a finding.
//! - Every operator must act on an essential finding. The other findings
//!   show no loss of Bitcoin backing. `AlertMode` decides if they alert.
//! - `BtcRpcInconsistency` means a Bitcoin RPC answer contradicts one the
//!   monitor already holds. The bridge cannot cause it. The inner enum names
//!   the contradiction.
//! - `GuardianInconsistency` means a guardian log that an honest guardian
//!   cannot write. The guardian is the cause. The inner enum names the rule
//!   it breaks.

use crate::domain::BtcConfirmedDeposit;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::SuiDepositApprovedEvent;
use crate::domain::SuiDepositRequestedEvent;
use crate::domain::UtxoOrigin;
use crate::domain::WithdrawalEventType;
use crate::domain::WithdrawalTx;
use crate::domain::utxo_pool::Utxo;
use crate::time::human_duration;
use crate::time::human_timestamp_delta;
use crate::time::utc_timestamp;
use crate::timing::Timing;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixMillis;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use sui_sdk_types::Address;

/// The findings that alert: an ERROR log line, and the finding metric. A
/// finding that does not alert is a WARN log line.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AlertMode {
    /// Every finding alerts.
    #[default]
    Strict,
    /// Only the essential findings alert. See `MonitorFinding::is_essential`.
    Essential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum EventRelation {
    Predecessor,
    Successor,
}

/// Why a paid deposit has no approval, as far as the monitor can infer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnapprovedCause {
    /// Bitcoin paid another amount than the request claims.
    AmountMismatch,
    /// The block is more than `DEPOSIT_REQUEST_EXPIRY` after the request.
    PaidAfterExpiry,
    /// Neither of the above: a sanction, or a committee that withholds the
    /// approval. The monitor cannot tell them apart.
    SanctionOrWithheld,
}

impl UnapprovedCause {
    /// The causes for a payment of `paid_amount` in a block at `block_time`,
    /// for a request of `requested_amount` at `requested_at`.
    fn infer(
        requested_amount: u64,
        paid_amount: u64,
        requested_at: UnixSeconds,
        block_time: UnixSeconds,
        timing: &Timing,
    ) -> Vec<Self> {
        let mut causes = Vec::new();
        if paid_amount != requested_amount {
            causes.push(Self::AmountMismatch);
        }
        if block_time > requested_at + timing.deposit_request_expiry {
            causes.push(Self::PaidAfterExpiry);
        }
        if causes.is_empty() {
            causes.push(Self::SanctionOrWithheld);
        }
        causes
    }
}

/// Why two events of one deposit request disagree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DepositMismatchReason {
    /// E2 and E3: the Bitcoin payment and the approval differ in amount or
    /// script.
    PaymentDiffers {
        sui: SuiDepositApprovedEvent,
        btc: BtcConfirmedDeposit,
    },
    /// E1 and E3: the approval differs from its request. Move copies the
    /// request, so Move has a fault or the Sui answer is wrong.
    ApprovalDiffers {
        request: SuiDepositRequestedEvent,
        approval: SuiDepositApprovedEvent,
    },
    /// E1 and E1: a request came again with other contents.
    RequestDiffers {
        held: SuiDepositRequestedEvent,
        new: SuiDepositRequestedEvent,
    },
}

/// Findings emitted by the monitor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorFinding {
    InvalidEventAdded(String),
    /// A withdrawal event came after its deadline in the timing table.
    WithdrawalEventLate {
        event: MonitorWithdrawalEvent,
        relation: EventRelation,
        deadline: UnixSeconds,
        occurred_at: UnixSeconds, // same as event.timestamp
    },
    /// A withdrawal event is still missing after its deadline in the timing
    /// table, at the cursor of its source.
    WithdrawalEventMissing {
        wid: WithdrawalID,
        event_type: WithdrawalEventType,
        relation: EventRelation,
        deadline: UnixSeconds,
        cursor: UnixSeconds,
    },
    /// The Hashi approval's txid is not the txid of the transaction that its
    /// inputs and outputs build.
    WithdrawalTxidMismatch {
        wid: WithdrawalID,
        claimed: Txid,
        computed: Txid,
    },
    /// The Hashi approval's inputs and outputs do not build a Bitcoin transaction.
    WithdrawalTxUnbuildable {
        wid: WithdrawalID,
        claimed: Txid,
        reason: String,
    },
    /// The Hashi approval and the guardian's log state different inputs,
    /// user payouts or change for the withdrawal.
    WithdrawalMismatch {
        wid: WithdrawalID,
        sui: WithdrawalTx,
        guardian: WithdrawalTx,
    },
    /// E3 without E2: Hashi approved a deposit, but its outpoint holds no
    /// unspent Bitcoin output.
    DepositUnbacked {
        sui: SuiDepositApprovedEvent,
    },
    /// E3 and E2 found, but the E2 block is later than E3 plus the skew.
    ///
    /// Hashi approved a deposit whose block is later than `deadline`, the
    /// approval plus the skew. Either Hashi approved before Bitcoin
    /// confirmed, or a miner dated the block past the skew.
    DepositLate {
        sui: SuiDepositApprovedEvent,
        deadline: UnixSeconds,
        block_time: UnixSeconds,
    },
    /// Two events of one deposit request disagree. See
    /// `DepositMismatchReason`.
    DepositMismatch {
        request_id: Address,
        reason: DepositMismatchReason,
    },
    /// E2 found, but no E3 `DEPOSIT_REQUEST_WATCH` after the latest request.
    /// `causes` gives what the monitor can infer. The daily pool check
    /// repeats it until an approval comes.
    DepositNotApproved {
        outpoint: OutPoint,
        requested_amount: u64,
        paid_amount: u64,
        requested_at: UnixSeconds,
        block_time: UnixSeconds,
        causes: Vec<UnapprovedCause>,
    },
    /// A Bitcoin RPC answer contradicts one the monitor already holds. See
    /// `BtcRpcInconsistency`.
    BtcRpcInconsistency(BtcRpcInconsistency),
    /// A UTXO in the monitor's UTXO pool has sat unspent on Bitcoin past the
    /// warn age. The committee can spend a UTXO alone 60 days after it
    /// confirms. This includes an unapproved deposit: a committee that
    /// withholds the approval can take it then.
    UtxoTooOld {
        outpoint: OutPoint,
        age_secs: u64,
        threshold_secs: u64,
    },
    /// A UTXO in the monitor's UTXO pool was spent on Bitcoin, and no Hashi
    /// withdrawal confirmed on Bitcoin spent it.
    UtxoUnexpectedSpend {
        outpoint: OutPoint,
        amount: u64,
    },
    /// A confirmed Hashi withdrawal spent a UTXO that is not in Move's pool,
    /// by the monitor's account. `held` is `None` if the pool never held it.
    /// The monitor missed an event, or Move has a fault.
    UtxoOutsideMovePoolSpent {
        outpoint: OutPoint,
        txid: Txid,
        held: Option<UtxoOrigin>,
    },
    /// A deposit and a withdrawal's change claim one outpoint. Move refuses a
    /// request for held change, so an insider or a Move fault is the cause.
    UtxoOriginConflict {
        outpoint: OutPoint,
        held: UtxoOrigin,
        new: UtxoOrigin,
    },
    /// Sui's hBTC supply has exceeded the value of the UTXO pool since
    /// `since`, for longer than the grace. Bitcoin does not back every hBTC.
    HbtcSupplyExceedsPool {
        hbtc_supply: u64,
        pool_value: u64,
        since: UnixSeconds,
    },
    /// A source was last checked longer ago than its limit. Its events go
    /// unchecked until it catches up.
    SourceStale {
        source: &'static str,
        checked_through: UnixSeconds,
        limit_secs: u64,
    },
    /// No snapshot save has succeeded for longer than the limit. A restart
    /// repeats the work done since the last save.
    SnapshotStale {
        last_saved: UnixSeconds,
        limit_secs: u64,
    },
    /// The time the guardian signed into a log differs from the time S3
    /// recorded the object by more than `MAX_EXPECTED_LOG_CLOCK_SKEW`.
    GuardianClockSkew {
        session_id: SessionID,
        object_key: String,
        /// The guardian's signed time.
        logged_at_ms: UnixMillis,
        /// S3's `LastModified` time.
        stored_at_ms: UnixMillis,
    },
    /// The guardian's logs break a rule that an honest guardian keeps. See
    /// `GuardianInconsistency`.
    GuardianInconsistency(GuardianInconsistency),
}

impl MonitorFinding {
    /// A `DepositNotApproved` for the held `utxo` at `outpoint`, with the
    /// causes that the monitor can infer. `None` if `utxo` is not an
    /// unapproved deposit.
    pub fn deposit_not_approved(outpoint: OutPoint, utxo: &Utxo, timing: &Timing) -> Option<Self> {
        let UtxoOrigin::UnapprovedDeposit {
            requested_at,
            requested_amount,
        } = utxo.origin
        else {
            return None;
        };
        Some(Self::DepositNotApproved {
            outpoint,
            requested_amount,
            paid_amount: utxo.amount,
            requested_at,
            block_time: utxo.first_seen,
            causes: UnapprovedCause::infer(
                requested_amount,
                utxo.amount,
                requested_at,
                utxo.first_seen,
                timing,
            ),
        })
    }

    /// Whether every operator must act on the finding. The other findings
    /// show no loss of Bitcoin backing.
    pub fn is_essential(&self) -> bool {
        match self {
            // Hashi approved before Bitcoin confirmed, or a miner dated the
            // block late. The payment came, so Bitcoin now backs the hBTC.
            Self::DepositLate { .. } => false,
            // No hBTC was minted. A user waits for it.
            Self::DepositNotApproved { .. } => false,
            // A bad guardian clock or a slow S3 write. The checks still run.
            Self::GuardianClockSkew { .. } => false,
            Self::InvalidEventAdded(_)
            | Self::WithdrawalEventLate { .. }
            | Self::WithdrawalEventMissing { .. }
            | Self::WithdrawalTxidMismatch { .. }
            | Self::WithdrawalTxUnbuildable { .. }
            | Self::WithdrawalMismatch { .. }
            | Self::DepositUnbacked { .. }
            | Self::DepositMismatch { .. }
            | Self::BtcRpcInconsistency(_)
            | Self::UtxoTooOld { .. }
            | Self::UtxoUnexpectedSpend { .. }
            | Self::UtxoOutsideMovePoolSpent { .. }
            | Self::UtxoOriginConflict { .. }
            | Self::HbtcSupplyExceedsPool { .. }
            | Self::SourceStale { .. }
            | Self::SnapshotStale { .. }
            | Self::GuardianInconsistency(_) => true,
        }
    }

    /// Whether the finding alerts in `mode`.
    pub fn alerts_in(&self, mode: AlertMode) -> bool {
        mode == AlertMode::Strict || self.is_essential()
    }

    /// The variant name. Alerting labels each finding with it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidEventAdded(_) => "InvalidEventAdded",
            Self::WithdrawalEventLate { .. } => "WithdrawalEventLate",
            Self::WithdrawalEventMissing { .. } => "WithdrawalEventMissing",
            Self::WithdrawalTxidMismatch { .. } => "WithdrawalTxidMismatch",
            Self::WithdrawalTxUnbuildable { .. } => "WithdrawalTxUnbuildable",
            Self::WithdrawalMismatch { .. } => "WithdrawalMismatch",
            Self::DepositUnbacked { .. } => "DepositUnbacked",
            Self::DepositLate { .. } => "DepositLate",
            Self::DepositMismatch { .. } => "DepositMismatch",
            Self::DepositNotApproved { .. } => "DepositNotApproved",
            Self::BtcRpcInconsistency(_) => "BtcRpcInconsistency",
            Self::UtxoTooOld { .. } => "UtxoTooOld",
            Self::UtxoUnexpectedSpend { .. } => "UtxoUnexpectedSpend",
            Self::UtxoOutsideMovePoolSpent { .. } => "UtxoOutsideMovePoolSpent",
            Self::UtxoOriginConflict { .. } => "UtxoOriginConflict",
            Self::HbtcSupplyExceedsPool { .. } => "HbtcSupplyExceedsPool",
            Self::SourceStale { .. } => "SourceStale",
            Self::SnapshotStale { .. } => "SnapshotStale",
            Self::GuardianClockSkew { .. } => "GuardianClockSkew",
            Self::GuardianInconsistency(_) => "GuardianInconsistency",
        }
    }
}

/// A Bitcoin RPC answer that contradicts one the monitor already holds. A
/// chain cannot produce it, so it is a lying node, a reorg, or a monitor
/// bug. The bridge is not the cause, and an engineer has to look.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BtcRpcInconsistency {
    /// Bitcoin confirmed an outpoint the monitor's UTXO pool knows with a
    /// second amount or script. An output has one of each.
    UtxoMismatch {
        outpoint: OutPoint,
        held_amount: u64,
        seen_amount: u64,
        held_script: ScriptBuf,
        seen_script: ScriptBuf,
    },
    /// A UTXO the monitor's UTXO pool holds does not exist on Bitcoin at the
    /// daily pool check. Bitcoin confirmed it once.
    UtxoVanished {
        outpoint: OutPoint,
        first_seen: UnixSeconds,
    },
}

/// A guardian log that an honest guardian cannot write. The guardian is
/// the cause, and an engineer has to look.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuardianInconsistency {
    /// Two withdrawal logs have the same seq. The guardian's limiter takes
    /// each seq once, so two guardian sessions signed from one limiter state.
    SeqDuplicate { seq: u64, object_key: String },
    /// No withdrawal log has `seq` by `expect_by`, but a later seq has one.
    /// The guardian signed a withdrawal without a log, or a log was lost.
    SeqGap { seq: u64, expect_by: UnixSeconds },
    /// A withdrawal log skips more than a few seqs: its seq is far above
    /// `next_seq`, the seq that the monitor expects next.
    SeqJump {
        next_seq: u64,
        seq: u64,
        object_key: String,
    },
}

impl fmt::Display for GuardianInconsistency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SeqDuplicate { seq, object_key } => {
                write!(f, "SeqDuplicate(seq={seq}, key={object_key})")
            }
            Self::SeqGap { seq, expect_by } => write!(
                f,
                "SeqGap(seq={seq}, expect_by={})",
                utc_timestamp(*expect_by)
            ),
            Self::SeqJump {
                next_seq,
                seq,
                object_key,
            } => write!(
                f,
                "SeqJump(next_seq={next_seq}, seq={seq}, key={object_key})"
            ),
        }
    }
}

impl fmt::Display for BtcRpcInconsistency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UtxoMismatch {
                outpoint,
                held_amount,
                seen_amount,
                held_script,
                seen_script,
            } => write!(
                f,
                "UtxoMismatch(outpoint={outpoint}, held_amount={held_amount}, seen_amount={seen_amount}, held_script={held_script:x}, seen_script={seen_script:x})"
            ),
            Self::UtxoVanished {
                outpoint,
                first_seen,
            } => write!(
                f,
                "UtxoVanished(outpoint={outpoint}, first_seen={})",
                utc_timestamp(*first_seen),
            ),
        }
    }
}

impl fmt::Display for DepositMismatchReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PaymentDiffers { sui, btc } => write!(
                f,
                "PaymentDiffers(deposit_id={}, hashi_amount={}, btc_amount={}, hashi_script={:x}, btc_script={:x})",
                sui.deposit_id, sui.amount, btc.amount, sui.script_pubkey, btc.script_pubkey,
            ),
            Self::ApprovalDiffers { request, approval } => write!(
                f,
                "ApprovalDiffers(request={}, approval={})",
                MonitorEvent::DepositRequested(request.clone()),
                MonitorEvent::DepositApproved(approval.clone()),
            ),
            Self::RequestDiffers { held, new } => write!(
                f,
                "RequestDiffers(held={}, new={})",
                MonitorEvent::DepositRequested(held.clone()),
                MonitorEvent::DepositRequested(new.clone()),
            ),
        }
    }
}

impl fmt::Display for MonitorFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEventAdded(message) => {
                write!(f, "InvalidEventAdded(message={message})")
            }
            Self::WithdrawalEventLate {
                event,
                relation,
                deadline,
                occurred_at,
            } => write!(
                f,
                "WithdrawalEventLate(event={}, relation={relation:?}, deadline={}, occurred_at={}, late_by={})",
                MonitorEvent::Withdrawal(event.clone()),
                utc_timestamp(*deadline),
                utc_timestamp(*occurred_at),
                human_duration(occurred_at.saturating_sub(*deadline)),
            ),
            Self::WithdrawalEventMissing {
                wid,
                event_type,
                relation,
                deadline,
                cursor,
            } => write!(
                f,
                "WithdrawalEventMissing(wid={wid}, event_type={event_type:?}, relation={relation:?}, deadline={}, cursor={})",
                utc_timestamp(*deadline),
                utc_timestamp(*cursor),
            ),
            Self::WithdrawalTxidMismatch {
                wid,
                claimed,
                computed,
            } => write!(
                f,
                "WithdrawalTxidMismatch(wid={wid}, claimed={claimed}, computed={computed})"
            ),
            Self::WithdrawalTxUnbuildable {
                wid,
                claimed,
                reason,
            } => write!(
                f,
                "WithdrawalTxUnbuildable(wid={wid}, claimed={claimed}, reason={reason})"
            ),
            Self::WithdrawalMismatch { wid, sui, guardian } => write!(
                f,
                "WithdrawalMismatch(wid={wid}, sui={{{sui}}}, guardian={{{guardian}}})",
            ),
            Self::DepositUnbacked { sui } => write!(
                f,
                "DepositUnbacked({})",
                MonitorEvent::DepositApproved(sui.clone()),
            ),
            Self::DepositLate {
                sui,
                deadline,
                block_time,
            } => write!(
                f,
                "DepositLate({}, deadline={}, block_time={})",
                MonitorEvent::DepositApproved(sui.clone()),
                utc_timestamp(*deadline),
                utc_timestamp(*block_time),
            ),
            Self::DepositMismatch { request_id, reason } => {
                write!(f, "DepositMismatch(request_id={request_id}, {reason})")
            }
            Self::DepositNotApproved {
                outpoint,
                requested_amount,
                paid_amount,
                requested_at,
                block_time,
                causes,
            } => write!(
                f,
                "DepositNotApproved(outpoint={outpoint}, requested_amount={requested_amount}, paid_amount={paid_amount}, requested_at={}, block_time={}, causes={causes:?})",
                utc_timestamp(*requested_at),
                utc_timestamp(*block_time),
            ),
            Self::BtcRpcInconsistency(inconsistency) => {
                write!(f, "BtcRpcInconsistency({inconsistency})")
            }
            Self::UtxoTooOld {
                outpoint,
                age_secs,
                threshold_secs,
            } => write!(
                f,
                "UtxoTooOld(outpoint={outpoint}, age={}, threshold={})",
                human_duration(*age_secs),
                human_duration(*threshold_secs),
            ),
            Self::UtxoUnexpectedSpend { outpoint, amount } => write!(
                f,
                "UtxoUnexpectedSpend(outpoint={outpoint}, amount={amount})"
            ),
            Self::UtxoOutsideMovePoolSpent {
                outpoint,
                txid,
                held,
            } => write!(
                f,
                "UtxoOutsideMovePoolSpent(outpoint={outpoint}, txid={txid}, held={held:?})"
            ),
            Self::UtxoOriginConflict {
                outpoint,
                held,
                new,
            } => write!(
                f,
                "UtxoOriginConflict(outpoint={outpoint}, held={held:?}, new={new:?})"
            ),
            Self::HbtcSupplyExceedsPool {
                hbtc_supply,
                pool_value,
                since,
            } => write!(
                f,
                "HbtcSupplyExceedsPool(hbtc_supply={hbtc_supply}, pool_value={pool_value}, excess={}, since={})",
                hbtc_supply.saturating_sub(*pool_value),
                utc_timestamp(*since),
            ),
            Self::SourceStale {
                source,
                checked_through,
                limit_secs,
            } => write!(
                f,
                "SourceStale(source={source}, checked_through={}, limit={})",
                utc_timestamp(*checked_through),
                human_duration(*limit_secs),
            ),
            Self::SnapshotStale {
                last_saved,
                limit_secs,
            } => write!(
                f,
                "SnapshotStale(last_saved={}, limit={})",
                utc_timestamp(*last_saved),
                human_duration(*limit_secs),
            ),
            Self::GuardianClockSkew {
                session_id,
                object_key,
                logged_at_ms,
                stored_at_ms,
            } => {
                let logged_at = unix_millis_to_seconds(*logged_at_ms);
                let stored_at = unix_millis_to_seconds(*stored_at_ms);
                let skew_ms = i128::from(*stored_at_ms) - i128::from(*logged_at_ms);
                write!(
                    f,
                    "GuardianClockSkew(session_id={session_id}, key={object_key}, guardian_time={}, s3_time={}, s3_minus_guardian={} ({skew_ms}ms))",
                    utc_timestamp(logged_at),
                    utc_timestamp(stored_at),
                    human_timestamp_delta(stored_at, logged_at),
                )
            }
            Self::GuardianInconsistency(inconsistency) => {
                write!(f, "GuardianInconsistency({inconsistency})")
            }
        }
    }
}
