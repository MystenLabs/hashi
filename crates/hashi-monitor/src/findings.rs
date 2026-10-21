// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The findings the monitor reports, and their category.
//!
//! Why it exists: every check in the pollers and the state machines reports
//! its result as one value of `MonitorFinding`. The auditors log each
//! finding at the level of its category, and the metrics count them by
//! category.
//!
//! The categories:
//! - A liveness finding means a successor event is late or still missing
//!   after its deadline.
//! - A safety finding means a source contradicts another: a late or missing
//!   predecessor, a contradictory event, a transaction or deposit that does
//!   not match its claim, or a guardian clock that disagrees with S3.
//! - `RpcInconsistency` is a safety finding where an RPC answer contradicts
//!   one the monitor already holds. The bridge cannot cause it. The inner
//!   enum names the contradiction.

use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorEventId;
use crate::domain::MonitorEventType;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::WithdrawalTx;
use crate::time::human_duration;
use crate::time::human_timestamp_delta;
use crate::time::utc_timestamp;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixMillis;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventRelation {
    Predecessor,
    Successor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindingCategory {
    Safety,
    Liveness,
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Safety => write!(f, "safety"),
            Self::Liveness => write!(f, "liveness"),
        }
    }
}

/// Findings emitted by the monitor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorFinding {
    InvalidEventAdded(String),
    EventOccurredAfterDeadline {
        event: MonitorEvent,
        relation: EventRelation,
        deadline: UnixSeconds,
        occurred_at: UnixSeconds, // same as event.timestamp
    },
    ExpectedEventMissing {
        event_id: MonitorEventId,
        event_type: MonitorEventType,
        relation: EventRelation,
        deadline: UnixSeconds,
        cursor: UnixSeconds,
    },
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
    /// The Sui event scan covered `event` but never returned it, so other events the
    /// scan should have returned may be missing too.
    SuiScanMissedEvent {
        event: MonitorEvent,
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
    /// The confirmed Bitcoin transaction has no output at the deposit's vout.
    DepositOutputMissing {
        deposit_id: DepositId,
        output_count: usize,
    },
    /// The deposit Bitcoin confirms differs in amount or script from the one
    /// the Sui request claims.
    DepositMismatch {
        sui: MonitorDepositEvent,
        btc: MonitorDepositEvent,
    },
    /// An RPC answer contradicts one the monitor already holds. See
    /// `RpcInconsistency`.
    RpcInconsistency(RpcInconsistency),
    /// A UTXO in the monitor's UTXO pool has sat unspent on Bitcoin past the
    /// warn age, or past the critical age. The committee can spend a UTXO
    /// alone 60 days after it confirms.
    UtxoTooOld {
        outpoint: OutPoint,
        age_secs: u64,
        threshold_secs: u64,
        critical: bool,
    },
    /// A UTXO in the monitor's UTXO pool was spent on Bitcoin, and no Hashi
    /// withdrawal confirmed on Bitcoin spent it.
    UtxoUnexpectedSpend {
        outpoint: OutPoint,
        amount: u64,
    },
    /// A confirmed Hashi withdrawal spent a UTXO the monitor's UTXO pool
    /// never held. The bridge spent a UTXO that no verified deposit or
    /// change brought in, or the pool missed the UTXO's entry.
    UtxoUnknownInputSpent {
        outpoint: OutPoint,
        txid: Txid,
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
}

/// An RPC answer that contradicts one the monitor already holds. A chain
/// cannot produce it, so it is a lying node, a reorg, or a monitor bug.
/// The bridge is not the cause, and an engineer has to look.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcInconsistency {
    /// Bitcoin confirmed an outpoint the monitor's UTXO pool knows with a
    /// second amount or script. An output has one of each.
    UtxoMismatch {
        outpoint: OutPoint,
        held_amount: u64,
        seen_amount: u64,
        held_script: ScriptBuf,
        seen_script: ScriptBuf,
    },
    /// A confirmed Hashi withdrawal spent a UTXO the monitor's UTXO pool
    /// records as spent by another confirmed transaction.
    UtxoSpentTwice {
        outpoint: OutPoint,
        first_txid: Txid,
        second_txid: Txid,
    },
    /// A UTXO the monitor's UTXO pool holds does not exist on Bitcoin, and
    /// its grace period has passed. Bitcoin confirmed it once.
    UtxoVanished {
        outpoint: OutPoint,
        first_seen: UnixSeconds,
    },
}

impl fmt::Display for RpcInconsistency {
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
            Self::UtxoSpentTwice {
                outpoint,
                first_txid,
                second_txid,
            } => write!(
                f,
                "UtxoSpentTwice(outpoint={outpoint}, first_txid={first_txid}, second_txid={second_txid})"
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

impl MonitorFinding {
    pub fn category(&self) -> FindingCategory {
        match self {
            Self::InvalidEventAdded(_) => FindingCategory::Safety,
            Self::EventOccurredAfterDeadline { relation, .. } => match relation {
                EventRelation::Predecessor => FindingCategory::Safety,
                EventRelation::Successor => FindingCategory::Liveness,
            },
            Self::ExpectedEventMissing { relation, .. } => match relation {
                EventRelation::Predecessor => FindingCategory::Safety,
                EventRelation::Successor => FindingCategory::Liveness,
            },
            Self::WithdrawalEventLate { relation, .. } => match relation {
                EventRelation::Predecessor => FindingCategory::Safety,
                EventRelation::Successor => FindingCategory::Liveness,
            },
            Self::WithdrawalEventMissing { relation, .. } => match relation {
                EventRelation::Predecessor => FindingCategory::Safety,
                EventRelation::Successor => FindingCategory::Liveness,
            },
            Self::SuiScanMissedEvent { .. } => FindingCategory::Safety,
            Self::WithdrawalTxidMismatch { .. } => FindingCategory::Safety,
            Self::WithdrawalTxUnbuildable { .. } => FindingCategory::Safety,
            Self::WithdrawalMismatch { .. } => FindingCategory::Safety,
            Self::DepositOutputMissing { .. } => FindingCategory::Safety,
            Self::DepositMismatch { .. } => FindingCategory::Safety,
            Self::RpcInconsistency(_) => FindingCategory::Safety,
            Self::UtxoTooOld { critical, .. } => {
                if *critical {
                    FindingCategory::Safety
                } else {
                    FindingCategory::Liveness
                }
            }
            Self::UtxoUnexpectedSpend { .. } => FindingCategory::Safety,
            Self::UtxoUnknownInputSpent { .. } => FindingCategory::Safety,
            Self::GuardianClockSkew { .. } => FindingCategory::Safety,
        }
    }
}

impl fmt::Display for MonitorFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEventAdded(message) => {
                write!(f, "InvalidEventAdded(message={message})")
            }
            Self::EventOccurredAfterDeadline {
                event,
                relation,
                deadline,
                occurred_at,
            } => write!(
                f,
                "EventOccurredAfterDeadline(event={event}, relation={relation:?}, deadline={}, occurred_at={}, late_by={})",
                utc_timestamp(*deadline),
                utc_timestamp(*occurred_at),
                human_duration(occurred_at.saturating_sub(*deadline)),
            ),
            Self::ExpectedEventMissing {
                event_id,
                event_type,
                relation,
                deadline,
                cursor,
            } => write!(
                f,
                "ExpectedEventMissing({event_id}, event_type={event_type:?}, relation={relation:?}, deadline={}, cursor={})",
                utc_timestamp(*deadline),
                utc_timestamp(*cursor),
            ),
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
            Self::SuiScanMissedEvent { event, cursor } => write!(
                f,
                "SuiScanMissedEvent(event={event}, cursor={})",
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
            Self::DepositOutputMissing {
                deposit_id,
                output_count,
            } => write!(
                f,
                "DepositOutputMissing(deposit_id={deposit_id}, output_count={output_count})"
            ),
            Self::DepositMismatch { sui, btc } => write!(
                f,
                "DepositMismatch(deposit_id={}, sui_amount={}, btc_amount={}, sui_script={:x}, btc_script={:x})",
                sui.deposit_id, sui.amount, btc.amount, sui.script_pubkey, btc.script_pubkey,
            ),
            Self::RpcInconsistency(inconsistency) => {
                write!(f, "RpcInconsistency({inconsistency})")
            }
            Self::UtxoTooOld {
                outpoint,
                age_secs,
                threshold_secs,
                critical,
            } => write!(
                f,
                "UtxoTooOld(outpoint={outpoint}, age={}, threshold={}, critical={critical})",
                human_duration(*age_secs),
                human_duration(*threshold_secs),
            ),
            Self::UtxoUnexpectedSpend { outpoint, amount } => write!(
                f,
                "UtxoUnexpectedSpend(outpoint={outpoint}, amount={amount})"
            ),
            Self::UtxoUnknownInputSpent { outpoint, txid } => {
                write!(f, "UtxoUnknownInputSpent(outpoint={outpoint}, txid={txid})")
            }
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
        }
    }
}
