// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The findings the monitor reports.
//!
//! Why it exists: every check in the pollers and the state machines reports
//! its result as one value of `MonitorFinding`. The auditor logs each
//! finding, and the metrics record the time of the last one.
//!
//! Assumptions:
//! - Every finding needs an operator action, so all findings have one level.
//!   A condition that needs no action is not a finding.
//! - `RpcInconsistency` means an RPC answer contradicts one the monitor
//!   already holds. The bridge cannot cause it. The inner enum names the
//!   contradiction.

use crate::domain::ConfirmedDeposit;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::SuiDepositApprovedEvent;
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
use serde::Deserialize;
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum EventRelation {
    Predecessor,
    Successor,
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
    /// Hashi approved a deposit for minting that Bitcoin shows no matching
    /// deposit for.
    DepositUnbacked {
        sui: SuiDepositApprovedEvent,
    },
    /// Hashi approved a deposit whose block is later than `deadline`, the
    /// approval plus the skew. Either Hashi approved before Bitcoin
    /// confirmed, or a miner dated the block past the skew.
    DepositLate {
        sui: SuiDepositApprovedEvent,
        deadline: UnixSeconds,
        block_time: UnixSeconds,
    },
    /// The deposit Bitcoin confirmed differs in amount or script from the
    /// one Hashi approved.
    DepositMismatch {
        sui: SuiDepositApprovedEvent,
        btc: ConfirmedDeposit,
    },
    /// An RPC answer contradicts one the monitor already holds. See
    /// `RpcInconsistency`.
    RpcInconsistency(RpcInconsistency),
    /// A UTXO in the monitor's UTXO pool has sat unspent on Bitcoin past the
    /// warn age. The committee can spend a UTXO alone 60 days after it
    /// confirms.
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
    /// A confirmed Hashi withdrawal spent a UTXO the monitor's UTXO pool
    /// never held. The bridge spent a UTXO that no verified deposit or
    /// change brought in, or the pool missed the UTXO's entry.
    UtxoUnknownInputSpent {
        outpoint: OutPoint,
        txid: Txid,
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
}

impl MonitorFinding {
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
            Self::RpcInconsistency(_) => "RpcInconsistency",
            Self::UtxoTooOld { .. } => "UtxoTooOld",
            Self::UtxoUnexpectedSpend { .. } => "UtxoUnexpectedSpend",
            Self::UtxoUnknownInputSpent { .. } => "UtxoUnknownInputSpent",
            Self::SourceStale { .. } => "SourceStale",
            Self::SnapshotStale { .. } => "SnapshotStale",
            Self::GuardianClockSkew { .. } => "GuardianClockSkew",
        }
    }
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
            Self::DepositMismatch { sui, btc } => write!(
                f,
                "DepositMismatch(request_id={}, deposit_id={}, hashi_amount={}, btc_amount={}, hashi_script={:x}, btc_script={:x})",
                sui.request_id,
                sui.deposit_id,
                sui.amount,
                btc.amount,
                sui.script_pubkey,
                btc.script_pubkey,
            ),
            Self::RpcInconsistency(inconsistency) => {
                write!(f, "RpcInconsistency({inconsistency})")
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
            Self::UtxoUnknownInputSpent { outpoint, txid } => {
                write!(f, "UtxoUnknownInputSpent(outpoint={outpoint}, txid={txid})")
            }
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
        }
    }
}
