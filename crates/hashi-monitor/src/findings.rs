// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorEventId;
use crate::domain::MonitorEventType;
use crate::domain::human_duration;
use crate::domain::utc_timestamp;
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
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
    /// A change output of the Hashi approval does not pay the bridge's change address.
    ChangeOutputNotToBridge {
        wid: WithdrawalID,
        vout: u32,
        bitcoin_address: Vec<u8>,
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
            Self::SuiScanMissedEvent { .. } => FindingCategory::Safety,
            Self::WithdrawalTxidMismatch { .. } => FindingCategory::Safety,
            Self::WithdrawalTxUnbuildable { .. } => FindingCategory::Safety,
            Self::ChangeOutputNotToBridge { .. } => FindingCategory::Safety,
            Self::DepositOutputMissing { .. } => FindingCategory::Safety,
            Self::DepositMismatch { .. } => FindingCategory::Safety,
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
            Self::ChangeOutputNotToBridge {
                wid,
                vout,
                bitcoin_address,
            } => write!(
                f,
                "ChangeOutputNotToBridge(wid={wid}, vout={vout}, bitcoin_address={})",
                hex::encode(bitcoin_address),
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
        }
    }
}
