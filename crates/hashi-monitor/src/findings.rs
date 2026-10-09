// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::domain::DepositId;
use crate::domain::MonitorEvent;
use crate::domain::MonitorEventId;
use crate::domain::MonitorEventType;
use crate::domain::human_duration;
use crate::domain::utc_timestamp;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::bitcoin::DerivationPath;
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
    /// The deposit's Bitcoin output does not hold the amount the Sui request claims.
    DepositAmountMismatch {
        deposit_id: DepositId,
        claimed: u64,
        onchain: u64,
    },
    /// The deposit's Bitcoin output does not pay the bridge address of the
    /// derivation path the Sui request claims.
    DepositOutputNotToBridge {
        deposit_id: DepositId,
        derivation_path: Option<DerivationPath>,
        script_pubkey: ScriptBuf,
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
            Self::DepositAmountMismatch { .. } => FindingCategory::Safety,
            Self::DepositOutputNotToBridge { .. } => FindingCategory::Safety,
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
            Self::DepositAmountMismatch {
                deposit_id,
                claimed,
                onchain,
            } => write!(
                f,
                "DepositAmountMismatch(deposit_id={deposit_id}, claimed={claimed}, onchain={onchain})"
            ),
            Self::DepositOutputNotToBridge {
                deposit_id,
                derivation_path,
                script_pubkey,
            } => write!(
                f,
                "DepositOutputNotToBridge(deposit_id={deposit_id}, derivation_path={}, script_pubkey={script_pubkey:x})",
                derivation_path.map_or("none".to_string(), |path| path.to_string()),
            ),
        }
    }
}
