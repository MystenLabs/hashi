// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::domain::MonitorEvent;
use crate::domain::MonitorEventType;
use hashi_types::guardian::time_utils::UnixSeconds;
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
        event_type: MonitorEventType,
        relation: EventRelation,
        deadline: UnixSeconds,
        cursor: UnixSeconds,
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
                // TODO: Before treating a missing withdrawal predecessor as a
                // definitive safety finding, perform a focused Sui history
                // search. A too-small lookback can otherwise cause a false
                // positive.
                EventRelation::Predecessor => FindingCategory::Safety,
                EventRelation::Successor => FindingCategory::Liveness,
            },
        }
    }
}

impl fmt::Display for MonitorFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
