// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::domain::MonitorEvent;
use crate::domain::MonitorEventType;
use crate::domain::utc_timestamp;
use hashi_types::guardian::time_utils::UnixSeconds;
use std::fmt;

struct HumanDuration(UnixSeconds);

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hours = self.0 / 3_600;
        let minutes = (self.0 % 3_600) / 60;
        let seconds = self.0 % 60;

        if hours > 0 {
            write!(f, "{hours}h")?;
        }
        if minutes > 0 || hours > 0 {
            write!(f, "{minutes}m")?;
        }
        write!(f, "{seconds}s")
    }
}

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
                HumanDuration(occurred_at.saturating_sub(*deadline)),
            ),
            Self::ExpectedEventMissing {
                event_type,
                relation,
                deadline,
                cursor,
            } => write!(
                f,
                "ExpectedEventMissing(event_type={event_type:?}, relation={relation:?}, deadline={}, cursor={})",
                utc_timestamp(*deadline),
                utc_timestamp(*cursor),
            ),
        }
    }
}
