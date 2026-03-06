use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;
use hashi_types::guardian::time_utils::UnixSeconds;
use std::fmt;

/// Findings emitted by the monitor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorError {
    InvalidEventAdded(String),
    EventOccurredAfterDeadline {
        event: MonitorWithdrawalEvent,
        deadline: UnixSeconds,
        occurred_at: UnixSeconds, // same as event.timestamp
    },
    ExpectedEventMissing {
        event_type: WithdrawalEventType,
        deadline: UnixSeconds,
        cursor: UnixSeconds,
    },
}

impl fmt::Display for MonitorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
