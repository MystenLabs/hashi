//! Auditor implementations.
//! Goal: Attempt to match all withdrawals that emit an event inside the input time window
//!       even if some corresponding events for that withdrawal occur outside the window.
//! Core workflow:
//!     - User inputs a window (either just start or both start & end).
//!     - We pull logs with an expanded window, e.g., see BatchAuditWindow & ContinuousAuditWindow
//!     - At a desired frequency, auditors do:
//!         - advance cursors
//!         - call `WithdrawalStateMachine::violations(&cursors, &audit_window)` to identify errors.

use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;

pub mod batch;
pub mod continuous;

pub use batch::BatchAuditor;
pub use continuous::ContinuousAuditor;

pub trait AuditWindow {
    fn in_window(&self, e: &WithdrawalEvent) -> bool;
}

/// A continuous audit only requires a start time
pub struct ContinuousAuditWindow {
    pub user_start: UnixSeconds,
    pub actual_start: UnixSeconds,
}

impl AuditWindow for ContinuousAuditWindow {
    fn in_window(&self, e: &WithdrawalEvent) -> bool {
        e.timestamp >= self.user_start
    }
}
