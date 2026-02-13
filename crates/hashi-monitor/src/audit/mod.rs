//! Auditor implementations.
//! Goal: Attempt to match all withdrawals that emit an event inside the input time window
//!       even if some corresponding events for that withdrawal occur outside the window.
//! Core workflow:
//!     - User inputs a window (either just start or both start & end).
//!     - We pull logs with an expanded window, e.g., see BatchAuditWindow & ContinuousAuditWindow
//!     - At a desired frequency, auditors do:
//!         - advance cursors
//!         - call `WithdrawalStateMachine::violations(&cursors, &audit_window)` to identify errors.

use crate::config::Config;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;

pub mod batch;
pub mod continuous;

pub use batch::BatchAuditor;
pub use continuous::ContinuousAuditor;

pub trait AuditWindow {
    fn in_window(&self, e: &WithdrawalEvent) -> bool;
}

/// the exact amount of time to look back or ahead to identify all the potentially interesting events
#[derive(Clone, Copy, Debug)]
pub struct BatchAuditWindow {
    /// time range input by user
    user_start: UnixSeconds,
    user_end: UnixSeconds,
    /// relaxed time ranges used to pull logs from sui & guardian
    sui_start: UnixSeconds,
    sui_end: UnixSeconds,
    guardian_start: UnixSeconds,
    guardian_end: UnixSeconds,
}

impl BatchAuditWindow {
    pub fn new(cfg: &Config, start: UnixSeconds, end: UnixSeconds, cur_time: UnixSeconds) -> Self {
        let sui_start = start.saturating_sub(cfg.e1_e2_delay_secs); // guardian_e2@{start} might match sui_e1@{start-e1_e2_delay_secs}
        let sui_end = end.saturating_add(cfg.clock_skew).min(cur_time); // guardian_e2@{end} might match sui_e1@{end+skew}

        let guardian_start = start.saturating_sub(cfg.clock_skew); // sui_e1@{start} might match guardian_e2@{start-skew}
        let guardian_end = end.saturating_add(cfg.e1_e2_delay_secs).min(cur_time); // sui_e1@{end} might match guardian_e2@{end+e1_e2_delay_secs}

        Self {
            user_start: start,
            user_end: end,
            sui_start,
            sui_end,
            guardian_start,
            guardian_end,
        }
    }

    pub fn sui_start(&self) -> UnixSeconds {
        self.sui_start
    }
    pub fn sui_end(self) -> UnixSeconds {
        self.sui_end
    }
    pub fn guardian_start(&self) -> UnixSeconds {
        self.guardian_start
    }
    pub fn guardian_end(self) -> UnixSeconds {
        self.guardian_end
    }
}

impl AuditWindow for BatchAuditWindow {
    fn in_window(&self, e: &WithdrawalEvent) -> bool {
        e.timestamp() >= self.user_start && e.timestamp() <= self.user_end
    }
}

/// A continuous audit only requires a start time
pub struct ContinuousAuditWindow {
    pub user_start: UnixSeconds,
    pub actual_start: UnixSeconds,
}

impl AuditWindow for ContinuousAuditWindow {
    fn in_window(&self, e: &WithdrawalEvent) -> bool {
        e.timestamp() >= self.user_start
    }
}
