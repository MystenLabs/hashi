// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Read-only reconciler that compares the local-limiter snapshot
//! against the guardian's authoritative `LimiterState` on a fixed
//! interval. Surfaces drift as metrics + logs; never mutates state.
//!
//! The watcher's gap-fill (`crate::onchain::watcher::replay_gap`) is
//! the actual recovery path for missed events — this module is the
//! integrity check that makes a stuck or invisible drift detectable.

use hashi_types::guardian::LimiterState;

/// Result of comparing a `(local, guardian)` snapshot pair. Drives the
/// reconciler's metric labels and log severity. Stays an enum (not a
/// struct of nullable fields) so adding a new outcome forces every
/// match site to consider the new case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Local and guardian agree (`next_seq` equal).
    Healthy,
    /// Guardian is ahead of local by `drift_seq`, but within
    /// `tolerance` — expected window for in-flight withdrawals
    /// approved by the guardian but not yet committed on-chain.
    LaggingWithinTolerance { drift_seq: u64 },
    /// Guardian is ahead of local by more than `tolerance`. The
    /// watcher's gap-fill should close this on the next reconnect;
    /// if it persists, we've genuinely lost sync.
    Lagging { drift_seq: u64 },
    /// Local has advanced past the guardian. Impossible during normal
    /// operation: every local advance is caused by a chain event that
    /// the guardian had already approved (and incremented its own
    /// counter for). Always indicates a bug or a guardian rollback.
    Ahead { drift_seq: u64 },
}

/// Pure comparison of two `LimiterState` snapshots. `tolerance` is the
/// number of `next_seq` units guardian is allowed to lead local by
/// before it counts as drift — typically the in-flight cap (1) plus a
/// little slack for clock/checkpoint propagation.
pub fn classify(local: &LimiterState, guardian: &LimiterState, tolerance: u64) -> Outcome {
    if guardian.next_seq < local.next_seq {
        return Outcome::Ahead {
            drift_seq: local.next_seq - guardian.next_seq,
        };
    }
    let drift_seq = guardian.next_seq - local.next_seq;
    if drift_seq == 0 {
        Outcome::Healthy
    } else if drift_seq <= tolerance {
        Outcome::LaggingWithinTolerance { drift_seq }
    } else {
        Outcome::Lagging { drift_seq }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(next_seq: u64) -> LimiterState {
        LimiterState {
            num_tokens_available: 0,
            last_updated_at: 0,
            next_seq,
        }
    }

    #[test]
    fn healthy_when_seqs_match() {
        assert_eq!(classify(&st(7), &st(7), 2), Outcome::Healthy);
    }

    #[test]
    fn lagging_within_tolerance_at_boundary() {
        assert_eq!(
            classify(&st(7), &st(9), 2),
            Outcome::LaggingWithinTolerance { drift_seq: 2 }
        );
    }

    #[test]
    fn lagging_one_past_tolerance() {
        assert_eq!(classify(&st(7), &st(10), 2), Outcome::Lagging { drift_seq: 3 });
    }

    #[test]
    fn lagging_far_behind() {
        assert_eq!(
            classify(&st(0), &st(5_000), 2),
            Outcome::Lagging { drift_seq: 5_000 }
        );
    }

    #[test]
    fn ahead_when_local_runs_past_guardian() {
        assert_eq!(classify(&st(10), &st(7), 2), Outcome::Ahead { drift_seq: 3 });
    }

    #[test]
    fn zero_tolerance_treats_any_lag_as_lagging() {
        assert_eq!(classify(&st(7), &st(8), 0), Outcome::Lagging { drift_seq: 1 });
    }

    #[test]
    fn equal_with_zero_tolerance_is_healthy() {
        assert_eq!(classify(&st(7), &st(7), 0), Outcome::Healthy);
    }
}
