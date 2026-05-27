// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Local emulator of the guardian's token-bucket limiter. Bootstrapped
//! from the guardian at startup and advanced by the watcher on every
//! `WithdrawalSignedEvent`. MPC signing only `validate_consume`s.

use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use std::fmt;
use std::sync::RwLock;

pub struct LocalLimiter {
    config: LimiterConfig,
    state: RwLock<LimiterState>,
}

#[derive(Debug, thiserror::Error)]
pub enum LocalLimiterError {
    #[error("stale timestamp: local last_updated_at={local_last}, incoming={incoming}")]
    StaleTimestamp { local_last: u64, incoming: u64 },

    #[error("insufficient capacity: needed {needed}, available {available}")]
    InsufficientCapacity { needed: u64, available: u64 },

    #[error("seq mismatch: local={local}, incoming={incoming}")]
    SeqMismatch { local: u64, incoming: u64 },
}

impl fmt::Debug for LocalLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalLimiter")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl LocalLimiter {
    pub fn new(config: LimiterConfig, state: LimiterState) -> Self {
        Self {
            config,
            state: RwLock::new(state),
        }
    }

    pub fn config(&self) -> &LimiterConfig {
        &self.config
    }

    pub fn snapshot(&self) -> LimiterState {
        *self.state.read().unwrap()
    }

    pub fn capacity_at(&self, timestamp_secs: u64) -> u64 {
        let state = *self.state.read().unwrap();
        project_capacity(&self.config, &state, timestamp_secs)
    }

    pub fn next_seq(&self) -> u64 {
        self.state.read().unwrap().next_seq
    }

    /// Validate a consume; does not mutate state.
    pub fn validate_consume(
        &self,
        expected_seq: u64,
        timestamp_secs: u64,
        amount_sats: u64,
    ) -> Result<(), LocalLimiterError> {
        let state = *self.state.read().unwrap();
        if expected_seq != state.next_seq {
            return Err(LocalLimiterError::SeqMismatch {
                local: state.next_seq,
                incoming: expected_seq,
            });
        }
        if timestamp_secs < state.last_updated_at {
            return Err(LocalLimiterError::StaleTimestamp {
                local_last: state.last_updated_at,
                incoming: timestamp_secs,
            });
        }
        let capacity = project_capacity(&self.config, &state, timestamp_secs);
        if capacity < amount_sats {
            return Err(LocalLimiterError::InsufficientCapacity {
                needed: amount_sats,
                available: capacity,
            });
        }
        Ok(())
    }

    /// Advance local state to match an accepted consume. State is left
    /// untouched on error.
    pub fn apply_consume(
        &self,
        applied_seq: u64,
        timestamp_secs: u64,
        amount_sats: u64,
    ) -> Result<(), LocalLimiterError> {
        let mut guard = self.state.write().unwrap();
        if applied_seq != guard.next_seq {
            return Err(LocalLimiterError::SeqMismatch {
                local: guard.next_seq,
                incoming: applied_seq,
            });
        }
        if timestamp_secs < guard.last_updated_at {
            return Err(LocalLimiterError::StaleTimestamp {
                local_last: guard.last_updated_at,
                incoming: timestamp_secs,
            });
        }
        let capacity = project_capacity(&self.config, &guard, timestamp_secs);
        if capacity < amount_sats {
            return Err(LocalLimiterError::InsufficientCapacity {
                needed: amount_sats,
                available: capacity,
            });
        }
        guard.num_tokens_available = capacity - amount_sats;
        guard.last_updated_at = timestamp_secs;
        guard.next_seq += 1;
        Ok(())
    }

    /// Overwrite local state with the guardian's authoritative `state` (the
    /// recovery path when the watcher's event stream can't re-sync on its own,
    /// e.g. an event dropped across a checkpoint-subscription reconnect).
    pub fn reconcile_to(&self, state: LimiterState) {
        *self.state.write().unwrap() = state;
    }
}

fn project_capacity(config: &LimiterConfig, state: &LimiterState, timestamp_secs: u64) -> u64 {
    let elapsed = timestamp_secs.saturating_sub(state.last_updated_at);
    let refilled = elapsed.saturating_mul(config.refill_rate);
    state
        .num_tokens_available
        .saturating_add(refilled)
        .min(config.max_bucket_capacity)
}

/// Defer when the local limiter is behind a guardian-consumed seq for a
/// *different* withdrawal; same-wid retries are served idempotently.
pub(crate) fn should_defer_guardian_finalize(
    next_seq: u64,
    last_finalized: Option<(u64, sui_sdk_types::Address)>,
    wid: sui_sdk_types::Address,
) -> bool {
    last_finalized.is_some_and(|(last_seq, last_wid)| next_seq <= last_seq && wid != last_wid)
}

/// Consecutive reconcile ticks the mirror must stay drifted *at the same local
/// seq* before we treat it as a genuine stall (vs. normal in-flight lag, where
/// `local_seq` keeps advancing between ticks). 20 ticks ≈ 5 min at 15 s — wide
/// enough that a slow guardian-RPC → on-chain-event round-trip doesn't trip a
/// false stall and over-advance the mirror.
pub(crate) const STALL_RECONCILE_TICKS: u32 = 20;

/// Detects a frozen mirror over a streak of reconcile ticks; returns `true`
/// once the streak crosses [`STALL_RECONCILE_TICKS`] and resets afterwards.
#[derive(Default)]
pub(crate) struct LimiterStallTracker {
    frozen_at_seq: Option<u64>,
    frozen_ticks: u32,
}

impl LimiterStallTracker {
    pub(crate) fn observe(&mut self, local_seq: u64, guardian_seq: u64) -> bool {
        if local_seq == guardian_seq {
            self.reset();
            return false;
        }
        if self.frozen_at_seq == Some(local_seq) {
            self.frozen_ticks += 1;
        } else {
            self.frozen_at_seq = Some(local_seq);
            self.frozen_ticks = 1;
        }
        if self.frozen_ticks >= STALL_RECONCILE_TICKS {
            self.reset();
            true
        } else {
            false
        }
    }

    fn reset(&mut self) {
        self.frozen_at_seq = None;
        self.frozen_ticks = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_limiter(
        num_tokens_available: u64,
        last_updated_at: u64,
        next_seq: u64,
    ) -> LocalLimiter {
        let config = LimiterConfig {
            refill_rate: 1_000,
            max_bucket_capacity: 2_000_000,
        };
        let state = LimiterState {
            num_tokens_available,
            last_updated_at,
            next_seq,
        };
        LocalLimiter::new(config, state)
    }

    #[test]
    fn test_validate_consume_happy_path() {
        let limiter = make_limiter(0, 0, 7);
        limiter.validate_consume(7, 100, 80_000).unwrap();
    }

    #[test]
    fn test_validate_rejects_seq_mismatch() {
        let limiter = make_limiter(100_000, 0, 5);
        let err = limiter.validate_consume(7, 100, 1_000).unwrap_err();
        match err {
            LocalLimiterError::SeqMismatch { local, incoming } => {
                assert_eq!(local, 5);
                assert_eq!(incoming, 7);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_validate_rejects_stale_timestamp() {
        let limiter = make_limiter(0, 100, 0);
        let err = limiter.validate_consume(0, 50, 0).unwrap_err();
        assert!(matches!(err, LocalLimiterError::StaleTimestamp { .. }));
    }

    #[test]
    fn test_validate_rejects_over_capacity() {
        let limiter = make_limiter(0, 0, 0);
        let err = limiter.validate_consume(0, 10, 50_000).unwrap_err();
        match err {
            LocalLimiterError::InsufficientCapacity { needed, available } => {
                assert_eq!(needed, 50_000);
                assert_eq!(available, 10_000);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_apply_bumps_seq_and_updates_last_updated_at() {
        let limiter = make_limiter(0, 0, 42);
        limiter.validate_consume(42, 100, 80_000).unwrap();
        limiter.apply_consume(42, 100, 80_000).unwrap();
        let snap = limiter.snapshot();
        assert_eq!(snap.next_seq, 43);
        assert_eq!(snap.last_updated_at, 100);
        assert_eq!(snap.num_tokens_available, 20_000);
    }

    #[test]
    fn test_apply_rejects_seq_mismatch() {
        let limiter = make_limiter(0, 0, 0);
        let err = limiter.apply_consume(5, 100, 1_000).unwrap_err();
        assert!(matches!(err, LocalLimiterError::SeqMismatch { .. }));
    }

    #[test]
    fn test_capacity_at_refills_linearly_and_clamps_to_ceiling() {
        let limiter = make_limiter(100_000, 10, 0);
        assert_eq!(limiter.capacity_at(15), 105_000);
        assert_eq!(limiter.capacity_at(u64::MAX), 2_000_000);
    }

    #[test]
    fn test_next_seq_matches_snapshot() {
        let limiter = make_limiter(0, 0, 11);
        assert_eq!(limiter.next_seq(), 11);
    }

    #[test]
    fn defer_only_for_a_different_wid_at_an_already_consumed_seq() {
        let a = sui_sdk_types::Address::new([1u8; 32]);
        let b = sui_sdk_types::Address::new([2u8; 32]);
        assert!(!should_defer_guardian_finalize(0, None, a));
        assert!(should_defer_guardian_finalize(5, Some((5, a)), b));
        assert!(should_defer_guardian_finalize(4, Some((5, a)), b));
        assert!(!should_defer_guardian_finalize(5, Some((5, a)), a));
        assert!(!should_defer_guardian_finalize(6, Some((5, a)), b));
    }

    #[test]
    fn reconcile_to_overwrites_state_in_either_direction() {
        let limiter = make_limiter(0, 0, 21);
        // Forward: recover a mirror stuck behind the guardian.
        limiter.reconcile_to(LimiterState {
            num_tokens_available: 500,
            last_updated_at: 100,
            next_seq: 30,
        });
        let s = limiter.snapshot();
        assert_eq!(s.next_seq, 30);
        assert_eq!(s.num_tokens_available, 500);
        assert_eq!(s.last_updated_at, 100);
        // Backward: correct an overshoot back to the source of truth.
        limiter.reconcile_to(LimiterState {
            num_tokens_available: 1,
            last_updated_at: 200,
            next_seq: 25,
        });
        assert_eq!(limiter.snapshot().next_seq, 25);
    }

    #[test]
    fn stall_tracker_ignores_normal_advancing_lag() {
        let mut tracker = LimiterStallTracker::default();
        // Mirror trails the guardian by one but keeps advancing -> never a stall.
        for seq in 5..5 + 3 * u64::from(STALL_RECONCILE_TICKS) {
            assert!(!tracker.observe(seq, seq + 1));
        }
    }

    #[test]
    fn stall_tracker_resets_when_caught_up() {
        let mut tracker = LimiterStallTracker::default();
        assert!(!tracker.observe(21, 22));
        assert!(!tracker.observe(22, 22)); // caught up -> reset
        assert!(!tracker.observe(22, 23)); // streak starts over
    }

    #[test]
    fn stall_tracker_fires_after_persistent_freeze_then_resets() {
        let mut tracker = LimiterStallTracker::default();
        for _ in 0..STALL_RECONCILE_TICKS - 1 {
            assert!(!tracker.observe(21, 22));
        }
        assert!(tracker.observe(21, 22)); // genuine stall
        assert!(!tracker.observe(21, 22)); // reset after firing
    }

    #[test]
    fn stall_tracker_fires_for_overshoot_too() {
        let mut tracker = LimiterStallTracker::default();
        for _ in 0..STALL_RECONCILE_TICKS - 1 {
            assert!(!tracker.observe(24, 22)); // local ahead of the guardian
        }
        assert!(tracker.observe(24, 22));
    }
}
