// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Local emulator of the guardian's token-bucket limiter. Bootstrapped
//! from the guardian at startup and advanced by the watcher on every
//! `WithdrawalSignedEvent`. MPC signing only `validate_consume`s.

use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use std::collections::VecDeque;
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

    /// Overwrite local state with the guardian's authoritative `state`.
    pub fn reconcile_to(&self, state: LimiterState) {
        *self.state.write().unwrap() = state;
    }

    /// Snap the mirror to the guardian's `state` on genuine drift, only at a matching
    /// `next_seq` (so a racing `apply_consume` isn't clobbered). A pure refill-timing
    /// difference — same bucket line, different snapshot instant — isn't drift (equal
    /// projected capacity at a common time); clobbering it would stall the refill.
    pub fn reconcile_token_drift(&self, state: LimiterState) -> bool {
        let mut guard = self.state.write().unwrap();
        if guard.next_seq != state.next_seq {
            return false;
        }
        let common = guard.last_updated_at.max(state.last_updated_at);
        if project_capacity(&self.config, &guard, common)
            == project_capacity(&self.config, &state, common)
        {
            return false;
        }
        *guard = state;
        true
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

/// 20 ticks ≈ 5 min at the reconcile cadence.
pub(crate) const STALL_RECONCILE_TICKS: usize = 20;

/// Flags a local mirror that has fallen out of lockstep with the guardian.
///
/// The guardian bumps `next_seq` at finalize-request time but a node only
/// advances on the matching on-chain `WithdrawalSignedEvent`, so `local <
/// guardian` is ordinary in-flight lag and must not, on its own, trip a
/// reconcile (forward-snapping a healthy mirror would double-count the event
/// still in flight). We fire only when the mirror has failed to reach the
/// seq the guardian held a full [`STALL_RECONCILE_TICKS`] window ago — by
/// now those withdrawals have certainly emitted their events, so a mirror
/// still short has genuinely dropped one — or when it runs ahead of the
/// guardian, which can only happen once lockstep is already lost.
#[derive(Default)]
pub(crate) struct LimiterStallTracker {
    /// Guardian `next_seq` seen on each of the last [`STALL_RECONCILE_TICKS`] ticks.
    guardian_seq_window: VecDeque<u64>,
}

impl LimiterStallTracker {
    pub(crate) fn observe(&mut self, local_seq: u64, guardian_seq: u64) -> bool {
        // Once the window is full its front is the guardian seq from a full
        // window ago; the mirror should have reached it by now.
        let stalled = self.guardian_seq_window.len() == STALL_RECONCILE_TICKS
            && self
                .guardian_seq_window
                .front()
                .is_some_and(|&windowed_seq| local_seq < windowed_seq || local_seq > guardian_seq);
        if stalled {
            self.guardian_seq_window.clear();
            return true;
        }
        self.guardian_seq_window.push_back(guardian_seq);
        if self.guardian_seq_window.len() > STALL_RECONCILE_TICKS {
            self.guardian_seq_window.pop_front();
        }
        false
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
    fn test_validate_consume_releases_after_refill() {
        // An over-budget withdrawal clears once the bucket refills.
        let limiter = make_limiter(0, 0, 7);
        let amount = 80_000;
        // refill_rate = 1_000/s ⇒ capacity_at(t) = t * 1_000 on an empty bucket.
        let early = limiter.validate_consume(7, 10, amount).unwrap_err();
        assert!(matches!(
            early,
            LocalLimiterError::InsufficientCapacity {
                needed: 80_000,
                available: 10_000,
            }
        ));
        limiter.validate_consume(7, 100, amount).unwrap();
        assert_eq!(limiter.next_seq(), 7);
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
    fn stall_tracker_ignores_normal_in_flight_lag() {
        let mut tracker = LimiterStallTracker::default();
        // Guardian advances every tick; the mirror trails by one (an event in
        // flight) but always reaches the seq the guardian held a window ago.
        // Spanning several full windows, this normal skew must never fire.
        for tick in 0..(3 * STALL_RECONCILE_TICKS) as u64 {
            assert!(!tracker.observe(100 + tick, 101 + tick));
        }
    }

    #[test]
    fn stall_tracker_does_not_fire_once_the_mirror_catches_up() {
        let mut tracker = LimiterStallTracker::default();
        // Behind for most of a window, then the in-flight events land and the
        // mirror reaches the guardian -> no stall, even across later windows.
        for _ in 0..STALL_RECONCILE_TICKS - 1 {
            assert!(!tracker.observe(40, 45));
        }
        for _ in 0..2 * STALL_RECONCILE_TICKS {
            assert!(!tracker.observe(45, 45));
        }
    }

    #[test]
    fn stall_tracker_stays_quiet_until_a_full_window_of_history() {
        let mut tracker = LimiterStallTracker::default();
        // A mirror behind from the first tick is still granted a full window
        // before any reconcile, so a cold/booting limiter isn't acted on.
        for _ in 0..STALL_RECONCILE_TICKS {
            assert!(!tracker.observe(0, 9));
        }
    }

    #[test]
    fn stall_tracker_fires_when_frozen_behind_a_stalled_guardian() {
        let mut tracker = LimiterStallTracker::default();
        // Leader deficit: mirror wedged at 50 while the guardian sits at 52
        // (the stuck leader finalizes nothing new). Fires after a full window.
        for _ in 0..STALL_RECONCILE_TICKS {
            assert!(!tracker.observe(50, 52));
        }
        assert!(tracker.observe(50, 52));
    }

    #[test]
    fn stall_tracker_fires_when_advancing_mirror_stays_below_the_window() {
        let mut tracker = LimiterStallTracker::default();
        // The mirror creeps up each tick but started so far behind a plateaued
        // guardian that it still hasn't reached where the guardian was a full
        // window ago -> a real dropped event, not in-flight lag.
        for tick in 0..STALL_RECONCILE_TICKS as u64 {
            assert!(!tracker.observe(100 + tick, 200));
        }
        assert!(tracker.observe(100 + STALL_RECONCILE_TICKS as u64, 200));
    }

    #[test]
    fn stall_tracker_fires_for_a_mirror_running_ahead() {
        let mut tracker = LimiterStallTracker::default();
        // local ahead of the guardian can only happen once lockstep is lost.
        for _ in 0..STALL_RECONCILE_TICKS {
            assert!(!tracker.observe(30, 28));
        }
        assert!(tracker.observe(30, 28));
    }

    #[test]
    fn reconcile_token_drift_only_at_matching_seq() {
        let guardian = LimiterState {
            num_tokens_available: 925_600,
            last_updated_at: 838,
            next_seq: 7,
        };
        // Same seq, diverged bucket → snaps.
        let drifted = make_limiter(231_160, 839, 7);
        assert!(drifted.reconcile_token_drift(guardian));
        assert_eq!(drifted.snapshot(), guardian);
        // Already in sync → no-op.
        assert!(!drifted.reconcile_token_drift(guardian));
        // Mirror raced ahead by seq → never clobbered.
        let ahead = make_limiter(0, 900, 8);
        assert!(!ahead.reconcile_token_drift(guardian));
        assert_eq!(ahead.snapshot().next_seq, 8);
        // Behind by seq (in-flight lag) → left to the stall-gated tick.
        let behind = make_limiter(0, 900, 6);
        assert!(!behind.reconcile_token_drift(guardian));
    }

    #[test]
    fn reconcile_token_drift_ignores_refill_timing_on_the_same_line() {
        // Same refill line, snapshotted 100s apart (rate 1_000/s): not drift —
        // clobbering it resets the refill baseline each cycle and wedges forever.
        let guardian = LimiterState {
            num_tokens_available: 500_000,
            last_updated_at: 1_000,
            next_seq: 7,
        };
        let mirror = make_limiter(600_000, 1_100, 7); // 500_000 + 100 * 1_000
        assert!(!mirror.reconcile_token_drift(guardian));
        assert_eq!(mirror.snapshot().num_tokens_available, 600_000);
        assert_eq!(mirror.snapshot().last_updated_at, 1_100);
    }

    #[test]
    fn reconcile_token_drift_still_snaps_genuine_divergence() {
        // Different refill lines at the same seq = real drift → still snaps.
        let guardian = LimiterState {
            num_tokens_available: 925_600,
            last_updated_at: 838,
            next_seq: 7,
        };
        let mirror = make_limiter(600_000, 1_100, 7);
        assert!(mirror.reconcile_token_drift(guardian));
        assert_eq!(mirror.snapshot(), guardian);
    }
}
