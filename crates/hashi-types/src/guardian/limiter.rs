// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianError::InvalidInputs;
use super::GuardianError::RateLimitExceeded;
use super::GuardianResult;
use serde::Serialize;
use std::collections::HashMap;

/// How long a soft reservation is held before the guardian garbage
/// collects it. Long enough to cover committee fan-out + MPC signing
/// on any realistic path; short enough that a crashed caller does not
/// lock capacity for operators to notice and intervene.
pub const SOFT_RESERVE_TTL_SECS: u64 = 5 * 60;

/// Immutable configuration for the token bucket rate limiter.
#[derive(Debug, Copy, Clone, PartialEq, Serialize)]
pub struct LimiterConfig {
    /// Refill rate in sats per second.
    pub refill_rate: u64,
    /// Maximum bucket capacity in sats.
    pub max_bucket_capacity: u64,
}

/// Serializable state for the token bucket rate limiter.
/// Provisioners provide this when initializing the enclave.
#[derive(Debug, Copy, Clone, PartialEq, Serialize)]
pub struct LimiterState {
    /// Available tokens in sats.
    pub num_tokens_available: u64,
    /// Last refill timestamp in unix seconds.
    pub last_updated_at: u64,
    /// Next expected withdrawal sequence number.
    pub next_seq: u64,
}

/// An in-flight soft reservation. Held by the guardian until either a
/// matching `consume` converts it to a hard reserve or the TTL expires.
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct PendingReserve {
    /// Amount of sats soft-reserved.
    pub amount_sats: u64,
    /// Timestamp of the reserving request (unix seconds).
    pub timestamp_secs: u64,
    /// Unix-seconds wall-clock at which the guardian will drop this entry
    /// if still present.
    pub expires_at_secs: u64,
}

/// Token bucket rate limiter. Tokens refill linearly over time.
///
/// Pure data structure — concurrency is handled by the caller via a Mutex.
pub struct RateLimiter {
    config: LimiterConfig,
    state: LimiterState,
    /// In-flight soft reservations keyed by `wid`. Idempotent on wid.
    /// Subtracted from refilled capacity on new soft-reserve capacity
    /// checks so concurrent reservations do not over-commit the bucket.
    pending_reserves: HashMap<u64, PendingReserve>,
    /// Snapshot of state before the most recent `consume`, used for revert.
    prev_state: LimiterState,
}

impl RateLimiter {
    pub fn new(config: LimiterConfig, state: LimiterState) -> GuardianResult<Self> {
        if state.num_tokens_available > config.max_bucket_capacity {
            return Err(InvalidInputs(
                "num_tokens_available exceeds max_bucket_capacity".into(),
            ));
        }
        let prev_state = state;
        Ok(Self {
            config,
            state,
            pending_reserves: HashMap::new(),
            prev_state,
        })
    }

    pub fn config(&self) -> &LimiterConfig {
        &self.config
    }

    pub fn state(&self) -> &LimiterState {
        &self.state
    }

    pub fn next_seq(&self) -> u64 {
        self.state.next_seq
    }

    /// Number of pending soft reservations (exposed for metrics/tests).
    pub fn pending_reserves_len(&self) -> usize {
        self.pending_reserves.len()
    }

    /// Look up a pending soft reservation by wid.
    pub fn pending_reserve(&self, wid: u64) -> Option<&PendingReserve> {
        self.pending_reserves.get(&wid)
    }

    /// Effective "last updated at" — the max of the committed
    /// `last_updated_at` and the timestamps of all outstanding soft
    /// reservations. New requests must supply a timestamp at least this
    /// large so the refill window is monotonic.
    pub fn effective_last_updated_at(&self) -> u64 {
        let latest_pending = self
            .pending_reserves
            .values()
            .map(|r| r.timestamp_secs)
            .max()
            .unwrap_or(0);
        self.state.last_updated_at.max(latest_pending)
    }

    /// Reserve `amount_sats` for `wid` pending a future `consume`.
    ///
    /// Idempotent on wid: a repeat call with an already-pending wid
    /// returns the existing reservation unchanged. This makes it safe
    /// for multiple validators to probe the guardian concurrently.
    ///
    /// `now_unix_secs` is the guardian's wall clock used to compute the
    /// TTL deadline; the authoritative refill check uses the
    /// caller-supplied `timestamp_secs` (monotonic across the Sui
    /// clock).
    pub fn soft_reserve(
        &mut self,
        wid: u64,
        timestamp_secs: u64,
        amount_sats: u64,
        now_unix_secs: u64,
    ) -> GuardianResult<PendingReserve> {
        // Idempotency: re-probing with the same wid returns the same
        // reservation. Extend its TTL so legitimate retries don't race
        // with expiry.
        if let Some(existing) = self.pending_reserves.get_mut(&wid) {
            existing.expires_at_secs = now_unix_secs.saturating_add(SOFT_RESERVE_TTL_SECS);
            return Ok(*existing);
        }

        let effective_last = self.effective_last_updated_at();
        if timestamp_secs < effective_last {
            return Err(InvalidInputs(format!(
                "timestamp {timestamp_secs} < effective_last_updated_at {effective_last}"
            )));
        }

        let capacity = self.capacity_at(timestamp_secs);
        if capacity < amount_sats {
            return Err(RateLimitExceeded);
        }

        let reserve = PendingReserve {
            amount_sats,
            timestamp_secs,
            expires_at_secs: now_unix_secs.saturating_add(SOFT_RESERVE_TTL_SECS),
        };
        self.pending_reserves.insert(wid, reserve);
        Ok(reserve)
    }

    /// Drop any pending reserve whose TTL has elapsed at `now_unix_secs`.
    /// Returns the number of entries removed (for tests + metrics).
    pub fn expire_pending(&mut self, now_unix_secs: u64) -> usize {
        let before = self.pending_reserves.len();
        self.pending_reserves
            .retain(|_, r| r.expires_at_secs > now_unix_secs);
        before - self.pending_reserves.len()
    }

    /// Capacity at `timestamp` accounting for refill since
    /// `last_updated_at` AND outstanding soft reserves. Used by
    /// `soft_reserve` to reject over-commitment.
    fn capacity_at(&self, timestamp_secs: u64) -> u64 {
        let elapsed = timestamp_secs.saturating_sub(self.state.last_updated_at);
        let refilled = elapsed.saturating_mul(self.config.refill_rate);
        let base = self
            .state
            .num_tokens_available
            .saturating_add(refilled)
            .min(self.config.max_bucket_capacity);
        let pending_sum: u64 = self.pending_reserves.values().map(|r| r.amount_sats).sum();
        base.saturating_sub(pending_sum)
    }

    /// Consume tokens from the bucket. Validates seq and timestamp ordering,
    /// refills based on elapsed time, then debits the requested amount.
    ///
    /// If a soft reservation exists for `wid`, it is removed as part of
    /// the consume (converting the soft reserve to a hard reserve).
    pub fn consume(
        &mut self,
        wid: u64,
        seq: u64,
        timestamp: u64,
        amount_sats: u64,
    ) -> GuardianResult<()> {
        if seq != self.state.next_seq {
            return Err(InvalidInputs(format!(
                "seq mismatch: expected {}, got {}",
                self.state.next_seq, seq
            )));
        }
        if timestamp < self.state.last_updated_at {
            return Err(InvalidInputs(format!(
                "timestamp {} < last_updated_at {}",
                timestamp, self.state.last_updated_at
            )));
        }

        // Refill tokens based on elapsed time.
        let elapsed = timestamp
            .checked_sub(self.state.last_updated_at)
            .expect("timestamp checked above");
        let refilled = elapsed.saturating_mul(self.config.refill_rate);
        let capacity = self
            .state
            .num_tokens_available
            .saturating_add(refilled)
            .min(self.config.max_bucket_capacity);

        if capacity < amount_sats {
            return Err(RateLimitExceeded);
        }

        // Snapshot for revert, then mutate. The matching soft reservation
        // (if any) is removed on success; on revert it would otherwise
        // double-count against future capacity, so we drop it here
        // regardless.
        self.prev_state = self.state;
        self.pending_reserves.remove(&wid);
        self.state.last_updated_at = timestamp;
        self.state.num_tokens_available = capacity - amount_sats;
        self.state.next_seq += 1;
        Ok(())
    }

    /// Revert a previous `consume`. Restores state to pre-consume snapshot.
    pub fn revert(&mut self) {
        self.state = self.prev_state;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn make_limiter() -> (LimiterConfig, LimiterState) {
        let config = LimiterConfig {
            refill_rate: 1_000,
            max_bucket_capacity: 2_000_000,
        };
        let state = LimiterState {
            num_tokens_available: 0,
            last_updated_at: 0,
            next_seq: 0,
        };

        (config, state)
    }

    #[test]
    fn test_basic() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();
        assert!(limiter.consume(1, 0, 1, config.refill_rate).is_ok());

        let target_amount = 1_000_000u64;
        let num_secs_required = target_amount.div_ceil(config.refill_rate);
        assert!(
            limiter
                .consume(2, 1, num_secs_required, target_amount)
                .is_err()
        );
        assert!(
            limiter
                .consume(2, 1, 1 + num_secs_required, target_amount)
                .is_ok()
        );
    }

    #[test]
    fn test_limits() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();
        assert!(
            limiter
                .consume(1, 0, u64::MAX, config.max_bucket_capacity + 1)
                .is_err()
        );
        assert!(
            limiter
                .consume(1, 0, u64::MAX, config.max_bucket_capacity)
                .is_ok()
        );
    }

    #[test]
    fn test_revert_restores_pre_refill_state() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();
        // Consume after refill, then revert — should restore original state.
        limiter.consume(1, 0, 100, 50_000).unwrap();
        assert_eq!(limiter.state().num_tokens_available, 50_000); // 100*1000 - 50_000
        limiter.revert();
        assert_eq!(limiter.state().num_tokens_available, 0);
        assert_eq!(limiter.state().last_updated_at, 0);
        assert_eq!(limiter.state().next_seq, 0);
    }

    #[test]
    fn test_rejects_wrong_seq_and_old_timestamp() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();
        // Wrong seq.
        assert!(limiter.consume(1, 1, 0, 0).is_err());
        // Advance state.
        limiter.consume(1, 0, 100, 1_000).unwrap();
        // Old timestamp.
        assert!(limiter.consume(2, 1, 50, 1_000).is_err());
    }

    // ============================
    //   Soft reserve behavior
    // ============================

    #[test]
    fn test_soft_reserve_is_idempotent_on_wid() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();

        // First soft reserve at t=100 for 50k sats, 100*1000=100k refill.
        let r1 = limiter.soft_reserve(42, 100, 50_000, 1_000).unwrap();
        assert_eq!(r1.amount_sats, 50_000);
        assert_eq!(limiter.pending_reserves_len(), 1);

        // Idempotent: same wid returns the same amount/timestamp; TTL refreshed.
        let r2 = limiter.soft_reserve(42, 200, 999_999, 2_000).unwrap();
        assert_eq!(limiter.pending_reserves_len(), 1);
        assert_eq!(r2.amount_sats, r1.amount_sats);
        assert_eq!(r2.timestamp_secs, r1.timestamp_secs);
        assert!(r2.expires_at_secs > r1.expires_at_secs);
    }

    #[test]
    fn test_soft_reserve_rejects_over_commitment_across_wids() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();

        // Capacity at t=100 = 100k. First reserve takes 80k.
        limiter.soft_reserve(1, 100, 80_000, 1_000).unwrap();

        // Second distinct wid only has 20k left.
        assert!(matches!(
            limiter.soft_reserve(2, 100, 30_000, 1_000),
            Err(RateLimitExceeded)
        ));
        assert!(limiter.soft_reserve(2, 100, 20_000, 1_000).is_ok());
    }

    #[test]
    fn test_soft_reserve_enforces_monotonic_timestamp() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();

        limiter.soft_reserve(1, 200, 10_000, 1_000).unwrap();
        // A soft reserve older than the latest pending timestamp is rejected.
        assert!(limiter.soft_reserve(2, 150, 10_000, 1_000).is_err());
    }

    #[test]
    fn test_expire_pending_drops_stale_reservations() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();

        limiter.soft_reserve(1, 100, 1_000, 1_000).unwrap();
        assert_eq!(limiter.pending_reserves_len(), 1);

        // Just before TTL — nothing expires.
        let removed = limiter.expire_pending(1_000 + SOFT_RESERVE_TTL_SECS - 1);
        assert_eq!(removed, 0);
        assert_eq!(limiter.pending_reserves_len(), 1);

        // Past TTL — entry dropped.
        let removed = limiter.expire_pending(1_000 + SOFT_RESERVE_TTL_SECS + 1);
        assert_eq!(removed, 1);
        assert_eq!(limiter.pending_reserves_len(), 0);
    }

    #[test]
    fn test_consume_removes_matching_soft_reserve() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();

        limiter.soft_reserve(42, 100, 50_000, 1_000).unwrap();
        assert_eq!(limiter.pending_reserves_len(), 1);

        limiter.consume(42, 0, 100, 50_000).unwrap();
        assert_eq!(limiter.pending_reserves_len(), 0);
        assert_eq!(limiter.state().num_tokens_available, 50_000); // 100k refill - 50k
    }

    #[test]
    fn test_soft_reserve_leaves_room_for_hard_reserve_of_same_wid() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();

        // Reserve all available headroom for a single wid.
        limiter.soft_reserve(42, 100, 100_000, 1_000).unwrap();

        // Hard reserve for the same wid converts the pending reservation.
        assert!(limiter.consume(42, 0, 100, 100_000).is_ok());
        assert_eq!(limiter.pending_reserves_len(), 0);
    }
}
