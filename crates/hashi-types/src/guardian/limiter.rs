// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianError::InvalidInputs;
use super::GuardianError::RateLimitExceeded;
use super::GuardianResult;
use serde::Deserialize;
use serde::Serialize;

/// Immutable configuration for the token bucket rate limiter.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimiterConfig {
    /// Refill rate in sats per second.
    pub refill_rate: u64,
    /// Maximum bucket capacity in sats.
    pub max_bucket_capacity: u64,
}

/// Serializable state for the token bucket rate limiter.
/// Provisioners provide this when initializing the enclave; it is also embedded
/// in each successful withdrawal log so the next KP can recover it.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimiterState {
    /// Available tokens in sats.
    pub num_tokens_available: u64,
    /// Last refill timestamp in unix seconds.
    pub last_updated_at: u64,
    /// Next expected withdrawal sequence number.
    pub next_seq: u64,
}

impl LimiterState {
    /// Genesis state for a freshly bootstrapped enclave: a full bucket, no
    /// consumes yet, no refill timestamp.
    ///
    /// TODO: if the provisioner-init rotation path falls back here (no Success
    /// logs in the prior enclave's walk-back window), `next_seq = 0` may not
    /// match Hashi's current seq counter. Recover the real seq from a
    /// separate source instead of falling back to 0.
    pub fn genesis(config: &super::LimiterConfig) -> Self {
        Self {
            num_tokens_available: config.max_bucket_capacity,
            last_updated_at: 0,
            next_seq: 0,
        }
    }
}

/// Token bucket rate limiter. Tokens refill linearly over time.
///
/// Pure data structure — concurrency is handled by the caller via a Mutex.
pub struct RateLimiter {
    config: LimiterConfig,
    state: LimiterState,
}

impl RateLimiter {
    pub fn new(config: LimiterConfig, state: LimiterState) -> GuardianResult<Self> {
        if state.num_tokens_available > config.max_bucket_capacity {
            return Err(InvalidInputs(
                "num_tokens_available exceeds max_bucket_capacity".into(),
            ));
        }
        Ok(Self { config, state })
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

    /// Consume tokens from the bucket. Validates seq and timestamp ordering,
    /// refills based on elapsed time, then debits the requested amount.
    pub fn consume(&mut self, seq: u64, timestamp: u64, amount_sats: u64) -> GuardianResult<()> {
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

        self.state.last_updated_at = timestamp;
        self.state.num_tokens_available = capacity - amount_sats;
        self.state.next_seq += 1;
        Ok(())
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
        assert!(limiter.consume(0, 1, config.refill_rate).is_ok());

        let target_amount = 1_000_000u64;
        let num_secs_required = target_amount.div_ceil(config.refill_rate);
        assert!(
            limiter
                .consume(1, num_secs_required, target_amount)
                .is_err()
        );
        assert!(
            limiter
                .consume(1, 1 + num_secs_required, target_amount)
                .is_ok()
        );
    }

    #[test]
    fn test_limits() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();
        assert!(
            limiter
                .consume(0, u64::MAX, config.max_bucket_capacity + 1)
                .is_err()
        );
        assert!(
            limiter
                .consume(0, u64::MAX, config.max_bucket_capacity)
                .is_ok()
        );
    }

    #[test]
    fn test_rejects_wrong_seq_and_old_timestamp() {
        let (config, state) = make_limiter();
        let mut limiter = RateLimiter::new(config, state).unwrap();
        // Wrong seq.
        assert!(limiter.consume(1, 0, 0).is_err());
        // Advance state.
        limiter.consume(0, 100, 1_000).unwrap();
        // Old timestamp.
        assert!(limiter.consume(1, 50, 1_000).is_err());
    }
}
